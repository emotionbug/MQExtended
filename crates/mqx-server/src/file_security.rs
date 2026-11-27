use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use mqx_auth::{AclFileError, PasswordFile, PasswordFileError, external::ExternalSecurity};
use mqx_broker::{Broker, SecurityHandle};
use mqx_server::{ServerConfig, ServerError};

pub(super) struct PolicyWatch {
    files: Vec<WatchedPolicy>,
}

struct WatchedPolicy {
    path: PathBuf,
    observed: Option<Fingerprint>,
    attempted: Option<Fingerprint>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl Fingerprint {
    fn read(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        // Follow symlinks so an atomic Kubernetes ..data swap is visible.
        let metadata = fs::metadata(path).ok()?;
        Some(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}

impl PolicyWatch {
    /// Snapshot before opening the files so a racing replacement isn't missed.
    pub(super) fn new(config: &ServerConfig) -> Self {
        let mut paths = BTreeSet::new();
        for listener in &config.listeners {
            let (password, acl) = config.credential_paths_for(listener);
            paths.extend([password, acl].into_iter().flatten());
        }
        let files = paths
            .into_iter()
            .map(|path| {
                let observed = Fingerprint::read(path);
                WatchedPolicy {
                    path: path.to_owned(),
                    observed,
                    attempted: observed,
                }
            })
            .collect();
        Self { files }
    }

    pub(super) fn stable_change(&mut self) -> bool {
        let mut changed = false;
        let mut stable = true;
        for file in &mut self.files {
            let current = Fingerprint::read(&file.path);
            stable &= file.observed == current;
            changed |= file.attempted != current;
            file.observed = current;
        }
        if changed && stable {
            // Reload the whole set together. After a failure, retry only
            // when the set changes rather than logging the same error again.
            for file in &mut self.files {
                file.attempted = file.observed;
            }
            true
        } else {
            false
        }
    }
}

pub(super) struct SecurityHandles {
    groups: Vec<PolicyGroup>,
    slots: Vec<(usize, usize)>,
}

struct PolicyGroup {
    handle: SecurityHandle,
    listeners: Vec<usize>,
}

impl SecurityHandles {
    /// `external` holds the initialized auth plugins, indexed like
    /// [`ServerConfig::external_plugins`].
    pub(super) fn new(
        config: &ServerConfig,
        external: &[Arc<dyn ExternalSecurity>],
    ) -> Result<Self, ServerError> {
        let mut by_plugin = BTreeMap::new();
        let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
        let mut slots = Vec::with_capacity(config.listeners.len());
        for (index, listener) in config.listeners.iter().enumerate() {
            let (password, acl) = listener.security.file_plugins.paths();
            let group = if config.per_listener_settings {
                // Built-in file paths can independently change at SIGHUP.
                groups.len()
            } else {
                // Named plugins can vary by listener without per_listener_settings.
                // Group by their immutable startup paths, not reloadable built-ins.
                *by_plugin
                    .entry((
                        password.map(Path::as_os_str),
                        acl.map(Path::as_os_str),
                        listener.external_plugin,
                    ))
                    .or_insert(groups.len())
            };
            if group == groups.len() {
                // Stable cluster policy IDs. Keep the existing shared/global ID
                // at 1; new listener-specific groups use the first listener index.
                let id = if config.per_listener_settings {
                    index as u64 + 1
                } else if password.is_some() || acl.is_some() || listener.external_plugin.is_some()
                {
                    index as u64 + 2
                } else {
                    1
                };
                groups.push((id, Vec::new()));
            }
            let members = &mut groups[group].1;
            slots.push((group, members.len()));
            members.push(index);
        }
        let groups = groups
            .into_iter()
            .map(|(id, listeners)| {
                let credentials = Credentials::load(config, listeners[0])?;
                let mut handle = credentials
                    .install(|password, acl| SecurityHandle::with_id(id, password, acl))?;
                if let Some(plugin) = config.listeners[listeners[0]].external_plugin {
                    // The declaration index is identical on every node.
                    handle = handle.with_external(plugin as u32, external[plugin].clone());
                }
                Ok(PolicyGroup { handle, listeners })
            })
            .collect::<Result<_, ServerError>>()?;
        Ok(Self { groups, slots })
    }

    /// Every policy handle, for [`Broker::clustered_with_security`].
    pub(super) fn handles(&self) -> Vec<SecurityHandle> {
        self.groups
            .iter()
            .map(|group| group.handle.clone())
            .collect()
    }

    pub(super) fn for_listener(&self, index: usize) -> SecurityHandle {
        let (group, slot) = self.slots[index];
        self.groups[group].handle.clone().for_listener(slot)
    }

    pub(super) fn reload(
        &self,
        config: &ServerConfig,
        before_install: impl FnOnce(),
    ) -> Result<(), ServerError> {
        let replacements = self
            .groups
            .iter()
            .map(|group| {
                let anonymous = group
                    .listeners
                    .iter()
                    .map(|&index| config.allow_anonymous_for(&config.listeners[index]))
                    .collect();
                Credentials::load(config, group.listeners[0])?.install(|password, acl| {
                    group.handle.prepare_replacement(password, acl, anonymous)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        before_install();
        for install in replacements {
            install();
        }
        Ok(())
    }

    pub(super) async fn register(&self, broker: &Broker) -> Result<(), ServerError> {
        for group in &self.groups {
            broker
                .register_security(&group.handle)
                .await
                .map_err(ServerError::Cluster)?;
        }
        Ok(())
    }
}

struct Credentials<'a> {
    password: Option<PasswordFile>,
    acl: Option<(&'a Path, Vec<u8>)>,
}

impl<'a> Credentials<'a> {
    fn load(config: &'a ServerConfig, index: usize) -> Result<Self, ServerError> {
        let (password, acl) = config.credential_paths_for(&config.listeners[index]);
        let password = password
            .map(|path| {
                let password = || {
                    let text = read_policy(path).map_err(|source| PasswordFileError::Io {
                        path: path.into(),
                        source,
                    })?;
                    PasswordFile::parse(&text)
                };
                password().map_err(|source| ServerError::PasswordFile {
                    path: path.into(),
                    source,
                })
            })
            .transpose()?;
        let acl = acl
            .map(|path| {
                read_policy(path)
                    .map(|text| (path, text))
                    .map_err(|source| ServerError::AclFile {
                        path: path.into(),
                        source: AclFileError::Io {
                            path: path.into(),
                            source,
                        },
                    })
            })
            .transpose()?;
        Ok(Self { password, acl })
    }

    fn install<R>(
        self,
        import: impl FnOnce(Option<PasswordFile>, Option<Vec<u8>>) -> Result<R, AclFileError>,
    ) -> Result<R, ServerError> {
        let (path, acl) = match self.acl {
            Some((path, text)) => (Some(path), Some(text)),
            None => (None, None),
        };
        import(self.password, acl).map_err(|source| ServerError::AclFile {
            path: path
                .expect("ACL parsing failed only when an ACL was supplied")
                .into(),
            source,
        })
    }
}

fn read_policy(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // libcommon/file_common.c: mosquitto_fopen(..., restrict_read=true)
        // opens the final component without following symlinks, then checks
        // the actual descriptor. Do not block waiting for a FIFO to open.
        let mut flags = nix::libc::O_NONBLOCK;
        if std::env::var_os("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS").is_none() {
            flags |= nix::libc::O_NOFOLLOW;
        }
        options.custom_flags(flags);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}
