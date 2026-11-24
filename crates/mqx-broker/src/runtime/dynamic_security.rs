use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

use mqx_auth::{
    Access, DynamicSecurity, DynsecRequest,
    external::{AclAccess, Binding, Subject, Verdict},
};

use super::*;
use crate::{external_acl_precheck, security_callbacks, state::DynamicControl};

impl Broker {
    /// Installs this node's JSON destination and uses `initial` only if no
    /// Dynamic Security policy has been committed. `None` joins existing state.
    pub async fn register_dynamic_security(
        &self,
        path: PathBuf,
        initial: Option<DynamicSecurity>,
    ) -> Result<(), BrokerError> {
        self.register_dynamic_security_inner(path, || Ok(initial))
            .await
    }

    /// Like [`Self::register_dynamic_security`], but loads or generates credentials
    /// only if the broker has not initialized Dynamic Security yet.
    pub async fn register_dynamic_security_with(
        &self,
        path: PathBuf,
        initial: impl FnOnce() -> Result<DynamicSecurity, BrokerError>,
    ) -> Result<(), BrokerError> {
        self.register_dynamic_security_inner(path, || initial().map(Some))
            .await
    }

    async fn register_dynamic_security_inner(
        &self,
        path: PathBuf,
        initial: impl FnOnce() -> Result<Option<DynamicSecurity>, BrokerError>,
    ) -> Result<(), BrokerError> {
        let _registration = self.0.dynamic_security_registration.lock().await;
        if let Some(previous) = &self.0.runtime.lock().unwrap().dynamic_security_path {
            return if *previous == path {
                Ok(())
            } else {
                Err(file_error(
                    &path,
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "another Dynamic Security file is registered",
                    ),
                ))
            };
        }

        let initialized = match &self.0.log {
            Log::Local { .. } => self
                .0
                .runtime
                .lock()
                .unwrap()
                .local
                .as_ref()
                .unwrap()
                .state
                .dynamic_policy()
                .is_some(),
            Log::Replicated(log) => {
                log.cluster
                    .linearizable_read(|machine| machine.state.dynamic_policy().is_some())
                    .await?
            }
        };
        if !initialized {
            if let Some(initial) = initial()? {
                self.submit(Command::InitDynamicSecurity(Arc::new(initial)))
                    .await?;
            } else if let Log::Replicated(log) = &self.0.log {
                let mut applied = log.applied.clone();
                tokio::time::timeout(log.timeout, async {
                    loop {
                        drop(applied.borrow_and_update());
                        if log
                            .cluster
                            .read(|machine| machine.state.dynamic_policy().is_some())
                        {
                            return Ok::<(), BrokerError>(());
                        }
                        applied
                            .changed()
                            .await
                            .map_err(|_| ClusterError::Shutdown)?;
                    }
                })
                .await
                .map_err(|_| BrokerError::DynamicSecurityUninitialized)??;
            } else {
                return Err(BrokerError::DynamicSecurityUninitialized);
            }
        }

        // Save and attach the path in apply lock order so a concurrent mutation
        // cannot save newer state before the registration writes its first file.
        match &self.0.log {
            Log::Local { .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                register_file(&path, &runtime.local.as_ref().unwrap().state)?;
                runtime.dynamic_security_path = Some(path);
            }
            Log::Replicated(log) => log.cluster.read(|machine| {
                let mut runtime = self.0.runtime.lock().unwrap();
                register_file(&path, &machine.state)?;
                runtime.dynamic_security_path = Some(path);
                Ok::<(), BrokerError>(())
            })?,
        }
        Ok(())
    }

    pub(crate) fn dynamic_policy_snapshot(
        &self,
        security: &SecurityHandle,
    ) -> Option<(u64, Arc<DynamicSecurity>)> {
        security.1?;
        let snapshot = |state: &State| {
            state
                .dynamic_policy()
                .map(|(revision, policy)| (revision, policy.clone()))
        };
        match &self.0.log {
            Log::Local { .. } => {
                snapshot(&self.0.runtime.lock().unwrap().local.as_ref().unwrap().state)
            }
            Log::Replicated(log) => log.cluster.read(|machine| snapshot(&machine.state)),
        }
    }

    /// Mosquitto http_api.c: check_access runs Basic authentication and the
    /// requested URL through the listener's security callbacks.
    pub async fn http_read_allowed(
        &self,
        security: &SecurityHandle,
        username: Option<&str>,
        password: Option<&[u8]>,
        allow_anonymous: bool,
        url: &str,
    ) -> bool {
        let client_id = Arc::<str>::from("http-api");
        let username = username.map(Arc::<str>::from);
        let password = password.map(Bytes::copy_from_slice);
        let file = security.0.snapshots.borrow().clone();
        let allow_anonymous = security.anonymous(&file, allow_anonymous);
        let dynamic = security.1.zip(
            self.dynamic_policy_snapshot(security)
                .map(|(_, policy)| policy),
        );
        let plugin = security.3.as_ref().map(|(_, plugin)| plugin.as_ref());
        let (verdict, credentials) = file
            .clone()
            .authenticate(
                &client_id,
                username.as_ref(),
                password.as_ref(),
                allow_anonymous,
                dynamic.as_ref(),
                plugin,
            )
            .await;
        if verdict != Verdict::Allow {
            return false;
        }
        let user = username.as_deref();
        if let Some(plugin) = plugin {
            // plugin_acl_check.c: URL READ uses the same reserved-topic rules.
            if url.starts_with("$share") || !external_acl_precheck(plugin, &client_id, user) {
                return false;
            }
            let subject = Subject {
                client_id: &client_id,
                username: user,
                binding: Binding {
                    credentials,
                    ..Binding::default()
                },
            };
            if let Some(identity) = plugin.acl_identity(subject) {
                match plugin
                    .authorize(&identity, url, AclAccess::Read)
                    .await
                    .verdict
                {
                    Verdict::Allow => return true,
                    Verdict::Deny | Verdict::Error => return false,
                    Verdict::Defer => {}
                }
            }
        }
        security_callbacks(
            security.1,
            || {
                file.acl
                    .as_ref()
                    .map(|acl| acl.check(&client_id, user, url, Access::Read))
            },
            || {
                dynamic
                    .as_ref()
                    .and_then(|(_, policy)| policy.authorize(&client_id, user, url, Access::Read))
            },
        )
        .unwrap_or(security.1.is_none() && plugin.is_none())
    }

    pub(super) async fn receive_dynamic_control(
        &self,
        live: &Live,
        publication: Publication,
    ) -> Result<Reply, BrokerError> {
        let verdicts = self.resolve_write(&live.lease, &publication).await;
        let now = publication.now;
        let payload = publication.packet.payload;
        let payload_len = payload.len();
        let (origin, admission) = match &self.0.log {
            Log::Local { .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                let local = runtime.local.as_mut().unwrap();
                local.update_security(None);
                (
                    Owner::LOCAL,
                    local.state.check_dynamic_control(
                        Owner::LOCAL,
                        &live.lease,
                        payload_len,
                        now,
                        &verdicts,
                    ),
                )
            }
            Log::Replicated(log) => (
                log.owner,
                log.cluster.read(|machine| {
                    machine.state.check_dynamic_control(
                        log.owner,
                        &live.lease,
                        payload_len,
                        now,
                        &verdicts,
                    )
                }),
            ),
        };
        let allowed = match admission {
            Ok(()) => true,
            Err(reply @ (Reply::Stale | Reply::ExternalAclError)) => return Ok(reply),
            Err(_) => false,
        };
        // Never hash passwords from publications that fail the local WRITE ACL,
        // and never replicate the unprepared payload, including on rejection.
        let request = if allowed {
            let request = tokio::task::spawn_blocking(move || DynsecRequest::prepare(&payload))
                .await
                .map_err(io::Error::other)?
                .map_err(BrokerError::DynamicSecurityRequest)?;
            if request.needs_connections() {
                let connections = match &self.0.log {
                    Log::Local { .. } => {
                        let runtime = self.0.runtime.lock().unwrap();
                        runtime.dynamic_connections(&runtime.local.as_ref().unwrap().state)
                    }
                    Log::Replicated(log) => log.cluster.read(|machine| {
                        self.0
                            .runtime
                            .lock()
                            .unwrap()
                            .dynamic_connections(&machine.state)
                    }),
                };
                Some(request.with_connections(connections))
            } else {
                Some(request)
            }
        } else {
            None
        };
        let qos = publication.packet.qos;
        let reply = self
            .submit(Command::DynamicSecurityControl(DynamicControl {
                origin,
                lease: live.lease.clone(),
                endpoint_registered: true,
                request,
                payload_len,
                qos,
                now,
                verdicts,
            }))
            .await?;
        live.credit_control(qos, &reply);
        Ok(reply)
    }
}

impl Runtime {
    fn dynamic_connections(&self, state: &State) -> Vec<(String, String, Option<String>)> {
        let mut active: Vec<_> = self
            .live
            .values()
            .filter_map(|live| {
                state
                    .connection_username(&live.lease)
                    .map(|username| (live, username))
            })
            .collect();
        active.sort_unstable_by_key(|(live, _)| live.lease.epoch);
        active
            .into_iter()
            .map(|(live, username)| {
                (
                    username.to_owned(),
                    live.lease.id.to_string(),
                    live.peer_address.as_deref().map(str::to_owned),
                )
            })
            .collect()
    }

    pub(super) fn save_dynamic_security(&self, state: &State) {
        if let Some((path, (_, policy))) = self
            .dynamic_security_path
            .as_deref()
            .zip(state.dynamic_policy())
            && let Err(error) = save(path, policy)
        {
            // config.c: a save failure is logged, not a rollback of the command.
            tracing::error!(path = %path.display(), %error, "Could not save Dynamic Security configuration");
        }
    }
}

impl Reply {
    pub(super) fn dynamic_security_mutated(&self) -> bool {
        matches!(
            self,
            Self::DynamicSecurityInitialized | Self::ControlAccepted { changed: true }
        )
    }
}

fn register_file(path: &Path, state: &State) -> Result<(), BrokerError> {
    let (_, policy) = state
        .dynamic_policy()
        .ok_or(BrokerError::DynamicSecurityUninitialized)?;
    save(path, policy).map_err(|source| file_error(path, source))
}

fn file_error(path: &Path, source: io::Error) -> BrokerError {
    BrokerError::DynamicSecurityFile {
        path: path.to_owned(),
        source,
    }
}

fn save(path: &Path, policy: &DynamicSecurity) -> io::Result<()> {
    let contents = policy.to_json().map_err(io::Error::other)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&contents)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
