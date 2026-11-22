use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as SyncMutex, RwLock};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use bytes::Bytes;
use futures_util::{Stream, TryStreamExt};
use openraft::alias::{EntryPayloadOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf};
use openraft::storage::{EntryResponder, RaftStateMachine};
use openraft::{EntryPayload, RaftSnapshotBuilder};
use tokio::sync::{Mutex, broadcast};

use crate::lease::{Leases, Stamp};
use crate::node::{Command, LogId, Types};
use crate::snapshot_file::SnapshotData;
use crate::transport::{decode, encode, invalid_data};
use crate::{NodeEvent, StateMachine};

const SNAPSHOT_FILE: &str = "snapshot.mpk";

pub(crate) type Snapshot = SnapshotOf<Types, SnapshotData>;
pub(crate) type SnapshotMeta = SnapshotMetaOf<Types>;
type StoredMembership = StoredMembershipOf<Types>;

pub(crate) struct Applied<S> {
    pub(crate) app: S,
    pub(crate) leases: Leases,
    last_applied: Option<LogId>,
    membership: StoredMembership,
}

pub(crate) struct Store<S> {
    pub(crate) state: Arc<RwLock<Applied<S>>>,
    snapshot: Arc<Mutex<Option<Snapshot>>>,
    dir: Arc<Path>,
    disk_open: Arc<SyncMutex<bool>>,
    pub(crate) events: broadcast::Sender<NodeEvent>,
}

impl<S> Clone for Store<S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            snapshot: self.snapshot.clone(),
            dir: self.dir.clone(),
            disk_open: self.disk_open.clone(),
            events: self.events.clone(),
        }
    }
}

impl<S: StateMachine> Store<S> {
    pub(crate) fn open(app: S, dir: PathBuf, leases: Leases) -> io::Result<Self> {
        let mut state = Applied {
            app,
            leases,
            last_applied: None,
            membership: StoredMembership::default(),
        };
        let snapshot = match open_private_file(&dir.join(SNAPSHOT_FILE)) {
            Ok(file) => {
                let (meta, snapshot) = SnapshotData::open(file)?;
                Some(Snapshot { meta, snapshot })
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        if let Some(snapshot) = &snapshot {
            let leases = state.decode_leases(&snapshot.snapshot)?;
            state.restore(&snapshot.meta, leases, &snapshot.snapshot.application()?)?;
        }
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            snapshot: Arc::new(Mutex::new(snapshot)),
            dir: dir.into(),
            disk_open: Arc::new(SyncMutex::new(true)),
            events,
        })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn validate_snapshot(&self, data: &SnapshotData) -> io::Result<()> {
        self.state.read().unwrap().decode_leases(data).map(drop)
    }

    pub(crate) fn expire(&self, stamp: Stamp, timeout_ms: u64) -> Vec<crate::lease::LeaseCommand> {
        self.state.read().unwrap().leases.expired(stamp, timeout_ms)
    }

    pub(crate) async fn close(&self) -> io::Result<()> {
        let disk_open = self.disk_open.clone();
        tokio::task::spawn_blocking(move || *disk_open.lock().unwrap() = false)
            .await
            .map_err(io::Error::other)
    }
}

impl<S: StateMachine> Applied<S> {
    fn decode_leases(&self, snapshot: &SnapshotData) -> io::Result<Leases> {
        let leases: Leases = decode(&snapshot.leases)?;
        if !leases.ids().eq(self.leases.ids()) {
            return Err(invalid_data("snapshot belongs to a different membership"));
        }
        Ok(leases)
    }

    fn restore(&mut self, meta: &SnapshotMeta, leases: Leases, app: &[u8]) -> io::Result<()> {
        self.app.restore(app).map_err(invalid_data)?;
        self.leases = leases;
        self.last_applied = meta.last_log_id;
        self.membership = meta.last_membership.clone();
        Ok(())
    }
}

impl<S: StateMachine> RaftStateMachine<Types> for Store<S> {
    type SnapshotData = SnapshotData;
    type SnapshotBuilder = Self;

    async fn applied_state(&mut self) -> io::Result<(Option<LogId>, StoredMembership)> {
        let state = self.state.read().unwrap();
        Ok((state.last_applied, state.membership.clone()))
    }

    async fn apply<St>(&mut self, mut entries: St) -> io::Result<()>
    where
        St: Stream<Item = io::Result<EntryResponder<Types>>> + Unpin + Send,
    {
        while let Some((entry, responder)) = entries.try_next().await? {
            let mut state = self.state.write().unwrap();
            let log_id = entry.log_id;
            let reply: Result<Option<Bytes>, String> = match entry.payload {
                EntryPayloadOf::<Types>::Blank => Ok(None),
                EntryPayload::Membership(membership) => {
                    state.membership = StoredMembership::new(Some(log_id), membership);
                    Ok(None)
                }
                EntryPayload::Normal(Command::App(body)) => match decode(&body) {
                    Ok(command) => {
                        let response = state.app.apply(log_id.index, command);
                        if responder.is_some() {
                            encode(&response)
                                .map(|bytes| Some(bytes.into()))
                                .map_err(|error| error.to_string())
                        } else {
                            Ok(None)
                        }
                    }
                    Err(_) => {
                        tracing::error!(
                            index = log_id.index,
                            "skipping undecodable committed application command"
                        );
                        Err("undecodable committed application command".into())
                    }
                },
                EntryPayload::Normal(Command::Lease(command)) => {
                    if let Some(event) = state.leases.apply(log_id, command) {
                        state.app.on_node_event(event);
                        let _ = self.events.send(event);
                    }
                    Ok(None)
                }
            };
            state.last_applied = Some(log_id);
            if let Some(responder) = responder {
                // A response serialization error must not stop Raft after the
                // application command has already taken effect.
                responder.send(reply);
            }
        }
        Ok(())
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta,
        data: SnapshotData,
    ) -> io::Result<()> {
        let mut current = self.snapshot.lock().await;
        let meta = meta.clone();
        let store = self.clone();
        *current = Some(
            tokio::task::spawn_blocking(move || {
                let app = data.application()?;
                {
                    let mut state = store.state.write().unwrap();
                    let leases = state.decode_leases(&data)?;
                    state.restore(&meta, leases, &app)?;
                }
                drop(app);
                let _disk = store.lock_disk()?;
                let snapshot = data.publish(&store.dir, SNAPSHOT_FILE)?;
                Ok::<_, io::Error>(Snapshot { meta, snapshot })
            })
            .await
            .map_err(io::Error::other)??,
        );
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> io::Result<Option<Snapshot>> {
        Ok(self.snapshot.lock().await.clone())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }
}

impl<S: StateMachine> RaftSnapshotBuilder<Types> for Store<S> {
    type SnapshotData = SnapshotData;

    async fn build_snapshot(&mut self) -> io::Result<Snapshot> {
        let mut current = self.snapshot.lock().await;
        let (meta, leases, app) = {
            let state = self.state.read().unwrap();
            let meta = SnapshotMeta {
                last_log_id: state.last_applied,
                last_membership: state.membership.clone(),
            };
            if let Some(current) = current
                .as_ref()
                .filter(|current| current.meta.last_log_id == meta.last_log_id)
            {
                return Ok(current.clone());
            }
            (
                meta,
                Bytes::from(encode(&state.leases)?),
                state.app.snapshot(),
            )
        };
        let store = self.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            let _disk = store.lock_disk()?;
            let snapshot = SnapshotData::build(&store.dir, SNAPSHOT_FILE, &meta, leases, &app)?;
            Ok::<_, io::Error>(Snapshot { meta, snapshot })
        })
        .await
        .map_err(io::Error::other)??;
        *current = Some(snapshot.clone());
        Ok(snapshot)
    }
}

impl<S> Store<S> {
    fn lock_disk(&self) -> io::Result<std::sync::MutexGuard<'_, bool>> {
        // OpenRaft snapshot jobs can outlive RaftCore. Shutdown fences the disk
        // before releasing the WAL directory lock to a successor process.
        let open = self.disk_open.lock().unwrap();
        if !*open {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(open)
    }
}

pub(crate) fn private_tempfile(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".mqx-");
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o600));
    builder.tempfile_in(dir)
}

pub(crate) fn open_private_file(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(invalid_data("cluster state path is not a regular file"));
    }
    let file = File::open(path)?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

pub(crate) fn atomic_write(
    dir: &Path,
    name: &str,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let mut temp = private_tempfile(dir)?;
    write(temp.as_file_mut())?;
    temp.as_file().sync_all()?;
    temp.persist(dir.join(name))?;
    File::open(dir)?.sync_all()
}

pub(crate) fn prepare_dir(dir: &Path, wal: bool) -> io::Result<()> {
    create_durable_dir(dir)?;
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.is_dir() {
        return Err(invalid_data(
            "cluster data and WAL paths must be real directories",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        if wal {
            tracing::warn!(path = %dir.display(), "restricting existing cluster WAL directory to mode 0700");
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            File::open(dir)?.sync_all()?;
        } else {
            tracing::warn!(path = %dir.display(), "INSECURE cluster data directory is group/world accessible; restrict it to mode 0700");
        }
    }
    #[cfg(not(unix))]
    let _ = wal;
    Ok(())
}

fn create_durable_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() || dir.as_os_str().is_empty() {
        return Ok(());
    }
    let parent = dir.parent().ok_or(io::ErrorKind::NotFound)?;
    create_durable_dir(parent)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    match builder.create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(error) => return Err(error),
    }
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    File::open(parent)?.sync_all()
}
