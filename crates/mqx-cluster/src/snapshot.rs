use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex, RwLock};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use bytes::Bytes;
use futures_util::{Stream, TryStreamExt};
use openraft::alias::{
    EntryOf, EntryPayloadOf, MembershipOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf,
};
use openraft::storage::{EntryResponder, RaftStateMachine};
use openraft::{BasicNode, EntryPayload, RaftSnapshotBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast, watch};

use crate::lease::{Leases, Stamp};
use crate::membership::{Desired, MemberRole, MemberStatus, MembershipStatus};
use crate::node::{Command, Leadership, LogId, Types};
use crate::snapshot_file::SnapshotData;
use crate::transport::{decode, encode, invalid_data};
use crate::{NodeEvent, StateMachine, version};

pub(crate) const SNAPSHOT_FILE: &str = "snapshot.mpk";
pub(crate) const RETIRED_FILE: &str = "removed";
const TEMP_FILE_PREFIX: &str = ".mqx-stage-";
const TEMP_FILE_RANDOM_LEN: usize = 6;

pub(crate) type Snapshot = SnapshotOf<Types, SnapshotData>;
pub(crate) type SnapshotMeta = SnapshotMetaOf<Types>;
type StoredMembership = StoredMembershipOf<Types>;

#[derive(Serialize, Deserialize)]
struct MembershipState<L = Leases, D = Desired, R = BTreeSet<u64>> {
    leases: L,
    desired: D,
    retired: R,
}

pub(crate) struct Applied<S> {
    pub(crate) app: S,
    pub(crate) leases: Leases,
    pub(crate) desired: Desired,
    retired: BTreeSet<u64>,
    last_applied: Option<LogId>,
    pub(crate) membership: StoredMembership,
    sealed: bool,
}

pub(crate) struct Store<S> {
    pub(crate) state: Arc<RwLock<Applied<S>>>,
    snapshot: Arc<Mutex<Option<Snapshot>>>,
    snapshot_size: Arc<AtomicU64>,
    snapshot_limit: u64,
    dir: Arc<Path>,
    disk_open: Arc<SyncMutex<bool>>,
    pub(crate) events: broadcast::Sender<NodeEvent>,
    pub(crate) status: watch::Sender<MembershipStatus>,
    pub(crate) format: u16,
}

impl<S> Clone for Store<S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            snapshot: self.snapshot.clone(),
            snapshot_size: self.snapshot_size.clone(),
            snapshot_limit: self.snapshot_limit,
            dir: self.dir.clone(),
            disk_open: self.disk_open.clone(),
            events: self.events.clone(),
            status: self.status.clone(),
            format: self.format,
        }
    }
}

impl<S: StateMachine> Store<S> {
    pub(crate) fn open(app: S, dir: PathBuf, format: u16) -> io::Result<Self> {
        let mut state = Applied {
            app,
            leases: Leases::new(std::iter::empty()),
            desired: Desired::default(),
            retired: BTreeSet::new(),
            last_applied: None,
            membership: StoredMembership::default(),
            sealed: false,
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
            let control = decode_membership::<S>(&snapshot.snapshot)?;
            if format == 1 && control.desired.generation != 0 {
                return Err(invalid_data(
                    "cannot downgrade dynamic membership to state format 1",
                ));
            }
            state.restore(
                &snapshot.meta,
                control,
                snapshot.snapshot.app_version,
                &snapshot.snapshot.application()?,
            )?;
        }
        let (events, _) = broadcast::channel(256);
        let (status, _) = watch::channel(state.membership_status()?);
        let snapshot_size = snapshot.as_ref().map_or(0, |s| s.snapshot.size());
        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            snapshot: Arc::new(Mutex::new(snapshot)),
            snapshot_size: Arc::new(AtomicU64::new(snapshot_size)),
            snapshot_limit: crate::DEFAULT_MAX_SNAPSHOT_SIZE,
            dir: dir.into(),
            disk_open: Arc::new(SyncMutex::new(true)),
            events,
            status,
            format,
        })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn validate_snapshot(&self, data: &SnapshotData) -> io::Result<()> {
        let control = decode_membership::<S>(data)?;
        if self.format == 1 && control.desired.generation != 0 {
            return Err(invalid_data("dynamic membership requires state format 2"));
        }
        Ok(())
    }

    pub(crate) fn expire(&self, stamp: Stamp, timeout_ms: u64) -> Vec<crate::lease::LeaseCommand> {
        self.state.read().unwrap().leases.expired(stamp, timeout_ms)
    }

    pub(crate) fn last_applied(&self) -> Option<LogId> {
        self.state.read().unwrap().last_applied
    }

    pub(crate) fn seal(&self) {
        self.state.write().unwrap().sealed = true;
    }

    pub(crate) fn replay_for_fork(&self, entries: Vec<EntryOf<Types>>) -> io::Result<()> {
        let mut state = self.state.write().unwrap();
        for entry in entries {
            let _ = state.apply_entry(&self.status, &self.events, self.format, entry, false)?;
        }
        Ok(())
    }

    pub(crate) fn fork_snapshot(
        &self,
        dir: &Path,
        node_id: u64,
        peers: BTreeMap<u64, SocketAddr>,
        term: u64,
    ) -> io::Result<()> {
        let (meta, leases, app) = {
            let state = &mut *self.state.write().unwrap();
            let index = state.last_applied.map_or(Ok(0), |id| {
                id.index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("Raft index overflow"))
            })?;
            let term = state
                .last_applied
                .map_or(term, |id| term.max(id.leader_id.term))
                .checked_add(1)
                .ok_or_else(|| invalid_data("Raft term overflow"))?;
            let log_id = LogId::new(Leadership { term, node_id }, index);
            let membership = MembershipOf::<Types>::from(BTreeMap::from([(
                node_id,
                BasicNode {
                    addr: peers[&node_id].to_string(),
                },
            )]));
            let meta = SnapshotMeta {
                last_log_id: Some(log_id),
                last_membership: StoredMembership::new(Some(log_id), membership),
            };
            // Startup seeds can predate a committed membership change. Never
            // replace its peer list while retaining the same generation.
            let fallback = Desired {
                generation: 0,
                peers,
            };
            let desired = if state.desired.peers.is_empty() {
                &fallback
            } else {
                &state.desired
            };
            for &id in desired.peers.keys() {
                state.leases.ensure(id);
            }
            // This is a new snapshot boundary, not a replicated removal.
            let leases = encode(&MembershipState {
                leases: &state.leases,
                desired,
                retired: &state.retired,
            })?;
            (meta, Bytes::from(leases), state.app.snapshot())
        };
        SnapshotData::build(
            dir,
            SNAPSHOT_FILE,
            &meta,
            leases,
            &app,
            (2, S::WRITE_VERSION),
        )?;
        Ok(())
    }

    pub(crate) async fn close(&self) -> io::Result<()> {
        let disk_open = self.disk_open.clone();
        tokio::task::spawn_blocking(move || *disk_open.lock().unwrap() = false)
            .await
            .map_err(io::Error::other)
    }
}

fn decode_membership<S: StateMachine>(snapshot: &SnapshotData) -> io::Result<MembershipState> {
    version::check_app::<S>("application snapshot", snapshot.app_version).map_err(invalid_data)?;
    if snapshot.format == 1 {
        Ok(MembershipState {
            leases: decode(&snapshot.leases)?,
            desired: Desired::default(),
            retired: BTreeSet::new(),
        })
    } else {
        decode(&snapshot.leases)
    }
}

impl<S: StateMachine> Applied<S> {
    fn membership_status(&self) -> io::Result<MembershipStatus> {
        let membership = self.membership.membership();
        let voters: BTreeSet<_> = membership.voter_ids().collect();
        let members = membership
            .nodes()
            .map(|(&id, node)| {
                Ok((
                    id,
                    MemberStatus {
                        address: node.addr.parse().map_err(invalid_data)?,
                        role: if voters.contains(&id) {
                            MemberRole::Voter
                        } else {
                            MemberRole::Learner
                        },
                        liveness: self.leases.status(id),
                    },
                ))
            })
            .collect::<io::Result<_>>()?;
        Ok(MembershipStatus {
            generation: self.desired.generation,
            desired: self.desired.peers.clone(),
            joint: membership.get_joint_config().len() > 1,
            members,
            retired: self.retired.clone(),
            ..Default::default()
        })
    }

    fn publish_membership(&self, status: &watch::Sender<MembershipStatus>) -> io::Result<()> {
        let next = self.membership_status()?;
        status.send_modify(|state| {
            let error = state.reconciliation_error.take();
            *state = next;
            state.reconciliation_error = error;
        });
        Ok(())
    }

    fn restore(
        &mut self,
        meta: &SnapshotMeta,
        control: MembershipState,
        version: u16,
        app: &[u8],
    ) -> io::Result<()> {
        self.app
            .restore_versioned(version, app)
            .map_err(invalid_data)?;
        self.leases = control.leases;
        self.desired = control.desired;
        self.retired = control.retired;
        self.last_applied = meta.last_log_id;
        self.membership = meta.last_membership.clone();
        Ok(())
    }

    fn apply_entry(
        &mut self,
        status: &watch::Sender<MembershipStatus>,
        events: &broadcast::Sender<NodeEvent>,
        format: u16,
        entry: EntryOf<Types>,
        respond: bool,
    ) -> io::Result<Result<Option<Bytes>, String>> {
        let log_id = entry.log_id;
        let reply = match entry.payload {
            EntryPayloadOf::<Types>::Blank => Ok(None),
            EntryPayload::Membership(membership) => {
                let previous = std::mem::take(&mut self.membership);
                let retired_count = self.retired.len();
                self.retired.extend(
                    previous
                        .nodes()
                        .filter_map(|(&id, _)| membership.get_node(&id).is_none().then_some(id)),
                );
                if self.retired.len() != retired_count {
                    self.app.on_members_removed(log_id.index, &self.retired);
                }
                for (&id, _) in membership.nodes() {
                    self.leases.ensure(id);
                }
                self.membership = StoredMembership::new(Some(log_id), membership);
                self.publish_membership(status)?;
                Ok(None)
            }
            EntryPayload::Normal(Command::App(body)) => {
                let command = version::command::<S>(&body).map_err(invalid_data)?;
                let response = self
                    .app
                    .apply_with_retired(log_id.index, command, &self.retired);
                if respond {
                    encode(&response)
                        .map(|bytes| Some(bytes.into()))
                        .map_err(|error| error.to_string())
                } else {
                    Ok(None)
                }
            }
            EntryPayload::Normal(Command::Lease(command)) => {
                if let Some(event) = self.leases.apply(log_id, command) {
                    status.send_if_modified(|status| {
                        if let Some(member) = status.members.get_mut(&event.node_id) {
                            member.liveness = event.status;
                            true
                        } else {
                            false
                        }
                    });
                    self.app.on_node_event(event);
                    let _ = events.send(event);
                }
                Ok(None)
            }
            EntryPayload::Normal(Command::Desired(desired)) => {
                if format == 1 {
                    return Err(invalid_data("dynamic membership requires state format 2"));
                }
                if desired.generation > self.desired.generation {
                    self.desired = desired;
                    self.publish_membership(status)?;
                }
                Ok(None)
            }
        };
        self.last_applied = Some(log_id);
        Ok(reply)
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
            if state.sealed {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let reply = state.apply_entry(
                &self.status,
                &self.events,
                self.format,
                entry,
                responder.is_some(),
            )?;
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
        let mut current = self.snapshot.clone().lock_owned().await;
        let meta = meta.clone();
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let app = data.application()?;
            {
                let mut state = store.state.write().unwrap();
                if state.sealed {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                let control = decode_membership::<S>(&data)?;
                state.restore(&meta, control, data.app_version, &app)?;
            }
            drop(app);
            let _disk = store.lock_disk()?;
            let snapshot = data.publish(&store.dir, SNAPSHOT_FILE)?;
            store
                .state
                .read()
                .unwrap()
                .publish_membership(&store.status)?;
            let size = snapshot.size();
            *current = Some(Snapshot { meta, snapshot });
            store.record_snapshot_size(size);
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
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
        // A spawned blocking job can outlive its caller. Keep the publication
        // lock through both the rename and the matching cache update.
        let mut current = self.snapshot.clone().lock_owned().await;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let (meta, leases, app) = {
                let state = store.state.read().unwrap();
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
                    Bytes::from(if store.format == 1 {
                        encode(&state.leases)?
                    } else {
                        encode(&MembershipState {
                            leases: &state.leases,
                            desired: &state.desired,
                            retired: &state.retired,
                        })?
                    }),
                    state.app.snapshot(),
                )
            };
            // Release the state read lock before writing or syncing the file.
            let _disk = store.lock_disk()?;
            let snapshot = SnapshotData::build(
                &store.dir,
                SNAPSHOT_FILE,
                &meta,
                leases,
                &app,
                (store.format, S::WRITE_VERSION),
            )?;
            let snapshot = Snapshot { meta, snapshot };
            *current = Some(snapshot.clone());
            store.record_snapshot_size(snapshot.snapshot.size());
            Ok(snapshot)
        })
        .await
        .map_err(io::Error::other)?
    }
}

impl<S> Store<S> {
    pub(crate) fn with_snapshot_limit(mut self, limit: u64) -> Self {
        self.snapshot_limit = limit;
        self
    }

    pub(crate) fn snapshot_size(&self) -> u64 {
        self.snapshot_size.load(Ordering::Relaxed)
    }

    fn record_snapshot_size(&self, size: u64) {
        self.snapshot_size.store(size, Ordering::Relaxed);
        if size > self.snapshot_limit {
            tracing::warn!(
                snapshot_size_bytes = size,
                limit_bytes = self.snapshot_limit,
                "new Raft snapshot exceeds the configured transfer limit"
            );
        }
    }

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
    builder
        .prefix(TEMP_FILE_PREFIX)
        .rand_bytes(TEMP_FILE_RANDOM_LEN);
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o600));
    builder.tempfile_in(dir)
}

pub(crate) fn is_staged_tempfile(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    // Older builds used tempfile's default six random characters and .mqx-.
    name.strip_prefix(TEMP_FILE_PREFIX.as_bytes())
        .or_else(|| name.strip_prefix(b".mqx-"))
        .is_some_and(|suffix| {
            suffix.len() == TEMP_FILE_RANDOM_LEN && suffix.iter().all(u8::is_ascii_alphanumeric)
        })
}

pub(crate) fn remove_staged_tempfiles(dir: &Path) -> io::Result<()> {
    let mut removed = false;
    for entry in dir.read_dir()? {
        let entry = entry?;
        if is_staged_tempfile(&entry.file_name()) && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
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
        // A path error says nothing about the Raft contents. Do not archive a WAL symlink.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn staging_cleanup_removes_only_exact_regular_tempfiles() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let (_, staged) = private_tempfile(dir).unwrap().keep().unwrap();
        let legacy = dir.join(".mqx-Ab12Xy");
        fs::write(&legacy, b"partial snapshot").unwrap();

        let unrelated = [
            ".mqx-Ab12X",
            ".mqx-Ab12XyZ",
            ".mqx-Ab12-y",
            ".mqx-stage-Ab12Xy~",
            crate::survivor::LOCK_FILE,
            crate::survivor::IDENTITY_FILE,
            crate::survivor::RECORD_FILE,
            SNAPSHOT_FILE,
            RETIRED_FILE,
        ];
        for name in unrelated {
            fs::write(dir.join(name), name.as_bytes()).unwrap();
        }
        let subdirs = [".mqx-D1rABC", "wal", crate::survivor::DISCARDED];
        for name in subdirs {
            let nested = dir.join(name);
            fs::create_dir(&nested).unwrap();
            fs::write(nested.join(".mqx-A1b2C3"), b"nested state").unwrap();
        }
        #[cfg(unix)]
        let symlink = {
            let link = dir.join(".mqx-stage-SymlnK");
            std::os::unix::fs::symlink(dir.join(SNAPSHOT_FILE), &link).unwrap();
            link
        };

        remove_staged_tempfiles(dir).unwrap();
        assert!(!staged.exists());
        assert!(!legacy.exists());
        for name in unrelated {
            assert_eq!(fs::read(dir.join(name)).unwrap(), name.as_bytes());
        }
        for name in subdirs {
            assert_eq!(
                fs::read(dir.join(name).join(".mqx-A1b2C3")).unwrap(),
                b"nested state"
            );
        }
        #[cfg(unix)]
        assert!(symlink.is_symlink());
    }

    struct PausedEncoder {
        entered: Arc<tokio::sync::Notify>,
        release: SyncMutex<mpsc::Receiver<()>>,
    }

    impl StateMachine for PausedEncoder {
        type Command = ();
        type Response = ();
        fn apply(&mut self, _: u64, _: ()) {}
        fn snapshot(&self) -> Vec<u8> {
            self.entered.notify_one();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            vec![42]
        }
        fn restore(&mut self, _: &[u8]) -> Result<(), crate::ClusterError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_snapshot_builder_publishes_matching_disk_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (release, wait) = mpsc::channel();
        let entered = Arc::new(tokio::sync::Notify::new());
        let mut store = Store::open(
            PausedEncoder {
                entered: entered.clone(),
                release: SyncMutex::new(wait),
            },
            dir.path().into(),
            2,
        )
        .unwrap();
        assert_eq!(store.snapshot_size(), 0);
        let mut builder = store.clone();
        let job = tokio::spawn(async move { builder.build_snapshot().await });
        // This task must still run on a single worker while encoding is paused.
        entered.notified().await;
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        let cached = store.get_current_snapshot().await.unwrap().unwrap();
        let (meta, disk) =
            SnapshotData::open(File::open(dir.path().join(SNAPSHOT_FILE)).unwrap()).unwrap();
        assert_eq!(cached.meta, meta);
        assert_eq!(store.snapshot_size(), disk.size());
        assert_eq!(cached.snapshot.application().unwrap(), [42]);
        assert_eq!(disk.application().unwrap(), [42]);
    }
}
