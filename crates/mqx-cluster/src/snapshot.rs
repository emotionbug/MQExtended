use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as SyncMutex, RwLock};

use bytes::Bytes;
use futures_util::{Stream, TryStreamExt};
use openraft::alias::{EntryPayloadOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf};
use openraft::storage::{EntryResponder, RaftStateMachine};
use openraft::{EntryPayload, RaftSnapshotBuilder};
use tokio::sync::{Mutex, broadcast};

use crate::lease::{Leases, Stamp};
use crate::node::{Command, LogId, Types};
use crate::transport::{decode, encode, invalid_data};
use crate::{NodeEvent, StateMachine};

const SNAPSHOT_FILE: &str = "snapshot.mpk";
const SNAPSHOT_MAGIC: &[u8; 8] = b"MQXSNAP1";

pub(crate) type Snapshot = SnapshotOf<Types, SnapshotData>;
pub(crate) type SnapshotMeta = SnapshotMetaOf<Types>;
type StoredMembership = StoredMembershipOf<Types>;

#[derive(Clone, Debug)]
pub(crate) struct SnapshotData {
    pub(crate) leases: Bytes,
    pub(crate) app: Bytes,
}

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
        let snapshot = match File::open(dir.join(SNAPSHOT_FILE)) {
            Ok(file) => Some(read_snapshot(file)?),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        if let Some(snapshot) = &snapshot {
            state.restore(&snapshot.meta, &snapshot.snapshot)?;
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
    fn restore(&mut self, meta: &SnapshotMeta, snapshot: &SnapshotData) -> io::Result<()> {
        let leases: Leases = decode(&snapshot.leases)?;
        if !leases.ids().eq(self.leases.ids()) {
            return Err(invalid_data("snapshot belongs to a different membership"));
        }
        self.app.restore(&snapshot.app).map_err(invalid_data)?;
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
            let reply = match entry.payload {
                EntryPayloadOf::<Types>::Blank => None,
                EntryPayload::Membership(membership) => {
                    state.membership = StoredMembership::new(Some(log_id), membership);
                    None
                }
                EntryPayload::Normal(Command::App(body)) => {
                    let response = state.app.apply(log_id.index, decode(&body)?);
                    responder
                        .is_some()
                        .then(|| encode(&response).map(Bytes::from))
                }
                EntryPayload::Normal(Command::Lease(command)) => {
                    if let Some(event) = state.leases.apply(log_id, command) {
                        state.app.on_node_event(event);
                        let _ = self.events.send(event);
                    }
                    None
                }
            };
            state.last_applied = Some(log_id);
            if let Some(responder) = responder {
                // A response serialization error must not stop Raft after the
                // application command has already taken effect.
                responder.send(reply.transpose().map_err(|error| error.to_string()));
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
        {
            let mut state = self.state.write().unwrap();
            state.restore(meta, &data)?;
        }
        let snapshot = Snapshot {
            meta: meta.clone(),
            snapshot: data,
        };
        save_snapshot(self.dir.clone(), self.disk_open.clone(), snapshot.clone()).await?;
        *current = Some(snapshot);
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
        let snapshot = {
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
            Snapshot {
                meta,
                snapshot: SnapshotData {
                    leases: encode(&state.leases)?.into(),
                    app: state.app.snapshot().into(),
                },
            }
        };
        save_snapshot(self.dir.clone(), self.disk_open.clone(), snapshot.clone()).await?;
        *current = Some(snapshot.clone());
        Ok(snapshot)
    }
}

async fn save_snapshot(
    dir: Arc<Path>,
    disk_open: Arc<SyncMutex<bool>>,
    snapshot: Snapshot,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        // Snapshot builds may outlive RaftCore. Do not allow an old builder to
        // replace a file after shutdown has released the WAL directory lock.
        let open = disk_open.lock().unwrap();
        if !*open {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let meta = encode(&snapshot.meta)?;
        atomic_write(&dir, SNAPSHOT_FILE, |file| {
            file.write_all(SNAPSHOT_MAGIC)?;
            for body in [
                meta.as_slice(),
                &snapshot.snapshot.leases,
                &snapshot.snapshot.app,
            ] {
                file.write_all(&(body.len() as u64).to_be_bytes())?;
                file.write_all(body)?;
            }
            Ok(())
        })
    })
    .await
    .map_err(io::Error::other)?
}

fn read_snapshot(file: File) -> io::Result<Snapshot> {
    let mut reader = BufReader::new(file);
    let mut magic = [0; SNAPSHOT_MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if &magic != SNAPSHOT_MAGIC {
        return Err(invalid_data("unknown snapshot format"));
    }
    let meta = decode(&read_body(&mut reader)?)?;
    let leases = read_body(&mut reader)?;
    let app = read_body(&mut reader)?;
    if reader.read(&mut [0])? != 0 {
        return Err(invalid_data("trailing data in snapshot"));
    }
    Ok(Snapshot {
        meta,
        snapshot: SnapshotData { leases, app },
    })
}

fn read_body(reader: &mut impl Read) -> io::Result<Bytes> {
    let mut len = [0; 8];
    reader.read_exact(&mut len)?;
    let len = u64::from_be_bytes(len);
    let mut body = Vec::new();
    if reader.take(len).read_to_end(&mut body)? as u64 != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(body.into())
}

pub(crate) fn atomic_write(
    dir: &Path,
    name: &str,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let mut temp = tempfile::Builder::new().prefix(".mqx-").tempfile_in(dir)?;
    write(temp.as_file_mut())?;
    temp.as_file().sync_all()?;
    temp.persist(dir.join(name))?;
    File::open(dir)?.sync_all()
}

pub(crate) fn create_durable_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() || dir.as_os_str().is_empty() {
        return Ok(());
    }
    let parent = dir.parent().ok_or(io::ErrorKind::NotFound)?;
    create_durable_dir(parent)?;
    match fs::create_dir(dir) {
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
