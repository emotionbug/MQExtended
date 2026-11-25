use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt, unfold};
use openraft::alias::{EntryPayloadOf, LeaderIdOf, LogIdOf, MembershipOf, VoteOf};
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ClientWriteError, InitializeError, LinearizableReadError, RaftError};
use openraft::raft::{
    AppendEntriesRequest, Precondition, StreamAppendResult, TransferLeaderRequest, VoteRequest,
    WriteOption,
};
use openraft::storage::{RaftLogReader, RaftLogStorage};
use openraft::{BasicNode, ChangeMembers, Raft, ReadPolicy, ServerState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, broadcast, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, timeout, timeout_at};

use crate::admission::Admission;
use crate::lease::{LeaseCommand, Stamp};
use crate::membership::{Desired, MemberRole, MembershipControl, Serving, validate_change};
use crate::mtls::Tls;
use crate::mux::{CallError, Response, write_responses};
use crate::snapshot::{
    RETIRED_FILE, SNAPSHOT_FILE, Snapshot, SnapshotMeta, Store, TEMP_FILE_PREFIX, atomic_write,
    open_private_file, prepare_dir,
};
use crate::snapshot_file::SnapshotData;
use crate::survivor::{
    self, IDENTITY_FILE, IDENTITY_VERSION, Incarnation, JOINED, Probe, ProbeRequest, Record,
    SurvivorEvent, SurvivorReason, Switch,
};
use crate::transport::{
    APPEND_WINDOW, CLUSTER_ID_FILE, Connection, Endpoint, Frame, Limits, MAX_APPEND_ENTRIES,
    Network, Op, SESSION_HEADER_LEN, decode, decode_session_header, encode, invalid_data,
    write_control,
};
use crate::wal::{Wal, WalMetrics};
use crate::{ClusterConfig, ClusterError, Mesh, NodeEvent, NodeStatus, StateMachine, version};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_WINDOW: usize = 256;
const HEALTHY_RECOVERY_SWEEP: Duration = Duration::from_secs(30);
pub(crate) type Leadership = LeaderIdOf<Types>;
pub(crate) type LogId = LogIdOf<Types>;
type WriteResponse = Result<Option<Bytes>, String>;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum Command {
    App(Bytes),
    Lease(LeaseCommand),
    Desired(Desired),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::App(body) => write!(f, "application command ({} bytes)", body.len()),
            Self::Lease(_) => f.write_str("node lease command"),
            Self::Desired(desired) => {
                write!(f, "desired membership generation {}", desired.generation)
            }
        }
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

openraft::declare_raft_types!(pub(crate) Types: D = Command, R = WriteResponse);

/// Local Raft progress. Log indexes are inclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterMetrics {
    pub node_id: u64,
    pub current_term: u64,
    pub leader: Option<u64>,
    pub last_log_index: Option<u64>,
    pub committed_index: Option<u64>,
    pub applied_index: Option<u64>,
    pub snapshot_index: Option<u64>,
    pub purged_index: Option<u64>,
    pub running: bool,
    pub auto_recover: bool,
    pub incarnation: u64,
    pub last_survivor_event: Option<SurvivorEvent>,
}

/// A Raft member. Clones share the same local node, transport and state machine.
pub struct Cluster<S: StateMachine>(Arc<Node<S>>);

impl<S: StateMachine> Clone for Cluster<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

struct Node<S: StateMachine> {
    core: Arc<Core<S>>,
    wal: Wal,
    driver: Mutex<Option<JoinHandle<Result<(), ClusterError>>>>,
}

impl<S: StateMachine> Drop for Node<S> {
    fn drop(&mut self) {
        self.core.mesh.stop.send_replace(true);
    }
}

struct Core<S: StateMachine> {
    raft: Raft<Types, Store<S>>,
    store: Store<S>,
    mesh: Mesh,
    requested: watch::Sender<Option<Desired>>,
    serving: watch::Sender<Serving>,
    safe_until: watch::Sender<Option<Instant>>,
    restart: Option<watch::Sender<bool>>,
    repair: AtomicBool,
    replication_source: AtomicU64,
    #[cfg(test)]
    filter_lease_renewals: std::sync::atomic::AtomicBool,
    heartbeat_interval: Duration,
    request_timeout: Duration,
    snapshot_timeout: Duration,
    lease_interval: Duration,
    lease_timeout: Duration,
    clock_origin: Instant,
    bootstrap_identity: Option<Incarnation>,
}

enum IncarnationChange {
    Fork {
        unreachable: Duration,
        parent: Incarnation,
    },
    Rejoin {
        peer: u64,
        identity: Incarnation,
    },
}

impl<S: StateMachine> Cluster<S> {
    /// Start listening and recover the latest durable state. This does not wait for a leader.
    /// An empty node initializes only in bootstrap mode; a joiner waits for replication.
    pub async fn start(config: ClusterConfig, state_machine: S) -> Result<Self, ClusterError> {
        let raft_config = Arc::new(config.raft_config()?);
        version::check_app::<S>("application write", S::WRITE_VERSION)?;
        if config.state_format == 1 && S::WRITE_VERSION != 1 {
            return Err(ClusterError::InvalidConfig(
                "legacy state format requires application write version 1".into(),
            ));
        }
        let listener = TcpListener::bind(config.raft_addr).await?;
        let ClusterConfig {
            node_id,
            data_dir,
            security,
            peers,
            join,
            membership_generation,
            state_format,
            wal_direct_io,
            auto_recover,
            auto_recover_timeout,
            heartbeat_interval,
            request_timeout,
            snapshot_timeout,
            max_snapshot_size,
            max_command_size,
            max_append_size,
            max_mesh_size,
            lease_interval,
            lease_timeout,
            ..
        } = config;
        let recovery_timeout = auto_recover.then(|| auto_recover_timeout.unwrap_or(lease_timeout));
        let bootstrap_identity = if auto_recover {
            Some(Incarnation::original(
                Sha256::digest(encode(&peers)?).into(),
            ))
        } else {
            None
        };
        let requested = (membership_generation != 0).then(|| Desired {
            generation: membership_generation,
            peers: peers.clone(),
        });
        let (endpoint, wal, store, initial, existing, lock) =
            tokio::task::spawn_blocking(move || {
                let tls = Tls::load(&security, node_id)?;
                let limits = Limits {
                    command: max_command_size,
                    append: max_append_size,
                    mesh: max_mesh_size,
                };
                prepare_dir(&data_dir, false)?;
                let lock = survivor::lock(&data_dir, auto_recover)?;
                if lock.is_some() {
                    Switch::recover(&data_dir, auto_recover.then_some(node_id))?;
                }
                match open_private_file(&data_dir.join(RETIRED_FILE)) {
                    Ok(_) => return Err(ClusterError::Removed(node_id)),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let new_join = join && !data_dir.join(IDENTITY_FILE).exists();
                if new_join {
                    for entry in data_dir.read_dir()? {
                        let entry = entry?;
                        let name = entry.file_name();
                        let kind = entry.file_type()?;
                        // A crash before the node identity's rename can leave its
                        // temporary file and a WAL without any Raft state.
                        if (name == "wal" && kind.is_dir())
                            || (name
                                .as_encoded_bytes()
                                .starts_with(TEMP_FILE_PREFIX.as_bytes())
                                && kind.is_file())
                            || (lock.is_some() && name == survivor::DISCARDED && kind.is_dir())
                        {
                            continue;
                        }
                        return Err(ClusterError::InvalidConfig(
                            "a new joining node needs an empty data directory".into(),
                        ));
                    }
                }
                let recover = |error| unusable_state(&data_dir, node_id, auto_recover, error);
                let wal = Wal::open_with_direct(
                    &data_dir.join("wal"),
                    max_append_size,
                    state_format,
                    wal_direct_io,
                )
                .map_err(|error| recover(error.into()))?;
                let loaded = (|| {
                    let (initial, digest, existing, record) = load_identity(
                        &data_dir,
                        node_id,
                        &peers,
                        join,
                        membership_generation,
                        &wal,
                        auto_recover,
                    )?;
                    if record.is_some() && state_format != 2 {
                        return Err(ClusterError::InvalidConfig(
                            "a recovery incarnation requires 'cluster_state_format 2'".into(),
                        ));
                    }
                    Ok((
                        initial,
                        digest,
                        existing,
                        record,
                        Store::open(state_machine, data_dir.clone(), state_format)?,
                    ))
                })();
                let (initial, digest, existing, record, store) = match loaded {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        drop(wal);
                        return Err(recover(error));
                    }
                };
                if store.status.borrow().retired.contains(&node_id) {
                    return Err(ClusterError::Removed(node_id));
                }
                let mut endpoint = Endpoint::new(
                    node_id,
                    peers,
                    (data_dir, digest),
                    store.status.subscribe(),
                    tls,
                    max_snapshot_size,
                    (limits, request_timeout),
                );
                endpoint.set_recovery(recovery_timeout, record);
                let wal = wal.with_term_floor(
                    endpoint
                        .record()
                        .filter(|record| record.event.reason == SurvivorReason::PeerUnreachable)
                        .and_then(|_| store.last_applied().map(|id| id.leader_id.term)),
                );
                Ok((Arc::new(endpoint), wal, store, initial, existing, lock))
            })
            .await
            .map_err(io::Error::other)??;
        let mut wal = wal;
        let raft = match Raft::build(
            node_id,
            raft_config,
            Network {
                endpoint: endpoint.clone(),
                append_timeout: request_timeout,
            },
            wal.clone(),
            store.clone(),
        )
        .await
        {
            Ok(raft) => raft,
            Err(error) => {
                if auto_recover {
                    let _ = store.close().await;
                    let _ = wal.close().await;
                    let dir = store.dir().to_path_buf();
                    return Err(tokio::task::spawn_blocking(move || {
                        unusable_state(
                            &dir,
                            node_id,
                            auto_recover,
                            ClusterError::Raft(error.to_string()),
                        )
                    })
                    .await
                    .map_err(io::Error::other)?);
                }
                return Err(ClusterError::Raft(error.to_string()));
            }
        };
        if store.status.borrow().retired.contains(&node_id) {
            return Err(ClusterError::Removed(node_id));
        }
        let repair = if let Some(record) = endpoint.record() {
            record.event.reason != SurvivorReason::PeerUnreachable
                && !survivor::join_complete(store.dir(), store.last_applied().map(|id| id.index))?
        } else {
            false
        };
        let core = Arc::new(Core {
            raft,
            store,
            mesh: Mesh::new(endpoint, request_timeout),
            requested: watch::channel(requested).0,
            serving: watch::channel(Serving::Waiting).0,
            safe_until: watch::channel(None).0,
            restart: auto_recover.then(|| watch::channel(false).0),
            repair: AtomicBool::new(repair),
            replication_source: AtomicU64::new(0),
            #[cfg(test)]
            filter_lease_renewals: std::sync::atomic::AtomicBool::new(false),
            heartbeat_interval,
            request_timeout,
            snapshot_timeout,
            lease_interval,
            lease_timeout,
            clock_origin: Instant::now(),
            bootstrap_identity,
        });
        if repair {
            core.raft.runtime_config().elect(false);
        }
        if auto_recover {
            let wait = recovery_timeout.expect("automatic recovery timeout");
            let replies = core
                .probe_incarnations(wait.min(request_timeout).min(Duration::from_millis(250)))
                .await;
            let mut local = core.incarnation_probe(None);
            local.committed = local
                .committed
                .max(wal.read_committed().await?.map(|id| id.index))
                .max(core.store.last_applied().map(|id| id.index));
            if Core::<S>::reported_retired(&local, &replies) {
                core.retire().await?;
                wal.close().await?;
                return Err(ClusterError::Removed(node_id));
            }
            let rejoin = Core::<S>::rejoin_choice(node_id, &local, &replies).or_else(|| {
                // An empty volume has no proof that its ID is not already a
                // voter. Let an existing replica identify the incarnation first.
                (!repair && local.committed.is_none())
                    .then(|| {
                        replies.iter().find_map(|(&peer, probe)| {
                            let identity = probe.identity.as_ref()?;
                            (!probe.repair
                                && probe.committed.is_some_and(|index| index > 0)
                                && Some(identity.digest) == core.mesh.endpoint.digest())
                            .then(|| IncarnationChange::Rejoin {
                                peer,
                                identity: identity.clone(),
                            })
                        })
                    })
                    .flatten()
            });
            if let Some(change) = rejoin {
                let switch = core.prepare_switch(change, &mut wal).await?;
                wal.close().await?;
                tokio::task::spawn_blocking(move || switch.commit())
                    .await
                    .map_err(io::Error::other)??;
                return Err(ClusterError::Restart);
            }
        }
        let start_single_voter = auto_recover
            && !repair
            && core
                .mesh
                .endpoint
                .record()
                .is_some_and(|record| record.event.reason == SurvivorReason::PeerUnreachable)
            && wal
                .read_vote()
                .await?
                .is_some_and(|vote| vote.leader_id.node_id == 0)
            && {
                let state = core.store.status.borrow();
                !state.joint
                    && state
                        .members
                        .values()
                        .filter(|m| m.role == MemberRole::Voter)
                        .count()
                        == 1
                    && state
                        .members
                        .get(&node_id)
                        .is_some_and(|m| m.role == MemberRole::Voter)
            };
        if start_single_voter {
            // The snapshot has no granted vote. Start the uncontested election
            // without waiting for a randomized follower deadline.
            core.raft.runtime_config().elect(false);
        }
        core.raft.run();
        let driver = tokio::spawn(core.clone().run(listener, wal.clone(), lock));
        let cluster = Self(Arc::new(Node {
            core,
            wal,
            driver: Mutex::new(Some(driver)),
        }));
        if start_single_voter {
            let raft = &cluster.0.core.raft;
            if let Err(error) = raft.trigger().elect(false).await {
                let _ = cluster.shutdown().await;
                return Err(ClusterError::Raft(error.to_string()));
            }
            raft.runtime_config().elect(true);
        }
        if let Some(peers) = initial {
            let membership = MembershipOf::<Types>::from(
                peers
                    .into_iter()
                    .map(|(id, address)| {
                        (
                            id,
                            BasicNode {
                                addr: address.to_string(),
                            },
                        )
                    })
                    .collect::<BTreeMap<_, _>>(),
            );
            // A durable vote, snapshot or WAL entry fences a second initialization.
            match cluster.0.core.raft.initialize(membership).await {
                Ok(()) | Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {}
                Err(error) => {
                    let _ = cluster.shutdown().await;
                    return Err(ClusterError::Raft(error.to_string()));
                }
            }
        }
        if existing && state_format == 2 && cluster.0.core.probe_retired().await {
            cluster.0.core.retire().await?;
            let _ = cluster.shutdown().await;
            return Err(ClusterError::Removed(node_id));
        }
        Ok(cluster)
    }

    /// Commit an application command on any member and return the leader's result.
    /// Retries definitive redirects and failed connections until the request deadline.
    /// A lost reply or interrupted in-flight proposal returns `WriteUncertain`; retry
    /// only if the application command is idempotent or has a replicated deduplication key.
    ///
    /// The encoded command must fit in `ClusterConfig::max_command_size`.
    pub async fn submit(&self, command: S::Command) -> Result<S::Response, ClusterError> {
        let body = encode_command::<S>(
            command,
            self.0.core.mesh.endpoint.limits.command,
            self.0.core.store.format,
        )?;
        let core = &self.0.core;
        let deadline = Instant::now() + core.request_timeout;
        let mut hint = None;
        loop {
            core.check_running()?;
            let target = core.target(hint.take());
            let response = if target == self.node_id() {
                core.write_local(body.clone(), deadline).await?
            } else {
                match core.rpc(target, Op::Write, body.clone(), deadline).await {
                    Ok(response) => decode(&response)
                        .map_err(|error| ClusterError::WriteUncertain(error.to_string()))?,
                    Err(CallError::Unsent(_)) => {
                        core.retry_pause(deadline).await?;
                        continue;
                    }
                    Err(CallError::Uncertain(error) | CallError::Remote(error)) => {
                        return Err(ClusterError::WriteUncertain(error.to_string()));
                    }
                }
            };
            match response {
                Route::Value(response) => return decode_response(response),
                Route::Redirect(leader) => hint = leader,
                Route::Retry => {}
                Route::Rejected => return Err(ClusterError::WriteRejected),
                Route::UnsupportedVersion(version) => {
                    return Err(ClusterError::UnsupportedVersion {
                        kind: "application command",
                        version,
                    });
                }
                Route::Failed(error) => return Err(ClusterError::WriteUncertain(error)),
            }
            core.retry_pause(deadline).await?;
        }
    }

    /// Submit a command only on the local node. Return `Ok(None)` if Raft
    /// rejects it before append because this node is not the leader. Do not
    /// forward or retry. `WriteUncertain` means the command may have committed.
    pub async fn submit_if_leader(
        &self,
        command: S::Command,
    ) -> Result<Option<S::Response>, ClusterError> {
        let core = &self.0.core;
        core.check_running()?;
        let body = encode_command::<S>(
            command,
            core.mesh.endpoint.limits.command,
            core.store.format,
        )?;
        let deadline = Instant::now() + core.request_timeout;
        match core.write_local(body, deadline).await? {
            Route::Value(response) => decode_response(response).map(Some),
            Route::Redirect(_) => Ok(None),
            Route::Retry => Err(ClusterError::Deadline),
            Route::Rejected => Err(ClusterError::WriteRejected),
            Route::UnsupportedVersion(version) => Err(ClusterError::UnsupportedVersion {
                kind: "application command",
                version,
            }),
            Route::Failed(error) => Err(ClusterError::WriteUncertain(error)),
        }
    }

    /// Read the local applied state without contacting the leader. Do not block in `f`.
    pub fn read<R>(&self, f: impl FnOnce(&S) -> R) -> R {
        f(&self.0.core.store.state.read().unwrap().app)
    }

    /// Obtain a quorum-confirmed read index from the leader, then wait for the local
    /// state machine to apply through it before running `f` on this node.
    pub async fn linearizable_read<R>(&self, f: impl FnOnce(&S) -> R) -> Result<R, ClusterError> {
        let core = &self.0.core;
        let deadline = Instant::now() + core.request_timeout;
        let mut hint = None;
        let index = loop {
            core.check_running()?;
            let target = core.target(hint.take());
            let response = if target == self.node_id() {
                timeout_at(deadline, core.read_index())
                    .await
                    .map_err(|_| ClusterError::Deadline)?
            } else {
                match core.read_remote(target, deadline).await {
                    Ok(response) => response,
                    Err(_) => Route::Retry,
                }
            };
            match response {
                Route::Value(index) => break index,
                Route::Redirect(leader) => hint = leader,
                Route::Retry
                | Route::Failed(_)
                | Route::Rejected
                | Route::UnsupportedVersion(_) => {}
            }
            core.retry_pause(deadline).await?;
        };
        timeout_at(
            deadline,
            core.raft
                .wait(None)
                .applied_index_at_least(Some(index), "local read index"),
        )
        .await
        .map_err(|_| ClusterError::Deadline)?
        .map_err(|error| ClusterError::Raft(error.to_string()))?;
        Ok(self.read(f))
    }

    pub fn node_id(&self) -> u64 {
        self.0.core.mesh.endpoint.node_id
    }

    /// The latest locally known leader, which may be stale during an election.
    pub fn leader(&self) -> Option<u64> {
        self.metrics().leader
    }

    /// The locally applied voter addresses. Learners do not serve clients.
    pub fn members(&self) -> BTreeMap<u64, SocketAddr> {
        self.0
            .core
            .store
            .status
            .borrow()
            .members
            .iter()
            .filter(|(_, member)| member.role == MemberRole::Voter)
            .map(|(&id, member)| (id, member.address))
            .collect()
    }

    /// Capture the IDs of the locally applied voters without copying addresses.
    pub fn voter_ids(&self) -> Vec<u64> {
        self.0
            .core
            .store
            .status
            .borrow()
            .members
            .iter()
            .filter(|(_, member)| member.role == MemberRole::Voter)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Locally applied lease status, or `None` if the ID is not a voter.
    pub fn voter_status(&self, node_id: u64) -> Option<NodeStatus> {
        self.0
            .core
            .store
            .status
            .borrow()
            .members
            .get(&node_id)
            .filter(|member| member.role == MemberRole::Voter)
            .map(|member| member.liveness)
    }

    /// Wait for the local replica to apply a Down event, demotion or removal.
    /// A transport failure alone does not establish any of these.
    pub async fn wait_voter_inactive(&self, node_id: u64) -> Result<(), ClusterError> {
        self.0
            .core
            .store
            .status
            .subscribe()
            .wait_for(|status| {
                status.members.get(&node_id).is_none_or(|member| {
                    member.role != MemberRole::Voter || member.liveness == NodeStatus::Down
                })
            })
            .await
            .map(|_| ())
            .map_err(|_| ClusterError::Shutdown)
    }

    pub fn membership_control(&self) -> MembershipControl {
        let core = &self.0.core;
        let weak = Arc::downgrade(core);
        MembershipControl {
            node_id: self.node_id(),
            status: core.store.status.subscribe(),
            requested: core.requested.clone(),
            serving: core.serving.subscribe(),
            safe_until: core.safe_until.subscribe(),
            stop: core.mesh.stop.subscribe(),
            restart: core.restart.as_ref().map(watch::Sender::subscribe),
            leader: Arc::new(move || weak.upgrade().and_then(|core| core.current_leader())),
            dynamic: core.store.format == 2,
        }
    }

    /// Local WAL worker metrics. A read barrier can be used to sample after a workload.
    pub async fn wal_metrics(&self) -> Result<WalMetrics, ClusterError> {
        Ok(self.0.wal.metrics().await?)
    }

    pub fn metrics(&self) -> ClusterMetrics {
        let receiver = self.0.core.raft.metrics();
        let m = receiver.borrow_watched();
        let endpoint = &self.0.core.mesh.endpoint;
        ClusterMetrics {
            node_id: m.id,
            current_term: m.current_term,
            leader: m.current_leader,
            last_log_index: m.last_log_index,
            committed_index: m.local_committed.map(|id| id.index),
            applied_index: m.last_applied.map(|id| id.index),
            snapshot_index: m.snapshot.map(|id| id.index),
            purged_index: m.purged.map(|id| id.index),
            running: !*self.0.core.mesh.stop.borrow() && m.running_state.is_ok(),
            auto_recover: endpoint.recovery_timeout().is_some(),
            incarnation: endpoint
                .record()
                .and_then(|record| record.identity.as_ref())
                .map_or(0, |id| id.number),
            last_survivor_event: endpoint.record().map(|record| record.event),
        }
    }

    pub fn mesh(&self) -> &Mesh {
        &self.0.core.mesh
    }

    /// The latest locally applied liveness state, including nodes not observed yet.
    pub fn node_statuses(&self) -> BTreeMap<u64, NodeStatus> {
        self.0.core.store.state.read().unwrap().leases.statuses()
    }

    /// Best-effort notification from this replica's apply loop. Receivers may lag;
    /// snapshots restore liveness without sending historical transitions.
    pub fn subscribe_node_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.0.core.store.events.subscribe()
    }

    pub async fn shutdown(&self) -> Result<(), ClusterError> {
        self.0.core.mesh.stop.send_replace(true);
        let mut driver = self.0.driver.lock().await;
        if let Some(task) = driver.as_mut() {
            let result = task.await;
            *driver = None;
            result.map_err(|error| ClusterError::Raft(error.to_string()))??;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
enum Route<T> {
    Value(T),
    Redirect(Option<u64>),
    Retry,
    Failed(String),
    Rejected,
    UnsupportedVersion(u16),
}

impl<S: StateMachine> Core<S> {
    fn check_running(&self) -> Result<(), ClusterError> {
        let node_id = self.mesh.endpoint.node_id;
        if *self.serving.borrow() == Serving::Removed
            || self.store.status.borrow().retired.contains(&node_id)
        {
            return Err(ClusterError::Removed(node_id));
        }
        if *self.mesh.stop.borrow() {
            return Err(ClusterError::Shutdown);
        }
        let receiver = self.raft.metrics();
        let metrics = receiver.borrow_watched();
        if let Err(error) = &metrics.running_state {
            return Err(ClusterError::Raft(error.to_string()));
        }
        Ok(())
    }

    fn target(&self, hint: Option<u64>) -> u64 {
        hint.filter(|id| self.mesh.endpoint.address(*id).is_some())
            .or_else(|| self.current_leader())
            .unwrap_or(self.mesh.endpoint.node_id)
    }

    fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().current_leader
    }

    async fn rpc(
        &self,
        target: u64,
        op: Op,
        body: Bytes,
        deadline: Instant,
    ) -> Result<Bytes, CallError> {
        // A stale leader's unreachable address must not consume the entire deadline.
        let connect = deadline.min(Instant::now() + Duration::from_millis(200));
        self.mesh
            .endpoint
            .call(target, op, body, deadline, connect)
            .await
    }

    async fn retry_pause(&self, deadline: Instant) -> Result<(), ClusterError> {
        if Instant::now() >= deadline {
            return Err(ClusterError::Deadline);
        }
        let mut metrics = self.raft.metrics();
        drop(metrics.borrow_and_update());
        let _ = timeout_at(
            deadline.min(Instant::now() + Duration::from_millis(20)),
            metrics.changed(),
        )
        .await;
        if Instant::now() >= deadline {
            return Err(ClusterError::Deadline);
        }
        Ok(())
    }

    async fn write_local(
        &self,
        body: Bytes,
        deadline: Instant,
    ) -> Result<Route<Option<Bytes>>, ClusterError> {
        timeout_at(deadline, self.write(Command::App(body)))
            .await
            .map_err(|_| ClusterError::WriteUncertain("local proposal timed out".into()))
    }

    async fn write(&self, command: Command) -> Route<Option<Bytes>> {
        match self.raft.client_write(command).await {
            Ok(response) => match response.data {
                Ok(result) => Route::Value(result),
                Err(error) => Route::Failed(error),
            },
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(leader))) => {
                Route::Redirect(leader.leader_id)
            }
            Err(error) => Route::Failed(error.to_string()),
        }
    }

    async fn read_index(&self) -> Route<u64> {
        match self.raft.ensure_linearizable(ReadPolicy::ReadIndex).await {
            Ok(id) => Route::Value(id.index()),
            Err(RaftError::APIError(LinearizableReadError::ForwardToLeader(leader))) => {
                Route::Redirect(leader.leader_id)
            }
            Err(RaftError::APIError(LinearizableReadError::QuorumNotEnough(_))) => Route::Retry,
            Err(error) => Route::Failed(error.to_string()),
        }
    }

    async fn read_remote(&self, target: u64, deadline: Instant) -> io::Result<Route<u64>> {
        let response = self
            .rpc(target, Op::ReadIndex, Bytes::new(), deadline)
            .await?;
        decode(&response)
    }

    fn leadership(&self) -> Option<Leadership> {
        let receiver = self.raft.metrics();
        let metrics = receiver.borrow_watched();
        (metrics.state == ServerState::Leader).then_some(Leadership {
            term: metrics.current_term,
            node_id: metrics.id,
        })
    }

    fn stamp(&self, leader: Leadership) -> Stamp {
        Stamp {
            leader,
            millis: self
                .clock_origin
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            occurred_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        }
    }

    async fn heartbeat(&self, node_id: u64) -> Route<Option<Bytes>> {
        if !self.store.status.borrow().members.contains_key(&node_id) {
            return Route::Rejected;
        }
        let Some(leader) = self.leadership() else {
            return Route::Redirect(self.current_leader());
        };
        let stamp = self.stamp(leader);
        self.write(Command::Lease(LeaseCommand::Heartbeat { node_id, stamp }))
            .await
    }

    async fn renew_leases(&self) -> Result<Option<IncarnationChange>, ClusterError> {
        let mut applied = self.store.status.subscribe();
        let node_id = self.mesh.endpoint.node_id;
        let mut next = Instant::now();
        let mut last_renewal = next;
        let mut next_probe = next;
        let mut lapsed = false;
        loop {
            tokio::select! {
                retired = async { applied.wait_for(|status| status.retired.contains(&node_id)).await.is_ok() } => {
                    if retired {
                        self.retire().await?;
                    }
                    return Ok(None);
                },
                _ = tokio::time::sleep_until(next) => {},
            }
            let started = Instant::now();
            let deadline = started + self.lease_interval;
            let leader = self
                .current_leader()
                .filter(|_| !self.repair.load(Ordering::Acquire));
            #[cfg(test)]
            let leader = leader.filter(|_| {
                !self
                    .filter_lease_renewals
                    .load(std::sync::atomic::Ordering::Acquire)
            });
            let renewed = if let Some(leader) = leader {
                timeout_at(deadline, self.renew_lease(leader, deadline))
                    .await
                    .unwrap_or(false)
            } else {
                false
            };
            // Admission closes at the local deadline even while a renewal is
            // in flight; report each gap, however short.
            if !lapsed
                && self
                    .safe_until
                    .borrow()
                    .is_some_and(|until| until <= Instant::now())
            {
                lapsed = true;
                tracing::warn!(
                    "Cluster lease expired; refusing new MQTT clients until a quorum renews it."
                );
            }
            if renewed && self.is_voter(node_id) {
                last_renewal = Instant::now();
                // The leader's expiry clock cannot start before we issue this
                // renewal. Don't extend local ownership by RPC or apply latency.
                self.safe_until
                    .send_replace(Some(started + self.lease_window()));
                self.serving.send_if_modified(|state| {
                    let changed = *state == Serving::Waiting;
                    if changed {
                        *state = Serving::Active;
                    }
                    changed
                });
                if std::mem::take(&mut lapsed) {
                    tracing::info!("Cluster lease renewed; admitting MQTT clients again.");
                }
            } else {
                if last_renewal.elapsed() >= self.lease_timeout {
                    self.serving.send_if_modified(|state| {
                        let changed = *state == Serving::Active;
                        if changed {
                            *state = Serving::Waiting;
                        }
                        changed
                    });
                }
                if self.store.format == 2
                    && self.mesh.endpoint.recovery_timeout().is_none()
                    && Instant::now() >= next_probe
                {
                    next_probe =
                        Instant::now() + self.lease_interval.max(Duration::from_millis(200));
                    if self.probe_retired().await {
                        self.retire().await?;
                        return Ok(None);
                    }
                }
            }
            let period = if *self.serving.borrow() == Serving::Waiting {
                self.heartbeat_interval.min(self.lease_interval)
            } else {
                self.lease_interval
            };
            let period = self
                .mesh
                .endpoint
                .recovery_timeout()
                .map_or(period, |wait| {
                    period.min((wait / 3).max(Duration::from_millis(1)))
                });
            next = Instant::now() + period;
        }
    }

    fn lease_window(&self) -> Duration {
        self.lease_timeout - (self.lease_timeout / 4).min(Duration::from_millis(100))
    }

    async fn recover_incarnation(
        &self,
        wait: Duration,
    ) -> Result<Option<IncarnationChange>, ClusterError> {
        let mut last_viable = Instant::now();
        let period = self
            .lease_interval
            .max(Duration::from_millis(200))
            .min(wait);
        let mut ticks = tokio::time::interval(period);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let endpoint = &self.mesh.endpoint;
        let mut membership = self.store.status.subscribe();
        membership.mark_changed();
        let mut settled = false;
        let mut next_sweep = Instant::now();
        loop {
            ticks.tick().await;
            if membership.has_changed().unwrap_or(false) {
                let status = membership.borrow_and_update();
                let desired = if status.desired.is_empty() {
                    &endpoint.seeds
                } else {
                    &status.desired
                };
                let voters = status
                    .members
                    .iter()
                    .filter(|(_, m)| m.role == MemberRole::Voter && m.liveness == NodeStatus::Alive)
                    .map(|(id, m)| (id, &m.address));
                settled = !status.joint
                    && status.members.contains_key(&endpoint.node_id)
                    && status.members.len() == desired.len()
                    && voters.eq(desired);
            }
            let now = Instant::now();
            // A routine probe opens a new (normally mTLS) connection to each
            // peer. A settled voter already has quorum-backed renewal evidence.
            // Keep an occasional full sweep for conflicting histories/settings.
            if settled
                && now < next_sweep
                && let Some(renewed) = self.recent_renewal(now, wait)
            {
                last_viable = last_viable.max(renewed);
                continue;
            }
            if let Some(change) = self.check_recovery(wait, &mut last_viable).await? {
                return Ok(Some(change));
            }
            next_sweep = now + HEALTHY_RECOVERY_SWEEP;
        }
    }

    fn recent_renewal(&self, now: Instant, wait: Duration) -> Option<Instant> {
        if self.repair.load(Ordering::Acquire) {
            return None;
        }
        let until = (*self.safe_until.borrow()).filter(|&until| until > now)?;
        let renewed = until - self.lease_window();
        (now.saturating_duration_since(renewed) < wait).then_some(renewed)
    }

    fn incarnation_probe(&self, asking: Option<u64>) -> Probe {
        let endpoint = &self.mesh.endpoint;
        let receiver = self.raft.metrics();
        let metrics = receiver.borrow_watched();
        let membership = &metrics.committed_membership_config;
        let repair = self.repair.load(Ordering::Acquire);
        let safe_until = (!repair && !*self.mesh.stop.borrow() && self.is_voter(endpoint.node_id))
            .then_some(*self.safe_until.borrow())
            .flatten();
        let now = Instant::now();
        let quorum = safe_until.is_some_and(|until| until > now);
        let renewal_age =
            safe_until.map(|until| now.saturating_duration_since(until - self.lease_window()));
        let learner_at = if quorum
            && metrics.current_leader == Some(endpoint.node_id)
            && membership.membership().get_joint_config().len() == 1
        {
            asking
                .filter(|asking| {
                    membership
                        .membership()
                        .non_write_voter_ids()
                        .any(|id| id == *asking)
                })
                .and_then(|_| membership.log_id().map(|id| id.index))
        } else {
            None
        };
        let voters = membership.voter_ids().count();
        let voters = if voters == 0 {
            self.store
                .status
                .borrow()
                .members
                .values()
                .filter(|m| m.role == MemberRole::Voter)
                .count()
        } else {
            voters
        };
        Probe {
            timeout: endpoint.recovery_timeout(),
            identity: endpoint.identity(),
            shared_digest: None,
            quorum,
            renewal_age,
            voters,
            committed: metrics
                .local_committed
                .map(|id| id.index)
                .max(self.store.last_applied().map(|id| id.index)),
            repair,
            retired: asking.is_some_and(|id| self.store.status.borrow().retired.contains(&id)),
            learner_at,
        }
    }

    async fn probe_incarnations(&self, wait: Duration) -> BTreeMap<u64, Probe> {
        let endpoint = &self.mesh.endpoint;
        let repair = self.repair.load(Ordering::Acquire);
        let deadline = Instant::now() + wait;
        let mut pending: FuturesUnordered<_> = {
            let status = self.store.status.borrow();
            let desired = if status.desired.is_empty() {
                &endpoint.seeds
            } else {
                &status.desired
            };
            desired
                .iter()
                .map(|(&id, &addr)| (id, addr))
                .chain(
                    status
                        .members
                        .iter()
                        .filter(|(id, _)| !desired.contains_key(*id))
                        .map(|(&id, member)| (id, member.address)),
                )
                .filter(|&(id, _)| id != endpoint.node_id)
                .map(|(id, address)| async move {
                    endpoint
                        .query_incarnation(id, address, repair, deadline)
                        .await
                        .map(|probe| (id, probe))
                })
                .collect()
        };
        let mut replies = BTreeMap::new();
        while let Some(result) = pending.next().await {
            if let Ok((id, probe)) = result {
                replies.insert(id, probe);
            }
        }
        replies
    }

    fn reported_retired(local: &Probe, replies: &BTreeMap<u64, Probe>) -> bool {
        replies.values().any(|reply| {
            reply.retired
                && reply.identity.as_ref().is_some_and(|remote| {
                    local
                        .identity
                        .as_ref()
                        .is_none_or(|local| local.related(remote))
                })
        })
    }

    fn rejoin_choice(
        node_id: u64,
        local: &Probe,
        replies: &BTreeMap<u64, Probe>,
    ) -> Option<IncarnationChange> {
        // No extra work on a healthy branch. With three divergent histories
        // pairwise preference need not be transitive: an ancestor can beat
        // one child on progress, lose to the other, and the first child can
        // win between the siblings on voter count. Elect from the whole view,
        // not just from the branches that beat this particular replica.
        let eligible = |p: &Probe| {
            !p.repair
                && p.identity.as_ref().is_some_and(|identity| {
                    local
                        .identity
                        .as_ref()
                        .map_or(p.quorum, |ours| ours.related(identity))
                })
        };
        if !replies.values().any(|p| {
            p.identity.as_ref().map(|id| id.digest) != local.identity.as_ref().map(|id| id.digest)
                && eligible(p)
        }) {
            return None;
        }
        let mut branches = BTreeMap::new();
        for (peer, probe) in
            std::iter::once((node_id, local)).chain(replies.iter().map(|(&id, p)| (id, p)))
        {
            let Some(identity) = probe.identity.as_ref() else {
                continue;
            };
            if peer != node_id && !eligible(probe) {
                continue;
            }
            let best = branches.entry(identity.digest).or_insert((peer, probe));
            if (probe.committed, probe.voters, std::cmp::Reverse(peer))
                > (best.1.committed, best.1.voters, std::cmp::Reverse(best.0))
            {
                *best = (peer, probe);
            }
        }
        // Digest order and a single representative per branch give identical
        // views the same winner regardless of who asked or responded first.
        let (peer, probe) =
            branches.into_values().reduce(
                |best, next| {
                    if next.1.wins_over(best.1) { next } else { best }
                },
            )?;
        if probe.identity == local.identity {
            return None;
        }
        Some(IncarnationChange::Rejoin {
            peer,
            identity: probe.identity.clone()?,
        })
    }

    async fn check_recovery(
        &self,
        wait: Duration,
        last_viable: &mut Instant,
    ) -> Result<Option<IncarnationChange>, ClusterError> {
        let started = Instant::now();
        let replies = self
            .probe_incarnations(
                wait.min(self.request_timeout)
                    .min(Duration::from_millis(200)),
            )
            .await;
        let local_sampled_at = Instant::now();
        let local = self.incarnation_probe(None);
        if Self::reported_retired(&local, &replies) {
            self.retire().await?;
            return Ok(None);
        }
        if let Some(change) = Self::rejoin_choice(self.mesh.endpoint.node_id, &local, &replies) {
            return Ok(Some(change));
        }
        if local.repair {
            let source = replies.iter().find_map(|(&id, peer)| {
                (peer.identity.is_some() && peer.identity == local.identity)
                    .then_some(peer.learner_at)
                    .flatten()
                    .map(|index| (id, index))
            });
            if let Some((_, index)) = source
                && self
                    .store
                    .last_applied()
                    .is_some_and(|id| id.index >= index)
            {
                let dir = self.store.dir().to_path_buf();
                tokio::task::spawn_blocking(move || {
                    let bytes = encode(&index)?;
                    atomic_write(&dir, JOINED, |file| file.write_all(&bytes))
                })
                .await
                .map_err(io::Error::other)??;
                self.repair.store(false, Ordering::Release);
                self.raft.runtime_config().elect(true);
            }
            self.replication_source
                .store(source.map_or(0, |(id, _)| id), Ordering::Release);
        }
        let own_renewal = local
            .renewal_age
            .and_then(|age| local_sampled_at.checked_sub(age));
        let peer_renewals = replies
            .values()
            .filter(|peer| peer.identity.is_some() && peer.identity == local.identity)
            .filter_map(|peer| started.checked_sub(peer.renewal_age?));
        // Repeated observations of a cached admission lease must not push the
        // recovery deadline forward. Subtract from the send time so network
        // delays cannot make the peer's last renewal look newer.
        for renewed_at in own_renewal.into_iter().chain(peer_renewals) {
            *last_viable = (*last_viable).max(renewed_at);
        }
        let (single_voter, reachable_quorum) = {
            let receiver = self.raft.metrics();
            let metrics = receiver.borrow_watched();
            let configs = metrics.membership_config.membership().get_joint_config();
            let node = self.mesh.endpoint.node_id;
            let single_voter = matches!(configs.as_slice(), [voters] if voters.len() == 1 && voters.contains(&node));
            let reachable_quorum = !configs.is_empty()
                && configs.iter().all(|voters| {
                    voters
                        .iter()
                        .filter(|&&id| {
                            (id == node && !local.repair)
                                || replies.get(&id).is_some_and(|peer| {
                                    !peer.repair
                                        && peer.identity.is_some()
                                        && peer.identity == local.identity
                                })
                        })
                        .count()
                        > voters.len() / 2
                });
            (single_voter, reachable_quorum)
        };
        // A healthy sole voter cannot repair a disk stall by replacing itself.
        // A fenced sole voter, however, cannot elect or obtain a learner grant:
        // if no other branch returns, it needs the normal recovery timeout.
        if single_voter && !local.repair {
            return Ok(None);
        }
        let wait = if self.store.last_applied().is_some() {
            wait
        } else {
            wait.saturating_mul(6)
        };
        // Replicas that answer a real protocol probe can still be waiting for
        // a durable vote or append. Allow one request deadline for Raft to
        // recover with a reachable quorum. An unresponsive TCP listener alone
        // contributes nothing, and the grace ends if the quorum disappears.
        let wait = if reachable_quorum {
            wait.max(self.request_timeout)
        } else {
            wait
        };
        let unreachable = last_viable.elapsed();
        if unreachable < wait {
            return Ok(None);
        }
        let parent = local
            .identity
            .or_else(|| self.bootstrap_identity.clone())
            .expect("automatic recovery has a bootstrap identity");
        Ok(Some(IncarnationChange::Fork {
            unreachable,
            parent,
        }))
    }

    async fn renew_lease(&self, leader: u64, deadline: Instant) -> bool {
        if leader == self.mesh.endpoint.node_id {
            // A local proposal already waits for local apply.
            return matches!(self.heartbeat(leader).await, Route::Value(_));
        }
        let renewed = self
            .rpc(leader, Op::Lease, Bytes::new(), deadline)
            .await
            .is_ok_and(|body| matches!(decode::<Route<Option<Bytes>>>(&body), Ok(Route::Value(_))));
        if !renewed
            || (*self.serving.borrow() == Serving::Active
                && self
                    .safe_until
                    .borrow()
                    .is_some_and(|until| until > Instant::now()))
        {
            return renewed;
        }

        // Admission may already have closed on the local deadline even if
        // the renewal loop has not changed the serving flag. Reopen only
        // after applying through a fresh quorum-confirmed read index.
        let Ok(Route::Value(index)) = self.read_remote(leader, deadline).await else {
            return false;
        };
        self.raft
            .wait(None)
            .applied_index_at_least(Some(index), "lease recovery read index")
            .await
            .is_ok()
    }

    fn is_voter(&self, node_id: u64) -> bool {
        self.store
            .status
            .borrow()
            .members
            .get(&node_id)
            .is_some_and(|m| m.role == MemberRole::Voter)
    }

    async fn probe_retired(&self) -> bool {
        let endpoint = &self.mesh.endpoint;
        let peers = {
            let mut peers = endpoint.seeds.clone();
            let status = self.store.status.borrow();
            peers.extend(status.members.iter().map(|(&id, m)| (id, m.address)));
            peers
        };
        let deadline = Instant::now() + self.request_timeout.min(Duration::from_millis(200));
        let mut probes: FuturesUnordered<_> = peers
            .into_iter()
            .filter(|(id, _)| *id != endpoint.node_id)
            .map(|(id, address)| async move {
                endpoint
                    .query_retired(id, address, deadline)
                    .await
                    .unwrap_or(false)
            })
            .collect();
        while let Some(retired) = probes.next().await {
            if retired {
                return true;
            }
        }
        false
    }

    async fn retire(&self) -> Result<(), ClusterError> {
        if *self.serving.borrow() == Serving::Removed {
            return Ok(());
        }
        let dir = self.store.dir().to_path_buf();
        let result =
            tokio::task::spawn_blocking(move || atomic_write(&dir, RETIRED_FILE, |_| Ok(())))
                .await
                .map_err(io::Error::other)?;
        self.serving.send_replace(Serving::Removed);
        self.mesh.stop.send_replace(true);
        Ok(result?)
    }

    async fn reconcile_loop(&self) {
        let mut ticks = tokio::time::interval(self.heartbeat_interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            if self.store.format != 2 || self.leadership().is_none() {
                continue;
            }
            let error = match timeout(self.request_timeout, self.reconcile()).await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => {
                    Some("membership waiting for quorum; voter change was not confirmed".into())
                }
            };
            self.store.status.send_if_modified(|status| {
                if status.reconciliation_error == error {
                    return false;
                }
                if let Some(error) = &error {
                    tracing::warn!(%error, "cluster membership pending");
                }
                status.reconciliation_error = error;
                true
            });
        }
    }

    async fn reconcile(&self) -> Result<(), ClusterError> {
        if self.mesh.endpoint.recovery_timeout().is_some() && self.reconcile_recovery().await? {
            return Ok(());
        }
        let (local, committed) = {
            let requested = self.requested.borrow();
            let state = self.store.state.read().unwrap();
            let membership = state.membership.membership();
            let joint = membership.get_joint_config();
            let local = requested.as_ref().filter(|local| {
                local.generation >= state.desired.generation && **local != state.desired
            });
            if local.is_none()
                && (state.desired.generation == 0
                    || (joint.len() == 1
                        && joint[0].iter().eq(state.desired.peers.keys())
                        && membership.non_write_voter_ids().next().is_none()))
            {
                return Ok(());
            }
            (local.cloned(), state.desired.clone())
        };
        let (stored, leader) = {
            let receiver = self.raft.metrics();
            let metrics = receiver.borrow_watched();
            if metrics.state != ServerState::Leader
                || metrics.membership_config != metrics.committed_membership_config
                || metrics.last_applied.as_ref() < metrics.membership_config.log_id().as_ref()
            {
                return Ok(());
            }
            (metrics.membership_config.clone(), metrics.vote.leader_id)
        };
        let membership = stored.membership();
        let joint = membership.get_joint_config();
        if joint.len() < 2
            && let Some(local) = local
        {
            if local.generation == committed.generation && local != committed {
                return Err(ClusterError::Membership(format!(
                    "generation {} already has a different desired configuration",
                    local.generation
                )));
            }
            if local.generation > committed.generation {
                validate_change(&self.store.status.borrow(), &local)?;
                match self.write(Command::Desired(local)).await {
                    Route::Value(_) => return Ok(()),
                    _ => return Err(ClusterError::Deadline),
                }
            }
        }
        if committed.generation == 0 {
            return Ok(());
        }
        let target = if joint.len() > 1 {
            // Finish an interrupted joint change before observing a newer request.
            joint
                .last()
                .expect("joint membership has a final configuration")
                .clone()
        } else {
            validate_change(&self.store.status.borrow(), &committed)?;
            for (&id, address) in &committed.peers {
                if membership.get_node(&id).is_none() {
                    self.raft
                        .add_learner(
                            id,
                            BasicNode {
                                addr: address.to_string(),
                            },
                            false,
                        )
                        .await
                        .map_err(|error| ClusterError::Membership(error.to_string()))?;
                    return Ok(());
                }
            }
            committed.peers.keys().copied().collect::<BTreeSet<_>>()
        };
        let extra_learners = membership
            .non_write_voter_ids()
            .filter(|id| !target.contains(id))
            .collect::<BTreeSet<_>>();
        if joint.len() == 1 && joint[0] == target && extra_learners.is_empty() {
            return Ok(());
        }
        // ReadIndex verifies the current quorum. Require a majority of the
        // proposed voters to have that prefix and answer a fresh probe before
        // appending a new configuration, which takes effect before it commits.
        let barrier = match self.read_index().await {
            Route::Value(index) => index,
            _ => return Err(ClusterError::Deadline),
        };
        let mut learners: BTreeSet<_> = membership
            .non_write_voter_ids()
            .filter(|id| target.contains(id))
            .collect();
        let caught_up = {
            let receiver = self.raft.metrics();
            let metrics = receiver.borrow_watched();
            let Some(matches) = &metrics.replication else {
                return Err(ClusterError::Deadline);
            };
            for &id in &learners {
                if matches
                    .get(&id)
                    .and_then(|id| *id)
                    .is_none_or(|log| log.index < barrier)
                {
                    return Err(ClusterError::Membership(format!(
                        "learner {id} has not caught up"
                    )));
                }
            }
            target
                .iter()
                .copied()
                .filter(|id| {
                    *id == metrics.id
                        || matches
                            .get(id)
                            .and_then(|id| *id)
                            .is_some_and(|log| log.index >= barrier)
                })
                .collect::<Vec<_>>()
        };
        let endpoint = &self.mesh.endpoint;
        let deadline = Instant::now() + self.request_timeout.min(Duration::from_millis(250));
        let needed = target.len() / 2 + 1;
        let mut reachable = usize::from(caught_up.contains(&endpoint.node_id));
        let mut probes: FuturesUnordered<_> = caught_up
            .into_iter()
            .filter(|id| *id != endpoint.node_id)
            .map(|id| async move {
                let reachable = if let Some(address) = endpoint.address(id) {
                    endpoint
                        .query_retired(id, address, deadline)
                        .await
                        .is_ok_and(|retired| !retired)
                } else {
                    false
                };
                (id, reachable)
            })
            .collect();
        while reachable < needed || !learners.is_empty() {
            let Some((id, replied)) = probes.next().await else {
                return Err(ClusterError::Membership(
                    "proposed voter set would lose quorum".into(),
                ));
            };
            if learners.remove(&id) && !replied {
                return Err(ClusterError::Membership(format!(
                    "learner {id} stopped responding before promotion"
                )));
            }
            reachable += usize::from(replied);
        }
        let edit = ChangeMembers::Batch(vec![
            ChangeMembers::ReplaceAllVoters(target),
            ChangeMembers::RemoveNodes(extra_learners),
        ]);
        self.raft
            .change_membership_if(
                edit,
                false,
                [
                    Precondition::CommittedLeaderId {
                        committed_leader_id: leader,
                    },
                    Precondition::LastMembershipLogId {
                        last_membership_log_id: *stored.log_id(),
                    },
                ],
            )
            .await
            .map_err(|error| ClusterError::Membership(error.to_string()))?;
        Ok(())
    }

    // Recovery changes one node at a time. An absent configured peer does
    // not prevent another peer from rejoining and serving.
    async fn reconcile_recovery(&self) -> Result<bool, ClusterError> {
        let (stored, leader) = {
            let receiver = self.raft.metrics();
            let metrics = receiver.borrow_watched();
            if metrics.state != ServerState::Leader
                || metrics.membership_config != metrics.committed_membership_config
                || metrics.last_applied.as_ref() < metrics.membership_config.log_id().as_ref()
            {
                return Ok(true);
            }
            (
                metrics.committed_membership_config.clone(),
                metrics.vote.leader_id,
            )
        };
        let endpoint = &self.mesh.endpoint;
        let (desired, candidates) = {
            let requested = self.requested.borrow();
            let state = self.store.state.read().unwrap();
            if requested.as_ref().is_some_and(|requested| {
                requested.generation >= state.desired.generation && *requested != state.desired
            }) {
                return Ok(false);
            }
            let status = self.store.status.borrow();
            let desired = if state.desired.peers.is_empty() {
                &endpoint.seeds
            } else {
                &state.desired.peers
            };
            let candidates = desired
                .iter()
                .filter(|&(id, _)| *id != endpoint.node_id && !status.retired.contains(id))
                .filter(|&(id, _)| {
                    status.members.get(id).is_none_or(|member| {
                        member.role == MemberRole::Learner || member.liveness == NodeStatus::Down
                    })
                })
                .map(|(&id, &address)| (id, address))
                .collect::<Vec<_>>();
            let normal_change = stored
                .membership()
                .nodes()
                .any(|(id, _)| !desired.contains_key(id));
            (!normal_change, candidates)
        };
        if !desired {
            return Ok(false);
        }
        let membership = stored.membership();
        let joint = membership.get_joint_config();
        let mut voters: BTreeSet<_> = membership.voter_ids().collect();
        let preconditions = || {
            [
                Precondition::CommittedLeaderId {
                    committed_leader_id: leader,
                },
                Precondition::LastMembershipLogId {
                    last_membership_log_id: *stored.log_id(),
                },
            ]
        };
        if joint.len() > 1 {
            if matches!(self.read_index().await, Route::Value(_)) {
                self.raft
                    .change_membership_if(
                        ChangeMembers::ReplaceAllVoters(
                            joint.last().expect("joint voters").clone(),
                        ),
                        true,
                        preconditions(),
                    )
                    .await
                    .map_err(|error| ClusterError::Membership(error.to_string()))?;
            }
            return Ok(true);
        }
        let deadline = Instant::now() + self.request_timeout.min(Duration::from_millis(200));
        let mut probes: FuturesUnordered<_> = candidates
            .into_iter()
            .map(|(id, address)| async move {
                (
                    id,
                    address,
                    endpoint
                        .query_incarnation(id, address, false, deadline)
                        .await,
                )
            })
            .collect();
        while let Some((id, address, reply)) = probes.next().await {
            let Ok(probe) = reply else {
                continue;
            };
            if probe.identity.as_ref().map(|identity| identity.digest) != endpoint.digest() {
                continue;
            }
            if voters.contains(&id) {
                if !probe.repair || !matches!(self.read_index().await, Route::Value(_)) {
                    continue;
                }
                // Retain the ID as a learner, not as a retired member. The
                // returning process will not accept a vote or any replication
                // until this voter change commits.
                voters.remove(&id);
            } else if membership.get_node(&id).is_none() {
                if self.store.state.read().unwrap().leases.status(id) == NodeStatus::Alive {
                    // Commit the peer's Down event and its wills before it can
                    // renew a lease under the same node ID.
                    continue;
                }
                self.raft
                    .add_learner(
                        id,
                        BasicNode {
                            addr: address.to_string(),
                        },
                        false,
                    )
                    .await
                    .map_err(|error| ClusterError::Membership(error.to_string()))?;
                return Ok(true);
            } else {
                if probe.repair {
                    continue;
                }
                let Route::Value(barrier) = self.read_index().await else {
                    continue;
                };
                let caught_up = self
                    .raft
                    .metrics()
                    .borrow_watched()
                    .replication
                    .as_ref()
                    .and_then(|matches| matches.get(&id).copied().flatten())
                    .is_some_and(|log| log.index >= barrier);
                if !caught_up {
                    continue;
                }
                voters.insert(id);
            }
            self.raft
                .change_membership_if(
                    ChangeMembers::ReplaceAllVoters(voters),
                    true,
                    preconditions(),
                )
                .await
                .map_err(|error| ClusterError::Membership(error.to_string()))?;
            return Ok(true);
        }
        Ok(true)
    }

    async fn expire_leases(&self) {
        let mut ticks = tokio::time::interval(self.lease_interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut current = None;
        let mut elected_at = Instant::now();
        let timeout_ms = self
            .lease_timeout
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        loop {
            ticks.tick().await;
            let leader = self.leadership();
            if leader != current {
                // Give all nodes a full lease period to reach each newly elected leader.
                // This also handles leases stamped by a previous leader's monotonic clock.
                current = leader;
                elected_at = Instant::now();
            }
            if let Some(leader) = leader.filter(|_| elected_at.elapsed() >= self.lease_timeout) {
                self.expire_leases_once(leader, timeout_ms).await;
            }
        }
    }

    async fn expire_leases_once(&self, leader: Leadership, timeout_ms: u64) {
        let expired = self.store.expire(self.stamp(leader), timeout_ms);
        // Keep each expiry as its own Raft entry (with its own event index and
        // heartbeat check), but don't wait for a fresh quorum write per peer.
        for batch in expired.chunks(MAX_APPEND_ENTRIES as usize) {
            let _ = timeout(self.request_timeout, async {
                if let Ok(mut results) = self
                    .raft
                    .client_write_many(
                        batch.iter().copied().map(Command::Lease),
                        WriteOption::expect_leader(leader),
                    )
                    .await
                {
                    // Wait for application before scanning for more expiries.
                    while let Some(Ok(Ok(_))) = results.next().await {}
                }
            })
            .await;
        }
    }

    async fn run(
        self: Arc<Self>,
        listener: TcpListener,
        mut wal: Wal,
        _lock: Option<File>,
    ) -> Result<(), ClusterError> {
        let mut stop = self.mesh.stop.subscribe();
        let recover = self.mesh.endpoint.recovery_timeout().is_some();
        let recovery_timeout = self.mesh.endpoint.recovery_timeout();
        let (_, change) = tokio::join!(self.serve(listener), async {
            let result = tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => Ok(None),
                result = self.renew_leases() => result,
                result = async { self.recover_incarnation(recovery_timeout.expect("recovery enabled")).await }, if recover => result,
                result = self.raft_failure(), if recover => Err(result),
                _ = self.expire_leases() => Ok(None),
                _ = self.reconcile_loop() => Ok(None),
            };
            self.mesh.stop.send_replace(true);
            result
        });
        let raft_result = self.raft.try_shutdown().await;
        self.mesh.endpoint.close().await;
        let cleanup = async {
            if recover {
                self.store.seal();
            }
            self.store.close().await?;
            let switch = match change {
                Ok(Some(change)) => Some(self.prepare_switch(change, &mut wal).await?),
                Ok(None) => None,
                Err(error) => {
                    wal.close().await?;
                    return Err(error);
                }
            };
            wal.close().await?;
            if let Some(switch) = switch {
                tokio::task::spawn_blocking(move || switch.commit())
                    .await
                    .map_err(io::Error::other)??;
                return Err(ClusterError::Restart);
            }
            raft_result.map_err(|error| ClusterError::Raft(error.to_string()))
        }
        .await;
        if cleanup.is_err()
            && let Some(restart) = &self.restart
        {
            restart.send_replace(true);
        }
        cleanup
    }

    async fn raft_failure(&self) -> ClusterError {
        let mut metrics = self.raft.metrics();
        loop {
            if let Err(error) = &metrics.borrow_and_update().running_state {
                return ClusterError::Raft(error.to_string());
            }
            if metrics.changed().await.is_err() {
                return ClusterError::Raft("Raft metrics channel closed".into());
            }
        }
    }

    async fn prepare_switch(
        &self,
        change: IncarnationChange,
        wal: &mut Wal,
    ) -> Result<Switch, ClusterError> {
        let endpoint = &self.mesh.endpoint;
        let node = endpoint.node_id;
        let preserve_archive = endpoint
            .record()
            .is_some_and(|record| record.identity.is_none());
        let (record, fork) = match change {
            IncarnationChange::Fork {
                unreachable,
                parent,
            } => {
                // RaftCore stopped advancing the commit frontier. The apply
                // worker may still be behind; replay the locally committed tail.
                let metrics_commit = self.raft.metrics().borrow_watched().local_committed;
                let committed = metrics_commit.max(wal.read_committed().await?);
                if let Some(committed) =
                    committed.filter(|id| Some(*id) > self.store.last_applied())
                {
                    let mut start = self.store.last_applied().map_or(0, |id| id.index + 1);
                    while start <= committed.index {
                        let end = committed.index.min(start.saturating_add(127));
                        let entries = wal.try_get_log_entries(start..=end).await?;
                        if entries.len() as u64 != end - start + 1
                            || entries
                                .iter()
                                .zip(start..=end)
                                .any(|(entry, index)| entry.log_id.index != index)
                            || (end == committed.index
                                && entries.last().map(|entry| entry.log_id) != Some(committed))
                        {
                            return Err(invalid_data(
                                "missing locally committed entries during cluster recovery",
                            )
                            .into());
                        }
                        self.store.replay_for_fork(entries)?;
                        if end == committed.index {
                            break;
                        }
                        start = end + 1;
                    }
                }
                if self.store.status.borrow().retired.contains(&node) {
                    self.retire().await?;
                    return Err(ClusterError::Removed(node));
                }
                let identity = parent.fork(node, self.store.last_applied().map(|id| id.index))?;
                let metrics_term = self.raft.metrics().borrow_watched().current_term;
                let last_log_term = wal
                    .get_log_state()
                    .await?
                    .last_log_id
                    .map_or(0, |id| id.leader_id.term);
                let vote_term = wal.read_vote().await?.map_or(0, |vote| vote.leader_id.term);
                let peers = endpoint.seeds.clone();
                let peer = peers.keys().copied().find(|id| *id != node);
                (
                    Record::new(Some(identity), SurvivorReason::PeerUnreachable, peer),
                    Some((
                        unreachable,
                        metrics_term.max(last_log_term).max(vote_term),
                        peers,
                    )),
                )
            }
            IncarnationChange::Rejoin { peer, identity } => (
                Record::new(
                    Some(identity),
                    if preserve_archive {
                        SurvivorReason::UnusableState
                    } else {
                        SurvivorReason::PeerWon
                    },
                    Some(peer),
                ),
                None,
            ),
        };
        let number = record
            .identity
            .as_ref()
            .expect("incarnation assigned")
            .number;
        let peer = record.event.peer;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let switch = Switch::prepare(store.dir(), node, record)?;
            if preserve_archive {
                switch.keep_archive()?;
            }
            if let Some((unreachable, term, peers)) = fork {
                tracing::warn!(
                    "Cluster quorum unreachable for {unreachable:?}; continuing alone as a new single-voter cluster (incarnation {number}). Clients reconnect; state not committed here can be lost.",
                );
                store.fork_snapshot(&switch.fresh(), node, peers, term)?;
            } else if let Some(peer) = peer {
                tracing::warn!(
                    "Cluster peer {peer} continued without this node (incarnation {number}); discarding local cluster state and rejoining.",
                );
            }
            Ok::<_, io::Error>(switch)
        }).await.map_err(io::Error::other)?.map_err(Into::into)
    }

    fn check_repair_source(&self, from: u64) -> io::Result<()> {
        if self.repair.load(Ordering::Acquire)
            && self.replication_source.load(Ordering::Acquire) != from
        {
            return Err(invalid_data(
                "replication is fenced until the leader installs this node as a learner",
            ));
        }
        Ok(())
    }

    async fn serve(self: &Arc<Self>, listener: TcpListener) {
        let mut handlers = JoinSet::new();
        let admission = Arc::new(Admission::default());
        let mut stop = self.mesh.stop.subscribe();
        loop {
            tokio::select! {
                biased;
                _ = async { let _ = stop.wait_for(|stopped| *stopped).await; } => break,
                Some(done) = handlers.join_next(), if !handlers.is_empty() => {
                    if let Err(error) = done { tracing::debug!(%error, "cluster RPC task stopped"); }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, source)) => {
                            let Some(idle) = admission.idle() else { continue; };
                            let core = self.clone();
                            let admission = admission.clone();
                            let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
                            handlers.spawn(async move {
                                if let Err(error) = core.connection(stream, source.ip().to_canonical(), deadline, &admission, idle).await {
                                    tracing::trace!(%error, "cluster RPC rejected or failed");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::warn!(%error, "cluster TCP accept failed");
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }
            }
        }
        drop(listener);
        handlers.shutdown().await;
    }

    async fn connection(
        self: &Arc<Self>,
        stream: TcpStream,
        source: IpAddr,
        deadline: Instant,
        admission: &Admission,
        idle: OwnedSemaphorePermit,
    ) -> io::Result<()> {
        let (mut stream, from, op) = timeout_at(deadline, async {
            stream.readable().await?;
            let _handshake = admission
                .handshake(source)
                .ok_or(io::ErrorKind::WouldBlock)?;
            drop(idle);
            self.mesh.endpoint.accept(stream).await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        let _rpc = admission.rpc().ok_or(io::ErrorKind::WouldBlock)?;
        match op {
            Op::Session => self.run_session(stream, from, deadline).await,
            Op::Snapshot => timeout(self.snapshot_timeout, async {
                self.receive_snapshot(&mut stream, from).await?;
                stream.flush().await
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?,
            Op::Retired => {
                let retired = self.store.status.borrow().retired.contains(&from);
                let reply = if retired {
                    1
                } else if self.check_running().is_ok() {
                    0
                } else {
                    2
                };
                timeout_at(deadline, async {
                    stream.write_u8(reply).await?;
                    stream.flush().await
                })
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            }
            Op::Incarnation => timeout_at(deadline, async {
                let endpoint = &self.mesh.endpoint;
                let request: ProbeRequest = endpoint.limits.read_control(&mut stream).await?;
                endpoint.observe_recovery_timeout(from, request.timeout);
                let mut probe = self.incarnation_probe(Some(from));
                if request.repair && probe.learner_at.is_some() {
                    // Demotion retains the node ID and thus Raft's previous
                    // matching index. Authorize a one-time rewind for this
                    // learner before letting it receive replication again.
                    if endpoint.recovery_timeout().is_none()
                        || request.timeout.is_none()
                        || request.digest != endpoint.digest()
                        || !matches!(
                            self.raft.trigger().allow_next_revert(&from, true).await,
                            Ok(Ok(()))
                        )
                    {
                        probe.learner_at = None;
                    }
                }
                probe.for_request(&request);
                write_control(&mut stream, &probe).await?;
                stream.flush().await
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            _ => Err(invalid_data("RPC requires an established cluster session")),
        }
    }

    async fn run_session(
        self: &Arc<Self>,
        mut stream: Connection,
        from: u64,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut superseded = self.mesh.endpoint.accept_session(from, deadline).await?;
        let session = async {
            timeout_at(deadline, async {
                stream.write_u8(0).await?;
                stream.flush().await
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
            let (reader, writer) = stream.split_session();
            let (responses, replies) = mpsc::channel(SESSION_WINDOW);
            let (mesh, mesh_rx) = mpsc::channel(SESSION_WINDOW);
            let (append, append_rx) = mpsc::channel(SESSION_WINDOW);
            tokio::select! {
                result = write_responses(writer, replies, self.request_timeout) => result,
                result = self.read_calls(reader, from, &responses, mesh, append) => result,
                () = self.run_ordered(from, mesh_rx, &responses) => Ok(()),
                () = reply_to_appends(append_rx, &responses, |request| self.rpc_response(from, request)) => Ok(()),
            }
        };
        // Drop the old reader and ordered work before releasing `superseded`.
        tokio::select! {
            biased;
            _ = superseded.changed() => Ok(()),
            result = session => result,
        }
    }

    async fn read_calls(
        self: &Arc<Self>,
        mut reader: impl AsyncReadExt + Unpin,
        from: u64,
        responses: &mpsc::Sender<Response>,
        mesh: mpsc::Sender<Request>,
        append: mpsc::Sender<Request>,
    ) -> io::Result<()> {
        let limits = self.mesh.endpoint.limits;
        let mut workers = JoinSet::new();
        let mut latest = 0u64;
        loop {
            while let Some(result) = workers.try_join_next() {
                result.map_err(io::Error::other)?;
            }
            // Idle sessions are normal. Once a frame begins, bound its receive time.
            let mut header = [0; SESSION_HEADER_LEN];
            let received = reader.read(&mut header).await?;
            if received == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let request = timeout(self.request_timeout, async {
                reader.read_exact(&mut header[received..]).await?;
                let (id, op, len) = decode_session_header(header);
                let op = Op::try_from(op)?;
                if id <= latest || matches!(op, Op::Session | Op::Snapshot | Op::Incarnation) {
                    return Err(invalid_data("invalid cluster session request"));
                }
                let frame = limits
                    .read_frame_body(
                        &mut reader,
                        len,
                        limits.request(op),
                        matches!(op, Op::Append),
                    )
                    .await?;
                Ok(Request { id, op, frame })
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
            latest = request.id;
            match request.op {
                Op::MeshRequest | Op::MeshSend => mesh
                    .try_send(request)
                    .map_err(|_| io::ErrorKind::WouldBlock)?,
                Op::Append => append
                    .try_send(request)
                    .map_err(|_| io::ErrorKind::WouldBlock)?,
                _ => {
                    if workers.len() >= SESSION_WINDOW {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    let core = self.clone();
                    let responses = responses.clone();
                    workers.spawn(async move { core.process_rpc(from, request, &responses).await });
                }
            }
        }
    }

    async fn run_ordered(
        &self,
        from: u64,
        mut calls: mpsc::Receiver<Request>,
        responses: &mpsc::Sender<Response>,
    ) {
        while let Some(request) = calls.recv().await {
            self.process_rpc(from, request, responses).await;
        }
    }

    async fn process_rpc(&self, from: u64, request: Request, responses: &mpsc::Sender<Response>) {
        let op = request.op;
        let response = self.rpc_response(from, request).await;
        if matches!(op, Op::MeshSend) {
            if let Err(error) = response.body {
                tracing::debug!(%error, from, "mesh send handler failed");
            }
        } else {
            let _ = responses.send(response).await;
        }
    }

    async fn rpc_response(&self, from: u64, request: Request) -> Response {
        let body = timeout(
            self.request_timeout,
            self.dispatch(from, request.op, &request.frame),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        .and_then(|result| result)
        .and_then(|body| {
            if body.len() > self.mesh.endpoint.limits.response(request.op) {
                return Err(invalid_data(
                    "cluster RPC response exceeds configured limit",
                ));
            }
            Ok(body)
        });
        Response {
            id: request.id,
            body,
        }
    }

    async fn dispatch(&self, from: u64, op: Op, frame: &Frame) -> io::Result<Bytes> {
        if matches!(op, Op::Append) {
            self.check_repair_source(from)?;
        } else if self.repair.load(Ordering::Acquire) {
            return Err(invalid_data("cluster node is recovering as a learner"));
        }
        let (retired, established) = {
            let status = self.store.status.borrow();
            (status.retired.contains(&from), !status.members.is_empty())
        };
        if retired || (!established && !self.mesh.endpoint.seeds.contains_key(&from)) {
            return Err(invalid_data("sender is not a member of this cluster"));
        }
        if matches!(
            op,
            Op::Write | Op::ReadIndex | Op::MeshRequest | Op::MeshSend
        ) && !self.is_voter(from)
            && !self
                .raft
                .metrics()
                .borrow_watched()
                .committed_membership_config
                .voter_ids()
                .any(|id| id == from)
        {
            if matches!(op, Op::Write) {
                let reply: Route<Option<Bytes>> = if established {
                    Route::Rejected
                } else {
                    Route::Retry
                };
                return encode(&reply).map(Bytes::from);
            }
            return Err(invalid_data("application RPC requires an active voter"));
        }
        match op {
            Op::Append => {
                let request: AppendEntriesRequest<Types> = decode(frame)?;
                check_vote_sender(request.vote, from)?;
                for entry in &request.entries {
                    match &entry.payload {
                        EntryPayloadOf::<Types>::Normal(Command::App(body)) => {
                            version::command_version::<S>(body).map_err(invalid_data)?;
                        }
                        EntryPayloadOf::<Types>::Normal(Command::Desired(_))
                            if self.store.format == 1 =>
                        {
                            return Err(invalid_data("dynamic membership requires state format 2"));
                        }
                        _ => {}
                    }
                }
                let result = self
                    .raft
                    .append_entries(request)
                    .await
                    .map(|result| -> StreamAppendResult<Types> { result.map_err(Into::into) });
                encode(&result).map(Bytes::from)
            }
            Op::Vote | Op::PreVote => {
                let effective = self
                    .raft
                    .metrics()
                    .borrow_watched()
                    .membership_config
                    .clone();
                if effective.log_id().is_some() && !effective.voter_ids().any(|id| id == from) {
                    return Err(invalid_data("candidate is not a known voter"));
                }
                let request: VoteRequest<Types> = decode(frame)?;
                check_vote_sender(request.vote, from)?;
                let result = if matches!(op, Op::Vote) {
                    self.raft.vote(request).await
                } else {
                    self.raft.pre_vote(request).await
                };
                encode(&result).map(Bytes::from)
            }
            Op::Transfer => {
                let request: TransferLeaderRequest<Types> = decode(frame)?;
                check_vote_sender(*request.from_leader(), from)?;
                encode(&self.raft.handle_transfer_leader(request).await).map(Bytes::from)
            }
            Op::Write => {
                encode(&self.write_remote(from, frame.bytes.clone()).await).map(Bytes::from)
            }
            Op::ReadIndex => encode(&self.read_index().await).map(Bytes::from),
            Op::Lease => encode(&self.heartbeat(from).await).map(Bytes::from),
            Op::MeshRequest | Op::MeshSend => self
                .mesh
                .handle(from, frame.bytes.clone())
                .await
                .map_err(io::Error::other),
            Op::Session | Op::Snapshot | Op::Retired | Op::Incarnation => {
                Err(invalid_data("invalid cluster session request"))
            }
        }
    }

    async fn receive_snapshot(&self, stream: &mut Connection, from: u64) -> io::Result<()> {
        self.check_repair_source(from)?;
        let endpoint = &self.mesh.endpoint;
        if self.store.status.borrow().retired.contains(&from) {
            return Err(invalid_data("retired node cannot send a snapshot"));
        }
        let (vote, meta): (VoteOf<Types>, SnapshotMeta) =
            endpoint.limits.read_control(stream).await?;
        self.check_snapshot_meta(vote, from, &meta)?;
        let (stored, data) = SnapshotData::receive(
            stream,
            self.store.dir().to_path_buf(),
            endpoint.max_snapshot_size,
        )
        .await?;
        if stored != meta {
            return Err(invalid_data(
                "snapshot metadata does not match the transfer header",
            ));
        }
        self.store.validate_snapshot(&data)?;
        let result = self
            .raft
            .install_full_snapshot(
                vote,
                Snapshot {
                    meta,
                    snapshot: data,
                },
            )
            .await;
        write_control(stream, &result).await
    }

    async fn write_remote(&self, from: u64, body: Bytes) -> Route<Option<Bytes>> {
        if let Err(error) = version::command::<S>(&body) {
            tracing::warn!(from, %error, "rejected cluster application command");
            return match error {
                ClusterError::UnsupportedVersion { version, .. } => {
                    Route::UnsupportedVersion(version)
                }
                _ => Route::Rejected,
            };
        }
        self.write(Command::App(body)).await
    }

    fn check_snapshot_meta(
        &self,
        vote: VoteOf<Types>,
        from: u64,
        meta: &SnapshotMeta,
    ) -> io::Result<()> {
        check_vote_sender(vote, from)?;
        let last = meta
            .last_log_id
            .ok_or_else(|| invalid_data("missing snapshot log id"))?;
        let membership_log = meta
            .last_membership
            .log_id()
            .ok_or_else(|| invalid_data("missing snapshot membership log id"))?;
        if !vote.committed
            || last.leader_id > vote.leader_id
            || last.index < membership_log.index
            || last < membership_log
        {
            return Err(invalid_data(
                "snapshot metadata is inconsistent with the leader or membership",
            ));
        }
        Ok(())
    }
}

type Peers = BTreeMap<u64, SocketAddr>;
type NodeIdentity = (Option<Peers>, Option<[u8; 32]>, bool, Option<Record>);

fn unusable_state(dir: &Path, node: u64, enabled: bool, error: ClusterError) -> ClusterError {
    let recoverable = match &error {
        ClusterError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::Other
        ),
        ClusterError::UnusableIdentity(_)
        | ClusterError::UnsupportedVersion { .. }
        | ClusterError::Raft(_) => true,
        _ => false,
    };
    if !enabled || !recoverable {
        return error;
    }
    tracing::warn!(node, %error, "Unusable local cluster state; discarding it and rejoining with empty state");
    let record = Record::new(None, SurvivorReason::UnusableState, None);
    match Switch::prepare(dir, node, record).and_then(Switch::commit) {
        Ok(()) => ClusterError::Restart,
        Err(error) => error.into(),
    }
}

fn load_identity(
    dir: &Path,
    node_id: u64,
    peers: &Peers,
    join: bool,
    generation: u64,
    wal: &Wal,
    auto_recover: bool,
) -> Result<NodeIdentity, ClusterError> {
    let path = dir.join(IDENTITY_FILE);
    let read = |path: &Path| {
        let mut bytes = Vec::new();
        open_private_file(path)?.read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    };
    let unusable = if auto_recover {
        ClusterError::UnusableIdentity
    } else {
        ClusterError::InvalidConfig
    };
    match read(&path) {
        Ok(identity) => {
            let (version, prior_id, bootstrap): (u8, u64, Bytes) = decode(&identity)?;
            if prior_id != node_id {
                return Err(unusable("data directory belongs to another node ID".into()));
            }
            match version {
                1 => Ok((
                    Some(decode(&bootstrap)?),
                    Some(Sha256::digest(&bootstrap).into()),
                    true,
                    None,
                )),
                2 | IDENTITY_VERSION => {
                    let digest = match read(&dir.join(CLUSTER_ID_FILE)) {
                        Ok(bytes) => Some(
                            bytes
                                .try_into()
                                .map_err(|_| invalid_data("invalid cluster identity"))?,
                        ),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                        Err(error) => return Err(error.into()),
                    };
                    let record = if version == IDENTITY_VERSION {
                        Some(Record::read(dir, digest)?)
                    } else {
                        None
                    };
                    Ok((None, digest, true, record))
                }
                version => Err(ClusterError::UnsupportedVersion {
                    kind: "node identity",
                    version: u16::from(version),
                }),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let has_snapshot = match dir.join(SNAPSHOT_FILE).symlink_metadata() {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if has_snapshot || wal.has_raft_state() {
                return Err(unusable(
                    "cluster data directory contains Raft state without a node identity".into(),
                ));
            }
            if !peers.contains_key(&node_id)
                || (join && peers.len() < 2)
                || (!join && generation != 0)
            {
                return Err(ClusterError::InvalidConfig("empty nodes require self in cluster_peer, generation zero for bootstrap, and an existing seed for join".into()));
            }
            let bootstrap = if join {
                Bytes::new()
            } else {
                encode(peers)?.into()
            };
            let digest = (!join).then(|| Sha256::digest(&bootstrap).into());
            let identity = encode(&(if join { 2u8 } else { 1u8 }, node_id, bootstrap))?;
            atomic_write(dir, IDENTITY_FILE, |file| file.write_all(&identity))?;
            Ok(((!join).then(|| peers.clone()), digest, false, None))
        }
        Err(error) => Err(error.into()),
    }
}

struct Request {
    id: u64,
    op: Op,
    frame: Frame,
}

async fn reply_to_appends<T, F>(
    calls: mpsc::Receiver<T>,
    responses: &mpsc::Sender<Response>,
    mut respond: impl FnMut(T) -> F,
) where
    F: Future<Output = Response>,
{
    // Buffered first-polls requests in wire order. OpenRaft enqueues each
    // request (in FIFO order even if its channel is full) before waiting
    // for the durable result. Do not spawn these requests out of order.
    let pipeline = unfold(calls, |mut calls| async {
        calls.recv().await.map(|request| (request, calls))
    })
    .map(|request| {
        let response = respond(request);
        // Send from the future, not from the ordered output stream. A heartbeat
        // for an already-durable index need not wait for an unrelated append.
        // The wire correlates replies by ID; the leader still yields the results
        // of each replication stream to OpenRaft in order.
        async move { responses.send(response.await).await }
    })
    .buffered(APPEND_WINDOW);
    let mut pipeline = std::pin::pin!(pipeline);
    while let Some(Ok(())) = pipeline.next().await {}
}

fn encode_command<S: StateMachine>(
    command: S::Command,
    max: usize,
    format: u16,
) -> Result<Bytes, ClusterError> {
    let body = version::encode(&command, S::WRITE_VERSION, format == 2)?;
    if body.len() > max {
        return Err(
            invalid_data("encoded application command exceeds configured size limit").into(),
        );
    }
    Ok(body)
}

fn decode_response<R: serde::de::DeserializeOwned>(
    response: Option<Bytes>,
) -> Result<R, ClusterError> {
    let body = response.ok_or_else(|| {
        ClusterError::WriteUncertain("leader returned no application response".into())
    })?;
    decode(&body).map_err(|error| ClusterError::WriteUncertain(error.to_string()))
}

fn check_vote_sender(vote: VoteOf<Types>, from: u64) -> io::Result<()> {
    if vote.leader_id.node_id != from {
        return Err(invalid_data(
            "Raft request vote does not belong to the sending member",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClusterSecurity, SnapshotPolicy};
    use openraft::alias::EntryOf;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};

    #[derive(Default)]
    struct Counter(u64);

    impl StateMachine for Counter {
        type Command = u64;
        type Response = (u64, u64);

        fn apply(&mut self, index: u64, increment: u64) -> Self::Response {
            self.0 += increment;
            (index, self.0)
        }

        fn snapshot(&self) -> Vec<u8> {
            encode(&self.0).unwrap()
        }

        fn restore(&mut self, bytes: &[u8]) -> Result<(), ClusterError> {
            self.0 = decode(bytes)?;
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn append_admission_is_fifo_but_ready_replies_do_not_wait_for_sync() {
        let (calls, incoming) = mpsc::channel(2);
        calls.try_send(1).unwrap();
        calls.try_send(2).unwrap();
        drop(calls);
        let (responses, mut replies) = mpsc::channel(2);
        let (release, stalled) = tokio::sync::oneshot::channel();
        let mut stalled = Some(stalled);
        let admitted = AtomicU64::new(0);
        let driver = reply_to_appends(incoming, &responses, |id| {
            let stalled = stalled.take();
            let admitted = &admitted;
            async move {
                assert_eq!(admitted.fetch_add(1, Ordering::Relaxed) + 1, id);
                if let Some(stalled) = stalled {
                    stalled.await.unwrap();
                }
                Response {
                    id,
                    body: Ok(Bytes::new()),
                }
            }
        });
        let caller = async move {
            assert_eq!(replies.recv().await.unwrap().id, 2);
            release.send(()).unwrap();
            assert_eq!(replies.recv().await.unwrap().id, 1);
        };
        timeout(Duration::from_secs(1), async {
            tokio::join!(driver, caller)
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_peer_dropped_by_a_fork_is_not_retired() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("old");
        let new = root.path().join("new");
        prepare_dir(&old, false).unwrap();
        prepare_dir(&new, false).unwrap();
        let peers = BTreeMap::from([
            (1, "127.0.0.1:1234".parse::<SocketAddr>().unwrap()),
            (2, "127.0.0.1:1235".parse::<SocketAddr>().unwrap()),
        ]);
        let mut store = Store::open(Counter::default(), old, 2).unwrap();
        let log_id = LogId::new(
            Leadership {
                term: 1,
                node_id: 1,
            },
            8,
        );
        let membership = MembershipOf::<Types>::from(
            peers
                .iter()
                .map(|(&id, address)| {
                    (
                        id,
                        BasicNode {
                            addr: address.to_string(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        );
        store
            .apply(futures_util::stream::iter([Ok((
                EntryOf::<Types> {
                    log_id,
                    payload: EntryPayloadOf::<Types>::Membership(membership),
                },
                None,
            ))]))
            .await
            .unwrap();
        store.fork_snapshot(&new, 1, peers.clone(), 2).unwrap();
        let forked = Store::open(Counter::default(), new, 2).unwrap();
        let s = forked.status.borrow();
        assert!(s.retired.is_empty());
        assert_eq!(s.members.keys().copied().collect::<Vec<_>>(), [1]);
        assert_eq!(s.desired, peers);
        validate_change(
            &s,
            &Desired {
                generation: 0,
                peers,
            },
        )
        .unwrap();
        assert_eq!(forked.last_applied().unwrap().index, 9);
        assert_eq!(forked.last_applied().unwrap().leader_id.term, 3);
    }

    #[tokio::test]
    async fn cached_admission_lease_does_not_extend_the_recovery_deadline() {
        let root = tempfile::tempdir().unwrap();
        let reserves: Vec<_> = (0..2)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: Peers = (1..=2)
            .zip(reserves.iter().map(|socket| socket.local_addr().unwrap()))
            .collect();
        drop(reserves);
        let nodes = futures_util::future::try_join_all(peers.iter().map(|(&id, &addr)| {
            let mut config = ClusterConfig::new(
                id,
                addr,
                peers.clone(),
                root.path().join(id.to_string()),
                ClusterSecurity::InsecurePlaintext,
            );
            config.lease_timeout = Duration::from_secs(5);
            Cluster::start(config, Counter::default())
        }))
        .await
        .unwrap();
        let [node, stopped] = nodes.as_slice() else {
            unreachable!()
        };
        for node in &nodes {
            timeout(
                Duration::from_secs(5),
                node.membership_control().wait_serving(),
            )
            .await
            .unwrap()
            .unwrap();
        }
        stopped.shutdown().await.unwrap();
        let core = &node.0.core;
        core.filter_lease_renewals.store(true, Ordering::Release);
        let renewal = Instant::now() - Duration::from_secs(2);
        core.safe_until
            .send_replace(Some(renewal + core.lease_window()));
        assert!(core.incarnation_probe(None).quorum);
        assert_eq!(
            core.recent_renewal(Instant::now(), Duration::from_secs(1)),
            None
        );
        let mut last_viable = renewal - Duration::from_secs(1);
        assert!(matches!(
            core.check_recovery(Duration::from_secs(1), &mut last_viable)
                .await
                .unwrap(),
            Some(IncarnationChange::Fork { .. })
        ));
        assert!(last_viable <= renewal);
        node.shutdown().await.unwrap();
    }

    #[test]
    fn a_cycle_of_three_branch_preferences_has_one_rejoin_target() {
        let root = Incarnation::original([7; 32]);
        let older_fork = root.clone().fork(2, Some(10)).unwrap();
        let newer_fork = root.clone().fork(3, Some(30)).unwrap();
        let probe = |identity, voters| Probe {
            identity: Some(identity),
            voters,
            committed: Some(20),
            ..Probe::default()
        };
        let probes = BTreeMap::from([
            (1, probe(root, 1)),
            (2, probe(older_fork, 2)),
            (3, probe(newer_fork, 1)),
        ]);
        assert!(probes[&1].wins_over(&probes[&2]));
        assert!(probes[&2].wins_over(&probes[&3]));
        assert!(probes[&3].wins_over(&probes[&1]));
        let mut targets = BTreeSet::new();
        for (&id, local) in &probes {
            let mut others = probes.clone();
            others.remove(&id);
            targets.insert(match Core::<Counter>::rejoin_choice(id, local, &others) {
                Some(IncarnationChange::Rejoin { peer, .. }) => peer,
                None => id,
                _ => unreachable!(),
            });
        }
        assert_eq!(
            targets.len(),
            1,
            "branches would abandon different winners: {targets:?}"
        );
    }

    #[tokio::test]
    async fn sole_voter_with_a_lost_rejoin_marker_can_serve_again() {
        let root = tempfile::tempdir().unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let peers = BTreeMap::from([(1, address)]);
        let mut config = ClusterConfig::new(
            1,
            address,
            peers.clone(),
            root.path().join("data"),
            ClusterSecurity::InsecurePlaintext,
        );
        config.auto_recover = true;
        config.auto_recover_timeout = Some(Duration::from_secs(1));
        let original = Cluster::start(config.clone(), Counter::default())
            .await
            .unwrap();
        original.membership_control().wait_serving().await.unwrap();
        original.submit(17).await.unwrap();
        original.shutdown().await.unwrap();
        let core = &original.0.core;
        // Disk image of a former learner, now the only committed voter. The
        // snapshot survived but the marker authorizing its promotion did not.
        let record = Record::new(
            core.mesh.endpoint.identity(),
            SurvivorReason::PeerWon,
            Some(2),
        );
        let switch = Switch::prepare(core.store.dir(), 1, record).unwrap();
        core.store
            .fork_snapshot(
                &switch.fresh(),
                1,
                peers,
                core.store.last_applied().unwrap().leader_id.term,
            )
            .unwrap();
        switch.commit().unwrap();

        let fenced = Cluster::start(config.clone(), Counter::default())
            .await
            .unwrap();
        let membership = fenced.membership_control();
        assert!(!membership.is_serving());
        timeout(Duration::from_secs(8), membership.wait_restart())
            .await
            .unwrap();
        assert!(matches!(
            fenced.shutdown().await,
            Err(ClusterError::Restart)
        ));
        let restored = Cluster::start(config, Counter::default()).await.unwrap();
        timeout(
            Duration::from_secs(5),
            restored.membership_control().wait_serving(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(restored.submit(1).await.unwrap().1, 18);
        restored.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_minority_incarnation_rejoins_the_majority_that_kept_committing() {
        let root = tempfile::tempdir().unwrap();
        let reserves: Vec<_> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: Peers = (1..=3)
            .zip(reserves.iter().map(|socket| socket.local_addr().unwrap()))
            .collect();
        drop(reserves);
        let configs: Vec<_> = peers
            .iter()
            .map(|(&id, &addr)| {
                let mut config = ClusterConfig::new(
                    id,
                    addr,
                    peers.clone(),
                    root.path().join(id.to_string()),
                    ClusterSecurity::InsecurePlaintext,
                );
                config.auto_recover = true;
                config.auto_recover_timeout = Some(Duration::from_secs(6));
                config.heartbeat_interval = Duration::from_millis(40);
                config.lease_interval = Duration::from_millis(120);
                config.lease_timeout = Duration::from_secs(1);
                config
            })
            .collect();
        let mut nodes = futures_util::future::try_join_all(
            configs
                .iter()
                .cloned()
                .map(|config| Cluster::start(config, Counter::default())),
        )
        .await
        .unwrap();
        for node in &nodes {
            timeout(
                Duration::from_secs(5),
                node.membership_control().wait_serving(),
            )
            .await
            .unwrap()
            .unwrap();
        }
        let isolated = nodes.pop().unwrap();
        nodes[0].submit(1).await.unwrap();
        assert_eq!(
            isolated
                .linearizable_read(|counter| counter.0)
                .await
                .unwrap(),
            1
        );
        isolated.shutdown().await.unwrap();
        let core = &isolated.0.core;
        let parent = core.mesh.endpoint.identity().unwrap();
        let applied = core.store.last_applied().unwrap();
        let fork = parent.fork(3, Some(applied.index)).unwrap();
        let switch = Switch::prepare(
            core.store.dir(),
            3,
            Record::new(Some(fork), SurvivorReason::PeerUnreachable, None),
        )
        .unwrap();
        core.store
            .fork_snapshot(&switch.fresh(), 3, peers, applied.leader_id.term)
            .unwrap();
        switch.commit().unwrap();

        // Let the original branch establish progress beyond the archived fork
        // point before bringing the divergent replica back.
        nodes[0].submit(41).await.unwrap();
        let config = configs[2].clone();
        assert!(matches!(
            Cluster::start(config.clone(), Counter::default()).await,
            Err(ClusterError::Restart)
        ));
        assert!(config.data_dir.join("discarded/snapshot.mpk").is_file());
        let recovered = Cluster::start(config, Counter::default()).await.unwrap();
        timeout(
            Duration::from_secs(8),
            recovered.membership_control().wait_serving(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recovered.metrics().incarnation, 0);
        assert_eq!(recovered.voter_ids(), [1, 2, 3]);
        assert_eq!(
            recovered
                .linearizable_read(|counter| counter.0)
                .await
                .unwrap(),
            42
        );
        recovered.shutdown().await.unwrap();
        for node in nodes {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_join_interrupted_before_writing_identity_can_restart() {
        let root = tempfile::tempdir().unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserve.local_addr().unwrap();
        let peers = BTreeMap::from([(1, address), (2, "127.0.0.1:1".parse().unwrap())]);
        drop(reserve);
        let mut config = ClusterConfig::new(
            1,
            address,
            peers,
            root.path().join("data"),
            ClusterSecurity::InsecurePlaintext,
        );
        config.join = true;
        Wal::open(&config.data_dir.join("wal"), config.max_append_size, 2)
            .unwrap()
            .close()
            .await
            .unwrap();
        crate::snapshot::private_tempfile(&config.data_dir)
            .unwrap()
            .keep()
            .unwrap();

        let node = Cluster::start(config.clone(), Counter::default())
            .await
            .unwrap();
        assert!(config.data_dir.join(IDENTITY_FILE).is_file());
        assert!(node.members().is_empty());
        node.shutdown().await.unwrap();

        config.data_dir = root.path().join("unidentified");
        let mut wal = Wal::open(&config.data_dir.join("wal"), config.max_append_size, 2).unwrap();
        wal.save_vote(&VoteOf::<Types>::new_committed(1, 1))
            .await
            .unwrap();
        wal.close().await.unwrap();
        assert!(matches!(
            Cluster::start(config.clone(), Counter::default()).await,
            Err(ClusterError::InvalidConfig(_))
        ));
        assert!(!config.data_dir.join(IDENTITY_FILE).exists());
    }

    #[tokio::test]
    async fn an_isolated_lease_holder_self_fences_and_catches_up_before_serving_again() {
        let root = tempfile::tempdir().unwrap();
        let reserves: Vec<_> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: BTreeMap<_, _> = (1..=3)
            .zip(reserves.iter().map(|socket| socket.local_addr().unwrap()))
            .collect();
        drop(reserves);
        let nodes = futures_util::future::try_join_all(peers.iter().map(|(&id, &addr)| {
            let mut config = ClusterConfig::new(
                id,
                addr,
                peers.clone(),
                root.path().join(id.to_string()),
                ClusterSecurity::InsecurePlaintext,
            );
            config.heartbeat_interval = Duration::from_millis(30);
            config.election_timeout_min = Duration::from_millis(140);
            config.election_timeout_max = Duration::from_millis(260);
            config.lease_interval = Duration::from_millis(60);
            config.lease_timeout = Duration::from_millis(800);
            Cluster::start(config, Counter::default())
        }))
        .await
        .unwrap();
        let wait = Duration::from_secs(5);
        for node in &nodes {
            timeout(wait, node.membership_control().wait_serving())
                .await
                .unwrap()
                .unwrap();
        }
        let leader_id = nodes[0].leader().unwrap();
        let leader = nodes
            .iter()
            .find(|node| node.node_id() == leader_id)
            .unwrap();
        let isolated = nodes
            .iter()
            .find(|node| node.node_id() != leader_id)
            .unwrap();
        let membership = isolated.membership_control();
        assert!(membership.lease_valid_until().is_some());
        let mut events = leader.subscribe_node_events();

        // Partition the lease lane, leaving Raft replication and the old
        // application task alive. Killing the owner would not test self-fencing.
        isolated
            .0
            .core
            .filter_lease_renewals
            .store(true, std::sync::atomic::Ordering::Release);
        timeout(wait, membership.wait_lease_invalid())
            .await
            .unwrap();
        assert_eq!(
            leader.voter_status(isolated.node_id()),
            Some(NodeStatus::Alive)
        );
        timeout(wait, async {
            loop {
                let event = events.recv().await.unwrap();
                if event.node_id == isolated.node_id() && event.status == NodeStatus::Down {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(membership.lease_valid_until().is_none());
        let mut serving = isolated.0.core.serving.subscribe();
        drop(
            timeout(wait, serving.wait_for(|state| *state == Serving::Waiting))
                .await
                .unwrap()
                .unwrap(),
        );

        // Pause replication's apply worker, without blocking the lease or
        // readiness tasks. The leader can renew our lease but we still have
        // the state from before the missed write, as on a stale restart.
        let (paused, sm_paused) = tokio::sync::oneshot::channel();
        let (resume, sm_resume) = tokio::sync::oneshot::channel();
        isolated
            .0
            .core
            .raft
            .external_state_machine_request(move |_| {
                Box::pin(async move {
                    let _ = paused.send(());
                    let _ = sm_resume.await;
                })
            })
            .await
            .unwrap();
        timeout(wait, sm_paused).await.unwrap().unwrap();
        let (index, _) = leader.submit(1).await.unwrap();
        isolated
            .0
            .core
            .filter_lease_renewals
            .store(false, std::sync::atomic::Ordering::Release);
        timeout(wait, async {
            loop {
                let event = events.recv().await.unwrap();
                if event.node_id == isolated.node_id() && event.status == NodeStatus::Alive {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(
            timeout(Duration::from_millis(500), membership.wait_serving())
                .await
                .is_err()
        );
        assert_eq!(isolated.read(|counter| counter.0), 0);
        resume.send(()).unwrap();
        timeout(wait, membership.wait_serving())
            .await
            .unwrap()
            .unwrap();
        assert!(isolated.metrics().applied_index.unwrap() >= index);
        assert_eq!(isolated.read(|counter| counter.0), 1);
        for node in &nodes {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn an_expired_lease_requires_catchup_even_before_the_serving_flag_changes() {
        let root = tempfile::tempdir().unwrap();
        let reserves: Vec<_> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: BTreeMap<_, _> = (1..=3)
            .zip(reserves.iter().map(|socket| socket.local_addr().unwrap()))
            .collect();
        drop(reserves);
        let nodes = futures_util::future::try_join_all(peers.iter().map(|(&id, &addr)| {
            Cluster::start(
                ClusterConfig::new(
                    id,
                    addr,
                    peers.clone(),
                    root.path().join(id.to_string()),
                    ClusterSecurity::InsecurePlaintext,
                ),
                Counter::default(),
            )
        }))
        .await
        .unwrap();
        let wait = Duration::from_secs(5);
        for node in &nodes {
            timeout(wait, node.membership_control().wait_serving())
                .await
                .unwrap()
                .unwrap();
        }
        let leader_id = nodes[0].leader().unwrap();
        let leader = nodes
            .iter()
            .find(|node| node.node_id() == leader_id)
            .unwrap();
        let isolated = nodes
            .iter()
            .find(|node| node.node_id() != leader_id)
            .unwrap();
        let core = &isolated.0.core;
        core.filter_lease_renewals
            .store(true, std::sync::atomic::Ordering::Release);

        let (paused, sm_paused) = tokio::sync::oneshot::channel();
        let (resume, sm_resume) = tokio::sync::oneshot::channel();
        core.raft
            .external_state_machine_request(move |_| {
                Box::pin(async move {
                    let _ = paused.send(());
                    let _ = sm_resume.await;
                })
            })
            .await
            .unwrap();
        timeout(wait, sm_paused).await.unwrap().unwrap();
        leader.submit(1).await.unwrap();
        assert_eq!(isolated.read(|counter| counter.0), 0);

        // A renewal can be in flight when the readiness deadline passes, but
        // the periodic renewal loop has not changed its serving flag yet.
        core.safe_until.send_replace(Some(Instant::now()));
        assert_eq!(*core.serving.borrow(), Serving::Active);
        assert!(isolated.membership_control().lease_valid_until().is_none());
        let renewal = core.renew_lease(leader_id, Instant::now() + wait);
        assert!(
            timeout(Duration::from_millis(500), renewal).await.is_err(),
            "the follower renewed admission without applying the missed write"
        );

        resume.send(()).unwrap();
        assert!(
            timeout(wait, core.renew_lease(leader_id, Instant::now() + wait))
                .await
                .unwrap()
        );
        assert_eq!(isolated.read(|counter| counter.0), 1);
        for node in &nodes {
            node.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn simultaneous_lease_expiries_share_a_sync_and_replay_after_a_crash() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let mut config = ClusterConfig::new(
            1,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::from([(1, "127.0.0.1:1".parse().unwrap())]),
            data.clone(),
            ClusterSecurity::InsecurePlaintext,
        );
        config.snapshot_policy = SnapshotPolicy::Never;
        config.lease_interval = Duration::from_secs(60);
        config.lease_timeout = Duration::from_secs(120);
        let max_append_size = config.max_append_size;
        let node = Cluster::start(config, Counter::default()).await.unwrap();
        timeout(
            Duration::from_secs(5),
            node.membership_control().wait_serving(),
        )
        .await
        .unwrap()
        .unwrap();
        let core = &node.0.core;
        for id in 2..=3 {
            core.raft
                .add_learner(
                    id,
                    BasicNode {
                        addr: format!("127.0.0.1:{id}"),
                    },
                    false,
                )
                .await
                .unwrap();
        }

        let mut events = core.store.events.subscribe();
        let before = node.wal_metrics().await.unwrap();
        core.expire_leases_once(core.leadership().unwrap(), 120_000)
            .await;
        let expired = node.wal_metrics().await.unwrap();
        assert_eq!(expired.appended_entries, before.appended_entries + 2);
        assert_eq!(expired.sync_batches, before.sync_batches + 1);
        let downs = [events.try_recv().unwrap(), events.try_recv().unwrap()];
        assert_eq!(
            downs.map(|e| (e.node_id, e.status)),
            [(2, NodeStatus::Down), (3, NodeStatus::Down)]
        );
        assert_eq!(downs[1].index, downs[0].index + 1);

        // The next required sync carries the expiry batch's committed index.
        // Copy the resulting image before graceful shutdown can log a newer
        // commit index; then replay it without a live quorum or a snapshot.
        assert_eq!(node.submit(7).await.unwrap(), (downs[1].index + 1, 7));
        let image = root.path().join("crashed");
        std::fs::create_dir_all(image.join("wal")).unwrap();
        for file in data.join("wal").read_dir().unwrap() {
            let file = file.unwrap();
            std::fs::copy(file.path(), image.join("wal").join(file.file_name())).unwrap();
        }
        let mut wal = Wal::open(&image.join("wal"), max_append_size, 2).unwrap();
        assert_eq!(
            wal.read_committed().await.unwrap().unwrap().index,
            downs[1].index
        );
        let mut replay = Store::open(Counter::default(), image, 2).unwrap();
        let mut replayed_events = replay.events.subscribe();
        openraft::storage::StorageHelper::new(&mut wal, &mut replay)
            .with_id(1)
            .get_initial_state()
            .await
            .unwrap();
        let replayed_downs = std::iter::from_fn(|| replayed_events.try_recv().ok())
            .filter(|event| event.status == NodeStatus::Down)
            .collect::<Vec<_>>();
        assert_eq!(replayed_downs, downs);
        assert_eq!(replay.last_applied().unwrap().index, downs[1].index);
        assert_eq!(replay.state.read().unwrap().app.0, 0);
        wal.close().await.unwrap();
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn remote_schema_mismatch_is_rejected_before_proposal() {
        // A single voter never dials its advertised address. Let the OS
        // choose the listening port at bind time instead of racing to rebind.
        let root = tempfile::tempdir().unwrap();
        let mut config = ClusterConfig::new(
            1,
            "127.0.0.1:0".parse().unwrap(),
            BTreeMap::from([(1, "127.0.0.1:1".parse().unwrap())]),
            root.path().join("data"),
            ClusterSecurity::InsecurePlaintext,
        );
        config.snapshot_policy = SnapshotPolicy::Never;
        config.lease_interval = Duration::from_secs(60);
        config.lease_timeout = Duration::from_secs(120);
        let node = Cluster::start(config, Counter::default()).await.unwrap();
        // The initial lease renewal also writes a log entry. Wait for it
        // before checking that the rejected proposal leaves no gap.
        timeout(
            Duration::from_secs(5),
            node.membership_control().wait_serving(),
        )
        .await
        .unwrap()
        .unwrap();
        let (index, total) = node.submit(1).await.unwrap();
        assert_eq!(total, 1);
        let core = &node.0.core;
        let response = core
            .write_remote(1, encode(&"not a counter command").unwrap().into())
            .await;
        assert!(matches!(response, Route::Rejected));
        assert_eq!(node.submit(2).await.unwrap(), (index + 1, 3));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_unknown_application_version_stops_replay_before_mutating_state() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(Counter::default(), root.path().to_path_buf(), 2).unwrap();
        let leader = Leadership {
            term: 1,
            node_id: 1,
        };
        let entry = |index, body: Vec<u8>| {
            Ok((
                EntryOf::<Types> {
                    log_id: LogId::new(leader, index),
                    payload: EntryPayloadOf::<Types>::Normal(Command::App(body.into())),
                },
                None,
            ))
        };
        let error = store
            .apply(futures_util::stream::iter([
                entry(1, encode(&1u64).unwrap()),
                entry(2, version::encode(&999u64, 50, true).unwrap().to_vec()),
                entry(3, encode(&2u64).unwrap()),
            ]))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported application command version 50")
        );
        assert_eq!(store.applied_state().await.unwrap().0.unwrap().index, 1);
        assert_eq!(store.state.read().unwrap().app.0, 1);
    }

    #[test]
    fn cannot_start_with_an_unknown_application_snapshot_version() {
        let root = tempfile::tempdir().unwrap();
        SnapshotData::build(
            root.path(),
            "snapshot.mpk",
            &SnapshotMeta::default(),
            Bytes::new(),
            &[],
            (2, 50),
        )
        .unwrap();
        let error = Store::open(Counter::default(), root.path().to_path_buf(), 2)
            .err()
            .expect("the unknown application snapshot must refuse startup");
        assert!(
            error
                .to_string()
                .contains("unsupported application snapshot version 50")
        );
    }
}
