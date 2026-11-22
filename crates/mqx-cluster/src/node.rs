use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt, unfold};
use openraft::alias::{EntryPayloadOf, LeaderIdOf, LogIdOf, MembershipOf, VoteOf};
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ClientWriteError, InitializeError, LinearizableReadError, RaftError};
use openraft::raft::{
    AppendEntriesRequest, Precondition, StreamAppendResult, TransferLeaderRequest, VoteRequest,
};
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
    RETIRED_FILE, Snapshot, SnapshotMeta, Store, TEMP_FILE_PREFIX, atomic_write, open_private_file,
    prepare_dir,
};
use crate::snapshot_file::SnapshotData;
use crate::transport::{
    APPEND_WINDOW, CLUSTER_ID_FILE, Connection, Endpoint, Frame, Limits, Network, Op, decode,
    encode, invalid_data, write_control,
};
use crate::wal::{Wal, WalMetrics};
use crate::{ClusterConfig, ClusterError, Mesh, NodeEvent, NodeStatus, StateMachine, version};

const IDENTITY_FILE: &str = "node.mpk";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_WINDOW: usize = 256;
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
    #[cfg(test)]
    filter_lease_renewals: std::sync::atomic::AtomicBool,
    heartbeat_interval: Duration,
    request_timeout: Duration,
    snapshot_timeout: Duration,
    lease_interval: Duration,
    lease_timeout: Duration,
    clock_origin: Instant,
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
        let requested = (membership_generation != 0).then(|| Desired {
            generation: membership_generation,
            peers: peers.clone(),
        });
        let (endpoint, wal, store, initial, existing) = tokio::task::spawn_blocking(move || {
            let tls = Tls::load(&security, node_id)?;
            let limits = Limits {
                command: max_command_size,
                append: max_append_size,
                mesh: max_mesh_size,
            };
            prepare_dir(&data_dir, false)?;
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
                    {
                        continue;
                    }
                    return Err(ClusterError::InvalidConfig(
                        "a new joining node needs an empty data directory".into(),
                    ));
                }
            }
            let wal = Wal::open(&data_dir.join("wal"), max_append_size, state_format)?;
            if new_join && wal.has_raft_state() {
                return Err(ClusterError::InvalidConfig(
                    "a new joining node cannot adopt a WAL without a node identity".into(),
                ));
            }
            let (initial, digest, existing) =
                load_identity(&data_dir, node_id, &peers, join, membership_generation)?;
            let store = Store::open(state_machine, data_dir.clone(), state_format)?;
            if store.status.borrow().retired.contains(&node_id) {
                return Err(ClusterError::Removed(node_id));
            }
            let endpoint = Arc::new(Endpoint::new(
                node_id,
                peers,
                (data_dir, digest),
                store.status.subscribe(),
                tls,
                max_snapshot_size,
                limits,
            ));
            Ok((endpoint, wal, store, initial, existing))
        })
        .await
        .map_err(io::Error::other)??;
        let raft = Raft::build(
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
        .map_err(|error| ClusterError::Raft(error.to_string()))?;
        if store.status.borrow().retired.contains(&node_id) {
            return Err(ClusterError::Removed(node_id));
        }
        let core = Arc::new(Core {
            raft,
            store,
            mesh: Mesh::new(endpoint, request_timeout),
            requested: watch::channel(requested).0,
            serving: watch::channel(Serving::Waiting).0,
            safe_until: watch::channel(None).0,
            #[cfg(test)]
            filter_lease_renewals: std::sync::atomic::AtomicBool::new(false),
            heartbeat_interval,
            request_timeout,
            snapshot_timeout,
            lease_interval,
            lease_timeout,
            clock_origin: Instant::now(),
        });
        core.raft.run();
        let driver = tokio::spawn(core.clone().run(listener, wal.clone()));
        let cluster = Self(Arc::new(Node {
            core,
            wal,
            driver: Mutex::new(Some(driver)),
        }));
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

    async fn renew_leases(&self) -> Result<(), ClusterError> {
        let mut applied = self.store.status.subscribe();
        let node_id = self.mesh.endpoint.node_id;
        let mut next = Instant::now();
        let mut last_renewal = next;
        let mut next_probe = next;
        loop {
            tokio::select! {
                retired = async { applied.wait_for(|status| status.retired.contains(&node_id)).await.is_ok() } => {
                    if retired {
                        return self.retire().await;
                    }
                    return Ok(());
                },
                _ = tokio::time::sleep_until(next) => {},
            }
            let started = Instant::now();
            let deadline = started + self.lease_interval;
            let leader = self.current_leader();
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
            if renewed && self.is_voter(node_id) {
                last_renewal = Instant::now();
                // The leader's expiry clock cannot start before we issue this
                // renewal. Don't extend local ownership by RPC or apply latency.
                let margin = (self.lease_timeout / 4).min(Duration::from_millis(100));
                self.safe_until
                    .send_replace(Some(started + (self.lease_timeout - margin)));
                self.serving.send_if_modified(|state| {
                    let changed = *state == Serving::Waiting;
                    if changed {
                        *state = Serving::Active;
                    }
                    changed
                });
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
                if self.store.format == 2 && Instant::now() >= next_probe {
                    next_probe =
                        Instant::now() + self.lease_interval.max(Duration::from_millis(200));
                    if self.probe_retired().await {
                        return self.retire().await;
                    }
                }
            }
            next = Instant::now()
                + if *self.serving.borrow() == Serving::Waiting {
                    self.heartbeat_interval.min(self.lease_interval)
                } else {
                    self.lease_interval
                };
        }
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
        if !renewed || *self.serving.borrow() != Serving::Waiting {
            return renewed;
        }

        // A leader can renew our lease while this replica is still reading
        // its pre-restart state. Fence admission on a fresh quorum read and
        // apply through that index locally before first serving again.
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
                for command in self.store.expire(self.stamp(leader), timeout_ms) {
                    let _ =
                        timeout(self.request_timeout, self.write(Command::Lease(command))).await;
                }
            }
        }
    }

    async fn run(self: Arc<Self>, listener: TcpListener, wal: Wal) -> Result<(), ClusterError> {
        let mut stop = self.mesh.stop.subscribe();
        let (_, membership) = tokio::join!(self.serve(listener), async {
            let result = tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => Ok(()),
                result = self.renew_leases() => result,
                _ = self.expire_leases() => Ok(()),
                _ = self.reconcile_loop() => Ok(()),
            };
            self.mesh.stop.send_replace(true);
            result
        });
        let result = self.raft.try_shutdown().await;
        self.mesh.endpoint.close().await;
        self.store.close().await?;
        wal.close().await?;
        membership?;
        result.map_err(|error| ClusterError::Raft(error.to_string()))
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
            _ => Err(invalid_data("RPC requires an established cluster session")),
        }
    }

    async fn run_session(
        self: &Arc<Self>,
        mut stream: Connection,
        from: u64,
        deadline: Instant,
    ) -> io::Result<()> {
        // A successor connection cannot overtake mesh work already being handled
        // on the previous connection. The old reader and ordered worker both exit
        // before this guard is released.
        let _session = self.mesh.endpoint.accept_session(from)?;
        timeout_at(deadline, async {
            stream.write_u8(0).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        let (reader, writer) = tokio::io::split(stream);
        let (responses, replies) = mpsc::channel(SESSION_WINDOW);
        let (mesh, mesh_rx) = mpsc::channel(SESSION_WINDOW);
        let (append, append_rx) = mpsc::channel(SESSION_WINDOW);
        tokio::select! {
            result = write_responses(writer, replies, self.request_timeout) => result,
            result = self.read_calls(reader, from, &responses, mesh, append) => result,
            () = self.run_ordered(from, mesh_rx, &responses) => Ok(()),
            () = self.run_appends(from, append_rx, &responses) => Ok(()),
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
            let mut id = [0; 8];
            id[0] = reader.read_u8().await?;
            let request = timeout(self.request_timeout, async {
                reader.read_exact(&mut id[1..]).await?;
                let id = u64::from_be_bytes(id);
                let op = Op::try_from(reader.read_u8().await?)?;
                if id <= latest || matches!(op, Op::Session | Op::Snapshot) {
                    return Err(invalid_data("invalid cluster session request"));
                }
                let frame = limits
                    .read_frame(&mut reader, limits.request(op), matches!(op, Op::Append))
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

    async fn run_appends(
        &self,
        from: u64,
        calls: mpsc::Receiver<Request>,
        responses: &mpsc::Sender<Response>,
    ) {
        // Poll each request first in wire order. OpenRaft queues it to RaftCore
        // before waiting on the durable response. Do not wait for one WAL sync
        // before admitting the next request from the same leader.
        let pipeline = unfold(calls, |mut calls| async {
            calls.recv().await.map(|request| (request, calls))
        })
        .map(|request| self.rpc_response(from, request))
        .buffered(APPEND_WINDOW);
        let mut pipeline = std::pin::pin!(pipeline);
        while let Some(response) = pipeline.next().await {
            if responses.send(response).await.is_err() {
                break;
            }
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
            Op::Session | Op::Snapshot | Op::Retired => {
                Err(invalid_data("invalid cluster session request"))
            }
        }
    }

    async fn receive_snapshot(&self, stream: &mut Connection, from: u64) -> io::Result<()> {
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
type NodeIdentity = (Option<Peers>, Option<[u8; 32]>, bool);

fn load_identity(
    dir: &Path,
    node_id: u64,
    peers: &Peers,
    join: bool,
    generation: u64,
) -> Result<NodeIdentity, ClusterError> {
    let path = dir.join(IDENTITY_FILE);
    let read = |path: &Path| {
        let mut bytes = Vec::new();
        open_private_file(path)?.read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    };
    match read(&path) {
        Ok(identity) => {
            let (version, prior_id, bootstrap): (u8, u64, Bytes) = decode(&identity)?;
            if prior_id != node_id {
                return Err(ClusterError::InvalidConfig(
                    "data directory belongs to another node ID".into(),
                ));
            }
            match version {
                1 => Ok((
                    Some(decode(&bootstrap)?),
                    Some(Sha256::digest(&bootstrap).into()),
                    true,
                )),
                2 => {
                    let digest = match read(&dir.join(CLUSTER_ID_FILE)) {
                        Ok(bytes) => Some(
                            bytes
                                .try_into()
                                .map_err(|_| invalid_data("invalid cluster identity"))?,
                        ),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                        Err(error) => return Err(error.into()),
                    };
                    Ok((None, digest, true))
                }
                version => Err(ClusterError::UnsupportedVersion {
                    kind: "node identity",
                    version: u16::from(version),
                }),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
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
            Ok(((!join).then(|| peers.clone()), digest, false))
        }
        Err(error) => Err(error.into()),
    }
}

struct Request {
    id: u64,
    op: Op,
    frame: Frame,
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
    async fn remote_schema_mismatch_is_rejected_before_proposal() {
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserve.local_addr().unwrap();
        drop(reserve);
        let root = tempfile::tempdir().unwrap();
        let mut config = ClusterConfig::new(
            1,
            address,
            BTreeMap::from([(1, address)]),
            root.path().join("data"),
            ClusterSecurity::InsecurePlaintext,
        );
        config.snapshot_policy = SnapshotPolicy::Never;
        config.lease_interval = Duration::from_secs(60);
        config.lease_timeout = Duration::from_secs(120);
        let node = Cluster::start(config, Counter::default()).await.unwrap();
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
