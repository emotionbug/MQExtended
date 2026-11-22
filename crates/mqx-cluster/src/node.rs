use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use openraft::alias::{LeaderIdOf, LogIdOf, VoteOf};
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ClientWriteError, InitializeError, LinearizableReadError, RaftError};
use openraft::raft::StreamAppendResult;
use openraft::{BasicNode, Raft, ReadPolicy, ServerState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, timeout, timeout_at};

use crate::lease::{LeaseCommand, Leases, Stamp};
use crate::snapshot::{Snapshot, SnapshotData, SnapshotMeta, Store, atomic_write};
use crate::transport::{
    Endpoint, MAX_COMMAND, MAX_FRAME, MAX_SNAPSHOT, Network, Op, decode, encode, invalid_data,
    read_frame, read_message, write_frame, write_message,
};
use crate::wal::Wal;
use crate::{ClusterConfig, ClusterError, Mesh, NodeEvent, NodeStatus, StateMachine};

const IDENTITY_FILE: &str = "node.mpk";
const MAX_CONNECTIONS: usize = 512;
pub(crate) type Leadership = LeaderIdOf<Types>;
pub(crate) type LogId = LogIdOf<Types>;
type WriteResponse = Result<Option<Bytes>, String>;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum Command {
    App(Bytes),
    Lease(LeaseCommand),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::App(body) => write!(f, "application command ({} bytes)", body.len()),
            Self::Lease(_) => f.write_str("node lease command"),
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
    request_timeout: Duration,
    snapshot_timeout: Duration,
    lease_interval: Duration,
    lease_timeout: Duration,
    clock_origin: Instant,
}

impl<S: StateMachine> Cluster<S> {
    /// Start listening and recover the latest durable state. This does not wait for a leader.
    /// All nodes must use the same static peer configuration, even on a cold start.
    pub async fn start(config: ClusterConfig, state_machine: S) -> Result<Self, ClusterError> {
        let raft_config = Arc::new(config.raft_config()?);
        let listener = TcpListener::bind(config.raft_addr).await?;
        let ClusterConfig {
            node_id,
            data_dir,
            peers,
            request_timeout,
            snapshot_timeout,
            lease_interval,
            lease_timeout,
            ..
        } = config;
        let peer_bytes = encode(&peers)?;
        let membership_digest = Sha256::digest(&peer_bytes).into();
        let endpoint = Arc::new(Endpoint {
            node_id,
            peers,
            membership_digest,
        });
        let storage_endpoint = endpoint.clone();
        let (wal, store) = tokio::task::spawn_blocking(move || {
            let wal = Wal::open(&data_dir.join("wal"))?;
            let identity = encode(&(1u8, node_id, Bytes::from(peer_bytes)))?;
            match fs::read(data_dir.join(IDENTITY_FILE)) {
                Ok(existing) if existing == identity => {}
                Ok(_) => {
                    return Err(ClusterError::InvalidConfig(
                        "data directory belongs to another node or peer configuration".into(),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    atomic_write(&data_dir, IDENTITY_FILE, |file| file.write_all(&identity))?;
                }
                Err(error) => return Err(error.into()),
            }
            let leases = Leases::new(storage_endpoint.peers.keys().copied());
            Ok((wal, Store::open(state_machine, data_dir, leases)?))
        })
        .await
        .map_err(io::Error::other)??;
        let raft = Raft::build(
            node_id,
            raft_config,
            Network(endpoint.clone()),
            wal.clone(),
            store.clone(),
        )
        .await
        .map_err(|error| ClusterError::Raft(error.to_string()))?;
        let core = Arc::new(Core {
            raft,
            store,
            mesh: Mesh::new(endpoint, request_timeout),
            request_timeout,
            snapshot_timeout,
            lease_interval,
            lease_timeout,
            clock_origin: Instant::now(),
        });
        core.raft.run();
        let driver = tokio::spawn(core.clone().run(listener, wal));
        let cluster = Self(Arc::new(Node {
            core,
            driver: Mutex::new(Some(driver)),
        }));
        let members: BTreeMap<_, _> = cluster
            .members()
            .iter()
            .map(|(&id, address)| {
                (
                    id,
                    BasicNode {
                        addr: address.to_string(),
                    },
                )
            })
            .collect();
        // OpenRaft permits concurrent initialization with identical membership. A vote,
        // snapshot or WAL entry from a previous run fences out another initialization.
        match cluster.0.core.raft.initialize(members).await {
            Ok(()) | Err(RaftError::APIError(InitializeError::NotAllowed(_))) => Ok(cluster),
            Err(error) => {
                let _ = cluster.shutdown().await;
                Err(ClusterError::Raft(error.to_string()))
            }
        }
    }

    /// Commit an application command on any member and return the leader's result.
    /// Retries definitive redirects and failed connections until the request deadline.
    /// A lost reply or interrupted in-flight proposal returns `WriteUncertain`; retry
    /// only if the application command is idempotent or has a replicated deduplication key.
    ///
    /// The MessagePack command must fit in 8 MiB.
    pub async fn submit(&self, command: S::Command) -> Result<S::Response, ClusterError> {
        let body = encode_command(command)?;
        let core = &self.0.core;
        let deadline = Instant::now() + core.request_timeout;
        let mut hint = None;
        loop {
            core.check_running()?;
            let target = core.target(hint.take());
            let response = if target == self.node_id() {
                core.write_local(body.clone(), deadline).await?
            } else {
                let mut stream = match core.connect(target, deadline).await {
                    Ok(stream) => stream,
                    Err(_) => {
                        core.retry_pause(deadline).await?;
                        continue;
                    }
                };
                timeout_at(deadline, async {
                    core.mesh
                        .endpoint
                        .header(&mut stream, target, Op::Write)
                        .await?;
                    write_frame(&mut stream, &body, MAX_COMMAND).await?;
                    read_message(&mut stream).await
                })
                .await
                .map_err(|_| ClusterError::WriteUncertain("forwarded proposal timed out".into()))?
                .map_err(|error| ClusterError::WriteUncertain(error.to_string()))?
            };
            match response {
                Route::Value(response) => return decode_response(response),
                Route::Redirect(leader) => hint = leader,
                Route::Retry => {}
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
        let body = encode_command(command)?;
        let deadline = Instant::now() + core.request_timeout;
        match core.write_local(body, deadline).await? {
            Route::Value(response) => decode_response(response).map(Some),
            Route::Redirect(_) => Ok(None),
            Route::Retry => Err(ClusterError::Deadline),
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
                Route::Retry | Route::Failed(_) => {}
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

    pub fn members(&self) -> &BTreeMap<u64, SocketAddr> {
        &self.0.core.mesh.endpoint.peers
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
}

impl<S: StateMachine> Core<S> {
    fn check_running(&self) -> Result<(), ClusterError> {
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
        hint.filter(|id| self.mesh.endpoint.peers.contains_key(id))
            .or_else(|| self.current_leader())
            .unwrap_or(self.mesh.endpoint.node_id)
    }

    fn current_leader(&self) -> Option<u64> {
        self.raft.metrics().borrow_watched().current_leader
    }

    async fn connect(&self, target: u64, deadline: Instant) -> io::Result<TcpStream> {
        // A stale leader with an unreachable address must not consume the whole
        // deadline while newer leader information is arriving through Raft.
        self.mesh
            .endpoint
            .connect(
                target,
                deadline.min(Instant::now() + self.lease_interval.min(Duration::from_millis(200))),
            )
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
        let mut stream = self.connect(target, deadline).await?;
        timeout_at(deadline, async {
            self.mesh
                .endpoint
                .header(&mut stream, target, Op::ReadIndex)
                .await?;
            read_message(&mut stream).await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
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
        let Some(leader) = self.leadership() else {
            return Route::Redirect(self.current_leader());
        };
        let stamp = self.stamp(leader);
        self.write(Command::Lease(LeaseCommand::Heartbeat { node_id, stamp }))
            .await
    }

    async fn renew_leases(&self) {
        let mut ticks = tokio::time::interval(self.lease_interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let node_id = self.mesh.endpoint.node_id;
        loop {
            ticks.tick().await;
            let Some(leader) = self.current_leader() else {
                continue;
            };
            let deadline = Instant::now() + self.lease_interval;
            if leader == node_id {
                let _ = timeout_at(deadline, self.heartbeat(node_id)).await;
            } else if let Ok(mut stream) = self.connect(leader, deadline).await {
                let _ = timeout_at(deadline, async {
                    self.mesh
                        .endpoint
                        .header(&mut stream, leader, Op::Lease)
                        .await?;
                    read_message::<Route<Option<Bytes>>>(&mut stream).await
                })
                .await;
            }
        }
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
        tokio::join!(self.serve(listener), async {
            tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => {},
                _ = self.renew_leases() => {},
                _ = self.expire_leases() => {},
            }
        });
        let result = self.raft.try_shutdown().await;
        self.store.close().await?;
        wal.close().await?;
        result.map_err(|error| ClusterError::Raft(error.to_string()))
    }

    async fn serve(self: &Arc<Self>, listener: TcpListener) {
        let mut handlers = JoinSet::new();
        let mut stop = self.mesh.stop.subscribe();
        loop {
            tokio::select! {
                biased;
                _ = async { let _ = stop.wait_for(|stopped| *stopped).await; } => break,
                Some(done) = handlers.join_next(), if !handlers.is_empty() => {
                    if let Err(error) = done { tracing::debug!(%error, "cluster RPC task stopped"); }
                }
                accepted = listener.accept(), if handlers.len() < MAX_CONNECTIONS => {
                    let core = self.clone();
                    match accepted {
                        Ok((stream, _)) => { handlers.spawn(async move {
                            if let Err(error) = core.connection(stream).await {
                                tracing::debug!(%error, "cluster RPC failed");
                            }
                        }); }
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

    async fn connection(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        let (from, op) = timeout(
            self.request_timeout,
            self.mesh.endpoint.accept_header(&mut stream),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        let budget = if matches!(op, Op::Snapshot) {
            self.snapshot_timeout
        } else {
            self.request_timeout
        };
        timeout(budget, self.dispatch(&mut stream, from, op))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
    }

    async fn dispatch(&self, stream: &mut TcpStream, from: u64, op: Op) -> io::Result<()> {
        match op {
            Op::Append => {
                let result = self
                    .raft
                    .append_entries(read_message(stream).await?)
                    .await
                    .map(|result| -> StreamAppendResult<Types> { result.map_err(Into::into) });
                write_message(stream, &result).await
            }
            Op::Vote => {
                let result = self.raft.vote(read_message(stream).await?).await;
                write_message(stream, &result).await
            }
            Op::PreVote => {
                let result = self.raft.pre_vote(read_message(stream).await?).await;
                write_message(stream, &result).await
            }
            Op::Transfer => {
                let result = self
                    .raft
                    .handle_transfer_leader(read_message(stream).await?)
                    .await;
                write_message(stream, &result).await
            }
            Op::Snapshot => {
                let (vote, meta): (VoteOf<Types>, SnapshotMeta) = read_message(stream).await?;
                let leases = read_frame(stream, MAX_FRAME).await?;
                let app = read_frame(stream, MAX_SNAPSHOT).await?;
                let result = self
                    .raft
                    .install_full_snapshot(
                        vote,
                        Snapshot {
                            meta,
                            snapshot: SnapshotData { leases, app },
                        },
                    )
                    .await;
                write_message(stream, &result).await
            }
            Op::Write => {
                let body = read_frame(stream, MAX_COMMAND).await?;
                write_message(stream, &self.write(Command::App(body)).await).await
            }
            Op::ReadIndex => write_message(stream, &self.read_index().await).await,
            Op::Lease => write_message(stream, &self.heartbeat(from).await).await,
            Op::MeshRequest | Op::MeshSend => {
                let body = read_frame(stream, MAX_FRAME).await?;
                let result = self.mesh.handle(from, body).await;
                if matches!(op, Op::MeshSend) {
                    if let Err(error) = result {
                        tracing::debug!(%error, from, "mesh send handler failed");
                    }
                    return Ok(());
                }
                match result {
                    Ok(body) => {
                        stream.write_u8(0).await?;
                        write_frame(stream, &body, MAX_FRAME).await
                    }
                    Err(error) => {
                        stream.write_u8(1).await?;
                        write_frame(stream, error.to_string().as_bytes(), MAX_FRAME).await
                    }
                }
            }
        }
    }
}

fn encode_command(command: impl Serialize) -> Result<Bytes, ClusterError> {
    let body = encode(&command)?;
    if body.len() > MAX_COMMAND {
        return Err(invalid_data("encoded application command exceeds 8 MiB").into());
    }
    Ok(body.into())
}

fn decode_response<R: serde::de::DeserializeOwned>(
    response: Option<Bytes>,
) -> Result<R, ClusterError> {
    let body = response.ok_or_else(|| {
        ClusterError::WriteUncertain("leader returned no application response".into())
    })?;
    decode(&body).map_err(|error| ClusterError::WriteUncertain(error.to_string()))
}
