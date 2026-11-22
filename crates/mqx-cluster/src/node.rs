use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use openraft::alias::{EntryPayloadOf, LeaderIdOf, LogIdOf, MembershipOf, VoteOf};
use openraft::async_runtime::WatchReceiver;
use openraft::errors::{ClientWriteError, InitializeError, LinearizableReadError, RaftError};
use openraft::raft::{
    AppendEntriesRequest, StreamAppendResult, TransferLeaderRequest, VoteRequest,
};
use openraft::{BasicNode, Raft, ReadPolicy, ServerState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, broadcast, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, timeout, timeout_at};

use crate::admission::Admission;
use crate::lease::{LeaseCommand, Leases, Stamp};
use crate::mtls::Tls;
use crate::mux::{CallError, Response, write_responses};
use crate::snapshot::{
    Snapshot, SnapshotMeta, Store, atomic_write, open_private_file, prepare_dir,
};
use crate::snapshot_file::SnapshotData;
use crate::transport::{
    Connection, Endpoint, Frame, Limits, Network, Op, decode, encode, invalid_data, write_control,
};
use crate::wal::Wal;
use crate::{ClusterConfig, ClusterError, Mesh, NodeEvent, NodeStatus, StateMachine};

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
    membership: MembershipOf<Types>,
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
            security,
            peers,
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
        let peer_bytes = encode(&peers)?;
        let membership_digest = Sha256::digest(&peer_bytes).into();
        let (endpoint, wal, store) = tokio::task::spawn_blocking(move || {
            let tls = Tls::load(&security, node_id)?;
            let limits = Limits {
                command: max_command_size,
                append: max_append_size,
                mesh: max_mesh_size,
            };
            let endpoint = Arc::new(Endpoint::new(
                node_id,
                peers,
                membership_digest,
                tls,
                max_snapshot_size,
                limits,
            ));
            prepare_dir(&data_dir, false)?;
            let wal = Wal::open(&data_dir.join("wal"), max_append_size)?;
            let identity = encode(&(1u8, node_id, Bytes::from(peer_bytes)))?;
            match open_private_file(&data_dir.join(IDENTITY_FILE)).and_then(|mut file| {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                Ok(data)
            }) {
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
            let leases = Leases::new(endpoint.peers.keys().copied());
            Ok((endpoint, wal, Store::open(state_machine, data_dir, leases)?))
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
        let voters: BTreeMap<_, _> = endpoint
            .peers
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
        let membership = MembershipOf::<Types>::from(voters);
        let core = Arc::new(Core {
            raft,
            store,
            mesh: Mesh::new(endpoint, request_timeout),
            membership: membership.clone(),
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
        // OpenRaft permits concurrent initialization with identical membership. A vote,
        // snapshot or WAL entry from a previous run fences out another initialization.
        match cluster.0.core.raft.initialize(membership).await {
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
    /// The encoded command must fit in `ClusterConfig::max_command_size`.
    pub async fn submit(&self, command: S::Command) -> Result<S::Response, ClusterError> {
        let body = encode_command(command, self.0.core.mesh.endpoint.limits.command)?;
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
        let body = encode_command(command, core.mesh.endpoint.limits.command)?;
        let deadline = Instant::now() + core.request_timeout;
        match core.write_local(body, deadline).await? {
            Route::Value(response) => decode_response(response).map(Some),
            Route::Redirect(_) => Ok(None),
            Route::Retry => Err(ClusterError::Deadline),
            Route::Rejected => Err(ClusterError::WriteRejected),
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
                Route::Retry | Route::Failed(_) | Route::Rejected => {}
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
    Rejected,
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
            } else {
                let _ = self.rpc(leader, Op::Lease, Bytes::new(), deadline).await;
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
        self.mesh.endpoint.close().await;
        self.store.close().await?;
        wal.close().await?;
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
            () = self.run_ordered(from, append_rx, &responses) => Ok(()),
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

    async fn process_rpc(&self, from: u64, request: Request, responses: &mpsc::Sender<Response>) {
        let body = timeout(
            self.request_timeout,
            self.dispatch(from, request.op, &request.frame),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        .and_then(|result| result);
        if matches!(request.op, Op::MeshSend) {
            if let Err(error) = body {
                tracing::debug!(%error, from, "mesh send handler failed");
            }
        } else {
            let body = body.and_then(|body| {
                if body.len() > self.mesh.endpoint.limits.response(request.op) {
                    return Err(invalid_data(
                        "cluster RPC response exceeds configured limit",
                    ));
                }
                Ok(body)
            });
            let _ = responses
                .send(Response {
                    id: request.id,
                    body,
                })
                .await;
        }
    }

    async fn dispatch(&self, from: u64, op: Op, frame: &Frame) -> io::Result<Bytes> {
        match op {
            Op::Append => {
                let request: AppendEntriesRequest<Types> = decode(frame)?;
                check_vote_sender(request.vote, from)?;
                for entry in &request.entries {
                    if let EntryPayloadOf::<Types>::Membership(membership) = &entry.payload
                        && *membership != self.membership
                    {
                        return Err(invalid_data(
                            "Raft log membership must match the static cluster",
                        ));
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
            Op::Session | Op::Snapshot => Err(invalid_data("invalid cluster session request")),
        }
    }

    async fn receive_snapshot(&self, stream: &mut Connection, from: u64) -> io::Result<()> {
        let endpoint = &self.mesh.endpoint;
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
        if decode::<S::Command>(&body).is_err() {
            tracing::warn!(from, "rejected undecodable cluster application command");
            return Route::Rejected;
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
            || !self
                .mesh
                .endpoint
                .peers
                .contains_key(&last.leader_id.node_id)
            || *meta.last_membership.membership() != self.membership
        {
            return Err(invalid_data(
                "snapshot metadata is inconsistent with the leader or membership",
            ));
        }
        Ok(())
    }
}

struct Request {
    id: u64,
    op: Op,
    frame: Frame,
}

fn encode_command(command: impl Serialize, max: usize) -> Result<Bytes, ClusterError> {
    let body = encode(&command)?;
    if body.len() > max {
        return Err(
            invalid_data("encoded application command exceeds configured size limit").into(),
        );
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
    use openraft::storage::RaftStateMachine;

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
    async fn an_existing_undecodable_entry_does_not_stop_replay() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(
            Counter::default(),
            root.path().to_path_buf(),
            Leases::new([1].into_iter()),
        )
        .unwrap();
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
        store
            .apply(futures_util::stream::iter([
                entry(1, encode(&1u64).unwrap()),
                entry(2, encode(&"older incompatible command").unwrap()),
                entry(3, encode(&2u64).unwrap()),
            ]))
            .await
            .unwrap();
        assert_eq!(store.applied_state().await.unwrap().0.unwrap().index, 3);
        assert_eq!(store.state.read().unwrap().app.0, 3);
    }
}
