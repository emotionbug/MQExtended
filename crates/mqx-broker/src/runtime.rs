mod bridge;
mod control;
mod dynamic_security;
mod proposals;
mod telemetry;
pub use bridge::{BridgeAck, BridgeIdentity, BridgeSession};
pub use telemetry::SocketObservation;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex, OnceLock, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use mqx_auth::AclFile;
use mqx_cluster::{Cluster, ClusterConfig, ClusterError, NodeEvent, NodeStatus, StateMachine};
use mqx_codec::{PacketId, QoS, v5::ReasonCode as R};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Notify, OnceCell, mpsc, oneshot, watch},
    time::{Instant, MissedTickBehavior},
};

use crate::{
    BrokerConfig, BrokerError, ConnectionInfo, PeerTransport, ReloadableLimits, SECURITY_REVISION,
    Security, SecurityHandle, connection, fast,
    inbox::{Delivery, Inbox, Offer, Outbound},
    persistence::PersistentState,
    state::{
        BatchEntry, Claim, ClaimToken, Command, Effect, Epoch, Lease, Mutations, Operation, Owner,
        Publication, Reply, State,
    },
    sys::{Metric, ProposalLatency, Traffic},
};

/// Shared MQTT broker. Each active transport is driven by one `serve` call.
#[derive(Clone)]
pub struct Broker(pub(super) Arc<Inner>);

pub(super) struct Inner {
    pub(super) config: Arc<ConfigCell>,
    connection_messages: AtomicBool,
    control_inventory: OnceLock<crate::ControlInventory>,
    pub(super) shutdown: watch::Sender<bool>,
    pub(super) traffic: Traffic,
    sys_interval: watch::Sender<Option<u16>>,
    runtime: Arc<Mutex<Runtime>>,
    log: Log,
    dynamic_security_registration: tokio::sync::Mutex<()>,
}

pub(super) struct ConfigCell {
    startup: Arc<BrokerConfig>,
    effective: RwLock<Arc<BrokerConfig>>,
}

impl ConfigCell {
    fn new(startup: Arc<BrokerConfig>) -> Self {
        Self {
            effective: RwLock::new(startup.clone()),
            startup,
        }
    }

    // The startup config can be borrowed across awaits for non-reloadable options.
    pub(super) fn startup(&self) -> &BrokerConfig {
        &self.startup
    }

    // Never hand out the lock guard: callers hold other locks (runtime,
    // inboxes) in both orders, and a waiting writer blocks new readers.
    pub(super) fn load(&self) -> Arc<BrokerConfig> {
        self.effective.read().unwrap().clone()
    }

    fn update(&self, config: &Arc<BrokerConfig>) {
        *self.effective.write().unwrap() = config.clone();
    }
}

// Both backends apply exactly the same commands. Only Raft writes wait for
// a quorum and the submitter's local replica; the single-node path is in memory.
enum Log {
    Local {
        started: Instant,
        wall_origin: Duration,
        expiry_changed: watch::Sender<()>,
    },
    Replicated(ReplicatedLog),
}

struct ReplicatedLog {
    cluster: Cluster<Machine>,
    owner: Owner,
    applied: watch::Receiver<u64>,
    boot: OnceCell<()>,
    timeout: Duration,
    fence_timeout: Duration,
    // MeshSend only confirms a socket write; waiting for each peer's
    // handler response prevents a later connection overtaking this one.
    peer_lanes: Mutex<BTreeMap<u64, Arc<tokio::sync::Mutex<()>>>>,
    proposals: mpsc::Sender<proposals::Proposal>,
    batch_limits: proposals::Limits,
    max_command_size: usize,
    proposal_latency: Box<ProposalLatency>,
}

struct LocalLog {
    state: State,
    security: HashMap<u64, (SecurityHandle, Arc<Security>)>,
    security_revision: u64,
    expiry_running: bool,
    persistence_changed: Option<watch::Sender<u64>>,
}

#[derive(Default)]
struct Runtime {
    local: Option<LocalLog>,
    live: HashMap<Epoch, Arc<Live>>,
    pending: HashMap<ClaimToken, Pending>,
    connections: usize,
    listeners: HashMap<usize, usize>,
    transient_drops: i64,
    dynamic_security_path: Option<std::path::PathBuf>,
}

struct Pending {
    transient: bool,
    receive_maximum: Option<u16>,
    peer_address: Option<Arc<str>>,
    live: Option<Arc<Live>>,
}

pub(super) struct Live {
    pub(super) lease: Lease,
    pub(super) inbox: Option<Mutex<Inbox>>,
    pub(super) taken: AtomicBool,
    pub(super) kicked: AtomicBool,
    pub(super) ready: Notify,
    bridge_queue_peak: AtomicUsize,
    peer_address: Option<Arc<str>>,
    sequence: AtomicU64,
    outbox: Mutex<Outbox>,
}

#[derive(Default)]
struct Outbox {
    packets: VecDeque<Outbound>,
    interrupted: bool,
}

pub(super) enum ClaimResult {
    Accepted(Arc<Live>, bool),
    Full,
    Unauthorized,
    Stale,
}

impl Live {
    fn new(
        lease: Lease,
        transient: bool,
        receive_maximum: Option<u16>,
        peer_address: Option<Arc<str>>,
    ) -> Self {
        Self {
            lease,
            inbox: transient.then(|| {
                let mut inbox = Inbox::default();
                inbox.receive_maximum = receive_maximum;
                Mutex::new(inbox)
            }),
            taken: AtomicBool::new(false),
            kicked: AtomicBool::new(false),
            ready: Notify::new(),
            bridge_queue_peak: AtomicUsize::new(0),
            peer_address,
            sequence: AtomicU64::new(0),
            outbox: Mutex::new(Outbox::default()),
        }
    }

    fn close(&self) {
        self.taken.store(true, Ordering::Release);
        self.ready.notify_one();
    }

    fn interrupt_outbound(&self) {
        // A snapshot can restore the cursor without the committed send
        // effects. Reconnecting recovers those packets from the inbox.
        self.outbox.lock().unwrap().interrupted = true;
        self.ready.notify_one();
    }

    fn pop_reserved(&self) -> Result<Option<Outbound>, BrokerError> {
        let mut outbox = self.outbox.lock().unwrap();
        if outbox.interrupted {
            return Err(ClusterError::WriteUncertain(
                "snapshot skipped outbound send effects".into(),
            )
            .into());
        }
        Ok(outbox.packets.pop_front())
    }

    fn bridge_queued(&self, pending: usize) {
        if self.bridge_queue_peak.fetch_max(pending, Ordering::Relaxed) < pending {
            self.ready.notify_one();
        }
    }
}

impl Broker {
    pub fn new(config: BrokerConfig) -> Self {
        let config = Arc::new(config);
        Self(Arc::new(Inner {
            config: Arc::new(ConfigCell::new(config.clone())),
            connection_messages: AtomicBool::new(config.connection_messages),
            control_inventory: OnceLock::new(),
            shutdown: watch::Sender::new(false),
            traffic: Traffic::default(),
            sys_interval: watch::Sender::new(None),
            dynamic_security_registration: tokio::sync::Mutex::new(()),
            log: Log::Local {
                started: Instant::now(),
                wall_origin: wall_now(),
                expiry_changed: watch::Sender::new(()),
            },
            runtime: Arc::new(Mutex::new(Runtime {
                local: Some(LocalLog {
                    state: State::new(config),
                    security: HashMap::new(),
                    security_revision: SECURITY_REVISION.load(Ordering::Acquire),
                    expiry_running: false,
                    persistence_changed: None,
                }),
                ..Runtime::default()
            })),
        }))
    }

    /// Starts a Raft-backed broker. All peers must use the same broker-wide
    /// configuration and assign the same security IDs to equivalent listeners.
    pub async fn clustered(
        config: BrokerConfig,
        cluster: ClusterConfig,
    ) -> Result<Self, BrokerError> {
        let owner = Owner {
            node: cluster.node_id,
            incarnation: new_token()?,
        };
        let config = Arc::new(config);
        let config_cell = Arc::new(ConfigCell::new(config.clone()));
        let runtime = Arc::new(Mutex::new(Runtime::default()));
        let (applied_tx, applied) = watch::channel(0);
        let (abandoned, cleanup) = mpsc::unbounded_channel();
        let (proposals, proposal_rx) = mpsc::channel(128);
        let tick = cluster.heartbeat_interval;
        let timeout = cluster.request_timeout;
        let fence_timeout = timeout.saturating_add(cluster.lease_timeout);
        let max_command_size = cluster.max_command_size;
        let batch_limits =
            proposals::Limits::new(cluster.max_command_size, cluster.max_append_size);
        let cluster = Cluster::start(
            cluster,
            Machine {
                state: State::new(config.clone()),
                config: config_cell.clone(),
                owner,
                runtime: runtime.clone(),
                applied: applied_tx,
                abandoned,
            },
        )
        .await?;
        let broker = Self(Arc::new(Inner {
            connection_messages: AtomicBool::new(config.connection_messages),
            control_inventory: OnceLock::new(),
            config: config_cell,
            runtime,
            shutdown: watch::Sender::new(false),
            traffic: Traffic::default(),
            sys_interval: watch::Sender::new(None),
            dynamic_security_registration: tokio::sync::Mutex::new(()),
            log: Log::Replicated(ReplicatedLog {
                cluster,
                owner,
                applied,
                boot: OnceCell::new(),
                timeout,
                fence_timeout,
                peer_lanes: Mutex::new(BTreeMap::new()),
                proposals,
                batch_limits,
                max_command_size,
                proposal_latency: Box::default(),
            }),
        }));
        let Log::Replicated(log) = &broker.0.log else {
            unreachable!()
        };
        let inner = Arc::downgrade(&broker.0);
        log.cluster.mesh().register_handler(move |from, body| {
            let inner = inner.clone();
            async move {
                let inner = inner.upgrade().ok_or(ClusterError::Shutdown)?;
                Broker(inner).receive_mesh(from, body).await
            }
        })?;
        tokio::spawn(proposals::run(Arc::downgrade(&broker.0), proposal_rx));
        tokio::spawn(cluster_maintenance(
            Arc::downgrade(&broker.0),
            tick,
            cleanup,
            broker.0.shutdown.subscribe(),
        ));
        Ok(broker)
    }

    /// Returns the six reloadable values currently in effect on this node.
    pub fn reloadable_limits(&self) -> ReloadableLimits {
        self.0.config.load().reloadable_limits()
    }

    /// Apply the limits immediately in standalone mode. In a cluster, commit
    /// changed values to the replicated log and wait for active replicas to apply.
    pub async fn reload_limits(&self, limits: ReloadableLimits) -> Result<(), BrokerError> {
        if let Log::Replicated(log) = &self.0.log {
            if self.reloadable_limits() != limits {
                log.submit(Command::ReloadLimits(limits)).await?;
            }
        } else {
            self.0.runtime.lock().unwrap().apply_local(
                Command::ReloadLimits(limits),
                &self.0.config,
                None,
            );
        }
        Ok(())
    }

    /// Install a listener's initial ACL, or commit changed bytes after a reload.
    /// Initial registration never overwrites a policy already committed by a peer.
    pub async fn register_security(&self, handle: &SecurityHandle) -> Result<(), BrokerError> {
        match &self.0.log {
            Log::Local { .. } => {
                self.0
                    .runtime
                    .lock()
                    .unwrap()
                    .local
                    .as_mut()
                    .unwrap()
                    .update_security(Some(handle));
            }
            Log::Replicated(log) => {
                log.security(handle, true).await?;
            }
        }
        Ok(())
    }

    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        stream: S,
        info: ConnectionInfo,
    ) -> Result<(), BrokerError> {
        self.record_socket_accept();
        let _socket = self.track_socket();
        self.serve_accepted(stream, info, Instant::now()).await
    }

    /// Serve a stream whose transport handshake already consumed part of the
    /// pre-CONNECT budget. `accepted_at` is the original socket accept time.
    pub async fn serve_accepted<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        stream: S,
        info: ConnectionInfo,
        accepted_at: Instant,
    ) -> Result<(), BrokerError> {
        self.serve_accepted_with(stream, info, accepted_at, PeerTransport::default())
            .await
    }

    /// As [`Self::serve_accepted`], with transport details Mosquitto logs.
    pub async fn serve_accepted_with<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        mut stream: S,
        info: ConnectionInfo,
        accepted_at: Instant,
        transport: PeerTransport<'_>,
    ) -> Result<(), BrokerError> {
        let peer = connection::Address::new(info.peer_addr, transport.address);
        let permit = self.admit(&info, &peer);
        let result = if permit.is_some() {
            connection::serve(self, &mut stream, info, accepted_at, peer, transport.tls).await
        } else {
            Ok(())
        };
        // TLS and WebSocket transports send their close indication here.
        // A blocked peer must still release its connection slot.
        let close = tokio::time::timeout(Duration::from_secs(1), stream.shutdown()).await;
        result?;
        close
            .map_err(std::io::Error::other)?
            .map_err(BrokerError::from)
    }

    /// Connection notices are reloadable independently of broker-wide protocol rules.
    pub fn set_connection_messages(&self, enabled: bool) {
        self.0.connection_messages.store(enabled, Ordering::Relaxed);
    }

    pub fn connection_messages(&self) -> bool {
        self.0.connection_messages.load(Ordering::Relaxed)
    }

    /// Whether this replica has MQTT state that would fence a migration.
    pub fn can_import_persistence(&self) -> bool {
        match &self.0.log {
            Log::Local { .. } => self
                .0
                .runtime
                .lock()
                .unwrap()
                .local
                .as_ref()
                .unwrap()
                .state
                .can_import_persistence(),
            Log::Replicated(log) => log
                .cluster
                .read(|machine| machine.state.can_import_persistence()),
        }
    }

    /// Run once before accepting connections. Cluster imports publish the
    /// image through the replicated log and apply it atomically.
    pub async fn restore_persistence(&self, state: PersistentState) -> Result<bool, BrokerError> {
        match &self.0.log {
            Log::Local { .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                let restored = runtime
                    .local
                    .as_mut()
                    .unwrap()
                    .state
                    .restore_persistence(state, self.now());
                self.schedule_local_expiry(&mut runtime);
                Ok(restored)
            }
            Log::Replicated(log) => log.import_persistence(state).await,
        }
    }

    /// Subscribe to the standalone broker's autosave-counted mutations.
    pub fn watch_persistence_changes(&self) -> Option<watch::Receiver<u64>> {
        let mut runtime = self.0.runtime.lock().unwrap();
        let local = runtime.local.as_mut()?;
        Some(
            local
                .persistence_changed
                .get_or_insert_with(|| watch::Sender::new(local.state.persistence_changes))
                .subscribe(),
        )
    }

    pub(super) fn count_transient_ack(&self, ack: crate::inbox::Ack) {
        if !self.is_clustered() && ack.counts_for_persistence() {
            let mut runtime = self.0.runtime.lock().unwrap();
            let local = runtime.local.as_mut().unwrap();
            local.state.persistence_changes += 1;
            local.notify_persistence_change();
        }
    }

    /// Capture standalone state and its autosave change watermark under one lock.
    pub fn persistence_snapshot(&self, shutdown: bool) -> Option<(u64, PersistentState)> {
        let mut runtime = self.0.runtime.lock().unwrap();
        let now = self.now();
        let local = runtime.local.as_mut()?;
        if shutdown {
            let mut effects = Vec::new();
            local.state.flush_shutdown_wills(now, &mut effects);
            runtime.dispatch(effects, &self.0.config.load(), Owner::LOCAL, None);
        }
        let state = &runtime.local.as_ref().unwrap().state;
        Some((state.persistence_changes, state.persistent_snapshot(now)))
    }

    /// Stop accepting clients and ask existing connections to close.
    pub fn shutdown(&self) {
        self.0.shutdown.send_replace(true);
        if let Log::Local { expiry_changed, .. } = &self.0.log {
            expiry_changed.send_replace(());
        }
    }

    /// Stop the local Raft node. For a graceful server shutdown, first call
    /// [`Self::shutdown`] and wait for connection tasks to finish committing.
    /// Connections left over after Raft stops are handled by the cluster lease.
    pub async fn shutdown_cluster(&self) -> Result<(), BrokerError> {
        let result = match &self.0.log {
            Log::Local { .. } => Ok(()),
            Log::Replicated(log) => log.cluster.shutdown().await.map_err(BrokerError::from),
        };
        self.shutdown();
        result
    }

    /// Control the local Raft membership; standalone brokers have no cluster.
    pub fn cluster_membership(&self) -> Option<mqx_cluster::MembershipControl> {
        match &self.0.log {
            Log::Local { .. } => None,
            Log::Replicated(log) => Some(log.cluster.membership_control()),
        }
    }

    // net.c: net__socket_accept checks accepted sockets, before MQTT CONNECT.
    fn admit(&self, info: &ConnectionInfo, peer: &connection::Address) -> Option<Permit<'_>> {
        if *self.0.shutdown.borrow() {
            return None;
        }
        let mut runtime = self.0.runtime.lock().unwrap();
        let key = Arc::as_ptr(&info.listener) as usize;
        let listener_limit = info.listener.max_connections;
        let global_limit = self.0.config.startup().global_max_connections;
        if (global_limit != 0 && runtime.connections >= global_limit)
            || (listener_limit != 0
                && runtime.listeners.get(&key).copied().unwrap_or(0) >= listener_limit)
        {
            if self.connection_messages() {
                // net.c: net__socket_accept logs the address only, as a notice.
                tracing::info!(
                    target: "mqx::notice",
                    "Client connection from {} denied: max_connections exceeded.",
                    peer.host.as_deref().unwrap_or("unknown")
                );
            }
            return None;
        }
        runtime.connections += 1;
        let listener = (listener_limit != 0).then_some(key);
        if let Some(key) = listener {
            *runtime.listeners.entry(key).or_default() += 1;
        }
        Some(Permit {
            inner: &self.0,
            listener,
        })
    }

    pub(super) async fn claim(
        &self,
        security: &SecurityHandle,
        mut claim: Claim,
        peer_address: Option<Arc<str>>,
    ) -> Result<ClaimResult, BrokerError> {
        let transient = claim.local_inbox();
        let receive_maximum = claim
            .v5
            .as_ref()
            .map(|v5| v5.outgoing_maximum(self.0.config.startup()));
        match &self.0.log {
            Log::Local { .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                claim.now = self.now();
                if runtime
                    .local
                    .as_ref()
                    .unwrap()
                    .state
                    .next_expiry()
                    .is_some_and(|time| time <= claim.now)
                {
                    runtime.apply_local(Command::Expire(claim.now), &self.0.config, None);
                }
                claim.publisher.security = security.0.id;
                let reply = runtime.apply_local(
                    Command::Claim {
                        owner: Owner::LOCAL,
                        token: [0; 16],
                        request: claim,
                    },
                    &self.0.config,
                    Some(security),
                );
                let (lease, present) = match reply {
                    Reply::Claimed { lease, present } => (lease, present),
                    Reply::Full => return Ok(ClaimResult::Full),
                    Reply::Stale => return Ok(ClaimResult::Stale),
                    Reply::DynamicSecurityChanged => return Ok(ClaimResult::Unauthorized),
                    _ => unreachable!(),
                };
                let live = Arc::new(Live::new(
                    lease,
                    transient,
                    receive_maximum,
                    peer_address.clone(),
                ));
                runtime.live.insert(live.lease.epoch, live.clone());
                self.schedule_local_expiry(&mut runtime);
                Ok(ClaimResult::Accepted(live, present))
            }
            Log::Replicated(log) => {
                log.ensure_boot().await?;
                claim.publisher.security = log.security(security, false).await?;
                claim.now = self.now();
                let token = new_token()?;
                {
                    let mut runtime = self.0.runtime.lock().unwrap();
                    runtime.pending.insert(
                        token,
                        Pending {
                            transient,
                            receive_maximum,
                            peer_address: peer_address.clone(),
                            live: None,
                        },
                    );
                }
                let mut pending = PendingClaim {
                    broker: self,
                    token,
                    finished: false,
                };
                let retry = (self.0.config.startup().global_max_clients != 0
                    && claim.internal_bridge.is_none())
                .then(|| claim.clone());
                let proposal = |request| BatchEntry::Claim {
                    owner: log.owner,
                    token,
                    request,
                };
                let mut reply = log.propose_one(proposal(claim)).await?;
                if reply == Reply::Full
                    && let Some(mut request) = retry
                {
                    // The failed claim is applied locally now. A due offline
                    // session can fill the limit until the next maintenance
                    // tick. Commit an ordinary expiry before retrying this
                    // definitive refusal, without changing Claim replay.
                    let now = self.now();
                    let (has_capacity, expiry_due) = log.cluster.read(|machine| {
                        (
                            machine.state.has_capacity_for(&request.publisher.id),
                            machine
                                .state
                                .next_session_expiry()
                                .is_some_and(|at| at <= now),
                        )
                    });
                    if has_capacity || expiry_due {
                        if expiry_due {
                            log.submit(Command::Expire(now)).await?;
                        }
                        request.now = self.now();
                        reply = log.propose_one(proposal(request)).await?;
                    }
                }
                let (lease, present) = match reply {
                    Reply::Claimed { lease, present } => (lease, present),
                    Reply::Full => {
                        pending.take();
                        return Ok(ClaimResult::Full);
                    }
                    Reply::DynamicSecurityChanged => {
                        pending.take();
                        return Ok(ClaimResult::Unauthorized);
                    }
                    Reply::Stale => {
                        pending.take();
                        return Ok(ClaimResult::Stale);
                    }
                    _ => unreachable!(),
                };
                // In the normal case local apply attached the transport before
                // dispatching any later traffic. Snapshot installation does not
                // replay attachments; reconcile that case against current state.
                let live = log.cluster.read(|machine| {
                    let mut runtime = self.0.runtime.lock().unwrap();
                    let pending = runtime.pending.remove(&token).unwrap();
                    pending.live.or_else(|| {
                        if !machine.state.owns(log.owner, &lease) {
                            return None;
                        }
                        let live = Arc::new(Live::new(
                            lease,
                            transient,
                            receive_maximum,
                            peer_address.clone(),
                        ));
                        if machine.state.has_reserved_outbound(&live.lease) {
                            live.interrupt_outbound();
                        }
                        runtime.live.insert(live.lease.epoch, live.clone());
                        Some(live)
                    })
                });
                pending.finished = true;
                Ok(live.map_or(ClaimResult::Stale, |live| {
                    ClaimResult::Accepted(live, present)
                }))
            }
        }
    }

    pub(super) fn is_clustered(&self) -> bool {
        matches!(self.0.log, Log::Replicated(_))
    }

    pub(super) fn now(&self) -> Duration {
        match &self.0.log {
            Log::Local {
                started,
                wall_origin,
                ..
            } => wall_origin.saturating_add(started.elapsed()),
            Log::Replicated(_) => wall_now(),
        }
    }

    pub(super) async fn act(
        &self,
        live: &Live,
        operation: Operation,
    ) -> Result<Reply, BrokerError> {
        self.submit(Command::Act(live.lease.clone(), operation))
            .await
    }

    // A standalone log is never replayed, so it can always use the newer
    // command; a replicated one writes `Ack` where both mean the same.
    pub(super) fn pubrec(&self, live: &Live, id: PacketId) -> Operation {
        match &self.0.log {
            Log::Local { .. } => Operation::ReceivedInFlight(id),
            Log::Replicated(log) => log
                .cluster
                .read(|machine| machine.state.pubrec(&live.lease, id)),
        }
    }

    pub(super) async fn receive(
        &self,
        live: &Live,
        publication: Publication,
        birth: bool,
    ) -> Result<Reply, BrokerError> {
        self.0.traffic.add(
            Metric::PayloadReceived,
            publication.packet.payload.len() as i64,
        );
        if publication.packet.topic.starts_with(crate::control::PREFIX) {
            return self.receive_control(live, publication).await;
        }
        let admitted_local = publication.packet.qos == QoS::AtLeastOnce
            && live
                .inbox
                .as_ref()
                .is_some_and(|inbox| inbox.lock().unwrap().simple_qos1());
        if !birth
            && let Log::Replicated(log) = &self.0.log
            && let Some((index, route)) = log.plan(live, &publication, admitted_local)
        {
            return self
                .forward_fast(log, live, index, route, publication)
                .await;
        }
        self.act(live, Operation::receive(publication, admitted_local, birth))
            .await
    }

    // Only a publisher with no possible self-delivery may aggregate PUBACKs:
    // Mosquitto can deliver a self-publication before its corresponding ACK.
    pub(super) fn can_pipeline(&self, live: &Live) -> bool {
        let Log::Replicated(log) = &self.0.log else {
            return false;
        };
        log.cluster
            .read(|machine| machine.state.publisher_only(&live.lease))
            && live.inbox.as_ref().map_or_else(
                || live.outbox.lock().unwrap().packets.is_empty(),
                |inbox| {
                    let inbox = inbox.lock().unwrap();
                    inbox.simple_qos1() && !inbox.has_outbound(self.0.config.startup())
                },
            )
    }

    pub(super) async fn receive_many(
        &self,
        live: &Live,
        publications: Vec<Publication>,
        sparkplug_aware: bool,
    ) -> Result<Vec<Reply>, BrokerError> {
        let Log::Replicated(log) = &self.0.log else {
            unreachable!()
        };
        let mut responses = Vec::with_capacity(publications.len());
        let mut durable = Vec::new();
        for publication in publications {
            self.0.traffic.add(
                Metric::PayloadReceived,
                publication.packet.payload.len() as i64,
            );
            if publication.packet.topic.starts_with(crate::control::PREFIX) {
                if !durable.is_empty() {
                    responses.extend(
                        log.propose(live.lease.clone(), std::mem::take(&mut durable))
                            .await?,
                    );
                    if matches!(responses.last(), Some(Reply::Stale | Reply::ProtocolError)) {
                        return Ok(responses);
                    }
                }
                let reply = self.receive_control(live, publication).await?;
                let stop = reply == Reply::Stale || live.taken.load(Ordering::Acquire);
                responses.push(reply);
                if stop {
                    return Ok(responses);
                }
                continue;
            }
            let local = publication.packet.qos == QoS::AtLeastOnce && live.inbox.is_some();
            let birth = sparkplug_aware && publication.sparkplug_birth();
            let mut plan = if birth {
                None
            } else {
                log.plan(live, &publication, local)
            };
            if plan.is_some() && !durable.is_empty() {
                responses.extend(
                    log.propose(live.lease.clone(), std::mem::take(&mut durable))
                        .await?,
                );
                if matches!(responses.last(), Some(Reply::Stale | Reply::ProtocolError)) {
                    return Ok(responses);
                }
                // Re-read after a durable predecessor. In particular, the
                // mesh fence must include its committed retained delivery.
                plan = log.plan(live, &publication, local);
            }
            if let Some((index, route)) = plan {
                responses.push(
                    self.forward_fast(log, live, index, route, publication)
                        .await?,
                );
                if matches!(responses.last(), Some(Reply::Stale)) {
                    return Ok(responses);
                }
            } else {
                durable.push(Operation::receive(publication, local, birth));
            }
        }
        if !durable.is_empty() {
            responses.extend(log.propose(live.lease.clone(), durable).await?);
        }
        Ok(responses)
    }

    async fn forward_fast(
        &self,
        log: &ReplicatedLog,
        live: &Live,
        index: u64,
        route: fast::Route,
        publication: Publication,
    ) -> Result<Reply, BrokerError> {
        if live.taken.load(Ordering::Acquire) {
            return Ok(Reply::Stale);
        }
        let reason = if route.matched {
            R::SUCCESS
        } else {
            R::NO_MATCHING_SUBSCRIBERS
        };
        if !route.targets.is_empty() {
            self.route_fast(log, live, index, route, publication)
                .await?;
        }
        Ok(if live.taken.load(Ordering::Acquire) {
            Reply::Stale
        } else {
            Reply::PublishReason(reason.0)
        })
    }

    async fn route_fast(
        &self,
        log: &ReplicatedLog,
        live: &Live,
        index: u64,
        route: fast::Route,
        publication: Publication,
    ) -> Result<(), BrokerError> {
        let sequence = live.sequence.fetch_add(1, Ordering::Relaxed);
        let message = publication.into_message(route.source);
        let mut by_node: BTreeMap<u64, Vec<fast::Target>> = BTreeMap::new();
        for (node, target) in route.targets {
            by_node.entry(node).or_default().push(target);
        }
        for (node, targets) in by_node {
            let publication = fast::Publication {
                index,
                epoch: live.lease.epoch,
                sequence,
                message: message.clone(),
                targets,
            };
            if node == log.owner.node {
                self.deliver_owned_fast(log, node, publication);
            } else {
                let lane = log.peer_lane(node);
                let _ordered = lane.lock().await;
                // Do not retry an uncertain send: it may already be in a
                // recipient's inbox, especially for QoS 0.
                if let Err(error) = log
                    .request(node, &fast::Request::Publish(publication))
                    .await
                {
                    // A transient sink cannot survive a lost peer, and its
                    // transport failure must not close the publishing client.
                    tracing::debug!(%error, node, "transient mesh delivery was not confirmed");
                }
            }
        }
        Ok(())
    }

    async fn receive_mesh(&self, from: u64, body: Bytes) -> Result<Bytes, ClusterError> {
        let Log::Replicated(log) = &self.0.log else {
            unreachable!()
        };
        let request: fast::Request = rmp_serde::from_slice(&body)
            .map_err(|error| ClusterError::MeshHandler(error.to_string()))?;
        match request {
            fast::Request::Fence(index) => log.wait_applied(index).await?,
            fast::Request::Publish(publication) => {
                // Any earlier retained publish or QoS 2 release from this
                // sender is already enqueued here before this direct delivery.
                log.wait_applied(publication.index).await?;
                self.deliver_owned_fast(log, from, publication);
            }
            fast::Request::SysSample => {
                return rmp_serde::to_vec(&self.sample_node(log.owner))
                    .map(Bytes::from)
                    .map_err(|error| ClusterError::MeshHandler(error.to_string()));
            }
        }
        Ok(Bytes::new())
    }

    fn deliver_owned_fast(&self, log: &ReplicatedLog, from: u64, publication: fast::Publication) {
        log.cluster.read(|machine| {
            if machine
                .state
                .owns_peer(from, &publication.message.source.id, publication.epoch)
            {
                self.deliver_fast(publication);
            }
        });
    }

    fn deliver_fast(&self, publication: fast::Publication) {
        let mut runtime = self.0.runtime.lock().unwrap();
        let config = self.0.config.load();
        // database.c: db__message_insert_outgoing reads the destination's setting.
        for (epoch, packet) in publication.deliveries(!config.allow_duplicate_messages) {
            runtime.deliver(epoch, packet, &config);
        }
    }

    pub(super) async fn next_outbound(&self, live: &Live) -> Result<Option<Outbound>, BrokerError> {
        if let Some(inbox) = &live.inbox {
            let mut inbox = inbox.lock().unwrap();
            let now = self.now();
            inbox.expire_before_qos0(now);
            return Ok(inbox.next_outbound(self.0.config.startup(), now));
        }
        if let Log::Replicated(log) = &self.0.log {
            if let Some(packet) = live.pop_reserved()? {
                return Ok(Some(packet));
            }
            let Some(operation) = log.cluster.read(|machine| {
                machine
                    .state
                    .outbound_reservation(&live.lease, || self.now())
            }) else {
                // A later committed delivery wakes the transport on apply.
                return Ok(None);
            };
            // Advance the replicated cursor before sending. The owning replica
            // already has the payload, so only a small reply crosses Raft RPC.
            let reply = self.act(live, operation).await?;
            match reply {
                Reply::OutboundReserved | Reply::NoChange => {
                    let packet = live.pop_reserved()?;
                    if packet.is_none()
                        && reply == Reply::OutboundReserved
                        && !live.taken.load(Ordering::Acquire)
                    {
                        return Err(ClusterError::WriteUncertain(
                            "outbound reservation applied without a local packet".into(),
                        )
                        .into());
                    }
                    return Ok(packet);
                }
                Reply::Stale => return Ok(None),
                _ => unreachable!(),
            }
        }
        match self.act(live, Operation::NextOutbound(self.now())).await? {
            Reply::Outbound(outbound) => Ok(outbound),
            Reply::Stale => Ok(None),
            _ => unreachable!(),
        }
    }

    async fn submit(&self, command: Command) -> Result<Reply, BrokerError> {
        match &self.0.log {
            Log::Local { .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                let old = runtime.local.as_ref().unwrap().state.next_expiry();
                let reply = runtime.apply_local(command, &self.0.config, None);
                if old != runtime.local.as_ref().unwrap().state.next_expiry() {
                    self.schedule_local_expiry(&mut runtime);
                }
                Ok(reply)
            }
            Log::Replicated(log) => match command {
                Command::Act(lease, operation) => {
                    log.propose_one(BatchEntry::Act(Mutations {
                        lease,
                        operations: vec![operation],
                    }))
                    .await
                }
                command => log.submit(command).await,
            },
        }
    }

    pub(super) async fn detach(
        &self,
        lease: Lease,
        graceful: bool,
        expiry: Option<u32>,
    ) -> Result<(), BrokerError> {
        match &self.0.log {
            Log::Local { .. } => {
                self.detach_local(lease, graceful, expiry);
                Ok(())
            }
            Log::Replicated(log) => {
                let removed = self
                    .0
                    .runtime
                    .lock()
                    .unwrap()
                    .live
                    .remove(&lease.epoch)
                    .is_some();
                if removed && log.cluster.metrics().running {
                    self.disconnect(lease, graceful, expiry).await?;
                }
                Ok(())
            }
        }
    }

    pub(super) fn detach_cancelled(&self, lease: Lease, graceful: bool, expiry: Option<u32>) {
        if let Log::Local { .. } = self.0.log {
            self.detach_local(lease, graceful, expiry);
        } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
            self.0.runtime.lock().unwrap().live.remove(&lease.epoch);
            let broker = self.clone();
            handle.spawn(async move {
                // DISCONNECT is fenced by epoch, so cancellation cannot
                // disconnect a successor or publish the old will twice.
                if let Err(error) = broker.disconnect(lease, graceful, expiry).await {
                    tracing::debug!(%error, "could not clean up cancelled connection");
                }
            });
        }
    }

    async fn disconnect(
        &self,
        lease: Lease,
        graceful: bool,
        expiry: Option<u32>,
    ) -> Result<(), BrokerError> {
        self.submit(Command::Act(
            lease,
            Operation::Disconnect {
                graceful,
                now: wall_now(),
                expiry,
            },
        ))
        .await?;
        Ok(())
    }

    fn detach_local(&self, lease: Lease, graceful: bool, expiry: Option<u32>) {
        let mut runtime = self.0.runtime.lock().unwrap();
        if runtime.live.remove(&lease.epoch).is_none() {
            return;
        }
        runtime.apply_local(
            Command::Act(
                lease,
                Operation::Disconnect {
                    graceful,
                    now: self.now(),
                    expiry,
                },
            ),
            &self.0.config,
            None,
        );
        self.schedule_local_expiry(&mut runtime);
    }

    fn schedule_local_expiry(&self, runtime: &mut Runtime) {
        let Log::Local { expiry_changed, .. } = &self.0.log else {
            unreachable!()
        };
        let local = runtime.local.as_mut().unwrap();
        if local.state.next_expiry().is_some() {
            if local.expiry_running {
                expiry_changed.send_replace(());
            } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
                local.expiry_running = true;
                handle.spawn(expire_local(
                    Arc::downgrade(&self.0),
                    expiry_changed.subscribe(),
                ));
            }
        }
    }
}

impl ReplicatedLog {
    fn peer_lane(&self, node: u64) -> Arc<tokio::sync::Mutex<()>> {
        self.peer_lanes
            .lock()
            .unwrap()
            .entry(node)
            .or_default()
            .clone()
    }

    fn plan(
        &self,
        live: &Live,
        publication: &Publication,
        admitted_local: bool,
    ) -> Option<(u64, fast::Route)> {
        self.cluster.leader()?;
        self.cluster.read(|machine| {
            machine
                .state
                .fast_route(self.owner, &live.lease, &publication.packet, admitted_local)
                .map(|route| (machine.state.applied, route))
        })
    }

    async fn propose(
        &self,
        lease: Lease,
        operations: Vec<Operation>,
    ) -> Result<Vec<Reply>, ClusterError> {
        self.enqueue(BatchEntry::Act(Mutations { lease, operations }))
            .await
    }

    async fn propose_one(&self, entry: BatchEntry) -> Result<Reply, BrokerError> {
        Ok(self
            .enqueue(entry)
            .await?
            .pop()
            .expect("single proposal reply"))
    }

    async fn enqueue(&self, entry: BatchEntry) -> Result<Vec<Reply>, ClusterError> {
        let (result, replies) = oneshot::channel();
        self.proposals
            .send(proposals::Proposal { entry, result })
            .await
            .map_err(|_| ClusterError::Shutdown)?;
        replies.await.map_err(|_| ClusterError::Shutdown)?
    }

    async fn import_persistence(&self, image: PersistentState) -> Result<bool, BrokerError> {
        let size = self.max_command_size.saturating_sub(128);
        if size == 0 {
            return Err(ClusterError::InvalidConfig(
                "command budget is too small for migration".into(),
            )
            .into());
        }
        let image = tokio::task::spawn_blocking(move || {
            rmp_serde::to_vec(&image)
                .map(Bytes::from)
                .map_err(std::io::Error::other)
        })
        .await
        .map_err(std::io::Error::other)??;
        for offset in (0..image.len()).step_by(size) {
            let end = (offset + size).min(image.len());
            let finish = (end == image.len()).then(wall_now);
            match self
                .submit(Command::ImportPersistence {
                    offset,
                    bytes: image.slice(offset..end),
                    finish,
                })
                .await?
            {
                Reply::PersistenceStaged => {}
                Reply::PersistenceImported => return Ok(true),
                Reply::NoChange => return Ok(false),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid replicated persistence import",
                    )
                    .into());
                }
            }
        }
        unreachable!("an encoded image always includes a MessagePack header")
    }

    async fn submit(&self, command: Command) -> Result<Reply, BrokerError> {
        let fence = match &command {
            Command::SetAcl { .. }
            | Command::InitDynamicSecurity(_)
            | Command::ReloadLimits(_)
            | Command::ImportPersistence {
                finish: Some(_), ..
            } => true,
            Command::Act(_, operation) => operation.needs_fence(),
            Command::Batch(batch) => batch.iter().any(BatchEntry::needs_fence),
            _ => false,
        };
        // Cluster::submit follows definitive redirects, but never retries an
        // ambiguous write. Propagation closes the MQTT connection on uncertainty.
        let started = Instant::now();
        let applied = self.cluster.submit(command).await;
        self.proposal_latency.record(started.elapsed());
        let applied = applied?;
        self.wait_applied(applied.index).await?;
        if fence || applied.reply.dynamic_security_mutated() {
            self.fence_peers(applied.index).await?;
        }
        Ok(applied.reply)
    }

    async fn wait_applied(&self, index: u64) -> Result<(), ClusterError> {
        let mut observer = self.applied.clone();
        tokio::time::timeout(self.timeout, observer.wait_for(|applied| *applied >= index))
            .await
            .map_err(|_| {
                ClusterError::WriteUncertain(
                    "committed command did not apply on the local broker before its deadline"
                        .into(),
                )
            })?
            .map_err(|_| {
                ClusterError::WriteUncertain(
                    "local broker stopped after the command committed".into(),
                )
            })?;
        Ok(())
    }

    async fn request(&self, node: u64, request: &fast::Request) -> Result<(), ClusterError> {
        let body = rmp_serde::to_vec(request)
            .map_err(|error| ClusterError::MeshHandler(error.to_string()))?;
        self.cluster.mesh().request(node, Bytes::from(body)).await?;
        Ok(())
    }

    async fn fence_peers(&self, index: u64) -> Result<(), ClusterError> {
        // An acknowledged subscription (or ACL change) must already be
        // visible to any existing publisher's local routing replica. A down
        // node cannot host an active session until its next committed Boot.
        let deadline = Instant::now() + self.fence_timeout;
        for node in self
            .cluster
            .voter_ids()
            .into_iter()
            .filter(|&node| node != self.owner.node)
        {
            let peer_gone = || {
                self.cluster
                    .voter_status(node)
                    .is_none_or(|status| status == NodeStatus::Down)
            };
            loop {
                if peer_gone() {
                    break;
                }
                match tokio::time::timeout_at(
                    deadline,
                    self.request(node, &fast::Request::Fence(index)),
                )
                .await
                {
                    Ok(Ok(())) => break,
                    Ok(Err(ClusterError::Shutdown)) => return Err(ClusterError::Shutdown),
                    Ok(Err(_)) if Instant::now() < deadline => {
                        // A failed TCP attempt does not fence the old owner:
                        // allow Raft time to declare it durably Down.
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    _ => {
                        if peer_gone() {
                            break;
                        }
                        return Err(ClusterError::WriteUncertain(format!(
                            "routing fence did not reach node {node}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    async fn ensure_boot(&self) -> Result<(), BrokerError> {
        self.boot
            .get_or_try_init(|| async {
                let mut previous = self
                    .cluster
                    .read(|machine| machine.state.incarnation(self.owner.node));
                loop {
                    let reply = self
                        .submit(Command::Boot {
                            owner: self.owner,
                            previous,
                            now: wall_now(),
                        })
                        .await?;
                    if reply != Reply::Stale {
                        return Ok(());
                    }
                    previous = self
                        .cluster
                        .linearizable_read(|machine| machine.state.incarnation(self.owner.node))
                        .await?;
                }
            })
            .await
            .copied()
    }

    async fn security(&self, handle: &SecurityHandle, explicit: bool) -> Result<u64, BrokerError> {
        let snapshot = handle.0.snapshots.borrow().clone();
        let id = match handle.0.stable_id {
            Some(id) if id != 0 => id,
            None if snapshot.acl.is_none() => return Ok(0),
            _ => return Err(BrokerError::ClusterSecurity),
        };
        if snapshot.acl.is_some() && snapshot.text.is_none() {
            return Err(BrokerError::ClusterSecurity);
        }
        let initial = !(explicit && snapshot.reload);
        if initial && snapshot.text.is_none() {
            return Ok(id);
        }
        if initial
            && self
                .cluster
                .read(|machine| machine.state.acl_text(id).is_some())
        {
            return Ok(id);
        }
        match self
            .submit(Command::SetAcl {
                security: id,
                text: snapshot.text.clone(),
                initial,
            })
            .await?
        {
            Reply::InvalidAcl => Err(BrokerError::InvalidClusterAcl),
            _ => Ok(id),
        }
    }
}

struct Machine {
    state: State,
    config: Arc<ConfigCell>,
    owner: Owner,
    runtime: Arc<Mutex<Runtime>>,
    applied: watch::Sender<u64>,
    abandoned: mpsc::UnboundedSender<Lease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Applied {
    index: u64,
    reply: Reply,
}

impl Machine {
    fn emit(&self, effects: Vec<Effect>, save_dynamic_security: bool) {
        if !effects.is_empty() || save_dynamic_security {
            let mut runtime = self.runtime.lock().unwrap();
            if save_dynamic_security {
                runtime.save_dynamic_security(&self.state);
            }
            runtime.dispatch(
                effects,
                self.state.config(),
                self.owner,
                Some(&self.abandoned),
            );
        }
        self.applied.send_replace(self.state.applied);
    }
}

impl StateMachine for Machine {
    type Command = Command;
    type Response = Applied;

    fn apply(&mut self, index: u64, command: Command) -> Applied {
        let reload = matches!(&command, Command::ReloadLimits(_));
        let outcome = self.state.apply(command);
        if reload {
            self.config.update(self.state.config());
        }
        self.state.applied = index;
        self.emit(outcome.effects, outcome.reply.dynamic_security_mutated());
        Applied {
            index,
            reply: outcome.reply,
        }
    }

    fn on_node_event(&mut self, event: NodeEvent) {
        let effects = self.state.node_event(event);
        self.emit(effects, false);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.state.snapshot()
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), ClusterError> {
        let previous = self.state.restore(bytes)?;
        let previous_dynamic = previous.dynamic_policy().map(|(revision, _)| revision);
        let skipped = self.state.applied > previous.applied;
        let mut runtime = self.runtime.lock().unwrap();
        self.config.update(self.state.config());
        if previous_dynamic != self.state.dynamic_policy().map(|(revision, _)| revision) {
            runtime.save_dynamic_security(&self.state);
        }
        runtime.live.retain(|_, live| {
            if self.state.owns(self.owner, &live.lease) {
                // An offline inbox only grows between attempts. Recover
                // enqueue wakes skipped while installing a newer snapshot.
                if skipped
                    && let Some(before) = previous.offline_lazy_pending(&live.lease)
                    && let Some(after) = self.state.offline_lazy_pending(&live.lease)
                    && after > before
                {
                    live.bridge_queued(after);
                }
                if skipped && self.state.has_reserved_outbound(&live.lease) {
                    live.interrupt_outbound();
                } else if self.state.has_outbound(&live.lease) {
                    live.ready.notify_one();
                }
                true
            } else {
                live.close();
                false
            }
        });
        self.applied.send_replace(self.state.applied);
        Ok(())
    }
}

impl Runtime {
    fn apply_local(
        &mut self,
        command: Command,
        config: &ConfigCell,
        security: Option<&SecurityHandle>,
    ) -> Reply {
        let local = self.local.as_mut().unwrap();
        local.update_security(security);
        let changes = local.state.persistence_changes;
        let reload = matches!(&command, Command::ReloadLimits(_));
        let outcome = local.state.apply(command);
        if reload {
            config.update(local.state.config());
        }
        if outcome.reply.dynamic_security_mutated() {
            self.save_dynamic_security(&self.local.as_ref().unwrap().state);
        }
        if !outcome.effects.is_empty() {
            self.dispatch(outcome.effects, &config.load(), Owner::LOCAL, None);
        }
        let local = self.local.as_ref().unwrap();
        if local.state.persistence_changes != changes {
            local.notify_persistence_change();
        }
        outcome.reply
    }

    fn dispatch(
        &mut self,
        effects: Vec<Effect>,
        config: &BrokerConfig,
        here: Owner,
        abandoned: Option<&mpsc::UnboundedSender<Lease>>,
    ) {
        for effect in effects {
            match effect {
                Effect::Attach {
                    owner,
                    token,
                    lease,
                } if owner == here => {
                    if let Some(pending) = self.pending.get_mut(&token) {
                        let live = Arc::new(Live::new(
                            lease,
                            pending.transient,
                            pending.receive_maximum,
                            pending.peer_address.clone(),
                        ));
                        self.live.insert(live.lease.epoch, live.clone());
                        pending.live = Some(live);
                    } else if let Some(abandoned) = abandoned {
                        // A Claim reported uncertain may still commit. No
                        // socket owns this epoch, so clean it up as a lost one.
                        let _ = abandoned.send(lease);
                    }
                }
                Effect::Attach { .. } => {}
                Effect::Deliver { owner, packet } => self.deliver(owner, packet, config),
                Effect::Ready(lease) => {
                    if let Some(live) = self.live.get(&lease.epoch) {
                        live.ready.notify_one();
                    }
                }
                Effect::BridgeOffline(owner) => {
                    if let Some(live) = self.live.get(&owner) {
                        // Reset in apply order so a subsequent queued delivery
                        // cannot be cleared by a late transport wakeup.
                        live.bridge_queue_peak.store(0, Ordering::Relaxed);
                    }
                }
                Effect::BridgeQueued { owner, pending } => {
                    if let Some(live) = self.live.get(&owner) {
                        live.bridge_queued(pending);
                    }
                }
                Effect::ReservedOutbound { owner, packet } => {
                    if let Some(live) = self.live.get(&owner) {
                        let mut outbox = live.outbox.lock().unwrap();
                        let first = outbox.packets.is_empty();
                        outbox.packets.push_back(packet);
                        drop(outbox);
                        if first {
                            live.ready.notify_one();
                        }
                    }
                }
                Effect::Takeover(owner) => {
                    if let Some(live) = self.live.remove(&owner) {
                        live.close();
                    }
                }
                Effect::Kick(owner) => {
                    if let Some(live) = self.live.remove(&owner) {
                        live.kicked.store(true, Ordering::Release);
                        live.close();
                    }
                }
                Effect::Expired(id) => tracing::info!("Expiring client {id} due to timeout."),
                Effect::QueueFull(id) => report_drop(&id),
            }
        }
    }

    fn deliver(&mut self, epoch: Epoch, mut packet: Delivery, config: &BrokerConfig) {
        let Some(live) = self.live.get(&epoch) else {
            return;
        };
        let Some(inbox) = &live.inbox else {
            return;
        };
        let result = {
            let mut inbox = inbox.lock().unwrap();
            // database.c: db__message_insert_outgoing uses the recipient's version.
            // A transient inbox has a receive maximum only for MQTT 5, so the
            // mesh publication does not need to carry the protocol version.
            if packet.dedup_id.is_some() && inbox.receive_maximum.is_some() {
                packet.dedup_id = None;
            }
            inbox.offer(packet, true, QoS::ExactlyOnce, config)
        };
        if matches!(result, Offer::Dropped | Offer::FirstDrop) {
            self.transient_drops += 1;
        }
        if result == Offer::FirstDrop {
            report_drop(&live.lease.id);
        }
        if result == Offer::Queued
            && let Some(local) = &mut self.local
        {
            local.state.persistence_changes += 1;
        }
        if result == Offer::Ready {
            live.ready.notify_one();
        }
    }
}

impl LocalLog {
    fn notify_persistence_change(&self) {
        if let Some(changed) = &self.persistence_changed {
            changed.send_replace(self.state.persistence_changes);
        }
    }

    fn update_security(&mut self, new: Option<&SecurityHandle>) {
        let revision = SECURITY_REVISION.load(Ordering::Acquire);
        if self.security_revision != revision {
            self.security_revision = revision;
            for (&id, (handle, previous)) in &mut self.security {
                let current = handle.0.snapshots.borrow();
                if !Arc::ptr_eq(&current, previous) {
                    if !same_acl(&current.acl, &previous.acl) {
                        self.state.install_local_acl(id, current.acl.clone());
                    }
                    *previous = current.clone();
                }
            }
        }
        if let Some(handle) = new {
            self.security.entry(handle.0.id).or_insert_with(|| {
                let current = handle.0.snapshots.borrow().clone();
                self.state
                    .install_local_acl(handle.0.id, current.acl.clone());
                (handle.clone(), current)
            });
        }
    }
}

fn same_acl(current: &Option<Arc<AclFile>>, previous: &Option<Arc<AclFile>>) -> bool {
    match (current, previous) {
        (None, None) => true,
        (Some(current), Some(previous)) => Arc::ptr_eq(current, previous),
        _ => false,
    }
}

fn report_drop(id: &str) {
    tracing::info!("Outgoing messages are being dropped for client {id}.");
}

fn new_token() -> Result<[u8; 16], BrokerError> {
    let mut token = [0; 16];
    getrandom::fill(&mut token).map_err(BrokerError::ClientId)?;
    Ok(token)
}

fn wall_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

struct PendingClaim<'a> {
    broker: &'a Broker,
    token: ClaimToken,
    finished: bool,
}

impl PendingClaim<'_> {
    fn take(&mut self) -> Option<Pending> {
        self.finished = true;
        self.broker
            .0
            .runtime
            .lock()
            .unwrap()
            .pending
            .remove(&self.token)
    }
}

impl Drop for PendingClaim<'_> {
    fn drop(&mut self) {
        if !self.finished
            && let Some(live) = self.take().and_then(|pending| pending.live)
        {
            self.broker
                .detach_cancelled(live.lease.clone(), false, None);
        }
    }
}

struct Permit<'a> {
    inner: &'a Inner,
    listener: Option<usize>,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut runtime = self.inner.runtime.lock().unwrap();
        runtime.connections -= 1;
        if let Some(key) = self.listener {
            let count = runtime.listeners.get_mut(&key).unwrap();
            *count -= 1;
            if *count == 0 {
                runtime.listeners.remove(&key);
            }
        }
    }
}

async fn expire_local(inner: Weak<Inner>, mut changed: watch::Receiver<()>) {
    loop {
        let deadline = {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let Log::Local {
                started,
                wall_origin,
                ..
            } = &inner.log
            else {
                unreachable!()
            };
            let mut runtime = inner.runtime.lock().unwrap();
            let now = wall_origin.saturating_add(started.elapsed());
            if runtime
                .local
                .as_ref()
                .unwrap()
                .state
                .next_expiry()
                .is_some_and(|time| time <= now)
            {
                runtime.apply_local(Command::Expire(now), &inner.config, None);
            }
            let local = runtime.local.as_mut().unwrap();
            if let Some(time) = local
                .state
                .next_expiry()
                .filter(|_| !*inner.shutdown.borrow())
            {
                *started + time.saturating_sub(*wall_origin)
            } else {
                local.expiry_running = false;
                return;
            }
        };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {},
            result = changed.changed() => if result.is_err() { return; },
        }
    }
}

async fn cluster_maintenance(
    inner: Weak<Inner>,
    tick: Duration,
    mut cleanup: mpsc::UnboundedReceiver<Lease>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut leader = None;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            abandoned = cleanup.recv() => {
                let (Some(lease), Some(inner)) = (abandoned, inner.upgrade()) else { return; };
                if let Err(error) = Broker(inner).disconnect(lease, false, None).await {
                    tracing::debug!(%error, "could not clean up abandoned claim");
                }
            }
            _ = interval.tick() => {
                let Some(inner) = inner.upgrade() else { return; };
                let Log::Replicated(log) = &inner.log else { unreachable!() };
                let metrics = log.cluster.metrics();
                if !metrics.running { return; }
                if metrics.leader != leader {
                    leader = metrics.leader;
                    if let Some(leader_id) = leader {
                        tracing::info!(leader_id, node_id = log.owner.node, "cluster raft leader");
                    }
                }
                if leader.is_some() && log.boot.get().is_none() {
                    // Replicated node incarnation fences sessions from an old
                    // process even if it restarted before the lease expired.
                    if let Err(error) = log.ensure_boot().await {
                        tracing::debug!(%error, "could not commit local broker incarnation");
                    }
                }
                if leader == Some(log.owner.node) {
                    let now = wall_now();
                    if log.cluster.read(|machine| machine.state.next_expiry().is_some_and(|expiry| expiry <= now))
                        && let Err(error) = log.cluster.submit_if_leader(Command::Expire(now)).await
                    {
                        tracing::debug!(%error, "session-expiry tick did not complete");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inbox::Publisher, state::SessionSettings};

    #[tokio::test]
    async fn an_expired_mqtt5_session_cannot_block_cluster_admission() {
        let storage = tempfile::tempdir().unwrap();
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let broker = Broker::clustered(
            BrokerConfig {
                global_max_clients: 1,
                ..BrokerConfig::default()
            },
            ClusterConfig::new(
                1,
                address,
                BTreeMap::from([(1, address)]),
                storage.path().join("node"),
                mqx_cluster::ClusterSecurity::InsecurePlaintext,
            ),
        )
        .await
        .unwrap();
        let security = SecurityHandle::default();
        let claim = |id: &str| Claim {
            publisher: Publisher {
                id: Arc::from(id),
                username: None,
                security: 0,
                dynamic_security: None,
            },
            clean_start: true,
            bridge: false,
            max_qos: QoS::ExactlyOnce,
            will: None,
            v5: Some(SessionSettings {
                session_expiry: 1,
                receive_maximum: None,
                will_delay: 0,
                will_expiry: 0,
                will_properties: Vec::new(),
            }),
            now: Duration::ZERO,
            internal_bridge: None,
            dynamic_security_revision: None,
        };
        let ClaimResult::Accepted(old, false) = broker
            .claim(&security, claim("offline"), None)
            .await
            .unwrap()
        else {
            panic!("the original client should be admitted");
        };
        assert!(matches!(
            broker.claim(&security, claim("new"), None).await.unwrap(),
            ClaimResult::Full
        ));

        // Isolate admission from the maintenance ticker and commit a
        // disconnect whose MQTT 5 expiry deadline has passed.
        broker.shutdown();
        broker.0.shutdown.closed().await;
        let Log::Replicated(log) = &broker.0.log else {
            unreachable!();
        };
        log.submit(Command::Act(
            old.lease.clone(),
            Operation::Disconnect {
                graceful: true,
                now: wall_now().saturating_sub(Duration::from_secs(3)),
                expiry: None,
            },
        ))
        .await
        .unwrap();
        assert!(matches!(
            broker.claim(&security, claim("new"), None).await.unwrap(),
            ClaimResult::Accepted(_, false)
        ));
        broker.shutdown_cluster().await.unwrap();
    }
}
