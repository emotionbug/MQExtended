use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use mqx_auth::AclFile;
use mqx_cluster::{Cluster, ClusterConfig, ClusterError, NodeEvent, StateMachine};
use mqx_codec::QoS;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Notify, OnceCell, mpsc, watch},
    time::{Instant, MissedTickBehavior},
};

use crate::{
    BrokerConfig, BrokerError, ConnectionInfo, SECURITY_REVISION, Security, SecurityHandle,
    connection,
    inbox::{Inbox, Offer, Outbound},
    state::{Claim, ClaimToken, Command, Effect, Epoch, Lease, Operation, Owner, Reply, State},
};

/// Shared MQTT broker. Each active transport is driven by one `serve` call.
#[derive(Clone)]
pub struct Broker(pub(super) Arc<Inner>);

pub(super) struct Inner {
    pub(super) config: Arc<BrokerConfig>,
    pub(super) shutdown: watch::Sender<bool>,
    runtime: Arc<Mutex<Runtime>>,
    log: Log,
}

// Both backends apply exactly the same commands. Only Raft writes wait for
// a quorum and the submitter's local replica; the single-node path is in memory.
enum Log {
    Local {
        started: Instant,
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
}

struct LocalLog {
    state: State,
    security: HashMap<u64, (SecurityHandle, Arc<Security>)>,
    security_revision: u64,
    expiry_running: bool,
}

#[derive(Default)]
struct Runtime {
    local: Option<LocalLog>,
    live: HashMap<Epoch, Arc<Live>>,
    pending: HashMap<ClaimToken, Pending>,
    connections: usize,
    listeners: HashMap<usize, usize>,
}

struct Pending {
    transient: bool,
    live: Option<Arc<Live>>,
}

pub(super) struct Live {
    pub(super) lease: Lease,
    pub(super) inbox: Option<Mutex<Inbox>>,
    pub(super) taken: AtomicBool,
    pub(super) ready: Notify,
}

pub(super) enum ClaimResult {
    Accepted(Arc<Live>, bool),
    Full,
    Stale,
}

impl Live {
    fn new(lease: Lease, transient: bool) -> Self {
        Self {
            lease,
            inbox: transient.then(Mutex::default),
            taken: AtomicBool::new(false),
            ready: Notify::new(),
        }
    }

    fn close(&self) {
        self.taken.store(true, Ordering::Release);
        self.ready.notify_one();
    }
}

impl Broker {
    pub fn new(config: BrokerConfig) -> Self {
        let config = Arc::new(config);
        Self(Arc::new(Inner {
            config: config.clone(),
            shutdown: watch::Sender::new(false),
            log: Log::Local {
                started: Instant::now(),
                expiry_changed: watch::Sender::new(()),
            },
            runtime: Arc::new(Mutex::new(Runtime {
                local: Some(LocalLog {
                    state: State::new(config),
                    security: HashMap::new(),
                    security_revision: SECURITY_REVISION.load(Ordering::Acquire),
                    expiry_running: false,
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
        let runtime = Arc::new(Mutex::new(Runtime::default()));
        let (applied_tx, applied) = watch::channel(0);
        let (abandoned, cleanup) = mpsc::unbounded_channel();
        let tick = cluster.heartbeat_interval;
        let timeout = cluster.request_timeout;
        let cluster = Cluster::start(
            cluster,
            Machine {
                state: State::new(config.clone()),
                config: config.clone(),
                owner,
                runtime: runtime.clone(),
                applied: applied_tx,
                abandoned,
            },
        )
        .await?;
        let broker = Self(Arc::new(Inner {
            config,
            runtime,
            shutdown: watch::Sender::new(false),
            log: Log::Replicated(ReplicatedLog {
                cluster,
                owner,
                applied,
                boot: OnceCell::new(),
                timeout,
            }),
        }));
        tokio::spawn(cluster_maintenance(
            Arc::downgrade(&broker.0),
            tick,
            cleanup,
            broker.0.shutdown.subscribe(),
        ));
        Ok(broker)
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
        self.serve_accepted(stream, info, Instant::now()).await
    }

    /// Serve a stream whose transport handshake already consumed part of the
    /// pre-CONNECT budget. `accepted_at` is the original socket accept time.
    pub async fn serve_accepted<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        mut stream: S,
        info: ConnectionInfo,
        accepted_at: Instant,
    ) -> Result<(), BrokerError> {
        let permit = self.admit(&info);
        let result = if permit.is_some() {
            connection::serve(self, &mut stream, info, accepted_at).await
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

    // net.c: net__socket_accept checks accepted sockets, before MQTT CONNECT.
    fn admit(&self, info: &ConnectionInfo) -> Option<Permit<'_>> {
        if *self.0.shutdown.borrow() {
            return None;
        }
        let mut runtime = self.0.runtime.lock().unwrap();
        let key = Arc::as_ptr(&info.listener) as usize;
        let listener_limit = info.listener.max_connections;
        let global_limit = self.0.config.global_max_connections;
        if (global_limit != 0 && runtime.connections >= global_limit)
            || (listener_limit != 0
                && runtime.listeners.get(&key).copied().unwrap_or(0) >= listener_limit)
        {
            if self.0.config.connection_messages {
                tracing::info!(
                    "Client connection from {} denied: max_connections exceeded.",
                    connection::Address(info.peer_addr)
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
    ) -> Result<ClaimResult, BrokerError> {
        let transient = claim.local_inbox();
        claim.now = self.now();
        match &self.0.log {
            Log::Local { started, .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                let now = started.elapsed();
                if runtime
                    .local
                    .as_ref()
                    .unwrap()
                    .state
                    .next_expiry()
                    .is_some_and(|time| time <= now)
                {
                    runtime.apply_local(Command::Expire(now), &self.0.config, None);
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
                    _ => unreachable!(),
                };
                let live = Arc::new(Live::new(lease, transient));
                runtime.live.insert(live.lease.epoch, live.clone());
                self.schedule_local_expiry(&mut runtime);
                Ok(ClaimResult::Accepted(live, present))
            }
            Log::Replicated(log) => {
                log.ensure_boot().await?;
                claim.publisher.security = log.security(security, false).await?;
                let token = new_token()?;
                {
                    let mut runtime = self.0.runtime.lock().unwrap();
                    runtime.pending.insert(
                        token,
                        Pending {
                            transient,
                            live: None,
                        },
                    );
                }
                let mut pending = PendingClaim {
                    broker: self,
                    token,
                    finished: false,
                };
                let reply = log
                    .submit(Command::Claim {
                        owner: log.owner,
                        token,
                        request: claim,
                    })
                    .await?;
                let (lease, present) = match reply {
                    Reply::Claimed { lease, present } => (lease, present),
                    Reply::Full => {
                        pending.take();
                        return Ok(ClaimResult::Full);
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
                        let live = Arc::new(Live::new(lease, transient));
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

    pub(super) fn now(&self) -> Duration {
        match &self.0.log {
            Log::Local { started, .. } => started.elapsed(),
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

    pub(super) async fn next_outbound(&self, live: &Live) -> Result<Option<Outbound>, BrokerError> {
        if let Some(inbox) = &live.inbox {
            return Ok(inbox
                .lock()
                .unwrap()
                .next_outbound(&self.0.config, self.now()));
        }
        if let Log::Replicated(log) = &self.0.log
            && !log
                .cluster
                .read(|machine| machine.state.has_outbound(&live.lease))
        {
            // A delivery committed after this read wakes the local transport
            // through its apply effect. An empty inbox needs no Raft write.
            return Ok(None);
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
            Log::Replicated(log) => log.submit(command).await,
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
    async fn submit(&self, command: Command) -> Result<Reply, BrokerError> {
        // Cluster::submit follows definitive redirects, but never retries an
        // ambiguous write. Propagation closes the MQTT connection on uncertainty.
        let applied = self.cluster.submit(command).await?;
        let mut observer = self.applied.clone();
        tokio::time::timeout(
            self.timeout,
            observer.wait_for(|index| *index >= applied.index),
        )
        .await
        .map_err(|_| {
            ClusterError::WriteUncertain(
                "committed command did not apply on the local broker before its deadline".into(),
            )
        })?
        .map_err(|_| {
            ClusterError::WriteUncertain("local broker stopped after the command committed".into())
        })?;
        Ok(applied.reply)
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
    config: Arc<BrokerConfig>,
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
    fn emit(&self, effects: Vec<Effect>) {
        if !effects.is_empty() {
            self.runtime.lock().unwrap().dispatch(
                effects,
                &self.config,
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
        let outcome = self.state.apply(command);
        self.state.applied = index;
        self.emit(outcome.effects);
        Applied {
            index,
            reply: outcome.reply,
        }
    }

    fn on_node_event(&mut self, event: NodeEvent) {
        let effects = self.state.node_event(event);
        self.emit(effects);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.state.snapshot()
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), ClusterError> {
        self.state.restore(bytes)?;
        self.runtime.lock().unwrap().live.retain(|_, live| {
            if self.state.owns(self.owner, &live.lease) {
                if self.state.has_outbound(&live.lease) {
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
        config: &BrokerConfig,
        security: Option<&SecurityHandle>,
    ) -> Reply {
        let local = self.local.as_mut().unwrap();
        local.update_security(security);
        let outcome = local.state.apply(command);
        self.dispatch(outcome.effects, config, Owner::LOCAL, None);
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
                        let live = Arc::new(Live::new(lease, pending.transient));
                        self.live.insert(live.lease.epoch, live.clone());
                        pending.live = Some(live);
                    } else if let Some(abandoned) = abandoned {
                        // A Claim reported uncertain may still commit. No
                        // socket owns this epoch, so clean it up as a lost one.
                        let _ = abandoned.send(lease);
                    }
                }
                Effect::Attach { .. } => {}
                Effect::Deliver { owner, packet } => {
                    if let Some(live) = self.live.get(&owner) {
                        let result = live.inbox.as_ref().unwrap().lock().unwrap().offer(
                            packet,
                            true,
                            QoS::ExactlyOnce,
                            config,
                        );
                        if result == Offer::FirstDrop {
                            report_drop(&live.lease.id);
                        }
                        if result == Offer::Ready {
                            live.ready.notify_one();
                        }
                    }
                }
                Effect::Ready(owner) => {
                    if let Some(live) = self.live.get(&owner) {
                        live.ready.notify_one();
                    }
                }
                Effect::Takeover(owner) => {
                    if let Some(live) = self.live.remove(&owner) {
                        live.close();
                    }
                }
                Effect::Expired(id) => tracing::info!("Expiring client {id} due to timeout."),
                Effect::QueueFull(id) => report_drop(&id),
            }
        }
    }
}

impl LocalLog {
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
            let Log::Local { started, .. } = &inner.log else {
                unreachable!()
            };
            let mut runtime = inner.runtime.lock().unwrap();
            let now = started.elapsed();
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
                *started + time
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
