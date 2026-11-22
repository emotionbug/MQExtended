//! Single-node MQTT 3.1 / 3.1.1 broker with Mosquitto 2.1.4 session semantics.

mod connection;
mod inbox;
mod retained;
mod state;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use mqx_auth::{AclFile, PasswordFile};
use mqx_codec::{DecodeError, EncodeError, QoS};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Notify, watch},
    time::Instant,
};

use inbox::{Inbox, Offer};
use state::{Claim, Command, CommandLog, Effect, Epoch, Lease, LocalLog, Operation, Reply};

/// Broker-wide options. Zero-valued limits are disabled.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub allow_anonymous: bool,
    pub allow_zero_length_clientid: bool,
    pub auto_id_prefix: String,
    pub clientid_prefixes: Option<String>,
    pub max_keepalive: u16,
    pub max_inflight_messages: usize,
    pub max_inflight_bytes: usize,
    pub max_queued_messages: usize,
    pub max_queued_bytes: usize,
    pub queue_qos0_messages: bool,
    pub message_size_limit: usize,
    pub max_packet_size: usize,
    pub persistent_client_expiration: Option<Duration>,
    pub retain_available: bool,
    pub upgrade_outgoing_qos: bool,
    pub allow_duplicate_messages: bool,
    pub check_retain_source: bool,
    pub global_max_connections: usize,
    pub global_max_clients: usize,
    pub connection_messages: bool,
}

impl Default for BrokerConfig {
    // conf.c: config__init_reload and config__check. The server must resolve
    // the no-config, local-only exception to allow_anonymous itself.
    fn default() -> Self {
        Self {
            allow_anonymous: false,
            allow_zero_length_clientid: true,
            auto_id_prefix: "auto-".into(),
            clientid_prefixes: None,
            max_keepalive: 0,
            max_inflight_messages: 20,
            max_inflight_bytes: 0,
            max_queued_messages: 1000,
            max_queued_bytes: 0,
            queue_qos0_messages: false,
            message_size_limit: 0,
            max_packet_size: 2_000_000,
            persistent_client_expiration: None,
            retain_available: true,
            upgrade_outgoing_qos: false,
            allow_duplicate_messages: true,
            check_retain_source: true,
            global_max_connections: 0,
            global_max_clients: 0,
            connection_messages: true,
        }
    }
}

/// Listener-level settings; share one `Arc<ListenerPolicy>` across connections
/// accepted by the same listener so connection limits are counted correctly.
#[derive(Debug, Clone)]
pub struct ListenerPolicy {
    pub allow_anonymous: Option<bool>,
    pub allow_zero_length_clientid: Option<bool>,
    pub auto_id_prefix: Option<String>,
    pub max_qos: QoS,
    pub max_connections: usize,
    pub use_username_as_clientid: bool,
    pub disable_protocol_v3: bool,
    pub disable_protocol_v4: bool,
    pub mount_point: Option<String>,
    pub security: SecurityHandle,
}

impl Default for ListenerPolicy {
    // listeners.c: listener__set_defaults. None means use the broker setting.
    fn default() -> Self {
        Self {
            allow_anonymous: None,
            allow_zero_length_clientid: None,
            auto_id_prefix: None,
            max_qos: QoS::ExactlyOnce,
            max_connections: 0,
            use_username_as_clientid: false,
            disable_protocol_v3: false,
            disable_protocol_v4: false,
            mount_point: None,
            security: SecurityHandle::default(),
        }
    }
}

struct Security {
    password: Option<PasswordFile>,
    acl: Option<Arc<AclFile>>,
}

struct SharedSecurity {
    id: u64,
    snapshots: watch::Sender<Arc<Security>>,
}

static NEXT_SECURITY_ID: AtomicU64 = AtomicU64::new(1);
static SECURITY_REVISION: AtomicU64 = AtomicU64::new(0);

/// One reloadable set of Mosquitto password and ACL files. Use a single handle
/// for listeners sharing security settings and separate handles for separate files.
#[derive(Clone)]
pub struct SecurityHandle(Arc<SharedSecurity>);

impl std::fmt::Debug for SecurityHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecurityHandle")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}

impl Default for SecurityHandle {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl SecurityHandle {
    pub fn new(password: Option<PasswordFile>, acl: Option<AclFile>) -> Self {
        Self(Arc::new(SharedSecurity {
            id: NEXT_SECURITY_ID.fetch_add(1, Ordering::Relaxed),
            snapshots: watch::Sender::new(Arc::new(Security {
                password,
                acl: acl.map(Arc::new),
            })),
        }))
    }

    /// Replaces both files together and causes connected clients to reauthenticate.
    pub fn replace(&self, password: Option<PasswordFile>, acl: Option<AclFile>) {
        self.0.snapshots.send_replace(Arc::new(Security {
            password,
            acl: acl.map(Arc::new),
        }));
        SECURITY_REVISION.fetch_add(1, Ordering::Release);
    }
}

/// Certificate identity mapping, as resolved by the listener's TLS layer.
#[derive(Debug, Clone, Default)]
pub enum CertIdentity {
    #[default]
    None,
    Username(String),
    MissingOrInvalid,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionInfo {
    pub peer_addr: Option<SocketAddr>,
    pub listener: Arc<ListenerPolicy>,
    pub cert_identity: CertIdentity,
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("connection I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("peer violated the MQTT protocol")]
    Protocol,
    #[error("operating system could not generate a client identifier: {0}")]
    ClientId(getrandom::Error),
}

/// Shared MQTT broker. Each active transport is driven by one `serve` call.
#[derive(Clone)]
pub struct Broker(Arc<Inner>);

struct Inner {
    config: Arc<BrokerConfig>,
    started: Instant,
    runtime: Mutex<Runtime>,
    shutdown: watch::Sender<bool>,
    expiry_changed: watch::Sender<()>,
}

struct Runtime {
    log: Box<dyn CommandLog>,
    live: HashMap<Epoch, Arc<Live>>,
    security: HashMap<u64, (SecurityHandle, Arc<Security>)>,
    security_revision: u64,
    connections: usize,
    listeners: HashMap<usize, usize>,
    expiry_running: bool,
}

struct Live {
    lease: Lease,
    inbox: Option<Mutex<Inbox>>,
    taken: AtomicBool,
    ready: Notify,
}

impl Broker {
    pub fn new(config: BrokerConfig) -> Self {
        let config = Arc::new(config);
        Self(Arc::new(Inner {
            config: config.clone(),
            started: Instant::now(),
            runtime: Mutex::new(Runtime {
                log: Box::new(LocalLog::new(config)),
                live: HashMap::new(),
                security: HashMap::new(),
                security_revision: SECURITY_REVISION.load(Ordering::Acquire),
                connections: 0,
                listeners: HashMap::new(),
                expiry_running: false,
            }),
            shutdown: watch::Sender::new(false),
            expiry_changed: watch::Sender::new(()),
        }))
    }

    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        mut stream: S,
        info: ConnectionInfo,
    ) -> Result<(), BrokerError> {
        let permit = self.admit(&info);
        let result = if permit.is_some() {
            connection::serve(self, &mut stream, info).await
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

    /// Stops accepting clients and wakes all existing connection tasks.
    pub fn shutdown(&self) {
        self.0.shutdown.send_replace(true);
        self.0.expiry_changed.send_replace(());
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

    fn claim(&self, security: &SecurityHandle, claim: Claim) -> Option<(Arc<Live>, bool)> {
        let mut runtime = self.0.runtime.lock().unwrap();
        runtime.update_security(Some(security));
        let now = self.0.started.elapsed();
        if runtime.log.next_expiry().is_some_and(|time| time <= now) {
            runtime.apply(Command::Expire(now), &self.0.config);
        }
        let transient = claim.transient;
        let Reply::Claimed { lease, present } =
            runtime.apply(Command::Claim(claim), &self.0.config)
        else {
            return None;
        };
        let live = Arc::new(Live {
            lease,
            inbox: transient.then(Mutex::default),
            ready: Notify::new(),
            taken: AtomicBool::new(false),
        });
        runtime.live.insert(live.lease.epoch, live.clone());
        Some((live, present))
    }

    fn act(&self, live: &Live, operation: Operation) -> Reply {
        let mut runtime = self.0.runtime.lock().unwrap();
        runtime.update_security(None);
        runtime.apply(Command::Act(live.lease.clone(), operation), &self.0.config)
    }

    fn detach(&self, live: &Live, graceful: bool) {
        let mut runtime = self.0.runtime.lock().unwrap();
        if runtime.live.remove(&live.lease.epoch).is_none() {
            return;
        }
        runtime.update_security(None);
        runtime.apply(
            Command::Act(
                live.lease.clone(),
                Operation::Disconnect {
                    graceful,
                    now: self.0.started.elapsed(),
                },
            ),
            &self.0.config,
        );
        if runtime.log.next_expiry().is_some() {
            if runtime.expiry_running {
                self.0.expiry_changed.send_replace(());
            } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
                runtime.expiry_running = true;
                handle.spawn(expire(
                    Arc::downgrade(&self.0),
                    self.0.expiry_changed.subscribe(),
                ));
            }
        }
    }
}

impl Runtime {
    fn update_security(&mut self, new: Option<&SecurityHandle>) {
        let revision = SECURITY_REVISION.load(Ordering::Acquire);
        if self.security_revision != revision {
            self.security_revision = revision;
            for (&security, (handle, previous)) in &mut self.security {
                let current = handle.0.snapshots.borrow();
                if !Arc::ptr_eq(&current, previous) {
                    if !same_acl(&current.acl, &previous.acl) {
                        self.log.apply(Command::SetAcl {
                            security,
                            acl: current.acl.clone(),
                        });
                    }
                    *previous = current.clone();
                }
            }
        }
        if let Some(handle) = new {
            self.security.entry(handle.0.id).or_insert_with(|| {
                let current = handle.0.snapshots.borrow().clone();
                if current.acl.is_some() {
                    self.log.apply(Command::SetAcl {
                        security: handle.0.id,
                        acl: current.acl.clone(),
                    });
                }
                (handle.clone(), current)
            });
        }
    }

    fn apply(&mut self, command: Command, config: &BrokerConfig) -> Reply {
        let outcome = self.log.apply(command);
        for effect in outcome.effects {
            match effect {
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
                        live.taken.store(true, Ordering::Release);
                        live.ready.notify_one();
                    }
                }
                Effect::Expired(id) => tracing::info!("Expiring client {id} due to timeout."),
                Effect::QueueFull(id) => report_drop(&id),
            }
        }
        outcome.reply
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

async fn expire(inner: Weak<Inner>, mut changed: watch::Receiver<()>) {
    loop {
        let deadline = {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let mut runtime = inner.runtime.lock().unwrap();
            let now = inner.started.elapsed();
            if runtime.log.next_expiry().is_some_and(|time| time <= now) {
                runtime.apply(Command::Expire(now), &inner.config);
            }
            if let Some(time) = runtime
                .log
                .next_expiry()
                .filter(|_| !*inner.shutdown.borrow())
            {
                inner.started + time
            } else {
                runtime.expiry_running = false;
                return;
            }
        };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {},
            result = changed.changed() => if result.is_err() { return; },
        }
    }
}
