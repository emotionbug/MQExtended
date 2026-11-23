//! Outgoing Mosquitto bridge connections. MQTT wire I/O is local to the
//! owner; subscriptions, inbound QoS 2 and outbound queues use broker state.

mod config;
mod wire;

pub use config::{BridgeConfig, Direction, Protocol, Psk, Restart, Start, TlsConfig, Topic};
pub use wire::Transport;

use std::{collections::HashMap, future::Future, io, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use mqx_broker::{BridgeAck, BridgeIdentity, BridgeSession, Broker, BrokerError, SecurityHandle};
use mqx_codec::{
    self as legacy, LastWill, QoS,
    v5::{self, Packet, Property, Publish, PublishAck, ReasonCode as R},
};
use tokio::{
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
    time::{self, Instant},
};

use wire::Wire;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Decode(#[from] legacy::DecodeError),
    #[error(transparent)]
    Encode(#[from] legacy::EncodeError),
    #[error(transparent)]
    DecodeV5(#[from] v5::DecodeError),
    #[error(transparent)]
    EncodeV5(#[from] v5::EncodeError),
    #[error("protocol error")]
    Protocol,
    #[error("MQTT protocol error ({0:?})")]
    ProtocolReason(R),
    #[error("connection refused")]
    Refused,
    #[error("keepalive timed out")]
    Keepalive,
}

impl Error {
    fn disconnect_reason(&self) -> Option<R> {
        match self {
            Self::ProtocolReason(reason) | Self::Broker(BrokerError::ProtocolV5(reason)) => {
                Some(*reason)
            }
            Self::Broker(BrokerError::Protocol) => Some(R::PROTOCOL_ERROR),
            Self::DecodeV5(error) => match error.response {
                Some(v5::ErrorResponse::Disconnect(reason)) => Some(reason),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Uses the same TLS implementation and trust policy as the embedding broker.
pub type TlsConnect = for<'a> fn(TcpStream, &'a str, &'a TlsConfig) -> TlsFuture<'a>;

pub type TlsFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Box<dyn Transport>>> + Send + 'a>>;

#[derive(Clone, Copy)]
struct Dialer {
    nodelay: bool,
    tls: TlsConnect,
}

/// Applies connection blocks by name; remote transports observe replacements
/// immediately or on disconnect according to the new block's reload mode.
pub struct Bridges {
    broker: Broker,
    security: SecurityHandle,
    dialer: Dialer,
    tasks: HashMap<String, Worker>,
    stopped: Vec<JoinHandle<()>>,
}

struct Worker {
    config: watch::Sender<Option<Arc<BridgeConfig>>>,
    task: JoinHandle<()>,
}

impl Bridges {
    pub fn new(
        broker: Broker,
        security: SecurityHandle,
        tcp_nodelay: bool,
        tls: TlsConnect,
    ) -> Self {
        Self {
            broker,
            security,
            dialer: Dialer {
                nodelay: tcp_nodelay,
                tls,
            },
            tasks: HashMap::new(),
            stopped: Vec::new(),
        }
    }

    pub fn start(&mut self, configurations: Vec<BridgeConfig>) {
        self.replace(configurations, true);
    }

    pub fn reload(&mut self, configurations: Vec<BridgeConfig>) {
        self.replace(configurations, false);
    }

    fn replace(&mut self, configurations: Vec<BridgeConfig>, startup: bool) {
        let mut old = std::mem::take(&mut self.tasks);
        self.stopped.retain(|task| !task.is_finished());
        for config in configurations {
            let name = config.name.clone();
            let config = Arc::new(config);
            let worker = if let Some(worker) = old.remove(&name) {
                worker.config.send_replace(Some(config));
                worker
            } else {
                let startup_config = startup.then(|| config.clone());
                let (config, changes) = watch::channel(Some(config));
                let task = tokio::spawn(run(
                    self.broker.clone(),
                    self.security.clone(),
                    self.dialer,
                    changes,
                    startup_config,
                ));
                Worker { config, task }
            };
            self.tasks.insert(name, worker);
        }
        for (_, worker) in old {
            worker.config.send_replace(None);
            self.stopped.push(worker.task);
        }
    }

    pub async fn shutdown(mut self) {
        // The broker's shutdown signal stops even workers that have no lease.
        for (_, worker) in self.tasks.drain() {
            self.stopped.push(worker.task);
        }
        for task in self.stopped.drain(..) {
            let _ = task.await;
        }
    }
}

const POLL: Duration = Duration::from_millis(100);

async fn run(
    broker: Broker,
    security: SecurityHandle,
    dialer: Dialer,
    mut changes: watch::Receiver<Option<Arc<BridgeConfig>>>,
    startup_config: Option<Arc<BridgeConfig>>,
) {
    let mut shutdown = broker.bridge_shutdown();
    loop {
        if *shutdown.borrow() {
            return;
        }
        let Some(config) = changes.borrow_and_update().clone() else {
            return;
        };
        let request = BridgeIdentity {
            name: &config.name,
            client_id: &config.local_clientid,
            remote_client_id: &config.remote_clientid,
            reuse_local_client_id: config.default_local_clientid,
            reuse_remote_client_id: config.default_remote_clientid,
            // bridge.c: bridge__new and database.c: db__message_store
            // record the remote username for synthetic retained-source checks.
            username: config.remote_username.as_deref(),
            local_clean: config.local_clean(),
            lazy: config.start == Start::Lazy,
            mqtt5: config.protocol == Protocol::V5,
            max_qos: QoS::ExactlyOnce,
        };
        match broker.claim_bridge(request, &security).await {
            Ok(Some(session)) => {
                let mut peer = Peer::new(&config, &session, broker.bridge_receive_maximum());
                let startup = startup_config
                    .as_ref()
                    .is_some_and(|initial| Arc::ptr_eq(initial, &config));
                let remove = match peer
                    .run(&config, &session, &mut changes, dialer, startup)
                    .await
                {
                    Ok(remove) => remove,
                    Err(error) => {
                        tracing::debug!("Bridge {} ended: {error}", config.name);
                        false
                    }
                };
                // mosquitto.c: post_shutdown_cleanup publishes local bridge
                // wills instead of clearing them on broker shutdown.
                if *shutdown.borrow()
                    && session.leased()
                    && let Err(error) = session.offline(false).await
                {
                    tracing::debug!("Bridge {} could not publish its will: {error}", config.name);
                }
                if let Err(error) = session.close(remove).await {
                    tracing::debug!(
                        "Bridge {} could not release its session: {error}",
                        config.name
                    );
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => tracing::debug!(
                "Bridge {} could not claim its session: {error}",
                config.name
            ),
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = changes.changed() => {},
            _ = time::sleep(POLL) => {},
        }
    }
}

struct Peer<'a> {
    local_id: &'a str,
    remote_id: &'a str,
    address: usize,
    protocol: Protocol,
    private: bool,
    retain: bool,
    max_qos: QoS,
    notification: Option<String>,
    initial: bool,
    backoff_ms: u64,
    connected_at: Option<Instant>,
    receive_maximum: u16,
    send_maximum: Option<u16>,
}

enum End {
    Retry { graceful: bool, use_primary: bool },
    Reconfigure,
    Lost,
}

impl<'a> Peer<'a> {
    fn new(
        config: &BridgeConfig,
        session: &'a BridgeSession,
        default_receive_maximum: u16,
    ) -> Self {
        Self {
            local_id: session.client_id(),
            remote_id: session.remote_client_id(),
            address: 0,
            protocol: config.protocol,
            private: config.try_private,
            retain: config.outgoing_retain,
            max_qos: QoS::ExactlyOnce,
            notification: config.notifications.then(|| {
                config.notification_topic.clone().unwrap_or_else(|| {
                    format!(
                        "$SYS/broker/connection/{}/state",
                        session.remote_client_id()
                    )
                })
            }),
            initial: true,
            backoff_ms: config.restart.initial_ms,
            connected_at: None,
            receive_maximum: if config.receive_maximum == 0 {
                default_receive_maximum
            } else {
                config.receive_maximum
            },
            send_maximum: None,
        }
    }

    // src/bridge.c: bridge__start_all, bridge__connect, and bridge_check.
    async fn run(
        &mut self,
        config: &Arc<BridgeConfig>,
        session: &BridgeSession,
        changes: &mut watch::Receiver<Option<Arc<BridgeConfig>>>,
        dialer: Dialer,
        startup: bool,
    ) -> Result<bool, Error> {
        // bridge.c: bridge__start_all dials immediately. bridge__reload and
        // reload_if_needed call only bridge__new; bridge_check then arms the
        // restart timer and advances the address, without creating local subs.
        if !startup {
            self.advance_backoff(config);
            self.address = 1 % config.addresses.len();
            if let Some(remove) = self.wait_restart(config, session, changes).await {
                return Ok(remove);
            }
        }
        loop {
            let filters = outbound_filters(config, self.max_qos);
            for (filter, _) in &filters {
                tracing::debug!(
                    "Bridge {} doing local SUBSCRIBE on topic {filter}",
                    self.local_id
                );
            }
            // The reference build's synchronous DNS path does not replay
            // retained messages until CONNACK (bridge__connect vs connect_step1).
            session
                .prepare(
                    filters,
                    self.will(),
                    self.max_qos,
                    config.clean_session,
                    (self.protocol == Protocol::V5).then_some(self.receive_maximum),
                )
                .await?;
            if self.initial
                && let Some(topic) = &self.notification
            {
                session.notify(topic, self.notification_qos(), b"0").await?;
            }
            let end = match self.attempt(config, session, changes, dialer).await {
                Ok(end) => end,
                Err(error) => {
                    if !session.active() {
                        return Ok(false);
                    }
                    tracing::debug!("Bridge {} connection ended: {error}", self.local_id);
                    End::Retry {
                        graceful: false,
                        use_primary: false,
                    }
                }
            };
            self.initial = false;
            match end {
                End::Lost => return Ok(false),
                End::Reconfigure => return Ok(true),
                End::Retry {
                    graceful,
                    use_primary,
                } => {
                    session.offline(graceful).await?;
                    self.advance_backoff(config);
                    self.address = if use_primary {
                        0
                    } else {
                        (self.address + 1) % config.addresses.len()
                    };
                }
            }
            if let Some(remove) = self.wait_restart(config, session, changes).await {
                return Ok(remove);
            }
        }
    }

    async fn wait_restart(
        &self,
        config: &Arc<BridgeConfig>,
        session: &BridgeSession,
        changes: &mut watch::Receiver<Option<Arc<BridgeConfig>>>,
    ) -> Option<bool> {
        let reconnect = async {
            match config.start {
                Start::Automatic => time::sleep(Duration::from_millis(self.backoff_ms)).await,
                Start::Once => std::future::pending::<()>().await,
                Start::Lazy => session.wait_for_lazy_restart(config.threshold).await,
            }
        };
        tokio::select! {
            biased;
            _ = session.lost() => Some(false),
            _ = replacement(changes, config, true) => Some(true),
            _ = reconnect => None,
        }
    }

    async fn attempt(
        &mut self,
        config: &Arc<BridgeConfig>,
        session: &BridgeSession,
        changes: &mut watch::Receiver<Option<Arc<BridgeConfig>>>,
        dialer: Dialer,
    ) -> Result<End, Error> {
        let (host, port) = &config.addresses[self.address];
        tracing::info!(target: "mqx::notice", "Connecting bridge {} ({host}:{port})", config.name);
        let budget = Duration::from_secs(u64::from(config.keepalive));
        let connect = time::timeout(
            budget,
            Wire::connect(config, self.address, self.protocol, dialer),
        );
        let mut wire = tokio::select! {
            biased;
            _ = session.lost() => return Ok(End::Lost),
            _ = replacement(changes, config, false) => return Ok(End::Reconfigure),
            result = connect => match result {
                Ok(Ok(wire)) => wire,
                Ok(Err(error)) => {
                    tracing::error!("Error creating bridge: {}.", error.to_string().split(" (os error ").next().unwrap());
                    if self.initial { tracing::warn!("Warning: Unable to connect bridge {}.", config.name); }
                    return Err(error.into());
                }
                Err(_) => return Err(Error::Keepalive),
            }
        };
        // lib/net_mosq.c: net__is_connected and database.c:
        // db__message_insert_outgoing admit messages once the socket exists;
        // nothing is written before CONNACK. Keep the previous capabilities
        // until then, as Mosquitto's context does.
        let offered = (self.max_qos, self.send_maximum);
        tokio::select! {
            biased;
            _ = session.lost() => return Ok(End::Lost),
            _ = replacement(changes, config, false) => return Ok(End::Reconfigure),
            result = session.online(offered.0, offered.1) => result?,
        }
        let ack = tokio::select! {
            biased;
            _ = session.lost() => return Ok(End::Lost),
            _ = replacement(changes, config, false) => return Ok(End::Reconfigure),
            result = time::timeout(budget, async {
                self.send_connect(config, &mut wire).await?;
                wire.recv().await
            }) => result.map_err(|_| Error::Keepalive)??,
        };
        let Packet::ConnAck(ack) = ack else {
            return Err(Error::Protocol);
        };
        tracing::debug!("Received CONNACK on connection {}.", self.local_id);
        let keepalive = self.connack(config, &mut wire, ack)?;
        if (self.max_qos, self.send_maximum) != offered {
            session.connack(self.max_qos, self.send_maximum).await?;
        }
        self.connected_at = Some(Instant::now());
        let result = tokio::select! {
            biased;
            _ = session.lost() => Ok(End::Lost),
            _ = replacement(changes, config, false) => Ok(End::Reconfigure),
            result = self.connected(config, session, &mut wire, keepalive) => result,
        };
        let reason = match &result {
            // bridge.c: bridge__destroy sends DISCONNECT on replacement.
            // Shutdown and lost ownership close the socket so the remote
            // broker can publish the bridge will.
            Ok(End::Reconfigure) => Some(R::SUCCESS),
            Err(Error::DecodeV5(error))
                // bridge_topic.c invokes topic_matches_sub before checking a
                // topic name. Its invalid-topic result closes without reply.
                if matches!(error.kind, v5::DecodeErrorKind::InvalidTopic("publish topic"))
                    && config.topics.iter().any(|rule| rule.incoming()
                        && (rule.local_prefix.is_some() || rule.remote_prefix.is_some())) => None,
            Err(error) if self.protocol == Protocol::V5 => error.disconnect_reason(),
            _ => None,
        };
        if let Some(reason) = reason
            && session.active()
        {
            tracing::debug!("Bridge {} sending DISCONNECT", self.local_id);
            let _ = time::timeout(
                Duration::from_millis(500),
                wire.send(Packet::Disconnect(v5::ReasonProperties {
                    reason,
                    properties: Vec::new(),
                })),
            )
            .await;
        }
        result
    }

    // lib/send_connect.c: send__connect uses the remote ID and credentials;
    // the v3.x private bit is never sent for MQTT 5.
    async fn send_connect(&self, config: &BridgeConfig, wire: &mut Wire) -> Result<(), Error> {
        let will = (!config.notifications_local_only)
            .then(|| self.will())
            .flatten()
            .map(|mut will| {
                will.retain &= self.retain;
                will
            });
        let client_id = self.remote_id.to_owned();
        let username = config.remote_username.clone();
        let password = config
            .remote_password
            .as_ref()
            .map(|password| Bytes::copy_from_slice(password.as_bytes()));
        tracing::debug!("Bridge {client_id} sending CONNECT");
        if let Some(protocol) = self.protocol.legacy() {
            if password.is_some() && username.is_none() {
                return Err(Error::Protocol);
            }
            wire.send_legacy_connect(legacy::Connect {
                protocol,
                is_bridge: self.private,
                clean_session: config.clean_session,
                keep_alive: config.keepalive,
                client_id,
                will,
                username,
                password,
            })
            .await?;
        } else {
            let mut properties = Vec::with_capacity(3);
            if config.max_topic_alias != 0 {
                properties.push(Property::TopicAliasMaximum(config.max_topic_alias));
            }
            if config.session_expiry != 0 {
                properties.push(Property::SessionExpiryInterval(config.session_expiry));
            }
            properties.push(Property::ReceiveMaximum(self.receive_maximum));
            wire.send(Packet::Connect(v5::Connect {
                private_protocol_bit: false,
                clean_start: config.clean_session,
                keep_alive: config.keepalive,
                properties,
                client_id,
                username,
                password,
                will: will.map(|will| v5::LastWill {
                    properties: Vec::new(),
                    topic: will.topic,
                    payload: will.payload,
                    qos: will.qos,
                    retain: will.retain,
                }),
            }))
            .await?;
        }
        Ok(())
    }

    // src/handle_connack.c: handle__connack[_properties]. Availability and
    // QoS constraints remain in the context across subsequent attempts.
    fn connack(
        &mut self,
        config: &BridgeConfig,
        wire: &mut Wire,
        ack: v5::ConnAck,
    ) -> Result<u16, Error> {
        let mut keepalive = config.keepalive;
        if self.protocol == Protocol::V5 {
            if ack.reason.0 == 1 && ack.properties.is_empty() {
                tracing::info!(target: "mqx::notice", "Warning: Remote bridge {} does not support MQTT v5.0, reconnecting using MQTT v3.1.1.", config.name);
                self.protocol = Protocol::V311;
                return Err(Error::Refused);
            }
            for property in ack.properties {
                match property {
                    Property::MaximumQos(value) => self.max_qos = qos(value),
                    Property::MaximumPacketSize(value) => {
                        let value = value as usize;
                        if wire.packet_limit == 0 || wire.packet_limit > value {
                            wire.packet_limit = value;
                        }
                    }
                    Property::ReceiveMaximum(maximum) => self.send_maximum = Some(maximum),
                    Property::RetainAvailable(value) => self.retain &= value != 0,
                    Property::ServerKeepAlive(seconds) => keepalive = seconds,
                    Property::TopicAliasMaximum(maximum) => {
                        wire.alias_max = maximum.min(config.max_topic_alias)
                    }
                    _ => {}
                }
            }
        }
        if ack.reason == R::SUCCESS {
            return Ok(keepalive);
        }
        let reason = if self.protocol == Protocol::V5 {
            match ack.reason {
                R::RETAIN_NOT_SUPPORTED => {
                    self.retain = false;
                    "retain not available (will retry)"
                }
                R::QOS_NOT_SUPPORTED => {
                    self.max_qos = qos((self.max_qos as u8).saturating_sub(1));
                    "QoS not supported (will retry)"
                }
                R(value) => reason_string(value),
            }
        } else {
            match ack.reason.0 {
                1 => {
                    self.private = false;
                    "unacceptable protocol version"
                }
                2 => "identifier rejected",
                3 => "broker unavailable",
                4 => "bad user name or password",
                5 => "not authorised",
                _ => "unknown reason",
            }
        };
        tracing::error!("Connection Refused: {reason}");
        Err(Error::Refused)
    }

    async fn connected(
        &self,
        config: &BridgeConfig,
        session: &BridgeSession,
        wire: &mut Wire,
        keepalive: u16,
    ) -> Result<End, Error> {
        self.on_connect(config, session, wire).await?;
        let mut ping = None;
        let keepalive = Duration::from_secs(u64::from(keepalive));
        let mut probe = (!config.round_robin && self.address != 0)
            .then(|| Instant::now() + Duration::from_secs(5));
        loop {
            if let Some(packet) = wire.decode()? {
                if let Some(graceful) = self
                    .incoming(config, session, wire, packet, &mut ping)
                    .await?
                {
                    return Ok(End::Retry {
                        graceful,
                        use_primary: false,
                    });
                }
                continue;
            }
            if let Some(packet) = session.next_outbound(self.protocol == Protocol::V5).await? {
                self.outgoing(config, session, wire, packet).await?;
                continue;
            }
            let idle = if config.start == Start::Lazy {
                Some(wire.last_write + 2 * keepalive + Duration::from_secs(config.idle_timeout))
            } else {
                None
            };
            let next_ping = (!keepalive.is_zero())
                .then(|| ping.unwrap_or_else(|| wire.last_read.min(wire.last_write)) + keepalive);
            tokio::select! {
                _ = session.ready() => {},
                result = wire.read() => result?,
                _ = until(idle) => {
                    tracing::info!(target: "mqx::notice", "Bridge connection {} has exceeded idle timeout, disconnecting.", self.local_id);
                    return Ok(End::Retry { graceful: true, use_primary: false });
                }
                _ = until(next_ping) => {
                    if ping.is_some() { return Err(Error::Keepalive); }
                    tracing::debug!("Sending PINGREQ to {}", self.local_id);
                    wire.send(Packet::PingReq).await?;
                    let now = Instant::now();
                    ping = Some(now);
                    wire.last_read = now;
                }
                _ = until(probe) => {
                    if time::timeout(Duration::from_secs(1), wire::tcp(config, 0)).await.is_ok_and(|result| result.is_ok()) {
                        return Ok(End::Retry { graceful: true, use_primary: true });
                    }
                    probe = Some(Instant::now() + Duration::from_secs(5));
                }
            }
        }
    }

    // src/bridge.c: bridge__on_connect sends state, remote subscriptions, then
    // queues local retained messages, before flushing the bridge inbox.
    async fn on_connect(
        &self,
        config: &BridgeConfig,
        session: &BridgeSession,
        wire: &mut Wire,
    ) -> Result<(), Error> {
        if let Some(topic) = &self.notification {
            let qos = self.notification_qos();
            if !config.notifications_local_only {
                let mid = session.packet_id().await?;
                if !wire
                    .send(Packet::Publish(Publish {
                        dup: false,
                        qos,
                        retain: self.retain,
                        topic: topic.clone(),
                        packet_id: (qos != QoS::AtMostOnce).then_some(mid),
                        properties: Vec::new(),
                        payload: Bytes::from_static(b"1"),
                    }))
                    .await?
                {
                    return Err(Error::Protocol);
                }
            }
            session.notify(topic, qos, b"1").await?;
        }
        for topic in &config.topics {
            let id = self.local_id;
            let filter = &topic.remote_filter;
            if topic.incoming() {
                let mid = session.packet_id().await?;
                let qos = cap_qos(topic.qos, self.max_qos);
                let mqtt5 = self.protocol == Protocol::V5;
                let options = if mqtt5 { 0x0c } else { 0 };
                tracing::debug!(
                    "Bridge {id} sending SUBSCRIBE (Mid: {mid}, Topic: {filter}, QoS: {}, Options: 0x{options:02x})",
                    qos as u8
                );
                wire.send(Packet::Subscribe(v5::Subscribe {
                    packet_id: mid,
                    properties: Vec::new(),
                    subscriptions: vec![v5::Subscription {
                        filter: filter.clone(),
                        qos,
                        no_local: mqtt5,
                        retain_as_published: mqtt5,
                        retain_handling: v5::RetainHandling::SendAlways,
                    }],
                }))
                .await?;
            } else if config.attempt_unsubscribe {
                let mid = session.packet_id().await?;
                tracing::debug!("Bridge {id} sending UNSUBSCRIBE (Mid: {mid}, Topic: {filter})");
                wire.send(Packet::Unsubscribe(v5::Unsubscribe {
                    packet_id: mid,
                    properties: Vec::new(),
                    filters: vec![filter.clone()],
                }))
                .await?;
            }
        }
        session
            .replay_retained(outbound_filters(config, self.max_qos))
            .await?;
        Ok(())
    }

    // src/handle_publish.c and lib/handle_pub*.c. Commit the broker action
    // before acknowledging the peer. QoS 2 PUBREL releases the staged input.
    async fn incoming(
        &self,
        config: &BridgeConfig,
        session: &BridgeSession,
        wire: &mut Wire,
        packet: Packet,
        ping: &mut Option<Instant>,
    ) -> Result<Option<bool>, Error> {
        let id = self.local_id;
        match packet {
            Packet::Publish(mut publish) => {
                if publish.qos as u8 > self.max_qos as u8 {
                    tracing::info!("Too high QoS in PUBLISH from {id}, disconnecting.");
                    return Err(Error::ProtocolReason(R::QOS_NOT_SUPPORTED));
                }
                wire.resolve_alias(&mut publish)?;
                remap(&mut publish.topic, config, true);
                if mqx_topic::validate_topic_name(&publish.topic).is_err() {
                    return Err(Error::ProtocolReason(R::MALFORMED_PACKET));
                }
                let mid = publish.packet_id;
                let qos = publish.qos;
                tracing::debug!(
                    "Received PUBLISH from {id} (d{}, q{}, r{}, m{}, '{}', ... ({} bytes))",
                    u8::from(publish.dup),
                    qos as u8,
                    u8::from(publish.retain),
                    mid.map_or(0, legacy::PacketId::get),
                    publish.topic,
                    publish.payload.len()
                );
                let reason = session.receive(publish).await?;
                if let Some(mid) = mid {
                    let ack = ack(
                        mid,
                        if reason.0 >= 0x80 || qos == QoS::AtLeastOnce {
                            if self.protocol != Protocol::V5 && reason == R::NO_MATCHING_SUBSCRIBERS
                            {
                                R::SUCCESS
                            } else {
                                reason
                            }
                        } else {
                            R::SUCCESS
                        },
                    );
                    if qos == QoS::AtLeastOnce {
                        tracing::debug!("Sending PUBACK to {id} (m{mid}, rc{})", ack.reason.0);
                        wire.send(Packet::PubAck(ack)).await?;
                    } else {
                        tracing::debug!("Sending PUBREC to {id} (m{mid}, rc{})", ack.reason.0);
                        wire.send(Packet::PubRec(ack)).await?;
                    }
                }
            }
            Packet::PubAck(ack) => {
                tracing::debug!(
                    "Received PUBACK from {id} (Mid: {}, RC:{})",
                    ack.packet_id,
                    ack.reason.0
                );
                session
                    .acknowledge(ack.packet_id, BridgeAck::PubAck)
                    .await?;
            }
            Packet::PubRec(p) => {
                let mid = p.packet_id;
                tracing::debug!("Received PUBREC from {id} (Mid: {mid})");
                if p.reason.0 >= 0x80 {
                    session.acknowledge(mid, BridgeAck::Reject).await?;
                } else {
                    session.acknowledge(mid, BridgeAck::PubRec).await?;
                    tracing::debug!("Sending PUBREL to {id} (m{mid})");
                    wire.send(Packet::PubRel(ack(mid, R::SUCCESS))).await?;
                }
            }
            Packet::PubRel(p) => {
                let mid = p.packet_id;
                tracing::debug!("Received PUBREL from {id} (Mid: {mid})");
                session.release(mid).await?;
                tracing::debug!("Sending PUBCOMP to {id} (m{mid})");
                wire.send(Packet::PubComp(ack(mid, R::SUCCESS))).await?;
            }
            Packet::PubComp(ack) => {
                tracing::debug!(
                    "Received PUBCOMP from {id} (Mid: {}, RC:{})",
                    ack.packet_id,
                    ack.reason.0
                );
                session
                    .acknowledge(ack.packet_id, BridgeAck::PubComp)
                    .await?;
            }
            Packet::SubAck(_) => tracing::debug!("Received SUBACK from {id}"),
            Packet::UnsubAck(_) => tracing::debug!("Received UNSUBACK from {id}"),
            Packet::PingResp => {
                tracing::debug!("Received PINGRESP from {id}");
                *ping = None;
            }
            Packet::PingReq => {
                tracing::debug!("Received PINGREQ from {id}");
                tracing::debug!("Sending PINGRESP to {id}");
                wire.send(Packet::PingResp).await?;
            }
            Packet::Disconnect(props) => {
                tracing::debug!("Received DISCONNECT from {id}");
                return Ok(Some(props.reason != R::DISCONNECT_WITH_WILL_MESSAGE));
            }
            _ => return Err(Error::Protocol),
        }
        Ok(None)
    }

    async fn outgoing(
        &self,
        config: &BridgeConfig,
        session: &BridgeSession,
        wire: &mut Wire,
        mut packet: Packet,
    ) -> Result<(), Error> {
        let mid = match &mut packet {
            Packet::Publish(p) => {
                remap(&mut p.topic, config, false);
                p.retain &= self.retain;
                tracing::debug!(
                    "Sending PUBLISH to {} (d{}, q{}, r{}, m{}, '{}', ... ({} bytes))",
                    self.local_id,
                    u8::from(p.dup),
                    p.qos as u8,
                    u8::from(p.retain),
                    p.packet_id.map_or(0, legacy::PacketId::get),
                    p.topic,
                    p.payload.len()
                );
                p.packet_id
            }
            Packet::PubRel(p) => {
                tracing::debug!("Sending PUBREL to {} (m{})", self.local_id, p.packet_id);
                None
            }
            _ => unreachable!("bridge inbox only yields PUBLISH and PUBREL"),
        };
        if !wire.send(packet).await?
            && let Some(mid) = mid
        {
            session.acknowledge(mid, BridgeAck::Drop).await?;
        }
        Ok(())
    }

    fn notification_qos(&self) -> QoS {
        cap_qos(QoS::AtLeastOnce, self.max_qos)
    }

    fn will(&self) -> Option<LastWill> {
        Some(LastWill {
            topic: self.notification.clone()?,
            payload: Bytes::from_static(b"0"),
            qos: self.notification_qos(),
            retain: true,
        })
    }

    // src/bridge.c: bridge__update_backoff / bridge__backoff_step. The
    // default prior delay is zero; the C remainder uses |high - low|.
    fn advance_backoff(&mut self, config: &BridgeConfig) {
        let Restart {
            base_ms,
            cap_ms,
            stable_secs,
            ..
        } = config.restart;
        if cap_ms == 0 {
            return;
        }
        if self
            .connected_at
            .take()
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(stable_secs))
        {
            tracing::info!(
                "Bridge {} connection was stable enough, resetting backoff",
                config.name
            );
            self.backoff_ms = base_ms;
        } else {
            let width = (self.backoff_ms * 3).abs_diff(base_ms);
            let mut random = [0; 4];
            self.backoff_ms = if width != 0 && getrandom::fill(&mut random).is_ok() {
                (base_ms + u64::from(i32::from_ne_bytes(random).unsigned_abs()) % width).min(cap_ms)
            } else {
                base_ms
            };
        }
        tracing::info!(
            "Bridge {} next backoff will be {} ms",
            config.name,
            self.backoff_ms
        );
    }
}

async fn replacement(
    changes: &mut watch::Receiver<Option<Arc<BridgeConfig>>>,
    old: &Arc<BridgeConfig>,
    disconnected: bool,
) {
    loop {
        if changes
            .borrow_and_update()
            .as_ref()
            .is_none_or(|new| !Arc::ptr_eq(old, new) && (disconnected || new.reload_immediate))
        {
            return;
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

async fn until(instant: Option<Instant>) {
    if let Some(instant) = instant {
        time::sleep_until(instant).await;
    } else {
        std::future::pending().await
    }
}

fn outbound_filters(config: &BridgeConfig, maximum: QoS) -> Vec<(String, QoS)> {
    config
        .topics
        .iter()
        .filter(|topic| topic.outgoing())
        .map(|topic| (topic.local_filter.clone(), cap_qos(topic.qos, maximum)))
        .collect()
}

fn cap_qos(qos: QoS, maximum: QoS) -> QoS {
    if qos as u8 > maximum as u8 {
        maximum
    } else {
        qos
    }
}
fn qos(qos: u8) -> QoS {
    match qos {
        0 => QoS::AtMostOnce,
        1 => QoS::AtLeastOnce,
        _ => QoS::ExactlyOnce,
    }
}

fn ack(packet_id: legacy::PacketId, reason: R) -> PublishAck {
    PublishAck {
        packet_id,
        reason,
        properties: Vec::new(),
    }
}

// src/bridge_topic.c: bridge__remap_topic_in and lib/send_publish.c:
// send__publish. Rules without prefixes do not participate in remapping.
fn remap(topic: &mut String, config: &BridgeConfig, incoming: bool) {
    for rule in &config.topics {
        let (filter, strip, add) = if incoming && rule.incoming() {
            (&rule.remote_filter, &rule.remote_prefix, &rule.local_prefix)
        } else if !incoming && rule.outgoing() {
            (&rule.local_filter, &rule.local_prefix, &rule.remote_prefix)
        } else {
            continue;
        };
        if (strip.is_some() || add.is_some()) && mqx_topic::matches(filter, topic).unwrap_or(false)
        {
            if let Some(prefix) = strip
                && topic.starts_with(prefix)
            {
                topic.drain(..prefix.len());
            }
            if let Some(prefix) = add {
                topic.insert_str(0, prefix);
            }
            return;
        }
    }
}

// libcommon/strings_common.c: mosquitto_reason_string.
fn reason_string(reason: u8) -> &'static str {
    match reason {
        0x01 => "Granted QoS 1",
        0x02 => "Granted QoS 2",
        0x04 => "Disconnect with Will Message",
        0x10 => "No matching subscribers",
        0x11 => "No subscription existed",
        0x18 => "Continue authentication",
        0x19 => "Re-authenticate",
        0x80 => "Unspecified error",
        0x81 => "Malformed Packet",
        0x82 => "Protocol Error",
        0x83 => "Implementation specific error",
        0x84 => "Unsupported Protocol Version",
        0x85 => "Client Identifier not valid",
        0x86 => "Bad User Name or Password",
        0x87 => "Not authorized",
        0x88 => "Server unavailable",
        0x89 => "Server busy",
        0x8a => "Banned",
        0x8b => "Server shutting down",
        0x8c => "Bad authentication method",
        0x8d => "Keep Alive timeout",
        0x8e => "Session taken over",
        0x8f => "Topic Filter invalid",
        0x90 => "Topic Name invalid",
        0x91 => "Packet Identifier in use",
        0x92 => "Packet Identifier not found",
        0x93 => "Receive Maximum exceeded",
        0x94 => "Topic Alias invalid",
        0x95 => "Packet too large",
        0x96 => "Message rate too high",
        0x97 => "Quota exceeded",
        0x98 => "Administrative action",
        0x99 => "Payload format invalid",
        0x9c => "Use another server",
        0x9d => "Server moved",
        0x9e => "Shared Subscriptions not supported",
        0x9f => "Connection rate exceeded",
        0xa0 => "Maximum connect time",
        0xa1 => "Subscription identifiers not supported",
        0xa2 => "Wildcard Subscriptions not supported",
        _ => "Unknown reason",
    }
}
