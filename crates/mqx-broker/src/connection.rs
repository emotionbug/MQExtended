use std::{
    fmt,
    future::{Future, pending, poll_fn},
    net::SocketAddr,
    pin::{Pin, pin},
    sync::{Arc, atomic::Ordering},
    task::Poll,
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use mqx_auth::BasicAuth;
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode as Code, DecodeContext, DecodeError, Packet,
    ProtocolVersion, Publish, QoS, SubAck, decode, encode,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::watch,
    time::{Instant, sleep_until},
};

use crate::{
    Broker, BrokerConfig, BrokerError, CertIdentity, ConnectionInfo, Live, Security,
    inbox::{Ack, Outbound, Publisher},
    state::{Claim, Operation, Reply},
};

pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    broker: &Broker,
    stream: S,
    info: ConnectionInfo,
    accepted_at: Instant,
) -> Result<(), BrokerError> {
    let config = &broker.0.config;
    let mut wire = Wire::new(stream);
    let mut shutdown = broker.0.shutdown.subscribe();
    // context.c: context__init gives peers 20 seconds of keepalive before CONNECT.
    let initial_deadline = accepted_at + keepalive_period(20);
    let mut connect = loop {
        if *shutdown.borrow() || Instant::now() >= initial_deadline {
            return Ok(());
        }
        match wire.packet(config, None) {
            Ok(Some(Packet::Connect(connect))) => break connect,
            Ok(Some(_)) => return Err(BrokerError::Protocol),
            Ok(None) => {}
            Err(BrokerError::Decode(DecodeError::UnacceptableProtocolVersion { .. })) => {
                return refuse(&mut wire, &mut shutdown, Code::UnacceptableProtocolVersion).await;
            }
            Err(error) => return Err(error),
        }
        if wire.eof {
            return Ok(());
        }
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = sleep_until(initial_deadline) => return Ok(()),
            result = wire.progress(true) => result?,
        }
    };

    let listener = &info.listener;
    let mut security = listener.security.0.snapshots.subscribe();
    let identity = match prepare(config, &info, &mut connect)? {
        Preparation::Accepted(identity) => identity,
        Preparation::Refused(code) => return refuse(&mut wire, &mut shutdown, code).await,
        Preparation::Close => return Ok(()),
    };
    let security_snapshot = security.borrow_and_update().clone();
    if !identity.authorized(security_snapshot).await {
        return refuse(&mut wire, &mut shutdown, Code::NotAuthorized).await;
    }
    if *shutdown.borrow() {
        return Ok(());
    }

    let publisher = Publisher {
        id: Arc::from(connect.client_id),
        username: identity.username.clone(),
        security: 0, // Filled by the log backend before claiming the session.
    };
    let Some((live, present)) = broker
        .claim(
            &listener.security,
            Claim {
                publisher,
                transient: connect.clean_session,
                bridge: connect.is_bridge,
                max_qos: listener.max_qos,
                will: connect.will,
            },
        )
        .await?
    else {
        return Ok(());
    };
    let present = present && connect.protocol == ProtocolVersion::V311;
    let mut session = Active {
        broker,
        live,
        graceful: false,
        detached: false,
    };
    if config.connection_messages {
        log_connected(
            info.peer_addr,
            &session.live.lease.id,
            &connect.protocol,
            connect.clean_session,
            connect.keep_alive,
            &identity,
            connect.is_bridge,
        );
    }

    // handle_connect.c: connect__on_authorised checks this after takeover and
    // includes the computed session-present flag even in a v3.x refusal.
    let too_long = config.max_keepalive != 0
        && (connect.keep_alive == 0 || connect.keep_alive > config.max_keepalive);
    wire.output(&Packet::ConnAck(ConnAck {
        session_present: present,
        code: if too_long {
            Code::IdentifierRejected
        } else {
            Code::Accepted
        },
    }))?;

    let mut deadline = deadline(connect.keep_alive);
    let mut delivering = !too_long;
    let mut prefer_input = false;
    let mut deferred = None;
    let result = 'active: loop {
        if session.live.taken.load(Ordering::Acquire) {
            break Ok(End::Takeover);
        }
        if *shutdown.borrow() {
            break Ok(End::Shutdown);
        }
        if security.has_changed().unwrap_or(false)
            && !reauthenticate(&identity, &mut security).await
        {
            break Ok(End::Security);
        }
        if wire.idle() {
            if too_long {
                break Ok(End::KeepaliveRefused);
            }
            if delivering && (!prefer_input || deferred.is_some()) {
                match session.broker.next_outbound(&session.live).await {
                    Ok(Some(outbound)) => {
                        if let Err(error) = wire.delivery(outbound, listener.mount_point.as_deref())
                        {
                            break Err(error);
                        }
                        prefer_input = true;
                        continue;
                    }
                    Ok(None) => delivering = false,
                    Err(error) => break Err(error),
                }
            }
            if let Some(ack) = deferred.take() {
                if let Err(error) = wire.output(&ack) {
                    break Err(error);
                }
                continue;
            }
            match wire.packet(config, Some(connect.protocol)) {
                Ok(Some(packet)) => {
                    prefer_input = false;
                    deadline = self::deadline(connect.keep_alive);
                    match session.process(packet, &info).await {
                        Ok(Step::Continue) => delivering = true,
                        Ok(Step::Reply(packet)) => {
                            if let Err(error) = wire.output(&packet) {
                                break Err(error);
                            }
                            delivering = true;
                        }
                        Ok(Step::ReplyAfterDelivery(packet)) => {
                            deferred = Some(packet);
                            delivering = true;
                        }
                        Ok(Step::EmptySubAck(id)) => {
                            // handle_subscribe.c: handle__subscribe accepts an
                            // empty v3.1 SUBSCRIBE and sends an empty SUBACK.
                            let [hi, lo] = id.get().to_be_bytes();
                            wire.output.extend_from_slice(&[0x90, 2, hi, lo]);
                        }
                        Ok(Step::End(end)) => break Ok(end),
                        Err(error) => break Err(error),
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) => break Err(error),
            }
            if wire.eof {
                break Ok(End::Eof);
            }
            if delivering {
                prefer_input = false;
                continue;
            }
        }

        tokio::select! {
            biased;
            _ = shutdown.changed() => break Ok(End::Shutdown),
            // Mark and use the exact security snapshot observed by this wakeup.
            snapshot = wait_security(&mut security) => {
                if !identity.authorized(snapshot).await { break Ok(End::Security); }
            }
            _ = timeout(deadline) => break Ok(End::Timeout),
            result = wire.progress(!too_long) => if let Err(error) = result { break 'active Err(error.into()); },
            _ = session.live.ready.notified() => delivering = true,
        }
    };
    session.graceful = matches!(result, Ok(End::Disconnect | End::Security));
    if config.connection_messages {
        log_disconnected(info.peer_addr, &session.live.lease.id, &result);
    }
    let detached = broker
        .detach(session.live.lease.clone(), session.graceful)
        .await;
    session.detached = true;
    result.map(|_| ()).and(detached)
}

struct Identity {
    username: Option<Arc<str>>,
    password: Option<Bytes>,
    certificate: bool,
    allow_anonymous: bool,
}

impl Identity {
    // plugin_basic_auth.c: mosquitto_basic_auth. A password file that abstains
    // on anonymous credentials lets allow_anonymous decide; a denial never does.
    async fn authorized(&self, snapshot: Arc<Security>) -> bool {
        if self.certificate {
            return true;
        }
        match (
            snapshot.password.as_ref(),
            self.username.as_ref(),
            self.password.as_ref(),
        ) {
            (Some(_), Some(username), Some(password)) => {
                let username = username.clone();
                let password = password.clone();
                tokio::task::spawn_blocking(move || {
                    snapshot
                        .password
                        .as_ref()
                        .unwrap()
                        .check(Some(&username), Some(&password))
                        == BasicAuth::Allow
                })
                .await
                .unwrap_or(false)
            }
            (Some(_), Some(_), None) => false,
            _ => self.allow_anonymous,
        }
    }
}

async fn wait_security(receiver: &mut watch::Receiver<Arc<Security>>) -> Arc<Security> {
    receiver
        .changed()
        .await
        .expect("the connection owns its security handle");
    receiver.borrow_and_update().clone()
}

async fn reauthenticate(
    identity: &Identity,
    receiver: &mut watch::Receiver<Arc<Security>>,
) -> bool {
    let snapshot = receiver.borrow_and_update().clone();
    identity.authorized(snapshot).await
}

enum Preparation {
    Accepted(Identity),
    Refused(Code),
    Close,
}

fn prepare(
    config: &BrokerConfig,
    info: &ConnectionInfo,
    connect: &mut Connect,
) -> Result<Preparation, BrokerError> {
    let listener = &info.listener;
    if match connect.protocol {
        ProtocolVersion::V31 => listener.disable_protocol_v3,
        ProtocolVersion::V311 => listener.disable_protocol_v4,
    } {
        return Ok(Preparation::Refused(Code::UnacceptableProtocolVersion));
    }
    if connect.will.as_ref().is_some_and(|will| {
        (will.retain && !config.retain_available) || will.qos as u8 > listener.max_qos as u8
    }) {
        return Ok(Preparation::Close);
    }
    // handle_connect.c: handle_zero_length_clientid and check_clientid_prefixes
    // run before processing credentials, even with use_username_as_clientid.
    if connect.client_id.is_empty() {
        if connect.protocol == ProtocolVersion::V31
            || !connect.clean_session
            || !listener
                .allow_zero_length_clientid
                .unwrap_or(config.allow_zero_length_clientid)
        {
            return Ok(Preparation::Refused(Code::IdentifierRejected));
        }
        connect.client_id = generate_id(
            listener
                .auto_id_prefix
                .as_deref()
                .unwrap_or(&config.auto_id_prefix),
        )?;
    }
    if config
        .clientid_prefixes
        .as_ref()
        .is_some_and(|prefix| !connect.client_id.starts_with(prefix))
    {
        return Ok(Preparation::Refused(Code::NotAuthorized));
    }
    if let Some(will) = &mut connect.will {
        if config.message_size_limit != 0 && will.payload.len() > config.message_size_limit {
            return Ok(Preparation::Refused(Code::NotAuthorized));
        }
        mount(&mut will.topic, listener.mount_point.as_deref());
    }
    // handle_connect.c: handle_username_from_cert_options ignores the MQTT
    // credentials entirely when a mapped TLS identity is required.
    let (username, password, certificate) = match &info.cert_identity {
        CertIdentity::Username(username) if !username.contains('\0') => {
            (Some(username.clone()), None, true)
        }
        CertIdentity::Username(_) | CertIdentity::MissingOrInvalid => {
            return Ok(Preparation::Refused(Code::BadUserNameOrPassword));
        }
        CertIdentity::None => (
            connect.username.take().filter(|value| !value.is_empty()),
            connect.password.take().filter(|value| !value.is_empty()),
            false,
        ),
    };
    if listener.use_username_as_clientid {
        // handle_connect.c: handle_username_as_clientid_option.
        let Some(username) = &username else {
            return Ok(Preparation::Refused(Code::NotAuthorized));
        };
        connect.client_id.clone_from(username);
    }
    Ok(Preparation::Accepted(Identity {
        username: username.map(Arc::from),
        password,
        certificate,
        allow_anonymous: listener.allow_anonymous.unwrap_or(config.allow_anonymous),
    }))
}

// handle_connect.c: clientid_gen uses uppercase hex, low nibble first, with
// separators in UUID positions and no version/variant bits forced.
fn generate_id(prefix: &str) -> Result<String, BrokerError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(BrokerError::ClientId)?;
    let mut id = String::with_capacity(prefix.len() + 36);
    id.push_str(prefix);
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (index, byte) in random.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        id.push(char::from(HEX[(byte & 15) as usize]));
        id.push(char::from(HEX[(byte >> 4) as usize]));
    }
    Ok(id)
}

fn mount(topic: &mut String, prefix: Option<&str>) {
    if let Some(prefix) = prefix {
        topic.insert_str(0, prefix);
    }
}

async fn refuse<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    shutdown: &mut watch::Receiver<bool>,
    code: Code,
) -> Result<(), BrokerError> {
    wire.output(&Packet::ConnAck(ConnAck {
        session_present: false,
        code,
    }))?;
    while !wire.idle() {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            result = wire.progress(false) => result?,
        }
    }
    Ok(())
}

fn keepalive_period(value: u16) -> Duration {
    Duration::from_millis(u64::from(value) * 1500)
}

fn deadline(value: u16) -> Option<Instant> {
    // keepalive.c: keepalive__check applies the 1.5× receive timeout.
    (value != 0).then(|| Instant::now() + keepalive_period(value))
}

async fn timeout(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        sleep_until(deadline).await;
    } else {
        pending().await
    }
}

struct Active<'a> {
    broker: &'a Broker,
    live: Arc<Live>,
    graceful: bool,
    detached: bool,
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        if !self.detached {
            self.broker
                .detach_cancelled(self.live.lease.clone(), self.graceful);
        }
    }
}

impl Active<'_> {
    async fn act(&self, operation: Operation) -> Result<Reply, BrokerError> {
        self.broker.act(&self.live, operation).await
    }

    async fn process(&self, packet: Packet, info: &ConnectionInfo) -> Result<Step, BrokerError> {
        let config = &self.broker.0.config;
        let mount_point = info.listener.mount_point.as_deref();
        let max_qos = info.listener.max_qos;
        match packet {
            Packet::Disconnect => Ok(Step::End(End::Disconnect)),
            Packet::PingReq => Ok(Step::Reply(Packet::PingResp)),
            Packet::Subscribe(mut sub) => {
                for (filter, qos) in &mut sub.filters {
                    mount(filter, mount_point);
                    if *qos as u8 > max_qos as u8 {
                        *qos = max_qos;
                    }
                }
                match self.act(Operation::Subscribe(sub.filters)).await? {
                    Reply::Subscribed(codes) if codes.is_empty() => {
                        Ok(Step::EmptySubAck(sub.packet_id))
                    }
                    Reply::Subscribed(return_codes) => Ok(Step::Reply(Packet::SubAck(SubAck {
                        packet_id: sub.packet_id,
                        return_codes,
                    }))),
                    reply => action_result(reply),
                }
            }
            Packet::Unsubscribe(mut unsub) => {
                for filter in &mut unsub.filters {
                    mount(filter, mount_point);
                }
                let step = action_result(self.act(Operation::Unsubscribe(unsub.filters)).await?)?;
                Ok(step.or_reply(Packet::UnsubAck(unsub.packet_id), false))
            }
            Packet::Publish(mut publish) => {
                // handle_publish.c: handle__publish disconnects for unsupported
                // retain/QoS, instead of the acknowledged ACL/size rejection.
                if publish.qos as u8 > max_qos as u8 || (publish.retain && !config.retain_available)
                {
                    return Ok(Step::End(End::Unsupported));
                }
                mount(&mut publish.topic, mount_point);
                let id = publish.packet_id;
                let qos = publish.qos;
                let mut reply = self.act(Operation::Receive(publish)).await?;
                if let Reply::ReceiveLocal(message) = reply {
                    let id = id.unwrap();
                    let inbox = self.live.inbox.as_ref().unwrap();
                    reply = match message {
                        None => {
                            inbox.lock().unwrap().credit_incoming();
                            Reply::NoChange
                        }
                        Some(message) if qos == QoS::ExactlyOnce => {
                            if inbox.lock().unwrap().receive(id, message, config) {
                                Reply::NoChange
                            } else {
                                Reply::ProtocolError
                            }
                        }
                        Some(message) => {
                            let allowed = inbox.lock().unwrap().can_publish_qos1(id, config);
                            if allowed {
                                self.act(Operation::Forward(message)).await?
                            } else {
                                Reply::NoChange
                            }
                        }
                    };
                }
                let step = action_result(reply)?;
                Ok(match id {
                    Some(id) if qos == QoS::ExactlyOnce => step.or_reply(Packet::PubRec(id), false),
                    Some(id) => step.or_reply(Packet::PubAck(id), true),
                    None => step,
                })
            }
            Packet::PubRel(id) => {
                let reply = if let Some(inbox) = &self.live.inbox {
                    let message = inbox.lock().unwrap().release(id);
                    if let Some(message) = message {
                        self.act(Operation::Forward(message)).await?
                    } else {
                        Reply::NoChange
                    }
                } else {
                    self.act(Operation::Release(id)).await?
                };
                Ok(action_result(reply)?.or_reply(Packet::PubComp(id), true))
            }
            Packet::PubAck(id) => self.ack(id, Ack::Acknowledged).await,
            Packet::PubRec(id) => Ok(self
                .ack(id, Ack::Received)
                .await?
                .or_reply(Packet::PubRel(id), false)),
            Packet::PubComp(id) => self.ack(id, Ack::Completed).await,
            Packet::Connect(_)
            | Packet::ConnAck(_)
            | Packet::PingResp
            | Packet::SubAck(_)
            | Packet::UnsubAck(_) => Err(BrokerError::Protocol),
        }
    }

    async fn ack(&self, id: mqx_codec::PacketId, ack: Ack) -> Result<Step, BrokerError> {
        if let Some(inbox) = &self.live.inbox {
            if inbox.lock().unwrap().ack(id, ack, &self.broker.0.config) {
                Ok(Step::Continue)
            } else {
                Err(BrokerError::Protocol)
            }
        } else {
            action_result(self.act(Operation::Ack(id, ack)).await?)
        }
    }
}

fn action_result(reply: Reply) -> Result<Step, BrokerError> {
    match reply {
        Reply::NoChange => Ok(Step::Continue),
        Reply::Stale => Ok(Step::End(End::Takeover)),
        Reply::ProtocolError => Err(BrokerError::Protocol),
        _ => unreachable!(),
    }
}

enum Step {
    Continue,
    Reply(Packet),
    ReplyAfterDelivery(Packet),
    EmptySubAck(mqx_codec::PacketId),
    End(End),
}

impl Step {
    fn or_reply(self, packet: Packet, after_delivery: bool) -> Self {
        match self {
            Self::Continue if after_delivery => Self::ReplyAfterDelivery(packet),
            Self::Continue => Self::Reply(packet),
            _ => self,
        }
    }
}

enum End {
    Disconnect,
    Eof,
    Timeout,
    Security,
    Shutdown,
    Takeover,
    Unsupported,
    KeepaliveRefused,
}

struct Wire<S> {
    stream: S,
    input: BytesMut,
    output: BytesMut,
    written: usize,
    flush: bool,
    eof: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            input: BytesMut::new(),
            output: BytesMut::new(),
            written: 0,
            flush: false,
            eof: false,
        }
    }

    fn idle(&self) -> bool {
        self.output.is_empty() && !self.flush
    }

    fn packet(
        &mut self,
        config: &BrokerConfig,
        protocol: Option<ProtocolVersion>,
    ) -> Result<Option<Packet>, BrokerError> {
        let mut max = config.max_packet_size;
        if let Some(&header) = self.input.first() {
            // lib/packet_mosq.c: packet__read_single rejects a non-CONNECT
            // first command before even reading its remaining length.
            let connect = header & 0xf0 == 0x10;
            if connect != protocol.is_none() {
                return Err(BrokerError::Protocol);
            }
            if connect {
                // lib/packet_mosq.c: packet__check_in_packet_oversize.
                const CONNECT_MAX: usize = 100_000;
                max = if max == 0 {
                    CONNECT_MAX
                } else {
                    max.min(CONNECT_MAX)
                };
            }
        }
        Ok(decode(&mut self.input, DecodeContext::new(max, protocol))?)
    }

    fn output(&mut self, packet: &Packet) -> Result<(), BrokerError> {
        Ok(encode(packet, &mut self.output)?)
    }

    fn delivery(
        &mut self,
        outbound: Outbound,
        mount_point: Option<&str>,
    ) -> Result<(), BrokerError> {
        let packet = match outbound {
            Outbound::Release(id) => Packet::PubRel(id),
            Outbound::Publish { delivery, id, dup } => {
                // lib/send_publish.c: send__publish strips the destination
                // listener's mount point by length before writing to the wire.
                let Some(topic) = delivery
                    .message
                    .topic
                    .get(mount_point.map_or(0, str::len)..)
                    .filter(|topic| !topic.is_empty())
                else {
                    return Ok(());
                };
                Packet::Publish(Publish {
                    dup,
                    qos: delivery.qos,
                    retain: delivery.retain,
                    topic: topic.to_owned(),
                    packet_id: id,
                    payload: delivery.message.payload.clone(),
                })
            }
        };
        self.output(&packet)
    }

    // Drive both halves without splitting the transport or letting another
    // MQTT packet accumulate in the output buffer behind a stalled write.
    async fn progress(&mut self, read: bool) -> std::io::Result<()> {
        poll_fn(|cx| {
            let mut progress = false;
            if !self.output.is_empty() {
                match Pin::new(&mut self.stream).poll_write(cx, &self.output[self.written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Ready(Ok(written)) => {
                        self.written += written;
                        if self.written == self.output.len() {
                            self.written = 0;
                            self.output.clear();
                            self.flush = true;
                        }
                        progress = true;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
            if self.flush {
                match Pin::new(&mut self.stream).poll_flush(cx) {
                    Poll::Ready(result) => {
                        result?;
                        self.flush = false;
                        progress = true;
                    }
                    Poll::Pending => {}
                }
            }
            // A backpressured client cannot make us buffer unlimited input.
            if read && self.idle() && !self.eof {
                if self.input.capacity() == self.input.len() {
                    self.input.reserve(4096);
                }
                let read = self.stream.read_buf(&mut self.input);
                match pin!(read).poll(cx) {
                    Poll::Ready(result) => {
                        self.eof = result? == 0;
                        progress = true;
                    }
                    Poll::Pending => {}
                }
            }
            if progress {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

pub(super) struct Address(pub(super) Option<SocketAddr>);

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(address) = self.0 {
            // Mosquitto prints the address and port separately, with no IPv6 brackets.
            write!(formatter, "{}:{}", address.ip(), address.port())
        } else {
            formatter.write_str("unknown:0")
        }
    }
}

fn log_connected(
    addr: Option<SocketAddr>,
    id: &str,
    protocol: &ProtocolVersion,
    clean: bool,
    keepalive: u16,
    identity: &Identity,
    bridge: bool,
) {
    // handle_connect.c: connect__on_authorised. Mosquitto 2.1.4's
    // mosquitto_internal.h protocol enum uses the wire versions (3 and 4).
    let protocol = match protocol {
        ProtocolVersion::V31 => 3,
        ProtocolVersion::V311 => 4,
    };
    let kind = if bridge { "bridge" } else { "client" };
    let clean = u8::from(clean);
    let addr = Address(addr);
    if let Some(username) = &identity.username {
        tracing::info!(
            "New {kind} connected from {addr} as {id} (p{protocol}, c{clean}, k{keepalive}, u'{username}')."
        );
    } else {
        tracing::info!(
            "New {kind} connected from {addr} as {id} (p{protocol}, c{clean}, k{keepalive})."
        );
    }
}

fn log_disconnected(addr: Option<SocketAddr>, id: &str, result: &Result<End, BrokerError>) {
    let addr = Address(addr);
    // loop.c: do_disconnect distinguishes an MQTT DISCONNECT from EOF/failure.
    let reason = match result {
        Ok(End::Disconnect | End::Security | End::Shutdown) => {
            tracing::info!("Client {id} [{addr}] disconnected.");
            return;
        }
        Ok(End::Eof) => "connection closed by client",
        Ok(End::Timeout) => "exceeded timeout",
        Ok(End::Takeover) => "session taken over",
        Ok(End::Unsupported) => {
            "used disallowed feature (QoS too high, retain not supported, or bad AUTH method)"
        }
        Ok(End::KeepaliveRefused) => "bad socket read/write: Invalid function arguments provided.",
        Err(BrokerError::Io(error)) => {
            tracing::info!("Client {id} [{addr}] disconnected: {error}.");
            return;
        }
        Err(BrokerError::Decode(DecodeError::PacketTooLarge { .. })) => "oversize packet",
        Err(BrokerError::Decode(_)) => "malformed packet",
        Err(_) => "protocol error",
    };
    tracing::info!("Client {id} [{addr}] disconnected: {reason}.");
}
