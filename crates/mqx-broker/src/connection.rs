mod v5;

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
use mqx_codec::v5::{self as codec5, Packet as Packet5, Property, ReasonCode as R};
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
    inbox::{Ack, Outbound, Publisher, Receive},
    runtime::ClaimResult,
    state::{Claim, Operation, Publication, Reply, SubscriptionRequest},
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
    let (mut connect, options, v5_settings) = loop {
        if *shutdown.borrow() || Instant::now() >= initial_deadline {
            return Ok(());
        }
        match wire.connect(config) {
            Ok(Some(Frame::Legacy(Packet::Connect(connect)))) => break (connect, None, None),
            Ok(Some(Frame::V5(Packet5::Connect(connect)))) => {
                // handle_connect.c: read_and_verify_protocol_version refuses
                // before the peer's Maximum Packet Size can affect CONNACK.
                if info.listener.disable_protocol_v5 {
                    return refuse_v5(
                        &mut wire,
                        &mut shutdown,
                        config,
                        &info,
                        R::UNSUPPORTED_PROTOCOL_VERSION,
                    )
                    .await;
                }
                let (connect, options, settings) = v5::Negotiated::connect(connect);
                wire.v5 = Some(v5::WireState::new(&info.listener, &options));
                break (connect, Some(options), Some(settings));
            }
            Ok(Some(_)) => return Err(BrokerError::Protocol),
            Ok(None) => {}
            Err(BrokerError::Decode(DecodeError::UnacceptableProtocolVersion { level })) => {
                if !matches!(level & 0x7f, 3..=5) {
                    return refuse_v5(
                        &mut wire,
                        &mut shutdown,
                        config,
                        &info,
                        R::UNSUPPORTED_PROTOCOL_VERSION,
                    )
                    .await;
                }
                return refuse(&mut wire, &mut shutdown, Code::UnacceptableProtocolVersion).await;
            }
            Err(BrokerError::DecodeV5(error)) => {
                let reason = if info.listener.disable_protocol_v5
                    && !matches!(error.kind, codec5::DecodeErrorKind::PacketTooLarge { .. })
                {
                    R::UNSUPPORTED_PROTOCOL_VERSION
                } else if let Some(codec5::ErrorResponse::ConnAck(reason)) = error.response {
                    reason
                } else {
                    return Err(error.into());
                };
                return refuse_v5(&mut wire, &mut shutdown, config, &info, reason).await;
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
    let identity = match prepare(config, &info, &mut connect, options.as_ref())? {
        Preparation::Accepted(identity) => identity,
        Preparation::Refused(code, reason) => {
            if options.is_some() {
                return refuse_v5(&mut wire, &mut shutdown, config, &info, reason).await;
            }
            return refuse(&mut wire, &mut shutdown, code).await;
        }
        Preparation::Close => return Ok(()),
    };
    // handle_connect.c: handle__connect_auth and plugin_extended_auth.c:
    // mosquitto_security_auth_start refuse unsupported methods before basic auth.
    if options
        .as_ref()
        .is_some_and(|options| options.authentication)
    {
        return refuse_v5(
            &mut wire,
            &mut shutdown,
            config,
            &info,
            R::BAD_AUTHENTICATION_METHOD,
        )
        .await;
    }
    let security_snapshot = security.borrow_and_update().clone();
    if !identity.authorized(security_snapshot).await {
        if options.is_some() {
            return refuse_v5(&mut wire, &mut shutdown, config, &info, R::NOT_AUTHORIZED).await;
        }
        return refuse(&mut wire, &mut shutdown, Code::NotAuthorized).await;
    }
    if *shutdown.borrow() {
        return Ok(());
    }

    let assigned_id = options
        .as_ref()
        .filter(|options| options.assigned_id)
        .map(|_| Property::AssignedClientIdentifier(connect.client_id.clone()));
    let publisher = Publisher {
        id: Arc::from(connect.client_id),
        username: identity.username.clone(),
        security: 0, // Filled by the log backend before claiming the session.
    };
    let (live, present) = match broker
        .claim(
            &listener.security,
            Claim {
                publisher,
                clean_start: connect.clean_session,
                bridge: connect.is_bridge,
                max_qos: listener.max_qos,
                will: connect.will,
                v5: v5_settings,
                now: Duration::ZERO, // Filled by the log backend when proposing.
            },
        )
        .await?
    {
        ClaimResult::Accepted(live, present) => (live, present),
        ClaimResult::Full if options.is_some() => {
            return refuse_v5(&mut wire, &mut shutdown, config, &info, R::SERVER_BUSY).await;
        }
        ClaimResult::Full | ClaimResult::Stale => return Ok(()),
    };
    let present = present && connect.protocol == ProtocolVersion::V311;
    let mut session = Active {
        broker,
        live,
        graceful: false,
        expiry_override: None,
        detached: false,
    };
    if config.connection_messages {
        log_connected(
            info.peer_addr,
            &session.live.lease.id,
            if options.is_some() {
                5
            } else if connect.protocol == ProtocolVersion::V31 {
                3
            } else {
                4
            },
            connect.clean_session,
            connect.keep_alive,
            &identity,
            connect.is_bridge,
        );
    }

    // handle_connect.c: connect__on_authorised checks this after takeover and
    // includes the computed session-present flag even in a v3.x refusal.
    let capped = config.max_keepalive != 0
        && (connect.keep_alive == 0 || connect.keep_alive > config.max_keepalive);
    let too_long = capped && options.is_none();
    if options.is_some() {
        let mut props = Vec::new();
        if capped {
            connect.keep_alive = config.max_keepalive;
            props.push(Property::ServerKeepAlive(connect.keep_alive));
        }
        if listener.max_topic_alias != 0 {
            props.push(Property::TopicAliasMaximum(listener.max_topic_alias));
        }
        props.extend(assigned_id);
        if !wire.connack_v5(&v5::connack(config, listener, present, R::SUCCESS, props))? {
            return Ok(());
        }
    } else {
        wire.output(&Packet::ConnAck(ConnAck {
            session_present: present,
            code: if too_long {
                Code::IdentifierRejected
            } else {
                Code::Accepted
            },
        }))?;
    }

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
                        match wire.delivery(outbound, listener.mount_point.as_deref(), broker.now())
                        {
                            Ok(Some(id)) => {
                                if let Err(error) = session.ack(id, Ack::Dropped).await {
                                    break Err(error);
                                }
                            }
                            Ok(None) => {}
                            Err(error) => break Err(error),
                        }
                        prefer_input = true;
                        continue;
                    }
                    Ok(None) => delivering = false,
                    Err(error) => break Err(error),
                }
            }
            if let Some(ack) = deferred.take() {
                if let Err(error) = wire.output_frame(&ack) {
                    break Err(error);
                }
                continue;
            }
            match wire.packet(config, connect.protocol) {
                Ok(Some(packet)) => {
                    prefer_input = false;
                    deadline = self::deadline(connect.keep_alive);
                    let step = match packet {
                        Frame::Legacy(packet) => session.process(packet, &info).await,
                        Frame::V5(packet) => {
                            session
                                .process_v5(
                                    packet,
                                    &info,
                                    wire.v5.as_mut().unwrap(),
                                    options.as_ref().unwrap().session_expiry,
                                )
                                .await
                        }
                    };
                    match step {
                        Ok(Step::Continue) => delivering = true,
                        Ok(Step::Reply(packet)) => {
                            if let Err(error) = wire.output_frame(&packet) {
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
    if options.is_some()
        && let Some(reason) = disconnect_reason(&result)
    {
        wire.terminate_v5(reason).await;
    }
    if config.connection_messages {
        log_disconnected(info.peer_addr, &session.live.lease.id, &result);
    }
    let detached = broker
        .detach(
            session.live.lease.clone(),
            session.graceful,
            session.expiry_override,
        )
        .await;
    session.detached = true;
    result.map(|_| ()).and(detached)
}

fn disconnect_reason(result: &Result<End, BrokerError>) -> Option<R> {
    // read_handle.c: handle__packet maps handler failures to DISCONNECT;
    // keepalive.c and the basic-auth reload path in security_default.c close
    // via do_disconnect directly, without an MQTT packet.
    match result {
        Ok(End::Takeover) => Some(R::SESSION_TAKEN_OVER),
        Err(BrokerError::Protocol) => Some(R::PROTOCOL_ERROR),
        Err(BrokerError::ProtocolV5(reason)) => Some(*reason),
        Err(BrokerError::DecodeV5(error)) => match error.response {
            Some(codec5::ErrorResponse::Disconnect(reason)) => Some(reason),
            _ => None,
        },
        _ => None,
    }
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
    Refused(Code, R),
    Close,
}

fn prepare(
    config: &BrokerConfig,
    info: &ConnectionInfo,
    connect: &mut Connect,
    v5: Option<&v5::Negotiated>,
) -> Result<Preparation, BrokerError> {
    let listener = &info.listener;
    if match (v5.is_some(), connect.protocol) {
        (true, _) => false,
        (false, ProtocolVersion::V31) => listener.disable_protocol_v3,
        (false, ProtocolVersion::V311) => listener.disable_protocol_v4,
    } {
        return Ok(Preparation::Refused(
            Code::UnacceptableProtocolVersion,
            R::UNSUPPORTED_PROTOCOL_VERSION,
        ));
    }
    if let Some(will) = &connect.will {
        let reason = if will.retain && !config.retain_available {
            Some(R::RETAIN_NOT_SUPPORTED)
        } else if will.qos as u8 > listener.max_qos as u8 {
            Some(R::QOS_NOT_SUPPORTED)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Ok(if v5.is_some() {
                Preparation::Refused(Code::NotAuthorized, reason)
            } else {
                Preparation::Close
            });
        }
    }
    // handle_connect.c: handle_zero_length_clientid and check_clientid_prefixes
    // run before processing credentials, even with use_username_as_clientid.
    if connect.client_id.is_empty() {
        if (v5.is_none() && (connect.protocol == ProtocolVersion::V31 || !connect.clean_session))
            || !listener
                .allow_zero_length_clientid
                .unwrap_or(config.allow_zero_length_clientid)
        {
            return Ok(Preparation::Refused(
                Code::IdentifierRejected,
                R::UNSPECIFIED_ERROR,
            ));
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
        return Ok(Preparation::Refused(Code::NotAuthorized, R::NOT_AUTHORIZED));
    }
    if let Some(will) = &mut connect.will {
        if config.message_size_limit != 0 && will.payload.len() > config.message_size_limit {
            return Ok(Preparation::Refused(
                Code::NotAuthorized,
                R::PACKET_TOO_LARGE,
            ));
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
            return Ok(Preparation::Refused(
                Code::BadUserNameOrPassword,
                R::BAD_USERNAME_OR_PASSWORD,
            ));
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
            return Ok(Preparation::Refused(Code::NotAuthorized, R::NOT_AUTHORIZED));
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
    flush(wire, shutdown).await
}

async fn refuse_v5<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    shutdown: &mut watch::Receiver<bool>,
    config: &BrokerConfig,
    info: &ConnectionInfo,
    reason: R,
) -> Result<(), BrokerError> {
    if wire.connack_v5(&v5::connack(
        config,
        &info.listener,
        false,
        reason,
        Vec::new(),
    ))? {
        flush(wire, shutdown).await?;
    }
    Ok(())
}

async fn flush<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), BrokerError> {
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
    expiry_override: Option<u32>,
    detached: bool,
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        if !self.detached {
            self.broker.detach_cancelled(
                self.live.lease.clone(),
                self.graceful,
                self.expiry_override,
            );
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
            Packet::PingReq => Ok(Step::Reply(Frame::Legacy(Packet::PingResp))),
            Packet::Subscribe(mut sub) => {
                for (filter, qos) in &mut sub.filters {
                    mount(filter, mount_point);
                    if *qos as u8 > max_qos as u8 {
                        *qos = max_qos;
                    }
                }
                let filters = sub
                    .filters
                    .into_iter()
                    .map(SubscriptionRequest::legacy)
                    .collect();
                match self
                    .act(Operation::Subscribe(filters, self.broker.now()))
                    .await?
                {
                    Reply::Subscribed(codes) if codes.is_empty() => {
                        Ok(Step::EmptySubAck(sub.packet_id))
                    }
                    Reply::Subscribed(return_codes) => {
                        Ok(Step::Reply(Frame::Legacy(Packet::SubAck(SubAck {
                            packet_id: sub.packet_id,
                            return_codes,
                        }))))
                    }
                    reply => action_result(reply),
                }
            }
            Packet::Unsubscribe(mut unsub) => {
                for filter in &mut unsub.filters {
                    mount(filter, mount_point);
                }
                let step = action_result(self.act(Operation::Unsubscribe(unsub.filters)).await?)?;
                Ok(step.or_reply(Frame::Legacy(Packet::UnsubAck(unsub.packet_id)), false))
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
                let reply = self
                    .receive(Publication::legacy(publish, self.broker.now()))
                    .await?;
                let step = action_result(reply)?;
                Ok(match id {
                    Some(id) if qos == QoS::ExactlyOnce => {
                        step.or_reply(Frame::Legacy(Packet::PubRec(id)), false)
                    }
                    Some(id) => step.or_reply(Frame::Legacy(Packet::PubAck(id)), true),
                    None => step,
                })
            }
            Packet::PubRel(id) => {
                let reply = self.release(id).await?;
                Ok(action_result(reply)?.or_reply(Frame::Legacy(Packet::PubComp(id)), true))
            }
            Packet::PubAck(id) => self.ack(id, Ack::Acknowledged).await,
            Packet::PubRec(id) => Ok(self
                .ack(id, Ack::Received)
                .await?
                .or_reply(Frame::Legacy(Packet::PubRel(id)), false)),
            Packet::PubComp(id) => self.ack(id, Ack::Completed).await,
            Packet::Connect(_)
            | Packet::ConnAck(_)
            | Packet::PingResp
            | Packet::SubAck(_)
            | Packet::UnsubAck(_) => Err(BrokerError::Protocol),
        }
    }

    async fn receive(&self, publication: Publication) -> Result<Reply, BrokerError> {
        let qos = publication.packet.qos;
        let id = publication.packet.packet_id;
        let now = publication.now;
        let config = &self.broker.0.config;
        let message = match self.act(Operation::Receive(publication)).await? {
            Reply::ReceiveLocal(message) => message,
            reply => return Ok(reply),
        };
        let id = id.unwrap();
        let inbox = self.live.inbox.as_ref().unwrap();
        Ok(match message {
            None => {
                inbox.lock().unwrap().credit_incoming();
                Reply::NoChange
            }
            Some(message) if qos == QoS::ExactlyOnce => {
                match inbox.lock().unwrap().receive(id, message, config) {
                    Receive::Duplicate => Reply::ProtocolError,
                    Receive::Accepted | Receive::Quota => Reply::NoChange,
                }
            }
            Some(message) => {
                let allowed = inbox.lock().unwrap().can_publish_qos1(id, config);
                if allowed {
                    self.act(Operation::Forward(message, now)).await?
                } else {
                    Reply::NoChange
                }
            }
        })
    }

    async fn release(&self, id: mqx_codec::PacketId) -> Result<Reply, BrokerError> {
        let now = self.broker.now();
        if let Some(inbox) = &self.live.inbox {
            let message = inbox.lock().unwrap().release(id);
            if let Some(message) = message {
                self.act(Operation::Forward(message, now)).await
            } else {
                Ok(Reply::NoChange)
            }
        } else {
            self.act(Operation::Release(id, now)).await
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
        Reply::NoChange | Reply::PublishReason(_) | Reply::Unsubscribed(_) => Ok(Step::Continue),
        Reply::Stale => Ok(Step::End(End::Takeover)),
        Reply::ProtocolError => Err(BrokerError::Protocol),
        _ => unreachable!(),
    }
}

enum Step {
    Continue,
    Reply(Frame),
    ReplyAfterDelivery(Frame),
    EmptySubAck(mqx_codec::PacketId),
    End(End),
}

impl Step {
    fn or_reply(self, packet: Frame, after_delivery: bool) -> Self {
        match self {
            Self::Continue if after_delivery => Self::ReplyAfterDelivery(packet),
            Self::Continue => Self::Reply(packet),
            _ => self,
        }
    }
}

enum End {
    Disconnect,
    DisconnectWithWill,
    Eof,
    Timeout,
    Security,
    Shutdown,
    Takeover,
    Unsupported,
    KeepaliveRefused,
}

enum Frame {
    Legacy(Packet),
    V5(Packet5),
}

struct Wire<S> {
    stream: S,
    input: BytesMut,
    output: BytesMut,
    written: usize,
    flush: bool,
    eof: bool,
    v5: Option<v5::WireState>,
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
            v5: None,
        }
    }

    fn idle(&self) -> bool {
        self.output.is_empty() && !self.flush
    }

    fn connect(&mut self, config: &BrokerConfig) -> Result<Option<Frame>, BrokerError> {
        // lib/packet_mosq.c: packet__read_single rejects a non-CONNECT first
        // command, and checks the CONNECT limit before the protocol is known.
        const CONNECT_MAX: usize = 100_000;
        let max = if config.max_packet_size == 0 {
            CONNECT_MAX
        } else {
            CONNECT_MAX.min(config.max_packet_size)
        };
        if self
            .input
            .first()
            .is_some_and(|header| header & 0xf0 != 0x10)
        {
            return Err(BrokerError::Protocol);
        }
        if matches!(
            codec5::peek_connect_protocol_level(&self.input),
            Ok(Some(5 | 0x85))
        ) {
            return Ok(
                codec5::decode(&mut self.input, codec5::DecodeContext::new(max))?.map(Frame::V5),
            );
        }
        Ok(decode(&mut self.input, DecodeContext::new(max, None))?.map(Frame::Legacy))
    }

    fn packet(
        &mut self,
        config: &BrokerConfig,
        legacy_protocol: ProtocolVersion,
    ) -> Result<Option<Frame>, BrokerError> {
        let Some(v5) = &self.v5 else {
            if self
                .input
                .first()
                .is_some_and(|header| header & 0xf0 == 0x10)
            {
                return Err(BrokerError::Protocol);
            }
            return Ok(decode(
                &mut self.input,
                DecodeContext::new(config.max_packet_size, Some(legacy_protocol)),
            )?
            .map(Frame::Legacy));
        };
        let command = self.input.first().map_or(0, |header| header & 0xf0);
        // packet_mosq.c: packet__check_in_packet_oversize checks the
        // per-command ceilings first. Unlike the global cap, they close silently.
        let command_cap = match command {
            0x40 | 0x50 | 0x60 | 0x70 | 0xb0 | 0xe0 => 10_000,
            0x10 | 0x80 | 0xa0 | 0xf0 => 100_000,
            _ => usize::MAX,
        };
        let max = if config.max_packet_size == 0 {
            command_cap
        } else {
            command_cap.min(config.max_packet_size)
        };
        let context = codec5::DecodeContext::new(max).with_topic_alias_maximum(v5.incoming_maximum);
        match codec5::decode(&mut self.input, context) {
            Ok(packet) => Ok(packet.map(Frame::V5)),
            Err(mut error) => {
                use codec5::DecodeErrorKind as Fault;
                if matches!(error.kind, Fault::PacketTooLarge { size, .. } if size > command_cap)
                    || command == 0x10
                {
                    error.response = None;
                } else if command == 0xf0
                    && !matches!(
                        error.kind,
                        Fault::PacketTooLarge { .. } | Fault::MalformedRemainingLength
                    )
                {
                    return Err(BrokerError::Protocol);
                }
                Err(error.into())
            }
        }
    }

    fn output(&mut self, packet: &Packet) -> Result<(), BrokerError> {
        Ok(encode(packet, &mut self.output)?)
    }

    fn output_v5(&mut self, packet: &Packet5) -> Result<(), BrokerError> {
        Ok(codec5::encode(packet, &mut self.output)?)
    }

    fn output_frame(&mut self, packet: &Frame) -> Result<(), BrokerError> {
        match packet {
            Frame::Legacy(packet) => self.output(packet),
            Frame::V5(packet) => self.output_v5(packet),
        }
    }

    fn connack_v5(&mut self, packet: &Packet5) -> Result<bool, BrokerError> {
        self.output_v5(packet)?;
        let fits = self.v5.as_ref().is_none_or(|v5| v5.fits(self.output.len()));
        if !fits {
            self.output.clear();
        }
        Ok(fits)
    }

    fn delivery(
        &mut self,
        outbound: Outbound,
        mount_point: Option<&str>,
        now: Duration,
    ) -> Result<Option<mqx_codec::PacketId>, BrokerError> {
        let Outbound::Publish { delivery, id, dup } = outbound else {
            let Outbound::Release(id) = outbound else {
                unreachable!()
            };
            if self.v5.is_some() {
                self.output_v5(&Packet5::PubRel(v5::publish_ack(id, R::SUCCESS)))?;
            } else {
                self.output(&Packet::PubRel(id))?;
            }
            return Ok(None);
        };
        // lib/send_publish.c: send__publish strips the destination
        // listener's mount point by length before writing to the wire.
        let Some(topic) = delivery
            .message
            .topic
            .get(mount_point.map_or(0, str::len)..)
            .filter(|topic| !topic.is_empty())
        else {
            return Ok(None);
        };
        if let Some(v5) = &mut self.v5 {
            let (topic, alias) = v5.outgoing_topic(topic);
            // Reject payloads that cannot fit even before accounting for
            // properties and additional Remaining Length bytes.
            let minimum =
                5 + topic.len() + 2 * usize::from(id.is_some()) + delivery.message.payload.len();
            if !v5.fits(minimum) {
                return Ok(id);
            }
            let expiry = delivery.message.expires.and_then(|at| {
                let seconds = at.as_secs().checked_sub(now.as_secs())? as u32;
                (seconds != 0 && seconds != u32::MAX).then_some(seconds)
            });
            let mut properties = Vec::with_capacity(
                delivery.message.properties.len()
                    + usize::from(expiry.is_some())
                    + usize::from(alias.is_some())
                    + usize::from(delivery.subscription_identifier != 0),
            );
            properties.extend(
                delivery
                    .message
                    .properties
                    .iter()
                    .map(|property| property.wire()),
            );
            properties.extend(expiry.map(Property::MessageExpiryInterval));
            properties.extend(alias.map(Property::TopicAlias));
            if delivery.subscription_identifier != 0 {
                properties.push(Property::SubscriptionIdentifier(
                    delivery.subscription_identifier,
                ));
            }
            let packet = Packet5::Publish(codec5::Publish {
                dup,
                qos: delivery.qos,
                retain: delivery.retain,
                topic,
                packet_id: id,
                properties,
                payload: delivery.message.payload.clone(),
            });
            match codec5::encode(&packet, &mut self.output) {
                Err(codec5::EncodeError::PacketTooLarge) => return Ok(id),
                Err(error) => return Err(error.into()),
                Ok(()) => {}
            }
            if !v5.fits(self.output.len()) {
                self.output.clear();
                return Ok(id);
            }
        } else {
            self.output(&Packet::Publish(Publish {
                dup,
                qos: delivery.qos,
                retain: delivery.retain,
                topic: topic.to_owned(),
                packet_id: id,
                payload: delivery.message.payload.clone(),
            }))?;
        }
        Ok(None)
    }

    async fn terminate_v5(&mut self, reason: R) {
        // lib/send_disconnect.c: send__disconnect does not check the peer's
        // Maximum Packet Size or wait for a backpressured socket to drain.
        if self.flush_ready().await
            && self
                .output_v5(&Packet5::Disconnect(codec5::ReasonProperties {
                    reason,
                    properties: Vec::new(),
                }))
                .is_ok()
        {
            self.flush_ready().await;
        }
    }

    async fn flush_ready(&mut self) -> bool {
        poll_fn(|cx| {
            while !self.idle() {
                if !matches!(pin!(self.progress(false)).poll(cx), Poll::Ready(Ok(()))) {
                    return Poll::Ready(false);
                }
            }
            Poll::Ready(true)
        })
        .await
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
    protocol: u8,
    clean: bool,
    keepalive: u16,
    identity: &Identity,
    bridge: bool,
) {
    // handle_connect.c: connect__on_authorised logs the wire protocol version.
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
        Ok(End::Disconnect | End::DisconnectWithWill | End::Security | End::Shutdown) => {
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
