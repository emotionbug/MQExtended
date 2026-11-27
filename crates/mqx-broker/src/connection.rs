mod pipeline;
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

use bytes::{Buf, BufMut, Bytes, BytesMut};
use mqx_auth::{
    DynamicSecurity,
    external::{Binding, Verdict},
};
use mqx_codec::v5::{self as codec5, Packet as Packet5, Property, ReasonCode as R};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode as Code, DecodeContext, DecodeError, Packet,
    ProtocolVersion, QoS, SubAck, decode, encode,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::watch,
    time::{Instant, sleep_until},
};

use crate::{
    Broker, BrokerConfig, BrokerError, CertIdentity, ConnectionInfo, Live, Security,
    SecurityHandle,
    inbox::{Ack, Delivery, Outbound, Publisher, Receive},
    runtime::ClaimResult,
    state::{Claim, Operation, Publication, Reply, SubscriptionRequest},
    sys::Metric,
};

pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    broker: &Broker,
    stream: S,
    info: ConnectionInfo,
    accepted_at: Instant,
    peer: Address,
    tls: Option<(&str, &str)>,
) -> Result<(), BrokerError> {
    let config = broker.0.config.startup();
    let mut wire = Wire::new(stream, broker.clone());
    let mut shutdown = broker.0.shutdown.subscribe();
    // context.c: context__init gives peers 20 seconds of keepalive before CONNECT.
    let initial_deadline = accepted_at + keepalive_period(20);
    let (mut connect, options, v5_settings) = loop {
        if *shutdown.borrow() || Instant::now() >= initial_deadline {
            return Ok(());
        }
        match wire.connect(config, info.listener.mount_point.is_none()) {
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
                } else if let Some(codec5::ErrorResponse::LegacyConnAck(code)) = error.response {
                    return refuse(&mut wire, &mut shutdown, code).await;
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
            result = wire.progress(usize::MAX) => result?,
        }
    };

    let listener = &info.listener;
    let mut security = listener.security.0.snapshots.subscribe();
    let preparation = prepare(
        &broker.0.config.load(),
        &info,
        &mut connect,
        options.as_ref(),
    )?;
    let identity = match preparation {
        Preparation::Accepted(identity) => identity,
        Preparation::Refused(code, reason, refusal) => {
            log_refusal(broker, &peer, &connect.client_id, refusal);
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
    let client_id = Arc::<str>::from(std::mem::take(&mut connect.client_id));
    let dynamic = broker.dynamic_policy_snapshot(&listener.security);
    let dynamic_security_revision = dynamic.as_ref().map(|(revision, _)| *revision);
    let dynamic = listener.security.1.zip(dynamic.map(|(_, policy)| policy));
    let security_snapshot = security.borrow_and_update().clone();
    let (verdict, credentials) = identity
        .authenticate(
            &listener.security,
            &client_id,
            security_snapshot,
            dynamic.as_ref(),
        )
        .await;
    // handle_connect.c: handle__connect sends CONNACK Not Authorized only
    // for an auth refusal, not a backend error.
    if verdict == Verdict::Error {
        return Ok(());
    }
    if verdict != Verdict::Allow {
        log_refusal(
            broker,
            &peer,
            &client_id,
            Refusal::NotAuthorised { named: true },
        );
        if options.is_some() {
            return refuse_v5(&mut wire, &mut shutdown, config, &info, R::NOT_AUTHORIZED).await;
        }
        return refuse(&mut wire, &mut shutdown, Code::NotAuthorized).await;
    }
    drop(dynamic);
    if *shutdown.borrow() {
        return Ok(());
    }

    let assigned_id = options
        .as_ref()
        .filter(|options| options.assigned_id)
        .map(|_| Property::AssignedClientIdentifier(client_id.to_string()));
    let publisher_id = client_id.clone();
    let publisher = Publisher {
        id: client_id,
        username: identity.username.clone(),
        security: 0, // Filled by the log backend before claiming the session.
        dynamic_security: listener.security.1,
        external: listener.security.3.as_ref().map(|(id, _)| {
            (
                *id,
                Binding {
                    credentials,
                    certificate: identity.certificate,
                    synthetic: false,
                },
            )
        }),
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
                internal_bridge: None,
                dynamic_security_revision,
                verdicts: Vec::new(),
            },
            peer.host.clone(),
        )
        .await?
    {
        ClaimResult::Accepted(live, present) => (live, present),
        ClaimResult::Full if options.is_some() => {
            return refuse_v5(&mut wire, &mut shutdown, config, &info, R::SERVER_BUSY).await;
        }
        ClaimResult::StoragePressure => {
            if options.is_some() {
                return refuse_v5(&mut wire, &mut shutdown, config, &info, R::QUOTA_EXCEEDED).await;
            }
            return refuse(&mut wire, &mut shutdown, Code::ServerUnavailable).await;
        }
        ClaimResult::Unauthorized => {
            log_refusal(
                broker,
                &peer,
                &publisher_id,
                Refusal::NotAuthorised { named: true },
            );
            if options.is_some() {
                return refuse_v5(&mut wire, &mut shutdown, config, &info, R::NOT_AUTHORIZED).await;
            }
            return refuse(&mut wire, &mut shutdown, Code::NotAuthorized).await;
        }
        ClaimResult::Full | ClaimResult::Stale => return Ok(()),
    };
    let present = present && connect.protocol == ProtocolVersion::V311;
    let mut session = Active {
        broker,
        live,
        security,
        sparkplug_aware: info.listener.sparkplug_aware,
        graceful: false,
        expiry_override: None,
        detached: false,
    };
    if broker.connection_messages() {
        log_connected(
            &peer,
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
    // handle_connect.c: connect__on_authorised logs the TLS session even
    // without connection_messages.
    if let Some((version, cipher)) = tls {
        tracing::info!(
            target: "mqx::notice",
            "Client {} negotiated {version} cipher {cipher}",
            session.live.lease.id
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
    let mut partial_bytes = 0;
    let mut delivering = !too_long;
    let mut prefer_input = false;
    let mut deferred = None;
    let clustered = broker.is_clustered();
    // External WRITE errors must stop the stream at the rejected packet.
    let pipeline_enabled = listener.security.3.is_none();
    let result = 'active: loop {
        if session.live.taken.load(Ordering::Acquire) {
            break Ok(if session.live.kicked.load(Ordering::Relaxed) {
                End::Kicked
            } else {
                End::Takeover
            });
        }
        if *shutdown.borrow() {
            break Ok(End::Shutdown);
        }
        if session.security.has_changed().unwrap_or(false) {
            let snapshot = session.security.borrow_and_update().clone();
            if !identity
                .reauthenticate(broker, &listener.security, &session.live.lease.id, snapshot)
                .await
            {
                break Ok(End::Security);
            }
        }
        if wire.idle() {
            if too_long {
                break Ok(End::KeepaliveRefused);
            }
            if delivering && (!prefer_input || deferred.is_some()) {
                let next = session.broker.next_outbound(&session.live);
                let next = if clustered {
                    wire.prefetch(next).await
                } else {
                    next.await
                };
                match next {
                    Ok(Some(outbound)) => {
                        let coalesce = deferred.is_none()
                            && (session.live.inbox.is_some()
                                || matches!(&outbound, Outbound::Publish { delivery, .. }
                                    if delivery.qos == QoS::AtLeastOnce));
                        match wire.delivery(outbound, listener.mount_point.as_deref(), broker.now())
                        {
                            Ok(Some(id)) => {
                                if let Err(error) = session.ack(id, Ack::Dropped).await {
                                    break Err(error);
                                }
                            }
                            Ok(None) => {
                                if coalesce
                                    && let Err(error) = wire.coalesce_ready(
                                        &session.live,
                                        listener.mount_point.as_deref(),
                                    )
                                {
                                    break Err(error);
                                }
                            }
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
            let input_bytes = wire.input.len();
            match wire.packet(config, connect.protocol) {
                Ok(Some(packet)) => {
                    prefer_input = false;
                    partial_bytes = 0;
                    deadline = self::deadline(connect.keep_alive);
                    let packet_bytes = input_bytes - wire.input.len();
                    let step = if pipeline_enabled
                        && packet_bytes < pipeline::PREFETCH_BYTES
                        && pipeline::can_follow(
                            &wire.input,
                            pipeline::PREFETCH_BYTES - packet_bytes,
                            listener,
                            config,
                        )
                        && pipeline::eligible(&packet, listener, config)
                        && broker.can_pipeline(&session.live)
                    {
                        pipeline::publish(
                            &session,
                            &mut wire,
                            packet,
                            listener,
                            connect.protocol,
                            pipeline::PREFETCH_BYTES - packet_bytes,
                        )
                        .await
                    } else if clustered
                        && session.live.inbox.is_none()
                        && let Some(id) = pipeline::simple_ack(&packet)
                    {
                        pipeline::acknowledge(
                            &session,
                            &mut wire,
                            id,
                            connect.protocol,
                            listener.mount_point.as_deref(),
                            connect.keep_alive,
                            &mut shutdown,
                        )
                        .await
                    } else {
                        match packet {
                            Frame::Legacy(packet) => {
                                let step = session.process(packet, &info, connect.protocol);
                                if clustered {
                                    wire.prefetch(step).await
                                } else {
                                    step.await
                                }
                            }
                            Frame::V5(packet) => {
                                let mut aliases = wire.v5.take().unwrap();
                                let step = session.process_v5(
                                    packet,
                                    &info,
                                    &mut aliases,
                                    options.as_ref().unwrap().session_expiry,
                                );
                                let step = if clustered {
                                    wire.prefetch(step).await
                                } else {
                                    step.await
                                };
                                wire.v5 = Some(aliases);
                                step
                            }
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
                            wire.enqueue(4);
                        }
                        Ok(Step::End(end)) => break Ok(end),
                        Err(error) => break Err(error),
                    }
                    continue;
                }
                Ok(None) if deadline.is_some() && partial_bytes != input_bytes => {
                    // lib/packet_mosq.c: packet__read_single refreshes keepalive on
                    // partial body reads with >1000 bytes left. An unrelated wakeup
                    // or an incomplete fixed header is not client activity.
                    partial_bytes = input_bytes;
                    if frame_size(&wire.input)
                        .is_some_and(|size| size.saturating_sub(input_bytes) > 1000)
                    {
                        deadline = self::deadline(connect.keep_alive);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    // Earlier filters are still processed. Their ACL error can
                    // stop the handler before it reaches the malformed filter.
                    let step = match wire.filter_prefix.take() {
                        Some(Frame::Legacy(packet)) => {
                            session.process(packet, &info, connect.protocol).await
                        }
                        Some(Frame::V5(packet)) => {
                            let mut aliases = wire.v5.take().unwrap();
                            let step = session
                                .process_v5(
                                    packet,
                                    &info,
                                    &mut aliases,
                                    options.as_ref().unwrap().session_expiry,
                                )
                                .await;
                            wire.v5 = Some(aliases);
                            step
                        }
                        None => break Err(error),
                    };
                    match step {
                        Ok(Step::End(End::ExternalAcl)) => break Ok(End::ExternalAcl),
                        Ok(Step::Continue) => {
                            let size = frame_size(&wire.input).expect("complete filter packet");
                            wire.input.advance(size);
                            deadline = self::deadline(connect.keep_alive);
                            partial_bytes = 0;
                            delivering = true;
                            prefer_input = false;
                            continue;
                        }
                        _ => {}
                    }
                    break Err(error);
                }
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
            snapshot = wait_security(&mut session.security) => {
                if !identity.reauthenticate(broker, &listener.security, &session.live.lease.id, snapshot).await {
                    break Ok(End::Security);
                }
            }
            _ = timeout(deadline) => break Ok(End::Timeout),
            result = wire.progress(if too_long { 0 } else { usize::MAX }) => if let Err(error) = result { break 'active Err(error.into()); },
            _ = session.live.ready.notified() => delivering = true,
        }
    };
    let result =
        if matches!(result, Ok(End::Takeover)) && session.live.kicked.load(Ordering::Acquire) {
            Ok(End::Kicked)
        } else {
            result
        };
    session.graceful = matches!(result, Ok(End::Disconnect | End::Security | End::Kicked));
    if options.is_some()
        && let Some(reason) = disconnect_reason(&result)
    {
        wire.terminate_v5(reason).await;
    } else if matches!(result, Ok(End::Kicked)) {
        wire.flush_ready().await;
    }
    if broker.connection_messages() {
        log_disconnected(&peer, &session.live.lease.id, &result);
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
        Ok(End::Kicked) => Some(R::ADMINISTRATIVE_ACTION),
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
    certificate_username: bool,
    allow_anonymous: bool,
}

impl Identity {
    async fn authenticate(
        &self,
        security: &SecurityHandle,
        client_id: &Arc<str>,
        snapshot: Arc<Security>,
        dynamic: Option<&(bool, Arc<DynamicSecurity>)>,
    ) -> (Verdict, bool) {
        if self.certificate_username {
            return (Verdict::Allow, false);
        }
        let anonymous = security.anonymous(&snapshot, self.allow_anonymous);
        snapshot
            .authenticate(
                client_id,
                self.username.as_ref(),
                self.password.as_ref(),
                anonymous,
                dynamic,
                security.3.as_ref().map(|(_, plugin)| plugin.as_ref()),
            )
            .await
    }

    async fn reauthenticate(
        &self,
        broker: &Broker,
        security: &SecurityHandle,
        client_id: &Arc<str>,
        snapshot: Arc<Security>,
    ) -> bool {
        // security_default.c: reload disconnects anonymous contexts before
        // consulting callbacks when anonymous access has been disabled.
        if self.username.is_none() && !security.anonymous(&snapshot, self.allow_anonymous) {
            return false;
        }
        let dynamic = security.1.zip(
            broker
                .dynamic_policy_snapshot(security)
                .map(|(_, policy)| policy),
        );
        let (verdict, _) = self
            .authenticate(security, client_id, snapshot, dynamic.as_ref())
            .await;
        verdict == Verdict::Allow
    }
}

async fn wait_security(receiver: &mut watch::Receiver<Arc<Security>>) -> Arc<Security> {
    receiver
        .changed()
        .await
        .expect("the connection owns its security handle");
    receiver.borrow_and_update().clone()
}

enum Preparation {
    Accepted(Identity),
    Refused(Code, R, Refusal),
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
            Refusal::Silent,
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
                Preparation::Refused(Code::NotAuthorized, reason, Refusal::Silent)
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
                Refusal::ZeroLengthId {
                    v31: v5.is_none() && connect.protocol == ProtocolVersion::V31,
                },
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
        return Ok(Preparation::Refused(
            Code::NotAuthorized,
            R::NOT_AUTHORIZED,
            Refusal::NotAuthorised { named: false },
        ));
    }
    if let Some(will) = &mut connect.will {
        // handle_connect.c: will__read mounts the topic, then refuses a
        // `$CONTROL/` Will with MOSQ_ERR_ACL_DENIED (no CONNACK on any
        // protocol), before the Will payload size check.
        mount(&mut will.topic, listener.mount_point.as_deref());
        // will__read then applies mosquitto_pub_topic_check to the mounted
        // topic, e.g. its hierarchy limit; that error also sends no CONNACK.
        if will.topic.starts_with(crate::control::PREFIX)
            || mqx_topic::validate_topic_name(&will.topic).is_err()
        {
            return Ok(Preparation::Close);
        }
        if config.message_size_limit != 0 && will.payload.len() > config.message_size_limit {
            return Ok(Preparation::Refused(
                Code::NotAuthorized,
                R::PACKET_TOO_LARGE,
                Refusal::OversizePayload,
            ));
        }
    }
    // proxy_v2.c and handle_connect.c: handle_username_from_cert_options
    // discard MQTT credentials for both certificate sources, but only a
    // locally verified TLS identity bypasses mosquitto_basic_auth.
    let (username, password, certificate_username) = match &info.cert_identity {
        CertIdentity::Username(username) if !username.contains('\0') => {
            (Some(username.clone()), None, true)
        }
        CertIdentity::ForwardedUsername(username)
            if !username.is_empty() && !username.contains('\0') =>
        {
            (Some(username.clone()), None, false)
        }
        CertIdentity::Username(_)
        | CertIdentity::ForwardedUsername(_)
        | CertIdentity::MissingOrInvalid => {
            return Ok(Preparation::Refused(
                Code::BadUserNameOrPassword,
                R::BAD_USERNAME_OR_PASSWORD,
                Refusal::NotAuthorised { named: true },
            ));
        }
        CertIdentity::None | CertIdentity::Presented => (
            connect.username.take().filter(|value| !value.is_empty()),
            connect.password.take().filter(|value| !value.is_empty()),
            false,
        ),
    };
    if listener.use_username_as_clientid {
        // handle_connect.c: handle_username_as_clientid_option.
        let Some(username) = &username else {
            return Ok(Preparation::Refused(
                Code::NotAuthorized,
                R::NOT_AUTHORIZED,
                Refusal::NotAuthorised { named: true },
            ));
        };
        connect.client_id.clone_from(username);
    }
    Ok(Preparation::Accepted(Identity {
        username: username.map(Arc::from),
        password,
        certificate: certificate_username || matches!(info.cert_identity, CertIdentity::Presented),
        certificate_username,
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
            result = wire.progress(0) => result?,
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
    security: watch::Receiver<Arc<Security>>,
    sparkplug_aware: bool,
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

    async fn process(
        &self,
        packet: Packet,
        info: &ConnectionInfo,
        protocol: ProtocolVersion,
    ) -> Result<Step, BrokerError> {
        let config = self.broker.0.config.startup();
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
                let logged = tracing::enabled!(target: "mqx::subscribe", tracing::Level::INFO)
                    .then(|| sub.filters.clone());
                let granted = (protocol == ProtocolVersion::V31).then(|| {
                    sub.filters
                        .iter()
                        .map(|(_, qos)| *qos)
                        .collect::<Vec<QoS>>()
                });
                let filters = sub
                    .filters
                    .into_iter()
                    .map(SubscriptionRequest::legacy)
                    .collect();
                match self
                    .act(Operation::subscribe(filters, self.broker.now()))
                    .await?
                {
                    Reply::Subscribed(codes) if codes.is_empty() => {
                        Ok(Step::EmptySubAck(sub.packet_id))
                    }
                    Reply::Subscribed(mut return_codes) => {
                        // Mosquitto handle_subscribe.c: handle__subscribe logs the
                        // mounted filter and granted QoS after installing the leaf.
                        if let Some(logged) = logged {
                            for ((filter, qos), code) in logged.into_iter().zip(&return_codes) {
                                if matches!(code, mqx_codec::SubscribeReturnCode::Success(_)) {
                                    tracing::info!(target: "mqx::subscribe", "{} {} {filter}", self.live.lease.id, qos as u8);
                                }
                            }
                        }
                        // handle_subscribe.c: handle__subscribe replaces a denied QoS
                        // with 0x80 only for MQTT 3.1.1; MQTT 3.1 gets the granted
                        // QoS back although the subscription is not installed.
                        if let Some(granted) = granted {
                            for (code, qos) in return_codes.iter_mut().zip(granted) {
                                if *code == mqx_codec::SubscribeReturnCode::Failure {
                                    *code = mqx_codec::SubscribeReturnCode::Success(qos);
                                }
                            }
                        }
                        Ok(Step::Reply(Frame::Legacy(Packet::SubAck(SubAck {
                            packet_id: sub.packet_id,
                            return_codes,
                        }))))
                    }
                    reply => action_result(reply),
                }
            }
            Packet::Unsubscribe(unsub) => {
                // handle_unsubscribe.c: handle__unsubscribe checks ACL and
                // removes the filter as sent, without the listener mount_point.
                for filter in &unsub.filters {
                    tracing::info!(target: "mqx::unsubscribe", "{} {filter}", self.live.lease.id);
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
                let control = matches!(reply, Reply::ControlAccepted { .. });
                let step = action_result(reply)?;
                Ok(match id {
                    Some(id) if qos == QoS::ExactlyOnce => {
                        step.or_reply(Frame::Legacy(Packet::PubRec(id)), false)
                    }
                    Some(id) => step.or_reply(Frame::Legacy(Packet::PubAck(id)), !control),
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
        let birth = self.sparkplug_aware && publication.sparkplug_birth();
        let qos = publication.packet.qos;
        let id = publication.packet.packet_id;
        let now = publication.now;
        let config = self.broker.0.config.startup();
        let (message, reason) = match self.broker.receive(&self.live, publication, birth).await? {
            Reply::ReceiveLocal(message, reason) => (message, reason),
            reply => return Ok(reply),
        };
        let id = id.unwrap();
        let inbox = self.live.inbox.as_ref().unwrap();
        Ok(match message {
            None => {
                inbox.lock().unwrap().credit_incoming();
                Reply::PublishReason(reason)
            }
            Some(message) if qos == QoS::ExactlyOnce => {
                let mut inbox = inbox.lock().unwrap();
                match inbox.receive(id, message, config) {
                    Receive::Quota => {
                        self.broker.0.traffic.add(Metric::Dropped, 1);
                        if inbox.receive_maximum.is_some() {
                            inbox.credit_incoming();
                            Reply::PublishReason(R::QUOTA_EXCEEDED.0)
                        } else {
                            Reply::NoChange
                        }
                    }
                    Receive::Duplicate => Reply::ProtocolError,
                    Receive::Accepted => Reply::NoChange,
                }
            }
            Some(message) => {
                let allowed = inbox.lock().unwrap().can_publish_qos1(id, config);
                if !allowed {
                    self.broker.0.traffic.add(Metric::Dropped, 1);
                }
                if birth {
                    self.act(Operation::ForwardBirth {
                        message,
                        now,
                        admitted: allowed,
                    })
                    .await?
                } else if allowed {
                    self.act(Operation::Forward(message, now)).await?
                } else {
                    Reply::PublishReason(R::QUOTA_EXCEEDED.0)
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
            let acknowledged = {
                let mut inbox = inbox.lock().unwrap();
                let backlogged = inbox.backlogged();
                let ok = inbox.ack(id, ack, &self.broker.0.config.load());
                if backlogged && !inbox.backlogged() {
                    self.live.drained.notify_waiters();
                }
                ok
            };
            if acknowledged {
                self.broker.count_transient_ack(ack);
                Ok(Step::Continue)
            } else {
                Err(BrokerError::Protocol)
            }
        } else {
            let operation = if ack == Ack::Received {
                self.broker.pubrec(&self.live, id)
            } else {
                Operation::Ack(id, ack)
            };
            action_result(self.act(operation).await?)
        }
    }
}

fn action_result(reply: Reply) -> Result<Step, BrokerError> {
    match reply {
        Reply::NoChange
        | Reply::ControlAccepted { .. }
        | Reply::PublishReason(_)
        | Reply::Unsubscribed(_) => Ok(Step::Continue),
        // handle_subscribe.c: retain__queue failure aborts the packet without
        // a SUBACK, but the caller keeps the connection and queued deliveries.
        Reply::RetainedAclError => Ok(Step::Continue),
        // handle_publish.c and handle_subscribe.c return the callback error
        // without an ACK, and read_handle.c sends no MQTT 5 DISCONNECT for it.
        Reply::ExternalAclError => Ok(Step::End(End::ExternalAcl)),
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
    ExternalAcl,
    Shutdown,
    Takeover,
    Kicked,
    Unsupported,
    KeepaliveRefused,
}

enum Frame {
    Legacy(Packet),
    V5(Packet5),
}

struct Wire<S> {
    stream: S,
    broker: Broker,
    input: BytesMut,
    output: BytesMut,
    written: usize,
    selected_end: usize,
    queued: i64,
    queued_bytes: i64,
    flush: bool,
    eof: bool,
    v5: Option<v5::WireState>,
    pending_error: Option<BrokerError>,
    // The valid filters of a refused SUBSCRIBE or UNSUBSCRIBE, applied
    // without an acknowledgement before the connection ends.
    filter_prefix: Option<Frame>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    fn new(stream: S, broker: Broker) -> Self {
        Self {
            stream,
            broker,
            input: BytesMut::new(),
            output: BytesMut::new(),
            written: 0,
            selected_end: 0,
            queued: 0,
            queued_bytes: 0,
            flush: false,
            eof: false,
            v5: None,
            pending_error: None,
            filter_prefix: None,
        }
    }

    fn idle(&self) -> bool {
        self.output.is_empty() && !self.flush
    }

    fn account_received(&self, command: u8, result: &Result<Option<Frame>, BrokerError>) {
        // packet_mosq.c: packet__read_single counts complete frames;
        // read_handle.c: handle__packet counts CONNECT/PUBLISH before validation.
        let complete = match result {
            Ok(packet) => packet.is_some(),
            Err(BrokerError::Decode(DecodeError::PacketTooLarge { .. })) => false,
            Err(BrokerError::DecodeV5(error))
                if matches!(error.kind, codec5::DecodeErrorKind::PacketTooLarge { .. }) =>
            {
                false
            }
            Err(_) => frame_size(&self.input).is_some_and(|size| size <= self.input.len()),
        };
        if complete {
            let stats = &self.broker.0.traffic;
            stats.add(Metric::Received, 1);
            match command >> 4 {
                1 => stats.add(Metric::Connect, 1),
                3 => stats.add(Metric::PublishReceived, 1),
                _ => {}
            }
        }
    }

    fn enqueue(&mut self, size: usize) {
        // packet_mosq.c: packet__queue_append / packet__get_next_out.
        self.queued += 1;
        self.queued_bytes += size as i64;
        self.broker.0.traffic.add(Metric::Queued, 1);
        self.broker.0.traffic.add(Metric::QueuedBytes, size as i64);
    }

    fn select_packet(&mut self, offset: usize) {
        let size = if self.queued == 1 {
            self.output.len() - offset
        } else {
            frame_size(&self.output[offset..]).expect("encoded MQTT frame")
        };
        self.selected_end = offset + size;
        self.queued -= 1;
        self.queued_bytes -= size as i64;
        self.broker.0.traffic.add(Metric::Queued, -1);
        self.broker
            .0
            .traffic
            .add(Metric::QueuedBytes, -(size as i64));
    }

    fn connect(
        &mut self,
        config: &BrokerConfig,
        unmounted: bool,
    ) -> Result<Option<Frame>, BrokerError> {
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
        let result = if matches!(
            codec5::peek_connect_protocol_level(&self.input),
            Ok(Some(5 | 0x85))
        ) {
            // handle_connect.c: will__read refuses a `$CONTROL/` Will before
            // reading its payload; only an unmounted topic can be checked there.
            let context = codec5::DecodeContext::new(max);
            let context = if unmounted {
                context.with_unmounted_will()
            } else {
                context
            };
            codec5::decode(&mut self.input, context)
                .map(|packet| packet.map(Frame::V5))
                .map_err(BrokerError::from)
        } else {
            decode(&mut self.input, DecodeContext::new(max, None))
                .map(|packet| packet.map(Frame::Legacy))
                .map_err(BrokerError::from)
        };
        self.account_received(0x10, &result);
        result
    }

    fn packet(
        &mut self,
        config: &BrokerConfig,
        legacy_protocol: ProtocolVersion,
    ) -> Result<Option<Frame>, BrokerError> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let command = self.input.first().copied().unwrap_or_default();
        let result = self.decode_packet(config, legacy_protocol);
        self.account_received(command, &result);
        result
    }

    fn decode_packet(
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
            let context = DecodeContext::new(config.max_packet_size, Some(legacy_protocol));
            return match decode(&mut self.input, context) {
                Ok(packet) => Ok(packet.map(Frame::Legacy)),
                Err(error) => {
                    self.filter_prefix =
                        mqx_codec::decode_filter_prefix(&self.input, context).map(Frame::Legacy);
                    Err(error.into())
                }
            };
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
                if matches!(command, 0x80 | 0xa0) {
                    self.filter_prefix =
                        codec5::decode_filter_prefix(&self.input, context).map(Frame::V5);
                }
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
        let before = self.output.len();
        encode(packet, &mut self.output)?;
        self.enqueue(self.output.len() - before);
        Ok(())
    }

    fn output_v5(&mut self, packet: &Packet5) -> Result<(), BrokerError> {
        let before = self.output.len();
        codec5::encode(packet, &mut self.output)?;
        self.enqueue(self.output.len() - before);
        Ok(())
    }

    fn output_frame(&mut self, packet: &Frame) -> Result<(), BrokerError> {
        match packet {
            Frame::Legacy(packet) => self.output(packet),
            Frame::V5(packet) => self.output_v5(packet),
        }
    }

    fn connack_v5(&mut self, packet: &Packet5) -> Result<bool, BrokerError> {
        codec5::encode(packet, &mut self.output)?;
        let fits = self.v5.as_ref().is_none_or(|v5| v5.fits(self.output.len()));
        if !fits {
            self.output.clear();
        } else {
            self.enqueue(self.output.len());
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
        // send_publish.c: send__publish counts payload before the packet
        // maximum check in send__real_publish.
        self.broker
            .0
            .traffic
            .add(Metric::PayloadSent, delivery.message.payload.len() as i64);
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
            self.enqueue(self.output.len());
        } else {
            let before = self.output.len();
            mqx_codec::encode_publish(
                &mut self.output,
                topic,
                &delivery.message.payload,
                delivery.qos,
                id,
                delivery.retain,
                dup,
            )?;
            self.enqueue(self.output.len() - before);
        }
        self.broker.0.traffic.add(Metric::PublishSent, 1);
        Ok(None)
    }

    // database.c: db__message_write_inflight_out_all emits already admitted
    // packets in send order. Don't wait for more, make another durable
    // reservation, or put another delivery ahead of already-buffered input
    // or a deferred acknowledgement.
    fn coalesce_ready(&mut self, live: &Live, mount: Option<&str>) -> Result<(), BrokerError> {
        const MAX_BYTES: usize = 16 * 1024;
        if self.v5.is_some() || !self.input.is_empty() || self.output.len() >= MAX_BYTES {
            return Ok(());
        }
        let fits = |delivery: &Delivery, room| {
            // At most 5 fixed-header bytes, two topic-length bytes and a MID.
            delivery.message.topic.len() + delivery.message.payload.len() + 9 <= room
        };
        let mut inbox = live.inbox.as_ref().map(|inbox| inbox.lock().unwrap());
        if inbox.is_none() && !self.broker.is_clustered() {
            return Ok(());
        }
        for _ in 1..16 {
            let room = MAX_BYTES - self.output.len();
            let packet = if let Some(inbox) = &mut inbox {
                inbox.reserve_ready_qos1(|delivery| fits(delivery, room))
            } else {
                live.pop_reserved_if(|packet| {
                    matches!(packet, Outbound::Publish { delivery, .. }
                        if delivery.qos == QoS::AtLeastOnce && fits(delivery, room))
                })?
            };
            let Some(packet) = packet else { break };
            let dropped = self.delivery(packet, mount, Duration::ZERO)?;
            debug_assert!(dropped.is_none());
        }
        Ok(())
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
                if !matches!(pin!(self.progress(0)).poll(cx), Poll::Ready(Ok(()))) {
                    return Poll::Ready(false);
                }
            }
            Poll::Ready(true)
        })
        .await
    }

    // Continue consuming transport input while a mesh or Raft operation is
    // outstanding. The next QoS 0/1 run can then enter the proposal lane as a
    // batch, without executing any subsequent MQTT packet out of order.
    async fn prefetch<T>(
        &mut self,
        request: impl Future<Output = Result<T, BrokerError>>,
    ) -> Result<T, BrokerError> {
        let mut request = pin!(request);
        while !self.eof
            && self.pending_error.is_none()
            && self.input.len() < pipeline::PREFETCH_BYTES
        {
            let remaining = pipeline::PREFETCH_BYTES - self.input.len();
            tokio::select! {
                biased;
                reply = &mut request => return reply,
                result = self.progress(remaining) => result?,
            }
        }
        request.await
    }

    // A committed reservation is independent of the outstanding PUBACK, but
    // executing another input packet or requesting a new reservation is not.
    async fn while_acknowledging(
        &mut self,
        session: &Active<'_>,
        id: mqx_codec::PacketId,
        mount: Option<&str>,
        keep_alive: u16,
        shutdown: &mut watch::Receiver<bool>,
        request: impl Future<Output = Result<(usize, Step), BrokerError>>,
    ) -> Result<(usize, Step), BrokerError> {
        let mut request = pin!(request);
        let live = &session.live;
        let mut expires = deadline(keep_alive);
        let mut ready = None;
        let mut emitted = None;
        let mut dropped = None;
        let fits = |packet: &Outbound| {
            matches!(packet, Outbound::Publish { delivery, id: Some(mid), .. }
                if delivery.qos == QoS::AtLeastOnce && *mid != id)
        };
        loop {
            if live.taken.load(Ordering::Acquire) {
                return Ok((1, Step::End(End::Takeover)));
            }
            let bytes = self.input.len();
            let read = if self.pending_error.is_none() && !self.eof {
                pipeline::PREFETCH_BYTES.saturating_sub(bytes)
            } else {
                0
            };
            let idle = self.idle();
            let can_send = ready != Some(false)
                && emitted != Some(false)
                && dropped.is_none()
                && idle
                && bytes == 0
                && read != 0;
            // A complete packet is already waiting for the ordered handler.
            // Only use the receive timeout if more input is actually needed.
            let waiting_for_input = frame_size(&self.input).is_none_or(|size| size > bytes);
            tokio::select! {
                biased;
                _ = shutdown.changed() => return Ok((1, Step::End(End::Shutdown))),
                _ = timeout(expires), if waiting_for_input => return Ok((1, Step::End(End::Timeout))),
                reply = &mut request => {
                    let (count, step) = reply?;
                    if let Some(dropped) = dropped
                        && matches!(step, Step::Continue)
                        && !live.taken.load(Ordering::Acquire)
                    {
                        let step = session.ack(dropped, Ack::Dropped).await?;
                        return Ok((count, step));
                    }
                    return Ok((count, step));
                }
                _ = live.ready.notified() => {
                    // A snapshot can invalidate this outbox even while a
                    // transport write is already pending.
                    ready = Some(live.has_reserved_if(fits)?);
                }
                result = self.progress(read), if read != 0 || !idle => {
                    result?;
                    if expires.is_some()
                        && self.input.len() != bytes
                        && frame_size(&self.input).is_some_and(|size| {
                            size.saturating_sub(self.input.len()) > 1000
                        })
                    {
                        expires = deadline(keep_alive);
                    }
                }
                _ = std::future::ready(()), if can_send => {
                    // Check the local outbox before taking the replicated state
                    // lock. A lone ACK usually has no next packet to overlap.
                    if ready.is_none() && !live.has_reserved_if(fits)? {
                        ready = Some(false);
                        continue;
                    }
                    // Leave queued packets for reauthentication in the outer loop.
                    if session.security.has_changed().unwrap_or(true) {
                        emitted = Some(false);
                        continue;
                    }
                    if !*emitted.get_or_insert_with(|| {
                        session.broker.emitted_ack_head(live, id, mount.map_or(0, str::len))
                    }) {
                        continue;
                    }
                    let packet = live.pop_reserved_if(fits)?;
                    ready = Some(packet.is_some());
                    if let Some(packet) = packet {
                        // Use the ordinary encoder (alias allocation, packet
                        // size checks, and expiry). If it drops a packet,
                        // settle that drop after the preceding ACK applies.
                        dropped = self.delivery(packet, mount, self.broker.now())?;
                    }
                }
            }
        }
    }

    // Drive both halves without splitting the transport or letting another
    // MQTT packet accumulate in the output buffer behind a stalled write.
    async fn progress(&mut self, read_budget: usize) -> std::io::Result<()> {
        poll_fn(|cx| {
            let mut progress = false;
            if !self.output.is_empty() {
                if self.selected_end == self.written {
                    self.select_packet(self.written);
                }
                match Pin::new(&mut self.stream).poll_write(cx, &self.output[self.written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Ready(Ok(written)) => {
                        self.broker.0.traffic.add(Metric::BytesSent, written as i64);
                        self.written += written;
                        let mut sent = 0;
                        while self.selected_end <= self.written {
                            sent += 1;
                            if self.selected_end == self.written {
                                break;
                            }
                            self.select_packet(self.selected_end);
                        }
                        if sent != 0 {
                            self.broker.0.traffic.add(Metric::Sent, sent);
                        }
                        if self.written == self.output.len() {
                            self.written = 0;
                            self.selected_end = 0;
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
            // Opportunistic reads after a write must not grow a busy
            // publisher's backlog forever. A read-only pass can still finish
            // a legal packet larger than the prefetch window.
            let read_budget = if progress {
                read_budget.min(pipeline::PREFETCH_BYTES.saturating_sub(self.input.len()))
            } else {
                read_budget
            };
            if read_budget != 0 && self.idle() && !self.eof {
                if self.input.capacity() == self.input.len() {
                    self.input.reserve(4096.min(read_budget));
                }
                let mut space = (&mut self.input).limit(read_budget);
                let read = self.stream.read_buf(&mut space);
                match pin!(read).poll(cx) {
                    Poll::Ready(result) => {
                        let read = result?;
                        self.eof = read == 0;
                        if read != 0 {
                            self.broker
                                .0
                                .traffic
                                .add(Metric::BytesReceived, read as i64);
                        }
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

impl<S> Drop for Wire<S> {
    fn drop(&mut self) {
        if self.queued != 0 {
            self.broker.0.traffic.add(Metric::Queued, -self.queued);
            self.broker
                .0
                .traffic
                .add(Metric::QueuedBytes, -self.queued_bytes);
        }
    }
}

fn frame_size(input: &[u8]) -> Option<usize> {
    let mut remaining = 0;
    for (index, &byte) in input.iter().skip(1).take(4).enumerate() {
        remaining |= usize::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some(remaining + index + 2);
        }
    }
    None
}

/// A peer as Mosquitto's `context->address` and `remote_port` show it.
#[derive(Clone)]
pub(super) struct Address {
    pub(super) host: Option<Arc<str>>,
    port: u16,
}

impl Address {
    /// `text` is the transport's own address text, e.g. a Unix socket path or
    /// a PROXY v1 source as sent; otherwise the IP is formatted like inet_ntop.
    pub(super) fn new(peer: Option<SocketAddr>, text: Option<&str>) -> Self {
        Self {
            host: text
                .map(Arc::from)
                .or_else(|| peer.map(|peer| Arc::from(ntop(peer.ip())))),
            port: peer.map_or(0, |peer| peer.port()),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mosquitto prints the address and port separately, with no IPv6 brackets.
        let host = self.host.as_deref().unwrap_or("unknown");
        write!(formatter, "{host}:{}", self.port)
    }
}

// lib/net_mosq.c: net__socket_get_address uses inet_ntop, which writes an
// IPv4-compatible or IPv4-mapped IPv6 address with a dotted suffix
// (`::1.2.3.4`, `::ffff:1.2.3.4`) and compresses the first longest zero run.
pub(super) fn ntop(ip: std::net::IpAddr) -> String {
    use std::fmt::Write;
    let ip = match ip {
        std::net::IpAddr::V4(ip) => return ip.to_string(),
        std::net::IpAddr::V6(ip) => ip,
    };
    let words = ip.segments();
    let (mut best, mut run) = ((0, 0), (0, 0));
    for (index, word) in words.iter().enumerate() {
        if *word == 0 {
            if run.1 == 0 {
                run.0 = index;
            }
            run.1 += 1;
            if run.1 > best.1 {
                best = run;
            }
        } else {
            run.1 = 0;
        }
    }
    if best.1 < 2 {
        best = (usize::MAX, 0);
    }
    let mut text = String::with_capacity(46);
    for (index, word) in words.iter().enumerate() {
        if (best.0..best.0.saturating_add(best.1)).contains(&index) {
            if index == best.0 {
                text.push(':');
            }
            continue;
        }
        if index != 0 {
            text.push(':');
        }
        if index == 6 && best.0 == 0 && (best.1 == 6 || (best.1 == 5 && words[5] == 0xffff)) {
            let [.., a, b, c, d] = ip.octets();
            let _ = write!(text, "{a}.{b}.{c}.{d}");
            return text;
        }
        let _ = write!(text, "{word:x}");
    }
    if best.0.saturating_add(best.1) == 8 {
        text.push(':');
    }
    text
}

// How Mosquitto logs a refused CONNECT: handle_connect.c logs a zero-length
// client id itself; loop.c: do_disconnect then names the reason. Before
// handle__connect sets context->id, the line names the client by address.
#[derive(Clone, Copy)]
enum Refusal {
    Silent,
    ZeroLengthId { v31: bool },
    NotAuthorised { named: bool },
    OversizePayload,
}

fn log_refusal(broker: &Broker, addr: &Address, id: &str, refusal: Refusal) {
    let host = addr.host.as_deref().unwrap_or("unknown");
    let (id, reason) = match refusal {
        Refusal::Silent => return,
        Refusal::ZeroLengthId { v31 } => {
            // handle_connect.c: handle_zero_length_clientid.
            if v31 {
                tracing::info!(
                    "Protocol error from {addr}: v3.1 CONNECT with zero length clientid."
                );
            } else {
                tracing::info!(
                    "Protocol error from {addr}: CONNECT with zero length clientid when forbidden."
                );
            }
            (host, "protocol error")
        }
        Refusal::NotAuthorised { named } => (if named { id } else { host }, "not authorised"),
        Refusal::OversizePayload => (host, "oversize payload"),
    };
    if broker.connection_messages() {
        tracing::info!(target: "mqx::notice", "Client {id} [{addr}] disconnected: {reason}.");
    }
}

fn log_connected(
    addr: &Address,
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
    if let Some(username) = &identity.username {
        tracing::info!(
            target: "mqx::notice",
            "New {kind} connected from {addr} as {id} (p{protocol}, c{clean}, k{keepalive}, u'{username}')."
        );
    } else {
        tracing::info!(
            target: "mqx::notice",
            "New {kind} connected from {addr} as {id} (p{protocol}, c{clean}, k{keepalive})."
        );
    }
}

fn log_disconnected(addr: &Address, id: &str, result: &Result<End, BrokerError>) {
    // loop.c: do_disconnect distinguishes an MQTT DISCONNECT from EOF/failure.
    let reason = match result {
        Ok(End::Disconnect | End::DisconnectWithWill | End::Security | End::Shutdown) => {
            tracing::info!(target: "mqx::notice", "Client {id} [{addr}] disconnected.");
            return;
        }
        Ok(End::Eof) => "connection closed by client",
        Ok(End::Timeout) => "exceeded timeout",
        Ok(End::Takeover) => "session taken over",
        Ok(End::Kicked) => "administrative action",
        Ok(End::ExternalAcl) => "external ACL error",
        Ok(End::Unsupported) => {
            "used disallowed feature (QoS too high, retain not supported, or bad AUTH method)"
        }
        Ok(End::KeepaliveRefused) => "bad socket read/write: Invalid function arguments provided.",
        Err(BrokerError::Io(error)) => {
            tracing::info!(target: "mqx::notice", "Client {id} [{addr}] disconnected: {error}.");
            return;
        }
        Err(BrokerError::Decode(DecodeError::PacketTooLarge { .. })) => "oversize packet",
        Err(BrokerError::Decode(_)) => "malformed packet",
        Err(_) => "protocol error",
    };
    tracing::info!(target: "mqx::notice", "Client {id} [{addr}] disconnected: {reason}.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_proposal_bounds_prefetch_even_after_a_large_packet() {
        use tokio::io::AsyncWriteExt;

        let cap = pipeline::PREFETCH_BYTES;
        let (stream, mut client) = tokio::io::duplex(4096);
        let mut wire = Wire::new(stream, Broker::new(BrokerConfig::default()));
        wire.input.reserve(cap * 2);
        wire.input.resize(cap - 1, 0);
        client.write_all(b"next").await.unwrap();
        let (finish, done) = tokio::sync::oneshot::channel();
        {
            let mut pending = pin!(wire.prefetch(async {
                done.await.unwrap();
                Ok(())
            }));
            assert!(futures_util::poll!(&mut pending).is_pending());
            finish.send(()).unwrap();
            pending.await.unwrap();
        }
        assert_eq!(&wire.input[cap - 1..], b"n");
        wire.progress(usize::MAX).await.unwrap();
        assert_eq!(&wire.input[cap - 1..], b"next");
    }

    #[tokio::test]
    async fn durable_qos1_writes_a_reservation_before_the_previous_ack_finishes() {
        use std::collections::BTreeMap;

        use mqx_cluster::{ClusterConfig, ClusterSecurity};
        use mqx_codec::{PacketId, Publish};
        use tokio::{
            io::AsyncWriteExt,
            net::{TcpListener, TcpStream},
            sync::oneshot,
        };

        let storage = tempfile::tempdir().unwrap();
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut cluster = ClusterConfig::new(
            1,
            address,
            BTreeMap::from([(1, address)]),
            storage.path().join("node"),
            ClusterSecurity::InsecurePlaintext,
        );
        cluster.storage_reserve = Some(0);
        let broker = Broker::clustered(
            BrokerConfig {
                max_inflight_messages: 3,
                ..BrokerConfig::default()
            },
            cluster,
        )
        .await
        .unwrap();
        let security = SecurityHandle::default();
        let claim = |id: &str, clean_start| Claim {
            publisher: Publisher {
                id: Arc::from(id),
                username: None,
                security: 0,
                dynamic_security: None,
                external: None,
            },
            clean_start,
            bridge: false,
            max_qos: QoS::ExactlyOnce,
            will: None,
            v5: None,
            now: broker.now(),
            internal_bridge: None,
            dynamic_security_revision: None,
            verdicts: Vec::new(),
        };
        let ClaimResult::Accepted(live, false) = broker
            .claim(&security, claim("sink", false), None)
            .await
            .unwrap()
        else {
            panic!("persistent subscriber claim failed");
        };
        let ClaimResult::Accepted(source, false) = broker
            .claim(&security, claim("source", true), None)
            .await
            .unwrap()
        else {
            panic!("publisher claim failed");
        };
        let mut session = Active {
            broker: &broker,
            live,
            security: security.0.snapshots.subscribe(),
            sparkplug_aware: false,
            graceful: false,
            expiry_override: None,
            detached: false,
        };
        let subscription = SubscriptionRequest::legacy(("mount/queue".into(), QoS::AtLeastOnce));
        session
            .act(Operation::subscribe(vec![subscription], broker.now()))
            .await
            .unwrap();
        let mid = |id| PacketId::new(id).unwrap();
        let publication = |id| {
            Publication::legacy(
                Publish {
                    packet_id: Some(mid(id)),
                    topic: "mount/queue".into(),
                    qos: QoS::AtLeastOnce,
                    dup: false,
                    retain: false,
                    payload: Bytes::from_static(b"message"),
                },
                broker.now(),
            )
        };
        assert_eq!(
            broker
                .receive_many(&source, (1..=3).map(&publication).collect(), false)
                .await
                .unwrap(),
            vec![Reply::PublishReason(R::SUCCESS.0); 3]
        );

        async fn read_publish(socket: &mut TcpStream, topic: &str, id: PacketId) {
            let mut expected = BytesMut::new();
            codec5::encode(
                &Packet5::Publish(codec5::Publish {
                    packet_id: Some(id),
                    topic: topic.into(),
                    qos: QoS::AtLeastOnce,
                    dup: false,
                    retain: false,
                    properties: vec![Property::TopicAlias(1)],
                    payload: Bytes::from_static(b"message"),
                }),
                &mut expected,
            )
            .unwrap();
            let mut received = vec![0; expected.len()];
            socket.read_exact(&mut received).await.unwrap();
            assert_eq!(received.as_slice(), &expected[..]);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        let mut client = client.unwrap();
        let mut wire = Wire::new(server.unwrap().0, broker.clone());
        wire.v5 = Some(v5::WireState::new(
            &crate::ListenerPolicy::default(),
            &v5::Negotiated {
                maximum_packet_size: 32,
                alias_maximum: 1,
                ..v5::Negotiated::default()
            },
        ));
        let mount = Some("mount/");
        let first = broker.next_outbound(&session.live).await.unwrap().unwrap();
        assert_eq!(wire.delivery(first, mount, broker.now()).unwrap(), None);
        while !wire.idle() {
            wire.progress(0).await.unwrap();
        }
        tokio::time::timeout(
            Duration::from_secs(3),
            read_publish(&mut client, "queue", mid(1)),
        )
        .await
        .unwrap();
        let (_shutdown, mut shutdown) = watch::channel(false);
        for (id, input, reload) in [
            (mid(3), &[][..], false),
            (mid(1), &[][..], true),
            (mid(1), &[0xc0, 0x00][..], false),
        ] {
            if reload {
                security.0.snapshots.send_modify(|_| {});
            }
            // An unsent ID is not an eligibility proof, and a buffered
            // control must not be passed even when the ACK itself is valid.
            wire.input.extend_from_slice(input);
            {
                let mut waiting = pin!(wire.while_acknowledging(
                    &session,
                    id,
                    mount,
                    0,
                    &mut shutdown,
                    pending(),
                ));
                assert!(futures_util::poll!(&mut waiting).is_pending());
            }
            assert!(wire.idle());
            let mut head = None;
            session
                .live
                .pop_reserved_if(|packet| {
                    if let Outbound::Publish { id, .. } = packet {
                        head = *id;
                    }
                    false
                })
                .unwrap();
            assert_eq!(head, Some(mid(2)));
            session.security.borrow_and_update();
        }
        assert!(matches!(
            wire.packet(broker.0.config.startup(), ProtocolVersion::V311)
                .unwrap(),
            Some(Frame::V5(Packet5::PingReq)),
        ));

        let (finish, done) = oneshot::channel();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                wire.while_acknowledging(&session, mid(1), mount, 0, &mut shutdown, async {
                    done.await.unwrap();
                    Ok((1, session.ack(mid(1), Ack::Acknowledged).await?))
                }),
                async {
                    // The pending durable ACK cannot complete until this
                    // socket has seen both remaining PUBLISH packets.
                    read_publish(&mut client, "", mid(2)).await;
                    read_publish(&mut client, "", mid(3)).await;
                    finish.send(()).unwrap();
                },
            )
        })
        .await
        .unwrap();
        assert!(matches!(result.unwrap(), (1, Step::Continue)));

        // If the outbox starts empty, a later committed reservation must
        // wake the transport while the ACK is still outstanding.
        let (finish, done) = oneshot::channel();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            let ack = async {
                done.await.unwrap();
                Ok((1, session.ack(mid(2), Ack::Acknowledged).await?))
            };
            let mut waiting =
                pin!(wire.while_acknowledging(&session, mid(2), mount, 0, &mut shutdown, ack));
            assert!(futures_util::poll!(&mut waiting).is_pending());
            tokio::join!(waiting, async {
                assert_eq!(
                    broker
                        .receive(&source, publication(4), false)
                        .await
                        .unwrap(),
                    Reply::PublishReason(R::SUCCESS.0),
                );
                read_publish(&mut client, "", mid(4)).await;
                finish.send(()).unwrap();
            })
        })
        .await
        .unwrap();
        assert!(matches!(result.unwrap(), (1, Step::Continue)));

        let extended = Packet5::PubAck(codec5::PublishAck {
            packet_id: mid(5),
            reason: R::NOT_AUTHORIZED,
            properties: vec![Property::ReasonString("denied".into())],
        });
        let mut raw = BytesMut::new();
        for id in [mid(3), mid(4)] {
            codec5::encode(&Packet5::PubAck(v5::publish_ack(id, R::SUCCESS)), &mut raw).unwrap();
        }
        codec5::encode(&extended, &mut raw).unwrap();
        codec5::encode(&Packet5::PingReq, &mut raw).unwrap();
        client.write_all(&raw).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while wire.input.len() < raw.len() {
                wire.progress(usize::MAX).await.unwrap();
            }
        })
        .await
        .unwrap();
        let config = broker.0.config.startup();
        let protocol = ProtocolVersion::V311;
        let first = wire.packet(config, protocol).unwrap().unwrap();
        let id = pipeline::simple_ack(&first).unwrap();
        assert!(matches!(
            pipeline::acknowledge(&session, &mut wire, id, protocol, mount, 0, &mut shutdown)
                .await
                .unwrap(),
            Step::Continue,
        ));
        assert!(matches!(
            wire.packet(config, protocol).unwrap(),
            Some(Frame::V5(packet)) if packet == extended,
        ));
        assert!(matches!(
            wire.packet(config, protocol).unwrap(),
            Some(Frame::V5(Packet5::PingReq)),
        ));
        assert!(broker.next_outbound(&session.live).await.unwrap().is_none());
        broker
            .detach(session.live.lease.clone(), true, None)
            .await
            .unwrap();
        session.detached = true;
        broker.shutdown_cluster().await.unwrap();
    }

    // Expected strings come from glibc inet_ntop via Python's socket.inet_ntop.
    #[test]
    fn ipv6_text_matches_inet_ntop() {
        for (input, expected) in [
            ("::1", "::1"),
            ("::", "::"),
            ("::1.2.3.4", "::1.2.3.4"),
            ("::ffff:1.2.3.4", "::ffff:1.2.3.4"),
            ("1::", "1::"),
            ("1:0:0:1:0:0:0:1", "1:0:0:1::1"),
            ("1:0:0:1:0:0:1:1", "1::1:0:0:1:1"),
            ("2001:db8::ff00:42:8329", "2001:db8::ff00:42:8329"),
            ("::ffff:0:1.2.3.4", "::ffff:0:102:304"),
            ("0:0:0:0:0:1:0:0", "::1:0:0"),
            ("::0.0.0.2", "::2"),
            ("fe80::1:0:0:0", "fe80::1:0:0:0"),
            ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
            ("0:1:0:1:0:1:0:1", "0:1:0:1:0:1:0:1"),
            ("::fffe:1.2.3.4", "::fffe:102:304"),
        ] {
            let ip: std::net::IpAddr = input.parse().unwrap();
            assert_eq!(ntop(ip), expected, "{input}");
        }
        let peer = Some("[::1.2.3.4]:1883".parse().unwrap());
        assert_eq!(Address::new(peer, None).to_string(), "::1.2.3.4:1883");
        assert_eq!(
            Address::new(None, Some("/run/mqtt.sock")).to_string(),
            "/run/mqtt.sock:0"
        );
    }
}
