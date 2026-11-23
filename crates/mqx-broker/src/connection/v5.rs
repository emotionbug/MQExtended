use std::{collections::HashMap, sync::Arc, time::Duration};

use mqx_codec::{
    Connect, LastWill, ProtocolVersion, Publish, QoS,
    v5::{self, Packet as Packet5, Property, ReasonCode as R, SubscriptionAck},
};

use super::{Active, End, Frame, Step, action_result, mount};
use crate::{
    BrokerConfig, BrokerError, ConnectionInfo, ListenerPolicy,
    inbox::{Ack, Message, PublishProperty},
    state::{Operation, Publication, Reply, SessionSettings, SubscriptionRequest},
};

#[derive(Default)]
pub(super) struct Negotiated {
    pub(super) session_expiry: u32,
    pub(super) receive_maximum: Option<u16>,
    pub(super) maximum_packet_size: usize,
    pub(super) alias_maximum: u16,
    pub(super) assigned_id: bool,
    pub(super) authentication: bool,
}

impl Negotiated {
    // property_broker.c: property__process_connect consumes limits, but ignores
    // request/response information and user properties without a plugin.
    pub(super) fn connect(packet: v5::Connect) -> (Connect, Self, SessionSettings) {
        let mut options = Self {
            assigned_id: packet.client_id.is_empty(),
            ..Self::default()
        };
        for property in packet.properties {
            match property {
                Property::SessionExpiryInterval(value) => options.session_expiry = value,
                Property::ReceiveMaximum(value) => options.receive_maximum = Some(value),
                Property::MaximumPacketSize(value) => options.maximum_packet_size = value as usize,
                Property::TopicAliasMaximum(value) => options.alias_maximum = value,
                Property::AuthenticationMethod(method) => {
                    options.authentication = !method.is_empty()
                }
                _ => {}
            }
        }
        let mut settings = SessionSettings {
            session_expiry: options.session_expiry,
            receive_maximum: options.receive_maximum,
            will_delay: 0,
            will_expiry: 0,
            will_properties: Vec::new(),
        };
        let will = packet.will.map(|will| {
            for property in will.properties {
                match property {
                    Property::WillDelayInterval(value) => settings.will_delay = value,
                    Property::MessageExpiryInterval(value) => settings.will_expiry = value,
                    property => settings
                        .will_properties
                        .extend(PublishProperty::take(property)),
                }
            }
            LastWill {
                topic: will.topic,
                payload: will.payload,
                qos: will.qos,
                retain: will.retain,
            }
        });
        (
            Connect {
                protocol: ProtocolVersion::V311,
                is_bridge: false,
                clean_session: packet.clean_start,
                keep_alive: packet.keep_alive,
                client_id: packet.client_id,
                will,
                username: packet.username,
                password: packet.password,
            },
            options,
            settings,
        )
    }
}

pub(super) struct WireState {
    maximum_packet_size: usize,
    pub(super) incoming_maximum: u16,
    outgoing_maximum: u16,
    incoming: HashMap<u16, Arc<str>>,
    outgoing: HashMap<Box<str>, u16>,
}

impl WireState {
    pub(super) fn new(listener: &ListenerPolicy, options: &Negotiated) -> Self {
        Self {
            maximum_packet_size: options.maximum_packet_size,
            incoming_maximum: listener.max_topic_alias,
            outgoing_maximum: options.alias_maximum.min(listener.max_topic_alias_broker),
            incoming: HashMap::new(),
            outgoing: HashMap::new(),
        }
    }

    pub(super) fn fits(&self, size: usize) -> bool {
        self.maximum_packet_size == 0 || size <= self.maximum_packet_size
    }

    // handle_publish.c: handle__publish resolves an alias before mounting the
    // topic or checking ACLs. An unassigned alias is a protocol error.
    pub(super) fn publication(
        &mut self,
        packet: v5::Publish,
        now: Duration,
    ) -> Result<Publication, BrokerError> {
        let mut topic = packet.topic;
        let mut expires = None;
        let mut properties = Vec::new();
        for property in packet.properties {
            match property {
                Property::TopicAlias(alias) if topic.is_empty() => {
                    topic = self
                        .incoming
                        .get(&alias)
                        .ok_or(BrokerError::Protocol)?
                        .to_string();
                }
                Property::TopicAlias(alias) => {
                    self.incoming.insert(alias, Arc::from(topic.as_str()));
                }
                Property::MessageExpiryInterval(interval) => {
                    expires = Message::expiry(Duration::from_secs(now.as_secs()), interval);
                }
                // src/handle_publish.c: Mosquitto forwards PFI=1 without
                // applying mqtt-string validation to the payload bytes.
                property => properties.extend(PublishProperty::take(property)),
            }
        }
        Ok(Publication {
            packet: Publish {
                dup: packet.dup,
                qos: packet.qos,
                retain: packet.retain,
                topic,
                packet_id: packet.packet_id,
                payload: packet.payload,
            },
            properties,
            expires,
            now,
        })
    }

    // lib/send_publish.c: send__real_publish allocates even if size later
    // prevents delivery, and does not replace a previously assigned alias.
    pub(super) fn outgoing_topic(&mut self, topic: &str) -> (String, Option<u16>) {
        if let Some(alias) = self.outgoing.get(topic) {
            return (String::new(), Some(*alias));
        }
        let alias = if self.outgoing.len() < usize::from(self.outgoing_maximum) {
            let alias = (self.outgoing.len() + 1) as u16;
            self.outgoing.insert(topic.into(), alias);
            Some(alias)
        } else {
            None
        };
        (topic.to_owned(), alias)
    }
}

pub(super) fn connack(
    config: &BrokerConfig,
    listener: &ListenerPolicy,
    present: bool,
    reason: R,
    mut properties: Vec<Property>,
) -> v5::Packet {
    // send_connack.c: send__connack appends these in this order; Maximum
    // QoS is also present on a refusal, unlike the other broker limits.
    if reason == R::SUCCESS {
        if !config.retain_available {
            properties.push(Property::RetainAvailable(0));
        }
        if config.max_packet_size > 0 {
            properties.push(Property::MaximumPacketSize(config.max_packet_size as u32));
        }
        if (1..usize::from(u16::MAX)).contains(&config.max_inflight_messages) {
            properties.push(Property::ReceiveMaximum(
                config.max_inflight_messages as u16,
            ));
        }
    }
    if listener.max_qos != QoS::ExactlyOnce {
        properties.push(Property::MaximumQos(listener.max_qos as u8));
    }
    v5::Packet::ConnAck(v5::ConnAck {
        session_present: present,
        reason,
        properties,
    })
}

impl Active<'_> {
    pub(super) async fn process_v5(
        &mut self,
        packet: Packet5,
        info: &ConnectionInfo,
        wire: &mut WireState,
        session_expiry: u32,
    ) -> Result<Step, BrokerError> {
        use Packet5::*;
        let config = self.broker.0.config.startup();
        let mount_point = info.listener.mount_point.as_deref();
        let max_qos = info.listener.max_qos;
        let now = self.broker.now();
        match packet {
            Disconnect(packet) => {
                // property_broker.c: property__process_disconnect only forbids
                // changing an initially zero interval to a nonzero interval.
                let expiry = packet
                    .properties
                    .into_iter()
                    .find_map(|property| match property {
                        Property::SessionExpiryInterval(value) => Some(value),
                        _ => None,
                    });
                if session_expiry == 0 && expiry.is_some_and(|value| value != 0) {
                    return Err(BrokerError::Protocol);
                }
                self.expiry_override = expiry;
                Ok(Step::End(
                    if packet.reason == R::DISCONNECT_WITH_WILL_MESSAGE {
                        End::DisconnectWithWill
                    } else {
                        End::Disconnect
                    },
                ))
            }
            PingReq => Ok(Step::Reply(Frame::V5(PingResp))),
            Subscribe(packet) => {
                let identifier = packet
                    .properties
                    .into_iter()
                    .find_map(|property| match property {
                        Property::SubscriptionIdentifier(value) => Some(value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let filters = packet
                    .subscriptions
                    .into_iter()
                    .map(|mut sub| {
                        mount(&mut sub.filter, mount_point);
                        SubscriptionRequest {
                            filter: sub.filter,
                            qos: if sub.qos as u8 > max_qos as u8 {
                                max_qos
                            } else {
                                sub.qos
                            },
                            no_local: sub.no_local,
                            retain_as_published: sub.retain_as_published,
                            retain_handling: sub.retain_handling as u8,
                            identifier,
                        }
                    })
                    .collect::<Vec<_>>();
                let logged = tracing::enabled!(target: "mqx::subscribe", tracing::Level::INFO)
                    .then(|| {
                        filters
                            .iter()
                            .map(|sub| (sub.filter.clone(), sub.qos))
                            .collect::<Vec<_>>()
                    });
                match self.act(Operation::subscribe(filters, now)).await? {
                    Reply::Subscribed(codes) => {
                        if let Some(logged) = logged {
                            for ((filter, qos), code) in logged.into_iter().zip(&codes) {
                                if matches!(code, mqx_codec::SubscribeReturnCode::Success(_)) {
                                    tracing::info!(target: "mqx::subscribe", "{} {} {filter}", self.live.lease.id, qos as u8);
                                }
                            }
                        }
                        Ok(Step::Reply(Frame::V5(SubAck(SubscriptionAck {
                            packet_id: packet.packet_id,
                            properties: Vec::new(),
                            reasons: codes
                                .into_iter()
                                .map(|code| match code {
                                    mqx_codec::SubscribeReturnCode::Success(qos) => R(qos as u8),
                                    mqx_codec::SubscribeReturnCode::Failure => R::NOT_AUTHORIZED,
                                    mqx_codec::SubscribeReturnCode::Unrecognized(reason) => {
                                        R(reason)
                                    }
                                })
                                .collect(),
                        }))))
                    }
                    reply => action_result(reply),
                }
            }
            Unsubscribe(packet) => {
                // handle_unsubscribe.c: handle__unsubscribe checks ACL and
                // removes the filter as sent, without the listener mount_point.
                for filter in &packet.filters {
                    tracing::info!(target: "mqx::unsubscribe", "{} {filter}", self.live.lease.id);
                }
                match self.act(Operation::Unsubscribe(packet.filters)).await? {
                    Reply::Unsubscribed(reasons) => {
                        Ok(Step::Reply(Frame::V5(UnsubAck(SubscriptionAck {
                            packet_id: packet.packet_id,
                            properties: Vec::new(),
                            reasons: reasons.into_iter().map(R).collect(),
                        }))))
                    }
                    reply => action_result(reply),
                }
            }
            Publish(packet) => {
                if packet.qos as u8 > max_qos as u8 {
                    return Err(BrokerError::ProtocolV5(R::QOS_NOT_SUPPORTED));
                }
                if packet.retain && !config.retain_available {
                    return Err(BrokerError::ProtocolV5(R::RETAIN_NOT_SUPPORTED));
                }
                let id = packet.packet_id;
                let qos = packet.qos;
                let mut publication = wire.publication(packet, now)?;
                mount(&mut publication.packet.topic, mount_point);
                let reply = self.receive(publication).await?;
                let control = matches!(reply, Reply::ControlAccepted { .. });
                let reason = match reply {
                    Reply::PublishReason(reason) => R(reason),
                    _ => R::SUCCESS,
                };
                let step = action_result(reply)?;
                Ok(match id {
                    Some(id) if qos == QoS::ExactlyOnce => {
                        step.or_reply(Frame::V5(PubRec(publish_ack(id, reason))), false)
                    }
                    Some(id) => step.or_reply(
                        Frame::V5(PubAck(publish_ack(id, reason))),
                        !control && reason.0 < 0x80,
                    ),
                    None => step,
                })
            }
            PubRel(packet) => Ok(
                action_result(self.release(packet.packet_id).await?)?.or_reply(
                    Frame::V5(PubComp(publish_ack(packet.packet_id, R::SUCCESS))),
                    true,
                ),
            ),
            PubAck(packet) => self.ack(packet.packet_id, Ack::Acknowledged).await,
            PubRec(packet) if packet.reason.0 >= 0x80 => {
                self.ack(packet.packet_id, Ack::Rejected).await
            }
            PubRec(packet) => Ok(self.ack(packet.packet_id, Ack::Received).await?.or_reply(
                Frame::V5(PubRel(publish_ack(packet.packet_id, R::SUCCESS))),
                false,
            )),
            PubComp(packet) => self.ack(packet.packet_id, Ack::Completed).await,
            // handle_auth.c: handle__auth checks for an existing method first.
            Auth(_) | Connect(_) | ConnAck(_) | PingResp | SubAck(_) | UnsubAck(_) => {
                Err(BrokerError::Protocol)
            }
        }
    }
}

pub(super) fn publish_ack(packet_id: mqx_codec::PacketId, reason: R) -> v5::PublishAck {
    v5::PublishAck {
        packet_id,
        reason,
        properties: Vec::new(),
    }
}
