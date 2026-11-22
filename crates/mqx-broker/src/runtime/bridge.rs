use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use bytes::Bytes;
use mqx_cluster::MembershipControl;
use mqx_codec::{
    LastWill, PacketId, Publish, QoS,
    v5::{Property, Publish as Publish5, ReasonCode as R},
};
use tokio::time;

use super::{
    Broker, BrokerError, ClaimResult, Live, Log, Operation, Publication, Reply, SecurityHandle,
};
use crate::{
    inbox::{Ack, Message, Outbound, PublishProperty, Publisher},
    state::{BridgeState, Claim, SessionSettings, SubscriptionRequest},
};

/// In-process session identity for an outgoing bridge. Its live traffic
/// bypasses local authentication and ACLs, unlike a private-bit socket client.
pub struct BridgeIdentity<'a> {
    pub name: &'a str,
    pub client_id: &'a str,
    pub remote_client_id: &'a str,
    pub reuse_local_client_id: bool,
    pub reuse_remote_client_id: bool,
    pub username: Option<&'a str>,
    pub local_clean: bool,
    pub lazy: bool,
    pub mqtt5: bool,
    pub max_qos: QoS,
}

/// Epoch-fenced broker session. Only its owner runs an outgoing transport.
pub struct BridgeSession {
    broker: Broker,
    live: Arc<Live>,
    remote_client_id: Arc<str>,
    membership: Option<MembershipControl>,
    detached: bool,
}

impl Broker {
    pub async fn claim_bridge(
        &self,
        id: BridgeIdentity<'_>,
        security: &SecurityHandle,
    ) -> Result<Option<BridgeSession>, BrokerError> {
        if *self.0.shutdown.borrow() {
            return Ok(None);
        }
        if let Log::Replicated(log) = &self.0.log
            && log
                .cluster
                .read(|machine| machine.state.bridge_claimed(id.client_id, id.name))
        {
            return Ok(None);
        }
        let membership = self.cluster_membership();
        if membership
            .as_ref()
            .is_some_and(|membership| membership.lease_valid_until().is_none())
        {
            return Ok(None);
        }
        match self
            .claim(
                security,
                Claim {
                    publisher: Publisher {
                        id: Arc::from(id.client_id),
                        username: id.username.map(Arc::from),
                        security: 0,
                        dynamic_security: None,
                    },
                    clean_start: false,
                    bridge: true,
                    max_qos: id.max_qos,
                    will: None,
                    v5: id.mqtt5.then_some(SessionSettings {
                        session_expiry: u32::MAX,
                        receive_maximum: None,
                        will_delay: 0,
                        will_expiry: 0,
                        will_properties: Vec::new(),
                    }),
                    now: Duration::ZERO,
                    internal_bridge: Some(Box::new(BridgeState {
                        name: Arc::from(id.name),
                        remote_clientid: Arc::from(id.remote_client_id),
                        reuse_remote_clientid: id.reuse_remote_client_id,
                        reuse_local_clientid: id.reuse_local_client_id,
                        local_clean: id.local_clean,
                        lazy: id.lazy,
                        online: false,
                    })),
                    dynamic_security_revision: None,
                },
                None,
            )
            .await?
        {
            ClaimResult::Accepted(live, _) => {
                let remote_client_id = match &self.0.log {
                    Log::Local { .. } => self
                        .0
                        .runtime
                        .lock()
                        .unwrap()
                        .local
                        .as_ref()
                        .unwrap()
                        .state
                        .bridge_remote_id(&live.lease),
                    Log::Replicated(log) => log
                        .cluster
                        .read(|machine| machine.state.bridge_remote_id(&live.lease)),
                }
                .unwrap_or_else(|| Arc::from(id.remote_client_id));
                Ok(Some(BridgeSession {
                    broker: self.clone(),
                    live,
                    remote_client_id,
                    membership,
                    detached: false,
                }))
            }
            ClaimResult::Stale | ClaimResult::Full | ClaimResult::Unauthorized => Ok(None),
        }
    }

    pub fn bridge_shutdown(&self) -> tokio::sync::watch::Receiver<bool> {
        self.0.shutdown.subscribe()
    }

    pub fn bridge_receive_maximum(&self) -> u16 {
        u16::try_from(self.0.config.max_inflight_messages).unwrap_or(u16::MAX)
    }
}

impl BridgeSession {
    pub fn client_id(&self) -> &str {
        &self.live.lease.id
    }

    pub fn remote_client_id(&self) -> &str {
        &self.remote_client_id
    }

    pub fn active(&self) -> bool {
        self.leased() && !*self.broker.0.shutdown.borrow()
    }

    pub fn leased(&self) -> bool {
        !self.live.taken.load(Ordering::Acquire)
            && self
                .membership
                .as_ref()
                .is_none_or(|membership| membership.lease_valid_until().is_some())
    }

    pub async fn lost(&self) {
        let mut shutdown = self.broker.bridge_shutdown();
        tokio::select! {
            _ = async {
                if let Some(membership) = &self.membership {
                    membership.wait_lease_invalid().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
            _ = async {
                while !self.live.taken.load(Ordering::Acquire) {
                    time::sleep(Duration::from_millis(100)).await;
                }
            }, if self.membership.is_some() => {},
            _ = shutdown.wait_for(|closed| *closed) => {},
        };
    }

    pub fn pending(&self) -> usize {
        match &self.broker.0.log {
            Log::Local { .. } => self
                .broker
                .0
                .runtime
                .lock()
                .unwrap()
                .local
                .as_ref()
                .unwrap()
                .state
                .bridge_pending(&self.live.lease),
            Log::Replicated(log) => log
                .cluster
                .read(|machine| machine.state.bridge_pending(&self.live.lease)),
        }
    }

    pub async fn ready(&self) {
        self.live.ready.notified().await;
    }

    pub async fn prepare(
        &self,
        filters: Vec<(String, QoS)>,
        will: Option<LastWill>,
        max_qos: QoS,
        clean_incoming: bool,
        receive_maximum: Option<u16>,
    ) -> Result<(), BrokerError> {
        {
            let mut outbox = self.live.outbox.lock().unwrap();
            outbox.packets.clear();
            outbox.interrupted = false;
        }
        let now = self.broker.now();
        self.apply(Operation::BridgePrepare {
            filters: subscriptions(filters, false),
            will,
            max_qos,
            clean_incoming,
            receive_maximum,
            now,
        })
        .await?;
        Ok(())
    }

    pub async fn online(
        &self,
        max_qos: QoS,
        receive_maximum: Option<u16>,
    ) -> Result<(), BrokerError> {
        self.apply(Operation::BridgeOnline {
            max_qos,
            receive_maximum,
            now: self.broker.now(),
        })
        .await?;
        Ok(())
    }

    pub async fn replay_retained(&self, filters: Vec<(String, QoS)>) -> Result<(), BrokerError> {
        self.apply(Operation::Subscribe(
            subscriptions(filters, true),
            self.broker.now(),
        ))
        .await?;
        Ok(())
    }

    pub async fn offline(&self, graceful: bool) -> Result<(), BrokerError> {
        self.apply(Operation::BridgeOffline {
            now: self.broker.now(),
            graceful,
        })
        .await?;
        Ok(())
    }

    pub async fn close(mut self, remove: bool) -> Result<(), BrokerError> {
        if remove && !self.live.taken.load(Ordering::Acquire) {
            self.apply(Operation::BridgeRemove).await?;
        }
        self.detached = true;
        self.broker
            .detach(self.live.lease.clone(), self.leased(), None)
            .await
    }

    pub async fn notify(
        &self,
        topic: &str,
        qos: QoS,
        payload: &'static [u8],
    ) -> Result<(), BrokerError> {
        self.apply(Operation::BridgeNotify(Publication::legacy(
            Publish {
                dup: false,
                qos,
                retain: true,
                topic: topic.into(),
                packet_id: None,
                payload: Bytes::from_static(payload),
            },
            self.broker.now(),
        )))
        .await?;
        Ok(())
    }

    pub async fn packet_id(&self) -> Result<PacketId, BrokerError> {
        match self.apply(Operation::BridgeMid).await? {
            Reply::BridgeMid(id) => Ok(id),
            _ => unreachable!("bridge mid command returns a packet id"),
        }
    }

    pub async fn next_outbound(
        &self,
        mqtt5: bool,
    ) -> Result<Option<mqx_codec::v5::Packet>, BrokerError> {
        use mqx_codec::v5::{Packet, PublishAck};
        let Some(packet) = self.broker.next_outbound(&self.live).await? else {
            return Ok(None);
        };
        Ok(Some(match packet {
            Outbound::Release(packet_id) => Packet::PubRel(PublishAck {
                packet_id,
                reason: R::SUCCESS,
                properties: Vec::new(),
            }),
            Outbound::Publish { delivery, id, dup } => {
                let message = &delivery.message;
                let mut properties = if mqtt5 {
                    message
                        .properties
                        .iter()
                        .map(PublishProperty::wire)
                        .collect()
                } else {
                    Vec::new()
                };
                if mqtt5 && let Some(expires) = message.expires {
                    let ttl = expires
                        .as_secs()
                        .saturating_sub(self.broker.now().as_secs());
                    if ttl != 0 {
                        properties.push(Property::MessageExpiryInterval(ttl as u32));
                    }
                }
                Packet::Publish(Publish5 {
                    dup,
                    qos: delivery.qos,
                    retain: delivery.retain,
                    topic: message.topic.to_string(),
                    packet_id: id,
                    properties,
                    payload: message.payload.clone(),
                })
            }
        }))
    }

    pub async fn receive(&self, packet: Publish5) -> Result<R, BrokerError> {
        if packet.retain && !self.broker.0.config.retain_available {
            return Err(BrokerError::ProtocolV5(R::RETAIN_NOT_SUPPORTED));
        }
        let now = self.broker.now();
        let mut expires = None;
        let properties = packet
            .properties
            .into_iter()
            .filter_map(|property| {
                if let Property::MessageExpiryInterval(interval) = property {
                    expires = Message::expiry(Duration::from_secs(now.as_secs()), interval);
                    None
                } else {
                    PublishProperty::take(property)
                }
            })
            .collect();
        let packet = Publish {
            dup: packet.dup,
            qos: packet.qos,
            retain: packet.retain,
            topic: packet.topic,
            packet_id: packet.packet_id,
            payload: packet.payload,
        };
        match self
            .apply(Operation::Receive(Publication {
                packet,
                properties,
                expires,
                now,
            }))
            .await?
        {
            Reply::NoChange => Ok(R::SUCCESS),
            Reply::PublishReason(reason) => Ok(R(reason)),
            _ => unreachable!("internal bridge uses a durable inbox"),
        }
    }

    pub async fn release(&self, id: PacketId) -> Result<(), BrokerError> {
        self.apply(Operation::Release(id, self.broker.now()))
            .await?;
        Ok(())
    }

    pub async fn acknowledge(
        &self,
        id: PacketId,
        acknowledgment: BridgeAck,
    ) -> Result<(), BrokerError> {
        let kind = match acknowledgment {
            BridgeAck::PubAck => Ack::Acknowledged,
            BridgeAck::PubRec => Ack::Received,
            BridgeAck::PubComp => Ack::Completed,
            BridgeAck::Reject => Ack::Rejected,
            BridgeAck::Drop => Ack::Dropped,
        };
        self.apply(Operation::Ack(id, kind)).await?;
        Ok(())
    }

    async fn apply(&self, operation: Operation) -> Result<Reply, BrokerError> {
        match self.broker.act(&self.live, operation).await? {
            Reply::Stale => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "bridge lost ownership",
            )
            .into()),
            Reply::ProtocolError => Err(BrokerError::Protocol),
            reply => Ok(reply),
        }
    }
}

#[derive(Clone, Copy)]
pub enum BridgeAck {
    PubAck,
    PubRec,
    PubComp,
    Reject,
    Drop,
}

impl Drop for BridgeSession {
    fn drop(&mut self) {
        if !self.detached {
            self.broker
                .detach_cancelled(self.live.lease.clone(), false, None);
        }
    }
}

fn subscriptions(filters: Vec<(String, QoS)>, replay: bool) -> Vec<SubscriptionRequest> {
    filters
        .into_iter()
        .map(|(filter, qos)| SubscriptionRequest {
            filter,
            qos,
            no_local: true,
            retain_as_published: true,
            retain_handling: if replay { 0 } else { 2 },
            identifier: 0,
        })
        .collect()
}
