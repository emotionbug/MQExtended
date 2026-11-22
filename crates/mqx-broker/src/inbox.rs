use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use bytes::Bytes;
use mqx_codec::{PacketId, QoS};
use serde::{Deserialize, Serialize};

use crate::BrokerConfig;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Publisher {
    pub(crate) id: Arc<str>,
    pub(crate) username: Option<Arc<str>>,
    pub(crate) security: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Message {
    pub(crate) source: Publisher,
    pub(crate) topic: Box<str>,
    pub(crate) payload: Bytes,
    pub(crate) qos: QoS,
    pub(crate) retain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Delivery {
    pub(crate) message: Arc<Message>,
    pub(crate) qos: QoS,
    pub(crate) retain: bool,
    pub(crate) dedup_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Outbound {
    Publish {
        delivery: Delivery,
        id: Option<PacketId>,
        dup: bool,
    },
    Release(PacketId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Ack {
    Received,
    Acknowledged,
    Completed,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Publish,
    AwaitAck,
    AwaitRec,
    Release,
    AwaitComp,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Outgoing {
    delivery: Delivery,
    id: Option<PacketId>,
    dup: bool,
    phase: Phase,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Counters {
    count: usize,
    bytes: usize,
    qos_count: usize,
    qos_bytes: usize,
}

impl Counters {
    fn change(&mut self, delivery: &Delivery, add: bool) {
        let bytes = delivery.message.payload.len();
        if add {
            self.count += 1;
            self.bytes += bytes;
            if delivery.qos != QoS::AtMostOnce {
                self.qos_count += 1;
                self.qos_bytes += bytes;
            }
        } else {
            self.count -= 1;
            self.bytes -= bytes;
            if delivery.qos != QoS::AtMostOnce {
                self.qos_count -= 1;
                self.qos_bytes -= bytes;
            }
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Inbox {
    last_mid: u16,
    last_delivered: Option<u64>,
    in_flight: VecDeque<Outgoing>,
    queued: VecDeque<Outgoing>,
    flight_stats: Counters,
    queue_stats: Counters,
    next_unsent: usize,
    dropped: bool,
    incoming: BTreeMap<PacketId, Incoming>,
    incoming_bytes: usize,
    incoming_slots: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Incoming {
    message: Arc<Message>,
    repeated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    Ready,
    Queued,
    Dropped,
    FirstDrop,
    Suppressed,
}

impl Inbox {
    // lib/util_mosq.c: mosquitto__mid_generate; subs.c: subs__send allocates
    // before duplicate suppression and queue admission, so even drops use IDs.
    pub(crate) fn offer(
        &mut self,
        mut delivery: Delivery,
        online: bool,
        max_qos: QoS,
        config: &BrokerConfig,
    ) -> Offer {
        let id = if delivery.qos == QoS::AtMostOnce {
            None
        } else {
            self.last_mid = self.last_mid.wrapping_add(1).max(1);
            PacketId::new(self.last_mid)
        };
        if delivery.dedup_id.is_some() && delivery.dedup_id == self.last_delivered {
            return Offer::Suppressed;
        }
        if !online && delivery.qos == QoS::AtMostOnce && !config.queue_qos0_messages {
            return Offer::Suppressed;
        }
        let ready = online && self.flight_available(delivery.qos, config);
        if !ready
            && ((online && delivery.qos == QoS::AtMostOnce)
                || !self.queue_available(online, config))
        {
            return if std::mem::replace(&mut self.dropped, true) {
                Offer::Dropped
            } else {
                Offer::FirstDrop
            };
        }
        if delivery.dedup_id.is_some() {
            self.last_delivered = delivery.dedup_id;
        }
        // database.c: db__message_insert_outgoing clamps delivery QoS after
        // admitting the message, e.g. after a session changes listeners.
        if delivery.qos as u8 > max_qos as u8 {
            delivery.qos = max_qos;
        }
        let entry = Outgoing {
            delivery,
            id,
            dup: false,
            phase: Phase::Publish,
        };
        if ready {
            self.flight_stats.change(&entry.delivery, true);
            self.in_flight.push_back(entry);
            Offer::Ready
        } else {
            self.queue_stats.change(&entry.delivery, true);
            self.queued.push_back(entry);
            Offer::Queued
        }
    }

    // database.c: db__ready_for_flight checks existing payload bytes, so the
    // last admitted packet can cross the configured byte limit.
    fn flight_available(&self, qos: QoS, config: &BrokerConfig) -> bool {
        if qos == QoS::AtMostOnce {
            if config.max_inflight_messages == 0 && config.max_inflight_bytes == 0 {
                return true;
            }
            if config.max_queued_messages == 0 && config.max_inflight_bytes == 0 {
                return true;
            }
            return below(
                self.flight_stats.count - self.next_unsent,
                config.max_queued_messages,
            ) && below(
                self.flight_stats
                    .bytes
                    .saturating_sub(config.max_inflight_bytes),
                config.max_queued_bytes,
            );
        }
        below(self.flight_stats.qos_count, config.max_inflight_messages)
            && below(self.flight_stats.qos_bytes, config.max_inflight_bytes)
    }

    // database.c: db__ready_for_queue's online allowance includes an extra
    // flight window. Offline QoS 0 does not contribute to either counter.
    fn queue_available(&self, online: bool, config: &BrokerConfig) -> bool {
        let extra_count = if online {
            config.max_inflight_messages
        } else {
            0
        };
        let extra_bytes = if online { config.max_inflight_bytes } else { 0 };
        below(
            self.queue_stats.qos_count.saturating_sub(extra_count),
            config.max_queued_messages,
        ) && below(
            self.queue_stats.qos_bytes.saturating_sub(extra_bytes),
            config.max_queued_bytes,
        )
    }

    fn promote(&mut self, config: &BrokerConfig) {
        while self
            .queued
            .front()
            .is_some_and(|entry| self.flight_available(entry.delivery.qos, config))
        {
            let entry = self.queued.pop_front().unwrap();
            self.queue_stats.change(&entry.delivery, false);
            self.flight_stats.change(&entry.delivery, true);
            self.in_flight.push_back(entry);
        }
    }

    pub(crate) fn has_outbound(&self, config: &BrokerConfig) -> bool {
        self.in_flight
            .iter()
            .skip(self.next_unsent)
            .any(|entry| matches!(entry.phase, Phase::Publish | Phase::Release))
            || self
                .queued
                .front()
                .is_some_and(|entry| self.flight_available(entry.delivery.qos, config))
    }

    pub(crate) fn next_outbound(&mut self, config: &BrokerConfig) -> Option<Outbound> {
        self.promote(config);
        loop {
            let entry = self.in_flight.get_mut(self.next_unsent)?;
            match entry.phase {
                Phase::Publish if entry.delivery.qos == QoS::AtMostOnce => {
                    let entry = self.remove_flight(self.next_unsent);
                    return Some(Outbound::Publish {
                        delivery: entry.delivery,
                        id: None,
                        dup: false,
                    });
                }
                Phase::Publish => {
                    let packet = Outbound::Publish {
                        delivery: entry.delivery.clone(),
                        id: entry.id,
                        dup: entry.dup,
                    };
                    entry.dup = true;
                    entry.phase = if entry.delivery.qos == QoS::AtLeastOnce {
                        Phase::AwaitAck
                    } else {
                        Phase::AwaitRec
                    };
                    self.next_unsent += 1;
                    return Some(packet);
                }
                Phase::Release => {
                    entry.phase = Phase::AwaitComp;
                    self.next_unsent += 1;
                    return Some(Outbound::Release(entry.id.unwrap()));
                }
                Phase::AwaitAck | Phase::AwaitRec | Phase::AwaitComp => self.next_unsent += 1,
            }
        }
    }

    // database.c: db__message_delete_outgoing, db__message_update_outgoing;
    // lib/handle_pubrec.c: even an unknown PUBREC gets a PUBREL on v3.x.
    pub(crate) fn ack(&mut self, id: PacketId, kind: Ack, config: &BrokerConfig) -> bool {
        if let Some(index) = self.in_flight.iter().position(|entry| entry.id == Some(id)) {
            if !ack_entry(&mut self.in_flight[index], kind) {
                return false;
            }
            if kind != Ack::Received {
                self.remove_flight(index);
            }
        } else if let Some(index) = self.queued.iter().position(|entry| entry.id == Some(id)) {
            if !ack_entry(&mut self.queued[index], kind) {
                return false;
            }
            if kind != Ack::Received {
                let entry = self.queued.remove(index).unwrap();
                self.queue_stats.change(&entry.delivery, false);
            }
        }
        if kind != Ack::Received {
            self.promote(config);
        }
        true
    }

    fn remove_flight(&mut self, index: usize) -> Outgoing {
        let entry = self.in_flight.remove(index).unwrap();
        if index < self.next_unsent {
            self.next_unsent -= 1;
        }
        self.flight_stats.change(&entry.delivery, false);
        entry
    }

    pub(crate) fn reset_outbound(&mut self) {
        self.dropped = false;
        self.next_unsent = 0;
        for entry in &mut self.in_flight {
            entry.phase = if matches!(entry.phase, Phase::AwaitComp | Phase::Release) {
                Phase::Release
            } else {
                Phase::Publish
            };
        }
    }

    // database.c: db__message_reconnect_reset and db__check_acl_of_all_messages.
    pub(crate) fn resume(
        &mut self,
        mut allowed: impl FnMut(&str, bool) -> bool,
        config: &BrokerConfig,
    ) {
        self.reset_outbound();
        self.promote(config);
        self.in_flight.retain(|entry| {
            let allowed = allowed(&entry.delivery.message.topic, false);
            if !allowed {
                self.flight_stats.change(&entry.delivery, false);
            }
            allowed
        });
        self.queued.retain(|entry| {
            let allowed = allowed(&entry.delivery.message.topic, false);
            if !allowed {
                self.queue_stats.change(&entry.delivery, false);
            }
            allowed
        });
        self.incoming_slots = self.incoming.len().min(config.max_inflight_messages);
        self.incoming.retain(|_, entry| {
            let allowed = allowed(&entry.message.topic, true);
            if !allowed {
                self.incoming_bytes -= entry.message.payload.len();
            }
            allowed
        });
        for entry in self.incoming.values_mut() {
            entry.repeated = false;
        }
    }

    // handle_publish.c: handle__accepted_publish replaces a pending QoS 2 on
    // mismatched content, even if DUP is set, and rejects the second retry.
    // Quota-rejected publishes are acknowledged but not stored.
    pub(crate) fn receive(
        &mut self,
        id: PacketId,
        message: Arc<Message>,
        config: &BrokerConfig,
    ) -> bool {
        if let Some(previous) = self.incoming.get_mut(&id) {
            if previous.message.qos == message.qos
                && previous.message.topic == message.topic
                && previous.message.payload == message.payload
            {
                return !std::mem::replace(&mut previous.repeated, true);
            }
            self.remove_incoming(id);
        }
        if self.incoming_available(config) {
            if config.max_inflight_messages != 0 {
                self.incoming_slots += 1;
            }
            self.incoming_bytes += message.payload.len();
            self.incoming.insert(
                id,
                Incoming {
                    message,
                    repeated: false,
                },
            );
        }
        true
    }

    pub(crate) fn can_publish_qos1(&mut self, id: PacketId, config: &BrokerConfig) -> bool {
        self.remove_incoming(id);
        let admitted = self.incoming_available(config);
        if !admitted {
            self.credit_incoming();
        }
        admitted
    }

    fn incoming_available(&self, config: &BrokerConfig) -> bool {
        below(self.incoming_slots, config.max_inflight_messages)
            && below(self.incoming_bytes, config.max_inflight_bytes)
    }

    // lib/send_mosq.c: send__puback and send__pubcomp credit the quota even
    // when the corresponding QoS 1 publish or QoS 2 release was rejected.
    pub(crate) fn credit_incoming(&mut self) {
        self.incoming_slots = self.incoming_slots.saturating_sub(1);
    }

    // lib/handle_pubrel.c: send PUBCOMP even when no message is stored.
    pub(crate) fn release(&mut self, id: PacketId) -> Option<Arc<Message>> {
        self.credit_incoming();
        self.remove_incoming(id)
    }

    fn remove_incoming(&mut self, id: PacketId) -> Option<Arc<Message>> {
        let entry = self.incoming.remove(&id)?;
        self.incoming_bytes -= entry.message.payload.len();
        Some(entry.message)
    }
}

fn below(value: usize, limit: usize) -> bool {
    limit == 0 || value < limit
}

fn ack_entry(entry: &mut Outgoing, kind: Ack) -> bool {
    match kind {
        Ack::Received if entry.delivery.qos == QoS::ExactlyOnce => {
            entry.phase = Phase::AwaitComp;
            true
        }
        Ack::Acknowledged => entry.delivery.qos == QoS::AtLeastOnce,
        Ack::Completed => entry.delivery.qos == QoS::ExactlyOnce && entry.phase == Phase::AwaitComp,
        Ack::Received => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(bytes: &'static [u8], qos: QoS) -> Delivery {
        Delivery {
            message: Arc::new(Message {
                source: Publisher {
                    id: Arc::from("source"),
                    username: None,
                    security: 0,
                },
                topic: "topic".into(),
                payload: Bytes::from_static(bytes),
                qos,
                retain: false,
            }),
            qos,
            retain: false,
            dedup_id: None,
        }
    }

    fn assert_publish_id(inbox: &mut Inbox, config: &BrokerConfig, expected: u16) {
        assert!(
            matches!(inbox.next_outbound(config), Some(Outbound::Publish { id: Some(id), dup: false, .. }) if id.get() == expected)
        );
    }

    // util_mosq.c: mosquitto__mid_generate skips zero at wraparound.
    #[test]
    fn qos0_does_not_consume_a_mid_and_wrap_skips_zero() {
        let config = BrokerConfig::default();
        let mut inbox = Inbox {
            last_mid: u16::MAX - 1,
            ..Inbox::default()
        };
        assert_eq!(
            inbox.offer(
                delivery(b"", QoS::AtMostOnce),
                true,
                QoS::ExactlyOnce,
                &config
            ),
            Offer::Ready
        );
        assert!(matches!(
            inbox.next_outbound(&config),
            Some(Outbound::Publish { id: None, .. })
        ));
        for id in [u16::MAX, 1] {
            assert_eq!(
                inbox.offer(
                    delivery(b"", QoS::AtLeastOnce),
                    true,
                    QoS::ExactlyOnce,
                    &config
                ),
                Offer::Ready
            );
            assert_publish_id(&mut inbox, &config, id);
        }
    }

    // database.c: db__ready_for_flight and db__ready_for_queue count bytes
    // already accepted, including an extra flight allowance for online queues.
    #[test]
    fn byte_limits_cross_the_threshold_once_and_keep_queue_order() {
        let config = BrokerConfig {
            max_inflight_messages: 0,
            max_inflight_bytes: 3,
            max_queued_messages: 0,
            max_queued_bytes: 3,
            ..BrokerConfig::default()
        };
        let mut inbox = Inbox::default();
        let msg = delivery(b"four", QoS::AtLeastOnce);
        assert_eq!(
            inbox.offer(msg.clone(), true, QoS::ExactlyOnce, &config),
            Offer::Ready
        );
        assert_eq!(
            inbox.offer(msg.clone(), true, QoS::ExactlyOnce, &config),
            Offer::Queued
        );
        assert_eq!(
            inbox.offer(msg.clone(), true, QoS::ExactlyOnce, &config),
            Offer::Queued
        );
        assert_eq!(
            inbox.offer(msg.clone(), true, QoS::ExactlyOnce, &config),
            Offer::FirstDrop
        );
        assert_eq!(
            inbox.offer(msg, true, QoS::ExactlyOnce, &config),
            Offer::Dropped
        );
        for id in 1..=3 {
            assert_publish_id(&mut inbox, &config, id);
            assert!(inbox.next_outbound(&config).is_none());
            assert!(inbox.ack(PacketId::new(id).unwrap(), Ack::Acknowledged, &config));
        }
        assert!(inbox.next_outbound(&config).is_none());
    }
}
