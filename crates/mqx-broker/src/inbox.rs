use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use mqx_codec::v5::Property;
use mqx_codec::{PacketId, QoS};
use serde::{Deserialize, Serialize};

use crate::{
    BrokerConfig,
    persistence::{PersistentOutgoing, PersistentSession},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Publisher {
    pub(crate) id: Arc<str>,
    pub(crate) username: Option<Arc<str>>,
    pub(crate) security: u64,
    #[serde(default)]
    pub(crate) dynamic_security: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) external: Option<(u32, mqx_auth::external::Binding)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Message {
    pub(crate) source: Publisher,
    pub(crate) topic: Box<str>,
    pub(crate) payload: Bytes,
    pub(crate) qos: QoS,
    pub(crate) retain: bool,
    #[serde(default)]
    pub(crate) properties: Vec<PublishProperty>,
    #[serde(default)]
    pub(crate) expires: Option<Duration>,
}

impl Message {
    pub(crate) const CERTIFICATE_PREFIX: &str = "$sparkplug/certificates/";

    pub(crate) fn sparkplug_certificate(&self, retain: bool) -> Arc<Self> {
        let mut topic = String::with_capacity(Self::CERTIFICATE_PREFIX.len() + self.topic.len());
        topic.push_str(Self::CERTIFICATE_PREFIX);
        topic.push_str(&self.topic);
        Arc::new(Self {
            source: Publisher {
                id: Arc::default(),
                username: None,
                security: 0,
                dynamic_security: None,
                external: None,
            },
            topic: topic.into_boxed_str(),
            payload: self.payload.clone(),
            qos: self.qos,
            retain,
            properties: self.properties.clone(),
            // property__process_publish removes expiry from callback properties.
            expires: None,
        })
    }

    // database.c: db__message_store reserves zero and UINT32_MAX for no expiry.
    pub(crate) fn expiry(now: Duration, interval: u32) -> Option<Duration> {
        (interval != 0 && interval != u32::MAX)
            .then(|| now.saturating_add(Duration::from_secs(u64::from(interval))))
    }

    pub(crate) fn expired(&self, now: Duration) -> bool {
        self.expires
            .is_some_and(|expiry| now.as_secs() > expiry.as_secs())
    }
}

// The subset of v5 properties persisted by property_broker.c:
// property__process_publish and property__process_will. Order is significant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PublishProperty {
    PayloadFormat(u8),
    ContentType(String),
    ResponseTopic(String),
    CorrelationData(Bytes),
    User(String, String),
}

impl PublishProperty {
    pub(crate) fn take(property: Property) -> Option<Self> {
        Some(match property {
            Property::PayloadFormatIndicator(value) => Self::PayloadFormat(value),
            Property::ContentType(value) => Self::ContentType(value),
            Property::ResponseTopic(value) => Self::ResponseTopic(value),
            Property::CorrelationData(value) => Self::CorrelationData(value),
            Property::UserProperty(name, value) => Self::User(name, value),
            _ => return None,
        })
    }

    pub(crate) fn wire(&self) -> Property {
        match self {
            Self::PayloadFormat(value) => Property::PayloadFormatIndicator(*value),
            Self::ContentType(value) => Property::ContentType(value.clone()),
            Self::ResponseTopic(value) => Property::ResponseTopic(value.clone()),
            Self::CorrelationData(value) => Property::CorrelationData(value.clone()),
            Self::User(name, value) => Property::UserProperty(name.clone(), value.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Delivery {
    pub(crate) message: Arc<Message>,
    pub(crate) qos: QoS,
    pub(crate) retain: bool,
    pub(crate) dedup_id: Option<DedupId>,
    #[serde(default)]
    pub(crate) subscription_identifier: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum DedupId {
    Log(u64),
    Peer([u64; 2]),
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
    Rejected,
    Dropped,
}

impl Ack {
    // database.c: db__message_delete_outgoing counts normal acknowledgements
    // and the negative PUBREC path, but not discards for an oversized packet.
    pub(crate) fn counts_for_persistence(self) -> bool {
        matches!(self, Self::Acknowledged | Self::Completed | Self::Rejected)
    }
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

// Match the legacy socket's write coalescing budget; the in-flight window
// itself can be larger or unlimited.
const REPLAY_BATCH_PACKETS: usize = 16;
const REPLAY_BATCH_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OutboundPrefix {
    next_unsent: usize,
    ids: Vec<PacketId>,
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
    last_delivered: Option<DedupId>,
    in_flight: VecDeque<Outgoing>,
    queued: VecDeque<Outgoing>,
    flight_stats: Counters,
    queue_stats: Counters,
    next_unsent: usize,
    dropped: bool,
    incoming: BTreeMap<PacketId, Incoming>,
    incoming_bytes: usize,
    incoming_slots: usize,
    #[serde(default)]
    pub(crate) receive_maximum: Option<u16>,
    #[serde(default)]
    send_used: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bridge_receive_maximum: Option<u16>,
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

pub(crate) enum Receive {
    Accepted,
    Quota,
    Duplicate,
}

impl Inbox {
    pub(crate) fn persist_into(
        &self,
        entry: &mut PersistentSession,
        mut intern: impl FnMut(&Arc<Message>) -> usize,
    ) {
        entry.last_mid = self.last_mid;
        entry.incoming.extend(
            self.incoming
                .iter()
                .map(|(&id, message)| (id, intern(&message.message))),
        );
        entry.outgoing.extend(
            self.in_flight
                .iter()
                .map(|entry| (entry, false))
                .chain(self.queued.iter().map(|entry| (entry, true)))
                .map(|(entry, queued)| PersistentOutgoing {
                    message: intern(&entry.delivery.message),
                    id: entry.id,
                    qos: entry.delivery.qos,
                    retain: entry.delivery.retain,
                    dup: entry.dup,
                    release: matches!(entry.phase, Phase::Release | Phase::AwaitComp),
                    queued,
                    identifier: entry.delivery.subscription_identifier,
                }),
        );
    }

    pub(crate) fn restore_persisted(
        entry: &mut PersistentSession,
        messages: &[Arc<Message>],
        config: &BrokerConfig,
        now: Duration,
    ) -> Self {
        let mut inbox = Self {
            last_mid: entry.last_mid,
            ..Self::default()
        };
        for (id, index) in std::mem::take(&mut entry.incoming) {
            let message = &messages[index];
            if !message.expired(now)
                && let std::collections::btree_map::Entry::Vacant(slot) = inbox.incoming.entry(id)
            {
                inbox.incoming_bytes += message.payload.len();
                slot.insert(Incoming {
                    message: message.clone(),
                    repeated: false,
                });
            }
        }
        inbox.incoming_slots = inbox.incoming.len().min(config.max_inflight_messages);
        for msg in std::mem::take(&mut entry.outgoing) {
            let message = &messages[msg.message];
            if message.expired(now) {
                continue;
            }
            let outgoing = Outgoing {
                delivery: Delivery {
                    message: message.clone(),
                    qos: msg.qos,
                    retain: msg.retain,
                    dedup_id: None,
                    subscription_identifier: msg.identifier,
                },
                id: msg.id,
                dup: msg.dup,
                phase: if msg.release {
                    Phase::Release
                } else {
                    Phase::Publish
                },
            };
            // persist_read.c: persist__client_msg_restore respects the new
            // server's flight quota even for records that were in flight.
            if msg.queued
                || (msg.qos != QoS::AtMostOnce
                    && !below(inbox.flight_stats.qos_count, config.max_inflight_messages))
            {
                inbox.queue_stats.change(&outgoing.delivery, true);
                inbox.queued.push_back(outgoing);
            } else {
                inbox.push_flight(outgoing);
            }
        }
        inbox
    }

    pub(crate) fn visit_messages(&self, mut visit: impl FnMut(&Arc<Message>)) {
        for entry in self.in_flight.iter().chain(&self.queued) {
            visit(&entry.delivery.message);
        }
        for entry in self.incoming.values() {
            visit(&entry.message);
        }
    }

    pub(crate) fn visit_acl_topics(&self, now: Duration, mut visit: impl FnMut(&str, bool)) {
        for entry in self.in_flight.iter().chain(&self.queued) {
            let message = &entry.delivery.message;
            if !message.expired(now) {
                visit(&message.topic, false);
            }
        }
        for entry in self.incoming.values() {
            if !entry.message.expired(now) {
                visit(&entry.message.topic, true);
            }
        }
    }

    // lib/util_mosq.c: mosquitto__mid_generate; subs.c: subs__send allocates
    // before duplicate suppression and queue admission, so even drops use IDs.
    pub(crate) fn offer(
        &mut self,
        delivery: Delivery,
        online: bool,
        max_qos: QoS,
        config: &BrokerConfig,
    ) -> Offer {
        self.offer_with_offline(delivery, online, max_qos, config, false, false)
    }

    pub(crate) fn allocate_mid(&mut self) -> PacketId {
        self.last_mid = self.last_mid.wrapping_add(1).max(1);
        PacketId::new(self.last_mid).unwrap()
    }

    pub(crate) fn outgoing_count(&self) -> usize {
        self.in_flight.len() + self.queued.len()
    }

    // A second window is already waiting behind the unacknowledged one.
    // Cap the watermark so a large receive maximum doesn't hide congestion.
    pub(crate) fn backlogged(&self) -> bool {
        self.queued.len() >= self.in_flight.len().clamp(1, 32)
    }

    pub(crate) fn offer_with_offline(
        &mut self,
        mut delivery: Delivery,
        online: bool,
        max_qos: QoS,
        config: &BrokerConfig,
        queue_qos0: bool,
        clean_offline: bool,
    ) -> Offer {
        let id = if delivery.qos == QoS::AtMostOnce {
            None
        } else {
            Some(self.allocate_mid())
        };
        if delivery.dedup_id.is_some() && delivery.dedup_id == self.last_delivered {
            return Offer::Suppressed;
        }
        // database.c: db__message_insert_outgoing checks QoS 0 admission per insertion.
        if !online
            && (clean_offline
                || delivery.qos == QoS::AtMostOnce && !(config.queue_qos0_messages || queue_qos0))
        {
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
            self.push_flight(entry);
            Offer::Ready
        } else {
            self.queue_stats.change(&entry.delivery, true);
            self.queued.push_back(entry);
            Offer::Queued
        }
    }

    fn send_maximum(&self, config: &BrokerConfig) -> usize {
        self.receive_maximum
            .map_or(config.max_inflight_messages, usize::from)
    }

    // database.c: db__ready_for_flight checks existing payload bytes, so the
    // last admitted packet can cross the configured byte limit.
    fn flight_available(&self, qos: QoS, config: &BrokerConfig) -> bool {
        if qos == QoS::AtMostOnce {
            if self.send_maximum(config) == 0 && config.max_inflight_bytes == 0 {
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
        let used = if self.receive_maximum.is_some() {
            self.send_used
        } else {
            self.flight_stats.qos_count
        };
        below(used, self.send_maximum(config))
            && below(self.flight_stats.qos_bytes, config.max_inflight_bytes)
    }

    fn push_flight(&mut self, entry: Outgoing) {
        if entry.delivery.qos != QoS::AtMostOnce
            && let Some(max) = self.receive_maximum
        {
            self.send_used = (self.send_used + 1).min(usize::from(max));
        }
        self.flight_stats.change(&entry.delivery, true);
        self.in_flight.push_back(entry);
    }

    // database.c: db__ready_for_queue adds one flight window while online.
    // Unlike Mosquitto, count all queued traffic, including offline QoS 0.
    // The existing total counters include QoS 0 in older snapshots too.
    fn queue_available(&self, online: bool, config: &BrokerConfig) -> bool {
        let extra_count = if online { self.send_maximum(config) } else { 0 };
        let extra_bytes = if online { config.max_inflight_bytes } else { 0 };
        below(
            self.queue_stats.count.saturating_sub(extra_count),
            config.max_queued_messages,
        ) && below(
            self.queue_stats.bytes.saturating_sub(extra_bytes),
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
            self.push_flight(entry);
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

    pub(crate) fn has_reserved(&self) -> bool {
        self.next_unsent != 0
    }

    pub(crate) fn reserve_ready_qos1(
        &mut self,
        fits: impl FnOnce(&Delivery) -> bool,
    ) -> Option<Outbound> {
        let entry = self.in_flight.get_mut(self.next_unsent)?;
        // An ACK has no timestamp. Expiring messages use the timed path.
        if entry.phase != Phase::Publish
            || entry.delivery.qos != QoS::AtLeastOnce
            || entry.delivery.message.expires.is_some()
            || !fits(&entry.delivery)
        {
            return None;
        }
        self.next_unsent += 1;
        Some(reserve_publish(entry))
    }

    fn replay_prefix_ids(&self) -> impl Iterator<Item = PacketId> + '_ {
        let mut room = REPLAY_BATCH_BYTES;
        self.in_flight
            .iter()
            .skip(self.next_unsent)
            .take(REPLAY_BATCH_PACKETS)
            .map_while(move |entry| {
                let message = &entry.delivery.message;
                if entry.phase != Phase::Publish
                    || entry.delivery.qos != QoS::AtLeastOnce
                    || message.expires.is_some()
                    || message.topic.starts_with(crate::control::PREFIX)
                {
                    return None;
                }
                let id = entry.id?;
                // At most five fixed header bytes, two topic-length bytes
                // and two MID bytes. A mount point can only shorten the topic.
                room = room.checked_sub(message.topic.len() + message.payload.len() + 9)?;
                Some(id)
            })
    }

    pub(crate) fn outbound_prefix(&self) -> Option<OutboundPrefix> {
        let mut ready = self.replay_prefix_ids();
        let first = ready.next()?;
        let second = ready.next()?;
        let mut ids = Vec::with_capacity(REPLAY_BATCH_PACKETS);
        ids.extend([first, second]);
        ids.extend(ready);
        Some(OutboundPrefix {
            next_unsent: self.next_unsent,
            ids,
        })
    }

    pub(crate) fn reserve_outbound_prefix(
        &mut self,
        prefix: OutboundPrefix,
        mut emit: impl FnMut(Outbound),
    ) -> bool {
        let count = prefix.ids.len();
        // The owning socket serializes its ACKs, drops and timed reservations
        // with this request. Other publications only append, or reserve a
        // ready packet in apply order, advancing the cursor. The lease fences
        // off a reconnect (which resets the cursor). Check the whole observed
        // prefix before committing any attempt; never skip or promote here.
        if self.next_unsent != prefix.next_unsent
            || !(2..=REPLAY_BATCH_PACKETS).contains(&count)
            || !self.replay_prefix_ids().take(count).eq(prefix.ids)
        {
            return false;
        }
        for entry in self.in_flight.iter_mut().skip(self.next_unsent).take(count) {
            emit(reserve_publish(entry));
        }
        self.next_unsent += count;
        true
    }

    // database.c: db__message_write_inflight_out_latest starts at the head
    // when a new QoS 0 follows the only already-written in-flight message.
    // The write's expiry check can then free that message's send quota.
    pub(crate) fn expired_before_qos0(&self, now: Duration) -> bool {
        self.receive_maximum.is_some()
            && self.next_unsent == 1
            && self.in_flight.get(1).is_some_and(|entry| {
                entry.phase == Phase::Publish && entry.delivery.qos == QoS::AtMostOnce
            })
            && self.in_flight[0].delivery.message.expired(now)
    }

    pub(crate) fn expire_before_qos0(&mut self, now: Duration) {
        if self.expired_before_qos0(now) {
            self.send_used = self.send_used.saturating_sub(1);
            self.remove_flight(0);
        }
    }

    pub(crate) fn next_outbound(
        &mut self,
        config: &BrokerConfig,
        now: Duration,
    ) -> Option<Outbound> {
        self.promote(config);
        loop {
            // database.c: db__message_write_inflight_out uses a strict comparison.
            // Equality still permits delivery without a Message Expiry property.
            let entry = self.in_flight.get_mut(self.next_unsent)?;
            if entry.delivery.message.expired(now) {
                if entry.delivery.qos != QoS::AtMostOnce {
                    self.send_used = self.send_used.saturating_sub(1);
                }
                self.remove_flight(self.next_unsent);
                self.promote(config);
                continue;
            }
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
                    let packet = reserve_publish(entry);
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
        self.acknowledge(id, kind, config, false)
    }

    // The apply meaning of a replicated `Operation::Ack`, kept for WAL and
    // snapshot replay: a PUBREC naming a queued QoS 2 id marks it received.
    pub(crate) fn replay_ack(&mut self, id: PacketId, kind: Ack, config: &BrokerConfig) -> bool {
        self.acknowledge(id, kind, config, true)
    }

    pub(crate) fn in_flight(&self, id: PacketId) -> bool {
        self.in_flight.iter().any(|entry| entry.id == Some(id))
    }

    // Promotions during this batch must not make an input ID eligible for
    // the same batch. Check only the already-written in-flight prefix.
    pub(crate) fn emitted_ack_prefix(
        &self,
        ids: &[PacketId],
        pending_writes: usize,
        mount_len: usize,
    ) -> usize {
        self.in_flight
            .iter()
            .take(self.next_unsent.saturating_sub(pending_writes))
            .zip(ids)
            .take_while(|(entry, id)| {
                let topic = &entry.delivery.message.topic;
                entry.phase == Phase::AwaitAck
                    && entry.id == Some(**id)
                    && mount_len < topic.len()
                    && topic.is_char_boundary(mount_len)
            })
            .count()
    }

    fn acknowledge(
        &mut self,
        id: PacketId,
        kind: Ack,
        config: &BrokerConfig,
        queued_pubrec: bool,
    ) -> bool {
        // lib/handle_pubackcomp.c: even unknown ACK/COMP returns send quota.
        // database.c: oversize drops and negative PUBREC remove the message
        // without returning this quota for the current connection.
        if matches!(kind, Ack::Acknowledged | Ack::Completed) {
            self.send_used = self.send_used.saturating_sub(1);
        }
        if let Some(index) = self.in_flight.iter().position(|entry| entry.id == Some(id)) {
            if !ack_entry(&mut self.in_flight[index], kind) {
                return false;
            }
            if kind != Ack::Received {
                self.remove_flight(index);
            }
        } else if (queued_pubrec || kind != Ack::Received)
            && let Some(index) = self.queued.iter().position(|entry| entry.id == Some(id))
        {
            // handle_pubrec.c: handle__pubrec calls db__message_update_outgoing
            // with persist = true, which never looks at queued messages, so a
            // PUBREC naming a queued id only gets its PUBREL.
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

    // database.c: db__messages_delete uses separate clean flags for the two directions.
    pub(crate) fn bridge_reset(&mut self, clean_outgoing: bool, clean_incoming: bool) {
        self.reset_outbound();
        if clean_outgoing {
            self.in_flight.clear();
            self.queued.clear();
            self.flight_stats = Counters::default();
            self.queue_stats = Counters::default();
            self.last_delivered = None;
            self.send_used = 0;
        }
        if clean_incoming {
            self.incoming.clear();
            self.incoming_bytes = 0;
            self.incoming_slots = 0;
        }
    }

    // database.c: db__message_reconnect_reset and db__check_acl_of_all_messages.
    // db__expire_all_messages prunes both directions on reconnection.
    pub(crate) fn resume(
        &mut self,
        mut allowed: impl FnMut(&str, bool) -> bool,
        config: &BrokerConfig,
        now: Duration,
    ) {
        self.reset_outbound();
        if self.receive_maximum.is_none() {
            self.promote(config);
        }
        self.in_flight.retain(|entry| {
            let allowed = !entry.delivery.message.expired(now)
                && allowed(&entry.delivery.message.topic, false);
            if !allowed {
                self.flight_stats.change(&entry.delivery, false);
            }
            allowed
        });
        self.queued.retain(|entry| {
            let allowed = !entry.delivery.message.expired(now)
                && allowed(&entry.delivery.message.topic, false);
            if !allowed {
                self.queue_stats.change(&entry.delivery, false);
            }
            allowed
        });
        self.incoming_slots = self.incoming.len().min(self.incoming_maximum(config));
        self.incoming.retain(|_, entry| {
            let allowed = !entry.message.expired(now) && allowed(&entry.message.topic, true);
            if !allowed {
                self.incoming_bytes -= entry.message.payload.len();
            }
            allowed
        });
        for entry in self.incoming.values_mut() {
            entry.repeated = false;
        }
        if let Some(maximum) = self.receive_maximum {
            self.send_used = self.flight_stats.qos_count.min(usize::from(maximum));
            self.incoming_slots = self.incoming.len().min(self.incoming_maximum(config));
            self.promote(config);
        }
    }

    // src/handle_connack.c: handle__connack_properties recomputes the send
    // quota from the messages already in flight when a bridge CONNACK changes
    // Receive Maximum. Nothing was written before CONNACK except packets a
    // cluster reserved, so keep the cursor, phases and DUP flags.
    pub(crate) fn bridge_connack(&mut self, config: &BrokerConfig) {
        if let Some(maximum) = self.receive_maximum {
            self.send_used = self.flight_stats.qos_count.min(usize::from(maximum));
        }
        self.promote(config);
    }

    // handle_publish.c: handle__accepted_publish replaces a pending QoS 2 on
    // mismatched content, even if DUP is set, and rejects the second retry.
    // Quota-rejected publishes are acknowledged but not stored.
    pub(crate) fn receive(
        &mut self,
        id: PacketId,
        message: Arc<Message>,
        config: &BrokerConfig,
    ) -> Receive {
        if let Some(previous) = self.incoming.get_mut(&id) {
            if previous.message.qos == message.qos
                && previous.message.topic == message.topic
                && previous.message.payload == message.payload
            {
                return if std::mem::replace(&mut previous.repeated, true) {
                    Receive::Duplicate
                } else {
                    Receive::Accepted
                };
            }
            self.remove_incoming(id);
        }
        if self.incoming_available(config) {
            if self.incoming_maximum(config) != 0 {
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
            Receive::Accepted
        } else {
            Receive::Quota
        }
    }

    // A QoS 1 PUBLISH is immediately acknowledged and has no incoming
    // state of its own. Only pending QoS 2 handshakes can make it change
    // the inbox or its receive quota (handle_publish.c: handle__accepted_publish).
    pub(crate) fn simple_qos1(&self) -> bool {
        self.incoming.is_empty() && self.incoming_slots == 0
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
        below(self.incoming_slots, self.incoming_maximum(config))
            && below(self.incoming_bytes, config.max_inflight_bytes)
    }

    fn incoming_maximum(&self, config: &BrokerConfig) -> usize {
        self.bridge_receive_maximum
            .map_or(config.max_inflight_messages, usize::from)
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

fn reserve_publish(entry: &mut Outgoing) -> Outbound {
    let packet = Outbound::Publish {
        delivery: entry.delivery.clone(),
        id: entry.id,
        dup: entry.dup,
    };
    // database.c: db__message_write_inflight_out_single marks the attempt
    // before any retry; reconnect preserves DUP.
    entry.dup = true;
    entry.phase = if entry.delivery.qos == QoS::AtLeastOnce {
        Phase::AwaitAck
    } else {
        Phase::AwaitRec
    };
    packet
}

fn ack_entry(entry: &mut Outgoing, kind: Ack) -> bool {
    match kind {
        Ack::Received if entry.delivery.qos == QoS::ExactlyOnce => {
            entry.phase = Phase::AwaitComp;
            true
        }
        Ack::Acknowledged => entry.delivery.qos == QoS::AtLeastOnce,
        Ack::Completed => entry.delivery.qos == QoS::ExactlyOnce && entry.phase == Phase::AwaitComp,
        Ack::Rejected => entry.delivery.qos == QoS::ExactlyOnce && entry.phase == Phase::AwaitRec,
        Ack::Dropped => true,
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
                    dynamic_security: None,
                    external: None,
                },
                topic: "topic".into(),
                payload: Bytes::from_static(bytes),
                qos,
                retain: false,
                properties: Vec::new(),
                expires: None,
            }),
            qos,
            retain: false,
            dedup_id: None,
            subscription_identifier: 0,
        }
    }

    fn assert_publish_id(inbox: &mut Inbox, config: &BrokerConfig, expected: u16) {
        assert!(
            matches!(inbox.next_outbound(config, Duration::ZERO), Some(Outbound::Publish { id: Some(id), dup: false, .. }) if id.get() == expected)
        );
    }

    #[test]
    fn replay_prefix_stops_at_each_noneligible_entry_and_ignores_a_concurrent_append() {
        let config = BrokerConfig::default();
        for kind in 0..5 {
            let mut inbox = Inbox::default();
            let lead = delivery(b"lead", QoS::AtLeastOnce);
            for packet in [lead.clone(), lead] {
                assert_eq!(
                    inbox.offer(packet, true, QoS::ExactlyOnce, &config),
                    Offer::Ready
                );
            }
            let qos = match kind {
                0 => QoS::AtMostOnce,
                1 => QoS::ExactlyOnce,
                _ => QoS::AtLeastOnce,
            };
            assert_eq!(
                inbox.offer(delivery(b"barrier", qos), true, QoS::ExactlyOnce, &config),
                Offer::Ready
            );
            let barrier = &mut inbox.in_flight[2];
            match kind {
                0 => {}
                1 => barrier.phase = Phase::Release,
                2 => {
                    Arc::get_mut(&mut barrier.delivery.message).unwrap().expires =
                        Some(Duration::from_secs(1));
                }
                3 => barrier.id = None,
                _ => {
                    Arc::get_mut(&mut barrier.delivery.message).unwrap().topic =
                        "$CONTROL/test".into();
                }
            }

            let prefix = inbox.outbound_prefix().unwrap();
            assert_eq!(prefix.ids.len(), 2);
            assert_eq!(
                inbox.offer(
                    delivery(b"append", QoS::AtLeastOnce),
                    true,
                    QoS::ExactlyOnce,
                    &config
                ),
                Offer::Ready
            );
            let mut packets = Vec::new();
            assert!(inbox.reserve_outbound_prefix(prefix, |packet| packets.push(packet)));
            assert_eq!(packets.len(), 2);
            for (index, packet) in packets.into_iter().enumerate() {
                assert!(matches!(
                    packet,
                    Outbound::Publish { id: Some(id), dup: false, .. }
                        if usize::from(id.get()) == index + 1
                ));
            }
            assert_eq!(inbox.next_unsent, 2);
            assert!(inbox.outbound_prefix().is_none());
            assert!(!inbox.in_flight[3].dup);
        }
    }

    #[test]
    fn replay_prefix_rejects_ack_or_reservation_races_without_partial_effects() {
        let config = BrokerConfig::default();
        for acknowledged in [false, true] {
            let mut inbox = Inbox::default();
            for _ in 0..4 {
                assert_eq!(
                    inbox.offer(
                        delivery(b"", QoS::AtLeastOnce),
                        true,
                        QoS::ExactlyOnce,
                        &config
                    ),
                    Offer::Ready
                );
            }
            let planned = inbox.outbound_prefix().unwrap();
            if acknowledged {
                assert!(inbox.ack(PacketId::new(2).unwrap(), Ack::Acknowledged, &config));
            } else {
                assert!(inbox.reserve_ready_qos1(|_| true).is_some());
            }
            assert!(!inbox.reserve_outbound_prefix(planned, |_| panic!("stale reservation")));
            assert_publish_id(&mut inbox, &config, if acknowledged { 1 } else { 2 });
        }
    }

    #[test]
    fn replay_prefix_bounds_count_and_bytes() {
        let config = BrokerConfig::default();
        let mut inbox = Inbox::default();
        for _ in 0..=REPLAY_BATCH_PACKETS {
            assert_eq!(
                inbox.offer(
                    delivery(b"", QoS::AtLeastOnce),
                    true,
                    QoS::ExactlyOnce,
                    &config
                ),
                Offer::Ready
            );
        }
        assert_eq!(
            inbox.outbound_prefix().unwrap().ids.len(),
            REPLAY_BATCH_PACKETS
        );

        let mut inbox = Inbox::default();
        for _ in 0..2 {
            assert_eq!(
                inbox.offer(
                    delivery(&[0; REPLAY_BATCH_BYTES / 2], QoS::AtLeastOnce),
                    true,
                    QoS::ExactlyOnce,
                    &config
                ),
                Offer::Ready
            );
        }
        assert!(inbox.outbound_prefix().is_none());
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
            inbox.next_outbound(&config, Duration::ZERO),
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

    // lib/handle_pubrec.c: a PUBREC for a queued id must not mark that
    // message as received; otherwise it is never sent once promoted.
    #[test]
    fn pubrec_for_a_queued_id_leaves_the_message_unsent() {
        let config = BrokerConfig {
            max_inflight_messages: 1,
            ..BrokerConfig::default()
        };
        let mut inbox = Inbox::default();
        for expected in [Offer::Ready, Offer::Queued] {
            let offer = inbox.offer(
                delivery(b"", QoS::ExactlyOnce),
                true,
                QoS::ExactlyOnce,
                &config,
            );
            assert_eq!(offer, expected);
        }
        assert_publish_id(&mut inbox, &config, 1);
        let queued = PacketId::new(2).unwrap();
        assert!(inbox.ack(queued, Ack::Received, &config));
        let first = PacketId::new(1).unwrap();
        assert!(inbox.ack(first, Ack::Received, &config));
        assert!(inbox.ack(first, Ack::Completed, &config));
        assert_publish_id(&mut inbox, &config, 2);
    }

    // A replicated `Operation::Ack` written by an older binary must replay
    // as it applied then: the queued message is marked received and is not
    // sent after promotion.
    #[test]
    fn replayed_pubrec_for_a_queued_id_keeps_its_original_meaning() {
        let config = BrokerConfig {
            max_inflight_messages: 1,
            ..BrokerConfig::default()
        };
        let mut inbox = Inbox::default();
        for _ in 0..2 {
            inbox.offer(
                delivery(b"", QoS::ExactlyOnce),
                true,
                QoS::ExactlyOnce,
                &config,
            );
        }
        assert_publish_id(&mut inbox, &config, 1);
        assert!(inbox.replay_ack(PacketId::new(2).unwrap(), Ack::Received, &config));
        let first = PacketId::new(1).unwrap();
        assert!(inbox.replay_ack(first, Ack::Received, &config));
        assert!(inbox.replay_ack(first, Ack::Completed, &config));
        assert!(inbox.next_outbound(&config, Duration::ZERO).is_none());
        assert!(inbox.replay_ack(PacketId::new(2).unwrap(), Ack::Completed, &config));
        assert!(inbox.outgoing_count() == 0);
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
            assert!(inbox.next_outbound(&config, Duration::ZERO).is_none());
            assert!(inbox.ack(PacketId::new(id).unwrap(), Ack::Acknowledged, &config));
        }
        assert!(inbox.next_outbound(&config, Duration::ZERO).is_none());
    }

    #[test]
    fn offline_qos0_only_queue_stops_at_the_message_limit_and_drains() {
        let config = BrokerConfig {
            max_queued_messages: 2,
            queue_qos0_messages: true,
            ..BrokerConfig::default()
        };
        let mut inbox = Inbox::default();
        let message = delivery(b"qos0", QoS::AtMostOnce);
        for expected in [
            Offer::Queued,
            Offer::Queued,
            Offer::FirstDrop,
            Offer::Dropped,
        ] {
            assert_eq!(
                inbox.offer(message.clone(), false, QoS::ExactlyOnce, &config),
                expected
            );
        }
        assert_eq!(inbox.outgoing_count(), 2);
        for _ in 0..2 {
            assert!(matches!(
                inbox.next_outbound(&config, Duration::ZERO),
                Some(Outbound::Publish { id: None, .. })
            ));
        }
        assert!(inbox.next_outbound(&config, Duration::ZERO).is_none());
        assert_eq!(inbox.queue_stats, Counters::default());
        assert_eq!(inbox.flight_stats, Counters::default());
        assert_eq!(
            inbox.offer(message, false, QoS::ExactlyOnce, &config),
            Offer::Queued
        );
    }

    #[test]
    fn queued_qos0_bytes_still_count_after_raft_and_standalone_restore() {
        let config = BrokerConfig {
            max_queued_bytes: 6,
            queue_qos0_messages: true,
            ..BrokerConfig::default()
        };
        let message = delivery(b"four", QoS::AtMostOnce);
        let mut inbox = Inbox::default();
        // Admit based on the existing payload bytes, so the second message
        // can cross the threshold, just as with QoS 1/2.
        for _ in 0..2 {
            assert_eq!(
                inbox.offer(message.clone(), false, QoS::ExactlyOnce, &config),
                Offer::Queued
            );
        }
        let mut persisted = PersistentSession {
            publisher: message.message.source.clone(),
            last_mid: 0,
            expiry_interval: None,
            expires: None,
            bridge: None,
            subscriptions: Vec::new(),
            outgoing: Vec::new(),
            incoming: Vec::new(),
        };
        inbox.persist_into(&mut persisted, |_| 0);
        let restored = Inbox::restore_persisted(
            &mut persisted,
            std::slice::from_ref(&message.message),
            &config,
            Duration::ZERO,
        );
        let snapshot = rmp_serde::to_vec(&inbox).unwrap();
        let decoded: Inbox = rmp_serde::from_slice(&snapshot).unwrap();
        let qos1 = delivery(b"next", QoS::AtLeastOnce);
        for mut inbox in [restored, decoded] {
            assert_eq!(
                inbox.offer(qos1.clone(), false, QoS::ExactlyOnce, &config),
                Offer::FirstDrop
            );
            inbox.resume(|_, _| false, &config, Duration::ZERO);
            assert_eq!(inbox.outgoing_count(), 0);
            assert_eq!(
                inbox.offer(qos1.clone(), false, QoS::ExactlyOnce, &config),
                Offer::Queued
            );
        }
    }
}
