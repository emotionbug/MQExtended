use std::collections::HashSet;

use super::*;
use crate::sys::{UPTIME_TOPIC, VERSION_PAYLOAD, VERSION_TOPIC};

// Mosquitto database.c counts each base message once, even when multiple
// subscriptions or a retained slot reference it. Do the scan only at a tick.
#[derive(Default)]
pub(crate) struct Store {
    seen: HashSet<*const Message>,
    bytes: i64,
}

impl Store {
    pub(crate) fn visit(&mut self, message: &Arc<Message>) {
        if self.seen.insert(Arc::as_ptr(message)) {
            self.bytes += message.payload.len() as i64;
        }
    }

    pub(crate) fn count(&self) -> i64 {
        self.seen.len() as i64
    }

    pub(crate) fn bytes(&self) -> i64 {
        self.bytes
    }
}

impl State {
    pub(crate) fn gauges(&self, values: &mut Values) {
        values.set(Metric::Sessions, self.sessions.len() as i64);
        let shared: usize = self.groups.values().map(|group| group.members.len()).sum();
        let subscriptions: usize = self
            .sessions
            .values()
            .map(|session| session.filters.len())
            .sum();
        values.set(Metric::SharedSubscriptions, shared as i64);
        values.set(Metric::Subscriptions, (subscriptions - shared) as i64);
        values.set(Metric::Retained, self.retained.count());
    }

    fn visit_store(&self, store: &mut Store) {
        self.retained.for_each(|message| store.visit(message));
        for inbox in self
            .sessions
            .values()
            .filter_map(|session| session.inbox.as_ref())
        {
            inbox.visit_messages(|message| store.visit(message));
        }
    }

    pub(crate) fn cluster_store(&self, now: u64, startup: bool) -> (i64, i64) {
        // Arc sharing is local to a process and can change on snapshot restore.
        // Only the leader counts base records; deterministic apply uses that
        // observation rather than independently relying on pointer identity.
        let mut store = Store::default();
        self.visit_store(&mut store);
        let (mut count, mut bytes) = (store.count(), store.bytes());
        if self.config.retain_available {
            let startup = startup && self.sys.wall.is_none();
            let uptime = if startup { 0 } else { self.sys.uptime(now) };
            if startup {
                count += 1;
                bytes += VERSION_PAYLOAD.len() as i64;
            }
            let mut previous = None;
            self.retained.for_each(|message| {
                if message.topic.as_ref() == UPTIME_TOPIC && Arc::strong_count(message) == 1 {
                    previous = Some(message.payload.len() as i64);
                }
            });
            count += i64::from(previous.is_none());
            bytes += format!("{uptime} seconds").len() as i64 - previous.unwrap_or(0);
        }
        (count, bytes)
    }

    pub(crate) fn sample_sys(
        &mut self,
        tick: Tick,
        effects: &mut Vec<Effect>,
        transient_store: impl FnOnce(&mut Store),
    ) {
        let Tick {
            wall,
            now,
            startup,
            nodes,
            cluster_store,
        } = tick;
        // A new Raft leader can race a committed tick from the previous
        // leader. No replica may publish a tick twice or roll it back.
        if self
            .sys
            .wall
            .is_some_and(|last| last == wall || cluster_store.is_some() && last > wall)
        {
            return;
        }
        let startup = startup && self.sys.wall.is_none();
        // Standalone `now` is boot time for uptime metrics, not a publication timestamp.
        let time = Duration::from_secs(wall);
        let mut sampler = std::mem::take(&mut self.sys);
        if startup {
            self.publish_system(
                VERSION_TOPIC,
                Bytes::from_static(VERSION_PAYLOAD.as_bytes()),
                time,
                None,
                effects,
            );
        }
        let uptime = if startup { 0 } else { sampler.uptime(now) };
        self.publish_system(
            UPTIME_TOPIC,
            Bytes::from(format!("{uptime} seconds")),
            time,
            None,
            effects,
        );
        // sys_tree.c: sys_tree__update samples after enqueuing uptime, and
        // before enqueuing loads and integer metrics.
        let mut values = self.sys_counters;
        self.gauges(&mut values);
        let (stored, bytes) = cluster_store.unwrap_or_else(|| {
            let mut store = Store::default();
            self.visit_store(&mut store);
            transient_store(&mut store);
            // With retain_available false, uptime may be queued only for
            // transient subscribers; its base record is live until dispatch.
            for effect in effects.iter() {
                if let Effect::Deliver { packet, .. } = effect {
                    store.visit(&packet.message);
                }
            }
            (store.count(), store.bytes())
        });
        values.set(Metric::Stored, stored);
        values.set(Metric::StoredBytes, bytes);
        let values = sampler.combine(values, nodes);
        sampler.sample(wall, now, values, startup, |topic, payload| {
            self.publish_system(topic, Bytes::from(payload), time, None, effects);
        });
        self.sys = sampler;
    }

    // database.c: db__messages_easy_queue with a NULL context is broker-origin.
    pub(super) fn publish_system(
        &mut self,
        topic: &str,
        payload: Bytes,
        now: Duration,
        expires: Option<Duration>,
        effects: &mut Vec<Effect>,
    ) {
        self.publish(
            Message {
                source: Publisher {
                    id: Arc::from(""),
                    username: None,
                    security: 0,
                    dynamic_security: None,
                    external: None,
                },
                topic: topic.into(),
                payload,
                qos: QoS::ExactlyOnce,
                retain: expires.is_none() && self.config.retain_available,
                properties: Vec::new(),
                expires,
                broker_expires: None,
            }
            .published(now),
            now,
            effects,
        );
    }
}
