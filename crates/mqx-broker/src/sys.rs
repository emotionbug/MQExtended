use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed},
};

use serde::{Deserialize, Serialize};

// Advertise the protocol reference version, not the MQExtended package version.
// The latter is available separately on MQExtended's HTTP extension.
pub const MOSQUITTO_VERSION: &str = "2.1.4";
pub(crate) const VERSION_TOPIC: &str = "$SYS/broker/version";
pub(crate) const UPTIME_TOPIC: &str = "$SYS/broker/uptime";
pub(crate) const VERSION_PAYLOAD: &str = "mosquitto version 2.1.4";

macro_rules! metrics {
    ($($id:ident => ($topic:expr, $alias:expr)),+ $(,)?) => {
        #[derive(Clone, Copy)]
        #[repr(usize)]
        pub(crate) enum Metric { $($id),+ }
        const TOPICS: &[(Option<&str>, Option<&str>)] = &[$(($topic, $alias)),+];
        const METRICS: usize = TOPICS.len();
    };
}

macro_rules! topic {
    ($suffix:literal) => {
        Some(concat!("$SYS/broker/", $suffix))
    };
}

// sys_tree.c: metrics[], in publication order. Heap statistics are not
// included: there is no Mosquitto allocator or WITH_MEMORY_TRACKING build here.
metrics! {
    Sessions => (topic!("clients/total"), None),
    MaxSessions => (topic!("clients/maximum"), None),
    Disconnected => (topic!("clients/disconnected"), topic!("clients/inactive")),
    Connected => (topic!("clients/connected"), topic!("clients/active")),
    Expired => (topic!("clients/expired"), None),
    Stored => (topic!("messages/stored"), topic!("store/messages/count")),
    StoredBytes => (topic!("store/messages/bytes"), None),
    Subscriptions => (topic!("subscriptions/count"), None),
    SharedSubscriptions => (topic!("shared_subscriptions/count"), None),
    Retained => (topic!("retained messages/count"), None),
    Received => (topic!("messages/received"), None),
    Sent => (topic!("messages/sent"), None),
    BytesReceived => (topic!("bytes/received"), None),
    BytesSent => (topic!("bytes/sent"), None),
    PayloadReceived => (topic!("publish/bytes/received"), None),
    PayloadSent => (topic!("publish/bytes/sent"), None),
    Queued => (topic!("packet/out/count"), None),
    QueuedBytes => (topic!("packet/out/bytes"), None),
    Sockets => (topic!("connections/socket/count"), None),
    Connect => (None, None),
    Dropped => (topic!("publish/messages/dropped"), None),
    PublishReceived => (topic!("publish/messages/received"), None),
    PublishSent => (topic!("publish/messages/sent"), None),
}

const LOADS: &[(&str, Metric)] = &[
    ("messages/received", Metric::Received),
    ("messages/sent", Metric::Sent),
    ("publish/dropped", Metric::Dropped),
    ("publish/received", Metric::PublishReceived),
    ("publish/sent", Metric::PublishSent),
    ("bytes/received", Metric::BytesReceived),
    ("bytes/sent", Metric::BytesSent),
    ("sockets", Metric::Sockets),
    ("connections", Metric::Connect),
];
const WINDOWS: [(&str, f64); 3] = [("1min", 60.0), ("5min", 300.0), ("15min", 900.0)];

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Values([i64; METRICS]);

impl Values {
    pub(crate) fn get(self, metric: Metric) -> i64 {
        self.0[metric as usize]
    }

    pub(crate) fn set(&mut self, metric: Metric, value: i64) {
        self.0[metric as usize] = value;
    }

    pub(crate) fn add(&mut self, metric: Metric, value: i64) {
        self.0[metric as usize] = self.get(metric).wrapping_add(value);
    }

    fn merge(&mut self, other: Self) {
        for (value, other) in self.0.iter_mut().zip(other.0) {
            *value = value.wrapping_add(other);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Traffic([AtomicI64; METRICS]);

impl Traffic {
    pub(crate) fn add(&self, metric: Metric, delta: i64) {
        self.0[metric as usize].fetch_add(delta, Relaxed);
    }

    pub(crate) fn snapshot(&self) -> Values {
        Values(std::array::from_fn(|index| self.0[index].load(Relaxed)))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct NodeSample {
    pub(crate) incarnation: [u8; 16],
    pub(crate) traffic: Values,
}

// Transport counters are process-local; fold the last known counters of dead
// processes into the running totals, but never keep their last socket gauges.
fn counter_part(mut values: Values) -> Values {
    for gauge in [
        Metric::Connected,
        Metric::Queued,
        Metric::QueuedBytes,
        Metric::Stored,
        Metric::StoredBytes,
    ] {
        values.set(gauge, 0);
    }
    values
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Sampler {
    pub(crate) started: Option<u64>,
    pub(crate) wall: Option<u64>,
    last: u64,
    values: Values,
    loads: [[f64; 3]; 9],
    nodes: BTreeMap<u64, NodeSample>,
    previous_incarnations: Values,
}

impl Default for Sampler {
    fn default() -> Self {
        Self {
            started: None,
            wall: None,
            last: 0,
            values: Values([1; METRICS]),
            loads: [[0.0; 3]; 9],
            nodes: BTreeMap::new(),
            previous_incarnations: Values::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Tick {
    pub(crate) wall: u64,
    pub(crate) now: u64,
    pub(crate) startup: bool,
    pub(crate) nodes: BTreeMap<u64, NodeSample>,
    pub(crate) cluster_store: Option<(i64, i64)>,
}

impl Sampler {
    pub(crate) fn uptime(&self, now: u64) -> u64 {
        now.saturating_sub(self.started.unwrap_or_default())
    }

    pub(crate) fn snapshot(&self, now: u64) -> SysTree {
        SysTree {
            values: self.values,
            uptime: self.uptime(now),
        }
    }

    pub(crate) fn combine(
        &mut self,
        mut values: Values,
        nodes: BTreeMap<u64, NodeSample>,
    ) -> Values {
        for (&id, &sample) in &nodes {
            if let Some(previous) = self.nodes.insert(id, sample)
                && previous.incarnation != sample.incarnation
            {
                self.previous_incarnations
                    .merge(counter_part(previous.traffic));
            }
        }
        values.merge(self.previous_incarnations);
        for (&id, sample) in &self.nodes {
            values.merge(if nodes.contains_key(&id) {
                sample.traffic
            } else {
                counter_part(sample.traffic)
            });
        }
        values.set(Metric::MaxSessions, values.get(Metric::Sessions));
        // sys_tree.c subtracts unsigned HASH_CNT values before assigning to int64_t.
        values.set(
            Metric::Disconnected,
            i64::from(
                (values.get(Metric::Sessions) as u32)
                    .wrapping_sub(values.get(Metric::Connected) as u32),
            ),
        );
        values
    }

    // sys_tree.c: sys_tree__update computes loads before advancing integers.
    pub(crate) fn sample(
        &mut self,
        wall: u64,
        now: u64,
        next: Values,
        startup: bool,
        mut append: impl FnMut(&str, String),
    ) {
        if startup {
            self.started = Some(now);
            self.last = now;
        }
        if let Some(dt) = now.checked_sub(self.last).filter(|&dt| dt != 0) {
            let mult = 60.0 / dt as f64;
            let exponents = WINDOWS.map(|(_, seconds)| (-(dt as f64) / seconds).exp());
            for (load, &(name, counter)) in self.loads.iter_mut().zip(LOADS) {
                let rate = next.get(counter).wrapping_sub(self.values.get(counter)) as f64 * mult;
                for (index, old) in load.iter_mut().enumerate() {
                    if update_load(old, rate, exponents[index]) {
                        append(
                            &format!("$SYS/broker/load/{name}/{}", WINDOWS[index].0),
                            format!("{old:.2}"),
                        );
                    }
                }
            }
        }
        for (index, &(topic, alias)) in TOPICS.iter().enumerate() {
            let old = &mut self.values.0[index];
            let new = next.0[index];
            if if index == Metric::MaxSessions as usize {
                new > *old
            } else {
                new != *old
            } {
                *old = new;
                for topic in [topic, alias].into_iter().flatten() {
                    // snprintf("%lu") on the reference LP64 build.
                    append(topic, (new as u64).to_string());
                }
            }
        }
        if startup {
            for &(name, _) in LOADS {
                for (window, _) in WINDOWS {
                    append(&format!("$SYS/broker/load/{name}/{window}"), "0.00".into());
                }
            }
        }
        self.last = now;
        self.wall = Some(wall);
    }
}

fn update_load(old: &mut f64, rate: f64, exponent: f64) -> bool {
    let new = rate + exponent * (*old - rate);
    let publish = (new - *old).abs() >= 0.01;
    *old = new;
    publish
}

/// Sampled primary Mosquitto systree topics; uptime is read at request time.
#[derive(Clone, Copy, Debug)]
pub struct SysTree {
    values: Values,
    uptime: u64,
}

impl SysTree {
    pub fn entries(&self) -> impl Iterator<Item = (&'static str, i64)> + '_ {
        TOPICS
            .iter()
            .zip(self.values.0)
            .filter_map(|(&(topic, _), value)| topic.map(|topic| (topic, value)))
            .chain([(UPTIME_TOPIC, self.uptime as i64)])
    }
}

pub(crate) const BUCKETS: [f64; 10] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0,
];

#[derive(Default)]
pub(crate) struct ProposalLatency {
    buckets: [AtomicU64; BUCKETS.len() + 1],
    nanos: AtomicU64,
}

impl ProposalLatency {
    pub(crate) fn record(&self, elapsed: std::time::Duration) {
        let index = BUCKETS.partition_point(|&seconds| seconds < elapsed.as_secs_f64());
        self.nanos.fetch_add(elapsed.as_nanos() as u64, Relaxed);
        self.buckets[index].fetch_add(1, Relaxed);
    }

    pub(crate) fn snapshot(&self) -> ProposalHistogram {
        let mut count = 0;
        let buckets = BUCKETS
            .into_iter()
            .zip(&self.buckets)
            .map(|(bound, bucket)| {
                count += bucket.load(Relaxed);
                (bound, count)
            })
            .collect();
        count += self.buckets[BUCKETS.len()].load(Relaxed);
        ProposalHistogram {
            buckets,
            count,
            sum_seconds: self.nanos.load(Relaxed) as f64 / 1e9,
        }
    }
}

#[derive(Debug)]
pub struct ProposalHistogram {
    pub buckets: Vec<(f64, u64)>,
    pub count: u64,
    pub sum_seconds: f64,
}

/// Current per-process transport statistics and locally applied broker gauges.
#[derive(Debug)]
pub struct BrokerMetrics {
    pub connections: i64,
    pub sessions: i64,
    pub messages_received: i64,
    pub messages_sent: i64,
    pub bytes_received: i64,
    pub bytes_sent: i64,
    pub retained: i64,
    pub subscriptions: i64,
    pub shared_subscriptions: i64,
    pub proposal_latency: ProposalHistogram,
}

impl BrokerMetrics {
    pub(crate) fn new(values: Values, proposal_latency: ProposalHistogram) -> Self {
        Self {
            connections: values.get(Metric::Connected),
            sessions: values.get(Metric::Sessions),
            messages_received: values.get(Metric::Received),
            messages_sent: values.get(Metric::Sent),
            bytes_received: values.get(Metric::BytesReceived),
            bytes_sent: values.get(Metric::BytesSent),
            retained: values.get(Metric::Retained),
            subscriptions: values.get(Metric::Subscriptions),
            shared_subscriptions: values.get(Metric::SharedSubscriptions),
            proposal_latency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_periodic_updates_format_only_changed_metrics() {
        let mut sampler = Sampler::default();
        let mut publications = BTreeMap::new();
        let mut next = Values::default();
        next.set(Metric::Connected, -1);
        sampler.sample(31, 1, next, true, |topic, payload| {
            publications.insert(topic.to_owned(), payload);
        });
        assert_eq!(
            publications["$SYS/broker/clients/connected"],
            "18446744073709551615"
        );
        assert_eq!(
            publications["$SYS/broker/clients/active"],
            publications["$SYS/broker/clients/connected"]
        );
        assert!(!publications.contains_key("$SYS/broker/clients/maximum"));
        assert_eq!(
            publications
                .iter()
                .filter(|(topic, _)| topic.contains("/load/"))
                .count(),
            27
        );
        assert!(
            publications
                .iter()
                .filter(|(topic, _)| topic.contains("/load/"))
                .all(|(_, payload)| payload == "0.00")
        );
        sampler.sample(40, 10, next, false, |topic, _| {
            panic!("unexpected update to {topic}")
        });
    }

    #[test]
    fn load_threshold_compares_against_previous_calculation_not_last_publication() {
        let mut old = 0.0;
        assert!(update_load(&mut old, 60.0, (-1.0_f64).exp()));
        assert_eq!(format!("{old:.2}"), "37.93");
        let mut old = 0.0;
        for _ in 0..100 {
            assert!(!update_load(&mut old, 0.1, 0.95));
        }
        assert_eq!(format!("{old:.2}"), "0.10");
    }
}
