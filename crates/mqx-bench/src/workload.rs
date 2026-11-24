use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Bytes, BytesMut};
use mqx_codec::{Packet, PacketId, Publish, QoS};
use tokio::{
    task::JoinSet,
    time::{Instant, sleep_until, timeout_at},
};

use crate::{
    Error, Load, LoadResult, Pattern, Storm, StormResult,
    accounting::{Deliveries, Histogram, SequenceSet, nanos},
    mqtt::{Client, HANDSHAKE_TIMEOUT},
};

const HEADER_BYTES: usize = 28;
const BATCH: usize = 32;

fn nonce() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    nanos(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes 1970"),
    )
    .wrapping_add(NEXT.fetch_add(1, Ordering::Relaxed))
}

#[derive(Clone, Copy)]
struct Window {
    start: Instant,
    end: Instant,
}

impl Window {
    fn new(duration: Duration) -> Result<Self, Error> {
        let start = Instant::now() + Duration::from_millis(10);
        let end = start
            .checked_add(duration)
            .ok_or(Error::Configuration("load duration overflows the clock"))?;
        Ok(Self { start, end })
    }
}

/// Each client owns every Nth global slot. Fractional per-client rates still
/// produce the requested aggregate schedule, without a contended rate limiter.
struct Pace {
    window: Window,
    slot: u128,
    stride: u128,
    rate: Option<u64>,
}

impl Pace {
    fn new(window: Window, index: usize, lanes: usize, rate: Option<u64>) -> Self {
        Self {
            window,
            slot: index as u128,
            stride: lanes as u128,
            rate,
        }
    }

    fn due(&self) -> Instant {
        self.rate.map_or(self.window.start, |rate| {
            let offset = self.slot * 1_000_000_000 / u128::from(rate);
            self.window.start
                + self
                    .window
                    .end
                    .duration_since(self.window.start)
                    .min(Duration::from_nanos(
                        u64::try_from(offset).unwrap_or(u64::MAX),
                    ))
        })
    }

    fn advance(&mut self) {
        self.slot += self.stride;
    }
}

fn validate_load(addresses: &[SocketAddr], config: &Load) -> Result<(), Error> {
    if addresses.is_empty()
        || config.publishers == 0
        || config.subscribers == 0
        || u32::try_from(config.publishers).is_err()
    {
        return Err(Error::Configuration(
            "need at least one endpoint, publisher and subscriber, and at most u32::MAX publishers",
        ));
    }
    let valid_pattern = match config.pattern {
        Pattern::FanIn => config.subscribers == 1,
        Pattern::FanOut => config.publishers == 1,
        Pattern::OneToOne => config.publishers == config.subscribers,
        Pattern::Shared => true,
    };
    if !valid_pattern {
        return Err(Error::Configuration(
            "fan-in needs one subscriber, fan-out one publisher, one-to-one equal counts",
        ));
    }
    if !(HEADER_BYTES..=mqx_codec::MAX_REMAINING_LENGTH - 128).contains(&config.payload_bytes) {
        return Err(Error::Configuration(
            "payload must fit MQTT's packet limit and include the 28-byte timestamp header",
        ));
    }
    if config.duration.is_zero()
        || config.drain.is_zero()
        || config.rate == Some(0)
        || config.inflight == 0
    {
        return Err(Error::Configuration(
            "duration, drain, rate and inflight window must be positive",
        ));
    }
    Ok(())
}

struct Connection {
    client: Client,
    latency: Duration,
    accepted: Instant,
}

async fn establish(
    addresses: &[SocketAddr],
    run: u64,
    config: &Load,
    subscribers: bool,
) -> Result<Vec<Connection>, Error> {
    let count = if subscribers {
        config.subscribers
    } else {
        config.publishers
    };
    let role = if subscribers { 's' } else { 'p' };
    let mut jobs = JoinSet::new();
    let clean = config.clean_session;
    for index in 0..count {
        // Even a one-to-one workload crosses cluster nodes.
        let address =
            addresses[(index % addresses.len() + usize::from(subscribers)) % addresses.len()];
        let topic = subscribers.then(|| match config.pattern {
            Pattern::OneToOne => format!("mqxbench/{run:x}/{index}"),
            // Mosquitto src/topic_tok.c: sub__topic_tokenise recognises the
            // shared filter prefix independently of the CONNECT version.
            Pattern::Shared => format!("$share/work/mqxbench/{run:x}/all"),
            Pattern::FanIn | Pattern::FanOut => format!("mqxbench/{run:x}/all"),
        });
        let qos = config.qos.into();
        jobs.spawn(async move {
            let (mut client, latency, _) =
                Client::connect(address, format!("mqxb-{run:x}-{role}{index}"), clean).await?;
            let accepted = Instant::now();
            if let Some(topic) = topic {
                client.subscribe(topic, qos).await?;
            }
            Ok::<_, Error>((
                index,
                Connection {
                    client,
                    latency,
                    accepted,
                },
            ))
        });
    }
    let mut ready = Vec::with_capacity(count);
    while let Some(job) = jobs.join_next().await {
        ready.push(job??);
    }
    ready.sort_unstable_by_key(|entry| entry.0);
    Ok(ready.into_iter().map(|entry| entry.1).collect())
}

/// Run one workload. Endpoints are assigned round-robin for each client role.
pub async fn load(addresses: &[SocketAddr], config: &Load) -> Result<LoadResult, Error> {
    validate_load(addresses, config)?;
    let run = nonce();
    let connecting = Instant::now();
    let subscribers = establish(addresses, run, config, true).await?;
    let publishers = establish(addresses, run, config, false).await?;
    let mut connect_latency = Histogram::default();
    let mut accepted = connecting;
    for connection in subscribers.iter().chain(&publishers) {
        accepted = accepted.max(connection.accepted);
        connect_latency.record(connection.latency);
    }
    let connections = (publishers.len() + subscribers.len()) as u64;
    let window = Window::new(config.duration)?;
    let drain_deadline = window
        .end
        .checked_add(config.drain)
        .ok_or(Error::Configuration("drain duration overflows the clock"))?;
    let mut receivers = JoinSet::new();
    let qos = config.qos.into();
    let shared = match config.pattern {
        Pattern::Shared => Some(Arc::<[_]>::from_iter(
            (0..publishers.len()).map(|_| Mutex::new(SequenceSet::default())),
        )),
        _ => None,
    };
    for (index, sub) in subscribers.into_iter().enumerate() {
        let coverage = match config.pattern {
            Pattern::OneToOne => Coverage::Local {
                first: index,
                streams: vec![SequenceSet::default()],
            },
            Pattern::Shared => Coverage::Shared(Arc::clone(shared.as_ref().unwrap())),
            Pattern::FanIn | Pattern::FanOut => Coverage::Local {
                first: 0,
                streams: (0..publishers.len())
                    .map(|_| SequenceSet::default())
                    .collect(),
            },
        };
        let sub = Receiver {
            client: sub.client,
            qos,
            run,
            window,
            coverage,
            stats: Deliveries::default(),
        };
        receivers.spawn(sub.receive(drain_deadline));
    }
    let mut senders = JoinSet::new();
    for (index, publisher) in publishers.into_iter().enumerate() {
        let topic = match config.pattern {
            Pattern::OneToOne => format!("mqxbench/{run:x}/{index}"),
            _ => format!("mqxbench/{run:x}/all"),
        };
        let sender = Sender {
            client: publisher.client,
            qos,
            topic,
            run,
            index,
            pace: Pace::new(window, index, config.publishers, config.rate),
            deadline: drain_deadline,
            payload_bytes: config.payload_bytes,
            inflight: usize::from(config.inflight),
        };
        senders.spawn(sender.publish());
    }

    let mut sent = vec![0; config.publishers];
    let mut acknowledged = 0;
    while let Some(job) = senders.join_next().await {
        let (index, published, acked) = job??;
        sent[index] = published;
        acknowledged += acked;
    }
    // Receivers listen until the requested drain deadline, even if the
    // publishers received all their ACKs early. Bound teardown after drain.
    let shutdown_deadline =
        drain_deadline
            .checked_add(HANDSHAKE_TIMEOUT)
            .ok_or(Error::Configuration(
                "subscriber shutdown deadline overflows the clock",
            ))?;
    let delivered = timeout_at(shutdown_deadline, async {
        let mut delivered = Deliveries::default();
        while let Some(job) = receivers.join_next().await {
            let (coverage, stats) = job??;
            if let Coverage::Local { first, streams } = coverage {
                for (stream, &count) in streams.iter().zip(&sent[first..]) {
                    stream.verify(count)?;
                }
            }
            delivered.merge(&stats);
        }
        Ok::<_, Error>(delivered)
    })
    .await
    .map_err(|_| Error::Timeout("shutting down subscribers"))??;
    if let Some(shared) = shared {
        for (stream, &count) in shared.iter().zip(&sent) {
            stream.lock().unwrap().verify(count)?;
        }
    }
    let published: u64 = sent.into_iter().sum();
    let copies = if matches!(config.pattern, Pattern::FanOut) {
        config.subscribers as u64
    } else {
        1
    };
    let expected = published
        .checked_mul(copies)
        .ok_or(Error::Configuration("delivery count exceeds u64"))?;
    let seconds = config.duration.as_secs_f64();
    Ok(LoadResult {
        published,
        acknowledged: (qos != QoS::AtMostOnce).then_some(acknowledged),
        expected_deliveries: expected,
        unique_deliveries: delivered.unique,
        duplicates: delivered.duplicates,
        lost: delivered.loss(expected)?,
        published_per_second: published as f64 / seconds,
        delivered_per_second: (delivered.unique - delivered.late) as f64 / seconds,
        late_deliveries: delivered.late,
        delivery_latency: delivered.latency.summary(),
        connections,
        connections_per_second: connections as f64
            / accepted.duration_since(connecting).as_secs_f64(),
        connect_latency: connect_latency.summary(),
    })
}

enum Coverage {
    Local {
        first: usize,
        streams: Vec<SequenceSet>,
    },
    Shared(Arc<[Mutex<SequenceSet>]>),
}

impl Coverage {
    fn insert(&mut self, publisher: usize, seq: u64) -> Result<bool, Error> {
        let invalid = Error::Protocol(
            "delivery reached an unexpected subscriber or identifies an unknown publisher",
        );
        match self {
            Self::Local { first, streams } => {
                let stream = publisher
                    .checked_sub(*first)
                    .and_then(|index| streams.get_mut(index))
                    .ok_or(invalid)?;
                Ok(stream.insert(seq))
            }
            Self::Shared(streams) => Ok(streams
                .get(publisher)
                .ok_or(invalid)?
                .lock()
                .unwrap()
                .insert(seq)),
        }
    }
}

struct Receiver {
    client: Client,
    qos: QoS,
    run: u64,
    window: Window,
    coverage: Coverage,
    stats: Deliveries,
}

impl Receiver {
    fn record(&mut self, payload: &[u8], arrival: Instant) -> Result<(), Error> {
        // Unrelated traffic is ignored; the same run's malformed data is an error.
        if !payload.starts_with(&self.run.to_be_bytes()) {
            return Ok(());
        }
        let Some(header) = payload.get(..HEADER_BYTES) else {
            return Err(Error::Protocol("truncated benchmark payload"));
        };
        let publisher = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        let sequence = u64::from_be_bytes(header[12..20].try_into().unwrap());
        let timestamp = u64::from_be_bytes(header[20..28].try_into().unwrap());
        let elapsed = nanos(arrival.saturating_duration_since(self.window.start))
            .checked_sub(timestamp)
            .ok_or(Error::Protocol("delivery timestamp lies in the future"))?;
        let new = self.coverage.insert(publisher, sequence)?;
        self.stats.record(
            new,
            arrival >= self.window.end,
            Duration::from_nanos(elapsed),
        );
        Ok(())
    }

    async fn receive(mut self, deadline: Instant) -> Result<(Coverage, Deliveries), Error> {
        let mut incoming = HashMap::<PacketId, Bytes>::new();
        let end = sleep_until(deadline);
        tokio::pin!(end);
        loop {
            let packet = tokio::select! {
                biased;
                () = &mut end => break,
                packet = self.client.recv() => packet?,
            };
            let arrival = Instant::now();
            match packet {
                Packet::Publish(message) if message.qos == self.qos => {
                    match (message.qos, message.packet_id) {
                        (QoS::AtMostOnce, None) => self.record(&message.payload, arrival)?,
                        (QoS::AtLeastOnce, Some(id)) => {
                            self.record(&message.payload, arrival)?;
                            self.client.send(&Packet::PubAck(id)).await?;
                        }
                        (QoS::ExactlyOnce, Some(id)) => {
                            incoming.entry(id).or_insert(message.payload);
                            self.client.send(&Packet::PubRec(id)).await?;
                        }
                        _ => return Err(Error::Protocol("invalid incoming PUBLISH identifier")),
                    }
                }
                Packet::PubRel(id) if self.qos == QoS::ExactlyOnce => {
                    // lib/handle_pubrel.c: handle__pubrel delivers on the first PUBREL,
                    // then answers even a repeated release with PUBCOMP.
                    if let Some(payload) = incoming.remove(&id) {
                        self.record(&payload, arrival)?;
                    }
                    self.client.send(&Packet::PubComp(id)).await?;
                }
                _ => {
                    return Err(Error::Protocol(
                        "unexpected packet or delivery QoS at subscriber",
                    ));
                }
            }
        }
        self.client.disconnect().await?;
        Ok((self.coverage, self.stats))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Ack,
    Rec,
    Comp,
    Done,
}

struct Sender {
    client: Client,
    qos: QoS,
    topic: String,
    run: u64,
    index: usize,
    pace: Pace,
    deadline: Instant,
    payload_bytes: usize,
    inflight: usize,
}

fn packet_id(seq: u64) -> PacketId {
    PacketId::new(1 + (seq % u64::from(u16::MAX)) as u16).unwrap()
}

impl Sender {
    async fn publish(mut self) -> Result<(usize, u64, u64), Error> {
        let mut payload = BytesMut::zeroed(self.payload_bytes);
        payload[..8].copy_from_slice(&self.run.to_be_bytes());
        payload[8..12].copy_from_slice(&(self.index as u32).to_be_bytes());
        let mut packet = Packet::Publish(Publish {
            dup: false,
            qos: self.qos,
            retain: false,
            topic: std::mem::take(&mut self.topic),
            packet_id: None,
            payload: Bytes::new(),
        });
        // Amortize socket writes without accumulating dozens of huge payloads.
        let batch_limit = (65_536 / (self.payload_bytes + 128)).clamp(1, BATCH);
        let mut pending = VecDeque::with_capacity(if self.qos == QoS::AtMostOnce {
            0
        } else {
            self.inflight
        });
        let mut acknowledged = 0;
        let mut published = 0u64;
        loop {
            let cap = if self.qos == QoS::AtMostOnce {
                batch_limit
            } else {
                (self.inflight - pending.len()).min(batch_limit)
            };
            let mut batch = 0;
            for _ in 0..cap {
                let now = Instant::now();
                if now >= self.pace.window.end || now < self.pace.due() {
                    break;
                }
                // Keep the payload allocation; the codec only borrows it during encoding.
                payload[12..20].copy_from_slice(&published.to_be_bytes());
                payload[20..28].copy_from_slice(
                    &nanos(now.duration_since(self.pace.window.start)).to_be_bytes(),
                );
                let Packet::Publish(message) = &mut packet else {
                    unreachable!()
                };
                message.packet_id = (self.qos != QoS::AtMostOnce).then(|| packet_id(published));
                message.payload = payload.freeze();
                self.client.queue(&packet)?;
                let Packet::Publish(message) = &mut packet else {
                    unreachable!()
                };
                payload = std::mem::take(&mut message.payload)
                    .try_into_mut()
                    .expect("codec doesn't retain payload");
                if self.qos != QoS::AtMostOnce {
                    pending.push_back(if self.qos == QoS::AtLeastOnce {
                        Pending::Ack
                    } else {
                        Pending::Rec
                    });
                }
                published += 1;
                batch += 1;
                self.pace.advance();
            }
            if batch != 0 {
                timeout_at(self.deadline, self.client.flush())
                    .await
                    .map_err(|_| Error::Timeout("writing a PUBLISH batch"))??;
                continue;
            }

            let due = self.pace.due();
            let more = Instant::now() < self.pace.window.end && due < self.pace.window.end;
            if pending.is_empty() {
                if !more {
                    break;
                }
                sleep_until(due).await;
                continue;
            }
            let packet = tokio::select! {
                () = sleep_until(self.deadline) => break,
                () = sleep_until(due), if more && pending.len() < self.inflight => continue,
                packet = self.client.recv() => packet?,
            };
            let (id, expected) = match packet {
                Packet::PubAck(id) => (id, Pending::Ack),
                Packet::PubRec(id) => (id, Pending::Rec),
                Packet::PubComp(id) => (id, Pending::Comp),
                _ => return Err(Error::Protocol("unexpected packet at publisher")),
            };
            let first = u32::from(packet_id(published - pending.len() as u64).get());
            let offset = (u32::from(id.get()) + u32::from(u16::MAX) - first) % u32::from(u16::MAX);
            let phase = pending
                .get_mut(offset as usize)
                .ok_or(Error::Protocol("unknown publisher acknowledgement ID"))?;
            if *phase != expected && !(*phase == Pending::Comp && expected == Pending::Rec) {
                return Err(Error::Protocol("publisher acknowledgement out of phase"));
            }
            if expected == Pending::Rec {
                *phase = Pending::Comp;
                timeout_at(self.deadline, self.client.send(&Packet::PubRel(id)))
                    .await
                    .map_err(|_| Error::Timeout("sending publisher PUBREL"))??;
            } else {
                *phase = Pending::Done;
                acknowledged += 1;
                while pending.front() == Some(&Pending::Done) {
                    pending.pop_front();
                }
            }
        }
        self.client.disconnect().await?;
        Ok((self.index, published, acknowledged))
    }
}

/// Offer paced connection attempts, rotating over stable client IDs and
/// disconnecting each successful client before its next scheduled attempt.
pub async fn storm(addresses: &[SocketAddr], config: &Storm) -> Result<StormResult, Error> {
    if addresses.is_empty() || config.clients == 0 || config.rate == 0 || config.duration.is_zero()
    {
        return Err(Error::Configuration(
            "storm needs endpoints and positive rate, client count and duration",
        ));
    }
    let run = nonce();
    let window = Window::new(config.duration)?;
    let addresses: Arc<[SocketAddr]> = addresses.into();
    let mut storm = JoinSet::new();
    for index in 0..config.clients {
        let mut pace = Pace::new(window, index, config.clients, Some(config.rate));
        let id = format!("mqxb-{run:x}-storm{index}");
        let clean = config.clean_session;
        let addresses = Arc::clone(&addresses);
        storm.spawn(async move {
            let mut counts = [0; 5]; // attempts, successful, in window, failed, resumed
            let mut latency = Histogram::default();
            let mut endpoint = index % addresses.len();
            loop {
                let due = pace.due();
                if due >= window.end {
                    break;
                }
                sleep_until(due).await;
                if Instant::now() >= window.end {
                    break;
                }
                pace.advance();
                counts[0] += 1;
                match Client::connect(addresses[endpoint], id.clone(), clean).await {
                    Ok((mut client, elapsed, resumed)) => {
                        counts[1] += 1;
                        counts[2] += u64::from(Instant::now() < window.end);
                        counts[4] += u64::from(resumed);
                        latency.record(elapsed);
                        // The next CONNECT fences any older connection even if DISCONNECT was lost.
                        let _ = client.disconnect().await;
                    }
                    Err(_) => counts[3] += 1,
                }
                endpoint = (endpoint + 1) % addresses.len();
            }
            (counts, latency)
        });
    }
    let mut counts = [0; 5];
    let mut latency = Histogram::default();
    while let Some(job) = storm.join_next().await {
        let (result, samples) = job?;
        for (a, b) in counts.iter_mut().zip(result) {
            *a += b;
        }
        latency.merge(&samples);
    }
    let [attempts, connections, in_window, failures, resumed_sessions] = counts;
    Ok(StormResult {
        attempts,
        connections,
        failures,
        resumed_sessions,
        connections_per_second: in_window as f64 / config.duration.as_secs_f64(),
        connect_latency: latency.summary(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paced_clients_split_the_aggregate_rate_without_rounding_each_lane() {
        let start = Instant::now();
        let window = Window {
            start,
            end: start + Duration::from_secs(2),
        };
        let mut lanes = [0, 1, 2].map(|index| Pace::new(window, index, 3, Some(2)));
        for (lane, expected_ms) in lanes.iter().zip([0, 500, 1000]) {
            assert_eq!(lane.due() - start, Duration::from_millis(expected_ms));
        }
        lanes.iter_mut().for_each(Pace::advance);
        assert_eq!(lanes[0].due() - start, Duration::from_millis(1500));
        assert_eq!(lanes[1].due(), window.end);
        assert_eq!(lanes[2].due(), window.end);
    }

    #[test]
    fn one_to_one_uses_recipient_identity_and_shared_uses_group_identity() {
        let mut pair = Coverage::Local {
            first: 1,
            streams: vec![SequenceSet::default()],
        };
        assert!(pair.insert(1, 0).unwrap());
        assert!(!pair.insert(1, 0).unwrap());
        assert!(pair.insert(0, 0).is_err());

        let streams: Arc<[_]> = Arc::new([Mutex::new(SequenceSet::default())]);
        let mut first = Coverage::Shared(Arc::clone(&streams));
        let mut second = Coverage::Shared(streams);
        assert!(first.insert(0, 0).unwrap());
        assert!(!second.insert(0, 0).unwrap());
    }
}
