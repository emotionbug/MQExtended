//! MQTT 3.1.1 load generation and local broker comparison.
//!
//! ```text
//! cargo build --release -p mqx-server -p mqx-bench
//! MOSQUITTO_BUILD_DIR=/path/to/mosquitto/build target/release/mqx-bench \
//!   compare --rate 100 --state-dir . --json results.json
//! target/release/mqx-bench load --endpoint 127.0.0.1:1883 \
//!   --pattern shared --publishers 8 --subscribers 4 --qos 2 --rate 100
//! target/release/mqx-bench storm --rate 250 --clients 50 --persistent
//! ```
//!
//! Omit `--rate` to send as fast as the socket and QoS window permit. For a
//! disk-backed cluster comparison, use a state directory on the intended disk,
//! not a tmpfs. Each row starts fresh brokers with anonymous loopback listeners.
//! Set `MQEXTENDED_RELEASE_BIN` for a release binary outside the normal target directory.
//!
//! Publish and delivery rates use the active load window. Setup connection
//! rate runs through the last CONNACK. Loss is measured after draining,
//! relative to completed PUBLISH writes, not target rate or PUBACKs. Every
//! fan-out subscriber receives its own expected copy; a shared group expects
//! one copy across all members. Latency covers first delivery of each copy,
//! including copies that arrive during drain.

mod accounting;
mod mqtt;
mod runner;
mod workload;

use std::{io, path::PathBuf, time::Duration};

use clap::ValueEnum;
use mqx_codec::QoS;
use serde::Serialize;
use thiserror::Error;

pub use runner::{Broker, Comparison, ComparisonOptions, compare};
pub use workload::{load, storm};

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Encode(#[from] mqx_codec::EncodeError),
    #[error(transparent)]
    Decode(#[from] mqx_codec::DecodeError),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("invalid benchmark configuration: {0}")]
    Configuration(&'static str),
    #[error("unexpected MQTT exchange: {0}")]
    Protocol(&'static str),
    #[error("deadline exceeded while {0}")]
    Timeout(&'static str),
    #[error("{broker} node {node} startup failed: {reason}\n{log}")]
    Startup {
        broker: Broker,
        node: usize,
        reason: String,
        log: String,
    },
    #[error("{broker} {pattern:?}/{qos:?} workload failed: {source}\n{logs}")]
    Workload {
        broker: Broker,
        pattern: Pattern,
        qos: Quality,
        #[source]
        source: Box<Self>,
        logs: String,
    },
    #[error("cannot use broker executable {path}: {source}")]
    Binary { path: PathBuf, source: io::Error },
    #[error("expected Mosquitto 2.1.4 from {path}, got {version:?}")]
    MosquittoVersion { path: PathBuf, version: String },
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Pattern {
    FanIn,
    FanOut,
    #[value(name = "one-to-one")]
    OneToOne,
    Shared,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
pub enum Quality {
    #[value(name = "0")]
    #[serde(rename = "0")]
    Qos0,
    #[value(name = "1")]
    #[serde(rename = "1")]
    Qos1,
    #[value(name = "2")]
    #[serde(rename = "2")]
    Qos2,
}

impl From<Quality> for QoS {
    fn from(quality: Quality) -> Self {
        match quality {
            Quality::Qos0 => Self::AtMostOnce,
            Quality::Qos1 => Self::AtLeastOnce,
            Quality::Qos2 => Self::ExactlyOnce,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Load {
    pub publishers: usize,
    pub subscribers: usize,
    pub pattern: Pattern,
    pub qos: Quality,
    pub payload_bytes: usize,
    /// Aggregate publications per second, or `None` for unrestricted sending.
    pub rate: Option<u64>,
    pub duration: Duration,
    /// Time to finish publisher handshakes and, separately, to receive late deliveries.
    pub drain: Duration,
    pub clean_session: bool,
    pub inflight: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Storm {
    pub rate: u64,
    pub clients: usize,
    pub duration: Duration,
    pub clean_session: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Latency {
    pub samples: u64,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
    pub max_ns: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadResult {
    pub published: u64,
    /// Broker-completed publisher handshakes; not applicable to QoS 0.
    pub acknowledged: Option<u64>,
    pub expected_deliveries: u64,
    pub unique_deliveries: u64,
    pub duplicates: u64,
    pub lost: u64,
    pub published_per_second: f64,
    /// Counts unique deliveries received within the load window, excluding drain.
    pub delivered_per_second: f64,
    pub late_deliveries: u64,
    pub delivery_latency: Latency,
    pub connections: u64,
    pub connections_per_second: f64,
    pub connect_latency: Latency,
}

#[derive(Debug, Clone, Serialize)]
pub struct StormResult {
    pub attempts: u64,
    pub connections: u64,
    pub failures: u64,
    pub resumed_sessions: u64,
    pub connections_per_second: f64,
    pub connect_latency: Latency,
}
