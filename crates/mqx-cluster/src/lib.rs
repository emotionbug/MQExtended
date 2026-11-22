//! Durable static-membership Raft and a direct application mesh.
//!
//! The peer port carries trusted cluster traffic. Bind it to an isolated private network;
//! it does not authenticate peers or encrypt traffic.

mod lease;
mod node;
mod snapshot;
mod transport;
mod wal;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use lease::{NodeEvent, NodeStatus};
pub use node::{Cluster, ClusterMetrics};
pub use openraft::SnapshotPolicy;
pub use transport::Mesh;

/// The initial state must be identical on all nodes. A restored node must only rely on
/// application state stored in the snapshot and in subsequently applied log entries.
pub trait StateMachine: Send + Sync + 'static {
    type Command: Serialize + DeserializeOwned + Clone + Debug + Send + Sync + 'static;
    type Response: Serialize + DeserializeOwned + Clone + Debug + Send + Sync + 'static;

    /// Apply a committed command deterministically. On each node this runs in log order,
    /// once per applied entry per process lifetime. Restart replays entries after the
    /// snapshot; installing a snapshot does not re-apply entries it already covers.
    /// Process-local effects are the application's responsibility.
    fn apply(&mut self, index: u64, command: Self::Command) -> Self::Response;

    /// Handle a replicated liveness transition in the same state machine and at the same
    /// index on every replica. Change replicated state here, not in a broadcast consumer.
    /// Do not perform an external effect on every replica: use replicated outbox state
    /// and delivery fencing or idempotency for effects outside Raft.
    fn on_node_event(&mut self, _event: NodeEvent) {}

    fn snapshot(&self) -> Vec<u8>;

    /// Replace replicated state with this snapshot. Do not replay historical effects.
    fn restore(&mut self, bytes: &[u8]) -> Result<(), ClusterError>;
}

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    pub node_id: u64,
    /// Local TCP bind address. Advertise its reachable address in `peers[node_id]`.
    pub raft_addr: SocketAddr,
    /// The identical static configuration on every node, including self.
    pub peers: BTreeMap<u64, SocketAddr>,
    pub data_dir: PathBuf,
    pub heartbeat_interval: Duration,
    pub election_timeout_min: Duration,
    pub election_timeout_max: Duration,
    /// Total deadline for forwarding, Raft commit and linearizable reads; also the mesh RPC deadline.
    pub request_timeout: Duration,
    pub lease_interval: Duration,
    pub lease_timeout: Duration,
    pub snapshot_timeout: Duration,
    pub snapshot_policy: SnapshotPolicy,
    pub snapshot_log_retention: u64,
}

impl ClusterConfig {
    pub fn new(
        node_id: u64,
        raft_addr: SocketAddr,
        peers: BTreeMap<u64, SocketAddr>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            node_id,
            raft_addr,
            peers,
            data_dir,
            heartbeat_interval: Duration::from_millis(100),
            election_timeout_min: Duration::from_millis(400),
            election_timeout_max: Duration::from_millis(800),
            request_timeout: Duration::from_secs(5),
            lease_interval: Duration::from_secs(1),
            lease_timeout: Duration::from_secs(5),
            snapshot_timeout: Duration::from_secs(120),
            snapshot_policy: SnapshotPolicy::LogsSinceLast(5000),
            snapshot_log_retention: 1000,
        }
    }

    fn raft_config(&self) -> Result<openraft::Config, ClusterError> {
        let invalid = ClusterError::InvalidConfig;
        if !self.peers.contains_key(&self.node_id) {
            return Err(invalid("peers must contain node_id".into()));
        }
        if self
            .peers
            .values()
            .any(|addr| addr.port() == 0 || addr.ip().is_unspecified())
            || self.peers.values().collect::<BTreeSet<_>>().len() != self.peers.len()
        {
            return Err(invalid(
                "peer addresses must be distinct and routable".into(),
            ));
        }
        if self.data_dir.as_os_str().is_empty()
            || self.lease_timeout <= self.lease_interval
            || matches!(self.snapshot_policy, SnapshotPolicy::LogsSinceLast(0))
        {
            return Err(invalid(
                "invalid storage path, timeout or snapshot policy".into(),
            ));
        }
        let millis = |duration: Duration| {
            u64::try_from(duration.as_millis())
                .ok()
                .filter(|ms| *ms > 0)
                .ok_or_else(|| invalid("Raft timings must fit in nonzero milliseconds".into()))
        };
        millis(self.request_timeout)?;
        millis(self.lease_interval)?;
        millis(self.lease_timeout)?;
        openraft::Config {
            heartbeat_interval: millis(self.heartbeat_interval)?,
            election_timeout_min: millis(self.election_timeout_min)?,
            election_timeout_max: millis(self.election_timeout_max)?,
            install_snapshot_timeout: millis(self.snapshot_timeout)?,
            max_payload_entries: transport::MAX_APPEND_ENTRIES,
            snapshot_policy: self.snapshot_policy.clone(),
            max_in_snapshot_log_to_keep: self.snapshot_log_retention,
            purge_batch_size: 1,
            enable_pre_vote: Some(true),
            ..Default::default()
        }
        .validate()
        .map_err(|error| invalid(error.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum ClusterError {
    #[error("invalid cluster configuration: {0}")]
    InvalidConfig(String),
    #[error("cluster IO: {0}")]
    Io(#[from] io::Error),
    #[error("Raft node failed: {0}")]
    Raft(String),
    #[error("no leader or quorum before the request deadline")]
    Deadline,
    #[error("write may already have committed: {0}")]
    WriteUncertain(String),
    #[error("cluster node is shut down")]
    Shutdown,
    #[error("no cluster member with ID {0}")]
    UnknownNode(u64),
    #[error("node {node_id} is unreachable: {source}")]
    Unreachable { node_id: u64, source: io::Error },
    #[error("node {0} did not answer before the mesh request deadline")]
    MeshTimeout(u64),
    #[error("a mesh handler is already registered")]
    MeshHandlerRegistered,
    #[error("mesh handler failed: {0}")]
    MeshHandler(String),
    #[error("application snapshot cannot be restored: {0}")]
    Restore(String),
}
