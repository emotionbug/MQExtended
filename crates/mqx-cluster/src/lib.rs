//! Durable Raft with dynamic membership and a direct application mesh.
//!
//! Use a CA dedicated to this cluster. A certificate authorizes its holder to
//! participate in Raft; application RPCs additionally require voter membership.

mod admission;
mod lease;
mod membership;
mod mtls;
mod mux;
mod node;
mod snapshot;
mod snapshot_file;
mod survivor;
mod transport;
mod version;
mod wal;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub use lease::{NodeEvent, NodeStatus};
pub use membership::{MemberRole, MemberStatus, MembershipControl, MembershipStatus};
pub use node::{Cluster, ClusterMetrics};
pub use openraft::SnapshotPolicy;
pub use survivor::{SurvivorEvent, SurvivorReason};
pub use transport::Mesh;
pub use wal::WalMetrics;

/// Largest configurable snapshot transfer, including the encoded metadata.
pub const MAX_SNAPSHOT_SIZE: u64 = 256 * 1024 * 1024;
/// Default maximum snapshot transfer size.
pub const DEFAULT_MAX_SNAPSHOT_SIZE: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_COMMAND_SIZE: usize = 2 * 1024 * 1024;
pub const DEFAULT_MAX_APPEND_SIZE: usize = 9 * 1024 * 1024;
pub const DEFAULT_MAX_MESH_SIZE: usize = DEFAULT_MAX_COMMAND_SIZE;

const MAX_PACKET_SIZE: usize = 268_435_460; // MQTT Remaining Length plus fixed header.
const PACKET_ENVELOPE: usize = 64 * 1024;

/// Transport security for the peer listener and all outgoing Raft and mesh RPCs.
#[derive(Clone, Debug)]
pub enum ClusterSecurity {
    /// PEM credentials. The leaf must have exactly one Common Name, `mqx-node-<id>`,
    /// and be valid for both TLS server and client authentication.
    Tls {
        ca_file: PathBuf,
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    /// No peer authentication or encryption. Use only on a trusted isolated network.
    InsecurePlaintext,
}

/// The initial state must be identical on all nodes. A restored node must only rely on
/// application state stored in the snapshot and in subsequently applied log entries.
pub trait StateMachine: Send + Sync + 'static {
    type Command: Serialize + DeserializeOwned + Clone + Debug + Send + Sync + 'static;
    type Response: Serialize + DeserializeOwned + Clone + Debug + Send + Sync + 'static;

    /// Application payload schema to write. Keep this at the previous version
    /// until every replica's command and snapshot readers support the new one.
    const WRITE_VERSION: u16 = 1;

    /// Accepted application payload versions. Default readers handle schema 1.
    fn supports_version(version: u16) -> bool {
        version == 1
    }

    /// Override when decoding older schemas requires translating their commands.
    fn decode_command(_version: u16, bytes: &[u8]) -> Result<Self::Command, ClusterError> {
        Ok(transport::decode(bytes)?)
    }

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

    /// Override when older snapshot schemas need a migration on restore.
    fn restore_versioned(&mut self, _version: u16, bytes: &[u8]) -> Result<(), ClusterError> {
        self.restore(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    pub node_id: u64,
    /// Local TCP bind address. Advertise its reachable address in `peers[node_id]`.
    pub raft_addr: SocketAddr,
    /// Desired voters. On first bootstrap these are the initial voters. On
    /// an empty joining node they also identify the existing seed peers.
    pub peers: BTreeMap<u64, SocketAddr>,
    /// Start an empty node without initializing a separate Raft cluster.
    pub join: bool,
    /// Monotonically increasing desired membership revision; zero only bootstraps.
    pub membership_generation: u64,
    /// Write legacy format 1 for a rolling upgrade from static membership, or
    /// format 2 for tagged payloads and dynamic membership.
    pub state_format: u16,
    /// Opt in to recovering without a quorum, discarding divergent state if needed.
    pub auto_recover: bool,
    /// Defaults to the lease timeout; only valid with automatic recovery enabled.
    pub auto_recover_timeout: Option<Duration>,
    pub data_dir: PathBuf,
    /// Create a direct-I/O WAL on an empty Linux storage directory. Never converts a legacy WAL.
    pub wal_direct_io: bool,
    pub security: ClusterSecurity,
    pub heartbeat_interval: Duration,
    pub election_timeout_min: Duration,
    pub election_timeout_max: Duration,
    /// Total deadline for forwarding, Raft commit and linearizable reads; also
    /// the mesh RPC and AppendEntries replication stream deadline.
    pub request_timeout: Duration,
    pub lease_interval: Duration,
    pub lease_timeout: Duration,
    pub snapshot_timeout: Duration,
    /// Maximum encoded snapshot transfer size in bytes (default 64 MiB, maximum 256 MiB).
    pub max_snapshot_size: u64,
    /// Maximum MessagePack application command size. Use identical limits on all peers.
    pub max_command_size: usize,
    /// Maximum encoded AppendEntries body, including its entries and Raft metadata.
    pub max_append_size: usize,
    /// Maximum unreplicated mesh request or response body.
    pub max_mesh_size: usize,
    pub snapshot_policy: SnapshotPolicy,
    pub snapshot_log_retention: u64,
}

impl ClusterConfig {
    pub fn new(
        node_id: u64,
        raft_addr: SocketAddr,
        peers: BTreeMap<u64, SocketAddr>,
        data_dir: PathBuf,
        security: ClusterSecurity,
    ) -> Self {
        Self {
            node_id,
            raft_addr,
            peers,
            join: false,
            membership_generation: 0,
            state_format: 2,
            auto_recover: false,
            auto_recover_timeout: None,
            data_dir,
            wal_direct_io: false,
            security,
            heartbeat_interval: Duration::from_millis(100),
            election_timeout_min: Duration::from_millis(400),
            election_timeout_max: Duration::from_millis(800),
            request_timeout: Duration::from_secs(5),
            lease_interval: Duration::from_secs(1),
            lease_timeout: Duration::from_secs(5),
            snapshot_timeout: Duration::from_secs(120),
            max_snapshot_size: DEFAULT_MAX_SNAPSHOT_SIZE,
            max_command_size: DEFAULT_MAX_COMMAND_SIZE,
            max_append_size: DEFAULT_MAX_APPEND_SIZE,
            max_mesh_size: DEFAULT_MAX_MESH_SIZE,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(5000),
            snapshot_log_retention: 1000,
        }
    }

    /// Raise RPC limits to fit an MQTT packet plus a broker command or mesh envelope.
    /// The server should use the effective broker `max_packet_size` shared by all
    /// members; zero means MQTT's wire maximum. Default limits are never lowered.
    pub fn set_packet_limit(&mut self, max_packet_size: usize) -> Result<(), ClusterError> {
        let packet = if max_packet_size == 0 {
            MAX_PACKET_SIZE
        } else {
            max_packet_size.min(MAX_PACKET_SIZE)
        };
        self.max_command_size = self.max_command_size.max(packet + PACKET_ENVELOPE);
        self.max_mesh_size = self.max_mesh_size.max(packet + PACKET_ENVELOPE);
        self.max_append_size = self
            .max_append_size
            .max(self.max_command_size.saturating_add(PACKET_ENVELOPE));
        self.check_frame_limits()
    }

    fn check_frame_limits(&self) -> Result<(), ClusterError> {
        if !(1..=MAX_PACKET_SIZE + PACKET_ENVELOPE).contains(&self.max_command_size)
            || !(1..=MAX_PACKET_SIZE + PACKET_ENVELOPE).contains(&self.max_mesh_size)
            || self.max_append_size > MAX_PACKET_SIZE + 2 * PACKET_ENVELOPE
            || self.max_append_size < self.max_command_size + PACKET_ENVELOPE
        {
            return Err(ClusterError::InvalidConfig(
                "invalid cluster frame sizes: AppendEntries must fit a maximum command plus 64 KiB of Raft metadata".into(),
            ));
        }
        Ok(())
    }

    /// Validate the recovery directives before opening the data directory.
    pub fn validate_auto_recover(&self) -> Result<(), ClusterError> {
        let invalid = |message: &str| ClusterError::InvalidConfig(message.into());
        if self.auto_recover {
            if self.state_format != 2 {
                return Err(invalid(
                    "'auto_recover true' requires 'cluster_state_format 2'",
                ));
            }
            if !self.peers.contains_key(&self.node_id) {
                return Err(invalid(
                    "'auto_recover true' requires a 'cluster_peer' entry for this node",
                ));
            }
            if self
                .auto_recover_timeout
                .is_some_and(|timeout| timeout.as_millis() == 0)
            {
                return Err(invalid(
                    "'auto_recover_timeout' must be a positive number of milliseconds",
                ));
            }
        } else if self.auto_recover_timeout.is_some() {
            return Err(invalid(
                "'auto_recover_timeout' requires 'auto_recover true'",
            ));
        }
        Ok(())
    }

    fn raft_config(&self) -> Result<openraft::Config, ClusterError> {
        self.check_frame_limits()?;
        let invalid = ClusterError::InvalidConfig;
        membership::validate_peers(&self.peers)?;
        if !matches!(self.state_format, 1 | 2) {
            return Err(ClusterError::UnsupportedVersion {
                kind: "state write format",
                version: self.state_format,
            });
        }
        self.validate_auto_recover()?;
        if self.state_format == 1 && (self.join || self.membership_generation != 0) {
            return Err(invalid("dynamic membership requires state format 2".into()));
        }
        if !(1..=MAX_SNAPSHOT_SIZE).contains(&self.max_snapshot_size) {
            return Err(invalid(
                "max_snapshot_size must be between 1 byte and 256 MiB".into(),
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
            // OpenRaft's entry-count cap complements the byte cap in Wal::limited_get_log_entries.
            api_batch_linger_ms: Some(1),
            // Replication and local disk may advance concurrently; Raft still
            // gates acknowledgments on the logged durable I/O frontier.
            broadcast_submitted_on_append: Some(true),
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
    #[error("invalid cluster configuration: {0}")]
    UnusableIdentity(String),
    #[error("cluster IO: {0}")]
    Io(#[from] io::Error),
    #[error("Raft node failed: {0}")]
    Raft(String),
    #[error("no leader or quorum before the request deadline")]
    Deadline,
    #[error("write may already have committed: {0}")]
    WriteUncertain(String),
    #[error("peer rejected the application write before proposal")]
    WriteRejected,
    #[error("cluster node is shut down")]
    Shutdown,
    #[error("cluster incarnation changed; restart the process")]
    Restart,
    #[error("no cluster member with ID {0}")]
    UnknownNode(u64),
    #[error("node {0} has been permanently removed from the cluster")]
    Removed(u64),
    #[error("membership configuration refused: {0}")]
    Membership(String),
    #[error("unsupported {kind} version {version}")]
    UnsupportedVersion { kind: &'static str, version: u16 },
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
