//! MQTT 3.1 / 3.1.1 broker with Mosquitto 2.1.4 session semantics.

mod connection;
mod inbox;
mod retained;
mod runtime;
mod state;

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use mqx_auth::{AclFile, AclFileError, PasswordFile};
use mqx_cluster::ClusterError;
use mqx_codec::{DecodeError, EncodeError, QoS};
use thiserror::Error;
use tokio::sync::watch;

pub use runtime::Broker;
use runtime::Live;

/// Broker-wide options. Zero-valued limits are disabled.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub allow_anonymous: bool,
    pub allow_zero_length_clientid: bool,
    pub auto_id_prefix: String,
    pub clientid_prefixes: Option<String>,
    pub max_keepalive: u16,
    pub max_inflight_messages: usize,
    pub max_inflight_bytes: usize,
    pub max_queued_messages: usize,
    pub max_queued_bytes: usize,
    pub queue_qos0_messages: bool,
    pub message_size_limit: usize,
    pub max_packet_size: usize,
    pub persistent_client_expiration: Option<Duration>,
    pub retain_available: bool,
    pub upgrade_outgoing_qos: bool,
    pub allow_duplicate_messages: bool,
    pub check_retain_source: bool,
    pub global_max_connections: usize,
    pub global_max_clients: usize,
    pub connection_messages: bool,
}

impl Default for BrokerConfig {
    // conf.c: config__init_reload and config__check. The server must resolve
    // the no-config, local-only exception to allow_anonymous itself.
    fn default() -> Self {
        Self {
            allow_anonymous: false,
            allow_zero_length_clientid: true,
            auto_id_prefix: "auto-".into(),
            clientid_prefixes: None,
            max_keepalive: 0,
            max_inflight_messages: 20,
            max_inflight_bytes: 0,
            max_queued_messages: 1000,
            max_queued_bytes: 0,
            queue_qos0_messages: false,
            message_size_limit: 0,
            max_packet_size: 2_000_000,
            persistent_client_expiration: None,
            retain_available: true,
            upgrade_outgoing_qos: false,
            allow_duplicate_messages: true,
            check_retain_source: true,
            global_max_connections: 0,
            global_max_clients: 0,
            connection_messages: true,
        }
    }
}

/// Listener-level settings; share one `Arc<ListenerPolicy>` across connections
/// accepted by the same listener so connection limits are counted correctly.
#[derive(Debug, Clone)]
pub struct ListenerPolicy {
    pub allow_anonymous: Option<bool>,
    pub allow_zero_length_clientid: Option<bool>,
    pub auto_id_prefix: Option<String>,
    pub max_qos: QoS,
    pub max_connections: usize,
    pub use_username_as_clientid: bool,
    pub disable_protocol_v3: bool,
    pub disable_protocol_v4: bool,
    pub mount_point: Option<String>,
    pub security: SecurityHandle,
}

impl Default for ListenerPolicy {
    // listeners.c: listener__set_defaults. None means use the broker setting.
    fn default() -> Self {
        Self {
            allow_anonymous: None,
            allow_zero_length_clientid: None,
            auto_id_prefix: None,
            max_qos: QoS::ExactlyOnce,
            max_connections: 0,
            use_username_as_clientid: false,
            disable_protocol_v3: false,
            disable_protocol_v4: false,
            mount_point: None,
            security: SecurityHandle::default(),
        }
    }
}

struct Security {
    password: Option<PasswordFile>,
    acl: Option<Arc<AclFile>>,
    text: Option<Bytes>,
    reload: bool,
}

struct SharedSecurity {
    id: u64,
    stable_id: Option<u64>,
    snapshots: watch::Sender<Arc<Security>>,
}

static NEXT_LOCAL_SECURITY_ID: AtomicU64 = AtomicU64::new(1);
static SECURITY_REVISION: AtomicU64 = AtomicU64::new(0);

/// One reloadable set of Mosquitto password and ACL files. Use a single handle
/// for listeners sharing security settings and separate handles for separate files.
#[derive(Clone)]
pub struct SecurityHandle(Arc<SharedSecurity>);

impl std::fmt::Debug for SecurityHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityHandle")
            .field("cluster_id", &self.0.stable_id)
            .finish_non_exhaustive()
    }
}

impl Default for SecurityHandle {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl SecurityHandle {
    pub fn new(password: Option<PasswordFile>, acl: Option<AclFile>) -> Self {
        Self::new_inner(None, password, acl, None)
    }

    /// Configures a nonzero cluster-wide policy ID shared by equivalent listeners.
    /// The original ACL bytes are needed to apply the same parsed policy on every node.
    pub fn with_id(
        id: u64,
        password: Option<PasswordFile>,
        acl: Option<Vec<u8>>,
    ) -> Result<Self, AclFileError> {
        let (parsed, text) = parse_acl(acl)?;
        Ok(Self::new_inner(Some(id), password, parsed, text))
    }

    fn new_inner(
        stable_id: Option<u64>,
        password: Option<PasswordFile>,
        acl: Option<AclFile>,
        text: Option<Bytes>,
    ) -> Self {
        Self(Arc::new(SharedSecurity {
            id: NEXT_LOCAL_SECURITY_ID.fetch_add(1, Ordering::Relaxed),
            stable_id,
            snapshots: watch::Sender::new(Arc::new(Security {
                password,
                acl: acl.map(Arc::new),
                text,
                reload: false,
            })),
        }))
    }

    /// Replaces policy files loaded by the caller. In cluster mode follow
    /// this with [`Broker::register_security`] to commit the changed ACL.
    pub fn replace_text(
        &self,
        password: Option<PasswordFile>,
        acl: Option<Vec<u8>>,
    ) -> Result<(), AclFileError> {
        let (parsed, text) = parse_acl(acl)?;
        self.replace_inner(password, parsed, text);
        Ok(())
    }

    /// Replaces both files together and causes connected clients to reauthenticate.
    pub fn replace(&self, password: Option<PasswordFile>, acl: Option<AclFile>) {
        self.replace_inner(password, acl, None);
    }

    fn replace_inner(
        &self,
        password: Option<PasswordFile>,
        acl: Option<AclFile>,
        text: Option<Bytes>,
    ) {
        self.0.snapshots.send_replace(Arc::new(Security {
            password,
            acl: acl.map(Arc::new),
            text,
            reload: true,
        }));
        SECURITY_REVISION.fetch_add(1, Ordering::Release);
    }
}

fn parse_acl(acl: Option<Vec<u8>>) -> Result<(Option<AclFile>, Option<Bytes>), AclFileError> {
    let parsed = acl.as_deref().map(AclFile::parse).transpose()?;
    Ok((parsed, acl.map(Bytes::from)))
}

/// Certificate identity mapping, as resolved by the listener's TLS layer.
#[derive(Debug, Clone, Default)]
pub enum CertIdentity {
    #[default]
    None,
    Username(String),
    MissingOrInvalid,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionInfo {
    pub peer_addr: Option<SocketAddr>,
    pub listener: Arc<ListenerPolicy>,
    pub cert_identity: CertIdentity,
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("connection I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("peer violated the MQTT protocol")]
    Protocol,
    #[error("operating system could not generate a random identity: {0}")]
    ClientId(getrandom::Error),
    #[error(transparent)]
    Cluster(#[from] ClusterError),
    #[error("replicated ACLs require a stable nonzero policy ID and original file bytes")]
    ClusterSecurity,
    #[error("replicated ACL bytes were rejected by the ACL parser")]
    InvalidClusterAcl,
}
