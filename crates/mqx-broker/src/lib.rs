//! MQTT 3.1, 3.1.1 and 5 broker with Mosquitto 2.1.4 session semantics.

mod connection;
mod control;
mod fast;
mod inbox;
mod persistence;
mod retained;
mod runtime;
mod state;
mod sys;

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
use mqx_auth::{AclFile, AclFileError, BasicAuth, DynamicSecurity, PasswordFile};
use mqx_cluster::ClusterError;
use mqx_codec::{DecodeError, EncodeError, QoS};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::watch;

pub use control::{ControlInventory, ControlListener};
pub use persistence::{PersistenceCounts, PersistentState};
use runtime::Live;
pub use runtime::{BridgeAck, BridgeIdentity, BridgeSession, Broker, SocketObservation};
pub use sys::{BrokerMetrics, MOSQUITTO_VERSION, ProposalHistogram, SysTree};

/// An IP address as Mosquitto prints it: lib/net_mosq.c uses inet_ntop, so
/// IPv4-compatible and IPv4-mapped IPv6 addresses keep a dotted suffix.
pub fn inet_ntop(ip: std::net::IpAddr) -> String {
    connection::ntop(ip)
}

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
    pub retain_expiry_interval: Option<Duration>,
    pub persistent_client_expiration: Option<Duration>,
    pub retain_available: bool,
    pub upgrade_outgoing_qos: bool,
    pub allow_duplicate_messages: bool,
    pub check_retain_source: bool,
    pub global_max_connections: usize,
    pub global_max_clients: usize,
    pub connection_messages: bool,
    /// Global plugin callbacks also receive publications from outgoing bridges.
    pub sparkplug_aware: bool,
}

/// Broker options Mosquitto 2.1.4 applies on SIGHUP (conf.c: config__copy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadableLimits {
    pub message_size_limit: usize,
    pub persistent_client_expiration: Option<Duration>,
    pub queue_qos0_messages: bool,
    pub upgrade_outgoing_qos: bool,
    pub allow_duplicate_messages: bool,
    pub clientid_prefixes: Option<String>,
}

impl BrokerConfig {
    /// Extract the limits that can be applied without restarting the broker.
    pub fn reloadable_limits(&self) -> ReloadableLimits {
        ReloadableLimits {
            message_size_limit: self.message_size_limit,
            persistent_client_expiration: self.persistent_client_expiration,
            queue_qos0_messages: self.queue_qos0_messages,
            upgrade_outgoing_qos: self.upgrade_outgoing_qos,
            allow_duplicate_messages: self.allow_duplicate_messages,
            clientid_prefixes: self.clientid_prefixes.clone(),
        }
    }

    fn with_reloadable_limits(&self, limits: &ReloadableLimits) -> Self {
        Self {
            allow_anonymous: self.allow_anonymous,
            allow_zero_length_clientid: self.allow_zero_length_clientid,
            auto_id_prefix: self.auto_id_prefix.clone(),
            clientid_prefixes: limits.clientid_prefixes.clone(),
            max_keepalive: self.max_keepalive,
            max_inflight_messages: self.max_inflight_messages,
            max_inflight_bytes: self.max_inflight_bytes,
            max_queued_messages: self.max_queued_messages,
            max_queued_bytes: self.max_queued_bytes,
            queue_qos0_messages: limits.queue_qos0_messages,
            message_size_limit: limits.message_size_limit,
            max_packet_size: self.max_packet_size,
            retain_expiry_interval: self.retain_expiry_interval,
            persistent_client_expiration: limits.persistent_client_expiration,
            retain_available: self.retain_available,
            upgrade_outgoing_qos: limits.upgrade_outgoing_qos,
            allow_duplicate_messages: limits.allow_duplicate_messages,
            check_retain_source: self.check_retain_source,
            global_max_connections: self.global_max_connections,
            global_max_clients: self.global_max_clients,
            connection_messages: self.connection_messages,
            sparkplug_aware: self.sparkplug_aware,
        }
    }
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
            retain_expiry_interval: None,
            persistent_client_expiration: None,
            retain_available: true,
            upgrade_outgoing_qos: false,
            allow_duplicate_messages: true,
            check_retain_source: true,
            global_max_connections: 0,
            global_max_clients: 0,
            connection_messages: true,
            sparkplug_aware: false,
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
    pub disable_protocol_v5: bool,
    pub max_topic_alias: u16,
    pub max_topic_alias_broker: u16,
    pub mount_point: Option<String>,
    pub sparkplug_aware: bool,
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
            disable_protocol_v5: false,
            max_topic_alias: 10,
            max_topic_alias_broker: 10,
            mount_point: None,
            sparkplug_aware: false,
            security: SecurityHandle::default(),
        }
    }
}

struct Security {
    password: Option<PasswordFile>,
    acl: Option<Arc<AclFile>>,
    text: Option<Bytes>,
    // Effective listener settings installed with the credential files at reload.
    anonymous: Box<[bool]>,
    reload: bool,
}

impl Security {
    async fn authenticate(
        self: Arc<Self>,
        client_id: &Arc<str>,
        username: Option<&Arc<str>>,
        password: Option<&Bytes>,
        allow_anonymous: bool,
        dynamic: Option<&(bool, Arc<DynamicSecurity>)>,
    ) -> bool {
        if username.is_some()
            && password.is_some()
            && (self.password.is_some() || dynamic.is_some())
        {
            let client_id = client_id.clone();
            let username = username.cloned();
            let password = password.cloned();
            let dynamic = dynamic.cloned();
            tokio::task::spawn_blocking(move || {
                self.basic_auth(
                    &client_id,
                    username.as_deref(),
                    password.as_deref(),
                    allow_anonymous,
                    dynamic.as_ref(),
                )
            })
            .await
            .unwrap_or(false)
        } else {
            self.basic_auth(
                client_id,
                username.map(AsRef::as_ref),
                password.map(AsRef::as_ref),
                allow_anonymous,
                dynamic,
            )
        }
    }

    fn basic_auth(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
        allow_anonymous: bool,
        dynamic: Option<&(bool, Arc<DynamicSecurity>)>,
    ) -> bool {
        let file = || match self.password.as_ref()?.check(username, password) {
            BasicAuth::Allow => Some(true),
            BasicAuth::Deny => Some(false),
            BasicAuth::Ignore => None,
        };
        let policy = || dynamic?.1.authenticate(client_id, username, password);
        // plugin_basic_auth.c: unlike an ignored password-file callback, a
        // deferred callback can fall back to allow_anonymous only for no user.
        security_callbacks(dynamic.map(|(order, _)| *order), file, policy)
            .unwrap_or(allow_anonymous && (dynamic.is_none() || username.is_none()))
    }
}

fn security_callbacks(
    dynamic_before_file: Option<bool>,
    file: impl FnOnce() -> Option<bool>,
    dynamic: impl FnOnce() -> Option<bool>,
) -> Option<bool> {
    match dynamic_before_file {
        Some(true) => dynamic().or_else(file),
        Some(false) => file().or_else(dynamic),
        None => file(),
    }
}

struct SharedSecurity {
    id: u64,
    stable_id: Option<u64>,
    snapshots: watch::Sender<Arc<Security>>,
}

static NEXT_LOCAL_SECURITY_ID: AtomicU64 = AtomicU64::new(1);
static SECURITY_REVISION: AtomicU64 = AtomicU64::new(0);

/// Reloadable security callbacks. Listeners sharing password/ACL files share a
/// handle; dynamic security state is owned by the broker, not by the handle.
#[derive(Clone)]
pub struct SecurityHandle(Arc<SharedSecurity>, Option<bool>, usize);

impl std::fmt::Debug for SecurityHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityHandle")
            .field("cluster_id", &self.0.stable_id)
            .field("dynamic_security_before_file", &self.1)
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
        Self(
            Arc::new(SharedSecurity {
                id: NEXT_LOCAL_SECURITY_ID.fetch_add(1, Ordering::Relaxed),
                stable_id,
                snapshots: watch::Sender::new(Arc::new(Security {
                    password,
                    acl: acl.map(Arc::new),
                    text,
                    anonymous: Box::default(),
                    reload: false,
                })),
            }),
            None,
            0,
        )
    }

    /// Enables this listener's Dynamic Security auth and ACL callbacks.
    /// `before_file` places them before password/ACL file callbacks.
    pub fn with_dynamic_security(mut self, before_file: bool) -> Self {
        self.1 = Some(before_file);
        self
    }

    /// Select this listener's anonymous setting when sharing a credential store.
    pub fn for_listener(mut self, index: usize) -> Self {
        self.2 = index;
        self
    }

    fn anonymous(&self, snapshot: &Security, initial: bool) -> bool {
        if snapshot.anonymous.is_empty() {
            initial
        } else {
            snapshot.anonymous.get(self.2).copied().unwrap_or(false)
        }
    }

    /// Replaces policy files loaded by the caller. In cluster mode follow
    /// this with [`Broker::register_security`] to commit the changed ACL.
    pub fn replace_text(
        &self,
        password: Option<PasswordFile>,
        acl: Option<Vec<u8>>,
        anonymous: Box<[bool]>,
    ) -> Result<(), AclFileError> {
        let (parsed, text) = parse_acl(acl)?;
        self.replace_inner(password, parsed, text, anonymous);
        Ok(())
    }

    /// Replaces both files together and causes connected clients to reauthenticate.
    pub fn replace(&self, password: Option<PasswordFile>, acl: Option<AclFile>) {
        self.replace_inner(password, acl, None, Box::default());
    }

    fn replace_inner(
        &self,
        password: Option<PasswordFile>,
        acl: Option<AclFile>,
        text: Option<Bytes>,
        anonymous: Box<[bool]>,
    ) {
        self.0.snapshots.send_replace(Arc::new(Security {
            password,
            acl: acl.map(Arc::new),
            text,
            anonymous,
            reload: true,
        }));
        SECURITY_REVISION.fetch_add(1, Ordering::Release);
    }
}

fn parse_acl(acl: Option<Vec<u8>>) -> Result<(Option<AclFile>, Option<Bytes>), AclFileError> {
    let parsed = acl.as_deref().map(AclFile::parse).transpose()?;
    Ok((parsed, acl.map(Bytes::from)))
}

/// Certificate identity mapping, as resolved by the listener transport.
#[derive(Debug, Clone, Default)]
pub enum CertIdentity {
    #[default]
    None,
    /// Username from a locally verified TLS client certificate.
    Username(String),
    /// Username asserted by PROXY v2; it does not satisfy basic authentication.
    ForwardedUsername(String),
    MissingOrInvalid,
}

/// What the transport knows about a peer beyond [`ConnectionInfo`], as
/// Mosquitto keeps it on the client context.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerTransport<'a> {
    /// `context->address`: a Unix socket path, or a PROXY v1 source address
    /// exactly as sent. Without it the IP of `peer_addr` is formatted as
    /// inet_ntop does.
    pub address: Option<&'a str>,
    /// The negotiated TLS version and OpenSSL cipher name, e.g. `TLSv1.3`
    /// and `TLS_AES_256_GCM_SHA384`, for a TLS connection the listener
    /// terminated itself.
    pub tls: Option<(&'a str, &'a str)>,
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
    #[error(transparent)]
    DecodeV5(#[from] mqx_codec::v5::DecodeError),
    #[error(transparent)]
    EncodeV5(#[from] mqx_codec::v5::EncodeError),
    #[error("peer violated the MQTT 5 protocol (reason {0:?})")]
    ProtocolV5(mqx_codec::v5::ReasonCode),
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
    #[error("dynamic security is not initialized")]
    DynamicSecurityUninitialized,
    #[error("could not prepare a dynamic security request: {0}")]
    DynamicSecurityRequest(getrandom::Error),
    #[error("dynamic security configuration {path}: {source}")]
    DynamicSecurityFile {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}
