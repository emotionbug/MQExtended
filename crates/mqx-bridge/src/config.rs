use std::{fmt, path::PathBuf};

use mqx_codec::QoS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Protocol {
    V31,
    #[default]
    V311,
    V5,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Start {
    #[default]
    Automatic,
    Lazy,
    Once,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    In,
    Out,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Topic {
    pub pattern: Option<String>,
    pub direction: Direction,
    pub qos: QoS,
    pub local_prefix: Option<String>,
    pub remote_prefix: Option<String>,
    pub local_filter: String,
    pub remote_filter: String,
}

impl Topic {
    pub fn incoming(&self) -> bool {
        self.direction != Direction::Out
    }

    pub fn outgoing(&self) -> bool {
        self.direction != Direction::In
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct TlsConfig {
    pub cafile: Option<PathBuf>,
    pub capath: Option<PathBuf>,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub alpn: Option<String>,
    pub ciphers: Option<String>,
    pub ciphers_tls13: Option<String>,
    pub version: Option<String>,
    pub insecure: bool,
    pub use_os_certs: bool,
}

impl TlsConfig {
    pub(crate) fn enabled(&self) -> bool {
        self.cafile.is_some() || self.capath.is_some() || self.use_os_certs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Restart {
    pub initial_ms: u64,
    pub base_ms: u64,
    pub cap_ms: u64,
    pub stable_secs: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BridgeConfig {
    pub name: String,
    pub addresses: Vec<(String, u16)>,
    pub local_clientid: String,
    pub remote_clientid: String,
    pub default_local_clientid: bool,
    pub default_remote_clientid: bool,
    pub local_username: Option<String>,
    pub local_password: Option<String>,
    pub remote_username: Option<String>,
    pub remote_password: Option<String>,
    pub topics: Vec<Topic>,
    pub keepalive: u16,
    pub notifications: bool,
    pub notifications_local_only: bool,
    pub notification_topic: Option<String>,
    pub start: Start,
    pub idle_timeout: u64,
    pub restart: Restart,
    pub threshold: usize,
    pub try_private: bool,
    pub attempt_unsubscribe: bool,
    pub protocol: Protocol,
    pub outgoing_retain: bool,
    pub clean_session: bool,
    pub local_clean_session: Option<bool>,
    pub round_robin: bool,
    pub reload_immediate: bool,
    pub max_topic_alias: u16,
    pub receive_maximum: u16,
    pub session_expiry: u32,
    pub max_packet_size: usize,
    pub bind_address: Option<String>,
    pub tcp_keepalive: Option<(u32, u32, u32)>,
    pub tcp_user_timeout: Option<u32>,
    pub tls: TlsConfig,
}

impl fmt::Debug for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeConfig")
            .field("name", &self.name)
            .field("local_clientid", &self.local_clientid)
            .field("remote_clientid", &self.remote_clientid)
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}

impl BridgeConfig {
    // Mosquitto src/conf.c: config__read_file_core initializes each connection block.
    pub fn new(name: String) -> Self {
        Self {
            name,
            addresses: Vec::new(),
            local_clientid: String::new(),
            remote_clientid: String::new(),
            default_local_clientid: false,
            default_remote_clientid: false,
            local_username: None,
            local_password: None,
            remote_username: None,
            remote_password: None,
            topics: Vec::new(),
            keepalive: 60,
            notifications: true,
            notifications_local_only: false,
            notification_topic: None,
            start: Start::Automatic,
            idle_timeout: 60,
            restart: Restart {
                initial_ms: 0,
                base_ms: 5_000,
                cap_ms: 30_000,
                stable_secs: 0,
            },
            threshold: 10,
            try_private: true,
            attempt_unsubscribe: true,
            protocol: Protocol::V311,
            outgoing_retain: true,
            clean_session: false,
            local_clean_session: None,
            round_robin: false,
            reload_immediate: false,
            max_topic_alias: 10,
            receive_maximum: 0,
            session_expiry: 0,
            max_packet_size: 0,
            bind_address: None,
            tcp_keepalive: None,
            tcp_user_timeout: None,
            tls: TlsConfig::default(),
        }
    }

    pub(crate) fn local_clean(&self) -> bool {
        self.local_clean_session.unwrap_or(self.clean_session)
    }
}
