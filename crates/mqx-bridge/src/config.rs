use std::{fmt, path::PathBuf, sync::Arc};

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

/// A decoded TLS pre-shared key, shared with the outgoing handshake callback.
#[derive(Clone, Eq, PartialEq)]
pub struct Psk(Arc<Vec<u8>>);

impl Psk {
    pub fn from_hex(hex: &str) -> Result<Self, &'static str> {
        let digits = hex.as_bytes();
        let invalid = "bridge_psk must be a hexadecimal key of 1 to 512 bytes without 0x.";
        if digits.len() > 1025 || !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid);
        }
        // Mosquitto lib/util_mosq.c: mosquitto__hex2bin preserves leading zero
        // octets, then decodes the remaining digits as a big-endian integer.
        let leading = digits.chunks_exact(2).take_while(|pair| *pair == b"00").count();
        let digits = &digits[2 * leading..];
        let odd = digits.len() % 2;
        let high = odd != 0 && digits[0] != b'0';
        let len = leading + digits.len() / 2 + usize::from(high);
        if !(1..=512).contains(&len) {
            return Err(invalid);
        }
        let nibble = |digit: u8| match digit {
            b'0'..=b'9' => digit - b'0',
            _ => digit.to_ascii_lowercase() - b'a' + 10,
        };
        let mut key = Vec::with_capacity(len);
        key.resize(leading, 0);
        if high {
            key.push(nibble(digits[0]));
        }
        for pair in digits[odd..].chunks_exact(2) {
            key.push(nibble(pair[0]) << 4 | nibble(pair[1]));
        }
        Ok(Self(Arc::new(key)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk([redacted])")
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
    pub identity: Option<Arc<str>>,
    pub psk: Option<Psk>,
    pub require_ocsp: bool,
}

impl TlsConfig {
    fn has_roots(&self) -> bool {
        self.cafile.is_some() || self.capath.is_some() || self.use_os_certs
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match (&self.psk, &self.identity) {
            (Some(_), None) => return Err("Invalid bridge configuration: missing bridge_identity."),
            (None, Some(_)) => return Err("Invalid bridge configuration: missing bridge_psk."),
            (Some(_), Some(identity)) => {
                if identity.is_empty() || identity.len() >= 256 || identity.contains('\0') {
                    return Err("bridge_identity must be 1 to 255 bytes and contain no NUL.");
                }
                if self.has_roots() || self.certfile.is_some() || self.keyfile.is_some() {
                    return Err("Cannot use bridge_psk with certificate-based bridge TLS.");
                }
                if self.require_ocsp {
                    return Err("Cannot use bridge_require_ocsp with bridge_psk.");
                }
                if self.version.as_deref() == Some("tlsv1.3") {
                    return Err("bridge_psk requires TLS 1.2, not bridge_tls_version tlsv1.3.");
                }
            }
            (None, None) => {}
        }
        if self.require_ocsp {
            if !self.has_roots() {
                return Err("bridge_require_ocsp needs a bridge CA file, directory, or OS roots.");
            }
            if self.certfile.is_some() != self.keyfile.is_some() {
                return Err("Both bridge_certfile and bridge_keyfile must be provided.");
            }
        }
        Ok(())
    }

    pub(crate) fn enabled(&self) -> bool {
        self.has_roots() || self.psk.is_some() || self.identity.is_some() || self.require_ocsp
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
