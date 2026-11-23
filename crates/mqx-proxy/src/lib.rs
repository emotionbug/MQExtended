//! HAProxy framing for listeners behind a trusted proxy.
//!
//! The peer can claim any address or TLS identity. Do not expose such a
//! listener to untrusted peers.

mod v1;
mod v2;

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// Nominal pre-CONNECT deadline measured from TCP accept, not from the last
/// PROXY byte. Finishing the header does not restart it.
///
/// Mosquitto `src/context.c:context__init` sets a 20 s initial keepalive;
/// `src/net.c:net__socket_accept` registers it and
/// `src/keepalive.c:keepalive__check` expires it after 1.5 times that interval,
/// on the broker's timer tick. Neither PROXY reader refreshes it.
pub const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProxyVersion {
    V1 = 1,
    V2 = 2,
}

impl TryFrom<i32> for ProxyVersion {
    type Error = ProxyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        // Mosquitto src/conf.c:config__read_file_core.
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(ProxyError::InvalidVersion(value)),
        }
    }
}

/// Listener policy for the TLS-enabled Mosquitto 2.1.4 build. The flags apply
/// to PROXY v2 only; a v1 listener can have its own TLS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyOptions {
    pub version: ProxyVersion,
    pub require_tls: bool,
    pub require_certificate: bool,
    pub use_identity_as_username: bool,
}

impl From<ProxyVersion> for ProxyOptions {
    fn from(version: ProxyVersion) -> Self {
        Self {
            version,
            require_tls: false,
            require_certificate: false,
            use_identity_as_username: false,
        }
    }
}

impl ProxyOptions {
    /// Validates PROXY-specific restrictions on listener TLS configuration.
    pub fn validate_listener(
        self,
        use_subject_as_username: bool,
        has_certfile: bool,
        has_keyfile: bool,
    ) -> Result<(), ProxyError> {
        // Mosquitto src/conf.c:config__check_proxy rejects either file alone.
        if self.version == ProxyVersion::V2 {
            if use_subject_as_username {
                return Err(ProxyError::SubjectUsernameWithV2);
            }
            if has_certfile || has_keyfile {
                return Err(ProxyError::ListenerTlsWithV2);
            }
        }
        Ok(())
    }

    /// Whether a plaintext v2 listener should use the forwarded CN instead of
    /// MQTT credentials at CONNECT. If true and there is no CN, return a
    /// bad-credentials CONNACK rather than dropping during header parsing.
    pub fn uses_forwarded_username(self) -> bool {
        // Mosquitto src/handle_connect.c:handle_username_from_cert_options.
        self.version == ProxyVersion::V2
            && self.require_certificate
            && self.use_identity_as_username
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyInfo {
    /// V1 fall back to the actual socket peer.
    Unknown,
    /// V2 LOCAL/UNSPEC health check. Close the connection without reading MQTT.
    Local,
    Proxied {
        addresses: ProxyAddresses,
        tls: Option<ProxyTls>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyAddresses {
    Ip {
        source: SocketAddr,
        destination: SocketAddr,
        /// The v1 source address token exactly as sent. Mosquitto
        /// src/proxy_v1.c: proxy_v1__decode keeps it as `context->address`;
        /// v2 carries binary addresses and has none.
        source_text: Option<Box<str>>,
    },
    Unix {
        source: Box<[u8]>,
        destination: Box<[u8]>,
    },
}

/// Presence means an SSL TLV was received, even if its SSL bit was unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTls {
    /// At least one SSL TLV asserts TLS, a session certificate, and verify=0.
    pub certificate_verified: bool,
    pub version: Option<String>,
    pub cipher: Option<String>,
    /// Populated only with `use_identity_as_username`.
    pub common_name: Option<String>,
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("enable_proxy_protocol must be 1 or 2, got {0}")]
    InvalidVersion(i32),
    #[error("use_subject_as_username cannot be used with enable_proxy_protocol 2")]
    SubjectUsernameWithV2,
    #[error("certfile and keyfile cannot be used with enable_proxy_protocol 2")]
    ListenerTlsWithV2,
    #[error("malformed PROXY header")]
    MalformedHeader,
    #[error("PROXY header exceeds the size limit")]
    TooLong,
    #[error("malformed PROXY v2 TLV")]
    MalformedTlv,
    #[error("malformed UTF-8 in PROXY v2 SSL sub-TLV {kind:#04x}: {source}")]
    InvalidTlsString {
        kind: u8,
        #[source]
        source: mqx_codec::Utf8Error,
    },
    #[error("duplicate PROXY v2 SSL common name")]
    DuplicateCommonName,
    #[error("the listener requires a PROXY v2 TLS indication")]
    TlsRequired,
    #[error("the listener requires a PROXY v2 verified client certificate")]
    CertificateRequired,
    /// A PROXY v2 header named its source but its TLVs or TLS policy were
    /// rejected. Only [`read_proxy_header`] returns this.
    #[error("PROXY v2 connection rejected: {reason}")]
    Rejected {
        addresses: ProxyAddresses,
        reason: Box<ProxyError>,
    },
    #[cfg(feature = "tokio")]
    #[error("reading PROXY header: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one header at the start of a cumulative buffer, returning the
/// unconsumed bytes. `Ok(None)` means keep all the bytes and retry with more.
///
/// Framing is independent of how TCP fragments the input, unlike Mosquitto's
/// socket readers (`src/proxy_v1.c:proxy_v1__read`,
/// `src/proxy_v2.c:proxy_v2__read`), which can reject short reads or overwrite
/// earlier bytes. The caller enforces the pre-CONNECT deadline.
pub fn parse_proxy_header(
    input: &[u8],
    options: impl Into<ProxyOptions>,
) -> Result<Option<(ProxyInfo, &[u8])>, ProxyError> {
    let options = options.into();
    match options.version {
        ProxyVersion::V1 => v1::parse(input),
        ProxyVersion::V2 => v2::parse(input, options),
    }
}

/// Reads one header, preserving any bytes read beyond it. The caller owns
/// the stream and enforces [`PROXY_HEADER_TIMEOUT`].
#[cfg(feature = "tokio")]
pub async fn read_proxy_header<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    options: impl Into<ProxyOptions>,
) -> Result<(ProxyInfo, bytes::Bytes), ProxyError> {
    use std::io::ErrorKind;
    use tokio::io::AsyncReadExt;

    let mut buffer = [0; v2::MAX_FRAMED_LEN];
    let mut filled = 0;
    let options = options.into();
    while filled < buffer.len() {
        let read = stream.read(&mut buffer[filled..]).await?;
        if read == 0 {
            return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into());
        }
        filled += read;
        match parse_proxy_header(&buffer[..filled], options) {
            Ok(Some((info, leftover))) => {
                return Ok((info, bytes::Bytes::copy_from_slice(leftover)));
            }
            Ok(None) => {}
            Err(
                reason @ (ProxyError::MalformedTlv
                | ProxyError::InvalidTlsString { .. }
                | ProxyError::DuplicateCommonName
                | ProxyError::TlsRequired
                | ProxyError::CertificateRequired),
            ) => {
                return Err(match v2::rejected_addresses(&buffer[..filled]) {
                    Some(addresses) => ProxyError::Rejected {
                        addresses,
                        reason: Box::new(reason),
                    },
                    None => reason,
                });
            }
            Err(error) => return Err(error),
        }
    }

    // A full buffer with an incomplete frame can only be LOCAL/UNSPEC.
    // Mosquitto doesn't cap its length; discard the opaque remainder without
    // allocating for it or consuming subsequent MQTT bytes.
    let mut remaining = v2::framed_len(&buffer) - filled;
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..chunk]).await?;
        remaining -= chunk;
    }
    Ok((ProxyInfo::Local, bytes::Bytes::new()))
}

fn c_string(input: &[u8]) -> &[u8] {
    input.split(|&byte| byte == 0).next().unwrap_or_default()
}
