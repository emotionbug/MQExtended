use std::{
    fmt,
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use mqx_proxy::{ProxyAddresses, ProxyInfo, ProxyOptions, read_proxy_header};
use mqx_ws::WsOptions;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

use crate::{CertIdentity, TlsConfig};

/// MQTT byte stream after any PROXY, TLS, and WebSocket negotiations.
pub struct ConnectionStream(Stream);

enum Stream {
    Tcp(TcpStream),
    Layered(Box<dyn TransportIo>),
}

trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportIo for T {}

impl fmt::Debug for ConnectionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Stream::Tcp(stream) => f.debug_tuple("Tcp").field(stream).finish(),
            Stream::Layered(_) => f.write_str("LayeredStream"),
        }
    }
}

impl ConnectionStream {
    pub(crate) fn tcp(stream: TcpStream) -> Self {
        Self(Stream::Tcp(stream))
    }

    /// Returns the socket if no application transport is wrapping it.
    pub fn as_tcp_stream(&self) -> Option<&TcpStream> {
        match &self.0 {
            Stream::Tcp(stream) => Some(stream),
            Stream::Layered(_) => None,
        }
    }

    fn layered(stream: impl TransportIo + 'static) -> Self {
        Self(Stream::Layered(Box::new(stream)))
    }
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.0 {
            Stream::Tcp(stream) => stream.is_write_vectored(),
            Stream::Layered(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

pub(crate) enum PeerAddress {
    Ip(SocketAddr),
    Unix(Box<[u8]>),
}

impl PeerAddress {
    pub(crate) fn ip(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr) => Some(*addr),
            Self::Unix(_) => None,
        }
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => fmt::Display::fmt(addr, f),
            Self::Unix(path) => f.write_str(&String::from_utf8_lossy(path)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NegotiationError {
    #[error("PROXY handshake failed: {0}")]
    Proxy(#[from] mqx_proxy::ProxyError),
    #[error("TLS handshake failed: {0}")]
    Tls(#[source] io::Error),
    #[error("WebSocket handshake failed: {0}")]
    Websocket(#[from] mqx_ws::WsError),
}

pub(crate) fn plain_identity(tls: &TlsConfig) -> CertIdentity {
    // Mosquitto src/handle_connect.c: handle_username_from_cert_options.
    if tls.require_certificate && tls.use_identity_as_username {
        CertIdentity::MissingOrInvalid
    } else {
        CertIdentity::None
    }
}

pub(crate) async fn negotiate(
    mut stream: TcpStream,
    peer: &mut PeerAddress,
    proxy: Option<ProxyOptions>,
    acceptor: Option<TlsAcceptor>,
    tls: &TlsConfig,
    ws: Option<&WsOptions>,
) -> Result<Option<(ConnectionStream, CertIdentity)>, NegotiationError> {
    let mut identity = plain_identity(tls);
    let prefix = if let Some(options) = proxy {
        let (info, prefix) = read_proxy_header(&mut stream, options).await?;
        // Mosquitto src/proxy_v2.c: proxy_v2__read; src/proxy_v1.c: proxy_v1__decode.
        // V2 LOCAL is a health check, never an MQTT or WebSocket connection.
        match info {
            ProxyInfo::Local => return Ok(None),
            ProxyInfo::Unknown => (),
            ProxyInfo::Proxied { addresses, tls } => {
                *peer = match addresses {
                    ProxyAddresses::Ip { source, .. } => PeerAddress::Ip(source),
                    ProxyAddresses::Unix { source, .. } => PeerAddress::Unix(source),
                };
                if let Some(tls) = tls {
                    if let (Some(version), Some(cipher)) = (tls.version, tls.cipher) {
                        tracing::info!(target: "mqx::notice", "Connection from {peer} negotiated {version} cipher {cipher}");
                    }
                    // The PROXY reader enforces require_certificate and validates the CN.
                    if options.uses_forwarded_username() {
                        identity = tls
                            .common_name
                            .map_or(CertIdentity::MissingOrInvalid, CertIdentity::Username);
                    }
                }
            }
        }
        prefix
    } else {
        Bytes::new()
    };

    let stream = if acceptor.is_none() && ws.is_none() && prefix.is_empty() {
        ConnectionStream::tcp(stream)
    } else if prefix.is_empty() {
        upgrade(stream, acceptor, tls, ws, &mut identity).await?
    } else {
        let stream = Replay { stream, prefix };
        upgrade(stream, acceptor, tls, ws, &mut identity).await?
    };
    Ok(Some((stream, identity)))
}

async fn upgrade<S: TransportIo + 'static>(
    stream: S,
    acceptor: Option<TlsAcceptor>,
    tls: &TlsConfig,
    ws: Option<&WsOptions>,
    identity: &mut CertIdentity,
) -> Result<ConnectionStream, NegotiationError> {
    if let Some(acceptor) = acceptor {
        let stream = acceptor
            .accept(stream)
            .await
            .map_err(NegotiationError::Tls)?;
        let certificate = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first());
        *identity = crate::tls::identity(tls, certificate);
        if let Some(options) = ws {
            Ok(ConnectionStream::layered(
                mqx_ws::accept(stream, options).await?,
            ))
        } else {
            Ok(ConnectionStream::layered(stream))
        }
    } else if let Some(options) = ws {
        Ok(ConnectionStream::layered(
            mqx_ws::accept(stream, options).await?,
        ))
    } else {
        Ok(ConnectionStream::layered(stream))
    }
}

// PROXY over-read bytes must feed the next layer, even if they start a TLS
// ClientHello or a WebSocket HTTP request rather than an MQTT packet.
struct Replay {
    stream: TcpStream,
    prefix: Bytes,
}

impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.is_empty() {
            return Pin::new(&mut self.stream).poll_read(cx, buf);
        }
        let len = buf.remaining().min(self.prefix.len());
        buf.put_slice(&self.prefix[..len]);
        self.prefix.advance(len);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
