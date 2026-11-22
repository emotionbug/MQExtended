use std::{
    fmt,
    io::{self, IoSlice},
    net::SocketAddr,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use mqx_proxy::{ProxyAddresses, ProxyInfo, ProxyOptions, read_proxy_header};
use mqx_ws::WsOptions;
use openssl::ssl::Ssl;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_openssl::SslStream;

use crate::{
    CertIdentity, TlsConfig,
    tls::{self, ListenerAcceptor},
};

/// MQTT byte stream after any PROXY, TLS, and WebSocket negotiations.
pub struct ConnectionStream(Stream);

pub(crate) enum SocketStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl SocketStream {
    pub(crate) fn set_tcp_nodelay(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nodelay(true),
            #[cfg(unix)]
            Self::Unix(_) => Ok(()),
        }
    }
}

enum Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    Layered(Box<dyn TransportIo>),
}

trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportIo for T {}

impl fmt::Debug for ConnectionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Stream::Tcp(stream) => f.debug_tuple("Tcp").field(stream).finish(),
            #[cfg(unix)]
            Stream::Unix(stream) => f.debug_tuple("Unix").field(stream).finish(),
            Stream::Layered(_) => f.write_str("LayeredStream"),
        }
    }
}

impl ConnectionStream {
    fn tcp(stream: TcpStream) -> Self {
        Self(Stream::Tcp(stream))
    }

    #[cfg(unix)]
    fn unix(stream: UnixStream) -> Self {
        Self(Stream::Unix(stream))
    }

    pub(crate) fn plain(stream: SocketStream) -> Self {
        match stream {
            SocketStream::Tcp(stream) => Self::tcp(stream),
            #[cfg(unix)]
            SocketStream::Unix(stream) => Self::unix(stream),
        }
    }

    /// Returns the socket if no application transport is wrapping it.
    pub fn as_tcp_stream(&self) -> Option<&TcpStream> {
        match &self.0 {
            Stream::Tcp(stream) => Some(stream),
            _ => None,
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
            #[cfg(unix)]
            Stream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
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
            #[cfg(unix)]
            Stream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
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
            #[cfg(unix)]
            Stream::Unix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.0 {
            Stream::Tcp(stream) => stream.is_write_vectored(),
            #[cfg(unix)]
            Stream::Unix(stream) => stream.is_write_vectored(),
            Stream::Layered(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Stream::Unix(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Stream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Stream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Layered(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

pub(crate) enum PeerAddress<'a> {
    Ip(SocketAddr),
    Unix(Box<[u8]>),
    LocalUnix(&'a Path),
}

impl PeerAddress<'_> {
    pub(crate) fn ip(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr) => Some(*addr),
            Self::Unix(_) | Self::LocalUnix(_) => None,
        }
    }
}

impl fmt::Display for PeerAddress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{}:{}", addr.ip(), addr.port()),
            Self::Unix(path) => f.write_str(&String::from_utf8_lossy(path)),
            // Mosquitto src/net.c: net__socket_get_address uses the listener's
            // pathname (getsockname), and net__socket_accept logs remote port 0.
            Self::LocalUnix(path) => write!(f, "{}:0", path.display()),
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
    stream: SocketStream,
    peer: &mut PeerAddress<'_>,
    proxy: Option<ProxyOptions>,
    acceptor: Option<ListenerAcceptor>,
    tls: &TlsConfig,
    ws: Option<&WsOptions>,
) -> Result<Option<(ConnectionStream, CertIdentity)>, NegotiationError> {
    match stream {
        SocketStream::Tcp(stream) => {
            negotiate_stream(
                stream,
                ConnectionStream::tcp,
                peer,
                proxy,
                acceptor,
                tls,
                ws,
            )
            .await
        }
        #[cfg(unix)]
        SocketStream::Unix(stream) => {
            negotiate_stream(
                stream,
                ConnectionStream::unix,
                peer,
                proxy,
                acceptor,
                tls,
                ws,
            )
            .await
        }
    }
}

async fn negotiate_stream<S: TransportIo + 'static>(
    mut stream: S,
    plain: impl FnOnce(S) -> ConnectionStream,
    peer: &mut PeerAddress<'_>,
    proxy: Option<ProxyOptions>,
    acceptor: Option<ListenerAcceptor>,
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
                    // Mosquitto src/handle_connect.c: handle_username_from_cert_options
                    // uses the forwarded CN but still runs basic auth without a local SSL context.
                    if options.uses_forwarded_username() {
                        identity = tls.common_name.map_or(
                            CertIdentity::MissingOrInvalid,
                            CertIdentity::ForwardedUsername,
                        );
                    }
                }
            }
        }
        prefix
    } else {
        Bytes::new()
    };

    let stream = if acceptor.is_none() && ws.is_none() && prefix.is_empty() {
        plain(stream)
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
    acceptor: Option<ListenerAcceptor>,
    tls: &TlsConfig,
    ws: Option<&WsOptions>,
    identity: &mut CertIdentity,
) -> Result<ConnectionStream, NegotiationError> {
    match acceptor {
        Some(ListenerAcceptor::Rustls(acceptor)) => {
            let stream = acceptor
                .accept(stream)
                .await
                .map_err(NegotiationError::Tls)?;
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first());
            *identity = tls::identity(tls, certificate.map(AsRef::as_ref));
            upgrade_websocket(stream, ws).await
        }
        Some(ListenerAcceptor::OpenSsl(context)) => {
            let tls_error = |error| NegotiationError::Tls(io::Error::other(error));
            let ssl = Ssl::new(&context).map_err(tls_error)?;
            let mut stream = SslStream::new(ssl, stream).map_err(tls_error)?;
            Pin::new(&mut stream)
                .accept()
                .await
                .map_err(|error| NegotiationError::Tls(io::Error::other(error)))?;
            let certificate = if tls.use_identity_as_username || tls.use_subject_as_username {
                stream
                    .ssl()
                    .peer_certificate()
                    .map(|cert| cert.to_der())
                    .transpose()
                    .map_err(tls_error)?
            } else {
                None
            };
            *identity = tls::identity(tls, certificate.as_deref());
            upgrade_websocket(stream, ws).await
        }
        None => upgrade_websocket(stream, ws).await,
    }
}

async fn upgrade_websocket(
    stream: impl TransportIo + 'static,
    ws: Option<&WsOptions>,
) -> Result<ConnectionStream, NegotiationError> {
    if let Some(options) = ws {
        Ok(ConnectionStream::layered(
            mqx_ws::accept(stream, options).await?,
        ))
    } else {
        Ok(ConnectionStream::layered(stream))
    }
}

// PROXY over-read bytes must feed the next layer, even if they start a TLS
// ClientHello or a WebSocket HTTP request rather than an MQTT packet.
struct Replay<S> {
    stream: S,
    prefix: Bytes,
}

impl<S: TransportIo> AsyncRead for Replay<S> {
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

impl<S: TransportIo> AsyncWrite for Replay<S> {
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
