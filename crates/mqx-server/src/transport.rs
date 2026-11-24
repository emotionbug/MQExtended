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
    /// With the PROXY v1 source token as sent, if any.
    Ip(SocketAddr, Option<Box<str>>),
    Unix(Box<[u8]>),
    LocalUnix(&'a Path),
}

impl PeerAddress<'_> {
    pub(crate) fn ip(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr, _) => Some(*addr),
            Self::Unix(_) | Self::LocalUnix(_) => None,
        }
    }

    /// Mosquitto's `context->address` when it is not the inet_ntop form of
    /// [`Self::ip`]: a PROXY v1 source token or a Unix socket path.
    pub(crate) fn text(&self) -> Option<String> {
        match self {
            Self::Ip(_, text) => text.as_deref().map(str::to_owned),
            Self::Unix(path) => Some(String::from_utf8_lossy(path).into_owned()),
            Self::LocalUnix(path) => Some(path.display().to_string()),
        }
    }
}

impl fmt::Display for PeerAddress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Mosquitto src/proxy_v1.c keeps the v1 source token; lib/net_mosq.c
            // and src/proxy_v2.c format binary addresses with inet_ntop.
            Self::Ip(addr, Some(text)) => write!(f, "{text}:{}", addr.port()),
            Self::Ip(addr, None) => {
                write!(f, "{}:{}", mqx_broker::inet_ntop(addr.ip()), addr.port())
            }
            // Mosquitto src/proxy_v2.c: proxy_v2__read stores a proxied Unix
            // source with remote_port 0, and logs print "%s:%d".
            Self::Unix(path) => write!(f, "{}:0", String::from_utf8_lossy(path)),
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

/// Mosquitto's notices for a refused PROXY header. They are not gated on
/// connection_messages; short reads and v2 framing errors are silent.
fn log_proxy_rejection(options: ProxyOptions, error: &mqx_proxy::ProxyError) {
    use mqx_proxy::{ProxyError, ProxyVersion};

    match (options.version, error) {
        // Mosquitto src/proxy_v1.c: proxy_v1__decode and proxy_v1__read.
        (ProxyVersion::V1, ProxyError::MalformedHeader | ProxyError::TooLong) => {
            tracing::info!(target: "mqx::notice", "Connection rejected, corrupt PROXY header.");
        }
        // Mosquitto src/proxy_v2.c: proxy_v2__read.
        (ProxyVersion::V2, ProxyError::Rejected { addresses, reason }) => {
            let peer = match addresses {
                ProxyAddresses::Ip {
                    source,
                    source_text,
                    ..
                } => PeerAddress::Ip(*source, source_text.clone()),
                ProxyAddresses::Unix { source, .. } => PeerAddress::Unix(source.clone()),
            };
            let why = match **reason {
                ProxyError::TlsRequired => "client did not connect using TLS",
                ProxyError::CertificateRequired => "client did not provide a certificate",
                _ => "corrupt PROXY header",
            };
            tracing::info!(target: "mqx::notice", "Connection from {peer} rejected, {why}.");
        }
        _ => {}
    }
}

/// A negotiated transport. `tls` is the version and OpenSSL cipher name of a
/// TLS session this listener terminated itself.
pub(crate) type Negotiated = (ConnectionStream, CertIdentity, Option<(String, String)>);

pub(crate) async fn negotiate(
    stream: SocketStream,
    peer: &mut PeerAddress<'_>,
    proxy: Option<ProxyOptions>,
    acceptor: Option<ListenerAcceptor>,
    tls: &TlsConfig,
    ws: Option<&WsOptions>,
) -> Result<Option<Negotiated>, NegotiationError> {
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
) -> Result<Option<Negotiated>, NegotiationError> {
    let mut identity = plain_identity(tls);
    let prefix = if let Some(options) = proxy {
        let (info, prefix) = read_proxy_header(&mut stream, options)
            .await
            .inspect_err(|error| log_proxy_rejection(options, error))?;
        // Mosquitto src/proxy_v2.c: proxy_v2__read; src/proxy_v1.c: proxy_v1__decode.
        // V2 LOCAL is a health check, never an MQTT or WebSocket connection.
        match info {
            ProxyInfo::Local => return Ok(None),
            ProxyInfo::Unknown => (),
            ProxyInfo::Proxied { addresses, tls } => {
                *peer = match addresses {
                    ProxyAddresses::Ip {
                        source,
                        source_text,
                        ..
                    } => PeerAddress::Ip(source, source_text),
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

    let mut session = None;
    let stream = if acceptor.is_none() && ws.is_none() && prefix.is_empty() {
        plain(stream)
    } else if prefix.is_empty() {
        upgrade(stream, acceptor, tls, ws, &mut identity, &mut session).await?
    } else {
        let stream = Replay { stream, prefix };
        upgrade(stream, acceptor, tls, ws, &mut identity, &mut session).await?
    };
    Ok(Some((stream, identity, session)))
}

async fn upgrade<S: TransportIo + 'static>(
    stream: S,
    acceptor: Option<ListenerAcceptor>,
    tls: &TlsConfig,
    ws: Option<&WsOptions>,
    identity: &mut CertIdentity,
    session: &mut Option<(String, String)>,
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
            *session = stream
                .get_ref()
                .1
                .negotiated_cipher_suite()
                .and_then(tls::rustls_session);
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
            let certificate = stream
                .ssl()
                .peer_certificate()
                .map(|cert| cert.to_der())
                .transpose()
                .map_err(tls_error)?;
            *identity = tls::identity(tls, certificate.as_deref());
            // src/handle_connect.c: SSL_get_cipher_version and SSL_get_cipher_name.
            *session = stream
                .ssl()
                .current_cipher()
                .map(|cipher| (cipher.version().to_owned(), cipher.name().to_owned()));
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

#[cfg(test)]
mod tests {
    use super::PeerAddress;

    #[test]
    fn proxied_unix_source_is_shown_with_port_zero() {
        let peer = PeerAddress::Unix(b"/tmp/sock".to_vec().into_boxed_slice());
        assert_eq!(peer.to_string(), "/tmp/sock:0");
    }
}
