//! The mosquitto-go-auth gRPC back-end and its `grpc/auth.proto` wire types.

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioIo};

use mqx_auth::external::BoxFuture;
use prost::Message;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tokio_rustls::TlsConnector;
use tonic::{
    Request,
    client::Grpc,
    codegen::http::{Uri, uri::PathAndQuery},
    transport::{Channel, Endpoint},
};
use tonic_prost::ProstCodec;
use tower_service::Service;

use crate::{
    backend::LoadError,
    goauth::backend::{Backend, BackendError, Init, Log},
};

#[derive(Clone, PartialEq, Message)]
struct Empty {}

#[derive(Clone, PartialEq, Message)]
struct GetUserRequest {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
    #[prost(string, tag = "3")]
    clientid: String,
}

#[derive(Clone, PartialEq, Message)]
struct GetSuperuserRequest {
    #[prost(string, tag = "1")]
    username: String,
}

#[derive(Clone, PartialEq, Message)]
struct CheckAclRequest {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    topic: String,
    #[prost(string, tag = "3")]
    clientid: String,
    #[prost(int32, tag = "4")]
    acc: i32,
}

#[derive(Clone, PartialEq, Message)]
struct AuthResponse {
    #[prost(bool, tag = "1")]
    ok: bool,
}

#[derive(Clone, PartialEq, Message)]
struct NameResponse {
    #[prost(string, tag = "1")]
    name: String,
}

pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    // grpc.go: NewGRPC does not change the shared log level.
    let option = |key| {
        init.options
            .get(key)
            .map(String::as_str)
            .unwrap_or_default()
    };
    let host = option("grpc_host");
    let port = option("grpc_port");
    if host.is_empty() || port.is_empty() {
        return Err(LoadError::new("grpc must have a host and port"));
    }
    let address = format!("{host}:{port}");
    let mut timeout = 500_i64;
    if let Some(value) = init.options.get("grpc_dial_timeout_ms") {
        match value.parse() {
            Ok(milliseconds) => timeout = milliseconds,
            Err(err) => init.log.warn(format_args!(
                "invalid grpc dial timeout value: strconv.Atoi: parsing {value:?}: {}",
                if matches!(
                    err.kind(),
                    std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
                ) {
                    "value out of range"
                } else {
                    "invalid syntax"
                }
            )),
        }
    }
    let ca = option("grpc_ca_cert");
    let mut endpoint = Endpoint::from_shared(format!("http://{address}")).map_err(load_error)?;
    let mut connector = Connector {
        tcp: HttpConnector::new(),
        tls: None,
        ready: None,
    };
    if ca.is_empty() {
        // grpc.go: setup ignores client certificate options on an insecure channel.
        init.log.warn(format_args!("creating insecure grpc client"));
    } else {
        init.log.info(format_args!("creating grpc client"));
        let tls = tls_config(
            ca,
            option("grpc_tls_cert"),
            option("grpc_tls_key"),
            &init.log,
        )
        .await?;
        connector.tls = Some(tls);
        // The connector performs TLS itself so it can observe the first h2 frame.
        // Keep the real scheme in HTTP/2 :scheme independently of the connector URI.
        endpoint = endpoint.origin(
            format!("https://{address}")
                .parse::<Uri>()
                .map_err(load_error)?,
        );
    }
    // grpc.go: initClient. Only WithBlock waits for the transport to be ready.
    // grpc-go retries a failed connection until the dial context expires.
    let timeout = timeout.wrapping_mul(1_000_000).max(0) as u64;
    if timeout == 0 {
        return Err(LoadError::new("context deadline exceeded"));
    }
    let channel = if option("grpc_fail_on_dial_error") == "true" {
        tokio::time::timeout(Duration::from_nanos(timeout), connect(&endpoint, connector))
            .await
            .map_err(|_| LoadError::new("context deadline exceeded"))?
    } else {
        endpoint.connect_with_connector_lazy(connector)
    };
    // grpc.go: GetName. Registration calls this without an RPC deadline, even
    // with a nonblocking dial. A failed RPC does not fail registration.
    let name = rpc::<_, NameResponse>(channel.clone(), "/grpc.AuthService/GetName", Empty {})
        .await
        .map_or_else(|_| "gRPC".into(), |response| response.name);
    Ok(Box::new(Client {
        channel: Mutex::new(Some(channel)),
        disable_superuser: option("grpc_disable_superuser") == "true",
        name,
        log: init.log,
    }))
}

async fn connect(endpoint: &Endpoint, connector: Connector) -> Channel {
    let mut backoff = Duration::from_secs(1);
    loop {
        let (ready, preface) = oneshot::channel();
        let attempt = Connector {
            tcp: connector.tcp.clone(),
            tls: connector.tls.clone(),
            ready: Some(ready),
        };
        if let Ok(channel) = endpoint.connect_with_connector(attempt).await
            && preface.await.is_ok()
        {
            return channel;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 8 / 5).min(Duration::from_secs(120));
    }
}

async fn tls_config(ca: &str, cert: &str, key: &str, log: &Log) -> Result<TlsConnector, LoadError> {
    // grpc.go: setup uses only the supplied CA pool, not system roots.
    let ca_pem = tokio::fs::read(ca).await.map_err(|err| {
        LoadError::new(format!(
            "could not load grpc ca certificate (grpc_ca_cert) from file ({ca}): {err}"
        ))
    })?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()).filter_map(Result::ok) {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(LoadError::new(
            "append ca cert to pool error. Maybe the ca file (grpc_ca_cert) does not contain a valid x509 certificate",
        ));
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(load_error)?
            .with_root_certificates(roots);
    let mut config = if !cert.is_empty() && !key.is_empty() {
        let load_error =
            |err: &dyn std::fmt::Display| LoadError::new(format!("load x509 keypair error: {err}"));
        let cert = tokio::fs::read(cert)
            .await
            .map_err(|err| load_error(&err))?;
        let key = tokio::fs::read(key).await.map_err(|err| load_error(&err))?;
        let certs = rustls_pemfile::certs(&mut cert.as_slice())
            .collect::<io::Result<Vec<_>>>()
            .map_err(|err| load_error(&err))?;
        let key = rustls_pemfile::private_key(&mut key.as_slice())
            .map_err(|err| load_error(&err))?
            .ok_or_else(|| LoadError::new("load x509 keypair error: no PEM private key"))?;
        config
            .with_client_auth_cert(certs, key)
            .map_err(|err| load_error(&err))?
    } else {
        if !cert.is_empty() || !key.is_empty() {
            log.warn(format_args!("gRPC backend warning: mutual TLS was disabled due to missing client certificate (grpc_tls_cert) or client key (grpc_tls_key)"));
        }
        config.with_no_client_auth()
    };
    config.alpn_protocols.push(b"h2".to_vec());
    Ok(TlsConnector::from(Arc::new(config)))
}

fn load_error(error: impl std::fmt::Display) -> LoadError {
    LoadError::new(error.to_string())
}

struct Connector {
    tcp: HttpConnector,
    tls: Option<TlsConnector>,
    ready: Option<oneshot::Sender<()>>,
}

impl Service<Uri> for Connector {
    type Response = TokioIo<Connection>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tcp.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = self.tls.clone();
        let socket = self.tcp.call(uri.clone());
        let ready = self.ready.take();
        Box::pin(async move {
            let socket = socket.await?.into_inner();
            let stream: Box<dyn Io> = if let Some(tls) = tls {
                let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
                let stream = tls
                    .connect(ServerName::try_from(host.to_owned())?, socket)
                    .await?;
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err("gRPC TLS peer did not negotiate h2".into());
                }
                Box::new(stream)
            } else {
                Box::new(socket)
            };
            Ok(TokioIo::new(Connection {
                stream,
                preface: ready.map(|ready| Preface {
                    ready,
                    header: [0; 9],
                    received: 0,
                }),
            }))
        })
    }
}

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

struct Connection {
    stream: Box<dyn Io>,
    preface: Option<Preface>,
}

struct Preface {
    ready: oneshot::Sender<()>,
    header: [u8; 9],
    received: usize,
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(status) = &result
            && let Some(mut preface) = self.preface.take()
        {
            let bytes = &buf.filled()[start..];
            if status.is_ok() && !bytes.is_empty() {
                // grpc-go internal/transport/http2_client.go: readServerPreface
                // waits for the peer's SETTINGS frame, not just a TCP connection.
                // Observe the frame without consuming it from tonic's HTTP/2 client.
                let header_end = preface.header.len();
                if preface.received < header_end {
                    let n = bytes.len().min(header_end - preface.received);
                    preface.header[preface.received..preface.received + n]
                        .copy_from_slice(&bytes[..n]);
                }
                preface.received += bytes.len();
                let [a, b, c, kind, flags, stream_id @ ..] = preface.header;
                let len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
                if preface.received < header_end {
                    self.preface = Some(preface);
                } else if kind == 4
                    && flags & 1 == 0
                    && stream_id == [0; 4]
                    && len <= 16_384
                    && len.is_multiple_of(6)
                {
                    if preface.received < header_end + len {
                        self.preface = Some(preface);
                    } else {
                        let _ = preface.ready.send(());
                    }
                }
            }
        }
        result
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct Client {
    channel: Mutex<Option<Channel>>,
    disable_superuser: bool,
    name: String,
    log: Log,
}

impl Client {
    async fn authorize(
        &self,
        path: &'static str,
        request: impl Message + 'static,
        check: &str,
    ) -> Result<bool, BackendError> {
        let channel = self
            .channel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| BackendError::new("gRPC client is closed"))?;
        rpc::<_, AuthResponse>(channel, path, request)
            .await
            .map(|response| response.ok)
            .inspect_err(|err| {
                self.log.error(format_args!("grpc {check} error: {err}"));
            })
    }
}

// grpc/auth.proto: AuthService. No timeout metadata is sent (Go uses context.Background).
async fn rpc<I, O>(channel: Channel, path: &'static str, request: I) -> Result<O, BackendError>
where
    I: Message + 'static,
    O: Message + Default + 'static,
{
    let mut client = Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|err| BackendError::new(err.to_string()))?;
    client
        .unary(
            Request::new(request),
            PathAndQuery::from_static(path),
            ProstCodec::<I, O>::default(),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|err| BackendError::new(err.to_string()))
}

impl Backend for Client {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        client_id: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        // grpc.go: GetUser. Go's protobuf marshaler rejects a non-UTF-8 string.
        Box::pin(async move {
            let password =
                std::str::from_utf8(password).map_err(|err| BackendError::new(err.to_string()))?;
            self.authorize(
                "/grpc.AuthService/GetUser",
                GetUserRequest {
                    username: username.into(),
                    password: password.into(),
                    clientid: client_id.into(),
                },
                "get user",
            )
            .await
        })
    }

    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            // grpc.go: GetSuperuser bypasses the RPC when disabled.
            if self.disable_superuser {
                return Ok(false);
            }
            self.authorize(
                "/grpc.AuthService/GetSuperuser",
                GetSuperuserRequest {
                    username: username.into(),
                },
                "get superuser",
            )
            .await
        })
    }

    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        client_id: &'a str,
        acc: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            self.authorize(
                "/grpc.AuthService/CheckAcl",
                CheckAclRequest {
                    username: username.into(),
                    topic: topic.into(),
                    clientid: client_id.into(),
                    acc,
                },
                "check acl",
            )
            .await
        })
    }

    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // grpc.go: Halt sends the RPC before closing the connection.
            let channel = self
                .channel
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(channel) = channel
                && let Err(err) = rpc::<_, Empty>(channel, "/grpc.AuthService/Halt", Empty {}).await
            {
                self.log.error(format_args!("grpc halt: {err}"));
            }
        })
    }
}
