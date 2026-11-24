//! HTTP requests made by go-auth's HTTP and remote JWT back-ends.

use std::{
    fmt,
    io::Read,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Uri,
    header::{
        ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST,
        HeaderValue, LOCATION, REFERER, USER_AGENT,
    },
};
use hyper_util::{
    client::legacy::{
        Client as HyperClient,
        connect::{Connected, Connection, HttpConnector},
    },
    rt::{TokioExecutor, TokioIo},
};
use mqx_auth::external::BoxFuture;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tower_service::Service;

use crate::backend::LoadError;
use crate::goauth::backend::{Backend, BackendError, Init, Log};

pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    init.log.set_level(init.log.level()); // http.go: NewHTTP
    Ok(Box::new(Http(Endpoint::new(&init, Mode::Http, false)?)))
}

struct Http(Endpoint);

impl Backend for Http {
    fn name(&self) -> String {
        "HTTP".into()
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        client_id: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        // http.go: GetUser. json.Marshal and Values.Encode sort map keys.
        Box::pin(async move {
            self.0
                .request(
                    &self.0.host,
                    &self.0.user_uri,
                    username,
                    None,
                    Some(&[
                        ("clientid", Param::text(client_id)),
                        ("password", Param::String(password)),
                        ("username", Param::text(username)),
                    ]),
                )
                .await
        })
    }

    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            // http.go: GetSuperuser
            if self.0.superuser_uri.is_empty() {
                return Ok(false);
            }
            self.0
                .request(
                    &self.0.host,
                    &self.0.superuser_uri,
                    username,
                    None,
                    Some(&[("username", Param::text(username))]),
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
        // http.go: CheckAcl
        Box::pin(async move {
            self.0
                .request(
                    &self.0.host,
                    &self.0.acl_uri,
                    username,
                    None,
                    Some(&[
                        ("acc", Param::Int(acc)),
                        ("clientid", Param::text(client_id)),
                        ("topic", Param::text(topic)),
                        ("username", Param::text(username)),
                    ]),
                )
                .await
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Http,
    Jwt,
}

#[derive(Clone, Copy)]
enum ResponseMode {
    Status,
    Text,
    Json,
}

pub(super) struct Endpoint {
    mode: Mode,
    pub(super) host: String,
    pub(super) whitelist: Vec<String>,
    port: String,
    pub(super) user_uri: String,
    pub(super) superuser_uri: String,
    pub(super) acl_uri: String,
    user_agent: String,
    tls: bool,
    form: bool,
    method: Method,
    response: ResponseMode,
    timeout: i64,
    client: HyperClient<Connector, Full<Bytes>>,
    log: Log,
}

impl Endpoint {
    // http.go: NewHTTP; jwt_remote.go: NewRemoteJWTChecker.
    pub(super) fn new(init: &Init<'_>, mode: Mode, parse_token: bool) -> Result<Self, LoadError> {
        let (prefix, title, method_key, timeout_key) = match mode {
            Mode::Http => ("http", "HTTP", "http_method", "http_timeout"),
            Mode::Jwt => ("jwt", "JWT", "jwt_http_method", "jwt_http_timeout"),
        };
        let option = |name| {
            init.options
                .get(&format!("{prefix}_{name}"))
                .map(String::as_str)
        };
        let mut missing = String::new();
        let mut required = |key| {
            option(key).unwrap_or_else(|| {
                use fmt::Write as _;
                let _ = write!(missing, " {prefix}_{key}");
                ""
            })
        };
        let user_uri = required("getuser_uri");
        let acl_uri = required("aclcheck_uri");
        let host = if parse_token {
            option("host").unwrap_or_default()
        } else {
            required("host")
        };
        let mut whitelist = Vec::new();
        if mode == Mode::Jwt {
            if let Some(value) = option("host_whitelist") {
                if value == "*" {
                    init.log.warn(format_args!("Backend host whitelisting is turned off. This is not secure and should not be used in the production environment"));
                    whitelist.push(value.into());
                } else {
                    for host in value.split(',').map(str::trim) {
                        if !valid_whitelist_host(host) {
                            return Err(LoadError::new(format!(
                                "JWT backend error: bad host {host} in jwt_host_whitelist"
                            )));
                        }
                        whitelist.push(host.into());
                    }
                }
            } else if host.is_empty() {
                required("host_whitelist");
            }
        }
        let port = required("port");
        let read_timeout = || {
            init.options
                .get(timeout_key)
                .map_or(5, |value| match value.parse::<i64>() {
                    Ok(seconds) => seconds,
                    Err(err) => {
                        init.log.error(format_args!(
                            "unable to parse timeout: strconv.Atoi: parsing {value:?}: {}",
                            if matches!(
                                err.kind(),
                                std::num::IntErrorKind::PosOverflow
                                    | std::num::IntErrorKind::NegOverflow
                            ) {
                                "value out of range"
                            } else {
                                "invalid syntax"
                            }
                        ));
                        5
                    }
                })
        };
        let timeout = if mode == Mode::Http || missing.is_empty() {
            read_timeout()
        } else {
            5
        };
        if !missing.is_empty() {
            return Err(LoadError::new(format!(
                "{title} backend error: missing remote options: {missing}"
            )));
        }
        let tls = option("with_tls") == Some("true");
        let verify = option("verify_peer") == Some("true");
        let connector = Connector::new(verify).map_err(|err| LoadError::new(err.to_string()))?;
        let mut client = HyperClient::builder(TokioExecutor::new());
        client.http1_title_case_headers(true);
        if !verify {
            // A Go Transport literal has zero IdleConnTimeout (DefaultTransport uses 90s).
            client.pool_idle_timeout(None);
        }
        Ok(Self {
            mode,
            host: host.into(),
            whitelist,
            port: port.into(),
            user_uri: user_uri.into(),
            superuser_uri: option("superuser_uri").unwrap_or_default().into(),
            acl_uri: acl_uri.into(),
            user_agent: option("user_agent")
                .map_or_else(|| format!("mosquitto-{}", init.version), str::to_owned),
            tls,
            form: option("params_mode") == Some("form"),
            method: match init.options.get(method_key).map(String::as_str) {
                Some("GET") => Method::GET,
                Some("PUT") => Method::PUT,
                _ => Method::POST,
            },
            response: match option("response_mode") {
                Some("text") => ResponseMode::Text,
                Some("json") => ResponseMode::Json,
                _ => ResponseMode::Status,
            },
            timeout,
            client: client.build(connector),
            log: init.log.clone(),
        })
    }

    // http.go: httpRequest; jwt_remote.go: jwtRequest.
    pub(super) async fn request(
        &self,
        host: &str,
        path: &str,
        subject: &str,
        token: Option<&str>,
        params: Option<&[(&str, Param<'_>)]>,
    ) -> Result<bool, BackendError> {
        let scheme = if self.tls { "https" } else { "http" };
        let port = !self.port.is_empty() && (self.mode == Mode::Http || !host.contains(':'));
        let url = if port {
            format!("{scheme}://{host}:{}{path}", self.port)
        } else {
            format!("{scheme}://{host}{path}")
        };
        let mut method = self.method.clone();
        let user_agent = if self.form && self.mode == Mode::Http {
            if method == Method::GET {
                self.log.error(format_args!(
                    "error form param only supported for POST/PUT."
                ));
                return Err(BackendError::new(
                    "form only supported for POST/PUT, error code: 500",
                ));
            }
            // http.go: httpRequest calls PostForm, not NewRequest, even for PUT.
            method = Method::POST;
            "Go-http-client/1.1"
        } else {
            &self.user_agent
        };
        let body = Bytes::from(encode(params, self.form));
        let content_type = if self.form {
            "application/x-www-form-urlencoded"
        } else {
            "application/json"
        };
        let url = parse_uri(&url)?;
        let request = self.exchange(url, method, body, user_agent, content_type, token);
        // Go's Client.Timeout bounds redirects and the complete body read. A
        // non-positive time.Duration disables it.
        let timeout = self.timeout.wrapping_mul(1_000_000_000);
        let result = if timeout > 0 {
            tokio::time::timeout(Duration::from_nanos(timeout as u64), request)
                .await
                .unwrap_or_else(|_| Err(BackendError::new("Client.Timeout exceeded")))
        } else {
            request.await
        };
        let (status, body) = result.inspect_err(|err| {
            let prefix = if self.mode == Mode::Http {
                "http request error"
            } else {
                "error"
            };
            self.log.error(format_args!("{prefix}: {err}"));
        })?;
        if !(200..300).contains(&status) {
            self.log.info(format_args!("error code: {status}"));
            return if status >= 500 {
                Err(BackendError::new(format!("error code: {status}")))
            } else {
                Ok(false)
            };
        }
        match self.response {
            ResponseMode::Text if body != b"ok"[..] => {
                self.log.info(format_args!(
                    "api error: {}",
                    String::from_utf8_lossy(&body)
                ));
                return Ok(false);
            }
            ResponseMode::Json => {
                let reply: Reply = serde_json::from_slice(&body).map_err(|err| {
                    self.log.error(format_args!("unmarshal error: {err}"));
                    wire_error(err)
                })?;
                if !reply.ok {
                    self.log.info(format_args!("api error: {}", reply.error));
                    return Ok(false);
                }
            }
            _ => {}
        }
        let label = if self.mode == Mode::Http {
            "http"
        } else {
            "jwt"
        };
        self.log
            .debug(format_args!("{label} request approved for {subject}"));
        Ok(true)
    }

    async fn exchange(
        &self,
        mut url: Uri,
        mut method: Method,
        body: Bytes,
        user_agent: &str,
        content_type: &'static str,
        token: Option<&str>,
    ) -> Result<(u16, Bytes), BackendError> {
        let mut authorization = token.map(|token| format!("Bearer {token}"));
        let mut referer = None;
        let mut has_body = true;
        let origin = url.host().unwrap_or_default().to_ascii_lowercase();
        // net/http/client.go: redirectBehavior, defaultCheckRedirect, refererForURL.
        for hop in 0..10 {
            let data = if has_body { body.clone() } else { Bytes::new() };
            let mut request = Request::builder().method(method.clone()).uri(url.clone());
            if let Some(host) = url.authority() {
                request = request.header(HOST, host.as_str());
            }
            if !user_agent.is_empty() {
                request = request.header(USER_AGENT, user_agent.trim_matches([' ', '\t']));
            }
            if !data.is_empty() || method == Method::POST || method == Method::PUT {
                request = request.header(CONTENT_LENGTH, data.len());
            }
            request = request.header(ACCEPT_ENCODING, "gzip");
            if let Some(auth) = &authorization {
                request = request.header(AUTHORIZATION, auth.trim_matches([' ', '\t']));
            }
            request = request.header(CONTENT_TYPE, content_type);
            if let Some(previous) = &referer {
                request = request.header(REFERER, previous);
            }
            let response = self
                .client
                .request(request.body(Full::new(data)).map_err(wire_error)?)
                .await
                .map_err(wire_error)?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308)
                && let Some(location) = response
                    .headers()
                    .get(LOCATION)
                    .filter(|location| !location.is_empty())
            {
                if hop == 9 {
                    return Err(BackendError::new("stopped after 10 redirects"));
                }
                let next = redirect_uri(&url, location)?;
                referer = if url.scheme_str() == Some("https") && next.scheme_str() == Some("http")
                {
                    None
                } else {
                    Some(url.to_string())
                };
                let next_host = next.host().unwrap_or_default().to_ascii_lowercase();
                if next_host != origin
                    && !next_host
                        .strip_suffix(&origin)
                        .is_some_and(|prefix| prefix.ends_with('.'))
                {
                    authorization = None;
                }
                if matches!(status, 301..=303) {
                    method = Method::GET;
                    has_body = false;
                }
                // The Go client reads up to 2 KiB to keep the preceding connection reusable.
                if response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
                    .is_none_or(|len| len <= 2048)
                {
                    let mut body = response.into_body();
                    let mut seen = 0;
                    while let Some(Ok(frame)) = body.frame().await {
                        if let Some(data) = frame.data_ref() {
                            seen += data.len();
                            if seen >= 2048 {
                                break;
                            }
                        }
                    }
                }
                url = next;
                continue;
            }
            let gzip = response
                .headers()
                .get(CONTENT_ENCODING)
                .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(wire_error)?
                .to_bytes();
            return if gzip {
                let mut decoded = Vec::new();
                flate2::read::MultiGzDecoder::new(body.as_ref())
                    .read_to_end(&mut decoded)
                    .map_err(wire_error)?;
                Ok((status, decoded.into()))
            } else {
                Ok((status, body))
            };
        }
        unreachable!("ten-hop redirect limit checked in loop")
    }
}

fn valid_whitelist_host(host: &str) -> bool {
    // jwt_remote.go: NewRemoteJWTChecker, including the three-byte minimum.
    let (name, port) = host
        .split_once(':')
        .map_or((host, None), |(name, port)| (name, Some(port)));
    let name = name.as_bytes();
    name.len() >= 3
        && name[0].is_ascii_alphanumeric()
        && name[name.len() - 1].is_ascii_alphanumeric()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        && port.is_none_or(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_uri(raw: &str) -> Result<Uri, BackendError> {
    // net/url/url.go: Parse, EscapedPath. Don't normalize a literal dot segment
    // on an initial request or rewrite an already valid RawPath.
    let bad = || BackendError::new("invalid HTTP URL");
    if raw.bytes().any(|b| b.is_ascii_control()) {
        return Err(bad());
    }
    let raw = raw.split_once('#').map_or(raw, |(head, _)| head);
    let (scheme, tail) = raw.split_once("://").ok_or_else(bad)?;
    let at = tail.find(['/', '?']).unwrap_or(tail.len());
    let (host, path) = tail.split_at(at);
    let host = host.strip_suffix(':').unwrap_or(host);
    let (path, query) = path
        .split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)));
    let is_unreserved = |b: u8| b.is_ascii_alphanumeric() || b"-_.~".contains(&b);
    let is_path = |b: u8| is_unreserved(b) || b"$&+,/:;=@".contains(&b);
    let mut escaped = String::new();
    let path = if path.bytes().all(|b| is_path(b) || b"!%'()*[]".contains(&b)) {
        for (i, b) in path.bytes().enumerate() {
            if b == b'%'
                && !path
                    .as_bytes()
                    .get(i + 1..i + 3)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return Err(bad());
            }
        }
        path
    } else {
        for (i, b) in path.bytes().enumerate() {
            if b == b'%'
                && !path
                    .as_bytes()
                    .get(i + 1..i + 3)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return Err(bad());
            }
        }
        let mut buffer = Vec::with_capacity(path.len());
        for b in percent_encoding::percent_decode_str(path) {
            if is_path(b) {
                buffer.push(b);
            } else {
                append_percent(&mut buffer, b);
            }
        }
        // All bytes in buffer are ASCII (escaped path).
        escaped.push_str(std::str::from_utf8(&buffer).map_err(wire_error)?);
        &escaped
    };
    let path = if path.is_empty() { "/" } else { path };
    let path_and_query = if let Some(query) = query {
        format!("{path}?{query}")
    } else {
        path.to_owned()
    };
    Uri::builder()
        .scheme(scheme)
        .authority(host)
        .path_and_query(path_and_query)
        .build()
        .map_err(wire_error)
}

fn redirect_uri(base: &Uri, location: &HeaderValue) -> Result<Uri, BackendError> {
    // ResolveReference treats relative URLs against the previous request URL.
    let base = url::Url::parse(&base.to_string()).map_err(wire_error)?;
    let next = base
        .join(location.to_str().map_err(wire_error)?)
        .map_err(wire_error)?;
    parse_uri(next.as_str())
}

fn wire_error(error: impl fmt::Display) -> BackendError {
    BackendError::new(error.to_string())
}

type WireError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct Connector {
    tcp: HttpConnector,
    tls: SslConnector,
    verify: bool,
}

impl Connector {
    fn new(verify: bool) -> Result<Self, openssl::error::ErrorStack> {
        let mut tcp = HttpConnector::new();
        tcp.enforce_http(false);
        // DefaultTransport sets the Dialer timeout; a literal Transport doesn't.
        if verify {
            tcp.set_connect_timeout(Some(Duration::from_secs(30)));
        }
        let mut tls = SslConnector::builder(SslMethod::tls_client())?;
        if verify {
            // DefaultTransport advertises h2; the custom Go transport does not.
            tls.set_alpn_protos(b"\x02h2\x08http/1.1")?;
        } else {
            tls.set_verify(SslVerifyMode::NONE);
        }
        Ok(Self {
            tcp,
            tls: tls.build(),
            verify,
        })
    }
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl Io for TcpStream {}
impl Io for SslStream<TcpStream> {}

struct ConnectedIo {
    stream: TokioIo<Box<dyn Io>>,
    h2: bool,
}

impl Connection for ConnectedIo {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if self.h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl hyper::rt::Read for ConnectedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for ConnectedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
}

impl Service<Uri> for Connector {
    type Response = ConnectedIo;
    type Error = WireError;
    type Future = BoxFuture<'static, Result<ConnectedIo, WireError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tcp.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.tls.clone();
        let verify = self.verify;
        let socket = self.tcp.call(uri.clone());
        Box::pin(async move {
            let socket = socket.await?.into_inner();
            let mut h2 = false;
            let stream: Box<dyn Io> = match uri.scheme_str() {
                Some("http") => Box::new(socket),
                Some("https") => {
                    let host = uri.host().unwrap_or_default();
                    let host = host
                        .strip_prefix('[')
                        .and_then(|s| s.strip_suffix(']'))
                        .unwrap_or(host);
                    let ssl = connector
                        .configure()?
                        .verify_hostname(verify)
                        .into_ssl(host)?;
                    let mut stream = SslStream::new(ssl, socket)?;
                    if verify {
                        tokio::time::timeout(
                            Duration::from_secs(10),
                            Pin::new(&mut stream).connect(),
                        )
                        .await??;
                    } else {
                        Pin::new(&mut stream).connect().await?;
                    }
                    if stream.ssl().selected_alpn_protocol() == Some(b"h2") {
                        h2 = true;
                    }
                    Box::new(stream)
                }
                _ => return Err("unsupported HTTP scheme".into()),
            };
            Ok(ConnectedIo {
                stream: TokioIo::new(stream),
                h2,
            })
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum Param<'a> {
    String(&'a [u8]),
    Int(i32),
}

impl<'a> Param<'a> {
    pub(super) fn text(text: &'a str) -> Self {
        Self::String(text.as_bytes())
    }
}

fn encode(params: Option<&[(&str, Param<'_>)]>, form: bool) -> Vec<u8> {
    use std::io::Write as _;
    // Go marshals nil maps as null and encodes nil form values as no bytes.
    let Some(params) = params else {
        return if form { Vec::new() } else { b"null".to_vec() };
    };
    let mut output = Vec::new();
    if !form {
        output.push(b'{');
    }
    for (i, (key, value)) in params.iter().enumerate() {
        if i > 0 {
            output.push(if form { b'&' } else { b',' });
        }
        if form {
            // Keys in both back-ends are ASCII identifiers in sorted order.
            output.extend_from_slice(key.as_bytes());
            output.push(b'=');
        } else {
            json_string(&mut output, key.as_bytes());
            output.push(b':');
        }
        match value {
            Param::Int(n) => {
                let _ = write!(output, "{n}");
            }
            Param::String(s) if form => {
                // net/url/url.go: QueryEscape, including '*' vs '~'.
                for &b in *s {
                    match b {
                        b' ' => output.push(b'+'),
                        b'-' | b'_' | b'.' | b'~' => output.push(b),
                        b if b.is_ascii_alphanumeric() => output.push(b),
                        b => append_percent(&mut output, b),
                    }
                }
            }
            Param::String(s) => json_string(&mut output, s),
        }
    }
    if !form {
        output.push(b'}');
    }
    output
}

fn append_percent(output: &mut Vec<u8>, b: u8) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    output.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
}

fn json_string(output: &mut Vec<u8>, bytes: &[u8]) {
    // encoding/json/encode.go: appendString escapes HTML and JS separators
    // and emits one replacement per invalid UTF-8 byte.
    const HEX: &[u8] = b"0123456789abcdef";
    output.push(b'"');
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => output.extend_from_slice(b"\\\""),
                '\\' => output.extend_from_slice(b"\\\\"),
                '\n' => output.extend_from_slice(b"\\n"),
                '\r' => output.extend_from_slice(b"\\r"),
                '\t' => output.extend_from_slice(b"\\t"),
                '\u{8}' => output.extend_from_slice(b"\\b"),
                '\u{c}' => output.extend_from_slice(b"\\f"),
                '\u{2028}' => output.extend_from_slice(b"\\u2028"),
                '\u{2029}' => output.extend_from_slice(b"\\u2029"),
                c @ ('\0'..='\u{1f}' | '<' | '>' | '&') => {
                    let n = c as usize;
                    output.extend_from_slice(&[b'\\', b'u', b'0', b'0', HEX[n >> 4], HEX[n & 15]]);
                }
                c => output.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
            }
        }
        for _ in chunk.invalid() {
            output.extend_from_slice(b"\\ufffd");
        }
    }
    output.push(b'"');
}

#[derive(Default)]
struct Reply {
    ok: bool,
    error: String,
}

impl<'de> serde::Deserialize<'de> for Reply {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Reply;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an HTTP response object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Reply, E> {
                Ok(Reply::default())
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Reply, M::Error> {
                let mut reply = Reply::default();
                // encoding/json/decode.go: object folds field names; null does
                // not overwrite either Go scalar field, but duplicates do.
                while let Some(key) = map.next_key::<String>()? {
                    if key.eq_ignore_ascii_case("ok") {
                        if let Some(value) = map.next_value::<Option<bool>>()? {
                            reply.ok = value;
                        }
                    } else if key.eq_ignore_ascii_case("error") {
                        if let Some(value) = map.next_value::<Option<String>>()? {
                            reply.error = value;
                        }
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(reply)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
