use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue};
use hyper::{Method, Request, Uri, Version, client::conn::http1};
use hyper_util::rt::TokioIo;
use openssl::ssl::{SslConnector, SslMethod};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio_openssl::SslStream;

pub(crate) struct Client(Option<SslConnector>);

pub(crate) enum Auth<'a> {
    Basic(&'a str, &'a [u8]),
    Header(&'a str),
}

#[derive(Debug)]
pub(crate) enum Error {
    Url,
    Resolve,
    Connect,
    Tls,
    Verify,
    Send,
    Receive,
    Partial,
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Url => "URL using bad/illegal format or missing URL",
            Self::Resolve => "Could not resolve hostname",
            Self::Connect => "Could not connect to server",
            Self::Tls => "SSL connect error",
            Self::Verify => "SSL peer certificate or SSH remote key was not OK",
            Self::Send => "Failed sending data to the peer",
            Self::Receive => "Failure when receiving data from the peer",
            Self::Partial => "Transferred a partial file",
            Self::Timeout => "Timeout was reached",
        })
    }
}

impl Client {
    pub(crate) fn new(tls: bool) -> Result<Self, openssl::error::ErrorStack> {
        // SslConnector uses OpenSSL's default certificate paths and verifies
        // both the server certificate and the URL hostname (not the Host override).
        Ok(Self(if tls {
            Some(SslConnector::builder(SslMethod::tls_client())?.build())
        } else {
            None
        }))
    }

    // be-http.c and be-jwt.c: http_post create a fresh curl handle, do not
    // follow redirects, and bound each complete transfer to ten seconds.
    pub(crate) async fn post(
        &self,
        url: &str,
        host: Option<&str>,
        auth: Auth<'_>,
        body: String,
    ) -> Result<u16, Error> {
        tokio::time::timeout(Duration::from_secs(10), self.request(url, host, auth, body))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn request(
        &self,
        url: &str,
        host: Option<&str>,
        auth: Auth<'_>,
        body: String,
    ) -> Result<u16, Error> {
        let url = url.parse::<Uri>().map_err(|_| Error::Url)?;
        let authority = url.authority().ok_or(Error::Url)?;
        let authority_host = authority.host();
        let server = authority_host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(authority_host);
        let default_port = if self.0.is_some() { 443 } else { 80 };
        let host_port = authority.as_str().rsplit('@').next().ok_or(Error::Url)?;
        let port = match &host_port[authority_host.len()..] {
            "" | ":" => default_port,
            suffix => suffix
                .strip_prefix(':')
                .and_then(|n| n.parse::<u16>().ok())
                .ok_or(Error::Url)?,
        };
        let target = request_target(&url);
        let target = target.parse::<Uri>().map_err(|_| Error::Url)?;
        let mut request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri(target);
        // curl orders generated Authorization before Accept, but explicit
        // Authorization after Accept. Host can be overridden independently.
        let host = host.map(str::as_bytes).unwrap_or_else(|| {
            if port == default_port {
                authority_host.as_bytes()
            } else {
                host_port.as_bytes()
            }
        });
        if !host.is_empty() {
            request = request.header(HOST, HeaderValue::from_bytes(host).map_err(|_| Error::Url)?);
        }
        let request = match auth {
            Auth::Basic(username, password) => request
                .header(AUTHORIZATION, basic(username, password))
                .header(ACCEPT, "*/*"),
            Auth::Header(value) => request.header(ACCEPT, "*/*").header(AUTHORIZATION, value),
        }
        .header(CONTENT_LENGTH, body.len())
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| Error::Url)?;
        let mut connected = None;
        for addr in lookup_host((server, port))
            .await
            .map_err(|_| Error::Resolve)?
        {
            if let Ok(stream) = TcpStream::connect(addr).await {
                connected = Some(stream);
                break;
            }
        }
        let stream = connected.ok_or(Error::Connect)?;
        if let Some(tls) = &self.0 {
            let ssl = tls
                .configure()
                .and_then(|tls| tls.into_ssl(server))
                .map_err(|_| Error::Tls)?;
            let mut stream = SslStream::new(ssl, stream).map_err(|_| Error::Tls)?;
            if Pin::new(&mut stream).connect().await.is_err() {
                return Err(
                    if stream.ssl().verify_result() == openssl::x509::X509VerifyResult::OK {
                        Error::Tls
                    } else {
                        Error::Verify
                    },
                );
            }
            exchange(stream, request).await
        } else {
            exchange(stream, request).await
        }
    }
}

fn basic(username: &str, password: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut key = Vec::with_capacity(username.len() + password.len() + 1);
    key.extend_from_slice(username.as_bytes());
    key.push(b':');
    key.extend_from_slice(password);
    let mut value = String::with_capacity(6 + key.len().div_ceil(3) * 4);
    value.push_str("Basic ");
    STANDARD.encode_string(key, &mut value);
    value
}

// libcurl removes literal dot segments (not %2e) by default.
fn request_target(url: &Uri) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let Some(target) = url.path_and_query() else {
        return Cow::Borrowed("/");
    };
    let path = target.path();
    if !path.split('/').any(|part| matches!(part, "." | "..")) {
        return Cow::Borrowed(target.as_str());
    }
    let mut normalized = String::with_capacity(target.as_str().len());
    let mut parts = path[1..].split('/').peekable();
    while let Some(part) = parts.next() {
        match part {
            "." => (),
            ".." => {
                if let Some(at) = normalized.rfind('/') {
                    normalized.truncate(at);
                }
            }
            part => {
                normalized.push('/');
                normalized.push_str(part);
            }
        }
        if parts.peek().is_none() && matches!(part, "." | "..") {
            normalized.push('/');
        }
    }
    if let Some(query) = target.query() {
        normalized.push('?');
        normalized.push_str(query);
    }
    Cow::Owned(normalized)
}

async fn exchange(
    stream: impl AsyncRead + AsyncWrite + Send + Unpin + 'static,
    request: Request<Full<Bytes>>,
) -> Result<u16, Error> {
    let (mut sender, connection) = http1::Builder::new()
        .title_case_headers(true)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| Error::Send)?;
    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| Error::Receive)?;
        let status = response.status().as_u16();
        // curl_easy_perform completes the transfer before checking status.
        // Drain it without buffering it (curl's default also writes to stdout).
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            frame.map_err(|_| Error::Partial)?;
        }
        Ok(status)
    };
    tokio::pin!(exchange);
    tokio::pin!(connection);
    tokio::select! {
        biased;
        result = &mut exchange => result,
        _ = &mut connection => exchange.await,
    }
}
