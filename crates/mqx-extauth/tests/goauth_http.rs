//! `cargo test -p mqx-extauth --test goauth_http -- --ignored`
//! Requires `MOSQUITTO_BUILD_DIR` and `MOSQUITTO_GO_AUTH_SO`.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    future::Future,
    io,
    net::{Ipv4Addr, TcpListener as StdListener},
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use mqx_auth::external::{AclAccess, Binding, Subject, Verdict};
use mqx_extauth::{Library, load};
use prost::Message;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Request, Response, Status,
    body::Body,
    codegen::{StdError, http},
    server::{Grpc, NamedService, UnaryService},
    transport::Server,
};
use tonic_prost::ProstCodec;
use tower_service::Service;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_ID: &str = "wire-client";

fn path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(key).unwrap_or_else(|| panic!("set {key} to run this test")))
}

fn launch_reference(
    options: &[(&str, String)],
) -> (Child, u16, tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let port = StdListener::bind((LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let build = path("MOSQUITTO_BUILD_DIR");
    let so = path("MOSQUITTO_GO_AUTH_SO");
    let config = tempfile::NamedTempFile::new().unwrap();
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut text = format!(
        "listener {port} 127.0.0.1\nauth_plugin {}\nlog_type all\n",
        so.display()
    );
    use std::fmt::Write as _;
    for (key, value) in options {
        writeln!(text, "auth_opt_{key} {value}").unwrap();
    }
    std::fs::write(config.path(), text).unwrap();
    let child = Command::new(build.join("src/mosquitto"))
        .arg("-c")
        .arg(config.path())
        .stdout(Stdio::null())
        .stderr(log.reopen().unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    (child, port, config, log)
}

async fn reference(options: &[(&str, String)]) -> (Child, u16) {
    let (mut child, port, _config, log) = launch_reference(options);
    let ready = tokio::time::timeout(TIMEOUT, async {
        loop {
            if child.try_wait().unwrap().is_some() {
                return false;
            }
            if TcpStream::connect((LOOPBACK, port)).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await;
    assert_eq!(
        ready.ok(),
        Some(true),
        "{}",
        std::fs::read_to_string(log.path()).unwrap()
    );
    (child, port)
}

async fn stop(mut child: Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    assert!(
        tokio::time::timeout(TIMEOUT, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

fn string(packet: &mut Vec<u8>, bytes: &[u8]) {
    packet.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(bytes);
}

async fn send(socket: &mut TcpStream, kind: u8, payload: &[u8]) {
    let mut len = payload.len();
    let mut packet = vec![kind];
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        packet.push(if len > 0 { byte | 0x80 } else { byte });
        if len == 0 {
            break;
        }
    }
    packet.extend_from_slice(payload);
    socket.write_all(&packet).await.unwrap();
}

async fn receive(socket: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    tokio::time::timeout(TIMEOUT, async {
        let kind = match socket.read_u8().await {
            Ok(kind) => kind,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return None;
            }
            Err(err) => panic!("MQTT read: {err}"),
        };
        let mut len = 0;
        for shift in [0, 7, 14, 21] {
            let byte = socket.read_u8().await.unwrap();
            len |= usize::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                let mut msg = vec![0; len];
                socket.read_exact(&mut msg).await.unwrap();
                return Some((kind, msg));
            }
        }
        panic!("bad MQTT length")
    })
    .await
    .expect("reference MQTT response timed out")
}

struct Check<'a> {
    user: &'a str,
    password: &'a [u8],
    connect: Verdict,
    write: Option<(&'a str, Verdict)>,
}

impl Check<'_> {
    async fn reference(&self, port: u16) -> (Verdict, Option<Verdict>) {
        let mut socket = TcpStream::connect((LOOPBACK, port)).await.unwrap();
        let mut connect = b"\0\x04MQTT\x05\xc2\0\x1e\0".to_vec();
        string(&mut connect, CLIENT_ID.as_bytes());
        string(&mut connect, self.user.as_bytes());
        string(&mut connect, self.password);
        send(&mut socket, 0x10, &connect).await;
        let auth = match receive(&mut socket).await {
            Some((0x20, msg)) if msg[1] == 0 => Verdict::Allow,
            Some((0x20, msg)) if msg[1] == 0x87 => Verdict::Deny,
            None | Some((0xe0, _)) => Verdict::Error,
            result => panic!("unexpected CONNACK: {result:?}"),
        };
        let acl = if auth == Verdict::Allow
            && let Some((topic, _)) = self.write
        {
            let mut publish = Vec::new();
            string(&mut publish, topic.as_bytes());
            publish.extend_from_slice(b"\0\x01\0x"); // QoS 1 message id, property length, payload
            send(&mut socket, 0x32, &publish).await;
            Some(match receive(&mut socket).await {
                Some((0x40, msg)) if matches!(msg.get(2).copied().unwrap_or(0), 0 | 0x10) => {
                    Verdict::Allow
                }
                Some((0x40, msg)) if msg[2] == 0x87 => Verdict::Deny,
                None | Some((0xe0, _)) => Verdict::Error,
                result => panic!("unexpected PUBACK: {result:?}"),
            })
        } else {
            None
        };
        (auth, acl)
    }
}

type Capture<T> = Arc<Mutex<Vec<T>>>;

async fn compare<T: std::fmt::Debug + PartialEq>(
    options: &[(&str, String)],
    checks: &[Check<'_>],
    capture: &Capture<T>,
) -> Vec<T> {
    let (child, port) = reference(options).await;
    for check in checks {
        assert_eq!(
            check.reference(port).await,
            (check.connect, check.write.map(|(_, verdict)| verdict)),
            "reference user {}",
            check.user
        );
    }
    stop(child).await;
    let observed = std::mem::take(&mut *capture.lock().unwrap());
    let plugin = tokio::time::timeout(
        TIMEOUT,
        load(
            Library::GoAuth,
            options
                .iter()
                .map(|(k, v)| ((*k).into(), v.clone()))
                .collect(),
            true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    for check in checks {
        assert_eq!(
            plugin
                .authenticate(CLIENT_ID, Some(check.user), Some(check.password))
                .await,
            check.connect,
            "native user {}",
            check.user
        );
        if let Some((topic, verdict)) = check.write {
            let identity = plugin
                .acl_identity(Subject {
                    client_id: CLIENT_ID,
                    username: Some(check.user),
                    binding: Binding::default(),
                })
                .unwrap();
            assert_eq!(
                plugin
                    .authorize(&identity, topic, AclAccess::Write)
                    .await
                    .verdict,
                verdict,
                "native ACL {topic}"
            );
        }
    }
    tokio::time::timeout(TIMEOUT, plugin.halt()).await.unwrap();
    let native = std::mem::take(&mut *capture.lock().unwrap());
    assert_eq!(observed, native);
    observed
}

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn http_exchange(socket: Box<dyn HttpIo>, capture: Capture<HttpRequest>) -> io::Result<()> {
    let mut socket = BufReader::new(socket);
    let mut line = String::new();
    while socket.read_line(&mut line).await? != 0 {
        let mut parts = line.split_ascii_whitespace();
        let method = parts.next().unwrap().into();
        let path: String = parts.next().unwrap().into();
        let mut headers = BTreeMap::new();
        loop {
            line.clear();
            if socket.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line == "\r\n" {
                break;
            }
            let (header, value) = line.split_once(':').unwrap();
            assert_eq!(
                headers.insert(header.to_ascii_lowercase(), value.trim().into()),
                None
            );
        }
        let mut body = vec![
            0;
            headers
                .get("content-length")
                .map_or(0, |v: &String| v.parse().unwrap())
        ];
        socket.read_exact(&mut body).await?;
        let slow = path == "/slow-body";
        let gzip = path == "/gzip";
        let (status, reply, extra) = match path.split('?').next().unwrap() {
            "/super" | "/denied" => ("403 Forbidden", "bad", ""),
            "/error" => ("503 Service Unavailable", "oops", ""),
            "/text" => ("200 OK", "ok", ""),
            "/text-bad" => ("200 OK", "ok\n", ""),
            "/json" | "/a/../json" => (
                "201 Created",
                "{\"OK\":true,\"ok\":null,\"ignored\":[]}",
                "",
            ),
            "/json-bad" => ("200 OK", "{\"ok\":1}", ""),
            "/redirect" => ("302 Found", "", "Location: /status\r\n"),
            _ => ("204 No Content", "", ""),
        };
        let compressed;
        let (status, reply, extra) = if gzip {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(b"ok").unwrap();
            compressed = encoder.finish().unwrap();
            (
                "200 OK",
                compressed.as_slice(),
                "Content-Encoding: gzip\r\n",
            )
        } else if slow {
            ("200 OK", &b"ok"[..], "")
        } else {
            (status, reply.as_bytes(), extra)
        };
        capture.lock().unwrap().push(HttpRequest {
            method,
            path,
            headers,
            body,
        });
        socket
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}\r\n",
                    reply.len()
                )
                .as_bytes(),
            )
            .await?;
        if slow {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        socket.write_all(reply).await?;
        line.clear();
    }
    Ok(())
}

trait HttpIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> HttpIo for T {}

async fn http_server(capture: Capture<HttpRequest>, tls: Option<openssl::ssl::SslAcceptor>) -> u16 {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let capture = capture.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let socket: Box<dyn HttpIo> = if let Some(tls) = tls {
                    let ssl = openssl::ssl::Ssl::new(tls.context()).unwrap();
                    let mut socket = tokio_openssl::SslStream::new(ssl, socket).unwrap();
                    if Pin::new(&mut socket).accept().await.is_err() {
                        return;
                    }
                    Box::new(socket)
                } else {
                    Box::new(socket)
                };
                let _ = http_exchange(socket, capture).await;
            });
        }
    });
    port
}

struct Credential(
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
);

impl Credential {
    fn new(name: &str, ca: Option<&Self>) -> Self {
        use openssl::{
            asn1::{Asn1Integer, Asn1Time},
            hash::MessageDigest,
            pkey::PKey,
            rsa::Rsa,
            x509::{
                X509, X509NameBuilder,
                extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
            },
        };
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(
            &Asn1Integer::from_bn(
                &openssl::bn::BigNum::from_u32(if ca.is_none() {
                    1
                } else if name == "broker" {
                    2
                } else {
                    3
                })
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        cert.set_subject_name(&subject).unwrap();
        cert.set_issuer_name(ca.map_or(&subject, |ca| ca.0.subject_name()))
            .unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if let Some(ca) = ca {
            let usage = ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()
                .unwrap();
            cert.append_extension(usage).unwrap();
            let san = SubjectAlternativeName::new()
                .ip("127.0.0.1")
                .build(&cert.x509v3_context(Some(&ca.0), None))
                .unwrap();
            cert.append_extension(san).unwrap();
        } else {
            cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        }
        cert.sign(ca.map_or(&key, |ca| &ca.1), MessageDigest::sha256())
            .unwrap();
        Self(cert.build(), key)
    }
}

#[tokio::test]
#[ignore = "requires a Mosquitto 2.1.4 build and the go-auth.so reference plugin"]
async fn http_tls_gzip_and_body_timeout() {
    let capture = Capture::default();
    let ca = Credential::new("test CA", None);
    let server = Credential::new("broker", Some(&ca));
    let mut tls =
        openssl::ssl::SslAcceptor::mozilla_intermediate_v5(openssl::ssl::SslMethod::tls()).unwrap();
    tls.set_certificate(&server.0).unwrap();
    tls.set_private_key(&server.1).unwrap();
    let port = http_server(capture.clone(), Some(tls.build())).await;
    let mut opts = http_options(
        port,
        "/gzip",
        "/status",
        &[("http_with_tls", "true"), ("http_response_mode", "text")],
    );
    let mut check = Check {
        user: "tls",
        password: b"p",
        connect: Verdict::Allow,
        write: None,
    };
    let observed = compare(&opts, std::slice::from_ref(&check), &capture).await;
    assert_eq!(observed[0].headers["accept-encoding"], "gzip");
    opts.push(("http_verify_peer", "true".into()));
    check.connect = Verdict::Error;
    assert!(
        compare(&opts, std::slice::from_ref(&check), &capture)
            .await
            .is_empty()
    );

    let port = http_server(capture.clone(), None).await;
    let opts = http_options(port, "/slow-body", "/status", &[("http_timeout", "1")]);
    assert_eq!(compare(&opts, &[check], &capture).await.len(), 1);
}

fn http_options(
    port: u16,
    user: &str,
    acl: &str,
    extra: &[(&'static str, &str)],
) -> Vec<(&'static str, String)> {
    let mut options = vec![
        ("backends", "http".into()),
        ("http_host", LOOPBACK.to_string()),
        ("http_port", port.to_string()),
        ("http_getuser_uri", user.into()),
        ("http_aclcheck_uri", acl.into()),
        ("http_superuser_uri", "/super".into()),
    ];
    options.extend(extra.iter().map(|(key, value)| (*key, (*value).into())));
    options
}

#[tokio::test]
#[ignore = "requires a Mosquitto 2.1.4 build and the go-auth.so reference plugin"]
async fn http_wire_and_verdicts() {
    let capture = Capture::default();
    let port = http_server(capture.clone(), None).await;
    let user = "u<&\"é";
    let password = b"p ~*\xff\xe2\x82\t";
    let allow = Check {
        user,
        password,
        connect: Verdict::Allow,
        write: Some(("demo/é&", Verdict::Allow)),
    };
    let options = http_options(
        port,
        "/a/../json?x=%2f+1",
        "/json",
        &[("http_method", "GET"), ("http_response_mode", "json")],
    );
    let observed = compare(&options, std::slice::from_ref(&allow), &capture).await;
    assert_eq!(
        observed
            .iter()
            .map(|req| req.method.as_str())
            .collect::<Vec<_>>(),
        ["GET", "GET", "GET"]
    );
    assert_eq!(observed[0].path, "/a/../json?x=%2f+1");
    // auth-plugin.c: mosquitto_auth_plugin_init uses the libmosquitto header macros.
    assert_eq!(observed[0].headers["user-agent"], "mosquitto-2.1.0");
    assert_eq!(observed[0].body, r#"{"clientid":"wire-client","password":"p ~*\ufffd\ufffd\ufffd\t","username":"u\u003c\u0026\"é"}"#.as_bytes());
    assert_eq!(observed[2].body, r#"{"acc":2,"clientid":"wire-client","topic":"demo/é\u0026","username":"u\u003c\u0026\"é"}"#.as_bytes());

    let opts = http_options(
        port,
        "/text",
        "/text",
        &[
            ("http_method", "PUT"),
            ("http_params_mode", "form"),
            ("http_user_agent", "ignored"),
            ("http_response_mode", "text"),
        ],
    );
    let observed = compare(&opts, std::slice::from_ref(&allow), &capture).await;
    assert!(
        observed
            .iter()
            .all(|req| req.method == "POST" && req.headers["user-agent"] == "Go-http-client/1.1")
    );
    assert_eq!(
        observed[0].body,
        b"clientid=wire-client&password=p+~%2A%FF%E2%82%09&username=u%3C%26%22%C3%A9"
    );
    let bad_form = http_options(
        port,
        "/status",
        "/status",
        &[("http_method", "GET"), ("http_params_mode", "form")],
    );
    assert!(
        compare(
            &bad_form,
            &[Check {
                user,
                password,
                connect: Verdict::Error,
                write: None
            }],
            &capture
        )
        .await
        .is_empty()
    );

    for (target, response_mode, verdict) in [
        ("/denied", "status", Verdict::Deny),
        ("/error", "status", Verdict::Error),
        ("/text-bad", "text", Verdict::Deny),
        ("/json-bad", "json", Verdict::Error),
    ] {
        let options = http_options(
            port,
            target,
            "/status",
            &[("http_response_mode", response_mode)],
        );
        compare(
            &options,
            &[Check {
                user,
                password,
                connect: verdict,
                write: None,
            }],
            &capture,
        )
        .await;
        let options = http_options(
            port,
            if response_mode == "text" {
                "/text"
            } else if response_mode == "json" {
                "/json"
            } else {
                "/status"
            },
            target,
            &[("http_response_mode", response_mode)],
        );
        compare(
            &options,
            &[Check {
                user,
                password,
                connect: Verdict::Allow,
                write: Some(("topic", verdict)),
            }],
            &capture,
        )
        .await;
    }
    let opts = http_options(
        port,
        "/redirect",
        "/status",
        &[("http_method", "PUT"), ("http_user_agent", "explicit")],
    );
    let observed = compare(
        &opts,
        &[Check {
            user,
            password,
            connect: Verdict::Allow,
            write: None,
        }],
        &capture,
    )
    .await;
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].method, "PUT");
    assert_eq!(observed[1].method, "GET");
    assert!(observed[1].body.is_empty());
}

const JWT_KEY: &str = "go-auth-differential-key-v1";

fn token(claims: serde_json::Value, key: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let mut token = format!("{header}.{claims}.");
    let mut signature = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key.as_bytes()).unwrap();
    signature.update(&token.as_bytes()[..token.len() - 1]);
    URL_SAFE_NO_PAD.encode_string(signature.finalize().into_bytes(), &mut token);
    token
}

fn jwt_options(port: u16) -> Vec<(&'static str, String)> {
    vec![
        ("backends", "jwt".into()),
        ("jwt_mode", "remote".into()),
        ("jwt_host", LOOPBACK.to_string()),
        ("jwt_port", port.to_string()),
        ("jwt_getuser_uri", "/status".into()),
        ("jwt_aclcheck_uri", "/status".into()),
        ("jwt_superuser_uri", "/super".into()),
        ("jwt_secret", JWT_KEY.into()),
    ]
}

#[tokio::test]
#[ignore = "requires a Mosquitto 2.1.4 build and the go-auth.so reference plugin"]
async fn jwt_wire_claims_and_files() {
    use serde_json::json;
    let capture = Capture::default();
    let port = http_server(capture.clone(), None).await;
    let issuer = format!("127.0.0.1:{port}");
    let valid = token(
        json!({"sub":"subject", "username":"u <&", "iss":issuer}),
        JWT_KEY,
    );
    let expired = token(json!({"sub":"subject", "iss":issuer, "exp":1}), JWT_KEY);
    let future = token(
        json!({"sub":"subject", "iss":issuer, "exp":1, "nbf":4_000_000_000_u64}),
        JWT_KEY,
    );
    let other_issuer = token(json!({"sub":"subject", "iss":"example.com"}), JWT_KEY);
    let bad_key = token(
        json!({"sub":"subject", "iss":issuer, "exp":1}),
        "wrong-fixed-key",
    );
    let no_subject = token(json!({"iss":issuer}), JWT_KEY);
    let bad_subject = token(json!({"sub":7, "iss":issuer}), JWT_KEY);
    let check = |user, connect| Check {
        user,
        password: b"ignored",
        connect,
        write: (connect == Verdict::Allow).then_some(("check/é", Verdict::Allow)),
    };

    let observed = compare(
        &jwt_options(port),
        &[check(&valid, Verdict::Allow)],
        &capture,
    )
    .await;
    assert_eq!(observed[0].body, b"null");
    assert_eq!(observed[1].body, b"null");
    assert_eq!(
        observed[2].body,
        r#"{"acc":2,"clientid":"wire-client","topic":"check/é"}"#.as_bytes()
    );
    assert_eq!(
        observed[0].headers["authorization"],
        format!("Bearer {valid}")
    );

    let mut form = jwt_options(port);
    form.extend([
        ("jwt_params_mode", "form".into()),
        ("jwt_http_method", "GET".into()),
        ("jwt_user_agent", "jwt-agent".into()),
    ]);
    let observed = compare(&form, &[check(&valid, Verdict::Allow)], &capture).await;
    assert!(
        observed
            .iter()
            .all(|req| req.method == "GET" && req.headers["user-agent"] == "jwt-agent")
    );
    assert!(observed[0].body.is_empty());
    assert_eq!(
        observed[2].body,
        b"acc=2&clientid=wire-client&topic=check%2F%C3%A9"
    );
    form.extend([
        ("jwt_http_method", "PUT".into()),
        ("jwt_parse_token", "true".into()),
        ("jwt_userfield", "Username".into()),
    ]);
    let observed = compare(&form, &[check(&valid, Verdict::Allow)], &capture).await;
    assert!(observed.iter().all(|req| req.method == "PUT"));
    assert_eq!(observed[0].body, b"username=u+%3C%26");

    let mut dynamic = jwt_options(9);
    dynamic.retain(|(key, _)| *key != "jwt_host");
    dynamic.extend([
        ("jwt_parse_token", "true".into()),
        ("jwt_host_whitelist", format!("example.org, {issuer}")),
        ("jwt_skip_user_expiration", "true".into()),
        ("jwt_skip_acl_expiration", "true".into()),
    ]);
    let observed = compare(
        &dynamic,
        &[
            check(&expired, Verdict::Allow),
            check(&no_subject, Verdict::Allow),
            check(&other_issuer, Verdict::Error),
            check(&bad_key, Verdict::Error),
            check(&future, Verdict::Error),
            check(&bad_subject, Verdict::Error),
        ],
        &capture,
    )
    .await;
    assert_eq!(observed.len(), 6);
    assert_eq!(observed[0].body, b"{\"username\":\"subject\"}");
    assert_eq!(observed[3].body, b"{\"username\":\"\"}");

    let acl = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(acl.path(), "user subject\ntopic write check/+\n").unwrap();
    let mut files = http_options(port, "/status", "/status", &[("http_register", "user")]);
    files.extend([
        ("backends", "http,jwt".into()),
        ("jwt_mode", "files".into()),
        ("jwt_register", "acl".into()),
        ("jwt_secret", JWT_KEY.into()),
        ("jwt_acl_path", acl.path().display().to_string()),
    ]);
    let observed = compare(
        &files,
        &[
            check(&valid, Verdict::Allow),
            Check {
                user: &expired,
                password: b"ignored",
                connect: Verdict::Allow,
                write: Some(("check/é", Verdict::Error)),
            },
            Check {
                user: &no_subject,
                password: b"ignored",
                connect: Verdict::Allow,
                write: Some(("check/é", Verdict::Deny)),
            },
        ],
        &capture,
    )
    .await;
    assert_eq!(observed.len(), 3);
}

#[derive(Clone, PartialEq, Message)]
struct Empty {}
#[derive(Clone, PartialEq, Message)]
struct User {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
    #[prost(string, tag = "3")]
    clientid: String,
}
#[derive(Clone, PartialEq, Message)]
struct Superuser {
    #[prost(string, tag = "1")]
    username: String,
}
#[derive(Clone, PartialEq, Message)]
struct Acl {
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
struct Auth {
    #[prost(bool, tag = "1")]
    ok: bool,
}
#[derive(Clone, PartialEq, Message)]
struct Name {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Debug, PartialEq)]
enum Rpc {
    User(User),
    Superuser(Superuser),
    Acl(Acl),
    Name,
    Halt,
}

#[derive(Clone)]
struct GrpcServer {
    capture: Capture<Rpc>,
    name_error: bool,
}

impl NamedService for GrpcServer {
    const NAME: &'static str = "grpc.AuthService";
}

impl<B> Service<http::Request<B>> for GrpcServer
where
    B: http_body_util::BodyExt + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let server = self.clone();
        Box::pin(async move {
            macro_rules! rpc {
                ($input:ty, $output:ty, |$state:ident, $msg:ident| $handler:expr) => {{
                    struct Handler(GrpcServer);
                    impl UnaryService<$input> for Handler {
                        type Response = $output;
                        type Future = std::future::Ready<Result<Response<$output>, Status>>;
                        fn call(&mut self, request: Request<$input>) -> Self::Future {
                            let $state = &mut self.0;
                            let $msg = request.into_inner();
                            std::future::ready(($handler).map(Response::new))
                        }
                    }
                    Grpc::new(ProstCodec::<$output, $input>::default())
                        .unary(Handler(server), request)
                        .await
                }};
            }
            let response = match request.uri().path() {
                "/grpc.AuthService/GetUser" => rpc!(User, Auth, |server, msg| {
                    let error = msg.username == "rpc-error";
                    let ok = msg.username == "allowed" && msg.password == "password";
                    server.capture.lock().unwrap().push(Rpc::User(msg));
                    if error {
                        Err(Status::unavailable("authentication service unavailable"))
                    } else {
                        Ok(Auth { ok })
                    }
                }),
                "/grpc.AuthService/GetSuperuser" => rpc!(Superuser, Auth, |server, msg| {
                    server.capture.lock().unwrap().push(Rpc::Superuser(msg));
                    Ok(Auth { ok: false })
                }),
                "/grpc.AuthService/CheckAcl" => rpc!(Acl, Auth, |server, msg| {
                    let ok = msg.topic == "grpc/allowed";
                    server.capture.lock().unwrap().push(Rpc::Acl(msg));
                    Ok(Auth { ok })
                }),
                "/grpc.AuthService/GetName" => rpc!(Empty, Name, |server, _msg| {
                    server.capture.lock().unwrap().push(Rpc::Name);
                    if server.name_error {
                        Err(Status::unimplemented("no name"))
                    } else {
                        Ok(Name {
                            name: "GoAuth test".into(),
                        })
                    }
                }),
                "/grpc.AuthService/Halt" => rpc!(Empty, Empty, |server, _msg| {
                    server.capture.lock().unwrap().push(Rpc::Halt);
                    Ok(Empty {})
                }),
                other => panic!("unknown RPC: {other}"),
            };
            Ok(response)
        })
    }
}

fn grpc_options(port: u16) -> Vec<(&'static str, String)> {
    vec![
        ("backends", "grpc".into()),
        ("grpc_host", LOOPBACK.to_string()),
        ("grpc_port", port.to_string()),
    ]
}

#[tokio::test]
#[ignore = "requires a Mosquitto 2.1.4 build and the go-auth.so reference plugin"]
async fn grpc_wire_verdicts_and_halt() {
    for (with_block, with_tls) in [(true, false), (false, false), (true, true)] {
        let capture = Capture::default();
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = GrpcServer {
            capture: capture.clone(),
            name_error: !with_block,
        };
        if with_tls {
            let ca = Credential::new("test CA", None);
            let client = Credential::new("client", Some(&ca));
            let broker = Credential::new("broker", Some(&ca));
            let ca_file = tempfile::NamedTempFile::new().unwrap();
            let cert_file = tempfile::NamedTempFile::new().unwrap();
            let key_file = tempfile::NamedTempFile::new().unwrap();
            let ca_pem = ca.0.to_pem().unwrap();
            std::fs::write(ca_file.path(), &ca_pem).unwrap();
            std::fs::write(cert_file.path(), client.0.to_pem().unwrap()).unwrap();
            std::fs::write(
                key_file.path(),
                client.1.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();
            let tls = tonic::transport::ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(
                    broker.0.to_pem().unwrap(),
                    broker.1.private_key_to_pem_pkcs8().unwrap(),
                ))
                .client_ca_root(tonic::transport::Certificate::from_pem(ca_pem));
            let mut options = grpc_options(port);
            options.extend([
                ("grpc_ca_cert", ca_file.path().display().to_string()),
                ("grpc_tls_cert", cert_file.path().display().to_string()),
                ("grpc_tls_key", key_file.path().display().to_string()),
                ("grpc_fail_on_dial_error", "true".into()),
                ("grpc_dial_timeout_ms", "3000".into()),
            ]);
            tokio::spawn(async move {
                Server::builder()
                    .tls_config(tls)
                    .unwrap()
                    .add_service(server)
                    .serve_with_incoming(TcpListenerStream::new(listener))
                    .await
                    .unwrap();
            });
            let observed = compare(
                &options,
                &[Check {
                    user: "allowed",
                    password: b"password",
                    connect: Verdict::Allow,
                    write: Some(("grpc/allowed", Verdict::Allow)),
                }],
                &capture,
            )
            .await;
            assert_eq!(observed.len(), 5);
            continue;
        }
        tokio::spawn(async move {
            Server::builder()
                .add_service(server)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let mut options = grpc_options(port);
        options.extend([
            ("grpc_fail_on_dial_error", with_block.to_string()),
            ("grpc_disable_superuser", (!with_block).to_string()),
        ]);
        let observed = compare(
            &options,
            &[
                Check {
                    user: "allowed",
                    password: b"password",
                    connect: Verdict::Allow,
                    write: Some(("grpc/allowed", Verdict::Allow)),
                },
                Check {
                    user: "allowed",
                    password: b"password",
                    connect: Verdict::Allow,
                    write: Some(("grpc/denied", Verdict::Deny)),
                },
                Check {
                    user: "denied",
                    password: b"password",
                    connect: Verdict::Deny,
                    write: None,
                },
                Check {
                    user: "rpc-error",
                    password: b"password",
                    connect: Verdict::Error,
                    write: None,
                },
            ],
            &capture,
        )
        .await;
        assert_eq!(observed.first(), Some(&Rpc::Name));
        assert_eq!(observed.last(), Some(&Rpc::Halt));
        assert_eq!(
            observed
                .iter()
                .filter(|r| matches!(r, Rpc::Superuser(_)))
                .count(),
            if with_block { 2 } else { 0 }
        );
        assert_eq!(
            observed[1],
            Rpc::User(User {
                username: "allowed".into(),
                password: "password".into(),
                clientid: CLIENT_ID.into()
            })
        );
        assert!(observed.contains(&Rpc::Acl(Acl {
            username: "allowed".into(),
            topic: "grpc/allowed".into(),
            clientid: CLIENT_ID.into(),
            acc: 2
        })));
    }
    let port = StdListener::bind((LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut options = grpc_options(port);
    options.extend([
        ("grpc_fail_on_dial_error", "true".into()),
        ("grpc_dial_timeout_ms", "20".into()),
    ]);
    let as_native = || {
        options
            .iter()
            .map(|(k, v)| ((*k).into(), v.clone()))
            .collect()
    };
    assert!(
        tokio::time::timeout(TIMEOUT, load(Library::GoAuth, as_native(), true))
            .await
            .unwrap()
            .is_err()
    );
    options.push(("grpc_fail_on_dial_error", "false".into()));
    let plugin = tokio::time::timeout(
        TIMEOUT,
        load(
            Library::GoAuth,
            options.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        plugin
            .authenticate(CLIENT_ID, Some("allowed"), Some(b"password"))
            .await,
        Verdict::Error
    );
    tokio::time::timeout(TIMEOUT, plugin.halt()).await.unwrap();

    // TCP connect succeeds, but this peer never sends an HTTP/2 preface.
    let silent = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let mut options = grpc_options(silent.local_addr().unwrap().port());
    options.extend([
        ("grpc_fail_on_dial_error", "true".into()),
        ("grpc_dial_timeout_ms", "50".into()),
    ]);
    let (mut reference, _, _config, log) = launch_reference(&options);
    let status = tokio::time::timeout(TIMEOUT, reference.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.code(), Some(1));
    assert!(
        std::fs::read_to_string(log.path())
            .unwrap()
            .contains("context deadline exceeded")
    );
    let options = options.into_iter().map(|(k, v)| (k.into(), v)).collect();
    let result = tokio::time::timeout(TIMEOUT, load(Library::GoAuth, options, true))
        .await
        .unwrap();
    assert_eq!(result.err().unwrap().0, "context deadline exceeded");
}
