use std::{fs, io, net::SocketAddr, sync::Arc, time::Duration};

use mqx_auth::PasswordFile;
use mqx_broker::{Broker, BrokerConfig, ConnectionInfo, ListenerPolicy, SecurityHandle};
use mqx_server::{CertIdentity, Server, ServerConfig};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, RevokedCertParams, date_time_ymd,
};
use rustls::{ClientConfig, RootCertStore, crypto::ring, pki_types::ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::TlsConnector;

const DEADLINE: Duration = Duration::from_secs(5);

fn local_config(extra: &str) -> ServerConfig {
    let mut config = ServerConfig::parse(&format!("listener 1888 127.0.0.1\n{extra}")).unwrap();
    config.listeners[0].port = 0; // Request a kernel-selected test port, not a config directive.
    config
}

#[cfg(unix)]
#[tokio::test]
async fn unix_listener_preserves_occupied_paths_and_a_replacement_on_shutdown() {
    use std::os::unix::{fs::symlink, net::UnixStream};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mqtt.sock");
    let config = ServerConfig::parse(&format!("listener 0 {}", path.display())).unwrap();

    fs::write(&path, b"not a socket").unwrap();
    assert!(Server::bind(&config).await.is_err());
    assert_eq!(fs::read(&path).unwrap(), b"not a socket");

    let backup = dir.path().join("backup");
    fs::rename(&path, &backup).unwrap();
    symlink(&backup, &path).unwrap();
    assert!(Server::bind(&config).await.is_err());
    assert_eq!(fs::read_link(&path).unwrap(), backup);
    fs::remove_file(&path).unwrap();

    let original = Server::bind(&config).await.unwrap();
    assert!(Server::bind(&config).await.is_err());
    UnixStream::connect(&path).unwrap();

    fs::rename(&path, dir.path().join("retired.sock")).unwrap();
    let replacement = Server::bind(&config).await.unwrap();
    drop(original);
    UnixStream::connect(&path).unwrap();
    drop(replacement);
    assert!(!path.exists());
}

#[tokio::test]
async fn listener_limit_refuses_extra_tcp_connections_before_dispatch() {
    let config = local_config("max_connections 1\nset_tcp_nodelay true");
    let server = Server::bind(&config).await.unwrap();
    let addr = server.local_addrs().next().unwrap().unwrap();
    let (stop, stopped) = oneshot::channel();
    let (accepted, mut events) = mpsc::unbounded_channel();
    let serving = tokio::spawn(server.run_until(
        move |connection| {
            let accepted = accepted.clone();
            async move {
                let mut stream = connection.stream;
                accepted
                    .send(stream.as_tcp_stream().unwrap().nodelay().unwrap())
                    .unwrap();
                assert_eq!(stream.read_u8().await.unwrap(), 7);
            }
        },
        async {
            stopped.await.unwrap();
        },
        || {},
    ));
    let mut first = TcpStream::connect(addr).await.unwrap();
    assert_eq!(timeout(DEADLINE, events.recv()).await.unwrap(), Some(true));
    let mut second = TcpStream::connect(addr).await.unwrap();
    match timeout(DEADLINE, second.read_u8()).await.unwrap() {
        Ok(_) => panic!("over-limit connection reached the handler"),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        )),
    }
    assert!(events.try_recv().is_err());
    first.write_u8(7).await.unwrap();
    assert_eq!(
        timeout(DEADLINE, first.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    stop.send(()).unwrap();
    serving.await.unwrap().unwrap();
}

const CONNECT: &[u8] = b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03dev";
const ACCEPT: [u8; 4] = [0x20, 2, 0, 0];
const V1: &[u8] = b"PROXY TCP4 192.0.2.7 127.0.0.1 47568 1888\r\n";
const V2_LOCAL: &[u8] = b"\r\n\r\n\0\r\nQUIT\n\x20\0\0\0";
const V2_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n\x21\x11";
const UPGRADE: &[u8] = b"GET /mqtt HTTP/1.1\r\nHost: localhost\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: mqtt\r\n\
    Origin: https://device.example\r\n\r\n";

fn v2(tlv: &[u8], leftover: &[u8]) -> Vec<u8> {
    let mut input = V2_PREFIX.to_vec();
    input.extend_from_slice(&(12 + tlv.len() as u16).to_be_bytes());
    input.extend_from_slice(&[192, 0, 2, 7, 127, 0, 0, 1, 0xb9, 0xd0, 0x07, 0x60]);
    input.extend_from_slice(tlv);
    input.extend_from_slice(leftover);
    input
}

struct RunningBroker {
    addr: SocketAddr,
    observed: mpsc::UnboundedReceiver<(Option<SocketAddr>, CertIdentity)>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), mqx_server::ServerError>>,
}

impl RunningBroker {
    async fn start(config: &ServerConfig) -> Self {
        let server = Server::bind(config).await.unwrap();
        let addr = server.local_addrs().next().unwrap().unwrap();
        // The handler sends observations but always drives the actual MQTT broker.
        let broker = Broker::new(BrokerConfig::default());
        let password = config
            .security_for(&config.listeners[0])
            .password_file
            .as_deref()
            .map(|path| PasswordFile::load(path).unwrap());
        let listener = Arc::new(ListenerPolicy {
            allow_anonymous: Some(config.allow_anonymous_for(&config.listeners[0])),
            security: SecurityHandle::new(password, None),
            ..ListenerPolicy::default()
        });
        let shutdown = broker.clone();
        let (accepted, observed) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run_until(
            move |connection| {
                let broker = broker.clone();
                let listener = listener.clone();
                let accepted = accepted.clone();
                async move {
                    accepted
                        .send((connection.peer_addr, connection.cert_identity.clone()))
                        .unwrap();
                    broker
                        .serve_accepted(
                            connection.stream,
                            ConnectionInfo {
                                peer_addr: connection.peer_addr,
                                listener,
                                cert_identity: connection.cert_identity.into(),
                            },
                            connection.accepted_at,
                        )
                        .await
                        .unwrap();
                }
            },
            async {
                stopped.await.unwrap();
            },
            move || shutdown.shutdown(),
        ));
        Self {
            addr,
            observed,
            stop,
            task,
        }
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap().unwrap();
    }

    async fn observed(&mut self) -> (Option<SocketAddr>, CertIdentity) {
        timeout(DEADLINE, self.observed.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

async fn read_ack(io: &mut (impl AsyncReadExt + Unpin)) -> [u8; 4] {
    let mut ack = [0; 4];
    timeout(DEADLINE, io.read_exact(&mut ack))
        .await
        .unwrap()
        .unwrap();
    ack
}

async fn read_upgrade(io: &mut (impl AsyncReadExt + Unpin)) {
    let mut reply = Vec::new();
    timeout(DEADLINE, async {
        while !reply.ends_with(b"\r\n\r\n") {
            reply.push(io.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(
        reply.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"),
        "{reply:?}"
    );
    assert!(
        String::from_utf8(reply)
            .unwrap()
            .contains("Sec-WebSocket-Protocol: mqtt\r\n")
    );
}

async fn websocket_connect(io: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin)) {
    // RFC6455 masked binary client frame carrying exactly one MQTT CONNECT.
    let mask = [1, 2, 3, 4];
    let mut frame = vec![0x82, 0x80 | CONNECT.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(
        CONNECT
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ mask[i % 4]),
    );
    io.write_all(&frame).await.unwrap();
    io.flush().await.unwrap();
    let mut actual = [0; 6];
    timeout(DEADLINE, io.read_exact(&mut actual))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&actual[..2], &[0x82, 4]);
    assert_eq!(actual[2..], ACCEPT);
}

#[tokio::test]
async fn tcp_proxy_overread_is_forwarded_to_mqtt_and_reports_the_source() {
    // Mosquitto test/broker/21-proxy-v1-success.py and 21-proxy-v2-ipv4.py.
    for (version, input) in [(1, [V1, CONNECT].concat()), (2, v2(&[], CONNECT))] {
        let config = local_config(&format!(
            "allow_anonymous true\nenable_proxy_protocol {version}"
        ));
        let mut broker = RunningBroker::start(&config).await;
        let mut stream = TcpStream::connect(broker.addr).await.unwrap();
        // The header reader can read the MQTT packet in the same syscall.
        stream.write_all(&input).await.unwrap();
        assert_eq!(read_ack(&mut stream).await, ACCEPT);
        assert_eq!(
            broker.observed().await,
            (Some("192.0.2.7:47568".parse().unwrap()), CertIdentity::None)
        );
        broker.stop().await;
    }
}

#[tokio::test]
async fn proxy_v2_local_and_unverified_certificate_never_reach_mqtt() {
    let config = local_config(
        "allow_anonymous true\nenable_proxy_protocol 2\nproxy_protocol_v2_require_tls true\nrequire_certificate true",
    );
    let mut broker = RunningBroker::start(&config).await;
    for input in [
        [V2_LOCAL, CONNECT].concat(),
        v2(&[], CONNECT),
        v2(b"\x20\x00\x05\x05\x00\x00\x00\x01", CONNECT),
    ] {
        let mut stream = TcpStream::connect(broker.addr).await.unwrap();
        stream.write_all(&input).await.unwrap();
        let error = timeout(DEADLINE, stream.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ));
    }
    assert!(broker.observed.try_recv().is_err());
    broker.stop().await;
}

#[tokio::test]
async fn proxy_v2_verified_common_name_is_used_instead_of_mqtt_credentials() {
    // Mosquitto test/broker/21-proxy-v2-ssl-common-name-{success,failure}.py.
    let config = local_config(
        "enable_proxy_protocol 2\nproxy_protocol_v2_require_tls true\nrequire_certificate true\nuse_identity_as_username true\nallow_anonymous true",
    );
    let mut broker = RunningBroker::start(&config).await;
    let mut stream = TcpStream::connect(broker.addr).await.unwrap();
    // SSL flag 0x01 | certificate from session flag 0x04; verify result 0.
    let ssl_with_cn = b"\x20\x00\x0e\x05\x00\x00\x00\x00\x22\x00\x06device";
    stream.write_all(&v2(ssl_with_cn, CONNECT)).await.unwrap();
    assert_eq!(read_ack(&mut stream).await, ACCEPT);
    assert_eq!(
        broker.observed().await.1,
        CertIdentity::ForwardedUsername("device".into())
    );
    let mut stream = TcpStream::connect(broker.addr).await.unwrap();
    let ssl_without_cn = b"\x20\x00\x05\x05\x00\x00\x00\x00";
    stream
        .write_all(&v2(ssl_without_cn, CONNECT))
        .await
        .unwrap();
    assert_eq!(read_ack(&mut stream).await, [0x20, 2, 0, 4]);
    assert_eq!(broker.observed().await.1, CertIdentity::MissingOrInvalid);
    broker.stop().await;
}

#[tokio::test]
async fn forwarded_common_name_cannot_bypass_password_file_but_local_mtls_can() {
    let pki = TestPki::with_common_name("test");
    let path = pki.dir.path().join("passwords");
    // Mosquitto test/broker/09-pwfile-parse-invalid.py: user and password "test".
    fs::write(&path, "test:$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==\n").unwrap();
    let basic_auth = format!("allow_anonymous false\npassword_file {}", path.display());
    let correct_password =
        b"\x10\x1b\x00\x04MQTT\x04\xc2\x00\x3c\x00\x03dev\x00\x04test\x00\x04test";
    let plain = RunningBroker::start(&local_config(&basic_auth)).await;
    let mut stream = TcpStream::connect(plain.addr).await.unwrap();
    stream.write_all(correct_password).await.unwrap();
    assert_eq!(read_ack(&mut stream).await, ACCEPT);
    plain.stop().await;

    let auth = format!("require_certificate true\nuse_identity_as_username true\n{basic_auth}");
    let proxy = local_config(&format!("enable_proxy_protocol 2\n{auth}"));
    let mut broker = RunningBroker::start(&proxy).await;
    let cn = b"\x20\x00\x0c\x05\x00\x00\x00\x00\x22\x00\x04test";
    for connect in [CONNECT, correct_password.as_slice()] {
        let mut stream = TcpStream::connect(broker.addr).await.unwrap();
        stream.write_all(&v2(cn, connect)).await.unwrap();
        // Even correctly supplied MQTT credentials are discarded with a forwarded CN.
        assert_eq!(read_ack(&mut stream).await, [0x20, 2, 0, 5]);
        assert_eq!(
            broker.observed().await.1,
            CertIdentity::ForwardedUsername("test".into())
        );
    }
    broker.stop().await;

    let mut broker = RunningBroker::start(&pki.server_config(&auth)).await;
    let tcp = TcpStream::connect(broker.addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(pki.client_config(true)));
    let mut stream = timeout(
        DEADLINE,
        tls.connect(ServerName::try_from("localhost").unwrap(), tcp),
    )
    .await
    .unwrap()
    .unwrap();
    stream.write_all(CONNECT).await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(read_ack(&mut stream).await, ACCEPT);
    assert_eq!(
        broker.observed().await.1,
        CertIdentity::Username("test".into())
    );
    broker.stop().await;
}

#[tokio::test]
async fn tls_websocket_dispatches_mqtt_with_and_without_a_proxy_v1_prefix() {
    let pki = TestPki::new();
    for proxy in ["", "enable_proxy_protocol 1\n"] {
        let config = pki.server_config(&format!(
            "allow_anonymous true\n\
            protocol websockets\nwebsockets_origin https://device.example\n{proxy}"
        ));
        let mut broker = RunningBroker::start(&config).await;
        let mut tcp = TcpStream::connect(broker.addr).await.unwrap();
        let source = if proxy.is_empty() {
            tcp.local_addr().unwrap()
        } else {
            tcp.write_all(V1).await.unwrap();
            "192.0.2.7:47568".parse().unwrap()
        };
        let tls = TlsConnector::from(Arc::new(pki.client_config(false)));
        let mut stream = timeout(
            DEADLINE,
            tls.connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap();
        stream.write_all(UPGRADE).await.unwrap();
        stream.flush().await.unwrap();
        read_upgrade(&mut stream).await;
        websocket_connect(&mut stream).await;
        assert_eq!(broker.observed().await, (Some(source), CertIdentity::None));
        broker.stop().await;
    }
}

#[tokio::test]
async fn proxy_v2_can_pass_a_pipelined_http_upgrade_to_websocket() {
    // Mosquitto test/broker/21-proxy-v2-websockets.py.
    let config = local_config(
        "allow_anonymous true\nenable_proxy_protocol 2\nprotocol websockets\npacket_buffer_size 512",
    );
    let mut broker = RunningBroker::start(&config).await;
    let mut stream = TcpStream::connect(broker.addr).await.unwrap();
    stream.write_all(&v2(&[], UPGRADE)).await.unwrap();
    read_upgrade(&mut stream).await;
    websocket_connect(&mut stream).await;
    assert_eq!(
        broker.observed().await.0,
        Some("192.0.2.7:47568".parse().unwrap())
    );
    broker.stop().await;
}

#[tokio::test]
async fn websocket_listener_applies_origin_and_http_buffer_limits_before_mqtt() {
    for rule in [
        "websockets_origin https://other.example",
        "websockets_headers_size 32",
    ] {
        let config = local_config(&format!(
            "allow_anonymous true\nprotocol websockets\n{rule}"
        ));
        let mut broker = RunningBroker::start(&config).await;
        let mut stream = TcpStream::connect(broker.addr).await.unwrap();
        stream.write_all(UPGRADE).await.unwrap();
        // Built-in Mosquitto waits for EOF when the HTTP buffer fills.
        stream.shutdown().await.unwrap();
        let error = timeout(DEADLINE, stream.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ));
        assert!(broker.observed.try_recv().is_err());
        broker.stop().await;
    }
}

struct TestPki {
    dir: tempfile::TempDir,
    ca: CertifiedIssuer<'static, KeyPair>,
    client: Certificate,
    client_key: KeyPair,
}

impl TestPki {
    fn new() -> Self {
        Self::with_common_name(" Néw+device ")
    }

    fn with_common_name(common_name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params.signed_by(&key, &ca).unwrap();
        fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
        fs::write(dir.path().join("server.pem"), certificate.pem()).unwrap();
        fs::write(dir.path().join("server.key"), key.serialize_pem()).unwrap();

        let mut params = CertificateParams::default();
        params.serial_number = Some(25.into());
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CountryName, "GB");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Mosquitto, Test");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client = params.signed_by(&client_key, &ca).unwrap();
        Self {
            dir,
            ca,
            client,
            client_key,
        }
    }

    fn server_config(&self, extra: &str) -> ServerConfig {
        let dir = self.dir.path();
        local_config(&format!(
            "certfile {}\nkeyfile {}\ncafile {}\n{extra}",
            dir.join("server.pem").display(),
            dir.join("server.key").display(),
            dir.join("ca.pem").display()
        ))
    }

    fn client_config(&self, client_cert: bool) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.der().clone()).unwrap();
        let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        if client_cert {
            builder
                .with_client_auth_cert(
                    vec![self.client.der().clone()],
                    self.client_key.serialize_der().try_into().unwrap(),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        }
    }
}

async fn dial(addr: SocketAddr, config: ClientConfig) -> io::Result<u8> {
    let stream = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let mut stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await?;
    // A TLS 1.3 client can locally finish before it receives a fatal server alert.
    stream.read_u8().await
}

async fn serve_tls(
    config: &ServerConfig,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<CertIdentity>,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let server = Server::bind(config).await.unwrap();
    let addr = server.local_addrs().next().unwrap().unwrap();
    let (stop, stopped) = oneshot::channel();
    let (events, identities) = mpsc::unbounded_channel();
    let serving = tokio::spawn(async move {
        server
            .run_until(
                move |mut connection| {
                    let events = events.clone();
                    async move {
                        events.send(connection.cert_identity).unwrap();
                        connection.stream.write_u8(42).await.unwrap();
                        connection.stream.shutdown().await.unwrap();
                    }
                },
                async {
                    stopped.await.unwrap();
                },
                || {},
            )
            .await
            .unwrap();
    });
    (addr, identities, stop, serving)
}

#[tokio::test]
async fn authenticated_tls_dispatches_common_name_or_openssl_rfc2253_subject() {
    let pki = TestPki::new();
    for (extra, expected) in [
        (
            "use_identity_as_username true\nuse_subject_as_username true",
            " Néw+device ",
        ),
        (
            "use_subject_as_username true",
            r"CN=\ N\C3\A9w\+device\ ,O=Mosquitto\, Test,C=GB",
        ),
    ] {
        let config = pki.server_config(&format!("require_certificate true\n{extra}"));
        let (addr, mut identities, stop, serving) = serve_tls(&config).await;
        assert!(
            timeout(DEADLINE, dial(addr, pki.client_config(false)))
                .await
                .unwrap()
                .is_err()
        );
        assert!(identities.try_recv().is_err());
        assert_eq!(
            timeout(DEADLINE, dial(addr, pki.client_config(true)))
                .await
                .unwrap()
                .unwrap(),
            42
        );
        assert_eq!(
            identities.try_recv().unwrap(),
            CertIdentity::Username(expected.into())
        );
        stop.send(()).unwrap();
        serving.await.unwrap();
    }
}

#[tokio::test]
async fn tls_without_client_auth_does_not_request_a_certificate() {
    let pki = TestPki::new();
    let config = pki.server_config("require_certificate false\nuse_identity_as_username true");
    let (addr, mut identities, stop, serving) = serve_tls(&config).await;
    assert_eq!(
        timeout(DEADLINE, dial(addr, pki.client_config(true)))
            .await
            .unwrap()
            .unwrap(),
        42
    );
    assert_eq!(
        identities.try_recv().unwrap(),
        CertIdentity::MissingOrInvalid
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn capath_requires_the_issuing_certificate_under_its_openssl_subject_hash() {
    let pki = TestPki::new();
    let directory = pki.dir.path();
    let mut config = pki.server_config("require_certificate true");
    config.listeners[0].tls.cafile = None;
    config.listeners[0].tls.capath = Some(directory.into());
    // `openssl x509 -subject_hash` for rcgen's default issuer DN is 3b291c1d.
    let indexed = directory.join("3b291c1d.0");
    fs::write(directory.join("deadbeef.0"), pki.ca.pem()).unwrap();
    assert!(Server::bind(&config).await.is_err());
    fs::write(indexed, pki.ca.pem()).unwrap();
    let (addr, _identities, stop, serving) = serve_tls(&config).await;
    assert_eq!(
        timeout(DEADLINE, dial(addr, pki.client_config(true)))
            .await
            .unwrap()
            .unwrap(),
        42
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn certificate_revocation_file_refuses_a_revoked_client() {
    let pki = TestPki::new();
    let params = CertificateRevocationListParams {
        this_update: date_time_ymd(2020, 1, 1),
        next_update: date_time_ymd(2099, 1, 1),
        crl_number: 1.into(),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: 25.into(),
            revocation_time: date_time_ymd(2020, 1, 1),
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let path = pki.dir.path().join("revoked.pem");
    fs::write(&path, params.signed_by(&pki.ca).unwrap().pem().unwrap()).unwrap();
    let config = pki.server_config(&format!(
        "require_certificate true\ncrlfile {}",
        path.display()
    ));
    let (addr, mut identities, stop, serving) = serve_tls(&config).await;
    assert!(
        timeout(DEADLINE, dial(addr, pki.client_config(true)))
            .await
            .unwrap()
            .is_err()
    );
    assert!(identities.try_recv().is_err());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn invalid_tls_directives_report_the_misconfigured_option() {
    // Mosquitto v2.1.4 test/broker/16-config-parse-errors-tls.py.
    let pki = TestPki::new();
    for (input, expected) in [
        ("certfile ./16-config-parse-errors.py", "certfile"),
        ("keyfile ./16-config-parse-errors.py", "keyfile"),
        ("crlfile invalid", "crlfile"),
        ("ciphers invalid", "ciphers"),
        ("ciphers_tls1.3 invalid", "ciphers_tls1.3"),
    ] {
        let Err(error) = Server::bind(&pki.server_config(input)).await else {
            panic!("unexpected startup with {input}");
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
}
