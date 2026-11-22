use std::{fs, io, net::SocketAddr, sync::Arc, time::Duration};

use mqx_server::{CertIdentity, ConnectionStream, Server, ServerConfig};
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
                let ConnectionStream::Tcp(mut stream) = connection.stream else {
                    panic!("not TCP");
                };
                accepted.send(stream.nodelay().unwrap()).unwrap();
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

#[tokio::test]
async fn unsupported_transport_cannot_bind_as_plain_mqtt() {
    for (option, diagnostic) in [
        ("protocol websockets", "protocol websockets"),
        ("enable_proxy_protocol 1", "enable_proxy_protocol"),
    ] {
        let result = Server::bind(&local_config(option)).await;
        let Err(error) = result else {
            panic!("{option} unexpectedly started");
        };
        assert!(error.to_string().contains(diagnostic));
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
            .push(DnType::CommonName, " Néw+device ");
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
