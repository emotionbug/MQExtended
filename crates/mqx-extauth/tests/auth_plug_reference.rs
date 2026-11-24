//! Run with `cargo test --locked -p mqx-extauth --test auth_plug_reference -- --ignored`.
//! Optional paths (defaults for the local reference build):
//! - `MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build`
//! - `MQX_AUTH_REFERENCE_SO=/tmp/mosquitto-auth-plug/auth-plug.so`
//! - `MQX_AUTH_SERVER_BIN=/tmp/authref/root/usr/bin` (redis-server, redis-cli, memcached)
//! - `MQX_AUTH_REFERENCE_LD_LIBRARY_PATH=/tmp/authref/root/usr/lib/x86_64-linux-gnu:/tmp/mosquitto/build/lib`

use std::io;
use std::net::{Ipv4Addr, TcpListener as StdListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use mqx_auth::external::{AclAccess, Binding, ExternalSecurity, Subject, Verdict};
use mqx_extauth::{Library, load};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const HASH: &str = "PBKDF2$sha256$901$QrqEwoNkUOWjr3Dg$6CbjEcRO6xEy2Bxa3gXtAYOYGpErf2KH";
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const ID: &str = "differential";
const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn build_dir() -> PathBuf {
    path("MOSQUITTO_BUILD_DIR", "/tmp/mosquitto/build")
}

fn command(program: PathBuf) -> Command {
    let mut command = Command::new(program);
    let libs = std::env::var_os("MQX_AUTH_REFERENCE_LD_LIBRARY_PATH").unwrap_or_else(|| {
        let mosquitto = build_dir().join("lib");
        std::env::join_paths([
            PathBuf::from("/tmp/authref/root/usr/lib/x86_64-linux-gnu"),
            mosquitto,
        ])
        .unwrap()
    });
    command.env("LD_LIBRARY_PATH", libs).env("NO_PROXY", "*");
    command
}

fn server(program: &str) -> Command {
    command(path("MQX_AUTH_SERVER_BIN", "/tmp/authref/root/usr/bin").join(program))
}

struct Process {
    child: Child,
    log: tempfile::NamedTempFile,
}

impl Process {
    fn spawn(mut cmd: Command) -> Self {
        let log = tempfile::NamedTempFile::new().unwrap();
        let child = cmd
            .stdout(Stdio::null())
            .stderr(log.reopen().unwrap())
            .spawn()
            .unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
        Self { child, log }
    }

    async fn ready(&mut self, port: u16) {
        for _ in 0..150 {
            if self.child.try_wait().unwrap().is_some() {
                break;
            }
            if TcpStream::connect((LOOPBACK, port)).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "service did not start on port {port}: {}",
            std::fs::read_to_string(self.log.path()).unwrap()
        );
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unused_port() -> u16 {
    StdListener::bind((LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn reference(options: &[(&str, String)]) -> (Process, u16) {
    let port = unused_port();
    let so = path(
        "MQX_AUTH_REFERENCE_SO",
        "/tmp/mosquitto-auth-plug/auth-plug.so",
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut config = format!(
        "listener {port} 127.0.0.1\nauth_plugin {}\nlog_type all\n",
        so.display()
    );
    use std::fmt::Write as _;
    for (option, value) in options {
        writeln!(config, "auth_opt_{option} {value}").unwrap();
    }
    std::fs::write(file.path(), config).unwrap();
    let mut cmd = command(build_dir().join("src/mosquitto"));
    cmd.arg("-c").arg(file.path());
    let mut broker = Process::spawn(cmd);
    broker.ready(port).await;
    (broker, port)
}

async fn rust(options: &[(&str, String)]) -> Arc<dyn ExternalSecurity> {
    load(
        Library::AuthPlug,
        options
            .iter()
            .map(|(k, v)| ((*k).into(), v.clone()))
            .collect(),
        true,
    )
    .await
    .unwrap()
}

struct Mqtt(TcpStream);

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

impl Mqtt {
    async fn send(&mut self, kind: u8, payload: &[u8]) {
        assert!(payload.len() < 128);
        self.0
            .write_all(&[kind, payload.len() as u8])
            .await
            .unwrap();
        self.0.write_all(payload).await.unwrap();
    }

    async fn recv(&mut self) -> Option<(u8, Vec<u8>)> {
        tokio::time::timeout(IO_TIMEOUT, async {
            let mut header = [0; 2];
            if let Err(error) = self.0.read_exact(&mut header).await {
                assert!(matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ));
                return None;
            }
            assert!(header[1] < 128);
            let mut payload = vec![0; header[1] as usize];
            self.0.read_exact(&mut payload).await.unwrap();
            Some((header[0], payload))
        })
        .await
        .expect("timed out waiting for the reference broker")
    }

    async fn connect(port: u16, user: &str, password: &[u8]) -> (Verdict, Self) {
        let mut mqtt = Self(TcpStream::connect((LOOPBACK, port)).await.unwrap());
        let mut payload = b"\x00\x04MQTT\x05\xc2\x00\x1e\x00".to_vec();
        field(&mut payload, ID.as_bytes());
        field(&mut payload, user.as_bytes());
        field(&mut payload, password);
        mqtt.send(0x10, &payload).await;
        let verdict = match mqtt.recv().await {
            Some((0x20, msg)) if msg[1] == 0 => Verdict::Allow,
            Some((0x20, msg)) if msg[1] == 0x87 => Verdict::Defer,
            None => Verdict::Error,
            result => panic!("unexpected CONNECT outcome: {result:?}"),
        };
        (verdict, mqtt)
    }

    async fn acl(&mut self, access: AclAccess, topic: &str) -> Verdict {
        let mut payload = Vec::new();
        match access {
            AclAccess::Subscribe => {
                payload.extend_from_slice(&[0, 1, 0]); // packet ID, property length
                field(&mut payload, topic.as_bytes());
                payload.push(0); // requested QoS
                self.send(0x82, &payload).await;
            }
            AclAccess::Write => {
                field(&mut payload, topic.as_bytes());
                payload.extend_from_slice(&[0, 1, 0]);
                payload.push(b'x');
                self.send(0x32, &payload).await;
            }
            AclAccess::Read => panic!("READ is broker initiated"),
        }
        match self.recv().await {
            Some((0x90, msg)) if msg[3] == 0 => Verdict::Allow,
            Some((0x90, msg)) if msg[3] == 0x87 => Verdict::Defer,
            Some((0x40, msg)) if matches!(msg.get(2).copied().unwrap_or(0), 0 | 0x10) => {
                Verdict::Allow
            }
            Some((0x40, msg)) if msg[2] == 0x87 => Verdict::Defer,
            Some((0xe0, msg)) if msg.first() == Some(&0x80) => Verdict::Error,
            None => Verdict::Error,
            other => panic!("unexpected ACL outcome: {other:?}"),
        }
    }
}

async fn auth_both(
    plugin: &dyn ExternalSecurity,
    port: u16,
    user: &str,
    password: &[u8],
    expected: Verdict,
) -> Mqtt {
    let (reference, mqtt) = Mqtt::connect(port, user, password).await;
    assert_eq!(reference, expected);
    assert_eq!(
        plugin.authenticate(ID, Some(user), Some(password)).await,
        reference
    );
    mqtt
}

async fn rust_acl(
    plugin: &dyn ExternalSecurity,
    user: &str,
    topic: &str,
    access: AclAccess,
) -> Verdict {
    let identity = plugin
        .acl_identity(Subject {
            client_id: ID,
            username: Some(user),
            binding: Binding {
                credentials: true,
                ..Binding::default()
            },
        })
        .unwrap();
    plugin.authorize(&identity, topic, access).await.verdict
}

fn redis(port: u16, args: &[&str]) -> String {
    let out = server("redis-cli")
        .arg("--raw")
        .arg("-p")
        .arg(port.to_string())
        .arg("-n")
        .arg("2")
        .env("REDISCLI_AUTH", "backend-pass")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}

#[tokio::test]
#[ignore = "requires the reference Mosquitto, auth-plug.so and redis-server"]
async fn redis_verdicts_auth_select_queries_and_reconnect() {
    let port = unused_port();
    let mut cmd = server("redis-server");
    cmd.args([
        "--bind",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--save",
        "",
        "--appendonly",
        "no",
        "--requirepass",
        "backend-pass",
    ]);
    let mut service = Process::spawn(cmd);
    service.ready(port).await;
    assert_eq!(redis(port, &["SET", "pw:user", HASH]), "OK");
    assert_eq!(redis(port, &["SET", "acl:user:wide", "4tail"]), "OK");
    assert_eq!(redis(port, &["SET", "acl:user:write", "2"]), "OK");
    assert_eq!(redis(port, &["LPUSH", "acl:user:list", "9"]), "1");
    let options = [
        ("backends", "redis".into()),
        ("redis_host", "127.0.0.1".into()),
        ("redis_port", port.to_string()),
        ("redis_pass", "backend-pass".into()),
        ("redis_db", "2".into()),
        ("redis_userquery", "GET pw:%s".into()),
        ("redis_aclquery", "GET acl:%s:%s".into()),
        ("acl_cacheseconds", "0".into()),
    ];
    let (_broker, broker_port) = reference(&options).await;
    let plugin = rust(&options).await;
    auth_both(&*plugin, broker_port, "user", b"wrong", Verdict::Defer).await;
    auth_both(
        &*plugin,
        broker_port,
        "missing",
        b"password",
        Verdict::Defer,
    )
    .await;
    let mut mqtt = auth_both(&*plugin, broker_port, "user", b"password", Verdict::Allow).await;
    for (access, topic, expected) in [
        (AclAccess::Subscribe, "wide", Verdict::Allow),
        (AclAccess::Write, "write", Verdict::Allow),
        (AclAccess::Subscribe, "write", Verdict::Defer),
        (AclAccess::Subscribe, "list", Verdict::Defer),
    ] {
        assert_eq!(mqtt.acl(access, topic).await, expected);
        assert_eq!(rust_acl(&*plugin, "user", topic, access).await, expected);
    }
    drop(mqtt);
    let killed = redis(port, &["CLIENT", "KILL", "TYPE", "normal", "SKIPME", "yes"]);
    assert_eq!(killed, "2");
    auth_both(&*plugin, broker_port, "user", b"password", Verdict::Error).await;
    auth_both(&*plugin, broker_port, "user", b"password", Verdict::Allow).await;
}

async fn memcached_set(port: u16, key: &str, value: &str) {
    let mut socket = TcpStream::connect((LOOPBACK, port)).await.unwrap();
    let command = format!("set {key} 0 0 {}\r\n{value}\r\n", value.len());
    socket.write_all(command.as_bytes()).await.unwrap();
    let mut response = [0; 8];
    socket.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"STORED\r\n");
}

#[tokio::test]
#[ignore = "requires the reference Mosquitto, auth-plug.so and memcached"]
async fn memcached_verdicts_and_key_format() {
    let port = unused_port();
    let mut cmd = server("memcached");
    cmd.args(["-l", "127.0.0.1", "-p", &port.to_string(), "-U", "0"]);
    if let Some(user) = std::env::var_os("USER") {
        cmd.arg("-u").arg(user);
    }
    let mut service = Process::spawn(cmd);
    service.ready(port).await;
    for (key, value) in [
        ("user", HASH),
        ("user-wide", "4"),
        ("user-write", "2"),
        ("user-denied", "0"),
    ] {
        memcached_set(port, key, value).await;
    }
    let options = [
        ("backends", "memcached".into()),
        ("memcached_host", "127.0.0.1".into()),
        ("memcached_port", port.to_string()),
        ("memcached_db", "999".into()),
        ("memcached_pass", "ignored".into()),
        ("memcached_userquery", "ignored %s".into()),
        ("memcached_aclquery", "ignored %s%s".into()),
        ("acl_cacheseconds", "0".into()),
    ];
    let (_broker, broker_port) = reference(&options).await;
    let plugin = rust(&options).await;
    auth_both(&*plugin, broker_port, "absent", b"password", Verdict::Defer).await;
    auth_both(&*plugin, broker_port, "user", b"wrong", Verdict::Defer).await;
    let mut mqtt = auth_both(&*plugin, broker_port, "user", b"password", Verdict::Allow).await;
    for (access, topic, expected) in [
        (AclAccess::Subscribe, "wide", Verdict::Allow),
        (AclAccess::Write, "write", Verdict::Allow),
        (AclAccess::Subscribe, "denied", Verdict::Defer),
        (AclAccess::Write, "absent", Verdict::Error),
    ] {
        assert_eq!(mqtt.acl(access, topic).await, expected);
        assert_eq!(rust_acl(&*plugin, "user", topic, access).await, expected);
    }
    drop(service);
    auth_both(&*plugin, broker_port, "user", b"password", Verdict::Defer).await;
    let (_offline_broker, offline_port) = reference(&options).await;
    let offline_plugin = rust(&options).await;
    auth_both(
        &*offline_plugin,
        offline_port,
        "user",
        b"password",
        Verdict::Defer,
    )
    .await;
}

async fn record_http(listener: Arc<TcpListener>, statuses: &[u16]) -> Vec<Vec<u8>> {
    let mut requests = Vec::new();
    for status in statuses {
        let (connection, _) = tokio::time::timeout(IO_TIMEOUT, listener.accept())
            .await
            .expect("expected another HTTP request")
            .unwrap();
        let mut stream = BufReader::new(connection);
        let mut raw = Vec::new();
        let mut length = None;
        loop {
            let start = raw.len();
            assert!(stream.read_until(b'\n', &mut raw).await.unwrap() > 0);
            let line = &raw[start..];
            if line == b"\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix(b"Content-Length: ") {
                length = Some(
                    std::str::from_utf8(value)
                        .unwrap()
                        .trim()
                        .parse::<usize>()
                        .unwrap(),
                );
            }
        }
        let end = raw.len();
        raw.resize(end + length.expect("missing Content-Length"), 0);
        stream.read_exact(&mut raw[end..]).await.unwrap();
        let response =
            format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
        requests.push(raw);
    }
    requests
}

#[tokio::test]
#[ignore = "requires the reference Mosquitto and auth-plug.so"]
async fn http_and_jwt_match_reference_requests_byte_for_byte() {
    let user = "u &é.token~";
    let pass = b"p +/\xff&no";
    let topic = "house/special &é/+";
    // Neither endpoint permits retries on a 4xx. The first status for JWT
    // is a transport-level callback error without a retry; HTTP retries 5xx.
    for (backend, override_key, statuses) in [
        ("http", false, &[503, 201, 401, 204, 403, 404, 401][..]),
        ("http", true, &[503, 201, 401, 204, 403, 404, 401][..]),
        ("jwt", false, &[503, 201, 401, 204, 403, 404, 401][..]),
    ] {
        let server = Arc::new(TcpListener::bind((LOOPBACK, 0)).await.unwrap());
        let mut options = vec![
            ("backends", backend.into()),
            ("http_ip", "127.0.0.1".into()),
            (
                "http_hostname",
                if backend == "jwt" {
                    "localhost"
                } else {
                    "virtual.example"
                }
                .into(),
            ),
            ("http_port", server.local_addr().unwrap().port().to_string()),
            ("http_getuser_uri", "/user".into()),
            ("http_superuser_uri", "/super".into()),
            ("http_aclcheck_uri", "/acl".into()),
            ("http_retry_count", "1".into()),
            ("acl_cacheseconds", "0".into()),
        ];
        if override_key {
            options.push(("http_basic_auth_key", "a2V5OnZhbHVl".into()));
        }
        let (broker, port) = reference(&options).await;
        let plugin = rust(&options).await;
        let capture = tokio::spawn(record_http(server.clone(), statuses));
        if backend == "jwt" {
            assert_eq!(Mqtt::connect(port, user, pass).await.0, Verdict::Error);
        }
        let (verdict, mut mqtt) = Mqtt::connect(port, user, pass).await;
        assert_eq!(verdict, Verdict::Allow);
        assert_eq!(
            mqtt.acl(AclAccess::Write, "house/special &é").await,
            Verdict::Allow
        );
        assert_eq!(mqtt.acl(AclAccess::Subscribe, topic).await, Verdict::Defer);
        assert_eq!(
            Mqtt::connect(port, "denied", b"other").await.0,
            Verdict::Defer
        );
        let reference = capture.await.unwrap();
        drop(mqtt);
        drop(broker);
        let capture = tokio::spawn(record_http(server.clone(), statuses));
        if backend == "jwt" {
            assert_eq!(
                plugin.authenticate(ID, Some(user), Some(pass)).await,
                Verdict::Error
            );
        }
        assert_eq!(
            plugin.authenticate(ID, Some(user), Some(pass)).await,
            Verdict::Allow
        );
        assert_eq!(
            rust_acl(&*plugin, user, "house/special &é", AclAccess::Write).await,
            Verdict::Allow
        );
        assert_eq!(
            rust_acl(&*plugin, user, topic, AclAccess::Subscribe).await,
            Verdict::Defer
        );
        assert_eq!(
            plugin
                .authenticate(ID, Some("denied"), Some(b"other"))
                .await,
            Verdict::Defer
        );
        let native = capture.await.unwrap();
        for (expected, actual) in reference.iter().zip(native.iter()) {
            assert_eq!(
                String::from_utf8_lossy(actual),
                String::from_utf8_lossy(expected),
                "{backend} override={override_key}"
            );
        }
        assert_eq!(native, reference);
    }
}

#[tokio::test]
async fn native_http_parameter_prefix_and_raw_certificate_client_id() {
    let server = Arc::new(TcpListener::bind((LOOPBACK, 0)).await.unwrap());
    let capture = tokio::spawn(record_http(server.clone(), &[404, 204]));
    let options = [
        ("backends", "http".into()),
        ("http_ip", "127.0.0.1".into()),
        ("http_port", server.local_addr().unwrap().port().to_string()),
        ("http_getuser_uri", "/user".into()),
        ("http_superuser_uri", "/super".into()),
        ("http_aclcheck_uri", "/acl".into()),
        (
            "http_aclcheck_params",
            "p aram=_MQX_EXTAUTH_UNSET_ENV_TEST".into(),
        ),
    ];
    let plugin = rust(&options).await;
    let identity = plugin
        .acl_identity(Subject {
            client_id: "id&raw=two",
            username: Some("user name"),
            binding: Binding {
                certificate: true,
                ..Binding::default()
            },
        })
        .unwrap();
    assert_eq!(
        plugin
            .authorize(&identity, "topic value", AclAccess::Write)
            .await
            .verdict,
        Verdict::Allow
    );
    let requests = capture.await.unwrap();
    assert!(requests[1].ends_with(b"\r\n\r\np%20aram=NULL&username=user%20name&password=&topic=topic%20value&acc=2&clientid=id&raw=two"));
}
