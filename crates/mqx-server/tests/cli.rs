use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mqextended");
#[cfg(unix)]
const PERSISTENT_CONNECT: &[u8] = b"\x10\x0f\x00\x04MQTT\x04\x00\x00\x3c\x00\x03dev";

#[cfg(unix)]
mod raft_clients {
    use bytes::{Bytes, BytesMut};
    use mqx_codec::{
        ConnAck, Connect, ConnectReturnCode, Packet, PacketId, ProtocolVersion, Publish, QoS,
        SubAck, Subscribe, SubscribeReturnCode, encode,
    };
    use std::{io, net::SocketAddr, path::Path, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::timeout,
    };

    pub(super) const WAIT: Duration = Duration::from_secs(15);
    const STATE_TOPIC: &str = "a/state";

    pub(super) fn tls_configs<const N: usize>(directory: &Path) -> [String; N] {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair,
        };
        use std::fs;

        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let ca_path = directory.join("cluster-ca.pem");
        fs::write(&ca_path, ca.pem()).unwrap();
        std::array::from_fn(|index| {
            let id = index + 1;
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, format!("mqx-node-{id}"));
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let cert = params.signed_by(&key, &ca).unwrap();
            let cert_path = directory.join(format!("cluster-{id}.pem"));
            let key_path = directory.join(format!("cluster-{id}.key"));
            fs::write(&cert_path, cert.pem()).unwrap();
            fs::write(&key_path, key.serialize_pem()).unwrap();
            format!(
                "cluster_cafile {}\ncluster_certfile {}\ncluster_keyfile {}\n",
                ca_path.display(),
                cert_path.display(),
                key_path.display(),
            )
        })
    }

    async fn send(socket: &mut TcpStream, packet: &Packet) -> io::Result<()> {
        let mut encoded = BytesMut::new();
        encode(packet, &mut encoded).unwrap();
        socket.write_all(&encoded).await
    }

    async fn expect(socket: &mut TcpStream, packet: &Packet) {
        let mut expected = BytesMut::new();
        encode(packet, &mut expected).unwrap();
        let mut received = vec![0; expected.len()];
        socket.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, &expected[..], "expected {packet:?}");
    }

    pub(super) async fn writer(addr: SocketAddr, session_present: bool) -> TcpStream {
        timeout(WAIT, async {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            socket.write_all(super::PERSISTENT_CONNECT).await.unwrap();
            expect(
                &mut socket,
                &Packet::ConnAck(ConnAck {
                    session_present,
                    code: ConnectReturnCode::Accepted,
                }),
            )
            .await;
            socket
        })
        .await
        .expect("MQTT writer did not connect")
    }

    pub(super) async fn retained_write(
        socket: &mut TcpStream,
        topic: &str,
        payload: &'static [u8],
    ) -> io::Result<()> {
        send(
            socket,
            &Packet::Publish(Publish {
                dup: false,
                qos: QoS::AtLeastOnce,
                retain: true,
                topic: topic.into(),
                packet_id: Some(PacketId::MIN),
                payload: Bytes::from_static(payload),
            }),
        )
        .await
    }

    pub(super) async fn commit(socket: &mut TcpStream, payload: &'static [u8]) {
        timeout(WAIT, async {
            retained_write(socket, STATE_TOPIC, payload).await.unwrap();
            expect(socket, &Packet::PubAck(PacketId::MIN)).await;
        })
        .await
        .expect("retained write was not acknowledged");
    }

    pub(super) async fn assert_retained(addr: SocketAddr, payload: &'static [u8]) {
        timeout(WAIT, async {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            send(
                &mut socket,
                &Packet::Connect(Connect {
                    protocol: ProtocolVersion::V311,
                    is_bridge: false,
                    clean_session: true,
                    keep_alive: 60,
                    client_id: "retained-reader".into(),
                    will: None,
                    username: None,
                    password: None,
                }),
            )
            .await
            .unwrap();
            expect(
                &mut socket,
                &Packet::ConnAck(ConnAck {
                    session_present: false,
                    code: ConnectReturnCode::Accepted,
                }),
            )
            .await;
            send(
                &mut socket,
                &Packet::Subscribe(Subscribe {
                    packet_id: PacketId::MIN,
                    filters: vec![(STATE_TOPIC.into(), QoS::AtMostOnce)],
                }),
            )
            .await
            .unwrap();
            expect(
                &mut socket,
                &Packet::SubAck(SubAck {
                    packet_id: PacketId::MIN,
                    return_codes: vec![SubscribeReturnCode::Success(QoS::AtMostOnce)],
                }),
            )
            .await;
            expect(
                &mut socket,
                &Packet::Publish(Publish {
                    dup: false,
                    qos: QoS::AtMostOnce,
                    retain: true,
                    topic: STATE_TOPIC.into(),
                    packet_id: None,
                    payload: Bytes::from_static(payload),
                }),
            )
            .await;
        })
        .await
        .expect("committed retained message was not replayed");
    }
}

#[cfg(unix)]
async fn wait_ready(socket: &tokio::net::UnixDatagram) {
    let mut packet = [0; 32];
    let len = tokio::time::timeout(std::time::Duration::from_secs(10), socket.recv(&mut packet))
        .await
        .expect("broker did not send READY=1")
        .unwrap();
    assert_eq!(&packet[..len], b"READY=1");
}

#[cfg(unix)]
async fn connect_and_read_ack(addr: std::net::SocketAddr) -> [u8; 4] {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket.write_all(PERSISTENT_CONNECT).await.unwrap();
        let mut ack = [0; 4];
        socket.read_exact(&mut ack).await.unwrap();
        ack
    })
    .await
    .unwrap()
}

// Mosquitto src/mosquitto.c: main with --test-config validates only the configuration
// file and exits 0, or 3 when no file was given.
#[test]
fn test_config_checks_the_file_without_starting() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.conf");
    // The credential file does not exist: --test-config must not load it.
    std::fs::write(
        &good,
        "listener 18990 127.0.0.1\npassword_file /nonexistent/passwd\nlog_dest stderr\n",
    )
    .unwrap();
    let output = Command::new(BIN)
        .args(["--test-config", "-c"])
        .arg(&good)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Configuration file is OK."));

    let bad = dir.path().join("bad.conf");
    std::fs::write(&bad, "listener 1883\nbridge_bogus 1\n").unwrap();
    let output = Command::new(BIN)
        .args(["--test-config", "-c"])
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));

    let output = Command::new(BIN).arg("--test-config").output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Please provide a configuration file to test.")
    );
}

#[test]
fn help_and_invalid_mosquitto_flags_are_actionable() {
    let output = Command::new(BIN).arg("-h").output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Usage: mqextended")
    );
    // Missing option values and the unknown flag come from Mosquitto test/broker/16-cmd-args.py.
    for (arg, diagnostic) in [
        ("-p", "-p argument given, but no port specified."),
        ("-c", "-c argument given, but no config file specified."),
        ("--unknown", "Unknown option '--unknown'."),
    ] {
        let output = Command::new(BIN).arg(arg).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains(diagnostic)
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn invalid_credentials_on_sighup_stop_the_broker() {
    use std::{fs, net::TcpListener, process::Stdio, time::Duration};

    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use tokio::{net::UnixDatagram, time::timeout};
    for (option, good, bad) in [
        ("acl_file", "topic readwrite a/#", "topic readwrite a#"),
        ("password_file", "", "test:bad\n"),
    ] {
        let pin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = pin.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("broker.conf");
        let rules = dir.path().join("rules");
        let log = dir.path().join("broker.log");
        let notify_path = dir.path().join("notify");
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        fs::write(&rules, good).unwrap();
        fs::write(&config, format!("user root\nlistener {} 127.0.0.1\nallow_anonymous true\n{option} {}\nlog_type information\nlog_type error\nlog_dest file {}\nlog_timestamp_format %Y\nconnection_messages false\n", addr.port(), rules.display(), log.display())).unwrap();
        drop(pin);
        let child = tokio::process::Command::new(BIN)
            .arg("-c")
            .arg(&config)
            .env("NOTIFY_SOCKET", &notify_path)
            .env("TOKIO_WORKER_THREADS", "2")
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id().unwrap() as i32);
        wait_ready(&notify).await;
        assert_eq!(connect_and_read_ack(addr).await, [0x20, 2, 0, 0]);
        fs::write(&rules, bad).unwrap();
        kill(pid, Signal::SIGHUP).unwrap();
        let output = timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        let log = fs::read_to_string(&log).unwrap();
        assert!(log.contains(&format!("Security reload failed: Unable to load {option}")));
        let (timestamp, _) = log.lines().next().unwrap().split_once(": ").unwrap();
        assert_eq!(timestamp.len(), 4);
        assert!(timestamp.bytes().all(|digit| digit.is_ascii_digit()));
        assert!(log.contains(": Reloading config."));
        assert!(!log.contains("New connection from"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn configured_single_voter_creates_raft_storage_and_restores_an_mqtt_session() {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use raft_clients::{assert_retained, commit, tls_configs, writer};
    use std::{fs, net::TcpListener, process::Stdio, time::Duration};

    let mqtt = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let raft = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mqtt_addr = mqtt.local_addr().unwrap();
    let raft_addr = raft.local_addr().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let notify_path = directory.path().join("notify");
    let notify = tokio::net::UnixDatagram::bind(&notify_path).unwrap();
    let path = directory.path().join("broker.conf");
    let storage = directory.path().join("raft state");
    let acl = directory.path().join("acl");
    fs::write(&acl, "topic readwrite a/#\n").unwrap();
    let [tls] = tls_configs::<1>(directory.path());
    fs::write(
        &path,
        format!(
            "user root\nlistener {} 127.0.0.1\nallow_anonymous true\nacl_file {}\ncluster_node_id 1\n\
        cluster_bind {raft_addr}\ncluster_peer 1 {raft_addr}\ncluster_data_dir {}\n{tls}",
            mqtt_addr.port(),
            acl.display(),
            storage.display(),
        ),
    )
    .unwrap();
    assert!(!storage.exists());
    drop((mqtt, raft));

    for resumed in [false, true] {
        let child = tokio::process::Command::new(BIN)
            .arg("-c")
            .arg(&path)
            .env("NOTIFY_SOCKET", &notify_path)
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id().unwrap() as i32);
        wait_ready(&notify).await;
        let mut publisher = writer(mqtt_addr, resumed).await;
        if resumed {
            assert_retained(mqtt_addr, b"singleton state").await;
        } else {
            commit(&mut publisher, b"singleton state").await;
        }
        drop(publisher);
        assert!(storage.is_dir());
        kill(pid, Signal::SIGTERM).unwrap();
        let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn fatal_raft_wal_error_exits_nonzero_without_auto_recover() {
    use raft_clients::{WAIT, commit, retained_write, writer};
    use std::{fs, net::TcpListener, process::Stdio};
    use tokio::{net::UnixDatagram, time::timeout};

    static PAYLOAD: [u8; 256 * 1024] = [b'x'; 256 * 1024];
    let mqtt = TcpListener::bind("127.0.0.1:0").unwrap();
    let raft = TcpListener::bind("127.0.0.1:0").unwrap();
    let mqtt_addr = mqtt.local_addr().unwrap();
    let raft_addr = raft.local_addr().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broker.conf");
    let notify_path = directory.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    fs::write(
        &path,
        format!(
            "user root\nlistener {} 127.0.0.1\nallow_anonymous true\n\
             log_dest stdout\nlog_type error\ncluster_node_id 1\n\
             cluster_bind {raft_addr}\ncluster_peer 1 {raft_addr}\n\
             cluster_data_dir {}\ncluster_insecure_plaintext true\n",
            mqtt_addr.port(),
            directory.path().join("raft").display(),
        ),
    )
    .unwrap();
    drop((mqtt, raft));

    // Ignore SIGXFSZ so the WAL writer gets EFBIG rather than the kernel killing
    // the broker. A pipe keeps log writes outside the regular-file size limit.
    let child = tokio::process::Command::new("sh")
        .args([
            "-ec",
            "trap '' XFSZ; ulimit -f 64; exec \"$@\"",
            "--",
            BIN,
            "-c",
        ])
        .arg(&path)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_ready(&notify).await;
    let mut publisher = writer(mqtt_addr, false).await;
    commit(&mut publisher, b"before storage failure").await;
    timeout(WAIT, retained_write(&mut publisher, "a/fatal", &PAYLOAD))
        .await
        .unwrap()
        .unwrap();
    let output = timeout(WAIT, child.wait_with_output())
        .await
        .expect("broker kept running after its Raft WAL write failed")
        .unwrap();
    let log = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(3), "{log}");
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("Raft node failed:") && line.contains("File too large"))
            .count(),
        1,
        "{log}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn two_voters_lose_quorum_and_recover_retained_state_after_restart() {
    use raft_clients::{WAIT, assert_retained, commit, retained_write, tls_configs, writer};
    use std::{
        fs,
        io::{self, ErrorKind},
        net::{SocketAddr, TcpListener},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UnixDatagram},
        time::{sleep, timeout},
    };

    async fn http(addr: SocketAddr, path: &str) -> (u16, String) {
        let response = timeout(WAIT, async {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        })
        .await
        .unwrap_or_else(|_| panic!("{addr}{path} did not respond"));
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head
            .split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, body.into())
    }

    async fn wait_for_readiness(addr: SocketAddr, expected: u16) {
        timeout(WAIT, async {
            loop {
                let (status, _) = http(addr, "/api/v1/mqx/ready").await;
                if status == expected {
                    break;
                }
                assert!(
                    matches!(status, 200 | 503),
                    "unexpected readiness: {status}"
                );
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("readiness at {addr} did not become {expected}"));
    }

    async fn raft_status(addr: SocketAddr) -> serde_json::Value {
        let (status, body) = http(addr, "/api/v1/mqx/cluster").await;
        assert_eq!(status, 200);
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["raft"].take()
    }

    async fn assert_mqtt_refused(socket: &mut TcpStream, sent: io::Result<()>, request: &str) {
        let result = match sent {
            Err(error) => Err(error),
            Ok(()) => timeout(WAIT, socket.read_u8())
                .await
                .unwrap_or_else(|_| panic!("{request} did not finish without quorum")),
        };
        let error = result.expect_err(request);
        assert!(
            matches!(
                error.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ),
            "{request}: {error}"
        );
    }

    let sockets: [[_; 2]; 3] =
        std::array::from_fn(|_| std::array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap()));
    let [mqtt, raft, http_addr] = sockets
        .each_ref()
        .map(|pair| pair.each_ref().map(|s| s.local_addr().unwrap()));
    let directory = tempfile::tempdir().unwrap();
    let tls = tls_configs::<2>(directory.path());
    // Two voters commit only with both acknowledgements. On CI a 1 s lease
    // expired while the leader's appends to the just-restarted node timed out.
    let configs = [0, 1].map(|index| {
        let id = index + 1;
        let path = directory.path().join(format!("node-{id}.conf"));
        fs::write(
            &path,
            format!(
                "user root\nallow_anonymous true\nlistener {} 127.0.0.1\n\
                 listener {} 127.0.0.1\nprotocol http_api\n\
                 cluster_node_id {id}\ncluster_bind {}\ncluster_peer 1 {}\ncluster_peer 2 {}\n\
                 cluster_data_dir {}\ncluster_request_timeout 5000\ncluster_lease_interval 100\ncluster_lease_timeout 3000\n{}",
                mqtt[index].port(),
                http_addr[index].port(),
                raft[index],
                raft[0],
                raft[1],
                directory.path().join(format!("raft-{id}")).display(),
                tls[index],
            ),
        )
        .unwrap();
        path
    });
    let notify_paths = configs.each_ref().map(|path| path.with_extension("notify"));
    let notify = notify_paths
        .each_ref()
        .map(|path| UnixDatagram::bind(path).unwrap());
    let late_peer = sockets[1][1].try_clone().unwrap();
    late_peer.set_nonblocking(true).unwrap();
    let late_peer = tokio::net::TcpListener::from_std(late_peer).unwrap();
    drop(sockets);
    let start = |index: usize| {
        tokio::process::Command::new(BIN)
            .arg("-c")
            .arg(&configs[index])
            .env("NOTIFY_SOCKET", &notify_paths[index])
            .env("TOKIO_WORKER_THREADS", "2")
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    };

    let mut first = start(0);
    // Wait for the first voter to contact its missing peer. Its own port
    // opens before WAL initialization, which can take seconds on a slow disk.
    let (attempt, _) = timeout(WAIT, late_peer.accept())
        .await
        .expect("first voter never contacted its peer")
        .unwrap();
    drop((attempt, late_peer));
    // A staggered cold start must not require restarting the first voter
    // when the second arrives after the configured Raft request deadline.
    assert!(
        timeout(Duration::from_millis(5500), first.wait())
            .await
            .is_err(),
        "first voter exited before its peer started"
    );
    let mut brokers = [first, start(1)];
    for index in [0, 1] {
        wait_ready(&notify[index]).await;
        wait_for_readiness(http_addr[index], 200).await;
    }
    let survivor = match raft_status(http_addr[0]).await["leader"].as_u64() {
        Some(1) => 0,
        Some(2) => 1,
        leader => panic!("two ready voters reported an invalid leader: {leader:?}"),
    };
    let lost = 1 - survivor;
    let mut publisher = writer(mqtt[survivor], false).await;
    commit(&mut publisher, b"before loss").await;
    assert_retained(mqtt[lost], b"before loss").await;

    brokers[lost].kill().await.unwrap();
    let survivor_http = http_addr[survivor];
    wait_for_readiness(survivor_http, 503).await;

    let committed = raft_status(survivor_http).await["committed_index"]
        .as_u64()
        .unwrap();
    let mut newcomer = TcpStream::connect(mqtt[survivor]).await.unwrap();
    let sent = newcomer.write_all(PERSISTENT_CONNECT).await;
    assert_mqtt_refused(&mut newcomer, sent, "survivor admitted a new MQTT client").await;
    // A timed-out proposal can still commit after quorum returns. Use a separate
    // topic so that replaying the pre-loss state does not depend on that outcome.
    let sent = retained_write(&mut publisher, "a/minority", b"without quorum").await;
    assert_mqtt_refused(
        &mut publisher,
        sent,
        "survivor acknowledged a durable write",
    )
    .await;
    assert_eq!(
        raft_status(survivor_http).await["committed_index"].as_u64(),
        Some(committed),
        "the Raft commit index advanced without a majority"
    );

    brokers[lost] = start(lost);
    wait_ready(&notify[lost]).await;
    wait_for_readiness(http_addr[lost], 200).await;
    wait_for_readiness(survivor_http, 200).await;
    assert_retained(mqtt[lost], b"before loss").await;
    let mut publisher = writer(mqtt[lost], true).await;
    commit(&mut publisher, b"after restore").await;
    assert_retained(mqtt[survivor], b"after restore").await;

    for broker in &mut brokers {
        broker.kill().await.unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_promotes_a_joiner_and_then_disconnects_it_on_removal() {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use std::{
        fs,
        io::ErrorKind,
        net::{SocketAddr, TcpListener},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UnixDatagram},
        time::{sleep, timeout},
    };

    async fn connect(addr: SocketAddr) -> std::io::Result<(TcpStream, [u8; 4])> {
        let mut socket = TcpStream::connect(addr).await?;
        socket.write_all(PERSISTENT_CONNECT).await?;
        let mut ack = [0; 4];
        socket.read_exact(&mut ack).await?;
        Ok((socket, ack))
    }

    fn closed(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
        )
    }

    // The process can report READY before a joining voter is promoted and
    // finishes security registration. Only a complete CONNACK proves MQTT is ready.
    async fn wait_serving(addr: SocketAddr) -> (TcpStream, [u8; 4]) {
        timeout(Duration::from_secs(10), async {
            loop {
                match connect(addr).await {
                    Ok(client) => return client,
                    Err(error) if closed(&error) => sleep(Duration::from_millis(20)).await,
                    Err(error) => panic!("MQTT connect to {addr}: {error}"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("MQTT listener {addr} never served a CONNECT"))
    }

    let sockets: [_; 4] = std::array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap());
    let [mqtt1, raft1, mqtt2, raft2] = sockets.each_ref().map(|s| s.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let first_config = directory.path().join("one.conf");
    let second_config = directory.path().join("two.conf");
    let config = |id: u64, mqtt: std::net::SocketAddr, raft| {
        format!(
            "user root\nlistener {} 127.0.0.1\nallow_anonymous true\ncluster_node_id {id}\n\
             cluster_bind {raft}\ncluster_peer 1 {raft1}\ncluster_insecure_plaintext true\n\
             cluster_data_dir {}\ncluster_lease_interval 100\ncluster_lease_timeout 1000\n",
            mqtt.port(),
            directory.path().join(id.to_string()).display(),
        )
    };
    let initial = config(1, mqtt1, raft1);
    fs::write(&first_config, &initial).unwrap();
    fs::write(
        &second_config,
        format!(
            "{}cluster_peer 2 {raft2}\ncluster_join true\n",
            config(2, mqtt2, raft2)
        ),
    )
    .unwrap();
    drop(sockets);
    let start = |path: &std::path::Path| {
        let notify_path = path.with_extension("notify");
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        let child = tokio::process::Command::new(BIN)
            .arg("-c")
            .arg(path)
            .env("NOTIFY_SOCKET", &notify_path)
            .env("TOKIO_WORKER_THREADS", "2")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        (child, notify)
    };
    let (mut first, first_ready) = start(&first_config);
    let pid = Pid::from_raw(first.id().unwrap().try_into().unwrap());
    let wait = Duration::from_secs(10);
    wait_ready(&first_ready).await;
    assert_eq!(wait_serving(mqtt1).await.1, [0x20, 2, 0, 0]);
    let (mut second, second_ready) = start(&second_config);
    wait_ready(&second_ready).await;
    let unpromoted = timeout(wait, connect(mqtt2))
        .await
        .expect("unpromoted learner did not refuse the connection")
        .expect_err("unpromoted learner served MQTT");
    assert!(closed(&unpromoted), "{unpromoted}");

    fs::write(
        &first_config,
        format!("{initial}cluster_peer 2 {raft2}\ncluster_membership_generation 1\n"),
    )
    .unwrap();
    kill(pid, Signal::SIGHUP).unwrap();
    let (mut connected, ack) = wait_serving(mqtt2).await;
    assert_eq!(ack, [0x20, 2, 1, 0]);

    fs::write(
        &first_config,
        format!("{initial}cluster_membership_generation 2\n"),
    )
    .unwrap();
    kill(pid, Signal::SIGHUP).unwrap();
    let rejected = timeout(wait, connected.read_u8())
        .await
        .expect("retired node did not close the existing connection")
        .expect_err("retired node still served the existing connection");
    assert!(closed(&rejected), "{rejected}");
    let rejected = timeout(wait, connect(mqtt2))
        .await
        .expect("retired node did not refuse a new connection")
        .expect_err("retired node served a new MQTT connection");
    assert!(closed(&rejected), "{rejected}");
    assert_eq!(wait_serving(mqtt1).await.1, [0x20, 2, 1, 0]);

    for child in [&mut first, &mut second] {
        kill(
            Pid::from_raw(child.id().unwrap().try_into().unwrap()),
            Signal::SIGTERM,
        )
        .unwrap();
        assert!(
            timeout(wait, child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires the Mosquitto 2.1.4 reference with Unix sockets"]
async fn unix_listener_replaces_stale_socket_and_unlinks_on_shutdown() {
    use std::{
        fs,
        os::unix::fs::{FileTypeExt, PermissionsExt},
        path::PathBuf,
        process::Stdio,
        time::Duration,
    };

    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        time::{sleep, timeout},
    };

    let reference = PathBuf::from(
        std::env::var_os("MOSQUITTO_BUILD_DIR")
            .expect("set MOSQUITTO_BUILD_DIR to the Mosquitto 2.1.4 build directory"),
    )
    .join("src/mosquitto")
    .canonicalize()
    .unwrap();
    let wait = Duration::from_secs(5);
    for binary in [reference, PathBuf::from(BIN)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mqtt.sock");
        let log_path = dir.path().join("broker.log");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        fs::write(
            dir.path().join("broker.conf"),
            "user root\nlistener 0 mqtt.sock\nlistener_allow_anonymous true\n\
             set_tcp_nodelay true\nlog_dest stderr\nlog_type all\n",
        )
        .unwrap();
        let mut child = tokio::process::Command::new(&binary)
            .args(["-c", "broker.conf"])
            .current_dir(dir.path())
            .env_remove("PUID")
            .env_remove("PGID")
            .env("TOKIO_WORKER_THREADS", "2")
            .stderr(Stdio::from(fs::File::create(&log_path).unwrap()))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let (ack, pong) = timeout(wait, async {
            let mut stream = loop {
                if let Ok(stream) = UnixStream::connect(&path).await {
                    break stream;
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "{binary:?} exited before accepting a Unix connection:\n{}",
                    fs::read_to_string(&log_path).unwrap(),
                );
                sleep(Duration::from_millis(10)).await;
            };
            // Mosquitto test/broker/01-connect-unix-socket.py checks MQTT CONNECT/CONNACK.
            stream
                .write_all(b"\x10\x17\x00\x04MQTT\x04\x02\x00\x3c\x00\x0bunix-socket")
                .await
                .unwrap();
            let mut ack = [0; 4];
            stream.read_exact(&mut ack).await.unwrap();
            stream.write_all(b"\xc0\x00").await.unwrap();
            let mut pong = [0; 2];
            stream.read_exact(&mut pong).await.unwrap();
            // Drain the disconnect before SIGTERM. In Mosquitto loop.c the
            // signal handler only clears g_run; racing it with mux__handle
            // on an active disconnect can leave epoll waiting for the next tick.
            stream.write_all(b"\xe0\x00").await.unwrap();
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            (ack, pong)
        })
        .await
        .unwrap_or_else(|_| panic!("{binary:?} did not serve MQTT on its Unix socket"));
        assert_eq!(ack, [0x20, 2, 0, 0], "{binary:?}");
        assert_eq!(pong, [0xd0, 0], "{binary:?}");

        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket(), "{binary:?}");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o770, "{binary:?}");
        let pid = Pid::from_raw(child.id().unwrap().try_into().unwrap());
        kill(pid, Signal::SIGTERM).unwrap();
        let status = timeout(Duration::from_secs(10), child.wait())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{binary:?} did not stop:\n{}",
                    fs::read_to_string(&log_path).unwrap()
                )
            })
            .unwrap();
        assert!(status.success(), "{binary:?} exited with {status}");
        assert!(
            !path.exists(),
            "{binary:?} left the listener pathname behind"
        );

        let log = fs::read_to_string(log_path).unwrap();
        assert!(log.contains("Opening unix listen socket on path mqtt.sock."));
        assert!(log.contains("New connection from mqtt.sock:0 on port 0."));
        assert!(!log.contains("Unable to set TCP_NODELAY"));
    }
}
