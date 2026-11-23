//! Live ports of Mosquitto 2.1.4's `test/broker/06-bridge-*.py` scenarios.
//!
//! The broker under test runs in `Harness`. Where the reference script uses a
//! scripted upstream, `Remote` is the listening end of that bridge connection.

use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant};

use mqx_codec::ProtocolVersion;
use mqx_difftest::{
    BrokerConfig, BrokerKind, ClusterConfig, Connection, Harness, Reading, Transcript,
};

const RESPONSE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(20);
const ANONYMOUS: &str = "allow_anonymous true\n";
const PERSISTENT: &str = "allow_anonymous true\npersistence true\npersistence_file bridge.db\n";
const VERSIONS: [Version; 2] = [Version::V311, Version::V5];
const BRIDGE_OPTS: u8 = 0x0c; // No Local and Retain As Published
const PING: &[u8] = &[0xc0, 0];
const PONG: &[u8] = &[0xd0, 0];
const DISCONNECT: &[u8] = &[0xe0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    V31,
    V311,
    V5,
}

impl Version {
    fn directive(self) -> &'static str {
        match self {
            Self::V31 => "mqttv31",
            Self::V311 => "mqttv311",
            Self::V5 => "mqttv50",
        }
    }

    fn level(self) -> u8 {
        match self {
            Self::V31 => 3,
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }
}

fn config(conf: &str) -> BrokerConfig<'_> {
    BrokerConfig {
        conf,
        ..BrokerConfig::default()
    }
}

fn start(kind: BrokerKind, conf: &str) -> Harness {
    Harness::start(kind, config(conf)).unwrap_or_else(|error| panic!("{kind:?}: {error}"))
}

fn bridge_config(version: Version, addr: SocketAddr, options: &str, topics: &str) -> String {
    // bridge.c: bridge_check schedules a retry once. An earlier event can
    // wake the reference mux before its retry is due without rearming that
    // timer. Give the reference loop a regular tick independent of traffic.
    format!(
        "sys_interval 1\nconnection bridge_sample\naddress {addr}\nbridge_protocol_version {}\n{options}{topics}",
        version.directive()
    )
}

fn differential<T: Debug + PartialEq>(scenario: impl Fn(BrokerKind) -> T) {
    let expected = scenario(BrokerKind::Mosquitto);
    let actual = scenario(BrokerKind::MqExtended);
    assert_eq!(
        actual, expected,
        "mqextended bridge transcript differs from Mosquitto"
    );
}

fn default_id() -> &'static str {
    static ID: LazyLock<String> = LazyLock::new(|| {
        let hostname = Command::new("hostname").output().unwrap();
        assert!(hostname.status.success());
        format!(
            "{}.bridge_sample",
            std::str::from_utf8(&hostname.stdout).unwrap().trim_end()
        )
    });
    &ID
}

// Small wire fixtures allow exact comparisons across protocol versions and
// the deliberately malformed frames sent by several of the Python scenarios.
fn frame(header: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![header];
    let mut len = body.len();
    loop {
        let digit = u8::try_from(len % 128).unwrap();
        len /= 128;
        packet.push(digit | if len == 0 { 0 } else { 0x80 });
        if len == 0 {
            break;
        }
    }
    packet.extend_from_slice(body);
    packet
}

fn field(body: &mut Vec<u8>, value: &[u8]) {
    body.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    body.extend_from_slice(value);
}

fn properties(body: &mut Vec<u8>, props: &[u8]) {
    assert!(props.len() < 128);
    body.push(u8::try_from(props.len()).unwrap());
    body.extend_from_slice(props);
}

fn connect_packet(
    level: u8,
    id: &str,
    keepalive: u16,
    flags: u8,
    props: &[u8],
    will_topic: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    field(
        &mut body,
        if level & 0x7f == 3 {
            b"MQIsdp"
        } else {
            b"MQTT"
        },
    );
    body.extend_from_slice(&[level, flags]);
    body.extend(keepalive.to_be_bytes());
    if level == 5 {
        properties(&mut body, props);
    }
    field(&mut body, id.as_bytes());
    if let Some(topic) = will_topic {
        if level == 5 {
            properties(&mut body, &[]);
        }
        field(&mut body, topic.as_bytes());
        field(&mut body, b"0");
    }
    frame(0x10, &body)
}

fn connack(version: Version, present: bool, reason: u8, extra: &[u8]) -> Vec<u8> {
    let mut body = vec![u8::from(present), reason];
    if version == Version::V5 {
        let mut props = vec![0x22, 0, 10]; // Topic Alias Maximum
        props.extend_from_slice(extra);
        props.extend_from_slice(&[0x27, 0, 30, 132, 128, 0x21, 0, 20]);
        properties(&mut body, &props);
    }
    frame(0x20, &body)
}

fn subscribe_packet(version: Version, mid: u16, topic: &str, options: u8) -> Vec<u8> {
    let mut body = mid.to_be_bytes().to_vec();
    if version == Version::V5 {
        properties(&mut body, &[]);
    }
    field(&mut body, topic.as_bytes());
    body.push(options);
    frame(0x82, &body)
}

fn suback(version: Version, mid: u16, qos: u8) -> Vec<u8> {
    let mut body = mid.to_be_bytes().to_vec();
    if version == Version::V5 {
        properties(&mut body, &[]);
    }
    body.push(qos);
    frame(0x90, &body)
}

fn publish(version: Version, topic: &str, payload: &[u8], qos: u8, mid: u16, flags: u8) -> Vec<u8> {
    let mut body = Vec::new();
    field(&mut body, topic.as_bytes());
    if qos != 0 {
        body.extend(mid.to_be_bytes());
    }
    if version == Version::V5 {
        properties(&mut body, &[]);
    }
    body.extend_from_slice(payload);
    frame(0x30 | qos << 1 | flags, &body)
}

fn ack(header: u8, mid: u16) -> Vec<u8> {
    frame(header, &mid.to_be_bytes())
}

fn puback(version: Version, mid: u16, reason: u8) -> Vec<u8> {
    if version == Version::V5 && reason != 0 {
        let [hi, lo] = mid.to_be_bytes();
        frame(0x40, &[hi, lo, reason])
    } else {
        ack(0x40, mid)
    }
}

fn read_frame(socket: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(None),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let mut wire = vec![byte[0]];
    let mut len = 0;
    for shift in [0, 7, 14, 21] {
        socket.read_exact(&mut byte)?;
        wire.push(byte[0]);
        len |= usize::from(byte[0] & 127) << shift;
        if byte[0] < 128 {
            let header_len = wire.len();
            wire.resize(header_len + len, 0);
            socket.read_exact(&mut wire[header_len..])?;
            return Ok(Some(wire));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "bad MQTT frame length",
    ))
}

struct Remote {
    listener: TcpListener,
    transcript: Vec<Vec<u8>>,
}

impl Remote {
    fn bind() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            listener,
            transcript: Vec::new(),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    fn accept_within(&self, timeout: Duration) -> Option<TcpStream> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    socket.set_read_timeout(Some(RESPONSE)).unwrap();
                    socket.set_write_timeout(Some(RESPONSE)).unwrap();
                    socket.set_nodelay(true).unwrap();
                    return Some(socket);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return None;
                    }
                    thread::sleep(POLL.min(remaining));
                }
                Err(error) => panic!("accepting bridge peer: {error}"),
            }
        }
    }

    #[track_caller]
    fn accept(&self) -> TcpStream {
        self.accept_within(RESPONSE)
            .expect("bridge did not connect")
    }

    #[track_caller]
    fn expect(&mut self, socket: &mut TcpStream, expected: &[u8]) {
        let packet = read_frame(socket)
            .unwrap_or_else(|error| panic!("bridge read failed; expected {expected:02x?}: {error}"))
            .expect("bridge closed before its expected packet");
        assert_eq!(packet, expected, "bridge packet");
        self.transcript.push(packet);
    }

    #[track_caller]
    fn connect(&mut self, version: Version, alias: bool) -> TcpStream {
        let mut socket = self.accept();
        self.expect(
            &mut socket,
            &bridge_connect(version, default_id(), 60, alias, None),
        );
        socket.write_all(&connack(version, false, 0, &[])).unwrap();
        socket
    }

    #[track_caller]
    fn subscribe(
        &mut self,
        socket: &mut TcpStream,
        version: Version,
        mid: u16,
        topic: &str,
        qos: u8,
    ) {
        let options = qos
            | if version == Version::V5 {
                BRIDGE_OPTS
            } else {
                0
            };
        self.expect(socket, &subscribe_packet(version, mid, topic, options));
        socket.write_all(&suback(version, mid, qos)).unwrap();
    }
}

fn bridge_connect(
    version: Version,
    id: &str,
    keepalive: u16,
    alias: bool,
    will: Option<(&str, u8, bool)>,
) -> Vec<u8> {
    let level = version.level() | if version == Version::V5 { 0 } else { 0x80 };
    let props: &[u8] = if alias {
        &[0x22, 0, 10, 0x21, 0, 20]
    } else {
        &[0x21, 0, 20]
    };
    let flags = will.map_or(0, |(_, qos, retain)| {
        4 | (qos << 3) | (u8::from(retain) << 5)
    });
    connect_packet(
        level,
        id,
        keepalive,
        flags,
        props,
        will.map(|(topic, _, _)| topic),
    )
}

#[track_caller]
fn local_expect(h: &mut Harness, client: Connection, expected: &[u8]) {
    match h.receive_raw(client, RESPONSE).unwrap() {
        Reading::Raw(wire) => assert_eq!(wire.as_ref(), expected, "{client:?}"),
        other => panic!("{client:?}: expected {expected:02x?}, got {other:?}"),
    }
}

#[track_caller]
fn send(h: &mut Harness, client: Connection, packet: &[u8]) {
    h.send_raw(client, packet).unwrap();
}

#[track_caller]
fn client(
    h: &mut Harness,
    node: usize,
    version: Version,
    id: &str,
    private: bool,
    persistent: bool,
    present: bool,
) -> Connection {
    let connection = match version {
        Version::V31 => h.open_on(node, ProtocolVersion::V31),
        Version::V311 => h.open_on(node, ProtocolVersion::V311),
        Version::V5 => h.open_v5_on(node),
    }
    .unwrap();
    let level = version.level() | if private { 0x80 } else { 0 };
    let props: &[u8] = if persistent {
        &[0x21, 0, 20, 0x11, 0, 0, 0x13, 0x88]
    } else {
        &[0x21, 0, 20]
    };
    send(
        h,
        connection,
        &connect_packet(level, id, 60, if persistent { 0 } else { 2 }, props, None),
    );
    local_expect(h, connection, &connack(version, present, 0, &[]));
    connection
}

#[track_caller]
fn local_subscribe(
    h: &mut Harness,
    client: Connection,
    version: Version,
    mid: u16,
    filter: &str,
    opts: u8,
) {
    send(h, client, &subscribe_packet(version, mid, filter, opts));
    local_expect(h, client, &suback(version, mid, opts & 3));
}

#[track_caller]
fn ping(h: &mut Harness, client: Connection) {
    send(h, client, PING);
    local_expect(h, client, PONG);
}

#[track_caller]
fn closed(socket: &mut TcpStream) {
    let packet = read_frame(socket).expect("waiting for bridge TCP close");
    assert_eq!(
        packet, None,
        "bridge should close without another MQTT packet"
    );
}

const DISCONNECT_TOPIC: &str = "bridge/disconnect/test";
const DISCONNECT_MESSAGE: &[u8] = b"disconnect-message";

// 06-bridge-b2br-disconnect-qos{1,2}.py: remote -> bridge.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn inbound_qos_survives_peer_disconnects() {
    for version in VERSIONS {
        for qos in [1, 2] {
            differential(|kind| {
                let mut remote = Remote::bind();
                let conf = bridge_config(
                    version,
                    remote.addr(),
                    "notifications false\nrestart_timeout 1\n",
                    &format!("topic bridge/# both {qos}\n"),
                );
                let h = start(kind, &conf);
                let mut peer = remote.connect(version, true);
                remote.subscribe(&mut peer, version, 1, "bridge/#", qos);
                let mid = if qos == 1 { 3 } else { 5 };
                let packet = |mid, flags| {
                    publish(
                        version,
                        DISCONNECT_TOPIC,
                        DISCONNECT_MESSAGE,
                        qos,
                        mid,
                        flags,
                    )
                };
                peer.write_all(&packet(mid, 0)).unwrap();
                drop(peer);

                let mut peer = remote.connect(version, true);
                remote.subscribe(&mut peer, version, 2, "bridge/#", qos);
                if qos == 1 {
                    // The ACK must be for this new PUBLISH, not the one on the old socket.
                    peer.write_all(&packet(20, 0)).unwrap();
                    remote.expect(&mut peer, &ack(0x40, 20));
                } else {
                    peer.write_all(&packet(mid, 8)).unwrap();
                    remote.expect(&mut peer, &ack(0x50, mid));
                    peer.write_all(&ack(0x62, mid)).unwrap();
                    drop(peer);

                    let mut peer = remote.connect(version, true);
                    remote.subscribe(&mut peer, version, 3, "bridge/#", qos);
                    peer.write_all(&packet(mid, 8)).unwrap();
                    remote.expect(&mut peer, &ack(0x50, mid));
                    peer.write_all(&ack(0x62, mid)).unwrap();
                    remote.expect(&mut peer, &ack(0x70, mid));
                }
                (remote.transcript, h.into_transcript())
            });
        }
    }
}

#[track_caller]
fn publish_local(h: &mut Harness, client: Connection, packet: &[u8], qos: u8, mid: u16) {
    send(h, client, packet);
    match qos {
        0 => {}
        1 => local_expect(h, client, &ack(0x40, mid)),
        2 => {
            local_expect(h, client, &ack(0x50, mid));
            send(h, client, &ack(0x62, mid));
            local_expect(h, client, &ack(0x70, mid));
        }
        _ => unreachable!("invalid QoS {qos}"),
    }
}

// 06-bridge-br2b-disconnect-qos{1,2}.py: bridge -> remote.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn outbound_qos_retries_same_packet_id_after_disconnect() {
    for version in VERSIONS {
        for qos in [1, 2] {
            differential(|kind| {
                let mut remote = Remote::bind();
                let conf = bridge_config(
                    version,
                    remote.addr(),
                    "notifications false\nrestart_timeout 2\nbridge_max_topic_alias 0\n",
                    &format!("topic bridge/# both {qos}\n"),
                );
                let mut h = start(kind, &format!("{ANONYMOUS}log_type all\n{conf}"));
                let mut peer = remote.connect(version, false);
                remote.subscribe(&mut peer, version, 1, "bridge/#", qos);
                let local = client(&mut h, 1, version, "test-helper", false, false, false);
                let packet = |mid, flags| {
                    publish(
                        version,
                        DISCONNECT_TOPIC,
                        DISCONNECT_MESSAGE,
                        qos,
                        mid,
                        flags,
                    )
                };
                let sent_mid = if qos == 1 { 2 } else { 312 };
                publish_local(&mut h, local, &packet(sent_mid, 0), qos, sent_mid);
                h.close_socket(local);
                remote.expect(&mut peer, &packet(2, 0));
                drop(peer);

                let mut peer = remote.connect(version, false);
                remote.subscribe(&mut peer, version, 3, "bridge/#", qos);
                remote.expect(&mut peer, &packet(2, 8));
                if qos == 2 {
                    peer.write_all(&ack(0x50, 2)).unwrap();
                    remote.expect(&mut peer, &ack(0x62, 2));
                    drop(peer);

                    let mut peer = remote.accept_within(RESPONSE).unwrap_or_else(|| {
                        panic!(
                            "{kind:?} did not resume QoS 2 using {version:?}:\n{}",
                            h.node_log(1).unwrap()
                        )
                    });
                    remote.expect(
                        &mut peer,
                        &bridge_connect(version, default_id(), 60, false, None),
                    );
                    peer.write_all(&connack(version, false, 0, &[])).unwrap();
                    remote.subscribe(&mut peer, version, 4, "bridge/#", qos);
                    remote.expect(&mut peer, &ack(0x62, 2));
                    peer.write_all(&ack(0x70, 2)).unwrap();
                }
                (remote.transcript, h.into_transcript())
            });
        }
    }
}

// Mosquitto 2.1.4 test/broker/08-tls-psk-bridge.py and its .psk fixture.
#[test]
#[ignore = "requires the Mosquitto 2.1.4 reference built with TLS-PSK and mqextended"]
fn outgoing_psk_bridge_delivers_through_mosquitto() {
    differential(|kind| {
        let dir = tempfile::tempdir().unwrap();
        let psk_file = dir.path().join("bridge.psk");
        std::fs::write(&psk_file, "psk-test:deadbeef\n").unwrap();
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let remote = reservation.local_addr().unwrap();
        let config = format!(
            "{ANONYMOUS}psk_file {}\nlistener {} 127.0.0.1\npsk_hint hint\n",
            psk_file.display(),
            remote.port(),
        );
        drop(reservation);
        let mut upstream = start(BrokerKind::Mosquitto, &config);
        let version = Version::V311;
        let subscriber = client(
            &mut upstream,
            1,
            version,
            "no-psk-test-client",
            false,
            false,
            false,
        );
        let state = "psk/bridge-state";
        for (mid, topic) in [(1, "psk/test"), (2, state)] {
            send(
                &mut upstream,
                subscriber,
                &subscribe_packet(version, mid, topic, 0),
            );
            local_expect(&mut upstream, subscriber, &suback(version, mid, 0));
        }
        let bridge = bridge_config(
            version,
            remote,
            "bridge_identity psk-test\nbridge_psk deadbeef\nnotification_topic psk/bridge-state\n",
            "topic psk/test out 0\n",
        );
        let mut local = start(kind, &format!("{ANONYMOUS}{bridge}"));
        // Wait for the bridge's remote notification before publishing at QoS 0.
        local_expect(
            &mut upstream,
            subscriber,
            &publish(version, state, b"1", 0, 0, 0),
        );
        let publisher = client(&mut local, 1, version, "publisher", false, false, false);
        let packet = publish(version, "psk/test", b"message", 0, 0, 0);
        send(&mut local, publisher, &packet);
        local_expect(&mut upstream, subscriber, &packet);
        (local.into_transcript(), upstream.into_transcript())
    });
}

fn certificate_bridge_delivers(kind: BrokerKind, san: bool, options: &str) {
    let dir = tempfile::tempdir().unwrap();
    let certfile = dir.path().join("server.pem");
    let keyfile = dir.path().join("server.key");
    let mut params = rcgen::CertificateParams::new(if san {
        vec!["localhost".to_owned()]
    } else {
        Vec::new()
    })
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let key = rcgen::KeyPair::generate().unwrap();
    std::fs::write(&certfile, params.self_signed(&key).unwrap().pem()).unwrap();
    std::fs::write(&keyfile, key.serialize_pem()).unwrap();
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    // `localhost` resolves to ::1 first on some hosts (GitHub's runners), and
    // Mosquitto's non-blocking bridge connect stops at the first address
    // (lib/net_mosq.c: net__try_connect_tcp). Serve the name on both loopbacks.
    let tls = format!(
        "certfile {}\nkeyfile {}\n",
        certfile.display(),
        keyfile.display()
    );
    let core = start(
        BrokerKind::Mosquitto,
        &format!("{ANONYMOUS}listener {port} 127.0.0.1\n{tls}listener {port} ::1\n{tls}"),
    );
    let edge = start(
        kind,
        &format!(
            "{ANONYMOUS}connection bridge_sample\naddress localhost:{port}\n\
             bridge_cafile {}\nnotification_topic difftest/bridge-tls\n\
             {options}topic {READY_TOPIC} out 0\n",
            certfile.display(),
        ),
    );
    wait_bridge_state(&core, "difftest/bridge-tls", b"1");
    wait_for_bridge_traffic(&edge, &core);
}

// lib/tls_mosq.c: tls__set_verify_hostname uses OpenSSL's DNS certificate checks.
#[test]
#[ignore = "requires Mosquitto 2.1.4 with TLS and mqextended"]
fn certificate_bridge_accepts_trusted_dns_common_name_without_a_san() {
    differential(|kind| certificate_bridge_delivers(kind, false, ""));
}

// lib/net_mosq.c: net__init_ssl_ctx passes bridge_ciphers to OpenSSL.
#[test]
#[ignore = "requires Mosquitto 2.1.4 with TLS and mqextended"]
fn certificate_bridge_accepts_openssl_cipher_selectors() {
    differential(|kind| {
        certificate_bridge_delivers(kind, true, "bridge_ciphers DEFAULT:@SECLEVEL=2\n");
    });
}

// lib/net_mosq.c: net__is_connected covers a socket awaiting CONNACK.
// Hold just that packet between two real brokers so the publish happens
// after the bridge has connected to the transport but before MQTT is ready.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn clean_bridge_delivers_publications_accepted_while_waiting_for_connack() {
    differential(|kind| {
        let version = Version::V311;
        let topic = "bridge/handshake";
        let mut core = start(BrokerKind::Mosquitto, ANONYMOUS);
        let reader = client(
            &mut core,
            1,
            version,
            "handshake-reader",
            false,
            false,
            false,
        );
        local_subscribe(&mut core, reader, version, 1, topic, 1);
        let proxy = Remote::bind();
        let bridge = bridge_config(
            version,
            proxy.addr(),
            "local_cleansession true\nnotifications false\nbridge_attempt_unsubscribe false\n",
            &format!("topic {topic} out 1\n"),
        );
        let mut edge = start(kind, &format!("{ANONYMOUS}{bridge}"));
        let mut bridge_socket = proxy.accept();
        let mut core_socket = TcpStream::connect(core.node_addr(1).unwrap()).unwrap();
        core_socket.set_read_timeout(Some(RESPONSE)).unwrap();
        core_socket
            .write_all(&read_frame(&mut bridge_socket).unwrap().unwrap())
            .unwrap();
        let response = read_frame(&mut core_socket).unwrap().unwrap();
        assert_eq!(response, connack(version, false, 0, &[]));
        let writer = client(
            &mut edge,
            1,
            version,
            "handshake-writer",
            false,
            false,
            false,
        );
        let packet = publish(version, topic, b"during handshake", 1, 1, 0);
        publish_local(&mut edge, writer, &packet, 1, 1);
        bridge_socket.write_all(&response).unwrap();
        let forwarded = read_frame(&mut bridge_socket)
            .unwrap_or_else(|error| {
                panic!("{kind:?}: bridge discarded the pre-CONNACK message: {error}")
            })
            .unwrap();
        core_socket.write_all(&forwarded).unwrap();
        local_expect(&mut core, reader, &packet);
        (edge.into_transcript(), core.into_transcript())
    });
}

// Frames the bridge sends before going quiet for `quiet`.
fn drain(socket: &mut TcpStream, quiet: Duration) -> Vec<Vec<u8>> {
    socket.set_read_timeout(Some(quiet)).unwrap();
    let mut frames = Vec::new();
    loop {
        match read_frame(socket) {
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => panic!("reading bridge frames: {error}"),
        }
    }
    socket.set_read_timeout(Some(RESPONSE)).unwrap();
    frames
}

// MQTT 5 CONNACK with only a Receive Maximum property.
fn connack_receive_maximum(maximum: u16) -> Vec<u8> {
    let [hi, lo] = maximum.to_be_bytes();
    frame(0x20, &[0, 0, 3, 0x21, hi, lo])
}

// src/handle_connack.c: handle__connack_properties calls
// db__message_reconnect_reset when CONNACK lowers Receive Maximum. Messages
// admitted while CONNACK was pending stay in flight; later ones use the quota.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn connack_receive_maximum_applies_to_publications_accepted_during_the_handshake() {
    differential(|kind| {
        let topic = "bridge/handshake";
        let mut remote = Remote::bind();
        let bridge = bridge_config(
            Version::V5,
            remote.addr(),
            "notifications false\nbridge_attempt_unsubscribe false\nbridge_max_topic_alias 0\n",
            &format!("topic {topic} out 1\n"),
        );
        let mut edge = start(kind, &format!("{ANONYMOUS}{bridge}"));
        let mut peer = remote.accept();
        remote.expect(
            &mut peer,
            &bridge_connect(Version::V5, default_id(), 60, false, None),
        );
        let writer = client(
            &mut edge,
            1,
            Version::V311,
            "handshake-writer",
            false,
            false,
            false,
        );
        for mid in 1..=2 {
            let packet = publish(Version::V311, topic, &[b'0' + mid as u8], 1, mid, 0);
            publish_local(&mut edge, writer, &packet, 1, mid);
        }
        peer.write_all(&connack_receive_maximum(1)).unwrap();
        let during_handshake = drain(&mut peer, Duration::from_millis(500));
        for mid in 1..=2 {
            peer.write_all(&ack(0x40, mid)).unwrap();
        }
        // Each PUBACK returns one quota slot. Let both reach the edge before
        // the next messages are admitted, or either broker may release two.
        thread::sleep(Duration::from_millis(300));
        for mid in 3..=4 {
            let packet = publish(Version::V311, topic, &[b'0' + mid as u8], 1, mid, 0);
            publish_local(&mut edge, writer, &packet, 1, mid);
        }
        let after_connack = drain(&mut peer, Duration::from_millis(500));
        peer.write_all(&ack(0x40, 3)).unwrap();
        let after_ack = drain(&mut peer, Duration::from_millis(500));
        (during_handshake, after_connack, after_ack)
    });
}

// Cluster variant: another node accepts the publication while the bridge
// owner awaits CONNACK, which then lowers Receive Maximum. The remote sees
// the message once, from the one node that dialled it.
#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn cluster_bridge_delivers_publications_accepted_while_waiting_for_connack_once() {
    let topic = "bridge/handshake";
    let mut remote = Remote::bind();
    let bridge = bridge_config(
        Version::V5,
        remote.addr(),
        "local_cleansession true\nnotifications false\nbridge_attempt_unsubscribe false\n\
         bridge_max_topic_alias 0\n",
        &format!("topic {topic} out 1\n"),
    );
    let conf = format!("{ANONYMOUS}log_type all\n{bridge}");
    let mut cluster = Harness::start_cluster(config(&conf), ClusterConfig::default()).unwrap();
    let mut peer = remote.accept();
    remote.expect(
        &mut peer,
        &bridge_connect(Version::V5, default_id(), 60, false, None),
    );
    let owner = bridge_owner(&cluster, default_id());
    let other = if owner == 1 { 2 } else { 1 };
    let writer = client(
        &mut cluster,
        other,
        Version::V311,
        "handshake-writer",
        false,
        false,
        false,
    );
    let packet = publish(Version::V311, topic, b"during handshake", 1, 1, 0);
    publish_local(&mut cluster, writer, &packet, 1, 1);
    peer.write_all(&connack_receive_maximum(1)).unwrap();
    remote.expect(
        &mut peer,
        &publish(Version::V5, topic, b"during handshake", 1, 1, 0),
    );
    assert_eq!(
        drain(&mut peer, Duration::from_millis(500)),
        Vec::<Vec<u8>>::new()
    );
    peer.write_all(&ack(0x40, 1)).unwrap();
    let packet = publish(Version::V311, topic, b"after connack", 1, 2, 0);
    publish_local(&mut cluster, writer, &packet, 1, 2);
    remote.expect(
        &mut peer,
        &publish(Version::V5, topic, b"after connack", 1, 2, 0),
    );
    peer.write_all(&ack(0x40, 2)).unwrap();
    peer.write_all(PING).unwrap();
    remote.expect(&mut peer, PONG);
    assert!(
        remote.accept_within(Duration::from_millis(250)).is_none(),
        "more than one live bridge"
    );
}

// 06-bridge-b2br-late-connection{,-retain}.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn bridge_delivers_queued_and_restored_retained_publications() {
    for version in VERSIONS {
        for retained in [false, true] {
            differential(|kind| {
                let mut remote = Remote::bind();
                let bridge = bridge_config(
                    version,
                    remote.addr(),
                    "notifications false\nbridge_attempt_unsubscribe false\nbridge_max_topic_alias 0\n",
                    "topic bridge/# out 1\n",
                );
                let before = if retained { PERSISTENT } else { ANONYMOUS };
                let after = format!("{before}{bridge}");
                let mut h = start(kind, if retained { before } else { &after });
                let mut peer = (!retained).then(|| remote.accept());

                let local = client(&mut h, 1, version, "client", false, false, false);
                let packet = publish(version, "bridge/test", b"message", 1, 1, u8::from(retained));
                let ack = puback(version, 1, if retained { 16 } else { 0 });
                send(&mut h, local, &packet);
                local_expect(&mut h, local, &ack);
                h.close_socket(local);

                let mut peer = if retained {
                    h.stop_node(1).unwrap();
                    h.reload_node(1, &after).unwrap();
                    h.restart_node(1).unwrap();
                    remote.accept()
                } else {
                    peer.take().unwrap()
                };
                remote.expect(
                    &mut peer,
                    &bridge_connect(version, default_id(), 60, false, None),
                );
                peer.write_all(&connack(version, false, 0, &[])).unwrap();
                remote.expect(&mut peer, &packet);
                if retained {
                    peer.write_all(&ack).unwrap();
                    peer.write_all(PING).unwrap();
                    remote.expect(&mut peer, PONG);
                }
                (remote.transcript, h.into_transcript())
            });
        }
    }
}

// 06-bridge-fail-persist-resend-qos{1,2}.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn unsolicited_qos_acknowledgements_do_not_break_the_bridge() {
    for version in VERSIONS {
        for qos2 in [false, true] {
            differential(|kind| {
                let mut remote = Remote::bind();
                let conf = bridge_config(
                    version,
                    remote.addr(),
                    "remote_clientid bridge-u-test\ncleansession true\ntry_private false\n\
                     notifications false\nbridge_max_topic_alias 0\nrestart_timeout 5\n",
                    "topic bridge/# out\n",
                );
                let h = start(kind, &conf);
                let mut peer = remote.accept();
                remote.expect(
                    &mut peer,
                    &connect_packet(
                        version.level(),
                        "bridge-u-test",
                        60,
                        2,
                        &[0x21, 0, 20],
                        None,
                    ),
                );
                peer.write_all(&connack(version, false, 0, &[])).unwrap();
                let mut unsub = vec![0, 1];
                if version == Version::V5 {
                    properties(&mut unsub, &[]);
                }
                field(&mut unsub, b"bridge/#");
                remote.expect(&mut peer, &frame(0xa2, &unsub));
                let unsuback: &[u8] = if version == Version::V5 {
                    &[0, 1, 0, 0]
                } else {
                    &[0, 1]
                };
                peer.write_all(&frame(0xb0, unsuback)).unwrap();
                if qos2 {
                    peer.write_all(&ack(0x50, 2001)).unwrap();
                    remote.expect(&mut peer, &ack(0x62, 2001));
                    peer.write_all(&ack(0x62, 2002)).unwrap();
                    remote.expect(&mut peer, &ack(0x70, 2002));
                    peer.write_all(&ack(0x70, 2003)).unwrap();
                } else {
                    peer.write_all(&ack(0x40, 2000)).unwrap();
                }
                let topic = if qos2 {
                    "bridge/unknown/qos2"
                } else {
                    "bridge/unknown/qos1"
                };
                peer.write_all(&publish(version, topic, b"bridge-message", 1, 180, 0))
                    .unwrap();
                remote.expect(&mut peer, &ack(0x40, 180));
                (remote.transcript, h.into_transcript())
            });
        }
    }
}

// 06-bridge-no-local.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn remote_bridge_subscriptions_do_not_loop_back_own_publish() {
    for version in [Version::V31, Version::V311, Version::V5] {
        differential(|kind| {
            let mut h = start(kind, ANONYMOUS);
            let local = client(
                &mut h,
                1,
                version,
                "bridge-test",
                version != Version::V5,
                false,
                false,
            );
            let options = if version == Version::V5 { 4 } else { 0 };
            local_subscribe(&mut h, local, version, 1, "loop/test", options);
            send(
                &mut h,
                local,
                &publish(version, "loop/test", b"message", 0, 0, 0),
            );
            ping(&mut h, local);
            h.into_transcript()
        });
    }
}

// src/plugin_acl_check.c: mosquitto_acl_check exempts the internally created
// bridge context only; ordinary local clients still use the configured ACL.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn outgoing_bridge_context_bypasses_acl_in_both_directions() {
    differential(|kind| {
        let version = Version::V311;
        let mut remote = Remote::bind();
        let bridge = bridge_config(
            version,
            remote.addr(),
            "notifications false\nbridge_attempt_unsubscribe false\n\
             local_username blocked\nremote_username blocked\n",
            "topic outbound/# out 1\ntopic inbound/# in 1\n",
        );
        let conf = format!("{ANONYMOUS}{bridge}");
        let mut h = Harness::start(
            kind,
            BrokerConfig {
                conf: &conf,
                acl: Some(
                    "topic write outbound/#\ntopic read inbound/#\nuser blocked\ntopic deny #\n",
                ),
                ..BrokerConfig::default()
            },
        )
        .unwrap();
        let mut peer = remote.accept();
        let mut connect = bytes::BytesMut::new();
        mqx_codec::encode(
            &mqx_codec::Packet::Connect(mqx_codec::Connect {
                protocol: ProtocolVersion::V311,
                is_bridge: true,
                clean_session: false,
                keep_alive: 60,
                client_id: default_id().into(),
                will: None,
                username: Some("blocked".into()),
                password: None,
            }),
            &mut connect,
        )
        .unwrap();
        remote.expect(&mut peer, &connect);
        peer.write_all(&connack(version, false, 0, &[])).unwrap();
        remote.subscribe(&mut peer, version, 1, "inbound/#", 1);
        let local = client(&mut h, 1, version, "local-acl-user", false, false, false);
        local_subscribe(&mut h, local, version, 1, "inbound/#", 1);
        let inbound = publish(version, "inbound/test", b"from remote", 1, 10, 0);
        peer.write_all(&inbound).unwrap();
        remote.expect(&mut peer, &ack(0x40, 10));
        local_expect(
            &mut h,
            local,
            &publish(version, "inbound/test", b"from remote", 1, 1, 0),
        );
        send(&mut h, local, &ack(0x40, 1));
        publish_local(
            &mut h,
            local,
            &publish(version, "outbound/test", b"from local", 1, 11, 0),
            1,
            11,
        );
        remote.expect(
            &mut peer,
            &publish(version, "outbound/test", b"from local", 1, 2, 0),
        );
        peer.write_all(&ack(0x40, 2)).unwrap();
        (remote.transcript, h.into_transcript())
    });
}

// 06-bridge-outgoing-retain.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn outgoing_retain_option_controls_the_bridge_wire_flag() {
    for version in [Version::V31, Version::V311, Version::V5] {
        for retain in [false, true] {
            differential(|kind| {
                let mut remote = Remote::bind();
                let conf = bridge_config(
                    version,
                    remote.addr(),
                    &format!(
                        "notifications false\nrestart_timeout 5\nbridge_max_topic_alias 0\n\
                         bridge_outgoing_retain {retain}\n"
                    ),
                    "topic \"bridge with space/#\" both 1\n",
                );
                let mut h = start(kind, &format!("{ANONYMOUS}{conf}"));
                let mut peer = remote.connect(version, false);
                remote.subscribe(&mut peer, version, 1, "bridge with space/#", 1);
                let local = client(&mut h, 1, version, "helper", false, false, false);
                let topic = "bridge with space/retain/test";
                send(&mut h, local, &publish(version, topic, b"message", 0, 0, 1));
                h.close_socket(local);
                remote.expect(
                    &mut peer,
                    &publish(version, topic, b"message", 0, 0, u8::from(retain)),
                );
                (remote.transcript, h.into_transcript())
            });
        }
    }
}

const REMAPS: [(&str, &str, &str, &str); 8] = [
    ("#", "local/topic/", "remote/topic/", "remote/topic/#"),
    (
        "prefix/#",
        "local2/topic/",
        "remote2/topic/",
        "remote2/topic/prefix/#",
    ),
    (
        "+/value",
        "local3/topic/",
        "remote3/topic/",
        "remote3/topic/+/value",
    ),
    ("ic/+", "local4/top", "remote4/tip", "remote4/tipic/+"),
    (
        "clients/total",
        "test/mosquitto/org",
        "$SYS/broker/",
        "$SYS/broker/clients/total",
    ),
    ("rmapped", "", "remote/mapped/", "remote/mapped/rmapped"),
    ("lmapped", "local/mapped/", "", "lmapped"),
    ("", "local/single", "remote/single", "remote/single"),
];

const INBOUND_TOPICS: [(&str, &str); 10] = [
    ("local/topic/something", "remote/topic/something"),
    ("local/topic/some/t/h/i/n/g", "remote/topic/some/t/h/i/n/g"),
    ("local/topic/value", "remote/topic/value"),
    (
        "local2/topic/prefix/something",
        "remote2/topic/prefix/something",
    ),
    (
        "local3/topic/something/value",
        "remote3/topic/something/value",
    ),
    ("local4/topic/something", "remote4/tipic/something"),
    (
        "test/mosquitto/orgclients/total",
        "$SYS/broker/clients/total",
    ),
    ("local/mapped/lmapped", "lmapped"),
    ("rmapped", "remote/mapped/rmapped"),
    ("local/single", "remote/single"),
];

// 06-bridge-b2br-remapping.py and 06-bridge-per-listener-settings.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn incoming_remaps_cover_wildcards_system_topics_and_empty_prefixes() {
    use std::fmt::Write as _;

    for version in VERSIONS {
        for per_listener in [false, true] {
            differential(|kind| {
                let mut remote = Remote::bind();
                let mut topics = String::new();
                let count = if per_listener { 5 } else { REMAPS.len() };
                for (filter, local, remote, _) in &REMAPS[..count] {
                    let token = |field: &str| {
                        if field.is_empty() {
                            "\"\"".into()
                        } else {
                            field.to_owned()
                        }
                    };
                    writeln!(
                        topics,
                        "topic {} in 0 {} {}",
                        token(filter),
                        token(local),
                        token(remote)
                    )
                    .unwrap();
                }
                let bridge = bridge_config(
                    version,
                    remote.addr(),
                    "notifications false\nbridge_attempt_unsubscribe false\n\
                     bridge_max_topic_alias 0\nrestart_timeout 5\n",
                    &topics,
                );
                let prefix = if per_listener {
                    "per_listener_settings true\n"
                } else {
                    ""
                };
                let mut h = start(kind, &format!("{prefix}{ANONYMOUS}{bridge}"));
                let local = client(&mut h, 1, version, "pub-test", false, false, false);
                let mut peer = remote.connect(version, false);
                for (index, (_, _, _, filter)) in REMAPS[..count].iter().enumerate() {
                    let mid = u16::try_from(index + 1).unwrap();
                    remote.subscribe(&mut peer, version, mid, filter, 0);
                }
                let options = if version == Version::V5 {
                    BRIDGE_OPTS
                } else {
                    0
                };
                local_subscribe(&mut h, local, version, 4, "#", options);
                let count = if per_listener {
                    7
                } else {
                    INBOUND_TOPICS.len()
                };
                for (local_topic, remote_topic) in &INBOUND_TOPICS[..count] {
                    peer.write_all(&publish(version, remote_topic, b"", 0, 0, 0))
                        .unwrap();
                    local_expect(&mut h, local, &publish(version, local_topic, b"", 0, 0, 0));
                }
                (remote.transcript, h.into_transcript())
            });
        }
    }
}

// 06-bridge-br2b-remapping.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn outgoing_remaps_forward_only_topics_matching_each_filter() {
    use std::fmt::Write as _;

    for version in VERSIONS {
        differential(|kind| {
            let mut remote = Remote::bind();
            let mut topics = String::new();
            for (filter, local, remote, _) in &REMAPS[..4] {
                writeln!(topics, "topic {filter} out 0 {local} {remote}").unwrap();
            }
            let bridge = bridge_config(
                version,
                remote.addr(),
                "notifications false\nbridge_attempt_unsubscribe false\n\
                 bridge_max_topic_alias 0\nrestart_timeout 5\n",
                &topics,
            );
            let mut h = start(kind, &format!("{ANONYMOUS}{bridge}"));
            let local = client(&mut h, 1, version, "pub-test", false, false, false);
            let mut peer = remote.connect(version, false);
            // The PINGRESP confirms the bridge processed the remote CONNACK.
            peer.write_all(PING).unwrap();
            remote.expect(&mut peer, PONG);
            let cases = [
                INBOUND_TOPICS[0],
                INBOUND_TOPICS[1],
                INBOUND_TOPICS[2],
                ("local2/topic/something", ""),
                INBOUND_TOPICS[3],
                INBOUND_TOPICS[4],
                INBOUND_TOPICS[5],
                ("local5/topic/something", ""),
            ];
            for (local_topic, remote_topic) in cases {
                send(&mut h, local, &publish(version, local_topic, b"", 0, 0, 0));
                if remote_topic.is_empty() {
                    ping(&mut h, local);
                    peer.write_all(PING).unwrap();
                    remote.expect(&mut peer, PONG);
                } else {
                    remote.expect(&mut peer, &publish(version, remote_topic, b"", 0, 0, 0));
                }
            }
            (remote.transcript, h.into_transcript())
        });
    }
}

// 06-bridge-remap-receive-wildcard.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn invalid_wildcard_publication_closes_remapped_bridge() {
    differential(|kind| {
        let version = Version::V5;
        let mut remote = Remote::bind();
        let bridge = bridge_config(
            version,
            remote.addr(),
            "notifications false\nremote_clientid mosquitto\nkeepalive_interval 600\n",
            "topic room1/# both 2 sensor/ myhouse/\ntopic tst/ba both 2\ntopic # both 2\n",
        );
        let h = start(kind, &format!("{ANONYMOUS}{bridge}"));
        let mut peer = remote.accept();
        remote.expect(
            &mut peer,
            &bridge_connect(version, "mosquitto", 600, true, None),
        );
        peer.write_all(&connack(version, false, 0, &[])).unwrap();
        remote.subscribe(&mut peer, version, 1, "myhouse/room1/#", 2);
        remote.subscribe(&mut peer, version, 2, "tst/ba", 2);
        remote.subscribe(&mut peer, version, 3, "#", 2);
        peer.write_all(&[
            0x32, 0x0c, 0, 6, b'+', b'+', b'+', b'+', b'+', b'+', 0, 4, 0, 0x33, 0xc0, 0,
        ])
        .unwrap();
        closed(&mut peer);
        (remote.transcript, h.into_transcript())
    });
}

// 06-bridge-config-reload.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn immediate_reload_reconnects_but_lazy_reload_waits_for_disconnect() {
    differential(|kind| {
        let version = Version::V311;
        let mut remote = Remote::bind();
        let addr = remote.addr();
        let conf = |number, immediate| {
            let reload = if immediate {
                "bridge_reload_type immediate\n"
            } else {
                ""
            };
            let bridge = bridge_config(
                version,
                addr,
                &format!(
                    "notifications false\nrestart_timeout 1\nbridge_max_topic_alias 0\n{reload}"
                ),
                &format!("topic # in 0 local/topic/ remote/topic{number}/\n"),
            );
            format!("{ANONYMOUS}{bridge}")
        };
        let mut h = start(kind, &conf(1, true));
        let mut peer = remote.connect(version, false);
        remote.subscribe(&mut peer, version, 1, "remote/topic1/#", 0);
        h.reload_node(1, &conf(2, true)).unwrap();
        // Leave the old socket open until a replacement proves this was an immediate reload.
        let mut next = remote.connect(version, false);
        remote.subscribe(&mut next, version, 1, "remote/topic2/#", 0);
        drop(peer);

        h.reload_node(1, &conf(3, false)).unwrap();
        assert!(
            remote.accept_within(Duration::from_secs(2)).is_none(),
            "lazy reload disconnected the live bridge"
        );
        next.write_all(PING).unwrap();
        remote.expect(&mut next, PONG);
        drop(next);

        let mut peer = remote.connect(version, false);
        remote.subscribe(&mut peer, version, 1, "remote/topic3/#", 0);
        (remote.transcript, h.into_transcript())
    });
}

// bridge.c: bridge__reload only constructs the context. Unlike startup,
// bridge_check does not dial a fresh lazy or once bridge.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn reload_does_not_start_new_or_recreated_lazy_and_once_bridges() {
    for mode in ["lazy", "once"] {
        for recreate in [false, true] {
            differential(|kind| {
                let version = Version::V311;
                let mut remote = Remote::bind();
                let address = remote.addr();
                let bridge = |start_type| {
                    bridge_config(
                        version,
                        address,
                        &format!(
                            "notifications false\nrestart_timeout 1\n\
                                 bridge_attempt_unsubscribe false\nbridge_reload_type immediate\n\
                                 start_type {start_type}\nthreshold 1\n"
                        ),
                        "topic deferred/# out 1\n",
                    )
                };
                let before = if recreate {
                    format!("{ANONYMOUS}{}", bridge(mode))
                } else {
                    ANONYMOUS.to_owned()
                };
                let mut h = start(kind, &before);
                let mut existing = recreate.then(|| remote.connect(version, false));
                if let Some(peer) = &mut existing {
                    peer.write_all(PING).unwrap();
                    remote.expect(peer, PONG);
                }

                // The separate automatic bridge proves that this reload was
                // applied before we assert silence on the deferred bridge.
                let mut barrier = Remote::bind();
                let reload = format!(
                    "{ANONYMOUS}{}connection barrier\naddress {}\n\
                     remote_clientid reload-barrier\nrestart_timeout 1\n\
                     notifications false\nbridge_attempt_unsubscribe false\ntopic barrier/# out\n",
                    bridge(mode),
                    barrier.addr(),
                );
                h.reload_node(1, &reload).unwrap();
                let mut ready = barrier.accept();
                barrier.expect(
                    &mut ready,
                    &bridge_connect(version, "reload-barrier", 60, false, None),
                );
                if let Some(peer) = &mut existing {
                    remote.expect(peer, DISCONNECT);
                }
                let local = client(&mut h, 1, version, "after-reload", false, false, false);
                publish_local(
                    &mut h,
                    local,
                    &publish(version, "deferred/test", b"not subscribed yet", 1, 1, 0),
                    1,
                    1,
                );
                assert!(
                    remote.accept_within(Duration::from_secs(2)).is_none(),
                    "{kind:?} started {mode} bridge after reload (recreate={recreate})",
                );
                (remote.transcript, barrier.transcript, h.into_transcript())
            });
        }
    }
}

fn log_contains(h: &Harness, fragment: &str) {
    let deadline = Instant::now() + RESPONSE;
    loop {
        let log = h.node_log(1).unwrap();
        if log.contains(fragment) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "missing diagnostic {fragment:?} in:\n{log}"
        );
        thread::sleep(POLL);
    }
}

const QUOTED_FILTER: &str = "topic \"bridge with space/#\" both 1\n";

// 06-bridge-connack-v{4,5}-error.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn connack_refusals_have_the_corresponding_operator_diagnostic() {
    let cases = [
        (Version::V311, 3, "broker unavailable"),
        (Version::V311, 4, "bad user name or password"),
        (Version::V311, 5, "not authorised"),
        (Version::V311, 2, "identifier rejected"),
        (Version::V311, 1, "unacceptable protocol version"),
        (Version::V311, 128, "unknown reason"),
        (Version::V5, 0x86, "Bad User Name or Password"),
    ];
    for (version, reason, diagnostic) in cases {
        differential(|kind| {
            let mut remote = Remote::bind();
            let bridge = bridge_config(
                version,
                remote.addr(),
                "bridge_max_topic_alias 0\n",
                QUOTED_FILTER,
            );
            let h = start(kind, &format!("{ANONYMOUS}{bridge}"));
            let mut peer = remote.accept();
            let will = format!("$SYS/broker/connection/{}/state", default_id());
            remote.expect(
                &mut peer,
                &bridge_connect(version, default_id(), 60, false, Some((&will, 1, true))),
            );
            peer.write_all(&connack(version, false, reason, &[]))
                .unwrap();
            closed(&mut peer);
            log_contains(&h, &format!("Connection Refused: {diagnostic}"));
            (remote.transcript, h.into_transcript())
        });
    }
}

// 06-bridge-connack-{qos,retain}-not-supported.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn connack_capability_refusal_changes_the_next_connect_will() {
    let cases = [
        (
            "maximum_qos 0",
            0x9b,
            &[0x24, 0][..],
            0,
            true,
            "QoS not supported",
        ),
        (
            "retain_available false",
            0x9a,
            &[0x25, 0][..],
            1,
            false,
            "retain not available",
        ),
    ];
    for (setting, reason, property, retry_qos, retry_retain, diagnostic) in cases {
        differential(|kind| {
            let version = Version::V5;
            let mut remote = Remote::bind();
            let bridge = bridge_config(
                version,
                remote.addr(),
                "bridge_max_topic_alias 0\nrestart_timeout 1\n",
                QUOTED_FILTER,
            );
            let h = start(kind, &format!("{ANONYMOUS}{setting}\n{bridge}"));
            let will = format!("$SYS/broker/connection/{}/state", default_id());
            for (qos, retain) in [(1, true), (retry_qos, retry_retain)] {
                let mut peer = remote.accept();
                remote.expect(
                    &mut peer,
                    &bridge_connect(version, default_id(), 60, false, Some((&will, qos, retain))),
                );
                peer.write_all(&connack(version, false, reason, property))
                    .unwrap();
                closed(&mut peer);
            }
            log_contains(
                &h,
                &format!("Connection Refused: {diagnostic} (will retry)"),
            );
            (remote.transcript, h.into_transcript())
        });
    }
}

// 06-bridge-connack-v5-bad-protocol-version.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn v5_bridge_falls_back_to_private_v311_on_legacy_refusal() {
    differential(|kind| {
        let mut remote = Remote::bind();
        let bridge = bridge_config(
            Version::V5,
            remote.addr(),
            "bridge_max_topic_alias 0\nrestart_timeout 1\n",
            QUOTED_FILTER,
        );
        let h = start(
            kind,
            &format!("{ANONYMOUS}retain_available false\n{bridge}"),
        );
        let will = format!("$SYS/broker/connection/{}/state", default_id());
        for version in [Version::V5, Version::V311] {
            let mut peer = remote.accept_within(RESPONSE).unwrap_or_else(|| {
                panic!(
                    "{kind:?} did not connect using {version:?}:\n{}",
                    h.node_log(1).unwrap()
                )
            });
            remote.expect(
                &mut peer,
                &bridge_connect(version, default_id(), 60, false, Some((&will, 1, true))),
            );
            peer.write_all(&connack(Version::V311, false, 1, &[]))
                .unwrap();
            closed(&mut peer);
        }
        log_contains(
            &h,
            "Remote bridge bridge_sample does not support MQTT v5.0, reconnecting using MQTT v3.1.1.",
        );
        (remote.transcript, h.into_transcript())
    });
}

// Readiness connections are outside the scenario transcript: a status watcher
// may subscribe on either side of the online transition during startup.
fn probe_socket(h: &Harness, id: &str) -> TcpStream {
    let mut socket = TcpStream::connect_timeout(&h.node_addr(1).unwrap(), RESPONSE).unwrap();
    socket.set_read_timeout(Some(RESPONSE)).unwrap();
    socket.set_write_timeout(Some(RESPONSE)).unwrap();
    socket.set_nodelay(true).unwrap();
    socket
        .write_all(&connect_packet(4, id, 60, 2, &[], None))
        .unwrap();
    assert_eq!(
        read_frame(&mut socket).unwrap(),
        Some(connack(Version::V311, false, 0, &[]))
    );
    socket
}

fn wait_bridge_state(h: &Harness, topic: &str, expected: &[u8]) {
    let mut socket = probe_socket(h, "bridge-state-probe");
    let version = Version::V311;
    socket
        .write_all(&subscribe_packet(version, 1, topic, 0))
        .unwrap();
    assert_eq!(
        read_frame(&mut socket).unwrap(),
        Some(suback(version, 1, 0))
    );
    let deadline = Instant::now() + RESPONSE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "no {expected:?} notification on {topic}"
        );
        socket.set_read_timeout(Some(remaining)).unwrap();
        let packet = read_frame(&mut socket)
            .unwrap_or_else(|err| panic!("waiting for {expected:?} notification on {topic}: {err}"))
            .expect("bridge notification subscriber closed");
        let is_state = |state| {
            [0, 1]
                .into_iter()
                .any(|retain| packet == publish(version, topic, state, 0, 0, retain))
        };
        if is_state(expected) {
            return;
        }
        assert!(
            is_state(b"0") || is_state(b"1"),
            "unexpected bridge state on {topic}: {packet:02x?}"
        );
    }
}

const READY_TOPIC: &str = "difftest/bridge-ready";

fn wait_for_bridge_traffic(edge: &Harness, core: &Harness) {
    let version = Version::V311;
    let mut subscriber = probe_socket(core, "bridge-ready-subscriber");
    subscriber
        .write_all(&subscribe_packet(version, 1, READY_TOPIC, 0))
        .unwrap();
    assert_eq!(
        read_frame(&mut subscriber).unwrap(),
        Some(suback(version, 1, 0))
    );
    let mut publisher = probe_socket(edge, "bridge-ready-publisher");
    let packet = publish(version, READY_TOPIC, b"ready", 0, 0, 0);
    subscriber
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let deadline = Instant::now() + RESPONSE;
    loop {
        publisher.write_all(&packet).unwrap();
        match read_frame(&mut subscriber) {
            Ok(actual) => {
                assert_eq!(actual, Some(packet));
                return;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && Instant::now() < deadline => {}
            Err(error) => panic!("bridge did not forward readiness publication: {error}"),
        }
    }
}

fn check_queue_matrix(
    kind: BrokerKind,
    clean: bool,
    local_clean: Option<bool>,
) -> (Transcript, Transcript) {
    let version = Version::V311; // All six upstream launchers select MQTT 3.1.1.
    let mut core = start(kind, PERSISTENT);
    let local_clean_setting =
        local_clean.map_or_else(String::new, |value| format!("local_cleansession {value}\n"));
    let bridge = bridge_config(
        version,
        core.node_addr(1).unwrap(),
        &format!(
            "local_clientid id_local\nremote_clientid id_remote\nkeepalive_interval 5\n\
             restart_timeout 2\nbridge_max_topic_alias 0\ncleansession {clean}\n{local_clean_setting}"
        ),
        &format!("topic br_out/# out 1\ntopic br_in/# in 1\ntopic {READY_TOPIC} out 0\n"),
    );
    let mut edge = start(kind, &format!("{PERSISTENT}{bridge}"));
    let mut a = client(&mut edge, 1, version, "client_a_edge", false, true, false);
    let mut b = client(&mut core, 1, version, "client_b_core", false, true, false);
    local_subscribe(&mut edge, a, version, 1, "br_in/#", 1);
    local_subscribe(&mut core, b, version, 1, "br_out/#", 1);
    let send_publish = |h: &mut Harness, client, direction, number| {
        let topic = format!("br_{direction}/test-queued{number}");
        let payload = format!("message-from-{topic}");
        publish_local(
            h,
            client,
            &publish(version, &topic, payload.as_bytes(), 1, number, 0),
            1,
            number,
        );
    };
    let receive_publish = |h: &mut Harness, client, direction, number, mid| {
        let topic = format!("br_{direction}/test-queued{number}");
        let payload = format!("message-from-{topic}");
        local_expect(
            h,
            client,
            &publish(version, &topic, payload.as_bytes(), 1, mid, 0),
        );
        send(h, client, &ack(0x40, mid));
    };
    let state = "$SYS/broker/connection/id_remote/state";

    send_publish(&mut edge, a, "out", 1);
    receive_publish(&mut core, b, "out", 1, 1);
    send_publish(&mut core, b, "in", 1);
    receive_publish(&mut edge, a, "in", 1, 1);
    ping(&mut edge, a);

    core.stop_node(1).unwrap();
    core.close_socket(b);
    wait_bridge_state(&edge, state, b"0");
    send_publish(&mut edge, a, "out", 2);
    core.restart_node(1).unwrap();
    b = client(&mut core, 1, version, "client_b_core", false, true, true);
    wait_bridge_state(&core, state, b"1");
    wait_for_bridge_traffic(&edge, &core);
    send_publish(&mut edge, a, "out", 3);
    if local_clean.unwrap_or(clean) {
        receive_publish(&mut core, b, "out", 3, 2);
    } else {
        receive_publish(&mut core, b, "out", 2, 2);
        receive_publish(&mut core, b, "out", 3, 3);
    }
    ping(&mut core, b);

    edge.stop_node(1).unwrap();
    edge.close_socket(a);
    send_publish(&mut core, b, "in", 2);
    edge.restart_node(1).unwrap();
    a = client(&mut edge, 1, version, "client_a_edge", false, true, true);
    wait_bridge_state(&edge, state, b"1");
    // The bridge sends its inbound SUBSCRIBE before it can forward this probe.
    wait_for_bridge_traffic(&edge, &core);
    send_publish(&mut core, b, "in", 3);
    if clean {
        receive_publish(&mut edge, a, "in", 3, 2);
    } else {
        receive_publish(&mut edge, a, "in", 2, 2);
        receive_publish(&mut edge, a, "in", 3, 3);
    }
    ping(&mut edge, a);
    edge.stop_node(1).unwrap();
    core.stop_node(1).unwrap();
    (edge.into_transcript(), core.into_transcript())
}

// 06-bridge-clean-session-core.py and its six cs{F,T}-lcs{F,N,T} launchers.
macro_rules! queue_case {
    ($name:ident, $clean:expr, $local_clean:expr) => {
        #[test]
        #[ignore = "requires Mosquitto 2.1.4 and mqextended with persistence"]
        fn $name() {
            differential(|kind| check_queue_matrix(kind, $clean, $local_clean));
        }
    };
}

queue_case!(durable_remote_durable_local_session, false, Some(false));
queue_case!(durable_remote_default_local_session, false, None);
queue_case!(durable_remote_clean_local_session, false, Some(true));
queue_case!(clean_remote_durable_local_session, true, Some(false));
queue_case!(clean_remote_default_local_session, true, None);
queue_case!(clean_remote_clean_local_session, true, Some(true));

// 06-bridge-reconnect-local-out.py
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended with persistence"]
fn outbound_local_subscription_is_restored_after_graceful_restart() {
    for version in VERSIONS {
        differential(|kind| {
            let mut core = start(kind, ANONYMOUS);
            let bridge = bridge_config(
                version,
                core.node_addr(1).unwrap(),
                "bridge_max_topic_alias 0\ncleansession false\n",
                "topic bridge/# out\n",
            );
            let mut edge = start(kind, &format!("{PERSISTENT}{bridge}"));
            let state = format!("$SYS/broker/connection/{}/state", default_id());
            wait_bridge_state(&edge, &state, b"1");
            edge.stop_node(1).unwrap();
            edge.restart_node(1).unwrap();
            wait_bridge_state(&edge, &state, b"1");
            let subscriber = client(
                &mut core,
                1,
                version,
                "bridge-reconnect-test",
                version != Version::V5,
                false,
                false,
            );
            for _ in 0..2 {
                local_subscribe(&mut core, subscriber, version, 180, "bridge/#", 0);
            }
            let publisher = client(&mut edge, 1, version, "test-helper", false, false, false);
            let topic = "bridge/reconnect";
            let payload = b"bridge-reconnect-message";
            publish_local(
                &mut edge,
                publisher,
                &publish(version, topic, payload, 1, 1, 0),
                1,
                1,
            );
            send(&mut edge, publisher, DISCONNECT);
            local_expect(
                &mut core,
                subscriber,
                &publish(version, topic, payload, 0, 0, 0),
            );
            edge.stop_node(1).unwrap();
            core.stop_node(1).unwrap();
            (edge.into_transcript(), core.into_transcript())
        });
    }
}

// 06-bridge-remote-shutdown.py uses a reference-only persistence event plugin
// to detect unwanted bridge expiry. Instead, let the expiry deadline pass
// while the bridge is down and check that its queue survives on both brokers.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended with persistence"]
fn remote_shutdown_publishes_bridge_down_without_expiring_the_bridge() {
    for version in VERSIONS {
        differential(|kind| {
            let mut core = start(kind, PERSISTENT);
            let subscriber = client(
                &mut core,
                1,
                version,
                "upstream-consumer",
                false,
                true,
                false,
            );
            let topic = "bridge/expiry";
            local_subscribe(&mut core, subscriber, version, 1, topic, 1);
            let bridge = bridge_config(
                version,
                core.node_addr(1).unwrap(),
                "bridge_max_topic_alias 0\ncleansession false\n\
                 notification_topic bridge_state\nrestart_timeout 1\n",
                "topic bridge/# out 1\n",
            );
            let mut edge = start(
                kind,
                &format!("{ANONYMOUS}persistent_client_expiration 2s\n{bridge}"),
            );
            wait_bridge_state(&edge, "bridge_state", b"1");
            let watcher = client(&mut edge, 1, version, "test-client", false, false, false);
            local_subscribe(&mut edge, watcher, version, 180, "#", 0);
            local_expect(
                &mut edge,
                watcher,
                &publish(version, "bridge_state", b"1", 0, 0, 1),
            );
            core.stop_node(1).unwrap();
            local_expect(
                &mut edge,
                watcher,
                &publish(version, "bridge_state", b"0", 0, 0, 0),
            );
            let echo = publish(version, "echo_topic", b"sample-message", 0, 0, 0);
            send(&mut edge, watcher, &echo);
            local_expect(&mut edge, watcher, &echo);
            ping(&mut edge, watcher);
            edge.close_socket(watcher);
            core.close_socket(subscriber);

            let publisher = client(
                &mut edge,
                1,
                version,
                "offline-publisher",
                false,
                false,
                false,
            );
            let queued = publish(version, topic, b"past the expiry deadline", 1, 1, 0);
            publish_local(&mut edge, publisher, &queued, 1, 1);
            thread::sleep(Duration::from_secs(3));

            core.restart_node(1).unwrap();
            let subscriber = client(
                &mut core,
                1,
                version,
                "upstream-consumer",
                false,
                true,
                true,
            );
            local_expect(&mut core, subscriber, &queued);
            send(&mut core, subscriber, &ack(0x40, 1));
            ping(&mut core, subscriber);
            edge.stop_node(1).unwrap();
            (edge.into_transcript(), core.into_transcript())
        });
    }
}

fn bridge_owner(h: &Harness, remote_id: &str) -> usize {
    let connect_log = format!("Bridge {remote_id} sending CONNECT");
    let deadline = Instant::now() + RESPONSE;
    loop {
        let logs: Vec<_> = (1..=3).map(|node| h.node_log(node).unwrap()).collect();
        let mut owners = logs
            .iter()
            .enumerate()
            .filter(|(_, log)| log.contains(&connect_log));
        if let Some((index, _)) = owners.next() {
            assert!(
                owners.next().is_none(),
                "multiple nodes opened the bridge:\n{logs:#?}"
            );
            return index + 1;
        }
        assert!(
            Instant::now() < deadline,
            "could not identify bridge owner:\n{logs:#?}"
        );
        thread::sleep(POLL);
    }
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn sigkill_of_bridge_owner_resumes_inflight_and_queued_messages_on_one_survivor() {
    let version = Version::V311;
    let mut remote = Remote::bind();
    let bridge = bridge_config(
        version,
        remote.addr(),
        "local_clientid failover-local\nnotifications false\nbridge_attempt_unsubscribe false\n\
         restart_timeout 1\nbridge_max_topic_alias 0\n",
        "topic bridge/# out 1\n",
    );
    let conf = format!("{ANONYMOUS}log_type all\nmax_inflight_messages 1\n{bridge}");
    let mut cluster = Harness::start_cluster(config(&conf), ClusterConfig::default()).unwrap();
    let mut peer = remote.connect(version, false);
    peer.write_all(PING).unwrap();
    remote.expect(&mut peer, PONG);
    let owner = bridge_owner(&cluster, default_id());
    let survivor = if owner == 1 { 2 } else { 1 };
    let local = client(
        &mut cluster,
        survivor,
        version,
        "failover-publisher",
        false,
        false,
        false,
    );
    let packet =
        |payload: &[u8], mid, flags| publish(version, "bridge/failover", payload, 1, mid, flags);
    publish_local(&mut cluster, local, &packet(b"inflight", 40, 0), 1, 40);
    remote.expect(&mut peer, &packet(b"inflight", 1, 0));
    assert!(
        remote.accept_within(Duration::from_millis(250)).is_none(),
        "more than one live bridge"
    );

    // Leave the first remote delivery unacknowledged; kill the actual socket owner.
    cluster.kill_node(owner).unwrap();
    closed(&mut peer);
    publish_local(&mut cluster, local, &packet(b"queued", 41, 0), 1, 41);
    let mut peer = remote.connect(version, false);
    remote.expect(&mut peer, &packet(b"inflight", 1, 8));
    peer.write_all(&ack(0x40, 1)).unwrap();
    remote.expect(&mut peer, &packet(b"queued", 2, 0));
    peer.write_all(&ack(0x40, 2)).unwrap();
    peer.write_all(PING).unwrap();
    remote.expect(&mut peer, PONG);

    cluster.restart_node(owner).unwrap();
    assert!(
        remote.accept_within(Duration::from_secs(2)).is_none(),
        "rejoining node duplicated the surviving bridge"
    );
    publish_local(&mut cluster, local, &packet(b"new traffic", 42, 0), 1, 42);
    remote.expect(&mut peer, &packet(b"new traffic", 3, 0));
    peer.write_all(&ack(0x40, 3)).unwrap();
    peer.write_all(PING).unwrap();
    remote.expect(&mut peer, PONG);
}

// lib/handle_pubrec.c: handle__pubrec serves bridge contexts too. A PUBREC
// naming a still-queued packet id gets PUBREL, and the queued message is sent
// normally once the in-flight one completes.
#[test]
#[ignore = "requires Mosquitto 2.1.4 and mqextended"]
fn remote_pubrec_for_a_queued_packet_id_does_not_stall_the_bridge() {
    let version = Version::V311;
    differential(|kind| {
        let mut remote = Remote::bind();
        let conf = bridge_config(
            version,
            remote.addr(),
            "remote_clientid bridge-q-test\ncleansession true\ntry_private false\n\
             notifications false\nbridge_max_topic_alias 0\nrestart_timeout 5\n",
            "topic bridge/# out 2\n",
        );
        let mut h = start(kind, &format!("{ANONYMOUS}max_inflight_messages 1\n{conf}"));
        let mut peer = remote.accept();
        remote.expect(
            &mut peer,
            &connect_packet(version.level(), "bridge-q-test", 60, 2, &[], None),
        );
        peer.write_all(&connack(version, false, 0, &[])).unwrap();
        let mut unsub = vec![0, 1];
        field(&mut unsub, b"bridge/#");
        remote.expect(&mut peer, &frame(0xa2, &unsub));
        peer.write_all(&frame(0xb0, &[0, 1])).unwrap();
        let local = client(&mut h, 1, version, "queued-helper", false, false, false);
        for (mid, payload) in [(1, b"first"), (2, b"secnd")] {
            publish_local(
                &mut h,
                local,
                &publish(version, "bridge/queued", payload, 2, mid, 0),
                2,
                mid,
            );
        }
        remote.expect(
            &mut peer,
            &publish(version, "bridge/queued", b"first", 2, 2, 0),
        );
        peer.write_all(&ack(0x50, 3)).unwrap();
        remote.expect(&mut peer, &ack(0x62, 3));
        peer.write_all(&ack(0x50, 2)).unwrap();
        remote.expect(&mut peer, &ack(0x62, 2));
        peer.write_all(&ack(0x70, 2)).unwrap();
        remote.expect(
            &mut peer,
            &publish(version, "bridge/queued", b"secnd", 2, 3, 0),
        );
        peer.write_all(&ack(0x50, 3)).unwrap();
        remote.expect(&mut peer, &ack(0x62, 3));
        peer.write_all(&ack(0x70, 3)).unwrap();
        (remote.transcript, h.into_transcript())
    });
}
