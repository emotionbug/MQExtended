use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use mqx_codec::v5::{
    ConnAck, DecodeContext, Packet, Property as P, Publish, PublishAck, QoS, ReasonCode as R,
    RetainHandling, SubscriptionAck, decode, encode, peek_connect_protocol_level,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const TOPIC: &str = "v5/wire/é";
const BODY: &str = "v5 test payload";
const CONTEXT: DecodeContext = DecodeContext::new(8192);

struct Client(Option<Child>);

impl Client {
    fn start(binary: &Path, listener: &TcpListener, args: &[&str]) -> Self {
        let child = Command::new(binary)
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME")
            .args([
                "-h",
                "127.0.0.1",
                "-p",
                &listener.local_addr().unwrap().port().to_string(),
                "-V",
                "5",
            ])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("spawn {}: {err}", binary.display()));
        Self(Some(child))
    }

    fn wait(mut self) -> Output {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                let output = self.0.take().unwrap().wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "Mosquitto client exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
                return output;
            }
            assert!(Instant::now() < deadline, "Mosquitto client did not exit");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Peer {
    socket: TcpStream,
    input: BytesMut,
}

impl Peer {
    fn accept(listener: &TcpListener, client: &mut Client) -> Self {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if client.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                        let output = client.0.take().unwrap().wait_with_output().unwrap();
                        panic!(
                            "Mosquitto client exited before CONNECT: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    assert!(
                        Instant::now() < deadline,
                        "Mosquitto client did not connect"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("accept: {err}"),
            }
        };
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        Self {
            socket,
            input: BytesMut::new(),
        }
    }

    fn receive(&mut self) -> Option<Packet> {
        let mut block = [0; 4096];
        loop {
            if let Some(packet) = decode(&mut self.input, CONTEXT).unwrap() {
                return Some(packet);
            }
            let count = self.socket.read(&mut block).unwrap();
            if count == 0 {
                assert!(self.input.is_empty(), "client sent a partial packet");
                return None;
            }
            self.input.extend_from_slice(&block[..count]);
        }
    }

    fn send(&mut self, packet: Packet) {
        let mut output = BytesMut::new();
        encode(&packet, &mut output).unwrap();
        self.socket.write_all(&output).unwrap();
    }

    fn connack(&mut self) {
        self.send(Packet::ConnAck(ConnAck {
            session_present: false,
            reason: R::SUCCESS,
            properties: vec![P::ReceiveMaximum(8), P::TopicAliasMaximum(3)],
        }));
    }

    fn expect_connect(&mut self, client_id: &str) -> mqx_codec::v5::Connect {
        while peek_connect_protocol_level(&self.input).unwrap().is_none() {
            let mut bytes = [0; 64];
            let count = self.socket.read(&mut bytes).unwrap();
            assert_ne!(
                count, 0,
                "client closed before sending the CONNECT protocol byte"
            );
            self.input.extend_from_slice(&bytes[..count]);
        }
        assert_eq!(peek_connect_protocol_level(&self.input).unwrap(), Some(5));
        let Some(Packet::Connect(connect)) = self.receive() else {
            panic!("expected CONNECT")
        };
        assert_eq!(connect.client_id, client_id);
        assert!(!connect.private_protocol_bit);
        connect
    }

    fn finishing(mut self) {
        // lib/packet_mosq.c: packet__write half-closes after sending DISCONNECT.
        // Drop the broker end so mosquitto_sub sees EOF and its loop can exit.
        // client/pub_client.c: pub_other_loop may exit without flushing it.
        match self.receive() {
            Some(Packet::Disconnect(packet)) => {
                assert_eq!(packet.reason, R::NORMAL_DISCONNECTION);
                assert!(self.input.is_empty());
            }
            None => {}
            other => panic!("expected DISCONNECT or EOF, got {other:?}"),
        }
    }
}

fn binary(build: &Path, name: &str) -> PathBuf {
    let path = build.join("client").join(name);
    assert!(
        path.is_file(),
        "Missing {}. Build Mosquitto 2.1.4 and set MOSQUITTO_BUILD_DIR.",
        path.display()
    );
    path
}

fn publisher(binary: &Path) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut client = Client::start(
        binary,
        &listener,
        &[
            "-i",
            "mqx-v5-pub",
            "-t",
            TOPIC,
            "-m",
            BODY,
            "-q",
            "2",
            "-r",
            "-D",
            "connect",
            "session-expiry-interval",
            "42",
            "-D",
            "connect",
            "user-property",
            "key",
            "connect",
            "--will-topic",
            "unexpected/exit",
            "--will-payload",
            "lost",
            "--will-qos",
            "1",
            "--will-retain",
            "-D",
            "will",
            "will-delay-interval",
            "7",
            "-D",
            "will",
            "content-type",
            "text/termination",
            "-D",
            "will",
            "user-property",
            "key",
            "will",
            "-D",
            "publish",
            "response-topic",
            "wire/reply",
            "-D",
            "publish",
            "content-type",
            "text/plain",
            "-D",
            "publish",
            "correlation-data",
            "request-key",
            "-D",
            "publish",
            "user-property",
            "key",
            "first",
            "-D",
            "publish",
            "user-property",
            "key",
            "second",
        ],
    );
    let mut peer = Peer::accept(&listener, &mut client);
    let connect = peer.expect_connect("mqx-v5-pub");
    assert!(connect.properties.contains(&P::SessionExpiryInterval(42)));
    assert!(
        connect
            .properties
            .contains(&P::UserProperty("key".into(), "connect".into()))
    );
    let will = connect.will.unwrap();
    assert!(will.retain);
    assert_eq!(will.topic, "unexpected/exit");
    assert_eq!(will.qos, QoS::AtLeastOnce);
    assert_eq!(will.payload, b"lost".as_slice());
    assert_eq!(
        will.properties,
        [
            P::WillDelayInterval(7),
            P::ContentType("text/termination".into()),
            P::UserProperty("key".into(), "will".into())
        ]
    );
    peer.connack();
    let Some(Packet::Publish(publish)) = peer.receive() else {
        panic!("expected PUBLISH")
    };
    assert_eq!(publish.topic, TOPIC);
    assert_eq!(publish.payload, BODY.as_bytes());
    assert_eq!(publish.qos, QoS::ExactlyOnce);
    assert!(publish.retain);
    assert_eq!(
        publish.properties,
        [
            P::ResponseTopic("wire/reply".into()),
            P::ContentType("text/plain".into()),
            P::CorrelationData(Bytes::from_static(b"request-key")),
            P::UserProperty("key".into(), "first".into()),
            P::UserProperty("key".into(), "second".into())
        ]
    );
    let mut ack = PublishAck {
        packet_id: publish.packet_id.unwrap(),
        reason: R::SUCCESS,
        properties: vec![P::ReasonString("received".into())],
    };
    peer.send(Packet::PubRec(ack.clone()));
    ack.properties.clear();
    assert_eq!(peer.receive(), Some(Packet::PubRel(ack.clone())));
    peer.send(Packet::PubComp(ack));
    peer.finishing();
    client.wait();
}

fn subscriber(binary: &Path) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut client = Client::start(
        binary,
        &listener,
        &[
            "-i",
            "mqx-v5-sub",
            "-t",
            TOPIC,
            "-q",
            "1",
            "-C",
            "1",
            "-D",
            "connect",
            "session-expiry-interval",
            "24",
            "-D",
            "subscribe",
            "subscription-identifier",
            "128",
            "-D",
            "subscribe",
            "user-property",
            "key",
            "subscribe",
        ],
    );
    let mut peer = Peer::accept(&listener, &mut client);
    let connect = peer.expect_connect("mqx-v5-sub");
    assert!(connect.properties.contains(&P::SessionExpiryInterval(24)));
    peer.connack();
    let Some(Packet::Subscribe(subscribe)) = peer.receive() else {
        panic!("expected SUBSCRIBE")
    };
    assert_eq!(
        subscribe.properties,
        [
            P::SubscriptionIdentifier(128),
            P::UserProperty("key".into(), "subscribe".into())
        ]
    );
    let [sub] = subscribe.subscriptions.as_slice() else {
        panic!("expected one subscription")
    };
    assert_eq!(sub.filter, TOPIC);
    assert_eq!(sub.qos, QoS::AtLeastOnce);
    assert_eq!(sub.retain_handling, RetainHandling::SendAlways);
    peer.send(Packet::SubAck(SubscriptionAck {
        packet_id: subscribe.packet_id,
        properties: vec![P::ReasonString("subscribed".into())],
        reasons: vec![R::GRANTED_QOS_1],
    }));
    peer.send(Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtLeastOnce,
        retain: false,
        topic: TOPIC.into(),
        packet_id: Some(subscribe.packet_id),
        properties: vec![
            P::SubscriptionIdentifier(128),
            P::ContentType("text/plain".into()),
            P::UserProperty("key".into(), "delivery".into()),
        ],
        payload: Bytes::from_static(BODY.as_bytes()),
    }));
    assert_eq!(
        peer.receive(),
        Some(Packet::PubAck(PublishAck {
            packet_id: subscribe.packet_id,
            reason: R::SUCCESS,
            properties: Vec::new()
        }))
    );
    peer.finishing();
    let output = client.wait();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{BODY}\n")
    );
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 clients (MOSQUITTO_BUILD_DIR)"]
fn real_mosquitto_pub_and_sub_exchange_v5_packets_and_properties() {
    let build = PathBuf::from(
        env::var_os("MOSQUITTO_BUILD_DIR")
            .expect("set MOSQUITTO_BUILD_DIR to the Mosquitto 2.1.4 CMake build directory"),
    );
    let pub_client = binary(&build, "mosquitto_pub");
    let sub_client = binary(&build, "mosquitto_sub");
    publisher(&pub_client);
    subscriber(&sub_client);
}
