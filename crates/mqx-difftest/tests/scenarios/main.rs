use std::time::Duration;

use bytes::{Bytes, BytesMut};
use mqx_codec::ConnectReturnCode::{
    Accepted, IdentifierRejected, NotAuthorized, UnacceptableProtocolVersion,
};
use mqx_codec::ProtocolVersion::{V31, V311};
use mqx_codec::QoS::{AtLeastOnce as Q1, AtMostOnce as Q0, ExactlyOnce as Q2};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, LastWill, Packet, PacketId, ProtocolVersion, Publish, QoS,
    SubAck, Subscribe, SubscribeReturnCode, Unsubscribe, encode,
};
use mqx_difftest::{
    BrokerConfig, BrokerKind, ClusterConfig, Connection, Harness, Reading, Transcript,
};

const RESPONSE: Duration = Duration::from_secs(3);
const SILENCE: Duration = Duration::from_millis(100);
const ANONYMOUS: &str = "allow_anonymous true";

macro_rules! scenario {
    ($name:ident, $conf:expr) => {
        scenario!($name, $conf, crate::compare);
    };
    ($name:ident, $conf:expr, $compare:path) => {
        mod $name {
            use super::*;

            #[test]
            #[ignore = "requires real Mosquitto 2.1.4 binaries"]
            fn mosquitto_self() {
                let first = crate::run(crate::BrokerKind::Mosquitto, $conf, super::$name);
                let second = crate::run(crate::BrokerKind::Mosquitto, $conf, super::$name);
                $compare(&first, &second);
            }

            #[test]
            #[ignore = "requires real Mosquitto 2.1.4 and mqextended binaries"]
            fn cross_broker() {
                // Resolve and run mqextended first so a missing MQEXTENDED_BIN fails immediately.
                let actual = crate::run(crate::BrokerKind::MqExtended, $conf, super::$name);
                let expected = crate::run(crate::BrokerKind::Mosquitto, $conf, super::$name);
                $compare(&expected, &actual);
            }

            #[test]
            #[ignore = "requires real Mosquitto 2.1.4 and cluster-enabled mqextended binaries"]
            fn cross_cluster() {
                let mut cluster = crate::start_cluster($conf);
                super::$name(&mut cluster);
                let actual = cluster.into_transcript();
                let expected = crate::run(crate::BrokerKind::Mosquitto, $conf, super::$name);
                $compare(&expected, &actual);
            }
        }
    };
}

mod codec_parity;
mod connect;
mod failover;
mod persistence;
mod publish;
mod sessions;
mod sys;
mod v5;

fn config(conf: &'static str) -> BrokerConfig<'static> {
    BrokerConfig {
        conf,
        ..BrokerConfig::default()
    }
}

fn start_cluster(conf: BrokerConfig<'_>) -> Harness {
    Harness::start_cluster(conf, ClusterConfig::default())
        .unwrap_or_else(|err| panic!("mqextended cluster: {err}"))
}

fn run(kind: BrokerKind, conf: BrokerConfig<'_>, scenario: fn(&mut Harness)) -> Transcript {
    let mut harness = Harness::start(kind, conf).unwrap_or_else(|err| panic!("{kind:?}: {err}"));
    scenario(&mut harness);
    harness.into_transcript()
}

fn compare(expected: &Transcript, actual: &Transcript) {
    for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        assert_eq!(expected, actual, "transcript observation #{index}");
    }
    assert_eq!(expected.len(), actual.len(), "transcript length");
}

fn id(value: u16) -> PacketId {
    PacketId::new(value).unwrap()
}

fn options(client_id: &str) -> Connect {
    Connect {
        protocol: V311,
        is_bridge: false,
        clean_session: true,
        keep_alive: 0,
        client_id: client_id.into(),
        will: None,
        username: None,
        password: None,
    }
}

#[track_caller]
fn send(h: &mut Harness, client: Connection, packet: Packet) {
    h.send(client, &packet)
        .unwrap_or_else(|err| panic!("{client:?}: MQTT packet send failed: {err}"));
}

#[track_caller]
fn raw(h: &mut Harness, client: Connection, wire: &[u8]) {
    h.send_raw(client, wire)
        .unwrap_or_else(|err| panic!("{client:?}: raw send failed: {err}"));
}

#[track_caller]
fn read(h: &mut Harness, client: Connection, timeout: Duration) -> &Reading {
    h.receive(client, timeout)
        .unwrap_or_else(|err| panic!("{client:?}: receive failed: {err}"))
}

#[track_caller]
fn received(h: &mut Harness, client: Connection, expected: Packet) {
    match read(h, client, RESPONSE) {
        Reading::Received { packet, .. } => assert_eq!(packet, &expected, "{client:?}"),
        reading => panic!("{client:?}: expected {expected:?}, observed {reading:?}"),
    }
}

#[track_caller]
fn closed(h: &mut Harness, client: Connection) {
    assert_eq!(read(h, client, RESPONSE), &Reading::Closed, "{client:?}");
    h.close_socket(client);
}

#[track_caller]
fn silent(h: &mut Harness, client: Connection) {
    assert_eq!(read(h, client, SILENCE), &Reading::TimedOut, "{client:?}");
}

#[track_caller]
fn connack(h: &mut Harness, client: Connection, code: ConnectReturnCode, session_present: bool) {
    received(
        h,
        client,
        Packet::ConnAck(ConnAck {
            code,
            session_present,
        }),
    );
}

#[track_caller]
fn connect_with(h: &mut Harness, settings: Connect, session_present: bool) -> Connection {
    let client = h.open(settings.protocol).unwrap();
    send(h, client, Packet::Connect(settings));
    connack(h, client, Accepted, session_present);
    client
}

#[track_caller]
fn client(h: &mut Harness, client_id: &str) -> Connection {
    connect_with(h, options(client_id), false)
}

#[track_caller]
fn subscribe(h: &mut Harness, client: Connection, mid: u16, filters: &[(&str, QoS)]) {
    let packet_id = id(mid);
    send(
        h,
        client,
        Packet::Subscribe(Subscribe {
            packet_id,
            filters: filters
                .iter()
                .map(|(topic, qos)| ((*topic).into(), *qos))
                .collect(),
        }),
    );
    received(
        h,
        client,
        Packet::SubAck(SubAck {
            packet_id,
            return_codes: filters
                .iter()
                .map(|(_, qos)| SubscribeReturnCode::Success(*qos))
                .collect(),
        }),
    );
}

#[track_caller]
fn unsubscribe(h: &mut Harness, client: Connection, mid: u16, filter: &str) {
    send(
        h,
        client,
        Packet::Unsubscribe(Unsubscribe {
            packet_id: id(mid),
            filters: vec![filter.into()],
        }),
    );
    received(h, client, Packet::UnsubAck(id(mid)));
}

fn publish(topic: &str, payload: &'static [u8], qos: QoS, mid: u16) -> Publish {
    assert_eq!(mid == 0, qos == Q0);
    Publish {
        dup: false,
        retain: false,
        qos,
        topic: topic.into(),
        packet_id: PacketId::new(mid),
        payload: Bytes::from_static(payload),
    }
}

#[track_caller]
fn publish_from(h: &mut Harness, sender: Connection, message: Publish) {
    let qos = message.qos;
    let mid = message.packet_id;
    send(h, sender, Packet::Publish(message));
    match qos {
        Q0 => ping(h, sender),
        Q1 => received(h, sender, Packet::PubAck(mid.unwrap())),
        Q2 => {
            let mid = mid.unwrap();
            received(h, sender, Packet::PubRec(mid));
            send(h, sender, Packet::PubRel(mid));
            received(h, sender, Packet::PubComp(mid));
        }
    }
}

#[track_caller]
fn accept_publish(h: &mut Harness, receiver: Connection, message: Publish) {
    let qos = message.qos;
    let mid = message.packet_id;
    received(h, receiver, Packet::Publish(message));
    match qos {
        Q0 => (),
        Q1 => send(h, receiver, Packet::PubAck(mid.unwrap())),
        Q2 => {
            let mid = mid.unwrap();
            send(h, receiver, Packet::PubRec(mid));
            received(h, receiver, Packet::PubRel(mid));
            send(h, receiver, Packet::PubComp(mid));
        }
    }
}

#[track_caller]
fn ping(h: &mut Harness, client: Connection) {
    send(h, client, Packet::PingReq);
    received(h, client, Packet::PingResp);
}

#[track_caller]
fn disconnect(h: &mut Harness, client: Connection) {
    send(h, client, Packet::Disconnect);
    // EOF is also a barrier before the next socket uses the same session.
    closed(h, client);
}
