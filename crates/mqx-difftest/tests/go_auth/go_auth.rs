//! Compare the native port with the pinned go-auth.so through real broker processes.

use std::time::Duration;

use bytes::Bytes;
use mqx_codec::v5::{self, Packet, ReasonCode as R};
use mqx_codec::{PacketId, QoS};
use mqx_difftest::{
    BrokerConfig, BrokerKind, ClusterConfig, ClusterReadiness, Connection, Harness, Reading,
    Transcript,
};
use services::{Request, SECRET};

#[derive(Debug, Clone, Copy)]
enum Target {
    Mosquitto,
    Standalone,
    Cluster,
}

#[derive(Default)]
struct Trace {
    mqtt: Transcript,
    requests: Vec<Request>,
    queries: Vec<String>,
}

fn compare(first: Target, second: Target, script: impl Fn(Target) -> Trace) {
    // Some fixture servers are reused and must only see one broker run at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = SERIAL.lock().unwrap_or_else(|err| err.into_inner());
    let mut left = script(first);
    let mut right = script(second);
    for (index, (left, right)) in left.mqtt.iter().zip(&right.mqtt).enumerate() {
        assert_eq!(left, right, "{second:?}, MQTT observation {index}");
    }
    assert_eq!(
        left.mqtt.len(),
        right.mqtt.len(),
        "{second:?}, MQTT observation count"
    );
    // The relative arrival order of independent cluster checks is not stable.
    // Preserve duplicates and compare complete request headers and bodies.
    left.requests.sort_unstable();
    right.requests.sort_unstable();
    assert_eq!(
        left.requests, right.requests,
        "{second:?}, HTTP request multiset"
    );
    left.queries.sort_unstable();
    right.queries.sort_unstable();
    assert_eq!(
        left.queries, right.queries,
        "{second:?}, database query multiset"
    );
}

macro_rules! scenario {
    ($name:ident, $script:expr) => {
        mod $name {
            use super::*;

            #[test]
            #[ignore = "requires scripts/go-auth-reference.sh and backend fixtures"]
            fn mosquitto_self() {
                compare(Target::Mosquitto, Target::Mosquitto, $script);
            }

            #[test]
            #[ignore = "requires scripts/go-auth-reference.sh and mqextended"]
            fn cross_broker() {
                compare(Target::Mosquitto, Target::Standalone, $script);
            }

            #[test]
            #[ignore = "requires scripts/go-auth-reference.sh and cluster-enabled mqextended"]
            fn cross_cluster() {
                compare(Target::Mosquitto, Target::Cluster, $script);
            }
        }
    };
}

#[path = "databases.rs"]
mod databases;
#[path = "http.rs"]
mod http;
#[path = "services.rs"]
mod services;

fn broker(target: Target, backends: &str, options: &str) -> Harness {
    let plugin = services::go_auth_path("MOSQUITTO_GO_AUTH_SO");
    let conf = format!(
        "per_listener_settings true\nlistener_allow_anonymous true\nmax_packet_size 2000000\n\
         auth_plugin {}\n\
         auth_opt_backends {backends}\nauth_opt_hasher_salt_encoding utf-8\n\
         auth_opt_log_level error\n{options}",
        plugin.display()
    );
    let config = BrokerConfig {
        conf: &conf,
        ..BrokerConfig::default()
    };
    match target {
        Target::Mosquitto => Harness::start_with_binary(
            BrokerKind::Mosquitto,
            &services::go_auth_path("MOSQUITTO_GO_AUTH_BINARY"),
            config,
        ),
        Target::Standalone => Harness::start(BrokerKind::MqExtended, config),
        Target::Cluster => Harness::start_cluster(
            config,
            ClusterConfig {
                readiness: ClusterReadiness::HttpStatus,
                ..ClusterConfig::default()
            },
        ),
    }
    .unwrap_or_else(|error| panic!("{target:?}: {error}"))
}

fn mid(number: u16) -> PacketId {
    PacketId::new(number).unwrap()
}

#[track_caller]
fn receive(h: &mut Harness, c: Connection) -> &Reading {
    h.receive(c, Duration::from_secs(4)).unwrap()
}

#[track_caller]
fn expect(h: &mut Harness, c: Connection, packet: Packet) {
    let observed = receive(h, c);
    assert!(
        matches!(observed, Reading::ReceivedV5 { packet: actual, .. } if *actual == packet),
        "expected {packet:?}, got {observed:?}"
    );
}

#[track_caller]
fn connect(h: &mut Harness, id: &str, username: &str, password: &str, reason: R) -> Connection {
    connect_with(h, id, Some(username), Some(password), None, reason)
}

#[track_caller]
fn connect_with(
    h: &mut Harness,
    id: &str,
    username: Option<&str>,
    password: Option<&str>,
    will: Option<v5::LastWill>,
    reason: R,
) -> Connection {
    let c = h.open_v5().unwrap();
    h.send_v5(
        c,
        &Packet::Connect(v5::Connect {
            private_protocol_bit: false,
            clean_start: true,
            keep_alive: 0,
            properties: Vec::new(),
            client_id: id.into(),
            will,
            username: username.map(str::to_owned),
            password: password.map(|s| Bytes::copy_from_slice(s.as_bytes())),
        }),
    )
    .unwrap();
    let observed = receive(h, c);
    assert!(
        matches!(observed, Reading::ReceivedV5 { packet: Packet::ConnAck(ack), .. } if ack.reason == reason),
        "{id}: expected CONNACK {reason:?}, got {observed:?}"
    );
    if reason != R::SUCCESS {
        assert_eq!(receive(h, c), &Reading::Closed);
    }
    c
}

#[track_caller]
fn subscribe(h: &mut Harness, c: Connection, id: u16, filter: &str, reason: R) {
    let packet_id = mid(id);
    h.send_v5(
        c,
        &Packet::Subscribe(v5::Subscribe {
            packet_id,
            properties: Vec::new(),
            subscriptions: vec![v5::Subscription {
                filter: filter.into(),
                qos: QoS::AtMostOnce,
                no_local: false,
                retain_as_published: false,
                retain_handling: v5::RetainHandling::SendAlways,
            }],
        }),
    )
    .unwrap();
    expect(
        h,
        c,
        Packet::SubAck(v5::SubscriptionAck {
            packet_id,
            properties: Vec::new(),
            reasons: vec![reason],
        }),
    );
}

#[track_caller]
fn unsubscribe(h: &mut Harness, c: Connection, id: u16, filter: &str) {
    let packet_id = mid(id);
    h.send_v5(
        c,
        &Packet::Unsubscribe(v5::Unsubscribe {
            packet_id,
            properties: Vec::new(),
            filters: vec![filter.into()],
        }),
    )
    .unwrap();
    expect(
        h,
        c,
        Packet::UnsubAck(v5::SubscriptionAck {
            packet_id,
            properties: Vec::new(),
            reasons: vec![R::SUCCESS],
        }),
    );
}

#[track_caller]
fn publish(h: &mut Harness, c: Connection, id: u16, topic: &str, retain: bool, reason: R) {
    let packet_id = mid(id);
    h.send_v5(
        c,
        &Packet::Publish(v5::Publish {
            dup: false,
            retain,
            qos: QoS::AtLeastOnce,
            topic: topic.into(),
            packet_id: Some(packet_id),
            properties: Vec::new(),
            payload: Bytes::from_static(b"value"),
        }),
    )
    .unwrap();
    expect(
        h,
        c,
        Packet::PubAck(v5::PublishAck {
            packet_id,
            properties: Vec::new(),
            reason,
        }),
    );
}

#[track_caller]
fn delivery(h: &mut Harness, c: Connection, topic: &str, payload: &'static [u8], retain: bool) {
    expect(
        h,
        c,
        Packet::Publish(v5::Publish {
            dup: false,
            retain,
            qos: QoS::AtMostOnce,
            topic: topic.into(),
            packet_id: None,
            properties: Vec::new(),
            payload: Bytes::from_static(payload),
        }),
    );
}

fn files(dir: &tempfile::TempDir, acl: &str) -> String {
    let password = dir.path().join("pw");
    let acl_path = dir.path().join("acl");
    std::fs::write(&password, format!("alice:{}\n", services::HASH)).unwrap();
    std::fs::write(&acl_path, acl).unwrap();
    format!(
        "auth_opt_files_password_path {}\nauth_opt_files_acl_path {}\n",
        password.display(),
        acl_path.display(),
    )
}
