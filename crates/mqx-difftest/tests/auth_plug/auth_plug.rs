//! Compare the native port with the real v4 plugin, including MQTT frames and HTTP requests.

#[path = "services.rs"]
mod services;

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use mqx_codec::ConnectReturnCode::{Accepted, NotAuthorized};
use mqx_codec::ProtocolVersion::V311;
use mqx_codec::QoS::{AtLeastOnce as Q1, AtMostOnce as Q0, ExactlyOnce as Q2};
use mqx_codec::v5::{self, ReasonCode as R};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, LastWill, Packet, PacketId, Publish, QoS, SubAck,
    Subscribe, SubscribeReturnCode,
};
use mqx_difftest::{
    BrokerConfig, BrokerKind, ClusterConfig, Connection, Harness, Reading, Transcript,
};
use services::{HASH, Http, Request, SECRET};
use tempfile::TempDir;

const RESPONSE: Duration = Duration::from_secs(3);
const SILENCE: Duration = Duration::from_millis(100);
const ALICE: Option<(&str, &str)> = Some(("alice", SECRET));
static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy)]
enum Target {
    Mosquitto,
    Standalone,
    Cluster,
}

#[derive(Default, PartialEq, Eq, Debug)]
struct Trace {
    mqtt: Vec<Transcript>,
    http: Vec<Request>,
}

impl Trace {
    fn mqtt(
        &mut self,
        target: Target,
        config: BrokerConfig<'_>,
        script: impl FnOnce(&mut Harness),
    ) {
        let mut h = match target {
            Target::Mosquitto => Harness::start_with_binary(
                BrokerKind::Mosquitto,
                &services::path("MOSQUITTO_AUTH_PLUG_BINARY"),
                config,
            ),
            Target::Standalone => Harness::start(BrokerKind::MqExtended, config),
            Target::Cluster => Harness::start_cluster(config, ClusterConfig::default()),
        }
        .unwrap_or_else(|error| panic!("{target:?}: {error}"));
        script(&mut h);
        self.mqtt.push(h.into_transcript());
    }

    fn http(&mut self, server: &Http) {
        // Different cluster nodes can issue independent delivery checks concurrently.
        // Compare all requests, preserving duplicates and their complete headers and body.
        let mut requests = server.take_requests();
        requests.sort_unstable();
        self.http.extend(requests);
    }
}

fn compare(first: Target, second: Target, script: impl Fn(Target) -> Trace) {
    // In-process HTTP responses and mutable backend data are shared across runs.
    let _lock = SERIAL.lock().unwrap_or_else(|err| err.into_inner());
    let expected = script(first);
    let actual = script(second);
    for (index, (expected, actual)) in expected.mqtt.iter().zip(&actual.mqtt).enumerate() {
        for (packet, (expected, actual)) in expected.iter().zip(actual).enumerate() {
            assert_eq!(
                expected, actual,
                "{second:?}, broker run {index}, MQTT observation {packet}"
            );
        }
        assert_eq!(
            expected.len(),
            actual.len(),
            "broker run {index}, MQTT observation count"
        );
    }
    assert_eq!(expected.mqtt.len(), actual.mqtt.len());
    assert_eq!(expected.http, actual.http, "{second:?} HTTP requests");
}

macro_rules! scenario {
    ($name:ident, $script:expr) => {
        mod $name {
            use super::*;

            #[test]
            #[ignore = "requires scripts/auth-plug-reference.sh"]
            fn mosquitto_self() {
                compare(Target::Mosquitto, Target::Mosquitto, $script);
            }

            #[test]
            #[ignore = "requires scripts/auth-plug-reference.sh and mqextended"]
            fn cross_broker() {
                compare(Target::Mosquitto, Target::Standalone, $script);
            }

            #[test]
            #[ignore = "requires scripts/auth-plug-reference.sh and cluster-enabled mqextended"]
            fn cross_cluster() {
                compare(Target::Mosquitto, Target::Cluster, $script);
            }
        }
    };
}

fn config(backends: &str, anonymous: bool, options: &str) -> String {
    let plugin = services::path("MOSQUITTO_AUTH_PLUG_SO");
    format!(
        "allow_anonymous {anonymous}\nmax_packet_size 2000000\n\
         auth_plugin {}\nauth_opt_backends {backends}\nauth_opt_log_quiet true\n{options}",
        plugin.display(),
    )
}

fn files(dir: &TempDir, users: &[&str], acl: Option<&str>) -> String {
    let passwd = dir.path().join("plugin-passwd");
    let contents: String = users
        .iter()
        .map(|user| format!("{user}:{HASH}\n"))
        .collect();
    fs::write(&passwd, contents).unwrap();
    let mut options = format!("auth_opt_password_file {}\n", passwd.display());
    if let Some(acl) = acl {
        let path = dir.path().join("plugin-acl");
        fs::write(&path, acl).unwrap();
        options.push_str(&format!("auth_opt_acl_file {}\n", path.display()));
    }
    options
}

#[track_caller]
fn read(h: &mut Harness, c: Connection) -> &Reading {
    h.receive(c, RESPONSE).unwrap()
}

#[track_caller]
fn receive(h: &mut Harness, c: Connection, expected: Packet) {
    let actual = read(h, c);
    assert!(
        matches!(actual, Reading::Received { packet, .. } if *packet == expected),
        "expected {expected:?}, got {actual:?}"
    );
}

#[track_caller]
fn receive_v5(h: &mut Harness, c: Connection, expected: v5::Packet) {
    let actual = read(h, c);
    assert!(
        matches!(actual, Reading::ReceivedV5 { packet, .. } if *packet == expected),
        "expected {expected:?}, got {actual:?}"
    );
}

#[track_caller]
fn silent(h: &mut Harness, c: Connection) {
    assert_eq!(h.receive(c, SILENCE).unwrap(), &Reading::TimedOut);
}

fn bytes(value: &str) -> Bytes {
    Bytes::copy_from_slice(value.as_bytes())
}

#[track_caller]
fn open(
    h: &mut Harness,
    id: &str,
    credentials: Option<(&str, &str)>,
    will: Option<LastWill>,
) -> Connection {
    let c = h.open(V311).unwrap();
    h.send(
        c,
        &Packet::Connect(Connect {
            protocol: V311,
            is_bridge: false,
            clean_session: true,
            keep_alive: 0,
            client_id: id.into(),
            will,
            username: credentials.map(|(user, _)| user.into()),
            password: credentials.map(|(_, password)| bytes(password)),
        }),
    )
    .unwrap();
    c
}

#[track_caller]
fn connect(
    h: &mut Harness,
    id: &str,
    credentials: Option<(&str, &str)>,
    code: ConnectReturnCode,
) -> Connection {
    let c = open(h, id, credentials, None);
    receive(
        h,
        c,
        Packet::ConnAck(ConnAck {
            code,
            session_present: false,
        }),
    );
    if code != Accepted {
        assert_eq!(read(h, c), &Reading::Closed);
    }
    c
}

#[track_caller]
fn connect_v5(h: &mut Harness, id: &str, credentials: (&str, &str), expected: R) -> Connection {
    let c = h.open_v5().unwrap();
    h.send_v5(
        c,
        &v5::Packet::Connect(v5::Connect {
            private_protocol_bit: false,
            clean_start: true,
            keep_alive: 0,
            properties: Vec::new(),
            client_id: id.into(),
            will: None,
            username: Some(credentials.0.into()),
            password: Some(bytes(credentials.1)),
        }),
    )
    .unwrap();
    let actual = read(h, c);
    assert!(
        matches!(actual, Reading::ReceivedV5 { packet: v5::Packet::ConnAck(ack), .. } if ack.reason == expected),
        "expected CONNACK {expected:?}, got {actual:?}"
    );
    if expected != R::SUCCESS {
        assert_eq!(read(h, c), &Reading::Closed);
    }
    c
}

fn id(mid: u16) -> PacketId {
    PacketId::new(mid).unwrap()
}

#[track_caller]
fn subscribe(h: &mut Harness, c: Connection, mid: u16, filters: &[(&str, bool)]) {
    h.send(
        c,
        &Packet::Subscribe(Subscribe {
            packet_id: id(mid),
            filters: filters
                .iter()
                .map(|(filter, _)| ((*filter).into(), Q0))
                .collect(),
        }),
    )
    .unwrap();
    receive(
        h,
        c,
        Packet::SubAck(SubAck {
            packet_id: id(mid),
            return_codes: filters
                .iter()
                .map(|(_, allowed)| {
                    if *allowed {
                        SubscribeReturnCode::Success(Q0)
                    } else {
                        SubscribeReturnCode::Failure
                    }
                })
                .collect(),
        }),
    );
}

#[track_caller]
fn subscribe_v5(h: &mut Harness, c: Connection, mid: u16, filters: &[(&str, bool)]) {
    h.send_v5(
        c,
        &v5::Packet::Subscribe(v5::Subscribe {
            packet_id: id(mid),
            properties: Vec::new(),
            subscriptions: filters
                .iter()
                .map(|(filter, _)| v5::Subscription {
                    filter: (*filter).into(),
                    qos: Q0,
                    no_local: false,
                    retain_as_published: false,
                    retain_handling: v5::RetainHandling::SendAlways,
                })
                .collect(),
        }),
    )
    .unwrap();
    receive_v5(
        h,
        c,
        v5::Packet::SubAck(v5::SubscriptionAck {
            packet_id: id(mid),
            properties: Vec::new(),
            reasons: filters
                .iter()
                .map(|(_, allowed)| {
                    if *allowed {
                        R::SUCCESS
                    } else {
                        R::NOT_AUTHORIZED
                    }
                })
                .collect(),
        }),
    );
}

fn publication(topic: &str, payload: &'static [u8], qos: QoS, mid: u16, retain: bool) -> Publish {
    Publish {
        dup: false,
        retain,
        qos,
        topic: topic.into(),
        packet_id: PacketId::new(mid),
        payload: Bytes::from_static(payload),
    }
}

#[track_caller]
fn ping(h: &mut Harness, c: Connection) {
    h.send(c, &Packet::PingReq).unwrap();
    receive(h, c, Packet::PingResp);
}

#[track_caller]
fn publish(h: &mut Harness, c: Connection, p: Publish, allowed: bool) {
    let qos = p.qos;
    let mid = p.packet_id;
    h.send(c, &Packet::Publish(p)).unwrap();
    // Mosquitto handle_publish.c: process_bad_message acknowledges rejected QoS 1/2;
    // MQTT 3.1.1 has no reason byte. QoS 0 has no ACK on either path.
    match qos {
        Q0 => ping(h, c),
        Q1 => receive(h, c, Packet::PubAck(mid.unwrap())),
        Q2 => {
            let mid = mid.unwrap();
            receive(h, c, Packet::PubRec(mid));
            if allowed {
                h.send(c, &Packet::PubRel(mid)).unwrap();
                receive(h, c, Packet::PubComp(mid));
            }
        }
    }
}

fn ack(mid: PacketId, reason: R) -> v5::PublishAck {
    v5::PublishAck {
        packet_id: mid,
        reason,
        properties: Vec::new(),
    }
}

#[track_caller]
fn publish_v5(h: &mut Harness, c: Connection, topic: &str, qos: QoS, mid: u16, allowed: bool) {
    h.send_v5(
        c,
        &v5::Packet::Publish(v5::Publish {
            dup: false,
            retain: false,
            qos,
            topic: topic.into(),
            packet_id: PacketId::new(mid),
            properties: Vec::new(),
            payload: Bytes::from_static(if allowed { b"ok" } else { b"denied" }),
        }),
    )
    .unwrap();
    let reason = if allowed {
        R::SUCCESS
    } else {
        R::NOT_AUTHORIZED
    };
    match qos {
        Q0 => {
            h.send_v5(c, &v5::Packet::PingReq).unwrap();
            receive_v5(h, c, v5::Packet::PingResp);
        }
        Q1 => receive_v5(h, c, v5::Packet::PubAck(ack(id(mid), reason))),
        Q2 => {
            let mid = id(mid);
            receive_v5(h, c, v5::Packet::PubRec(ack(mid, reason)));
            if allowed {
                h.send_v5(c, &v5::Packet::PubRel(ack(mid, R::SUCCESS)))
                    .unwrap();
                receive_v5(h, c, v5::Packet::PubComp(ack(mid, R::SUCCESS)));
            }
        }
    }
}

#[track_caller]
fn delivery(h: &mut Harness, c: Connection, topic: &str, payload: &'static [u8], retain: bool) {
    receive(
        h,
        c,
        Packet::Publish(publication(topic, payload, Q0, 0, retain)),
    );
}

#[derive(Clone, Copy)]
enum Backend {
    Files,
    Cdb,
    Sqlite,
    Redis,
    Memcached,
    Postgres,
    Mysql,
    Ldap,
}

impl Backend {
    fn config(self, dir: &TempDir) -> (&'static str, String) {
        match self {
            Self::Files => (
                "files",
                files(
                    dir,
                    &["alice", "root-exempt"],
                    Some("topic read allowed\ntopic write allowed\n"),
                ),
            ),
            Self::Cdb => {
                let map = dir.path().join("cdb-input");
                let db = dir.path().join("passwords.cdb");
                fs::write(&map, format!("alice\t{HASH}\n")).unwrap();
                services::run(
                    Command::new(services::path("MOSQUITTO_AUTH_PLUG_CDB"))
                        .args(["-c", "-m"])
                        .arg(&db)
                        .arg(&map),
                );
                ("cdb", format!("auth_opt_cdbname {}\n", db.display()))
            }
            Self::Sqlite => {
                let db = dir.path().join("passwords.sqlite");
                let sql = format!(
                    "CREATE TABLE users(name, hash); INSERT INTO users VALUES('alice', '{HASH}');"
                );
                services::run(services::tool("usr/bin/sqlite3").arg(&db).arg(sql));
                (
                    "sqlite",
                    format!(
                        "auth_opt_dbpath {}\nauth_opt_sqliteuserquery SELECT hash FROM users WHERE name = ?\n",
                        db.display()
                    ),
                )
            }
            Self::Redis => ("redis", redis_options(services::redis())),
            Self::Memcached => (
                "memcached",
                format!(
                    "auth_opt_memcached_host 127.0.0.1\nauth_opt_memcached_port {}\n\
                 auth_opt_memcached_aclquery enabled\n",
                    services::memcached()
                ),
            ),
            Self::Postgres => (
                "postgres",
                format!(
                    "auth_opt_host 127.0.0.1\nauth_opt_port {}\nauth_opt_user mqx\nauth_opt_dbname postgres\n\
                 auth_opt_userquery SELECT hash FROM users WHERE name = $1\n\
                 auth_opt_superquery SELECT admin FROM users WHERE name = $1\n\
                 auth_opt_aclquery SELECT topic FROM acl WHERE name = $1 AND access = $2\n",
                    services::postgres()
                ),
            ),
            Self::Mysql => (
                "mysql",
                format!(
                    "auth_opt_host 127.0.0.1\nauth_opt_port {}\nauth_opt_user mqx\nauth_opt_pass fixture\nauth_opt_dbname mqtt\n\
                 auth_opt_userquery SELECT hash FROM users WHERE name = '%s'\n\
                 auth_opt_superquery SELECT admin FROM users WHERE name = '%s'\n\
                 auth_opt_aclquery SELECT topic FROM acl WHERE name = '%s' AND access = %d\n",
                    services::mysql()
                ),
            ),
            Self::Ldap => (
                "ldap",
                format!(
                    "auth_opt_ldap_uri ldap://127.0.0.1:{}/dc=example,dc=test?cn?sub?(cn=@)\n\
                 auth_opt_binddn cn=admin,dc=example,dc=test\nauth_opt_bindpw fixture\n",
                    services::ldap()
                ),
            ),
        }
    }
}

fn redis_options(port: u16) -> String {
    format!(
        "auth_opt_redis_host 127.0.0.1\nauth_opt_redis_port {port}\nauth_opt_redis_aclquery GET acl:%s:%s\n"
    )
}

scenario!(files, |target| backend(target, Backend::Files));
scenario!(cdb, |target| backend(target, Backend::Cdb));
scenario!(sqlite, |target| backend(target, Backend::Sqlite));
scenario!(redis, |target| backend(target, Backend::Redis));
scenario!(memcached, |target| backend(target, Backend::Memcached));
scenario!(postgres, |target| backend(target, Backend::Postgres));
scenario!(mysql, |target| backend(target, Backend::Mysql));
scenario!(ldap, |target| backend(target, Backend::Ldap));

fn backend(target: Target, backend: Backend) -> Trace {
    let mut trace = Trace::default();
    let dir = tempfile::tempdir().unwrap();
    let (name, options) = backend.config(&dir);
    for anonymous in [false, true] {
        let conf = config(name, anonymous, &options);
        trace.mqtt(
            target,
            BrokerConfig {
                conf: &conf,
                ..BrokerConfig::default()
            },
            |h| {
                // Empty credentials defer (auth-plug.c: mosquitto_auth_unpwd_check); send
                // anonymous first, before v4 can reuse a stale client-pointer entry.
                let anonymous_client = connect(
                    h,
                    "anonymous",
                    None,
                    if anonymous { Accepted } else { NotAuthorized },
                );
                if anonymous {
                    subscribe(h, anonymous_client, 1, &[("allowed", false)]);
                }
                let alice = connect(h, "alice", ALICE, Accepted);
                connect(h, "wrong", Some(("alice", "wrong")), NotAuthorized);
                connect(h, "unknown", Some(("unknown", SECRET)), NotAuthorized);
                // CDB, SQLite, and LDAP grant any ACL by default; files rules omit SUBSCRIBE.
                let unrestricted =
                    matches!(backend, Backend::Cdb | Backend::Sqlite | Backend::Ldap);
                let allowed = !matches!(backend, Backend::Files);
                subscribe(
                    h,
                    alice,
                    2,
                    &[("allowed", allowed), ("denied", unrestricted)],
                );
                let writer = connect(h, "writer", ALICE, Accepted);
                publish(
                    h,
                    writer,
                    publication("allowed", b"round trip", Q1, 3, false),
                    true,
                );
                if allowed {
                    delivery(h, alice, "allowed", b"round trip", false);
                }
                if matches!(backend, Backend::Memcached) {
                    // be-memcached.c: be_memcached_aclcheck distinguishes zero from a missing key.
                    h.send(
                        alice,
                        &Packet::Publish(publication("missing", b"error", Q1, 4, false)),
                    )
                    .unwrap();
                    assert_eq!(read(h, alice), &Reading::Closed);
                }
                if matches!(backend, Backend::Mysql | Backend::Postgres) {
                    let admin = connect(h, "admin", Some(("db-admin", SECRET)), Accepted);
                    subscribe(h, admin, 1, &[("owned/#", true), ("denied", true)]);
                    // backends.c: t_expand uses the v4 identity, not the real CONNECT id.
                    let owned = "owned/alice/client id not available";
                    publish(h, alice, publication(owned, b"literal", Q1, 5, false), true);
                    delivery(h, admin, owned, b"literal", false);
                    publish(
                        h,
                        alice,
                        publication("owned/alice/alice", b"real id", Q1, 6, false),
                        false,
                    );
                    silent(h, admin);
                }
            },
        );
    }
    trace
}

scenario!(file_patterns_and_fallthrough, patterns);
fn patterns(target: Target) -> Trace {
    let dir = tempfile::tempdir().unwrap();
    let mut trace = Trace::default();
    for deny_special in [true, false] {
        let options = files(
            &dir,
            &["alice", "root-exempt", "bad/name"],
            Some("pattern write owned/%u/%c\n"),
        );
        let conf = config(
            "files",
            true,
            &format!(
                "{options}auth_opt_superusers root-*\nauth_opt_anonusername root-exempt\n\
                 auth_plugin_deny_special_chars {deny_special}\n"
            ),
        );
        trace.mqtt(target, BrokerConfig {
            conf: &conf,
            // auth-plug.c: MOSQ_DENY_ACL aliases PLUGIN_DEFER for the v4 ABI.
            acl: Some("topic readwrite fallback\nuser alice\ntopic readwrite built-in\nuser bad/name\ntopic readwrite built-in\n"),
            ..BrokerConfig::default()
        }, |h| {
            let anon = connect(h, "anonymous", None, Accepted);
            // acl_check.c: acl_file__check permits SUBSCRIBE; its read/write ACL
            // is checked separately when messages are published and delivered.
            subscribe(h, anon, 1, &[("fallback", true), ("owned/#", true)]);
            let anon_writer = connect(h, "anonymous-writer", None, Accepted);
            publish(h, anon_writer, publication("fallback", b"built-in", Q1, 2, false), true);
            delivery(h, anon, "fallback", b"built-in", false);
            let root = connect(h, "observer", Some(("root-exempt", SECRET)), Accepted);
            subscribe(h, root, 1, &[("owned/#", true), ("built-in", true)]);
            let alice = connect(h, "actual-id", ALICE, Accepted);
            publish(h, alice, publication("built-in", b"authenticated fallthrough", Q1, 1, false), true);
            delivery(h, root, "built-in", b"authenticated fallthrough", false);
            let topic = "owned/alice/client id not available";
            // The missing client-table entry defers before anonusername is consulted.
            publish(h, anon_writer, publication(topic, b"not a superuser", Q1, 3, false), false);
            silent(h, root);
            publish(h, alice, publication(topic, b"expanded", Q1, 2, false), true);
            delivery(h, root, topic, b"expanded", false);
            publish(h, alice, publication("owned/alice/actual-id", b"wrong id", Q1, 3, false), false);
            silent(h, root);
            // plugin_acl_check.c: acl__pre_check sees the true id; auth-plug sees the placeholder.
            let special_id = connect(h, "with/slash", ALICE, Accepted);
            publish(h, special_id, publication(topic, b"special id", Q1, 1, false), !deny_special);
            if deny_special {
                silent(h, root);
            } else {
                delivery(h, root, topic, b"special id", false);
            }
            // auth-plug.c: mosquitto_auth_acl_check itself defers a dangerous username.
            let special_user = connect(h, "special-user", Some(("bad/name", SECRET)), Accepted);
            subscribe(h, special_user, 1, &[("subscription-probe", !deny_special)]);
            publish(h, special_user, publication("built-in", b"special user", Q1, 2, false), !deny_special);
            if deny_special {
                silent(h, root);
            } else {
                delivery(h, root, "built-in", b"special user", false);
            }
        });
    }
    trace
}

fn http_options(port: u16, retries: u8) -> String {
    format!(
        "auth_opt_http_ip 127.0.0.1\nauth_opt_http_port {port}\nauth_opt_http_getuser_uri /getuser\n\
         auth_opt_http_superuser_uri /superuser\nauth_opt_http_aclcheck_uri /acl\n\
         auth_opt_http_retry_count {retries}\nauth_opt_acl_cacheseconds 0\n"
    )
}

fn http_response(request: &Request) -> u16 {
    match (request.uri.as_str(), request.param("username")) {
        ("/getuser", "error") => 503,
        ("/getuser", "alice" | "writer") if request.param("password") == SECRET => 204,
        ("/superuser", "writer") => 204,
        ("/acl", "alice") => match (request.param("topic"), request.param("acc")) {
            ("acl%2F%23", "4")
            | ("acl%2Fallow", "1" | "2")
            | ("acl%2Fwrite-only", "2")
            | ("acl%2Fwill-allow", "1" | "2")
            | ("acl%2Fretained-allow", "1") => 204,
            _ => 403,
        },
        _ => 403,
    }
}

scenario!(http_mqtt_and_requests, http_mqtt);
fn http_mqtt(target: Target) -> Trace {
    let mut trace = Trace::default();
    let server = Http::start(http_response);
    for anonymous in [false, true] {
        let conf = config(
            "http",
            anonymous,
            &format!(
                "{}check_retain_source {anonymous}\n",
                http_options(server.port, 1)
            ),
        );
        trace.mqtt(
            target,
            BrokerConfig {
                conf: &conf,
                ..BrokerConfig::default()
            },
            |h| {
                connect(
                    h,
                    "anonymous",
                    None,
                    if anonymous { Accepted } else { NotAuthorized },
                );
                let writer = connect(h, "writer", Some(("writer", SECRET)), Accepted);
                let alice = connect(h, "alice", ALICE, Accepted);
                connect(h, "wrong", Some(("alice", "wrong&+=%")), NotAuthorized);
                connect(h, "unknown", Some(("unknown", SECRET)), NotAuthorized);
                connect_v5(h, "wrong-v5", ("alice", "wrong"), R::NOT_AUTHORIZED);
                let error = open(h, "backend-error", Some(("error", SECRET)), None);
                assert_eq!(read(h, error), &Reading::Closed);
                if anonymous {
                    // retain.c: retain__process rechecks the writer on a synthetic
                    // context. The v4 plugin has no credentials for it and defers.
                    publish(
                        h,
                        writer,
                        publication("acl/retained-allow", b"yes", Q1, 1, true),
                        true,
                    );
                    subscribe(h, alice, 1, &[("acl/#", true)]);
                    silent(h, alice);
                    return;
                }
                subscribe(h, writer, 1, &[("acl/#", true)]);
                subscribe(h, alice, 1, &[("acl/#", true), ("acl/deny-filter", false)]);
                let alice_v5 = connect_v5(h, "alice-v5", ("alice", SECRET), R::SUCCESS);
                subscribe_v5(
                    h,
                    alice_v5,
                    1,
                    &[("acl/#", true), ("acl/deny-filter", false)],
                );
                let publisher = connect(h, "publisher", ALICE, Accepted);
                let publisher_v5 = connect_v5(h, "publisher-v5", ("alice", SECRET), R::SUCCESS);
                for (qos, mid) in [(Q0, 0), (Q1, 2), (Q2, 3)] {
                    publish(
                        h,
                        publisher,
                        publication("acl/denied", b"denied", qos, mid, false),
                        false,
                    );
                    if qos == Q2 {
                        // MQTT 3.1.1 cannot distinguish refusal at PUBREC.
                        // handle_pubrel.c: handle__pubrel completes even without a stored publication.
                        h.send(publisher, &Packet::PubRel(id(mid))).unwrap();
                        receive(h, publisher, Packet::PubComp(id(mid)));
                    }
                    publish(
                        h,
                        publisher,
                        publication(
                            "acl/allow",
                            b"ok",
                            qos,
                            mid + u16::from(mid != 0) * 10,
                            false,
                        ),
                        true,
                    );
                    delivery(h, writer, "acl/allow", b"ok", false);
                    delivery(h, alice, "acl/allow", b"ok", false);
                    alice_v5_delivery(h, alice_v5);
                    publish_v5(h, publisher_v5, "acl/denied", qos, mid, false);
                    publish_v5(
                        h,
                        publisher_v5,
                        "acl/allow",
                        qos,
                        mid + u16::from(mid != 0) * 10,
                        true,
                    );
                    delivery(h, writer, "acl/allow", b"ok", false);
                    delivery(h, alice, "acl/allow", b"ok", false);
                    alice_v5_delivery(h, alice_v5);
                }
                publish(
                    h,
                    publisher,
                    publication("acl/write-only", b"hidden", Q1, 20, false),
                    true,
                );
                delivery(h, writer, "acl/write-only", b"hidden", false);
                silent(h, alice);
                silent(h, alice_v5);
                // v4 UNSUBSCRIBE bypasses the plugin (plugin_acl_check.c: acl__pre_check).
                h.send_v5(
                    alice_v5,
                    &v5::Packet::Unsubscribe(v5::Unsubscribe {
                        packet_id: id(19),
                        properties: Vec::new(),
                        filters: vec!["acl/#".into()],
                    }),
                )
                .unwrap();
                receive_v5(
                    h,
                    alice_v5,
                    v5::Packet::UnsubAck(v5::SubscriptionAck {
                        packet_id: id(19),
                        properties: Vec::new(),
                        reasons: vec![R::SUCCESS],
                    }),
                );
                let retainer = connect(h, "retainer", Some(("writer", SECRET)), Accepted);
                for (topic, payload) in [
                    ("acl/retained-allow", b"yes"),
                    ("acl/retained-deny", b"no!"),
                ] {
                    publish(h, retainer, publication(topic, payload, Q1, 30, true), true);
                    delivery(h, writer, topic, payload, false);
                }
                delivery(h, alice, "acl/retained-allow", b"yes", false);
                let late = connect(h, "replay", ALICE, Accepted);
                subscribe(h, late, 1, &[("acl/#", true)]);
                delivery(h, late, "acl/retained-allow", b"yes", true);
                silent(h, late);
                for (topic, allowed) in [("acl/will-deny", false), ("acl/will-allow", true)] {
                    let c = open(
                        h,
                        if allowed { "will-allow" } else { "will-deny" },
                        ALICE,
                        Some(LastWill {
                            topic: topic.into(),
                            payload: bytes("will"),
                            qos: Q0,
                            retain: false,
                        }),
                    );
                    receive(
                        h,
                        c,
                        Packet::ConnAck(ConnAck {
                            code: Accepted,
                            session_present: false,
                        }),
                    );
                    h.close_socket(c);
                    if allowed {
                        // Every subscriber must be observed: the request trace is
                        // read as soon as this script returns.
                        delivery(h, writer, topic, b"will", false);
                        delivery(h, alice, topic, b"will", false);
                        delivery(h, late, topic, b"will", false);
                    } else {
                        silent(h, writer);
                    }
                }
            },
        );
        trace.http(server);
    }
    assert_http(&trace.http);
    // libcurl sends the MQTT credentials as Basic auth, and escapes the form fields,
    // but leaves the v4 ACL clientid literal unescaped (be-http.c: http_post).
    assert!(trace.http.iter().any(|r| r.uri == "/getuser"
        && r.header("authorization") == "Basic YWxpY2U6c2VjcmV0"
        && r.body == "username=alice&password=secret&topic=&acc=-1&clientid="));
    assert!(
        trace
            .http
            .iter()
            .any(|r| r.param("password") == "wrong%26%2B%3D%25")
    );
    assert!(trace.http.iter().any(|r| r.uri == "/acl"
        && r.body
            == "username=alice&password=&topic=acl%2F%23&acc=4&clientid=client id not available"));
    assert!(!trace.http.iter().any(|r| r.param("acc") == "8"));
    // be-http.c: be_http_getuser uses <= retry_count (one retry is two requests).
    assert_eq!(
        trace
            .http
            .iter()
            .filter(|r| r.uri == "/getuser" && r.param("username") == "error")
            .count(),
        4
    );
    trace
}

#[track_caller]
fn alice_v5_delivery(h: &mut Harness, c: Connection) {
    receive_v5(
        h,
        c,
        v5::Packet::Publish(v5::Publish {
            dup: false,
            retain: false,
            qos: Q0,
            topic: "acl/allow".into(),
            packet_id: None,
            properties: Vec::new(),
            payload: Bytes::from_static(b"ok"),
        }),
    );
}

fn assert_http(requests: &[Request]) {
    assert!(!requests.is_empty());
    for r in requests {
        assert_eq!(r.method, "POST");
        assert_eq!(r.version, "HTTP/1.1");
        assert_eq!(
            r.header("content-type"),
            "application/x-www-form-urlencoded"
        );
    }
}

fn jwt_response(request: &Request) -> u16 {
    match (request.uri.as_str(), request.header("authorization")) {
        ("/getuser", "Bearer down") => 503,
        ("/getuser" | "/acl", "Bearer token%2Bfixture") => 204,
        _ => 403,
    }
}

scenario!(jwt_token_and_opaque_password, jwt);
fn jwt(target: Target) -> Trace {
    let mut trace = Trace::default();
    let server = Http::start(jwt_response);
    for anonymous in [false, true] {
        let conf = config("jwt", anonymous, &http_options(server.port, 9));
        trace.mqtt(
            target,
            BrokerConfig {
                conf: &conf,
                ..BrokerConfig::default()
            },
            |h| {
                connect(
                    h,
                    "anonymous",
                    None,
                    if anonymous { Accepted } else { NotAuthorized },
                );
                connect(h, "empty", Some(("token+fixture", "")), NotAuthorized);
                connect(h, "unknown", Some(("unknown", SECRET)), NotAuthorized);
                let error = open(h, "jwt-error", Some(("down", SECRET)), None);
                assert_eq!(read(h, error), &Reading::Closed);
                // be-jwt.c: be_jwt_getuser uses the username as token and ignores the password.
                // Use back-to-back connections with different nonempty passwords to prove it.
                connect(h, "token", Some(("token+fixture", SECRET)), Accepted);
                connect(
                    h,
                    "token-other-password",
                    Some(("token+fixture", "wrong")),
                    Accepted,
                );
            },
        );
        trace.http(server);
    }
    assert_http(&trace.http);
    assert!(
        trace
            .http
            .iter()
            .all(|r| r.body == "topic=&acc=-1&clientid=")
    );
    assert_eq!(
        trace
            .http
            .iter()
            .filter(|r| r.header("authorization") == "Bearer down")
            .count(),
        2
    );
    assert_eq!(
        trace
            .http
            .iter()
            .filter(|r| r.header("authorization") == "Bearer token%2Bfixture")
            .count(),
        4
    );
    trace
}

scenario!(http_endpoint_unavailable, unavailable);
fn unavailable(target: Target) -> Trace {
    // Keep the port reserved but not listening. connect(2) fails without a DNS or HTTP timeout.
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    let port = socket
        .local_addr()
        .unwrap()
        .as_socket_ipv4()
        .unwrap()
        .port();
    let conf = config("http", false, &http_options(port, 0));
    let mut trace = Trace::default();
    trace.mqtt(
        target,
        BrokerConfig {
            conf: &conf,
            ..BrokerConfig::default()
        },
        |h| {
            // auth-plug.c: mosquitto_auth_unpwd_check passes UNKNOWN on an unrescued backend
            // error; handle_connect.c: handle__connect closes without a CONNACK.
            let client = open(h, "unavailable", ALICE, None);
            assert_eq!(read(h, client), &Reading::Closed);
        },
    );
    trace
}

fn chain_response(request: &Request) -> u16 {
    match (
        request.uri.as_str(),
        request.param("username"),
        request.param("topic"),
        request.param("acc"),
    ) {
        ("/getuser", "alice" | "error", _, _) => 503,
        ("/superuser", "backend-admin", _, _) => 204,
        ("/acl", _, "chain%2Fgranted" | "chain%2Fbroken", _) => 503,
        ("/acl", _, "chain%2Fhttp", "2") => 204,
        _ => 403,
    }
}

scenario!(chain_error_accumulation, chain);
fn chain(target: Target) -> Trace {
    let dir = tempfile::tempdir().unwrap();
    let file = files(
        &dir,
        &["alice", "ordinary", "backend-admin"],
        Some("topic write chain/granted\n"),
    );
    let server = Http::start(chain_response);
    let mut trace = Trace::default();
    let (_, ldap) = Backend::Ldap.config(&dir);
    for backends in ["http,files,ldap", "files,http,ldap"] {
        let options = format!(
            "{file}{ldap}{}auth_opt_ldap_acl_deny true\n",
            http_options(server.port, 0)
        );
        let conf = config(backends, false, &options);
        trace.mqtt(
            target,
            BrokerConfig {
                conf: &conf,
                ..BrokerConfig::default()
            },
            |h| {
                let alice = connect(h, "error-rescued", ALICE, Accepted);
                connect(h, "defer-rescued", Some(("ordinary", SECRET)), Accepted);
                let client = open(h, "error-not-rescued", Some(("alice", "wrong")), None);
                assert_eq!(read(h, client), &Reading::Closed);
                connect(
                    h,
                    "defer-not-rescued",
                    Some(("unknown", SECRET)),
                    NotAuthorized,
                );
                let admin = connect(
                    h,
                    "backend-admin",
                    Some(("backend-admin", SECRET)),
                    Accepted,
                );
                // ACL checks every backend's superuser before ACL checks (auth-plug.c:
                // mosquitto_auth_acl_check), even when files authenticated the client.
                subscribe(h, admin, 1, &[("chain/#", true)]);
                publish(
                    h,
                    alice,
                    publication("chain/granted", b"files", Q1, 2, false),
                    true,
                );
                delivery(h, admin, "chain/granted", b"files", false);
                publish(
                    h,
                    alice,
                    publication("chain/http", b"http", Q1, 3, false),
                    true,
                );
                delivery(h, admin, "chain/http", b"http", false);
                subscribe(h, alice, 1, &[("chain/blocked", false)]);
                h.send(
                    alice,
                    &Packet::Publish(publication("chain/broken", b"error", Q1, 4, false)),
                )
                .unwrap();
                assert_eq!(read(h, alice), &Reading::Closed);
                // A subsequent LDAP DENY does not erase the HTTP error.
                let subscriber = connect(h, "broken-subscribe", ALICE, Accepted);
                h.send(
                    subscriber,
                    &Packet::Subscribe(Subscribe {
                        packet_id: id(1),
                        filters: vec![("chain/broken".into(), Q0)],
                    }),
                )
                .unwrap();
                assert_eq!(read(h, subscriber), &Reading::Closed);
                silent(h, admin);
            },
        );
        trace.http(server);
    }
    assert_http(&trace.http);
    trace
}

scenario!(acl_cache_across_backend_change, cache);
fn cache(target: Target) -> Trace {
    let mut trace = Trace::default();
    let port = services::redis();
    let conf = config(
        "redis",
        false,
        &format!("{}auth_opt_acl_cacheseconds 3\n", redis_options(port)),
    );
    let update = |first, second| {
        services::redis_command(
            port,
            &[
                "MSET",
                "acl:alice:cache/first",
                first,
                "acl:alice:cache/second",
                second,
            ],
        )
    };
    update("4", "0");
    trace.mqtt(
        target,
        BrokerConfig {
            conf: &conf,
            ..BrokerConfig::default()
        },
        |h| {
            let alice = connect(h, "alice", ALICE, Accepted);
            let start = Instant::now();
            subscribe(
                h,
                alice,
                1,
                &[("cache/first", true), ("cache/second", false)],
            );
            update("0", "4");
            // cache.c: acl_cache_q caches negative answers too; now == expiry remains valid.
            subscribe(
                h,
                alice,
                2,
                &[("cache/first", true), ("cache/second", false)],
            );
            thread::sleep(Duration::from_secs(4).saturating_sub(start.elapsed()));
            subscribe(
                h,
                alice,
                3,
                &[("cache/first", false), ("cache/second", true)],
            );
        },
    );
    trace
}
