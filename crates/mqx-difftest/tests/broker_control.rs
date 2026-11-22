//! Live parity for Mosquitto's test/broker/17-control-*.py scenarios.

#[cfg(unix)]
use std::time::Instant;
use std::{env, fs, net::TcpListener, path::PathBuf, process::Command, time::Duration};

use bytes::Bytes;
use mqx_codec::{PacketId, QoS, v5};
#[cfg(unix)]
use mqx_difftest::ClusterConfig;
use mqx_difftest::{BrokerConfig, BrokerKind, Connection, Harness, Reading};
use serde_json::{Value, json};
use v5::{Packet, ReasonCode as R};

const TOPIC: &str = "$CONTROL/broker/v1";
const RESPONSE: &str = "$CONTROL/broker/v1/response";
const LIST: &[u8] = br#"{"commands":[{"command":"listListeners","correlationData":"listeners"}]}"#;
const CONFIG: &str = "allow_anonymous true\nsys_interval 0\n";
const ENABLED: &str = "enable_control_api true\n";
const DISABLED: &str = "enable_control_api false\n";
const TIMEOUT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(100);

fn reference(var: &str) -> PathBuf {
    PathBuf::from(
        env::var_os(var).unwrap_or_else(|| panic!("set {var} to a Mosquitto 2.1.4 build")),
    )
    .canonicalize()
    .unwrap()
}

fn standalone(kind: BrokerKind, conf: &str) -> Harness {
    Harness::start(
        kind,
        BrokerConfig {
            conf,
            ..BrokerConfig::default()
        },
    )
    .unwrap()
}

fn client(
    harness: &mut Harness,
    node: usize,
    id: &str,
    credentials: Option<(&str, &str)>,
) -> Connection {
    let connection = harness.open_v5_on(node).unwrap();
    harness
        .send_v5(
            connection,
            &Packet::Connect(v5::Connect {
                private_protocol_bit: false,
                clean_start: true,
                keep_alive: 20,
                properties: Vec::new(),
                client_id: id.into(),
                will: None,
                username: credentials.map(|(user, _)| user.into()),
                password: credentials
                    .map(|(_, password)| Bytes::copy_from_slice(password.as_bytes())),
            }),
        )
        .unwrap();
    assert!(
        matches!(packet(harness, connection), Packet::ConnAck(ack) if ack.reason == R::SUCCESS)
    );
    connection
}

fn packet(harness: &mut Harness, connection: Connection) -> &Packet {
    match harness.receive(connection, TIMEOUT).unwrap() {
        Reading::ReceivedV5 { packet, .. } => packet,
        other => panic!("expected MQTT 5 packet, received {other:?}"),
    }
}

fn subscribe(harness: &mut Harness, connection: Connection, filter: &str) {
    let packet_id = PacketId::new(1).unwrap();
    harness
        .send_v5(
            connection,
            &Packet::Subscribe(v5::Subscribe {
                packet_id,
                properties: Vec::new(),
                subscriptions: vec![v5::Subscription {
                    filter: filter.into(),
                    qos: QoS::ExactlyOnce,
                    no_local: false,
                    retain_as_published: false,
                    retain_handling: v5::RetainHandling::SendAlways,
                }],
            }),
        )
        .unwrap();
    assert_eq!(
        packet(harness, connection),
        &Packet::SubAck(v5::SubscriptionAck {
            packet_id,
            properties: Vec::new(),
            reasons: vec![R::GRANTED_QOS_2],
        })
    );
}

fn request(
    harness: &mut Harness,
    connection: Connection,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    reason: R,
) -> PacketId {
    let id = PacketId::new(2).unwrap();
    harness
        .send_v5(
            connection,
            &Packet::Publish(v5::Publish {
                dup: false,
                qos,
                retain: true,
                topic: topic.into(),
                packet_id: (qos != QoS::AtMostOnce).then_some(id),
                // JSON correlationData, not MQTT 5 request/response properties, is used.
                properties: vec![
                    v5::Property::ResponseTopic("wrong-response-topic".into()),
                    v5::Property::CorrelationData(Bytes::from_static(b"unrelated")),
                ],
                payload: Bytes::copy_from_slice(payload),
            }),
        )
        .unwrap();
    let ack = v5::PublishAck {
        packet_id: id,
        reason,
        properties: Vec::new(),
    };
    match qos {
        QoS::AtMostOnce => {}
        QoS::AtLeastOnce => assert_eq!(packet(harness, connection), &Packet::PubAck(ack)),
        QoS::ExactlyOnce => assert_eq!(packet(harness, connection), &Packet::PubRec(ack)),
    }
    id
}

fn payload<'a>(packet: &'a Packet, topic: &str) -> &'a [u8] {
    let Packet::Publish(packet) = packet else {
        panic!("expected PUBLISH, received {packet:?}")
    };
    assert_eq!(packet.topic, topic);
    assert_eq!(packet.qos, QoS::AtMostOnce);
    assert!(!packet.dup && !packet.retain && packet.packet_id.is_none());
    assert!(
        packet.properties.is_empty(),
        "unexpected properties: {:?}",
        packet.properties
    );
    &packet.payload
}

fn response(harness: &mut Harness, connection: Connection, topic: &str) -> Value {
    serde_json::from_slice(payload(packet(harness, connection), topic)).unwrap()
}

fn silent(harness: &mut Harness, connection: Connection) {
    assert_eq!(
        harness.receive(connection, QUIET).unwrap(),
        &Reading::TimedOut
    );
}

fn listeners(expected: Value) -> Value {
    json!({"responses":[{
        "command": "listListeners",
        "data": {"listeners": expected},
        "correlationData": "listeners",
    }]})
}

#[test]
#[ignore = "requires the Mosquitto HTTP/WebSocket build and MQExtended"]
fn listener_inventory_reports_native_transport_fields_in_configuration_order() {
    let reference = reference("MOSQUITTO_HTTP_BUILD_DIR").join("src/mosquitto");
    let cert_dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certfile = cert_dir.path().join("control-test.pem");
    let keyfile = cert_dir.path().join("control-test.key");
    fs::write(&certfile, cert.pem()).unwrap();
    fs::write(&keyfile, signing_key.serialize_pem()).unwrap();
    let sockets = std::array::from_fn::<_, 3, _>(|_| TcpListener::bind("127.0.0.1:0").unwrap());
    let [ws, tls, http] = sockets
        .each_ref()
        .map(|socket| socket.local_addr().unwrap().port());
    drop(sockets);
    let unix = if cfg!(unix) {
        "listener 0 control-test.sock\n"
    } else {
        ""
    };
    let conf = format!(
        "{CONFIG}{ENABLED}listener {ws} 127.0.0.1\nprotocol websockets\n\
         listener {tls} 127.0.0.1\ncertfile {}\nkeyfile {}\n\
         listener {http} 127.0.0.1\nprotocol http_api\ncertfile {}\nkeyfile {}\n{unix}",
        certfile.display(),
        keyfile.display(),
        certfile.display(),
        keyfile.display(),
    );
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        let mut harness = match kind {
            BrokerKind::Mosquitto => Harness::start_with_binary(
                kind,
                &reference,
                BrokerConfig {
                    conf: &conf,
                    ..BrokerConfig::default()
                },
            )
            .unwrap(),
            BrokerKind::MqExtended => standalone(kind, &conf),
        };
        let mut expected = json!([
            {"port":harness.node_addr(1).unwrap().port(),"bind-address":"127.0.0.1","protocol":"mqtt","tls":false},
            {"port":ws,"bind-address":"127.0.0.1","protocol":"mqtt+websockets","tls":false},
            {"port":tls,"bind-address":"127.0.0.1","protocol":"mqtt","tls":true},
            {"port":http,"bind-address":"127.0.0.1","tls":false},
        ]);
        if cfg!(unix) {
            expected.as_array_mut().unwrap().push(json!({
                "port":0,"socket-path":"control-test.sock","protocol":"mqtt","tls":false
            }));
        }
        let writer = client(&mut harness, 1, "inventory", None);
        subscribe(&mut harness, writer, RESPONSE);
        request(
            &mut harness,
            writer,
            TOPIC,
            LIST,
            QoS::AtMostOnce,
            R::SUCCESS,
        );
        assert_eq!(
            response(&mut harness, writer, RESPONSE),
            listeners(expected),
            "{kind:?}"
        );
        let newcomer = client(&mut harness, 1, "no-retain", None);
        subscribe(&mut harness, newcomer, "$CONTROL/broker/#");
        silent(&mut harness, newcomer);
    }
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 and MQExtended"]
fn envelope_errors_correlations_and_qos_match_native_control() {
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        let mut harness = standalone(kind, &format!("{CONFIG}{ENABLED}"));
        let writer = client(&mut harness, 1, "control-writer", None);
        subscribe(&mut harness, writer, "$CONTROL/broker/#");
        for (request_json, expected) in [
            (&b"not valid json"[..], json!([{"command":"Unknown command","error":"Payload not valid JSON"}])),
            (b"{}", json!([{"command":"Unknown command","error":"Invalid/missing commands"}])),
            (br#"{"commands":[]}"#, json!([])),
            (br#"{"commands":[false]}"#, json!([{"command":"Unknown command","error":"Command not an object"}])),
            (br#"{"commands":[{}]}"#, json!([{"command":"Unknown command","error":"Missing command"}])),
            (
                br#"{"Commands":[{"Command":"unknown","CorrelationData":"a"},{"command":"LiStPlUgInS","correlationData":"b"},false,{"command":"listListeners"}]} trailing bytes"#,
                json!([
                    {"command":"unknown","error":"Unknown command","correlationData":"a"},
                    {"command":"listPlugins","data":{"plugins":[]},"correlationData":"b"},
                    {"command":"Unknown command","error":"Command not an object","correlationData":"b"},
                ]),
            ),
            (
                br#"{"commands":[{"command":"listPlugins","correlationData":true},{"command":"listListeners"}]}"#,
                json!([{"command":"listPlugins","error":"Invalid correlationData data type."}]),
            ),
        ] {
            request(&mut harness, writer, TOPIC, request_json, QoS::AtLeastOnce, R::SUCCESS);
            assert_eq!(response(&mut harness, writer, RESPONSE), json!({"responses":expected}), "{kind:?}");
        }
        let mid = request(
            &mut harness,
            writer,
            TOPIC,
            LIST,
            QoS::ExactlyOnce,
            R::SUCCESS,
        );
        assert_eq!(
            response(&mut harness, writer, RESPONSE)["responses"][0]["correlationData"],
            "listeners"
        );
        let ack = v5::PublishAck {
            packet_id: mid,
            reason: R::SUCCESS,
            properties: Vec::new(),
        };
        harness
            .send_v5(writer, &Packet::PubRel(ack.clone()))
            .unwrap();
        assert_eq!(packet(&mut harness, writer), &Packet::PubComp(ack));
        silent(&mut harness, writer);
    }
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 and MQExtended"]
fn request_write_and_broadcast_read_are_checked_independently() {
    let acl = "user writer\ntopic write $CONTROL/broker/v1\nuser observer\ntopic read $CONTROL/broker/v1/response\n";
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        for startup in [ENABLED, DISABLED] {
            let mut harness = Harness::start(
                kind,
                BrokerConfig {
                    conf: &format!("{CONFIG}{startup}"),
                    passwords: &[("writer", "write-only"), ("observer", "read-only")],
                    acl: Some(acl),
                },
            )
            .unwrap();
            let writer = client(
                &mut harness,
                1,
                "control-writer",
                Some(("writer", "write-only")),
            );
            let observer = client(
                &mut harness,
                1,
                "control-observer",
                Some(("observer", "read-only")),
            );
            subscribe(&mut harness, observer, "$CONTROL/broker/#");
            request(
                &mut harness,
                observer,
                TOPIC,
                LIST,
                QoS::AtLeastOnce,
                R::NOT_AUTHORIZED,
            );
            silent(&mut harness, observer);
            if startup == ENABLED {
                subscribe(&mut harness, writer, RESPONSE);
                request(
                    &mut harness,
                    writer,
                    TOPIC,
                    LIST,
                    QoS::AtLeastOnce,
                    R::SUCCESS,
                );
                assert_eq!(
                    response(&mut harness, observer, RESPONSE)["responses"][0]["correlationData"],
                    "listeners"
                );
                silent(&mut harness, writer);
            } else {
                // A direct error has neither a subscription nor a read ACL.
                expect_missing(&mut harness, writer, observer, TOPIC);
            }
        }
    }
}

#[test]
#[ignore = "requires the Mosquitto plugin build and MQExtended"]
fn list_plugins_includes_dynamic_security_without_configuration_or_options() {
    let build = reference("MOSQUITTO_PLUGIN_BUILD_DIR");
    let plugin = build.join(format!(
        "plugins/dynamic-security/mosquitto_dynamic_security.{}",
        if cfg!(windows) { "dll" } else { "so" },
    ));
    assert!(plugin.is_file(), "missing plugin: {}", plugin.display());
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("private-plugin-settings.json");
    let output = Command::new(build.join("apps/mosquitto_ctrl/mosquitto_ctrl"))
        .args([
            "dynsec",
            "init",
            settings.to_str().unwrap(),
            "admin",
            "control-test-secret",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "dynsec init failed: {output:?}");
    // apps/mosquitto_ctrl/dynsec.c: init_create grants only Dynamic Security
    // administration. Control topics never inherit the default ACL grants.
    let mut policy: Value = serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    let admin = policy["roles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|role| role["rolename"] == "admin")
        .unwrap();
    let rights = [
        ("publishClientSend", TOPIC),
        ("subscribeLiteral", RESPONSE),
        ("publishClientReceive", RESPONSE),
    ];
    admin["acls"]
        .as_array_mut()
        .unwrap()
        .extend(rights.map(|(kind, topic)| {
            json!({
                "acltype": kind,
                "topic": topic,
                "allow": true,
                "priority": 0,
            })
        }));
    fs::write(&settings, serde_json::to_vec(&policy).unwrap()).unwrap();
    let conf = format!(
        "{CONFIG}{ENABLED}plugin {}\nplugin_opt_config_file {}\n",
        plugin.display(),
        settings.display(),
    );
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        let mut harness = match kind {
            BrokerKind::Mosquitto => Harness::start_with_binary(
                kind,
                &build.join("src/mosquitto"),
                BrokerConfig {
                    conf: &conf,
                    ..BrokerConfig::default()
                },
            )
            .unwrap(),
            BrokerKind::MqExtended => standalone(kind, &conf),
        };
        let admin = client(
            &mut harness,
            1,
            "plugin-inventory",
            Some(("admin", "control-test-secret")),
        );
        subscribe(&mut harness, admin, RESPONSE);
        request(
            &mut harness,
            admin,
            TOPIC,
            br#"{"commands":[{"command":"listPlugins"}]}"#,
            QoS::AtLeastOnce,
            R::SUCCESS,
        );
        assert_eq!(
            response(&mut harness, admin, RESPONSE),
            json!({"responses":[{
                "command":"listPlugins",
                "data":{"plugins":[{"name":"dynamic-security","control-endpoints":["$CONTROL/dynamic-security/v1"]}]},
            }]}),
            "{kind:?}"
        );
    }
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 with the stock plugins and mqextended"]
fn inventory_includes_file_and_sparkplug_plugins_in_registration_order() {
    let plugins = reference("MOSQUITTO_PLUGIN_BUILD_DIR").join("plugins");
    let settings = tempfile::tempdir().unwrap();
    let acl = settings.path().join("acl");
    fs::write(&acl, "topic readwrite $CONTROL/#\n").unwrap();
    let ext = if cfg!(windows) { "dll" } else { "so" };
    let conf = format!(
        "{CONFIG}{ENABLED}plugin {}/sparkplug-aware/mosquitto_sparkplug_aware.{ext}\n\
         plugin {}/acl-file/mosquitto_acl_file.{ext}\nplugin_opt_acl_file {}\n",
        plugins.display(),
        plugins.display(),
        acl.display()
    );
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        let mut harness = standalone(kind, &conf);
        let admin = client(&mut harness, 1, "inventory", None);
        subscribe(&mut harness, admin, RESPONSE);
        request(
            &mut harness,
            admin,
            TOPIC,
            br#"{"commands":[{"command":"listPlugins"}]}"#,
            QoS::AtLeastOnce,
            R::SUCCESS,
        );
        assert_eq!(
            response(&mut harness, admin, RESPONSE),
            json!({"responses":[{"command":"listPlugins","data":{"plugins":[
                {"name":"sparkplug-aware","version":"1.0","control-endpoints":[]},
                {"name":"acl-file","control-endpoints":[]}
            ]}}]}),
            "{kind:?}"
        );
    }
}

fn expect_missing(harness: &mut Harness, writer: Connection, observer: Connection, topic: &str) {
    request(harness, writer, topic, LIST, QoS::AtLeastOnce, R::SUCCESS);
    assert_eq!(
        response(harness, writer, &format!("{topic}/response")),
        json!({"error":"endpoint not available"})
    );
    silent(harness, observer);
}

#[cfg(unix)]
fn expect_list(harness: &mut Harness, writer: Connection, observer: Connection, node: usize) {
    let port = harness.node_addr(node).unwrap().port();
    request(harness, writer, TOPIC, LIST, QoS::AtLeastOnce, R::SUCCESS);
    let data = response(harness, observer, RESPONSE);
    let entries = data["responses"][0]["data"]["listeners"]
        .as_array()
        .unwrap();
    assert_eq!(
        entries[0],
        json!({"port":port,"protocol":"mqtt","bind-address":"127.0.0.1","tls":false})
    );
    assert_eq!(data["responses"][0]["correlationData"], "listeners");
    silent(harness, writer);
}

#[cfg(unix)]
fn wait_for_reload(harness: &mut Harness, watcher: Connection) {
    let topic = "$SYS/broker/log/M/unsubscribe";
    let marker = "broker-control-reload-marker";
    let deadline = Instant::now() + TIMEOUT;
    // An unsubscribe log proves logging was reconfigured, rather than only
    // proving that the SIGHUP handler started or that the socket stayed open.
    loop {
        harness
            .send_v5(
                watcher,
                &Packet::Unsubscribe(v5::Unsubscribe {
                    packet_id: PacketId::new(3).unwrap(),
                    properties: Vec::new(),
                    filters: vec![marker.into()],
                }),
            )
            .unwrap();
        let mut ack = false;
        let mut log = false;
        loop {
            match harness.receive(watcher, QUIET).unwrap() {
                Reading::ReceivedV5 {
                    packet: Packet::UnsubAck(_),
                    ..
                } => ack = true,
                Reading::ReceivedV5 {
                    packet: Packet::Publish(p),
                    ..
                } if p.topic == topic => {
                    assert!(p.payload.ends_with(marker.as_bytes()));
                    log = true;
                }
                Reading::TimedOut => break,
                other => panic!("unexpected packet during reload: {other:?}"),
            }
            if ack && log {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "node did not reload its logging configuration"
        );
    }
}

#[cfg(unix)]
fn reload_contract(mut harness: Harness, enabled: bool, clustered: bool) {
    let node = if clustered { 2 } else { 1 };
    let writer = client(&mut harness, node, "control-reload-writer", None);
    let observer = client(&mut harness, 1, "control-reload-observer", None);
    subscribe(&mut harness, observer, "$CONTROL/#");
    let watcher = client(&mut harness, node, "control-reload-watcher", None);
    subscribe(&mut harness, watcher, "$SYS/broker/log/M/unsubscribe");
    expect_missing(&mut harness, writer, observer, "$CONTROL/broker/v2");
    let check = |harness: &mut Harness| {
        if enabled {
            expect_list(harness, writer, observer, node);
        } else {
            expect_missing(harness, writer, observer, TOPIC);
        }
    };
    check(&mut harness);
    let changed = if enabled { DISABLED } else { ENABLED };
    harness
        .reload_node(
            node,
            &format!(
                "{CONFIG}{changed}log_dest topic\nlog_type unsubscribe\nlog_timestamp false\n",
            ),
        )
        .unwrap();
    wait_for_reload(&mut harness, watcher);
    harness.close_socket(watcher);
    check(&mut harness);
}

#[cfg(unix)]
#[test]
#[ignore = "requires Mosquitto 2.1.4 and MQExtended"]
fn sighup_keeps_the_startup_registration_on_standalone() {
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        for (startup, enabled) in [("", false), (ENABLED, true)] {
            reload_contract(
                standalone(kind, &format!("{CONFIG}{startup}")),
                enabled,
                false,
            );
        }
    }
}

#[cfg(unix)]
#[test]
#[ignore = "requires MQExtended"]
fn sighup_keeps_node_local_registration_and_inventory_in_a_cluster() {
    for (startup, enabled) in [(DISABLED, false), (ENABLED, true)] {
        let harness = Harness::start_cluster(
            BrokerConfig {
                conf: &format!("{CONFIG}{startup}"),
                ..BrokerConfig::default()
            },
            ClusterConfig::default(),
        )
        .unwrap();
        reload_contract(harness, enabled, true);
    }
}
