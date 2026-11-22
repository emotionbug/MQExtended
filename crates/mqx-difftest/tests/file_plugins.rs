//! Mosquitto 2.1.4's stock password-file and acl-file shared modules.
#![cfg(unix)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, Packet, PacketId, ProtocolVersion, Publish, QoS, SubAck,
    Subscribe, SubscribeReturnCode,
};
use mqx_difftest::{BrokerConfig, BrokerKind, Connection, Harness, Reading, Transcript};

const RESPONSE: Duration = Duration::from_secs(5);
const QOS: QoS = QoS::AtMostOnce;

#[test]
#[ignore = "requires Mosquitto 2.1.4 built with the password-file and acl-file plugins"]
fn stock_file_plugins_match_connect_acl_and_sighup() {
    let build = PathBuf::from(
        env::var_os("MOSQUITTO_PLUGIN_BUILD_DIR").expect("set MOSQUITTO_PLUGIN_BUILD_DIR"),
    )
    .canonicalize()
    .unwrap();
    let expected = exercise(BrokerKind::Mosquitto, &build);
    let actual = exercise(BrokerKind::MqExtended, &build);
    assert_eq!(expected, actual);
}

fn exercise(kind: BrokerKind, build: &Path) -> Transcript {
    let password_module = build.join("plugins/password-file/mosquitto_password_file.so");
    let acl_module = build.join("plugins/acl-file/mosquitto_acl_file.so");
    for path in [&password_module, &acl_module] {
        assert!(
            path.is_file(),
            "missing reference plugin: {}",
            path.display()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let password = dir.path().join("users.pw");
    let acl = dir.path().join("policy.acl");
    write_password(build, &password, "original");
    fs::write(&acl, "user sensor\ntopic readwrite sensors/one\n").unwrap();
    let config = format!(
        "allow_anonymous true\nauth_plugin {}\nauth_opt_password_file {}\n\
         plugin_load policy {}\nplugin_use policy\nplugin_opt_acl_file {}\n\
         auth_plugin_deny_special_chars true\n",
        password_module.display(),
        password.display(),
        acl_module.display(),
        acl.display(),
    );
    let config = BrokerConfig {
        conf: &config,
        ..BrokerConfig::default()
    };
    let mut h = match kind {
        BrokerKind::Mosquitto => {
            Harness::start_with_binary(kind, &build.join("src/mosquitto"), config)
        }
        BrokerKind::MqExtended => Harness::start(kind, config),
    }
    .unwrap_or_else(|error| panic!("{kind:?}: {error}"));

    let anon = connect(&mut h, "anon", None, None, ConnectReturnCode::Accepted);
    h.close_socket(anon);
    let wrong = connect(
        &mut h,
        "wrong",
        Some("sensor"),
        Some(b"wrong"),
        ConnectReturnCode::NotAuthorized,
    );
    h.close_socket(wrong);
    let unknown = connect(
        &mut h,
        "unknown",
        Some("unknown"),
        Some(b"original"),
        ConnectReturnCode::NotAuthorized,
    );
    h.close_socket(unknown);

    // plugin_acl_check.c does not perform the legacy special character precheck
    // for v5 plugins. acl_file__check itself only guards its pattern rules.
    let live = connect(
        &mut h,
        "sensor/+",
        Some("sensor"),
        Some(b"original"),
        ConnectReturnCode::Accepted,
    );
    exercise_access(&mut h, live, "sensors/one", "sensors/two");

    // The files change, but the paths and attachments from startup do not.
    write_password(build, &password, "rotated");
    fs::write(&acl, "user sensor\ntopic readwrite sensors/two\n").unwrap();
    let reload = format!(
        "allow_anonymous true\nplugin {}\nplugin_opt_password_file nonexistent.pw\n",
        password_module.display(),
    );
    h.reload_node(1, &reload).unwrap();
    assert_eq!(h.receive(live, RESPONSE).unwrap(), &Reading::Closed);
    let old = connect(
        &mut h,
        "old-password",
        Some("sensor"),
        Some(b"original"),
        ConnectReturnCode::NotAuthorized,
    );
    h.close_socket(old);
    let renewed = connect(
        &mut h,
        "sensor/+",
        Some("sensor"),
        Some(b"rotated"),
        ConnectReturnCode::Accepted,
    );
    exercise_access(&mut h, renewed, "sensors/two", "sensors/one");

    // test/broker/23-security-acl-file-reload.py: bad plugin data is fatal.
    fs::write(&acl, "topic readwrite invalid#\n").unwrap();
    h.reload_node(1, &reload).unwrap();
    assert_eq!(h.receive(renewed, RESPONSE).unwrap(), &Reading::Closed);
    let deadline = Instant::now() + RESPONSE;
    loop {
        let log = h.node_log(1).unwrap();
        if log.contains("mosquitto version 2.1.4 terminating") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{kind:?} did not terminate: {log}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    h.into_transcript()
}

fn write_password(build: &Path, path: &Path, password: &str) {
    let mut command = Command::new(build.join("apps/mosquitto_passwd/mosquitto_passwd"));
    command.arg("-b");
    if !path.exists() {
        command.arg("-c");
    }
    let output = command
        .arg(path)
        .args(["sensor", password])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
}

fn connect(
    h: &mut Harness,
    id: &str,
    username: Option<&str>,
    password: Option<&'static [u8]>,
    code: ConnectReturnCode,
) -> Connection {
    let protocol = ProtocolVersion::V311;
    let client = h.open(protocol).unwrap();
    h.send(
        client,
        &Packet::Connect(Connect {
            protocol,
            is_bridge: false,
            clean_session: true,
            keep_alive: 30,
            client_id: id.into(),
            will: None,
            username: username.map(str::to_owned),
            password: password.map(Bytes::from_static),
        }),
    )
    .unwrap();
    receive(
        h,
        client,
        &Packet::ConnAck(ConnAck {
            session_present: false,
            code,
        }),
    );
    client
}

fn exercise_access(h: &mut Harness, client: Connection, allowed: &str, denied: &str) {
    let packet_id = PacketId::new(1).unwrap();
    h.send(
        client,
        &Packet::Subscribe(Subscribe {
            packet_id,
            filters: vec![("sensors/#".into(), QOS)],
        }),
    )
    .unwrap();
    receive(
        h,
        client,
        &Packet::SubAck(SubAck {
            packet_id,
            return_codes: vec![SubscribeReturnCode::Success(QOS)],
        }),
    );
    let publish = |topic: &str| {
        Packet::Publish(Publish {
            dup: false,
            qos: QOS,
            retain: false,
            topic: topic.into(),
            packet_id: None,
            payload: Bytes::from_static(b"data"),
        })
    };
    let allowed = publish(allowed);
    h.send(client, &allowed).unwrap();
    receive(h, client, &allowed);
    h.send(client, &publish(denied)).unwrap();
    h.send(client, &Packet::PingReq).unwrap();
    receive(h, client, &Packet::PingResp);
    assert_eq!(
        h.receive(client, Duration::from_millis(100)).unwrap(),
        &Reading::TimedOut,
    );
}

fn receive(h: &mut Harness, client: Connection, expected: &Packet) {
    match h.receive(client, RESPONSE).unwrap() {
        Reading::Received { packet, .. } => assert_eq!(packet, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}
