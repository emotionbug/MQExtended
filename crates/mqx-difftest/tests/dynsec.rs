//! Dynamic security parity with the Mosquitto 2.1.4 plugin and mosquitto_ctrl.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, Packet, PacketId, ProtocolVersion, QoS, Subscribe,
    SubscribeReturnCode,
};
use mqx_difftest::{
    BrokerConfig, BrokerKind, ClusterConfig, Connection, Harness, Reading, Transcript,
};

const ADMIN: &str = "admin";
const ADMIN_PASSWORD: &str = "dynsec-admin-password";
const USER: &str = "sensor";
const PASSWORD: &str = "dynsec-user-password";
const ROTATED: &str = "dynsec-rotated-password";
const FILTER: &str = "sensors/#";
const RESPONSE: Duration = Duration::from_secs(5);
const CONVERGENCE: Duration = Duration::from_secs(10);

struct Reference {
    build: PathBuf,
    plugin: PathBuf,
}

impl Reference {
    fn new() -> Self {
        let build = PathBuf::from(env::var_os("MOSQUITTO_PLUGIN_BUILD_DIR").expect(
            "set MOSQUITTO_PLUGIN_BUILD_DIR to a Mosquitto 2.1.4 build with the dynsec plugin",
        ));
        let build = build.canonicalize().unwrap_or_else(|err| {
            panic!("MOSQUITTO_PLUGIN_BUILD_DIR ({}): {err}", build.display())
        });
        let file = format!(
            "plugins/dynamic-security/mosquitto_dynamic_security.{}",
            if cfg!(windows) { "dll" } else { "so" }
        );
        let plugin = artifact(build.join(file));
        Self { build, plugin }
    }

    fn broker(&self) -> PathBuf {
        artifact(self.build.join("src/mosquitto"))
    }

    fn ctrl(&self) -> PathBuf {
        artifact(self.build.join("apps/mosquitto_ctrl/mosquitto_ctrl"))
    }

    fn upstream_dir(&self) -> PathBuf {
        let cache = artifact(self.build.join("CMakeCache.txt"));
        let text = fs::read_to_string(&cache).unwrap();
        let root = text
            .lines()
            .find_map(|line| line.strip_prefix("CMAKE_HOME_DIRECTORY:INTERNAL="))
            .unwrap_or_else(|| {
                panic!(
                    "{} does not name the Mosquitto source tree",
                    cache.display()
                )
            });
        Path::new(root).join("test/broker")
    }

    fn config(&self, file: &Path) -> String {
        format!(
            "allow_anonymous false\nplugin {}\nplugin_opt_config_file {}\n",
            self.plugin.display(),
            file.display()
        )
    }
}

fn artifact(path: PathBuf) -> PathBuf {
    assert!(
        path.is_file(),
        "required dynsec artifact missing: {}",
        path.display()
    );
    path
}

fn mqextended() -> PathBuf {
    let path = env::var_os("MQEXTENDED_BIN").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/mqextended"),
        PathBuf::from,
    );
    let path = artifact(path);
    path.canonicalize()
        .unwrap_or_else(|err| panic!("MQEXTENDED_BIN ({}): {err}", path.display()))
}

fn upstream(scenario: &str) {
    let reference = Reference::new();
    let dir = reference.upstream_dir();
    let script = artifact(dir.join(format!("14-dynsec-{scenario}.py")));
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dynsec_upstream.py");
    for (kind, binary) in [
        ("Mosquitto", reference.broker()),
        ("MQExtended", mqextended()),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let output = Command::new("python3")
            .arg(&runner)
            .arg(kind)
            .arg(&binary)
            .arg(&reference.plugin)
            .arg(&script)
            .current_dir(scratch.path())
            .env("BUILD_ROOT", &reference.build)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("MOSQ_USE_VALGRIND")
            .env_remove("MOSQUITTO_DYNSEC_PASSWORD")
            .env_remove("CTEST_RESOURCE_GROUP_0_PORTS")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|err| panic!("could not run {} with python3: {err}", script.display()));
        // Upstream's feature-gated exit code 77 is a failure here, not a skip.
        assert_success(&format!("{kind}: {}", script.display()), &output);
    }
}

macro_rules! upstream_cases {
    ($($name:ident => $case:literal),+ $(,)?) => {
        $(
            #[test]
            #[ignore = "requires the Mosquitto 2.1.4 plugin build and source tree"]
            fn $name() {
                upstream($case);
            }
        )+
    };
}

upstream_cases! {
    upstream_acl => "acl",
    upstream_allow_wildcard => "allow-wildcard",
    upstream_anon_group => "anon-group",
    upstream_auth => "auth",
    upstream_client_invalid => "client-invalid",
    upstream_client => "client",
    upstream_config_init_env => "config-init-env",
    upstream_config_init_file => "config-init-file",
    upstream_config_init_random => "config-init-random",
    upstream_default_access => "default-access",
    upstream_delete_role => "delete-role",
    upstream_disable_client => "disable-client",
    upstream_group_invalid => "group-invalid",
    upstream_group => "group",
    upstream_modify_client => "modify-client",
    upstream_modify_group => "modify-group",
    upstream_modify_role => "modify-role",
    upstream_plugin_invalid => "plugin-invalid",
    upstream_role_invalid => "role-invalid",
    upstream_role => "role",
}

#[track_caller]
fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} exited with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Ctrl {
    binary: PathBuf,
    home: tempfile::TempDir,
}

impl Ctrl {
    fn new(reference: &Reference) -> Self {
        Self {
            binary: reference.ctrl(),
            home: tempfile::tempdir().unwrap(),
        }
    }

    fn run(&self, label: &str, args: &[&str]) -> Output {
        let mut child = Command::new(&self.binary)
            .args(args)
            .env("XDG_CONFIG_HOME", self.home.path())
            .env("HOME", self.home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("could not execute {}: {err}", self.binary.display()));
        // The tool's network loop can block even after its internal deadline.
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                // The child can have exited between try_wait and kill.
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!("mosquitto_ctrl {label} timed out: {output:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_success(label, &output);
        output
    }

    fn init(&self, file: &Path) {
        let output = self.run(
            "dynsec init",
            &[
                "dynsec",
                "init",
                file.to_str().unwrap(),
                ADMIN,
                ADMIN_PASSWORD,
            ],
        );
        assert!(output.stderr.is_empty(), "{output:?}");
        assert!(
            file.is_file(),
            "mosquitto_ctrl did not create {}",
            file.display()
        );
    }

    fn request(&self, h: &Harness, node: usize, command: &[&str]) -> (String, String) {
        let addr = h.node_addr(node).unwrap();
        let port = addr.port().to_string();
        let mut args = vec![
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-u",
            ADMIN,
            "-P",
            ADMIN_PASSWORD,
            "dynsec",
        ];
        args.extend_from_slice(command);
        let output = self.run(&format!("dynsec {} on node {node}", command[0]), &args);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut stderr = String::from_utf8(output.stderr).unwrap();
        let warning = concat!(
            "Warning: You are running mosquitto_ctrl without encryption.\n",
            "This means all of the configuration changes you are making are visible on the network, including passwords.\n\n",
        );
        if stderr.starts_with(warning) {
            drop(stderr.drain(..warning.len()));
        }
        (stdout, stderr)
    }

    #[track_caller]
    fn ok(&self, h: &Harness, node: usize, command: &[&str]) -> String {
        let (stdout, stderr) = self.request(h, node, command);
        assert!(stderr.is_empty(), "{} on node {node}: {stderr}", command[0]);
        stdout
    }

    #[track_caller]
    fn change(&self, h: &Harness, node: usize, command: &[&str]) {
        let stdout = self.ok(h, node, command);
        assert!(stdout.is_empty(), "{} on node {node}: {stdout}", command[0]);
    }
}

#[track_caller]
fn login(h: &mut Harness, node: usize, password: &'static str) -> (Connection, ConnectReturnCode) {
    login_as(h, node, USER, password)
}

#[track_caller]
fn login_as(
    h: &mut Harness,
    node: usize,
    username: &str,
    password: &'static str,
) -> (Connection, ConnectReturnCode) {
    let c = h.open_on(node, ProtocolVersion::V311).unwrap();
    h.send(
        c,
        &Packet::Connect(Connect {
            protocol: ProtocolVersion::V311,
            is_bridge: false,
            clean_session: true,
            keep_alive: 0,
            client_id: format!("dynsec-{username}-{node}"),
            will: None,
            username: Some(username.into()),
            password: Some(Bytes::from_static(password.as_bytes())),
        }),
    )
    .unwrap();
    match h.receive(c, RESPONSE).unwrap() {
        Reading::Received {
            packet:
                Packet::ConnAck(ConnAck {
                    session_present: false,
                    code,
                }),
            ..
        } => (c, *code),
        reading => panic!("node {node}: expected CONNACK, got {reading:?}"),
    }
}

#[track_caller]
fn require_login(h: &mut Harness, node: usize, password: &'static str) -> Connection {
    let (c, code) = login(h, node, password);
    assert_eq!(code, ConnectReturnCode::Accepted, "node {node}");
    c
}

#[track_caller]
fn require_refused(h: &mut Harness, node: usize, password: &'static str) {
    let (c, code) = login(h, node, password);
    assert_eq!(code, ConnectReturnCode::NotAuthorized, "node {node}");
    h.close_socket(c);
}

#[track_caller]
fn require_subscription(h: &mut Harness, c: Connection, expected: SubscribeReturnCode) {
    let mid = PacketId::new(1).unwrap();
    h.send(
        c,
        &Packet::Subscribe(Subscribe {
            packet_id: mid,
            filters: vec![(FILTER.into(), QoS::AtLeastOnce)],
        }),
    )
    .unwrap();
    match h.receive(c, RESPONSE).unwrap() {
        Reading::Received {
            packet: Packet::SubAck(ack),
            ..
        } => {
            assert_eq!(ack.packet_id, mid);
            assert_eq!(ack.return_codes, [expected], "{c:?}");
        }
        reading => panic!("{c:?}: expected SUBACK, got {reading:?}"),
    }
}

#[track_caller]
fn expect_closed(h: &mut Harness, c: Connection) {
    assert_eq!(
        h.receive(c, CONVERGENCE).unwrap(),
        &Reading::Closed,
        "{c:?}"
    );
    h.close_socket(c);
}

const GRANTED: SubscribeReturnCode = SubscribeReturnCode::Success(QoS::AtLeastOnce);
const DENIED: SubscribeReturnCode = SubscribeReturnCode::Failure;
const CREATE_CLIENT: &[&str] = &["createClient", USER, "-p", PASSWORD];
const CREATE_ROLE: &[&str] = &["createRole", "sensor-reader"];
const ADD_ACL: &[&str] = &[
    "addRoleACL",
    "sensor-reader",
    "subscribePattern",
    FILTER,
    "allow",
    "7",
];
const REMOVE_ACL: &[&str] = &["removeRoleACL", "sensor-reader", "subscribePattern", FILTER];

fn ctrl_workflow(reference: &Reference, kind: BrokerKind) -> (Vec<String>, Transcript) {
    let ctrl = Ctrl::new(reference);
    let file = ctrl.home.path().join("dynamic-security.json");
    ctrl.init(&file);
    let binary = match kind {
        BrokerKind::Mosquitto => reference.broker(),
        BrokerKind::MqExtended => mqextended(),
    };
    let conf = reference.config(&file);
    let mut h = Harness::start_with_binary(
        kind,
        &binary,
        BrokerConfig {
            conf: &conf,
            ..BrokerConfig::default()
        },
    )
    .unwrap();

    require_refused(&mut h, 1, PASSWORD);
    for command in [
        CREATE_CLIENT,
        CREATE_ROLE,
        &["createGroup", "readers"],
        &["addGroupRole", "readers", "sensor-reader", "4"],
        &["addGroupClient", "readers", USER, "2"],
    ] {
        ctrl.change(&h, 1, command);
    }
    let c = require_login(&mut h, 1, PASSWORD);
    require_subscription(&mut h, c, DENIED);
    ctrl.change(&h, 1, ADD_ACL);
    expect_closed(&mut h, c);
    let c = require_login(&mut h, 1, PASSWORD);
    require_subscription(&mut h, c, GRANTED);

    let clients = ctrl.ok(&h, 1, &["listClients"]);
    let group = ctrl.ok(&h, 1, &["getGroup", "readers"]);
    let role = ctrl.ok(&h, 1, &["getRole", "sensor-reader"]);
    assert_eq!(clients, "admin\nsensor\n");
    assert!(group.contains("sensor-reader (priority: 4)"), "{group}");
    assert!(
        group
            .lines()
            .any(|line| line.split_whitespace().eq(["Clients:", USER])),
        "{group}"
    );
    assert!(
        role.contains(FILTER) && role.contains("priority: 7"),
        "{role}"
    );

    ctrl.change(&h, 1, &["deleteClient", USER]);
    expect_closed(&mut h, c);
    require_refused(&mut h, 1, PASSWORD);
    let (stdout, error) = ctrl.request(&h, 1, &["getClient", USER]);
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(error, "getClient: Error: Client not found.\n");
    (vec![clients, group, role, error], h.into_transcript())
}

#[test]
#[ignore = "requires the Mosquitto 2.1.4 plugin build and mosquitto_ctrl"]
fn mosquitto_ctrl_cross_broker() {
    let reference = Reference::new();
    assert_eq!(
        ctrl_workflow(&reference, BrokerKind::Mosquitto),
        ctrl_workflow(&reference, BrokerKind::MqExtended)
    );
}

// src/plugin_basic_auth.c: mosquitto_basic_auth; src/plugin_acl_check.c:
// mosquitto_acl_check. Global dynsec callbacks run before the built-ins.
#[test]
#[ignore = "requires the Mosquitto 2.1.4 plugin build, mosquitto_ctrl and mosquitto_passwd"]
fn dynamic_security_and_builtin_files_cross_broker() {
    const FILE_USER: &str = "file-only";
    const FILE_PASSWORD: &str = "file-password";

    let reference = Reference::new();
    let passwd = artifact(
        reference
            .build
            .join("apps/mosquitto_passwd/mosquitto_passwd"),
    );
    let mut transcripts = Vec::new();
    for (kind, binary) in [
        (BrokerKind::Mosquitto, reference.broker()),
        (BrokerKind::MqExtended, mqextended()),
    ] {
        let ctrl = Ctrl::new(&reference);
        let file = ctrl.home.path().join("dynamic-security.json");
        ctrl.init(&file);
        let password = ctrl.home.path().join("passwords");
        let acl = ctrl.home.path().join("acl");
        for (mode, user) in [(["-b", "-c"].as_slice(), USER), (&["-b"], FILE_USER)] {
            let output = Command::new(&passwd)
                .args(mode)
                .arg(&password)
                .args([user, FILE_PASSWORD])
                .output()
                .unwrap();
            assert_success("mosquitto_passwd", &output);
        }
        fs::write(
            &acl,
            "user sensor\ntopic readwrite sensors/#\nuser file-only\ntopic readwrite sensors/#\n",
        )
        .unwrap();
        let conf = format!(
            "password_file {}\nacl_file {}\n{}",
            password.display(),
            acl.display(),
            reference.config(&file),
        );
        let mut h = Harness::start_with_binary(
            kind,
            &binary,
            BrokerConfig {
                conf: &conf,
                ..BrokerConfig::default()
            },
        )
        .unwrap();
        for command in [
            CREATE_CLIENT,
            CREATE_ROLE,
            &["addClientRole", USER, "sensor-reader"],
            &[
                "addRoleACL",
                "sensor-reader",
                "subscribePattern",
                FILTER,
                "deny",
            ],
        ] {
            ctrl.change(&h, 1, command);
        }
        require_refused(&mut h, 1, FILE_PASSWORD);
        let sensor = require_login(&mut h, 1, PASSWORD);
        require_subscription(&mut h, sensor, DENIED);

        let (fallback, status) = login_as(&mut h, 1, FILE_USER, FILE_PASSWORD);
        assert_eq!(status, ConnectReturnCode::Accepted);
        require_subscription(&mut h, fallback, GRANTED);
        transcripts.push(h.into_transcript());
    }
    assert_eq!(transcripts[0], transcripts[1]);
}

fn start_cluster(reference: &Reference, ctrl: &Ctrl) -> Harness {
    let init = ctrl.home.path().join("admin-password");
    fs::write(&init, format!("{ADMIN_PASSWORD}\n")).unwrap();
    // Each node starts with its own state file rather than reading another node's writes.
    let conf = format!(
        "{}plugin_opt_password_init_file {}\n",
        reference.config(Path::new("dynamic-security.json")),
        init.display()
    );
    Harness::start_cluster(
        BrokerConfig {
            conf: &conf,
            ..BrokerConfig::default()
        },
        ClusterConfig::default(),
    )
    .unwrap()
}

#[track_caller]
fn wait_for_user(h: &mut Harness, node: usize) -> Connection {
    let deadline = Instant::now() + CONVERGENCE;
    loop {
        let (c, code) = login(h, node, PASSWORD);
        if code == ConnectReturnCode::Accepted {
            return c;
        }
        assert_eq!(code, ConnectReturnCode::NotAuthorized, "node {node}");
        h.close_socket(c);
        assert!(
            Instant::now() < deadline,
            "new client did not propagate to node {node}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires mosquitto_ctrl and three MQExtended nodes"]
fn dynsec_cluster_credential_updates_and_kicks() {
    let reference = Reference::new();
    let ctrl = Ctrl::new(&reference);
    let mut h = start_cluster(&reference, &ctrl);
    let leader = h.wait_for_leader(CONVERGENCE).unwrap();
    let follower = leader % 3 + 1;
    let other = follower % 3 + 1;

    for node in 1..=3 {
        require_refused(&mut h, node, PASSWORD);
    }
    ctrl.change(&h, follower, CREATE_CLIENT);
    let connected = [1, 2, 3].map(|node| wait_for_user(&mut h, node));

    ctrl.change(&h, leader, &["setClientPassword", USER, ROTATED]);
    for c in connected {
        expect_closed(&mut h, c);
    }
    for node in 1..=3 {
        require_refused(&mut h, node, PASSWORD);
    }
    let connected = [1, 2, 3].map(|node| require_login(&mut h, node, ROTATED));

    ctrl.change(&h, other, &["disableClient", USER]);
    for c in connected {
        expect_closed(&mut h, c);
    }
    for node in 1..=3 {
        require_refused(&mut h, node, ROTATED);
    }
}

#[test]
#[ignore = "requires mosquitto_ctrl and three MQExtended nodes"]
fn dynsec_cluster_acl_updates_reach_live_and_rejoining_nodes() {
    let reference = Reference::new();
    let ctrl = Ctrl::new(&reference);
    let mut h = start_cluster(&reference, &ctrl);
    let leader = h.wait_for_leader(CONVERGENCE).unwrap();
    let follower = leader % 3 + 1;
    let rejoining = follower % 3 + 1;

    for command in [
        CREATE_CLIENT,
        CREATE_ROLE,
        &["addClientRole", USER, "sensor-reader"],
    ] {
        ctrl.change(&h, follower, command);
    }
    let connected = [1, 2, 3].map(|node| {
        let c = wait_for_user(&mut h, node);
        require_subscription(&mut h, c, DENIED);
        c
    });
    ctrl.change(&h, rejoining, ADD_ACL);
    for c in connected {
        expect_closed(&mut h, c);
    }
    let connected = [1, 2, 3].map(|node| {
        let c = require_login(&mut h, node, PASSWORD);
        require_subscription(&mut h, c, GRANTED);
        c
    });

    h.kill_node(rejoining).unwrap();
    expect_closed(&mut h, connected[rejoining - 1]);
    ctrl.change(&h, leader, REMOVE_ACL);
    for node in [leader, follower] {
        expect_closed(&mut h, connected[node - 1]);
        let c = require_login(&mut h, node, PASSWORD);
        require_subscription(&mut h, c, DENIED);
    }
    h.restart_node(rejoining).unwrap();
    let c = require_login(&mut h, rejoining, PASSWORD);
    require_subscription(&mut h, c, DENIED);
}
