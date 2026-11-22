use std::{
    collections::BTreeMap,
    env, fs,
    io::{BufRead as _, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use mqx_difftest::BrokerKind;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
enum Mode {
    Startup,
    Disabled,
    Protected,
    Traffic,
    Tls,
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Response {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

fn request(port: u16, method: &str, path: &str, auth: Option<&str>) -> std::io::Result<Response> {
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    exchange(stream, method, path, auth)
}

fn exchange(
    mut stream: impl Read + Write,
    method: &str,
    path: &str,
    auth: Option<&str>,
) -> std::io::Result<Response> {
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    )?;
    if let Some(auth) = auth {
        write!(stream, "Authorization: Basic {auth}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.flush()?;
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    stream.read_line(&mut line)?;
    let status = line
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        stream.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        let (key, value) = line.split_once(':').unwrap();
        headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
    }
    let mut body = String::new();
    let size = headers
        .get("content-length")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    stream.take(size).read_to_string(&mut body)?;
    assert_eq!(body.len() as u64, size);
    Ok(Response {
        status,
        headers,
        body,
    })
}

fn reference() -> PathBuf {
    let prefix = env::var_os("MOSQUITTO_HTTP_BUILD_DIR")
        .expect("set MOSQUITTO_HTTP_BUILD_DIR to a Mosquitto 2.1.4 build with libmicrohttpd");
    PathBuf::from(prefix).canonicalize().unwrap()
}

fn executable(kind: BrokerKind) -> PathBuf {
    match kind {
        BrokerKind::Mosquitto => reference().join("src/mosquitto"),
        BrokerKind::MqExtended => env::var_os("MQEXTENDED_BIN")
            .map_or_else(
                || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/mqextended"),
                PathBuf::from,
            )
            .canonicalize()
            .unwrap(),
    }
}

fn start(kind: BrokerKind, directory: &Path, config: String) -> Process {
    fs::write(directory.join("mosquitto.conf"), config).unwrap();
    let out = fs::File::create(directory.join("broker.log")).unwrap();
    let child = Command::new(executable(kind))
        .args(["-c", "mosquitto.conf"])
        .current_dir(directory)
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::null())
        .stderr(out)
        .spawn()
        .unwrap();
    Process(child)
}

#[derive(Debug, PartialEq, Eq)]
struct Transcript {
    responses: Vec<(u16, Option<String>, String)>,
    listeners: Option<Value>,
    systree: Option<Value>,
}

fn scenario(kind: BrokerKind, mode: Mode, [mqtt, http]: [u16; 2]) -> Transcript {
    let temp = tempfile::tempdir().unwrap();
    let site = temp.path().join("site");
    fs::create_dir(&site).unwrap();
    fs::create_dir(site.join("sub")).unwrap();
    fs::write(site.join("index.html"), "<html></html>").unwrap();
    fs::write(site.join("sub/index.html"), "sub-index").unwrap();
    let neighbor = temp.path().join("site-unserved");
    fs::create_dir(&neighbor).unwrap();
    fs::write(neighbor.join("test.txt"), "not public").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&neighbor, site.join("escape")).unwrap();
    let interval = match mode {
        Mode::Disabled => 0,
        Mode::Traffic => 1,
        Mode::Startup | Mode::Protected | Mode::Tls => 65535,
    };
    let mut conf = format!(
        "allow_anonymous true\nsys_interval {interval}\nlistener {mqtt} 127.0.0.1\nlistener {http} 127.0.0.1\nprotocol http_api\nhttp_dir {}\n",
        site.display()
    );
    if matches!(mode, Mode::Protected) {
        let status = Command::new(reference().join("apps/mosquitto_passwd/mosquitto_passwd"))
            .args(["-b", "-c", "passwords", "user", "password"])
            .current_dir(temp.path())
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(
            temp.path().join("acl"),
            "user user\ntopic read /api/v1/version\n",
        )
        .unwrap();
        conf.push_str("listener_allow_anonymous false\npassword_file passwords\nacl_file acl\n");
    }
    let client_tls = matches!(mode, Mode::Tls).then(|| {
        conf.push_str("certfile broker.pem\nkeyfile broker.key\nrequire_certificate true\n");
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(temp.path().join("broker.pem"), cert.pem()).unwrap();
        fs::write(temp.path().join("broker.key"), signing_key.serialize_pem()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    });
    let mut process = start(kind, temp.path(), conf);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", http)).is_ok() {
            break;
        }
        assert!(
            process.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "{kind:?} HTTP startup failed: {}",
            fs::read_to_string(temp.path().join("broker.log")).unwrap()
        );
        thread::sleep(Duration::from_millis(10));
    }
    if matches!(mode, Mode::Traffic) {
        return traffic(mqtt, http);
    }
    let send = |method, path, auth| {
        if let Some(config) = &client_tls {
            let stream = TcpStream::connect(("127.0.0.1", http)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let client =
                ClientConnection::new(config.clone(), "localhost".try_into().unwrap()).unwrap();
            exchange(StreamOwned::new(client, stream), method, path, auth).unwrap()
        } else {
            request(http, method, path, auth).unwrap()
        }
    };
    let get = |path| send("GET", path, None);
    let mut responses = Vec::new();
    let mut push = |response: Response, status, body: &str| {
        assert_eq!(response.status, status, "{response:?}");
        assert_eq!(response.body, body);
        let cors = response.headers.get("access-control-allow-origin").cloned();
        assert!(!response.headers.contains_key("content-type"));
        responses.push((status, cors, response.body));
    };
    // src/http_api.c: http_api_handler checks the method first, even when the
    // authorization callback would reject the request.
    push(
        send("POST", "/api/v1/version", None),
        405,
        "Invalid HTTP Method\n",
    );
    if matches!(mode, Mode::Protected) {
        for (path, auth) in [
            ("/api/v1/version", None),
            ("/api/v1/version", Some("dXNlcjppbnZhbGlk")),
            ("/api/v1/systree", Some("dXNlcjpwYXNzd29yZA==")),
            ("/missing", Some("dXNlcjpwYXNzd29yZA==")),
        ] {
            let response = request(http, "GET", path, auth).unwrap();
            let challenge = response.headers["www-authenticate"].to_ascii_lowercase();
            assert!(
                challenge.starts_with("basic realm=\"mosquitto api\""),
                "{challenge}"
            );
            push(response, 401, "Not authorised\n");
        }
        push(
            request(http, "GET", "/api/v1/version", Some("dXNlcjpwYXNzd29yZA==")).unwrap(),
            200,
            "2.1.4",
        );
        return Transcript {
            responses,
            listeners: None,
            systree: None,
        };
    }
    push(get("/api/v1/version"), 200, "2.1.4");
    push(get("/API/v1/version"), 404, "Not found.\n");
    push(get("/api/v1/missing"), 404, "Not found.\n");
    push(get("/missing"), 404, "Not found.\n");
    push(get("/"), 200, "<html></html>");
    push(get("/sub/"), 200, "sub-index");
    push(get("/sub"), 404, "Not found.\n");
    push(get("/%2e%2e/site-unserved/test.txt"), 404, "Not found.\n");
    push(get("/escape/test.txt"), 404, "Not found.\n");

    let listeners = api_json(get("/api/v1/listeners"));
    assert_eq!(
        listeners,
        json!({"listeners": [
            {"port": mqtt, "protocol": "mqtt", "tls": false, "mtls": false, "allow_anonymous": true},
            {"port": http, "protocol": "httpapi", "tls": client_tls.is_some(), "mtls": client_tls.is_some(), "allow_anonymous": true},
        ]})
    );

    let mut systree = loop {
        let tree = api_json(get("/api/v1/systree"));
        // Mosquitto opens the HTTP thread before running sys_tree__init.
        if matches!(mode, Mode::Disabled) || tree["$SYS/broker/clients/total"] == 0 {
            break tree;
        }
        assert!(
            Instant::now() < deadline,
            "initial system sample was never captured"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let metrics = systree.as_object_mut().unwrap();
    for key in ["$SYS/broker/heap/current", "$SYS/broker/heap/maximum"] {
        if let Some(value) = metrics.remove(key) {
            assert!(matches!(kind, BrokerKind::Mosquitto));
            assert!(value.as_u64().unwrap() > 0); // conditional INC_MEMTRACK build
        }
    }
    let uptime = metrics
        .remove("$SYS/broker/uptime")
        .unwrap()
        .as_u64()
        .unwrap();
    if matches!(mode, Mode::Disabled) {
        assert!(uptime > 0);
        assert!(metrics.values().all(|value| value.as_i64() == Some(1)));
    } else {
        assert!(uptime <= 5);
        assert_eq!(metrics["$SYS/broker/messages/stored"], 2);
        let stored_bytes = &mut metrics["$SYS/broker/store/messages/bytes"];
        assert!(matches!(stored_bytes.as_u64().unwrap(), 32 | 51));
        *stored_bytes = json!(32);
        assert_eq!(metrics["$SYS/broker/retained messages/count"], 2);
    }
    assert_eq!(metrics.len(), 22);
    if matches!(kind, BrokerKind::MqExtended) {
        let extension = get("/api/v1/mqx/cluster");
        assert_eq!(extension.status, 200);
        assert_eq!(
            serde_json::from_str::<Value>(&extension.body).unwrap()["mode"],
            "standalone"
        );
        let prometheus = get("/metrics");
        assert_eq!(prometheus.status, 200);
        assert!(prometheus.body.contains("mqx_connections 0\n"));
        assert!(
            prometheus
                .body
                .contains("mqx_raft_proposal_duration_seconds_count 0\n")
        );
    }
    Transcript {
        responses,
        listeners: Some(listeners),
        systree: Some(systree),
    }
}

fn traffic(mqtt: u16, http: u16) -> Transcript {
    let mut mqtt = TcpStream::connect(("127.0.0.1", mqtt)).unwrap();
    mqtt.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut send = |sent: &[u8], expected: &[u8]| {
        mqtt.write_all(sent).unwrap();
        let mut reply = vec![0; expected.len()];
        mqtt.read_exact(&mut reply).unwrap();
        assert_eq!(reply, expected);
    };
    send(b"\x10\x0f\0\x04MQTT\x04\x02\0\0\0\x03sys", b"\x20\x02\0\0");
    send(b"\x82\x08\0\x01\0\x03sta\0", b"\x90\x03\0\x01\0");
    send(b"\x30\x08\0\x03staxyz", b"\x30\x08\0\x03staxyz");
    send(b"\xc0\0", b"\xd0\0");
    let deadline = Instant::now() + Duration::from_secs(5);
    let tree = loop {
        let values = api_json(request(http, "GET", "/api/v1/systree", None).unwrap());
        if values["$SYS/broker/messages/received"] == 4 && values["$SYS/broker/messages/sent"] == 4
        {
            break values;
        }
        assert!(
            Instant::now() < deadline,
            "packet statistics not sampled: {values}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let expected = [
        ("clients/total", 1),
        ("clients/connected", 1),
        ("clients/disconnected", 0),
        ("subscriptions/count", 1),
        ("messages/received", 4),
        ("messages/sent", 4),
        ("bytes/received", 39),
        ("bytes/sent", 21),
        ("publish/bytes/received", 3),
        ("publish/bytes/sent", 3),
        ("packet/out/count", 0),
        ("packet/out/bytes", 0),
        ("connections/socket/count", 1),
        ("publish/messages/dropped", 0),
        ("publish/messages/received", 1),
        ("publish/messages/sent", 1),
    ];
    let mut counters = serde_json::Map::new();
    for (suffix, expected) in expected {
        let topic = format!("$SYS/broker/{suffix}");
        assert_eq!(tree[&topic], expected, "{topic}");
        counters.insert(topic.clone(), tree[topic].clone());
    }
    Transcript {
        responses: Vec::new(),
        listeners: None,
        systree: Some(counters.into()),
    }
}

fn ports<const N: usize>() -> [u16; N] {
    let sockets = std::array::from_fn::<_, N, _>(|_| TcpListener::bind(("127.0.0.1", 0)).unwrap());
    sockets
        .each_ref()
        .map(|socket| socket.local_addr().unwrap().port())
}

fn api_json(response: Response) -> Value {
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.headers["access-control-allow-origin"], "*");
    assert!(!response.headers.contains_key("content-type"));
    serde_json::from_str(&response.body).unwrap()
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 with libmicrohttpd"]
fn http_api_mosquitto_self() {
    for mode in [
        Mode::Startup,
        Mode::Disabled,
        Mode::Protected,
        Mode::Traffic,
        Mode::Tls,
    ] {
        let ports = ports();
        assert_eq!(
            scenario(BrokerKind::Mosquitto, mode, ports),
            scenario(BrokerKind::Mosquitto, mode, ports)
        );
    }
}

#[test]
#[ignore = "requires MQExtended and Mosquitto 2.1.4 with libmicrohttpd"]
fn http_api_cross_broker() {
    for mode in [
        Mode::Startup,
        Mode::Disabled,
        Mode::Protected,
        Mode::Traffic,
        Mode::Tls,
    ] {
        let ports = ports();
        assert_eq!(
            scenario(BrokerKind::Mosquitto, mode, ports),
            scenario(BrokerKind::MqExtended, mode, ports)
        );
    }
}

// src/signals.c: signal__flag_check loads the new file before reapplying
// security to connected clients. Changing the path is not an in-place edit.
#[cfg(unix)]
#[test]
#[ignore = "requires MQExtended and Mosquitto 2.1.4 with libmicrohttpd"]
fn sighup_rotates_credentials_and_revokes_anonymous_sessions() {
    for kind in [BrokerKind::Mosquitto, BrokerKind::MqExtended] {
        let [mqtt, http] = ports();
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        fs::write(dir.join("old"), "").unwrap();
        assert!(
            Command::new(reference().join("apps/mosquitto_passwd/mosquitto_passwd"))
                .args(["-b", "-c", "new", "user", "password"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success()
        );
        let a = format!("listener {mqtt} 127.0.0.1\n");
        let b = format!("listener {http} 127.0.0.1\nprotocol http_api\n");
        let mut process = start(
            kind,
            dir,
            format!("allow_anonymous true\npassword_file old\n{a}{b}"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while request(http, "GET", "/api/v1/version", None).is_err() {
            assert!(Instant::now() < deadline && process.0.try_wait().unwrap().is_none());
            thread::sleep(Duration::from_millis(10));
        }
        let connect = || {
            let mut stream = TcpStream::connect(("127.0.0.1", mqtt)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .write_all(b"\x10\x0f\0\x04MQTT\x04\x02\0\0\0\x03sys")
                .unwrap();
            let mut ack = [0; 4];
            stream.read_exact(&mut ack).unwrap();
            (stream, ack)
        };
        let (mut active, ack) = connect();
        assert_eq!(ack, [0x20, 2, 0, 0]);
        // Keep the HTTP listener open to anonymous monitoring while revoking
        // it on MQTT. File order is deliberately different from bound order.
        let reload = |conf| {
            fs::write(dir.join("mosquitto.conf"), conf).unwrap();
            assert!(
                Command::new("kill")
                    .args(["-HUP", &process.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        };
        reload(format!(
            "allow_anonymous false\npassword_file new\n{b}listener_allow_anonymous true\n{a}"
        ));
        assert_eq!(active.read(&mut [0]).unwrap(), 0, "{kind:?}");
        assert_eq!(connect().1, [0x20, 2, 0, 5]);
        let listeners = api_json(request(http, "GET", "/api/v1/listeners", None).unwrap());
        assert_eq!(listeners["listeners"][0]["allow_anonymous"], false);
        assert_eq!(listeners["listeners"][1]["allow_anonymous"], true);
        reload(format!(
            "allow_anonymous false\npassword_file new\n{a}{b}listener_allow_anonymous false\n"
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while request(http, "GET", "/api/v1/version", None)
            .unwrap()
            .status
            != 401
        {
            assert!(
                Instant::now() < deadline,
                "{kind:?}: HTTP still permits anonymous reads"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            request(http, "GET", "/api/v1/version", Some("dXNlcjpwYXNzd29yZA=="))
                .unwrap()
                .status,
            200
        );
    }
}

#[test]
#[ignore = "requires MQExtended"]
fn cluster_http_reports_members_and_raft_progress() {
    let [m1, m2, m3, h1, h2, h3, r1, r2, r3] = ports();
    let raft = [r1, r2, r3];
    let http = [h1, h2, h3];
    let temp = tempfile::tempdir().unwrap();
    let mut processes = Vec::new();
    for (index, (mqtt, http)) in [m1, m2, m3].into_iter().zip(http).enumerate() {
        let dir = temp.path().join(index.to_string());
        fs::create_dir(&dir).unwrap();
        let local = raft[index];
        let id = index + 1;
        let mut config = format!(
            "allow_anonymous true\nsys_interval 1\nlistener {mqtt} 127.0.0.1\nlistener {http} 127.0.0.1\nprotocol http_api\n\
             cluster_node_id {id}\ncluster_bind 127.0.0.1:{local}\ncluster_data_dir raft\ncluster_insecure_plaintext true\n",
        );
        for (peer, port) in raft.into_iter().enumerate() {
            use std::fmt::Write as _;
            writeln!(config, "cluster_peer {} 127.0.0.1:{port}", peer + 1).unwrap();
        }
        processes.push(start(BrokerKind::MqExtended, &dir, config));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let snapshot = loop {
        let snapshots: Vec<_> = http
            .into_iter()
            .filter_map(|port| request(port, "GET", "/api/v1/mqx/cluster", None).ok())
            .map(|response| {
                assert_eq!(response.status, 200);
                serde_json::from_str::<Value>(&response.body).unwrap()
            })
            .collect();
        if let Some(leader) = snapshots
            .first()
            .and_then(|node| node["raft"]["leader"].as_u64())
            && snapshots.len() == 3
            && snapshots.iter().all(|node| {
                node["raft"]["leader"] == leader
                    && node["membership"]["members"]
                        .as_object()
                        .is_some_and(|members| {
                            members.len() == 3
                                && members.values().all(|member| member["liveness"] == "Alive")
                        })
            })
        {
            break snapshots;
        }
        assert!(
            Instant::now() < deadline,
            "cluster not ready: {snapshots:?}"
        );
        thread::sleep(Duration::from_millis(50));
    };
    for (offset, node) in snapshot.iter().enumerate() {
        assert_eq!(node["mode"], "cluster");
        assert_eq!(node["raft"]["node_id"], offset + 1);
        assert!(node["raft"]["term"].as_u64().unwrap() > 0);
        let commit = node["raft"]["committed_index"].as_u64().unwrap();
        assert!(node["raft"]["applied_index"].as_u64().unwrap() <= commit);
        for (peer, port) in raft.into_iter().enumerate() {
            let member = &node["membership"]["members"][(peer + 1).to_string()];
            assert_eq!(member["address"], format!("127.0.0.1:{port}"));
            assert_eq!(member["role"], "Voter");
        }
    }
    let leader = snapshot[0]["raft"]["leader"].as_u64().unwrap() as usize - 1;
    let mut publisher = TcpStream::connect(("127.0.0.1", [m1, m2, m3][leader])).unwrap();
    publisher
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    publisher
        .write_all(b"\x10\x0f\0\x04MQTT\x04\x02\0\0\0\x03sys")
        .unwrap();
    let mut ack = [0; 4];
    publisher.read_exact(&mut ack).unwrap();
    assert_eq!(ack, *b"\x20\x02\0\0");
    let metrics = request(http[leader], "GET", "/metrics", None).unwrap();
    assert_eq!(metrics.status, 200);
    assert!(
        metrics
            .body
            .lines()
            .any(|line| line.starts_with("mqx_raft_commit_index "))
    );
    assert!(
        metrics
            .body
            .lines()
            .any(|line| line.starts_with("mqx_raft_apply_index "))
    );
    assert!(metrics.body.lines().any(|line| {
        line.strip_prefix("mqx_raft_proposal_duration_seconds_count ")
            .is_some_and(|count| count.parse::<u64>().unwrap() > 0)
    }));
    let readiness = || request(http[leader], "GET", "/api/v1/mqx/ready", None).unwrap();
    assert_eq!(readiness().status, 200);
    for (i, process) in processes.iter_mut().enumerate() {
        if i != leader {
            process.0.kill().unwrap();
            process.0.wait().unwrap();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while readiness().status != 503 {
        assert!(Instant::now() < deadline, "isolated voter remained ready");
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        request(http[leader], "GET", "/api/v1/mqx/cluster", None)
            .unwrap()
            .status,
        200
    );
}
