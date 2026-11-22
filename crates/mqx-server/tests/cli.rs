use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mqextended");
#[cfg(unix)]
const PERSISTENT_CONNECT: &[u8] = b"\x10\x0f\x00\x04MQTT\x04\x00\x00\x3c\x00\x03dev";

#[cfg(unix)]
async fn connect_and_read_ack(addr: std::net::SocketAddr) -> [u8; 4] {
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::{sleep, timeout},
    };

    timeout(Duration::from_secs(10), async {
        let mut socket = loop {
            match TcpStream::connect(addr).await {
                Ok(socket) => break socket,
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        };
        socket.write_all(PERSISTENT_CONNECT).await.unwrap();
        let mut ack = [0; 4];
        socket.read_exact(&mut ack).await.unwrap();
        ack
    })
    .await
    .unwrap()
}

#[test]
fn help_and_rejected_mosquitto_flags_are_actionable() {
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
        ("-d", "Unsupported Mosquitto option '-d'."),
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
    use tokio::time::timeout;
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
        fs::write(&rules, good).unwrap();
        fs::write(&config, format!("listener {} 127.0.0.1\nallow_anonymous true\n{option} {}\nlog_type information\nlog_dest file {}\nlog_timestamp_format %Y\nconnection_messages false\n", addr.port(), rules.display(), log.display())).unwrap();
        drop(pin);
        let child = tokio::process::Command::new(BIN)
            .arg("-c")
            .arg(&config)
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id().unwrap() as i32);
        // Wait for the signal handlers as well as the TCP bind.
        assert_eq!(connect_and_read_ack(addr).await, [0x20, 2, 0, 0]);
        fs::write(&rules, bad).unwrap();
        kill(pid, Signal::SIGHUP).unwrap();
        let output = timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains(&format!("Security reload failed: Unable to load {option}"))
        );
        let log = fs::read_to_string(&log).unwrap();
        let (timestamp, _) = log.split_once(": Opening ipv4 listen socket").unwrap();
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
    use std::{fs, net::TcpListener, process::Stdio, time::Duration};

    let mqtt = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let raft = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mqtt_addr = mqtt.local_addr().unwrap();
    let raft_addr = raft.local_addr().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broker.conf");
    let storage = directory.path().join("raft state");
    let acl = directory.path().join("acl");
    fs::write(&acl, "topic readwrite a/#\n").unwrap();
    fs::write(
        &path,
        format!(
            "listener {} 127.0.0.1\nallow_anonymous true\nacl_file {}\ncluster_node_id 1\n\
        cluster_bind {raft_addr}\ncluster_peer 1 {raft_addr}\ncluster_data_dir {}\n",
            mqtt_addr.port(),
            acl.display(),
            storage.display()
        ),
    )
    .unwrap();
    assert!(!storage.exists());
    drop((mqtt, raft));

    for session_present in [0, 1] {
        let child = tokio::process::Command::new(BIN)
            .arg("-c")
            .arg(&path)
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id().unwrap() as i32);
        assert_eq!(
            connect_and_read_ack(mqtt_addr).await,
            [0x20, 2, session_present, 0]
        );
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
