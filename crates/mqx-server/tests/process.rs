#![cfg(unix)]

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::{Pid, geteuid},
};
use tokio::{
    net::{TcpStream, UnixDatagram},
    process::{Child, Command},
    time::{sleep, timeout},
};

const BIN: &str = env!("CARGO_BIN_EXE_mqextended");
const WAIT: Duration = Duration::from_secs(10);
const RUNNING: &str = "mosquitto version 2.1.4 running";
const TERMINATING: &str = "mosquitto version 2.1.4 terminating";

fn command(binary: impl AsRef<Path>, dir: &Path) -> Command {
    let mut command = Command::new(binary.as_ref());
    command
        .current_dir(dir)
        .env("TOKIO_WORKER_THREADS", "2")
        .env_remove("NOTIFY_SOCKET")
        .env_remove("SNAP_NAME")
        .env_remove("PUID")
        .env_remove("PGID")
        .env_remove("UMASK_SET")
        .env_remove("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS")
        .env_remove("MOSQUITTO_PERSISTENCE_LOCATION")
        .kill_on_drop(true);
    command
}

fn id(child: &Child) -> Pid {
    Pid::from_raw(child.id().unwrap().try_into().unwrap())
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !condition() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the broker did not reach the expected state");
}

async fn stop(child: &mut Child) {
    kill(id(child), Signal::SIGTERM).unwrap();
    let status = timeout(WAIT, child.wait()).await.unwrap().unwrap();
    assert!(status.success(), "broker exited with {status}");
}

async fn ready(socket: &UnixDatagram) {
    let mut packet = [0; 32];
    let size = timeout(WAIT, socket.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..size], b"READY=1");
}

fn listen_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(address: SocketAddr) -> String {
    format!(
        "user root\nlistener {} 127.0.0.1\nallow_anonymous true\nsys_interval 0\n",
        address.port()
    )
}

#[tokio::test]
async fn ready_follows_pid_file_and_listeners_and_no_stopping_packet_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let address = listen_address();
    let pid_file = dir.path().join("broker.pid");
    let path = dir.path().join("broker.conf");
    fs::write(
        &path,
        format!(
            "{}pid_file broker.pid\nlog_dest stdout\nlog_type all\n",
            config(address)
        ),
    )
    .unwrap();
    let mut child = command(BIN, dir.path())
        .args(["-q", "-v", "-c", "broker.conf"])
        .env("UMASK_SET", "0027")
        .env("NOTIFY_SOCKET", &notify_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready(&notify).await;
    assert_eq!(
        fs::read_to_string(&pid_file).unwrap(),
        id(&child).to_string()
    );
    assert_eq!(
        fs::metadata(&pid_file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    drop(TcpStream::connect(address).await.unwrap());
    stop(&mut child).await;
    assert!(!pid_file.exists());
    assert!(
        matches!(notify.try_recv(&mut [0; 32]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    let output = child.wait_with_output().await.unwrap();
    assert!(
        output.stdout.is_empty(),
        "-q must override both -v and log_type all"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Info: running mosquitto as user"));
    assert!(!stderr.contains(RUNNING));
    assert!(!stderr.contains(TERMINATING));
}

#[tokio::test]
async fn daemon_child_detaches_redirects_descriptors_and_keeps_cwd_and_umask() {
    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let address = listen_address();
    let pid_file = dir.path().join("broker.pid");
    let log_file = dir.path().join("broker.log");
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "{}pid_file broker.pid\nlog_dest stdout\nlog_dest stderr\nlog_dest file broker.log\n",
            config(address)
        ),
    )
    .unwrap();
    let parent = command(BIN, dir.path())
        .args(["--daemon", "-c", "broker.conf"])
        .env("UMASK_SET", "0077")
        .env("NOTIFY_SOCKET", &notify_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let parent_id = id(&parent);
    let output = timeout(WAIT, parent.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(RUNNING));
    ready(&notify).await;
    let pid = Pid::from_raw(fs::read_to_string(&pid_file).unwrap().parse().unwrap());
    struct StopDaemon(Pid);
    impl Drop for StopDaemon {
        fn drop(&mut self) {
            let _ = kill(self.0, Signal::SIGTERM);
        }
    }
    let guard = StopDaemon(pid);
    assert_ne!(parent_id, pid);
    assert_eq!(nix::unistd::getsid(Some(pid)).unwrap(), pid);
    assert_eq!(
        fs::metadata(&pid_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(fs::read_to_string(&log_file).unwrap().contains(RUNNING));
    drop(TcpStream::connect(address).await.unwrap());
    drop(guard);
    eventually(|| !pid_file.exists()).await;
    assert!(fs::read_to_string(&log_file).unwrap().contains(TERMINATING));
}

#[tokio::test]
async fn invalid_umask_and_pid_file_fail_before_logging_or_listeners() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "{}pid_file missing/broker.pid\nlog_dest none\nlog_timestamp false\n",
            config(listen_address())
        ),
    )
    .unwrap();
    for (mask, code, diagnostic) in [
        (
            "8",
            3,
            "Error: UMASK_SET environment variable not a valid octal number.",
        ),
        (
            "01000",
            3,
            "Error: UMASK_SET environment variable out of range.",
        ),
        ("022", 14, "Error: Unable to write pid file."),
    ] {
        let output = command(BIN, dir.path())
            .args(["-c", "broker.conf"])
            .env("UMASK_SET", mask)
            .output()
            .await
            .unwrap();
        assert_eq!(output.status.code(), Some(code));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .ends_with(&format!("{diagnostic}\n{TERMINATING}\n"))
        );
    }
}

#[tokio::test]
async fn config_check_does_not_daemonize_or_create_pid_and_log_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("broker.conf"),
        "pid_file broker.pid\nlog_dest file broker.log\nlog_timestamp false\n",
    )
    .unwrap();
    let output = command(BIN, dir.path())
        .args(["-d", "-c", "broker.conf", "--test-config"])
        .env("UMASK_SET", "invalid-but-ignored")
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("Configuration file is OK.\n{TERMINATING}\n")
    );
    assert!(!dir.path().join("broker.pid").exists());
    assert!(!dir.path().join("broker.log").exists());
}

#[tokio::test]
async fn logger_reloads_destinations_and_connection_notices() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broker.conf");
    let first_log = dir.path().join("before.log");
    let second_log = dir.path().join("after.log");
    let removed_log = dir.path().join("rotated.log");
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let address = listen_address();
    let base = config(address);
    fs::write(&path, format!("{base}log_dest file before.log\nlog_type information\nlog_type notice\nlog_timestamp false\nconnection_messages false\n")).unwrap();
    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", &notify_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    ready(&notify).await;
    let connect = || async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03dev")
            .await
            .unwrap();
        let mut ack = [0; 4];
        timeout(WAIT, stream.read_exact(&mut ack))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack, [0x20, 2, 0, 0]);
        stream
    };
    drop(connect().await);
    assert!(
        !fs::read_to_string(&first_log)
            .unwrap()
            .contains("New connection")
    );
    #[cfg(target_os = "linux")]
    {
        fs::rename(&first_log, &removed_log).unwrap();
        assert!(
            Command::new("kill")
                .args([
                    format!("-{}", nix::libc::SIGRTMIN()),
                    id(&child).to_string(),
                ])
                .status()
                .await
                .unwrap()
                .success()
        );
        eventually(|| first_log.exists()).await;
        assert!(fs::read_to_string(&removed_log).unwrap().contains(RUNNING));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = removed_log;
    fs::write(
        &path,
        format!(
            "{base}log_dest file after.log\nlog_timestamp_format %Y\nconnection_messages true\n"
        ),
    )
    .unwrap();
    kill(id(&child), Signal::SIGHUP).unwrap();
    eventually(|| second_log.exists()).await;
    assert!(
        fs::read_to_string(&first_log)
            .unwrap()
            .ends_with("Reloading config.\n")
    );
    let mut stream = connect().await;
    stream
        .write_all(b"\x82\x08\x00\x01\x00\x03a/#\x01")
        .await
        .unwrap();
    let mut ack = [0; 5];
    timeout(WAIT, stream.read_exact(&mut ack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack, [0x90, 3, 0, 1, 1]);
    kill(id(&child), Signal::SIGUSR1).unwrap();
    kill(id(&child), Signal::SIGUSR2).unwrap();
    let mut stdout = child.stdout.take().unwrap();
    const TREE: &[u8] = b"    \n      a\n        # (dev, 1)\n    $SYS\n    \n";
    let mut tree = [0; TREE.len()];
    timeout(WAIT, stdout.read_exact(&mut tree))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&tree, TREE);
    stop(&mut child).await;
    let log = fs::read_to_string(&second_log).unwrap();
    let (stamp, _) = log.lines().next().unwrap().split_once(": ").unwrap();
    assert_eq!(stamp.len(), 4);
    assert!(stamp.bytes().all(|b| b.is_ascii_digit()));
    assert!(log.contains(": New connection from "));
    assert!(log.ends_with(&format!(": {TERMINATING}\n")));
}

#[tokio::test]
async fn root_only_identity_mapping_and_privilege_drop_order() {
    use nix::unistd::{Uid, User, chown};

    if !geteuid().is_root() {
        eprintln!("root-only process checks require effective UID 0");
        return;
    }
    let nobody = User::from_name("nobody")
        .unwrap()
        .expect("a nobody account is required");
    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    fs::set_permissions(&notify_path, fs::Permissions::from_mode(0o666)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let owned = dir.path().join("owned");
    fs::create_dir(&owned).unwrap();
    let uid = (60000..=65000)
        .map(Uid::from_raw)
        .find(|&uid| User::from_uid(uid).unwrap().is_none())
        .unwrap();
    let gid = nobody.gid;
    chown(&owned, Some(uid), Some(gid)).unwrap();
    let path = dir.path().join("broker.conf");
    let pid = owned.join("broker.pid");
    fs::write(
        &path,
        format!(
            "{}user absent-account\npid_file owned/broker.pid\nlog_timestamp false\n",
            config(listen_address())
        ),
    )
    .unwrap();
    for (puid, pgid, error) in [
        ("baduid", "badgid", "Error: PGID not a valid ID 'badgid'"),
        ("-1", "0", "Error: PUID must not be negative"),
    ] {
        let output = command(BIN, dir.path())
            .args(["-c", "broker.conf"])
            .env("PUID", puid)
            .env("PGID", pgid)
            .output()
            .await
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(String::from_utf8_lossy(&output.stderr).contains(error));
        assert!(!pid.exists());
    }
    let output = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .output()
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "Unable to drop privileges to 'absent-account' because this user does not exist."
    ));

    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("PUID", uid.to_string())
        .env("PGID", gid.to_string())
        .env("NOTIFY_SOCKET", &notify_path)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready(&notify).await;
    let metadata = fs::metadata(&pid).unwrap();
    assert_eq!(
        (metadata.uid(), metadata.gid()),
        (uid.as_raw(), gid.as_raw())
    );
    stop(&mut child).await;
    let output = child.wait_with_output().await.unwrap();
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .starts_with(&format!("Info: running mosquitto as user id: {uid}.\n"))
    );

    let mut snap = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("SNAP_NAME", "mosquitto")
        .env("PUID", "invalid-but-ignored")
        .env("NOTIFY_SOCKET", &notify_path)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready(&notify).await;
    assert_eq!(fs::metadata(&pid).unwrap().uid(), 0);
    stop(&mut snap).await;
    let output = snap.wait_with_output().await.unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Info: running mosquitto as user"));

    fs::write(dir.path().join("passwords"), "").unwrap();
    fs::set_permissions(
        dir.path().join("passwords"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(
        &path,
        format!(
            "{}user nobody\npassword_file passwords\nlog_timestamp false\n",
            config(listen_address())
        ),
    )
    .unwrap();
    let output = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .output()
        .await
        .unwrap();
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("Info: running mosquitto as user: nobody.\n"));
    assert!(!stderr.contains("Opening ipv4 listen socket"));
}

fn reference(var: &str) -> PathBuf {
    PathBuf::from(
        std::env::var_os(var)
            .unwrap_or_else(|| panic!("set {var} to the Mosquitto 2.1.4 build directory")),
    )
    .join("src/mosquitto")
    .canonicalize()
    .unwrap()
}

async fn lifecycle_logs(binary: &Path, dir: &Path, args: &[&str]) -> Vec<String> {
    let log_path = dir.join("capture.log");
    let mut child = command(binary, dir)
        .args(args)
        .stderr(Stdio::from(fs::File::create(&log_path).unwrap()))
        .spawn()
        .unwrap();
    let wait_line = |line: &'static str| {
        let path = &log_path;
        async move { eventually(|| fs::read_to_string(path).unwrap().contains(line)).await }
    };
    wait_line(RUNNING).await;
    kill(id(&child), Signal::SIGHUP).unwrap();
    wait_line("Reloading config.").await;
    stop(&mut child).await;
    fs::read_to_string(log_path)
        .unwrap()
        .lines()
        .map(|line| {
            let (timestamp, message) = line.split_once(": ").expect("timestamp separator");
            assert!(
                timestamp.bytes().all(|b| b.is_ascii_digit()) && timestamp.len() >= 10,
                "{line}"
            );
            message.to_owned()
        })
        .collect()
}

fn compare_build_features(mut mqx: Vec<String>, reference: Vec<String>) {
    // Reference builds can select a different feature set. Check what we report
    // first and normalize only the compile-time capabilities that can differ.
    for (ours, alternate) in [
        (
            "TLS-PSK support NOT available.",
            "TLS-PSK support available.",
        ),
        (
            "Websockets support available.",
            "Websockets support NOT available.",
        ),
    ] {
        let line = mqx.iter_mut().find(|line| *line == ours).unwrap();
        if reference.iter().any(|line| line == alternate) {
            *line = alternate.to_owned();
        }
    }
    if mqx.iter().any(|line| line == "Using default config.") {
        assert!(
            mqx.iter()
                .any(|line| line.starts_with("Opening http api listen socket"))
        );
        if !reference
            .iter()
            .any(|line| line.starts_with("Opening http api listen socket"))
        {
            mqx.retain(|line| !line.starts_with("Opening http api listen socket"));
        }
    }
    assert_eq!(mqx, reference);
}

#[tokio::test]
#[ignore = "requires the Mosquitto 2.1.4 reference broker"]
async fn startup_reload_and_shutdown_logs_match_the_reference() {
    let reference = reference("MOSQUITTO_BUILD_DIR");
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "{}listener 0 mqtt.sock\nallow_anonymous true\n",
            config(listen_address())
        ),
    )
    .unwrap();
    let port = listen_address().port().to_string();
    for args in [["-c", "broker.conf"], ["-p", &port]] {
        let upstream = lifecycle_logs(&reference, dir.path(), &args).await;
        let ours = lifecycle_logs(Path::new(BIN), dir.path(), &args).await;
        compare_build_features(ours, upstream);
    }
}

#[tokio::test]
#[ignore = "requires the Mosquitto 2.1.4 reference with built-in websockets"]
async fn built_in_websockets_use_reference_listener_log() {
    let reference = reference("MOSQUITTO_WS_BUILD_DIR");
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("broker.conf"),
        format!("{}protocol websockets\n", config(listen_address())),
    )
    .unwrap();
    let args = ["-c", "broker.conf"];
    let upstream = lifecycle_logs(&reference, dir.path(), &args).await;
    assert!(
        upstream
            .iter()
            .any(|line| line == "Websockets support available.")
    );
    let ours = lifecycle_logs(Path::new(BIN), dir.path(), &args).await;
    compare_build_features(ours, upstream);
}
