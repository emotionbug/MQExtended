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
    unistd::Pid,
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
        .env_remove("WATCHDOG_USEC")
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
async fn occupied_mqtt_listener_uses_the_reference_startup_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    fs::write(
        dir.path().join("broker.conf"),
        config(socket.local_addr().unwrap()),
    )
    .unwrap();
    let output = timeout(
        WAIT,
        command(BIN, dir.path())
            .args(["-c", "broker.conf"])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));

    // listeners.c: listeners__start_single_mqtt also returns 1 when the
    // certificate cannot be loaded or the host does not resolve.
    fs::write(dir.path().join("junk.pem"), "junk\n").unwrap();
    for listener in [
        format!(
            "{}certfile junk.pem\nkeyfile junk.pem\n",
            config(listen_address())
        ),
        "user root\nlistener 1888 no.such.host.invalid\n".to_owned(),
    ] {
        fs::write(dir.path().join("broker.conf"), &listener).unwrap();
        let output = timeout(
            WAIT,
            command(BIN, dir.path())
                .args(["-c", "broker.conf"])
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(output.status.code(), Some(1), "{listener}");
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

#[cfg(target_os = "linux")]
fn assert_process_ids(pid: Pid, uid: nix::unistd::Uid, gid: nix::unistd::Gid) {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    for (field, expected) in [("Uid:", uid.as_raw()), ("Gid:", gid.as_raw())] {
        let ids: Vec<u32> = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap()
            .split_ascii_whitespace()
            .map(|id| id.parse().unwrap())
            .collect();
        // Linux reports real, effective, saved and filesystem IDs in that order.
        assert_eq!(ids, [expected; 4], "process {pid} {field}");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn root_only_identity_mapping_and_privilege_drop_order() {
    use nix::{
        sys::wait::{WaitPidFlag, WaitStatus, waitpid},
        unistd::{Gid, Uid, User, chown, getegid, geteuid, getpid, getsid},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    let Some(opt_in) = std::env::var_os("MQX_ROOT_PROCESS_SMOKE") else {
        return;
    };
    assert_eq!(opt_in, "1");
    assert!(geteuid().is_root(), "the smoke requires effective UID 0");
    assert_eq!(getegid().as_raw(), 0, "the smoke requires effective GID 0");
    // The namespace reaps or kills any detached child, even if it fails before
    // publishing its pid file. Never run this test against the host PID namespace.
    assert_eq!(getpid().as_raw(), 1, "run in a private PID namespace");
    assert_eq!(fs::read_link("/proc/self").unwrap(), Path::new("1"));

    const ABSENT: &str = "mqx-process-test-absent";
    assert!(User::from_name(ABSENT).unwrap().is_none());
    let nobody = User::from_name("nobody")
        .unwrap()
        .expect("no nobody account");
    assert!(!nobody.uid.is_root());
    assert_ne!(nobody.gid.as_raw(), 0);
    let uid = (60000..=65000)
        .map(Uid::from_raw)
        .find(|&uid| User::from_uid(uid).unwrap().is_none())
        .unwrap();
    let gid = nobody.gid;
    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let mode = |path: &Path, mode| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(&notify_path, 0o222);
    mode(dir.path(), 0o711);
    let run = dir.path().join("run");
    fs::create_dir(&run).unwrap();
    mode(&run, 0o700);
    chown(&run, Some(uid), Some(gid)).unwrap();

    // Mosquitto src/mosquitto.c: main parses the config before dropping
    // privileges, then applies the umask, daemonises and opens runtime files.
    let path = dir.path().join("broker.conf");
    let pid_file = run.join("broker.pid");
    let socket_file = run.join("mqtt.sock");
    let log_file = run.join("broker.log");
    let config = "listener 0 run/mqtt.sock\nallow_anonymous true\n\
                  pid_file run/broker.pid\nsys_interval 0\nlog_timestamp false\n";
    fs::write(&path, format!("user {ABSENT}\n{config}")).unwrap();
    mode(&path, 0o600);
    let broker = || {
        let mut cmd = command(BIN, dir.path());
        cmd.args(["-c", "broker.conf"])
            .env("NOTIFY_SOCKET", &notify_path)
            .env("UMASK_SET", "0077");
        cmd
    };
    let no_startup_artifacts = || {
        assert!(!pid_file.exists());
        assert!(!socket_file.exists());
        assert!(matches!(
            notify.try_recv(&mut [0; 32]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    };
    for (puid, pgid, error) in [
        ("baduid", "badgid", "PGID not a valid ID 'badgid'"),
        ("-1", "0", "PUID must not be negative"),
        ("2147483648", "0", "PUID must not be less than 2147483647"),
        ("", "0", "PUID not a valid ID ''"),
    ] {
        // The privilege error must come from the original process, not a
        // forked daemon whose launcher would already have reported success.
        let output = timeout(
            WAIT,
            broker()
                .arg("-d")
                .env("SNAP_NAME", "mosquitto-other")
                .env("PUID", puid)
                .env("PGID", pgid)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(String::from_utf8_lossy(&output.stderr).contains(error));
        no_startup_artifacts();
    }
    let output = timeout(WAIT, broker().output()).await.unwrap().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
        "Unable to drop privileges to '{ABSENT}' because this user does not exist."
    )));
    no_startup_artifacts();

    let (root_uid, root_gid) = (Uid::from_raw(0), Gid::from_raw(0));
    let uid_env = format!(" +{uid}");
    let gid_env = gid.to_string();
    for (puid, pgid, snap, (expected_uid, expected_gid)) in [
        (
            Some(uid_env.as_str()),
            Some(gid_env.as_str()),
            None,
            (uid, gid),
        ),
        (Some(uid_env.as_str()), None, None, (uid, root_gid)),
        (None, Some(gid_env.as_str()), None, (root_uid, gid)),
        (Some("0"), Some("0"), None, (root_uid, root_gid)),
        (
            Some("baduid"),
            Some("badgid"),
            Some("mosquitto"),
            (root_uid, root_gid),
        ),
    ] {
        let mut cmd = broker();
        for (name, value) in [("PUID", puid), ("PGID", pgid), ("SNAP_NAME", snap)] {
            if let Some(value) = value {
                cmd.env(name, value);
            }
        }
        let mut child = cmd.stderr(Stdio::piped()).spawn().unwrap();
        ready(&notify).await;
        assert_process_ids(id(&child), expected_uid, expected_gid);
        let metadata = fs::metadata(&pid_file).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (expected_uid.as_raw(), expected_gid.as_raw())
        );
        drop(UnixStream::connect(&socket_file).await.unwrap());
        stop(&mut child).await;
        no_startup_artifacts();
        let output = child.wait_with_output().await.unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.contains("Warning: Mosquitto should not be run as root/administrator."),
            snap.is_none() && (expected_uid.is_root() || expected_gid == root_gid),
            "{stderr}"
        );
        if snap.is_some() {
            assert!(!stderr.contains("Info: running mosquitto as user"));
        } else if expected_uid == uid {
            assert!(stderr.starts_with(&format!("Info: running mosquitto as user id: {uid}.\n")));
        }
    }

    chown(&run, Some(nobody.uid), Some(gid)).unwrap();
    let passwords = dir.path().join("passwords");
    fs::write(&passwords, "").unwrap();
    mode(&passwords, 0o600);
    fs::write(
        &path,
        format!("user nobody\npassword_file passwords\n{config}"),
    )
    .unwrap();
    let output = timeout(WAIT, broker().output()).await.unwrap().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unable to load password_file 'passwords'"),
        "{stderr}"
    );
    assert!(stderr.contains("Permission denied"), "{stderr}");
    assert!(!stderr.contains("Opening unix listen socket"), "{stderr}");
    no_startup_artifacts();

    // Keep the password file root-owned; only the target group can read it.
    chown(&passwords, None, Some(gid)).unwrap();
    mode(&passwords, 0o640);
    fs::write(
        &path,
        format!(
            "user nobody\npassword_file passwords\n{config}\
             log_dest stdout\nlog_dest stderr\nlog_dest file run/broker.log\n"
        ),
    )
    .unwrap();
    let parent = broker()
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let parent_id = id(&parent);
    let output = timeout(WAIT, parent.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.starts_with("Info: running mosquitto as user: nobody.\n"));
    assert!(output.stdout.is_empty());
    assert!(!stderr.contains(RUNNING), "{stderr}");

    ready(&notify).await;
    let pid = Pid::from_raw(fs::read_to_string(&pid_file).unwrap().parse().unwrap());
    assert!(pid.as_raw() > 1);
    assert_ne!(parent_id, pid);
    assert_eq!(getsid(Some(pid)).unwrap(), pid);
    assert_process_ids(pid, nobody.uid, gid);
    for fd in 0..=2 {
        let target = fs::read_link(format!("/proc/{pid}/fd/{fd}")).unwrap();
        assert_eq!(target, Path::new("/dev/null"), "descriptor {fd}");
    }
    for file in [&pid_file, &log_file] {
        let metadata = fs::metadata(file).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (nobody.uid.as_raw(), gid.as_raw(), 0o600),
            "{}",
            file.display()
        );
    }
    assert!(fs::read_to_string(&log_file).unwrap().contains(RUNNING));
    timeout(WAIT, async {
        let mut stream = UnixStream::connect(&socket_file).await.unwrap();
        stream
            .write_all(b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03dev")
            .await
            .unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"\x20\x02\x00\x00");
    })
    .await
    .expect("the daemon did not answer MQTT CONNECT");
    kill(pid, Signal::SIGTERM).unwrap();
    eventually(|| match waitpid(pid, Some(WaitPidFlag::WNOHANG)).unwrap() {
        WaitStatus::StillAlive => false,
        WaitStatus::Exited(_, 0) => true,
        status => panic!("daemon exited with {status:?}"),
    })
    .await;
    no_startup_artifacts();
    assert!(fs::read_to_string(&log_file).unwrap().contains(TERMINATING));
}

const SAVE_ERROR: &str = "Error during saving in-memory database";

fn persistence_command(dir: &Path, address: SocketAddr, extra: &str) -> Command {
    fs::write(
        dir.join("broker.conf"),
        format!(
            "{}persistence true\nlog_dest file broker.log\nlog_type all\n{extra}\n",
            config(address)
        ),
    )
    .unwrap();
    let mut command = command(BIN, dir);
    command
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", dir.join("notify"));
    command
}

#[tokio::test]
async fn persistence_retries_failed_change_save_without_more_client_traffic() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn exchange<const N: usize>(stream: &mut TcpStream, request: &[u8], response: &[u8; N]) {
        timeout(WAIT, async {
            stream.write_all(request).await.unwrap();
            let mut received = [0; N];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, response);
        })
        .await
        .unwrap();
    }

    const CONNECT: &[u8] = b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03dev";
    const CONNACK: &[u8; 4] = b"\x20\x02\x00\x00";
    let dir = tempfile::tempdir().unwrap();
    let notify = UnixDatagram::bind(dir.path().join("notify")).unwrap();
    let address = listen_address();
    let mut command = persistence_command(
        dir.path(),
        address,
        "autosave_interval 1\nautosave_on_changes true",
    );
    let mut child = command.spawn().unwrap();
    ready(&notify).await;
    let snapshot = dir.path().join("mosquitto.db.mqx");
    let log = dir.path().join("broker.log");
    // A directory blocks atomic replacement even if the test runs as root.
    fs::create_dir(&snapshot).unwrap();
    let mut publisher = TcpStream::connect(address).await.unwrap();
    exchange(&mut publisher, CONNECT, CONNACK).await;
    exchange(
        &mut publisher,
        b"\x33\x0d\x00\x04keep\x00\x01value",
        b"\x40\x02\x00\x01",
    )
    .await;
    eventually(|| fs::read_to_string(&log).unwrap().contains(SAVE_ERROR)).await;
    fs::remove_dir(&snapshot).unwrap();
    eventually(|| snapshot.is_file()).await;

    // Do not let a final backup hide a missed autosave.
    child.kill().await.unwrap();
    let mut child = command.spawn().unwrap();
    ready(&notify).await;
    let mut subscriber = TcpStream::connect(address).await.unwrap();
    exchange(&mut subscriber, CONNECT, CONNACK).await;
    exchange(
        &mut subscriber,
        b"\x82\x09\x00\x01\x00\x04keep\x01",
        b"\x90\x03\x00\x01\x01\x33\x0d\x00\x04keep\x00\x01value",
    )
    .await;
    stop(&mut child).await;
}

#[tokio::test]
async fn persistence_failed_final_save_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let notify = UnixDatagram::bind(dir.path().join("notify")).unwrap();
    let mut child = persistence_command(dir.path(), listen_address(), "autosave_interval 0")
        .spawn()
        .unwrap();
    ready(&notify).await;
    let snapshot = dir.path().join("mosquitto.db.mqx");
    fs::create_dir(&snapshot).unwrap();
    kill(id(&child), Signal::SIGTERM).unwrap();
    let status = timeout(WAIT, child.wait()).await.unwrap().unwrap();
    assert!(matches!(status.code(), Some(code) if code != 0), "{status}");
    let log = fs::read_to_string(dir.path().join("broker.log")).unwrap();
    let (_, after_termination) = log.split_once(TERMINATING).unwrap();
    assert!(after_termination.contains(SAVE_ERROR), "{log}");
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

// A raw CONNECT: protocol level 3 (MQIsdp) or 4, clean session, keepalive 60.
fn raw_connect(level: u8, id: &str, will: Option<&[u8]>, login: Option<(&str, &str)>) -> Vec<u8> {
    let field = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    };
    let mut body = Vec::new();
    field(&mut body, if level == 3 { b"MQIsdp" } else { b"MQTT" });
    let mut flags = 0x02;
    if will.is_some() {
        flags |= 0x04;
    }
    if login.is_some() {
        flags |= 0xc0;
    }
    body.extend_from_slice(&[level, flags, 0, 60]);
    field(&mut body, id.as_bytes());
    if let Some(payload) = will {
        field(&mut body, b"will/topic");
        field(&mut body, payload);
    }
    if let Some((username, password)) = login {
        field(&mut body, username.as_bytes());
        field(&mut body, password.as_bytes());
    }
    let mut packet = vec![0x10, u8::try_from(body.len()).unwrap()];
    packet.extend(body);
    packet
}

// Replace each client's ephemeral port after `127.0.0.1:` with `PORT`.
fn mask_client_ports(log: &str) -> String {
    let mut out = String::with_capacity(log.len());
    let mut rest = log;
    while let Some(at) = rest.find("127.0.0.1:") {
        let (head, tail) = rest.split_at(at + "127.0.0.1:".len());
        out.push_str(head);
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            out.push_str("PORT");
        }
        rest = &tail[digits..];
    }
    out.push_str(rest);
    out
}

// src/handle_connect.c and src/loop.c: do_disconnect. A refused CONNECT is
// logged with its reason, naming the client by address until its id is set.
#[tokio::test]
#[ignore = "requires the Mosquitto 2.1.4 reference broker"]
async fn refused_connect_logs_match_the_reference() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let reference = reference("MOSQUITTO_BUILD_DIR");
    let passwd = reference
        .parent()
        .unwrap()
        .join("../apps/mosquitto_passwd/mosquitto_passwd");
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(passwd)
        .args(["-c", "-b", "passwords", "pfx-user", "secret"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    let address = listen_address();
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "listener {} 127.0.0.1\nallow_anonymous false\npassword_file passwords\n\
             clientid_prefixes pfx-\nallow_zero_length_clientid false\nmessage_size_limit 10\n",
            address.port()
        ),
    )
    .unwrap();
    let login = Some(("pfx-user", "secret"));
    let cases = [
        raw_connect(4, "pfx-badpw", None, Some(("pfx-user", "wrong"))),
        raw_connect(4, "pfx-anon", None, None),
        raw_connect(3, "pfx-anon31", None, None),
        raw_connect(4, "", None, login),
        raw_connect(3, "", None, login),
        raw_connect(4, "other", None, login),
        raw_connect(4, "pfx-will", Some(&[b'x'; 11]), login),
    ];
    let mut transcripts = Vec::new();
    for binary in [reference.as_path(), Path::new(BIN)] {
        let log_path = dir.path().join("refusals.log");
        let mut child = command(binary, dir.path())
            .args(["-c", "broker.conf"])
            .stderr(Stdio::from(fs::File::create(&log_path).unwrap()))
            .spawn()
            .unwrap();
        eventually(|| fs::read_to_string(&log_path).unwrap().contains(RUNNING)).await;
        for packet in &cases {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(packet).await.unwrap();
            let mut rest = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut rest))
                .await
                .unwrap()
                .unwrap();
        }
        stop(&mut child).await;
        let log = mask_client_ports(&fs::read_to_string(&log_path).unwrap());
        transcripts.push(
            log.lines()
                .filter_map(|line| line.split_once(": ").map(|(_, message)| message))
                .filter(|message| {
                    ["New connection", "disconnected:", "Protocol error", "Note:"]
                        .iter()
                        .any(|marker| message.contains(marker))
                })
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(transcripts[1], transcripts[0]);
    assert!(
        transcripts[0]
            .iter()
            .any(|line| line.ends_with("disconnected: oversize payload.")),
        "{:?}",
        transcripts[0]
    );
}

// src/handle_connect.c: connect__on_authorised logs the TLS version and the
// OpenSSL cipher name of every TLS client, whatever connection_messages says.
#[tokio::test]
#[ignore = "requires the Mosquitto 2.1.4 reference broker and clients, and openssl"]
async fn tls_client_negotiation_logs_match_the_reference() {
    let reference = reference("MOSQUITTO_BUILD_DIR");
    let publisher = reference.parent().unwrap().join("../client/mosquitto_pub");
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            "server.key",
            "-out",
            "server.crt",
        ])
        .current_dir(dir.path())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let address = listen_address();
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "listener {} 127.0.0.1\ncertfile server.crt\nkeyfile server.key\n\
             allow_anonymous true\nconnection_messages false\n",
            address.port()
        ),
    )
    .unwrap();
    let mut transcripts = Vec::new();
    for binary in [reference.as_path(), Path::new(BIN)] {
        let log_path = dir.path().join("tls.log");
        let mut child = command(binary, dir.path())
            .args(["-c", "broker.conf"])
            .stderr(Stdio::from(fs::File::create(&log_path).unwrap()))
            .spawn()
            .unwrap();
        eventually(|| fs::read_to_string(&log_path).unwrap().contains(RUNNING)).await;
        for (id, version) in [("tls13", "tlsv1.3"), ("tls12", "tlsv1.2")] {
            let status = Command::new(&publisher)
                .args(["-h", "127.0.0.1", "-p", &address.port().to_string()])
                .args([
                    "--cafile",
                    "server.crt",
                    "--insecure",
                    "--tls-version",
                    version,
                ])
                .args(["-i", id, "-t", "tls/check", "-m", "x"])
                .current_dir(dir.path())
                .status()
                .await
                .unwrap();
            assert!(status.success(), "{binary:?} {version}");
        }
        stop(&mut child).await;
        transcripts.push(
            fs::read_to_string(&log_path)
                .unwrap()
                .lines()
                .filter_map(|line| line.split_once(": ").map(|(_, message)| message))
                .filter(|message| message.contains(" negotiated "))
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(transcripts[0].len(), 2, "{:?}", transcripts[0]);
    assert_eq!(transcripts[1], transcripts[0]);
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

#[tokio::test]
async fn http_listener_inventory_reports_a_unix_listener_by_path() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let address = listen_address();
    let socket = "mqtt\"local\".sock";
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "{}protocol http_api\nlistener 0 {socket}\n",
            config(address)
        ),
    )
    .unwrap();
    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", &notify_path)
        .spawn()
        .unwrap();
    ready(&notify).await;

    let response = timeout(WAIT, async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                b"GET /api/v1/listeners HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap();
    let (header, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(header.starts_with("HTTP/1.1 200 "), "{header}");
    let listeners: serde_json::Value = serde_json::from_str(body).unwrap();
    let listener = &listeners["listeners"][1];
    assert_eq!(listener["path"], socket);
    assert_eq!(listener["protocol"], "mqtt");
    assert!(listener.get("port").is_none());
    stop(&mut child).await;
}

#[tokio::test]
async fn systemd_watchdog_pings_follow_ready_only_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let address = listen_address();
    fs::write(dir.path().join("broker.conf"), config(address)).unwrap();

    // watchdog.c: WATCHDOG_USEC=2000000 gives a one-second half interval.
    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("WATCHDOG_USEC", "2000000")
        .spawn()
        .unwrap();
    ready(&notify).await;
    for _ in 0..3 {
        let mut packet = [0; 32];
        let size = timeout(WAIT, notify.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..size], b"WATCHDOG=1");
    }
    stop(&mut child).await;
    while notify.try_recv(&mut [0; 32]).is_ok() {}

    for watchdog in [None, Some("abc"), Some("1999999")] {
        let mut command = command(BIN, dir.path());
        command
            .args(["-c", "broker.conf"])
            .env("NOTIFY_SOCKET", &notify_path);
        if let Some(watchdog) = watchdog {
            command.env("WATCHDOG_USEC", watchdog);
        }
        let mut child = command.spawn().unwrap();
        ready(&notify).await;
        let mut packet = [0; 32];
        assert!(
            timeout(Duration::from_millis(2500), notify.recv(&mut packet))
                .await
                .is_err(),
            "{watchdog:?}"
        );
        stop(&mut child).await;
    }
}

#[tokio::test]
async fn sighup_applies_reread_listener_settings_to_new_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broker.conf");
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let mounted = listen_address();
    let plain = listen_address();
    let base = format!("{}listener {} 127.0.0.1\n", config(plain), mounted.port());
    fs::write(&path, format!("{base}mount_point a/\n")).unwrap();
    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", &notify_path)
        .spawn()
        .unwrap();
    ready(&notify).await;

    // conf.c: config__read_file_core resets and rereads the listener in place.
    fs::write(
        &path,
        format!("{base}mount_point b/\nlog_dest file reloaded.log\n"),
    )
    .unwrap();
    kill(id(&child), Signal::SIGHUP).unwrap();
    eventually(|| dir.path().join("reloaded.log").exists()).await;

    let connect = async |address, id: &[u8]| {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut packet = vec![0x10, 12 + id.len() as u8, 0, 4];
        packet.extend_from_slice(b"MQTT\x04\x02\x00\x3c\x00");
        packet.push(id.len() as u8);
        packet.extend_from_slice(id);
        stream.write_all(&packet).await.unwrap();
        let mut ack = [0; 4];
        timeout(WAIT, stream.read_exact(&mut ack))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack, [0x20, 2, 0, 0]);
        stream
    };
    let mut observer = connect(plain, b"observer").await;
    observer
        .write_all(b"\x82\x06\x00\x01\x00\x01#\x00")
        .await
        .unwrap();
    let mut suback = [0; 5];
    timeout(WAIT, observer.read_exact(&mut suback))
        .await
        .unwrap()
        .unwrap();
    let mut publisher = connect(mounted, b"publisher").await;
    publisher.write_all(b"\x30\x04\x00\x01xA").await.unwrap();
    let mut publish = [0; 8];
    timeout(WAIT, observer.read_exact(&mut publish))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&publish, b"\x30\x06\x00\x03b/xA");
    stop(&mut child).await;
}

#[tokio::test]
async fn rejected_proxy_headers_log_the_reference_notices() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let v1 = listen_address();
    let v2 = listen_address();
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "{}enable_proxy_protocol 1\nlistener {} 127.0.0.1\nenable_proxy_protocol 2\n\
            proxy_protocol_v2_require_tls true\nlog_dest file broker.log\nconnection_messages false\n",
            config(v1),
            v2.port()
        ),
    )
    .unwrap();
    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", &notify_path)
        .spawn()
        .unwrap();
    ready(&notify).await;

    let refused = async |address, header: &[u8]| {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(header).await.unwrap();
        let mut rest = Vec::new();
        let _ = timeout(WAIT, stream.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty());
    };
    refused(v1, b"PROXY BOGUS\r\n").await;
    // IPv4 192.0.2.7:47568 -> 127.0.0.1:1888 with no SSL TLV.
    let mut v2_header = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c".to_vec();
    v2_header.extend_from_slice(&[192, 0, 2, 7, 127, 0, 0, 1, 0xb9, 0xd0, 0x07, 0x60]);
    refused(v2, &v2_header).await;
    // A truncated TLV after the same addresses.
    let mut corrupt = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0e".to_vec();
    corrupt.extend_from_slice(&v2_header[16..]);
    corrupt.extend_from_slice(&[0x20, 0x00]);
    refused(v2, &corrupt).await;

    let log = dir.path().join("broker.log");
    let expected = [
        "Connection rejected, corrupt PROXY header.",
        "Connection from 192.0.2.7:47568 rejected, client did not connect using TLS.",
        "Connection from 192.0.2.7:47568 rejected, corrupt PROXY header.",
    ];
    eventually(|| {
        let text = fs::read_to_string(&log).unwrap_or_default();
        expected.iter().all(|line| text.contains(line))
    })
    .await;
    stop(&mut child).await;
}

// src/persist_read.c: persist__restore rejects an unrecognised file, then
// src/database.c: db__open fails and src/mosquitto.c: main exits with 1.
#[tokio::test]
async fn corrupt_persistence_database_exits_with_the_reference_status() {
    for file in ["mosquitto.db", "mosquitto.db.mqx"] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(file), b"garbage-not-a-db").unwrap();
        let output = timeout(
            WAIT,
            persistence_command(dir.path(), listen_address(), "")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(output.status.code(), Some(1), "{file}");
        let log = fs::read_to_string(dir.path().join("broker.log")).unwrap();
        assert!(!log.contains(RUNNING), "{file}: {log}");
        // The unreadable file is left for recovery, unlike Mosquitto's final save.
        assert_eq!(
            fs::read(dir.path().join(file)).unwrap(),
            b"garbage-not-a-db"
        );
    }
}

#[tokio::test]
async fn auto_recover_discards_bad_persistence_and_saves_a_fresh_snapshot() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for (file, data, reason) in [
        (
            "mosquitto.db.mqx",
            &b"garbage-not-a-db"[..],
            "unrecognised MQExtended persistence header",
        ),
        (
            "mosquitto.db.mqx",
            &b""[..],
            "persistence database is empty",
        ),
        (
            "mosquitto.db",
            &b"\0\xb5\0mosquitto db\0"[..],
            "failed to fill whole buffer",
        ),
        ("mosquitto.db", &b""[..], "persistence database is empty"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file);
        let discarded = dir.path().join(format!("{file}.discarded"));
        let native = dir.path().join("mosquitto.db.mqx");
        let legacy = dir.path().join("mosquitto.db");
        fs::write(&path, data).unwrap();
        fs::write(&discarded, b"previous discarded database").unwrap();
        if path == native {
            // A failed native restore must not fall back to an older source.
            fs::write(&legacy, b"old import").unwrap();
        }
        let notify = UnixDatagram::bind(dir.path().join("notify")).unwrap();
        let address = listen_address();
        let mut child = persistence_command(
            dir.path(),
            address,
            "autosave_interval 0\nauto_recover true",
        )
        .spawn()
        .unwrap();
        ready(&notify).await;
        assert!(!path.exists(), "{file}");
        assert_eq!(fs::read(&discarded).unwrap(), data, "{file}");
        if path == native {
            assert_eq!(fs::read(&legacy).unwrap(), b"old import");
        }
        timeout(WAIT, async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03dev")
                .await
                .unwrap();
            let mut response = [0; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"\x20\x02\x00\x00");
        })
        .await
        .expect("the recovered broker did not answer MQTT CONNECT");
        stop(&mut child).await;
        assert!(
            mqx_broker::PersistentState::read_snapshot(&native)
                .unwrap()
                .is_some()
        );
        let log = fs::read_to_string(dir.path().join("broker.log")).unwrap();
        assert!(
            log.lines()
                .any(|line| line.contains(file) && line.contains(reason)),
            "{log}"
        );
    }
}

#[tokio::test]
async fn auto_recover_leaves_non_regular_persistence_paths_in_place() {
    use std::os::unix::fs::symlink;

    for file in ["mosquitto.db", "mosquitto.db.mqx"] {
        for is_symlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(file);
            let target = dir.path().join("symlink-target");
            if is_symlink {
                fs::write(&target, b"original target").unwrap();
                symlink(&target, &path).unwrap();
            } else {
                fs::create_dir(&path).unwrap();
            }
            let notify = UnixDatagram::bind(dir.path().join("notify")).unwrap();
            let mut child = persistence_command(
                dir.path(),
                listen_address(),
                "autosave_interval 0\nauto_recover true",
            )
            .env("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS", "1")
            .spawn()
            .unwrap();
            ready(&notify).await;
            stop(&mut child).await;
            if is_symlink {
                assert_eq!(fs::read_link(&path).unwrap(), target);
                assert_eq!(fs::read(&target).unwrap(), b"original target");
            } else {
                assert!(path.is_dir());
            }
            assert!(!dir.path().join(format!("{file}.discarded")).exists());
            if file == "mosquitto.db" {
                assert!(dir.path().join("mosquitto.db.mqx").is_file());
            }
            let log = fs::read_to_string(dir.path().join("broker.log")).unwrap();
            assert_eq!(
                log.matches("Persistence writes disabled for").count(),
                1,
                "{log}"
            );
        }
    }
}

#[tokio::test]
async fn occupied_listener_exits_nonzero_and_a_restart_can_bind_it() {
    let dir = tempfile::tempdir().unwrap();
    let notify = UnixDatagram::bind(dir.path().join("notify")).unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let mut command = persistence_command(dir.path(), address, "auto_recover true");
    let status = timeout(WAIT, command.status()).await.unwrap().unwrap();
    assert_eq!(status.code(), Some(1));

    drop(reserved);
    let mut child = command.spawn().unwrap();
    ready(&notify).await;
    drop(TcpStream::connect(address).await.unwrap());
    stop(&mut child).await;
}

// src/proxy_v1.c: proxy_v1__decode keeps the source token as sent;
// src/proxy_v2.c: proxy_v2__read formats binary addresses with inet_ntop.
#[tokio::test]
async fn proxied_peers_are_logged_with_the_reference_address_text() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let notify_path = dir.path().join("notify");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let v1 = listen_address();
    let v2 = listen_address();
    fs::write(
        dir.path().join("broker.conf"),
        format!(
            "{}enable_proxy_protocol 1\nlistener {} 127.0.0.1\nenable_proxy_protocol 2\n\
            log_dest file broker.log\n",
            config(v1),
            v2.port()
        ),
    )
    .unwrap();
    let mut child = command(BIN, dir.path())
        .args(["-c", "broker.conf"])
        .env("NOTIFY_SOCKET", &notify_path)
        .spawn()
        .unwrap();
    ready(&notify).await;

    const CONNECT: &[u8] = b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x03dev";
    let connected = async |address, header: &[u8]| {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&[header, CONNECT].concat()).await.unwrap();
        let mut connack = [0; 4];
        timeout(WAIT, stream.read_exact(&mut connack))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&connack, b"\x20\x02\x00\x00");
        stream.write_all(b"\xe0\x00").await.unwrap();
    };
    connected(v1, b"PROXY TCP6 2001:DB8:0:0:0:0:0:1 ::1 6275 1234\r\n").await;
    // IPv6 ::1.2.3.4 port 6278 -> ::1 port 1234.
    let mut v2_header = b"\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24".to_vec();
    v2_header.extend_from_slice(&[0; 12]);
    v2_header.extend_from_slice(&[1, 2, 3, 4]);
    v2_header.extend_from_slice(&[0; 15]);
    v2_header.extend_from_slice(&[1, 0x18, 0x86, 0x04, 0xd2]);
    connected(v2, &v2_header).await;

    let log = dir.path().join("broker.log");
    let expected = [
        "New client connected from 2001:DB8:0:0:0:0:0:1:6275 as dev (p4, c1, k60).",
        "New client connected from ::1.2.3.4:6278 as dev (p4, c1, k60).",
    ];
    eventually(|| {
        let text = fs::read_to_string(&log).unwrap_or_default();
        expected.iter().all(|line| text.contains(line))
    })
    .await;
    stop(&mut child).await;
}
