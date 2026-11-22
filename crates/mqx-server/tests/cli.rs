use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mqextended");

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
    use tokio::{
        net::TcpStream,
        time::{sleep, timeout},
    };
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
        // Wait until the broker accepts connections.
        timeout(Duration::from_secs(5), async {
            while TcpStream::connect(addr).await.is_err() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
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
