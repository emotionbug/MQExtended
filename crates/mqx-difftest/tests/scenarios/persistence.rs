use std::{fs, path::Path, thread, time::Instant};

use super::sessions::persistent;
use super::*;

const JOBS: &str = "jobs/new";
const INBOUND: &str = "incoming/qos2";
const RETAINED: &str = "saved/retained";

fn configuration(path: &Path, autosave: &str) -> String {
    format!(
        "{ANONYMOUS}\nuser root\nmax_inflight_messages 2\nretained_persistence true\npersistence_file state.db\npersistence_location {}\n{autosave}",
        path.display()
    )
}

fn configured(conf: &str) -> BrokerConfig<'_> {
    BrokerConfig {
        conf,
        ..BrokerConfig::default()
    }
}

// Mosquitto test/broker/15-persist-client-msg-{in,out,out-queue,out-dup}-v3-1-1.py and
// 15-persist-subscription-v3-1-1.py: the saved cursor and in-flight direction
// matter just as much as a subscription and its queued payloads.
fn populate(h: &mut Harness) {
    let subscriber = connect_with(h, persistent("durable-subscriber"), false);
    subscribe(h, subscriber, 10, &[("jobs/#", Q2), (INBOUND, Q1)]);
    let ephemeral = client(h, "clean-subscriber");
    subscribe(h, ephemeral, 11, &[("ephemeral", Q1)]);
    let publisher = connect_with(h, persistent("durable-publisher"), false);
    publish_from(h, publisher, publish(JOBS, b"waiting for PUBCOMP", Q2, 10));
    received(
        h,
        subscriber,
        Packet::Publish(publish(JOBS, b"waiting for PUBCOMP", Q2, 1)),
    );
    send(h, subscriber, Packet::PubRec(id(1)));
    received(h, subscriber, Packet::PubRel(id(1)));
    publish_from(h, publisher, publish(JOBS, b"already sent", Q1, 11));
    received(
        h,
        subscriber,
        Packet::Publish(publish(JOBS, b"already sent", Q1, 2)),
    );
    publish_from(h, publisher, publish(JOBS, b"never sent", Q1, 12));
    publish_from(h, publisher, publish(JOBS, b"dropped qos0", Q0, 0));
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(RETAINED, b"value", Q1, 13)
        },
    );
    send(
        h,
        publisher,
        Packet::Publish(publish(INBOUND, b"waiting for PUBREL", Q2, 14)),
    );
    received(h, publisher, Packet::PubRec(id(14)));
}

fn resume(h: &mut Harness) {
    let subscriber = connect_with(h, persistent("durable-subscriber"), true);
    received(h, subscriber, Packet::PubRel(id(1)));
    accept_publish(
        h,
        subscriber,
        Publish {
            dup: true,
            ..publish(JOBS, b"already sent", Q1, 2)
        },
    );
    send(h, subscriber, Packet::PubComp(id(1)));
    accept_publish(h, subscriber, publish(JOBS, b"never sent", Q1, 3));
    ping(h, subscriber);
    let publisher = connect_with(h, persistent("durable-publisher"), true);
    send(h, publisher, Packet::PubRel(id(14)));
    received(h, publisher, Packet::PubComp(id(14)));
    accept_publish(
        h,
        subscriber,
        publish(INBOUND, b"waiting for PUBREL", Q1, 4),
    );
    publish_from(h, publisher, publish(JOBS, b"new after restart", Q1, 15));
    accept_publish(h, subscriber, publish(JOBS, b"new after restart", Q1, 5));
    let ephemeral = connect_with(h, persistent("clean-subscriber"), false);
    publish_from(
        h,
        publisher,
        publish("ephemeral", b"not subscribed", Q1, 16),
    );
    ping(h, ephemeral);
    subscribe(h, ephemeral, 11, &[(RETAINED, Q1)]);
    // Mosquitto test/broker/15-persist-retain-v3-1-1.py.
    accept_publish(
        h,
        ephemeral,
        Publish {
            retain: true,
            ..publish(RETAINED, b"value", Q1, 1)
        },
    );
}

#[test]
#[ignore = "requires real Mosquitto 2.1.4 and mqextended binaries"]
fn persistence_clean_restart_preserves_only_durable_mqtt_state() {
    fn restart(kind: BrokerKind) -> Transcript {
        let dir = tempfile::tempdir().unwrap();
        let conf = configuration(dir.path(), "autosave_interval 0");
        let mut h = Harness::start(kind, configured(&conf)).unwrap();
        populate(&mut h);
        h.stop_node(1).unwrap();
        let log = h.node_log(1).unwrap();
        assert!(log.contains("Saving in-memory database to"), "{log}");
        assert!(
            log.find("terminating").unwrap() < log.find("Saving in-memory database to").unwrap(),
            "{log}"
        );
        h.restart_node(1).unwrap();
        resume(&mut h);
        h.into_transcript()
    }
    compare(
        &restart(BrokerKind::Mosquitto),
        &restart(BrokerKind::MqExtended),
    );
}

#[test]
#[ignore = "requires real Mosquitto 2.1.4 and mqextended binaries"]
fn persistence_imports_a_real_mosquitto_file_once_without_rewriting_it() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let conf = configuration(source.path(), "autosave_interval 0");
    let target_conf = configuration(target.path(), "autosave_interval 0");
    let mut writer = Harness::start(BrokerKind::Mosquitto, configured(&conf)).unwrap();
    populate(&mut writer);
    writer.stop_node(1).unwrap();
    let original = fs::read(source.path().join("state.db")).unwrap();
    assert_eq!(&original[..15], b"\0\xb5\0mosquitto db");
    fs::write(target.path().join("state.db"), &original).unwrap();

    let mut mosquitto = Harness::start(BrokerKind::Mosquitto, configured(&conf)).unwrap();
    let mut mqx = Harness::start(BrokerKind::MqExtended, configured(&target_conf)).unwrap();
    resume(&mut mosquitto);
    resume(&mut mqx);
    compare(&mosquitto.into_transcript(), &{
        let log = mqx.node_log(1).unwrap();
        assert!(
            log.contains("Imported Mosquitto persistence database"),
            "{log}"
        );
        mqx.stop_node(1).unwrap();
        assert_eq!(fs::read(target.path().join("state.db")).unwrap(), original);
        mqx.restart_node(1).unwrap();
        let subscriber = connect_with(&mut mqx, persistent("durable-subscriber"), true);
        ping(&mut mqx, subscriber); // A second import would replay acknowledged messages.
        let mut transcript = mqx.into_transcript();
        transcript.truncate(transcript.len() - 2);
        transcript
    });
}

#[test]
#[ignore = "requires real Mosquitto 2.1.4 and cluster-enabled mqextended binaries"]
fn persistence_cluster_bootstrap_import_is_replicated_not_a_standalone_backup() {
    let source = tempfile::tempdir().unwrap();
    let conf = configuration(source.path(), "autosave_interval 0");
    let mut writer = Harness::start(BrokerKind::Mosquitto, configured(&conf)).unwrap();
    populate(&mut writer);
    let publisher = client(&mut writer, "bulk");
    // Push the aggregate image beyond the usual 2 MiB Raft command limit.
    for (index, topic) in ["bulk/one", "bulk/two", "bulk/three"]
        .into_iter()
        .enumerate()
    {
        publish_from(
            &mut writer,
            publisher,
            Publish {
                retain: true,
                payload: Bytes::from(vec![b'a' + index as u8; 750_000]),
                ..publish(topic, b"", Q1, index as u16 + 1)
            },
        );
    }
    writer.stop_node(1).unwrap();
    let original = fs::read(source.path().join("state.db")).unwrap();

    let mut cluster = start_cluster(configured(&conf));
    let log = cluster.node_log(1).unwrap();
    assert!(
        log.contains("Imported Mosquitto persistence database"),
        "{log}"
    );
    for node in [2, 3] {
        assert!(
            !cluster
                .node_log(node)
                .unwrap()
                .contains("Imported Mosquitto persistence database")
        );
    }
    // The first CONNECT resumes on node 2, not the node that opened the file.
    let probe = cluster.open_on(3, V311).unwrap();
    cluster.close_socket(probe);
    resume(&mut cluster);
    assert!(!source.path().join("state.db.mqx").exists());
    assert_eq!(fs::read(source.path().join("state.db")).unwrap(), original);
    cluster.stop_node(1).unwrap();
    cluster.restart_node(1).unwrap();
    let reader = cluster.open_on(1, V311).unwrap();
    send(
        &mut cluster,
        reader,
        Packet::Connect(options("bulk-reader")),
    );
    connack(&mut cluster, reader, Accepted, false);
    subscribe(&mut cluster, reader, 7, &[("bulk/three", Q1)]);
    accept_publish(
        &mut cluster,
        reader,
        Publish {
            retain: true,
            payload: Bytes::from(vec![b'c'; 750_000]),
            ..publish("bulk/three", b"", Q1, 1)
        },
    );
    assert!(
        !cluster
            .node_log(1)
            .unwrap()
            .contains("Imported Mosquitto persistence database")
    );
}

#[cfg(unix)]
#[test]
#[ignore = "requires real Mosquitto 2.1.4 and mqextended binaries"]
fn persistence_live_backups_survive_an_immediate_process_kill() {
    use std::os::unix::fs::PermissionsExt;

    // src/loop.c: Mosquitto checks autosave only when its loop wakes, and an
    // idle loop sleeps until the next $SYS tick. Tick every second so the
    // reference saves within the deadline.
    for (autosave, signal) in [
        ("autosave_interval 0", true),
        (
            "autosave_interval 1\nautosave_on_changes true\nsys_interval 1",
            false,
        ),
        ("autosave_interval 1\nsys_interval 1", false),
    ] {
        let restart = |kind, filename| {
            let dir = tempfile::tempdir().unwrap();
            let conf = configuration(dir.path(), autosave);
            let mut h = Harness::start(kind, configured(&conf)).unwrap();
            let publisher = client(&mut h, "publisher");
            publish_from(
                &mut h,
                publisher,
                Publish {
                    retain: true,
                    ..publish(RETAINED, b"before kill", Q1, 1)
                },
            );
            if signal {
                h.backup_node(1).unwrap()
            }
            let path = dir.path().join(filename);
            let deadline = Instant::now() + RESPONSE + Duration::from_secs(3);
            while !path.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(25));
            }
            let mode = fs::metadata(&path)
                .unwrap_or_else(|err| panic!("{err}: {}", h.node_log(1).unwrap()))
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            h.kill_node(1).unwrap();
            h.restart_node(1).unwrap();
            let reader = client(&mut h, "reader");
            subscribe(&mut h, reader, 1, &[(RETAINED, Q1)]);
            accept_publish(
                &mut h,
                reader,
                Publish {
                    retain: true,
                    ..publish(RETAINED, b"before kill", Q1, 1)
                },
            );
            h.into_transcript()
        };
        compare(
            &restart(BrokerKind::Mosquitto, "state.db"),
            &restart(BrokerKind::MqExtended, "state.db.mqx"),
        );
    }
}
