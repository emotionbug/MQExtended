use std::collections::BTreeMap;

use super::*;

fn initial(kind: BrokerKind) -> BTreeMap<String, String> {
    let mut harness =
        Harness::start(kind, config("allow_anonymous true\nsys_interval 65535")).unwrap();
    let peer = client(&mut harness, "sys-reader");
    // libcommon/topic_common.c: '#' does not match '$SYS'.
    subscribe(&mut harness, peer, 1, &[("#", Q2)]);
    silent(&mut harness, peer);
    subscribe(&mut harness, peer, 2, &[("$SYS/broker/#", Q2)]);
    let mut tree = BTreeMap::new();
    loop {
        match read(&mut harness, peer, SILENCE) {
            Reading::TimedOut => break,
            Reading::Received {
                packet: Packet::Publish(publish),
                ..
            } => {
                assert!(publish.retain);
                assert!(!publish.dup);
                assert_eq!(publish.qos, Q2);
                let mid = publish.packet_id.unwrap();
                let topic = publish.topic.clone();
                let payload = std::str::from_utf8(&publish.payload).unwrap();
                if topic.starts_with("$SYS/broker/heap/") {
                    assert!(matches!(kind, BrokerKind::Mosquitto));
                    assert!(matches!(
                        topic.as_str(),
                        "$SYS/broker/heap/current" | "$SYS/broker/heap/maximum"
                    ));
                    assert!(payload.parse::<u64>().unwrap() > 0);
                } else {
                    assert!(tree.insert(topic, payload.to_owned()).is_none());
                }
                send(&mut harness, peer, Packet::PubRec(mid));
                // The broker can send more PUBLISHes before PUBREL, so collect
                // both interleaved packet types until the socket is quiet.
            }
            Reading::Received {
                packet: Packet::PubRel(mid),
                ..
            } => {
                let mid = *mid;
                send(&mut harness, peer, Packet::PubComp(mid));
            }
            other => panic!("unexpected $SYS packet: {other:?}"),
        }
    }
    assert_eq!(tree["$SYS/broker/version"], "mosquitto version 2.1.4");
    let uptime = &tree["$SYS/broker/uptime"];
    let seconds = uptime
        .strip_suffix(" seconds")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(uptime, &format!("{seconds} seconds"));
    assert!(seconds <= 5 || seconds >= u64::MAX - 5);
    let store_bytes = uptime.len() + tree["$SYS/broker/version"].len();
    tree.insert("$SYS/broker/uptime".into(), "0 seconds".into());
    assert_eq!(tree["$SYS/broker/messages/stored"], "2");
    assert_eq!(tree["$SYS/broker/store/messages/count"], "2");
    let recorded = tree
        .insert("$SYS/broker/store/messages/bytes".into(), "32".into())
        .unwrap();
    assert_eq!(recorded, store_bytes.to_string());
    assert_eq!(tree["$SYS/broker/retained messages/count"], "2");
    assert_eq!(tree["$SYS/broker/clients/connected"], "0");
    assert_eq!(tree["$SYS/broker/clients/active"], "0");
    assert!(!tree.contains_key("$SYS/broker/clients/maximum"));
    assert_eq!(
        tree.iter()
            .filter(|(topic, _)| topic.contains("/load/"))
            .count(),
        27
    );
    assert!(
        tree.iter()
            .filter(|(topic, _)| topic.contains("/load/"))
            .all(|(_, payload)| payload == "0.00")
    );
    tree
}

#[test]
#[ignore = "requires Mosquitto 2.1.4"]
fn deterministic_sys_startup_mosquitto_self() {
    assert_eq!(
        initial(BrokerKind::Mosquitto),
        initial(BrokerKind::Mosquitto)
    );
}

#[test]
#[ignore = "requires Mosquitto and MQExtended"]
fn deterministic_sys_startup_cross_broker() {
    assert_eq!(
        initial(BrokerKind::Mosquitto),
        initial(BrokerKind::MqExtended)
    );
}

#[test]
#[ignore = "requires MQExtended"]
fn only_the_raft_leader_publishes_each_sys_tick() {
    let mut harness = start_cluster(config("allow_anonymous true\nsys_interval 1"));
    let _leader = harness.wait_for_leader(RESPONSE).unwrap();
    let mut peers = Vec::new();
    for node in 1..=3 {
        let peer = harness.open_on(node, V311).unwrap();
        send(
            &mut harness,
            peer,
            Packet::Connect(options(&format!("sys-{node}"))),
        );
        connack(&mut harness, peer, Accepted, false);
        subscribe(&mut harness, peer, 1, &[("$SYS/broker/uptime", Q0)]);
        peers.push(peer);
    }
    for peer in peers {
        let mut last = None;
        let mut live = 0;
        while live != 3 {
            match read(&mut harness, peer, RESPONSE) {
                Reading::Received {
                    packet: Packet::Publish(publish),
                    ..
                } => {
                    assert_eq!(publish.topic, "$SYS/broker/uptime");
                    let payload = std::str::from_utf8(&publish.payload).unwrap();
                    let seconds = payload
                        .strip_suffix(" seconds")
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    if publish.retain {
                        assert!(last.is_none(), "received a competing retained sample");
                    } else {
                        assert!(
                            last.is_none_or(|value| seconds > value),
                            "multiple publications for one wall-clock tick: {payload}"
                        );
                        live += 1;
                    }
                    last = Some(seconds);
                }
                other => panic!("unexpected cluster $SYS packet: {other:?}"),
            }
        }
    }
    for node in 1..=3 {
        let peer = harness.open_on(node, V311).unwrap();
        send(
            &mut harness,
            peer,
            Packet::Connect(options(&format!("sys-replay-{node}"))),
        );
        connack(&mut harness, peer, Accepted, false);
        subscribe(&mut harness, peer, 1, &[("$SYS/broker/version", Q0)]);
        let mut version = publish("$SYS/broker/version", b"mosquitto version 2.1.4", Q0, 0);
        version.retain = true;
        received(&mut harness, peer, Packet::Publish(version));
        silent(&mut harness, peer);
    }
}

fn disabled_interval(kind: BrokerKind) -> Transcript {
    let mut harness = Harness::start(kind, config(
        "allow_anonymous true\nsys_interval 0\nlog_dest topic\nlog_type unsubscribe\nlog_timestamp false",
    )).unwrap();
    let peer = client(&mut harness, "log-reader");
    subscribe(&mut harness, peer, 1, &[("$SYS/broker/version", Q0)]);
    silent(&mut harness, peer);
    let topic = "$SYS/broker/log/M/unsubscribe";
    subscribe(&mut harness, peer, 2, &[(topic, Q1)]);
    let source = client(&mut harness, "log-source");
    subscribe(&mut harness, source, 1, &[("logging", Q0)]);
    unsubscribe(&mut harness, source, 2, "logging");
    accept_publish(
        &mut harness,
        peer,
        publish(topic, b"log-source logging", Q1, 1),
    );
    harness.into_transcript()
}

#[test]
#[ignore = "requires Mosquitto 2.1.4"]
fn disabled_interval_keeps_log_topics_mosquitto_self() {
    compare(
        &disabled_interval(BrokerKind::Mosquitto),
        &disabled_interval(BrokerKind::Mosquitto),
    );
}

#[test]
#[ignore = "requires Mosquitto and MQExtended"]
fn disabled_interval_keeps_log_topics_cross_broker() {
    compare(
        &disabled_interval(BrokerKind::Mosquitto),
        &disabled_interval(BrokerKind::MqExtended),
    );
}
