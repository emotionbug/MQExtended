use std::io::Write as _;
use std::time::Instant;
use std::{fs, num::NonZeroUsize, thread};

use mqx_difftest::ClusterReadiness;
use serde_json::Value;

use super::sessions::{persistent, with_will};
use super::*;

const ELECTION: Duration = Duration::from_secs(5);
const WILL_DELIVERY: Duration = Duration::from_secs(6);

#[track_caller]
fn on(h: &mut Harness, node: usize, settings: Connect, session_present: bool) -> Connection {
    let client = h.open_on(node, settings.protocol).unwrap();
    send(h, client, Packet::Connect(settings));
    connack(h, client, Accepted, session_present);
    client
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn persistent_inbox_resumes_on_different_node_after_kill() {
    let mut h = start_cluster(config("allow_anonymous true\nmax_inflight_messages 1"));
    let h = &mut h;
    let settings = persistent("durable");
    let topic = "failover/inbox";
    let publisher = on(h, 1, options("publisher"), false);
    let subscriber = on(h, 2, settings.clone(), false);
    subscribe(h, subscriber, 7, &[(topic, Q1)]);
    publish_from(h, publisher, publish(topic, b"inflight", Q1, 41));
    let inflight = publish(topic, b"inflight", Q1, 1);
    received(h, subscriber, Packet::Publish(inflight.clone()));

    h.kill_node(2).unwrap();
    closed(h, subscriber);
    publish_from(h, publisher, publish(topic, b"first queued", Q1, 42));
    publish_from(h, publisher, publish(topic, b"second queued", Q1, 43));
    let subscriber = on(h, 3, settings.clone(), true);
    // Mosquitto src/database.c: db__message_reconnect_reset_outgoing retries inflight
    // messages before queued messages. Only the packet already sent has DUP set.
    accept_publish(
        h,
        subscriber,
        Publish {
            dup: true,
            ..inflight
        },
    );
    accept_publish(h, subscriber, publish(topic, b"first queued", Q1, 2));
    accept_publish(h, subscriber, publish(topic, b"second queued", Q1, 3));
    ping(h, subscriber);
    disconnect(h, subscriber);
    let subscriber = on(h, 1, settings, true);
    ping(h, subscriber); // None of the three acknowledgements was lost in the handoff.
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn partial_ack_of_a_replay_window_survives_owner_loss() {
    let mut cluster = start_cluster(config("allow_anonymous true\nmax_inflight_messages 8"));
    let h = &mut cluster;
    let settings = persistent("window");
    let topic = "failover/window";
    let subscriber = on(h, 2, settings.clone(), false);
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    disconnect(h, subscriber);
    let publisher = on(h, 1, options("publisher"), false);
    let message = |n: u16| Publish {
        payload: Bytes::copy_from_slice(&n.to_be_bytes()),
        ..publish(topic, b"", Q1, n)
    };
    for n in 1..=16 {
        publish_from(h, publisher, message(n));
    }

    let subscriber = on(h, 2, settings.clone(), true);
    for n in 1..=8 {
        received(h, subscriber, Packet::Publish(message(n)));
    }
    for n in 1..=3 {
        send(h, subscriber, Packet::PubAck(id(n)));
    }
    // Seeing three replacements proves the three acknowledgements took effect.
    for n in 9..=11 {
        received(h, subscriber, Packet::Publish(message(n)));
    }
    h.kill_node(2).unwrap();
    let resumed = on(h, 3, settings, true);
    for n in 4..=16 {
        accept_publish(
            h,
            resumed,
            Publish {
                dup: n <= 11,
                ..message(n)
            },
        );
    }
    ping(h, resumed);
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn persistent_fanout_keeps_each_subscribers_send_state_after_kill() {
    let mut h = start_cluster(config("allow_anonymous true\nmax_inflight_messages 1"));
    let h = &mut h;
    let topic = "failover/fanout";
    let publisher = on(h, 1, options("publisher"), false);
    let a_settings = persistent("subscriber-a");
    let b_settings = persistent("subscriber-b");
    let a = on(h, 2, a_settings.clone(), false);
    let b = on(h, 2, b_settings.clone(), false);
    for subscriber in [a, b] {
        subscribe(h, subscriber, 1, &[(topic, Q1)]);
    }
    publish_from(h, publisher, publish(topic, b"first", Q1, 41));
    for subscriber in [a, b] {
        received(
            h,
            subscriber,
            Packet::Publish(publish(topic, b"first", Q1, 1)),
        );
    }
    publish_from(h, publisher, publish(topic, b"second", Q1, 42));
    // Only A frees its send window before the node is killed. Its second
    // message must be resent; B's second message has never been attempted.
    send(h, a, Packet::PubAck(id(1)));
    received(h, a, Packet::Publish(publish(topic, b"second", Q1, 2)));
    h.kill_node(2).unwrap();
    closed(h, a);
    closed(h, b);

    let a = on(h, 3, a_settings, true);
    accept_publish(
        h,
        a,
        Publish {
            dup: true,
            ..publish(topic, b"second", Q1, 2)
        },
    );
    ping(h, a);
    let b = on(h, 3, b_settings, true);
    accept_publish(
        h,
        b,
        Publish {
            dup: true,
            ..publish(topic, b"first", Q1, 1)
        },
    );
    accept_publish(h, b, publish(topic, b"second", Q1, 2));
    ping(h, b);
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn dead_node_lease_publishes_will_once_to_each_survivor() {
    let mut h = start_cluster(config(
        "allow_anonymous true\ncluster_lease_interval 200\ncluster_lease_timeout 2000",
    ));
    let h = &mut h;
    let topic = "failover/will";
    let first = on(h, 1, options("first-watcher"), false);
    let second = on(h, 3, options("second-watcher"), false);
    subscribe(h, first, 1, &[(topic, Q0)]);
    subscribe(h, second, 1, &[(topic, Q0)]);
    let dying = on(
        h,
        2,
        Connect {
            clean_session: false,
            ..with_will("will-owner", topic)
        },
        false,
    );
    let killed_at = Instant::now();
    h.kill_node(2).unwrap();
    let mut elapsed = Duration::ZERO;
    for watcher in [first, second] {
        let timeout = WILL_DELIVERY.saturating_sub(killed_at.elapsed());
        match read(h, watcher, timeout) {
            Reading::Received { packet, .. } => {
                assert_eq!(packet, &Packet::Publish(publish(topic, b"LWT", Q0, 0)))
            }
            other => panic!("expected the will after lease expiry, got {other:?}"),
        }
        if elapsed.is_zero() {
            elapsed = killed_at.elapsed();
        }
    }
    // The lease is 2000ms, renewed every 200ms. Use a conservative lower bound so
    // a stale heartbeat or election does not turn a timing assertion into a race.
    assert!(
        elapsed >= Duration::from_millis(1000),
        "will fired before lease timeout: {elapsed:?}"
    );
    closed(h, dying);
    for watcher in [first, second] {
        assert_eq!(
            read(h, watcher, Duration::from_millis(1200)),
            &Reading::TimedOut
        );
        disconnect(h, watcher);
    }
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn retained_messages_and_subscriptions_survive_node_loss() {
    let mut h = start_cluster(config(ANONYMOUS));
    let h = &mut h;
    let retained = "state/retained";
    let live = "state/live";
    let settings = persistent("durable-filter");
    let subscriber = on(h, 2, settings.clone(), false);
    let publisher = on(h, 2, options("original-publisher"), false);
    subscribe(h, subscriber, 1, &[("state/+", Q1)]);
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(retained, b"stored", Q1, 31)
        },
    );
    accept_publish(h, subscriber, publish(retained, b"stored", Q1, 1));
    disconnect(h, subscriber); // Confirm PUBACK before the process dies.

    h.kill_node(2).unwrap();
    closed(h, publisher);
    let subscriber = on(h, 3, settings, true);
    let fresh = on(h, 1, options("fresh"), false);
    // The routing fence can wait for a new election and durable lease expiry.
    subscribe_within(h, fresh, 2, &[(retained, Q1)], ELECTION + WILL_DELIVERY);
    accept_publish(
        h,
        fresh,
        Publish {
            retain: true,
            ..publish(retained, b"stored", Q1, 1)
        },
    );
    publish_from(h, fresh, publish(live, b"existing filter", Q1, 32));
    accept_publish(h, subscriber, publish(live, b"existing filter", Q1, 2));
    disconnect(h, subscriber);
    disconnect(h, fresh);
}

#[cfg(unix)]
#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn a_suspended_voter_does_not_delay_suback_after_lease_expiry() {
    let h = &mut start_cluster(config(
        "allow_anonymous true\ncluster_lease_interval 200\ncluster_lease_timeout 2000\ncluster_request_timeout 20000",
    ));
    let leader = h.wait_for_leader(ELECTION).unwrap();
    let mut followers = (1..=3).filter(|&node| node != leader);
    let paused = followers.next().unwrap();
    let publisher = on(
        h,
        followers.next().unwrap(),
        options("live-publisher"),
        false,
    );
    let subscriber = on(h, leader, options("fenced-subscriber"), false);
    subscribe(h, subscriber, 1, &[("before/pause", Q1)]);
    h.suspend_node(paused).unwrap(); // Established mesh TCP stays open; no reply or FIN.
    let topic = "during/pause";
    subscribe_within(h, subscriber, 2, &[(topic, Q1)], WILL_DELIVERY);
    publish_from(h, publisher, publish(topic, b"after fence", Q1, 8));
    accept_publish(h, subscriber, publish(topic, b"after fence", Q1, 1));
    h.resume_node(paused).unwrap();
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn cross_node_takeover_closes_old_owner_with_mosquitto_will_policy() {
    let mut h = start_cluster(config(ANONYMOUS));
    let h = &mut h;
    let topic = "failover/takeover";
    let watcher = on(h, 2, options("watcher"), false);
    subscribe(h, watcher, 1, &[(topic, Q0)]);
    for (index, (old_clean, new_clean)) in
        [(true, true), (true, false), (false, true), (false, false)]
            .into_iter()
            .enumerate()
    {
        let client_id = format!("owner-{index}");
        let old = on(
            h,
            1,
            Connect {
                clean_session: old_clean,
                ..with_will(&client_id, topic)
            },
            false,
        );
        let new = on(
            h,
            3,
            Connect {
                clean_session: new_clean,
                ..options(&client_id)
            },
            !old_clean && !new_clean,
        );
        closed(h, old);
        // Mosquitto src/handle_connect.c: connect__on_authorised only sends the old
        // will for MQTT 3.x takeover when the old or the new session is clean.
        if old_clean || new_clean {
            accept_publish(h, watcher, publish(topic, b"LWT", Q0, 0));
        }
        publish_from(h, new, publish(topic, b"new owner", Q1, 34));
        accept_publish(h, watcher, publish(topic, b"new owner", Q0, 0));
        disconnect(h, new);
    }
    disconnect(h, watcher);
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn surviving_connections_publish_after_raft_leader_sigkill() {
    let mut h = start_cluster(config(ANONYMOUS));
    let h = &mut h;
    let old_leader = h.wait_for_leader(ELECTION).unwrap();
    let mut followers = (1..=3).filter(|&node| node != old_leader);
    let publisher = on(h, followers.next().unwrap(), options("publisher"), false);
    let subscriber = on(
        h,
        followers.next().unwrap(),
        persistent("durable-subscriber"),
        false,
    );
    let topic = "failover/election";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    publish_from(h, publisher, publish(topic, b"before", Q1, 31));
    received(
        h,
        subscriber,
        Packet::Publish(publish(topic, b"before", Q1, 1)),
    );

    let deadline = Instant::now() + ELECTION;
    h.kill_node(old_leader).unwrap(); // Subscription still has an unacknowledged PUBLISH.
    send(h, subscriber, Packet::PubAck(id(1)));
    // Send on the surviving socket without waiting for election or replaying the publish.
    send(
        h,
        publisher,
        Packet::Publish(publish(topic, b"during election", Q1, 32)),
    );
    let remaining = || deadline.saturating_duration_since(Instant::now());
    assert!(
        matches!(read(h, publisher, remaining()), Reading::Received { packet: Packet::PubAck(mid), .. } if *mid == id(32))
    );
    assert_ne!(h.wait_for_leader(remaining()).unwrap(), old_leader);
    accept_publish(h, subscriber, publish(topic, b"during election", Q1, 2));
    publish_from(h, publisher, publish(topic, b"after", Q1, 33));
    accept_publish(h, subscriber, publish(topic, b"after", Q1, 3));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn restarted_node_serves_restored_and_caught_up_state() {
    let mut h = start_cluster(config(ANONYMOUS));
    let h = &mut h;
    let settings = persistent("returning");
    let old = on(h, 2, settings.clone(), false);
    let publisher = on(h, 1, options("publisher"), false);
    let topic = "restart/inbox";
    let retained = "restart/retained";
    subscribe(h, old, 1, &[(topic, Q1)]);
    disconnect(h, old);
    publish_from(h, publisher, publish(topic, b"before kill", Q1, 31));
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(retained, b"old value", Q1, 32)
        },
    );
    h.kill_node(2).unwrap();
    assert!(matches!(
        h.open_on(2, V311),
        Err(mqx_difftest::Error::NodeStopped(2))
    ));

    publish_from(h, publisher, publish(topic, b"while down", Q1, 33));
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(retained, b"new value", Q1, 34)
        },
    );
    h.restart_node(2).unwrap();
    let subscriber = on(h, 2, settings, true);
    accept_publish(h, subscriber, publish(topic, b"before kill", Q1, 1));
    accept_publish(h, subscriber, publish(topic, b"while down", Q1, 2));
    subscribe(h, subscriber, 2, &[(retained, Q1)]);
    accept_publish(
        h,
        subscriber,
        Publish {
            retain: true,
            ..publish(retained, b"new value", Q1, 3)
        },
    );
    publish_from(h, publisher, publish(topic, b"after restart", Q1, 35));
    accept_publish(h, subscriber, publish(topic, b"after restart", Q1, 4));
    subscribe(h, publisher, 3, &[("restart/response", Q1)]);
    publish_from(
        h,
        subscriber,
        publish("restart/response", b"routed from restarted node", Q1, 51),
    );
    accept_publish(
        h,
        publisher,
        publish("restart/response", b"routed from restarted node", Q1, 1),
    );
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

const LEASE_MS: u64 = 5000;
const RECOVER_MS: u64 = 1000;
const REQUEST: Duration = Duration::from_secs(5);
// The leader waits a full lease timeout after election before proposing Down.
const MAJORITY_DOWN_BOUND: Duration = ELECTION
    .saturating_add(Duration::from_millis(LEASE_MS))
    .saturating_add(REQUEST);
const RECOVERY_BOUND: Duration = Duration::from_millis(LEASE_MS + RECOVER_MS + 3000);
const EMPTY_JOIN_BOUND: Duration = Duration::from_millis(LEASE_MS + 6 * RECOVER_MS + 3000);
const REJOIN_BOUND: Duration = Duration::from_secs(20);
const STATUS_POLL: Duration = Duration::from_millis(20);

fn recovery_cluster(nodes: usize, enabled: bool) -> Harness {
    let mut conf = format!(
        "{ANONYMOUS}\ncluster_state_format 2\ncluster_lease_interval 200\ncluster_lease_timeout {LEASE_MS}\ncluster_request_timeout {}\nauto_recover {enabled}\n",
        REQUEST.as_millis()
    );
    if enabled {
        conf.push_str(&format!("auto_recover_timeout {RECOVER_MS}\n"));
    }
    let h = Harness::start_cluster(
        BrokerConfig {
            conf: &conf,
            ..BrokerConfig::default()
        },
        ClusterConfig {
            nodes: NonZeroUsize::new(nodes).unwrap(),
            readiness: ClusterReadiness::HttpStatus,
            ..ClusterConfig::default()
        },
    )
    .unwrap();
    let voters = (1..=nodes).collect::<Vec<_>>();
    let deadline = Instant::now() + ELECTION;
    for &node in &voters {
        let status = wait_status(&h, node, deadline, "initial cluster", |status, ready| {
            ready && has_voters(status, &voters)
        });
        assert_eq!(status["auto_recover"], enabled);
        assert_eq!(status["incarnation"], 0);
        assert_eq!(status.get("last_survivor_event"), Some(&Value::Null));
    }
    h
}

fn has_voters(status: &Value, voters: &[usize]) -> bool {
    let membership = &status["membership"];
    membership["joint"] == false
        && membership["members"].as_object().is_some_and(|members| {
            members.len() == voters.len()
                && voters.iter().all(|id| {
                    members.get(&id.to_string()).is_some_and(|member| {
                        member["role"] == "Voter" && member["liveness"] == "Alive"
                    })
                })
        })
}

#[track_caller]
fn wait_status(
    h: &Harness,
    node: usize,
    deadline: Instant,
    expected: &str,
    matches: impl Fn(&Value, bool) -> bool,
) -> Value {
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let mut last = None;
    loop {
        if let Some(status) = h.node_cluster_status(node, remaining()).unwrap() {
            assert_eq!(status["raft"]["node_id"], node);
            let ready = h.node_mqtt_ready(node, remaining()).unwrap();
            if ready.is_some_and(|ready| matches(&status, ready)) {
                assert!(Instant::now() <= deadline, "node {node}: late {expected}");
                return status;
            }
            last = Some((status, ready));
        }
        assert!(
            Instant::now() < deadline,
            "node {node}: expected {expected}, last HTTP observation: {last:?}"
        );
        thread::sleep(STATUS_POLL.min(remaining()));
    }
}

#[track_caller]
fn wait_fork(h: &Harness, node: usize, incarnation: u64, deadline: Instant) -> Value {
    wait_status(
        h,
        node,
        deadline,
        "serving as a single voter after fork",
        |status, ready| {
            ready && status["incarnation"] == incarnation && has_voters(status, &[node])
        },
    )
}

#[track_caller]
fn assert_event(status: &Value, reason: &str, peer: usize) {
    assert_eq!(status["auto_recover"], true);
    let event = &status["last_survivor_event"];
    assert_eq!(event["reason"], reason, "{status}");
    assert_eq!(event["peer"], peer, "{status}");
    assert!(event["timestamp_seconds"].as_u64().is_some_and(|t| t > 0));
}

#[track_caller]
fn wait_recovered_voters(h: &Harness, voters: &[usize], incarnation: u64) -> Vec<Value> {
    let deadline = Instant::now() + REJOIN_BOUND;
    voters
        .iter()
        .map(|&node| {
            let status = wait_status(h, node, deadline, "all voters serving", |status, ready| {
                ready && status["incarnation"] == incarnation && has_voters(status, voters)
            });
            assert_eq!(status["membership"]["retired"], serde_json::json!([]));
            status
        })
        .collect()
}

#[track_caller]
fn store_retained(h: &mut Harness, sender: Connection, topic: &str, payload: &'static [u8]) {
    publish_from(
        h,
        sender,
        Publish {
            retain: true,
            ..publish(topic, payload, Q1, 61)
        },
    );
}

#[track_caller]
fn expect_retained(h: &mut Harness, node: usize, topic: &str, payload: &'static [u8]) {
    let reader = on(h, node, options("retained-reader"), false);
    subscribe(h, reader, 1, &[(topic, Q1)]);
    accept_publish(
        h,
        reader,
        Publish {
            retain: true,
            ..publish(topic, payload, Q1, 1)
        },
    );
    disconnect(h, reader);
}

#[track_caller]
fn survivor_cycle(h: &mut Harness, survivor: usize, failed: usize, incarnation: u64) {
    let prefix = format!("recovery/cycle-{incarnation}");
    let inbox = format!("{prefix}/inbox");
    let retained = format!("{prefix}/retained");
    let will = format!("{prefix}/will");
    let settings = persistent(&format!("inbox-{incarnation}"));
    let watcher_settings = persistent(&format!("watcher-{incarnation}"));
    let old = on(h, failed, settings.clone(), false);
    subscribe(h, old, 1, &[(&inbox, Q1)]);
    disconnect(h, old);
    let watcher = on(h, survivor, watcher_settings.clone(), false);
    subscribe(h, watcher, 1, &[(&will, Q1)]);
    disconnect(h, watcher); // The survivor re-execs; the will must wait in this inbox.

    let publisher = on(h, failed, options("before-fork-publisher"), false);
    store_retained(h, publisher, &retained, b"committed before fork");
    publish_from(h, publisher, publish(&inbox, b"queued before fork", Q1, 41));
    let mut will_settings = with_will("failed-node-will", &will);
    will_settings.will.as_mut().unwrap().qos = Q1;
    let doomed = on(h, failed, will_settings, false);
    // This CONNECT applies on the surviving replica after the writes above.
    let local_settings = persistent(&format!("survivor-session-{incarnation}"));
    let local = on(h, survivor, local_settings.clone(), false);
    let deadline = Instant::now() + RECOVERY_BOUND;
    h.kill_node(failed).unwrap();
    let fork = wait_fork(h, survivor, incarnation, deadline);
    assert_event(&fork, "peer_unreachable", failed);
    let publisher_after = on(h, survivor, local_settings, true);
    assert!(
        Instant::now() <= deadline,
        "survivor CONNECT exceeded recovery bound"
    );
    closed(h, local);
    closed(h, doomed);
    closed(h, publisher);

    let watcher = on(h, survivor, watcher_settings, true);
    match read(h, watcher, Duration::from_millis(LEASE_MS) + RESPONSE) {
        Reading::Received {
            packet: Packet::Publish(message),
            ..
        } => assert_eq!(message, &publish(&will, b"LWT", Q1, 1)),
        other => panic!("expected the failed node's will, observed {other:?}"),
    }
    send(h, watcher, Packet::PubAck(id(1)));
    let inbox_client = on(h, survivor, settings.clone(), true);
    accept_publish(
        h,
        inbox_client,
        publish(&inbox, b"queued before fork", Q1, 1),
    );
    publish_from(
        h,
        publisher_after,
        publish(&inbox, b"existing subscription", Q1, 42),
    );
    accept_publish(
        h,
        inbox_client,
        publish(&inbox, b"existing subscription", Q1, 2),
    );
    expect_retained(h, survivor, &retained, b"committed before fork");
    disconnect(h, inbox_client);
    publish_from(
        h,
        publisher_after,
        publish(&inbox, b"queued while alone", Q1, 43),
    );
    store_retained(h, publisher_after, &retained, b"committed while alone");

    h.restart_node(failed).unwrap();
    let both = wait_recovered_voters(h, &[survivor, failed], incarnation);
    assert_event(&both[1], "peer_won", survivor);
    let inbox_client = on(h, failed, settings, true);
    accept_publish(
        h,
        inbox_client,
        publish(&inbox, b"queued while alone", Q1, 3),
    );
    expect_retained(h, failed, &retained, b"committed while alone");
    let rejoined_publisher = on(h, failed, options("rejoined-publisher"), false);
    publish_from(
        h,
        rejoined_publisher,
        publish(&inbox, b"published by rejoined node", Q1, 44),
    );
    accept_publish(
        h,
        inbox_client,
        publish(&inbox, b"published by rejoined node", Q1, 4),
    );
    ping(h, watcher); // No duplicate while alone, or when the failed node comes back.
    silent(h, watcher);
    disconnect(h, watcher);
    disconnect(h, inbox_client);
    disconnect(h, rejoined_publisher);
    disconnect(h, publisher_after);
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn two_node_auto_recovery_preserves_state_and_can_repeat_in_reverse() {
    let h = &mut recovery_cluster(2, true);
    survivor_cycle(h, 1, 2, 1);
    survivor_cycle(h, 2, 1, 2);
    expect_retained(h, 1, "recovery/cycle-1/retained", b"committed while alone");
}

#[cfg(unix)]
#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn two_node_auto_recovery_rejoins_a_suspended_peer() {
    let h = &mut recovery_cluster(2, true);
    let topic = "recovery/suspended";
    let paused = on(h, 2, options("paused-before-fork"), false);
    let deadline = Instant::now() + RECOVERY_BOUND;
    h.suspend_node(2).unwrap();
    let fork = wait_fork(h, 1, 1, deadline);
    assert_event(&fork, "peer_unreachable", 2);
    let publisher = on(h, 1, options("publisher-during-suspension"), false);
    store_retained(h, publisher, topic, b"surviving node's data");
    h.resume_node(2).unwrap();
    let both = wait_recovered_voters(h, &[1, 2], 1);
    assert_event(&both[1], "peer_won", 1);
    closed(h, paused);
    expect_retained(h, 2, topic, b"surviving node's data");
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn two_node_cluster_without_auto_recovery_stops_admission_after_loss() {
    let h = &mut recovery_cluster(2, false);
    let killed_at = Instant::now();
    h.kill_node(2).unwrap();
    let status = wait_status(
        h,
        1,
        killed_at + Duration::from_millis(LEASE_MS + 1000),
        "admission closed",
        |_, ready| !ready,
    );
    assert_eq!(status["incarnation"], 0);
    assert_eq!(status["membership"]["members"]["2"]["role"], "Voter");
    while killed_at.elapsed() < RECOVERY_BOUND {
        assert_eq!(h.node_mqtt_ready(1, RESPONSE).unwrap(), Some(false));
        thread::sleep(STATUS_POLL);
    }
    let client = h.open_on(1, V311).unwrap();
    match h.send(client, &Packet::Connect(options("admission-probe"))) {
        Ok(()) => closed(h, client),
        Err(mqx_difftest::Error::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            h.close_socket(client);
        }
        Err(error) => panic!("CONNECT write failed: {error}"),
    }
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn auto_recovery_serves_when_the_winner_dies_during_rejoin() {
    let h = &mut recovery_cluster(2, true);
    h.kill_node(2).unwrap();
    wait_fork(h, 1, 1, Instant::now() + RECOVERY_BOUND);
    h.restart_node(2).unwrap();
    // The returning process serves status when it has installed the rejoin
    // record, but the winner waits for its old lease to expire before adding it.
    let rejoining = wait_status(
        h,
        2,
        Instant::now() + Duration::from_millis(LEASE_MS),
        "rejoin record installed before applying any Raft entries",
        |status, ready| {
            !ready
                && status["incarnation"] == 1
                && status["raft"]["applied_index"].is_null()
                && status["last_survivor_event"]["reason"] == "peer_won"
        },
    );
    assert_event(&rejoining, "peer_won", 1);
    assert!(has_voters(
        &h.node_cluster_status(1, RESPONSE).unwrap().unwrap(),
        &[1]
    ));
    let deadline = Instant::now() + EMPTY_JOIN_BOUND;
    h.kill_node(1).unwrap();
    wait_fork(h, 2, 2, deadline);
    let recovered = on(h, 2, options("recovered-from-empty-join"), false);
    store_retained(h, recovered, "recovery/empty-join", b"new writes commit");
    expect_retained(h, 2, "recovery/empty-join", b"new writes commit");
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn three_node_auto_recovery_restores_three_voters_after_majority_loss() {
    let h = &mut recovery_cluster(3, true);
    let topic = "recovery/majority-loss";
    let publisher = on(h, 1, options("majority-loss-publisher"), false);
    store_retained(h, publisher, topic, b"before majority loss");
    let deadline = Instant::now() + RECOVERY_BOUND;
    h.kill_node(2).unwrap();
    h.kill_node(3).unwrap();
    wait_fork(h, 1, 1, deadline);
    closed(h, publisher);
    expect_retained(h, 1, topic, b"before majority loss");

    let publisher = on(h, 1, options("sole-voter-publisher"), false);
    store_retained(h, publisher, topic, b"after majority loss");
    h.restart_node(2).unwrap();
    h.restart_node(3).unwrap();
    let statuses = wait_recovered_voters(h, &[1, 2, 3], 1);
    for state in &statuses[1..] {
        assert_event(state, "peer_won", 1);
    }
    expect_retained(h, 2, topic, b"after majority loss");
    expect_retained(h, 3, topic, b"after majority loss");
}

#[cfg(unix)]
#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn three_node_auto_recovery_keeps_the_majoritys_writes_during_isolation() {
    let h = &mut recovery_cluster(3, true);
    let paused_at = Instant::now();
    h.suspend_node(3).unwrap();
    wait_status(
        h,
        1,
        paused_at + MAJORITY_DOWN_BOUND,
        "majority serving with node 3 down",
        |status, ready| ready && status["membership"]["members"]["3"]["liveness"] == "Down",
    );
    assert!(paused_at.elapsed() >= Duration::from_millis(RECOVER_MS));
    let topic = "recovery/majority";
    let publisher = on(h, 1, options("majority-publisher"), false);
    store_retained(h, publisher, topic, b"committed with node 3 suspended");
    expect_retained(h, 2, topic, b"committed with node 3 suspended");

    // A stopped process cannot fork while stopped. On resume it must join
    // the still-serving majority, not replace that majority with its history.
    h.resume_node(3).unwrap();
    wait_recovered_voters(h, &[1, 2, 3], 0);
    expect_retained(h, 3, topic, b"committed with node 3 suspended");
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn auto_recovery_discards_a_corrupt_wal_and_rejoins() {
    let h = &mut recovery_cluster(3, true);
    let topic = "recovery/wal";
    let leader = h.wait_for_leader(ELECTION).unwrap();
    let follower = if leader == 3 { 2 } else { 3 };
    let publisher = on(h, leader, options("wal-recovery-publisher"), false);
    store_retained(h, publisher, topic, b"healthy majority data");
    // Ensure the leader already recorded replication progress for the node
    // whose log will disappear, without deliberately changing leader.
    expect_retained(h, follower, topic, b"healthy majority data");
    h.kill_node(follower).unwrap();

    let data = h.node_cluster_data_dir(follower).unwrap();
    let chunk = fs::read_dir(data.join("wal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "wal"))
        .min()
        .expect("committed entries created a WAL chunk");
    let corrupt = [0xff; 4];
    // Overwrite the first record type rather than truncating the tail,
    // which the WAL normally tolerates after a crash.
    fs::OpenOptions::new()
        .write(true)
        .open(&chunk)
        .unwrap()
        .write_all(&corrupt)
        .unwrap();
    h.restart_node(follower).unwrap();
    wait_recovered_voters(h, &[1, 2, 3], 0);
    let discarded_chunk = data.join("discarded/wal").join(chunk.file_name().unwrap());
    assert!(fs::read(discarded_chunk).unwrap().starts_with(&corrupt));
    expect_retained(h, follower, topic, b"healthy majority data");
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn auto_recovery_discards_a_corrupt_snapshot_and_rejoins() {
    let h = &mut recovery_cluster(3, true);
    let topic = "recovery/snapshot";
    let publisher = on(h, 3, options("snapshot-recovery-publisher"), false);
    store_retained(h, publisher, topic, b"before snapshot");
    h.kill_node(1).unwrap();
    h.kill_node(2).unwrap();
    wait_fork(h, 3, 1, Instant::now() + RECOVERY_BOUND);
    h.restart_node(1).unwrap();
    h.restart_node(2).unwrap();
    wait_recovered_voters(h, &[1, 2, 3], 1);
    expect_retained(h, 1, topic, b"before snapshot");

    // Forking writes a snapshot locally on node 3, and the repaired nodes
    // now hold its state. Corrupt node 3 after the other two can serve it.
    h.kill_node(3).unwrap();
    let data = h.node_cluster_data_dir(3).unwrap();
    let snapshot = data.join("snapshot.mpk");
    assert!(snapshot.is_file(), "the fork did not create a snapshot");
    fs::write(snapshot, b"invalid snapshot header").unwrap();
    h.restart_node(3).unwrap();
    wait_recovered_voters(h, &[1, 2, 3], 1);
    assert_eq!(
        fs::read(data.join("discarded/snapshot.mpk")).unwrap(),
        b"invalid snapshot header"
    );
    expect_retained(h, 3, topic, b"before snapshot");
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn auto_recovery_rejoins_after_losing_a_staged_switch() {
    let h = &mut recovery_cluster(3, true);
    let leader = h.wait_for_leader(ELECTION).unwrap();
    let follower = leader % 3 + 1;
    let topic = "recovery/interrupted";
    let publisher = on(h, leader, options("switch-recovery-publisher"), false);
    store_retained(h, publisher, topic, b"before repair");
    expect_retained(h, follower, topic, b"before repair");
    h.kill_node(follower).unwrap();

    // The old WAL has been moved into the journal. The staged replacement
    // is missing; neither the live directory nor the journal is usable alone.
    let data = h.node_cluster_data_dir(follower).unwrap();
    let archive = data.join(".mqx-survivor-switch/archive");
    fs::create_dir_all(&archive).unwrap();
    fs::rename(data.join("wal"), archive.join("wal")).unwrap();
    store_retained(h, publisher, topic, b"while peer was down");

    h.restart_node(follower).unwrap();
    wait_recovered_voters(h, &[1, 2, 3], 0);
    expect_retained(h, follower, topic, b"while peer was down");
    let saved = data.join("discarded/interrupted-switch");
    assert!(saved.join("journal/archive/wal").is_dir());
    assert!(saved.join("node.mpk").is_file());
}

#[test]
#[ignore = "requires the real Mosquitto binary to exercise process lifecycle"]
fn mosquitto_process_can_be_killed_and_restarted() {
    let mut h = Harness::start(BrokerKind::Mosquitto, config(ANONYMOUS)).unwrap();
    let h = &mut h;
    let before = on(h, 1, options("before"), false);
    assert!(matches!(
        h.open_on(0, V311),
        Err(mqx_difftest::Error::NodeIndex { index: 0, nodes: 1 })
    ));
    assert!(matches!(
        h.restart_node(1),
        Err(mqx_difftest::Error::NodeRunning(1))
    ));
    h.kill_node(1).unwrap();
    closed(h, before);
    assert!(matches!(
        h.open_on(1, V311),
        Err(mqx_difftest::Error::NodeStopped(1))
    ));
    h.restart_node(1).unwrap();
    let after = on(h, 1, options("after"), false);
    disconnect(h, after);
}
