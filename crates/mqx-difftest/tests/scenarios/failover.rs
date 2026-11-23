use std::time::Instant;

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
    let mut h = start_cluster(config(ANONYMOUS));
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
    subscribe(h, fresh, 2, &[(retained, Q1)]);
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
