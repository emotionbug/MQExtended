use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Instant;

use super::sessions::{persistent, with_will};
use super::*;

const RELOAD_NODE: usize = 1;
// A SIGHUP can take a replicated write deadline followed by local apply.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(11);

fn observer_node(h: &Harness) -> usize {
    match h.node_addr(2) {
        Ok(_) => 2,
        Err(mqx_difftest::Error::NodeIndex { nodes: 1, .. }) => RELOAD_NODE,
        Err(err) => panic!("could not locate observer node: {err}"),
    }
}

#[track_caller]
fn connect_on(
    h: &mut Harness,
    node: usize,
    settings: Connect,
    session_present: bool,
) -> Connection {
    let c = h.open_on(node, settings.protocol).unwrap();
    send(h, c, Packet::Connect(settings));
    connack(h, c, Accepted, session_present);
    c
}

fn probe_connack(addr: SocketAddr, connect: &[u8], timeout: Duration) -> io::Result<[u8; 4]> {
    let mut socket = TcpStream::connect_timeout(&addr, timeout)?;
    socket.set_write_timeout(Some(timeout))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.write_all(connect)?;
    let mut ack = [0; 4];
    socket.read_exact(&mut ack)?;
    Ok(ack)
}

#[track_caller]
fn reload(h: &mut Harness, observer: usize, conf: &str) {
    // SIGHUP has no completion ACK (signals.c: signal__flag_check). Probe
    // client ID rejection on both nodes without adding to either transcript.
    // Both brokers check the prefix before will__read rejects a $CONTROL/
    // will, so even a pre-reload probe never creates a replicated session.
    h.reload_node(
        RELOAD_NODE,
        &format!("{ANONYMOUS}\nclientid_prefixes reload-\n{conf}"),
    )
    .unwrap();
    let mut connect = BytesMut::new();
    encode(
        &Packet::Connect(with_will("outside-prefix-probe", "$CONTROL/reload-probe")),
        &mut connect,
    )
    .unwrap();
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    for node in RELOAD_NODE..=observer {
        let addr = h.node_addr(node).unwrap();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let observed = probe_connack(
                addr,
                &connect,
                remaining.clamp(Duration::from_millis(1), Duration::from_millis(250)),
            );
            if matches!(observed, Ok([0x20, 2, 0, 5])) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "node {node} did not apply the new client ID prefix: {observed:?}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

// Extends test/broker/02-subpub-qos1-oversize-payload.py to SIGHUP.
scenario!(connected_publish_limit_changes, config(ANONYMOUS));
fn connected_publish_limit_changes(h: &mut Harness) {
    let observer = observer_node(h);
    let sender = connect_on(h, observer, options("reload-sender"), false);
    let receiver = connect_on(h, RELOAD_NODE, options("reload-receiver"), false);
    let topic = "reload/payload";
    subscribe(h, receiver, 1, &[(topic, Q1)]);
    publish_from(h, sender, publish(topic, b"AB", Q1, 10));
    accept_publish(h, receiver, publish(topic, b"AB", Q1, 1));

    reload(h, observer, "message_size_limit 1");
    // handle_publish.c: handle__publish drops the oversized payload;
    // process_bad_message still sends a normal MQTT 3.1.1 PUBACK with MID 11.
    publish_from(h, sender, publish(topic, b"AB", Q1, 11));
    publish_from(h, sender, publish(topic, b"A", Q1, 12));
    accept_publish(h, receiver, publish(topic, b"A", Q1, 2));
}

// Extends test/broker/15-persist-client-msg-out-queue-v3-1-1.py to SIGHUP.
scenario!(offline_qos0_starts_queueing, config(ANONYMOUS));
fn offline_qos0_starts_queueing(h: &mut Harness) {
    let observer = observer_node(h);
    let settings = persistent("reload-durable");
    let receiver = connect_on(h, observer, settings.clone(), false);
    let sender = connect_on(h, observer, options("reload-sender"), false);
    let topic = "reload/offline";
    subscribe(h, receiver, 1, &[(topic, Q0)]);
    disconnect(h, receiver);

    publish_from(h, sender, publish(topic, b"discarded", Q0, 0));
    reload(h, observer, "queue_qos0_messages true");
    // database.c: db__message_insert_outgoing reads the flag at each enqueue.
    publish_from(h, sender, publish(topic, b"queued", Q0, 0));
    let receiver = connect_on(h, observer, settings, true);
    accept_publish(h, receiver, publish(topic, b"queued", Q0, 0));
    ping(h, receiver);
}

// Extends test/broker/04-retain-upgrade-outgoing-qos.py with live SIGHUP routing.
scenario!(live_outgoing_qos_is_upgraded, config(ANONYMOUS));
fn live_outgoing_qos_is_upgraded(h: &mut Harness) {
    let observer = observer_node(h);
    let sender = connect_on(h, observer, options("reload-sender"), false);
    let receiver = connect_on(h, RELOAD_NODE, options("reload-receiver"), false);
    let topic = "reload/upgrade";
    subscribe(h, receiver, 1, &[(topic, Q1)]);
    publish_from(h, sender, publish(topic, b"before", Q0, 0));
    accept_publish(h, receiver, publish(topic, b"before", Q0, 0));

    reload(h, observer, "upgrade_outgoing_qos true");
    // subs.c: subs__send now uses the QoS of the existing subscription.
    publish_from(h, sender, publish(topic, b"after", Q0, 0));
    accept_publish(h, receiver, publish(topic, b"after", Q1, 1));
}

// Extends test/broker/03-pattern-matching.py with a live deduplication change.
scenario!(
    overlapping_subscriptions_start_deduplicating,
    config(ANONYMOUS)
);
fn overlapping_subscriptions_start_deduplicating(h: &mut Harness) {
    let observer = observer_node(h);
    let sender = connect_on(h, observer, options("reload-sender"), false);
    let receiver = connect_on(h, observer, options("reload-receiver"), false);
    let topic = "reload/overlap";
    subscribe(h, receiver, 1, &[("reload/#", Q1), (topic, Q1)]);
    publish_from(h, sender, publish(topic, b"before", Q1, 10));
    accept_publish(h, receiver, publish(topic, b"before", Q1, 1));
    accept_publish(h, receiver, publish(topic, b"before", Q1, 2));

    reload(h, observer, "allow_duplicate_messages false");
    // database.c: db__message_insert_outgoing suppresses the second copy for MQTT 3.1.1.
    publish_from(h, sender, publish(topic, b"after", Q1, 11));
    accept_publish(h, receiver, publish(topic, b"after", Q1, 3));
    silent(h, receiver);
}

scenario!(
    session_expiry_changes_at_disconnect,
    config("allow_anonymous true\npersistent_client_expiration 1h")
);
fn session_expiry_changes_at_disconnect(h: &mut Harness) {
    let observer = observer_node(h);
    let offline = persistent("reload-already-offline");
    let online = persistent("reload-still-online");
    let c = connect_on(h, observer, offline.clone(), false);
    disconnect(h, c);
    let c = connect_on(h, observer, online.clone(), false);

    reload(h, observer, "persistent_client_expiration 1s");
    disconnect(h, c);
    // session_expiry.c: session_expiry__add schedules at disconnect, and
    // session_expiry__check expires only when the whole-second clock exceeds
    // the deadline. Reconnecting to poll would reschedule the session instead.
    thread::sleep(Duration::from_secs(3));
    connect_on(h, observer, offline, true);
    connect_on(h, observer, online, false);
}

#[test]
#[ignore = "requires standalone and clustered mqextended brokers"]
fn session_expiry_never_applies_on_reload_at_next_disconnect() {
    const CONF: &str = "allow_anonymous true\npersistent_client_expiration 1s";
    let finite = persistent("reload-finite");
    let durable = persistent("reload-durable");
    let mut standalone = Harness::start(BrokerKind::MqExtended, config(CONF)).unwrap();
    let mut cluster = start_cluster(config(CONF));
    for h in [&mut standalone, &mut cluster] {
        let observer = observer_node(h);
        let c = connect_on(h, observer, finite.clone(), false);
        disconnect(h, c);
        let c = connect_on(h, observer, durable.clone(), false);
        reload(h, observer, "persistent_client_expiration never");
        disconnect(h, c);
    }
    // Cross the old deadline without reconnecting (which would change it).
    // The pre-reload disconnect proves the finite expiry still takes effect.
    thread::sleep(Duration::from_secs(3));
    for h in [&mut standalone, &mut cluster] {
        let node = observer_node(h);
        connect_on(h, node, finite.clone(), false);
        connect_on(h, node, durable.clone(), true);
    }
}

scenario!(client_id_prefix_changes_for_next_connect, config(ANONYMOUS));
fn client_id_prefix_changes_for_next_connect(h: &mut Harness) {
    let observer = observer_node(h);
    let legacy = connect_on(h, observer, options("legacy-id"), false);

    reload(h, observer, "");
    // handle_connect.c: check_clientid_prefixes only runs during CONNECT.
    ping(h, legacy);
    let refused = h.open_on(observer, V311).unwrap();
    send(h, refused, Packet::Connect(options("legacy-new-id")));
    connack(h, refused, NotAuthorized, false);
    closed(h, refused);
    connect_on(h, observer, options("reload-new-id"), false);
}

scenario!(
    offline_queue_capacity_keeps_startup_limit,
    config("allow_anonymous true\nmax_queued_messages 2")
);
fn offline_queue_capacity_keeps_startup_limit(h: &mut Harness) {
    let observer = observer_node(h);
    let settings = persistent("reload-durable");
    let topic = "reload/capacity";
    let receiver = connect_on(h, observer, settings.clone(), false);
    subscribe(h, receiver, 1, &[(topic, Q1)]);
    disconnect(h, receiver);

    reload(h, observer, "max_queued_messages 1");
    let sender = connect_on(h, RELOAD_NODE, options("reload-sender"), false);
    for (mid, payload) in [
        (10, &b"first"[..]),
        (11, &b"second"[..]),
        (12, &b"third"[..]),
    ] {
        publish_from(h, sender, publish(topic, payload, Q1, mid));
    }
    // conf.c: config__copy leaves the limit used by database.c: db__ready_for_queue alone.
    let receiver = connect_on(h, observer, settings, true);
    accept_publish(h, receiver, publish(topic, b"first", Q1, 1));
    accept_publish(h, receiver, publish(topic, b"second", Q1, 2));
    ping(h, receiver);
}

scenario!(
    retained_publish_keeps_startup_availability,
    config("allow_anonymous true\nretain_available true")
);
fn retained_publish_keeps_startup_availability(h: &mut Harness) {
    let observer = observer_node(h);
    reload(h, observer, "retain_available false");
    let sender = connect_on(h, RELOAD_NODE, options("reload-sender"), false);
    let receiver = connect_on(h, observer, options("reload-receiver"), false);
    let topic = "reload/retained";
    let mut retained = publish(topic, b"still enabled", Q1, 10);
    retained.retain = true;
    // conf.c: config__copy leaves the retain gate in handle_publish.c: handle__publish alone.
    publish_from(h, sender, retained);
    subscribe(h, receiver, 1, &[(topic, Q1)]);
    let mut replay = publish(topic, b"still enabled", Q1, 1);
    replay.retain = true;
    accept_publish(h, receiver, replay);
}
