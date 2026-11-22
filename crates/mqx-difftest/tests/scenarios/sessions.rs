use super::*;

pub(super) fn persistent(client_id: &str) -> Connect {
    Connect {
        clean_session: false,
        ..options(client_id)
    }
}

// test/broker/15-persist-client-msg-out-queue-v3-1-1.py, plus a case enabling QoS 0 queueing.
scenario!(
    offline_queue_qos1_and_qos2,
    config("allow_anonymous true\nqueue_qos0_messages false")
);
fn offline_queue_qos1_and_qos2(h: &mut Harness) {
    offline_queue(h, false);
}

scenario!(
    offline_queue_qos0_enabled,
    config("allow_anonymous true\nqueue_qos0_messages true")
);
fn offline_queue_qos0_enabled(h: &mut Harness) {
    offline_queue(h, true);
}

fn offline_queue(h: &mut Harness, queue_qos0: bool) {
    let settings = persistent("queue");
    let subscriber = connect_with(h, settings.clone(), false);
    subscribe(h, subscriber, 1, &[("queue/#", Q2)]);
    disconnect(h, subscriber);

    let publisher = client(h, "publisher");
    publish_from(h, publisher, publish("queue/0", b"first", Q0, 0));
    publish_from(h, publisher, publish("queue/1", b"second", Q1, 17));
    publish_from(h, publisher, publish("queue/2", b"third", Q2, 18));
    let subscriber = connect_with(h, settings.clone(), true);
    // src/database.c: db__message_insert_outgoing discards offline QoS 0 by default.
    if queue_qos0 {
        accept_publish(h, subscriber, publish("queue/0", b"first", Q0, 0));
    }
    accept_publish(h, subscriber, publish("queue/1", b"second", Q1, 1));
    accept_publish(h, subscriber, publish("queue/2", b"third", Q2, 2));
    ping(h, subscriber);
    disconnect(h, subscriber);

    let subscriber = connect_with(h, settings, true);
    ping(h, subscriber); // Acknowledged packets are no longer queued.
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// Extends test/broker/15-persist-client-msg-out-queue-v3-1-1.py with max_queued_messages.
scenario!(
    offline_queue_overflow,
    config("allow_anonymous true\nmax_queued_messages 2")
);
fn offline_queue_overflow(h: &mut Harness) {
    let settings = persistent("queue-overflow");
    let subscriber = connect_with(h, settings.clone(), false);
    let topic = "queue/overflow";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    disconnect(h, subscriber);
    let publisher = client(h, "publisher");
    for (mid, payload) in [
        (51, &b"first"[..]),
        (52, &b"second"[..]),
        (53, &b"dropped"[..]),
    ] {
        publish_from(h, publisher, publish(topic, payload, Q1, mid));
    }
    let subscriber = connect_with(h, settings, true);
    // src/database.c: db__ready_for_queue rejects newer messages when the queue is full.
    accept_publish(h, subscriber, publish(topic, b"first", Q1, 1));
    accept_publish(h, subscriber, publish(topic, b"second", Q1, 2));
    ping(h, subscriber);
    // src/subs.c: subs__send allocates the packet id even for the dropped message.
    publish_from(h, publisher, publish(topic, b"live", Q1, 54));
    accept_publish(h, subscriber, publish(topic, b"live", Q1, 4));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/05-clean-session-qos1.py; check both queued packets and subscription state.
scenario!(clean_session_discards_state, config(ANONYMOUS));
fn clean_session_discards_state(h: &mut Harness) {
    let settings = persistent("clear-me");
    let subscriber = connect_with(h, settings.clone(), false);
    let topic = "clear/session";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    disconnect(h, subscriber);
    let publisher = client(h, "publisher");
    publish_from(h, publisher, publish(topic, b"queued", Q1, 33));
    let subscriber = connect_with(h, settings.clone(), true);
    received(
        h,
        subscriber,
        Packet::Publish(publish(topic, b"queued", Q1, 1)),
    );
    // Leave the message unacknowledged, so a clean reconnect has state to discard.
    disconnect(h, subscriber);
    let clean = client(h, "clear-me");
    ping(h, clean);
    publish_from(h, publisher, publish(topic, b"not subscribed", Q1, 34));
    ping(h, clean);
    disconnect(h, clean);
    let subscriber = connect_with(h, settings, false);
    ping(h, subscriber);
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// Extends test/broker/15-persist-client-v3-1-1.py to v3.1 using the same session.
scenario!(session_present_only_in_v311, config(ANONYMOUS));
fn session_present_only_in_v311(h: &mut Harness) {
    let mut settings = Connect {
        protocol: V31,
        ..persistent("legacy")
    };
    let subscriber = connect_with(h, settings.clone(), false);
    let topic = "legacy/session";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    disconnect(h, subscriber);
    let publisher = client(h, "publisher");
    publish_from(h, publisher, publish(topic, b"offline", Q1, 19));
    // src/handle_connect.c: connect__on_authorised restores the session but does not
    // set CONNACK session_present for v3.1.
    let subscriber = connect_with(h, settings.clone(), false);
    accept_publish(h, subscriber, publish(topic, b"offline", Q1, 1));
    disconnect(h, subscriber);
    settings.protocol = V311;
    let subscriber = connect_with(h, settings, true);
    ping(h, subscriber);
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/03-publish-b2c-disconnect-qos1.py.
scenario!(resend_qos1_after_reconnect, config(ANONYMOUS));
fn resend_qos1_after_reconnect(h: &mut Harness) {
    let settings = persistent("redelivery");
    let subscriber = connect_with(h, settings.clone(), false);
    let publisher = client(h, "publisher");
    let topic = "resend/one";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    publish_from(h, publisher, publish(topic, b"retry", Q1, 31));
    let outbound = publish(topic, b"retry", Q1, 1);
    received(h, subscriber, Packet::Publish(outbound.clone()));
    disconnect(h, subscriber);
    let subscriber = connect_with(h, settings.clone(), true);
    accept_publish(
        h,
        subscriber,
        Publish {
            dup: true,
            ..outbound
        },
    );
    disconnect(h, subscriber);
    let subscriber = connect_with(h, settings, true);
    ping(h, subscriber);
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/03-publish-b2c-disconnect-qos2.py and 15-persist-client-msg-out-dup-v3-1-1.py.
scenario!(resume_outbound_qos2_after_reconnect, config(ANONYMOUS));
fn resume_outbound_qos2_after_reconnect(h: &mut Harness) {
    let settings = persistent("redelivery");
    let subscriber = connect_with(h, settings.clone(), false);
    let publisher = client(h, "publisher");
    let topic = "resend/two";
    subscribe(h, subscriber, 1, &[(topic, Q2)]);
    publish_from(h, publisher, publish(topic, b"retry", Q2, 31));
    let outbound = publish(topic, b"retry", Q2, 1);
    received(h, subscriber, Packet::Publish(outbound.clone()));
    disconnect(h, subscriber);
    let subscriber = connect_with(h, settings.clone(), true);
    received(
        h,
        subscriber,
        Packet::Publish(Publish {
            dup: true,
            ..outbound
        }),
    );
    send(h, subscriber, Packet::PubRec(id(1)));
    received(h, subscriber, Packet::PubRel(id(1)));
    disconnect(h, subscriber);
    let subscriber = connect_with(h, settings, true);
    // src/database.c: db__message_reconnect_reset_outgoing resumes at PUBREL after PUBREC.
    received(h, subscriber, Packet::PubRel(id(1)));
    send(h, subscriber, Packet::PubComp(id(1)));
    ping(h, subscriber);
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/03-publish-c2b-disconnect-qos2.py and 15-persist-client-msg-in-v3-1-1.py.
scenario!(resume_inbound_qos2_after_reconnect, config(ANONYMOUS));
fn resume_inbound_qos2_after_reconnect(h: &mut Harness) {
    let settings = persistent("publisher");
    let publisher = connect_with(h, settings.clone(), false);
    let subscriber = client(h, "subscriber");
    let topic = "resume/inbound";
    subscribe(h, subscriber, 1, &[(topic, Q2)]);
    send(
        h,
        publisher,
        Packet::Publish(publish(topic, b"held", Q2, 31)),
    );
    received(h, publisher, Packet::PubRec(id(31)));
    disconnect(h, publisher);
    ping(h, subscriber);
    let publisher = connect_with(h, settings, true);
    send(h, publisher, Packet::PubRel(id(31)));
    received(h, publisher, Packet::PubComp(id(31)));
    accept_publish(h, subscriber, publish(topic, b"held", Q2, 1));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/01-connect-take-over.py, translated to MQTT 3.x (socket close, no DISCONNECT packet).
scenario!(same_id_takeover, config(ANONYMOUS));
fn same_id_takeover(h: &mut Harness) {
    let first = client(h, "owner");
    let second = client(h, "owner");
    closed(h, first);
    ping(h, second);
    disconnect(h, second);
}

pub(super) fn with_will(client_id: &str, topic: &str) -> Connect {
    Connect {
        will: Some(LastWill {
            topic: topic.into(),
            payload: Bytes::from_static(b"LWT"),
            qos: Q0,
            retain: false,
        }),
        ..options(client_id)
    }
}

// test/broker/07-will-qos0.py.
scenario!(will_on_socket_close_and_retained, config(ANONYMOUS));
fn will_on_socket_close_and_retained(h: &mut Harness) {
    let subscriber = client(h, "watcher");
    let topic = "will/lost";
    subscribe(h, subscriber, 53, &[(topic, Q0)]);
    let mut settings = with_will("lost", topic);
    settings.will.as_mut().unwrap().retain = true;
    let dying = connect_with(h, settings, false);
    h.close_socket(dying);
    accept_publish(h, subscriber, publish(topic, b"LWT", Q0, 0));
    let late = client(h, "late");
    subscribe(h, late, 53, &[(topic, Q0)]);
    accept_publish(
        h,
        late,
        Publish {
            retain: true,
            ..publish(topic, b"LWT", Q0, 0)
        },
    );
    disconnect(h, late);
    disconnect(h, subscriber);
}

// Extends test/broker/07-will-qos0.py: src/keepalive.c: keepalive__check disconnects idle clients.
scenario!(will_on_keepalive_timeout, config(ANONYMOUS));
fn will_on_keepalive_timeout(h: &mut Harness) {
    let subscriber = client(h, "watcher");
    let topic = "will/keepalive";
    subscribe(h, subscriber, 1, &[(topic, Q0)]);
    let dying = connect_with(
        h,
        Connect {
            keep_alive: 1,
            ..with_will("idle", topic)
        },
        false,
    );
    silent(h, dying); // Don't accept an immediate close in place of keepalive expiry.
    // Mosquitto advances integer-second timers and may sleep for five seconds.
    assert_eq!(read(h, dying, Duration::from_secs(8)), &Reading::Closed);
    h.close_socket(dying);
    accept_publish(h, subscriber, publish(topic, b"LWT", Q0, 0));
    disconnect(h, subscriber);
}

// test/broker/07-will-takeover.py (the four pairs of clean-session settings).
scenario!(will_on_takeover, config(ANONYMOUS));
fn will_on_takeover(h: &mut Harness) {
    let subscriber = client(h, "watcher");
    let topic = "will/takeover";
    subscribe(h, subscriber, 1, &[(topic, Q0)]);
    for (index, (old_clean, new_clean)) in
        [(true, true), (true, false), (false, true), (false, false)]
            .into_iter()
            .enumerate()
    {
        let old = Connect {
            clean_session: old_clean,
            ..with_will(&format!("taken-{index}"), topic)
        };
        let new = Connect {
            clean_session: new_clean,
            will: None,
            ..old.clone()
        };
        let old = connect_with(h, old, false);
        let new = connect_with(h, new, !old_clean && !new_clean);
        closed(h, old);
        // src/handle_connect.c: connect__on_authorised suppresses the old will only
        // when both sessions are persistent.
        if old_clean || new_clean {
            accept_publish(h, subscriber, publish(topic, b"LWT", Q0, 0));
        }
        publish_from(h, new, publish(topic, b"new owner", Q0, 0));
        accept_publish(h, subscriber, publish(topic, b"new owner", Q0, 0));
        disconnect(h, new);
    }
    disconnect(h, subscriber);
}

// Complements test/broker/07-will-qos0.py. src/handle_disconnect.c: handle__disconnect
// marks a graceful disconnect before context__send_will runs (src/context.c).
scenario!(no_will_on_disconnect, config(ANONYMOUS));
fn no_will_on_disconnect(h: &mut Harness) {
    let subscriber = client(h, "watcher");
    let topic = "will/graceful";
    subscribe(h, subscriber, 1, &[(topic, Q0)]);
    let mut settings = with_will("graceful", topic);
    settings.will.as_mut().unwrap().retain = true;
    let dying = connect_with(h, settings, false);
    disconnect(h, dying);
    ping(h, subscriber);
    unsubscribe(h, subscriber, 2, topic);
    subscribe(h, subscriber, 3, &[(topic, Q0)]);
    ping(h, subscriber); // The will was neither delivered nor retained.
    disconnect(h, subscriber);
}

// Complements the inbound limit in test/broker/03-publish-qos1-max-inflight.py.
scenario!(
    outgoing_inflight_window,
    config("allow_anonymous true\nmax_inflight_messages 1")
);
fn outgoing_inflight_window(h: &mut Harness) {
    let subscriber = client(h, "slow");
    let publisher = client(h, "publisher");
    let topic = "inflight/one";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    for (mid, payload) in [
        (70, &b"first"[..]),
        (71, &b"second"[..]),
        (72, &b"third"[..]),
    ] {
        publish_from(h, publisher, publish(topic, payload, Q1, mid));
    }
    // src/database.c: db__ready_for_flight holds later QoS 1 packets until PUBACK frees a slot.
    received(
        h,
        subscriber,
        Packet::Publish(publish(topic, b"first", Q1, 1)),
    );
    silent(h, subscriber);
    send(h, subscriber, Packet::PubAck(id(1)));
    received(
        h,
        subscriber,
        Packet::Publish(publish(topic, b"second", Q1, 2)),
    );
    silent(h, subscriber);
    send(h, subscriber, Packet::PubAck(id(2)));
    accept_publish(h, subscriber, publish(topic, b"third", Q1, 3));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}
