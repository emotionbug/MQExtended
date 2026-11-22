use std::thread;

use super::*;

// test/broker/05-session-expiry-v5.py; src/property_broker.c: property__process_disconnect.
scenario!(disconnect_session_expiry_override, config(ANONYMOUS));
fn disconnect_session_expiry_override(h: &mut Harness) {
    let settings = Connect {
        clean_start: false,
        properties: vec![Property::SessionExpiryInterval(1)],
        ..options("override-expiry")
    };
    let first = connect_with(h, settings.clone(), false);
    disconnect(
        h,
        first,
        R::NORMAL_DISCONNECTION,
        vec![Property::SessionExpiryInterval(10)],
    );
    thread::sleep(Duration::from_millis(2_200));
    let resumed = connect_with(h, settings.clone(), true);
    disconnect(
        h,
        resumed,
        R::NORMAL_DISCONNECTION,
        vec![Property::SessionExpiryInterval(0)],
    );
    let fresh = connect_with(h, settings, false);
    disconnect(h, fresh, R::NORMAL_DISCONNECTION, vec![]);

    let zero_expiry = client(h, "zero-expiry-cannot-increase");
    send(
        h,
        zero_expiry,
        Packet::Disconnect(ReasonProperties {
            reason: R::NORMAL_DISCONNECTION,
            properties: vec![Property::SessionExpiryInterval(10)],
        }),
    );
    expect_disconnect(h, zero_expiry, R::PROTOCOL_ERROR);
}

// test/broker/02-subpub-qos1-message-expiry.py; src/database.c: db__message_store and
// db__message_write_inflight_out_latest. One offline PUBLISH expires, the other ages.
scenario!(offline_message_expiry, config(ANONYMOUS), compare_expiry);
fn offline_message_expiry(h: &mut Harness) {
    let settings = Connect {
        clean_start: false,
        properties: vec![Property::SessionExpiryInterval(60)],
        ..options("offline-expiry")
    };
    let receiver = connect_with(h, settings.clone(), false);
    subscribe(h, receiver, 1, "offline/expiry", Q1);
    disconnect(h, receiver, R::NORMAL_DISCONNECTION, vec![]);

    let sender = client(h, "offline-expiry-publisher");
    for (mid, seconds, payload) in [(1, 1, b"expired".as_slice()), (2, 10, b"live".as_slice())] {
        publish_qos1(
            h,
            sender,
            Publish {
                properties: vec![Property::MessageExpiryInterval(seconds)],
                ..publication("offline/expiry", payload, Q1, mid)
            },
            R::SUCCESS,
        );
    }
    thread::sleep(Duration::from_secs(3));
    let receiver = connect_with(h, settings, true);
    let reading = read(h, receiver, RESPONSE);
    let Reading::ReceivedV5 {
        packet: Packet::Publish(message),
        ..
    } = reading
    else {
        panic!("expected a queued PUBLISH, got {reading:?}");
    };
    let [Property::MessageExpiryInterval(remaining)] = message.properties.as_slice() else {
        panic!("missing expiry interval in {message:?}");
    };
    // Mosquitto stores whole seconds. Allow tick rounding and reconnect latency, never 10.
    assert!(
        (5..=8).contains(remaining),
        "expiry was not decremented as expected: {message:?}"
    );
    assert_eq!(
        message,
        &Publish {
            properties: vec![Property::MessageExpiryInterval(*remaining)],
            ..publication("offline/expiry", b"live", Q1, 2)
        }
    );
    send(h, receiver, Packet::PubAck(ack(2, R::SUCCESS)));
    ping(h, receiver);
}

fn compare_expiry(expected: &Transcript, actual: &Transcript) {
    compare_variable_property(expected, actual, |packet| {
        if let Packet::Publish(message) = packet {
            for property in &mut message.properties {
                if let Property::MessageExpiryInterval(seconds) = property {
                    *seconds = 7;
                }
            }
        }
    });
}

const WILL_TOPIC: &str = "will/events";
const WILL_PAYLOAD: &[u8] = b"gone";

fn will_settings(client_id: &str, delay: Option<u32>) -> Connect {
    Connect {
        properties: delay
            .into_iter()
            .map(|_| Property::SessionExpiryInterval(60))
            .collect(),
        will: Some(LastWill {
            properties: vec![Property::ContentType("text/plain".into())]
                .into_iter()
                .chain(delay.map(Property::WillDelayInterval))
                .collect(),
            topic: WILL_TOPIC.into(),
            payload: Bytes::from_static(WILL_PAYLOAD),
            qos: Q2,
            retain: false,
        }),
        ..options(client_id)
    }
}

fn will_publication() -> Packet {
    Packet::Publish(Publish {
        properties: vec![Property::ContentType("text/plain".into())],
        ..publication(WILL_TOPIC, WILL_PAYLOAD, Q0, 0)
    })
}

// test/broker/07-will-delay.py and 07-will-properties.py; src/context.c: context__send_will.
scenario!(delayed_will, config(ANONYMOUS));
fn delayed_will(h: &mut Harness) {
    let watcher = client(h, "delayed-will-watcher");
    subscribe(h, watcher, 1, WILL_TOPIC, Q0);
    let owner = connect_with(h, will_settings("delayed-will-owner", Some(2)), false);
    h.close_socket(owner);
    assert_eq!(
        read(h, watcher, Duration::from_millis(700)),
        &Reading::TimedOut,
        "Will was not delayed"
    );
    received_within(h, watcher, will_publication(), Duration::from_secs(6));
    ping(h, watcher);
}

// test/broker/07-will-delay-reconnect.py; src/handle_connect.c: connect__on_authorised
// clears an old delayed Will when resuming the session.
scenario!(delayed_will_cancelled_on_resume, config(ANONYMOUS));
fn delayed_will_cancelled_on_resume(h: &mut Harness) {
    let watcher = client(h, "cancelled-will-watcher");
    subscribe(h, watcher, 1, WILL_TOPIC, Q0);
    let owner = connect_with(h, will_settings("cancelled-will-owner", Some(2)), false);
    h.close_socket(owner);
    silent(h, watcher);
    let owner = connect_with(
        h,
        Connect {
            clean_start: false,
            ..options("cancelled-will-owner")
        },
        true,
    );
    assert_eq!(
        read(h, watcher, Duration::from_secs(4)),
        &Reading::TimedOut,
        "old Will was not cancelled"
    );
    h.close_socket(owner);
    ping(h, watcher);
}

// test/broker/07-will-disconnect-with-will.py and 01-connect-disconnect-v5.py;
// src/handle_disconnect.c: handle__disconnect distinguishes reason 0x04 from reason 0x00.
scenario!(client_disconnect_with_will, config(ANONYMOUS));
fn client_disconnect_with_will(h: &mut Harness) {
    let watcher = client(h, "explicit-will-watcher");
    subscribe(h, watcher, 1, WILL_TOPIC, Q0);
    let settings = will_settings("explicit-will-owner", None);
    let owner = connect_with(h, settings.clone(), false);
    disconnect(
        h,
        owner,
        R::NORMAL_DISCONNECTION,
        vec![Property::UserProperty("normal".into(), "bye".into())],
    );
    silent(h, watcher);
    let owner = connect_with(h, settings, false);
    disconnect(h, owner, R::DISCONNECT_WITH_WILL_MESSAGE, vec![]);
    received(h, watcher, will_publication());
}

// test/broker/01-connect-take-over.py; src/handle_connect.c: connect__on_authorised.
scenario!(server_takeover_disconnect, config(ANONYMOUS));
fn server_takeover_disconnect(h: &mut Harness) {
    let settings = Connect {
        properties: vec![Property::SessionExpiryInterval(60)],
        ..options("replace-v5-owner")
    };
    let old = connect_with(h, settings.clone(), false);
    let new = connect_with(
        h,
        Connect {
            clean_start: false,
            ..settings
        },
        true,
    );
    expect_disconnect(h, old, R::SESSION_TAKEN_OVER);
    ping(h, new);
}

// Extend test/broker/07-will-qos0.py to an idle v5 client. src/keepalive.c: keepalive__check
// calls do_disconnect directly, so Mosquitto closes without sending 0x8D.
scenario!(keepalive_timeout_closes_without_reason, config(ANONYMOUS));
fn keepalive_timeout_closes_without_reason(h: &mut Harness) {
    let watcher = client(h, "idle-will-watcher");
    subscribe(h, watcher, 1, WILL_TOPIC, Q0);
    let idle = connect_with(
        h,
        Connect {
            keep_alive: 1,
            ..will_settings("idle-v5", None)
        },
        false,
    );
    ping(h, idle);
    assert_eq!(
        read(h, idle, Duration::from_secs(7)),
        &Reading::Closed,
        "expected EOF, not DISCONNECT 0x8D"
    );
    received(h, watcher, will_publication());
}

#[test]
#[ignore = "requires cluster-enabled mqextended"]
fn persistent_qos2_pubrel_and_unsent_qos1_resume_after_kill() {
    let mut h = crate::start_cluster(config(ANONYMOUS));
    let h = &mut h;
    let settings = Connect {
        clean_start: false,
        properties: vec![
            Property::SessionExpiryInterval(60),
            Property::ReceiveMaximum(1),
        ],
        ..options("durable-v5")
    };
    let receiver = h.open_v5_on(2).unwrap();
    send(h, receiver, Packet::Connect(settings.clone()));
    connack(h, receiver, false, connack_properties());
    let topic = "failover/qos2";
    subscribe(h, receiver, 1, topic, Q2);

    let publisher = h.open_on(1, crate::V311).unwrap();
    crate::send(
        h,
        publisher,
        crate::Packet::Connect(crate::options("source")),
    );
    crate::connack(h, publisher, crate::Accepted, false);
    crate::publish_from(h, publisher, crate::publish(topic, b"qos2", Q2, 10));
    received(
        h,
        receiver,
        Packet::Publish(publication(topic, b"qos2", Q2, 1)),
    );
    send(h, receiver, Packet::PubRec(ack(1, R::SUCCESS)));
    received(h, receiver, Packet::PubRel(ack(1, R::SUCCESS)));
    crate::publish_from(h, publisher, crate::publish(topic, b"queued", Q1, 11));

    h.kill_node(2).unwrap();
    closed(h, receiver);
    let receiver = h.open_v5_on(3).unwrap();
    send(h, receiver, Packet::Connect(settings));
    connack(h, receiver, true, connack_properties());
    // database.c: db__message_reconnect_reset_outgoing resumes PUBREL
    // after PUBREC, and an unattempted PUBLISH starts with DUP clear.
    received(h, receiver, Packet::PubRel(ack(1, R::SUCCESS)));
    send(h, receiver, Packet::PubComp(ack(1, R::SUCCESS)));
    received(
        h,
        receiver,
        Packet::Publish(publication(topic, b"queued", Q1, 2)),
    );
    send(h, receiver, Packet::PubAck(ack(2, R::SUCCESS)));
    ping(h, receiver);
}
