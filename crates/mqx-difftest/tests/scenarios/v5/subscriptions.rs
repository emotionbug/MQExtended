use super::super as v3;
use super::*;

const LEGACY_DEDUP: &str = "allow_anonymous true\nallow_duplicate_messages false";

#[track_caller]
fn subscribe_identified(
    h: &mut Harness,
    client: Connection,
    mid: u16,
    subscriptions: Vec<Subscription>,
    identifier: u32,
) {
    subscribe_with(
        h,
        client,
        mid,
        subscriptions,
        vec![Property::SubscriptionIdentifier(identifier)],
    );
}

#[track_caller]
fn accept_identified_publish(
    h: &mut Harness,
    client: Connection,
    mut message: Publish,
    identifier: u32,
) {
    let mid = message.packet_id;
    message
        .properties
        .push(Property::SubscriptionIdentifier(identifier));
    received(h, client, Packet::Publish(message));
    if let Some(mid) = mid {
        send(h, client, Packet::PubAck(ack(mid.get(), R::SUCCESS)));
    }
}

#[track_caller]
fn unsubscribe_filter(h: &mut Harness, client: Connection, mid: u16, filter: &str) {
    send(
        h,
        client,
        Packet::Unsubscribe(Unsubscribe {
            packet_id: id(mid),
            properties: vec![],
            filters: vec![filter.into()],
        }),
    );
    received(
        h,
        client,
        Packet::UnsubAck(SubscriptionAck {
            packet_id: id(mid),
            reasons: vec![R::SUCCESS],
            properties: vec![],
        }),
    );
}

// test/broker/11-persistent-subscription-no-local.py; src/subs.c: subs__process.
scenario!(subscription_no_local, config(ANONYMOUS));
fn subscription_no_local(h: &mut Harness) {
    let receiver = client(h, "no-local-receiver");
    subscribe_with(
        h,
        receiver,
        1,
        vec![Subscription {
            no_local: true,
            ..subscription("no/local", Q0)
        }],
        vec![],
    );
    send(
        h,
        receiver,
        Packet::Publish(publication("no/local", b"self", Q0, 0)),
    );
    ping(h, receiver);

    let publisher = client(h, "no-local-publisher");
    let remote = Packet::Publish(publication("no/local", b"remote", Q0, 0));
    send(h, publisher, remote.clone());
    received(h, receiver, remote);
}

// test/broker/06-bridge-outgoing-retain.py; src/subs.c: subs__send also applies
// Retain As Published to ordinary v5 clients.
scenario!(subscription_retain_as_published, config(ANONYMOUS));
fn subscription_retain_as_published(h: &mut Harness) {
    let preserve = client(h, "preserve-retain");
    subscribe_with(
        h,
        preserve,
        1,
        vec![Subscription {
            retain_as_published: true,
            ..subscription("retain/as-published", Q0)
        }],
        vec![],
    );
    let clear = client(h, "clear-retain");
    subscribe(h, clear, 1, "retain/as-published", Q0);
    let publisher = client(h, "publish-retained");
    let message = publication("retain/as-published", b"live retained", Q0, 0);
    let retained = Packet::Publish(Publish {
        retain: true,
        ..message.clone()
    });
    send(h, publisher, retained.clone());
    received(h, preserve, retained);
    received(h, clear, Packet::Publish(message));
}

// test/broker/02-subpub-qos0-send-retain.py; src/subs.c: sub__add_context and
// src/handle_subscribe.c: handle__subscribe.
scenario!(subscription_retain_handling, config(ANONYMOUS));
fn subscription_retain_handling(h: &mut Harness) {
    let publisher = client(h, "retain-handling-publisher");
    let receiver = client(h, "retain-handling-receiver");
    for (topic, handling, replay_first, replay_second) in [
        ("retain/always", RetainHandling::SendAlways, true, true),
        ("retain/new", RetainHandling::SendIfNew, true, false),
        ("retain/never", RetainHandling::DoNotSend, false, false),
    ] {
        let retained = Packet::Publish(Publish {
            retain: true,
            ..publication(topic, b"retained", Q0, 0)
        });
        send(h, publisher, retained.clone());
        ping(h, publisher);
        for (mid, replay) in [(1, replay_first), (2, replay_second)] {
            subscribe_with(
                h,
                receiver,
                mid,
                vec![Subscription {
                    retain_handling: handling,
                    ..subscription(topic, Q0)
                }],
                vec![],
            );
            if replay {
                received(h, receiver, retained.clone());
            } else {
                silent(h, receiver);
            }
        }
    }
}

// test/broker/02-subpub-qos0-subscription-id.py; src/subs.c: sub__add_leaf replaces
// the identifier on an existing subscription; lib/send_publish.c: send__real_publish appends it.
scenario!(subscription_identifiers, config(ANONYMOUS));
fn subscription_identifiers(h: &mut Harness) {
    let subscriber = client(h, "id-subscriber");
    let publisher = client(h, "id-publisher");
    for (mid, identifier) in [(1, Some(1)), (2, Some(16_384)), (3, None)] {
        let properties: Vec<_> = identifier
            .into_iter()
            .map(Property::SubscriptionIdentifier)
            .collect();
        subscribe_with(
            h,
            subscriber,
            mid,
            vec![subscription("identified/+", Q0)],
            properties.clone(),
        );
        let message = Publish {
            properties: vec![Property::ContentType("text/plain".into())],
            ..publication("identified/topic", b"with subscription ID", Q0, 0)
        };
        send(h, publisher, Packet::Publish(message.clone()));
        received(
            h,
            subscriber,
            Packet::Publish(Publish {
                properties: message.properties.into_iter().chain(properties).collect(),
                ..message
            }),
        );
    }
}

// Extends test/broker/02-subpub-qos0-subscription-id.py. Mosquitto database.c:
// db__message_insert_outgoing bypasses allow_duplicate_messages for MQTT 5.
scenario!(subscription_overlap_keeps_v5_copies, config(LEGACY_DEDUP));
fn subscription_overlap_keeps_v5_copies(h: &mut Harness) {
    let topic = "overlap/leaf";
    let wildcard = "overlap/#";
    let publisher = client(h, "overlap-publisher");
    // In the cluster these three connections land on separate nodes. The
    // first publication has no durable subscribers and can use the mesh path.
    let transient = client(h, "overlap-v5");
    let legacy = v3::client(h, "overlap-v311");
    subscribe_identified(h, transient, 1, vec![subscription(wildcard, Q0)], 17);
    subscribe_identified(h, transient, 2, vec![subscription(topic, Q1)], 23);
    v3::subscribe(h, legacy, 1, &[(wildcard, Q0), (topic, Q1)]);

    let live = b"live";
    publish_qos1(h, publisher, publication(topic, live, Q1, 41), R::SUCCESS);
    accept_identified_publish(h, transient, publication(topic, live, Q1, 1), 23);
    accept_identified_publish(h, transient, publication(topic, live, Q0, 0), 17);
    ping(h, transient);
    v3::accept_publish(h, legacy, v3::publish(topic, live, Q1, 1));
    v3::ping(h, legacy);

    let durable = connect_with(
        h,
        Connect {
            properties: vec![Property::SessionExpiryInterval(60)],
            ..options("overlap-v5-durable")
        },
        false,
    );
    subscribe_identified(
        h,
        durable,
        1,
        vec![subscription(wildcard, Q0), subscription(topic, Q1)],
        31,
    );
    let stored = b"stored";
    let retained = Publish {
        retain: true,
        ..publication(topic, stored, Q1, 42)
    };
    publish_qos1(h, publisher, retained, R::SUCCESS);
    for (receiver, mid, exact, broad) in [(transient, 2, 23, 17), (durable, 1, 31, 31)] {
        // RETAIN is clear for both live copies, so this also exercises the
        // MQTT 5 exception in replicated routing rather than retain bypass.
        accept_identified_publish(h, receiver, publication(topic, stored, Q1, mid), exact);
        accept_identified_publish(h, receiver, publication(topic, stored, Q0, 0), broad);
        ping(h, receiver);
    }
    v3::accept_publish(h, legacy, v3::publish(topic, stored, Q1, 2));
    v3::ping(h, legacy);

    let replay_if_new = Subscription {
        retain_handling: RetainHandling::SendIfNew,
        ..subscription(topic, Q1)
    };
    subscribe_identified(h, transient, 3, vec![replay_if_new.clone()], 33);
    ping(h, transient);
    unsubscribe_filter(h, transient, 4, topic);
    subscribe_identified(h, transient, 5, vec![replay_if_new], 37);
    accept_identified_publish(
        h,
        transient,
        Publish {
            retain: true,
            ..publication(topic, stored, Q1, 3)
        },
        37,
    );
    ping(h, transient);
}

// Extends test/broker/02-shared-qos0-v5.py with overlap in one session.
// subs.c: subs__shared_process rotates without reordering on replacement;
// retain.c: retain__queue never replays retained messages to a shared filter.
scenario!(
    shared_subscription_overlap_keeps_v5_copies,
    config(LEGACY_DEDUP)
);
fn shared_subscription_overlap_keeps_v5_copies(h: &mut Harness) {
    let topic = "workers/job";
    let group = "$share/team/workers/job";
    let publisher = client(h, "workers-publisher");
    let first = client(h, "worker-first");
    let second = client(h, "worker-second");

    let seed = Publish {
        retain: true,
        ..publication(topic, b"seed", Q0, 0)
    };
    send(h, publisher, Packet::Publish(seed.clone()));
    ping(h, publisher);
    subscribe_identified(h, first, 1, vec![subscription("workers/#", Q0)], 51);
    accept_identified_publish(h, first, seed, 51);
    subscribe_identified(h, first, 2, vec![subscription(group, Q0)], 61);
    subscribe_identified(h, second, 1, vec![subscription(group, Q0)], 63);
    ping(h, first);
    ping(h, second);

    for (mid, selected, identifier, retain) in [(1, first, 61, false), (2, second, 67, true)] {
        if mid == 2 {
            // Replacing the current head updates its identifier and flags,
            // but leaves it at the head and does not replay the retained value.
            subscribe_identified(
                h,
                second,
                2,
                vec![Subscription {
                    retain_as_published: true,
                    ..subscription(group, Q0)
                }],
                67,
            );
            ping(h, second);
        }
        let live = Publish {
            retain: true,
            ..publication(topic, b"job", Q1, mid)
        };
        publish_qos1(h, publisher, live, R::SUCCESS);
        let ordinary = publication(topic, b"job", Q0, 0);
        accept_identified_publish(h, first, ordinary.clone(), 51);
        accept_identified_publish(h, selected, Publish { retain, ..ordinary }, identifier);
        ping(h, first);
        ping(h, second);
    }
}

// test/broker/02-shared-qos0-v5.py; src/subs.c: subs__shared_process rotates each group.
scenario!(shared_subscriptions, config(ANONYMOUS));
fn shared_subscriptions(h: &mut Harness) {
    let ordinary = client(h, "shared-ordinary");
    subscribe(h, ordinary, 1, "shared/#", Q0);
    let first = client(h, "shared-first");
    subscribe(h, first, 1, "$share/one/shared/topic", Q0);
    let second = client(h, "shared-second");
    subscribe(h, second, 1, "$share/one/shared/topic", Q0);
    let other_group = client(h, "shared-other-group");
    subscribe(h, other_group, 1, "$share/two/shared/topic", Q0);

    for (chosen, unchosen, payload) in [
        (first, second, b"first".as_slice()),
        (second, first, b"second".as_slice()),
        (first, second, b"third".as_slice()),
    ] {
        let message = Packet::Publish(publication("shared/topic", payload, Q0, 0));
        send(h, ordinary, message.clone());
        for c in [ordinary, chosen, other_group] {
            received(h, c, message.clone());
        }
        silent(h, unchosen);
    }
}

// test/broker/02-shared-qos0-v5.py covers successful UNSUBACK; this extends it to
// mixed reasons. src/handle_subscribe.c: handle__subscribe and src/subs.c: sub__remove.
scenario!(subscription_ack_reasons, config(ANONYMOUS));
fn subscription_ack_reasons(h: &mut Harness) {
    let c = client(h, "suback-client");
    subscribe_with(
        h,
        c,
        1,
        vec![
            subscription("reasons/q2", Q2),
            subscription("reasons/q0", Q0),
            subscription("reasons/q1", Q1),
        ],
        vec![],
    );
    let packet_id = id(2);
    send(
        h,
        c,
        Packet::Unsubscribe(Unsubscribe {
            packet_id,
            properties: vec![Property::UserProperty(
                "unsubscribe".into(),
                "not echoed".into(),
            )],
            filters: ["reasons/q2", "reasons/missing", "reasons/q1"]
                .map(String::from)
                .into(),
        }),
    );
    received(
        h,
        c,
        Packet::UnsubAck(SubscriptionAck {
            packet_id,
            reasons: vec![R::SUCCESS, R::NO_SUBSCRIPTION_EXISTED, R::SUCCESS],
            properties: vec![],
        }),
    );
    ping(h, c);
}
