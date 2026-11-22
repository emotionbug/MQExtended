use super::*;

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
