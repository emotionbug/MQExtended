//! Protocol-engine edge cases that mix MQTT 3.x and MQTT 5 clients.

use mqx_codec::Packet as Packet3;
use mqx_codec::ProtocolVersion::V311;

use super::*;

// src/handle_connect.c: will__read refuses a `$CONTROL/` Will topic, after
// mounting, with MOSQ_ERR_ACL_DENIED: no CONNACK on either protocol.
scenario!(control_will_refused, config(ANONYMOUS));
fn control_will_refused(h: &mut Harness) {
    control_will_closes(h, "$CONTROL/broker/v1");
}

// The same check sees the mounted topic, so a mount point can create it.
scenario!(
    control_will_refused_after_mount,
    config("allow_anonymous true\nmount_point $CONTROL/")
);
fn control_will_refused_after_mount(h: &mut Harness) {
    control_will_closes(h, "broker/v1");
    // Without a Will the same listener accepts the client.
    let plain = crate::client(h, "no-will");
    crate::disconnect(h, plain);
}

fn control_will_closes(h: &mut Harness, topic: &str) {
    let v3 = h.open(V311).unwrap();
    crate::send(
        h,
        v3,
        Packet3::Connect(mqx_codec::Connect {
            will: Some(mqx_codec::LastWill {
                topic: topic.into(),
                payload: Bytes::from_static(b"will"),
                qos: Q0,
                retain: false,
            }),
            ..crate::options("control-will-v3")
        }),
    );
    closed(h, v3);
    let v5 = open_with_will(h, "control-will-v5", topic, b"will");
    closed(h, v5);
}

// The test client's encoder refuses a `$CONTROL/` Will, so encode a
// placeholder of the same length and patch it on the wire.
fn open_with_will(
    h: &mut Harness,
    client_id: &str,
    topic: &str,
    payload: &'static [u8],
) -> Connection {
    let wire = will_connect(client_id, topic, payload);
    let client = h.open_v5().unwrap();
    raw(h, client, &wire);
    client
}

fn will_connect(client_id: &str, topic: &str, payload: &'static [u8]) -> BytesMut {
    let placeholder = topic.replacen("$CONTROL/", "%CONTROL/", 1);
    let mut wire = BytesMut::new();
    codec::encode(
        &Packet::Connect(Connect {
            will: Some(LastWill {
                properties: Vec::new(),
                topic: placeholder.clone(),
                payload: Bytes::from_static(payload),
                qos: Q0,
                retain: false,
            }),
            ..options(client_id)
        }),
        &mut wire,
    )
    .unwrap();
    let at = wire
        .windows(placeholder.len())
        .position(|window| window == placeholder.as_bytes())
        .unwrap();
    wire[at..at + topic.len()].copy_from_slice(topic.as_bytes());
    wire
}

// src/handle_connect.c: will__read refuses `$CONTROL/` before reading the
// Will payload, so a truncated payload still closes without a CONNACK
// rather than getting Malformed Packet.
scenario!(control_will_refused_before_payload, config(ANONYMOUS));
fn control_will_refused_before_payload(h: &mut Harness) {
    let mut wire = will_connect("truncated-will", "$CONTROL/op", b"will");
    // Cut two payload bytes; the one-byte remaining length still frames it.
    assert!(wire[1] < 0x80);
    wire[1] -= 2;
    wire.truncate(wire.len() - 2);
    let client = h.open_v5().unwrap();
    raw(h, client, &wire);
    closed(h, client);
}

// will__read applies mosquitto_pub_topic_check to the mounted Will topic,
// here one level beyond TOPIC_HIERARCHY_LIMIT.
scenario!(
    mounted_will_hierarchy_limit,
    config("allow_anonymous true\nmount_point prefix/")
);
fn mounted_will_hierarchy_limit(h: &mut Harness) {
    let client = h.open(V311).unwrap();
    crate::send(
        h,
        client,
        Packet3::Connect(mqx_codec::Connect {
            will: Some(mqx_codec::LastWill {
                topic: "/".repeat(200),
                payload: Bytes::new(),
                qos: Q0,
                retain: false,
            }),
            ..crate::options("deep-will")
        }),
    );
    closed(h, client);
    let shallow = h.open(V311).unwrap();
    crate::send(
        h,
        shallow,
        Packet3::Connect(mqx_codec::Connect {
            will: Some(mqx_codec::LastWill {
                topic: "/".repeat(199),
                payload: Bytes::new(),
                qos: Q0,
                retain: false,
            }),
            ..crate::options("shallow-will")
        }),
    );
    crate::connack(h, shallow, mqx_codec::ConnectReturnCode::Accepted, false);
    crate::disconnect(h, shallow);
}

// A mount point in front of `$CONTROL/` hides it from will__read's check;
// src/send_publish.c: send__publish strips the mount point again on delivery.
scenario!(
    control_will_topic_mounted_elsewhere,
    config("allow_anonymous true\nmount_point mounted/")
);
fn control_will_topic_mounted_elsewhere(h: &mut Harness) {
    let watcher = crate::client(h, "will-watcher");
    crate::subscribe(h, watcher, 1, &[("$CONTROL/#", Q0)]);
    let v3 = crate::connect_with(
        h,
        mqx_codec::Connect {
            will: Some(mqx_codec::LastWill {
                topic: "$CONTROL/v3".into(),
                payload: Bytes::from_static(b"v3 will"),
                qos: Q0,
                retain: false,
            }),
            ..crate::options("mounted-will-v3")
        },
        false,
    );
    let v5 = open_with_will(h, "mounted-will-v5", "$CONTROL/v5", b"v5 will");
    connack(h, v5, false, connack_properties());
    h.close_socket(v3);
    crate::accept_publish(h, watcher, crate::publish("$CONTROL/v3", b"v3 will", Q0, 0));
    h.close_socket(v5);
    crate::accept_publish(h, watcher, crate::publish("$CONTROL/v5", b"v5 will", Q0, 0));
}

// src/plugin_acl_check.c: acl__check_dollar denies a PUBLISH to `$share/...`;
// src/handle_publish.c: process_bad_message still acknowledges it.
// src/subs.c: sub__messages_queue looks up shared subscriptions under the
// publish topic's own root, while src/topic_tok.c: sub__topic_tokenise files
// every shared filter under the ordinary root, so `$share/g/$x/y` never fires.
scenario!(shared_dollar_filters_and_share_topics, config(ANONYMOUS));
fn shared_dollar_filters_and_share_topics(h: &mut Harness) {
    let dollar = client(h, "shared-dollar");
    subscribe(h, dollar, 1, "$share/group/$custom/topic", Q1);
    let everything = client(h, "shared-everything");
    subscribe(h, everything, 1, "$share/group/#", Q1);
    let plain = client(h, "plain-topic");
    subscribe(h, plain, 1, "topic", Q1);
    let publisher = client(h, "share-publisher");

    publish_qos1(
        h,
        publisher,
        publication("$custom/topic", b"dollar", Q1, 1),
        R::NO_MATCHING_SUBSCRIBERS,
    );
    publish_qos1(
        h,
        publisher,
        publication("$share/group/topic", b"share", Q1, 2),
        R::NOT_AUTHORIZED,
    );
    let v3 = crate::client(h, "share-publisher-v3");
    crate::publish_from(
        h,
        v3,
        crate::publish("$share/group/topic", b"share v3", Q1, 3),
    );
    publish_qos1(
        h,
        publisher,
        publication("topic", b"plain", Q1, 4),
        R::SUCCESS,
    );
    for receiver in [everything, plain] {
        received(
            h,
            receiver,
            Packet::Publish(publication("topic", b"plain", Q1, 1)),
        );
        send(h, receiver, Packet::PubAck(ack(1, R::SUCCESS)));
    }
    ping(h, dollar);
}

// lib/handle_pubrec.c: handle__pubrec updates only in-flight messages
// (database.c: db__message_update_outgoing with persist = true), so a PUBREC
// naming a still-queued packet id is a warning plus PUBREL; the queued
// message is later sent normally.
scenario!(
    pubrec_for_queued_packet_id,
    config("allow_anonymous true\nmax_inflight_messages 1")
);
fn pubrec_for_queued_packet_id(h: &mut Harness) {
    let subscriber = crate::client(h, "queued-pubrec");
    crate::subscribe(h, subscriber, 1, &[("queued", Q2)]);
    let publisher = crate::client(h, "queued-publisher");
    crate::publish_from(h, publisher, crate::publish("queued", b"first", Q2, 1));
    crate::publish_from(h, publisher, crate::publish("queued", b"second", Q2, 2));
    crate::received(
        h,
        subscriber,
        Packet3::Publish(crate::publish("queued", b"first", Q2, 1)),
    );
    crate::send(h, subscriber, Packet3::PubRec(id(2)));
    crate::received(h, subscriber, Packet3::PubRel(id(2)));
    crate::send(h, subscriber, Packet3::PubRec(id(1)));
    crate::received(h, subscriber, Packet3::PubRel(id(1)));
    crate::send(h, subscriber, Packet3::PubComp(id(1)));
    crate::accept_publish(h, subscriber, crate::publish("queued", b"second", Q2, 2));
    crate::disconnect(h, subscriber);
    crate::disconnect(h, publisher);
}

fn dynamic_security_config() -> String {
    let build = std::path::PathBuf::from(
        std::env::var_os("MOSQUITTO_PLUGIN_BUILD_DIR").expect("set MOSQUITTO_PLUGIN_BUILD_DIR"),
    );
    let module = build.join(format!(
        "plugins/dynamic-security/mosquitto_dynamic_security.{}",
        if cfg!(windows) { "dll" } else { "so" }
    ));
    // The plugin creates this file in each broker's working directory; its
    // default ACL access denies subscriptions for anonymous clients.
    format!(
        "allow_anonymous true\nplugin {}\nplugin_opt_config_file dynamic-security.json",
        module.display()
    )
}

// src/handle_subscribe.c: handle__subscribe replaces a denied QoS with 0x80
// for MQTT 3.1.1 and MQTT 5 only. MQTT 3.1 gets the granted QoS back, though
// the subscription is not installed.
scenario!(
    denied_subscription_per_protocol,
    BrokerConfig {
        conf: &dynamic_security_config(),
        ..BrokerConfig::default()
    }
);
fn denied_subscription_per_protocol(h: &mut Harness) {
    use mqx_codec::{SubAck, Subscribe as Subscribe3, SubscribeReturnCode};
    for (client_id, protocol, code) in [
        (
            "denied-v31",
            mqx_codec::ProtocolVersion::V31,
            SubscribeReturnCode::Success(Q1),
        ),
        ("denied-v311", V311, SubscribeReturnCode::Failure),
    ] {
        let subscriber = crate::connect_with(
            h,
            mqx_codec::Connect {
                protocol,
                ..crate::options(client_id)
            },
            false,
        );
        crate::send(
            h,
            subscriber,
            Packet3::Subscribe(Subscribe3 {
                packet_id: id(7),
                filters: vec![("denied/#".into(), Q2), ("denied/qos1".into(), Q1)],
            }),
        );
        let granted = match code {
            SubscribeReturnCode::Success(_) => SubscribeReturnCode::Success(Q2),
            failure => failure,
        };
        crate::received(
            h,
            subscriber,
            Packet3::SubAck(SubAck {
                packet_id: id(7),
                return_codes: vec![granted, code],
            }),
        );
        crate::disconnect(h, subscriber);
    }
    let denied = client(h, "denied-v5");
    send(
        h,
        denied,
        Packet::Subscribe(codec::Subscribe {
            packet_id: id(8),
            properties: Vec::new(),
            subscriptions: vec![subscription("denied/#", Q2)],
        }),
    );
    received(
        h,
        denied,
        Packet::SubAck(SubscriptionAck {
            packet_id: id(8),
            properties: Vec::new(),
            reasons: vec![R::NOT_AUTHORIZED],
        }),
    );
}

fn persistent3(client_id: &str) -> mqx_codec::Connect {
    mqx_codec::Connect {
        clean_session: false,
        ..crate::options(client_id)
    }
}

// test/broker/15-persist-client-msg-out-queue-v3-1-1.py with a short queue;
// src/database.c: db__ready_for_queue counts only QoS 1/2 messages, but a
// full count also drops queued QoS 0; subs__send has already consumed a
// packet id for every dropped QoS 1/2 message.
scenario!(
    offline_queue_message_limit,
    config("allow_anonymous true\nmax_queued_messages 2\nqueue_qos0_messages true")
);
fn offline_queue_message_limit(h: &mut Harness) {
    let settings = persistent3("short-queue");
    let subscriber = crate::connect_with(h, settings.clone(), false);
    crate::subscribe(h, subscriber, 1, &[("limit/#", Q2)]);
    crate::disconnect(h, subscriber);
    let publisher = crate::client(h, "limit-publisher");
    for (index, (topic, qos)) in [
        ("limit/1", Q1),
        ("limit/0a", Q0),
        ("limit/2", Q2),
        ("limit/3", Q1),
        ("limit/0b", Q0),
        ("limit/4", Q2),
    ]
    .into_iter()
    .enumerate()
    {
        let mid = if qos == Q0 { 0 } else { index as u16 + 1 };
        crate::publish_from(h, publisher, crate::publish(topic, b"queued", qos, mid));
    }
    let subscriber = crate::connect_with(h, settings, true);
    crate::accept_publish(h, subscriber, crate::publish("limit/1", b"queued", Q1, 1));
    crate::accept_publish(h, subscriber, crate::publish("limit/0a", b"queued", Q0, 0));
    crate::accept_publish(h, subscriber, crate::publish("limit/2", b"queued", Q2, 2));
    crate::silent(h, subscriber);
    crate::publish_from(h, publisher, crate::publish("limit/5", b"live", Q1, 9));
    crate::accept_publish(h, subscriber, crate::publish("limit/5", b"live", Q1, 5));
    crate::disconnect(h, subscriber);
}

// src/database.c: db__ready_for_queue compares queued QoS 1/2 bytes before
// adding the new message, so the last admitted one may cross the limit.
scenario!(
    offline_queue_byte_limit,
    config("allow_anonymous true\nmax_queued_messages 0\nmax_queued_bytes 10")
);
fn offline_queue_byte_limit(h: &mut Harness) {
    let settings = persistent3("byte-queue");
    let subscriber = crate::connect_with(h, settings.clone(), false);
    crate::subscribe(h, subscriber, 1, &[("bytes", Q1)]);
    crate::disconnect(h, subscriber);
    let publisher = crate::client(h, "byte-publisher");
    for (mid, payload) in [(1, b"aaaa"), (2, b"bbbb"), (3, b"cccc"), (4, b"dddd")] {
        crate::publish_from(h, publisher, crate::publish("bytes", payload, Q1, mid));
    }
    let subscriber = crate::connect_with(h, settings, true);
    for (mid, payload) in [(1, b"aaaa"), (2, b"bbbb"), (3, b"cccc")] {
        crate::accept_publish(h, subscriber, crate::publish("bytes", payload, Q1, mid));
    }
    crate::silent(h, subscriber);
    crate::disconnect(h, subscriber);
}

// src/database.c: db__ready_for_flight compares in-flight QoS 1/2 bytes
// before adding; the rest waits in the queue until an acknowledgement.
scenario!(
    inflight_byte_limit,
    config("allow_anonymous true\nmax_inflight_bytes 5")
);
fn inflight_byte_limit(h: &mut Harness) {
    let subscriber = crate::client(h, "byte-flight");
    crate::subscribe(h, subscriber, 1, &[("flight", Q2)]);
    let publisher = crate::client(h, "flight-publisher");
    for (mid, payload, qos) in [
        (1, b"aaaa", Q1),
        (2, b"bbbb", Q2),
        (3, b"cccc", Q1),
        (0, b"dddd", Q0),
        (5, b"eeee", Q1),
    ] {
        crate::publish_from(h, publisher, crate::publish("flight", payload, qos, mid));
    }
    crate::received(
        h,
        subscriber,
        Packet3::Publish(crate::publish("flight", b"aaaa", Q1, 1)),
    );
    crate::received(
        h,
        subscriber,
        Packet3::Publish(crate::publish("flight", b"bbbb", Q2, 2)),
    );
    // QoS 0 is not held back by the QoS 1/2 byte window.
    crate::received(
        h,
        subscriber,
        Packet3::Publish(crate::publish("flight", b"dddd", Q0, 0)),
    );
    crate::silent(h, subscriber);
    crate::send(h, subscriber, Packet3::PubAck(id(1)));
    crate::received(
        h,
        subscriber,
        Packet3::Publish(crate::publish("flight", b"cccc", Q1, 3)),
    );
    crate::silent(h, subscriber);
    crate::send(h, subscriber, Packet3::PubRec(id(2)));
    crate::received(h, subscriber, Packet3::PubRel(id(2)));
    crate::send(h, subscriber, Packet3::PubComp(id(2)));
    crate::received(
        h,
        subscriber,
        Packet3::Publish(crate::publish("flight", b"eeee", Q1, 4)),
    );
    crate::send(h, subscriber, Packet3::PubAck(id(3)));
    crate::send(h, subscriber, Packet3::PubAck(id(4)));
    crate::disconnect(h, subscriber);
}

// src/handle_subscribe.c, src/handle_unsubscribe.c and src/handle_publish.c
// prefix filters and topics with mount_point; src/send_publish.c strips it
// again, including for retained replay.
scenario!(
    mount_point_topics,
    config("allow_anonymous true\nmount_point tenant/")
);
fn mount_point_topics(h: &mut Harness) {
    let publisher = crate::client(h, "mount-publisher");
    crate::publish_from(
        h,
        publisher,
        mqx_codec::Publish {
            retain: true,
            ..crate::publish("kept", b"retained", Q1, 1)
        },
    );
    let subscriber = crate::client(h, "mount-subscriber");
    crate::subscribe(h, subscriber, 1, &[("#", Q1)]);
    crate::accept_publish(
        h,
        subscriber,
        mqx_codec::Publish {
            retain: true,
            ..crate::publish("kept", b"retained", Q1, 1)
        },
    );
    crate::publish_from(h, publisher, crate::publish("live/one", b"live", Q1, 2));
    crate::accept_publish(h, subscriber, crate::publish("live/one", b"live", Q1, 2));
    // src/handle_unsubscribe.c: handle__unsubscribe does not mount the
    // filter, so "#" names no subscription and "tenant/#" removes it.
    crate::unsubscribe(h, subscriber, 2, "#");
    crate::publish_from(h, publisher, crate::publish("live/two", b"kept", Q1, 3));
    crate::accept_publish(h, subscriber, crate::publish("live/two", b"kept", Q1, 3));
    crate::unsubscribe(h, subscriber, 3, "tenant/#");
    crate::publish_from(h, publisher, crate::publish("live/three", b"gone", Q1, 4));
    crate::ping(h, subscriber);
    // An already mounted topic is mounted again rather than recognised.
    crate::publish_from(
        h,
        publisher,
        mqx_codec::Publish {
            retain: true,
            ..crate::publish("kept", b"", Q1, 5)
        },
    );
    let late = crate::client(h, "mount-late");
    crate::subscribe(h, late, 1, &[("tenant/#", Q1), ("+", Q1)]);
    crate::ping(h, late);
}

fn username_config() -> BrokerConfig<'static> {
    BrokerConfig {
        conf: "allow_anonymous false\nuse_username_as_clientid true",
        passwords: &[("device", "device-password")],
        ..BrokerConfig::default()
    }
}

// src/handle_connect.c: handle_username_as_clientid_option replaces the
// client id before the session lookup, so two different CONNECT client ids
// with one username take over and resume one session.
scenario!(username_as_clientid_takeover, username_config());
fn username_as_clientid_takeover(h: &mut Harness) {
    let login = |client_id: &str, clean_session: bool| mqx_codec::Connect {
        clean_session,
        username: Some("device".into()),
        password: Some(Bytes::from_static(b"device-password")),
        ..crate::options(client_id)
    };
    let first = crate::connect_with(h, login("first-id", false), false);
    crate::subscribe(h, first, 1, &[("device/#", Q1)]);
    let second = crate::connect_with(h, login("second-id", false), true);
    crate::closed(h, first);
    // src/handle_publish.c queues the self-delivery before sending PUBACK.
    let looped = crate::publish("device/self", b"loop", Q1, 1);
    crate::send(h, second, Packet3::Publish(looped.clone()));
    crate::received(h, second, Packet3::Publish(looped));
    crate::received(h, second, Packet3::PubAck(id(1)));
    crate::send(h, second, Packet3::PubAck(id(1)));
    // An empty MQTT 5 client id is first generated, then replaced, and the
    // CONNACK reports the username as the assigned identifier.
    let v5 = open(
        h,
        Connect {
            clean_start: false,
            username: Some("device".into()),
            password: Some(Bytes::from_static(b"device-password")),
            ..options("")
        },
    );
    connack(
        h,
        v5,
        true,
        vec![
            Property::TopicAliasMaximum(10),
            Property::AssignedClientIdentifier("device".into()),
            Property::MaximumPacketSize(PACKET_SIZE),
            Property::ReceiveMaximum(20),
        ],
    );
    crate::closed(h, second);
    let looped = publication("device/v5", b"v5", Q1, 2);
    send(h, v5, Packet::Publish(looped.clone()));
    received(h, v5, Packet::Publish(looped));
    received(h, v5, Packet::PubAck(ack(2, R::SUCCESS)));
    send(h, v5, Packet::PubAck(ack(2, R::SUCCESS)));
    disconnect(h, v5, R::NORMAL_DISCONNECTION, vec![]);
}

fn retained_acl_config() -> BrokerConfig<'static> {
    BrokerConfig {
        conf: "allow_anonymous false",
        passwords: &[("writer", "writer-password"), ("reader", "reader-password")],
        acl: Some(concat!(
            "user writer\n",
            "topic write stored/#\n",
            "user reader\n",
            "topic read stored/#\n",
            "topic deny stored/secret\n",
        )),
    }
}

// src/retain.c: retain__process checks READ per retained message on replay.
scenario!(retained_replay_acl, retained_acl_config());
fn retained_replay_acl(h: &mut Harness) {
    let login = |username: &str, password: &'static [u8]| mqx_codec::Connect {
        username: Some(username.into()),
        password: Some(Bytes::from_static(password)),
        ..crate::options(username)
    };
    let writer = crate::connect_with(h, login("writer", b"writer-password"), false);
    for (mid, topic) in [(1, "stored/public"), (2, "stored/secret"), (3, "other")] {
        crate::publish_from(
            h,
            writer,
            mqx_codec::Publish {
                retain: true,
                ..crate::publish(topic, b"retained", Q1, mid)
            },
        );
    }
    let reader = crate::connect_with(h, login("reader", b"reader-password"), false);
    crate::subscribe(h, reader, 1, &[("#", Q1)]);
    crate::accept_publish(
        h,
        reader,
        mqx_codec::Publish {
            retain: true,
            ..crate::publish("stored/public", b"retained", Q1, 1)
        },
    );
    crate::ping(h, reader);
    // The writer has no READ access, so its own replay is empty.
    crate::subscribe(h, writer, 2, &[("stored/#", Q1)]);
    crate::ping(h, writer);
}

// Each scenario runs on a three-node cluster with the publisher and the
// subscriber on different nodes: QoS 0/1 to a clean session take the mesh
// fast path while QoS 2 is replicated, so this checks one publisher's order
// across both paths. Acknowledging only after all reads keeps the transcript
// independent of timing.
fn mixed_qos_order(h: &mut Harness, clean: bool) {
    let settings = mqx_codec::Connect {
        clean_session: clean,
        ..crate::options("ordered-subscriber")
    };
    let subscriber = crate::connect_with(h, settings, false);
    crate::subscribe(h, subscriber, 1, &[("order", Q2)]);
    let publisher = crate::client(h, "ordered-publisher");
    let qos = [Q0, Q1, Q2, Q1, Q0, Q2, Q2, Q1, Q0, Q1, Q2, Q0];
    let payloads: [&'static [u8]; 12] = [
        b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9", b"10", b"11",
    ];
    for (index, (qos, payload)) in qos.iter().zip(payloads).enumerate() {
        let mid = if *qos == Q0 { 0 } else { index as u16 + 1 };
        crate::send(
            h,
            publisher,
            Packet3::Publish(crate::publish("order", payload, *qos, mid)),
        );
    }
    for (index, qos) in qos.iter().enumerate() {
        let mid = id(index as u16 + 1);
        match qos {
            Q0 => {}
            Q1 => crate::received(h, publisher, Packet3::PubAck(mid)),
            Q2 => crate::received(h, publisher, Packet3::PubRec(mid)),
        }
    }
    for (index, qos) in qos.iter().enumerate() {
        if *qos == Q2 {
            let mid = id(index as u16 + 1);
            crate::send(h, publisher, Packet3::PubRel(mid));
            crate::received(h, publisher, Packet3::PubComp(mid));
        }
    }
    let mut next = 0;
    let mut delivered = Vec::new();
    let order = qos
        .iter()
        .zip(payloads)
        .filter(|(qos, _)| **qos != Q2)
        .chain(qos.iter().zip(payloads).filter(|(qos, _)| **qos == Q2));
    for (qos, payload) in order {
        let mid = if *qos == Q0 {
            0
        } else {
            next += 1;
            next
        };
        crate::received(
            h,
            subscriber,
            Packet3::Publish(crate::publish("order", payload, *qos, mid)),
        );
        delivered.push((*qos, mid));
    }
    for (qos, mid) in delivered {
        match qos {
            Q0 => {}
            Q1 => crate::send(h, subscriber, Packet3::PubAck(id(mid))),
            Q2 => {
                crate::send(h, subscriber, Packet3::PubRec(id(mid)));
                crate::received(h, subscriber, Packet3::PubRel(id(mid)));
                crate::send(h, subscriber, Packet3::PubComp(id(mid)));
            }
        }
    }
    crate::ping(h, subscriber);
}

// src/handle_publish.c delivers QoS 0/1 on PUBLISH and src/handle_pubrel.c
// delivers QoS 2 on PUBREL, so the PUBRELs come last in delivery order.
scenario!(mixed_qos_order_clean, config(ANONYMOUS));
fn mixed_qos_order_clean(h: &mut Harness) {
    mixed_qos_order(h, true);
}

scenario!(mixed_qos_order_persistent, config(ANONYMOUS));
fn mixed_qos_order_persistent(h: &mut Harness) {
    mixed_qos_order(h, false);
}

// test/broker/01-connect-take-over.py with unacknowledged QoS 1 and 2 in
// flight: src/database.c: db__message_reconnect_reset resends PUBLISH with
// DUP and PUBREL, in order, to the connection that took the session over.
scenario!(takeover_with_messages_in_flight, config(ANONYMOUS));
fn takeover_with_messages_in_flight(h: &mut Harness) {
    let settings = persistent3("inflight-owner");
    let first = crate::connect_with(h, settings.clone(), false);
    crate::subscribe(h, first, 1, &[("inflight/#", Q2)]);
    let publisher = crate::client(h, "inflight-publisher");
    crate::publish_from(h, publisher, crate::publish("inflight/a", b"a", Q1, 1));
    crate::publish_from(h, publisher, crate::publish("inflight/b", b"b", Q2, 2));
    crate::publish_from(h, publisher, crate::publish("inflight/c", b"c", Q2, 3));
    crate::received(
        h,
        first,
        Packet3::Publish(crate::publish("inflight/a", b"a", Q1, 1)),
    );
    crate::received(
        h,
        first,
        Packet3::Publish(crate::publish("inflight/b", b"b", Q2, 2)),
    );
    crate::received(
        h,
        first,
        Packet3::Publish(crate::publish("inflight/c", b"c", Q2, 3)),
    );
    crate::send(h, first, Packet3::PubRec(id(3)));
    crate::received(h, first, Packet3::PubRel(id(3)));
    let second = crate::connect_with(h, settings, true);
    crate::closed(h, first);
    let dup = |message: mqx_codec::Publish| mqx_codec::Publish {
        dup: true,
        ..message
    };
    crate::received(
        h,
        second,
        Packet3::Publish(dup(crate::publish("inflight/a", b"a", Q1, 1))),
    );
    crate::received(
        h,
        second,
        Packet3::Publish(dup(crate::publish("inflight/b", b"b", Q2, 2))),
    );
    crate::received(h, second, Packet3::PubRel(id(3)));
    crate::publish_from(h, publisher, crate::publish("inflight/d", b"d", Q1, 4));
    crate::received(
        h,
        second,
        Packet3::Publish(crate::publish("inflight/d", b"d", Q1, 4)),
    );
    crate::send(h, second, Packet3::PubAck(id(1)));
    crate::send(h, second, Packet3::PubRec(id(2)));
    crate::received(h, second, Packet3::PubRel(id(2)));
    crate::send(h, second, Packet3::PubComp(id(2)));
    crate::send(h, second, Packet3::PubComp(id(3)));
    crate::send(h, second, Packet3::PubAck(id(4)));
    crate::disconnect(h, second);
}

// src/database.c: db__expire_all_messages runs on reconnection for in-flight
// and queued messages alike, so an unacknowledged message that expired while
// the session was offline is not resent; a live one is resent with DUP and
// its remaining interval. Expiry is counted in whole seconds, and a message
// sent in its last second carries no interval (lib/send_publish.c), so the
// short messages get 3 s to reach the subscriber on a loaded host.
scenario!(inflight_message_expiry, config(ANONYMOUS), compare_expiry);
fn inflight_message_expiry(h: &mut Harness) {
    let settings = Connect {
        clean_start: false,
        properties: vec![
            Property::SessionExpiryInterval(60),
            Property::ReceiveMaximum(2),
        ],
        ..options("inflight-expiry")
    };
    let receiver = connect_with(h, settings.clone(), false);
    subscribe(h, receiver, 1, "inflight/expiry", Q1);
    let sender = client(h, "inflight-expiry-publisher");
    for (mid, seconds, payload) in [
        (1, 3, b"short".as_slice()),
        (2, 30, b"long".as_slice()),
        (3, 3, b"queued short".as_slice()),
        (4, 30, b"queued long".as_slice()),
    ] {
        publish_qos1(
            h,
            sender,
            Publish {
                properties: vec![Property::MessageExpiryInterval(seconds)],
                ..publication("inflight/expiry", payload, Q1, mid)
            },
            R::SUCCESS,
        );
    }
    for (mid, payload) in [(1, b"short".as_slice()), (2, b"long".as_slice())] {
        expect_expiring(h, receiver, payload, mid, false);
    }
    disconnect(h, receiver, R::NORMAL_DISCONNECTION, vec![]);
    std::thread::sleep(Duration::from_millis(4_500));
    let receiver = connect_with(h, settings, true);
    expect_expiring(h, receiver, b"long", 2, true);
    send(h, receiver, Packet::PubAck(ack(2, R::SUCCESS)));
    expect_expiring(h, receiver, b"queued long", 4, false);
    send(h, receiver, Packet::PubAck(ack(4, R::SUCCESS)));
    ping(h, receiver);
}

#[track_caller]
fn expect_expiring(
    h: &mut Harness,
    client: Connection,
    payload: &'static [u8],
    mid: u16,
    dup: bool,
) {
    let reading = read(h, client, RESPONSE);
    let Reading::ReceivedV5 {
        packet: Packet::Publish(message),
        ..
    } = reading
    else {
        panic!("expected PUBLISH {payload:?}, got {reading:?}");
    };
    let [Property::MessageExpiryInterval(remaining)] = message.properties.as_slice() else {
        panic!("missing expiry interval in {message:?}");
    };
    assert!(*remaining <= 30, "{message:?}");
    assert_eq!(
        message,
        &Publish {
            dup,
            properties: vec![Property::MessageExpiryInterval(*remaining)],
            ..publication("inflight/expiry", payload, Q1, mid)
        }
    );
}

fn compare_expiry(expected: &Transcript, actual: &Transcript) {
    compare_variable_property(expected, actual, |packet| {
        if let Packet::Publish(message) = packet {
            for property in &mut message.properties {
                if let Property::MessageExpiryInterval(seconds) = property {
                    // Only whether the interval is short or long is stable.
                    *seconds = if *seconds <= 1 { 1 } else { 30 };
                }
            }
        }
    });
}

// src/handle_subscribe.c and src/handle_unsubscribe.c handle one filter at a
// time: filters before an invalid one stay installed (or removed) when the
// packet then closes the connection.
scenario!(partial_subscribe_and_unsubscribe, config(ANONYMOUS));
fn partial_subscribe_and_unsubscribe(h: &mut Harness) {
    let settings = persistent3("partial");
    let first = crate::connect_with(h, settings.clone(), false);
    raw(
        h,
        first,
        &[
            0x82, 14, 0, 1, 0, 1, b'a', 1, 0, 5, b'a', b'/', b'#', b'/', b'b', 1,
        ],
    );
    closed(h, first);
    let publisher = crate::client(h, "partial-publisher");
    let second = crate::connect_with(h, settings.clone(), true);
    crate::publish_from(h, publisher, crate::publish("a", b"installed", Q1, 1));
    crate::accept_publish(h, second, crate::publish("a", b"installed", Q1, 1));
    raw(
        h,
        second,
        &[
            0xa2, 12, 0, 2, 0, 1, b'a', 0, 5, b'a', b'/', b'#', b'/', b'b',
        ],
    );
    closed(h, second);
    let third = crate::connect_with(h, settings, true);
    crate::publish_from(h, publisher, crate::publish("a", b"removed", Q1, 2));
    crate::ping(h, third);
    crate::disconnect(h, third);
}

// The same for MQTT 5, which also sends DISCONNECT Malformed Packet.
scenario!(partial_subscribe_and_unsubscribe_v5, config(ANONYMOUS));
fn partial_subscribe_and_unsubscribe_v5(h: &mut Harness) {
    let settings = Connect {
        clean_start: false,
        properties: vec![Property::SessionExpiryInterval(60)],
        ..options("partial-v5")
    };
    let first = connect_with(h, settings.clone(), false);
    raw(
        h,
        first,
        &[
            0x82, 15, 0, 1, 0, 0, 1, b'a', 1, 0, 5, b'a', b'/', b'#', b'/', b'b', 1,
        ],
    );
    expect_disconnect(h, first, R::MALFORMED_PACKET);
    let publisher = client(h, "partial-v5-publisher");
    let second = connect_with(h, settings.clone(), true);
    publish_qos1(
        h,
        publisher,
        publication("a", b"installed", Q1, 1),
        R::SUCCESS,
    );
    received(
        h,
        second,
        Packet::Publish(publication("a", b"installed", Q1, 1)),
    );
    send(h, second, Packet::PubAck(ack(1, R::SUCCESS)));
    raw(
        h,
        second,
        &[
            0xa2, 13, 0, 2, 0, 0, 1, b'a', 0, 5, b'a', b'/', b'#', b'/', b'b',
        ],
    );
    expect_disconnect(h, second, R::MALFORMED_PACKET);
    let third = connect_with(h, settings, true);
    publish_qos1(
        h,
        publisher,
        publication("a", b"removed", Q1, 2),
        R::NO_MATCHING_SUBSCRIBERS,
    );
    ping(h, third);
}
