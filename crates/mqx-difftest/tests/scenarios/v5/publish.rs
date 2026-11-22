use super::super as v3;
use super::*;

// test/broker/02-subpub-qos0-topic-alias.py; src/handle_publish.c: handle__publish
// and lib/alias_mosq.c: alias__add, alias__find.
scenario!(client_to_broker_alias, config(ANONYMOUS));
fn client_to_broker_alias(h: &mut Harness) {
    let subscriber = client(h, "inbound-alias-subscriber");
    subscribe(h, subscriber, 1, "alias/#", Q0);
    let publisher = client(h, "inbound-alias-publisher");
    for (topic, sent_topic) in [
        ("alias/first", "alias/first"),
        ("alias/first", ""),
        ("alias/rebound", "alias/rebound"),
        ("alias/rebound", ""),
    ] {
        send(
            h,
            publisher,
            Packet::Publish(Publish {
                properties: vec![Property::TopicAlias(3)],
                ..publication(sent_topic, b"mapped", Q0, 0)
            }),
        );
        received(
            h,
            subscriber,
            Packet::Publish(publication(topic, b"mapped", Q0, 0)),
        );
    }
}

// test/broker/02-subpub-b2c-topic-alias.py; lib/send_publish.c: send__real_publish.
scenario!(broker_to_client_alias, config(ANONYMOUS));
fn broker_to_client_alias(h: &mut Harness) {
    let subscriber = connect_with(
        h,
        Connect {
            properties: vec![Property::TopicAliasMaximum(1)],
            ..options("outbound-alias-subscriber")
        },
        false,
    );
    subscribe(h, subscriber, 1, "alias/#", Q0);
    let publisher = client(h, "outbound-alias-publisher");
    for (topic, wire_topic, alias) in [
        ("alias/first", "alias/first", Some(1)),
        ("alias/first", "", Some(1)),
        ("alias/second", "alias/second", None),
        ("alias/second", "alias/second", None),
        ("alias/first", "", Some(1)),
    ] {
        send(
            h,
            publisher,
            Packet::Publish(publication(topic, b"outbound", Q0, 0)),
        );
        received(
            h,
            subscriber,
            Packet::Publish(Publish {
                properties: alias.into_iter().map(Property::TopicAlias).collect(),
                ..publication(wire_topic, b"outbound", Q0, 0)
            }),
        );
    }
}

// Extension of test/broker/02-subpub-qos0-topic-alias.py. src/handle_publish.c:
// handle__publish and src/read_handle.c: handle__packet distinguish invalid and unknown aliases.
scenario!(invalid_topic_alias, config(ANONYMOUS));
fn invalid_topic_alias(h: &mut Harness) {
    let zero = client(h, "alias-zero");
    // libcommon/property_common.c: mosquitto_property_check_all rejects alias 0
    // before handle__publish checks it against the negotiated maximum.
    raw(
        h,
        zero,
        &[0x30, 0x07, 0x00, 0x01, b'a', 0x03, 0x23, 0x00, 0x00],
    );
    expect_disconnect(h, zero, R::PROTOCOL_ERROR);

    for (topic, alias, reason) in [
        ("a", 11, R::TOPIC_ALIAS_INVALID),
        ("", 3, R::PROTOCOL_ERROR),
    ] {
        let c = client(h, "alias-invalid-or-unknown");
        send(
            h,
            c,
            Packet::Publish(Publish {
                properties: vec![Property::TopicAlias(alias)],
                ..publication(topic, b"", Q0, 0)
            }),
        );
        expect_disconnect(h, c, reason);
    }
}

// test/broker/12-prop-maximum-packet-size-publish-qos1.py exercises the indicator;
// src/handle_publish.c: handle__publish does not validate the payload as UTF-8.
scenario!(payload_format_indicator_invalid_utf8, config(ANONYMOUS));
fn payload_format_indicator_invalid_utf8(h: &mut Harness) {
    let receiver = client(h, "format-subscriber");
    subscribe(h, receiver, 1, "format", Q1);
    let sender = client(h, "format-publisher");
    let message = Publish {
        properties: vec![Property::PayloadFormatIndicator(1)],
        ..publication("format", b"\xff\xc0\x80", Q1, 1)
    };
    publish_qos1(h, sender, message.clone(), R::SUCCESS);
    received(h, receiver, Packet::Publish(message));
    send(h, receiver, Packet::PubAck(ack(1, R::SUCCESS)));
    ping(h, sender);
}

// test/broker/12-prop-response-topic-correlation-data.py and 15-persist-publish-properties-v5-0.py.
// lib/send_publish.c: send__real_publish sends stored properties only to v5 peers.
scenario!(mixed_protocol_publications, config(ANONYMOUS));
fn mixed_protocol_publications(h: &mut Harness) {
    let receiver_v31 = v3::connect_with(
        h,
        v3::Connect {
            protocol: v3::V31,
            ..v3::options("mixed-v31")
        },
        false,
    );
    let receiver_v311 = v3::client(h, "mixed-v311");
    for c in [receiver_v31, receiver_v311] {
        v3::subscribe(h, c, 1, &[("interop/request", Q1)]);
    }
    let receiver_v5 = client(h, "mixed-v5-observer");
    subscribe(h, receiver_v5, 1, "interop/request", Q1);
    let sender_v5 = client(h, "mixed-v5-publisher");
    subscribe_with(
        h,
        sender_v5,
        1,
        vec![subscription("interop/response", Q1)],
        vec![Property::SubscriptionIdentifier(128)],
    );
    let request = Publish {
        properties: vec![
            Property::UserProperty("sequence".into(), "first".into()),
            Property::ResponseTopic("interop/response".into()),
            Property::CorrelationData(Bytes::from_static(b"\x00\xff")),
            Property::PayloadFormatIndicator(1),
            Property::UserProperty("sequence".into(), "second".into()),
            Property::ContentType("text/plain".into()),
        ],
        ..publication("interop/request", b"request", Q1, 1)
    };
    publish_qos1(h, sender_v5, request.clone(), R::SUCCESS);
    for c in [receiver_v31, receiver_v311] {
        v3::accept_publish(h, c, v3::publish("interop/request", b"request", Q1, 1));
    }
    received(h, receiver_v5, Packet::Publish(request));
    send(h, receiver_v5, Packet::PubAck(ack(1, R::SUCCESS)));

    v3::publish_from(
        h,
        receiver_v311,
        v3::publish("interop/response", b"reply", Q1, 10),
    );
    received(
        h,
        sender_v5,
        Packet::Publish(Publish {
            properties: vec![Property::SubscriptionIdentifier(128)],
            ..publication("interop/response", b"reply", Q1, 1)
        }),
    );
    send(h, sender_v5, Packet::PubAck(ack(1, R::SUCCESS)));
}

// test/broker/09-acl-access-variants.py and 03-publish-qos1-no-subscribers-v5.py;
// src/handle_publish.c: process_bad_message and handle__accepted_publish.
scenario!(
    publish_ack_acl_reasons,
    BrokerConfig {
        conf: ANONYMOUS,
        acl: Some("topic deny acl/denied\ntopic readwrite acl/#\n"),
        ..BrokerConfig::default()
    }
);
fn publish_ack_acl_reasons(h: &mut Harness) {
    let receiver = client(h, "acl-receiver");
    // The built-in ACL file's acl_check allows subscriptions even to denied topics.
    subscribe(h, receiver, 1, "acl/denied", Q1);
    let sender = client(h, "acl-sender");
    publish_qos1(
        h,
        sender,
        publication("acl/denied", b"deny", Q1, 1),
        R::NOT_AUTHORIZED,
    );
    send(
        h,
        sender,
        Packet::Publish(publication("acl/denied", b"deny", Q2, 2)),
    );
    received(h, sender, Packet::PubRec(ack(2, R::NOT_AUTHORIZED)));
    ping(h, receiver);
    publish_qos1(
        h,
        sender,
        publication("acl/unmatched", b"allow", Q1, 3),
        R::NO_MATCHING_SUBSCRIBERS,
    );
    ping(h, sender);
}

// test/broker/03-publish-qos2-max-inflight-exceeded.py. The early DISCONNECT is
// compiled out in src/handle_publish.c: handle__accepted_publish; quota exhaustion gives 0x97.
scenario!(
    publish_ack_quota_exceeded,
    config("allow_anonymous true\nmax_inflight_messages 1")
);
fn publish_ack_quota_exceeded(h: &mut Harness) {
    for qos in [Q1, Q2] {
        let sender = open(h, options("saturate-inbound-window"));
        let mut properties = connack_properties();
        properties[2] = Property::ReceiveMaximum(1);
        connack(h, sender, false, properties);
        send(
            h,
            sender,
            Packet::Publish(publication("quota", b"held", Q2, 1)),
        );
        received(h, sender, Packet::PubRec(ack(1, R::SUCCESS)));

        // lib/send_mosq.c: send__puback and send__pubrec replenish the quota
        // even on a rejected publish. Exercise each rejection on a fresh connection.
        send(
            h,
            sender,
            Packet::Publish(publication("quota", b"reject", qos, 2)),
        );
        let reason = ack(2, R::QUOTA_EXCEEDED);
        received(
            h,
            sender,
            if qos == Q1 {
                Packet::PubAck(reason)
            } else {
                Packet::PubRec(reason)
            },
        );
        send(h, sender, Packet::PubRel(ack(1, R::SUCCESS)));
        received(h, sender, Packet::PubComp(ack(1, R::SUCCESS)));
        publish_qos1(
            h,
            sender,
            publication("quota", b"quota freed", Q1, 3),
            R::NO_MATCHING_SUBSCRIBERS,
        );
        disconnect(h, sender, R::NORMAL_DISCONNECTION, vec![]);
    }
}

// test/broker/02-subpub-qos1-oversize-payload.py; src/handle_publish.c: process_bad_message.
scenario!(
    publish_ack_payload_too_large,
    config("allow_anonymous true\nmessage_size_limit 1")
);
fn publish_ack_payload_too_large(h: &mut Harness) {
    let sender = client(h, "oversize-payload-sender");
    for (qos, expected) in [
        (Q1, Packet::PubAck(ack(1, R::PACKET_TOO_LARGE))),
        (Q2, Packet::PubRec(ack(1, R::PACKET_TOO_LARGE))),
    ] {
        send(
            h,
            sender,
            Packet::Publish(publication("oversize", b"AB", qos, 1)),
        );
        let mut wire = BytesMut::new();
        codec::encode(&expected, &mut wire).unwrap();
        // libmosquitto's ACK decoder rejects 0x95 even though the broker sends it.
        assert_eq!(
            h.receive_raw(sender, RESPONSE).unwrap(),
            &Reading::Raw(wire.freeze())
        );
    }
    ping(h, sender);
}

// test/broker/12-prop-maximum-packet-size-broker.py; lib/packet_mosq.c: packet__read.
scenario!(
    disconnect_for_incoming_packet_size,
    config("allow_anonymous true\nmax_packet_size 50")
);
fn disconnect_for_incoming_packet_size(h: &mut Harness) {
    let sender = open(h, options("incoming-packet-limit"));
    let mut properties = connack_properties();
    properties[1] = Property::MaximumPacketSize(50);
    connack(h, sender, false, properties);
    send(
        h,
        sender,
        Packet::Publish(publication("packet", &[b'a'; 39], Q0, 0)),
    );
    ping(h, sender);
    send(
        h,
        sender,
        Packet::Publish(publication("packet", &[b'a'; 40], Q0, 0)),
    );
    expect_disconnect(h, sender, R::PACKET_TOO_LARGE);
}
