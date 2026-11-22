use super::*;

// test/broker/12-prop-server-keepalive.py and 12-prop-maximum-packet-size-broker.py.
// src/handle_connect.c: connect__on_authorised; src/send_connack.c: send__connack.
scenario!(
    connect_properties,
    config(concat!(
        "allow_anonymous true\nmax_keepalive 60\nmax_inflight_messages 7\n",
        "max_packet_size 512\nmax_topic_alias 3"
    ))
);
fn connect_properties(h: &mut Harness) {
    for request_response in [0, 1] {
        let c = open(
            h,
            Connect {
                keep_alive: 61,
                properties: vec![
                    Property::SessionExpiryInterval(60),
                    Property::ReceiveMaximum(1),
                    Property::MaximumPacketSize(256),
                    Property::TopicAliasMaximum(2),
                    Property::RequestProblemInformation(0),
                    Property::RequestResponseInformation(request_response),
                    Property::UserProperty("connect".into(), "not echoed".into()),
                ],
                ..options("connect-properties")
            },
        );
        // src/property_broker.c: property__process_connect ignores the information requests.
        connack(
            h,
            c,
            false,
            vec![
                Property::ServerKeepAlive(60),
                Property::TopicAliasMaximum(3),
                Property::MaximumPacketSize(512),
                Property::ReceiveMaximum(7),
            ],
        );
        disconnect(h, c, R::NORMAL_DISCONNECTION, vec![]);
    }
}

// test/broker/12-prop-assigned-client-identifier.py; src/handle_connect.c: clientid_gen.
scenario!(
    assigned_identifier,
    config("allow_anonymous true\nauto_id_prefix parity-"),
    compare_assigned
);
fn assigned_identifier(h: &mut Harness) {
    let mut assigned = Vec::new();
    for clean_start in [true, false] {
        let c = open(
            h,
            Connect {
                clean_start,
                properties: vec![Property::SessionExpiryInterval(60)],
                ..options("")
            },
        );
        let Reading::ReceivedV5 {
            packet: Packet::ConnAck(ack),
            ..
        } = read(h, c, RESPONSE)
        else {
            panic!("expected successful CONNACK with an assigned client identifier");
        };
        let [_, Property::AssignedClientIdentifier(identifier), ..] = ack.properties.as_slice()
        else {
            panic!("missing assigned identifier in {ack:?}");
        };
        let suffix = identifier
            .strip_prefix("parity-")
            .expect("configured auto_id_prefix");
        assert_eq!(suffix.len(), 36);
        for (position, byte) in suffix.bytes().enumerate() {
            if [8, 13, 18, 23].contains(&position) {
                assert_eq!(byte, b'-');
            } else {
                assert!(
                    matches!(byte, b'0'..=b'9' | b'A'..=b'F'),
                    "invalid hex in {identifier:?}"
                );
            }
        }
        let mut properties = connack_properties();
        properties.insert(1, Property::AssignedClientIdentifier(identifier.clone()));
        assert_eq!(
            ack,
            &ConnAck {
                session_present: false,
                reason: R::SUCCESS,
                properties
            }
        );
        assert!(
            !assigned.contains(identifier),
            "identifier was reused: {identifier}"
        );
        assigned.push(identifier.clone());
        disconnect(h, c, R::NORMAL_DISCONNECTION, vec![]);
    }
    for identifier in assigned {
        let c = connect_with(
            h,
            Connect {
                clean_start: false,
                ..options(&identifier)
            },
            true,
        );
        ping(h, c);
    }
}

fn compare_assigned(expected: &Transcript, actual: &Transcript) {
    compare_variable_property(expected, actual, |packet| {
        if let Packet::ConnAck(ack) = packet {
            for property in &mut ack.properties {
                if let Property::AssignedClientIdentifier(value) = property {
                    *value = "parity-00000000-0000-0000-0000-000000000000".into();
                }
            }
        }
    });
}

// test/broker/09-auth-bad-method.py; src/handle_connect.c: handle__connect.
scenario!(authentication_method_refused, config(ANONYMOUS));
fn authentication_method_refused(h: &mut Harness) {
    let c = open(
        h,
        Connect {
            properties: vec![Property::AuthenticationMethod("basic".into())],
            ..options("unsupported-auth")
        },
    );
    received(
        h,
        c,
        Packet::ConnAck(ConnAck {
            reason: R::BAD_AUTHENTICATION_METHOD,
            session_present: false,
            properties: vec![],
        }),
    );
    closed(h, c);
}

// test/broker/02-subpub-qos2-receive-maximum-1.py; src/database.c: db__ready_for_flight.
scenario!(receive_maximum_limits_outgoing, config(ANONYMOUS));
fn receive_maximum_limits_outgoing(h: &mut Harness) {
    let subscriber = connect_with(
        h,
        Connect {
            properties: vec![Property::ReceiveMaximum(1)],
            ..options("one-in-flight")
        },
        false,
    );
    subscribe(h, subscriber, 1, "receive/max", Q1);
    let publisher = client(h, "window-publisher");
    for (mid, payload) in [(1, b"first".as_slice()), (2, b"second".as_slice())] {
        publish_qos1(
            h,
            publisher,
            publication("receive/max", payload, Q1, mid),
            R::SUCCESS,
        );
    }
    received(
        h,
        subscriber,
        Packet::Publish(publication("receive/max", b"first", Q1, 1)),
    );
    silent(h, subscriber);
    send(h, subscriber, Packet::PubAck(ack(1, R::SUCCESS)));
    received(
        h,
        subscriber,
        Packet::Publish(publication("receive/max", b"second", Q1, 2)),
    );
    send(h, subscriber, Packet::PubAck(ack(2, R::SUCCESS)));
    ping(h, subscriber);
}

// test/broker/12-prop-maximum-packet-size-publish-qos1.py;
// lib/send_publish.c: send__real_publish drops an oversized outgoing PUBLISH.
scenario!(maximum_packet_size_limits_outgoing, config(ANONYMOUS));
fn maximum_packet_size_limits_outgoing(h: &mut Harness) {
    let receiver = connect_with(
        h,
        Connect {
            properties: vec![Property::MaximumPacketSize(20)],
            ..options("small-packet-client")
        },
        false,
    );
    subscribe(h, receiver, 1, "max/size", Q1);
    let sender = client(h, "packet-size-sender");
    let oversized = Publish {
        // Four payload bytes fit until the two-byte property grows the frame to 21.
        properties: vec![Property::PayloadFormatIndicator(1)],
        ..publication("max/size", b"1234", Q1, 1)
    };
    publish_qos1(h, sender, oversized, R::SUCCESS);
    ping(h, receiver);
    publish_qos1(
        h,
        sender,
        publication("max/size", b"12345", Q1, 2),
        R::SUCCESS,
    );
    received(
        h,
        receiver,
        Packet::Publish(publication("max/size", b"12345", Q1, 2)),
    );
    send(h, receiver, Packet::PubAck(ack(2, R::SUCCESS)));
}
