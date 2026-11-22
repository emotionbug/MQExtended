use bytes::{Bytes, BytesMut};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, DecodeContext, LastWill, Packet, PacketId,
    ProtocolVersion, Publish, QoS, SubAck, Subscribe, SubscribeReturnCode, Unsubscribe, decode,
    encode,
};
use proptest::prelude::*;

fn packet_id() -> impl Strategy<Value = PacketId> {
    (1u16..=u16::MAX).prop_map(|id| PacketId::new(id).unwrap())
}

fn qos() -> impl Strategy<Value = QoS> {
    prop_oneof![
        Just(QoS::AtMostOnce),
        Just(QoS::AtLeastOnce),
        Just(QoS::ExactlyOnce),
    ]
}

fn text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9é水🙂]{0,32}"
}

fn topic() -> impl Strategy<Value = String> {
    "[A-Za-z0-9é水🙂$/]{1,64}"
}

fn topic_filter() -> impl Strategy<Value = String> {
    "([a-z0-9é水🙂$]*|\\+)/([a-z0-9é水🙂$]*|\\+|#)"
}

fn binary(max: usize) -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..=max).prop_map(Bytes::from)
}

fn publish() -> impl Strategy<Value = Publish> {
    (
        qos(),
        any::<bool>(),
        any::<bool>(),
        topic(),
        packet_id(),
        binary(300),
    )
        .prop_map(|(qos, dup, retain, topic, id, payload)| {
            let has_id = qos != QoS::AtMostOnce;
            Publish {
                dup: dup && has_id,
                qos,
                retain,
                topic,
                packet_id: has_id.then_some(id),
                payload,
            }
        })
}

fn connect() -> impl Strategy<Value = Connect> {
    let will =
        (topic(), binary(100), qos(), any::<bool>()).prop_map(|(topic, payload, qos, retain)| {
            LastWill {
                topic,
                payload,
                qos,
                retain,
            }
        });
    let credentials = prop::option::of((text(), prop::option::of(binary(32))));
    (
        prop_oneof![Just(ProtocolVersion::V31), Just(ProtocolVersion::V311)],
        any::<bool>(),
        any::<bool>(),
        any::<u16>(),
        text(),
        prop::option::of(will),
        credentials,
    )
        .prop_map(
            |(protocol, is_bridge, clean_session, keep_alive, client_id, will, credentials)| {
                let (username, password) = match credentials {
                    Some((username, password)) => (Some(username), password),
                    None => (None, None),
                };
                Connect {
                    protocol,
                    is_bridge,
                    clean_session,
                    keep_alive,
                    client_id,
                    will,
                    username,
                    password,
                }
            },
        )
}

fn connack() -> impl Strategy<Value = ConnAck> {
    prop_oneof![
        any::<bool>().prop_map(|session_present| ConnAck {
            session_present,
            code: ConnectReturnCode::Accepted
        }),
        prop::sample::select(vec![
            ConnectReturnCode::UnacceptableProtocolVersion,
            ConnectReturnCode::IdentifierRejected,
            ConnectReturnCode::ServerUnavailable,
            ConnectReturnCode::BadUserNameOrPassword,
            ConnectReturnCode::NotAuthorized,
        ])
        .prop_map(|code| ConnAck {
            session_present: false,
            code
        }),
    ]
}

fn packets() -> impl Strategy<Value = Vec<Packet>> {
    let filters = prop::collection::vec((topic_filter(), qos()), 1..=5);
    let unsub_filters = prop::collection::vec(topic_filter(), 1..=5);
    let return_codes = prop::collection::vec(
        any::<u8>().prop_map(|byte| match byte {
            0 => SubscribeReturnCode::Success(QoS::AtMostOnce),
            1 => SubscribeReturnCode::Success(QoS::AtLeastOnce),
            2 => SubscribeReturnCode::Success(QoS::ExactlyOnce),
            0x80 => SubscribeReturnCode::Failure,
            byte => SubscribeReturnCode::Unrecognized(byte),
        }),
        1..=5,
    );
    (
        connect(),
        connack(),
        publish(),
        prop::array::uniform8(packet_id()),
        filters,
        return_codes,
        unsub_filters,
    )
        .prop_map(
            |(connect, connack, publish, ids, filters, return_codes, unsub_filters)| {
                vec![
                    Packet::Connect(connect),
                    Packet::ConnAck(connack),
                    Packet::Publish(publish),
                    Packet::PubAck(ids[0]),
                    Packet::PubRec(ids[1]),
                    Packet::PubRel(ids[2]),
                    Packet::PubComp(ids[3]),
                    Packet::Subscribe(Subscribe {
                        packet_id: ids[4],
                        filters,
                    }),
                    Packet::SubAck(SubAck {
                        packet_id: ids[5],
                        return_codes,
                    }),
                    Packet::Unsubscribe(Unsubscribe {
                        packet_id: ids[6],
                        filters: unsub_filters,
                    }),
                    Packet::UnsubAck(ids[7]),
                    Packet::PingReq,
                    Packet::PingResp,
                    Packet::Disconnect,
                ]
            },
        )
}

fn drain(input: &mut BytesMut, protocol: &mut Option<ProtocolVersion>, output: &mut Vec<Packet>) {
    while let Some(packet) = decode(input, DecodeContext::new(0, *protocol)).unwrap() {
        if let Packet::Connect(connect) = &packet {
            *protocol = Some(connect.protocol);
        }
        output.push(packet);
    }
}

proptest! {
    #[test]
    fn every_type_round_trips(packets in packets()) {
        for version in [ProtocolVersion::V31, ProtocolVersion::V311] {
            let context = DecodeContext::new(0, Some(version));
            let mut bytes = BytesMut::new();
            for packet in &packets {
                encode(packet, &mut bytes).unwrap();
                let decoded = decode(&mut bytes, context).unwrap();
                prop_assert_eq!(decoded.as_ref(), Some(packet));
                prop_assert!(bytes.is_empty());
            }
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic(
        input in prop::collection::vec(any::<u8>(), 0..=512),
        command in any::<u8>(),
        max in prop_oneof![Just(0), 1usize..600],
    ) {
        // A length-consistent variant reaches the body parsers even when the
        // arbitrary bytes alone happen not to describe a complete frame.
        let mut framed = vec![command];
        if input.len() < 128 {
            framed.push(input.len() as u8);
        } else {
            framed.extend([(input.len() & 127) as u8 | 128, (input.len() >> 7) as u8]);
        }
        framed.extend_from_slice(&input);
        for wire in [input, framed] {
            for version in [None, Some(ProtocolVersion::V31), Some(ProtocolVersion::V311)] {
                for context in [DecodeContext::new(max, version), DecodeContext::for_client(max, version)] {
                    let mut bytes = BytesMut::from(wire.as_slice());
                    while let Ok(Some(_)) = decode(&mut bytes, context) {}
                }
            }
        }
    }

    #[test]
    fn arbitrary_stream_partitions_decode_identically(
        packets in packets(),
        mut cuts in prop::collection::vec(any::<u16>(), 0..=50),
    ) {
        let mut stream = BytesMut::new();
        for packet in &packets {
            encode(packet, &mut stream).unwrap();
        }
        let mut whole = Vec::new();
        let mut input = stream.clone();
        drain(&mut input, &mut None, &mut whole);
        prop_assert!(input.is_empty());
        prop_assert_eq!(&whole, &packets);

        let mut cuts: Vec<_> = cuts.drain(..).map(|n| usize::from(n) % (stream.len() + 1)).collect();
        cuts.sort_unstable();
        cuts.push(stream.len());
        let mut output = Vec::new();
        let mut protocol = None;
        let mut start = 0;
        for end in cuts {
            input.extend_from_slice(&stream[start..end]);
            drain(&mut input, &mut protocol, &mut output);
            start = end;
        }
        prop_assert!(input.is_empty());
        prop_assert_eq!(output, whole);
    }
}
