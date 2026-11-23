use bytes::{Bytes, BytesMut};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, DecodeContext, DecodeError, EncodeError, LastWill, Packet,
    PacketId, ProtocolVersion, Publish, QoS, SubAck, Subscribe, SubscribeReturnCode, Unsubscribe,
    Utf8Error, decode, encode, validate_utf8,
};

const V31: DecodeContext = DecodeContext::new(0, Some(ProtocolVersion::V31));
const V311: DecodeContext = DecodeContext::new(0, Some(ProtocolVersion::V311));
const NEW: DecodeContext = DecodeContext::new(0, None);
const CLIENT: DecodeContext = DecodeContext::for_client(0, Some(ProtocolVersion::V311));
const ID: PacketId = PacketId::new(0x1234).unwrap();

fn connect(protocol: ProtocolVersion) -> Connect {
    Connect {
        protocol,
        is_bridge: false,
        clean_session: true,
        keep_alive: 60,
        client_id: "c1".into(),
        will: None,
        username: None,
        password: None,
    }
}

fn publish() -> Publish {
    Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "t".into(),
        packet_id: None,
        payload: Bytes::new(),
    }
}

fn frame(command: u8, body: &[u8]) -> BytesMut {
    let mut length = body.len();
    let mut header = vec![command];
    loop {
        let digit = (length % 128) as u8;
        length /= 128;
        header.push(if length == 0 { digit } else { digit | 0x80 });
        if length == 0 {
            break;
        }
    }
    let mut wire = BytesMut::from(header.as_slice());
    wire.extend_from_slice(body);
    wire
}

fn blob(data: &[u8], body: &mut Vec<u8>) {
    body.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    body.extend_from_slice(data);
}

fn connect_frame(command: u8, protocol: ProtocolVersion, flags: u8, payload: &[u8]) -> BytesMut {
    let mut body = match protocol {
        ProtocolVersion::V31 => b"\0\x06MQIsdp\x03".to_vec(),
        ProtocolVersion::V311 => b"\0\x04MQTT\x04".to_vec(),
    };
    body.extend_from_slice(&[flags, 0, 60]);
    body.extend_from_slice(payload);
    frame(command, &body)
}

fn decoded(wire: &[u8], context: DecodeContext) -> Packet {
    let mut bytes = BytesMut::from(wire);
    let packet = decode(&mut bytes, context).unwrap().unwrap();
    assert!(bytes.is_empty());
    packet
}

fn rejected(wire: &[u8], context: DecodeContext, error: DecodeError) {
    let mut bytes = BytesMut::from(wire);
    assert_eq!(decode(&mut bytes, context), Err(error));
    assert_eq!(&bytes[..], wire);
}

fn exact(packet: &Packet, wire: &[u8], context: DecodeContext) {
    let mut dst = BytesMut::from(&b"prefix"[..]);
    encode(packet, &mut dst).unwrap();
    assert_eq!(&dst[..6], b"prefix");
    assert_eq!(&dst[6..], wire);
    assert_eq!(&decoded(wire, context), packet);
}

#[test]
fn canonical_packets_for_both_versions() {
    exact(
        &Packet::Connect(connect(ProtocolVersion::V31)),
        b"\x10\x10\0\x06MQIsdp\x03\x02\0<\0\x02c1",
        NEW,
    );
    exact(
        &Packet::Connect(connect(ProtocolVersion::V311)),
        b"\x10\x0e\0\x04MQTT\x04\x02\0<\0\x02c1",
        NEW,
    );

    let vectors: [(Packet, &[u8]); 16] = [
        (
            Packet::ConnAck(ConnAck {
                session_present: false,
                code: ConnectReturnCode::Accepted,
            }),
            b"\x20\x02\0\0",
        ),
        (Packet::Publish(publish()), b"\x30\x03\0\x01t"),
        (
            Packet::Publish(Publish {
                qos: QoS::AtLeastOnce,
                packet_id: Some(ID),
                payload: Bytes::from_static(b"hello"),
                ..publish()
            }),
            b"\x32\x0a\0\x01t\x12\x34hello",
        ),
        (
            Packet::Publish(Publish {
                dup: true,
                qos: QoS::ExactlyOnce,
                retain: true,
                packet_id: Some(ID),
                payload: Bytes::from_static(&[0xff]),
                ..publish()
            }),
            b"\x3d\x06\0\x01t\x12\x34\xff",
        ),
        (Packet::PubAck(ID), b"\x40\x02\x12\x34"),
        (Packet::PubRec(ID), b"\x50\x02\x12\x34"),
        (Packet::PubRel(ID), b"\x62\x02\x12\x34"),
        (Packet::PubComp(ID), b"\x70\x02\x12\x34"),
        (
            Packet::Subscribe(Subscribe {
                packet_id: ID,
                filters: vec![
                    ("a/+".into(), QoS::ExactlyOnce),
                    ("#".into(), QoS::AtMostOnce),
                ],
            }),
            b"\x82\x0c\x12\x34\0\x03a/+\x02\0\x01#\0",
        ),
        (
            Packet::SubAck(SubAck {
                packet_id: ID,
                return_codes: vec![
                    SubscribeReturnCode::Success(QoS::AtMostOnce),
                    SubscribeReturnCode::Success(QoS::AtLeastOnce),
                    SubscribeReturnCode::Success(QoS::ExactlyOnce),
                    SubscribeReturnCode::Failure,
                ],
            }),
            b"\x90\x06\x12\x34\0\x01\x02\x80",
        ),
        (
            Packet::Unsubscribe(Unsubscribe {
                packet_id: ID,
                filters: vec!["a/+".into(), "#".into()],
            }),
            b"\xa2\x0a\x12\x34\0\x03a/+\0\x01#",
        ),
        (Packet::UnsubAck(ID), b"\xb0\x02\x12\x34"),
        (Packet::PingReq, b"\xc0\0"),
        (Packet::PingResp, b"\xd0\0"),
        (Packet::Disconnect, b"\xe0\0"),
        (
            Packet::ConnAck(ConnAck {
                session_present: false,
                code: ConnectReturnCode::NotAuthorized,
            }),
            b"\x20\x02\0\x05",
        ),
    ];
    for (packet, wire) in vectors {
        exact(&packet, wire, V31);
        exact(&packet, wire, V311);
        exact(&packet, wire, CLIENT);
    }
}

#[test]
fn connect_flags_and_binary_fields_exact() {
    let mut packet = connect(ProtocolVersion::V311);
    packet.will = Some(LastWill {
        topic: "w".into(),
        payload: Bytes::from_static(b"\0\xff"),
        qos: QoS::ExactlyOnce,
        retain: true,
    });
    packet.username = Some("u".into());
    packet.password = Some(Bytes::from_static(b"\xfe\0"));
    exact(
        &Packet::Connect(packet.clone()),
        b"\x10\x1c\0\x04MQTT\x04\xf6\0<\0\x02c1\0\x01w\0\x02\0\xff\0\x01u\0\x02\xfe\0",
        NEW,
    );
    packet.protocol = ProtocolVersion::V31;
    packet.is_bridge = true;
    exact(
        &Packet::Connect(packet),
        b"\x10\x1e\0\x06MQIsdp\x83\xf6\0<\0\x02c1\0\x01w\0\x02\0\xff\0\x01u\0\x02\xfe\0",
        NEW,
    );
    // src/handle_connect.c: read_and_verify_protocol_version recognizes both private levels.
    exact(
        &Packet::Connect(Connect {
            is_bridge: true,
            ..connect(ProtocolVersion::V311)
        }),
        b"\x10\x0e\0\x04MQTT\x84\x02\0<\0\x02c1",
        NEW,
    );
}

#[test]
fn remaining_length_and_configured_limit_from_header() {
    // lib/packet_mosq.c: packet__read_single permits nonminimal remaining length
    // encodings, and packet__check_in_packet_oversize uses the canonical header size.
    assert_eq!(
        decoded(b"\xc0\x80\x80\x80\0", DecodeContext::new(2, None)),
        Packet::PingReq
    );
    rejected(
        b"\x30\x80\x80\x80\x80\0",
        NEW,
        DecodeError::MalformedRemainingLength,
    );
    let prefix = b"\x30\x80\x80\x80\x80";
    let mut input = BytesMut::from(prefix.as_slice());
    assert_eq!(decode(&mut input, NEW), Ok(None));
    assert_eq!(input, prefix.as_slice());
    rejected(
        b"\x30\x80\x01",
        DecodeContext::new(130, None),
        DecodeError::PacketTooLarge {
            size: 131,
            max: 130,
        },
    );
    rejected(
        b"\x30\xff\xff\xff\x7f",
        DecodeContext::new(10, None),
        DecodeError::PacketTooLarge {
            size: 268_435_460,
            max: 10,
        },
    );
    for (wire, limit) in [
        (&b"\x30\x80"[..], 130),
        (b"\x30\x80\x01", 131),
        (b"\x30\xff\xff\xff\x7f", 268_435_460),
        (b"\x30\xff\xff\xff\x7f", 0),
    ] {
        let mut bytes = BytesMut::from(wire);
        assert_eq!(
            decode(&mut bytes, DecodeContext::new(limit, None)),
            Ok(None)
        );
        assert_eq!(&bytes[..], wire);
    }
}

#[test]
fn framing_consumes_one_and_payload_shares_storage() {
    let mut wire = BytesMut::from(&b"\x30\x05\0\x01t\x00\xff\xc0\0"[..]);
    let payload_ptr = wire[5..].as_ptr();
    let Some(Packet::Publish(packet)) = decode(&mut wire, V311).unwrap() else {
        panic!("expected PUBLISH");
    };
    assert_eq!(packet.payload, &b"\0\xff"[..]);
    assert_eq!(packet.payload.as_ptr(), payload_ptr);
    assert_eq!(&wire[..], b"\xc0\0");
    assert_eq!(decode(&mut wire, V311), Ok(Some(Packet::PingReq)));
    assert_eq!(decode(&mut wire, V311), Ok(None));
}

#[test]
fn unknown_type_and_forbidden_fixed_header_flags() {
    // lib/packet_mosq.c: packet__read_single rejects RESERVED; src/read_handle.c
    // and lib/read_handle.c: handle__packet only dispatch supported commands.
    for (wire, kind) in [(&b"\x00\0"[..], 0), (b"\xf0\0", 15)] {
        rejected(wire, NEW, DecodeError::UnknownPacketType(kind));
    }
    for (wire, command) in [
        // lib/handle_connack.c: handle__connack.
        (&b"\x21\x02\0\0"[..], 0x21),
        // lib/handle_pubackcomp.c: handle__pubackcomp.
        (b"\x41\x02\x12\x34", 0x41),
        (b"\x71\x02\x12\x34", 0x71),
        // lib/handle_pubrec.c: handle__pubrec.
        (b"\x51\x02\x12\x34", 0x51),
        // src/handle_subscribe.c: handle__subscribe (unconditional first check).
        (b"\x8a\x06\x12\x34\0\x01a\0", 0x8a),
        // lib/handle_suback.c: handle__suback.
        (b"\x91\x03\x12\x34\0", 0x91),
        // src/handle_unsubscribe.c: handle__unsubscribe (unconditional first check).
        (b"\xaa\x05\x12\x34\0\x01a", 0xaa),
        // lib/handle_unsuback.c: handle__unsuback.
        (b"\xb1\x02\x12\x34", 0xb1),
        // lib/handle_ping.c: handle__pingreq / handle__pingresp.
        (b"\xc1\0", 0xc1),
        (b"\xd1\0", 0xd1),
    ] {
        for context in [V31, V311, CLIENT] {
            rejected(wire, context, DecodeError::InvalidFixedHeaderFlags(command));
        }
    }
    // lib/handle_pubrel.c: handle__pubrel and src/handle_disconnect.c: handle__disconnect.
    for (wire, command, packet) in [
        (&b"\x6a\x02\x12\x34"[..], 0x6a, Packet::PubRel(ID)),
        (b"\xe1\0", 0xe1, Packet::Disconnect),
    ] {
        assert_eq!(decoded(wire, V31), packet);
        rejected(wire, V311, DecodeError::InvalidFixedHeaderFlags(command));
    }
}

#[test]
fn fixed_size_packets_reject_wrong_lengths_before_body() {
    // lib/packet_mosq.c: packet__check_in_packet_oversize for narrow broker
    // packets; lib/handle_connack.c: handle__connack for CONNACK's exact length.
    for (command, expected, actual) in [
        (0x20, 2, 1),
        (0x20, 2, 3),
        (0x40, 2, 3),
        (0x50, 2, 3),
        (0x62, 2, 3),
        (0x70, 2, 3),
        (0xb0, 2, 3),
        (0xc0, 0, 1),
        (0xd0, 0, 1),
        (0xe0, 0, 1),
    ] {
        rejected(
            &[command, actual],
            V311,
            DecodeError::InvalidRemainingLength {
                packet_type: command >> 4,
                expected,
                actual: usize::from(actual),
            },
        );
    }
    // lib/handle_unsuback.c: handle__unsuback ignores trailing bytes in v3.x.
    assert_eq!(
        decoded(b"\xb0\x03\x12\x34\xff", CLIENT),
        Packet::UnsubAck(ID)
    );
}

#[test]
fn connect_protocol_errors_are_distinct() {
    // src/handle_connect.c: read_protocol_name and read_and_verify_protocol_version.
    for body in [
        &b"\0\x04XXXX\x04"[..],
        b"\0\x03MQT\x04",
        b"\0\x06MQTTxx\x04",
    ] {
        rejected(&frame(0x10, body), NEW, DecodeError::UnknownProtocolName);
    }
    for (body, level) in [
        (&b"\0\x06MQIsdp\x04"[..], 4),
        (b"\0\x04MQTT\x03", 3),
        (b"\0\x04MQTT\x05", 5),
        (b"\0\x04MQTT\x7f", 0x7f),
        (b"\0\x04XXXX\x06", 6),
    ] {
        rejected(
            &frame(0x10, body),
            NEW,
            DecodeError::UnacceptableProtocolVersion { level },
        );
    }
    rejected(
        &frame(0x10, b"\0\x04MQTT"),
        NEW,
        DecodeError::Truncated {
            field: "protocol level",
        },
    );
    assert_eq!(
        decoded(&frame(0x10, b"\0\x06MQTT\0x\x04\x02\0<\0\x02c1"), NEW),
        Packet::Connect(connect(ProtocolVersion::V311))
    );
}

#[test]
fn embedded_nul_preserves_the_legacy_connect_name_and_level_rules() {
    // src/handle_connect.c: read_and_verify_protocol_version accepts the MQTT
    // name at level 4, but after strcmp it still requires MQIsdp at level 3.
    let embedded_nul = b"\x10\x10\0\x06MQTT\0X\x04\x02\0<\0\x02c1";
    let canonical = b"\x10\x0e\0\x04MQTT\x04\x02\0<\0\x02c1";
    assert_eq!(decoded(embedded_nul, NEW), decoded(canonical, NEW));
    rejected(
        b"\x10\x10\0\x06MQTT\0X\x03\x02\0<\0\x02c1",
        NEW,
        DecodeError::UnacceptableProtocolVersion { level: 3 },
    );
    rejected(
        b"\x10\x10\0\x06MQIs\0p\x03\x02\0<\0\x02c1",
        NEW,
        DecodeError::UnknownProtocolName,
    );
}

#[test]
fn protocol_specific_connect_flags_and_trailing_data() {
    let client_id = b"\0\x02c1";
    let v31 = ProtocolVersion::V31;
    let v311 = ProtocolVersion::V311;
    // src/handle_connect.c: read_and_verify_protocol_version / read_and_verify_connect_flags.
    assert_eq!(
        decoded(&connect_frame(0x11, v31, 0x03, client_id), NEW),
        Packet::Connect(connect(v31))
    );
    rejected(
        &connect_frame(0x11, v311, 0x02, client_id),
        NEW,
        DecodeError::InvalidFixedHeaderFlags(0x11),
    );
    rejected(
        &connect_frame(0x10, v311, 0x03, client_id),
        NEW,
        DecodeError::ReservedConnectFlag,
    );
    // src/handle_connect.c: verify_will_options, handle__connect, and
    // check_additional_trailing_data.
    assert_eq!(
        decoded(&connect_frame(0x10, v31, 0x32, client_id), NEW),
        Packet::Connect(connect(v31))
    );
    for flags in [0x0a, 0x22, 0x32] {
        rejected(
            &connect_frame(0x10, v311, flags, client_id),
            NEW,
            DecodeError::WillFlagsWithoutWill,
        );
    }
    for protocol in [v31, v311] {
        for flags in [0x1a, 0x1e] {
            rejected(
                &connect_frame(0x10, protocol, flags, client_id),
                NEW,
                DecodeError::InvalidQos {
                    field: "Will",
                    value: 3,
                },
            );
        }
        rejected(
            &connect_frame(0x10, protocol, 0x02, b"\0\x02c1x"),
            NEW,
            DecodeError::TrailingConnectData,
        );
        rejected(
            &connect_frame(0x10, protocol, 0x06, b"\0\x02c1\0\x01w\0\x01"),
            NEW,
            DecodeError::Truncated {
                field: "Will payload",
            },
        );
    }
    // src/handle_connect.c: handle_zero_length_clientid is deliberately broker-owned.
    for protocol in [v31, v311] {
        for clean_session in [false, true] {
            let flags = u8::from(clean_session) << 1;
            assert_eq!(
                decoded(&connect_frame(0x10, protocol, flags, b"\0\0"), NEW),
                Packet::Connect(Connect {
                    client_id: String::new(),
                    clean_session,
                    ..connect(protocol)
                })
            );
        }
    }
}

#[test]
fn connect_credential_tolerance_tracks_reader_progress() {
    let v31 = ProtocolVersion::V31;
    let v311 = ProtocolVersion::V311;
    // src/handle_connect.c: read_and_verify_client_credentials_from_packet.
    for protocol in [v31, v311] {
        rejected(
            &connect_frame(0x10, protocol, 0x42, b"\0\x02c1\0\0"),
            NEW,
            DecodeError::PasswordWithoutUsername,
        );
        assert_eq!(
            decoded(
                &connect_frame(0x10, protocol, 0xc2, b"\0\x02c1\0\0\0\0"),
                NEW
            ),
            Packet::Connect(Connect {
                username: Some(String::new()),
                password: Some(Bytes::new()),
                ..connect(protocol)
            })
        );
    }
    // src/handle_connect.c: set_username_from_packet / set_password_from_packet.
    for (flags, base, missing) in [
        (0x82, &b"\0\x02c1"[..], "username"),
        (0xc2, &b"\0\x02c1\0\x01u"[..], "password"),
    ] {
        for suffix in [&b""[..], b"\0\x01"] {
            let body = [base, suffix].concat();
            let mut packet = connect(v31);
            if missing == "password" {
                packet.username = Some("u".into());
            }
            assert_eq!(
                decoded(&connect_frame(0x10, v31, flags, &body), NEW),
                Packet::Connect(packet)
            );
            rejected(
                &connect_frame(0x10, v311, flags, &body),
                NEW,
                DecodeError::Truncated { field: missing },
            );
        }
        let body = [base, b"\0\x02a"].concat();
        rejected(
            &connect_frame(0x10, v31, flags, &body),
            NEW,
            DecodeError::TrailingConnectData,
        );
    }
    let invalid_user_valid_password = b"\0\x02c1\0\x01\0\0\x01\xff";
    assert_eq!(
        decoded(
            &connect_frame(0x10, v31, 0xc2, invalid_user_valid_password),
            NEW
        ),
        Packet::Connect(Connect {
            password: Some(Bytes::from_static(b"\xff")),
            ..connect(v31)
        })
    );
    rejected(
        &connect_frame(0x10, v311, 0xc2, invalid_user_valid_password),
        NEW,
        DecodeError::InvalidUtf8 {
            field: "username",
            error: Utf8Error::DisallowedCodePoint { character: '\0' },
        },
    );
}

#[test]
fn connack_flags_and_return_codes() {
    // lib/handle_connack.c: handle__connack accepts codes 0..5 for MQTT 3.x;
    // reserved acknowledgement flags are only checked in v3.1.1.
    let packet = Packet::ConnAck(ConnAck {
        session_present: true,
        code: ConnectReturnCode::Accepted,
    });
    exact(&packet, b"\x20\x02\x01\0", V311);
    assert_eq!(decoded(b"\x20\x02\x81\0", V31), packet);
    rejected(
        b"\x20\x02\x81\0",
        V311,
        DecodeError::InvalidConnAckFlags(0x81),
    );
    rejected(
        b"\x20\x02\0\x06",
        V31,
        DecodeError::InvalidConnectReturnCode(6),
    );
}

#[test]
fn qos_packet_ids_and_subscription_options() {
    // src/handle_publish.c: handle__publish rejects both invalid flag combinations.
    rejected(
        b"\x36\x03\0\x01t",
        V311,
        DecodeError::InvalidQos {
            field: "PUBLISH",
            value: 3,
        },
    );
    rejected(b"\x38\x03\0\x01t", V31, DecodeError::DupWithQosZero);
    // lib/handle_publish.c: the client doesn't reject DUP with QoS 0.
    assert_eq!(
        decoded(b"\x38\x03\0\x01t", CLIENT),
        Packet::Publish(Publish {
            dup: true,
            ..publish()
        })
    );
    for wire in [
        // src/handle_publish.c and lib/handle_publish.c: handle__publish.
        &b"\x32\x05\0\x01t\0\0"[..],
        // lib/handle_pubackcomp.c, lib/handle_pubrec.c, lib/handle_pubrel.c.
        b"\x40\x02\0\0",
        b"\x50\x02\0\0",
        b"\x62\x02\0\0",
        b"\x70\x02\0\0",
        // src/handle_subscribe.c, lib/handle_suback.c, src/handle_unsubscribe.c, lib/handle_unsuback.c.
        b"\x82\x06\0\0\0\x01a\0",
        b"\x90\x03\0\0\0",
        b"\xa2\x05\0\0\0\x01a",
        b"\xb0\x02\0\0",
    ] {
        rejected(wire, V31, DecodeError::ZeroPacketId);
        rejected(wire, V311, DecodeError::ZeroPacketId);
    }
    // src/handle_subscribe.c: handle__subscribe reads the full byte as QoS in v3.x.
    for value in [3, 0x80, 0xff] {
        rejected(
            &[0x82, 6, 0x12, 0x34, 0, 1, b'a', value],
            V311,
            DecodeError::InvalidQos {
                field: "subscription",
                value,
            },
        );
    }
    // lib/packet_datatypes.c: packet__read_uint16 / packet__read_byte check the frame boundary.
    rejected(
        b"\x32\x03\0\x01t",
        V311,
        DecodeError::Truncated {
            field: "packet identifier",
        },
    );
    rejected(
        b"\x82\x05\x12\x34\0\x01a",
        V311,
        DecodeError::Truncated {
            field: "subscription QoS",
        },
    );
    rejected(
        b"\x30\x03\0\x02a",
        V311,
        DecodeError::Truncated {
            field: "PUBLISH topic",
        },
    );
}

#[test]
fn empty_lists_and_suback_unknown_codes() {
    // src/handle_subscribe.c and src/handle_unsubscribe.c: empty lists only fail in v3.1.1.
    let sub = Packet::Subscribe(Subscribe {
        packet_id: ID,
        filters: vec![],
    });
    assert_eq!(decoded(b"\x82\x02\x12\x34", V31), sub);
    assert_eq!(decoded(b"\x82\x04\x12\x34\0\0", V31), sub);
    for wire in [&b"\x82\x02\x12\x34"[..], b"\x82\x04\x12\x34\0\0"] {
        rejected(wire, V311, DecodeError::EmptyList("SUBSCRIBE filters"));
    }
    assert_eq!(
        decoded(b"\x82\x0a\x12\x34\0\0\0\x01a\0\0\0", V311),
        Packet::Subscribe(Subscribe {
            packet_id: ID,
            filters: vec![("a".into(), QoS::AtMostOnce)]
        })
    );
    assert_eq!(
        decoded(b"\xa2\x02\x12\x34", V31),
        Packet::Unsubscribe(Unsubscribe {
            packet_id: ID,
            filters: vec![]
        })
    );
    rejected(
        b"\xa2\x02\x12\x34",
        V311,
        DecodeError::EmptyList("UNSUBSCRIBE filters"),
    );
    // lib/handle_suback.c: handle__suback refuses an empty list and forwards raw code bytes.
    for context in [V31, V311] {
        rejected(
            b"\x90\x02\x12\x34",
            context,
            DecodeError::EmptyList("SUBACK return codes"),
        );
        exact(
            &Packet::SubAck(SubAck {
                packet_id: ID,
                return_codes: vec![SubscribeReturnCode::Unrecognized(0x81)],
            }),
            b"\x90\x03\x12\x34\x81",
            context,
        );
    }
}

#[test]
fn topic_and_filter_validation() {
    // All mirror libcommon/topic_common.c: mosquitto_pub_topic_check /
    // mosquitto_sub_topic_check and config.h TOPIC_HIERARCHY_LIMIT.
    let long_hierarchy = "/".repeat(201);
    for value in ["", "a/+", "a#", &long_hierarchy] {
        let mut body = Vec::new();
        blob(value.as_bytes(), &mut body);
        rejected(
            &frame(0x30, &body),
            V311,
            DecodeError::InvalidTopic {
                field: "PUBLISH topic",
            },
        );
        let mut will_body = b"\0\x02c1".to_vec();
        will_body.extend_from_slice(&body);
        will_body.extend_from_slice(b"\0\0");
        rejected(
            &connect_frame(0x10, ProtocolVersion::V31, 0x06, &will_body),
            NEW,
            DecodeError::InvalidTopic {
                field: "Will topic",
            },
        );
    }
    for value in ["a/#/b", "x+", "+x", "x#", "a##", &long_hierarchy] {
        let mut body = ID.get().to_be_bytes().to_vec();
        blob(value.as_bytes(), &mut body);
        rejected(
            &frame(0xa2, &body),
            V311,
            DecodeError::InvalidTopic {
                field: "unsubscription filter",
            },
        );
        body.push(0);
        rejected(
            &frame(0x82, &body),
            V311,
            DecodeError::InvalidTopic {
                field: "subscription filter",
            },
        );
    }
    // src/handle_unsubscribe.c: handle__unsubscribe rejects even a single empty filter.
    rejected(
        b"\xa2\x04\x12\x34\0\0",
        V31,
        DecodeError::InvalidTopic {
            field: "unsubscription filter",
        },
    );
    let maximum_hierarchy = "/".repeat(200);
    let mut body = Vec::new();
    blob(maximum_hierarchy.as_bytes(), &mut body);
    assert_eq!(
        decoded(&frame(0x30, &body), V311),
        Packet::Publish(Publish {
            topic: maximum_hierarchy,
            ..publish()
        })
    );
}

#[test]
fn utf8_matches_mosquitto_validator_and_string_reader() {
    // libcommon/utf8_common.c: mosquitto_validate_utf8.
    for value in [
        &b"\x80"[..],
        b"\xc2",
        b"\xc2A",
        b"\xc0\xaf",
        b"\xc1\xbf",
        b"\xe0\x81\x80",
        b"\xed\xa0\x80",
        b"\xf0\x80\xbf\xbf",
        b"\xf4\x90\x80\x80",
        b"\xf5\x80\x80\x80",
    ] {
        assert!(matches!(
            validate_utf8(value),
            Err(Utf8Error::InvalidEncoding(_))
        ));
    }
    for character in [
        '\0',
        '\u{1f}',
        '\u{7f}',
        '\u{80}',
        '\u{9f}',
        '\u{fdd0}',
        '\u{fdef}',
        '\u{fffe}',
        '\u{ffff}',
        '\u{1fffe}',
        '\u{10ffff}',
    ] {
        assert_eq!(
            validate_utf8(character.encode_utf8(&mut [0; 4]).as_bytes()),
            Err(Utf8Error::DisallowedCodePoint { character })
        );
    }
    let valid = " \u{7e}\u{a0}\u{feff}é😀\u{10fffd}";
    assert_eq!(validate_utf8(valid.as_bytes()), Ok(valid));
    assert_eq!(validate_utf8(b""), Ok(""));
    assert!(validate_utf8(&vec![b'a'; 65_536]).is_ok());
    assert_eq!(validate_utf8(&vec![b'a'; 65_537]), Err(Utf8Error::TooLong));

    // lib/packet_datatypes.c: packet__read_string applies the validator in each handler.
    for (wire, field) in [
        (
            connect_frame(0x10, ProtocolVersion::V311, 0x02, b"\0\x01\0"),
            "client identifier",
        ),
        (
            connect_frame(0x10, ProtocolVersion::V311, 0x06, b"\0\x02c1\0\x01\0\0\0"),
            "Will topic",
        ),
        (
            connect_frame(0x10, ProtocolVersion::V311, 0x82, b"\0\x02c1\0\x01\0"),
            "username",
        ),
        (frame(0x30, b"\0\x01\0"), "PUBLISH topic"),
        (frame(0x82, b"\x12\x34\0\x01\0\0"), "subscription filter"),
        (frame(0xa2, b"\x12\x34\0\x01\0"), "unsubscription filter"),
    ] {
        rejected(
            &wire,
            V311,
            DecodeError::InvalidUtf8 {
                field,
                error: Utf8Error::DisallowedCodePoint { character: '\0' },
            },
        );
    }
}

#[test]
fn invalid_packet_models_leave_encoding_destination_untouched() {
    let oversized = "x".repeat(usize::from(u16::MAX) + 1);
    let conn = connect(ProtocolVersion::V311);
    let mut dst = BytesMut::from(&b"prior data"[..]);
    for (packet, expected) in [
        // lib/packet_datatypes.c: packet__write_string has a uint16_t length.
        (
            Packet::Connect(Connect {
                client_id: oversized,
                ..conn.clone()
            }),
            EncodeError::FieldTooLong {
                field: "client identifier",
                len: 65_536,
            },
        ),
        (
            Packet::Connect(Connect {
                username: Some("u".into()),
                password: Some(Bytes::from(vec![0; 65_536])),
                ..conn.clone()
            }),
            EncodeError::FieldTooLong {
                field: "password",
                len: 65_536,
            },
        ),
        // lib/send_connect.c: send__connect checks Will payload size and username requirement.
        (
            Packet::Connect(Connect {
                will: Some(LastWill {
                    topic: "w".into(),
                    payload: Bytes::from(vec![0; 65_536]),
                    qos: QoS::AtMostOnce,
                    retain: false,
                }),
                ..conn.clone()
            }),
            EncodeError::FieldTooLong {
                field: "Will payload",
                len: 65_536,
            },
        ),
        (
            Packet::Connect(Connect {
                password: Some(Bytes::new()),
                ..conn
            }),
            EncodeError::PasswordWithoutUsername,
        ),
        // lib/send_publish.c: send__real_publish only writes a MID for QoS > 0;
        // src/handle_publish.c: handle__publish rejects DUP at QoS 0.
        (
            Packet::Publish(Publish {
                packet_id: Some(ID),
                ..publish()
            }),
            EncodeError::PublishPacketIdMismatch,
        ),
        (
            Packet::Publish(Publish {
                qos: QoS::AtLeastOnce,
                ..publish()
            }),
            EncodeError::PublishPacketIdMismatch,
        ),
        (
            Packet::Publish(Publish {
                dup: true,
                ..publish()
            }),
            EncodeError::DupWithQosZero,
        ),
        // lib/actions_publish.c validates UTF-8 and publish topic syntax on send.
        (
            Packet::Publish(Publish {
                topic: "+".into(),
                ..publish()
            }),
            EncodeError::InvalidTopic {
                field: "PUBLISH topic",
            },
        ),
        (
            Packet::Publish(Publish {
                topic: "\0".into(),
                ..publish()
            }),
            EncodeError::InvalidUtf8 {
                field: "PUBLISH topic",
                error: Utf8Error::DisallowedCodePoint { character: '\0' },
            },
        ),
        // lib/actions_subscribe.c / lib/actions_unsubscribe.c reject empty sends;
        // lib/handle_suback.c rejects an empty SUBACK receipt.
        (
            Packet::Subscribe(Subscribe {
                packet_id: ID,
                filters: vec![],
            }),
            EncodeError::EmptyList("SUBSCRIBE filters"),
        ),
        (
            Packet::Unsubscribe(Unsubscribe {
                packet_id: ID,
                filters: vec![],
            }),
            EncodeError::EmptyList("UNSUBSCRIBE filters"),
        ),
        (
            Packet::SubAck(SubAck {
                packet_id: ID,
                return_codes: vec![],
            }),
            EncodeError::EmptyList("SUBACK return codes"),
        ),
    ] {
        assert_eq!(encode(&packet, &mut dst), Err(expected));
        assert_eq!(&dst[..], b"prior data");
    }
}

// src/handle_subscribe.c and src/handle_unsubscribe.c act on each filter as
// they read it; the filters before an invalid one remain in effect.
#[test]
fn refused_subscription_packets_expose_their_valid_filter_prefix() {
    let subscribe: &[u8] = &[
        0x82, 14, 0, 1, 0, 1, b'a', 1, 0, 5, b'a', b'/', b'#', b'/', b'b', 1,
    ];
    let unsubscribe: &[u8] = &[
        0xa2, 12, 0, 2, 0, 1, b'a', 0, 5, b'a', b'/', b'#', b'/', b'b',
    ];
    for wire in [subscribe, unsubscribe] {
        assert!(matches!(
            decode(&mut BytesMut::from(wire), V311),
            Err(DecodeError::InvalidTopic { .. })
        ));
    }
    assert_eq!(
        mqx_codec::decode_filter_prefix(subscribe, V311),
        Some(Packet::Subscribe(Subscribe {
            packet_id: PacketId::new(1).unwrap(),
            filters: vec![("a".into(), QoS::AtLeastOnce)],
        }))
    );
    assert_eq!(
        mqx_codec::decode_filter_prefix(unsubscribe, V31),
        Some(Packet::Unsubscribe(Unsubscribe {
            packet_id: PacketId::new(2).unwrap(),
            filters: vec!["a".into()],
        }))
    );
    // Nothing precedes the failure, or the failure is not in a filter list.
    for (wire, context) in [
        (&[0x82, 8, 0, 1, 0, 3, b'a', b'#', b'b', 1][..], V311),
        (&[0x82, 6, 0, 1, 0, 1, b'a', 3][..], V311),
        (&[0x80, 6, 0, 1, 0, 1, b'a', 1][..], V311),
        (&[0x30, 3, 0, 1, b'a'][..], V311),
        (
            subscribe,
            DecodeContext::new(10, Some(ProtocolVersion::V311)),
        ),
    ] {
        assert_eq!(
            mqx_codec::decode_filter_prefix(wire, context),
            None,
            "{wire:?}"
        );
    }
}
