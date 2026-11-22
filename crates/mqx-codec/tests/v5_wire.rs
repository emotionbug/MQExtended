use bytes::{Bytes, BytesMut};
use mqx_codec::v5::{
    ConnAck, Connect, DecodeContext, DecodeErrorKind as E, ErrorResponse, LastWill, Packet,
    PacketId, PacketType, Property as P, Publish, PublishAck, QoS, ReasonCode as R,
    ReasonProperties, RetainHandling, Subscribe, Subscription, SubscriptionAck, Unsubscribe,
    decode, encode, peek_connect_protocol_level,
};
use proptest::prelude::*;

const BROKER: DecodeContext = DecodeContext::new(0);
const CLIENT: DecodeContext = DecodeContext::for_client(0);

fn read(wire: &[u8], ctx: DecodeContext) -> Packet {
    let mut input = BytesMut::from(wire);
    let packet = decode(&mut input, ctx)
        .expect("valid wire packet")
        .expect("complete packet");
    assert!(input.is_empty());
    packet
}

fn wire(packet: &Packet) -> BytesMut {
    let mut output = BytesMut::new();
    encode(packet, &mut output).unwrap();
    output
}

fn assert_vector(bytes: &[u8], packet: Packet, ctx: DecodeContext) {
    assert_eq!(read(bytes, ctx), packet);
    assert_eq!(wire(&packet), bytes);
}

fn reject(bytes: &[u8], ctx: DecodeContext, kind: E, response: Option<ErrorResponse>) {
    let mut input = BytesMut::from(bytes);
    let error = decode(&mut input, ctx).unwrap_err();
    assert_eq!(error.kind, kind, "{bytes:02x?}");
    assert_eq!(error.response, response, "{bytes:02x?}");
    assert_eq!(input, bytes);
}

fn id(value: u16) -> PacketId {
    PacketId::new(value).unwrap()
}

fn puback(reason: R) -> PublishAck {
    PublishAck {
        packet_id: id(42),
        reason,
        properties: Vec::new(),
    }
}

#[test]
fn send_functions_emit_byte_exact_vectors_for_every_packet_type() {
    // lib/send_connect.c: send__connect; src/send_connack.c: send__connack;
    // lib/send_publish.c: send__real_publish.
    assert_vector(
        b"\x10\x15\0\x04MQTT\x05\xc2\0\x11\x03\x21\0\x20\0\x01i\0\0\0\0",
        Packet::Connect(Connect {
            private_protocol_bit: false,
            clean_start: true,
            keep_alive: 17,
            properties: vec![P::ReceiveMaximum(32)],
            client_id: "i".into(),
            will: None,
            username: Some(String::new()),
            password: Some(Bytes::new()),
        }),
        BROKER,
    );
    assert_vector(
        b"\x20\x06\x01\x00\x03\x13\x00\x13",
        Packet::ConnAck(ConnAck {
            session_present: true,
            reason: R::SUCCESS,
            properties: vec![P::ServerKeepAlive(19)],
        }),
        CLIENT,
    );
    assert_vector(
        b"\x3b\x0e\0\x03a/b\0\x2a\x03\x23\0\x02\x00\xffx",
        Packet::Publish(Publish {
            dup: true,
            qos: QoS::AtLeastOnce,
            retain: true,
            topic: "a/b".into(),
            packet_id: Some(id(42)),
            properties: vec![P::TopicAlias(2)],
            payload: Bytes::from_static(b"\x00\xffx"),
        }),
        BROKER,
    );

    // lib/send_mosq.c: send__command_with_mid, send__simple_command.
    assert_vector(
        b"\x40\x02\0\x2a",
        Packet::PubAck(puback(R::SUCCESS)),
        BROKER,
    );
    assert_vector(
        b"\x50\x03\0\x2a\x10",
        Packet::PubRec(puback(R::NO_MATCHING_SUBSCRIBERS)),
        CLIENT,
    );
    assert_vector(
        b"\x62\x03\0\x2a\x92",
        Packet::PubRel(puback(R::PACKET_IDENTIFIER_NOT_FOUND)),
        BROKER,
    );
    assert_vector(
        b"\x70\x08\0\x2a\0\x04\x1f\0\x01y",
        Packet::PubComp(PublishAck {
            properties: vec![P::ReasonString("y".into())],
            ..puback(R::SUCCESS)
        }),
        CLIENT,
    );
    assert_vector(b"\xc0\0", Packet::PingReq, BROKER);
    assert_vector(b"\xd0\0", Packet::PingResp, CLIENT);

    // lib/send_subscribe.c and lib/send_unsubscribe.c; src/send_suback.c and src/send_unsuback.c.
    assert_vector(
        b"\x82\x0c\0\x2a\x03\x0b\x80\x01\0\x03a/+\x1d",
        Packet::Subscribe(Subscribe {
            packet_id: id(42),
            properties: vec![P::SubscriptionIdentifier(128)],
            subscriptions: vec![Subscription {
                filter: "a/+".into(),
                qos: QoS::AtLeastOnce,
                no_local: true,
                retain_as_published: true,
                retain_handling: RetainHandling::SendIfNew,
            }],
        }),
        BROKER,
    );
    assert_vector(
        b"\x90\x05\0\x2a\0\x01\x87",
        Packet::SubAck(SubscriptionAck {
            packet_id: id(42),
            properties: Vec::new(),
            reasons: vec![R::GRANTED_QOS_1, R::NOT_AUTHORIZED],
        }),
        CLIENT,
    );
    assert_vector(
        b"\xa2\x08\0\x2a\0\0\x03a/+",
        Packet::Unsubscribe(Unsubscribe {
            packet_id: id(42),
            properties: Vec::new(),
            filters: vec!["a/+".into()],
        }),
        BROKER,
    );
    assert_vector(
        b"\xb0\x05\0\x2a\0\x00\x11",
        Packet::UnsubAck(SubscriptionAck {
            packet_id: id(42),
            properties: Vec::new(),
            reasons: vec![R::SUCCESS, R::NO_SUBSCRIPTION_EXISTED],
        }),
        CLIENT,
    );

    // lib/send_disconnect.c: send__disconnect; src/send_auth.c: send__auth.
    assert_vector(
        b"\xe0\x01\x8b",
        Packet::Disconnect(ReasonProperties {
            reason: R::SERVER_SHUTTING_DOWN,
            properties: Vec::new(),
        }),
        CLIENT,
    );
    assert_vector(
        b"\xf0\x0a\x18\x08\x15\0\x01m\x16\0\x01\xff",
        Packet::Auth(ReasonProperties {
            reason: R::CONTINUE_AUTHENTICATION,
            properties: vec![
                P::AuthenticationMethod("m".into()),
                P::AuthenticationData(Bytes::from_static(b"\xff")),
            ],
        }),
        BROKER,
    );
}

#[test]
fn property_types_and_identifiers_are_byte_exact_in_wire_order() {
    // lib/property_mosq.c: property__read and property__write; values are ordered.
    let publish: &[u8] = b"\x30\x2c\0\x01t\x28\x01\x01\x02\x01\x02\x03\x04\x03\0\x01c\x08\0\x01r\x09\0\x02\0\xff\x0b\xff\xff\xff\x7f\x23\x12\x34\x26\0\0\0\x01i\x26\0\x01i\0\0";
    assert_vector(
        publish,
        Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "t".into(),
            packet_id: None,
            properties: vec![
                P::PayloadFormatIndicator(1),
                P::MessageExpiryInterval(0x0102_0304),
                P::ContentType("c".into()),
                P::ResponseTopic("r".into()),
                P::CorrelationData(Bytes::from_static(b"\0\xff")),
                P::SubscriptionIdentifier(268_435_455),
                P::TopicAlias(0x1234),
                P::UserProperty("".into(), "i".into()),
                P::UserProperty("i".into(), "".into()),
            ],
            payload: Bytes::new(),
        }),
        CLIENT,
    );

    let connack: &[u8] = b"\x20\x30\0\0\x2d\x11\0\0\0\x13\x12\0\x01i\x13\0\x05\x1a\0\x01r\x1c\0\x01s\x1f\0\x01x\x21\0\x20\x22\0\x04\x24\x01\x25\x00\x27\x01\x02\x03\x04\x28\x01\x29\x00\x2a\x01";
    assert_vector(
        connack,
        Packet::ConnAck(ConnAck {
            session_present: false,
            reason: R::SUCCESS,
            properties: vec![
                P::SessionExpiryInterval(19),
                P::AssignedClientIdentifier("i".into()),
                P::ServerKeepAlive(5),
                P::ResponseInformation("r".into()),
                P::ServerReference("s".into()),
                P::ReasonString("x".into()),
                P::ReceiveMaximum(32),
                P::TopicAliasMaximum(4),
                P::MaximumQos(1),
                P::RetainAvailable(0),
                P::MaximumPacketSize(0x0102_0304),
                P::WildcardSubscriptionAvailable(1),
                P::SubscriptionIdentifierAvailable(0),
                P::SharedSubscriptionAvailable(1),
            ],
        }),
        CLIENT,
    );

    let connect: &[u8] = b"\x10\x1e\0\x04MQTT\x05\x34\0\0\x04\x17\x00\x19\x01\0\x01i\x05\x18\0\0\0\x05\0\x01w\0\x01\xff";
    assert_vector(
        connect,
        Packet::Connect(Connect {
            private_protocol_bit: false,
            clean_start: false,
            keep_alive: 0,
            properties: vec![
                P::RequestProblemInformation(0),
                P::RequestResponseInformation(1),
            ],
            client_id: "i".into(),
            will: Some(LastWill {
                properties: vec![P::WillDelayInterval(5)],
                topic: "w".into(),
                payload: Bytes::from_static(b"\xff"),
                qos: QoS::ExactlyOnce,
                retain: true,
            }),
            username: None,
            password: None,
        }),
        BROKER,
    );
}

#[test]
fn broker_dispatches_connect_without_waiting_for_the_payload() {
    for (prefix, level) in [
        (b"\x10\x80\x02\0\x06MQIsdp\x83".as_slice(), 0x83),
        (b"\x10\x20\0\x04MQTT\x04", 4),
        (b"\x10\x20\0\x04MQTT\x05", 5),
        (b"\x10\x20\0\x06MQTT\0X\x05", 5),
        (b"\x10\x20\0\x06MQTT\0X\x04", 4),
        (b"\x10\x20\0\x06MQTT\0X\x03", 3),
        (b"\x10\x20\0\x06MQIsdp\x05", 5),
    ] {
        for i in 0..prefix.len() {
            assert_eq!(peek_connect_protocol_level(&prefix[..i]).unwrap(), None);
        }
        assert_eq!(peek_connect_protocol_level(prefix).unwrap(), Some(level));
    }
    let err = peek_connect_protocol_level(b"\x10\x02\0\x04MQTT\x05").unwrap_err();
    assert_eq!(err.kind, E::Truncated("protocol level"));
    assert!(matches!(
        peek_connect_protocol_level(b"\x30").unwrap_err().kind,
        E::ExpectedConnect(0x30)
    ));
}

#[test]
fn connect_protocol_name_is_compared_as_a_c_string() {
    // src/handle_connect.c: read_protocol_name consumes the full six bytes,
    // but read_and_verify_protocol_version stops comparing at NUL.
    let embedded_nul = b"\x10\x11\0\x06MQTT\0X\x05\x02\0<\0\0\x02c1";
    let canonical = b"\x10\x0f\0\x04MQTT\x05\x02\0<\0\0\x02c1";
    let packet = read(embedded_nul, BROKER);
    assert_eq!(packet, read(canonical, BROKER));
    assert_eq!(wire(&packet), &canonical[..]);
    reject(
        b"\x10\x11\0\x06MQTTXX\x05\x02\0<\0\0\x02c1",
        BROKER,
        E::UnknownProtocolName,
        None,
    );
}

#[test]
fn mqtt_31_protocol_name_with_level_5_requests_a_legacy_connack() {
    // src/handle_connect.c: read_and_verify_protocol_version sends the refusal
    // before setting the negotiated protocol to MQTT 5.
    let raw = b"\x10\x11\0\x06MQIsdp\x05\x02\0<\0\0\x02c1";
    let mut input = BytesMut::from(raw.as_slice());
    let error = decode(&mut input, BROKER).unwrap_err();
    assert_eq!(error.kind, E::UnacceptableProtocolVersion(5));
    let Some(ErrorResponse::LegacyConnAck(code)) = error.response else {
        panic!("expected a legacy CONNACK, got {:?}", error.response);
    };
    assert_eq!(input, raw.as_slice());
    let mut response = BytesMut::new();
    mqx_codec::encode(
        &mqx_codec::Packet::ConnAck(mqx_codec::ConnAck {
            session_present: false,
            code,
        }),
        &mut response,
    )
    .unwrap();
    assert_eq!(response, &b"\x20\x02\0\x01"[..]);
}

#[test]
fn framing_and_body_varints_have_different_minimality_rules() {
    // lib/packet_mosq.c: packet__read_single and packet__check_in_packet_oversize.
    assert_eq!(
        read(b"\xc0\x80\x80\x00", DecodeContext::new(2)),
        Packet::PingReq
    );
    let mut input = BytesMut::from(&b"\xc0\x80\x80\x80\x80"[..]);
    assert!(decode(&mut input, BROKER).unwrap().is_none());
    input.extend_from_slice(b"\x00");
    reject(&input, BROKER, E::MalformedRemainingLength, None);
    reject(
        b"\x00",
        BROKER,
        E::ReservedPacketType,
        Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR)),
    );
    reject(
        b"\xc0\x01",
        BROKER,
        E::InvalidRemainingLength {
            packet: PacketType::PingReq,
            length: 1,
        },
        None,
    );
    reject(
        b"\x30\x04",
        DecodeContext::new(5),
        E::PacketTooLarge { size: 6, max: 5 },
        Some(ErrorResponse::Disconnect(R::PACKET_TOO_LARGE)),
    );

    // lib/packet_datatypes.c: packet__read_varint rejects a zero continuation byte.
    let malformed = Some(ErrorResponse::Disconnect(R::MALFORMED_PACKET));
    reject(
        b"\x30\x05\0\x01t\x80\x00",
        BROKER,
        E::InvalidVarInt("property length"),
        malformed,
    );
    reject(
        b"\x30\x07\0\x01t\x03\x81\x00\x01",
        BROKER,
        E::InvalidVarInt("property identifier"),
        malformed,
    );
    reject(
        b"\x30\x07\0\x01t\x03\x0b\x81\x00",
        CLIENT,
        E::InvalidVarInt("subscription identifier"),
        malformed,
    );
    reject(
        b"\x30\x09\0\x01t\x05\x0b\x80\x80\x80\x80",
        CLIENT,
        E::InvalidVarInt("subscription identifier"),
        malformed,
    );
    reject(
        b"\x30\x06\0\x01t\x01\x01\x00",
        BROKER,
        E::Truncated("payload format indicator"),
        malformed,
    );
    reject(
        b"\x30\x04\0\x01t\x01",
        BROKER,
        E::Truncated("properties"),
        malformed,
    );
}

#[test]
fn property_errors_keep_the_mosquitto_reason_and_packet_scope() {
    // lib/property_mosq.c: property__read unknown identifiers are malformed.
    // libcommon/property_common.c: mosquitto_property_check_all handles semantic errors.
    let protocol = Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR));
    let malformed = Some(ErrorResponse::Disconnect(R::MALFORMED_PACKET));
    reject(
        b"\x30\x05\0\x01t\x01\x7f",
        BROKER,
        E::UnknownProperty(0x7f),
        malformed,
    );
    reject(
        b"\x30\x06\0\x01t\x02\x01\x02",
        BROKER,
        E::InvalidPropertyValue(1),
        protocol,
    );
    reject(
        b"\x30\x08\0\x01t\x04\x01\x01\x01\x00",
        BROKER,
        E::DuplicateProperty(1),
        protocol,
    );
    reject(
        b"\x30\x08\0\x01t\x04\x0b\x01\x0b\x02",
        CLIENT,
        E::DuplicateProperty(0x0b),
        protocol,
    );
    reject(
        b"\x30\x06\0\x01t\x02\x19\x00",
        BROKER,
        E::PropertyNotAllowed(0x19),
        protocol,
    );
    reject(
        b"\x30\x08\0\x01t\x04\x08\0\x01+",
        BROKER,
        E::InvalidPropertyValue(8),
        protocol,
    );
    reject(
        b"\x30\x07\0\x01t\x03\x08\0\x00",
        BROKER,
        E::InvalidPropertyValue(8),
        protocol,
    );
    reject(
        b"\x30\x07\0\x01t\x03\x23\0\x00",
        BROKER,
        E::InvalidPropertyValue(0x23),
        protocol,
    );
    reject(
        b"\x20\x06\x00\x00\x03\x21\x00\x00",
        CLIENT,
        E::InvalidPropertyValue(0x21),
        protocol,
    );
    reject(
        b"\x20\x08\x00\x00\x05\x27\x00\x00\x00\x00",
        CLIENT,
        E::InvalidPropertyValue(0x27),
        protocol,
    );
    // src/handle_subscribe.c / src/handle_unsubscribe.c turn property protocol errors into malformed packets.
    reject(
        b"\x82\x05\0\x01\x02\x01\x00",
        BROKER,
        E::PropertyNotAllowed(1),
        malformed,
    );
    reject(
        b"\xa2\x05\0\x01\x02\x01\x00",
        BROKER,
        E::PropertyNotAllowed(1),
        malformed,
    );
    reject(
        b"\x82\x05\0\x01\x02\x0b\x00",
        BROKER,
        E::InvalidPropertyValue(0x0b),
        protocol,
    );
}

#[test]
fn property_string_pairs_use_mosquitto_utf8_but_binary_does_not() {
    // lib/packet_datatypes.c: packet__read_string and packet__read_binary;
    // lib/read_handle.c maps malformed UTF-8 to a malformed-packet disconnect,
    // whereas src/read_handle.c leaves it to handlers.
    let bytes = b"\x30\x0a\0\x01t\x06\x26\0\0\0\x01\x00";
    for (ctx, response) in [
        (BROKER, None),
        (CLIENT, Some(ErrorResponse::Disconnect(R::MALFORMED_PACKET))),
    ] {
        let mut input = BytesMut::from(&bytes[..]);
        let error = decode(&mut input, ctx).unwrap_err();
        assert!(matches!(
            error.kind,
            E::InvalidUtf8 {
                field: "user property value",
                ..
            }
        ));
        assert_eq!(error.response, response);
        assert_eq!(input, &bytes[..]);
    }
    assert!(
        matches!(read(b"\x30\x08\0\x01t\x04\x09\0\x01\xff", BROKER), Packet::Publish(p) if p.properties == [P::CorrelationData(Bytes::from_static(b"\xff"))])
    );
}

#[test]
fn connect_failures_distinguish_connack_codes_from_silent_close() {
    // src/handle_connect.c: read_and_verify_protocol_version, read_and_verify_connect_flags,
    // read_and_verify_v5_connect_properties, read_and_verify_clientid_from_packet,
    // will__read, and check_additional_trailing_data.
    reject(
        b"\x10\x07\0\x04MQTT\x06",
        BROKER,
        E::UnacceptableProtocolVersion(6),
        Some(ErrorResponse::ConnAck(R::UNSUPPORTED_PROTOCOL_VERSION)),
    );
    reject(
        b"\x11\x07\0\x04MQTT\x05",
        BROKER,
        E::InvalidFixedHeaderFlags(0x11),
        None,
    );
    reject(
        b"\x10\x08\0\x04MQTT\x05\x01",
        BROKER,
        E::ReservedConnectFlag,
        None,
    );
    reject(
        b"\x10\x0c\0\x04MQTT\x05\0\0\0\x01\x7f",
        BROKER,
        E::UnknownProperty(0x7f),
        Some(ErrorResponse::ConnAck(R::MALFORMED_PACKET)),
    );
    reject(
        b"\x10\x0d\0\x04MQTT\x05\0\0\0\x02\x17\x02",
        BROKER,
        E::InvalidPropertyValue(0x17),
        Some(ErrorResponse::ConnAck(R::PROTOCOL_ERROR)),
    );
    reject(
        b"\x10\x0f\0\x04MQTT\x05\0\0\0\x04\x16\0\x01\xff",
        BROKER,
        E::MissingAuthenticationMethod,
        Some(ErrorResponse::ConnAck(R::PROTOCOL_ERROR)),
    );
    reject(
        b"\x10\x0d\0\x04MQTT\x05\x08\0\0\0\0\0",
        BROKER,
        E::WillFlagsWithoutWill,
        None,
    );
    reject(
        b"\x10\x0d\0\x04MQTT\x05\x1c\0\0\0\0\0",
        BROKER,
        E::InvalidQos {
            field: "Will",
            value: 3,
        },
        None,
    );
    reject(
        b"\x10\x10\0\x04MQTT\x05\x04\0\0\0\0\0\0\0\0",
        BROKER,
        E::InvalidTopic("Will topic"),
        Some(ErrorResponse::ConnAck(R::PROTOCOL_ERROR)),
    );
    reject(
        b"\x10\x0e\0\x04MQTT\x05\0\0\0\0\0\0x",
        BROKER,
        E::TrailingData(PacketType::Connect),
        Some(ErrorResponse::ConnAck(R::MALFORMED_PACKET)),
    );
    let mut invalid_id = BytesMut::from(&b"\x10\x0e\0\x04MQTT\x05\0\0\0\0\0\x01\x00"[..]);
    let error = decode(&mut invalid_id, BROKER).unwrap_err();
    assert!(matches!(
        error.kind,
        E::InvalidUtf8 {
            field: "client identifier",
            ..
        }
    ));
    assert_eq!(
        error.response,
        Some(ErrorResponse::ConnAck(R::CLIENT_IDENTIFIER_NOT_VALID))
    );

    let password_only = b"\x10\x11\0\x04MQTT\x05\x40\0\0\0\0\0\0\x02\0\xff";
    let Packet::Connect(packet) = read(password_only, BROKER) else {
        panic!("expected CONNECT")
    };
    assert!(packet.client_id.is_empty()); // v5 allows this even without Clean Start.
    assert_eq!(packet.username, None);
    assert_eq!(packet.password.as_deref(), Some(&b"\0\xff"[..]));
    assert_eq!(wire(&Packet::Connect(packet)), &password_only[..]);
    let private = b"\x10\x0d\0\x04MQTT\x85\x02\0\0\0\x01i";
    let packet = read(private, BROKER);
    assert!(
        matches!(&packet, Packet::Connect(packet) if packet.private_protocol_bit && packet.properties.is_empty())
    );
    assert_eq!(wire(&packet), &private[..]);
}

#[test]
fn publish_enforces_wire_alias_rules_not_the_alias_table() {
    // src/handle_publish.c: handle__publish; src/property_broker.c and
    // lib/handle_publish.c: property__process_publish.
    let protocol = Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR));
    let malformed = Some(ErrorResponse::Disconnect(R::MALFORMED_PACKET));
    reject(b"\x38\x04\0\x01t\0", BROKER, E::DupWithQosZero, malformed);
    assert!(matches!(read(b"\x38\x04\0\x01t\0", CLIENT), Packet::Publish(p) if p.dup));
    reject(
        b"\x36\x00",
        BROKER,
        E::InvalidQos {
            field: "PUBLISH",
            value: 3,
        },
        malformed,
    );
    reject(b"\x32\x06\0\x01t\0\0\0", BROKER, E::ZeroPacketId, protocol);
    reject(
        b"\x30\x03\0\0\0",
        BROKER,
        E::InvalidTopic("missing publish topic and alias"),
        malformed,
    );
    reject(
        b"\x30\x03\0\0\0",
        CLIENT,
        E::InvalidTopic("missing publish topic and alias"),
        protocol,
    );
    reject(
        b"\x30\x04\0\x01+\0",
        BROKER,
        E::InvalidTopic("publish topic"),
        malformed,
    );
    let alias = b"\x30\x06\0\0\x03\x23\0\x02";
    assert!(
        matches!(read(alias, BROKER.with_topic_alias_maximum(2)), Packet::Publish(p) if p.topic.is_empty() && p.properties == [P::TopicAlias(2)])
    );
    reject(
        alias,
        BROKER.with_topic_alias_maximum(1),
        E::TopicAliasOutOfRange { alias: 2, max: 1 },
        Some(ErrorResponse::Disconnect(R::TOPIC_ALIAS_INVALID)),
    );
    let subscription_id = b"\x30\x06\0\x01t\x02\x0b\x01";
    reject(
        subscription_id,
        BROKER,
        E::InvalidPropertyValue(0x0b),
        protocol,
    );
    assert_eq!(
        read(subscription_id, CLIENT),
        read(subscription_id, DecodeContext::for_bridge(0))
    );
}

#[test]
fn filters_and_subscription_options_follow_handler_order() {
    // src/handle_subscribe.c: handle__subscribe; src/handle_unsubscribe.c:
    // handle__unsubscribe; src/topic_tok.c: sub__topic_tokenise.
    let protocol = Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR));
    let malformed = Some(ErrorResponse::Disconnect(R::MALFORMED_PACKET));
    reject(b"\x82\x03\0\0\0", BROKER, E::ZeroPacketId, malformed);
    reject(
        b"\xa2\x03\0\x01\0",
        BROKER,
        E::EmptyList("unsubscription filters"),
        malformed,
    );
    reject(
        b"\x82\x03\0\x01\0",
        BROKER,
        E::EmptyList("subscriptions"),
        malformed,
    );
    reject(
        b"\x82\x05\0\x01\0\0\0",
        BROKER,
        E::EmptyList("subscriptions"),
        malformed,
    );
    let expected = read(b"\x82\x07\0\x01\0\0\x01t\0", BROKER);
    assert_eq!(read(b"\x82\x09\0\x01\0\0\0\0\x01t\0", BROKER), expected);
    reject(
        b"\x82\x07\0\x01\0\0\x01t\x30",
        BROKER,
        E::InvalidSubscriptionOptions(0x30),
        malformed,
    );
    reject(
        b"\x82\x07\0\x01\0\0\x01t\x80",
        BROKER,
        E::InvalidSubscriptionOptions(0x80),
        malformed,
    );
    reject(
        b"\x82\x07\0\x01\0\0\x01t\x03",
        BROKER,
        E::InvalidQos {
            field: "subscription",
            value: 3,
        },
        malformed,
    );
    reject(
        b"\x82\x10\0\x01\0\0\x0a$share/g/t\x84",
        BROKER,
        E::SharedSubscriptionNoLocal,
        protocol,
    );
    reject(
        b"\x82\x10\0\x01\0\0\x0a$share/+/t\0",
        BROKER,
        E::InvalidSharedFilter,
        protocol,
    );
    reject(
        b"\x82\x0f\0\x01\0\0\x09$share/g/\0",
        BROKER,
        E::InvalidSharedFilter,
        protocol,
    );
    assert!(matches!(
        read(b"\x82\x0f\0\x01\0\0\x09$share//t\0", BROKER),
        Packet::Subscribe(_)
    ));
    reject(
        b"\xa2\x07\0\x01\0\0\x02+x",
        BROKER,
        E::InvalidTopic("unsubscription filter"),
        malformed,
    );
}

#[test]
fn optional_reason_fields_and_reserved_flags_match_each_handler() {
    // lib/handle_pubackcomp.c: handle__pubackcomp; lib/handle_pubrec.c:
    // handle__pubrec; lib/handle_pubrel.c: handle__pubrel; src/handle_disconnect.c.
    let protocol = Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR));
    let malformed = Some(ErrorResponse::Disconnect(R::MALFORMED_PACKET));
    let ack = Packet::PubAck(puback(R::SUCCESS));
    for frame in [
        b"\x40\x02\0\x2a".as_slice(),
        b"\x40\x03\0\x2a\0",
        b"\x40\x04\0\x2a\0\0",
    ] {
        assert_eq!(read(frame, BROKER), ack);
    }
    reject(
        b"\x6a\x02\0\x2a",
        BROKER,
        E::InvalidFixedHeaderFlags(0x6a),
        protocol,
    );
    reject(
        b"\x41\x02\0\x2a",
        BROKER,
        E::InvalidFixedHeaderFlags(0x41),
        malformed,
    );
    reject(b"\x50\x02\0\0", BROKER, E::ZeroPacketId, protocol);
    reject(
        b"\x40\x04\0\x2a\x95\xff",
        BROKER,
        E::Truncated("property length"),
        malformed,
    );
    reject(
        b"\x50\x04\0\x2a\x95\xff",
        BROKER,
        E::InvalidReasonCode {
            packet: PacketType::PubRec,
            reason: R::PACKET_TOO_LARGE,
        },
        protocol,
    );
    reject(
        b"\x70\x05\0\x2a\0\0\x42",
        BROKER,
        E::TrailingData(PacketType::PubComp),
        malformed,
    );
    assert_eq!(
        wire(&Packet::PubAck(puback(R::PACKET_TOO_LARGE))),
        &b"\x40\x03\0\x2a\x95"[..]
    );
    reject(
        b"\xe1\0",
        BROKER,
        E::InvalidFixedHeaderFlags(0xe1),
        protocol,
    );
    reject(
        b"\xe0\x03\0\0\0",
        BROKER,
        E::TrailingData(PacketType::Disconnect),
        protocol,
    );
    assert_vector(
        b"\xe0\0",
        Packet::Disconnect(ReasonProperties::default()),
        BROKER,
    );
    assert_eq!(
        read(b"\xe0\x02\0\xff", CLIENT),
        Packet::Disconnect(ReasonProperties::default())
    );
    assert_eq!(
        read(b"\x20\x04\x01\xff\0\x2a", CLIENT),
        Packet::ConnAck(ConnAck {
            session_present: true,
            reason: R(255),
            properties: vec![]
        })
    );
    assert_eq!(
        read(b"\x90\x04\0\x2a\0\xff", CLIENT),
        Packet::SubAck(SubscriptionAck {
            packet_id: id(42),
            properties: vec![],
            reasons: vec![R(255)]
        })
    );
    reject(
        b"\x90\x03\0\x2a\0",
        CLIENT,
        E::EmptyList("SUBACK reasons"),
        protocol,
    );
    assert_vector(
        b"\xb0\x03\0\x2a\0",
        Packet::UnsubAck(SubscriptionAck {
            packet_id: id(42),
            properties: vec![],
            reasons: vec![],
        }),
        CLIENT,
    );
}

#[test]
fn auth_receivers_apply_different_wire_rules() {
    // src/handle_auth.c: handle__auth and lib/handle_auth.c: handle__auth.
    assert_eq!(
        read(b"\xf0\0", BROKER),
        Packet::Auth(ReasonProperties::default())
    );
    reject(b"\xf0\0", CLIENT, E::Truncated("reason code"), None);
    assert_eq!(
        read(b"\xf0\x02\0\0", CLIENT),
        Packet::Auth(ReasonProperties::default())
    );
    reject(
        b"\xf0\x02\0\0",
        BROKER,
        E::InvalidReasonCode {
            packet: PacketType::Auth,
            reason: R::SUCCESS,
        },
        Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR)),
    );
    let unspecified = Some(ErrorResponse::Disconnect(R::UNSPECIFIED_ERROR));
    reject(
        b"\xf0\x02\x18\0",
        BROKER,
        E::MissingAuthenticationMethod,
        unspecified,
    );
    reject(
        b"\xf0\x03\x18\x01\x7f",
        BROKER,
        E::UnknownProperty(0x7f),
        unspecified,
    );
    reject(
        b"\xf0\x05\x18\x03\x15\0\0",
        BROKER,
        E::MissingAuthenticationMethod,
        Some(ErrorResponse::Disconnect(R::PROTOCOL_ERROR)),
    );
}

#[test]
fn encoder_rejects_invalid_values_without_touching_output() {
    let mut output = BytesMut::from(&b"already here"[..]);
    let bad = Packet::ConnAck(ConnAck {
        session_present: false,
        reason: R::SUCCESS,
        properties: vec![P::MaximumQos(2)],
    });
    assert!(encode(&bad, &mut output).is_err());
    let bad = Packet::PubAck(PublishAck {
        properties: vec![P::ReasonString("a".repeat(65_536))],
        ..puback(R::SUCCESS)
    });
    assert!(encode(&bad, &mut output).is_err());
    let bad = Packet::PubAck(PublishAck {
        properties: vec![
            P::ReasonString("first".into()),
            P::ReasonString("second".into()),
        ],
        ..puback(R::SUCCESS)
    });
    assert!(encode(&bad, &mut output).is_err());
    assert_eq!(output, &b"already here"[..]);
}

fn all_packets(
    id: PacketId,
    text: &str,
    binary: &Bytes,
    n: u32,
    flags: u8,
) -> Vec<(Packet, DecodeContext)> {
    let user = || P::UserProperty(text.into(), "é".into());
    let reason = if flags & 1 != 0 {
        R::NOT_AUTHORIZED
    } else {
        R::SUCCESS
    };
    let retain = flags & 2 != 0;
    let qos = [QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce][usize::from(flags % 3)];
    let publish_id = (qos != QoS::AtMostOnce).then_some(id);
    let ack = |reason, with_props| PublishAck {
        packet_id: id,
        reason,
        properties: if with_props {
            vec![P::ReasonString(text.into()), user()]
        } else {
            vec![]
        },
    };
    let suback = |reason| SubscriptionAck {
        packet_id: id,
        reasons: vec![reason],
        properties: vec![user()],
    };
    let secret = vec![
        P::AuthenticationMethod("method".into()),
        P::AuthenticationData(binary.clone()),
    ];
    let mut config = secret.clone();
    config.push(P::SessionExpiryInterval(n));
    config.push(user());
    let private_protocol_bit = flags & 32 != 0;
    vec![
        (
            Packet::Connect(Connect {
                private_protocol_bit,
                clean_start: flags & 64 != 0,
                keep_alive: n as u16,
                properties: if private_protocol_bit { vec![] } else { config },
                client_id: text.into(),
                will: (flags & 4 != 0).then(|| LastWill {
                    properties: vec![
                        P::WillDelayInterval(n),
                        P::CorrelationData(binary.clone()),
                        user(),
                    ],
                    topic: "will/test".into(),
                    payload: binary.clone(),
                    qos,
                    retain,
                }),
                username: (flags & 8 != 0).then(|| text.into()),
                password: (flags & 16 != 0).then(|| binary.clone()),
            }),
            BROKER,
        ),
        (
            Packet::ConnAck(ConnAck {
                session_present: false,
                reason,
                properties: vec![P::ServerKeepAlive(n as u16), user()],
            }),
            CLIENT,
        ),
        (
            Packet::Publish(Publish {
                dup: publish_id.is_some() && flags & 4 != 0,
                qos,
                retain,
                packet_id: publish_id,
                topic: if flags & 2 != 0 {
                    String::new()
                } else {
                    "test/topic".into()
                },
                properties: vec![
                    P::TopicAlias(42),
                    P::SubscriptionIdentifier(n),
                    P::CorrelationData(binary.clone()),
                    user(),
                    user(),
                ],
                payload: binary.clone(),
            }),
            CLIENT,
        ),
        (Packet::PubAck(ack(reason, flags & 8 != 0)), BROKER),
        (
            Packet::PubRec(ack(R::NO_MATCHING_SUBSCRIBERS, flags & 16 != 0)),
            CLIENT,
        ),
        (
            Packet::PubRel(ack(R::PACKET_IDENTIFIER_NOT_FOUND, flags & 32 != 0)),
            BROKER,
        ),
        (Packet::PubComp(ack(R::SUCCESS, flags & 64 != 0)), CLIENT),
        (
            Packet::Subscribe(Subscribe {
                packet_id: id,
                properties: vec![P::SubscriptionIdentifier(n), user()],
                subscriptions: vec![Subscription {
                    filter: "test/+".into(),
                    qos,
                    no_local: retain,
                    retain_as_published: flags & 128 != 0,
                    retain_handling: [
                        RetainHandling::SendAlways,
                        RetainHandling::SendIfNew,
                        RetainHandling::DoNotSend,
                    ][usize::from(flags % 3)],
                }],
            }),
            BROKER,
        ),
        (Packet::SubAck(suback(R::GRANTED_QOS_2)), CLIENT),
        (
            Packet::Unsubscribe(Unsubscribe {
                packet_id: id,
                properties: vec![user()],
                filters: vec!["test/+".into(), "$share/test/#".into()],
            }),
            BROKER,
        ),
        (Packet::UnsubAck(suback(R::NO_SUBSCRIPTION_EXISTED)), CLIENT),
        (Packet::PingReq, BROKER),
        (Packet::PingResp, CLIENT),
        (
            Packet::Disconnect(ReasonProperties {
                reason,
                properties: if flags & 4 != 0 {
                    vec![P::SessionExpiryInterval(n), user()]
                } else {
                    vec![]
                },
            }),
            BROKER,
        ),
        (
            Packet::Auth(ReasonProperties {
                reason: if flags & 1 != 0 {
                    R::REAUTHENTICATE
                } else {
                    R::CONTINUE_AUTHENTICATION
                },
                properties: secret,
            }),
            BROKER,
        ),
    ]
}

#[test]
fn connect_binary_fields_share_the_input_without_consuming_the_next_packet() {
    let marker = Bytes::from_static(b"\xff\xfe\xfd\xfc");
    let packets = all_packets(id(7), "client", &marker, 42, 28);
    let mut input = wire(&packets[0].0);
    encode(&Packet::PingReq, &mut input).unwrap();
    let offsets: Vec<_> = input
        .windows(marker.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == marker).then_some(offset))
        .map(|offset| input[offset..].as_ptr())
        .collect();

    let Some(Packet::Connect(packet)) = decode(&mut input, BROKER).unwrap() else {
        panic!("expected CONNECT");
    };
    let will = packet.will.unwrap();
    let P::AuthenticationData(auth) = &packet.properties[1] else {
        panic!("expected authentication bytes");
    };
    let P::CorrelationData(correlation) = &will.properties[1] else {
        panic!("expected Will correlation bytes");
    };
    assert_eq!(
        offsets,
        [
            auth.as_ptr(),
            correlation.as_ptr(),
            will.payload.as_ptr(),
            packet.password.unwrap().as_ptr()
        ]
    );
    assert_eq!(decode(&mut input, BROKER).unwrap(), Some(Packet::PingReq));
}

proptest! {
    #[test]
    fn all_packet_types_round_trip_and_split_streams_equate(
        packet_id in 1..=u16::MAX, text in "[a-zA-Z0-9/ ]{0,80}",
        binary in prop::collection::vec(any::<u8>(), 0..512),
        n in 1..=268_435_455u32, flags in any::<u8>(), chunk in 1..75usize,
    ) {
        let packets = all_packets(id(packet_id), &text, &binary.into(), n, flags);
        let mut stream = BytesMut::new();
        for (packet, ctx) in &packets {
            let wire = wire(packet);
            prop_assert_eq!(read(&wire, *ctx), packet.clone());
            stream.extend_from_slice(&wire);
        }
        let mut incremental = BytesMut::new();
        let mut index = 0;
        for fragment in stream.chunks(chunk) {
            incremental.extend_from_slice(fragment);
            while let Some((expected, ctx)) = packets.get(index) {
                let Some(actual) = decode(&mut incremental, *ctx).unwrap() else { break };
                prop_assert_eq!(&actual, expected);
                index += 1;
            }
        }
        prop_assert_eq!(index, packets.len());
        prop_assert!(incremental.is_empty());
    }

    #[test]
    fn arbitrary_bytes_never_panic_or_change_buffer_on_failure(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        for ctx in [BROKER, CLIENT, DecodeContext::for_bridge(1024).with_topic_alias_maximum(7)] {
            let mut input = BytesMut::from(bytes.as_slice());
            loop {
                let before = input.len();
                match decode(&mut input, ctx) {
                    Ok(Some(_)) => prop_assert!(input.len() < before),
                    Ok(None) | Err(_) => {
                        prop_assert_eq!(&input[..], &bytes[bytes.len() - before..]);
                        break;
                    }
                }
            }
        }
        let _ = peek_connect_protocol_level(&bytes);
    }
}
