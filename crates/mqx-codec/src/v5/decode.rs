use std::ops::Range;

use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;

use super::property::{BinaryProperty, PropertyBlock, PropertyScope, has_auth_method};
use super::{
    ConnAck, Connect, LastWill, Packet, PacketId, PacketType, Property, Publish, PublishAck, QoS,
    ReasonCode, ReasonProperties, RetainHandling, Subscribe, Subscription, SubscriptionAck,
    Unsubscribe, valid_publish_ack_reason, valid_shared_filter,
};
use crate::{Utf8Error, remaining_length_bytes, valid_topic, validate_utf8};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeContext {
    /// Configured maximum packet size including the canonical header, or zero for no limit.
    pub max_packet_size: usize,
    /// Limit advertised to the sender, if known. `Some(0)` disables aliases.
    pub topic_alias_maximum: Option<u16>,
    receiver: Receiver,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Receiver {
    #[default]
    Broker,
    Client,
    BrokerBridge,
}

impl DecodeContext {
    pub const fn new(max_packet_size: usize) -> Self {
        Self {
            max_packet_size,
            topic_alias_maximum: None,
            receiver: Receiver::Broker,
        }
    }

    /// Applies libmosquitto's receive rules. This does not restrict packet direction.
    pub const fn for_client(max_packet_size: usize) -> Self {
        Self {
            receiver: Receiver::Client,
            ..Self::new(max_packet_size)
        }
    }

    /// Applies the broker receive rules for a configured bridge connection.
    pub const fn for_bridge(max_packet_size: usize) -> Self {
        Self {
            receiver: Receiver::BrokerBridge,
            ..Self::new(max_packet_size)
        }
    }

    pub const fn with_topic_alias_maximum(mut self, maximum: u16) -> Self {
        self.topic_alias_maximum = Some(maximum);
        self
    }

    fn client(self) -> bool {
        self.receiver == Receiver::Client
    }
}

/// The first reply Mosquitto sends for this wire failure, if any. Connection
/// state may mean the caller must close without sending a packet instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorResponse {
    ConnAck(ReasonCode),
    Disconnect(ReasonCode),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct DecodeError {
    #[source]
    pub kind: DecodeErrorKind,
    pub response: Option<ErrorResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeErrorKind {
    #[error("reserved MQTT packet type")]
    ReservedPacketType,
    #[error("expected CONNECT, got command {0:#04x}")]
    ExpectedConnect(u8),
    #[error("malformed remaining length")]
    MalformedRemainingLength,
    #[error("packet size {size} exceeds the configured maximum of {max}")]
    PacketTooLarge { size: usize, max: usize },
    #[error("invalid fixed-header flags in command {0:#04x}")]
    InvalidFixedHeaderFlags(u8),
    #[error("invalid length {length} for {packet:?}")]
    InvalidRemainingLength { packet: PacketType, length: usize },
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("invalid variable byte integer for {0}")]
    InvalidVarInt(&'static str),
    #[error("unknown CONNECT protocol name")]
    UnknownProtocolName,
    #[error("unacceptable CONNECT protocol level {0:#04x}")]
    UnacceptableProtocolVersion(u8),
    #[error("reserved CONNECT flag is set")]
    ReservedConnectFlag,
    #[error("CONNECT sets Will QoS or retain without a Will")]
    WillFlagsWithoutWill,
    #[error("invalid {field} QoS {value}")]
    InvalidQos { field: &'static str, value: u8 },
    #[error("PUBLISH sets DUP with QoS 0")]
    DupWithQosZero,
    #[error("packet identifier is zero")]
    ZeroPacketId,
    #[error("invalid CONNACK flags {0:#04x}")]
    InvalidConnAckFlags(u8),
    #[error("invalid reason code {reason:?} for {packet:?}")]
    InvalidReasonCode {
        packet: PacketType,
        reason: ReasonCode,
    },
    #[error("unknown property {0:#04x}")]
    UnknownProperty(u32),
    #[error("property {0:#04x} is not allowed in this packet")]
    PropertyNotAllowed(u8),
    #[error("duplicate property {0:#04x}")]
    DuplicateProperty(u8),
    #[error("invalid value for property {0:#04x}")]
    InvalidPropertyValue(u8),
    #[error("authentication method is absent or empty")]
    MissingAuthenticationMethod,
    #[error("topic alias {alias} exceeds the advertised maximum of {max}")]
    TopicAliasOutOfRange { alias: u16, max: u16 },
    #[error("invalid UTF-8 in {field}: {error}")]
    InvalidUtf8 {
        field: &'static str,
        #[source]
        error: Utf8Error,
    },
    #[error("invalid {0}")]
    InvalidTopic(&'static str),
    #[error("invalid shared subscription filter")]
    InvalidSharedFilter,
    #[error("shared subscription sets No Local")]
    SharedSubscriptionNoLocal,
    #[error("invalid subscription options {0:#04x}")]
    InvalidSubscriptionOptions(u8),
    #[error("empty {0} list")]
    EmptyList(&'static str),
    #[error("trailing bytes in {0:?}")]
    TrailingData(PacketType),
}

use DecodeErrorKind as Fault;
use ReasonCode as R;

impl Fault {
    fn without_reply(self) -> DecodeError {
        DecodeError {
            kind: self,
            response: None,
        }
    }

    fn connack(self, reason: ReasonCode) -> DecodeError {
        DecodeError {
            kind: self,
            response: Some(ErrorResponse::ConnAck(reason)),
        }
    }

    fn disconnect(self, reason: ReasonCode) -> DecodeError {
        DecodeError {
            kind: self,
            response: Some(ErrorResponse::Disconnect(reason)),
        }
    }

    // src/read_handle.c: handle__packet and lib/read_handle.c: handle__packet
    // translate handler failures, not all failures from the framing layer.
    fn for_packet(self, kind: PacketType, ctx: DecodeContext) -> DecodeError {
        use PacketType::*;
        let reason = match &self {
            Self::InvalidUtf8 {
                field: "publish topic" | "subscription filter" | "unsubscription filter",
                ..
            } => R::MALFORMED_PACKET,
            Self::InvalidUtf8 { .. } if !ctx.client() => return self.without_reply(),
            Self::InvalidPropertyValue(0x0b) if kind == Subscribe => R::PROTOCOL_ERROR,
            Self::PropertyNotAllowed(_) | Self::InvalidPropertyValue(_) | Self::ZeroPacketId
                if matches!(kind, Subscribe | Unsubscribe) =>
            {
                R::MALFORMED_PACKET
            }
            Self::InvalidFixedHeaderFlags(_) if kind == Disconnect && ctx.client() => {
                R::MALFORMED_PACKET
            }
            Self::InvalidFixedHeaderFlags(_) if matches!(kind, PubRel | Disconnect) => {
                R::PROTOCOL_ERROR
            }
            Self::ReservedPacketType
            | Self::InvalidConnAckFlags(_)
            | Self::InvalidReasonCode { .. }
            | Self::PropertyNotAllowed(_)
            | Self::DuplicateProperty(_)
            | Self::InvalidPropertyValue(_)
            | Self::ZeroPacketId
            | Self::SharedSubscriptionNoLocal
            | Self::InvalidSharedFilter
            | Self::MissingAuthenticationMethod => R::PROTOCOL_ERROR,
            Self::TopicAliasOutOfRange { .. } => R::TOPIC_ALIAS_INVALID,
            Self::TrailingData(Disconnect) | Self::EmptyList("SUBACK reasons") => R::PROTOCOL_ERROR,
            Self::InvalidQos { .. } if kind == Publish && ctx.client() => R::PROTOCOL_ERROR,
            Self::InvalidTopic("missing publish topic and alias") if ctx.client() => {
                R::PROTOCOL_ERROR
            }
            _ => R::MALFORMED_PACKET,
        };
        self.disconnect(reason)
    }

    // src/handle_connect.c: read_and_verify_v5_connect_properties and handle__connect.
    fn for_connect_properties(self) -> DecodeError {
        match self {
            Self::InvalidPropertyValue(_)
            | Self::PropertyNotAllowed(_)
            | Self::DuplicateProperty(_) => self.connack(R::PROTOCOL_ERROR),
            Self::InvalidUtf8 { .. } => self.without_reply(),
            _ => self.connack(R::MALFORMED_PACKET),
        }
    }
}

#[derive(Clone, Copy)]
struct Header {
    command: u8,
    kind: PacketType,
    start: usize,
    end: usize,
}

impl Header {
    fn read(src: &[u8]) -> Result<Option<Self>, Fault> {
        let Some(&command) = src.first() else {
            return Ok(None);
        };
        let kind = PacketType::from_command(command).ok_or(Fault::ReservedPacketType)?;
        let mut length = 0;
        // lib/packet_mosq.c: packet__read_single accepts non-minimal Remaining
        // Length encodings and only rejects the continued value on byte five.
        for (i, &byte) in src[1..].iter().take(5).enumerate() {
            if i == 4 {
                return Err(Fault::MalformedRemainingLength);
            }
            length |= usize::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                let start = i + 2;
                return Ok(Some(Self {
                    command,
                    kind,
                    start,
                    end: start + length,
                }));
            }
        }
        Ok(None)
    }
}

/// Read a buffered CONNECT's raw protocol level (3, 4, 5, or another level, with
/// the high bit preserved). Returns `None` until that byte arrives; does not
/// wait for the payload, consume bytes, or validate the rest of CONNECT.
pub fn peek_connect_protocol_level(src: &[u8]) -> Result<Option<u8>, DecodeError> {
    if let Some(&command) = src.first()
        && command & 0xf0 != crate::CONNECT
    {
        return Err(Fault::ExpectedConnect(command).without_reply());
    }
    let Some(header) = Header::read(src).map_err(Fault::without_reply)? else {
        return Ok(None);
    };
    let body = &src[header.start..src.len().min(header.end)];
    if header.end - header.start < 2 {
        return Err(Fault::Truncated("protocol name length").without_reply());
    }
    let Some(prefix) = body.get(..2) else {
        return Ok(None);
    };
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if !matches!(length, 4 | 6) {
        return Err(Fault::UnknownProtocolName.without_reply());
    }
    if header.end - header.start <= 2 + length {
        return Err(Fault::Truncated("protocol level").without_reply());
    }
    let Some(name) = body.get(2..2 + length) else {
        return Ok(None);
    };
    if !matches!(name, b"MQTT" | b"MQIsdp") {
        return Err(Fault::UnknownProtocolName.without_reply());
    }
    Ok(body.get(2 + length).copied())
}

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            end: bytes.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pos == self.end
    }

    fn take(&mut self, size: usize, field: &'static str) -> Result<Range<usize>, Fault> {
        if size > self.end - self.pos {
            return Err(Fault::Truncated(field));
        }
        let start = self.pos;
        self.pos += size;
        Ok(start..self.pos)
    }

    fn rest(&mut self) -> Range<usize> {
        let pos = self.pos;
        self.pos = self.end;
        pos..self.end
    }

    pub(super) fn block(&mut self, size: usize, field: &'static str) -> Result<Self, Fault> {
        let span = self.take(size, field)?;
        Ok(Self {
            bytes: self.bytes,
            pos: span.start,
            end: span.end,
        })
    }

    pub(super) fn byte(&mut self, field: &'static str) -> Result<u8, Fault> {
        Ok(self.bytes[self.take(1, field)?.start])
    }

    pub(super) fn u16(&mut self, field: &'static str) -> Result<u16, Fault> {
        let span = self.take(2, field)?;
        Ok(u16::from_be_bytes(
            self.bytes[span].try_into().expect("two bytes"),
        ))
    }

    pub(super) fn u32(&mut self, field: &'static str) -> Result<u32, Fault> {
        let span = self.take(4, field)?;
        Ok(u32::from_be_bytes(
            self.bytes[span].try_into().expect("four bytes"),
        ))
    }

    pub(super) fn varint(&mut self, field: &'static str) -> Result<u32, Fault> {
        let mut result = 0;
        // lib/packet_datatypes.c: packet__read_varint rejects non-minimal body varints.
        for i in 0..4 {
            let byte = self.byte(field)?;
            result |= u32::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return if i > 0 && byte == 0 {
                    Err(Fault::InvalidVarInt(field))
                } else {
                    Ok(result)
                };
            }
        }
        Err(Fault::InvalidVarInt(field))
    }

    pub(super) fn binary(&mut self, field: &'static str) -> Result<Range<usize>, Fault> {
        let length = usize::from(self.u16(field)?);
        self.take(length, field)
    }

    pub(super) fn string(&mut self, field: &'static str) -> Result<String, Fault> {
        let span = self.binary(field)?;
        validate_utf8(&self.bytes[span])
            .map(str::to_owned)
            .map_err(|error| Fault::InvalidUtf8 { field, error })
    }

    fn packet_id(&mut self) -> Result<PacketId, Fault> {
        PacketId::new(self.u16("packet identifier")?).ok_or(Fault::ZeroPacketId)
    }

    fn no_trailing(&self, kind: PacketType) -> Result<(), Fault> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Fault::TrailingData(kind))
        }
    }
}

#[derive(Default)]
struct Binaries {
    property: Option<BinaryProperty>,
    will_property: Option<BinaryProperty>,
    payload: Option<Range<usize>>,
    password: Option<Range<usize>>,
}

impl Binaries {
    fn finish(self, packet: &mut Packet, src: &mut BytesMut, header: Header) {
        if self.property.is_none()
            && self.will_property.is_none()
            && self.payload.is_none()
            && self.password.is_none()
        {
            src.advance(header.end);
            return;
        }
        src.advance(header.start);
        let frame = src.split_to(header.end - header.start).freeze();
        if let Some(property) = self.property {
            let properties = match packet {
                Packet::Connect(packet) => &mut packet.properties,
                Packet::ConnAck(packet) => &mut packet.properties,
                Packet::Publish(packet) => &mut packet.properties,
                Packet::Auth(packet) => &mut packet.properties,
                _ => unreachable!("invalid binary property scope"),
            };
            property.fill(properties, &frame);
        }
        if let Packet::Connect(connect) = packet {
            if let Some(span) = self.password {
                connect.password = Some(frame.slice(span));
            }
            if let Some(will) = &mut connect.will {
                if let Some(span) = self.payload {
                    will.payload = frame.slice(span);
                }
                if let Some(property) = self.will_property {
                    property.fill(&mut will.properties, &frame);
                }
            }
        } else if let Packet::Publish(publish) = packet
            && let Some(span) = self.payload
        {
            publish.payload = frame.slice(span);
        }
    }
}

/// Decode one packet. Incomplete and invalid input leave the buffer unchanged.
/// Binary values share the input allocation; strings are owned by the packet.
pub fn decode(src: &mut BytesMut, ctx: DecodeContext) -> Result<Option<Packet>, DecodeError> {
    let Some(header) = Header::read(src).map_err(|fault| match fault {
        Fault::ReservedPacketType => fault.disconnect(R::PROTOCOL_ERROR),
        _ => fault.without_reply(),
    })?
    else {
        return Ok(None);
    };
    let kind = header.kind;
    let length = header.end - header.start;
    let size = 1 + remaining_length_bytes(length) + length;
    if !ctx.client() && matches!(kind, PacketType::PingReq | PacketType::PingResp) && length != 0 {
        return Err(Fault::InvalidRemainingLength {
            packet: kind,
            length,
        }
        .without_reply());
    }
    if ctx.max_packet_size != 0 && size > ctx.max_packet_size {
        let fault = Fault::PacketTooLarge {
            size,
            max: ctx.max_packet_size,
        };
        return Err(if kind == PacketType::Connect {
            fault.without_reply()
        } else {
            fault.disconnect(R::PACKET_TOO_LARGE)
        });
    }
    let Some(body) = src.get(header.start..header.end) else {
        return Ok(None);
    };
    let mut cursor = Cursor::new(body);
    let mut binaries = Binaries::default();
    let mut packet = if kind == PacketType::Connect {
        Packet::Connect(read_connect(&mut cursor, header.command, &mut binaries)?)
    } else {
        if kind != PacketType::Publish && header.command != kind.command() {
            return Err(Fault::InvalidFixedHeaderFlags(header.command).for_packet(kind, ctx));
        }
        if kind == PacketType::Auth {
            Packet::Auth(read_auth(&mut cursor, ctx, &mut binaries)?)
        } else {
            read_packet(&mut cursor, header, ctx, &mut binaries)
                .map_err(|fault| fault.for_packet(kind, ctx))?
        }
    };
    binaries.finish(&mut packet, src, header);
    Ok(Some(packet))
}

fn read_connect(
    cur: &mut Cursor<'_>,
    command: u8,
    binaries: &mut Binaries,
) -> Result<Connect, DecodeError> {
    // src/handle_connect.c: read_protocol_name and read_and_verify_protocol_version.
    let name_len = usize::from(
        cur.u16("protocol name length")
            .map_err(Fault::without_reply)?,
    );
    if !matches!(name_len, 4 | 6) {
        return Err(Fault::UnknownProtocolName.without_reply());
    }
    let name = cur
        .take(name_len, "protocol name")
        .map_err(Fault::without_reply)?;
    let level = cur.byte("protocol level").map_err(Fault::without_reply)?;
    if cur.bytes[name] != *b"MQTT" {
        return Err(Fault::UnknownProtocolName.without_reply());
    }
    if level & 0x7f != 5 {
        return Err(
            Fault::UnacceptableProtocolVersion(level).connack(R::UNSUPPORTED_PROTOCOL_VERSION)
        );
    }
    if command != PacketType::Connect.command() {
        return Err(Fault::InvalidFixedHeaderFlags(command).without_reply());
    }
    let flags = cur.byte("CONNECT flags").map_err(Fault::without_reply)?;
    if flags & 1 != 0 {
        return Err(Fault::ReservedConnectFlag.without_reply());
    }
    let keep_alive = cur.u16("keep alive").map_err(Fault::without_reply)?;
    let private_protocol_bit = level != 5;
    let properties = if private_protocol_bit {
        PropertyBlock::default()
    } else {
        PropertyBlock::read(cur, PacketType::Connect.into())
            .map_err(Fault::for_connect_properties)?
    };
    let will_qos_value = (flags >> 3) & 3;
    let will_qos = QoS::from_wire(will_qos_value).ok_or_else(|| {
        Fault::InvalidQos {
            field: "Will",
            value: will_qos_value,
        }
        .without_reply()
    })?;
    if properties.binary.is_some() && !has_auth_method(&properties.values) {
        return Err(Fault::MissingAuthenticationMethod.connack(R::PROTOCOL_ERROR));
    }
    binaries.property = properties.binary;
    let client_id = cur
        .string("client identifier")
        .map_err(|fault| match fault {
            Fault::InvalidUtf8 { .. } => fault.connack(R::CLIENT_IDENTIFIER_NOT_VALID),
            _ => fault.without_reply(),
        })?;
    let will_retain = flags & crate::WILL_RETAIN_FLAG != 0;
    let will = if flags & crate::WILL_FLAG != 0 {
        let properties =
            PropertyBlock::read(cur, PropertyScope::Will).map_err(Fault::for_connect_properties)?;
        binaries.will_property = properties.binary;
        let topic = cur
            .string("Will topic")
            .map_err(Fault::for_connect_properties)?;
        // src/handle_connect.c: will__read sends a protocol CONNACK for an
        // empty topic, but closes silently for invalid syntax or $CONTROL.
        if topic.is_empty() {
            return Err(Fault::InvalidTopic("Will topic").connack(R::PROTOCOL_ERROR));
        }
        if !valid_topic(&topic, false) || topic.starts_with("$CONTROL/") {
            return Err(Fault::InvalidTopic("Will topic").without_reply());
        }
        let payload = cur
            .binary("Will payload")
            .map_err(Fault::for_connect_properties)?;
        binaries.payload = (!payload.is_empty()).then_some(payload);
        Some(LastWill {
            properties: properties.values,
            topic,
            payload: Bytes::new(),
            qos: will_qos,
            retain: will_retain,
        })
    } else {
        if will_qos != QoS::AtMostOnce || will_retain {
            return Err(Fault::WillFlagsWithoutWill.without_reply());
        }
        None
    };
    let username = if flags & crate::USERNAME_FLAG != 0 {
        Some(cur.string("username").map_err(Fault::without_reply)?)
    } else {
        None
    };
    let password = if flags & crate::PASSWORD_FLAG != 0 {
        let password = cur.binary("password").map_err(Fault::without_reply)?;
        binaries.password = (!password.is_empty()).then_some(password);
        Some(Bytes::new())
    } else {
        None
    };
    cur.no_trailing(PacketType::Connect).map_err(|fault| {
        if private_protocol_bit {
            fault.without_reply()
        } else {
            fault.connack(R::MALFORMED_PACKET)
        }
    })?;
    Ok(Connect {
        private_protocol_bit,
        clean_start: flags & crate::CLEAN_SESSION_FLAG != 0,
        keep_alive,
        properties: properties.values,
        client_id,
        will,
        username,
        password,
    })
}

fn read_packet(
    cur: &mut Cursor<'_>,
    header: Header,
    ctx: DecodeContext,
    binaries: &mut Binaries,
) -> Result<Packet, Fault> {
    let kind = header.kind;
    Ok(match kind {
        PacketType::ConnAck => {
            let flags = cur.byte("CONNACK flags")?;
            if flags & 0xfe != 0 {
                return Err(Fault::InvalidConnAckFlags(flags));
            }
            let reason = ReasonCode(cur.byte("reason code")?);
            let props = PropertyBlock::read(cur, kind.into())?;
            binaries.property = props.binary;
            // lib/handle_connack.c: handle__connack delivers the raw reason and
            // does not check for trailing bytes after valid properties.
            Packet::ConnAck(ConnAck {
                session_present: flags != 0,
                reason,
                properties: props.values,
            })
        }
        PacketType::Publish => Packet::Publish(read_publish(cur, header.command, ctx, binaries)?),
        PacketType::PubAck => Packet::PubAck(read_publish_ack(cur, kind)?),
        PacketType::PubRec => Packet::PubRec(read_publish_ack(cur, kind)?),
        PacketType::PubRel => Packet::PubRel(read_publish_ack(cur, kind)?),
        PacketType::PubComp => Packet::PubComp(read_publish_ack(cur, kind)?),
        PacketType::Subscribe => Packet::Subscribe(read_subscribe(cur)?),
        PacketType::Unsubscribe => Packet::Unsubscribe(read_unsubscribe(cur)?),
        PacketType::SubAck => Packet::SubAck(read_subscription_ack(cur, kind)?),
        PacketType::UnsubAck => Packet::UnsubAck(read_subscription_ack(cur, kind)?),
        PacketType::PingReq | PacketType::PingResp => {
            if !cur.is_empty() {
                return Err(Fault::InvalidRemainingLength {
                    packet: kind,
                    length: cur.end,
                });
            }
            if kind == PacketType::PingReq {
                Packet::PingReq
            } else {
                Packet::PingResp
            }
        }
        PacketType::Disconnect => Packet::Disconnect(read_disconnect(cur, ctx)?),
        PacketType::Connect | PacketType::Auth => {
            unreachable!("packet with specialized error reporting")
        }
    })
}

fn read_publish(
    cur: &mut Cursor<'_>,
    command: u8,
    ctx: DecodeContext,
    binaries: &mut Binaries,
) -> Result<Publish, Fault> {
    let dup = command & crate::DUP_FLAG != 0;
    let qos_value = (command >> 1) & 3;
    // src/handle_publish.c: handle__publish rejects QoS 0 DUP, unlike the client.
    if dup && qos_value == 0 && !ctx.client() {
        return Err(Fault::DupWithQosZero);
    }
    let qos = QoS::from_wire(qos_value).ok_or(Fault::InvalidQos {
        field: "PUBLISH",
        value: qos_value,
    })?;
    let topic = cur.string("publish topic")?;
    let packet_id = if qos != QoS::AtMostOnce {
        Some(cur.packet_id()?)
    } else {
        None
    };
    let properties = PropertyBlock::read(cur, PacketType::Publish.into())?;
    let mut alias = None;
    for property in &properties.values {
        match *property {
            // src/property_broker.c and lib/handle_publish.c: property__process_publish.
            Property::SubscriptionIdentifier(value)
                if ctx.receiver == Receiver::Broker || value == 0 =>
            {
                return Err(Fault::InvalidPropertyValue(property.identifier()));
            }
            Property::TopicAlias(value) => {
                // The client checks the alias while walking the properties;
                // the broker checks after processing the whole property list.
                if ctx.client()
                    && let Some(max) = ctx.topic_alias_maximum
                    && value > max
                {
                    return Err(Fault::TopicAliasOutOfRange { alias: value, max });
                }
                alias = Some(value);
            }
            _ => {}
        }
    }
    if !ctx.client()
        && let (Some(alias), Some(max)) = (alias, ctx.topic_alias_maximum)
        && alias > max
    {
        return Err(Fault::TopicAliasOutOfRange { alias, max });
    }
    if topic.is_empty() {
        if alias.is_none() {
            return Err(Fault::InvalidTopic("missing publish topic and alias"));
        }
    } else if !valid_topic(&topic, false) {
        return Err(Fault::InvalidTopic("publish topic"));
    }
    binaries.property = properties.binary;
    let payload = cur.rest();
    binaries.payload = (!payload.is_empty()).then_some(payload);
    Ok(Publish {
        dup,
        qos,
        retain: command & crate::RETAIN_FLAG != 0,
        topic,
        packet_id,
        properties: properties.values,
        payload: Bytes::new(),
    })
}

fn read_publish_ack(cur: &mut Cursor<'_>, kind: PacketType) -> Result<PublishAck, Fault> {
    let packet_id = cur.packet_id()?;
    if cur.is_empty() {
        return Ok(PublishAck {
            packet_id,
            reason: R::SUCCESS,
            properties: Vec::new(),
        });
    }
    let reason = ReasonCode(cur.byte("reason code")?);
    let valid = valid_publish_ack_reason(kind, reason);
    let checks_reason_first = matches!(kind, PacketType::PubRec | PacketType::PubRel);
    if checks_reason_first && !valid {
        return Err(Fault::InvalidReasonCode {
            packet: kind,
            reason,
        });
    }
    let properties = if cur.is_empty() {
        Vec::new()
    } else {
        PropertyBlock::read(cur, kind.into())?.values
    };
    if !valid {
        return Err(Fault::InvalidReasonCode {
            packet: kind,
            reason,
        });
    }
    cur.no_trailing(kind)?;
    Ok(PublishAck {
        packet_id,
        reason,
        properties,
    })
}

fn read_subscribe(cur: &mut Cursor<'_>) -> Result<Subscribe, Fault> {
    let packet_id = cur.packet_id()?;
    let properties = PropertyBlock::read(cur, PacketType::Subscribe.into())?.values;
    if properties
        .iter()
        .any(|p| matches!(p, Property::SubscriptionIdentifier(0)))
    {
        return Err(Fault::InvalidPropertyValue(0x0b));
    }
    let mut subscriptions = Vec::new();
    while !cur.is_empty() {
        let filter = cur.string("subscription filter")?;
        // src/handle_subscribe.c: handle__subscribe skips a NULL string without
        // reading options, but ultimately requires at least one subscription.
        if filter.is_empty() {
            continue;
        }
        if !valid_topic(&filter, true) {
            return Err(Fault::InvalidTopic("subscription filter"));
        }
        let options = cur.byte("subscription options")?;
        let no_local = options & 4 != 0;
        if no_local && filter.starts_with("$share/") {
            return Err(Fault::SharedSubscriptionNoLocal);
        }
        let retain_handling = match options >> 4 {
            0 => RetainHandling::SendAlways,
            1 => RetainHandling::SendIfNew,
            2 => RetainHandling::DoNotSend,
            _ => return Err(Fault::InvalidSubscriptionOptions(options)),
        };
        let value = options & 3;
        let qos = QoS::from_wire(value).ok_or(Fault::InvalidQos {
            field: "subscription",
            value,
        })?;
        if !valid_shared_filter(&filter) {
            return Err(Fault::InvalidSharedFilter);
        }
        subscriptions.push(Subscription {
            filter,
            qos,
            no_local,
            retain_as_published: options & 8 != 0,
            retain_handling,
        });
    }
    if subscriptions.is_empty() {
        return Err(Fault::EmptyList("subscriptions"));
    }
    Ok(Subscribe {
        packet_id,
        properties,
        subscriptions,
    })
}

fn read_unsubscribe(cur: &mut Cursor<'_>) -> Result<Unsubscribe, Fault> {
    let packet_id = cur.packet_id()?;
    let properties = PropertyBlock::read(cur, PacketType::Unsubscribe.into())?.values;
    let mut filters = Vec::new();
    while !cur.is_empty() {
        let filter = cur.string("unsubscription filter")?;
        if !valid_topic(&filter, true) {
            return Err(Fault::InvalidTopic("unsubscription filter"));
        }
        if !valid_shared_filter(&filter) {
            return Err(Fault::InvalidSharedFilter);
        }
        filters.push(filter);
    }
    if filters.is_empty() {
        return Err(Fault::EmptyList("unsubscription filters"));
    }
    Ok(Unsubscribe {
        packet_id,
        properties,
        filters,
    })
}

fn read_subscription_ack(cur: &mut Cursor<'_>, kind: PacketType) -> Result<SubscriptionAck, Fault> {
    let packet_id = cur.packet_id()?;
    let properties = PropertyBlock::read(cur, kind.into())?.values;
    // lib/handle_suback.c and lib/handle_unsuback.c: reason bytes are passed
    // through; only SUBACK enforces a non-empty list.
    let bytes = cur.rest();
    if kind == PacketType::SubAck && bytes.is_empty() {
        return Err(Fault::EmptyList("SUBACK reasons"));
    }
    let reasons = cur.bytes[bytes].iter().copied().map(ReasonCode).collect();
    Ok(SubscriptionAck {
        packet_id,
        properties,
        reasons,
    })
}

fn read_disconnect(cur: &mut Cursor<'_>, ctx: DecodeContext) -> Result<ReasonProperties, Fault> {
    let kind = PacketType::Disconnect;
    if cur.is_empty() && !ctx.client() {
        return Ok(ReasonProperties::default());
    }
    let reason = ReasonCode(cur.byte("reason code")?);
    // lib/handle_disconnect.c: handle__disconnect checks length > 2, not > 1,
    // and ignores trailing data. src/handle_disconnect.c: handle__disconnect
    // parses any present property block and requires it to finish the packet.
    let properties = if if ctx.client() {
        cur.end > 2
    } else {
        !cur.is_empty()
    } {
        PropertyBlock::read(cur, kind.into())?.values
    } else {
        Vec::new()
    };
    if !ctx.client() {
        cur.no_trailing(kind)?
    }
    Ok(ReasonProperties { reason, properties })
}

fn read_auth(
    cur: &mut Cursor<'_>,
    ctx: DecodeContext,
    binaries: &mut Binaries,
) -> Result<ReasonProperties, DecodeError> {
    // src/handle_auth.c: handle__auth accepts implicit success, but not an
    // explicit success reason from the client. lib/handle_auth.c: handle__auth
    // requires a reason and properties, but delegates the reason to the callback.
    let kind = PacketType::Auth;
    if cur.is_empty() {
        if ctx.client() {
            return Err(Fault::Truncated("reason code").without_reply());
        }
        return Ok(ReasonProperties::default());
    }
    let reason = ReasonCode(
        cur.byte("reason code")
            .map_err(|fault| fault.for_packet(kind, ctx))?,
    );
    if !ctx.client() && !matches!(reason, R::CONTINUE_AUTHENTICATION | R::REAUTHENTICATE) {
        return Err(Fault::InvalidReasonCode {
            packet: kind,
            reason,
        }
        .disconnect(R::PROTOCOL_ERROR));
    }
    let properties = PropertyBlock::read(cur, kind.into()).map_err(|fault| {
        if ctx.client() {
            fault.for_packet(kind, ctx)
        } else {
            fault.disconnect(R::UNSPECIFIED_ERROR)
        }
    })?;
    if !ctx.client() && !has_auth_method(&properties.values) {
        let method_present = properties
            .values
            .iter()
            .any(|property| matches!(property, Property::AuthenticationMethod(_)));
        return Err(
            Fault::MissingAuthenticationMethod.disconnect(if method_present {
                R::PROTOCOL_ERROR
            } else {
                R::UNSPECIFIED_ERROR
            }),
        );
    }
    binaries.property = properties.binary;
    Ok(ReasonProperties {
        reason,
        properties: properties.values,
    })
}
