use std::ops::Range;

use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;

use super::{
    CLEAN_SESSION_FLAG, CONNACK, CONNECT, ConnAck, Connect, ConnectReturnCode, DISCONNECT,
    DUP_FLAG, LastWill, PASSWORD_FLAG, PINGREQ, PINGRESP, PUBACK, PUBCOMP, PUBLISH, PUBREC, PUBREL,
    Packet, PacketId, ProtocolVersion, Publish, QoS, RETAIN_FLAG, SUBACK, SUBSCRIBE, SubAck,
    Subscribe, SubscribeReturnCode, UNSUBACK, UNSUBSCRIBE, USERNAME_FLAG, Unsubscribe, Utf8Error,
    WILL_FLAG, WILL_QOS_MASK, WILL_RETAIN_FLAG, connect_protocol_name, remaining_length_bytes,
    valid_topic, validate_utf8,
};

/// The caller supplies the negotiated version; CONNECT always uses its own version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeContext {
    /// Maximum packet size including header, or zero for no configured limit.
    pub max_packet_size: usize,
    /// `None` before negotiation. Version-dependent checks default to 3.1.1.
    pub protocol: Option<ProtocolVersion>,
    client_receiver: bool,
}

impl DecodeContext {
    /// Applies Mosquitto's broker-side checks where the broker and client differ.
    pub const fn new(max_packet_size: usize, protocol: Option<ProtocolVersion>) -> Self {
        Self {
            max_packet_size,
            protocol,
            client_receiver: false,
        }
    }

    /// Applies libmosquitto's receive behavior where it differs from the broker.
    /// This doesn't enforce connection state or forbid decoding any packet type.
    pub const fn for_client(max_packet_size: usize, protocol: Option<ProtocolVersion>) -> Self {
        Self {
            max_packet_size,
            protocol,
            client_receiver: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("unsupported MQTT packet type {0:#x}")]
    UnknownPacketType(u8),
    #[error("remaining length uses more than four bytes")]
    MalformedRemainingLength,
    #[error("packet size {size} exceeds the configured maximum of {max}")]
    PacketTooLarge { size: usize, max: usize },
    #[error("packet type {packet_type:#x} has remaining length {actual}, expected {expected}")]
    InvalidRemainingLength {
        packet_type: u8,
        expected: usize,
        actual: usize,
    },
    #[error("invalid fixed-header flags in command {0:#04x}")]
    InvalidFixedHeaderFlags(u8),
    #[error("truncated {field}")]
    Truncated { field: &'static str },
    #[error("unknown CONNECT protocol name")]
    UnknownProtocolName,
    /// Distinguishes version refusal from an unknown protocol name (disconnect only).
    #[error("unacceptable CONNECT protocol level {level:#04x}")]
    UnacceptableProtocolVersion { level: u8 },
    #[error("reserved CONNECT flag is set")]
    ReservedConnectFlag,
    #[error("CONNECT sets Will QoS or retain without a Will")]
    WillFlagsWithoutWill,
    #[error("CONNECT sets the password flag without the username flag")]
    PasswordWithoutUsername,
    #[error("invalid {field} QoS byte {value:#04x}")]
    InvalidQos { field: &'static str, value: u8 },
    #[error("PUBLISH sets DUP with QoS 0")]
    DupWithQosZero,
    #[error("invalid UTF-8 in {field}: {error}")]
    InvalidUtf8 {
        field: &'static str,
        #[source]
        error: Utf8Error,
    },
    #[error("invalid {field}")]
    InvalidTopic { field: &'static str },
    #[error("packet identifier is zero")]
    ZeroPacketId,
    #[error("empty {0} list")]
    EmptyList(&'static str),
    #[error("invalid CONNACK flags {0:#04x}")]
    InvalidConnAckFlags(u8),
    #[error("invalid CONNACK return code {0:#04x}")]
    InvalidConnectReturnCode(u8),
    #[error("trailing bytes in CONNECT")]
    TrailingConnectData,
}

struct Frame {
    command: u8,
    body_start: usize,
    end: usize,
}

impl Frame {
    fn parse(src: &[u8], context: DecodeContext) -> Result<Option<Self>, DecodeError> {
        let Some(&command) = src.first() else {
            return Ok(None);
        };
        let kind = command & 0xf0;
        if kind == 0 || kind == 0xf0 {
            return Err(DecodeError::UnknownPacketType(kind >> 4));
        }

        // lib/packet_mosq.c: packet__read_single accepts non-minimal encodings.
        let mut length = 0;
        for index in 0..4 {
            let Some(&byte) = src.get(index + 1) else {
                return Ok(None);
            };
            length |= usize::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                // lib/packet_mosq.c: packet__check_in_packet_oversize uses the
                // canonical header size for its configured limit, not the wire width.
                let size = 1 + remaining_length_bytes(length) + length;
                if context.max_packet_size != 0 && size > context.max_packet_size {
                    return Err(DecodeError::PacketTooLarge {
                        size,
                        max: context.max_packet_size,
                    });
                }
                let exact_length = match kind {
                    CONNACK | PUBACK | PUBREC | PUBREL | PUBCOMP => Some(2),
                    UNSUBACK if !context.client_receiver => Some(2),
                    PINGREQ | PINGRESP | DISCONNECT => Some(0),
                    _ => None,
                };
                if let Some(expected) = exact_length
                    && length != expected
                {
                    return Err(DecodeError::InvalidRemainingLength {
                        packet_type: kind >> 4,
                        expected,
                        actual: length,
                    });
                }
                let body_start = index + 2;
                let end = body_start + length;
                return Ok((src.len() >= end).then_some(Self {
                    command,
                    body_start,
                    end,
                }));
            }
        }
        // lib/packet_mosq.c: packet__read_single rejects a continued length
        // only when the fifth byte arrives, whatever its value.
        if src.len() < 6 {
            return Ok(None);
        }
        Err(DecodeError::MalformedRemainingLength)
    }

    fn cursor<'a>(&self, src: &'a [u8]) -> Cursor<'a> {
        Cursor {
            bytes: &src[..self.end],
            pos: self.body_start,
        }
    }

    fn consume(&self, src: &mut BytesMut, keep_bytes: bool) -> Bytes {
        if keep_bytes {
            src.split_to(self.end).freeze()
        } else {
            src.advance(self.end);
            Bytes::new()
        }
    }
}

/// Decode one packet, leaving the buffer unchanged on incomplete input or error.
/// Binary fields share the input allocation; strings are owned by the packet.
/// The caller decides which packet types are legal in its current session state.
pub fn decode(src: &mut BytesMut, context: DecodeContext) -> Result<Option<Packet>, DecodeError> {
    let Some(frame) = Frame::parse(src, context)? else {
        return Ok(None);
    };
    let v31 = context.protocol == Some(ProtocolVersion::V31);
    let kind = frame.command & 0xf0;
    let expected = match kind {
        CONNECT | PUBLISH => None,
        // PUBREL and DISCONNECT, unlike SUBSCRIBE and UNSUBSCRIBE, have no
        // unconditional command-byte check in the Mosquitto v3.1 handlers.
        PUBREL if v31 => None,
        DISCONNECT if v31 => None,
        PUBREL | SUBSCRIBE | UNSUBSCRIBE => Some(kind | 2),
        _ => Some(kind),
    };
    if let Some(expected) = expected {
        check_command(frame.command, expected)?;
    }
    if kind == CONNECT {
        return decode_connect(src, &frame).map(Some);
    }
    if kind == PUBLISH {
        return decode_publish(src, &frame, context.client_receiver).map(Some);
    }

    let mut cursor = frame.cursor(src);
    let packet = match kind {
        CONNACK => {
            // lib/handle_connack.c: handle__connack checks reserved flags only in 3.1.1.
            let flags = cursor.byte("CONNACK flags")?;
            if !v31 && flags & 0xfe != 0 {
                return Err(DecodeError::InvalidConnAckFlags(flags));
            }
            let code = cursor.byte("CONNACK return code")?;
            let code = ConnectReturnCode::from_wire(code)
                .ok_or(DecodeError::InvalidConnectReturnCode(code))?;
            Packet::ConnAck(ConnAck {
                session_present: flags & 1 != 0,
                code,
            })
        }
        PUBACK => Packet::PubAck(cursor.packet_id()?),
        PUBREC => Packet::PubRec(cursor.packet_id()?),
        PUBREL => Packet::PubRel(cursor.packet_id()?),
        PUBCOMP => Packet::PubComp(cursor.packet_id()?),
        SUBSCRIBE => decode_subscribe(&mut cursor, v31)?,
        SUBACK => {
            let packet_id = cursor.packet_id()?;
            if cursor.is_empty() {
                return Err(DecodeError::EmptyList("SUBACK return codes"));
            }
            // lib/handle_suback.c: handle__suback passes raw bytes through.
            let return_codes = cursor.bytes[cursor.pos..]
                .iter()
                .copied()
                .map(SubscribeReturnCode::from_wire)
                .collect();
            Packet::SubAck(SubAck {
                packet_id,
                return_codes,
            })
        }
        UNSUBSCRIBE => decode_unsubscribe(&mut cursor, v31)?,
        // lib/handle_unsuback.c: handle__unsuback ignores surplus bytes; the
        // broker's frame length check above is stricter than the client handler.
        UNSUBACK => Packet::UnsubAck(cursor.packet_id()?),
        PINGREQ => Packet::PingReq,
        PINGRESP => Packet::PingResp,
        DISCONNECT => Packet::Disconnect,
        _ => unreachable!("Frame::parse rejects unknown commands"),
    };
    src.advance(frame.end);
    Ok(Some(packet))
}

fn check_command(command: u8, expected: u8) -> Result<(), DecodeError> {
    if command == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidFixedHeaderFlags(command))
    }
}

fn decode_connect(src: &mut BytesMut, frame: &Frame) -> Result<Packet, DecodeError> {
    let mut cursor = frame.cursor(src);
    let name_len = usize::from(cursor.word("protocol name length")?);
    // src/handle_connect.c: read_protocol_name accepts only four or six bytes.
    if !matches!(name_len, 4 | 6) {
        return Err(DecodeError::UnknownProtocolName);
    }
    let name = cursor.take(name_len, "protocol name")?;
    let level = cursor.byte("protocol level")?;
    let version = level & 0x7f;
    if !matches!(version, 3..=5) {
        return Err(DecodeError::UnacceptableProtocolVersion { level });
    }
    let protocol = match connect_protocol_name(name) {
        b"MQIsdp" if version == 3 => ProtocolVersion::V31,
        b"MQTT" if version == 4 => ProtocolVersion::V311,
        b"MQIsdp" | b"MQTT" => return Err(DecodeError::UnacceptableProtocolVersion { level }),
        _ => return Err(DecodeError::UnknownProtocolName),
    };
    let v31 = protocol == ProtocolVersion::V31;
    if !v31 {
        check_command(frame.command, CONNECT)?;
    }
    let flags = cursor.byte("CONNECT flags")?;
    if !v31 && flags & 1 != 0 {
        return Err(DecodeError::ReservedConnectFlag);
    }
    let keep_alive = cursor.word("keep alive")?;
    let will_qos = qos((flags & WILL_QOS_MASK) >> 3, "Will")?;
    let client_id = cursor.string("client identifier")?.to_owned();
    let will = if flags & WILL_FLAG != 0 {
        let topic = cursor.topic("Will topic", false)?.to_owned();
        let payload = cursor.binary("Will payload")?;
        Some((topic, payload))
    } else {
        // src/handle_connect.c: handle__connect tolerates unused Will bits in
        // v3.1, but verify_will_options rejects QoS 3 even without a Will.
        if !v31 && flags & (WILL_QOS_MASK | WILL_RETAIN_FLAG) != 0 {
            return Err(DecodeError::WillFlagsWithoutWill);
        }
        None
    };

    let username = if flags & USERNAME_FLAG != 0 {
        // src/handle_connect.c: set_username_from_packet ignores a v3.1
        // read failure, but keeps the reader progress from packet__read_string.
        match cursor.string("username") {
            Ok(value) => Some(value.to_owned()),
            Err(_) if v31 => None,
            Err(error) => return Err(error),
        }
    } else {
        if flags & PASSWORD_FLAG != 0 {
            return Err(DecodeError::PasswordWithoutUsername);
        }
        None
    };
    let password = if flags & PASSWORD_FLAG != 0 {
        // src/handle_connect.c: set_password_from_packet has the same v3.1
        // exception for a truncated password, not for surplus bytes.
        match cursor.binary("password") {
            Ok(range) => Some(range),
            Err(_) if v31 => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    if !cursor.is_empty() {
        return Err(DecodeError::TrailingConnectData);
    }

    let keep_bytes = will.as_ref().is_some_and(|(_, range)| !range.is_empty())
        || password.as_ref().is_some_and(|range| !range.is_empty());
    let bytes = frame.consume(src, keep_bytes);
    Ok(Packet::Connect(Connect {
        protocol,
        is_bridge: level & 0x80 != 0,
        clean_session: flags & CLEAN_SESSION_FLAG != 0,
        keep_alive,
        client_id,
        will: will.map(|(topic, range)| LastWill {
            topic,
            payload: slice(&bytes, range),
            qos: will_qos,
            retain: flags & WILL_RETAIN_FLAG != 0,
        }),
        username,
        password: password.map(|range| slice(&bytes, range)),
    }))
}

fn decode_publish(
    src: &mut BytesMut,
    frame: &Frame,
    client_receiver: bool,
) -> Result<Packet, DecodeError> {
    let mut cursor = frame.cursor(src);
    let dup = frame.command & DUP_FLAG != 0;
    let qos = qos((frame.command >> 1) & 3, "PUBLISH")?;
    // src/handle_publish.c rejects DUP at QoS 0. lib/handle_publish.c does not.
    if !client_receiver && dup && qos == QoS::AtMostOnce {
        return Err(DecodeError::DupWithQosZero);
    }
    let topic = cursor.topic("PUBLISH topic", false)?.to_owned();
    let packet_id = if qos == QoS::AtMostOnce {
        None
    } else {
        Some(cursor.packet_id()?)
    };
    let range = cursor.pos..frame.end;
    let bytes = frame.consume(src, !range.is_empty());
    Ok(Packet::Publish(Publish {
        dup,
        qos,
        retain: frame.command & RETAIN_FLAG != 0,
        topic,
        packet_id,
        payload: slice(&bytes, range),
    }))
}

fn decode_subscribe(cursor: &mut Cursor<'_>, v31: bool) -> Result<Packet, DecodeError> {
    let packet_id = cursor.packet_id()?;
    let mut filters = Vec::new();
    subscribe_filters(cursor, &mut filters)?;
    if !v31 && filters.is_empty() {
        return Err(DecodeError::EmptyList("SUBSCRIBE filters"));
    }
    Ok(Packet::Subscribe(Subscribe { packet_id, filters }))
}

fn subscribe_filters(
    cursor: &mut Cursor<'_>,
    filters: &mut Vec<(String, QoS)>,
) -> Result<(), DecodeError> {
    while !cursor.is_empty() {
        let filter = cursor.string("subscription filter")?;
        // src/handle_subscribe.c: packet__read_string returns NULL for a zero
        // length, and handle__subscribe skips it without reading an option byte.
        if filter.is_empty() {
            continue;
        }
        if !valid_topic(filter, true) {
            return Err(DecodeError::InvalidTopic {
                field: "subscription filter",
            });
        }
        let qos = qos(cursor.byte("subscription QoS")?, "subscription")?;
        filters.push((filter.to_owned(), qos));
    }
    Ok(())
}

fn decode_unsubscribe(cursor: &mut Cursor<'_>, v31: bool) -> Result<Packet, DecodeError> {
    let packet_id = cursor.packet_id()?;
    let mut filters = Vec::new();
    unsubscribe_filters(cursor, &mut filters)?;
    if !v31 && filters.is_empty() {
        return Err(DecodeError::EmptyList("UNSUBSCRIBE filters"));
    }
    Ok(Packet::Unsubscribe(Unsubscribe { packet_id, filters }))
}

fn unsubscribe_filters(
    cursor: &mut Cursor<'_>,
    filters: &mut Vec<String>,
) -> Result<(), DecodeError> {
    while !cursor.is_empty() {
        filters.push(cursor.topic("unsubscription filter", true)?.to_owned());
    }
    Ok(())
}

/// After [`decode`] refused a SUBSCRIBE or UNSUBSCRIBE, returns the filters
/// before the one that failed, if any. src/handle_subscribe.c and
/// src/handle_unsubscribe.c act on each filter as they read it, so these were
/// already (un)subscribed when Mosquitto closed the connection. Leaves the
/// buffer unchanged; the caller still closes as for the decode error.
pub fn decode_filter_prefix(src: &[u8], context: DecodeContext) -> Option<Packet> {
    let frame = Frame::parse(src, context).ok()??;
    let kind = frame.command & 0xf0;
    if !matches!(kind, SUBSCRIBE | UNSUBSCRIBE) || frame.command != kind | 2 {
        return None;
    }
    let mut cursor = frame.cursor(src);
    let packet_id = cursor.packet_id().ok()?;
    if kind == SUBSCRIBE {
        let mut filters = Vec::new();
        let _ = subscribe_filters(&mut cursor, &mut filters);
        (!filters.is_empty()).then_some(Packet::Subscribe(Subscribe { packet_id, filters }))
    } else {
        let mut filters = Vec::new();
        let _ = unsubscribe_filters(&mut cursor, &mut filters);
        (!filters.is_empty()).then_some(Packet::Unsubscribe(Unsubscribe { packet_id, filters }))
    }
}

fn slice(bytes: &Bytes, range: Range<usize>) -> Bytes {
    if range.is_empty() {
        Bytes::new()
    } else {
        bytes.slice(range)
    }
}

fn qos(value: u8, field: &'static str) -> Result<QoS, DecodeError> {
    QoS::from_wire(value).ok_or(DecodeError::InvalidQos { field, value })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn range(&mut self, len: usize, field: &'static str) -> Result<Range<usize>, DecodeError> {
        let end = self.pos + len;
        if end > self.bytes.len() {
            return Err(DecodeError::Truncated { field });
        }
        let range = self.pos..end;
        self.pos = end;
        Ok(range)
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let range = self.range(len, field)?;
        Ok(&self.bytes[range])
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn word(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn packet_id(&mut self) -> Result<PacketId, DecodeError> {
        PacketId::new(self.word("packet identifier")?).ok_or(DecodeError::ZeroPacketId)
    }

    fn binary(&mut self, field: &'static str) -> Result<Range<usize>, DecodeError> {
        let len = usize::from(self.word(field)?);
        self.range(len, field)
    }

    fn string(&mut self, field: &'static str) -> Result<&'a str, DecodeError> {
        let range = self.binary(field)?;
        validate_utf8(&self.bytes[range]).map_err(|error| DecodeError::InvalidUtf8 { field, error })
    }

    fn topic(&mut self, field: &'static str, filter: bool) -> Result<&'a str, DecodeError> {
        let topic = self.string(field)?;
        if !valid_topic(topic, filter) {
            return Err(DecodeError::InvalidTopic { field });
        }
        Ok(topic)
    }
}
