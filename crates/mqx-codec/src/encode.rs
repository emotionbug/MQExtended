use bytes::{BufMut, BytesMut};
use thiserror::Error;

use super::{
    CLEAN_SESSION_FLAG, CONNACK, CONNECT, Connect, DISCONNECT, DUP_FLAG, MAX_REMAINING_LENGTH,
    PASSWORD_FLAG, PINGREQ, PINGRESP, PUBACK, PUBCOMP, PUBLISH, PUBREC, PUBREL, Packet, PacketId,
    QoS, RETAIN_FLAG, SUBACK, SUBSCRIBE, UNSUBACK, UNSUBSCRIBE, USERNAME_FLAG, Utf8Error,
    WILL_FLAG, WILL_RETAIN_FLAG, remaining_length_bytes, valid_topic, validate_code_points,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("{field} is {len} bytes, exceeding the 65535-byte field limit")]
    FieldTooLong { field: &'static str, len: usize },
    #[error("packet exceeds MQTT's maximum remaining length")]
    PacketTooLarge,
    #[error("invalid UTF-8 in {field}: {error}")]
    InvalidUtf8 {
        field: &'static str,
        #[source]
        error: Utf8Error,
    },
    #[error("invalid {field}")]
    InvalidTopic { field: &'static str },
    #[error("packet identifier must be present exactly when PUBLISH QoS is nonzero")]
    PublishPacketIdMismatch,
    #[error("PUBLISH sets DUP with QoS 0")]
    DupWithQosZero,
    #[error("CONNECT sets a password without a username")]
    PasswordWithoutUsername,
    #[error("empty {0} list")]
    EmptyList(&'static str),
}

/// Append one canonical MQTT 3.x packet. On error `dst` is not modified.
/// Session-dependent decisions (such as permitting an empty client ID or
/// setting the CONNACK session-present bit) are the application's responsibility.
pub fn encode(packet: &Packet, dst: &mut BytesMut) -> Result<(), EncodeError> {
    let (command, length) = wire_shape(packet)?;
    put_header(dst, command, length);
    match packet {
        Packet::Connect(connect) => put_connect(dst, connect),
        Packet::ConnAck(ack) => {
            dst.put_u8(u8::from(ack.session_present));
            dst.put_u8(ack.code as u8);
        }
        Packet::Publish(packet) => {
            put_publish(dst, &packet.topic, packet.packet_id, &packet.payload);
        }
        Packet::PubAck(id)
        | Packet::PubRec(id)
        | Packet::PubRel(id)
        | Packet::PubComp(id)
        | Packet::UnsubAck(id) => dst.put_u16(id.get()),
        Packet::Subscribe(packet) => {
            dst.put_u16(packet.packet_id.get());
            for (filter, qos) in &packet.filters {
                put_blob(dst, filter.as_bytes());
                dst.put_u8(*qos as u8);
            }
        }
        Packet::SubAck(packet) => {
            dst.put_u16(packet.packet_id.get());
            for code in &packet.return_codes {
                dst.put_u8(code.wire());
            }
        }
        Packet::Unsubscribe(packet) => {
            dst.put_u16(packet.packet_id.get());
            for filter in &packet.filters {
                put_blob(dst, filter.as_bytes());
            }
        }
        Packet::PingReq | Packet::PingResp | Packet::Disconnect => {}
    }
    Ok(())
}

fn wire_shape(packet: &Packet) -> Result<(u8, usize), EncodeError> {
    Ok(match packet {
        Packet::Connect(connect) => (CONNECT, connect_len(connect)?),
        Packet::ConnAck(_) => (CONNACK, 2),
        Packet::Publish(p) => publish_shape(
            &p.topic,
            p.payload.len(),
            p.qos,
            p.packet_id,
            p.retain,
            p.dup,
        )?,
        Packet::PubAck(_) => (PUBACK, 2),
        Packet::PubRec(_) => (PUBREC, 2),
        Packet::PubRel(_) => (PUBREL | 2, 2),
        Packet::PubComp(_) => (PUBCOMP, 2),
        Packet::Subscribe(packet) => {
            if packet.filters.is_empty() {
                return Err(EncodeError::EmptyList("SUBSCRIBE filters"));
            }
            let mut length = 2;
            for (filter, _) in &packet.filters {
                length = add_len(length, 1 + topic_len(filter, "subscription filter", true)?)?;
            }
            (SUBSCRIBE | 2, length)
        }
        Packet::SubAck(packet) => {
            if packet.return_codes.is_empty() {
                return Err(EncodeError::EmptyList("SUBACK return codes"));
            }
            (SUBACK, add_len(2, packet.return_codes.len())?)
        }
        Packet::Unsubscribe(packet) => {
            if packet.filters.is_empty() {
                return Err(EncodeError::EmptyList("UNSUBSCRIBE filters"));
            }
            let mut length = 2;
            for filter in &packet.filters {
                length = add_len(length, topic_len(filter, "unsubscription filter", true)?)?;
            }
            (UNSUBSCRIBE | 2, length)
        }
        Packet::UnsubAck(_) => (UNSUBACK, 2),
        Packet::PingReq => (PINGREQ, 0),
        Packet::PingResp => (PINGRESP, 0),
        Packet::Disconnect => (DISCONNECT, 0),
    })
}

/// Append an MQTT 3.x PUBLISH directly from a shared topic and payload.
/// Validation and wire bytes are identical to [`encode`].
pub fn encode_publish(
    dst: &mut BytesMut,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    id: Option<PacketId>,
    retain: bool,
    dup: bool,
) -> Result<(), EncodeError> {
    let (command, length) = publish_shape(topic, payload.len(), qos, id, retain, dup)?;
    put_header(dst, command, length);
    put_publish(dst, topic, id, payload);
    Ok(())
}

fn publish_shape(
    topic: &str,
    payload: usize,
    qos: QoS,
    id: Option<PacketId>,
    retain: bool,
    dup: bool,
) -> Result<(u8, usize), EncodeError> {
    let has_id = qos != QoS::AtMostOnce;
    if id.is_some() != has_id {
        return Err(EncodeError::PublishPacketIdMismatch);
    }
    if dup && !has_id {
        return Err(EncodeError::DupWithQosZero);
    }
    let mut command = PUBLISH | ((qos as u8) << 1);
    if dup {
        command |= DUP_FLAG;
    }
    if retain {
        command |= RETAIN_FLAG;
    }
    let header = topic_len(topic, "PUBLISH topic", false)? + usize::from(has_id) * 2;
    Ok((command, add_len(header, payload)?))
}

fn put_header(dst: &mut BytesMut, command: u8, length: usize) {
    dst.reserve(1 + remaining_length_bytes(length) + length);
    dst.put_u8(command);
    put_remaining_length(dst, length);
}

fn put_publish(dst: &mut BytesMut, topic: &str, id: Option<PacketId>, payload: &[u8]) {
    put_blob(dst, topic.as_bytes());
    if let Some(id) = id {
        dst.put_u16(id.get());
    }
    dst.extend_from_slice(payload);
}

fn connect_len(connect: &Connect) -> Result<usize, EncodeError> {
    if connect.password.is_some() && connect.username.is_none() {
        return Err(EncodeError::PasswordWithoutUsername);
    }
    let mut length = 6 + connect.protocol.wire().0.len();
    length += string_len(&connect.client_id, "client identifier")?;
    if let Some(will) = &connect.will {
        length += topic_len(&will.topic, "Will topic", false)?;
        length += blob_len(will.payload.len(), "Will payload")?;
    }
    if let Some(username) = &connect.username {
        length += string_len(username, "username")?;
    }
    if let Some(password) = &connect.password {
        length += blob_len(password.len(), "password")?;
    }
    Ok(length)
}

fn put_connect(dst: &mut BytesMut, connect: &Connect) {
    let (name, level) = connect.protocol.wire();
    put_blob(dst, name);
    dst.put_u8(level | if connect.is_bridge { 0x80 } else { 0 });
    let mut flags = 0;
    if connect.clean_session {
        flags |= CLEAN_SESSION_FLAG;
    }
    if let Some(will) = &connect.will {
        flags |= WILL_FLAG | ((will.qos as u8) << 3);
        if will.retain {
            flags |= WILL_RETAIN_FLAG;
        }
    }
    if connect.username.is_some() {
        flags |= USERNAME_FLAG;
    }
    if connect.password.is_some() {
        flags |= PASSWORD_FLAG;
    }
    dst.put_u8(flags);
    dst.put_u16(connect.keep_alive);
    put_blob(dst, connect.client_id.as_bytes());
    if let Some(will) = &connect.will {
        put_blob(dst, will.topic.as_bytes());
        put_blob(dst, &will.payload);
    }
    if let Some(username) = &connect.username {
        put_blob(dst, username.as_bytes());
    }
    if let Some(password) = &connect.password {
        put_blob(dst, password);
    }
}

fn add_len(left: usize, right: usize) -> Result<usize, EncodeError> {
    if right <= MAX_REMAINING_LENGTH - left {
        Ok(left + right)
    } else {
        Err(EncodeError::PacketTooLarge)
    }
}

fn blob_len(len: usize, field: &'static str) -> Result<usize, EncodeError> {
    if len > usize::from(u16::MAX) {
        Err(EncodeError::FieldTooLong { field, len })
    } else {
        Ok(2 + len)
    }
}

fn string_len(text: &str, field: &'static str) -> Result<usize, EncodeError> {
    let length = blob_len(text.len(), field)?;
    validate_code_points(text).map_err(|error| EncodeError::InvalidUtf8 { field, error })?;
    Ok(length)
}

fn topic_len(topic: &str, field: &'static str, filter: bool) -> Result<usize, EncodeError> {
    let length = string_len(topic, field)?;
    if !valid_topic(topic, filter) {
        return Err(EncodeError::InvalidTopic { field });
    }
    Ok(length)
}

fn put_blob(dst: &mut BytesMut, bytes: &[u8]) {
    dst.put_u16(bytes.len() as u16);
    dst.extend_from_slice(bytes);
}

fn put_remaining_length(dst: &mut BytesMut, mut length: usize) {
    // lib/packet_mosq.c: packet__alloc always emits the shortest encoding.
    while length >= 128 {
        dst.put_u8((length & 0x7f) as u8 | 0x80);
        length >>= 7;
    }
    dst.put_u8(length as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_length_boundary_without_allocating_a_max_size_packet() {
        assert_eq!(
            add_len(MAX_REMAINING_LENGTH - 1, 1),
            Ok(MAX_REMAINING_LENGTH)
        );
        assert_eq!(
            add_len(MAX_REMAINING_LENGTH, 1),
            Err(EncodeError::PacketTooLarge)
        );
        let mut bytes = BytesMut::new();
        put_remaining_length(&mut bytes, MAX_REMAINING_LENGTH);
        assert_eq!(&bytes[..], &[0xff, 0xff, 0xff, 0x7f]);
    }
}
