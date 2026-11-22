use bytes::{BufMut, BytesMut};
use thiserror::Error;

use super::decode::DecodeErrorKind as Fault;
use super::property::{self, PropertyScope, has_auth_method};
use super::{
    Connect, Packet, PacketType, Property, PublishAck, QoS, ReasonCode, ReasonProperties,
    valid_publish_ack_reason, valid_shared_filter,
};
use crate::{MAX_REMAINING_LENGTH, remaining_length_bytes, valid_topic, validate_utf8};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error(transparent)]
    Invalid(#[from] Fault),
    #[error("{0} exceeds the two-byte length prefix")]
    FieldTooLong(&'static str),
    #[error("packet exceeds the MQTT remaining length limit")]
    PacketTooLarge,
    #[error("PUBLISH packet identifier must be present exactly when QoS is nonzero")]
    PublishPacketId,
    #[error("CONNECT with private protocol level 0x85 cannot carry CONNECT properties")]
    PrivateConnectProperties,
}

pub(super) fn binary_len(value: &[u8], field: &'static str) -> Result<usize, EncodeError> {
    if value.len() > usize::from(u16::MAX) {
        return Err(EncodeError::FieldTooLong(field));
    }
    Ok(2 + value.len())
}

pub(super) fn string_len(value: &str, field: &'static str) -> Result<usize, EncodeError> {
    let size = binary_len(value.as_bytes(), field)?;
    validate_utf8(value.as_bytes()).map_err(|error| Fault::InvalidUtf8 { field, error })?;
    Ok(size)
}

pub(super) fn put_binary(dst: &mut BytesMut, value: &[u8]) {
    dst.put_u16(value.len() as u16);
    dst.put_slice(value);
}

// lib/packet_datatypes.c: packet__write_varint.
pub(super) fn put_varint(dst: &mut BytesMut, mut value: usize) {
    while value >= 128 {
        dst.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    dst.put_u8(value as u8);
}

struct Layout {
    command: u8,
    body: usize,
    properties: usize,
    will_properties: usize,
}

impl Layout {
    fn new(kind: PacketType) -> Self {
        Self {
            command: kind.command(),
            body: 0,
            properties: 0,
            will_properties: 0,
        }
    }

    fn add(&mut self, more: usize) -> Result<(), EncodeError> {
        if more > MAX_REMAINING_LENGTH - self.body {
            return Err(EncodeError::PacketTooLarge);
        }
        self.body += more;
        Ok(())
    }

    fn add_properties(
        &mut self,
        properties: &[Property],
        scope: PropertyScope,
    ) -> Result<(), EncodeError> {
        let size = property::encoded_len(properties, scope)?;
        match scope {
            PropertyScope::Packet(_) => self.properties = size,
            PropertyScope::Will => self.will_properties = size,
        }
        self.add(remaining_length_bytes(size) + size)
    }

    fn add_optional_reason(
        &mut self,
        reason: ReasonCode,
        properties: &[Property],
        kind: PacketType,
    ) -> Result<(), EncodeError> {
        // lib/send_mosq.c: send__command_with_mid; lib/send_disconnect.c:
        // send__disconnect omit the property length when there are no properties.
        if reason != ReasonCode::SUCCESS || !properties.is_empty() {
            self.add(1)?;
        }
        if !properties.is_empty() {
            self.add_properties(properties, kind.into())?;
        }
        Ok(())
    }

    fn measure(packet: &Packet) -> Result<Self, EncodeError> {
        let kind = packet.packet_type();
        let mut layout = Self::new(kind);
        match packet {
            Packet::Connect(packet) => layout.connect(packet)?,
            Packet::ConnAck(packet) => {
                layout.add(2)?;
                layout.add_properties(&packet.properties, kind.into())?;
            }
            Packet::Publish(packet) => {
                if packet.qos == QoS::AtMostOnce {
                    if packet.packet_id.is_some() {
                        return Err(EncodeError::PublishPacketId);
                    }
                    if packet.dup {
                        return Err(Fault::DupWithQosZero.into());
                    }
                } else {
                    if packet.packet_id.is_none() {
                        return Err(EncodeError::PublishPacketId);
                    }
                    layout.add(2)?;
                }
                layout.command |=
                    ((packet.dup as u8) << 3) | ((packet.qos as u8) << 1) | packet.retain as u8;
                layout.add(string_len(&packet.topic, "publish topic")?)?;
                layout.add_properties(&packet.properties, kind.into())?;
                if packet.topic.is_empty() {
                    if !packet
                        .properties
                        .iter()
                        .any(|p| matches!(p, Property::TopicAlias(_)))
                    {
                        return Err(Fault::InvalidTopic("missing publish topic and alias").into());
                    }
                } else if !valid_topic(&packet.topic, false) {
                    return Err(Fault::InvalidTopic("publish topic").into());
                }
                layout.add(packet.payload.len())?;
            }
            Packet::PubAck(packet)
            | Packet::PubRec(packet)
            | Packet::PubRel(packet)
            | Packet::PubComp(packet) => {
                // src/handle_publish.c: process_bad_message can send 0x95 even
                // though lib/handle_pubackcomp.c and lib/handle_pubrec.c reject it.
                if !(valid_publish_ack_reason(kind, packet.reason)
                    || matches!(kind, PacketType::PubAck | PacketType::PubRec)
                        && packet.reason == ReasonCode::PACKET_TOO_LARGE)
                {
                    return Err(Fault::InvalidReasonCode {
                        packet: kind,
                        reason: packet.reason,
                    }
                    .into());
                }
                layout.add(2)?;
                layout.add_optional_reason(packet.reason, &packet.properties, kind)?;
            }
            Packet::Subscribe(packet) => {
                if packet.subscriptions.is_empty() {
                    return Err(Fault::EmptyList("subscriptions").into());
                }
                layout.add(2)?;
                layout.add_properties(&packet.properties, kind.into())?;
                for sub in &packet.subscriptions {
                    layout.add(filter_len(&sub.filter, "subscription filter")? + 1)?;
                    if sub.no_local && sub.filter.starts_with("$share/") {
                        return Err(Fault::SharedSubscriptionNoLocal.into());
                    }
                }
            }
            Packet::Unsubscribe(packet) => {
                if packet.filters.is_empty() {
                    return Err(Fault::EmptyList("unsubscription filters").into());
                }
                layout.add(2)?;
                layout.add_properties(&packet.properties, kind.into())?;
                for filter in &packet.filters {
                    layout.add(filter_len(filter, "unsubscription filter")?)?;
                }
            }
            Packet::SubAck(packet) | Packet::UnsubAck(packet) => {
                if kind == PacketType::SubAck && packet.reasons.is_empty() {
                    return Err(Fault::EmptyList("SUBACK reasons").into());
                }
                layout.add(2)?;
                layout.add_properties(&packet.properties, kind.into())?;
                layout.add(packet.reasons.len())?;
            }
            Packet::Disconnect(packet) => {
                layout.add_optional_reason(packet.reason, &packet.properties, kind)?
            }
            Packet::Auth(packet) => {
                if !matches!(
                    packet.reason,
                    ReasonCode::SUCCESS
                        | ReasonCode::CONTINUE_AUTHENTICATION
                        | ReasonCode::REAUTHENTICATE
                ) {
                    return Err(Fault::InvalidReasonCode {
                        packet: kind,
                        reason: packet.reason,
                    }
                    .into());
                }
                if !has_auth_method(&packet.properties) {
                    return Err(Fault::MissingAuthenticationMethod.into());
                }
                // src/send_auth.c: send__auth and lib/extended_auth.c:
                // mosquitto_extended_auth always write the reason and properties.
                layout.add(1)?;
                layout.add_properties(&packet.properties, kind.into())?;
            }
            Packet::PingReq | Packet::PingResp => {}
        }
        Ok(layout)
    }

    fn connect(&mut self, packet: &Connect) -> Result<(), EncodeError> {
        self.add(10)?;
        if packet.private_protocol_bit {
            if !packet.properties.is_empty() {
                return Err(EncodeError::PrivateConnectProperties);
            }
        } else {
            self.add_properties(&packet.properties, PacketType::Connect.into())?;
            if packet
                .properties
                .iter()
                .any(|p| matches!(p, Property::AuthenticationData(data) if !data.is_empty()))
                && !has_auth_method(&packet.properties)
            {
                return Err(Fault::MissingAuthenticationMethod.into());
            }
        }
        self.add(string_len(&packet.client_id, "client identifier")?)?;
        if let Some(will) = &packet.will {
            self.add_properties(&will.properties, PropertyScope::Will)?;
            self.add(string_len(&will.topic, "Will topic")?)?;
            if !valid_topic(&will.topic, false) || will.topic.starts_with("$CONTROL/") {
                return Err(Fault::InvalidTopic("Will topic").into());
            }
            self.add(binary_len(&will.payload, "Will payload")?)?;
        }
        if let Some(username) = &packet.username {
            self.add(string_len(username, "username")?)?;
        }
        if let Some(password) = &packet.password {
            self.add(binary_len(password, "password")?)?;
        }
        Ok(())
    }
}

fn filter_len(filter: &str, field: &'static str) -> Result<usize, EncodeError> {
    let size = string_len(filter, field)?;
    if !valid_topic(filter, true) {
        return Err(Fault::InvalidTopic(field).into());
    }
    if !valid_shared_filter(filter) {
        return Err(Fault::InvalidSharedFilter.into());
    }
    Ok(size)
}

/// Append one packet, with canonical length encodings. An error leaves `dst` unchanged.
pub fn encode(packet: &Packet, dst: &mut BytesMut) -> Result<(), EncodeError> {
    let layout = Layout::measure(packet)?;
    dst.reserve(1 + remaining_length_bytes(layout.body) + layout.body);
    dst.put_u8(layout.command);
    put_varint(dst, layout.body);
    match packet {
        Packet::Connect(packet) => write_connect(packet, &layout, dst),
        Packet::ConnAck(packet) => {
            dst.put_u8(u8::from(packet.session_present));
            dst.put_u8(packet.reason.0);
            property::write(&packet.properties, layout.properties, dst);
        }
        Packet::Publish(packet) => {
            put_binary(dst, packet.topic.as_bytes());
            if let Some(id) = packet.packet_id {
                dst.put_u16(id.get());
            }
            property::write(&packet.properties, layout.properties, dst);
            dst.put_slice(&packet.payload);
        }
        Packet::PubAck(packet)
        | Packet::PubRec(packet)
        | Packet::PubRel(packet)
        | Packet::PubComp(packet) => {
            write_publish_ack(packet, layout.properties, dst);
        }
        Packet::Subscribe(packet) => {
            dst.put_u16(packet.packet_id.get());
            property::write(&packet.properties, layout.properties, dst);
            for sub in &packet.subscriptions {
                put_binary(dst, sub.filter.as_bytes());
                dst.put_u8(
                    sub.qos as u8
                        | ((sub.no_local as u8) << 2)
                        | ((sub.retain_as_published as u8) << 3)
                        | ((sub.retain_handling as u8) << 4),
                );
            }
        }
        Packet::Unsubscribe(packet) => {
            dst.put_u16(packet.packet_id.get());
            property::write(&packet.properties, layout.properties, dst);
            for filter in &packet.filters {
                put_binary(dst, filter.as_bytes());
            }
        }
        Packet::SubAck(packet) | Packet::UnsubAck(packet) => {
            dst.put_u16(packet.packet_id.get());
            property::write(&packet.properties, layout.properties, dst);
            for reason in &packet.reasons {
                dst.put_u8(reason.0);
            }
        }
        Packet::Disconnect(ReasonProperties { reason, properties }) => {
            write_optional_reason(*reason, properties, layout.properties, dst)
        }
        Packet::Auth(packet) => {
            dst.put_u8(packet.reason.0);
            property::write(&packet.properties, layout.properties, dst);
        }
        Packet::PingReq | Packet::PingResp => {}
    }
    Ok(())
}

fn write_connect(packet: &Connect, layout: &Layout, dst: &mut BytesMut) {
    dst.put_slice(b"\x00\x04MQTT");
    dst.put_u8(if packet.private_protocol_bit { 0x85 } else { 5 });
    let mut flags = (packet.clean_start as u8) << 1;
    if let Some(will) = &packet.will {
        flags |= crate::WILL_FLAG | ((will.qos as u8) << 3) | ((will.retain as u8) << 5);
    }
    flags |= ((packet.username.is_some() as u8) << 7) | ((packet.password.is_some() as u8) << 6);
    dst.put_u8(flags);
    dst.put_u16(packet.keep_alive);
    if !packet.private_protocol_bit {
        property::write(&packet.properties, layout.properties, dst);
    }
    put_binary(dst, packet.client_id.as_bytes());
    if let Some(will) = &packet.will {
        property::write(&will.properties, layout.will_properties, dst);
        put_binary(dst, will.topic.as_bytes());
        put_binary(dst, &will.payload);
    }
    if let Some(username) = &packet.username {
        put_binary(dst, username.as_bytes());
    }
    if let Some(password) = &packet.password {
        put_binary(dst, password);
    }
}

fn write_publish_ack(packet: &PublishAck, property_len: usize, dst: &mut BytesMut) {
    dst.put_u16(packet.packet_id.get());
    write_optional_reason(packet.reason, &packet.properties, property_len, dst);
}

fn write_optional_reason(
    reason: ReasonCode,
    properties: &[Property],
    len: usize,
    dst: &mut BytesMut,
) {
    if reason != ReasonCode::SUCCESS || !properties.is_empty() {
        dst.put_u8(reason.0);
    }
    if !properties.is_empty() {
        property::write(properties, len, dst);
    }
}
