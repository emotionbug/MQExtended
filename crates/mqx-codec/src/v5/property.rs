use std::ops::Range;

use bytes::{BufMut, Bytes, BytesMut};

use super::PacketType;
use super::decode::{Cursor, DecodeErrorKind as Fault};
use super::encode::{EncodeError, binary_len, put_binary, put_varint, string_len};
use crate::{MAX_REMAINING_LENGTH, remaining_length_bytes, valid_topic};

/// The wire order of properties, including repeated User Properties, is significant.
#[derive(Clone, PartialEq, Eq)]
pub enum Property {
    PayloadFormatIndicator(u8),
    MessageExpiryInterval(u32),
    ContentType(String),
    ResponseTopic(String),
    CorrelationData(Bytes),
    SubscriptionIdentifier(u32),
    SessionExpiryInterval(u32),
    AssignedClientIdentifier(String),
    ServerKeepAlive(u16),
    AuthenticationMethod(String),
    AuthenticationData(Bytes),
    RequestProblemInformation(u8),
    WillDelayInterval(u32),
    RequestResponseInformation(u8),
    ResponseInformation(String),
    ServerReference(String),
    ReasonString(String),
    ReceiveMaximum(u16),
    TopicAliasMaximum(u16),
    TopicAlias(u16),
    MaximumQos(u8),
    RetainAvailable(u8),
    UserProperty(String, String),
    MaximumPacketSize(u32),
    WildcardSubscriptionAvailable(u8),
    SubscriptionIdentifierAvailable(u8),
    SharedSubscriptionAvailable(u8),
}

impl std::fmt::Debug for Property {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        macro_rules! value {
            ($($variant:ident),+ $(,)?) => {
                match self {
                    $(Self::$variant(value) => fmt.debug_tuple(stringify!($variant)).field(value).finish(),)+
                    Self::UserProperty(name, value) => fmt.debug_tuple("UserProperty").field(name).field(value).finish(),
                    Self::AuthenticationData(_) => fmt.write_str("AuthenticationData(<redacted>)"),
                }
            };
        }
        value!(
            PayloadFormatIndicator,
            MessageExpiryInterval,
            ContentType,
            ResponseTopic,
            CorrelationData,
            SubscriptionIdentifier,
            SessionExpiryInterval,
            AssignedClientIdentifier,
            ServerKeepAlive,
            AuthenticationMethod,
            RequestProblemInformation,
            WillDelayInterval,
            RequestResponseInformation,
            ResponseInformation,
            ServerReference,
            ReasonString,
            ReceiveMaximum,
            TopicAliasMaximum,
            TopicAlias,
            MaximumQos,
            RetainAvailable,
            MaximumPacketSize,
            WildcardSubscriptionAvailable,
            SubscriptionIdentifierAvailable,
            SharedSubscriptionAvailable,
        )
    }
}

#[derive(Clone, Copy)]
pub(super) enum PropertyScope {
    Packet(PacketType),
    Will,
}

impl From<PacketType> for PropertyScope {
    fn from(kind: PacketType) -> Self {
        Self::Packet(kind)
    }
}

impl Property {
    pub const fn identifier(&self) -> u8 {
        match self {
            Self::PayloadFormatIndicator(_) => 0x01,
            Self::MessageExpiryInterval(_) => 0x02,
            Self::ContentType(_) => 0x03,
            Self::ResponseTopic(_) => 0x08,
            Self::CorrelationData(_) => 0x09,
            Self::SubscriptionIdentifier(_) => 0x0b,
            Self::SessionExpiryInterval(_) => 0x11,
            Self::AssignedClientIdentifier(_) => 0x12,
            Self::ServerKeepAlive(_) => 0x13,
            Self::AuthenticationMethod(_) => 0x15,
            Self::AuthenticationData(_) => 0x16,
            Self::RequestProblemInformation(_) => 0x17,
            Self::WillDelayInterval(_) => 0x18,
            Self::RequestResponseInformation(_) => 0x19,
            Self::ResponseInformation(_) => 0x1a,
            Self::ServerReference(_) => 0x1c,
            Self::ReasonString(_) => 0x1f,
            Self::ReceiveMaximum(_) => 0x21,
            Self::TopicAliasMaximum(_) => 0x22,
            Self::TopicAlias(_) => 0x23,
            Self::MaximumQos(_) => 0x24,
            Self::RetainAvailable(_) => 0x25,
            Self::UserProperty(..) => 0x26,
            Self::MaximumPacketSize(_) => 0x27,
            Self::WildcardSubscriptionAvailable(_) => 0x28,
            Self::SubscriptionIdentifierAvailable(_) => 0x29,
            Self::SharedSubscriptionAvailable(_) => 0x2a,
        }
    }

    // libcommon/property_common.c: mosquitto_property_check_command; Will's extra
    // exclusion of Reason String comes from src/property_broker.c: property__process_will.
    fn allowed(&self, scope: PropertyScope) -> bool {
        use PacketType::*;
        use PropertyScope::{Packet, Will};
        match self {
            Self::PayloadFormatIndicator(_)
            | Self::MessageExpiryInterval(_)
            | Self::ContentType(_)
            | Self::ResponseTopic(_)
            | Self::CorrelationData(_) => matches!(scope, Packet(Publish) | Will),
            Self::SubscriptionIdentifier(_) => matches!(scope, Packet(Publish | Subscribe)),
            Self::SessionExpiryInterval(_) => {
                matches!(scope, Packet(Connect | ConnAck | Disconnect))
            }
            Self::AssignedClientIdentifier(_)
            | Self::ServerKeepAlive(_)
            | Self::ResponseInformation(_)
            | Self::MaximumQos(_)
            | Self::RetainAvailable(_)
            | Self::WildcardSubscriptionAvailable(_)
            | Self::SubscriptionIdentifierAvailable(_)
            | Self::SharedSubscriptionAvailable(_) => matches!(scope, Packet(ConnAck)),
            Self::AuthenticationMethod(_) | Self::AuthenticationData(_) => {
                matches!(scope, Packet(Connect | ConnAck | Auth))
            }
            Self::RequestProblemInformation(_) | Self::RequestResponseInformation(_) => {
                matches!(scope, Packet(Connect))
            }
            Self::WillDelayInterval(_) => matches!(scope, Will),
            Self::ServerReference(_) => matches!(scope, Packet(ConnAck | Disconnect)),
            Self::ReasonString(_) => matches!(
                scope,
                Packet(
                    ConnAck
                        | PubAck
                        | PubRec
                        | PubRel
                        | PubComp
                        | SubAck
                        | UnsubAck
                        | Disconnect
                        | Auth
                )
            ),
            Self::ReceiveMaximum(_) | Self::TopicAliasMaximum(_) | Self::MaximumPacketSize(_) => {
                matches!(scope, Packet(Connect | ConnAck))
            }
            Self::TopicAlias(_) => matches!(scope, Packet(Publish)),
            Self::UserProperty(..) => true,
        }
    }

    // libcommon/property_common.c: mosquitto_property_check_all checks values before
    // command legality; subscription identifiers are checked by the packet handlers.
    fn valid_value(&self) -> bool {
        match self {
            Self::PayloadFormatIndicator(v)
            | Self::RequestProblemInformation(v)
            | Self::RequestResponseInformation(v)
            | Self::MaximumQos(v)
            | Self::RetainAvailable(v)
            | Self::WildcardSubscriptionAvailable(v)
            | Self::SubscriptionIdentifierAvailable(v)
            | Self::SharedSubscriptionAvailable(v) => *v <= 1,
            Self::MaximumPacketSize(v) => *v != 0,
            Self::ReceiveMaximum(v) | Self::TopicAlias(v) => *v != 0,
            Self::ResponseTopic(topic) => valid_topic(topic, false),
            _ => true,
        }
    }

    fn read(cur: &mut Cursor<'_>) -> Result<(Self, Option<Range<usize>>), Fault> {
        let id = cur.varint("property identifier")?;
        let mut binary = None;
        let property = match id {
            0x01 => Self::PayloadFormatIndicator(cur.byte("payload format indicator")?),
            0x02 => Self::MessageExpiryInterval(cur.u32("message expiry interval")?),
            0x03 => Self::ContentType(cur.string("content type")?),
            0x08 => Self::ResponseTopic(cur.string("response topic")?),
            0x09 => {
                binary = Some(cur.binary("correlation data")?);
                Self::CorrelationData(Bytes::new())
            }
            0x0b => Self::SubscriptionIdentifier(cur.varint("subscription identifier")?),
            0x11 => Self::SessionExpiryInterval(cur.u32("session expiry interval")?),
            0x12 => Self::AssignedClientIdentifier(cur.string("assigned client identifier")?),
            0x13 => Self::ServerKeepAlive(cur.u16("server keep alive")?),
            0x15 => Self::AuthenticationMethod(cur.string("authentication method")?),
            0x16 => {
                binary = Some(cur.binary("authentication data")?);
                Self::AuthenticationData(Bytes::new())
            }
            0x17 => Self::RequestProblemInformation(cur.byte("request problem information")?),
            0x18 => Self::WillDelayInterval(cur.u32("will delay interval")?),
            0x19 => Self::RequestResponseInformation(cur.byte("request response information")?),
            0x1a => Self::ResponseInformation(cur.string("response information")?),
            0x1c => Self::ServerReference(cur.string("server reference")?),
            0x1f => Self::ReasonString(cur.string("reason string")?),
            0x21 => Self::ReceiveMaximum(cur.u16("receive maximum")?),
            0x22 => Self::TopicAliasMaximum(cur.u16("topic alias maximum")?),
            0x23 => Self::TopicAlias(cur.u16("topic alias")?),
            0x24 => Self::MaximumQos(cur.byte("maximum QoS")?),
            0x25 => Self::RetainAvailable(cur.byte("retain available")?),
            0x26 => Self::UserProperty(
                cur.string("user property name")?,
                cur.string("user property value")?,
            ),
            0x27 => Self::MaximumPacketSize(cur.u32("maximum packet size")?),
            0x28 => {
                Self::WildcardSubscriptionAvailable(cur.byte("wildcard subscription available")?)
            }
            0x29 => Self::SubscriptionIdentifierAvailable(
                cur.byte("subscription identifier available")?,
            ),
            0x2a => Self::SharedSubscriptionAvailable(cur.byte("shared subscription available")?),
            _ => return Err(Fault::UnknownProperty(id)),
        };
        Ok((property, binary))
    }

    fn value_len(&self) -> Result<usize, EncodeError> {
        Ok(match self {
            Self::PayloadFormatIndicator(_)
            | Self::RequestProblemInformation(_)
            | Self::RequestResponseInformation(_)
            | Self::MaximumQos(_)
            | Self::RetainAvailable(_)
            | Self::WildcardSubscriptionAvailable(_)
            | Self::SubscriptionIdentifierAvailable(_)
            | Self::SharedSubscriptionAvailable(_) => 1,
            Self::ServerKeepAlive(_)
            | Self::ReceiveMaximum(_)
            | Self::TopicAliasMaximum(_)
            | Self::TopicAlias(_) => 2,
            Self::MessageExpiryInterval(_)
            | Self::SessionExpiryInterval(_)
            | Self::WillDelayInterval(_)
            | Self::MaximumPacketSize(_) => 4,
            Self::SubscriptionIdentifier(value) => {
                if *value == 0 || *value as usize > MAX_REMAINING_LENGTH {
                    return Err(Fault::InvalidPropertyValue(self.identifier()).into());
                }
                remaining_length_bytes(*value as usize)
            }
            Self::ContentType(value)
            | Self::ResponseTopic(value)
            | Self::AssignedClientIdentifier(value)
            | Self::AuthenticationMethod(value)
            | Self::ResponseInformation(value)
            | Self::ServerReference(value)
            | Self::ReasonString(value) => string_len(value, "string property")?,
            Self::CorrelationData(value) | Self::AuthenticationData(value) => {
                binary_len(value, "binary property")?
            }
            Self::UserProperty(name, value) => {
                string_len(name, "user property name")? + string_len(value, "user property value")?
            }
        })
    }

    fn write(&self, dst: &mut BytesMut) {
        // lib/property_mosq.c: property__write uses a canonical varint identifier.
        dst.put_u8(self.identifier());
        match self {
            Self::PayloadFormatIndicator(v)
            | Self::RequestProblemInformation(v)
            | Self::RequestResponseInformation(v)
            | Self::MaximumQos(v)
            | Self::RetainAvailable(v)
            | Self::WildcardSubscriptionAvailable(v)
            | Self::SubscriptionIdentifierAvailable(v)
            | Self::SharedSubscriptionAvailable(v) => dst.put_u8(*v),
            Self::ServerKeepAlive(v)
            | Self::ReceiveMaximum(v)
            | Self::TopicAliasMaximum(v)
            | Self::TopicAlias(v) => dst.put_u16(*v),
            Self::MessageExpiryInterval(v)
            | Self::SessionExpiryInterval(v)
            | Self::WillDelayInterval(v)
            | Self::MaximumPacketSize(v) => dst.put_u32(*v),
            Self::SubscriptionIdentifier(v) => put_varint(dst, *v as usize),
            Self::ContentType(v)
            | Self::ResponseTopic(v)
            | Self::AssignedClientIdentifier(v)
            | Self::AuthenticationMethod(v)
            | Self::ResponseInformation(v)
            | Self::ServerReference(v)
            | Self::ReasonString(v) => put_binary(dst, v.as_bytes()),
            Self::CorrelationData(v) | Self::AuthenticationData(v) => put_binary(dst, v),
            Self::UserProperty(name, value) => {
                put_binary(dst, name.as_bytes());
                put_binary(dst, value.as_bytes());
            }
        }
    }
}

fn validate(properties: &[Property], scope: PropertyScope) -> Result<(), Fault> {
    // libcommon/property_common.c: mosquitto_property_check_all rejects duplicates
    // of *every* property except User Property, even PUBLISH Subscription Identifier.
    let mut seen = 0u64;
    let mut duplicates = 0u64;
    for property in properties {
        if !matches!(property, Property::UserProperty(..)) {
            let bit = 1u64 << property.identifier();
            duplicates |= seen & bit;
            seen |= bit;
        }
    }
    for property in properties {
        let id = property.identifier();
        if !property.valid_value() {
            return Err(Fault::InvalidPropertyValue(id));
        }
        // The Will handler rejects this property after the common duplicate check.
        if !property.allowed(scope) && !(matches!(scope, PropertyScope::Will) && id == 0x1f) {
            return Err(Fault::PropertyNotAllowed(id));
        }
        if duplicates & (1u64 << id) != 0 {
            return Err(Fault::DuplicateProperty(id));
        }
    }
    if matches!(scope, PropertyScope::Will) && seen & (1u64 << 0x1f) != 0 {
        return Err(Fault::PropertyNotAllowed(0x1f));
    }
    Ok(())
}

/// No valid property block can contain more than one binary property. Record its
/// range and borrow the input allocation only after the whole packet validates.
#[derive(Default)]
pub(super) struct PropertyBlock {
    pub(super) values: Vec<Property>,
    pub(super) binary: Option<BinaryProperty>,
}

impl PropertyBlock {
    pub(super) fn read(cur: &mut Cursor<'_>, scope: PropertyScope) -> Result<Self, Fault> {
        let mut block = Self::default();
        let length = cur.varint("property length")? as usize;
        let mut properties = cur.block(length, "properties")?;
        // lib/property_mosq.c: property__read_all parses all encodings first,
        // then checks values, packet legality and duplicates in wire order.
        while !properties.is_empty() {
            let (property, span) = Property::read(&mut properties)?;
            if let Some(span) = span.filter(|span| !span.is_empty()) {
                block.binary = Some(BinaryProperty {
                    index: block.values.len(),
                    span,
                });
            }
            block.values.push(property);
        }
        validate(&block.values, scope)?;
        Ok(block)
    }
}

pub(super) struct BinaryProperty {
    index: usize,
    span: Range<usize>,
}

impl BinaryProperty {
    pub(super) fn fill(self, properties: &mut [Property], frame: &Bytes) {
        let value = match &mut properties[self.index] {
            Property::CorrelationData(value) | Property::AuthenticationData(value) => value,
            _ => unreachable!("recorded binary property changed type"),
        };
        *value = frame.slice(self.span);
    }
}

pub(super) fn has_auth_method(properties: &[Property]) -> bool {
    properties.iter().any(
        |property| matches!(property, Property::AuthenticationMethod(method) if !method.is_empty()),
    )
}

pub(super) fn encoded_len(
    properties: &[Property],
    scope: PropertyScope,
) -> Result<usize, EncodeError> {
    validate(properties, scope)?;
    let mut size = 0;
    for property in properties {
        size += 1 + property.value_len()?;
        if size > MAX_REMAINING_LENGTH {
            return Err(EncodeError::PacketTooLarge);
        }
    }
    Ok(size)
}

pub(super) fn write(properties: &[Property], size: usize, dst: &mut BytesMut) {
    put_varint(dst, size);
    for property in properties {
        property.write(dst);
    }
}
