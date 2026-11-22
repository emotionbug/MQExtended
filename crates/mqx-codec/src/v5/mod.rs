//! Sans-I/O MQTT 5.0 wire codec. Session state and packet direction belong to the caller.
//!
//! [`DecodeContext`] selects Mosquitto's broker or client receive rules; it
//! does not restrict which packet types can be decoded. Receive rules are
//! not always symmetric with [`encode`], which follows Mosquitto's send
//! functions and uses canonical length encodings.

mod decode;
mod encode;
mod property;

pub use crate::{PacketId, QoS};
pub use decode::{
    DecodeContext, DecodeError, DecodeErrorKind, ErrorResponse, decode, peek_connect_protocol_level,
};
pub use encode::{EncodeError, encode};
pub use property::Property;

use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect(Connect),
    ConnAck(ConnAck),
    Publish(Publish),
    PubAck(PublishAck),
    PubRec(PublishAck),
    PubRel(PublishAck),
    PubComp(PublishAck),
    Subscribe(Subscribe),
    SubAck(SubscriptionAck),
    Unsubscribe(Unsubscribe),
    UnsubAck(SubscriptionAck),
    PingReq,
    PingResp,
    Disconnect(ReasonProperties),
    Auth(ReasonProperties),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Connect = 0x10,
    ConnAck = 0x20,
    Publish = 0x30,
    PubAck = 0x40,
    PubRec = 0x50,
    PubRel = 0x60,
    PubComp = 0x70,
    Subscribe = 0x80,
    SubAck = 0x90,
    Unsubscribe = 0xa0,
    UnsubAck = 0xb0,
    PingReq = 0xc0,
    PingResp = 0xd0,
    Disconnect = 0xe0,
    Auth = 0xf0,
}

impl PacketType {
    fn from_command(command: u8) -> Option<Self> {
        Some(match command >> 4 {
            1 => Self::Connect,
            2 => Self::ConnAck,
            3 => Self::Publish,
            4 => Self::PubAck,
            5 => Self::PubRec,
            6 => Self::PubRel,
            7 => Self::PubComp,
            8 => Self::Subscribe,
            9 => Self::SubAck,
            10 => Self::Unsubscribe,
            11 => Self::UnsubAck,
            12 => Self::PingReq,
            13 => Self::PingResp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            _ => return None,
        })
    }

    const fn command(self) -> u8 {
        self as u8
            | match self {
                Self::PubRel | Self::Subscribe | Self::Unsubscribe => 2,
                _ => 0,
            }
    }
}

impl Packet {
    pub const fn packet_type(&self) -> PacketType {
        match self {
            Self::Connect(_) => PacketType::Connect,
            Self::ConnAck(_) => PacketType::ConnAck,
            Self::Publish(_) => PacketType::Publish,
            Self::PubAck(_) => PacketType::PubAck,
            Self::PubRec(_) => PacketType::PubRec,
            Self::PubRel(_) => PacketType::PubRel,
            Self::PubComp(_) => PacketType::PubComp,
            Self::Subscribe(_) => PacketType::Subscribe,
            Self::SubAck(_) => PacketType::SubAck,
            Self::Unsubscribe(_) => PacketType::Unsubscribe,
            Self::UnsubAck(_) => PacketType::UnsubAck,
            Self::PingReq => PacketType::PingReq,
            Self::PingResp => PacketType::PingResp,
            Self::Disconnect(_) => PacketType::Disconnect,
            Self::Auth(_) => PacketType::Auth,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Connect {
    /// Mosquitto accepts 0x85, but on this path omits CONNECT properties and does not tag the session as a bridge.
    pub private_protocol_bit: bool,
    pub clean_start: bool,
    pub keep_alive: u16,
    pub properties: Vec<Property>,
    pub client_id: String,
    pub will: Option<LastWill>,
    /// An empty string preserves wire presence, even though Mosquitto treats it as absent.
    pub username: Option<String>,
    /// An empty binary value preserves wire presence.
    pub password: Option<Bytes>,
}

impl std::fmt::Debug for Connect {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Connect")
            .field("private_protocol_bit", &self.private_protocol_bit)
            .field("clean_start", &self.clean_start)
            .field("keep_alive", &self.keep_alive)
            .field("properties", &self.properties)
            .field("client_id", &self.client_id)
            .field("will", &self.will)
            .field("username", &self.username)
            .field("password_present", &self.password.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastWill {
    pub properties: Vec<Property>,
    pub topic: String,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnAck {
    pub session_present: bool,
    pub reason: ReasonCode,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    /// Empty only when a topic alias is present; resolution belongs to the caller.
    pub topic: String,
    pub packet_id: Option<PacketId>,
    pub properties: Vec<Property>,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishAck {
    pub packet_id: PacketId,
    pub reason: ReasonCode,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    pub packet_id: PacketId,
    pub properties: Vec<Property>,
    pub subscriptions: Vec<Subscription>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub filter: String,
    pub qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: RetainHandling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RetainHandling {
    SendAlways = 0,
    SendIfNew = 1,
    DoNotSend = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    pub packet_id: PacketId,
    pub properties: Vec<Property>,
    pub filters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionAck {
    pub packet_id: PacketId,
    pub properties: Vec<Property>,
    pub reasons: Vec<ReasonCode>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReasonProperties {
    pub reason: ReasonCode,
    pub properties: Vec<Property>,
}

/// Raw reason byte, including values that Mosquitto passes through without checking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ReasonCode(pub u8);

impl ReasonCode {
    pub const SUCCESS: Self = Self(0x00);
    pub const NORMAL_DISCONNECTION: Self = Self(0x00);
    pub const GRANTED_QOS_0: Self = Self(0x00);
    pub const GRANTED_QOS_1: Self = Self(0x01);
    pub const GRANTED_QOS_2: Self = Self(0x02);
    pub const DISCONNECT_WITH_WILL_MESSAGE: Self = Self(0x04);
    pub const NO_MATCHING_SUBSCRIBERS: Self = Self(0x10);
    pub const NO_SUBSCRIPTION_EXISTED: Self = Self(0x11);
    pub const CONTINUE_AUTHENTICATION: Self = Self(0x18);
    pub const REAUTHENTICATE: Self = Self(0x19);
    pub const UNSPECIFIED_ERROR: Self = Self(0x80);
    pub const MALFORMED_PACKET: Self = Self(0x81);
    pub const PROTOCOL_ERROR: Self = Self(0x82);
    pub const IMPLEMENTATION_SPECIFIC_ERROR: Self = Self(0x83);
    pub const UNSUPPORTED_PROTOCOL_VERSION: Self = Self(0x84);
    pub const CLIENT_IDENTIFIER_NOT_VALID: Self = Self(0x85);
    pub const BAD_USERNAME_OR_PASSWORD: Self = Self(0x86);
    pub const NOT_AUTHORIZED: Self = Self(0x87);
    pub const SERVER_UNAVAILABLE: Self = Self(0x88);
    pub const SERVER_BUSY: Self = Self(0x89);
    pub const BANNED: Self = Self(0x8a);
    pub const SERVER_SHUTTING_DOWN: Self = Self(0x8b);
    pub const BAD_AUTHENTICATION_METHOD: Self = Self(0x8c);
    pub const KEEP_ALIVE_TIMEOUT: Self = Self(0x8d);
    pub const SESSION_TAKEN_OVER: Self = Self(0x8e);
    pub const TOPIC_FILTER_INVALID: Self = Self(0x8f);
    pub const TOPIC_NAME_INVALID: Self = Self(0x90);
    pub const PACKET_IDENTIFIER_IN_USE: Self = Self(0x91);
    pub const PACKET_IDENTIFIER_NOT_FOUND: Self = Self(0x92);
    pub const RECEIVE_MAXIMUM_EXCEEDED: Self = Self(0x93);
    pub const TOPIC_ALIAS_INVALID: Self = Self(0x94);
    pub const PACKET_TOO_LARGE: Self = Self(0x95);
    pub const MESSAGE_RATE_TOO_HIGH: Self = Self(0x96);
    pub const QUOTA_EXCEEDED: Self = Self(0x97);
    pub const ADMINISTRATIVE_ACTION: Self = Self(0x98);
    pub const PAYLOAD_FORMAT_INVALID: Self = Self(0x99);
    pub const RETAIN_NOT_SUPPORTED: Self = Self(0x9a);
    pub const QOS_NOT_SUPPORTED: Self = Self(0x9b);
    pub const USE_ANOTHER_SERVER: Self = Self(0x9c);
    pub const SERVER_MOVED: Self = Self(0x9d);
    pub const SHARED_SUBSCRIPTIONS_NOT_SUPPORTED: Self = Self(0x9e);
    pub const CONNECTION_RATE_EXCEEDED: Self = Self(0x9f);
    pub const MAXIMUM_CONNECT_TIME: Self = Self(0xa0);
    pub const SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED: Self = Self(0xa1);
    pub const WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED: Self = Self(0xa2);
}

// lib/handle_pubackcomp.c: handle__pubackcomp; lib/handle_pubrec.c: handle__pubrec;
// lib/handle_pubrel.c: handle__pubrel. Mosquitto rejects 0x95 even though it can send it.
fn valid_publish_ack_reason(kind: PacketType, reason: ReasonCode) -> bool {
    use ReasonCode as R;
    if matches!(kind, PacketType::PubAck | PacketType::PubRec) {
        matches!(
            reason,
            R::SUCCESS
                | R::NO_MATCHING_SUBSCRIBERS
                | R::UNSPECIFIED_ERROR
                | R::IMPLEMENTATION_SPECIFIC_ERROR
                | R::NOT_AUTHORIZED
                | R::TOPIC_NAME_INVALID
                | R::PACKET_IDENTIFIER_IN_USE
                | R::QUOTA_EXCEEDED
                | R::PAYLOAD_FORMAT_INVALID
        )
    } else {
        matches!(reason, R::SUCCESS | R::PACKET_IDENTIFIER_NOT_FOUND)
    }
}

// src/topic_tok.c: sub__topic_tokenise accepts an empty group, not an empty filter.
fn valid_shared_filter(filter: &str) -> bool {
    if let Some(shared) = filter.strip_prefix("$share/") {
        shared
            .split_once('/')
            .is_some_and(|(group, filter)| !group.contains(['+', '#']) && !filter.is_empty())
    } else {
        filter != "$share"
    }
}
