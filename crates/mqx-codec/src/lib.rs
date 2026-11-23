//! Sans-I/O MQTT 3.1 and 3.1.1 framing and packet validation.
//!
//! The application owns connection state, packet direction, and broker policy.
//!
//! MQTT 5.0 framing and packet validation are available in [`v5`].

mod decode;
mod encode;
pub mod v5;

use bytes::Bytes;
use thiserror::Error;

pub use decode::{DecodeContext, DecodeError, decode, decode_filter_prefix};
pub use encode::{EncodeError, encode};

pub const MAX_REMAINING_LENGTH: usize = 268_435_455;

pub type PacketId = std::num::NonZeroU16;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V31,
    V311,
}

impl ProtocolVersion {
    const fn wire(self) -> (&'static [u8], u8) {
        match self {
            Self::V31 => (b"MQIsdp", 3),
            Self::V311 => (b"MQTT", 4),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl QoS {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::AtMostOnce),
            1 => Some(Self::AtLeastOnce),
            2 => Some(Self::ExactlyOnce),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect(Connect),
    ConnAck(ConnAck),
    Publish(Publish),
    PubAck(PacketId),
    PubRec(PacketId),
    PubRel(PacketId),
    PubComp(PacketId),
    Subscribe(Subscribe),
    SubAck(SubAck),
    Unsubscribe(Unsubscribe),
    UnsubAck(PacketId),
    PingReq,
    PingResp,
    Disconnect,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    pub protocol: ProtocolVersion,
    /// Mosquitto's private bridge bit in the protocol level.
    pub is_bridge: bool,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub client_id: String,
    pub will: Option<LastWill>,
    /// Wire presence is preserved; Mosquitto's broker treats `Some("")` as absent.
    pub username: Option<String>,
    /// Wire presence is preserved; Mosquitto's broker treats an empty password as absent.
    pub password: Option<Bytes>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastWill {
    pub topic: String,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnAck {
    pub session_present: bool,
    pub code: ConnectReturnCode,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectReturnCode {
    Accepted = 0,
    UnacceptableProtocolVersion = 1,
    IdentifierRejected = 2,
    ServerUnavailable = 3,
    BadUserNameOrPassword = 4,
    NotAuthorized = 5,
}

impl ConnectReturnCode {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Accepted),
            1 => Some(Self::UnacceptableProtocolVersion),
            2 => Some(Self::IdentifierRejected),
            3 => Some(Self::ServerUnavailable),
            4 => Some(Self::BadUserNameOrPassword),
            5 => Some(Self::NotAuthorized),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub topic: String,
    pub packet_id: Option<PacketId>,
    pub payload: Bytes,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    pub packet_id: PacketId,
    pub filters: Vec<(String, QoS)>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAck {
    pub packet_id: PacketId,
    pub return_codes: Vec<SubscribeReturnCode>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeReturnCode {
    Success(QoS),
    Failure,
    /// libmosquitto forwards all SUBACK code bytes to the client callback.
    Unrecognized(u8),
}

impl SubscribeReturnCode {
    const fn from_wire(value: u8) -> Self {
        match value {
            0x80 => Self::Failure,
            _ => match QoS::from_wire(value) {
                Some(qos) => Self::Success(qos),
                None => Self::Unrecognized(value),
            },
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::Success(qos) => qos as u8,
            Self::Failure => 0x80,
            Self::Unrecognized(value) => value,
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe {
    pub packet_id: PacketId,
    pub filters: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Utf8Error {
    #[error("input exceeds Mosquitto's UTF-8 validator limit of 65536 bytes")]
    TooLong,
    #[error("ill-formed UTF-8: {0}")]
    InvalidEncoding(#[from] std::str::Utf8Error),
    #[error("code point U+{:04X} is forbidden in MQTT strings", *character as u32)]
    DisallowedCodePoint { character: char },
}

/// Validates a string as Mosquitto's `mosquitto_validate_utf8` does
/// (`libcommon/utf8_common.c`), returning the borrowed string without copying.
///
/// Like Mosquitto's validator, this accepts up to 65536 bytes (one more than
/// fits in an MQTT string prefix), and rejects ill-formed UTF-8, C0 and C1
/// controls including NUL and DEL, and Unicode noncharacters. Empty input
/// and U+FEFF are accepted. Binary packet fields must not be checked with this.
pub fn validate_utf8(bytes: &[u8]) -> Result<&str, Utf8Error> {
    if bytes.len() > 65_536 {
        return Err(Utf8Error::TooLong);
    }
    let text = std::str::from_utf8(bytes)?;
    validate_code_points(text)?;
    Ok(text)
}

fn validate_code_points(text: &str) -> Result<(), Utf8Error> {
    for character in text.chars() {
        let code = character as u32;
        if matches!(code, 0..=0x1f | 0x7f..=0x9f | 0xfdd0..=0xfdef) || code & 0xfffe == 0xfffe {
            return Err(Utf8Error::DisallowedCodePoint { character });
        }
    }
    Ok(())
}

const CONNECT: u8 = 0x10;
const CONNACK: u8 = 0x20;
const PUBLISH: u8 = 0x30;
const PUBACK: u8 = 0x40;
const PUBREC: u8 = 0x50;
const PUBREL: u8 = 0x60;
const PUBCOMP: u8 = 0x70;
const SUBSCRIBE: u8 = 0x80;
const SUBACK: u8 = 0x90;
const UNSUBSCRIBE: u8 = 0xa0;
const UNSUBACK: u8 = 0xb0;
const PINGREQ: u8 = 0xc0;
const PINGRESP: u8 = 0xd0;
const DISCONNECT: u8 = 0xe0;

const USERNAME_FLAG: u8 = 0x80;
const PASSWORD_FLAG: u8 = 0x40;
const WILL_RETAIN_FLAG: u8 = 0x20;
const WILL_QOS_MASK: u8 = 0x18;
const WILL_FLAG: u8 = 0x04;
const CLEAN_SESSION_FLAG: u8 = 0x02;
const DUP_FLAG: u8 = 0x08;
const RETAIN_FLAG: u8 = 0x01;

// src/handle_connect.c: read_protocol_name reads four or six bytes;
// read_and_verify_protocol_version compares them with strcmp.
fn connect_protocol_name(name: &[u8]) -> &[u8] {
    name.split(|&byte| byte == 0).next().unwrap_or(name)
}

const fn remaining_length_bytes(length: usize) -> usize {
    match length {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

// libcommon/topic_common.c: mosquitto_pub_topic_check / mosquitto_sub_topic_check;
// both limit the number of slash separators to TOPIC_HIERARCHY_LIMIT in config.h.
fn valid_topic(topic: &str, filter: bool) -> bool {
    let bytes = topic.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut slashes = 0;
    let mut level_start = true;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'/' => {
                slashes += 1;
                if slashes > 200 {
                    return false;
                }
            }
            b'+' if !filter
                || !level_start
                || bytes.get(index + 1).is_some_and(|&next| next != b'/') =>
            {
                return false;
            }
            b'#' if !filter || !level_start || index + 1 != bytes.len() => return false,
            _ => {}
        }
        level_start = byte == b'/';
    }
    true
}
