use std::{
    collections::HashMap,
    io::{self, Read},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use mqx_codec::{PacketId, QoS};
use mqx_topic::validate_topic_name;

use super::{
    PersistentOutgoing, PersistentSession, PersistentState, PersistentSubscription, invalid,
};
use crate::inbox::{Message, PublishProperty, Publisher};

const MAGIC: &[u8] = b"\0\xb5\0mosquitto db";
const MAX_PACKET: usize = 268_435_455;

// src/persist_read.c: persist__restore accepts 2 through 6. v5/v6 write
// fixed-size C structs with padding and native-endian dbids and timestamps;
// variable lengths and packet ids are in network order in all versions.
pub(super) fn read(
    mut input: impl Read,
    security_id: impl Fn(u16) -> u64,
) -> io::Result<PersistentState> {
    let mut header = [0; 23];
    if input.read(&mut header[..1])? == 0 {
        tracing::warn!("Warning: Persistence file is empty.");
        return Ok(PersistentState::default());
    }
    input.read_exact(&mut header[1..])?;
    if &header[..15] != MAGIC {
        return Err(invalid("unrecognised Mosquitto database format"));
    }
    let version = u32::from_be_bytes(header[19..].try_into().unwrap());
    if !(2..=6).contains(&version) {
        return Err(invalid(format!(
            "unsupported Mosquitto persistence version {version}"
        )));
    }
    let mut state = PersistentState::default();
    let mut messages = HashMap::new();
    let mut sessions = HashMap::new();
    let mut order = 0;
    let wide = version >= 5;
    loop {
        let mut header = [0; 8];
        let header = &mut header[if wide { 0 } else { 2 }..];
        if input.read(&mut header[..1])? == 0 {
            break;
        }
        input.read_exact(&mut header[1..])?;
        let kind = if wide {
            u32::from_be_bytes(header[..4].try_into().unwrap())
        } else {
            u32::from(u16::from_be_bytes(header[..2].try_into().unwrap()))
        };
        let length = u32::from_be_bytes(header[header.len() - 4..].try_into().unwrap());
        let mut chunk = (&mut input).take(u64::from(length));
        if !(1..=6).contains(&kind) {
            tracing::warn!(
                "Warning: Unsupported chunk \"{kind}\" in persistent database file. Ignoring."
            );
            io::copy(&mut chunk, &mut io::sink())?;
            if chunk.limit() != 0 {
                return Err(invalid("truncated Mosquitto database chunk"));
            }
            continue;
        }
        if length as usize > MAX_PACKET + 3 * usize::from(u16::MAX) + 32 {
            return Err(invalid("oversized Mosquitto database chunk"));
        }
        let mut bytes = Vec::new();
        chunk.read_to_end(&mut bytes)?;
        if chunk.limit() != 0 {
            return Err(invalid("truncated Mosquitto database chunk"));
        }
        let mut chunk = Record(Bytes::from(bytes));
        match kind {
            1 => {
                chunk.skip(if wide { 9 } else { 1 })?;
                if chunk.byte()? != 8 {
                    return Err(invalid("unsupported Mosquitto dbid width"));
                }
                chunk.skip(chunk.0.len())?; // remaining cfg fields and ABI padding
            }
            2 => {
                let (id, message) = chunk.base(version, &security_id)?;
                messages.insert(id, state.messages.len());
                state.messages.push(Arc::new(message));
            }
            3 => {
                let (client, id, mid, entry) = chunk.client_message(wide)?;
                if let (Some(client), Some(&message)) = (client, messages.get(&id)) {
                    let session = session(&mut state, &mut sessions, client, security_id(0));
                    match entry {
                        Some(mut entry) => {
                            entry.message = Some(message);
                            session.outgoing.push(entry);
                        }
                        None => session.incoming.extend(mid.map(|mid| (mid, Some(message)))),
                    }
                }
            }
            4 => {
                if let Some(&index) = messages.get(&chunk.native_id()?) {
                    state.retained.push(index);
                }
            }
            5 => {
                order += 1;
                let (client, sub) = chunk.subscription(wide, order)?;
                if let (Some(client), Some(sub)) = (client, sub) {
                    session(&mut state, &mut sessions, client, security_id(0))
                        .subscriptions
                        .push(sub);
                }
            }
            6 => {
                let (client, username, port, last_mid, expiry_interval, expires) =
                    chunk.client(version)?;
                if let Some(client) = client {
                    let session = session(&mut state, &mut sessions, client, security_id(port));
                    session.publisher.username = username.map(Into::into);
                    session.publisher.security = security_id(port);
                    session.last_mid = last_mid;
                    session.expiry_interval = expiry_interval;
                    session.expires = expires;
                }
            }
            _ => unreachable!(),
        }
        if !chunk.0.is_empty() {
            return Err(invalid(format!(
                "unexpected data in Mosquitto database chunk {kind}"
            )));
        }
    }
    state.validate()?;
    Ok(state)
}

fn session<'a>(
    state: &'a mut PersistentState,
    sessions: &mut HashMap<Arc<str>, usize>,
    client: String,
    security: u64,
) -> &'a mut PersistentSession {
    let client: Arc<str> = client.into();
    let index = sessions.entry(client.clone()).or_insert_with(|| {
        let index = state.sessions.len();
        state.sessions.push(PersistentSession {
            publisher: Publisher {
                id: client,
                username: None,
                security,
                dynamic_security: None,
                external: None,
            },
            last_mid: 0,
            expiry_interval: None,
            expires: None,
            bridge: None,
            subscriptions: Vec::new(),
            outgoing: Vec::new(),
            incoming: Vec::new(),
        });
        index
    });
    &mut state.sessions[*index]
}

struct Record(Bytes);

type Client = (
    Option<String>,
    Option<String>,
    u16,
    u16,
    Option<u32>,
    Option<Duration>,
);
type ClientMessage = (
    Option<String>,
    u64,
    Option<PacketId>,
    Option<PersistentOutgoing>,
);

impl Record {
    fn skip(&mut self, n: usize) -> io::Result<()> {
        if self.0.len() < n {
            return Err(invalid("truncated Mosquitto database record"));
        }
        self.0.advance(n);
        Ok(())
    }

    fn take(&mut self, n: usize) -> io::Result<Bytes> {
        if self.0.len() < n {
            return Err(invalid("truncated Mosquitto database record"));
        }
        Ok(self.0.split_to(n))
    }

    fn num<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let field = self
            .0
            .get(..N)
            .ok_or_else(|| invalid("truncated Mosquitto database record"))?;
        let number = field.try_into().unwrap();
        self.0.advance(N);
        Ok(number)
    }

    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.num::<1>()?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.num()?))
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.num()?))
    }
    fn native_id(&mut self) -> io::Result<u64> {
        Ok(u64::from_ne_bytes(self.num()?))
    }
    fn timestamp(&mut self) -> io::Result<Option<Duration>> {
        let value = i64::from_ne_bytes(self.num()?);
        Ok((value > 0).then(|| Duration::from_secs(value as u64)))
    }

    fn string(&mut self, len: u16) -> io::Result<Option<String>> {
        if len == 0 {
            return Ok(None);
        }
        let bytes = self.take(usize::from(len))?;
        // persist__read_string_len NUL-terminates the field for C callers.
        let bytes = bytes.split(|&b| b == 0).next().unwrap();
        Ok(Some(
            std::str::from_utf8(bytes).map_err(invalid)?.to_owned(),
        ))
    }

    fn prefixed_string(&mut self) -> io::Result<Option<String>> {
        let len = self.u16()?;
        self.string(len)
    }

    fn qos(&mut self) -> io::Result<QoS> {
        match self.byte()? {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            2 => Ok(QoS::ExactlyOnce),
            _ => Err(invalid("invalid Mosquitto database QoS")),
        }
    }

    fn client(&mut self, version: u32) -> io::Result<Client> {
        if version < 5 {
            let id = self.prefixed_string()?;
            let mid = self.u16()?;
            if version > 2 {
                // persist__chunk_client_read_v234 reads but does not use disconnect_t.
                if !matches!(self.0.len(), 4 | 8) {
                    return Err(invalid("invalid Mosquitto database time_t width"));
                }
                self.skip(self.0.len())?;
            }
            return Ok((id, None, 0, mid, None, None));
        }
        let expires = self.timestamp()?;
        let interval = self.u32()?;
        let mid = self.u16()?;
        let len = self.u16()?;
        let (port, username_len) = if version == 6 {
            let port = self.u16()?;
            let username = self.u16()?;
            if self.0.len() == 4 + usize::from(len) + usize::from(username) {
                self.skip(4)?;
            }
            (port, username)
        } else {
            (0, 0)
        };
        let id = self.string(len)?;
        let username = self.string(username_len)?;
        let expires = expires.map(|at| at.saturating_add(Duration::from_secs(1)));
        Ok((id, username, port, mid, Some(interval), expires))
    }

    fn base(
        &mut self,
        version: u32,
        security_id: &impl Fn(u16) -> u64,
    ) -> io::Result<(u64, Message)> {
        let id = self.native_id()?;
        let (expires, size, source, username, port, topic, qos, retain) = if version >= 5 {
            let expiry = self.timestamp()?;
            let size = self.u32()?;
            self.skip(2)?; // source packet id, tracked by incoming references
            let id_len = self.u16()?;
            let username_len = self.u16()?;
            let topic_len = self.u16()?;
            let port = self.u16()?;
            let qos = self.qos()?;
            let retain = self.byte()? != 0;
            (
                expiry,
                size,
                self.string(id_len)?,
                self.string(username_len)?,
                port,
                self.string(topic_len)?,
                qos,
                retain,
            )
        } else {
            let source = self.prefixed_string()?;
            let (username, port) = if version == 4 {
                (self.prefixed_string()?, self.u16()?)
            } else {
                (None, 0)
            };
            self.skip(4)?;
            let topic = self.prefixed_string()?;
            let qos = self.qos()?;
            let retain = self.byte()? != 0;
            (
                None,
                self.u32()?,
                source,
                username,
                port,
                topic,
                qos,
                retain,
            )
        };
        let topic = topic.ok_or_else(|| invalid("empty persisted Mosquitto topic"))?;
        validate_topic_name(&topic).map_err(invalid)?;
        if size as usize > MAX_PACKET {
            return Err(invalid("oversized Mosquitto payload"));
        }
        let payload = self.take(size as usize)?;
        let (properties, _) = self.properties()?;
        Ok((
            id,
            Message {
                source: Publisher {
                    id: source.unwrap_or_default().into(),
                    username: username.map(Into::into),
                    security: security_id(port),
                    dynamic_security: None,
                    external: None,
                },
                topic: topic.into_boxed_str(),
                payload,
                qos,
                retain,
                properties,
                expires,
                broker_expires: None,
            },
        ))
    }

    fn client_message(&mut self, wide: bool) -> io::Result<ClientMessage> {
        let (client, store_id, mid, qos, state, retain, dup, direction, identifier) = if wide {
            let store_id = self.native_id()?;
            let mid = self.u16()?;
            let len = self.u16()?;
            let qos = self.qos()?;
            let state = self.byte()?;
            let flags = self.byte()?;
            let direction = self.byte()?;
            let client = self.string(len)?;
            let (_, identifier) = self.properties()?;
            (
                client,
                store_id,
                mid,
                qos,
                state,
                flags >> 4 != 0,
                flags & 0x0f != 0,
                direction,
                identifier,
            )
        } else {
            let client = self.prefixed_string()?;
            let store_id = self.native_id()?;
            let mid = self.u16()?;
            let qos = self.qos()?;
            let retain = self.byte()? != 0;
            let direction = self.byte()?;
            let state = self.byte()?;
            let dup = self.byte()? != 0;
            (client, store_id, mid, qos, state, retain, dup, direction, 0)
        };
        let packet_id = PacketId::new(mid);
        let outgoing = (direction == 1).then_some(PersistentOutgoing {
            message: None,
            id: packet_id,
            qos,
            retain,
            dup,
            // database.c: db__message_reconnect_reset_outgoing resumes either
            // a PUBLISH or the QoS 2 PUBREL, preserving the PUBLISH DUP bit.
            release: matches!(state, 6 | 9),
            queued: state == 11,
            identifier,
        });
        let inbound = if direction != 1 && qos == QoS::ExactlyOnce {
            packet_id
        } else {
            None
        };
        Ok((client, store_id, inbound, outgoing))
    }

    fn subscription(
        &mut self,
        wide: bool,
        order: u64,
    ) -> io::Result<(Option<String>, Option<PersistentSubscription>)> {
        let (client, filter, qos, options, identifier) = if wide {
            let identifier = self.u32()?;
            let id_len = self.u16()?;
            let filter_len = self.u16()?;
            let qos = self.qos()?;
            let options = self.byte()?;
            self.skip(2)?; // src/persist.h: PF_sub tail padding
            (
                self.string(id_len)?,
                self.string(filter_len)?,
                qos,
                options,
                identifier,
            )
        } else {
            (
                self.prefixed_string()?,
                self.prefixed_string()?,
                self.qos()?,
                0,
                0,
            )
        };
        Ok((
            client,
            filter.map(|filter| PersistentSubscription {
                filter: filter.into(),
                order,
                qos,
                no_local: options & 0x04 != 0,
                retain_as_published: options & 0x08 != 0,
                identifier,
            }),
        ))
    }

    fn varint(&mut self) -> io::Result<u32> {
        let mut value = 0;
        for shift in [0, 7, 14, 21] {
            let byte = self.byte()?;
            value |= u32::from(byte & 127) << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        Err(invalid("invalid Mosquitto property varint"))
    }

    // persist_read_v5.c: the optional tail is a PUBLISH property section.
    fn properties(&mut self) -> io::Result<(Vec<PublishProperty>, u32)> {
        let mut properties = Vec::new();
        let mut identifier = 0;
        if self.0.is_empty() {
            return Ok((properties, identifier));
        }
        let len = self.varint()? as usize;
        let mut values = Record(self.take(len)?);
        let required_string = |r: &mut Self| r.prefixed_string().map(Option::unwrap_or_default);
        while !values.0.is_empty() {
            properties.push(match values.varint()? {
                1 => PublishProperty::PayloadFormat(values.byte()?),
                2 => {
                    values.skip(4)?;
                    continue;
                }
                3 => PublishProperty::ContentType(required_string(&mut values)?),
                8 => PublishProperty::ResponseTopic(required_string(&mut values)?),
                9 => {
                    let len = values.u16()?;
                    PublishProperty::CorrelationData(values.take(usize::from(len))?)
                }
                11 => {
                    identifier = values.varint()?;
                    continue;
                }
                35 => {
                    values.skip(2)?;
                    continue;
                }
                38 => PublishProperty::User(
                    required_string(&mut values)?,
                    required_string(&mut values)?,
                ),
                _ => return Err(invalid("unexpected Mosquitto PUBLISH property")),
            });
        }
        Ok((properties, identifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(db: &mut Vec<u8>, version: u32, kind: u32, bytes: &[u8]) {
        if version >= 5 {
            db.extend(kind.to_be_bytes());
        } else {
            db.extend((kind as u16).to_be_bytes());
        }
        db.extend((bytes.len() as u32).to_be_bytes());
        db.extend(bytes);
    }

    // The legacy records consumed by persist_read_v234.c and persist_read_v5.c.
    #[test]
    fn reads_legacy_database_records_and_rejects_a_truncated_chunk() {
        for version in 2u32..=5 {
            let mut db = MAGIC.to_vec();
            db.extend([0; 4]); // Historical checksum field.
            db.extend(version.to_be_bytes());
            let store = 17u64.to_ne_bytes();
            let mut config = Vec::new();
            if version == 5 {
                config.extend(store);
                config.extend([1, 8, 0, 0, 0, 0, 0, 0]);
            } else {
                config.extend([1, 8]);
                config.extend(store);
            }
            chunk(&mut db, version, 1, &config);
            let mut base = store.to_vec();
            if version == 5 {
                base.extend(120i64.to_ne_bytes());
                base.extend(3u32.to_be_bytes());
                base.extend(b"\0\x01\0\x01\0\0\0\x01\0\0\x01\x01");
                base.extend(b"stmsg");
            } else {
                base.extend(b"\0\x01s");
                if version == 4 {
                    base.extend(b"\0\0\0\0"); // Source username and listener.
                }
                base.extend(b"\0\x01\0\0\0\x01t\x01\x01");
                base.extend(3u32.to_be_bytes());
                base.extend(b"msg");
            }
            chunk(&mut db, version, 2, &base);
            let mut client = Vec::new();
            if version == 5 {
                client.extend([0; 8]);
                client.extend(u32::MAX.to_be_bytes());
                client.extend(b"\0\x09\0\x01c");
            } else {
                client.extend(b"\0\x01c\0\x09");
                if version > 2 {
                    client.extend([0; 8]);
                }
            }
            chunk(&mut db, version, 6, &client);
            let mut outgoing = Vec::new();
            if version == 5 {
                outgoing.extend(store);
                outgoing.extend(b"\0\x09\0\x01\x01\x0b\x10\x01c");
            } else {
                outgoing.extend(b"\0\x01c");
                outgoing.extend(store);
                outgoing.extend(b"\0\x09\x01\x01\x01\x0b\0");
            }
            chunk(&mut db, version, 3, &outgoing);
            chunk(&mut db, version, 4, &store);
            let sub = if version == 5 {
                b"\0\0\0\x0d\0\x01\0\x01\x01\x04\0\0ct" as &[u8]
            } else {
                b"\0\x01c\0\x01t\x01"
            };
            chunk(&mut db, version, 5, sub);
            chunk(&mut db, version, 101, b"unknown");
            let mut state = read(&db[..], |_| 1).unwrap();
            assert_eq!(state.messages[0].payload, b"msg"[..]);
            assert_eq!(state.retained, [0]);
            let session = &state.sessions[0];
            assert_eq!(session.publisher.id.as_ref(), "c");
            assert_eq!(session.last_mid, 9);
            assert_eq!(session.outgoing[0].id, PacketId::new(9));
            assert!(session.outgoing[0].queued);
            assert_eq!(session.subscriptions[0].filter.as_ref(), "t");
            assert_eq!(session.subscriptions[0].no_local, version == 5);
            let mqtt_deadline = (version == 5).then(|| Duration::from_secs(120));
            assert_eq!(state.messages[0].expires, mqtt_deadline);
            assert!(state.needs_message_age_upgrade());
            let imported_at = Duration::from_secs(100);
            state.cap_message_ages(imported_at);
            assert_eq!(state.messages[0].expires, mqtt_deadline);
            assert_eq!(
                state.messages[0].broker_expires,
                Some(imported_at + crate::inbox::MAX_MESSAGE_AGE)
            );
            assert!(read(&db[..db.len() - 1], |_| 1).is_err());
        }
    }
}
