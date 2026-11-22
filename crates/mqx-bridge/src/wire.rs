use std::{collections::HashMap, io, time::Duration};

use bytes::{Buf, BytesMut};
use mqx_codec::{
    self as legacy, ProtocolVersion,
    v5::{self, Packet, Property, PublishAck, ReasonCode as R},
};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream, lookup_host},
    time::Instant,
};

use crate::{BridgeConfig, Dialer, Protocol};

pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

pub(crate) struct Wire {
    stream: Box<dyn Transport>,
    input: BytesMut,
    output: BytesMut,
    pub(crate) protocol: Protocol,
    pub(crate) last_read: Instant,
    pub(crate) last_write: Instant,
    pub(crate) packet_limit: usize,
    pub(crate) alias_max: u16,
    inbound_aliases: HashMap<u16, String>,
    outbound_aliases: HashMap<String, u16>,
}

impl Wire {
    pub(crate) async fn connect(
        config: &BridgeConfig,
        address: usize,
        protocol: Protocol,
        dialer: Dialer,
    ) -> io::Result<Self> {
        let stream = tcp(config, address).await?;
        stream.set_nodelay(dialer.nodelay)?;
        let socket = SockRef::from(&stream);
        // src/bridge.c: bridge__set_tcp_keepalive / bridge__set_tcp_user_timeout.
        if let Some((idle, interval, count)) = config.tcp_keepalive {
            socket.set_keepalive(true)?;
            socket.set_tcp_keepalive(
                &TcpKeepalive::new()
                    .with_time(Duration::from_secs(u64::from(idle)))
                    .with_interval(Duration::from_secs(u64::from(interval)))
                    .with_retries(count),
            )?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ms) = config.tcp_user_timeout {
            socket.set_tcp_user_timeout(Some(Duration::from_millis(u64::from(ms))))?;
        }
        let stream: Box<dyn Transport> = if config.tls.enabled() {
            (dialer.tls)(stream, &config.addresses[address].0, &config.tls).await?
        } else {
            Box::new(stream)
        };
        let now = Instant::now();
        Ok(Self {
            stream,
            protocol,
            last_read: now,
            last_write: now,
            packet_limit: config.max_packet_size,
            alias_max: 0,
            input: BytesMut::new(),
            output: BytesMut::new(),
            inbound_aliases: HashMap::new(),
            outbound_aliases: HashMap::new(),
        })
    }

    pub(crate) fn decode(&mut self) -> Result<Option<Packet>, crate::Error> {
        // src/handle_connack.c: handle__connack sees the legacy refusal before
        // interpreting it as v5, and handles all legacy reason bytes itself.
        if self.input.first() == Some(&0x20)
            && let Some((offset, length)) = remaining_length(&self.input)
            && (self.protocol != Protocol::V5 || length == 2)
        {
            if self.input.len() < offset + length {
                return Ok(None);
            }
            if length < 2 {
                return Err(crate::Error::Protocol);
            }
            let flags = self.input[offset];
            let reason = R(self.input[offset + 1]);
            if self.protocol != Protocol::V5 || reason.0 == 1 {
                self.input.advance(offset + length);
                self.last_read = Instant::now();
                return Ok(Some(Packet::ConnAck(v5::ConnAck {
                    session_present: flags & 1 != 0,
                    reason,
                    properties: Vec::new(),
                })));
            }
        }
        let packet = if self.protocol == Protocol::V5 {
            v5::decode(&mut self.input, v5::DecodeContext::for_bridge(0))?
        } else {
            legacy::decode(
                &mut self.input,
                legacy::DecodeContext::new(0, self.protocol.legacy()),
            )?
            .map(upgrade)
            .transpose()?
        };
        if packet.is_some() {
            self.last_read = Instant::now();
        }
        Ok(packet)
    }

    pub(crate) async fn read(&mut self) -> io::Result<()> {
        if self.stream.read_buf(&mut self.input).await? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Result<Packet, crate::Error> {
        loop {
            if let Some(packet) = self.decode()? {
                return Ok(packet);
            }
            self.read().await?;
        }
    }

    pub(crate) async fn send(&mut self, packet: Packet) -> Result<bool, crate::Error> {
        self.output.clear();
        let publish = matches!(packet, Packet::Publish(_));
        let alias = if self.protocol == Protocol::V5 {
            let mut packet = packet;
            let alias = if let Packet::Publish(publish) = &mut packet {
                self.encode_alias(publish)
            } else {
                None
            };
            v5::encode(&packet, &mut self.output)?;
            alias
        } else {
            legacy::encode(
                &downgrade(packet, self.protocol.legacy().unwrap())?,
                &mut self.output,
            )?;
            None
        };
        // lib/send_publish.c: send__real_publish applies the packet limit.
        // Bridge control packets use the raw send helpers without this check.
        if publish && self.packet_limit != 0 && self.output.len() > self.packet_limit {
            return Ok(false);
        }
        self.stream.write_all(&self.output).await?;
        if let Some((topic, id)) = alias {
            self.outbound_aliases.insert(topic, id);
        }
        self.last_write = Instant::now();
        Ok(true)
    }

    pub(crate) async fn send_legacy_connect(
        &mut self,
        packet: legacy::Connect,
    ) -> Result<(), crate::Error> {
        self.output.clear();
        legacy::encode(&legacy::Packet::Connect(packet), &mut self.output)?;
        self.stream.write_all(&self.output).await?;
        self.last_write = Instant::now();
        Ok(())
    }

    // lib/send_publish.c: send__real_publish sends an alias + topic on its
    // first use and only the alias on subsequent uses; it does not evict.
    fn encode_alias(&self, publish: &mut v5::Publish) -> Option<(String, u16)> {
        if let Some(&id) = self.outbound_aliases.get(&publish.topic) {
            publish.properties.push(Property::TopicAlias(id));
            publish.topic.clear();
        } else if self.outbound_aliases.len() < usize::from(self.alias_max) {
            let id = (self.outbound_aliases.len() + 1) as u16;
            publish.properties.push(Property::TopicAlias(id));
            return Some((publish.topic.clone(), id));
        }
        None
    }

    // src/handle_publish.c: the bridge has no listener, so it has no listener
    // alias limit to check. Alias resolution precedes topic remapping.
    pub(crate) fn resolve_alias(&mut self, publish: &mut v5::Publish) -> Result<(), crate::Error> {
        if let Some(id) = publish.properties.iter().find_map(|prop| match prop {
            Property::TopicAlias(id) => Some(*id),
            _ => None,
        }) {
            if id == 0 {
                return Err(crate::Error::ProtocolReason(R::TOPIC_ALIAS_INVALID));
            }
            if publish.topic.is_empty() {
                publish.topic = self
                    .inbound_aliases
                    .get(&id)
                    .ok_or(crate::Error::ProtocolReason(R::PROTOCOL_ERROR))?
                    .clone();
            } else {
                self.inbound_aliases.insert(id, publish.topic.clone());
            }
        }
        Ok(())
    }
}

impl Protocol {
    pub(crate) fn legacy(self) -> Option<ProtocolVersion> {
        match self {
            Self::V31 => Some(ProtocolVersion::V31),
            Self::V311 => Some(ProtocolVersion::V311),
            Self::V5 => None,
        }
    }
}

// lib/net_mosq.c: net__try_connect resolves the destination and uses a source
// bind address of the same family; failed destinations advance in DNS order.
pub(crate) async fn tcp(config: &BridgeConfig, address: usize) -> io::Result<TcpStream> {
    let (host, port) = &config.addresses[address];
    let sources = match &config.bind_address {
        Some(host) => Some(lookup_host((host.as_str(), 0)).await?.collect::<Vec<_>>()),
        None => None,
    };
    let mut failure = io::Error::new(io::ErrorKind::AddrNotAvailable, "no usable bridge address");
    for address in lookup_host((host.as_str(), *port)).await? {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(sources) = &sources {
            let Some(source) = sources
                .iter()
                .find(|source| source.is_ipv4() == address.is_ipv4())
            else {
                continue;
            };
            socket.bind(*source)?;
        }
        match socket.connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}

fn remaining_length(input: &[u8]) -> Option<(usize, usize)> {
    let mut length = 0;
    for (index, byte) in input.iter().skip(1).take(4).copied().enumerate() {
        length |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((index + 2, length));
        }
    }
    None
}

fn upgrade(packet: legacy::Packet) -> Result<Packet, crate::Error> {
    use legacy::Packet as L;
    let ack = |packet_id| PublishAck {
        packet_id,
        reason: R::SUCCESS,
        properties: Vec::new(),
    };
    let subscription_ack = |packet_id| v5::SubscriptionAck {
        packet_id,
        properties: Vec::new(),
        reasons: Vec::new(),
    };
    Ok(match packet {
        L::Publish(p) => Packet::Publish(v5::Publish {
            dup: p.dup,
            qos: p.qos,
            retain: p.retain,
            topic: p.topic,
            packet_id: p.packet_id,
            properties: Vec::new(),
            payload: p.payload,
        }),
        L::PubAck(id) => Packet::PubAck(ack(id)),
        L::PubRec(id) => Packet::PubRec(ack(id)),
        L::PubRel(id) => Packet::PubRel(ack(id)),
        L::PubComp(id) => Packet::PubComp(ack(id)),
        L::SubAck(ack) => Packet::SubAck(subscription_ack(ack.packet_id)),
        L::UnsubAck(id) => Packet::UnsubAck(subscription_ack(id)),
        L::PingResp => Packet::PingResp,
        L::PingReq => Packet::PingReq,
        L::Disconnect => Packet::Disconnect(v5::ReasonProperties::default()),
        _ => return Err(crate::Error::Protocol),
    })
}

fn downgrade(packet: Packet, _protocol: ProtocolVersion) -> Result<legacy::Packet, crate::Error> {
    use legacy::Packet as L;
    Ok(match packet {
        Packet::Publish(p) => L::Publish(legacy::Publish {
            dup: p.dup,
            qos: p.qos,
            retain: p.retain,
            topic: p.topic,
            packet_id: p.packet_id,
            payload: p.payload,
        }),
        Packet::PubAck(ack) => L::PubAck(ack.packet_id),
        Packet::PubRec(ack) => L::PubRec(ack.packet_id),
        Packet::PubRel(ack) => L::PubRel(ack.packet_id),
        Packet::PubComp(ack) => L::PubComp(ack.packet_id),
        Packet::Subscribe(sub) => L::Subscribe(legacy::Subscribe {
            packet_id: sub.packet_id,
            filters: sub
                .subscriptions
                .into_iter()
                .map(|sub| (sub.filter, sub.qos))
                .collect(),
        }),
        Packet::Unsubscribe(sub) => L::Unsubscribe(legacy::Unsubscribe {
            packet_id: sub.packet_id,
            filters: sub.filters,
        }),
        Packet::PingReq => L::PingReq,
        Packet::PingResp => L::PingResp,
        Packet::Disconnect(_) => L::Disconnect,
        _ => return Err(crate::Error::Protocol),
    })
}
