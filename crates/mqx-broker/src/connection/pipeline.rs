use std::time::Duration;

use mqx_codec::{
    Packet, PacketId, ProtocolVersion, QoS,
    v5::{Packet as Packet5, ReasonCode as R},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};

use super::{Active, End, Frame, Step, Wire, mount, v5};
use crate::{
    BrokerConfig, BrokerError, ListenerPolicy,
    inbox::Ack,
    state::{Publication, Reply},
};

pub(super) const PREFETCH_BYTES: usize = 256 * 1024;
const BATCH_PACKETS: usize = 32;

pub(super) fn eligible(packet: &Frame, listener: &ListenerPolicy, config: &BrokerConfig) -> bool {
    let (qos, retain) = match packet {
        Frame::Legacy(Packet::Publish(packet)) => (packet.qos, packet.retain),
        Frame::V5(Packet5::Publish(packet)) => (packet.qos, packet.retain),
        _ => return false,
    };
    qos != QoS::ExactlyOnce
        && qos as u8 <= listener.max_qos as u8
        && (!retain || config.retain_available)
}

fn prepare<S>(
    wire: &mut Wire<S>,
    packet: Frame,
    mount_point: Option<&str>,
    now: Duration,
) -> Result<Publication, BrokerError> {
    let mut publication = match packet {
        Frame::Legacy(Packet::Publish(packet)) => Publication::legacy(packet, now),
        Frame::V5(Packet5::Publish(packet)) => {
            wire.v5.as_mut().unwrap().publication(packet, now)?
        }
        _ => unreachable!("only QoS 0/1 publications are pipelined"),
    };
    mount(&mut publication.packet.topic, mount_point);
    Ok(publication)
}

fn next_is_eligible(header: u8, listener: &ListenerPolicy, config: &BrokerConfig) -> bool {
    let qos = (header >> 1) & 3;
    header >> 4 == 3
        && qos <= 1
        && qos <= listener.max_qos as u8
        && (header & 1 == 0 || config.retain_available)
}

pub(super) async fn publish<S: AsyncRead + AsyncWrite + Unpin>(
    session: &Active<'_>,
    wire: &mut Wire<S>,
    first: Frame,
    listener: &ListenerPolicy,
    protocol: ProtocolVersion,
    mut remaining: usize,
) -> Result<Step, BrokerError> {
    let config = session.broker.0.config.startup();
    let mut publications = Vec::with_capacity(BATCH_PACKETS);
    let mut ids = [None; BATCH_PACKETS];
    let mount_point = listener.mount_point.as_deref();
    let mut packet = first;
    loop {
        let publication = match prepare(wire, packet, mount_point, session.broker.now()) {
            Ok(publication) => publication,
            Err(error) => {
                // Report a later malformed packet only after the earlier
                // packets have committed and their acknowledgements are sent.
                wire.pending_error = Some(error);
                break;
            }
        };
        ids[publications.len()] = publication.packet.packet_id;
        publications.push(publication);
        if publications.len() == BATCH_PACKETS
            || !can_follow(&wire.input, remaining, listener, config)
        {
            break;
        }
        let bytes = wire.input.len();
        match wire.packet(config, protocol) {
            Ok(Some(next)) => {
                packet = next;
                remaining = remaining.saturating_sub(bytes - wire.input.len());
            }
            Ok(None) => break,
            Err(error) => {
                wire.pending_error = Some(error);
                break;
            }
        }
    }
    if publications.is_empty() {
        return Err(wire.pending_error.take().expect("failed first publication"));
    }
    let replies = wire
        .prefetch(
            session
                .broker
                .receive_many(&session.live, publications, session.sparkplug_aware),
        )
        .await?;
    for (id, reply) in ids.into_iter().zip(replies) {
        let reason = match reply {
            Reply::PublishReason(reason) => R(reason),
            Reply::ControlAccepted { .. } => R::SUCCESS,
            Reply::ExternalAclError => return Ok(Step::End(End::ExternalAcl)),
            Reply::Stale => return Ok(Step::End(End::Takeover)),
            Reply::ProtocolError => return Err(BrokerError::Protocol),
            _ => unreachable!("QoS 0/1 pipeline got a handshake reply"),
        };
        if let Some(id) = id {
            if wire.v5.is_some() {
                wire.output_v5(&Packet5::PubAck(v5::publish_ack(id, reason)))?;
            } else {
                wire.output(&Packet::PubAck(id))?;
            }
        }
    }
    Ok(Step::Continue)
}

// The compact PUBACK is identical in v3 and v5. Other v5 reasons and
// properties continue to use the individual packet handler.
pub(super) fn simple_ack(packet: &Frame) -> Option<PacketId> {
    match packet {
        Frame::Legacy(Packet::PubAck(id)) => Some(*id),
        Frame::V5(Packet5::PubAck(ack))
            if ack.reason == R::SUCCESS && ack.properties.is_empty() =>
        {
            Some(ack.packet_id)
        }
        _ => None,
    }
}

pub(super) async fn acknowledge<S: AsyncRead + AsyncWrite + Unpin>(
    session: &Active<'_>,
    wire: &mut Wire<S>,
    first: PacketId,
    protocol: ProtocolVersion,
    mount_point: Option<&str>,
    keep_alive: u16,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Step, BrokerError> {
    debug_assert!(wire.idle());
    let mut ids = [first; BATCH_PACKETS];
    let mut count = 1;
    for frame in wire.input.as_chunks::<4>().0.iter().take(BATCH_PACKETS - 1) {
        let [0x40, 2, hi, lo] = *frame else { break };
        let Some(id) = PacketId::new(u16::from_be_bytes([hi, lo])) else {
            break;
        };
        ids[count] = id;
        count += 1;
    }
    let (count, step) = wire
        .while_acknowledging(session, first, mount_point, keep_alive, shutdown, async {
            if count > 1
                && let Some((applied, reply)) = session
                    .broker
                    .ack_prefix(
                        &session.live,
                        &ids[..count],
                        mount_point.map_or(0, str::len),
                    )
                    .await?
            {
                return Ok((applied, super::action_result(reply)?));
            }
            Ok((1, session.ack(first, Ack::Acknowledged).await?))
        })
        .await?;
    for _ in 1..count {
        // Reuse normal decoding and traffic accounting. Only complete compact
        // acknowledgements were selected, and transport progress never consumes input.
        let packet = wire.packet(session.broker.0.config.startup(), protocol)?;
        debug_assert!(packet.as_ref().and_then(simple_ack).is_some());
    }
    Ok(step)
}

pub(super) fn can_follow(
    input: &[u8],
    budget: usize,
    listener: &ListenerPolicy,
    config: &BrokerConfig,
) -> bool {
    input
        .first()
        .is_some_and(|&header| next_is_eligible(header, listener, config))
        && super::frame_size(input).is_some_and(|size| size <= budget.min(input.len()))
}
