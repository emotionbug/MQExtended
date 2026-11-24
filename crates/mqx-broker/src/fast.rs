//! A node can bypass Raft only for non-retained QoS 0/1 with no durable
//! subscriber or shared-group rotation to update. Acknowledged subscription
//! and ACL changes are fenced across live peers before a replica may route
//! a subsequent publish from its local index. During a partition, losing a
//! transient peer delivery does not roll back or retry a publication.
//!
//! Receivers wait for the publishing replica's applied index before delivery.
//! A publisher can pipeline consecutive deliveries to one remote node, but
//! waits for every handler before advancing past the burst to another path.
//! Unrelated publishers do not have to take turns waiting for network RTTs.

use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use mqx_codec::{QoS, v5::ReasonCode as R};
use serde::{Deserialize, Serialize};

use crate::{
    inbox::{DedupId, Delivery, Message, Publisher},
    state::Epoch,
};

pub(crate) struct Route {
    pub(crate) source: Publisher,
    // A matching subscription counts even when No Local or its read ACL
    // prevents delivery (Mosquitto subs.c: subs__process).
    pub(crate) matched: bool,
    pub(crate) targets: BTreeMap<u64, Vec<Target>>,
}

impl Route {
    pub(crate) fn sole_peer(&self, local: u64) -> Option<u64> {
        if self.targets.len() != 1 {
            return None;
        }
        let (&node, _) = self.targets.first_key_value()?;
        (node != local).then_some(node)
    }

    pub(crate) fn reason(&self) -> u8 {
        if self.matched {
            R::SUCCESS.0
        } else {
            R::NO_MATCHING_SUBSCRIBERS.0
        }
    }
}

// The connection limits the number and wire size of input PUBLISH packets.
// Also budget the encoded mesh bodies, which can grow with subscriber count.
const PEER_BATCH_BYTES: usize = 256 * 1024;

pub(crate) struct PeerBatch {
    pub(crate) node: u64,
    pub(crate) first_reply: usize,
    pub(crate) bodies: PeerBodies,
    bytes: usize,
}

pub(crate) enum PeerBodies {
    One(Bytes),
    Many(Vec<Bytes>),
}

impl PeerBatch {
    pub(crate) fn new(node: u64, first_reply: usize, body: Bytes) -> Self {
        Self {
            node,
            first_reply,
            bytes: body.len(),
            bodies: PeerBodies::One(body),
        }
    }

    pub(crate) fn can_append(&self, node: u64, body: &Bytes) -> bool {
        self.node == node && body.len() <= PEER_BATCH_BYTES - self.bytes
    }

    pub(crate) fn push(&mut self, body: Bytes) {
        self.bytes += body.len();
        match &mut self.bodies {
            PeerBodies::One(first) => {
                let mut bodies = Vec::with_capacity(4);
                bodies.push(std::mem::take(first));
                bodies.push(body);
                self.bodies = PeerBodies::Many(bodies);
            }
            PeerBodies::Many(bodies) => bodies.push(body),
        }
    }

    // A single oversized publication still uses the serial send path, and
    // must be flushed immediately rather than retained across the next plan.
    pub(crate) fn is_full(&self) -> bool {
        self.bytes >= PEER_BATCH_BYTES
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Target {
    pub(crate) epoch: Epoch,
    pub(crate) qos: QoS,
    pub(crate) identifier: u32,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Publication {
    pub(crate) index: u64,
    pub(crate) epoch: Epoch,
    pub(crate) sequence: u64,
    pub(crate) message: Arc<Message>,
    pub(crate) targets: Vec<Target>,
}

impl Publication {
    pub(crate) fn deliveries(self, deduplicate: bool) -> impl Iterator<Item = (Epoch, Delivery)> {
        let dedup_id = deduplicate.then_some(DedupId::Peer([self.epoch, self.sequence]));
        self.targets.into_iter().map(move |target| {
            (
                target.epoch,
                Delivery {
                    message: self.message.clone(),
                    qos: target.qos,
                    retain: false,
                    dedup_id,
                    subscription_identifier: target.identifier,
                },
            )
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) enum Request {
    Fence(u64),
    Publish(Publication),
    SysSample,
}
