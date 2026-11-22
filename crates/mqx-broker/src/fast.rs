//! A node can bypass Raft only for non-retained QoS 0/1 with no durable
//! subscriber or shared-group rotation to update. Acknowledged subscription
//! and ACL changes are fenced across live peers before a replica may route
//! a subsequent publish from its local index. During a partition, losing a
//! transient peer delivery does not roll back or retry a publication.
//!
//! Receivers wait for the publishing replica's applied index before delivery.
//! The sender drains a peer lane before the next publish can pass it, including
//! a retained or QoS 2 operation that instead uses Raft. This is source order,
//! not a total order between publishers on different nodes.

use std::sync::Arc;

use mqx_codec::QoS;
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
    pub(crate) targets: Vec<(u64, Target)>,
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
}
