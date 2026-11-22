use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::node::{Leadership, LogId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// No heartbeat or expiry has been applied for this member yet.
    Unknown,
    Alive,
    Down,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeEvent {
    pub index: u64,
    pub node_id: u64,
    pub status: NodeStatus,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct Stamp {
    pub(crate) leader: Leadership,
    // Monotonic milliseconds since the proposing process started. Only compare
    // values within one leadership; other clocks are not synchronized.
    pub(crate) millis: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Heartbeat {
    index: u64,
    stamp: Stamp,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) enum LeaseCommand {
    Heartbeat {
        node_id: u64,
        stamp: Stamp,
    },
    Expire {
        node_id: u64,
        heartbeat_index: Option<u64>,
        stamp: Stamp,
        timeout_ms: u64,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Lease {
    status: NodeStatus,
    heartbeat: Option<Heartbeat>,
    expired_at: Option<Stamp>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Leases(BTreeMap<u64, Lease>);

impl Leases {
    pub(crate) fn new(ids: impl Iterator<Item = u64>) -> Self {
        Self(
            ids.map(|id| {
                (
                    id,
                    Lease {
                        status: NodeStatus::Unknown,
                        heartbeat: None,
                        expired_at: None,
                    },
                )
            })
            .collect(),
        )
    }

    pub(crate) fn statuses(&self) -> BTreeMap<u64, NodeStatus> {
        self.0
            .iter()
            .map(|(&id, lease)| (id, lease.status))
            .collect()
    }

    pub(crate) fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.keys().copied()
    }

    pub(crate) fn expired(&self, stamp: Stamp, timeout_ms: u64) -> Vec<LeaseCommand> {
        self.0
            .iter()
            .filter(|(node_id, lease)| {
                **node_id != stamp.leader.node_id && lease.is_expired(stamp, timeout_ms)
            })
            .map(|(&node_id, lease)| LeaseCommand::Expire {
                node_id,
                heartbeat_index: lease.heartbeat.map(|h| h.index),
                stamp,
                timeout_ms,
            })
            .collect()
    }

    pub(crate) fn apply(&mut self, log_id: LogId, command: LeaseCommand) -> Option<NodeEvent> {
        let (node_id, stamp) = match command {
            LeaseCommand::Heartbeat { node_id, stamp }
            | LeaseCommand::Expire { node_id, stamp, .. } => (node_id, stamp),
        };
        // A proposal can race with the local node stepping down and regaining leadership.
        if stamp.leader != log_id.leader_id {
            return None;
        }
        let lease = self.0.get_mut(&node_id)?;
        let status = match command {
            LeaseCommand::Heartbeat { .. } => {
                if lease.expired_at.is_some_and(|expiry| {
                    expiry.leader == stamp.leader && expiry.millis >= stamp.millis
                }) || lease.heartbeat.is_some_and(|h| {
                    h.stamp.leader == stamp.leader && h.stamp.millis > stamp.millis
                }) {
                    return None;
                }
                lease.expired_at = None;
                lease.heartbeat = Some(Heartbeat {
                    index: log_id.index,
                    stamp,
                });
                NodeStatus::Alive
            }
            LeaseCommand::Expire {
                heartbeat_index,
                timeout_ms,
                ..
            } => {
                // A heartbeat committed ahead of this expiry invalidates the observation.
                if heartbeat_index != lease.heartbeat.map(|h| h.index)
                    || !lease.is_expired(stamp, timeout_ms)
                {
                    return None;
                }
                lease.expired_at = Some(stamp);
                NodeStatus::Down
            }
        };
        let changed = lease.status != status;
        lease.status = status;
        changed.then_some(NodeEvent {
            index: log_id.index,
            node_id,
            status,
        })
    }
}

impl Lease {
    fn is_expired(&self, now: Stamp, timeout_ms: u64) -> bool {
        self.status != NodeStatus::Down
            && self.heartbeat.is_none_or(|h| {
                h.stamp.leader != now.leader
                    || now.millis.saturating_sub(h.stamp.millis) >= timeout_ms
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_does_not_override_a_newer_heartbeat_or_revive_on_an_old_one() {
        let leader = Leadership {
            term: 2,
            node_id: 1,
        };
        let stamp = |millis| Stamp { leader, millis };
        let id = |index| LogId::new(leader, index);
        let heartbeat = |millis| LeaseCommand::Heartbeat {
            node_id: 2,
            stamp: stamp(millis),
        };
        let mut leases = Leases::new([1, 2].into_iter());
        assert_eq!(
            leases.apply(id(1), heartbeat(100)).unwrap().status,
            NodeStatus::Alive
        );

        let expired = leases.expired(stamp(200), 100)[0];
        assert_eq!(leases.apply(id(2), heartbeat(190)), None);
        assert_eq!(leases.apply(id(3), expired), None);
        assert_eq!(leases.statuses()[&2], NodeStatus::Alive);

        let expired = leases.expired(stamp(300), 100)[0];
        assert_eq!(
            leases.apply(id(4), expired).unwrap().status,
            NodeStatus::Down
        );
        assert_eq!(leases.apply(id(5), expired), None);
        assert_eq!(leases.apply(id(6), heartbeat(299)), None);
        assert_eq!(
            leases.apply(id(7), heartbeat(301)).unwrap().status,
            NodeStatus::Alive
        );
    }
}
