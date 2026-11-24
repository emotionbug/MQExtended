use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use crate::{ClusterError, NodeStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum MemberRole {
    Voter,
    Learner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberStatus {
    pub address: SocketAddr,
    pub role: MemberRole,
    pub liveness: NodeStatus,
}

/// Locally applied membership and current leader hint; not a linearizable read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MembershipStatus {
    pub generation: u64,
    pub desired: BTreeMap<u64, SocketAddr>,
    pub leader: Option<u64>,
    pub joint: bool,
    pub members: BTreeMap<u64, MemberStatus>,
    pub retired: BTreeSet<u64>,
    pub reconciliation_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Desired {
    pub(crate) generation: u64,
    pub(crate) peers: BTreeMap<u64, SocketAddr>,
}

pub(crate) fn validate_peers(peers: &BTreeMap<u64, SocketAddr>) -> Result<(), ClusterError> {
    if peers.is_empty() || peers.contains_key(&0) {
        return Err(ClusterError::InvalidConfig(
            "membership must contain positive node IDs".into(),
        ));
    }
    if peers
        .values()
        .any(|addr| addr.port() == 0 || addr.ip().is_unspecified())
        || peers.values().collect::<BTreeSet<_>>().len() != peers.len()
    {
        return Err(ClusterError::InvalidConfig(
            "peer addresses must be distinct and routable".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_change(
    status: &MembershipStatus,
    desired: &Desired,
) -> Result<(), ClusterError> {
    validate_peers(&desired.peers)?;
    for (&id, address) in &desired.peers {
        if status.retired.contains(&id) {
            return Err(ClusterError::Removed(id));
        }
        if status
            .members
            .get(&id)
            .is_some_and(|member| member.address != *address)
        {
            return Err(ClusterError::Membership(format!(
                "node {id} has a different committed address; use a new ID"
            )));
        }
        if status
            .members
            .iter()
            .any(|(&other, member)| other != id && member.address == *address)
        {
            return Err(ClusterError::Membership(format!(
                "address {address} is still in use; remove its current member and stop it before reusing the address"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Serving {
    Waiting,
    Active,
    Removed,
}

/// Controls membership independently of the application's StateMachine type.
#[derive(Clone)]
pub struct MembershipControl {
    pub(crate) node_id: u64,
    pub(crate) status: watch::Receiver<MembershipStatus>,
    pub(crate) requested: watch::Sender<Option<Desired>>,
    pub(crate) serving: watch::Receiver<Serving>,
    pub(crate) safe_until: watch::Receiver<Option<Instant>>,
    pub(crate) stop: watch::Receiver<bool>,
    pub(crate) restart: Option<watch::Receiver<bool>>,
    pub(crate) leader: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
    pub(crate) dynamic: bool,
}

impl MembershipControl {
    /// Stage a desired configuration on this node. Only a leader proposes it;
    /// once committed, all later leaders continue it. Configure the same, higher
    /// generation on all surviving nodes and observe convergence via `status`.
    pub fn configure(
        &self,
        generation: u64,
        peers: BTreeMap<u64, SocketAddr>,
    ) -> Result<(), ClusterError> {
        if *self.serving.borrow() == Serving::Removed {
            return Err(ClusterError::Removed(self.node_id));
        }
        if *self.stop.borrow() {
            return Err(ClusterError::Shutdown);
        }
        if !self.dynamic || generation == 0 {
            return Err(ClusterError::Membership(
                "dynamic membership requires state format 2 and a positive generation".into(),
            ));
        }
        let desired = Desired { generation, peers };
        {
            let status = self.status.borrow();
            if generation < status.generation {
                return Err(ClusterError::Membership(format!(
                    "generation {generation} is already obsolete"
                )));
            }
            if generation == status.generation && desired.peers != status.desired {
                return Err(ClusterError::Membership(format!(
                    "generation {generation} already has a different desired configuration"
                )));
            }
            validate_change(&status, &desired)?;
        }
        let mut refusal = None;
        self.requested.send_if_modified(|requested| {
            if let Some(previous) = requested {
                if generation < previous.generation
                    || (generation == previous.generation && *previous != desired)
                {
                    refusal = Some(ClusterError::Membership(format!(
                        "generation {generation} conflicts with queued generation {}",
                        previous.generation
                    )));
                    return false;
                }
                if *previous == desired {
                    return false;
                }
            }
            *requested = Some(desired);
            true
        });
        if let Some(error) = refusal {
            return Err(error);
        }
        Ok(())
    }

    pub fn status(&self) -> MembershipStatus {
        let mut status = self.status.borrow().clone();
        status.leader = (self.leader)();
        if *self.serving.borrow() == Serving::Removed {
            // A peer may confirm retirement before the final membership entry
            // can reach this replica; do not present this node as an active voter.
            status.members.remove(&self.node_id);
            status.retired.insert(self.node_id);
        }
        status
    }

    /// Wait for this process to demonstrate quorum-backed membership. Learners
    /// and stale restarts never admit MQTT clients.
    pub async fn wait_serving(&self) -> Result<(), ClusterError> {
        let mut serving = self.serving.clone();
        let mut stop = self.stop.clone();
        tokio::select! {
            biased;
            state = serving.wait_for(|s| *s != Serving::Waiting) => match state.as_deref() {
                Ok(Serving::Active) => Ok(()),
                Ok(Serving::Removed) => Err(ClusterError::Removed(self.node_id)),
                _ => Err(ClusterError::Shutdown),
            },
            _ = stop.wait_for(|s| *s) => Err(ClusterError::Shutdown),
        }
    }

    pub fn is_serving(&self) -> bool {
        *self.serving.borrow() == Serving::Active
            && !*self.stop.borrow()
            && self
                .status
                .borrow()
                .members
                .get(&self.node_id)
                .is_some_and(|m| m.role == MemberRole::Voter)
    }

    /// Conservative local deadline for work that requires exclusive ownership.
    /// Unlike serving status, this expires even during an in-flight renewal.
    pub fn lease_valid_until(&self) -> Option<Instant> {
        let deadline = (*self.safe_until.borrow()).filter(|&until| until > Instant::now())?;
        self.is_serving().then_some(deadline)
    }

    /// Returns as soon as local quorum-backed lease validity cannot be proven.
    pub async fn wait_lease_invalid(&self) {
        let mut view = self.clone();
        loop {
            view.safe_until.mark_unchanged();
            view.serving.mark_unchanged();
            view.stop.mark_unchanged();
            view.status.mark_unchanged();
            let Some(deadline) = view.lease_valid_until() else {
                return;
            };
            let changed = tokio::select! {
                change = view.safe_until.changed() => change,
                change = view.serving.changed() => change,
                change = view.stop.changed() => change,
                change = view.status.changed() => change,
                _ = sleep_until(deadline) => continue,
            };
            if changed.is_err() {
                return;
            }
        }
    }

    /// Wait until automatic recovery needs the server to restart.
    pub async fn wait_restart(&self) {
        if let Some(mut restart) = self.restart.clone()
            && restart.wait_for(|restart| *restart).await.is_ok()
        {
            return;
        }
        std::future::pending::<()>().await;
    }

    /// Wait for durable local or remote confirmation that this ID was retired.
    pub async fn wait_removed(&self) {
        if self
            .serving
            .clone()
            .wait_for(|s| *s == Serving::Removed)
            .await
            .is_err()
        {
            std::future::pending::<()>().await;
        }
    }
}
