//! Deterministic metadata and persistent inbox commands. Transport and clocks
//! are outside the log; command inputs carry the observed time and ACL data.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use mqx_auth::{Access, AclFile};
use mqx_codec::{LastWill, PacketId, Publish, QoS, SubscribeReturnCode, v5::ReasonCode as R};
use mqx_topic::{SubscriptionIndex, validate_topic_filter};
use serde::{Deserialize, Serialize};

use crate::{
    BrokerConfig,
    inbox::{Ack, Delivery, Inbox, Message, Offer, Outbound, PublishProperty, Publisher, Receive},
    retained::Retained,
};

pub(crate) type Epoch = u64;
pub(crate) type ClaimToken = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Owner {
    pub(crate) node: u64,
    pub(crate) incarnation: [u8; 16],
}

impl Owner {
    pub(crate) const LOCAL: Self = Self {
        node: 0,
        incarnation: [0; 16],
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Lease {
    pub(crate) id: Arc<str>,
    pub(crate) epoch: Epoch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Command {
    SetAcl {
        security: u64,
        text: Option<Bytes>,
        initial: bool,
    },
    Boot {
        owner: Owner,
        previous: Option<[u8; 16]>,
        now: Duration,
    },
    Claim {
        owner: Owner,
        token: ClaimToken,
        request: Claim,
    },
    Act(Lease, Operation),
    Expire(Duration),
    Batch(Vec<BatchEntry>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum BatchEntry {
    Claim {
        owner: Owner,
        token: ClaimToken,
        request: Claim,
    },
    Act(Mutations),
}

impl BatchEntry {
    pub(crate) fn needs_fence(&self) -> bool {
        matches!(self, Self::Act(entry) if entry.operations.iter().any(Operation::needs_fence))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Mutations {
    pub(crate) lease: Lease,
    pub(crate) operations: Vec<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Claim {
    pub(crate) publisher: Publisher,
    pub(crate) clean_start: bool,
    pub(crate) bridge: bool,
    pub(crate) max_qos: QoS,
    pub(crate) will: Option<LastWill>,
    #[serde(default)]
    pub(crate) v5: Option<SessionSettings>,
    #[serde(default)]
    pub(crate) now: Duration,
}

impl Claim {
    pub(crate) fn local_inbox(&self) -> bool {
        self.clean_start && self.v5.as_ref().is_none_or(|v5| v5.session_expiry == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionSettings {
    pub(crate) session_expiry: u32,
    pub(crate) receive_maximum: Option<u16>,
    pub(crate) will_delay: u32,
    pub(crate) will_expiry: u32,
    pub(crate) will_properties: Vec<PublishProperty>,
}

impl SessionSettings {
    pub(crate) fn outgoing_maximum(&self, config: &BrokerConfig) -> u16 {
        self.receive_maximum
            .unwrap_or_else(|| config.max_inflight_messages.try_into().unwrap_or(u16::MAX))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubscriptionRequest {
    pub(crate) filter: String,
    pub(crate) qos: QoS,
    pub(crate) no_local: bool,
    pub(crate) retain_as_published: bool,
    pub(crate) retain_handling: u8,
    pub(crate) identifier: u32,
}

impl SubscriptionRequest {
    pub(crate) fn legacy((filter, qos): (String, QoS)) -> Self {
        Self {
            filter,
            qos,
            no_local: false,
            retain_as_published: false,
            retain_handling: 0,
            identifier: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Publication {
    pub(crate) packet: Publish,
    pub(crate) properties: Vec<PublishProperty>,
    pub(crate) expires: Option<Duration>,
    pub(crate) now: Duration,
}

impl Publication {
    pub(crate) fn legacy(packet: Publish, now: Duration) -> Self {
        Self {
            packet,
            properties: Vec::new(),
            expires: None,
            now,
        }
    }

    pub(crate) fn into_message(self, source: Publisher) -> Arc<Message> {
        Arc::new(Message {
            source,
            topic: self.packet.topic.into_boxed_str(),
            payload: self.packet.payload,
            qos: self.packet.qos,
            retain: self.packet.retain,
            properties: self.properties,
            expires: self.expires,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Operation {
    Disconnect {
        graceful: bool,
        now: Duration,
        #[serde(default)]
        expiry: Option<u32>,
    },
    Subscribe(Vec<SubscriptionRequest>, Duration),
    Unsubscribe(Vec<String>),
    Receive(Publication),
    Release(PacketId, Duration),
    Forward(Arc<Message>, Duration),
    Ack(PacketId, Ack),
    NextOutbound(Duration),
    /// Local transient incoming state cannot influence this particular QoS 1.
    ReceiveAdmitted(Publication),
}

impl Operation {
    pub(crate) fn needs_fence(&self) -> bool {
        matches!(self, Self::Subscribe(..) | Self::Unsubscribe(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Reply {
    NoChange,
    Stale,
    Full,
    InvalidAcl,
    ProtocolError,
    Claimed { lease: Lease, present: bool },
    Subscribed(Vec<SubscribeReturnCode>),
    ReceiveLocal(Option<Arc<Message>>, u8),
    LocalInbox,
    Outbound(Option<Outbound>),
    PublishReason(u8),
    Unsubscribed(Vec<u8>),
    Batched(Vec<Vec<Reply>>),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Effect {
    Attach {
        owner: Owner,
        token: ClaimToken,
        lease: Lease,
    },
    Deliver {
        owner: Epoch,
        packet: Delivery,
    },
    Ready(Epoch),
    Takeover(Epoch),
    Expired(Arc<str>),
    QueueFull(Arc<str>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) reply: Reply,
    pub(crate) effects: Vec<Effect>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct State {
    #[serde(skip)]
    config: Arc<BrokerConfig>,
    #[serde(skip)]
    acls: BTreeMap<u64, Arc<AclFile>>,
    acl_text: BTreeMap<u64, Option<Bytes>>,
    pub(crate) applied: u64,
    nodes: BTreeMap<u64, NodeIdentity>,
    last_epoch: Epoch,
    last_message: u64,
    sessions: BTreeMap<Arc<str>, Session>,
    #[serde(skip)]
    normal: SubscriptionIndex<Arc<str>, Subscription>,
    #[serde(skip)]
    shared: SubscriptionIndex<Arc<str>, SharedKey>,
    last_subscription: u64,
    groups: BTreeMap<SharedKey, SharedGroup>,
    retained: Retained,
    expirations: BTreeMap<(Duration, Epoch), Arc<str>>,
    #[serde(default)]
    wills: BTreeMap<(Duration, Epoch), Arc<str>>,
    #[serde(default)]
    dollar_roots: BTreeSet<Arc<str>>,
    #[serde(default)]
    retain_sweep: Option<Duration>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Session {
    publisher: Publisher,
    epoch: Epoch,
    owner: Option<Owner>,
    bridge: bool,
    max_qos: QoS,
    inbox: Option<Inbox>,
    filters: BTreeMap<Arc<str>, IndexedSubscription>,
    will: Option<LastWill>,
    expires: Option<Duration>,
    #[serde(default)]
    v5: Option<SessionSettings>,
    #[serde(default)]
    will_at: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Subscription {
    qos: QoS,
    bridge: bool,
    #[serde(default)]
    no_local: bool,
    #[serde(default)]
    retain_as_published: bool,
    #[serde(default)]
    identifier: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct SharedKey {
    name: Arc<str>,
    filter: Arc<str>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SharedGroup {
    order: u64,
    members: VecDeque<(Arc<str>, Subscription)>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct IndexedSubscription {
    order: u64,
    subscription: Subscription,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NodeIdentity {
    incarnation: Option<[u8; 16]>,
    down: bool,
}

impl State {
    pub(crate) fn new(config: Arc<BrokerConfig>) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub(crate) fn next_expiry(&self) -> Option<Duration> {
        [
            self.expirations
                .first_key_value()
                .map(|(&(time, _), _)| time),
            self.wills.first_key_value().map(|(&(time, _), _)| time),
            self.retain_sweep,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(crate) fn acl_text(&self, id: u64) -> Option<&Option<Bytes>> {
        self.acl_text.get(&id)
    }

    pub(crate) fn incarnation(&self, node: u64) -> Option<[u8; 16]> {
        self.nodes.get(&node).and_then(|node| node.incarnation)
    }

    pub(crate) fn install_local_acl(&mut self, id: u64, acl: Option<Arc<AclFile>>) {
        if let Some(acl) = acl {
            self.acls.insert(id, acl);
        } else {
            self.acls.remove(&id);
        }
    }

    pub(crate) fn owns(&self, owner: Owner, lease: &Lease) -> bool {
        self.sessions
            .get(&lease.id)
            .is_some_and(|session| session.owner == Some(owner) && session.epoch == lease.epoch)
    }
    pub(crate) fn publisher_only(&self, lease: &Lease) -> bool {
        self.sessions.get(&lease.id).is_some_and(|session| {
            session.epoch == lease.epoch
                && session.filters.is_empty()
                && session
                    .inbox
                    .as_ref()
                    .is_none_or(|inbox| !inbox.has_outbound(&self.config))
        })
    }

    pub(crate) fn owns_peer(&self, node: u64, id: &str, epoch: Epoch) -> bool {
        self.sessions.get(id).is_some_and(|session| {
            session.epoch == epoch && session.owner.is_some_and(|owner| owner.node == node)
        })
    }

    pub(crate) fn fast_route(
        &self,
        owner: Owner,
        lease: &Lease,
        publish: &Publish,
        admitted_local: bool,
    ) -> Option<crate::fast::Route> {
        if publish.retain || publish.qos == QoS::ExactlyOnce || !self.owns(owner, lease) {
            return None;
        }
        let source = &self.sessions[&lease.id];
        if publish.qos == QoS::AtLeastOnce
            && !admitted_local
            && source
                .inbox
                .as_ref()
                .is_none_or(|inbox| !inbox.simple_qos1())
        {
            return None;
        }
        if publish_rejection(&self.config, &self.acls, &source.publisher, publish).is_some() {
            return None;
        }
        // Rotating the selected leaf is cluster-wide shared subscription state.
        if !publish.topic.starts_with('$') {
            let mut shared = false;
            self.shared
                .for_each_match(&publish.topic, |_, _| shared = true)
                .ok()?;
            if shared {
                return None;
            }
        }
        let mut targets = Vec::new();
        let mut matched = false;
        let mut durable = false;
        self.normal
            .for_each_match(&publish.topic, |id, sub| {
                matched = true;
                if durable {
                    return;
                }
                let session = &self.sessions[id];
                if !can_deliver(&self.acls, session, *sub, &lease.id, &publish.topic, false) {
                    return;
                }
                if session.inbox.is_some() {
                    durable = true;
                } else if let Some(owner) = session.owner {
                    targets.push((
                        owner.node,
                        crate::fast::Target {
                            epoch: session.epoch,
                            qos: outgoing_qos(publish.qos, sub.qos, &self.config),
                            identifier: sub.identifier,
                        },
                    ));
                }
            })
            .ok()?;
        (!durable).then(|| crate::fast::Route {
            source: source.publisher.clone(),
            matched,
            targets,
        })
    }

    pub(crate) fn has_outbound(&self, lease: &Lease) -> bool {
        self.sessions
            .get(&lease.id)
            .filter(|s| s.owner.is_some() && s.epoch == lease.epoch)
            .and_then(|s| s.inbox.as_ref())
            .is_some_and(|inbox| inbox.has_outbound(&self.config))
    }

    pub(crate) fn snapshot(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).expect("broker state is serializable")
    }

    pub(crate) fn restore(&mut self, bytes: &[u8]) -> Result<(), mqx_cluster::ClusterError> {
        fn invalid(error: impl std::fmt::Display) -> mqx_cluster::ClusterError {
            mqx_cluster::ClusterError::Restore(error.to_string())
        }
        let mut restored: Self = rmp_serde::from_slice(bytes).map_err(invalid)?;
        restored.config = self.config.clone();
        for (&id, text) in &restored.acl_text {
            if let Some(text) = text {
                restored
                    .acls
                    .insert(id, Arc::new(AclFile::parse(text).map_err(invalid)?));
            }
        }
        // Sort by original insertion order, not by the current owner or
        // shared rotation. Replacements must not reorder matching leaves.
        let mut normal = Vec::new();
        for (id, session) in &restored.sessions {
            for (filter, entry) in &session.filters {
                let (group, path) = split_filter(filter)
                    .ok_or_else(|| invalid("invalid subscription in snapshot"))?;
                if group.is_none() {
                    normal.push((entry.order, path, id, entry.subscription));
                }
            }
        }
        normal.sort_unstable_by_key(|entry| entry.0);
        for (_, path, id, sub) in normal {
            restored
                .normal
                .insert(path, id.clone(), sub)
                .map_err(invalid)?;
        }
        let mut groups: Vec<_> = restored.groups.iter().collect();
        groups.sort_unstable_by_key(|(_, group)| group.order);
        for (key, _) in groups {
            restored
                .shared
                .insert(&key.filter, key.name.clone(), key.clone())
                .map_err(invalid)?;
        }
        *self = restored;
        Ok(())
    }

    pub(crate) fn apply(&mut self, command: Command) -> Outcome {
        let mut effects = Vec::new();
        let reply = match command {
            Command::SetAcl {
                security,
                text,
                initial,
            } => {
                if !initial || !self.acl_text.contains_key(&security) {
                    let parsed = match text.as_ref().map(|text| AclFile::parse(text)).transpose() {
                        Ok(acl) => acl.map(Arc::new),
                        Err(_) => {
                            return Outcome {
                                reply: Reply::InvalidAcl,
                                effects,
                            };
                        }
                    };
                    self.install_local_acl(security, parsed);
                    self.acl_text.insert(security, text);
                }
                Reply::NoChange
            }
            Command::Boot {
                owner,
                previous,
                now,
            } => {
                let node = self.nodes.entry(owner.node).or_default();
                if node.incarnation != Some(owner.incarnation) {
                    if node.incarnation != previous {
                        // A forwarded boot from the previous process may
                        // arrive after its successor has installed a fence.
                        return Outcome {
                            reply: Reply::Stale,
                            effects,
                        };
                    }
                    node.incarnation = Some(owner.incarnation);
                    node.down = false;
                    self.lose_node(owner.node, now, &mut effects);
                }
                Reply::NoChange
            }
            Command::Claim {
                owner,
                token,
                request,
            } => self.claim(owner, token, request, &mut effects),
            Command::Expire(now) => {
                self.expire(now, &mut effects);
                Reply::NoChange
            }
            Command::Act(lease, action) => self.act(lease, action, &mut effects),
            Command::Batch(batch) => Reply::Batched(
                batch
                    .into_iter()
                    .map(|entry| match entry {
                        BatchEntry::Claim {
                            owner,
                            token,
                            request,
                        } => vec![self.claim(owner, token, request, &mut effects)],
                        BatchEntry::Act(entry) => {
                            let mut replies = Vec::with_capacity(entry.operations.len());
                            for operation in entry.operations {
                                let reply = self.act(entry.lease.clone(), operation, &mut effects);
                                let stop = matches!(reply, Reply::Stale | Reply::ProtocolError);
                                replies.push(reply);
                                if stop {
                                    break;
                                }
                            }
                            replies
                        }
                    })
                    .collect(),
            ),
        };
        Outcome { reply, effects }
    }

    pub(crate) fn node_event(&mut self, event: mqx_cluster::NodeEvent) -> Vec<Effect> {
        let mut effects = Vec::new();
        self.applied = event.index;
        let node = self.nodes.entry(event.node_id).or_default();
        node.down = event.status == mqx_cluster::NodeStatus::Down;
        if node.down {
            self.lose_node(event.node_id, event.occurred_at, &mut effects);
        }
        effects
    }

    fn lose_node(&mut self, node: u64, now: Duration, effects: &mut Vec<Effect>) {
        // The failed node's sockets are all gone before any will is routed.
        // Persistent subscribers on it get offline queue limits, not an
        // in-flight allowance merely because their disconnect sorts later.
        let mut lost = Vec::new();
        for (id, session) in &mut self.sessions {
            if session.owner.is_some_and(|owner| owner.node == node) {
                session.owner = None;
                effects.push(Effect::Takeover(session.epoch));
                lost.push(id.clone());
            }
        }
        for id in lost {
            self.offline(id, now, false, effects);
        }
    }

    fn expire(&mut self, now: Duration, effects: &mut Vec<Effect>) {
        // will_delay.c: will_delay__check publishes even when the session
        // itself does not expire. Session expiry cancels a later Will timer.
        while let Some((&(at, _), id)) = self.expirations.first_key_value() {
            if at > now {
                break;
            }
            let id = id.clone();
            let will = self.take_will(&id);
            self.remove_session(&id);
            if let Some(will) = will {
                self.publish_will(will, now, effects);
            }
            effects.push(Effect::Expired(id));
        }
        while let Some((&(at, _), id)) = self.wills.first_key_value() {
            if at > now {
                break;
            }
            let id = id.clone();
            if let Some(will) = self.take_will(&id) {
                self.publish_will(will, now, effects);
            }
        }
        if self.retain_sweep.is_some_and(|at| at <= now) {
            let pending = self.retained.expire(now);
            self.retain_sweep = self
                .config
                .retain_expiry_interval
                .filter(|_| pending)
                .map(|interval| now.saturating_add(interval));
        }
    }

    fn take_will(&mut self, id: &Arc<str>) -> Option<PendingWill> {
        let session = self.sessions.get_mut(id).unwrap();
        if let Some(at) = session.will_at.take() {
            self.wills.remove(&(at, session.epoch));
        }
        session.will.take().map(|packet| {
            let (properties, expiry) = session.v5.as_mut().map_or((Vec::new(), 0), |v5| {
                (std::mem::take(&mut v5.will_properties), v5.will_expiry)
            });
            PendingWill {
                source: session.publisher.clone(),
                packet,
                properties,
                expiry,
            }
        })
    }

    fn offline(&mut self, id: Arc<str>, now: Duration, graceful: bool, effects: &mut Vec<Effect>) {
        let session = self.sessions.get_mut(&id).unwrap();
        let expiry = session.v5.as_ref().map(|v5| v5.session_expiry);
        let persistent = expiry.map_or(session.inbox.is_some(), |interval| interval != 0);
        let delay = session.v5.as_ref().map_or(0, |v5| v5.will_delay);
        // context.c: context__send_will delays only if both intervals are nonzero.
        if !graceful && persistent && delay != 0 && session.will.is_some() {
            let at = Duration::from_secs(now.as_secs())
                .saturating_add(Duration::from_secs(u64::from(delay)));
            session.will_at = Some(at);
            self.wills.insert((at, session.epoch), id.clone());
        } else if let Some(will) = self.take_will(&id).filter(|_| !graceful) {
            self.publish_will(will, now, effects);
        }
        if !persistent {
            self.remove_session(&id);
            return;
        }
        let session = self.sessions.get_mut(&id).unwrap();
        session.owner = None;
        session.inbox.as_mut().unwrap().reset_outbound();
        // session_expiry.c: session_expiry__add applies the nonzero server cap;
        // session_expiry__check expires at the first second strictly past it.
        let cap = self
            .config
            .persistent_client_expiration
            .filter(|ttl| !ttl.is_zero())
            .map(|ttl| ttl.min(Duration::from_secs(u64::from(u32::MAX))));
        let requested = expiry
            .filter(|&ttl| ttl != u32::MAX)
            .map(|ttl| Duration::from_secs(u64::from(ttl)));
        if let Some(ttl) = [requested, cap].into_iter().flatten().min() {
            let at = if expiry.is_some() {
                Duration::from_secs(now.as_secs())
                    .saturating_add(ttl)
                    .saturating_add(Duration::from_secs(1))
            } else {
                now.saturating_add(ttl)
            };
            session.expires = Some(at);
            self.expirations.insert((at, session.epoch), id);
        }
    }

    // handle_connect.c: connect__on_authorised transfers the old session only
    // on Clean Start=false and when its expiry interval allows persistence.
    fn claim(
        &mut self,
        owner: Owner,
        token: ClaimToken,
        claim: Claim,
        effects: &mut Vec<Effect>,
    ) -> Reply {
        if owner != Owner::LOCAL
            && !self
                .nodes
                .get(&owner.node)
                .is_some_and(|node| !node.down && node.incarnation == Some(owner.incarnation))
        {
            return Reply::Stale;
        }
        let id = claim.publisher.id.clone();
        if !self.sessions.contains_key(&id)
            && self.config.global_max_clients != 0
            && self.sessions.len() >= self.config.global_max_clients
        {
            return Reply::Full;
        }
        let mut present = false;
        if let Some(previous) = self.sessions.get(&id) {
            let expired = previous.expires.is_some_and(|at| at <= claim.now);
            let due_will = previous.will_at.is_some_and(|at| at <= claim.now);
            let persistent = previous
                .v5
                .as_ref()
                .map_or(previous.inbox.is_some(), |v5| v5.session_expiry != 0);
            let active = previous.owner.is_some();
            if active {
                effects.push(Effect::Takeover(previous.epoch));
            }
            present = !claim.clean_start && persistent && !expired;
            let will = self.take_will(&id);
            if !present {
                self.remove_session(&id);
            } else if let Some(previous) = self.sessions.get_mut(&id)
                && let Some(at) = previous.expires.take()
            {
                self.expirations.remove(&(at, previous.epoch));
            }
            if let Some(will) = will.filter(|_| !present || due_will) {
                self.publish_will(will, claim.now, effects);
            }
            if expired {
                effects.push(Effect::Expired(id.clone()));
            }
        }
        self.last_epoch += 1;
        let epoch = self.last_epoch;
        let session = self.sessions.entry(id.clone()).or_insert_with(|| Session {
            publisher: claim.publisher.clone(),
            epoch,
            owner: Some(owner),
            bridge: claim.bridge,
            max_qos: claim.max_qos,
            inbox: (!claim.local_inbox()).then(Inbox::default),
            filters: BTreeMap::new(),
            will: None,
            expires: None,
            v5: None,
            will_at: None,
        });
        session.publisher = claim.publisher;
        session.epoch = epoch;
        session.owner = Some(owner);
        session.will = claim.will;
        session.v5 = claim.v5;
        session.bridge = claim.bridge;
        session.max_qos = claim.max_qos;
        if let Some(inbox) = &mut session.inbox {
            inbox.receive_maximum = session
                .v5
                .as_ref()
                .map(|v5| v5.outgoing_maximum(&self.config));
        }
        if present {
            let publisher = &session.publisher;
            session.inbox.as_mut().unwrap().resume(
                |topic, writing| {
                    allowed(
                        &self.acls,
                        publisher,
                        topic,
                        if writing { Access::Write } else { Access::Read },
                    )
                },
                &self.config,
                claim.now,
            );
        }
        let lease = Lease { id, epoch };
        if owner != Owner::LOCAL {
            effects.push(Effect::Attach {
                owner,
                token,
                lease: lease.clone(),
            });
        }
        Reply::Claimed { lease, present }
    }

    fn act(&mut self, lease: Lease, operation: Operation, effects: &mut Vec<Effect>) -> Reply {
        let Some(session) = self
            .sessions
            .get_mut(&lease.id)
            .filter(|s| s.owner.is_some() && s.epoch == lease.epoch)
        else {
            return Reply::Stale;
        };
        let admitted_local = matches!(&operation, Operation::ReceiveAdmitted(_));
        match operation {
            Operation::Disconnect {
                graceful,
                now,
                expiry,
            } => {
                if let Some((v5, expiry)) = session.v5.as_mut().zip(expiry) {
                    v5.session_expiry = expiry;
                }
                self.offline(lease.id, now, graceful, effects);
                Reply::NoChange
            }
            Operation::Subscribe(filters, now) => self.subscribe(&lease.id, filters, now, effects),
            Operation::Unsubscribe(filters) => {
                let mut reason = R::SUCCESS;
                let mut reasons = if session.v5.is_some() {
                    Vec::with_capacity(filters.len())
                } else {
                    Vec::new()
                };
                for filter in filters {
                    let acl_allowed =
                        allowed(&self.acls, &session.publisher, &filter, Access::Unsubscribe);
                    let Some((group, path)) = split_filter(&filter) else {
                        return Reply::ProtocolError;
                    };
                    // subs.c: sub__remove leaves the previous reason alone if
                    // the top-level hierarchy itself was never created.
                    if !acl_allowed {
                        reason = R::NOT_AUTHORIZED;
                    } else if group.is_some()
                        || !path.starts_with('$')
                        || dollar_root(path) == "$SYS"
                        || self.dollar_roots.contains(dollar_root(path))
                    {
                        reason = R::NO_SUBSCRIPTION_EXISTED;
                    }
                    if acl_allowed && session.filters.remove(filter.as_str()).is_some() {
                        reason = R::SUCCESS;
                        remove_filter(
                            &mut self.normal,
                            &mut self.shared,
                            &mut self.groups,
                            &lease.id,
                            &filter,
                        );
                    }
                    if session.v5.is_some() {
                        reasons.push(reason.0);
                    }
                }
                Reply::Unsubscribed(reasons)
            }
            Operation::Receive(publication) | Operation::ReceiveAdmitted(publication) => {
                let publish = &publication.packet;
                let rejection =
                    publish_rejection(&self.config, &self.acls, &session.publisher, publish);
                let qos = publish.qos;
                let id = publish.packet_id;
                if let Some(reason) = rejection {
                    if qos == QoS::AtLeastOnce || (qos == QoS::ExactlyOnce && session.v5.is_some())
                    {
                        if let Some(inbox) = &mut session.inbox {
                            inbox.credit_incoming();
                        } else if !admitted_local {
                            return Reply::ReceiveLocal(None, reason.0);
                        }
                    }
                    return Reply::PublishReason(reason.0);
                }
                let now = publication.now;
                let message = publication.into_message(session.publisher.clone());
                if let Some(id) = id.filter(|_| !admitted_local) {
                    let Some(inbox) = &mut session.inbox else {
                        return Reply::ReceiveLocal(Some(message), R::SUCCESS.0);
                    };
                    if qos == QoS::ExactlyOnce {
                        return match inbox.receive(id, message, &self.config) {
                            Receive::Accepted => Reply::NoChange,
                            Receive::Quota => {
                                if session.v5.is_some() {
                                    inbox.credit_incoming();
                                }
                                Reply::PublishReason(R::QUOTA_EXCEEDED.0)
                            }
                            Receive::Duplicate => Reply::ProtocolError,
                        };
                    }
                    if !inbox.can_publish_qos1(id, &self.config) {
                        return Reply::PublishReason(R::QUOTA_EXCEEDED.0);
                    }
                }
                let matched = self.publish(message, now, effects);
                Reply::PublishReason(if matched {
                    R::SUCCESS.0
                } else {
                    R::NO_MATCHING_SUBSCRIBERS.0
                })
            }
            Operation::Release(id, now) => {
                let Some(inbox) = &mut session.inbox else {
                    return Reply::LocalInbox;
                };
                if let Some(message) = inbox.release(id) {
                    self.publish(message, now, effects);
                }
                Reply::NoChange
            }
            Operation::Forward(message, now) => {
                Reply::PublishReason(if self.publish(message, now, effects) {
                    R::SUCCESS.0
                } else {
                    R::NO_MATCHING_SUBSCRIBERS.0
                })
            }
            Operation::Ack(id, ack) => {
                let Some(inbox) = &mut session.inbox else {
                    return Reply::LocalInbox;
                };
                if inbox.ack(id, ack, &self.config) {
                    if inbox.has_outbound(&self.config) {
                        effects.push(Effect::Ready(session.epoch));
                    }
                    Reply::NoChange
                } else {
                    Reply::ProtocolError
                }
            }
            Operation::NextOutbound(now) => {
                let Some(inbox) = &mut session.inbox else {
                    return Reply::LocalInbox;
                };
                Reply::Outbound(inbox.next_outbound(&self.config, now))
            }
        }
    }

    fn remove_session(&mut self, id: &Arc<str>) {
        let session = self.sessions.remove(id).unwrap();
        if let Some(at) = session.expires {
            self.expirations.remove(&(at, session.epoch));
        }
        if let Some(at) = session.will_at {
            self.wills.remove(&(at, session.epoch));
        }
        for filter in session.filters.keys() {
            remove_filter(
                &mut self.normal,
                &mut self.shared,
                &mut self.groups,
                id,
                filter,
            );
        }
    }

    fn subscribe(
        &mut self,
        id: &Arc<str>,
        filters: Vec<SubscriptionRequest>,
        now: Duration,
        effects: &mut Vec<Effect>,
    ) -> Reply {
        let session = self.sessions.get_mut(id).unwrap();
        let mut codes = Vec::with_capacity(filters.len());
        for request in filters {
            let SubscriptionRequest {
                filter,
                qos,
                no_local,
                retain_as_published,
                retain_handling,
                identifier,
            } = request;
            let Some((group, path)) = split_filter(&filter) else {
                return Reply::ProtocolError;
            };
            if validate_topic_filter(path).is_err() {
                return Reply::ProtocolError;
            }
            if !allowed(&self.acls, &session.publisher, &filter, Access::Subscribe) {
                codes.push(SubscribeReturnCode::Failure);
                continue;
            }
            let subscription = Subscription {
                qos,
                bridge: session.bridge,
                no_local,
                retain_as_published,
                identifier,
            };
            if let Some(group) = group {
                // src/topic_tok.c: sub__topic_tokenise always puts shared
                // filters under the ordinary root, even for a '$' filter.
                let key = SharedKey {
                    name: group.into(),
                    filter: path.into(),
                };
                let members = &mut self
                    .groups
                    .entry(key.clone())
                    .or_insert_with(|| {
                        self.shared.insert(path, key.name.clone(), key).unwrap();
                        self.last_subscription += 1;
                        SharedGroup {
                            order: self.last_subscription,
                            members: VecDeque::new(),
                        }
                    })
                    .members;
                if let Some((_, previous)) = members.iter_mut().find(|(member, _)| member == id) {
                    *previous = subscription;
                } else {
                    members.push_back((id.clone(), subscription));
                }
            } else {
                if path.starts_with('$') {
                    let root = dollar_root(path);
                    if root != "$SYS" && !self.dollar_roots.contains(root) {
                        self.dollar_roots.insert(Arc::from(root));
                    }
                }
                self.normal.insert(path, id.clone(), subscription).unwrap();
                // retain.c: retain__queue skips shared filters; retained replay
                // does not use the No Local / Retain As Published delivery path.
                if retain_handling == 0
                    || retain_handling == 1 && !session.filters.contains_key(filter.as_str())
                {
                    self.retained.visit(path, now, |message| {
                        if allowed(&self.acls, &session.publisher, &message.topic, Access::Read)
                            && (!self.config.check_retain_source
                                || allowed(
                                    &self.acls,
                                    &message.source,
                                    &message.topic,
                                    Access::Write,
                                ))
                        {
                            let qos = outgoing_qos(message.qos, qos, &self.config);
                            deliver(
                                session,
                                Delivery {
                                    message: message.clone(),
                                    qos,
                                    retain: true,
                                    dedup_id: None,
                                    subscription_identifier: identifier,
                                },
                                &self.config,
                                effects,
                            );
                        }
                    });
                }
            }
            if let Some(entry) = session.filters.get_mut(filter.as_str()) {
                entry.subscription = subscription;
            } else {
                self.last_subscription += 1;
                session.filters.insert(
                    Arc::from(filter),
                    IndexedSubscription {
                        order: self.last_subscription,
                        subscription,
                    },
                );
            }
            codes.push(SubscribeReturnCode::Success(qos));
        }
        Reply::Subscribed(codes)
    }

    // context.c: context__send_will checks ACL write at publication time.
    fn publish_will(&mut self, will: PendingWill, now: Duration, effects: &mut Vec<Effect>) {
        let PendingWill {
            source,
            packet: will,
            properties,
            expiry,
        } = will;
        if allowed(&self.acls, &source, &will.topic, Access::Write) {
            self.publish(
                Arc::new(Message {
                    source,
                    topic: will.topic.into_boxed_str(),
                    payload: will.payload,
                    qos: will.qos,
                    retain: will.retain,
                    properties,
                    expires: Message::expiry(Duration::from_secs(now.as_secs()), expiry),
                }),
                now,
                effects,
            );
        }
    }

    fn publish(&mut self, message: Arc<Message>, now: Duration, effects: &mut Vec<Effect>) -> bool {
        let topic = &message.topic;
        self.last_message += 1;
        let mut router = Router {
            sessions: &mut self.sessions,
            config: &self.config,
            acls: &self.acls,
            message: &message,
            id: self.last_message,
            matched: false,
            effects,
        };
        // subs.c: sub__messages_queue searches the normal tree before shared.
        let _ = self
            .normal
            .for_each_match(topic, |id, sub| router.route(id, *sub, false));
        if !topic.starts_with('$') {
            let _ = self.shared.for_each_match(topic, |_, key| {
                let members = &mut self.groups.get_mut(key).unwrap().members;
                // subs.c: subs__shared_process rotates even for an offline
                // subscriber or one denied by ACL; it never tries a fallback.
                let (id, sub) = members.front().unwrap();
                router.route(id, *sub, true);
                members.rotate_left(1);
            });
        }
        let matched = router.matched;
        if message.retain {
            if message.expires.is_some()
                && !message.payload.is_empty()
                && self.retain_sweep.is_none()
                && let Some(interval) = self.config.retain_expiry_interval
            {
                self.retain_sweep = Some(now.saturating_add(interval));
            }
            self.retained.store(topic, message.clone());
        }
        matched
    }
}

struct PendingWill {
    source: Publisher,
    packet: LastWill,
    properties: Vec<PublishProperty>,
    expiry: u32,
}

fn dollar_root(filter: &str) -> &str {
    filter.split('/').next().unwrap()
}

struct Router<'a> {
    sessions: &'a mut BTreeMap<Arc<str>, Session>,
    config: &'a BrokerConfig,
    acls: &'a BTreeMap<u64, Arc<AclFile>>,
    message: &'a Arc<Message>,
    id: u64,
    matched: bool,
    effects: &'a mut Vec<Effect>,
}

impl Router<'_> {
    fn route(&mut self, id: &Arc<str>, sub: Subscription, shared: bool) {
        self.matched = true;
        let session = self.sessions.get_mut(id).unwrap();
        let message = self.message;
        if !can_deliver(
            self.acls,
            session,
            sub,
            &message.source.id,
            &message.topic,
            shared,
        ) {
            return;
        }
        let retain = (sub.bridge || sub.retain_as_published) && message.retain;
        let qos = outgoing_qos(message.qos, sub.qos, self.config);
        let delivery = Delivery {
            message: message.clone(),
            qos,
            retain,
            dedup_id: (!retain && !self.config.allow_duplicate_messages)
                .then_some(crate::inbox::DedupId::Log(self.id)),
            subscription_identifier: sub.identifier,
        };
        deliver(session, delivery, self.config, self.effects);
    }
}

fn deliver(
    session: &mut Session,
    packet: Delivery,
    config: &BrokerConfig,
    effects: &mut Vec<Effect>,
) {
    if let Some(inbox) = &mut session.inbox {
        match inbox.offer(packet, session.owner.is_some(), session.max_qos, config) {
            Offer::Ready => effects.push(Effect::Ready(session.epoch)),
            Offer::FirstDrop => effects.push(Effect::QueueFull(session.publisher.id.clone())),
            Offer::Queued | Offer::Dropped | Offer::Suppressed => {}
        }
    } else {
        effects.push(Effect::Deliver {
            owner: session.epoch,
            packet,
        });
    }
}

fn can_deliver(
    acls: &BTreeMap<u64, Arc<AclFile>>,
    session: &Session,
    sub: Subscription,
    source: &str,
    topic: &str,
    shared: bool,
) -> bool {
    (shared || !(sub.bridge || sub.no_local) || session.publisher.id.as_ref() != source)
        && allowed(acls, &session.publisher, topic, Access::Read)
}

fn publish_rejection(
    config: &BrokerConfig,
    acls: &BTreeMap<u64, Arc<AclFile>>,
    source: &Publisher,
    publish: &Publish,
) -> Option<R> {
    // handle_publish.c: handle__publish checks size before write ACL.
    if config.message_size_limit != 0 && publish.payload.len() > config.message_size_limit {
        Some(R::PACKET_TOO_LARGE)
    } else if !allowed(acls, source, &publish.topic, Access::Write) {
        Some(R::NOT_AUTHORIZED)
    } else if publish.topic.starts_with("$CONTROL/") {
        Some(R::IMPLEMENTATION_SPECIFIC_ERROR)
    } else {
        None
    }
}

fn allowed(
    acls: &BTreeMap<u64, Arc<AclFile>>,
    publisher: &Publisher,
    topic: &str,
    access: Access,
) -> bool {
    // plugin_acl_check.c: acl__check_dollar runs before the file ACL. Only
    // bridge status writes are potentially permitted under `$SYS`.
    if (topic.starts_with("$share") && matches!(access, Access::Read | Access::Write))
        || (topic.starts_with("$SYS")
            && access == Access::Write
            && !mqx_topic::matches("$SYS/broker/connection/+/state", topic).unwrap_or(false))
    {
        return false;
    }
    acls.get(&publisher.security)
        .is_none_or(|acl| acl.check(&publisher.id, publisher.username.as_deref(), topic, access))
}

fn outgoing_qos(publish: QoS, subscribe: QoS, config: &BrokerConfig) -> QoS {
    if config.upgrade_outgoing_qos || publish as u8 > subscribe as u8 {
        subscribe
    } else {
        publish
    }
}

fn remove_filter(
    normal: &mut SubscriptionIndex<Arc<str>, Subscription>,
    shared: &mut SubscriptionIndex<Arc<str>, SharedKey>,
    groups: &mut BTreeMap<SharedKey, SharedGroup>,
    id: &Arc<str>,
    filter: &str,
) {
    let (group, path) = split_filter(filter).unwrap();
    if let Some(group) = group {
        let key = SharedKey {
            name: group.into(),
            filter: path.into(),
        };
        let members = &mut groups.get_mut(&key).unwrap().members;
        let index = members.iter().position(|(member, _)| member == id).unwrap();
        members.remove(index);
        if members.is_empty() {
            shared.remove(path, &key.name);
            groups.remove(&key);
        }
    } else {
        normal.remove(path, id);
    }
}

// src/topic_tok.c: sub__topic_tokenise. Its group-name wildcard check only
// applies to subscription, not publish, tokenization.
fn split_filter(filter: &str) -> Option<(Option<&str>, &str)> {
    if filter == "$share" {
        return None;
    }
    let Some(rest) = filter.strip_prefix("$share/") else {
        return Some((None, filter));
    };
    let (group, path) = rest.split_once('/')?;
    (!path.is_empty() && !group.contains(['+', '#'])).then_some((Some(group), path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;

    fn claim(id: Arc<str>, transient: bool) -> Command {
        make_claim(Owner::LOCAL, [0; 16], id, transient, None)
    }

    fn make_claim(
        owner: Owner,
        token: ClaimToken,
        id: Arc<str>,
        transient: bool,
        will: Option<LastWill>,
    ) -> Command {
        Command::Claim {
            owner,
            token,
            request: Claim {
                publisher: Publisher {
                    id,
                    username: None,
                    security: 1,
                },
                clean_start: transient,
                bridge: false,
                max_qos: QoS::ExactlyOnce,
                will,
                v5: None,
                now: Duration::ZERO,
            },
        }
    }

    #[test]
    fn replay_preserves_epochs_qos2_retention_and_inbox_state() {
        let acl = Bytes::from_static(b"topic readwrite topic/#\n");
        let config = Arc::new(BrokerConfig {
            persistent_client_expiration: Some(Duration::from_secs(20)),
            ..BrokerConfig::default()
        });
        let mut left = State::new(config.clone());
        let mut right = State::new(config);
        let subscriber = Lease {
            id: Arc::from("subscriber"),
            epoch: 1,
        };
        let publisher = Lease {
            id: Arc::from("publisher"),
            epoch: 2,
        };
        let new_owner = Lease {
            id: subscriber.id.clone(),
            epoch: 3,
        };
        let qos2 = Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: true,
            topic: "topic".into(),
            packet_id: PacketId::new(26),
            payload: Bytes::from_static(b"payload"),
        };
        let commands = [
            claim(subscriber.id.clone(), false),
            Command::Act(
                subscriber.clone(),
                Operation::Subscribe(
                    vec![SubscriptionRequest::legacy((
                        "topic/#".into(),
                        QoS::AtLeastOnce,
                    ))],
                    Duration::ZERO,
                ),
            ),
            Command::Act(
                subscriber.clone(),
                Operation::Disconnect {
                    graceful: true,
                    now: Duration::from_secs(1),
                    expiry: None,
                },
            ),
            claim(publisher.id.clone(), false),
            Command::SetAcl {
                security: 1,
                text: Some(acl),
                initial: true,
            },
            Command::Act(
                publisher.clone(),
                Operation::Receive(Publication::legacy(qos2, Duration::ZERO)),
            ),
            Command::Act(
                publisher,
                Operation::Release(PacketId::new(26).unwrap(), Duration::ZERO),
            ),
            Command::Expire(Duration::from_secs(5)),
            claim(subscriber.id.clone(), false),
            Command::Act(subscriber, Operation::Unsubscribe(vec!["topic/#".into()])),
            Command::Act(new_owner.clone(), Operation::NextOutbound(Duration::ZERO)),
            Command::Act(
                new_owner.clone(),
                Operation::Ack(PacketId::new(1).unwrap(), Ack::Acknowledged),
            ),
            Command::Act(
                new_owner,
                Operation::Disconnect {
                    graceful: true,
                    now: Duration::from_secs(10),
                    expiry: None,
                },
            ),
            Command::Expire(Duration::from_secs(40)),
        ];
        for (index, command) in commands.into_iter().enumerate() {
            let outcome = left.apply(command.clone());
            assert_eq!(outcome, right.apply(command));
            if index == 9 {
                assert_eq!(outcome.reply, Reply::Stale);
            }
            if index == 10 {
                assert!(
                    matches!(outcome.reply, Reply::Outbound(Some(Outbound::Publish { id: Some(id), dup: false, .. })) if id.get() == 1)
                );
            }
        }
        assert_eq!(left.snapshot(), right.snapshot());
        assert_eq!(left.sessions.len(), 1);
    }

    #[test]
    fn node_loss_uses_committed_time_and_a_late_boot_cannot_fence_the_successor() {
        let mut state = State::new(Arc::new(BrokerConfig {
            persistent_client_expiration: Some(Duration::from_secs(10)),
            ..BrokerConfig::default()
        }));
        let first = Owner {
            node: 1,
            incarnation: [1; 16],
        };
        let successor = Owner {
            node: 1,
            incarnation: [2; 16],
        };
        let original_boot = Command::Boot {
            owner: first,
            previous: None,
            now: Duration::ZERO,
        };
        state.apply(original_boot.clone());
        let id: Arc<str> = Arc::from("offline");
        state.apply(make_claim(first, [3; 16], id.clone(), false, None));
        state.node_event(mqx_cluster::NodeEvent {
            index: 5,
            node_id: 1,
            status: mqx_cluster::NodeStatus::Down,
            occurred_at: Duration::from_secs(50),
        });
        assert_eq!(state.next_expiry(), Some(Duration::from_secs(60)));
        state.apply(Command::Boot {
            owner: successor,
            previous: Some(first.incarnation),
            now: Duration::from_secs(51),
        });
        let Reply::Claimed { lease, .. } = state
            .apply(make_claim(
                successor,
                [4; 16],
                Arc::from("new"),
                false,
                None,
            ))
            .reply
        else {
            panic!("successor must be able to claim sessions");
        };
        assert_eq!(state.apply(original_boot).reply, Reply::Stale);
        assert!(state.owns(successor, &lease));
        state.apply(Command::Expire(Duration::from_secs(59)));
        assert!(state.sessions.contains_key(&id));
        state.apply(Command::Expire(Duration::from_secs(60)));
        assert!(!state.sessions.contains_key(&id));
    }

    proptest! {
        #[test]
        fn randomized_serialized_replay_matches_snapshot_restore(
            operations in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>()), 20..120),
            cut in any::<usize>()
        ) {
            let config = Arc::new(BrokerConfig {
                max_inflight_messages: 2,
                max_queued_messages: 4,
                persistent_client_expiration: Some(Duration::from_secs(10)),
                retain_expiry_interval: Some(Duration::from_secs(8)),
                ..BrokerConfig::default()
            });
            let mut a = State::new(config.clone());
            let mut b = State::new(config.clone());
            let mut restored = State::new(config);
            let cut = cut % operations.len();
            let owners = [Owner { node: 1, incarnation: [1;16] }, Owner { node: 2, incarnation: [2;16] }];
            let clients: Vec<Arc<str>> = ["c", "a", "b", "x"].into_iter().map(Arc::from).collect();
            for owner in owners {
                let boot = Command::Boot { owner, previous: None, now: Duration::ZERO };
                a.apply(boot.clone());
                b.apply(boot.clone());
                restored.apply(boot);
            }
            for (index, (client, op, value)) in operations.into_iter().enumerate() {
                let now = Duration::from_secs(index as u64);
                let id = &clients[usize::from(client) % clients.len()];
                let owner = owners[usize::from(value) % owners.len()];
                let epoch = a.sessions.get(id).map_or(0, |session| session.epoch);
                let lease = Lease { id: id.clone(), epoch };
                let qos = [QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce][usize::from(value) % 3];
                let filter = ["a/#", "#", "$share/work/#", "$share/other/#"][usize::from(value) % 4];
                let topic = ["a", "a/b", "c"][usize::from(value) % 3];
                let mid = PacketId::new(u16::from(value % 4) + 1).unwrap();
                let command = match op % 11 {
                    0 | 1 => {
                        let mut claim = make_claim(owner, [index as u8;16], id.clone(), value % 3 == 0, Some(LastWill {
                            topic: "a/will".into(), payload: Bytes::from_static(b"gone"), qos, retain: value % 2 == 0,
                        }));
                        let Command::Claim { request, .. } = &mut claim else { unreachable!() };
                        request.now = now;
                        if op % 11 == 1 {
                            request.v5 = Some(SessionSettings {
                                session_expiry: u32::from(value % 6),
                                receive_maximum: Some(u16::from(value % 5) + 1),
                                will_delay: u32::from(value % 10),
                                will_expiry: u32::from(value % 5),
                                will_properties: vec![PublishProperty::ContentType("a/type".into())],
                            });
                        }
                        claim
                    }
                    2 => Command::Act(lease, Operation::Subscribe(vec![SubscriptionRequest {
                        no_local: !filter.starts_with("$share/") && value % 3 == 0,
                        retain_as_published: value % 3 == 1,
                        retain_handling: value % 3,
                        identifier: u32::from(value % 8),
                        ..SubscriptionRequest::legacy((filter.into(), qos))
                    }], now)),
                    3 => Command::Act(lease, Operation::Unsubscribe(vec![filter.into()])),
                    4 => Command::Act(lease, Operation::Receive(Publication {
                        packet: Publish {
                            dup: value % 2 == 0, qos, retain: value % 5 == 0, topic: topic.into(),
                            packet_id: (qos != QoS::AtMostOnce).then_some(mid), payload: Bytes::from(vec![value]),
                        },
                        properties: vec![PublishProperty::User("key".into(), "value".into())],
                        expires: Message::expiry(now, u32::from(value % 4)),
                        now,
                    })),
                    5 => Command::Act(lease, Operation::Release(mid, now)),
                    6 => Command::Act(lease, Operation::NextOutbound(now)),
                    7 => Command::Act(lease, Operation::Ack(mid, Ack::Acknowledged)),
                    8 => Command::Act(lease, Operation::Disconnect { graceful: value % 2 == 0, now, expiry: None }),
                    9 => Command::Expire(now),
                    _ => Command::SetAcl {
                        security: 1, initial: false,
                        text: Some(Bytes::from_static(if value % 2 == 0 { b"topic readwrite #\n" } else { b"topic readwrite a/#\n" })),
                    },
                };
                let encoded = rmp_serde::to_vec(&command).unwrap();
                let load = || rmp_serde::from_slice(&encoded).unwrap();
                let outcome = a.apply(load());
                prop_assert_eq!(&outcome, &b.apply(load()));
                prop_assert_eq!(&outcome, &restored.apply(load()));
                a.applied = index as u64;
                b.applied = index as u64;
                restored.applied = index as u64;
                if index == cut {
                    restored.restore(&a.snapshot()).unwrap();
                }
            }
            let final_bytes = a.snapshot();
            prop_assert_eq!(&final_bytes, &b.snapshot());
            prop_assert_eq!(&final_bytes, &restored.snapshot());
        }
    }
}
