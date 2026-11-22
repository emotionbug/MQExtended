//! Deterministic metadata and persistent inbox commands. Transport and clocks
//! are outside the log; command inputs carry the observed time and ACL data.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use mqx_auth::{Access, AclFile};
use mqx_codec::{LastWill, PacketId, Publish, QoS, SubscribeReturnCode};
use mqx_topic::{SubscriptionIndex, validate_topic_filter};
use serde::{Deserialize, Serialize};

use crate::{
    BrokerConfig,
    inbox::{Ack, Delivery, Inbox, Message, Offer, Outbound, Publisher},
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Claim {
    pub(crate) publisher: Publisher,
    pub(crate) transient: bool,
    pub(crate) bridge: bool,
    pub(crate) max_qos: QoS,
    pub(crate) will: Option<LastWill>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Operation {
    Disconnect { graceful: bool, now: Duration },
    Subscribe(Vec<(String, QoS)>),
    Unsubscribe(Vec<String>),
    Receive(Publish),
    Release(PacketId),
    Forward(Arc<Message>),
    Ack(PacketId, Ack),
    NextOutbound,
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
    ReceiveLocal(Option<Arc<Message>>),
    LocalInbox,
    Outbound(Option<Outbound>),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Subscription {
    qos: QoS,
    bridge: bool,
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
        self.expirations
            .first_key_value()
            .map(|(&(time, _), _)| time)
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
                while self
                    .expirations
                    .first_key_value()
                    .is_some_and(|(&(time, _), _)| time <= now)
                {
                    let (_, id) = self.expirations.pop_first().unwrap();
                    self.remove_session(&id);
                    effects.push(Effect::Expired(id));
                }
                Reply::NoChange
            }
            Command::Act(lease, action) => self.act(lease, action, &mut effects),
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
        let mut wills = Vec::new();
        for (id, session) in &mut self.sessions {
            if session.owner.is_some_and(|owner| owner.node == node) {
                session.owner = None;
                effects.push(Effect::Takeover(session.epoch));
                if let Some(will) = session.will.take() {
                    wills.push((session.publisher.clone(), will));
                }
                lost.push(id.clone());
            }
        }
        for id in lost {
            self.offline(id, now);
        }
        for (publisher, will) in wills {
            self.publish_will(publisher, will, effects);
        }
    }

    fn offline(&mut self, id: Arc<str>, now: Duration) {
        let session = self.sessions.get_mut(&id).unwrap();
        if let Some(inbox) = session.inbox.as_mut() {
            session.owner = None;
            inbox.reset_outbound();
            // session_expiry.c: session_expiry__add.
            if let Some(ttl) = self
                .config
                .persistent_client_expiration
                .filter(|ttl| !ttl.is_zero())
            {
                let expiry = now.saturating_add(ttl.min(Duration::from_secs(u64::from(u32::MAX))));
                session.expires = Some(expiry);
                self.expirations.insert((expiry, session.epoch), id);
            }
        } else {
            self.remove_session(&id);
        }
    }

    // handle_connect.c: connect__on_authorised transfers persistent state and
    // sends the old will only when either end of a v3.x takeover is clean.
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
        if let Some(previous) = self.sessions.get_mut(&id) {
            if let Some(expiry) = previous.expires.take() {
                self.expirations.remove(&(expiry, previous.epoch));
            }
            if previous.owner.is_some() {
                effects.push(Effect::Takeover(previous.epoch));
            }
            present = !claim.transient && previous.inbox.is_some();
            if !present {
                let will = previous
                    .will
                    .take()
                    .map(|will| (previous.publisher.clone(), will));
                self.remove_session(&id);
                if let Some((publisher, will)) = will {
                    self.publish_will(publisher, will, effects);
                }
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
            inbox: (!claim.transient).then(Inbox::default),
            filters: BTreeMap::new(),
            will: None,
            expires: None,
        });
        session.publisher = claim.publisher;
        session.epoch = epoch;
        session.owner = Some(owner);
        session.will = claim.will;
        session.bridge = claim.bridge;
        session.max_qos = claim.max_qos;
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
        match operation {
            Operation::Disconnect { graceful, now } => {
                let will = session.will.take();
                if !graceful && let Some(will) = will {
                    let publisher = session.publisher.clone();
                    self.publish_will(publisher, will, effects);
                }
                self.offline(lease.id, now);
                Reply::NoChange
            }
            Operation::Subscribe(filters) => self.subscribe(&lease.id, filters, effects),
            Operation::Unsubscribe(filters) => {
                for filter in filters {
                    if split_filter(&filter).is_none() {
                        return Reply::ProtocolError;
                    }
                    if session.filters.remove(filter.as_str()).is_some() {
                        remove_filter(
                            &mut self.normal,
                            &mut self.shared,
                            &mut self.groups,
                            &lease.id,
                            &filter,
                        );
                    }
                }
                Reply::NoChange
            }
            Operation::Receive(publish) => {
                // handle_publish.c: process_bad_message. Rejected messages are
                // acknowledged on v3.x, but never enter the inbox or retention.
                if !allowed(
                    &self.acls,
                    &session.publisher,
                    &publish.topic,
                    Access::Write,
                ) || (self.config.message_size_limit != 0
                    && publish.payload.len() > self.config.message_size_limit)
                    || publish.topic.starts_with("$CONTROL/")
                {
                    if publish.qos == QoS::AtLeastOnce {
                        if let Some(inbox) = &mut session.inbox {
                            inbox.credit_incoming();
                        } else {
                            return Reply::ReceiveLocal(None);
                        }
                    }
                    return Reply::NoChange;
                }
                let topic = publish.topic.into_boxed_str();
                let message = Arc::new(Message {
                    source: session.publisher.clone(),
                    topic,
                    payload: publish.payload,
                    qos: publish.qos,
                    retain: publish.retain,
                });
                if let Some(id) = publish.packet_id {
                    let Some(inbox) = &mut session.inbox else {
                        return Reply::ReceiveLocal(Some(message));
                    };
                    if publish.qos == QoS::ExactlyOnce {
                        return if inbox.receive(id, message, &self.config) {
                            Reply::NoChange
                        } else {
                            Reply::ProtocolError
                        };
                    }
                    if !inbox.can_publish_qos1(id, &self.config) {
                        return Reply::NoChange;
                    }
                }
                self.publish(message, effects);
                Reply::NoChange
            }
            Operation::Release(id) => {
                let Some(inbox) = &mut session.inbox else {
                    return Reply::LocalInbox;
                };
                if let Some(message) = inbox.release(id) {
                    self.publish(message, effects);
                }
                Reply::NoChange
            }
            Operation::Forward(message) => {
                self.publish(message, effects);
                Reply::NoChange
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
            Operation::NextOutbound => {
                let Some(inbox) = &mut session.inbox else {
                    return Reply::LocalInbox;
                };
                Reply::Outbound(inbox.next_outbound(&self.config))
            }
        }
    }

    fn remove_session(&mut self, id: &Arc<str>) {
        let session = self.sessions.remove(id).unwrap();
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
        filters: Vec<(String, QoS)>,
        effects: &mut Vec<Effect>,
    ) -> Reply {
        let session = self.sessions.get_mut(id).unwrap();
        let mut codes = Vec::with_capacity(filters.len());
        for (filter, qos) in filters {
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
                self.normal.insert(path, id.clone(), subscription).unwrap();
                // retain.c: retain__queue skips shared filters but replays
                // retained messages on every normal (re)subscribe.
                self.retained.visit(path, |message| {
                    if allowed(&self.acls, &session.publisher, &message.topic, Access::Read)
                        && (!self.config.check_retain_source
                            || allowed(&self.acls, &message.source, &message.topic, Access::Write))
                    {
                        let qos = outgoing_qos(message.qos, qos, &self.config);
                        deliver(
                            session,
                            Delivery {
                                message: message.clone(),
                                qos,
                                retain: true,
                                dedup_id: None,
                            },
                            &self.config,
                            effects,
                        );
                    }
                });
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
    fn publish_will(&mut self, source: Publisher, will: LastWill, effects: &mut Vec<Effect>) {
        if allowed(&self.acls, &source, &will.topic, Access::Write) {
            self.publish(
                Arc::new(Message {
                    source,
                    topic: will.topic.into_boxed_str(),
                    payload: will.payload,
                    qos: will.qos,
                    retain: will.retain,
                }),
                effects,
            );
        }
    }

    fn publish(&mut self, message: Arc<Message>, effects: &mut Vec<Effect>) {
        let topic = &message.topic;
        self.last_message += 1;
        let mut router = Router {
            sessions: &mut self.sessions,
            config: &self.config,
            acls: &self.acls,
            message: &message,
            id: self.last_message,
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
        if message.retain {
            self.retained.store(topic, message.clone());
        }
    }
}

struct Router<'a> {
    sessions: &'a mut BTreeMap<Arc<str>, Session>,
    config: &'a BrokerConfig,
    acls: &'a BTreeMap<u64, Arc<AclFile>>,
    message: &'a Arc<Message>,
    id: u64,
    effects: &'a mut Vec<Effect>,
}

impl Router<'_> {
    fn route(&mut self, id: &Arc<str>, sub: Subscription, shared: bool) {
        let session = self.sessions.get_mut(id).unwrap();
        let message = self.message;
        if (!shared && sub.bridge && *id == message.source.id)
            || !allowed(self.acls, &session.publisher, &message.topic, Access::Read)
        {
            return;
        }
        let retain = sub.bridge && message.retain;
        let qos = outgoing_qos(message.qos, sub.qos, self.config);
        let delivery = Delivery {
            message: message.clone(),
            qos,
            retain,
            dedup_id: (!retain && !self.config.allow_duplicate_messages).then_some(self.id),
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
                transient,
                bridge: false,
                max_qos: QoS::ExactlyOnce,
                will,
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
                Operation::Subscribe(vec![("topic/#".into(), QoS::AtLeastOnce)]),
            ),
            Command::Act(
                subscriber.clone(),
                Operation::Disconnect {
                    graceful: true,
                    now: Duration::from_secs(1),
                },
            ),
            claim(publisher.id.clone(), false),
            Command::SetAcl {
                security: 1,
                text: Some(acl),
                initial: true,
            },
            Command::Act(publisher.clone(), Operation::Receive(qos2)),
            Command::Act(publisher, Operation::Release(PacketId::new(26).unwrap())),
            Command::Expire(Duration::from_secs(5)),
            claim(subscriber.id.clone(), false),
            Command::Act(subscriber, Operation::Unsubscribe(vec!["topic/#".into()])),
            Command::Act(new_owner.clone(), Operation::NextOutbound),
            Command::Act(
                new_owner.clone(),
                Operation::Ack(PacketId::new(1).unwrap(), Ack::Acknowledged),
            ),
            Command::Act(
                new_owner,
                Operation::Disconnect {
                    graceful: true,
                    now: Duration::from_secs(10),
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
                    0 | 1 => make_claim(owner, [index as u8;16], id.clone(), value % 3 == 0, Some(LastWill {
                        topic: "a/will".into(), payload: Bytes::from_static(b"gone"), qos, retain: value % 2 == 0,
                    })),
                    2 => Command::Act(lease, Operation::Subscribe(vec![(filter.into(), qos)])),
                    3 => Command::Act(lease, Operation::Unsubscribe(vec![filter.into()])),
                    4 => Command::Act(lease, Operation::Receive(Publish {
                        dup: value % 2 == 0, qos, retain: value % 5 == 0, topic: topic.into(),
                        packet_id: (qos != QoS::AtMostOnce).then_some(mid), payload: Bytes::from(vec![value]),
                    })),
                    5 => Command::Act(lease, Operation::Release(mid)),
                    6 => Command::Act(lease, Operation::NextOutbound),
                    7 => Command::Act(lease, Operation::Ack(mid, Ack::Acknowledged)),
                    8 => Command::Act(lease, Operation::Disconnect { graceful: value % 2 == 0, now }),
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
