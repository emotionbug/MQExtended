//! Deterministic metadata and persistent inbox commands. Transport and clocks
//! are outside the log; command inputs carry the observed time and ACL data.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use mqx_auth::{Access, AclFile};
use mqx_codec::{LastWill, PacketId, Publish, QoS, SubscribeReturnCode};
use mqx_topic::{SubscriptionIndex, validate_topic_filter};

use crate::{
    BrokerConfig,
    inbox::{Ack, Delivery, Inbox, Message, Offer, Outbound, Publisher},
    retained::Retained,
};

pub(crate) type Epoch = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lease {
    pub(crate) id: Arc<str>,
    pub(crate) epoch: Epoch,
}

#[derive(Clone)]
pub(crate) enum Command {
    SetAcl {
        security: u64,
        acl: Option<Arc<AclFile>>,
    },
    Claim(Claim),
    Act(Lease, Operation),
    Expire(Duration),
}

#[derive(Clone)]
pub(crate) struct Claim {
    pub(crate) publisher: Publisher,
    pub(crate) transient: bool,
    pub(crate) bridge: bool,
    pub(crate) max_qos: QoS,
    pub(crate) will: Option<LastWill>,
}

#[derive(Clone)]
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    NoChange,
    Stale,
    Full,
    ProtocolError,
    Claimed { lease: Lease, present: bool },
    Subscribed(Vec<SubscribeReturnCode>),
    ReceiveLocal(Option<Arc<Message>>),
    LocalInbox,
    Outbound(Option<Outbound>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    Deliver { owner: Epoch, packet: Delivery },
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

pub(crate) trait CommandLog: Send {
    fn apply(&mut self, command: Command) -> Outcome;
    fn next_expiry(&self) -> Option<Duration>;
}

pub(crate) struct LocalLog(State);

impl LocalLog {
    pub(crate) fn new(config: Arc<BrokerConfig>) -> Self {
        Self(State {
            config,
            ..State::default()
        })
    }
}

impl CommandLog for LocalLog {
    fn apply(&mut self, command: Command) -> Outcome {
        self.0.apply(command)
    }

    fn next_expiry(&self) -> Option<Duration> {
        self.0
            .expirations
            .first_key_value()
            .map(|(&(time, _), _)| time)
    }
}

#[derive(Debug, Default)]
struct State {
    config: Arc<BrokerConfig>,
    acls: HashMap<u64, Arc<AclFile>>,
    last_epoch: Epoch,
    last_message: u64,
    sessions: HashMap<Arc<str>, Session>,
    normal: SubscriptionIndex<Arc<str>, Subscription>,
    shared: SubscriptionIndex<Arc<str>, SharedKey>,
    groups: HashMap<SharedKey, VecDeque<(Arc<str>, Subscription)>>,
    retained: Retained,
    expirations: BTreeMap<(Duration, Epoch), Arc<str>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Session {
    publisher: Publisher,
    epoch: Epoch,
    online: bool,
    bridge: bool,
    max_qos: QoS,
    inbox: Option<Inbox>,
    filters: HashMap<Arc<str>, QoS>,
    will: Option<LastWill>,
    expires: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Subscription {
    qos: QoS,
    bridge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SharedKey {
    name: Arc<str>,
    filter: Arc<str>,
}

impl State {
    fn apply(&mut self, command: Command) -> Outcome {
        let mut effects = Vec::new();
        let reply = match command {
            Command::SetAcl { security, acl } => {
                if let Some(acl) = acl {
                    self.acls.insert(security, acl);
                } else {
                    self.acls.remove(&security);
                }
                Reply::NoChange
            }
            Command::Claim(claim) => self.claim(claim, &mut effects),
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

    // handle_connect.c: connect__on_authorised transfers persistent state and
    // sends the old will only when either end of a v3.x takeover is clean.
    fn claim(&mut self, claim: Claim, effects: &mut Vec<Effect>) -> Reply {
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
            if previous.online {
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
            online: true,
            bridge: claim.bridge,
            max_qos: claim.max_qos,
            inbox: (!claim.transient).then(Inbox::default),
            filters: HashMap::new(),
            will: None,
            expires: None,
        });
        session.publisher = claim.publisher;
        session.epoch = epoch;
        session.online = true;
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
        Reply::Claimed {
            lease: Lease { id, epoch },
            present,
        }
    }

    fn act(&mut self, lease: Lease, operation: Operation, effects: &mut Vec<Effect>) -> Reply {
        let Some(session) = self
            .sessions
            .get_mut(&lease.id)
            .filter(|s| s.online && s.epoch == lease.epoch)
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
                let session = self.sessions.get_mut(&lease.id).unwrap();
                if session.inbox.is_some() {
                    session.online = false;
                    // session_expiry.c: session_expiry__add.
                    if let Some(ttl) = self
                        .config
                        .persistent_client_expiration
                        .filter(|ttl| !ttl.is_zero())
                    {
                        let expiry =
                            now.saturating_add(ttl.min(Duration::from_secs(u64::from(u32::MAX))));
                        session.expires = Some(expiry);
                        self.expirations.insert((expiry, session.epoch), lease.id);
                    }
                } else {
                    self.remove_session(&lease.id);
                }
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
                let members = self.groups.entry(key.clone()).or_insert_with(|| {
                    self.shared.insert(path, key.name.clone(), key).unwrap();
                    VecDeque::new()
                });
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
            session.filters.insert(Arc::from(filter), qos);
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
                let members = self.groups.get_mut(key).unwrap();
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
    sessions: &'a mut HashMap<Arc<str>, Session>,
    config: &'a BrokerConfig,
    acls: &'a HashMap<u64, Arc<AclFile>>,
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
        match inbox.offer(packet, session.online, session.max_qos, config) {
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
    acls: &HashMap<u64, Arc<AclFile>>,
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
    groups: &mut HashMap<SharedKey, VecDeque<(Arc<str>, Subscription)>>,
    id: &Arc<str>,
    filter: &str,
) {
    let (group, path) = split_filter(filter).unwrap();
    if let Some(group) = group {
        let key = SharedKey {
            name: group.into(),
            filter: path.into(),
        };
        let members = groups.get_mut(&key).unwrap();
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

    fn claim(id: Arc<str>, transient: bool) -> Command {
        Command::Claim(Claim {
            publisher: Publisher {
                id,
                username: None,
                security: 1,
            },
            transient,
            bridge: false,
            max_qos: QoS::ExactlyOnce,
            will: None,
        })
    }

    #[test]
    fn replay_preserves_epochs_qos2_retention_and_inbox_state() {
        let acl = Arc::new(AclFile::parse(b"topic readwrite topic/#\n").unwrap());
        let config = Arc::new(BrokerConfig {
            persistent_client_expiration: Some(Duration::from_secs(20)),
            ..BrokerConfig::default()
        });
        let mut left = LocalLog::new(config.clone());
        let mut right = LocalLog::new(config);
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
                acl: Some(acl),
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
        assert_eq!(left.0.sessions, right.0.sessions);
        assert_eq!(left.0.normal, right.0.normal);
        assert_eq!(left.0.shared, right.0.shared);
        assert_eq!(left.0.retained, right.0.retained);
        assert_eq!(left.0.expirations, right.0.expirations);
        assert_eq!(left.0.sessions.len(), 1);
    }
}
