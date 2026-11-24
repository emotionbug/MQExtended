use std::{cell::RefCell, sync::RwLock};

use mqx_auth::external::{AclAccess, AclIdentity, Binding, ExternalSecurity, Subject, Verdict};

use super::*;

/// The registry is installed locally before replay and shared across snapshot restores.
#[derive(Clone, Default)]
pub(crate) struct ExternalPlugins(Arc<RwLock<BTreeMap<u32, Arc<dyn ExternalSecurity>>>>);

impl std::fmt::Debug for ExternalPlugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.read().unwrap().keys())
            .finish()
    }
}

impl ExternalPlugins {
    pub(crate) fn insert(&self, id: u32, plugin: Arc<dyn ExternalSecurity>) {
        self.0.write().unwrap().insert(id, plugin);
    }

    pub(crate) fn get(&self, id: u32) -> Option<Arc<dyn ExternalSecurity>> {
        self.0.read().unwrap().get(&id).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct VerdictKey {
    pub(crate) plugin: u32,
    pub(crate) identity: AclIdentity,
    pub(crate) topic: Arc<str>,
    pub(crate) access: AclAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResolvedVerdict {
    pub(crate) key: VerdictKey,
    pub(crate) verdict: Verdict,
    /// Zero is a single-use check: pin it for this apply, but never cache it.
    pub(crate) expires: Duration,
}

impl ResolvedVerdict {
    pub(super) fn sort(verdicts: &mut [Self]) {
        verdicts.sort_by(|left, right| left.key.cmp(&right.key));
    }

    fn single_use(&self) -> bool {
        self.expires.is_zero() || self.verdict == Verdict::Error
    }
}

/// An offline session and a will both resolve on the leader, but must not
/// consume each other's single-use checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum VerdictTarget {
    Session(Option<Owner>),
    Will,
}

impl VerdictTarget {
    pub(crate) fn owner(self) -> Option<Owner> {
        match self {
            Self::Session(owner) => owner,
            Self::Will => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum VerdictRequest {
    Cached(ResolvedVerdict),
    Missing(VerdictKey),
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct VerdictCache {
    entries: BTreeMap<VerdictKey, (Verdict, Duration)>,
    #[serde(skip)]
    deadlines: BTreeSet<(Duration, VerdictKey)>,
}

impl VerdictCache {
    fn lookup(&self, key: &VerdictKey, now: Duration) -> Option<(Verdict, Duration)> {
        self.entries
            .get(key)
            .copied()
            .filter(|&(_, expires)| now <= expires)
    }

    pub(super) fn insert(&mut self, verdicts: &[ResolvedVerdict], now: Duration) {
        for verdict in verdicts {
            if verdict.verdict == Verdict::Error
                || verdict.expires.is_zero()
                || verdict.expires < now
            {
                continue;
            }
            if let Some((_, old)) = self
                .entries
                .insert(verdict.key.clone(), (verdict.verdict, verdict.expires))
            {
                if old == verdict.expires {
                    continue;
                }
                self.deadlines.remove(&(old, verdict.key.clone()));
            }
            self.deadlines
                .insert((verdict.expires, verdict.key.clone()));
        }
    }

    pub(super) fn expire(&mut self, now: Duration) {
        while self.deadlines.first().is_some_and(|(at, _)| *at < now) {
            let (_, key) = self.deadlines.pop_first().unwrap();
            self.entries.remove(&key);
        }
    }

    pub(super) fn next_expiry(&self) -> Option<Duration> {
        self.deadlines
            .first()?
            .0
            .checked_add(Duration::from_nanos(1))
    }

    pub(super) fn rebuild_deadlines(&mut self) {
        self.deadlines = self
            .entries
            .iter()
            .map(|(key, &(_, at))| (at, key.clone()))
            .collect();
    }
}

pub(super) struct PinnedVerdicts<'a> {
    values: &'a [ResolvedVerdict],
    used: RefCell<Vec<bool>>,
}

impl<'a> PinnedVerdicts<'a> {
    pub(super) fn new(values: &'a [ResolvedVerdict]) -> Self {
        Self {
            values,
            used: RefCell::default(),
        }
    }

    fn matches(
        &self,
        plugin: u32,
        identity: &AclIdentity,
        topic: &str,
        access: AclAccess,
    ) -> impl Iterator<Item = (usize, &ResolvedVerdict)> {
        let query = (plugin, identity, topic, access);
        fn key(resolved: &ResolvedVerdict) -> (u32, &AclIdentity, &str, AclAccess) {
            let key = &resolved.key;
            (key.plugin, &key.identity, key.topic.as_ref(), key.access)
        }
        let start = self
            .values
            .partition_point(|resolved| key(resolved) < query);
        let end = start + self.values[start..].partition_point(|resolved| key(resolved) == query);
        (start..end).zip(&self.values[start..end])
    }

    fn consumed(&self, key: &VerdictKey) -> bool {
        let used = self.used.borrow();
        self.matches(key.plugin, &key.identity, &key.topic, key.access)
            .any(|(index, _)| used.get(index) == Some(&true))
    }
}

#[derive(Clone, Copy)]
pub(super) struct VerdictContext<'a> {
    pub(super) now: Duration,
    pinned: Option<&'a PinnedVerdicts<'a>>,
    single_use: bool,
}

impl<'a> VerdictContext<'a> {
    pub(super) fn new(now: Duration) -> Self {
        Self {
            now,
            pinned: None,
            single_use: false,
        }
    }

    pub(super) fn with_pins(self, pinned: &'a PinnedVerdicts<'a>, single_use: bool) -> Self {
        Self {
            pinned: Some(pinned),
            single_use,
            ..self
        }
    }

    fn lookup(
        self,
        plugin: u32,
        identity: &AclIdentity,
        topic: &str,
        access: AclAccess,
    ) -> Option<Verdict> {
        let pinned = self.pinned?;
        let mut reusable = None;
        for (index, resolved) in pinned.matches(plugin, identity, topic, access) {
            if resolved.single_use() {
                // plugin_acl_check.c: plugin__acl_check calls each callback
                // per ACL check. With auth-plug acl_cacheseconds=0 (cache.c:
                // acl_cache_q), a result belongs to one check, not one key.
                if self.single_use && reusable.is_none() {
                    let mut used = pinned.used.borrow_mut();
                    if used.is_empty() {
                        used.resize(pinned.values.len(), false);
                    }
                    if !std::mem::replace(&mut used[index], true) {
                        return Some(resolved.verdict);
                    }
                }
            } else {
                reusable = Some(resolved.verdict);
            }
        }
        reusable
    }
}

#[derive(PartialEq, Eq)]
pub(super) enum AclDecision {
    Allow,
    Deny,
    Error,
    Missing(VerdictKey),
}

impl Acls<'_> {
    pub(super) fn session_check(
        self,
        session: &Session,
        topic: &str,
        access: Access,
    ) -> AclDecision {
        if session.internal_bridge.is_some() {
            AclDecision::Allow
        } else {
            self.check(&session.publisher, topic, access, false, None)
        }
    }

    pub(super) fn check(
        self,
        publisher: &Publisher,
        topic: &str,
        access: Access,
        synthetic: bool,
        request: Option<&mut dyn FnMut(VerdictRequest)>,
    ) -> AclDecision {
        // plugin_acl_check.c: acl__check_dollar precedes every callback.
        if (topic.starts_with("$share") && matches!(access, Access::Read | Access::Write))
            || (topic.starts_with("$SYS")
                && access == Access::Write
                && !mqx_topic::matches("$SYS/broker/connection/+/state", topic).unwrap_or(false))
        {
            return AclDecision::Deny;
        }
        if let Some((id, binding)) = publisher.external {
            let plugins = self.plugins.0.read().unwrap();
            let Some(plugin) = plugins.get(&id) else {
                return AclDecision::Error;
            };
            let binding = if synthetic {
                Binding {
                    synthetic: true,
                    ..Binding::default()
                }
            } else {
                binding
            };
            let subject = Subject {
                client_id: &publisher.id,
                username: publisher.username.as_deref(),
                binding,
            };
            // plugin_v4.c: plugin_v4_acl_check runs acl__pre_check first.
            if !crate::external_acl_precheck(plugin.as_ref(), subject.client_id, subject.username) {
                return AclDecision::Deny;
            }
            let access = match access {
                Access::Read => AclAccess::Read,
                Access::Write => AclAccess::Write,
                Access::Subscribe => AclAccess::Subscribe,
                Access::Unsubscribe => return AclDecision::Allow,
            };
            let identity = plugin.acl_identity(subject);
            drop(plugins);
            if let Some(identity) = identity {
                let verdict =
                    if let Some(pinned) = self.context.lookup(id, &identity, topic, access) {
                        pinned
                    } else {
                        let key = VerdictKey {
                            plugin: id,
                            identity,
                            topic: topic.into(),
                            access,
                        };
                        match self.cache.lookup(&key, self.context.now) {
                            Some((verdict, expires)) => {
                                if let Some(request) = request {
                                    request(VerdictRequest::Cached(ResolvedVerdict {
                                        key,
                                        verdict,
                                        expires,
                                    }));
                                }
                                verdict
                            }
                            None => {
                                if let Some(request) = request {
                                    request(VerdictRequest::Missing(key.clone()));
                                }
                                return AclDecision::Missing(key);
                            }
                        }
                    };
                match verdict {
                    Verdict::Allow => return AclDecision::Allow,
                    Verdict::Deny => return AclDecision::Deny,
                    Verdict::Error => return AclDecision::Error,
                    Verdict::Defer => {}
                }
            }
        }
        if self.file_or_dynamic_allows(publisher, topic, access) {
            AclDecision::Allow
        } else {
            AclDecision::Deny
        }
    }

    pub(super) fn retained_source(
        self,
        config: &BrokerConfig,
        message: &Message,
        request: Option<&mut dyn FnMut(VerdictRequest)>,
    ) -> AclDecision {
        if !config.check_retain_source || message.source.id.is_empty() {
            AclDecision::Allow
        } else {
            self.check(
                &message.source,
                &message.topic,
                Access::Write,
                true,
                request,
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum PendingCheck {
    Allowed,
    Read,
    RetainedRead,
    RetainedSource,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingDelivery {
    pub(super) packet: Delivery,
    pub(super) check: PendingCheck,
}

impl PendingDelivery {
    fn check(
        &mut self,
        acl: Acls<'_>,
        publisher: &Publisher,
        config: &BrokerConfig,
    ) -> AclDecision {
        let message = &self.packet.message;
        match self.check {
            PendingCheck::Allowed => AclDecision::Allow,
            PendingCheck::Read => acl.check(publisher, &message.topic, Access::Read, false, None),
            PendingCheck::RetainedRead => {
                let decision = acl.check(publisher, &message.topic, Access::Read, false, None);
                if decision != AclDecision::Allow {
                    return decision;
                }
                self.check = PendingCheck::RetainedSource;
                acl.retained_source(config, message, None)
            }
            PendingCheck::RetainedSource => acl.retained_source(config, message, None),
        }
    }

    fn needed(&self, acl: Acls<'_>, session: &Session, config: &BrokerConfig) -> Vec<VerdictKey> {
        let message = &self.packet.message;
        let decision = if message.expired(acl.context.now) {
            AclDecision::Deny
        } else {
            match self.check {
                PendingCheck::Allowed => AclDecision::Allow,
                PendingCheck::Read => acl.session_check(session, &message.topic, Access::Read),
                PendingCheck::RetainedRead => {
                    match acl.session_check(session, &message.topic, Access::Read) {
                        AclDecision::Allow => acl.retained_source(config, message, None),
                        decision => decision,
                    }
                }
                PendingCheck::RetainedSource => acl.retained_source(config, message, None),
            }
        };
        needed(decision)
    }
}

fn needed(decision: AclDecision) -> Vec<VerdictKey> {
    match decision {
        AclDecision::Missing(key) => vec![key],
        _ => Vec::new(),
    }
}

impl State {
    pub(crate) fn external_plugins(&self) -> &ExternalPlugins {
        &self.external_plugins
    }

    pub(super) fn acl_at<'a>(&'a self, context: VerdictContext<'a>) -> Acls<'a> {
        Acls::new(
            &self.acls,
            self.dynamic_security.as_ref(),
            &self.external_plugins,
            &self.verdicts,
            context,
        )
    }

    pub(crate) fn write_verdicts(
        &self,
        lease: &Lease,
        topic: &str,
        payload_len: usize,
        now: Duration,
    ) -> Vec<VerdictRequest> {
        let Some(session) = self.claimed_session(lease) else {
            return Vec::new();
        };
        let mut requests = Vec::new();
        if !publish_oversize(&self.config, payload_len) && session.internal_bridge.is_none() {
            self.acl_at(VerdictContext::new(now)).check(
                &session.publisher,
                topic,
                Access::Write,
                false,
                Some(&mut |check| requests.push(check)),
            );
        }
        requests
    }

    pub(crate) fn operation_verdicts(
        &self,
        lease: &Lease,
        operation: &Operation,
        now: Duration,
    ) -> Vec<VerdictRequest> {
        self.operation_verdicts_with(lease, operation, now, &[])
    }

    // Resolve one missing gate at a time so a denied subscription never checks
    // its retained topics and a backend error never checks later filters.
    // `pinned` is sorted by key to keep lookups cheap for a retained wildcard.
    pub(crate) fn operation_verdicts_with(
        &self,
        lease: &Lease,
        operation: &Operation,
        now: Duration,
        pinned: &[ResolvedVerdict],
    ) -> Vec<VerdictRequest> {
        let Some(session) = self.claimed_session(lease) else {
            return Vec::new();
        };
        let pinned = PinnedVerdicts::new(pinned);
        let acl = self.acl_at(VerdictContext::new(now).with_pins(&pinned, true));
        let mut requests = Vec::new();
        let mut record = |check| requests.push(check);
        match operation {
            Operation::Receive(publication)
            | Operation::ReceiveAdmitted(publication)
            | Operation::ReceiveBirth { publication, .. } => {
                let packet = &publication.packet;
                if session.publisher.external.is_some()
                    && !publish_oversize(&self.config, packet.payload.len())
                {
                    acl.check(
                        &session.publisher,
                        &packet.topic,
                        Access::Write,
                        false,
                        Some(&mut record),
                    );
                }
            }
            Operation::Subscribe(filters, subscribed_at)
            | Operation::SubscribeDollarRoot(filters, subscribed_at) => {
                if session.publisher.external.is_none() && !self.config.check_retain_source {
                    return requests;
                }
                let mut installed = BTreeSet::new();
                for entry in filters {
                    let Some((group, path)) = split_filter(&entry.filter)
                        .filter(|(_, path)| validate_topic_filter(path).is_ok())
                    else {
                        break;
                    };
                    let decision = if session.internal_bridge.is_some() {
                        AclDecision::Allow
                    } else {
                        acl.check(
                            &session.publisher,
                            &entry.filter,
                            Access::Subscribe,
                            false,
                            Some(&mut record),
                        )
                    };
                    match decision {
                        AclDecision::Allow => {}
                        AclDecision::Deny => continue,
                        AclDecision::Error | AclDecision::Missing(_) => break,
                    }
                    let previous = session.filters.contains_key(entry.filter.as_str())
                        || !installed.insert(entry.filter.as_str());
                    if group.is_some()
                        || !(entry.retain_handling == 0 || entry.retain_handling == 1 && !previous)
                    {
                        continue;
                    }
                    let complete = self.retained.inspect(
                        path,
                        *subscribed_at,
                        matches!(operation, Operation::SubscribeDollarRoot(..)),
                        |message| {
                            let read = if session.internal_bridge.is_some() {
                                AclDecision::Allow
                            } else {
                                acl.check(
                                    &session.publisher,
                                    &message.topic,
                                    Access::Read,
                                    false,
                                    Some(&mut record),
                                )
                            };
                            let decision = if read == AclDecision::Allow {
                                acl.retained_source(&self.config, message, Some(&mut record))
                            } else {
                                read
                            };
                            matches!(decision, AclDecision::Allow | AclDecision::Deny)
                        },
                    );
                    if !complete {
                        break;
                    }
                }
            }
            _ => {}
        }
        requests
    }

    pub(crate) fn claim_verdicts(&self, claim: &Claim, now: Duration) -> Vec<VerdictRequest> {
        if claim.clean_start
            || claim.internal_bridge.is_some()
            || claim.publisher.external.is_none()
        {
            return Vec::new();
        }
        let Some(previous) = self
            .sessions
            .get(&claim.publisher.id)
            .filter(|session| session.persistent() && session.expires.is_none_or(|at| at > now))
        else {
            return Vec::new();
        };
        let acl = self.acl_at(VerdictContext::new(now));
        let mut requests = Vec::new();
        if let Some(inbox) = &previous.inbox {
            inbox.visit_acl_topics(now, |topic, writing| {
                acl.check(
                    &claim.publisher,
                    topic,
                    inbox_access(writing),
                    false,
                    Some(&mut |request| requests.push(request)),
                );
            });
        }
        requests
    }

    pub(crate) fn pending_verdicts(&self, now: Duration) -> Vec<(VerdictTarget, Vec<VerdictKey>)> {
        let acl = self.acl_at(VerdictContext::new(now));
        let mut requests = Vec::with_capacity(
            self.pending_sessions.len() + usize::from(!self.pending_wills.is_empty()),
        );
        for id in &self.pending_sessions {
            let session = &self.sessions[id];
            let pending = session.pending.front().unwrap();
            requests.push((
                VerdictTarget::Session(session.owner),
                pending.needed(acl, session, &self.config),
            ));
        }
        if let Some(will) = self.pending_wills.front() {
            requests.push((VerdictTarget::Will, needed(will.check(acl))));
        }
        requests
    }

    pub(super) fn request_pending(&self, id: &str, now: Duration, effects: &mut Vec<Effect>) {
        let session = &self.sessions[id];
        if let Some(pending) = session.pending.front() {
            effects.push(Effect::NeedVerdicts {
                target: VerdictTarget::Session(session.owner),
                keys: pending.needed(self.acl_at(VerdictContext::new(now)), session, &self.config),
            });
        }
    }

    pub(super) fn resolve_verdicts(
        &mut self,
        now: Duration,
        target: VerdictTarget,
        verdicts: &[ResolvedVerdict],
        effects: &mut Vec<Effect>,
    ) {
        self.verdicts.expire(now);
        self.verdicts.insert(verdicts, now);
        let pinned = PinnedVerdicts::new(verdicts);
        let context = VerdictContext::new(now);
        self.pending_sessions.retain(|id| {
            let session = self.sessions.get_mut(id).unwrap();
            let destination = VerdictTarget::Session(session.owner);
            let acl = Acls::new(
                &self.acls,
                self.dynamic_security.as_ref(),
                &self.external_plugins,
                &self.verdicts,
                context.with_pins(&pinned, target == destination),
            );
            let mut advanced = false;
            while let Some(pending) = session.pending.front_mut() {
                let previous = pending.check;
                let decision = if pending.packet.message.expired(now) {
                    AclDecision::Deny
                } else {
                    pending.check(acl, &session.publisher, &self.config)
                };
                if let AclDecision::Missing(key) = decision {
                    if advanced
                        || previous != pending.check
                        || target == destination && pinned.consumed(&key)
                    {
                        effects.push(Effect::NeedVerdicts {
                            target: destination,
                            keys: vec![key],
                        });
                    }
                    return true;
                }
                let pending = session.pending.pop_front().unwrap();
                advanced = true;
                if decision == AclDecision::Allow {
                    deliver(
                        session,
                        pending.packet,
                        &self.config,
                        effects,
                        &mut self.sys_counters,
                        &mut self.persistence_changes,
                    );
                }
            }
            false
        });
        let mut advanced = false;
        while let Some(will) = self.pending_wills.front() {
            let decision =
                will.check(self.acl_at(context.with_pins(&pinned, target == VerdictTarget::Will)));
            if let AclDecision::Missing(key) = decision {
                if advanced || target == VerdictTarget::Will && pinned.consumed(&key) {
                    effects.push(Effect::NeedVerdicts {
                        target: VerdictTarget::Will,
                        keys: vec![key],
                    });
                }
                break;
            }
            let will = self.pending_wills.pop_front().unwrap();
            advanced = true;
            if decision == AclDecision::Allow {
                self.publish_with_verdicts(
                    will.into_message(now),
                    context.with_pins(&pinned, false),
                    effects,
                );
            }
        }
    }
}

pub(super) fn inbox_access(writing: bool) -> Access {
    if writing { Access::Write } else { Access::Read }
}

#[cfg(test)]
mod tests;
