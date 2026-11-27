use std::{str::Split, sync::Arc, time::Duration};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::inbox::{MAX_MESSAGE_AGE, Message};

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RetainedTree")]
pub(crate) struct Retained {
    ordinary: Branch,
    dollar: Branch,
    #[serde(skip)]
    count: i64,
    #[serde(skip)]
    legacy_undated: bool,
}

#[derive(Deserialize)]
#[serde(rename = "Retained")]
struct RetainedTree {
    ordinary: Branch,
    dollar: Branch,
}

impl From<RetainedTree> for Retained {
    fn from(RetainedTree { ordinary, dollar }: RetainedTree) -> Self {
        Self {
            count: ordinary.count() + dollar.count(),
            ordinary,
            dollar,
            legacy_undated: false,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Branch {
    children: IndexMap<Box<str>, Self>,
    message: Option<Arc<Message>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stored_at: Option<Duration>,
}

impl Retained {
    pub(crate) fn for_each(&self, mut visit: impl FnMut(&Arc<Message>)) {
        self.for_each_stored(|message, _| visit(message));
    }

    pub(crate) fn for_each_stored(&self, mut visit: impl FnMut(&Arc<Message>, Option<Duration>)) {
        self.ordinary.for_each(&mut visit);
        self.dollar.for_each(&mut visit);
    }

    pub(crate) fn count(&self) -> i64 {
        self.count
    }

    // An exact lookup of the stored slot, without replay or expiry handling.
    pub(crate) fn get(&self, topic: &str) -> Option<&Arc<Message>> {
        let mut branch = self.root(topic);
        for level in topic.split('/') {
            branch = branch.children.get(level)?;
        }
        branch.message.as_ref()
    }

    fn root(&self, topic: &str) -> &Branch {
        if topic.starts_with('$') {
            &self.dollar
        } else {
            &self.ordinary
        }
    }

    // retain.c: retain__store creates hierarchy entries before processing a
    // tombstone. Only clearing an existing retained message prunes its path.
    pub(crate) fn store(&mut self, message: &Arc<Message>, stored_at: Option<Duration>) {
        // New messages already carry their publish time in the hard deadline.
        // Keep a side timestamp only if it contributes older legacy information.
        let stored_at = stored_at.filter(|at| {
            message
                .broker_expires
                .is_none_or(|deadline| at.saturating_add(MAX_MESSAGE_AGE) < deadline)
        });
        self.store_inner(message, stored_at, true);
    }

    pub(crate) fn clear_existing(&mut self, message: &Arc<Message>) {
        debug_assert!(message.payload.is_empty());
        self.store_inner(message, None, false);
    }

    fn store_inner(
        &mut self,
        message: &Arc<Message>,
        stored_at: Option<Duration>,
        create_path: bool,
    ) {
        let topic = &message.topic;
        let root = if topic.starts_with('$') {
            &mut self.dollar
        } else {
            &mut self.ordinary
        };
        root.store(
            topic.split('/'),
            message,
            stored_at,
            create_path,
            &mut self.count,
        );
    }

    pub(crate) fn visit(
        &mut self,
        filter: &str,
        now: Duration,
        dollar_root: bool,
        max_age: Option<Duration>,
        mut visit: impl FnMut(&Arc<Message>) -> bool,
    ) -> bool {
        self.seed_legacy_age(now);
        let mut expired = Vec::new();
        let complete = self.search(filter, dollar_root, |message, stored_at| {
            if Self::expired(message, stored_at, now, max_age) {
                expired.push(message.clone());
                true
            } else {
                visit(message)
            }
        });
        // retain.c: retain__delete_expired_msg removes the message, not the branch.
        for message in expired {
            let mut root = if message.topic.starts_with('$') {
                &mut self.dollar
            } else {
                &mut self.ordinary
            };
            for level in message.topic.split('/') {
                root = root.children.get_mut(level).unwrap();
            }
            root.clear_message(&mut self.count);
        }
        complete
    }

    pub(crate) fn inspect(
        &self,
        filter: &str,
        now: Duration,
        dollar_root: bool,
        max_age: Option<Duration>,
        mut visit: impl FnMut(&Arc<Message>) -> bool,
    ) -> bool {
        self.search(filter, dollar_root, |message, stored_at| {
            Self::expired(message, stored_at, now, max_age) || visit(message)
        })
    }

    fn search(
        &self,
        filter: &str,
        dollar_root: bool,
        mut visit: impl FnMut(&Arc<Message>, Option<Duration>) -> bool,
    ) -> bool {
        let mut levels = filter.split('/');
        if dollar_root && filter.starts_with('$') {
            // retain.c: retain__search starts a dollar topic at level zero,
            // where `/#` includes the parent only if it has children.
            self.dollar
                .children
                .get(levels.next().unwrap())
                .is_none_or(|branch| branch.search(levels, false, &mut visit))
        } else {
            self.root(filter).search(levels, true, &mut visit)
        }
    }

    fn published_at(message: &Message, stored_at: Duration) -> Duration {
        // QoS 2 release may store the retained value after the original PUBLISH.
        message.broker_expires.map_or(stored_at, |deadline| {
            stored_at.min(deadline.saturating_sub(MAX_MESSAGE_AGE))
        })
    }

    pub(crate) fn expired(
        message: &Message,
        stored_at: Option<Duration>,
        now: Duration,
        max_age: Option<Duration>,
    ) -> bool {
        let max_age = max_age.unwrap_or(MAX_MESSAGE_AGE).min(MAX_MESSAGE_AGE);
        message.expires.is_some_and(|at| at <= now)
            || message.broker_expired(now)
            || now >= Self::published_at(message, stored_at.unwrap_or(now)).saturating_add(max_age)
    }

    pub(crate) fn has_messages(&self) -> bool {
        self.count != 0
    }

    pub(crate) fn restore_age(&mut self) -> bool {
        self.legacy_undated = self.ordinary.initialize_age(None) | self.dollar.initialize_age(None);
        self.legacy_undated
    }

    fn seed_legacy_age(&mut self, now: Duration) {
        if std::mem::take(&mut self.legacy_undated) {
            self.ordinary.initialize_age(Some(now));
            self.dollar.initialize_age(Some(now));
        }
    }

    pub(crate) fn expire(
        &mut self,
        now: Duration,
        max_age: Option<Duration>,
        persistence_changes: &mut u64,
    ) -> bool {
        self.seed_legacy_age(now);
        self.ordinary
            .expire(now, max_age, persistence_changes, &mut self.count)
            | self
                .dollar
                .expire(now, max_age, persistence_changes, &mut self.count)
    }
}

impl Branch {
    fn for_each(&self, visit: &mut impl FnMut(&Arc<Message>, Option<Duration>)) {
        if let Some(message) = &self.message {
            visit(message, self.stored_at);
        }
        for child in self.children.values() {
            child.for_each(visit);
        }
    }

    fn count(&self) -> i64 {
        i64::from(self.message.is_some()) + self.children.values().map(Self::count).sum::<i64>()
    }

    fn clear_message(&mut self, count: &mut i64) -> bool {
        self.stored_at = None;
        let removed = self.message.take().is_some();
        *count -= i64::from(removed);
        removed
    }

    fn store(
        &mut self,
        mut levels: Split<'_, char>,
        message: &Arc<Message>,
        stored_at: Option<Duration>,
        create_path: bool,
        count: &mut i64,
    ) -> bool {
        let Some(level) = levels.next() else {
            if message.payload.is_empty() {
                return self.clear_message(count) && self.children.is_empty();
            }
            self.stored_at = stored_at;
            *count += i64::from(self.message.replace(message.clone()).is_none());
            return false;
        };
        let child = if let Some(index) = self.children.get_index_of(level) {
            self.children.get_index_mut(index).unwrap().1
        } else if create_path {
            self.children.entry(level.into()).or_default()
        } else {
            return false;
        };
        if child.store(levels, message, stored_at, create_path, count) {
            self.children.shift_remove(level);
            return self.children.is_empty() && self.message.is_none();
        }
        false
    }

    // retain.c: retain__search visits children in insertion order, and `#`
    // visits descendants before the parent that matched without a suffix.
    fn search(
        &self,
        mut levels: Split<'_, char>,
        include_leaf_for_hash: bool,
        visit: &mut impl FnMut(&Arc<Message>, Option<Duration>) -> bool,
    ) -> bool {
        match levels.next() {
            None => self.visit_message(visit),
            Some("#") => {
                self.children.values().all(|child| child.visit_tree(visit))
                    && ((!include_leaf_for_hash && self.children.is_empty())
                        || self.visit_message(visit))
            }
            Some("+") => self
                .children
                .values()
                .all(|child| child.search(levels.clone(), true, visit)),
            Some(level) => self
                .children
                .get(level)
                .is_none_or(|child| child.search(levels, true, visit)),
        }
    }

    fn visit_message(
        &self,
        visit: &mut impl FnMut(&Arc<Message>, Option<Duration>) -> bool,
    ) -> bool {
        self.message
            .as_ref()
            .is_none_or(|message| visit(message, self.stored_at))
    }

    fn visit_tree(&self, visit: &mut impl FnMut(&Arc<Message>, Option<Duration>) -> bool) -> bool {
        self.visit_message(visit) && self.children.values().all(|child| child.visit_tree(visit))
    }

    fn initialize_age(&mut self, now: Option<Duration>) -> bool {
        let mut undated = false;
        if let Some(message) = &mut self.message
            && message.broker_expires.is_none()
        {
            if let Some(stored_at) = self.stored_at.take().or(now) {
                // A subsequent retained replay must carry the same broker deadline.
                Arc::make_mut(message).cap_age(stored_at);
            } else {
                undated = true;
            }
        }
        for child in self.children.values_mut() {
            undated |= child.initialize_age(now);
        }
        undated
    }

    fn expire(
        &mut self,
        now: Duration,
        max_age: Option<Duration>,
        persistence_changes: &mut u64,
        count: &mut i64,
    ) -> bool {
        let mut pending = false;
        for child in self.children.values_mut() {
            pending |= child.expire(now, max_age, persistence_changes, count);
        }
        let Some(message) = &self.message else {
            return pending;
        };
        // retain.c: retain__expire drops the message and keeps the branch.
        if Retained::expired(message, self.stored_at, now, max_age) {
            // Native persistence omits $SYS, but the expiry policy includes it.
            *persistence_changes += u64::from(!message.topic.starts_with("$SYS"));
            self.clear_message(count);
        } else {
            pending = true;
        }
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerConfig, ReloadableLimits, inbox::Publisher, persistence::PersistentState};

    fn message(topic: &str, payload: &'static [u8], expires: Option<Duration>) -> Arc<Message> {
        Arc::new(Message {
            source: Publisher {
                id: "source".into(),
                username: None,
                security: 0,
                dynamic_security: None,
                external: None,
            },
            topic: topic.into(),
            payload: bytes::Bytes::from_static(payload),
            qos: mqx_codec::QoS::AtLeastOnce,
            retain: true,
            properties: Vec::new(),
            expires,
            broker_expires: None,
        })
    }

    #[test]
    fn retained_count_follows_slot_lifetime() {
        let mut tree = Retained::default();
        let now = Duration::from_secs(1);
        tree.store(&message("root", b"first", None), None);
        tree.store(&message("root", b"replacement", None), None);
        let child = message("root/child", b"child", Some(now));
        tree.store(&child, None);
        tree.store(&message("swept", b"value", Some(now)), None);
        tree.store(&message("$SYS/swept", b"value", Some(now)), None);
        assert_eq!(tree.count(), 4);

        let root = message("root", b"", None);
        tree.store(&root, None);
        tree.store(&root, None);
        tree.clear_existing(&message("missing/child", b"", None));
        assert_eq!(tree.count(), 3);

        tree.store(&message("$SYS/cleared", b"value", None), None);
        tree.clear_existing(&message("$SYS/cleared", b"", None));
        assert_eq!(tree.count(), 3);

        assert!(Arc::ptr_eq(tree.get("root/child").unwrap(), &child));
        assert!(tree.visit("root/#", now, false, None, |_| {
            panic!("expired retained message must not be replayed")
        }));
        assert!(tree.get("root/child").is_none());
        assert_eq!(tree.count(), 2);

        let mut persistence_changes = 0;
        assert!(!tree.expire(now, None, &mut persistence_changes));
        assert_eq!(persistence_changes, 1);
        assert_eq!(tree.count(), 0);
        assert!(!tree.has_messages());
    }

    #[test]
    fn disabled_max_age_keeps_legacy_messagepack_shapes() {
        #[derive(Serialize)]
        struct OldLimits {
            message_size_limit: usize,
            persistent_client_expiration: Option<Duration>,
            queue_qos0_messages: bool,
            upgrade_outgoing_qos: bool,
            allow_duplicate_messages: bool,
            clientid_prefixes: Option<String>,
        }

        let limits = BrokerConfig {
            retain_max_age: None,
            ..BrokerConfig::default()
        }
        .reloadable_limits();
        let old = OldLimits {
            message_size_limit: limits.message_size_limit,
            persistent_client_expiration: limits.persistent_client_expiration,
            queue_qos0_messages: limits.queue_qos0_messages,
            upgrade_outgoing_qos: limits.upgrade_outgoing_qos,
            allow_duplicate_messages: limits.allow_duplicate_messages,
            clientid_prefixes: limits.clientid_prefixes.clone(),
        };
        let encoded = rmp_serde::to_vec(&old).unwrap();
        assert_eq!(rmp_serde::to_vec(&limits).unwrap(), encoded);
        assert_eq!(
            rmp_serde::from_slice::<ReloadableLimits>(&encoded).unwrap(),
            limits
        );

        #[derive(Default, Serialize)]
        struct OldBranch {
            children: IndexMap<Box<str>, Self>,
            message: Option<Arc<Message>>,
        }

        let message = message("retained", b"retained payload", None);
        let mut tree = Retained::default();
        tree.store(&message, None);
        let ordinary = OldBranch {
            children: IndexMap::from([(
                "retained".into(),
                OldBranch {
                    message: Some(message.clone()),
                    ..OldBranch::default()
                },
            )]),
            message: None,
        };
        let encoded = rmp_serde::to_vec(&(ordinary, OldBranch::default())).unwrap();
        assert_eq!(rmp_serde::to_vec(&tree).unwrap(), encoded);
        let restored = rmp_serde::from_slice::<Retained>(&encoded).unwrap();
        assert_eq!(restored.count(), 1);
        assert_eq!(restored, tree);

        let image = PersistentState {
            messages: vec![message],
            retained: vec![0],
            ..PersistentState::default()
        };
        let encoded =
            rmp_serde::to_vec(&(&image.messages, &image.retained, &image.sessions)).unwrap();
        assert_eq!(rmp_serde::to_vec(&image).unwrap(), encoded);
        let restored: PersistentState = rmp_serde::from_slice(&encoded).unwrap();
        assert!(restored.retained_store_times.is_empty());
    }
}
