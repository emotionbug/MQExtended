use std::{str::Split, sync::Arc, time::Duration};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::inbox::Message;

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Retained {
    ordinary: Branch,
    dollar: Branch,
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
        let mut count = 0;
        self.for_each(|_| count += 1);
        count
    }

    // retain.c: retain__store creates hierarchy entries before processing a
    // tombstone. Only clearing an existing retained message prunes its path.
    pub(crate) fn store(&mut self, message: &Arc<Message>, stored_at: Option<Duration>) {
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
        root.store(topic.split('/'), message, stored_at, create_path);
    }

    pub(crate) fn visit(
        &mut self,
        filter: &str,
        now: Duration,
        dollar_root: bool,
        mut visit: impl FnMut(&Arc<Message>) -> bool,
    ) -> bool {
        // The max-age policy only runs at the sweep; unlike MQTT expiry, it
        // does not need to make messages invisible at an exact deadline.
        let mut expired = Vec::new();
        let complete = self.search(filter, dollar_root, |message| {
            if message.expires.is_some_and(|at| at <= now) {
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
            root.message = None;
            root.stored_at = None;
        }
        complete
    }

    pub(crate) fn inspect(
        &self,
        filter: &str,
        now: Duration,
        dollar_root: bool,
        mut visit: impl FnMut(&Arc<Message>) -> bool,
    ) -> bool {
        self.search(filter, dollar_root, |message| {
            message.expires.is_some_and(|at| at <= now) || visit(message)
        })
    }

    fn search(
        &self,
        filter: &str,
        dollar_root: bool,
        mut visit: impl FnMut(&Arc<Message>) -> bool,
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
            let root = if filter.starts_with('$') {
                &self.dollar
            } else {
                &self.ordinary
            };
            root.search(levels, true, &mut visit)
        }
    }

    pub(crate) fn can_age(message: &Message) -> bool {
        message.expires.is_none() && !message.topic.starts_with("$SYS")
    }

    pub(crate) fn has_age_candidates(&self) -> bool {
        let mut ineligible = |message: &Arc<Message>| !Self::can_age(message);
        !self.ordinary.visit_tree(&mut ineligible) || !self.dollar.visit_tree(&mut ineligible)
    }

    pub(crate) fn forget_store_times(&mut self, persistence_changes: &mut u64) -> bool {
        self.ordinary.forget_store_times(persistence_changes)
            | self.dollar.forget_store_times(persistence_changes)
    }

    pub(crate) fn expire(
        &mut self,
        now: Duration,
        mqtt_expiry: bool,
        max_age: Option<Duration>,
        has_session: impl Fn(&str) -> bool,
        persistence_changes: &mut u64,
    ) -> bool {
        self.ordinary
            .expire(now, mqtt_expiry, max_age, &has_session, persistence_changes)
            | self
                .dollar
                .expire(now, mqtt_expiry, max_age, &has_session, persistence_changes)
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

    fn store(
        &mut self,
        mut levels: Split<'_, char>,
        message: &Arc<Message>,
        stored_at: Option<Duration>,
        create_path: bool,
    ) -> bool {
        let Some(level) = levels.next() else {
            if message.payload.is_empty() {
                self.stored_at = None;
                return self.message.take().is_some() && self.children.is_empty();
            }
            self.stored_at = stored_at.filter(|_| message.expires.is_none());
            self.message = Some(message.clone());
            return false;
        };
        let child = if let Some(index) = self.children.get_index_of(level) {
            self.children.get_index_mut(index).unwrap().1
        } else if create_path {
            self.children.entry(level.into()).or_default()
        } else {
            return false;
        };
        if child.store(levels, message, stored_at, create_path) {
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
        visit: &mut impl FnMut(&Arc<Message>) -> bool,
    ) -> bool {
        match levels.next() {
            None => self.message.as_ref().is_none_or(visit),
            Some("#") => {
                self.children.values().all(|child| child.visit_tree(visit))
                    && ((!include_leaf_for_hash && self.children.is_empty())
                        || self.message.as_ref().is_none_or(visit))
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

    fn visit_tree(&self, visit: &mut impl FnMut(&Arc<Message>) -> bool) -> bool {
        self.message.as_ref().is_none_or(&mut *visit)
            && self.children.values().all(|child| child.visit_tree(visit))
    }

    fn forget_store_times(&mut self, persistence_changes: &mut u64) -> bool {
        let mut pending = false;
        for child in self.children.values_mut() {
            pending |= child.forget_store_times(persistence_changes);
        }
        let stored_at = self.stored_at.take();
        if let Some(message) = &self.message {
            *persistence_changes += u64::from(stored_at.is_some() && Retained::can_age(message));
            pending |= message.expires.is_some();
        }
        pending
    }

    fn expire(
        &mut self,
        now: Duration,
        mqtt_expiry: bool,
        max_age: Option<Duration>,
        has_session: &impl Fn(&str) -> bool,
        persistence_changes: &mut u64,
    ) -> bool {
        let mut pending = false;
        for child in self.children.values_mut() {
            pending |= child.expire(now, mqtt_expiry, max_age, has_session, persistence_changes);
        }
        let Some(message) = &self.message else {
            return pending;
        };
        // retain.c: retain__expire drops the message and keeps the branch.
        if let Some(at) = message.expires {
            if mqtt_expiry && at <= now {
                self.message = None;
                self.stored_at = None;
            } else {
                pending |= mqtt_expiry;
            }
        } else if let Some(max_age) = max_age.filter(|_| Retained::can_age(message)) {
            let Some(stored_at) = self.stored_at else {
                self.stored_at = Some(now);
                *persistence_changes += 1;
                return true;
            };
            if now.saturating_sub(stored_at) >= max_age && !has_session(&message.source.id) {
                self.message = None;
                self.stored_at = None;
                *persistence_changes += 1;
            } else {
                pending = true;
            }
        }
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerConfig, ReloadableLimits, inbox::Publisher, persistence::PersistentState};

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

        let message = Arc::new(Message {
            source: Publisher {
                id: "source".into(),
                username: None,
                security: 0,
                dynamic_security: None,
                external: None,
            },
            topic: "retained".into(),
            payload: bytes::Bytes::from_static(b"retained payload"),
            qos: mqx_codec::QoS::AtLeastOnce,
            retain: true,
            properties: Vec::new(),
            expires: None,
        });
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
        assert_eq!(rmp_serde::from_slice::<Retained>(&encoded).unwrap(), tree);

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
