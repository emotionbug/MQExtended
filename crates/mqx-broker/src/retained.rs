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
}

impl Retained {
    pub(crate) fn for_each(&self, mut visit: impl FnMut(&Arc<Message>)) {
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
    pub(crate) fn store(&mut self, topic: &str, message: Arc<Message>) {
        let root = if topic.starts_with('$') {
            &mut self.dollar
        } else {
            &mut self.ordinary
        };
        root.store(topic.split('/'), message);
    }

    pub(crate) fn visit(
        &mut self,
        filter: &str,
        now: Duration,
        dollar_root: bool,
        mut visit: impl FnMut(&Arc<Message>) -> bool,
    ) -> bool {
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

    pub(crate) fn expire(&mut self, now: Duration) -> bool {
        self.ordinary.expire(now) | self.dollar.expire(now)
    }
}

impl Branch {
    fn for_each(&self, visit: &mut impl FnMut(&Arc<Message>)) {
        if let Some(message) = &self.message {
            visit(message);
        }
        for child in self.children.values() {
            child.for_each(visit);
        }
    }

    fn store(&mut self, mut levels: Split<'_, char>, message: Arc<Message>) -> bool {
        let Some(level) = levels.next() else {
            if message.payload.is_empty() {
                return self.message.take().is_some() && self.children.is_empty();
            }
            self.message = Some(message);
            return false;
        };
        let child = if let Some(index) = self.children.get_index_of(level) {
            self.children.get_index_mut(index).unwrap().1
        } else {
            self.children.entry(level.into()).or_default()
        };
        if child.store(levels, message) {
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

    fn delete_expired(&mut self, now: Duration) -> bool {
        let expired = self
            .message
            .as_ref()
            .and_then(|m| m.expires)
            .is_some_and(|at| at <= now);
        if expired {
            self.message = None;
        }
        expired
    }

    fn expire(&mut self, now: Duration) -> bool {
        let mut pending = false;
        for child in self.children.values_mut() {
            pending |= child.expire(now);
        }
        self.delete_expired(now);
        pending || self.message.as_ref().is_some_and(|m| m.expires.is_some())
    }
}
