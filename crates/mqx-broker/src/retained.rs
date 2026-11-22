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
        mut visit: impl FnMut(&Arc<Message>),
    ) {
        let root = if filter.starts_with('$') {
            &mut self.dollar
        } else {
            &mut self.ordinary
        };
        // The ordinary hierarchy has an extra empty level in src/retain.c.
        // Start below it, but allow `foo/#` to include the parent `foo`.
        root.search(filter.split('/'), now, &mut visit);
    }

    pub(crate) fn expire(&mut self, now: Duration) -> bool {
        self.ordinary.expire(now) | self.dollar.expire(now)
    }
}

impl Branch {
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
        &mut self,
        mut levels: Split<'_, char>,
        now: Duration,
        visit: &mut impl FnMut(&Arc<Message>),
    ) {
        match levels.next() {
            None => self.visit_message(now, visit),
            Some("#") => {
                for child in self.children.values_mut() {
                    child.visit_tree(now, visit);
                }
                self.visit_message(now, visit);
            }
            Some("+") => {
                for child in self.children.values_mut() {
                    child.search(levels.clone(), now, visit);
                }
            }
            Some(level) => {
                if let Some(child) = self.children.get_mut(level) {
                    child.search(levels, now, visit);
                }
            }
        }
    }

    fn visit_tree(&mut self, now: Duration, visit: &mut impl FnMut(&Arc<Message>)) {
        self.visit_message(now, visit);
        for child in self.children.values_mut() {
            child.visit_tree(now, visit);
        }
    }

    fn visit_message(&mut self, now: Duration, visit: &mut impl FnMut(&Arc<Message>)) {
        // retain.c: retain__delete_expired_msg uses >=, unlike the inbox.
        self.delete_expired(now);
        if let Some(message) = &self.message {
            visit(message);
        }
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
