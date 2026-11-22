use std::{str::Split, sync::Arc};

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

    pub(crate) fn visit(&self, filter: &str, mut visit: impl FnMut(&Arc<Message>)) {
        let root = if filter.starts_with('$') {
            &self.dollar
        } else {
            &self.ordinary
        };
        // The ordinary hierarchy has an extra empty level in src/retain.c.
        // Start below it, but allow `foo/#` to include the parent `foo`.
        root.search(filter.split('/'), &mut visit);
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
    fn search(&self, mut levels: Split<'_, char>, visit: &mut impl FnMut(&Arc<Message>)) {
        match levels.next() {
            None => self.visit_message(visit),
            Some("#") => {
                for child in self.children.values() {
                    child.visit_tree(visit);
                }
                self.visit_message(visit);
            }
            Some("+") => {
                for child in self.children.values() {
                    child.search(levels.clone(), visit);
                }
            }
            Some(level) => {
                if let Some(child) = self.children.get(level) {
                    child.search(levels, visit);
                }
            }
        }
    }

    fn visit_tree(&self, visit: &mut impl FnMut(&Arc<Message>)) {
        self.visit_message(visit);
        for child in self.children.values() {
            child.visit_tree(visit);
        }
    }

    fn visit_message(&self, visit: &mut impl FnMut(&Arc<Message>)) {
        if let Some(message) = &self.message {
            visit(message);
        }
    }
}
