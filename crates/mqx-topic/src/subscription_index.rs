use std::{collections::BTreeMap, str::Split};

use crate::{TopicError, validate_topic_filter, validate_topic_name};

/// Index of validated filters and their subscriptions, keyed at each filter.
/// Matches are visited in Mosquitto routing order, not key or QoS order.
#[derive(Debug, PartialEq, Eq)]
pub struct SubscriptionIndex<K, V> {
    ordinary: Branch<K, V>,
    dollar: Branch<K, V>,
}

#[derive(Debug, PartialEq, Eq)]
struct Branch<K, V> {
    children: BTreeMap<Box<str>, Self>,
    entries: Vec<(K, V)>,
}

impl<K, V> Default for Branch<K, V> {
    fn default() -> Self {
        Self {
            children: BTreeMap::new(),
            entries: Vec::new(),
        }
    }
}

impl<K, V> Default for SubscriptionIndex<K, V> {
    fn default() -> Self {
        Self {
            ordinary: Branch::default(),
            dollar: Branch::default(),
        }
    }
}

impl<K: Eq, V> SubscriptionIndex<K, V> {
    /// Inserts or replaces an entry. Replacement preserves insertion order.
    pub fn insert(&mut self, filter: &str, key: K, value: V) -> Result<Option<V>, TopicError> {
        validate_topic_filter(filter)?;
        let filter = c_str(filter);
        let mut branch = self.root_mut(filter);
        for level in filter.split('/') {
            if branch.children.contains_key(level) {
                branch = branch.children.get_mut(level).unwrap();
            } else {
                branch = branch.children.entry(level.into()).or_default();
            }
        }
        if let Some((_, previous)) = branch.entries.iter_mut().find(|(entry, _)| *entry == key) {
            Ok(Some(std::mem::replace(previous, value)))
        } else {
            branch.entries.push((key, value));
            Ok(None)
        }
    }

    /// Removes an entry and prunes branches with no remaining subscriptions.
    pub fn remove(&mut self, filter: &str, key: &K) -> Option<V> {
        let filter = c_str(filter);
        self.root_mut(filter).remove(filter.split('/'), key)
    }

    /// Calls `visit` for each entry matched by a valid PUBLISH topic name.
    pub fn for_each_match(
        &self,
        topic: &str,
        mut visit: impl FnMut(&K, &V),
    ) -> Result<(), TopicError> {
        validate_topic_name(topic)?;
        let topic = c_str(topic);
        let root = if topic.starts_with('$') {
            &self.dollar
        } else {
            &self.ordinary
        };
        root.visit(topic.split('/'), &mut visit);
        Ok(())
    }

    fn root_mut(&mut self, text: &str) -> &mut Branch<K, V> {
        if text.starts_with('$') {
            &mut self.dollar
        } else {
            &mut self.ordinary
        }
    }
}

impl<K: Eq, V> Branch<K, V> {
    fn remove(&mut self, mut levels: Split<'_, char>, key: &K) -> Option<V> {
        let Some(level) = levels.next() else {
            let index = self.entries.iter().position(|(entry, _)| entry == key)?;
            return Some(self.entries.remove(index).1);
        };
        let child = self.children.get_mut(level)?;
        let value = child.remove(levels, key)?;
        if child.children.is_empty() && child.entries.is_empty() {
            self.children.remove(level);
        }
        Some(value)
    }

    // Mosquitto src/subs.c: sub__search visits literal, +, then #. A
    // child's # is visited before the exact subscription at that child.
    fn visit(&self, mut levels: Split<'_, char>, visit: &mut impl FnMut(&K, &V)) {
        let level = levels.next();
        if let Some(level) = level {
            for label in [level, "+"] {
                if let Some(child) = self.children.get(label) {
                    child.visit(levels.clone(), visit);
                }
            }
        }
        if let Some(wildcard) = self.children.get("#") {
            for (key, value) in &wildcard.entries {
                visit(key, value);
            }
        }
        if level.is_none() {
            for (key, value) in &self.entries {
                visit(key, value);
            }
        }
    }
}

fn c_str(text: &str) -> &str {
    text.split_once('\0').map_or(text, |(prefix, _)| prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn index_agrees_with_the_mosquitto_matcher(
            dollar_topic in any::<bool>(),
            topic_levels in prop::collection::vec(prop_oneof![Just(""), Just("a"), Just("b")], 1..8),
            filters in prop::collection::vec(
                (any::<bool>(), prop::collection::vec(
                    prop_oneof![Just(""), Just("a"), Just("b"), Just("+")], 1..8
                ), any::<bool>()), 0..40
            )
        ) {
            let topic = if dollar_topic { format!("$d/{}", topic_levels.join("/")) } else { topic_levels.join("/") };
            prop_assume!(!topic.is_empty());
            let mut index = SubscriptionIndex::default();
            let mut expected = Vec::new();
            for (id, (dollar, levels, hash)) in filters.into_iter().enumerate() {
                let mut filter = levels.join("/");
                if dollar {
                    filter.insert_str(0, "$d/");
                }
                if hash {
                    filter.push_str("/#");
                }
                if filter.is_empty() {
                    continue;
                }
                index.insert(&filter, id, ()).unwrap();
                if crate::matches(&filter, &topic).unwrap() {
                    expected.push(id);
                }
            }
            let mut actual = Vec::new();
            index.for_each_match(&topic, |&id, ()| actual.push(id)).unwrap();
            actual.sort_unstable();
            prop_assert_eq!(actual, expected);
        }
    }

    #[test]
    fn overlap_and_replacement_preserve_mosquitto_traversal_order() {
        let mut index = SubscriptionIndex::default();
        for (filter, id) in [("#", 1), ("foo", 2), ("foo/#", 3), ("+", 4), ("foo/#", 5)] {
            index.insert(filter, id, id).unwrap();
        }
        assert_eq!(index.insert("foo/#", 3, 6).unwrap(), Some(3));
        assert_eq!(index.remove("foo/#", &5), Some(5));
        let mut order = Vec::new();
        index
            .for_each_match("foo", |_, &value| order.push(value))
            .unwrap();
        assert_eq!(order, [6, 2, 4, 1]);
    }
}
