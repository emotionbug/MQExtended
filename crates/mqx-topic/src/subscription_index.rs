use std::{collections::BTreeMap, str::Split};

use crate::{TopicError, validate_topic_filter, validated_topic_name};

/// Index of validated filters and their subscriptions, keyed at each filter.
/// Matches are visited in Mosquitto routing order, not key or QoS order.
#[derive(Debug, PartialEq, Eq)]
pub struct SubscriptionIndex<K, V> {
    ordinary: Branch<K, V>,
    dollar: Branch<K, V>,
}

#[derive(Debug, PartialEq, Eq)]
struct Branch<K, V> {
    // Sparse literal paths shouldn't reserve space for full branches in unused B-tree slots.
    children: BTreeMap<Box<str>, Box<Self>>,
    // Literal-only routing needs one map lookup per level, not a lookup
    // for each possible wildcard too.
    plus: Option<Box<Self>>,
    hash: Option<Box<Self>>,
    entries: Vec<(K, V)>,
}

impl<K, V> Default for Branch<K, V> {
    fn default() -> Self {
        Self {
            children: BTreeMap::new(),
            plus: None,
            hash: None,
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
            let child = match level {
                "+" => branch.plus.get_or_insert_with(Box::default),
                "#" => branch.hash.get_or_insert_with(Box::default),
                _ => {
                    if branch.children.contains_key(level) {
                        branch.children.get_mut(level).unwrap()
                    } else {
                        branch.children.entry(level.into()).or_default()
                    }
                }
            };
            branch = child.as_mut();
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
        let topic = validated_topic_name(topic)?;
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
        let wildcard = match level {
            "+" => Some(&mut self.plus),
            "#" => Some(&mut self.hash),
            _ => None,
        };
        if let Some(slot) = wildcard {
            let child = slot.as_deref_mut()?;
            let value = child.remove(levels, key)?;
            if child.is_empty() {
                *slot = None;
            }
            Some(value)
        } else {
            let child = self.children.get_mut(level)?;
            let value = child.remove(levels, key)?;
            if child.is_empty() {
                self.children.remove(level);
            }
            Some(value)
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.children.is_empty()
            && self.plus.is_none()
            && self.hash.is_none()
    }

    // Mosquitto src/subs.c: sub__search visits literal, +, then #. A
    // child's # is visited before the exact subscription at that child.
    fn visit(&self, mut levels: Split<'_, char>, visit: &mut impl FnMut(&K, &V)) {
        let level = levels.next();
        if let Some(level) = level {
            if let Some(child) = self.children.get(level) {
                child.visit(levels.clone(), visit);
            }
            if let Some(child) = &self.plus {
                child.visit(levels, visit);
            }
        }
        if let Some(wildcard) = &self.hash {
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

    #[test]
    fn removing_last_wildcard_keeps_literals_and_dollar_matching_separate() {
        let mut index = SubscriptionIndex::default();
        for (filter, id) in [("a/+", 1), ("a/#", 2), ("a/", 3), ("$d/+", 4), ("#", 5)] {
            index.insert(filter, id, id).unwrap();
        }
        let matching = |index: &SubscriptionIndex<_, _>, topic| {
            let mut order = Vec::new();
            index
                .for_each_match(topic, |_, &value| order.push(value))
                .unwrap();
            order
        };
        assert_eq!(matching(&index, "a/\0not-part-of-topic/#"), [3, 1, 2, 5]);
        assert_eq!(matching(&index, "$d/"), [4]);
        assert_eq!(index.remove("a/+", &1), Some(1));
        assert_eq!(index.remove("a/#", &2), Some(2));
        assert_eq!(index.remove("#", &5), Some(5));
        assert_eq!(matching(&index, "a/"), [3]);
        assert_eq!(matching(&index, "$d/"), [4]);
        index.insert("a/+", 6, 6).unwrap();
        assert_eq!(matching(&index, "a/"), [3, 6]);
    }

    #[test]
    fn removing_literal_path_prunes_only_unused_branches() {
        let mut index = SubscriptionIndex::default();
        for (filter, id) in [
            ("devices/a", 1),
            ("devices/a/events/current", 2),
            ("devices/b/events/current", 3),
        ] {
            index.insert(filter, id, id).unwrap();
        }

        assert_eq!(index.remove("devices/a/events/current", &2), Some(2));
        let devices = &index.ordinary.children["devices"];
        assert!(devices.children["a"].children.is_empty());
        assert!(devices.children.contains_key("b"));

        assert_eq!(index.remove("devices/a", &1), Some(1));
        assert_eq!(index.remove("devices/b/events/current", &3), Some(3));
        assert_eq!(index, SubscriptionIndex::default());
    }
}
