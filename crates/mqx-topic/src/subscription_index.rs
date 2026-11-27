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
    children: LiteralChildren<K, V>,
    // Literal-only routing needs one map lookup per level, not a lookup
    // for each possible wildcard too.
    plus: Option<Box<Self>>,
    hash: Option<Box<Self>>,
    entries: Vec<(K, V)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum LiteralChildren<K, V> {
    #[default]
    Empty,
    // Keep the edge inline so a single literal doesn't allocate a B-tree node.
    Single(Box<str>, Box<Branch<K, V>>),
    Many(BTreeMap<Box<str>, Box<Branch<K, V>>>),
}

impl<K, V> Default for Branch<K, V> {
    fn default() -> Self {
        Self {
            children: LiteralChildren::Empty,
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
        Ok(self.root_mut(filter).insert(filter.split('/'), key, value))
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
    fn insert(&mut self, mut levels: Split<'_, char>, key: K, value: V) -> Option<V> {
        match levels.next() {
            Some("+") => self
                .plus
                .get_or_insert_with(Box::default)
                .insert(levels, key, value),
            Some("#") => self
                .hash
                .get_or_insert_with(Box::default)
                .insert(levels, key, value),
            Some(level) => self.children.insert(level, levels, key, value),
            None => {
                if let Some((_, previous)) =
                    self.entries.iter_mut().find(|(entry, _)| *entry == key)
                {
                    Some(std::mem::replace(previous, value))
                } else {
                    self.entries.push((key, value));
                    None
                }
            }
        }
    }

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
            self.children.remove(level, levels, key)
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && matches!(self.children, LiteralChildren::Empty)
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

impl<K: Eq, V> LiteralChildren<K, V> {
    fn get(&self, level: &str) -> Option<&Branch<K, V>> {
        match self {
            Self::Empty => None,
            Self::Single(existing, child) => (existing.as_ref() == level).then_some(child),
            Self::Many(children) => children.get(level).map(Box::as_ref),
        }
    }

    fn insert(&mut self, level: &str, levels: Split<'_, char>, key: K, value: V) -> Option<V> {
        match self {
            Self::Single(existing, child) if existing.as_ref() == level => {
                child.insert(levels, key, value)
            }
            Self::Many(children) => {
                // Borrow the lookup key so inserting under an existing edge needs
                // only one search and no key allocation.
                if let Some(child) = children.get_mut(level) {
                    child.insert(levels, key, value)
                } else {
                    children
                        .entry(level.into())
                        .or_default()
                        .insert(levels, key, value)
                }
            }
            _ => {
                let mut child = Box::<Branch<K, V>>::default();
                let previous = child.insert(levels, key, value);
                let level = level.into();
                *self = match std::mem::take(self) {
                    Self::Empty => Self::Single(level, child),
                    Self::Single(existing, sibling) => {
                        let mut children = BTreeMap::new();
                        children.insert(existing, sibling);
                        children.insert(level, child);
                        Self::Many(children)
                    }
                    Self::Many(_) => unreachable!(),
                };
                previous
            }
        }
    }

    fn remove(&mut self, level: &str, levels: Split<'_, char>, key: &K) -> Option<V> {
        match self {
            Self::Empty => None,
            Self::Single(existing, child) => {
                if existing.as_ref() != level {
                    return None;
                }
                let value = child.remove(levels, key)?;
                if child.is_empty() {
                    *self = Self::Empty;
                }
                Some(value)
            }
            Self::Many(children) => {
                let child = children.get_mut(level)?;
                let value = child.remove(levels, key)?;
                if child.is_empty() {
                    children.remove(level);
                    if children.len() == 1 {
                        let (level, child) = children.pop_first().unwrap();
                        *self = Self::Single(level, child);
                    }
                }
                Some(value)
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
        let a = "devices/a/events/current";
        let b = "devices/b/events/current";
        index.insert("devices/a", 1, 1).unwrap();
        index.insert(a, 2, 2).unwrap();
        let matching = |index: &SubscriptionIndex<_, _>, topic| {
            let mut values = Vec::new();
            index
                .for_each_match(topic, |_, &value| values.push(value))
                .unwrap();
            values
        };

        assert_eq!(matching(&index, a), [2]);
        assert_eq!(index.insert(b, 3, 3).unwrap(), None);
        assert_eq!(index.insert(b, 3, 4).unwrap(), Some(3));
        assert_eq!(matching(&index, a), [2]);
        assert_eq!(matching(&index, b), [4]);

        assert_eq!(index.remove(a, &2), Some(2));
        assert!(matching(&index, a).is_empty());
        assert_eq!(matching(&index, "devices/a"), [1]);
        assert_eq!(index.remove("devices/a", &1), Some(1));
        assert!(matching(&index, "devices/a").is_empty());
        assert_eq!(matching(&index, b), [4]);
        assert_eq!(index.remove(b, &3), Some(4));
        assert_eq!(index, SubscriptionIndex::default());
    }
}
