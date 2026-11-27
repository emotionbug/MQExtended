use std::collections::HashMap;

use crate::persistence::{PersistentSession, PersistentState, PersistentSubscription};

use super::*;

impl State {
    pub(crate) fn can_import_persistence(&self) -> bool {
        self.last_epoch == 0
    }

    pub(super) fn apply_import_part(
        &mut self,
        offset: usize,
        bytes: Bytes,
        finish: Option<Duration>,
    ) -> Reply {
        if !self.can_import_persistence() {
            return Reply::NoChange;
        }
        // After an interrupted bootstrap, the designated node starts again
        // from the unchanged source. No records are visible until the last part.
        if offset == 0 {
            self.pending_import = Some(PendingImport::default());
        }
        let Some(pending) = self.pending_import.as_mut().filter(|p| p.length == offset) else {
            return Reply::InvalidPersistence;
        };
        pending.length += bytes.len();
        pending.parts.push(bytes);
        let Some(now) = finish else {
            return Reply::PersistenceStaged;
        };
        let Ok(mut image) = self.pending_import.take().unwrap().decode() else {
            return Reply::InvalidPersistence;
        };
        image.from_mosquitto = true;
        assert!(
            self.restore_persistence(image, now),
            "import was checked for an empty broker"
        );
        Reply::PersistenceImported
    }

    pub(crate) fn persistent_snapshot(&self, now: Duration) -> PersistentState {
        let mut output = PersistentState::default();
        let mut indexes = HashMap::new();
        let mut intern = |message: &Arc<Message>| {
            *indexes.entry(Arc::as_ptr(message)).or_insert_with(|| {
                let index = output.messages.len();
                output.messages.push(message.clone());
                index
            })
        };
        // persist_write.c: persist__retain_save omits $SYS retained values
        // but persist__client_messages_save keeps queued $SYS publications.
        self.retained.for_each_stored(|message, stored_at| {
            if !message.topic.starts_with("$SYS")
                && !Retained::expired(message, stored_at, now, self.config.retain_max_age)
            {
                if let Some(stored_at) = stored_at {
                    output
                        .retained_store_times
                        .push((output.retained.len(), stored_at));
                }
                output.retained.push(intern(message));
            }
        });
        for session in self.sessions.values() {
            let Some(inbox) = &session.inbox else {
                continue;
            };
            // persist_write.c: persist__client_save and persist__subs_save.
            if session
                .internal_bridge
                .as_ref()
                .map_or(session.clean_start, |b| b.local_clean)
            {
                continue;
            }
            let expiry_interval = session.v5.as_ref().map(|settings| settings.session_expiry);
            if expiry_interval == Some(0) {
                continue;
            }
            let mut bridge = session.internal_bridge.clone();
            if let Some(bridge) = &mut bridge {
                bridge.online = false;
            }
            let expires = session.expires.or_else(|| {
                // persist_write.c: persist__client_save starts a connected
                // client's expiry clock at save time. Native snapshots also
                // apply the server cap, as on disconnect, without changing
                // expiry for sessions already offline or for local bridges.
                if session.owner.is_some() && bridge.is_none() {
                    session_expiry_deadline(
                        now,
                        expiry_interval,
                        self.config.persistent_client_expiration,
                    )
                } else {
                    None
                }
            });
            let mut entry = PersistentSession {
                publisher: session.publisher.clone(),
                last_mid: 0,
                expiry_interval,
                expires,
                bridge,
                subscriptions: session
                    .filters
                    .iter()
                    // persist_write.c: persist__subs_save walks normal leaves
                    // (`node->subs`), not the entries in `node->shared`.
                    .filter(|(filter, _)| !filter.starts_with("$share/"))
                    .map(|(filter, entry)| PersistentSubscription {
                        filter: filter.clone(),
                        order: entry.order,
                        qos: entry.subscription.qos,
                        no_local: entry.subscription.no_local,
                        retain_as_published: entry.subscription.retain_as_published,
                        identifier: entry.subscription.identifier,
                    })
                    .collect(),
                outgoing: Vec::new(),
                incoming: Vec::new(),
            };
            inbox.persist_into(&mut entry, now, &mut intern);
            output.sessions.push(entry);
        }
        output
    }

    pub(crate) fn restore_persistence(
        &mut self,
        mut input: PersistentState,
        now: Duration,
    ) -> bool {
        if self.last_epoch != 0 {
            return false;
        }
        input.cap_message_ages(now);
        // The epoch is a replicated, durable one-time gate, even for an empty image.
        self.last_epoch += 1;
        let PersistentState {
            messages,
            retained,
            sessions,
            from_mosquitto,
            retained_store_times,
        } = input;
        let mut store_times = retained_store_times.into_iter().peekable();
        for (position, index) in retained.into_iter().enumerate() {
            let stored_at = store_times
                .next_if(|&(entry, _)| entry == position)
                .map(|(_, stored_at)| stored_at)
                .or(from_mosquitto.then_some(now));
            let message = &messages[index];
            if !Retained::expired(message, stored_at, now, self.config.retain_max_age) {
                self.store_retained(message, now, stored_at);
            }
        }
        let mut subscriptions = Vec::new();
        for mut entry in sessions {
            // Native snapshots record the save/disconnect deadline or no
            // expiry. Only Mosquitto imports can start a new clock on restore
            // (session_expiry.c: session_expiry__add_from_persistence).
            let expires = entry.expires.or_else(|| {
                if !from_mosquitto || entry.bridge.is_some() {
                    return None;
                }
                let interval = entry
                    .expiry_interval
                    .filter(|&ttl| ttl != u32::MAX)
                    .map(u64::from);
                let cap = self
                    .config
                    .persistent_client_expiration
                    .map(|ttl| ttl.as_secs());
                [interval, cap].into_iter().flatten().min().map(|ttl| {
                    Duration::from_secs(now.as_secs())
                        .saturating_add(Duration::from_secs(ttl.saturating_add(1)))
                })
            });
            if entry.expiry_interval == Some(0) || expires.is_some_and(|at| at <= now) {
                continue;
            }
            self.last_epoch += 1;
            let epoch = self.last_epoch;
            let id = entry.publisher.id.clone();
            if let Some(at) = expires {
                self.expirations.insert((at, epoch), id.clone());
            }
            subscriptions.extend(
                std::mem::take(&mut entry.subscriptions)
                    .into_iter()
                    .map(|sub| (id.clone(), sub)),
            );
            let inbox = Inbox::restore_persisted(&mut entry, &messages, &self.config, now);
            self.sessions.insert(
                id,
                Session {
                    publisher: entry.publisher,
                    epoch,
                    owner: None,
                    bridge: entry.bridge.is_some(),
                    max_qos: QoS::ExactlyOnce,
                    inbox: Some(inbox),
                    filters: BTreeMap::new(),
                    will: None,
                    expires,
                    v5: entry.expiry_interval.map(|session_expiry| SessionSettings {
                        session_expiry,
                        receive_maximum: None,
                        will_delay: 0,
                        will_expiry: 0,
                        will_properties: Vec::new(),
                    }),
                    will_at: None,
                    internal_bridge: entry.bridge,
                    clean_start: false,
                    pending: VecDeque::new(),
                },
            );
        }
        subscriptions.sort_by_key(|(_, sub)| sub.order);
        for (id, entry) in subscriptions {
            self.restore_subscription(id, entry);
        }
        self.rebuild_bridge_index();
        self.rebuild_queue_expiry();
        true
    }

    fn restore_subscription(&mut self, id: Arc<str>, entry: PersistentSubscription) {
        let Some((group, path)) = split_filter(&entry.filter) else {
            return;
        };
        if validate_topic_filter(path).is_err() {
            return;
        }
        let session = self.sessions.get_mut(&id).unwrap();
        let subscription = Subscription {
            qos: entry.qos,
            bridge: session.bridge,
            no_local: entry.no_local,
            retain_as_published: entry.retain_as_published,
            identifier: entry.identifier,
        };
        // persist_read.c: persist__restore_sub installs the routing leaf,
        // without ACL checks, retained replay or packet-ID consumption.
        if let Some(group) = group {
            let key = SharedKey {
                name: group.into(),
                filter: path.into(),
            };
            let members = &mut self
                .groups
                .entry(key.clone())
                .or_insert_with(|| {
                    self.shared.insert(path, key.name.clone(), key).unwrap();
                    self.last_subscription += 1;
                    SharedGroup {
                        order: self.last_subscription,
                        members: VecDeque::new(),
                    }
                })
                .members;
            if let Some((_, existing)) = members.iter_mut().find(|(member, _)| member == &id) {
                *existing = subscription;
            } else {
                members.push_back((id.clone(), subscription));
            }
        } else {
            if path.starts_with('$') && dollar_root(path) != "$SYS" {
                self.dollar_roots.insert(Arc::from(dollar_root(path)));
            }
            self.normal.insert(path, id, subscription).unwrap();
        }
        self.last_subscription += 1;
        session.filters.insert(
            entry.filter,
            IndexedSubscription {
                order: self.last_subscription,
                subscription,
            },
        );
    }

    pub(crate) fn flush_shutdown_wills(&mut self, now: Duration, effects: &mut Vec<Effect>) {
        // mosquitto.c: post_shutdown_cleanup calls will_delay__send_all before backup.
        while let Some((_, id)) = self.wills.first_key_value() {
            let id = id.clone();
            if let Some(will) = self.take_will(&id) {
                self.publish_will(will, now, effects);
            }
        }
    }
}
