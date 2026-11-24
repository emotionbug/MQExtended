use std::collections::BTreeSet;

use mqx_auth::external::Verdict;
use tokio::task::JoinSet;

use super::*;
use crate::state::{ExternalPlugins, VerdictRequest};

type Request = (VerdictTarget, Arc<[VerdictKey]>);

pub(super) struct Resolver {
    send: mpsc::UnboundedSender<Request>,
    active: BTreeMap<VerdictTarget, BTreeMap<Arc<[VerdictKey]>, bool>>,
}

impl Resolver {
    fn request(&mut self, target: VerdictTarget, mut keys: Vec<VerdictKey>) {
        keys.sort_unstable();
        keys.dedup();
        let active = self.active.entry(target).or_default();
        if let Some(dirty) = active.get_mut(keys.as_slice()) {
            // A fresh request can race the apply that completed this check.
            // Look again after it commits, not while the same check is running.
            *dirty = true;
        } else {
            let keys: Arc<[_]> = keys.into();
            if self.send.send((target, keys.clone())).is_ok() {
                active.insert(keys, false);
            }
        }
    }

    fn finish(&mut self, target: VerdictTarget, keys: &[VerdictKey]) -> bool {
        let Some(active) = self.active.get_mut(&target) else {
            return false;
        };
        let dirty = active.remove(keys).unwrap_or(false);
        if active.is_empty() {
            self.active.remove(&target);
        }
        dirty
    }
}

impl Broker {
    pub(super) fn install_external(&self, handle: &SecurityHandle) {
        if let Some((id, plugin)) = &handle.3 {
            self.read_state(|state| state.external_plugins().insert(*id, plugin.clone()));
            self.start_verdict_resolver();
        }
    }

    pub(super) fn start_verdict_resolver(&self) {
        if self.0.external_enabled.load(Ordering::Acquire) {
            return;
        }
        let plugins = self.read_state(|state| state.external_plugins().clone());
        let mut runtime = self.0.runtime.lock().unwrap();
        if runtime.verdict_resolver.is_none() {
            let (tx, rx) = mpsc::unbounded_channel();
            runtime.verdict_resolver = Some(Resolver {
                send: tx,
                active: BTreeMap::new(),
            });
            self.0.external_enabled.store(true, Ordering::Release);
            tokio::spawn(run(
                Arc::downgrade(&self.0),
                plugins,
                rx,
                self.0.shutdown.subscribe(),
            ));
        }
    }

    pub(super) async fn resolve_operation(
        &self,
        lease: &Lease,
        operation: &Operation,
    ) -> Vec<ResolvedVerdict> {
        if !matches!(
            operation,
            Operation::Receive(_)
                | Operation::ReceiveAdmitted(_)
                | Operation::ReceiveBirth { .. }
                | Operation::Subscribe(..)
                | Operation::SubscribeDollarRoot(..)
        ) {
            return Vec::new();
        }
        let now = self.now();
        let mut verdicts = self
            .resolve_requests(|state, _| state.operation_verdicts(lease, operation, now))
            .await;
        if matches!(
            operation,
            Operation::Subscribe(..) | Operation::SubscribeDollarRoot(..)
        ) && !verdicts.is_empty()
        {
            loop {
                // Preserve the order of separate checks with the same key.
                verdicts.sort_by(|a, b| a.key.cmp(&b.key));
                let additional = self
                    .resolve_requests(|state, _| {
                        state.operation_verdicts_with(lease, operation, now, &verdicts)
                    })
                    .await;
                if additional.is_empty() {
                    break;
                }
                verdicts.extend(additional);
            }
        }
        verdicts
    }

    pub(super) async fn resolve_claim(&self, claim: &Claim) -> Vec<ResolvedVerdict> {
        if claim.clean_start || claim.publisher.external.is_none() {
            return Vec::new();
        }
        self.resolve_requests(|state, now| state.claim_verdicts(claim, now))
            .await
    }

    pub(super) async fn resolve_write(
        &self,
        lease: &Lease,
        publication: &Publication,
    ) -> Vec<ResolvedVerdict> {
        self.resolve_requests(|state, now| {
            state.write_verdicts(
                lease,
                &publication.packet.topic,
                publication.packet.payload.len(),
                now,
            )
        })
        .await
    }

    async fn resolve_requests(
        &self,
        plan: impl FnOnce(&State, Duration) -> Vec<VerdictRequest>,
    ) -> Vec<ResolvedVerdict> {
        if !self.0.external_enabled.load(Ordering::Acquire) {
            return Vec::new();
        }
        let now = self.now();
        let (plugins, requests) =
            self.read_state(|state| (state.external_plugins().clone(), plan(state, now)));
        let mut verdicts = Vec::with_capacity(requests.len());
        let mut reusable = BTreeSet::new();
        for request in &requests {
            let key = match request {
                VerdictRequest::Cached(value) => &value.key,
                VerdictRequest::Missing(key) => key,
            };
            if reusable.contains(key) {
                continue;
            }
            let verdict = match request {
                VerdictRequest::Cached(value) => value.clone(),
                VerdictRequest::Missing(key) => check(&plugins, key, self.now()).await,
            };
            if requests.len() > 1 && verdict.verdict != Verdict::Error && !verdict.expires.is_zero()
            {
                reusable.insert(key);
            }
            verdicts.push(verdict);
        }
        verdicts
    }

    pub(super) fn redrive_verdicts(&self) {
        let Log::Replicated(log) = &self.0.log else {
            return;
        };
        log.cluster.read(|machine| {
            let requests = machine.state.pending_verdicts(self.now());
            if !requests.is_empty() {
                let mut runtime = self.0.runtime.lock().unwrap();
                if let Some(resolver) = &mut runtime.verdict_resolver {
                    for (target, keys) in requests {
                        if responsible(&self.0, target) {
                            resolver.request(target, keys);
                        }
                    }
                }
            }
        });
    }

    fn finish_verdict_request(&self, target: VerdictTarget, finished: &[VerdictKey]) {
        let dirty = self
            .0
            .runtime
            .lock()
            .unwrap()
            .verdict_resolver
            .as_mut()
            .unwrap()
            .finish(target, finished);
        if !dirty || !responsible(&self.0, target) {
            return;
        }
        let retry = |state: &State| {
            state
                .pending_verdicts(self.now())
                .into_iter()
                .any(|(destination, keys)| destination == target && keys == finished)
        };
        match &self.0.log {
            Log::Local { .. } => {
                let mut runtime = self.0.runtime.lock().unwrap();
                if retry(&runtime.local.as_ref().unwrap().state) {
                    runtime
                        .verdict_resolver
                        .as_mut()
                        .unwrap()
                        .request(target, finished.to_vec());
                }
            }
            Log::Replicated(log) => log.cluster.read(|machine| {
                if retry(&machine.state) {
                    self.0
                        .runtime
                        .lock()
                        .unwrap()
                        .verdict_resolver
                        .as_mut()
                        .unwrap()
                        .request(target, finished.to_vec());
                }
            }),
        }
    }
}

impl Runtime {
    pub(super) fn request_verdicts(
        &mut self,
        here: Owner,
        target: VerdictTarget,
        keys: Vec<VerdictKey>,
    ) {
        // No I/O or waits under the apply lock. The resolver handles leadership
        // changes and local work; maintenance re-drives missed cluster effects.
        if target.owner().is_none_or(|owner| owner == here)
            && let Some(resolver) = &mut self.verdict_resolver
        {
            resolver.request(target, keys);
        }
    }
}

fn responsible(inner: &Inner, target: VerdictTarget) -> bool {
    let owner = target.owner();
    match &inner.log {
        Log::Local { .. } => true,
        Log::Replicated(log) => {
            owner == Some(log.owner)
                || (log.cluster.leader() == Some(log.owner.node)
                    && owner.is_none_or(|owner| {
                        log.cluster
                            .voter_status(owner.node)
                            .is_none_or(|s| s == NodeStatus::Down)
                    }))
        }
    }
}

async fn check(plugins: &ExternalPlugins, key: &VerdictKey, started: Duration) -> ResolvedVerdict {
    let (verdict, expires) = if let Some(plugin) = plugins.get(key.plugin) {
        let result = plugin
            .authorize(&key.identity, &key.topic, key.access)
            .await;
        let expires = if result.reuse_for.is_zero() {
            Duration::ZERO
        } else {
            started.saturating_add(result.reuse_for)
        };
        (result.verdict, expires)
    } else {
        (Verdict::Error, started)
    };
    ResolvedVerdict {
        key: key.clone(),
        verdict,
        expires,
    }
}

async fn run(
    inner: Weak<Inner>,
    plugins: ExternalPlugins,
    mut requests: mpsc::UnboundedReceiver<Request>,
    mut shutdown: watch::Receiver<bool>,
) {
    if *shutdown.borrow() {
        return;
    }
    const CONCURRENCY: usize = 32;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            Some(completed) = tasks.join_next(), if !tasks.is_empty() => {
                let (target, keys): Request = completed.expect("ACL resolver task panicked");
                let Some(node) = inner.upgrade() else { return; };
                Broker(node).finish_verdict_request(target, &keys);
            }
            request = requests.recv(), if tasks.len() < CONCURRENCY => {
                let (Some((target, keys)), Some(node)) = (request, inner.upgrade()) else { return; };
                if !responsible(&node, target) {
                    // A new leader or owner may now be responsible; its
                    // maintenance tick will re-drive the parked state.
                    node.runtime.lock().unwrap().verdict_resolver.as_mut().unwrap().finish(target, &keys);
                    continue;
                }
                let plugins = plugins.clone();
                let inner = inner.clone();
                let clock = match &node.log {
                    Log::Local { started, wall_origin, .. } => Some((*started, *wall_origin)),
                    Log::Replicated(_) => None,
                };
                tasks.spawn(async move {
                    let now = || clock.map_or_else(wall_now, |(origin, wall)| wall.saturating_add(origin.elapsed()));
                    let mut verdicts = Vec::with_capacity(keys.len());
                    for key in &*keys {
                        verdicts.push(check(&plugins, key, now()).await);
                    }
                    if let Some(inner) = inner.upgrade()
                        && let Err(error) = Broker(inner).submit(Command::ResolveVerdicts { now: now(), target, verdicts }).await
                    {
                        tracing::debug!(%error, "could not commit external ACL verdicts");
                    }
                    (target, keys)
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mqx_auth::external::{
        AclAccess, AclIdentity, Authorization, BoxFuture, ExternalSecurity, Subject,
    };
    use mqx_codec::Publish;
    use std::sync::atomic::AtomicUsize;

    use crate::{inbox::Publisher, state::SubscriptionRequest};

    use super::*;

    #[derive(Default)]
    struct Acl {
        block_read: bool,
        reading: Arc<Notify>,
        reads: AtomicUsize,
        reuse_for: Duration,
    }

    impl ExternalSecurity for Acl {
        fn deny_special_chars(&self) -> bool {
            true
        }

        fn authenticate<'a>(
            &'a self,
            _: &'a str,
            _: Option<&'a str>,
            _: Option<&'a [u8]>,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async { Verdict::Allow })
        }

        fn acl_identity(&self, _: Subject<'_>) -> Option<AclIdentity> {
            Some(AclIdentity {
                client_id: None,
                username: None,
            })
        }

        fn authorize<'a>(
            &'a self,
            _: &'a AclIdentity,
            _: &'a str,
            access: AclAccess,
        ) -> BoxFuture<'a, Authorization> {
            Box::pin(async move {
                if access == AclAccess::Read {
                    self.reads.fetch_add(1, Ordering::Relaxed);
                }
                if access == AclAccess::Read && self.block_read {
                    self.reading.notify_one();
                    std::future::pending().await
                } else {
                    Authorization {
                        verdict: Verdict::Allow,
                        reuse_for: self.reuse_for,
                    }
                }
            })
        }
    }

    fn claim(id: &str, bound: bool) -> Claim {
        Claim {
            publisher: Publisher {
                id: id.into(),
                username: None,
                security: 0,
                dynamic_security: None,
                external: bound.then_some((0, Default::default())),
            },
            clean_start: false,
            bridge: false,
            max_qos: QoS::ExactlyOnce,
            will: None,
            v5: None,
            now: Duration::ZERO,
            internal_bridge: None,
            dynamic_security_revision: None,
            verdicts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn standalone_resolves_each_single_use_read_for_a_shared_identity() {
        let broker = Broker::new(BrokerConfig::default());
        let plugin = Arc::new(Acl::default());
        let handle = SecurityHandle::default().with_external(0, plugin.clone());
        let mut sinks = Vec::new();
        for id in ["one", "two"] {
            let ClaimResult::Accepted(sink, false) =
                broker.claim(&handle, claim(id, true), None).await.unwrap()
            else {
                panic!("sink claim");
            };
            assert!(matches!(
                broker
                    .act(
                        &sink,
                        Operation::subscribe(
                            vec![SubscriptionRequest::legacy((
                                "topic".into(),
                                QoS::AtLeastOnce
                            ))],
                            broker.now()
                        )
                    )
                    .await
                    .unwrap(),
                Reply::Subscribed(_)
            ));
            sinks.push(sink);
        }
        let ClaimResult::Accepted(source, false) = broker
            .claim(&SecurityHandle::default(), claim("source", false), None)
            .await
            .unwrap()
        else {
            panic!("source claim");
        };
        broker
            .receive(
                &source,
                Publication::legacy(
                    Publish {
                        topic: "topic".into(),
                        payload: Bytes::from_static(b"single use"),
                        qos: QoS::AtLeastOnce,
                        packet_id: PacketId::new(1),
                        dup: false,
                        retain: false,
                    },
                    broker.now(),
                ),
                false,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            for sink in sinks {
                loop {
                    if let Some(Outbound::Publish { id, .. }) =
                        broker.next_outbound(&sink).await.unwrap()
                    {
                        assert_eq!(id, PacketId::new(1));
                        break;
                    }
                    sink.ready.notified().await;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(plugin.reads.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn wal_replay_uses_startup_plugin_registration_and_redrives_parked_read() {
        let storage = tempfile::tempdir().unwrap();
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let cluster = ClusterConfig::new(
            1,
            address,
            BTreeMap::from([(1, address)]),
            storage.path().join("node"),
            mqx_cluster::ClusterSecurity::InsecurePlaintext,
        );
        let reading = Arc::new(Notify::new());
        let security = |block_read| {
            SecurityHandle::default().with_external(
                0,
                Arc::new(Acl {
                    block_read,
                    reading: reading.clone(),
                    reuse_for: Duration::from_secs(60),
                    ..Acl::default()
                }),
            )
        };
        let start = |handle| {
            let cluster = cluster.clone();
            async move {
                Broker::clustered_with_security(BrokerConfig::default(), cluster, &[handle])
                    .await
                    .unwrap()
            }
        };
        let sink_security = security(true);
        let broker = start(sink_security.clone()).await;
        let ClaimResult::Accepted(sink, false) = broker
            .claim(&sink_security, claim("sink", true), None)
            .await
            .unwrap()
        else {
            panic!("first sink claim");
        };
        let ClaimResult::Accepted(source, false) = broker
            .claim(&SecurityHandle::default(), claim("source", false), None)
            .await
            .unwrap()
        else {
            panic!("source claim");
        };
        assert!(matches!(
            broker
                .act(
                    &sink,
                    Operation::subscribe(
                        vec![SubscriptionRequest::legacy((
                            "topic".into(),
                            QoS::AtLeastOnce
                        ))],
                        broker.now()
                    )
                )
                .await
                .unwrap(),
            Reply::Subscribed(_)
        ));
        broker
            .act(
                &source,
                Operation::Receive(Publication::legacy(
                    Publish {
                        topic: "topic".into(),
                        payload: Bytes::from_static(b"parked across restart"),
                        qos: QoS::AtLeastOnce,
                        packet_id: PacketId::new(1),
                        dup: false,
                        retain: false,
                    },
                    broker.now(),
                )),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), reading.notified())
            .await
            .unwrap();
        broker.shutdown_cluster().await.unwrap();
        drop(broker);

        // No post-start registration: a committed Subscribe needs the plugin
        // during recovery, not just when a new transport connects afterwards.
        let sink_security = security(false);
        let resumed = start(sink_security.clone()).await;
        let ClaimResult::Accepted(sink, true) = resumed
            .claim(&sink_security, claim("sink", true), None)
            .await
            .unwrap()
        else {
            panic!("persistent sink was not recovered");
        };
        let outbound = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(outbound) = resumed.next_outbound(&sink).await.unwrap() {
                    break outbound;
                }
                sink.ready.notified().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(outbound, Outbound::Publish { delivery, id, .. }
            if id == PacketId::new(1) && delivery.message.payload == b"parked across restart".as_slice()));
        resumed.shutdown_cluster().await.unwrap();
    }
}
