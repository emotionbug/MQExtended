use std::future::pending;

use tokio::task::JoinSet;

use super::*;
use crate::{
    BrokerMetrics, SysTree,
    state::Store,
    sys::{Metric, NodeSample, Tick, Values},
};

impl Broker {
    /// Start the periodic broker tree before admitting clients, or update its
    /// interval on reload. The HTTP control plane is not counted as MQTT traffic.
    pub fn start_sys_tree(&self, interval: u16) {
        let initial = self.0.sys_interval.send_replace(Some(interval));
        if initial.is_some() {
            return;
        }
        if interval != 0 && !self.is_clustered() {
            self.sample_local(wall_now().as_secs(), true);
        }
        tokio::spawn(run(
            Arc::downgrade(&self.0),
            self.0.sys_interval.subscribe(),
            self.0.shutdown.subscribe(),
            interval != 0,
        ));
    }

    pub fn sys_tree(&self) -> SysTree {
        let now = self.sys_clock();
        self.read_state(|state| state.sys.snapshot(now))
    }

    /// Snapshot the subscription hierarchy displayed in response to SIGUSR2.
    pub fn subscription_tree(&self) -> String {
        self.read_state(State::subscription_tree)
    }

    /// Publish a broker event from Mosquitto's log topic hierarchy.
    pub async fn publish_log(
        &self,
        topic: &'static str,
        payload: Vec<u8>,
    ) -> Result<(), BrokerError> {
        self.submit(Command::SysLog {
            topic: topic.into(),
            payload: Bytes::from(payload),
            now: self.now(),
        })
        .await?;
        Ok(())
    }

    pub fn metrics(&self) -> BrokerMetrics {
        let mut values = self.0.traffic.snapshot();
        self.read_state(|state| state.gauges(&mut values));
        let latency = match &self.0.log {
            Log::Local { .. } => ProposalLatency::default().snapshot(),
            Log::Replicated(log) => log.proposal_latency.snapshot(),
        };
        BrokerMetrics::new(values, latency)
    }

    pub fn raft_metrics(&self) -> Option<mqx_cluster::ClusterMetrics> {
        match &self.0.log {
            Log::Local { .. } => None,
            Log::Replicated(log) => Some(log.cluster.metrics()),
        }
    }

    /// Local WAL diagnostics, absent in standalone mode or after the WAL closes.
    pub async fn wal_metrics(&self) -> Option<mqx_cluster::WalMetrics> {
        match &self.0.log {
            Log::Local { .. } => None,
            Log::Replicated(log) => log.cluster.wal_metrics().await.ok(),
        }
    }

    /// Records a successful MQTT transport socket accept, including sockets
    /// rejected before admission (Mosquitto net.c: net__socket_accept).
    pub fn record_socket_accept(&self) {
        self.0.traffic.add(Metric::Sockets, 1);
    }

    /// Tracks an admitted socket from transport handshake until it closes.
    pub fn track_socket(&self) -> SocketObservation {
        self.0.traffic.add(Metric::Connected, 1);
        SocketObservation(self.clone())
    }

    fn read_state<R>(&self, read: impl FnOnce(&State) -> R) -> R {
        match &self.0.log {
            Log::Local { .. } => {
                read(&self.0.runtime.lock().unwrap().local.as_ref().unwrap().state)
            }
            Log::Replicated(log) => log.cluster.read(|machine| read(&machine.state)),
        }
    }

    fn sys_clock(&self) -> u64 {
        if !self.is_clustered() {
            #[cfg(unix)]
            {
                use nix::time::{ClockId, clock_gettime};
                #[cfg(any(target_os = "linux", target_os = "android"))]
                let clock = clock_gettime(ClockId::CLOCK_BOOTTIME);
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                let clock = clock_gettime(ClockId::CLOCK_MONOTONIC);
                if let Ok(time) = clock {
                    return time.tv_sec() as u64;
                }
            }
        }
        // A cluster samples a shared wall-clock time base, which keeps uptime
        // continuous when leadership moves between hosts with different boot times.
        wall_now().as_secs()
    }

    fn sample_local(&self, wall: u64, startup: bool) {
        let mut runtime = self.0.runtime.lock().unwrap();
        let traffic = runtime.transport_sample(self.0.traffic.snapshot());
        let Runtime { local, live, .. } = &mut *runtime;
        let local = local.as_mut().unwrap();
        local.update_security(None);
        let mut effects = Vec::new();
        local.state.sample_sys(
            Tick {
                wall,
                now: self.sys_clock(),
                startup,
                nodes: BTreeMap::from([(
                    0,
                    NodeSample {
                        incarnation: [0; 16],
                        traffic,
                    },
                )]),
                cluster_store: None,
            },
            &mut effects,
            |store| collect_transient(live, store),
        );
        runtime.dispatch(effects, &self.0.config.load(), Owner::LOCAL, None);
    }

    pub(super) fn sample_node(&self, owner: Owner) -> NodeSample {
        let runtime = self.0.runtime.lock().unwrap();
        let mut traffic = runtime.transport_sample(self.0.traffic.snapshot());
        let mut store = Store::default();
        collect_transient(&runtime.live, &mut store);
        traffic.set(Metric::Stored, store.count());
        traffic.set(Metric::StoredBytes, store.bytes());
        NodeSample {
            incarnation: owner.incarnation,
            traffic,
        }
    }

    async fn sample_cluster(&self, log: &ReplicatedLog, wall: u64, startup: bool, interval: u64) {
        if log.cluster.leader() != Some(log.owner.node) {
            return;
        }
        let last = self.read_state(|state| state.sys.wall);
        if last.is_some_and(|last| last >= wall)
            || !(startup && last.is_none() || wall.is_multiple_of(interval))
        {
            return;
        }
        let mut nodes = BTreeMap::from([(log.owner.node, self.sample_node(log.owner))]);
        let mut requests = JoinSet::new();
        let Ok(body) = rmp_serde::to_vec(&fast::Request::SysSample) else {
            unreachable!()
        };
        let body = Bytes::from(body);
        for (node, status) in log.cluster.node_statuses() {
            if node != log.owner.node && status == NodeStatus::Alive {
                let cluster = log.cluster.clone();
                let body = body.clone();
                requests.spawn(async move {
                    let result = tokio::time::timeout(
                        Duration::from_millis(500),
                        cluster.mesh().request(node, body),
                    )
                    .await;
                    (node, result)
                });
            }
        }
        while let Some(result) = requests.join_next().await {
            if let Ok((node, Ok(Ok(body)))) = result
                && let Ok(sample) = rmp_serde::from_slice(&body)
            {
                nodes.insert(node, sample);
            }
        }
        let started = Instant::now();
        let cluster_store = Some(
            log.cluster
                .read(|machine| machine.state.cluster_store(wall, startup)),
        );
        let result = log
            .cluster
            .submit_if_leader(Command::Sys(Tick {
                wall,
                now: wall,
                startup,
                nodes,
                cluster_store,
            }))
            .await;
        log.proposal_latency.record(started.elapsed());
        if let Err(error) = result {
            tracing::debug!(%error, "$SYS tick did not complete");
        }
    }
}

/// A live MQTT listener socket, including a connection awaiting CONNECT.
pub struct SocketObservation(Broker);

impl SocketObservation {
    pub fn connection_messages(&self) -> bool {
        self.0.connection_messages()
    }
}

impl Drop for SocketObservation {
    fn drop(&mut self) {
        self.0.0.traffic.add(Metric::Connected, -1);
    }
}

impl Runtime {
    fn transport_sample(&self, mut values: Values) -> Values {
        values.add(Metric::Dropped, self.transient_drops);
        values
    }
}

fn collect_transient(live: &HashMap<Epoch, Arc<Live>>, store: &mut Store) {
    for inbox in live.values().filter_map(|live| live.inbox.as_ref()) {
        inbox
            .lock()
            .unwrap()
            .visit_messages(|message| store.visit(message));
    }
}

async fn run(
    inner: Weak<Inner>,
    mut interval: watch::Receiver<Option<u16>>,
    mut shutdown: watch::Receiver<bool>,
    startup: bool,
) {
    loop {
        let seconds = u64::from(interval.borrow_and_update().unwrap());
        let sleep = async {
            if seconds == 0 {
                pending::<()>().await;
                return;
            }
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let broker = Broker(inner);
            let wall = wall_now();
            match &broker.0.log {
                Log::Local { .. } => {
                    if wall.as_secs().is_multiple_of(seconds) {
                        broker.sample_local(wall.as_secs(), false);
                    }
                }
                Log::Replicated(log) => {
                    broker
                        .sample_cluster(log, wall.as_secs(), startup, seconds)
                        .await
                }
            }
            drop(broker);
            // Check after a real-clock step instead of assuming Tokio's
            // monotonic deadlines are aligned to the system clock forever.
            let now = wall_now();
            tokio::time::sleep(Duration::from_nanos(
                1_000_000_000 - u64::from(now.subsec_nanos()),
            ))
            .await;
        };
        tokio::select! {
            _ = sleep => if inner.strong_count() == 0 { return; },
            result = interval.changed() => if result.is_err() { return; },
            _ = shutdown.changed() => return,
        }
    }
}
