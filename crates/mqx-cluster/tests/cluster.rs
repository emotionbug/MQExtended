use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::try_join_all;
use mqx_cluster::{
    Cluster, ClusterConfig, ClusterError, NodeEvent, NodeStatus, SnapshotPolicy, StateMachine,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{Instant, sleep, timeout};

const WAIT: Duration = Duration::from_secs(6);
const LEASE: Duration = Duration::from_millis(700);

type Node = Cluster<Kv>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Insert(String, String);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Reply {
    index: u64,
    previous: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Durable {
    values: BTreeMap<String, String>,
    writes: Vec<u64>,
    events: Vec<(u64, u64, NodeStatus, Duration)>,
}

#[derive(Default)]
struct Kv {
    durable: Durable,
    restored: usize,
    applied_here: Vec<u64>,
}

impl StateMachine for Kv {
    type Command = Insert;
    type Response = Reply;

    fn apply(&mut self, index: u64, Insert(key, value): Insert) -> Reply {
        self.applied_here.push(index);
        self.durable.writes.push(index);
        Reply {
            index,
            previous: self.durable.values.insert(key, value),
        }
    }

    fn on_node_event(&mut self, event: NodeEvent) {
        self.durable
            .events
            .push((event.index, event.node_id, event.status, event.occurred_at));
    }

    fn snapshot(&self) -> Vec<u8> {
        rmp_serde::to_vec_named(&self.durable).unwrap()
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), ClusterError> {
        self.durable = rmp_serde::from_slice(bytes)
            .map_err(|error| ClusterError::Restore(error.to_string()))?;
        self.restored += 1;
        Ok(())
    }
}

fn configs(
    root: &tempfile::TempDir,
    count: u64,
    policy: SnapshotPolicy,
) -> BTreeMap<u64, ClusterConfig> {
    let sockets: Vec<_> = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let peers: BTreeMap<_, SocketAddr> = (1..=count)
        .zip(sockets.iter().map(|sock| sock.local_addr().unwrap()))
        .collect();
    peers
        .iter()
        .map(|(&id, &address)| {
            let mut config =
                ClusterConfig::new(id, address, peers.clone(), root.path().join(id.to_string()));
            config.heartbeat_interval = Duration::from_millis(35);
            config.election_timeout_min = Duration::from_millis(140);
            config.election_timeout_max = Duration::from_millis(260);
            config.lease_interval = Duration::from_millis(70);
            config.lease_timeout = LEASE;
            config.request_timeout = Duration::from_secs(3);
            config.snapshot_timeout = Duration::from_secs(4);
            config.snapshot_policy = policy.clone();
            config.snapshot_log_retention = 0;
            (id, config)
        })
        .collect()
}

async fn start(configs: &BTreeMap<u64, ClusterConfig>) -> BTreeMap<u64, Node> {
    timeout(
        WAIT,
        try_join_all(
            configs
                .values()
                .cloned()
                .map(|cfg| Cluster::start(cfg, Kv::default())),
        ),
    )
    .await
    .expect("all cluster members must start")
    .unwrap()
    .into_iter()
    .map(|node| (node.node_id(), node))
    .collect()
}

async fn stop(nodes: BTreeMap<u64, Node>) {
    timeout(WAIT, try_join_all(nodes.values().map(Cluster::shutdown)))
        .await
        .unwrap()
        .unwrap();
}

async fn until<T>(mut ready: impl FnMut() -> Option<T>) -> T {
    timeout(WAIT, async {
        loop {
            if let Some(value) = ready() {
                return value;
            }
            sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("condition did not become true before deadline")
}

async fn elected(nodes: &BTreeMap<u64, Node>) -> u64 {
    until(|| {
        let leader = nodes.values().next()?.leader()?;
        (nodes.contains_key(&leader) && nodes.values().all(|node| node.leader() == Some(leader)))
            .then_some(leader)
    })
    .await
}

async fn put(node: &Node, key: &str, value: &str) -> Reply {
    node.submit(Insert(key.into(), value.into())).await.unwrap()
}

async fn event(
    receiver: &mut broadcast::Receiver<NodeEvent>,
    node_id: u64,
    status: NodeStatus,
) -> NodeEvent {
    timeout(WAIT, async {
        loop {
            let event = receiver.recv().await.unwrap();
            if event.node_id == node_id && event.status == status {
                return event;
            }
        }
    })
    .await
    .expect("expected liveness transition")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_and_log_tail_rebuild_standalone_before_election() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = configs(&root, 1, SnapshotPolicy::LogsSinceLast(8))
        .remove(&1)
        .unwrap();
    cfg.lease_interval = Duration::from_secs(30);
    cfg.lease_timeout = Duration::from_secs(60);
    let node = Cluster::start(cfg.clone(), Kv::default()).await.unwrap();
    let mut last = 0;
    for i in 0..8 {
        let reply = put(&node, &i.to_string(), "snapshot value").await;
        assert_eq!(reply.previous, None);
        last = reply.index;
    }
    let included = until(|| node.metrics().snapshot_index).await;
    assert!(included >= 7);
    until(|| {
        node.metrics()
            .purged_index
            .filter(|index| *index >= included)
    })
    .await;
    let initial = node.read(|kv| kv.durable.clone());
    node.shutdown().await.unwrap();

    cfg.snapshot_policy = SnapshotPolicy::Never;
    let node = Cluster::start(cfg.clone(), Kv::default()).await.unwrap();
    assert_eq!(node.read(|kv| kv.durable.clone()), initial);
    let tail = put(&node, "0", "after snapshot").await;
    assert!(tail.index > included && tail.index > last);
    assert_eq!(tail.previous.as_deref(), Some("snapshot value"));
    let before_restart = node
        .linearizable_read(|kv| kv.durable.clone())
        .await
        .unwrap();
    node.shutdown().await.unwrap();

    let rebuilt = Cluster::start(cfg, Kv::default()).await.unwrap();
    rebuilt.read(|kv| {
        assert_eq!(kv.durable, before_restart);
        assert_eq!(kv.restored, 1);
        assert!(kv.applied_here.contains(&tail.index));
        assert!(kv.applied_here.iter().all(|index| *index > included));
    });
    rebuilt.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_bootstrap_forwarding_failover_and_rejoining() {
    let root = tempfile::tempdir().unwrap();
    let configs = configs(&root, 3, SnapshotPolicy::Never);
    let mut nodes = start(&configs).await;
    let old_leader = elected(&nodes).await;
    until(|| {
        nodes
            .values()
            .all(|node| {
                node.node_statuses()
                    .values()
                    .all(|status| *status == NodeStatus::Alive)
            })
            .then_some(())
    })
    .await;
    let follower = nodes
        .values()
        .find(|node| node.node_id() != old_leader)
        .unwrap();
    assert!(
        follower
            .submit_if_leader(Insert("leader only".into(), "must not be forwarded".into()))
            .await
            .unwrap()
            .is_none()
    );
    let first = put(follower, "key", "before failover").await;
    for node in nodes.values() {
        let durable = node
            .linearizable_read(|kv| kv.durable.clone())
            .await
            .unwrap();
        assert_eq!(durable.values["key"], "before failover");
        assert_eq!(durable.writes, [first.index]);
    }

    let (tx, mut received) = mpsc::unbounded_channel();
    let leader = nodes.remove(&old_leader).unwrap();
    leader
        .mesh()
        .register_handler(move |from, bytes| {
            tx.send((from, bytes.clone())).unwrap();
            async move { Ok(bytes) }
        })
        .unwrap();
    let follower = nodes.values().next().unwrap();
    let caller = follower.node_id();
    assert_eq!(
        follower
            .mesh()
            .request(old_leader, Bytes::from_static(b"request"))
            .await
            .unwrap(),
        "request"
    );
    follower
        .mesh()
        .send(old_leader, Bytes::from_static(b"notice"))
        .await
        .unwrap();
    assert_eq!(
        received.recv().await.unwrap(),
        (caller, Bytes::from_static(b"request"))
    );
    assert_eq!(
        timeout(WAIT, received.recv()).await.unwrap().unwrap(),
        (caller, Bytes::from_static(b"notice"))
    );

    let mut survivors = nodes
        .values()
        .map(Cluster::subscribe_node_events)
        .collect::<Vec<_>>();
    let started = Instant::now();
    leader.shutdown().await.unwrap();
    let second = put(follower, "key", "after failover").await;
    assert_eq!(second.previous.as_deref(), Some("before failover"));
    assert!(started.elapsed() < configs[&caller].request_timeout);
    let new_leader = elected(&nodes).await;
    assert_ne!(new_leader, old_leader);
    let leader_only = nodes[&new_leader]
        .submit_if_leader(Insert("leader only".into(), "after failover".into()))
        .await
        .unwrap()
        .expect("the new leader accepts local-only writes");
    assert_eq!(leader_only.previous, None);
    assert!(
        matches!(follower.mesh().request(old_leader, Bytes::new()).await, Err(ClusterError::Unreachable { node_id, .. }) if node_id == old_leader)
    );

    let down = event(&mut survivors[0], old_leader, NodeStatus::Down).await;
    assert_eq!(
        event(&mut survivors[1], old_leader, NodeStatus::Down).await,
        down
    );
    sleep(LEASE / 2).await;
    for receiver in &mut survivors {
        while let Ok(event) = receiver.try_recv() {
            assert_ne!(
                (event.node_id, event.status),
                (old_leader, NodeStatus::Down)
            );
        }
    }

    let restarted = Cluster::start(configs[&old_leader].clone(), Kv::default())
        .await
        .unwrap();
    let alive = event(&mut survivors[0], old_leader, NodeStatus::Alive).await;
    assert!(alive.index > down.index);
    assert_eq!(
        event(&mut survivors[1], old_leader, NodeStatus::Alive).await,
        alive
    );
    let expected = restarted
        .linearizable_read(|kv| kv.durable.clone())
        .await
        .unwrap();
    assert_eq!(
        expected.writes,
        [first.index, second.index, leader_only.index]
    );
    assert_eq!(
        expected
            .events
            .iter()
            .filter(|(_, id, status, _)| *id == old_leader && *status == NodeStatus::Down)
            .count(),
        1
    );
    assert!(expected.events.contains(&(
        down.index,
        old_leader,
        NodeStatus::Down,
        down.occurred_at,
    )));
    assert!(expected.events.contains(&(
        alive.index,
        old_leader,
        NodeStatus::Alive,
        alive.occurred_at,
    )));
    nodes.insert(old_leader, restarted);
    stop(nodes).await;

    let nodes = start(&configs).await;
    elected(&nodes).await;
    for node in nodes.values() {
        assert_eq!(
            node.linearizable_read(|kv| kv.durable.clone())
                .await
                .unwrap(),
            expected
        );
    }
    stop(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_installs_snapshot_when_its_missing_prefix_has_been_purged() {
    let root = tempfile::tempdir().unwrap();
    let configs = configs(&root, 3, SnapshotPolicy::LogsSinceLast(8));
    let mut nodes = start(&configs).await;
    let leader_id = elected(&nodes).await;
    let follower_id = *nodes.keys().find(|&&id| id != leader_id).unwrap();
    let leader = nodes[&leader_id].clone();
    // A follower may not have received any entry yet right after the election;
    // wait for one so the lag below is measured from a real log position.
    until(|| nodes[&follower_id].metrics().last_log_index).await;
    let stopped = nodes.remove(&follower_id).unwrap();
    stopped.shutdown().await.unwrap();
    let lagged_at = stopped.metrics().last_log_index.unwrap();

    let large = "a".repeat(80 * 1024);
    let important = put(&leader, "large", &large).await;
    for i in 0..24 {
        put(&leader, &i.to_string(), "checkpoint").await;
    }
    until(|| {
        leader
            .metrics()
            .purged_index
            .filter(|index| *index > lagged_at && *index >= important.index)
    })
    .await;
    let tail = put(&leader, "tail", "after compaction").await;
    let mut cfg = configs[&follower_id].clone();
    cfg.snapshot_policy = SnapshotPolicy::Never;
    let returned = Cluster::start(cfg, Kv::default()).await.unwrap();
    returned
        .linearizable_read(|kv| {
            assert_eq!(kv.durable.values["large"], large);
            assert_eq!(kv.durable.values["tail"], "after compaction");
            assert_eq!(kv.restored, 1);
            assert!(kv.durable.writes.contains(&tail.index));
            assert!(!kv.applied_here.contains(&important.index));
        })
        .await
        .unwrap();
    assert!(returned.metrics().snapshot_index.unwrap() >= important.index);
    nodes.insert(follower_id, returned);
    stop(nodes).await;
}
