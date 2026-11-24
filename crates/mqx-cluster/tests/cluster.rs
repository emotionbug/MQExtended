use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::try_join_all;
use mqx_cluster::{
    Cluster, ClusterConfig, ClusterError, ClusterSecurity, MemberRole, NodeEvent, NodeStatus,
    SnapshotPolicy, StateMachine,
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

/// A free loopback address below the kernel's ephemeral port range.
///
/// Nodes bind their address only once `Cluster::start` runs, and a restarted
/// node binds it again. A port from `bind(0)` is free in between, so a peer's
/// outbound dial (every test keeps redialing down members) can take it and the
/// start fails with `AddrInUse`. Outbound connects never get ports outside the
/// ephemeral range, and the per-process offset keeps parallel runs apart.
fn peer_address() -> SocketAddr {
    use std::sync::atomic::{AtomicU32, Ordering};
    const FIRST: u32 = 10_000;
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let ephemeral = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u32>().ok())
        .unwrap_or(32_768);
    if ephemeral <= FIRST + 1_000 {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        return socket.local_addr().unwrap();
    }
    let span = ephemeral - FIRST;
    let offset = std::process::id().wrapping_mul(7_919) % span;
    for _ in 0..span {
        let port = FIRST + (offset + NEXT.fetch_add(1, Ordering::Relaxed)) % span;
        let port = u16::try_from(port).unwrap();
        if let Ok(socket) = TcpListener::bind(("127.0.0.1", port)) {
            return socket.local_addr().unwrap();
        }
    }
    panic!("no free port below the ephemeral range");
}

fn configs(
    root: &tempfile::TempDir,
    count: u64,
    policy: SnapshotPolicy,
) -> BTreeMap<u64, ClusterConfig> {
    let peers: BTreeMap<_, SocketAddr> = (1..=count).map(|id| (id, peer_address())).collect();
    peers
        .iter()
        .map(|(&id, &address)| {
            let mut config = ClusterConfig::new(
                id,
                address,
                peers.clone(),
                root.path().join(id.to_string()),
                ClusterSecurity::InsecurePlaintext,
            );
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

/// Knowing the leader is not enough to accept application RPCs: a follower
/// learns the leader from its first append, before it has committed the
/// membership that names its peers as voters. Production admits clients only
/// once `wait_serving` returns, so tests that use the mesh wait for it too.
async fn serving<'a>(nodes: impl IntoIterator<Item = &'a Node>) {
    timeout(
        WAIT,
        try_join_all(
            nodes
                .into_iter()
                .map(|node| async move { node.membership_control().wait_serving().await }),
        ),
    )
    .await
    .expect("every member must start serving")
    .unwrap();
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
async fn versioned_reader_restores_legacy_snapshot_and_versioned_wal_tail() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = configs(&root, 1, SnapshotPolicy::LogsSinceLast(8))
        .remove(&1)
        .unwrap();
    cfg.lease_interval = Duration::from_secs(30);
    cfg.lease_timeout = Duration::from_secs(60);
    cfg.state_format = 1;
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (path, expected) in [
            (cfg.data_dir.clone(), 0o700),
            (cfg.data_dir.join("wal"), 0o700),
            (cfg.data_dir.join("node.mpk"), 0o600),
            (cfg.data_dir.join("snapshot.mpk"), 0o600),
        ] {
            assert_eq!(
                path.metadata().unwrap().permissions().mode() & 0o777,
                expected,
                "{}",
                path.display()
            );
        }
    }
    // The first lease heartbeat can race the writes. Include its Alive
    // transition before comparing all application state across restarts.
    until(|| {
        node.read(|kv| {
            kv.durable
                .events
                .iter()
                .any(|(_, id, status, _)| *id == 1 && *status == NodeStatus::Alive)
        })
        .then_some(())
    })
    .await;
    let initial = node.read(|kv| kv.durable.clone());
    node.shutdown().await.unwrap();

    cfg.snapshot_policy = SnapshotPolicy::Never;
    cfg.state_format = 2;
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

async fn refuse_foreign_state_without_node_identity(only_snapshot: bool) {
    let root = tempfile::tempdir().unwrap();
    let policy = if only_snapshot {
        SnapshotPolicy::LogsSinceLast(2)
    } else {
        SnapshotPolicy::Never
    };
    let mut cfg = configs(&root, 1, policy).remove(&1).unwrap();
    let original = Cluster::start(cfg.clone(), Kv::default()).await.unwrap();
    let reply = put(&original, "key", "owned by node 1").await;
    if only_snapshot {
        until(|| {
            original
                .metrics()
                .snapshot_index
                .filter(|index| *index >= reply.index)
        })
        .await;
    }
    original.shutdown().await.unwrap();

    // An incomplete restore copied durable state but not the node identity.
    let identity = cfg.data_dir.join("node.mpk");
    std::fs::rename(&identity, root.path().join("original-node.mpk")).unwrap();
    if only_snapshot {
        std::fs::rename(cfg.data_dir.join("wal"), root.path().join("original-wal")).unwrap();
    }
    cfg.node_id = 2;
    cfg.peers = BTreeMap::from([(2, cfg.raft_addr)]);
    let result = Cluster::start(cfg, Kv::default()).await;
    if let Ok(node) = &result {
        node.shutdown().await.unwrap();
    }
    assert!(
        !identity.exists(),
        "assigned foreign state a new node identity"
    );
    assert!(matches!(result, Err(ClusterError::InvalidConfig(_))));
}

#[tokio::test]
async fn bootstrap_refuses_foreign_wal_without_node_identity() {
    refuse_foreign_state_without_node_identity(false).await;
}

#[tokio::test]
async fn bootstrap_refuses_foreign_snapshot_without_node_identity() {
    refuse_foreign_state_without_node_identity(true).await;
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
    let lagged_at = until(|| nodes[&follower_id].metrics().last_log_index).await;
    let stopped = nodes.remove(&follower_id).unwrap();
    stopped.shutdown().await.unwrap();

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

fn with_tls(root: &tempfile::TempDir, configs: &mut BTreeMap<u64, ClusterConfig>) {
    write_tls(root, configs, None);
}

fn write_tls(
    root: &tempfile::TempDir,
    configs: &mut BTreeMap<u64, ClusterConfig>,
    expires: Option<Duration>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let ca_cert = ca.self_signed(&key).unwrap();
    let issuer = Issuer::new(ca, key);
    let ca_file = root.path().join("ca.pem");
    std::fs::write(&ca_file, ca_cert.pem()).unwrap();
    for (&id, cfg) in configs {
        // Node identity comes from the CN, not from a DNS SAN.
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("mqx-node-{id}"));
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        if let Some(expires) = expires {
            params.not_after = rcgen::date_time_ymd(1970, 1, 1) + expires;
        }
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &issuer).unwrap();
        let cert_file = root.path().join(format!("{id}-cert.pem"));
        let key_file = root.path().join(format!("{id}-key.pem"));
        std::fs::write(&cert_file, leaf.pem()).unwrap();
        std::fs::write(&key_file, key.serialize_pem()).unwrap();
        cfg.security = ClusterSecurity::Tls {
            ca_file: ca_file.clone(),
            cert_file,
            key_file,
        };
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutually_authenticated_cluster_replicates_and_serves_mesh() {
    let root = tempfile::tempdir().unwrap();
    let mut configs = configs(&root, 3, SnapshotPolicy::Never);
    with_tls(&root, &mut configs);
    let mut nodes = start(&configs).await;
    let leader = elected(&nodes).await;
    let follower = nodes
        .values()
        .find(|node| node.node_id() != leader)
        .unwrap();
    let written = put(follower, "key", "via TLS").await;
    for node in nodes.values() {
        assert_eq!(
            node.linearizable_read(|kv| kv.durable.writes.clone())
                .await
                .unwrap(),
            [written.index]
        );
    }
    let expected = follower.node_id();
    let handled = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = handled.clone();
    nodes[&leader]
        .mesh()
        .register_handler(move |from, bytes| {
            assert_eq!(from, expected);
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async move { Ok(bytes) }
        })
        .unwrap();
    let greeting = Bytes::from_static(b"hello over TLS");
    assert_eq!(
        follower
            .mesh()
            .request(leader, greeting.clone())
            .await
            .unwrap(),
        greeting
    );
    nodes.remove(&expected).unwrap().shutdown().await.unwrap();
    let mut cfg = configs[&expected].clone();
    cfg.security = ClusterSecurity::InsecurePlaintext;
    let plaintext = Cluster::start(cfg, Kv::default()).await.unwrap();
    assert!(plaintext.mesh().request(leader, greeting).await.is_err());
    assert_eq!(handled.load(std::sync::atomic::Ordering::Relaxed), 1);
    plaintext.shutdown().await.unwrap();
    stop(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_reconnect_survives_corrupt_credentials_and_expired_leaf_rotation() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = tempfile::tempdir().unwrap();
    let mut configs = configs(&root, 3, SnapshotPolicy::Never);
    let unix_time = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let expires = unix_time() + Duration::from_secs(10);
    write_tls(&root, &mut configs, Some(expires));
    let mut nodes = start(&configs).await;
    elected(&nodes).await;
    serving(nodes.values()).await;

    fn echo(node: &Node) {
        node.mesh()
            .register_handler(|_, bytes| async move { Ok(bytes) })
            .unwrap();
    }
    async fn check_mesh(left: &Node, right: &Node) {
        let probe = Bytes::from_static(b"new peer session");
        for (client, server) in [(left, right), (right, left)] {
            let reply = client
                .mesh()
                .request(server.node_id(), probe.clone())
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "mesh {} -> {} failed: {error}",
                        client.node_id(),
                        server.node_id()
                    )
                });
            assert_eq!(reply, probe);
        }
    }
    echo(&nodes[&1]);
    echo(&nodes[&2]);
    echo(&nodes[&3]);
    check_mesh(&nodes[&1], &nodes[&2]).await;
    check_mesh(&nodes[&1], &nodes[&3]).await;

    nodes.remove(&3).unwrap().shutdown().await.unwrap();
    let ClusterSecurity::Tls { key_file, .. } = &configs[&1].security else {
        unreachable!()
    };
    std::fs::write(key_file, b"incomplete private key").unwrap();
    // Let the live node's credential check come due before forcing a full handshake.
    sleep(Duration::from_millis(1100)).await;
    let restarted = Cluster::start(configs[&3].clone(), Kv::default())
        .await
        .unwrap();
    serving([&restarted]).await;
    echo(&restarted);
    check_mesh(&nodes[&1], &restarted).await;
    restarted.shutdown().await.unwrap();

    // A different CA means neither end can pass by still using the old config.
    write_tls(&root, &mut configs, None);
    let ClusterSecurity::Tls { key_file, .. } = &configs[&2].security else {
        unreachable!()
    };
    std::fs::write(key_file, b"incomplete private key").unwrap();
    sleep(expires.saturating_sub(unix_time()) + Duration::from_secs(1)).await;
    let restarted = Cluster::start(configs[&3].clone(), Kv::default())
        .await
        .unwrap();
    // Node 3 cannot reach node 2 now, so it cannot renew a lease while node 2
    // leads. Mesh dispatch only needs node 1 in its applied membership.
    until(|| {
        let members = restarted.membership_control().status().members;
        (members.get(&1)?.role == MemberRole::Voter).then_some(())
    })
    .await;
    echo(&restarted);
    check_mesh(&nodes[&1], &restarted).await;
    // Neither side could establish these sessions again: node 2 still has A.
    check_mesh(&nodes[&1], &nodes[&2]).await;
    nodes.insert(3, restarted);
    stop(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_stays_fifo_without_blocking_raft_on_its_peer_connection() {
    let root = tempfile::tempdir().unwrap();
    let mut configs = configs(&root, 3, SnapshotPolicy::Never);
    with_tls(&root, &mut configs);
    let nodes = start(&configs).await;
    let leader = elected(&nodes).await;
    // The mesh rejects senders the leader has not yet seen as voters.
    serving(nodes.values()).await;
    let follower = nodes
        .values()
        .find(|node| node.node_id() != leader)
        .unwrap();
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let gate = release.clone();
    let (entered, mut arrivals) = mpsc::unbounded_channel();
    nodes[&leader]
        .mesh()
        .register_handler(move |_, body| {
            let entered = entered.clone();
            let gate = gate.clone();
            async move {
                entered.send(body.clone()).unwrap();
                if body == "first" {
                    gate.notified().await;
                }
                Ok(body)
            }
        })
        .unwrap();
    follower
        .mesh()
        .send(leader, Bytes::from_static(b"first"))
        .await
        .unwrap();
    assert_eq!(
        timeout(WAIT, arrivals.recv()).await.unwrap().unwrap(),
        "first"
    );
    let mesh = follower.mesh().clone();
    let next =
        tokio::spawn(async move { mesh.request(leader, Bytes::from_static(b"second")).await });
    assert_eq!(
        put(follower, "while mesh is blocked", "Raft still commits")
            .await
            .previous,
        None
    );
    assert!(
        timeout(Duration::from_millis(50), arrivals.recv())
            .await
            .is_err()
    );
    release.notify_one();
    assert_eq!(next.await.unwrap().unwrap(), "second");
    assert_eq!(
        timeout(WAIT, arrivals.recv()).await.unwrap().unwrap(),
        "second"
    );
    stop(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_packet_limit_carries_large_forwarded_commands_and_mesh_payloads() {
    let root = tempfile::tempdir().unwrap();
    let mut configs = configs(&root, 3, SnapshotPolicy::Never);
    for cfg in configs.values_mut() {
        cfg.set_packet_limit(3 * 1024 * 1024).unwrap();
    }
    let nodes = start(&configs).await;
    let leader = elected(&nodes).await;
    let follower = nodes
        .values()
        .find(|node| node.node_id() != leader)
        .unwrap();
    let value = "v".repeat(2 * 1024 * 1024 + 128);
    let written = put(follower, "large", &value).await;
    for node in nodes.values() {
        assert!(
            node.linearizable_read(
                |kv| kv.durable.values["large"] == value && kv.durable.writes == [written.index]
            )
            .await
            .unwrap()
        );
    }
    nodes[&leader]
        .mesh()
        .register_handler(|_, body| async move { Ok(body) })
        .unwrap();
    let payload = Bytes::from(value);
    assert_eq!(
        follower
            .mesh()
            .request(leader, payload.clone())
            .await
            .unwrap(),
        payload
    );
    stop(nodes).await;
}

/// `MQX_BENCH_DATA_DIR="$PWD/target" cargo test --release -p mqx-cluster --test cluster three_node_mtls_commit_throughput -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual local filesystem and mTLS throughput benchmark"]
async fn three_node_mtls_commit_throughput() {
    const CLIENTS_PER_NODE: usize = 64;
    const CLIENTS: usize = CLIENTS_PER_NODE * 3;
    const OPERATIONS: usize = 64;
    let root = match std::env::var_os("MQX_BENCH_DATA_DIR") {
        Some(parent) => tempfile::Builder::new()
            .prefix("mqx-wal-bench-")
            .tempdir_in(parent),
        None => tempfile::tempdir(),
    }
    .unwrap();
    println!("WAL benchmark data: {}", root.path().display());
    let mut configs = configs(&root, 3, SnapshotPolicy::Never);
    with_tls(&root, &mut configs);
    for cfg in configs.values_mut() {
        cfg.request_timeout = Duration::from_secs(15);
        cfg.lease_interval = Duration::from_secs(1);
        cfg.lease_timeout = Duration::from_secs(5);
        cfg.heartbeat_interval = Duration::from_millis(100);
        cfg.election_timeout_min = Duration::from_millis(500);
        cfg.election_timeout_max = Duration::from_secs(1);
    }
    let nodes = start(&configs).await;
    elected(&nodes).await;
    for node in nodes.values() {
        put(node, "warm-up", "ready").await;
    }
    let mut before = BTreeMap::new();
    for (&id, node) in &nodes {
        node.linearizable_read(|_| ()).await.unwrap();
        before.insert(id, node.wal_metrics().await.unwrap());
    }
    let start = Instant::now();
    let jobs = (0..CLIENTS)
        .map(|client| {
            let node = nodes[&((client % nodes.len()) as u64 + 1)].clone();
            tokio::spawn(async move {
                let key = format!("client-{client}");
                let mut samples = Vec::with_capacity(OPERATIONS);
                for _ in 0..OPERATIONS {
                    let started = Instant::now();
                    put(&node, &key, "payload").await;
                    samples.push(started.elapsed());
                }
                samples
            })
        })
        .collect::<Vec<_>>();
    let mut samples: Vec<_> = try_join_all(jobs)
        .await
        .unwrap()
        .into_iter()
        .flatten()
        .collect();
    let elapsed = start.elapsed();
    samples.sort_unstable();
    let p = |percent: usize| samples[(samples.len() - 1) * percent / 100].as_secs_f64() * 1000.0;
    println!(
        "mTLS, 3 nodes, {CLIENTS} clients: {} commits in {:.3}s, {:.1} commits/s; latency p50 {:.2}ms p95 {:.2}ms p99 {:.2}ms",
        samples.len(),
        elapsed.as_secs_f64(),
        samples.len() as f64 / elapsed.as_secs_f64(),
        p(50),
        p(95),
        p(99),
    );
    for (id, node) in &nodes {
        node.linearizable_read(|kv| {
            let writes = &kv.durable.writes;
            assert_eq!(writes.len(), CLIENTS * OPERATIONS + nodes.len());
            assert!(writes.windows(2).all(|pair| pair[0] < pair[1]));
        })
        .await
        .unwrap();
        let after = node.wal_metrics().await.unwrap();
        let entries = after.appended_entries - before[id].appended_entries;
        let syncs = after.sync_batches - before[id].sync_batches;
        println!(
            "node {id}: {entries} WAL entries / {syncs} sync batches = {:.2} entries/sync batch",
            entries as f64 / syncs as f64
        );
    }
    stop(nodes).await;
}

fn expanding_configs(
    root: &tempfile::TempDir,
    policy: SnapshotPolicy,
) -> BTreeMap<u64, ClusterConfig> {
    let mut configs = configs(root, 5, policy);
    for (&id, config) in &mut configs {
        config.join = id > 3;
        if !config.join {
            config.peers.retain(|id, _| *id <= 3);
        }
    }
    configs
}

fn request_membership(
    nodes: &BTreeMap<u64, Node>,
    generation: u64,
    peers: &BTreeMap<u64, SocketAddr>,
) {
    for node in nodes.values() {
        node.membership_control()
            .configure(generation, peers.clone())
            .unwrap();
    }
}

// Separate process so the replacement leaves a real crash WAL, without a final flush.
#[tokio::test]
#[ignore = "subprocess for the replacement test"]
async fn replacement_follower_process() {
    let Some(data_dir) = std::env::var_os("MQX_TEST_CRASH_DATA_DIR") else {
        return;
    };
    let peers = std::env::var("MQX_TEST_CRASH_PEERS")
        .unwrap()
        .split(',')
        .map(|pair| {
            let (id, address) = pair.split_once('=').unwrap();
            (id.parse().unwrap(), address.parse().unwrap())
        })
        .collect::<BTreeMap<u64, SocketAddr>>();
    let mut config = ClusterConfig::new(
        2,
        peers[&2],
        peers,
        data_dir.into(),
        ClusterSecurity::InsecurePlaintext,
    );
    config.lease_interval = Duration::from_millis(70);
    let _node = Node::start(config, Kv::default()).await.unwrap();
    std::future::pending::<()>().await;
}

struct FollowerProcess(std::process::Child);

impl Drop for FollowerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaces_a_killed_voter_without_stopping_writes_and_refuses_its_wal() {
    let root = tempfile::tempdir().unwrap();
    let configs = expanding_configs(&root, SnapshotPolicy::LogsSinceLast(8));
    let mut nodes = start(&BTreeMap::from([
        (1, configs[&1].clone()),
        (3, configs[&3].clone()),
    ]))
    .await;
    let leader = nodes[&elected(&nodes).await].clone();
    let peers = configs[&2]
        .peers
        .iter()
        .map(|(id, addr)| format!("{id}={addr}"))
        .collect::<Vec<_>>()
        .join(",");
    let crashed = FollowerProcess(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "replacement_follower_process"])
            .env("MQX_TEST_CRASH_DATA_DIR", &configs[&2].data_dir)
            .env("MQX_TEST_CRASH_PEERS", peers)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    until(|| (leader.node_statuses().get(&2) == Some(&NodeStatus::Alive)).then_some(())).await;
    let old_value = put(&leader, "retained", "before loss").await;
    drop(crashed);
    for i in 0..20 {
        put(&leader, &format!("before-replacement-{i}"), "committed").await;
    }
    until(|| {
        leader
            .metrics()
            .purged_index
            .filter(|index| *index >= old_value.index)
    })
    .await;
    let desired = BTreeMap::from([
        (1, configs[&1].raft_addr),
        (3, configs[&3].raft_addr),
        (4, configs[&4].raft_addr),
    ]);
    request_membership(&nodes, 1, &desired);
    until(|| {
        leader
            .membership_control()
            .status()
            .members
            .get(&4)
            .filter(|member| member.role == MemberRole::Learner)
            .cloned()
    })
    .await;
    put(&leader, "still-writes", "before learner started").await;
    let mut join = configs[&4].clone();
    join.snapshot_policy = SnapshotPolicy::Never;
    let replacement = Node::start(join, Kv::default()).await.unwrap();
    timeout(WAIT, async {
        for i in 0.. {
            put(&leader, &format!("during-replacement-{i}"), "committed").await;
            if replacement.members() == desired {
                break;
            }
            sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .unwrap();
    timeout(WAIT, replacement.membership_control().wait_serving())
        .await
        .unwrap()
        .unwrap();
    assert!(replacement.metrics().snapshot_index.unwrap() >= old_value.index);
    replacement
        .linearizable_read(|kv| {
            assert_eq!(kv.durable.values["retained"], "before loss");
            assert_eq!(kv.durable.values["still-writes"], "before learner started");
            assert!(kv.restored > 0);
        })
        .await
        .unwrap();
    put(&replacement, "still-writes", "after promotion").await;
    assert!(matches!(
        Node::start(configs[&2].clone(), Kv::default()).await,
        Err(ClusterError::Removed(2))
    ));
    assert!(matches!(
        leader
            .membership_control()
            .configure(2, configs[&2].peers.clone()),
        Err(ClusterError::Removed(2))
    ));
    nodes.insert(4, replacement);
    stop(nodes).await;
    // Old cluster_peer lines on restart must not undo the committed change.
    let nodes = start(&BTreeMap::from([
        (1, configs[&1].clone()),
        (3, configs[&3].clone()),
        (4, configs[&4].clone()),
    ]))
    .await;
    let leader = &nodes[&elected(&nodes).await];
    assert_eq!(
        put(leader, "still-writes", "after restart")
            .await
            .previous
            .as_deref(),
        Some("after promotion")
    );
    assert_eq!(leader.members(), desired);
    assert!(leader.membership_control().status().retired.contains(&2));
    stop(nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adds_mtls_voters_then_refuses_a_quorum_losing_removal() {
    let root = tempfile::tempdir().unwrap();
    let mut configs = expanding_configs(&root, SnapshotPolicy::Never);
    with_tls(&root, &mut configs);
    let initial = configs
        .iter()
        .filter(|(id, _)| **id <= 3)
        .map(|(&id, config)| (id, config.clone()))
        .collect();
    let mut nodes = start(&initial).await;
    let leader_id = elected(&nodes).await;
    let leader = nodes[&leader_id].clone();
    let desired = configs[&4].peers.clone();
    for id in [4, 5] {
        nodes.insert(
            id,
            Node::start(configs[&id].clone(), Kv::default())
                .await
                .unwrap(),
        );
        assert!(!nodes[&id].membership_control().is_serving());
    }
    request_membership(&nodes, 1, &desired);
    until(|| {
        nodes
            .values()
            .all(|node| node.members() == desired)
            .then_some(())
    })
    .await;
    put(&nodes[&5], "healthy", "five voters").await;
    for id in [4, 5] {
        nodes.remove(&id).unwrap().shutdown().await.unwrap();
    }
    // The existing five-voter group has a quorum; this target would not.
    request_membership(
        &nodes,
        2,
        &BTreeMap::from([
            (leader_id, desired[&leader_id]),
            (4, desired[&4]),
            (5, desired[&5]),
        ]),
    );
    until(|| {
        leader
            .membership_control()
            .status()
            .reconciliation_error
            .filter(|error| error.contains("would lose quorum"))
    })
    .await;
    assert_eq!(leader.members(), desired);
    put(&leader, "healthy", "unsafe request did not commit").await;

    let remove = nodes.keys().copied().find(|id| *id != leader_id).unwrap();
    let target: BTreeMap<_, _> = desired
        .into_iter()
        .filter(|(id, _)| *id != remove && *id != 4 && *id != 5)
        .collect();
    let removed = nodes[&remove].membership_control();
    request_membership(&nodes, 3, &target);
    timeout(WAIT, removed.wait_removed()).await.unwrap();
    assert!(!removed.is_serving());
    assert!(
        matches!(nodes[&remove].submit(Insert("unsafe".into(), "removed".into())).await, Err(ClusterError::Removed(id)) if id == remove)
    );
    assert_eq!(leader.members(), target);
    put(&leader, "healthy", "after safe removal").await;
    stop(nodes).await;
}

struct NextSchema(Kv);

impl StateMachine for NextSchema {
    type Command = Insert;
    type Response = Reply;

    const WRITE_VERSION: u16 = 2;

    fn supports_version(version: u16) -> bool {
        matches!(version, 1 | 2)
    }

    fn apply(&mut self, index: u64, command: Insert) -> Reply {
        self.0.apply(index, command)
    }

    fn snapshot(&self) -> Vec<u8> {
        self.0.snapshot()
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), ClusterError> {
        self.0.restore(bytes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_readers_refuse_new_payloads_without_losing_old_writes() {
    let root = tempfile::tempdir().unwrap();
    let configs = configs(&root, 3, SnapshotPolicy::Never);
    let nodes = start(&BTreeMap::from([
        (1, configs[&1].clone()),
        (2, configs[&2].clone()),
    ]))
    .await;
    let leader = &nodes[&elected(&nodes).await];
    let newer = Cluster::start(configs[&3].clone(), NextSchema(Kv::default()))
        .await
        .unwrap();
    timeout(WAIT, newer.membership_control().wait_serving())
        .await
        .unwrap()
        .unwrap();
    let error = newer
        .submit(Insert("future".into(), "must not commit".into()))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ClusterError::UnsupportedVersion {
            kind: "application command",
            version: 2
        }
    ));
    put(leader, "old", "committed").await;
    newer
        .linearizable_read(|state| {
            assert!(!state.0.durable.values.contains_key("future"));
            assert_eq!(state.0.durable.values["old"], "committed");
        })
        .await
        .unwrap();
    newer.shutdown().await.unwrap();
    stop(nodes).await;
}
