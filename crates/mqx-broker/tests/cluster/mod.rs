use std::{collections::BTreeMap, net::TcpListener};

use mqx_cluster::ClusterConfig;

use super::*;

mod external_security;

// A fixture drops its reservations before Raft takes ownership of the ports.
// Do not let another fixture reserve those same ports during the handoff.
static STARTUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct ClusterFixture {
    brokers: [Broker; 3],
    _storage: tempfile::TempDir,
}

impl ClusterFixture {
    async fn new(config: BrokerConfig) -> Self {
        let startup = STARTUP_LOCK.lock().await;
        let sockets: Vec<_> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: BTreeMap<_, _> = (1u64..)
            .zip(sockets.iter().map(|socket| socket.local_addr().unwrap()))
            .collect();
        let storage = tempfile::tempdir().unwrap();
        let packet_limit = config.max_packet_size;
        let make = |id| {
            let mut config = ClusterConfig::new(
                id,
                peers[&id],
                peers.clone(),
                storage.path().join(id.to_string()),
                mqx_cluster::ClusterSecurity::InsecurePlaintext,
            );
            config.set_packet_limit(packet_limit).unwrap();
            config.heartbeat_interval = Duration::from_millis(25);
            config.election_timeout_min = Duration::from_millis(100);
            config.election_timeout_max = Duration::from_millis(175);
            config.lease_interval = Duration::from_millis(40);
            config.lease_timeout = Duration::from_millis(240);
            config.request_timeout = Duration::from_secs(2);
            config
        };
        let configs = [make(1), make(2), make(3)];
        drop(sockets);
        let config = BrokerConfig {
            allow_anonymous: true,
            ..config
        };
        let [a, b, c] = configs;
        let (a, b, c) = tokio::try_join!(
            Broker::clustered(config.clone(), a),
            Broker::clustered(config.clone(), b),
            Broker::clustered(config, c),
        )
        .unwrap();
        drop(startup);
        Self {
            brokers: [a, b, c],
            _storage: storage,
        }
    }

    async fn shutdown(self) {
        let [a, b, c] = &self.brokers;
        tokio::try_join!(
            a.shutdown_cluster(),
            b.shutdown_cluster(),
            c.shutdown_cluster()
        )
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_limits_reach_existing_mesh_clients_and_new_connects() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let mut source = connected(a, "source", true, false).await;
    let mut sink = connected(c, "sink", true, false).await;
    sink.subscribe(&[("route/#", Q1), ("route/exact", Q1)], &[Q1, Q1])
        .await;
    source
        .send(Packet::Publish(publish("route/exact", b"old", Q0, 0)))
        .await;
    for _ in 0..2 {
        sink.expect(Packet::Publish(publish("route/exact", b"old", Q0, 0)))
            .await;
    }

    let mut limits = b.reloadable_limits();
    limits.message_size_limit = 2;
    limits.upgrade_outgoing_qos = true;
    limits.allow_duplicate_messages = false;
    limits.clientid_prefixes = Some("new-".into());
    b.reload_limits(limits).await.unwrap();

    source
        .send(Packet::Publish(publish("route/exact", b"large", Q1, 11)))
        .await;
    source.expect(Packet::PubAck(mid(11))).await;
    source
        .send(Packet::Publish(publish("route/exact", b"ok", Q0, 0)))
        .await;
    source.ping().await;
    sink.expect(Packet::Publish(publish("route/exact", b"ok", Q1, 1)))
        .await;
    sink.ping().await;
    let (mut rejected, _) = Client::spawn(c, ConnectionInfo::default());
    rejected
        .connect(request("no-prefix", true), Code::NotAuthorized, false)
        .await;

    sink.disconnect().await;
    source.disconnect().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordered_mesh_routes_qos0_and_qos1_and_raft_routes_retained_qos2() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let mut source = connected(a, "source", true, false).await;
    let mut sink = connected(b, "sink", true, false).await;
    let mut third = connected(c, "third", false, false).await;
    sink.subscribe(&[("samples/#", Q2)], &[Q2]).await;
    let proposal_count = || {
        cluster
            .brokers
            .iter()
            .map(|broker| broker.metrics().proposal_latency.count)
            .sum::<u64>()
    };
    let before_mesh = proposal_count();

    source
        .send(Packet::Publish(publish("samples/temp", b"q0", Q0, 0)))
        .await;
    sink.expect(Packet::Publish(publish("samples/temp", b"q0", Q0, 0)))
        .await;
    source
        .send(Packet::Publish(publish("samples/temp", b"q1", Q1, 31)))
        .await;
    source.expect(Packet::PubAck(mid(31))).await;
    assert_eq!(
        proposal_count(),
        before_mesh,
        "plain live publishers must not write to Raft"
    );
    sink.expect(Packet::Publish(publish("samples/temp", b"q1", Q1, 1)))
        .await;
    sink.send(Packet::PubAck(mid(1))).await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("samples/temp", b"q2 retained", Q2, 32)
        }))
        .await;
    source.expect(Packet::PubRec(mid(32))).await;
    source.send(Packet::PubRel(mid(32))).await;
    source.expect(Packet::PubComp(mid(32))).await;
    sink.expect(Packet::Publish(publish(
        "samples/temp",
        b"q2 retained",
        Q2,
        2,
    )))
    .await;
    sink.send(Packet::PubRec(mid(2))).await;
    sink.expect(Packet::PubRel(mid(2))).await;
    sink.send(Packet::PubComp(mid(2))).await;

    third.subscribe(&[("samples/#", Q1)], &[Q1]).await;
    third
        .expect(Packet::Publish(Publish {
            retain: true,
            ..publish("samples/temp", b"q2 retained", Q1, 1)
        }))
        .await;
    third.send(Packet::PubAck(mid(1))).await;
    source.disconnect().await;
    sink.disconnect().await;
    third.disconnect().await;
    cluster.shutdown().await;
}

// MQTT ACK order follows the input stream. A retained update also publishes
// live, so later mesh delivery must wait for it on every destination peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_publishers_keep_order_across_peer_and_raft_deliveries() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let mut first = connected(b, "first", true, false).await;
    let mut second = connected(c, "second", true, false).await;
    let mut durable = connected(c, "durable", false, false).await;
    first.subscribe(&[("live", Q1)], &[Q1]).await;
    second.subscribe(&[("live", Q1)], &[Q1]).await;
    durable.subscribe(&[("inbox", Q1)], &[Q1]).await;
    let mut source = connected(a, "source", true, false).await;
    let mut input = BytesMut::new();
    for publish in [
        publish("live", b"first", Q1, 21),
        Publish {
            retain: true,
            ..publish("live", b"second", Q1, 22)
        },
        publish("inbox", b"replicated", Q1, 23),
        publish("live", b"third", Q0, 0),
        publish("live", b"fourth", Q1, 24),
    ] {
        encode(&Packet::Publish(publish), &mut input).unwrap();
    }
    encode(&Packet::PingReq, &mut input).unwrap();
    source.io.write_all(&input).await.unwrap();
    for id in 21..=24 {
        source.expect(Packet::PubAck(mid(id))).await;
    }
    source.expect(Packet::PingResp).await;
    for sink in [&mut first, &mut second] {
        for packet in [
            publish("live", b"first", Q1, 1),
            publish("live", b"second", Q1, 2),
            publish("live", b"third", Q0, 0),
            publish("live", b"fourth", Q1, 3),
        ] {
            sink.expect(Packet::Publish(packet)).await;
        }
    }
    first.disconnect().await;
    second.disconnect().await;
    durable
        .expect(Packet::Publish(publish("inbox", b"replicated", Q1, 1)))
        .await;
    durable.disconnect().await;
    source.disconnect().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raised_packet_limit_reaches_both_mesh_and_durable_inboxes() {
    let cluster = ClusterFixture::new(BrokerConfig {
        max_packet_size: 3_000_000,
        ..BrokerConfig::default()
    })
    .await;
    let [a, b, c] = &cluster.brokers;
    let mut source = connected(a, "source", true, false).await;
    let mut live = connected(b, "live", true, false).await;
    let mut durable = connected(c, "durable", false, false).await;
    live.subscribe(&[("wide/live", Q1)], &[Q1]).await;
    durable.subscribe(&[("wide/durable", Q1)], &[Q1]).await;

    let bytes = Bytes::from(vec![b'!'; 2_200_000]);
    for (topic, recipient) in [("wide/live", &mut live), ("wide/durable", &mut durable)] {
        source
            .send(Packet::Publish(Publish {
                payload: bytes.clone(),
                ..publish(topic, b"", Q1, 42)
            }))
            .await;
        source.expect(Packet::PubAck(mid(42))).await;
        recipient
            .expect(Packet::Publish(Publish {
                payload: bytes.clone(),
                ..publish(topic, b"", Q1, 1)
            }))
            .await;
        recipient.send(Packet::PubAck(mid(1))).await;
    }
    source.disconnect().await;
    live.disconnect().await;
    durable.disconnect().await;
    cluster.shutdown().await;
}

// src/handle_connect.c: connect__on_authorised sends a takeover will only
// when the previous or successor connection is clean on MQTT 3.x.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_node_claim_fences_old_socket_and_preserves_mosquitto_will_rules() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let mut sink = connected(c, "sink", true, false).await;
    sink.subscribe(&[("events/#", Q0)], &[Q0]).await;
    for (index, (old_clean, new_clean)) in
        [(false, false), (false, true), (true, false), (true, true)]
            .into_iter()
            .enumerate()
    {
        let id = format!("same-{index}");
        let (mut previous, finished) = Client::spawn(a, ConnectionInfo::default());
        previous
            .connect(
                Connect {
                    will: Some(will("events/will")),
                    ..request(&id, old_clean)
                },
                Code::Accepted,
                false,
            )
            .await;
        let mut successor = connected(b, &id, new_clean, !old_clean && !new_clean).await;
        assert_eq!(previous.recv().await, None);
        finished.await.unwrap().unwrap();
        // A later publication is an ordered barrier on C, unlike PINGRESP.
        successor
            .send(Packet::Publish(publish("events/barrier", b"here", Q1, 19)))
            .await;
        successor.expect(Packet::PubAck(mid(19))).await;
        if old_clean || new_clean {
            sink.expect(Packet::Publish(publish("events/will", b"gone", Q0, 0)))
                .await;
        }
        sink.expect(Packet::Publish(publish("events/barrier", b"here", Q0, 0)))
            .await;
        successor.disconnect().await;
    }
    sink.disconnect().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_loss_publishes_wills_and_preserves_retention_and_inbox_for_another_owner() {
    let cluster = ClusterFixture::new(BrokerConfig {
        max_inflight_messages: 1,
        ..BrokerConfig::default()
    })
    .await;
    let [a, b, c] = &cluster.brokers;
    let mut subscriber = connected(a, "persistent", false, false).await;
    subscriber.subscribe(&[("data", Q1)], &[Q1]).await;
    let mut watcher = connected(b, "watcher", true, false).await;
    watcher.subscribe(&[("status", Q0)], &[Q0]).await;
    let (mut doomed, _) = Client::spawn(a, ConnectionInfo::default());
    doomed
        .connect(
            Connect {
                will: Some(LastWill {
                    retain: true,
                    ..will("status")
                }),
                ..request("lost", true)
            },
            Code::Accepted,
            false,
        )
        .await;
    let mut publisher = connected(c, "publisher", false, false).await;
    publisher
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("history", b"before", Q1, 1)
        }))
        .await;
    publisher.expect(Packet::PubAck(mid(1))).await;
    publisher
        .send(Packet::Publish(publish("data", b"unacked", Q1, 2)))
        .await;
    publisher.expect(Packet::PubAck(mid(2))).await;
    subscriber
        .expect(Packet::Publish(publish("data", b"unacked", Q1, 1)))
        .await;

    // Stop Raft before closing streams, so only the replicated node-down hook
    // can publish this will or detach the persistent inbox.
    a.shutdown_cluster().await.unwrap();
    assert_eq!(subscriber.recv().await, None);
    assert_eq!(doomed.recv().await, None);
    watcher
        .expect(Packet::Publish(publish("status", b"gone", Q0, 0)))
        .await;
    publisher
        .send(Packet::Publish(publish("data", b"offline", Q1, 3)))
        .await;
    publisher.expect(Packet::PubAck(mid(3))).await;

    let mut resumed = connected(b, "persistent", false, true).await;
    resumed
        .expect(Packet::Publish(Publish {
            dup: true,
            ..publish("data", b"unacked", Q1, 1)
        }))
        .await;
    resumed.send(Packet::PubAck(mid(1))).await;
    resumed
        .expect(Packet::Publish(publish("data", b"offline", Q1, 2)))
        .await;
    resumed.send(Packet::PubAck(mid(2))).await;
    let mut history = connected(c, "history-reader", true, false).await;
    history
        .subscribe(&[("history", Q1), ("status", Q0)], &[Q1, Q0])
        .await;
    history
        .expect(Packet::Publish(Publish {
            retain: true,
            ..publish("history", b"before", Q1, 1)
        }))
        .await;
    history
        .expect(Packet::Publish(Publish {
            retain: true,
            ..publish("status", b"gone", Q0, 0)
        }))
        .await;
    history.disconnect().await;
    resumed.disconnect().await;
    publisher.disconnect().await;
    watcher.disconnect().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_acl_reload_rechecks_original_retained_source_across_nodes() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let security =
        SecurityHandle::with_id(91, None, Some(b"topic write history\n".to_vec())).unwrap();
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            security: security.clone(),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut source, _) = Client::spawn(a, info);
    source
        .connect(request("source", true), Code::Accepted, false)
        .await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("history", b"stored", Q1, 1)
        }))
        .await;
    source.expect(Packet::PubAck(mid(1))).await;
    source.disconnect().await;
    let mut sink = connected(b, "sink", true, false).await;
    sink.subscribe(&[("history", Q1)], &[Q1]).await;
    sink.expect(Packet::Publish(Publish {
        retain: true,
        ..publish("history", b"stored", Q1, 1)
    }))
    .await;
    let install = security
        .prepare_replacement(None, Some(b"topic read history\n".to_vec()), Box::default())
        .unwrap();
    install();
    c.register_security(&security).await.unwrap();
    sink.subscribe(&[("history", Q1)], &[Q1]).await;
    sink.ping().await;
    sink.disconnect().await;
    cluster.shutdown().await;
}
