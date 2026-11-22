use std::{collections::BTreeMap, net::TcpListener};

use mqx_cluster::ClusterConfig;

use super::*;

struct ClusterFixture {
    brokers: [Broker; 3],
    _storage: tempfile::TempDir,
}

impl ClusterFixture {
    async fn new(config: BrokerConfig) -> Self {
        let sockets: Vec<_> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers: BTreeMap<_, _> = (1u64..)
            .zip(sockets.iter().map(|socket| socket.local_addr().unwrap()))
            .collect();
        let storage = tempfile::tempdir().unwrap();
        let make = |id| {
            let mut config = ClusterConfig::new(
                id,
                peers[&id],
                peers.clone(),
                storage.path().join(id.to_string()),
            );
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
async fn replicated_apply_routes_all_qos_to_another_nodes_transient_subscription() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let mut source = connected(a, "source", true, false).await;
    let mut sink = connected(b, "sink", true, false).await;
    sink.subscribe(&[("samples/#", Q2)], &[Q2]).await;

    source
        .send(Packet::Publish(publish("samples/temp", b"q0", Q0, 0)))
        .await;
    sink.expect(Packet::Publish(publish("samples/temp", b"q0", Q0, 0)))
        .await;
    source
        .send(Packet::Publish(publish("samples/temp", b"q1", Q1, 31)))
        .await;
    source.expect(Packet::PubAck(mid(31))).await;
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

    let mut third = connected(c, "third", false, false).await;
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
    security
        .replace_text(None, Some(b"topic read history\n".to_vec()))
        .unwrap();
    c.register_security(&security).await.unwrap();
    sink.subscribe(&[("history", Q1)], &[Q1]).await;
    sink.ping().await;
    sink.disconnect().await;
    cluster.shutdown().await;
}
