use mqx_auth::external::{AclAccess, Verdict};

use super::*;
use crate::external::{Scripted, connect_external, listener, send_qos1, silent};

async fn register(cluster: &ClusterFixture, plugins: &[Arc<Scripted>; 3]) -> [ConnectionInfo; 3] {
    let [a, b, c] = &cluster.brokers;
    let infos = plugins.each_ref().map(|plugin| listener(plugin.security()));
    tokio::try_join!(
        a.register_security(&infos[0].listener.security),
        b.register_security(&infos[1].listener.security),
        c.register_security(&infos[2].listener.security),
    )
    .unwrap();
    infos
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_node_delivery_resolves_write_at_ingress_and_read_at_the_session_owner() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let plugins = std::array::from_fn(|_| Scripted::new());
    let [source_info, sink_info, _] = register(&cluster, &plugins).await;
    let gate = plugins[1].delay("sink", "external/live", AclAccess::Read, Verdict::Allow);
    let mut source = connect_external(a, &source_info, "source", true, false).await;
    let mut sink = connect_external(b, &sink_info, "sink", true, false).await;
    let mut observer = connected(c, "observer", true, false).await;
    sink.subscribe(&[("external/live", Q1)], &[Q1]).await;
    observer.subscribe(&[("external/live", Q1)], &[Q1]).await;

    send_qos1(&mut source, "external/live", b"first", 11).await;
    gate.entered().await;
    observer
        .expect(Packet::Publish(publish("external/live", b"first", Q1, 1)))
        .await;
    send_qos1(&mut source, "external/live", b"second", 12).await;
    observer
        .expect(Packet::Publish(publish("external/live", b"second", Q1, 2)))
        .await;
    silent(&mut sink).await;
    gate.resolve();
    for (payload, id) in [(b"first".as_slice(), 1), (b"second".as_slice(), 2)] {
        sink.expect(Packet::Publish(publish("external/live", payload, Q1, id)))
            .await;
    }
    for (node, plugin) in plugins.iter().enumerate() {
        assert_eq!(
            plugin.count("source", "external/live", AclAccess::Write),
            usize::from(node == 0),
        );
        assert_eq!(
            plugin.count("sink", "external/live", AclAccess::Read) > 0,
            node == 1,
        );
    }

    sink.disconnect().await;
    source.disconnect().await;
    observer.disconnect().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_pipelined_write_error_keeps_prior_acks_and_stops_later_publications() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let [a, b, c] = &cluster.brokers;
    let plugins = std::array::from_fn(|_| Scripted::new());
    let [source_info, _, _] = register(&cluster, &plugins).await;
    plugins[0].set("source", "pipeline/deny", AclAccess::Write, Verdict::Deny);
    plugins[0].set("source", "pipeline/error", AclAccess::Write, Verdict::Error);
    let mut source = connect_external(a, &source_info, "source", true, false).await;
    let mut barrier = connected(b, "barrier", true, false).await;
    let mut sink = connected(c, "sink", true, false).await;
    sink.subscribe(&[("pipeline/#", Q1)], &[Q1]).await;

    let mut input = BytesMut::new();
    for (id, topic) in [
        (11, "pipeline/allow"),
        (12, "pipeline/deny"),
        (13, "pipeline/error"),
        (14, "pipeline/skipped"),
    ] {
        encode(
            &Packet::Publish(publish(topic, b"data", Q1, id)),
            &mut input,
        )
        .unwrap();
    }
    source.io.write_all(&input).await.unwrap();
    source.expect(Packet::PubAck(mid(11))).await;
    source.expect(Packet::PubAck(mid(12))).await;
    assert_eq!(source.recv().await, None);
    sink.expect(Packet::Publish(publish("pipeline/allow", b"data", Q1, 1)))
        .await;
    send_qos1(&mut barrier, "pipeline/barrier", b"after", 15).await;
    sink.expect(Packet::Publish(publish(
        "pipeline/barrier",
        b"after",
        Q1,
        2,
    )))
    .await;
    assert_eq!(
        plugins[0].count("source", "pipeline/error", AclAccess::Write),
        1
    );

    sink.disconnect().await;
    barrier.disconnect().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_redrives_a_parked_read_after_the_session_owner_dies() {
    let cluster = ClusterFixture::new(BrokerConfig::default()).await;
    let plugins = std::array::from_fn(|_| Scripted::new());
    let infos = register(&cluster, &plugins).await;
    let leader = timeout(WAIT, async {
        loop {
            if let Some(leader) = cluster.brokers[0].raft_metrics().unwrap().leader {
                break (leader - 1) as usize;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cluster did not elect a leader");
    let owner = (leader + 1) % 3;
    let ingress = (leader + 2) % 3;
    let owner_gate = plugins[owner].delay(
        "durable",
        "external/parked",
        AclAccess::Read,
        Verdict::Allow,
    );
    let leader_gate = plugins[leader].delay(
        "durable",
        "external/parked",
        AclAccess::Read,
        Verdict::Allow,
    );
    let mut sink = connect_external(
        &cluster.brokers[owner],
        &infos[owner],
        "durable",
        false,
        false,
    )
    .await;
    sink.subscribe(&[("external/parked", Q1)], &[Q1]).await;
    let mut source = connected(&cluster.brokers[ingress], "source", true, false).await;
    send_qos1(&mut source, "external/parked", b"survives", 11).await;
    owner_gate.entered().await;
    silent(&mut sink).await;
    assert_eq!(
        plugins[leader].count("durable", "external/parked", AclAccess::Read),
        0
    );

    // The owner dies with its backend request unanswered. Observe the leader's
    // replacement request before reconnecting so claim cannot trigger it.
    cluster.brokers[owner].shutdown_cluster().await.unwrap();
    assert_eq!(sink.recv().await, None);
    leader_gate.entered().await;
    leader_gate.resolve();
    let mut resumed = connect_external(
        &cluster.brokers[leader],
        &infos[leader],
        "durable",
        false,
        true,
    )
    .await;
    resumed
        .expect(Packet::Publish(publish(
            "external/parked",
            b"survives",
            Q1,
            1,
        )))
        .await;
    resumed.send(Packet::PubAck(mid(1))).await;
    send_qos1(&mut source, "external/parked", b"after", 12).await;
    resumed
        .expect(Packet::Publish(publish("external/parked", b"after", Q1, 2)))
        .await;
    resumed.ping().await;
    assert_eq!(
        plugins[ingress].count("durable", "external/parked", AclAccess::Read),
        0
    );

    owner_gate.resolve();
    resumed.disconnect().await;
    source.disconnect().await;
    cluster.shutdown().await;
}
