use std::time::Duration;

use bytes::{Bytes, BytesMut};
use mqx_bridge::{BridgeConfig, Bridges, Direction, Protocol, Start, TlsFuture, Topic};
use mqx_broker::{Broker, BrokerConfig, ConnectionInfo, SecurityHandle};
use mqx_codec::v5::{
    self, ConnAck, Connect, DecodeContext, Packet, PacketId, Publish, PublishAck, QoS,
    ReasonCode as R, RetainHandling, Subscribe, Subscription, SubscriptionAck,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);
const NO_RECONNECT: Duration = Duration::from_millis(300);
const STATE: &str = "bridge-state";
const Q0: QoS = QoS::AtMostOnce;
const Q1: QoS = QoS::AtLeastOnce;

struct Client<S> {
    io: S,
    input: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    fn new(io: S) -> Self {
        Self {
            io,
            input: BytesMut::new(),
        }
    }

    async fn recv(&mut self) -> Option<Packet> {
        timeout(WAIT, async {
            loop {
                if let Some(packet) =
                    v5::decode(&mut self.input, DecodeContext::for_client(0)).unwrap()
                {
                    return Some(packet);
                }
                if self.io.read_buf(&mut self.input).await.unwrap() == 0 {
                    assert!(self.input.is_empty());
                    return None;
                }
            }
        })
        .await
        .expect("timed out waiting for MQTT packet")
    }

    async fn send(&mut self, packet: Packet) {
        let mut frame = BytesMut::new();
        v5::encode(&packet, &mut frame).unwrap();
        self.io.write_all(&frame).await.unwrap();
    }

    async fn publish_received(&mut self, topic: &str, payload: &[u8]) -> Publish {
        let packet = self.recv().await;
        let Some(Packet::Publish(publish)) = packet else {
            panic!("expected PUBLISH, received {packet:?}");
        };
        assert_eq!(publish.topic, topic);
        assert_eq!(publish.payload.as_ref(), payload);
        publish
    }
}

impl Client<DuplexStream> {
    async fn connect(broker: &Broker, id: &str) -> Self {
        let (io, server) = tokio::io::duplex(1024);
        let broker = broker.clone();
        tokio::spawn(async move {
            broker
                .serve(server, ConnectionInfo::default())
                .await
                .unwrap()
        });
        let mut client = Self::new(io);
        client
            .send(Packet::Connect(Connect {
                private_protocol_bit: false,
                clean_start: true,
                keep_alive: 0,
                properties: Vec::new(),
                client_id: id.into(),
                will: None,
                username: None,
                password: None,
            }))
            .await;
        assert!(
            matches!(client.recv().await, Some(Packet::ConnAck(ack)) if ack.reason == R::SUCCESS)
        );
        client
    }

    async fn subscribe(&mut self, filter: &str) {
        self.send(Packet::Subscribe(Subscribe {
            packet_id: PacketId::new(1).unwrap(),
            properties: Vec::new(),
            subscriptions: vec![Subscription {
                filter: filter.into(),
                qos: Q0,
                no_local: false,
                retain_as_published: false,
                retain_handling: RetainHandling::SendAlways,
            }],
        }))
        .await;
        assert!(
            matches!(self.recv().await, Some(Packet::SubAck(ack)) if ack.reasons == [R::SUCCESS])
        );
    }

    async fn publish(&mut self, id: u16, topic: &str, payload: &'static [u8]) {
        let id = PacketId::new(id).unwrap();
        self.send(Packet::Publish(Publish {
            dup: false,
            retain: false,
            qos: Q1,
            topic: topic.into(),
            packet_id: Some(id),
            properties: Vec::new(),
            payload: Bytes::from_static(payload),
        }))
        .await;
        assert!(matches!(self.recv().await, Some(Packet::PubAck(ack)) if ack.packet_id == id));
    }
}

fn broker() -> Broker {
    Broker::new(BrokerConfig {
        allow_anonymous: true,
        ..BrokerConfig::default()
    })
}

fn plain_tls<'a>(_: TcpStream, _: &'a str, _: &'a mqx_bridge::TlsConfig) -> TlsFuture<'a> {
    unreachable!("these scenarios connect over plain TCP")
}

fn start(broker: &Broker, config: BridgeConfig) -> Bridges {
    let mut bridges = Bridges::new(broker.clone(), SecurityHandle::default(), true, plain_tls);
    bridges.start(vec![config]);
    bridges
}

async fn setup() -> (TcpListener, BridgeConfig) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let mut config = BridgeConfig::new("delivery".into());
    config
        .addresses
        .push((remote.ip().to_string(), remote.port()));
    config.local_clientid = "local.delivery".into();
    config.remote_clientid = "delivery".into();
    config.protocol = Protocol::V5;
    config.notification_topic = Some(STATE.into());
    config.attempt_unsubscribe = false;
    (listener, config)
}

fn topic(filter: &str, direction: Direction) -> Topic {
    Topic {
        pattern: Some(filter.into()),
        direction,
        qos: Q1,
        local_prefix: None,
        remote_prefix: None,
        local_filter: filter.into(),
        remote_filter: filter.into(),
    }
}

async fn accept(listener: &TcpListener) -> (Client<TcpStream>, Connect) {
    let (socket, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
    let mut client = Client::new(socket);
    let Some(Packet::Connect(connect)) = client.recv().await else {
        panic!("bridge did not send CONNECT");
    };
    (client, connect)
}

async fn connack(remote: &mut Client<TcpStream>) {
    remote
        .send(Packet::ConnAck(ConnAck {
            session_present: false,
            reason: R::SUCCESS,
            properties: Vec::new(),
        }))
        .await;
}

async fn ack(remote: &mut Client<TcpStream>, publish: &Publish) {
    assert_eq!(publish.qos, Q1);
    remote
        .send(Packet::PubAck(PublishAck {
            packet_id: publish.packet_id.unwrap(),
            reason: R::SUCCESS,
            properties: Vec::new(),
        }))
        .await;
}

#[tokio::test]
async fn lazy_bridge_waits_for_a_new_enqueue_after_a_failed_retry() {
    let broker = broker();
    let (listener, mut config) = setup().await;
    config.start = Start::Lazy;
    config.threshold = 2;
    config.notifications_local_only = true;
    config.topics.push(topic("telemetry", Direction::Out));

    let mut observer = Client::connect(&broker, "observer").await;
    observer.subscribe(STATE).await;
    let mut publisher = Client::connect(&broker, "publisher").await;
    let bridges = start(&broker, config);
    let (mut remote, _) = accept(&listener).await;
    connack(&mut remote).await;
    observer.publish_received(STATE, b"0").await;
    observer.publish_received(STATE, b"1").await;
    drop(remote);
    observer.publish_received(STATE, b"0").await;

    publisher.publish(1, "telemetry", b"first").await;
    assert!(timeout(NO_RECONNECT, listener.accept()).await.is_err());
    publisher.publish(2, "telemetry", b"second").await;
    let (remote, _) = accept(&listener).await;
    drop(remote);
    observer.publish_received(STATE, b"0").await;

    // Both messages remain queued, but neither may trigger another dial.
    assert!(timeout(NO_RECONNECT, listener.accept()).await.is_err());
    publisher.publish(3, "telemetry", b"third").await;
    let (mut remote, _) = accept(&listener).await;
    connack(&mut remote).await;
    for payload in [b"first".as_slice(), b"second", b"third"] {
        let publish = remote.publish_received("telemetry", payload).await;
        assert!(!publish.dup);
        ack(&mut remote, &publish).await;
    }

    broker.shutdown();
    bridges.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_the_bridge_for_its_remote_will_and_retains_the_local_will() {
    let edge = broker();
    let (listener, config) = setup().await;
    let bridges = start(&edge, config);
    let (mut remote, connect) = accept(&listener).await;
    let will = connect.will.unwrap();
    assert_eq!(will.topic, STATE);
    assert_eq!(will.payload.as_ref(), b"0");
    assert!(will.retain);
    connack(&mut remote).await;
    let online = remote.publish_received(STATE, b"1").await;
    assert!(online.retain);
    ack(&mut remote, &online).await;
    let mut observer = Client::connect(&edge, "observer").await;
    observer.subscribe(STATE).await;
    assert!(observer.publish_received(STATE, b"1").await.retain);

    edge.shutdown();
    bridges.shutdown().await;
    assert_eq!(
        remote.recv().await,
        None,
        "DISCONNECT would cancel the remote will"
    );
    let (_, saved) = edge.persistence_snapshot(false).unwrap();
    let restored = broker();
    assert!(restored.restore_persistence(saved).await.unwrap());
    let mut observer = Client::connect(&restored, "observer").await;
    observer.subscribe(STATE).await;
    assert!(observer.publish_received(STATE, b"0").await.retain);
}

#[tokio::test]
async fn publish_size_limit_does_not_prevent_bridge_subscriptions() {
    let broker = broker();
    let (listener, mut config) = setup().await;
    const FILTER: &str = "sensors/site-a/floor-two/room-twelve/#";
    config.notifications = false;
    config.max_packet_size = 32;
    config.topics.push(topic(FILTER, Direction::In));
    config.topics.push(topic("telemetry", Direction::Out));
    let bridges = start(&broker, config);
    let (mut remote, _) = accept(&listener).await;
    connack(&mut remote).await;
    let Some(Packet::Subscribe(sub)) = remote.recv().await else {
        panic!("a long filter must not abort the bridge connection");
    };
    assert_eq!(sub.subscriptions[0].filter, FILTER);
    remote
        .send(Packet::SubAck(SubscriptionAck {
            packet_id: sub.packet_id,
            properties: Vec::new(),
            reasons: vec![R(1)],
        }))
        .await;
    let mut publisher = Client::connect(&broker, "publisher").await;
    publisher.publish(1, "telemetry", &[b'x'; 32]).await;
    publisher.publish(2, "telemetry", b"small").await;
    let small = remote.publish_received("telemetry", b"small").await;
    ack(&mut remote, &small).await;

    broker.shutdown();
    bridges.shutdown().await;
}
