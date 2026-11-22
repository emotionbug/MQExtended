use std::{sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use mqx_auth::AclFile;
use mqx_broker::{
    Broker, BrokerConfig, BrokerError, ConnectionInfo, ListenerPolicy, SecurityHandle,
};
use mqx_codec::v5::{
    self, ConnAck, Connect, DecodeContext, LastWill, Packet, PacketId, Property as P, Publish,
    PublishAck, QoS, ReasonCode as R, ReasonProperties, RetainHandling, Subscribe, Subscription,
    SubscriptionAck, Unsubscribe,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinHandle,
    time::{advance, timeout},
};

const Q0: QoS = QoS::AtMostOnce;
const Q1: QoS = QoS::AtLeastOnce;
const Q2: QoS = QoS::ExactlyOnce;
const WAIT: Duration = Duration::from_secs(5);

struct Client {
    io: DuplexStream,
    input: BytesMut,
    server: JoinHandle<Result<(), BrokerError>>,
}

impl Client {
    fn open(broker: &Broker, info: ConnectionInfo) -> Self {
        let (io, peer) = tokio::io::duplex(64 * 1024);
        let broker = broker.clone();
        Self {
            io,
            input: BytesMut::new(),
            server: tokio::spawn(async move { broker.serve(peer, info).await }),
        }
    }

    async fn send(&mut self, packet: Packet) {
        let mut raw = BytesMut::new();
        v5::encode(&packet, &mut raw).unwrap();
        self.io.write_all(&raw).await.unwrap();
    }

    async fn next_packet(&mut self) -> Option<Packet> {
        loop {
            if let Some(packet) = v5::decode(&mut self.input, DecodeContext::for_client(0)).unwrap()
            {
                return Some(packet);
            }
            if self.io.read_buf(&mut self.input).await.unwrap() == 0 {
                assert!(self.input.is_empty());
                return None;
            }
        }
    }

    async fn next(&mut self) -> Option<Packet> {
        timeout(WAIT, self.next_packet()).await.unwrap()
    }

    async fn expect(&mut self, packet: Packet) {
        assert_eq!(self.next().await, Some(packet));
    }

    async fn silent(&mut self) {
        assert!(
            timeout(Duration::from_millis(10), self.next_packet())
                .await
                .is_err()
        );
    }

    async fn connect(&mut self, connect: Connect) -> ConnAck {
        self.send(Packet::Connect(connect)).await;
        let Some(Packet::ConnAck(ack)) = self.next().await else {
            panic!("expected CONNACK");
        };
        ack
    }

    async fn subscribe(&mut self, sub: Subscription, properties: Vec<P>) {
        let qos = sub.qos;
        self.send(Packet::Subscribe(Subscribe {
            packet_id: mid(1),
            subscriptions: vec![sub],
            properties,
        }))
        .await;
        self.expect(Packet::SubAck(SubscriptionAck {
            packet_id: mid(1),
            properties: vec![],
            reasons: vec![R(qos as u8)],
        }))
        .await;
    }

    async fn disconnect(mut self, reason: R, properties: Vec<P>) {
        self.send(disc(reason, properties)).await;
        assert_eq!(self.next().await, None);
        self.server.await.unwrap().unwrap();
    }

    async fn close(self) {
        drop(self.io);
        self.server.await.unwrap().unwrap();
    }
}

fn broker(config: BrokerConfig) -> Broker {
    Broker::new(BrokerConfig {
        allow_anonymous: true,
        ..config
    })
}

fn mid(id: u16) -> PacketId {
    PacketId::new(id).unwrap()
}

fn request(id: &str) -> Connect {
    Connect {
        client_id: id.to_owned(),
        clean_start: true,
        keep_alive: 0,
        private_protocol_bit: false,
        properties: vec![],
        will: None,
        username: None,
        password: None,
    }
}

fn sub(filter: &str, qos: QoS) -> Subscription {
    Subscription {
        filter: filter.to_owned(),
        qos,
        no_local: false,
        retain_as_published: false,
        retain_handling: RetainHandling::SendAlways,
    }
}

fn publish(topic: &str, payload: &'static [u8], qos: QoS, id: u16) -> Publish {
    Publish {
        dup: false,
        retain: false,
        qos,
        topic: topic.into(),
        payload: Bytes::from_static(payload),
        packet_id: (qos != Q0).then(|| mid(id)),
        properties: vec![],
    }
}

fn disc(reason: R, properties: Vec<P>) -> Packet {
    Packet::Disconnect(ReasonProperties { reason, properties })
}
fn ack(id: u16, reason: R) -> PublishAck {
    PublishAck {
        packet_id: mid(id),
        reason,
        properties: vec![],
    }
}

async fn connected(broker: &Broker, connect: Connect, present: bool) -> Client {
    let mut client = Client::open(broker, ConnectionInfo::default());
    let ack = client.connect(connect).await;
    assert_eq!((ack.reason, ack.session_present), (R::SUCCESS, present));
    client
}

// 12-prop-assigned-client-identifier.py; 12-prop-server-keepalive.py;
// src/send_connack.c: send__connack and src/property_broker.c: property__process_connect.
#[tokio::test(start_paused = true)]
async fn connack_orders_limits_and_assigns_id_without_echoing_client_properties() {
    let broker = broker(BrokerConfig {
        max_keepalive: 2,
        max_inflight_messages: 7,
        max_packet_size: 512,
        retain_available: false,
        auto_id_prefix: "mapped-".into(),
        ..BrokerConfig::default()
    });
    let mut client = Client::open(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                max_topic_alias: 3,
                max_qos: Q1,
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    let ack = client
        .connect(Connect {
            clean_start: false,
            properties: vec![
                P::RequestProblemInformation(0),
                P::RequestResponseInformation(1),
                P::UserProperty("client".into(), "only".into()),
            ],
            ..request("")
        })
        .await;
    assert_eq!(ack.reason, R::SUCCESS);
    assert!(!ack.session_present);
    let [
        P::ServerKeepAlive(2),
        P::TopicAliasMaximum(3),
        P::AssignedClientIdentifier(id),
        P::RetainAvailable(0),
        P::MaximumPacketSize(512),
        P::ReceiveMaximum(7),
        P::MaximumQos(1),
    ] = &ack.properties[..]
    else {
        panic!("unexpected CONNACK properties: {:?}", ack.properties)
    };
    let suffix = id.strip_prefix("mapped-").unwrap();
    assert_eq!(suffix.len(), 36);
    assert!(
        suffix
            .bytes()
            .enumerate()
            .all(|(index, b)| if [8, 13, 18, 23].contains(&index) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
            })
    );
    advance(Duration::from_secs(3)).await;
    assert_eq!(client.next().await, None, "keepalive.c: no MQTT DISCONNECT");
}

// 09-auth-bad-method.py; src/handle_auth.c: handle__auth.
#[tokio::test]
async fn authentication_without_a_plugin_never_enters_an_auth_exchange() {
    let broker = broker(BrokerConfig::default());
    let mut bad = Client::open(&broker, ConnectionInfo::default());
    let ack = bad
        .connect(Connect {
            properties: vec![P::AuthenticationMethod("unsupported".into())],
            ..request("bad")
        })
        .await;
    assert_eq!(
        ack,
        ConnAck {
            session_present: false,
            reason: R::BAD_AUTHENTICATION_METHOD,
            properties: vec![]
        }
    );
    assert_eq!(bad.next().await, None);

    let mut auth_data_only = Client::open(&broker, ConnectionInfo::default());
    auth_data_only
        .io
        .write_all(b"\x10\x12\0\x04MQTT\x05\x02\0\0\x04\x16\0\x01x\0\x01a")
        .await
        .unwrap();
    auth_data_only
        .expect(Packet::ConnAck(ConnAck {
            session_present: false,
            reason: R::PROTOCOL_ERROR,
            properties: vec![],
        }))
        .await;
    assert_eq!(auth_data_only.next().await, None);

    let mut client = connected(&broker, request("without-method"), false).await;
    client.io.write_all(&[0xf0, 0]).await.unwrap();
    client.expect(disc(R::PROTOCOL_ERROR, vec![])).await;
    assert_eq!(client.next().await, None);
}

// 02-subpub-b2c-topic-alias.py, 02-subpub-qos0-topic-alias.py;
// src/handle_publish.c: handle__publish.
#[tokio::test]
async fn inbound_and_outbound_aliases_are_independent_and_reconnect_resets_them() {
    let broker = broker(BrokerConfig::default());
    let mut sender = connected(&broker, request("sender"), false).await;
    let mut receiver = Client::open(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                max_topic_alias_broker: 1,
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    assert_eq!(
        receiver
            .connect(Connect {
                properties: vec![P::TopicAliasMaximum(2)],
                ..request("sink")
            })
            .await
            .reason,
        R::SUCCESS
    );
    receiver.subscribe(sub("#", Q0), vec![]).await;
    for (topic, output_topic) in [("a", "a"), ("", ""), ("b", "b"), ("", "b")] {
        sender
            .send(Packet::Publish(Publish {
                properties: vec![P::TopicAlias(1)],
                ..publish(topic, b"body", Q0, 0)
            }))
            .await;
        let properties = if output_topic == "b" {
            vec![]
        } else {
            vec![P::TopicAlias(1)]
        };
        receiver
            .expect(Packet::Publish(Publish {
                properties,
                ..publish(output_topic, b"body", Q0, 0)
            }))
            .await;
    }
    sender.disconnect(R::SUCCESS, vec![]).await;
    let mut sender = connected(&broker, request("sender"), false).await;
    sender
        .send(Packet::Publish(Publish {
            properties: vec![P::TopicAlias(1)],
            ..publish("", b"body", Q0, 0)
        }))
        .await;
    sender.expect(disc(R::PROTOCOL_ERROR, vec![])).await;
    assert_eq!(sender.next().await, None);

    let mut out_of_range = connected(&broker, request("invalid"), false).await;
    out_of_range
        .send(Packet::Publish(Publish {
            properties: vec![P::TopicAlias(11)],
            ..publish("a", b"", Q0, 0)
        }))
        .await;
    out_of_range
        .expect(disc(R::TOPIC_ALIAS_INVALID, vec![]))
        .await;
}

// src/property_broker.c: property__process_publish; lib/send_publish.c: send__real_publish;
// 02-subpub-qos0-subscription-id.py and src/handle_publish.c (no UTF-8 payload validation).
#[tokio::test(start_paused = true)]
async fn publication_properties_preserve_order_and_expiry_decrements_offline() {
    let broker = broker(BrokerConfig::default());
    let settings = Connect {
        properties: vec![P::SessionExpiryInterval(60)],
        ..request("sink")
    };
    let mut sink = connected(&broker, settings.clone(), false).await;
    sink.subscribe(sub("actual", Q1), vec![P::SubscriptionIdentifier(32)])
        .await;
    sink.disconnect(R::SUCCESS, vec![]).await;
    let mut sender = connected(&broker, request("sender"), false).await;
    let mut props = vec![
        P::UserProperty("a".into(), "1".into()),
        P::CorrelationData(Bytes::from_static(b"\0\xff")),
        P::ContentType("application/octet-stream".into()),
        P::ResponseTopic("response".into()),
        P::UserProperty("a".into(), "2".into()),
        P::PayloadFormatIndicator(1),
    ];
    let mut incoming = props.clone();
    incoming.insert(2, P::MessageExpiryInterval(4));
    sender
        .send(Packet::Publish(Publish {
            properties: incoming,
            ..publish("actual", b"\xff", Q1, 1)
        }))
        .await;
    sender.expect(Packet::PubAck(ack(1, R::SUCCESS))).await;
    sender
        .send(Packet::Publish(Publish {
            properties: vec![P::MessageExpiryInterval(1)],
            ..publish("actual", b"expires", Q1, 2)
        }))
        .await;
    sender.expect(Packet::PubAck(ack(2, R::SUCCESS))).await;
    advance(Duration::from_secs(2)).await;
    let mut sink = connected(
        &broker,
        Connect {
            clean_start: false,
            ..settings
        },
        true,
    )
    .await;
    props.extend([P::MessageExpiryInterval(2), P::SubscriptionIdentifier(32)]);
    sink.expect(Packet::Publish(Publish {
        properties: props,
        ..publish("actual", b"\xff", Q1, 1)
    }))
    .await;
    sink.send(Packet::PubAck(ack(1, R::SUCCESS))).await;
    sink.silent().await;
}

// retain.c: retain__search's level-zero `/#` fallback is different for
// dollar-prefixed roots, which have no leading empty hierarchy component.
#[tokio::test(start_paused = true)]
async fn dollar_root_retained_replay_distinguishes_a_leaf_from_a_parent() {
    let broker = broker(BrokerConfig::default());
    let mut sender = connected(&broker, request("sender"), false).await;
    let retained = Publish {
        retain: true,
        ..publish("$device", b"parent", Q1, 1)
    };
    sender.send(Packet::Publish(retained.clone())).await;
    sender
        .expect(Packet::PubAck(ack(1, R::NO_MATCHING_SUBSCRIBERS)))
        .await;

    let mut sink = connected(&broker, request("sink"), false).await;
    sink.subscribe(sub("$device/#", Q1), vec![]).await;
    sink.send(Packet::PingReq).await;
    sink.expect(Packet::PingResp).await;
    sink.subscribe(sub("$device", Q1), vec![]).await;
    sink.expect(Packet::Publish(retained.clone())).await;
    sink.disconnect(R::SUCCESS, vec![]).await;

    let child = Publish {
        retain: true,
        ..publish("$device/value", b"child", Q1, 2)
    };
    sender.send(Packet::Publish(child.clone())).await;
    sender
        .expect(Packet::PubAck(ack(2, R::NO_MATCHING_SUBSCRIBERS)))
        .await;
    let mut sink = connected(&broker, request("sink"), false).await;
    sink.subscribe(sub("$device/#", Q1), vec![]).await;
    sink.expect(Packet::Publish(Publish {
        packet_id: Some(mid(1)),
        ..child
    }))
    .await;
    sink.expect(Packet::Publish(Publish {
        packet_id: Some(mid(2)),
        ..retained
    }))
    .await;
}

// src/handle_subscribe.c: handle__subscribe; src/subs.c: subs__process;
// src/retain.c: retain__queue and test/broker/02-shared-qos0-v5.py.
#[tokio::test(start_paused = true)]
async fn subscription_replacement_controls_replay_and_self_delivery() {
    let broker = broker(BrokerConfig::default());
    let mut owner = connected(&broker, request("source"), false).await;
    let retained = Publish {
        retain: true,
        ..publish("a", b"old", Q1, 1)
    };
    owner.send(Packet::Publish(retained.clone())).await;
    owner
        .expect(Packet::PubAck(ack(1, R::NO_MATCHING_SUBSCRIBERS)))
        .await;
    let options = Subscription {
        no_local: true,
        retain_as_published: true,
        retain_handling: RetainHandling::SendIfNew,
        ..sub("a", Q1)
    };
    owner
        .subscribe(options.clone(), vec![P::SubscriptionIdentifier(1)])
        .await;
    owner
        .expect(Packet::Publish(Publish {
            properties: vec![P::SubscriptionIdentifier(1)],
            ..retained
        }))
        .await;
    owner.send(Packet::PubAck(ack(1, R::SUCCESS))).await;
    owner
        .subscribe(options, vec![P::SubscriptionIdentifier(2)])
        .await;
    owner
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("a", b"new", Q1, 2)
        }))
        .await;
    owner.expect(Packet::PubAck(ack(2, R::SUCCESS))).await;
    owner.silent().await;

    let mut first = connected(&broker, request("first"), false).await;
    let mut second = connected(&broker, request("second"), false).await;
    first.subscribe(sub("$share/work/#", Q0), vec![]).await;
    second.subscribe(sub("$share/work/#", Q0), vec![]).await;
    let mut rap = connected(&broker, request("rap"), false).await;
    rap.subscribe(
        Subscription {
            retain_handling: RetainHandling::DoNotSend,
            retain_as_published: true,
            ..sub("a", Q0)
        },
        vec![],
    )
    .await;
    let retained = Publish {
        retain: true,
        ..publish("a", b"live", Q0, 0)
    };
    owner.send(Packet::Publish(retained.clone())).await;
    rap.expect(Packet::Publish(retained.clone())).await;
    first
        .expect(Packet::Publish(Publish {
            retain: false,
            ..retained
        }))
        .await;
    owner
        .send(Packet::Publish(publish("b", b"next", Q0, 0)))
        .await;
    second
        .expect(Packet::Publish(publish("b", b"next", Q0, 0)))
        .await;

    rap.send(Packet::Unsubscribe(Unsubscribe {
        packet_id: mid(8),
        filters: vec![
            "$unknown/x".into(),
            "a".into(),
            "missing".into(),
            "$unknown/y".into(),
        ],
        properties: vec![],
    }))
    .await;
    rap.expect(Packet::UnsubAck(SubscriptionAck {
        packet_id: mid(8),
        properties: vec![],
        reasons: vec![
            R::SUCCESS,
            R::SUCCESS,
            R::NO_SUBSCRIPTION_EXISTED,
            R::NO_SUBSCRIPTION_EXISTED,
        ],
    }))
    .await;
}

// 12-prop-maximum-packet-size-publish-qos1.py; src/database.c: db__message_write_inflight_out_single.
#[tokio::test(start_paused = true)]
async fn maximum_packet_size_drops_outgoing_and_rejects_oversize_incoming() {
    let broker = broker(BrokerConfig {
        max_packet_size: 80,
        ..BrokerConfig::default()
    });
    let mut sink = connected(
        &broker,
        Connect {
            properties: vec![P::MaximumPacketSize(20)],
            ..request("sink")
        },
        false,
    )
    .await;
    sink.subscribe(sub("max/size", Q1), vec![]).await;
    let mut sender = connected(&broker, request("sender"), false).await;
    sender
        .send(Packet::Publish(Publish {
            properties: vec![P::PayloadFormatIndicator(1)],
            ..publish("max/size", b"1234", Q1, 1)
        }))
        .await;
    sender.expect(Packet::PubAck(ack(1, R::SUCCESS))).await;
    sink.silent().await;
    sender
        .send(Packet::Publish(publish("max/size", b"12345", Q1, 2)))
        .await;
    sink.expect(Packet::Publish(publish("max/size", b"12345", Q1, 2)))
        .await;
    sender.expect(Packet::PubAck(ack(2, R::SUCCESS))).await;
    let large = &[b'x'; 88];
    sender
        .send(Packet::Publish(publish("too-large", large, Q0, 0)))
        .await;
    sender.expect(disc(R::PACKET_TOO_LARGE, vec![])).await;
    assert_eq!(sender.next().await, None);

    let mut no_connack = Client::open(&broker, ConnectionInfo::default());
    no_connack
        .send(Packet::Connect(Connect {
            properties: vec![P::MaximumPacketSize(14)],
            ..request("no-connack")
        }))
        .await;
    assert_eq!(no_connack.next().await, None);
}

// src/handle_publish.c: process_bad_message and handle__accepted_publish;
// lib/handle_pubrec.c: handle__pubrec and lib/send_mosq.c: send__pubrec.
#[tokio::test(start_paused = true)]
async fn receive_maximum_and_rejections_keep_qos_flows_distinct() {
    let broker = broker(BrokerConfig {
        max_inflight_messages: 1,
        ..BrokerConfig::default()
    });
    let mut sender = connected(&broker, request("sender"), false).await;
    sender
        .send(Packet::Publish(publish("hold", b"x", Q2, 1)))
        .await;
    sender.expect(Packet::PubRec(ack(1, R::SUCCESS))).await;
    sender
        .send(Packet::Publish(publish("hold", b"y", Q2, 2)))
        .await;
    sender
        .expect(Packet::PubRec(ack(2, R::QUOTA_EXCEEDED)))
        .await;
    sender.send(Packet::PubRel(ack(1, R::SUCCESS))).await;
    sender.expect(Packet::PubComp(ack(1, R::SUCCESS))).await;

    let mut deny = Client::open(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                security: SecurityHandle::new(
                    None,
                    Some(AclFile::parse(b"topic deny locked\ntopic readwrite #\n").unwrap()),
                ),
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    assert_eq!(deny.connect(request("acl")).await.reason, R::SUCCESS);
    deny.send(Packet::Publish(publish("locked", b"x", Q1, 4)))
        .await;
    deny.expect(Packet::PubAck(ack(4, R::NOT_AUTHORIZED))).await;
    deny.send(Packet::Publish(publish("locked", b"x", Q2, 5)))
        .await;
    deny.expect(Packet::PubRec(ack(5, R::NOT_AUTHORIZED))).await;

    let mut sink = connected(
        &broker,
        Connect {
            properties: vec![P::ReceiveMaximum(1)],
            ..request("sink")
        },
        false,
    )
    .await;
    sink.subscribe(sub("r", Q1), vec![]).await;
    for id in [6, 7] {
        sender
            .send(Packet::Publish(publish("r", b"x", Q1, id)))
            .await;
        sender.expect(Packet::PubAck(ack(id, R::SUCCESS))).await;
    }
    sink.expect(Packet::Publish(publish("r", b"x", Q1, 1)))
        .await;
    sink.silent().await;
    sink.send(Packet::PubAck(ack(1, R::SUCCESS))).await;
    sink.expect(Packet::Publish(publish("r", b"x", Q1, 2)))
        .await;
}

// database.c: db__message_write_inflight_out_latest revisits the lone
// predecessor when writing the new QoS 0; an expired flight returns credit.
#[tokio::test(start_paused = true)]
async fn qos0_write_releases_an_expired_receive_window_slot() {
    for (session_expiry, expired) in [(0, false), (0, true), (60, false), (60, true)] {
        let broker = broker(BrokerConfig::default());
        let mut sink = connected(
            &broker,
            Connect {
                properties: vec![
                    P::ReceiveMaximum(1),
                    P::SessionExpiryInterval(session_expiry),
                ],
                ..request("receiver")
            },
            false,
        )
        .await;
        sink.subscribe(sub("stream", Q1), vec![]).await;
        let mut sender = connected(&broker, request("sender"), false).await;
        let first = Publish {
            properties: vec![P::MessageExpiryInterval(1)],
            ..publish("stream", b"expires", Q1, 1)
        };
        sender.send(Packet::Publish(first.clone())).await;
        sender.expect(Packet::PubAck(ack(1, R::SUCCESS))).await;
        sink.expect(Packet::Publish(first)).await;

        if expired {
            advance(Duration::from_secs(2)).await;
        }
        let marker = publish("stream", b"marker", Q0, 0);
        sender.send(Packet::Publish(marker.clone())).await;
        sink.expect(Packet::Publish(marker)).await;

        let second = publish("stream", b"next", Q1, 2);
        sender.send(Packet::Publish(second.clone())).await;
        sender.expect(Packet::PubAck(ack(2, R::SUCCESS))).await;
        if !expired {
            sink.silent().await;
            sink.send(Packet::PubAck(ack(1, R::SUCCESS))).await;
        }
        sink.expect(Packet::Publish(second)).await;
    }
}

// database.c: db__expire_all_messages and db__message_reconnect_reset_outgoing.
// Extend 03-publish-qos1-max-inflight-expire.py through the resumed QoS 2 flow.
#[tokio::test(start_paused = true)]
async fn resume_frees_expired_receive_window_but_keeps_qos2_until_pubcomp() {
    let broker = broker(BrokerConfig::default());
    let mut settings = Connect {
        properties: vec![P::SessionExpiryInterval(60), P::ReceiveMaximum(1)],
        ..request("receiver")
    };
    let mut sink = connected(&broker, settings.clone(), false).await;
    sink.subscribe(sub("stream", Q2), vec![]).await;
    let mut sender = connected(&broker, request("sender"), false).await;
    let expiring = Publish {
        properties: vec![P::MessageExpiryInterval(1)],
        ..publish("stream", b"expires", Q1, 1)
    };
    sender.send(Packet::Publish(expiring.clone())).await;
    sender.expect(Packet::PubAck(ack(1, R::SUCCESS))).await;
    sink.expect(Packet::Publish(expiring)).await;

    let second = publish("stream", b"qos 2", Q2, 2);
    sender.send(Packet::Publish(second.clone())).await;
    sender.expect(Packet::PubRec(ack(2, R::SUCCESS))).await;
    sender.send(Packet::PubRel(ack(2, R::SUCCESS))).await;
    sender.expect(Packet::PubComp(ack(2, R::SUCCESS))).await;
    let third = publish("stream", b"qos 1", Q1, 3);
    sender.send(Packet::Publish(third.clone())).await;
    sender.expect(Packet::PubAck(ack(3, R::SUCCESS))).await;
    sink.silent().await;
    sink.disconnect(R::SUCCESS, vec![]).await;

    advance(Duration::from_secs(2)).await;
    settings.clean_start = false;
    let mut sink = connected(&broker, settings.clone(), true).await;
    sink.expect(Packet::Publish(second)).await;
    sink.send(Packet::PubRec(ack(2, R::SUCCESS))).await;
    sink.expect(Packet::PubRel(ack(2, R::SUCCESS))).await;
    sink.disconnect(R::SUCCESS, vec![]).await;

    let mut sink = connected(&broker, settings, true).await;
    sink.expect(Packet::PubRel(ack(2, R::SUCCESS))).await;
    sink.silent().await;
    sink.send(Packet::PubComp(ack(2, R::SUCCESS))).await;
    sink.expect(Packet::Publish(third)).await;
}

// 07-will-delay-reconnect.py, 07-will-disconnect-with-will.py and src/session_expiry.c.
#[tokio::test(start_paused = true)]
async fn will_delay_is_cancelled_on_resume_and_expiry_override_ends_the_session() {
    let broker = broker(BrokerConfig::default());
    let mut watcher = connected(&broker, request("watcher"), false).await;
    watcher.subscribe(sub("will", Q0), vec![]).await;
    let settings = Connect {
        properties: vec![P::SessionExpiryInterval(30)],
        will: Some(LastWill {
            properties: vec![
                P::WillDelayInterval(4),
                P::MessageExpiryInterval(10),
                P::ContentType("will/type".into()),
            ],
            topic: "will".into(),
            payload: Bytes::from_static(b"gone"),
            qos: Q0,
            retain: false,
        }),
        ..request("owner")
    };
    connected(&broker, settings.clone(), false)
        .await
        .close()
        .await;
    advance(Duration::from_secs(1)).await;
    let owner = connected(
        &broker,
        Connect {
            clean_start: false,
            ..settings.clone()
        },
        true,
    )
    .await;
    advance(Duration::from_secs(5)).await;
    watcher.silent().await;
    owner
        .disconnect(
            R::DISCONNECT_WITH_WILL_MESSAGE,
            vec![P::SessionExpiryInterval(0)],
        )
        .await;
    watcher
        .expect(Packet::Publish(Publish {
            properties: vec![
                P::ContentType("will/type".into()),
                P::MessageExpiryInterval(10),
            ],
            ..publish("will", b"gone", Q0, 0)
        }))
        .await;
    let mut owner = connected(
        &broker,
        Connect {
            clean_start: false,
            ..request("owner")
        },
        false,
    )
    .await;
    owner
        .send(disc(R::SUCCESS, vec![P::SessionExpiryInterval(10)]))
        .await;
    owner.expect(disc(R::PROTOCOL_ERROR, vec![])).await;
    assert_eq!(owner.next().await, None);
}

// src/session_expiry.c: session_expiry__add/check; src/handle_connect.c: connect__on_authorised.
#[tokio::test(start_paused = true)]
async fn expiry_cap_publishes_will_before_long_delay_and_takeover_sends_its_reason() {
    let broker = broker(BrokerConfig {
        persistent_client_expiration: Some(Duration::from_secs(1)),
        ..BrokerConfig::default()
    });
    let mut watcher = connected(&broker, request("watcher"), false).await;
    watcher.subscribe(sub("will", Q0), vec![]).await;
    let settings = Connect {
        properties: vec![P::SessionExpiryInterval(u32::MAX)],
        will: Some(LastWill {
            properties: vec![P::WillDelayInterval(20)],
            topic: "will".into(),
            qos: Q0,
            retain: false,
            payload: Bytes::from_static(b"expired"),
        }),
        ..request("owner")
    };
    let mut old = connected(&broker, settings.clone(), false).await;
    let new = connected(
        &broker,
        Connect {
            clean_start: false,
            ..settings
        },
        true,
    )
    .await;
    old.expect(disc(R::SESSION_TAKEN_OVER, vec![])).await;
    assert_eq!(old.next().await, None);
    new.close().await;
    watcher.silent().await;
    advance(Duration::from_secs(2)).await;
    watcher
        .expect(Packet::Publish(publish("will", b"expired", Q0, 0)))
        .await;
    connected(
        &broker,
        Connect {
            clean_start: false,
            ..request("owner")
        },
        false,
    )
    .await
    .close()
    .await;
}

// lib/send_publish.c: send__real_publish; src/handle_connect.c: connect__on_authorised.
#[tokio::test]
async fn legacy_publisher_and_resumed_legacy_subscriber_share_v5_state_without_wire_properties() {
    use mqx_codec as legacy;
    let broker = broker(BrokerConfig::default());
    let mut subscriber = connected(
        &broker,
        Connect {
            properties: vec![P::SessionExpiryInterval(60)],
            ..request("mixed")
        },
        false,
    )
    .await;
    subscriber
        .subscribe(sub("mixed", Q1), vec![P::SubscriptionIdentifier(2)])
        .await;
    let mut legacy_publisher = Client::open(&broker, ConnectionInfo::default());
    let make_connect = |id: &str, clean_session| {
        legacy::Packet::Connect(legacy::Connect {
            protocol: legacy::ProtocolVersion::V311,
            is_bridge: false,
            clean_session,
            keep_alive: 0,
            client_id: id.into(),
            will: None,
            username: None,
            password: None,
        })
    };
    let mut encoded = BytesMut::new();
    legacy::encode(&make_connect("legacy", true), &mut encoded).unwrap();
    legacy_publisher.io.write_all(&encoded).await.unwrap();
    let mut connack = [0; 4];
    legacy_publisher.io.read_exact(&mut connack).await.unwrap();
    assert_eq!(connack, [0x20, 2, 0, 0]);
    encoded.clear();
    legacy::encode(
        &legacy::Packet::Publish(legacy::Publish {
            dup: false,
            qos: Q0,
            retain: false,
            topic: "mixed".into(),
            packet_id: None,
            payload: Bytes::from_static(b"old"),
        }),
        &mut encoded,
    )
    .unwrap();
    legacy_publisher.io.write_all(&encoded).await.unwrap();
    subscriber
        .expect(Packet::Publish(Publish {
            properties: vec![P::SubscriptionIdentifier(2)],
            ..publish("mixed", b"old", Q0, 0)
        }))
        .await;
    subscriber.disconnect(R::SUCCESS, vec![]).await;

    let mut sender = connected(&broker, request("new"), false).await;
    sender
        .send(Packet::Publish(Publish {
            properties: vec![P::UserProperty("new".into(), "value".into())],
            ..publish("mixed", b"new", Q1, 1)
        }))
        .await;
    sender.expect(Packet::PubAck(ack(1, R::SUCCESS))).await;
    let mut resumed = Client::open(&broker, ConnectionInfo::default());
    encoded.clear();
    legacy::encode(&make_connect("mixed", false), &mut encoded).unwrap();
    resumed.io.write_all(&encoded).await.unwrap();
    resumed.io.read_exact(&mut connack).await.unwrap();
    assert_eq!(connack, [0x20, 2, 1, 0]);
    let mut actual = [0; 14];
    timeout(WAIT, resumed.io.read_exact(&mut actual))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&actual, b"\x32\x0c\0\x05mixed\0\x01new");
}

// src/handle_connect.c: read_and_verify_protocol_version precedes property processing.
#[tokio::test]
async fn a_disabled_v5_listener_refuses_before_using_peer_packet_limits() {
    let broker = broker(BrokerConfig::default());
    let mut client = Client::open(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                disable_protocol_v5: true,
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    assert_eq!(
        client
            .connect(Connect {
                properties: vec![P::MaximumPacketSize(1)],
                ..request("disabled")
            })
            .await,
        ConnAck {
            session_present: false,
            reason: R::UNSUPPORTED_PROTOCOL_VERSION,
            properties: vec![]
        }
    );
    assert_eq!(client.next().await, None);
}

// src/handle_connect.c: connect__on_authorised calls do_disconnect even when
// the duplicate socket cannot accept any more bytes.
#[tokio::test]
async fn a_stalled_old_connection_cannot_delay_takeover() {
    let broker = broker(BrokerConfig::default());
    let mut old = connected(&broker, request("duplicate"), false).await;
    old.subscribe(sub("stall", Q0), vec![]).await;
    let mut publisher = connected(&broker, request("publisher"), false).await;
    publisher
        .send(Packet::Publish(Publish {
            payload: Bytes::from(vec![b'x'; 128 * 1024]),
            ..publish("stall", b"", Q0, 0)
        }))
        .await;
    assert_eq!(
        timeout(WAIT, old.io.read_u8()).await.unwrap().unwrap(),
        0x30
    );
    let mut new = connected(&broker, request("duplicate"), false).await;
    timeout(WAIT, old.server).await.unwrap().unwrap().unwrap();
    new.send(Packet::PingReq).await;
    new.expect(Packet::PingResp).await;
}
