use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use mqx_auth::{AclFile, PasswordFile};
use mqx_broker::{
    Broker, BrokerConfig, BrokerError, CertIdentity, ConnectionInfo, ListenerPolicy, SecurityHandle,
};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode as Code, DecodeContext, LastWill, Packet, PacketId,
    ProtocolVersion as Version, Publish, QoS, SubAck, Subscribe, SubscribeReturnCode, Unsubscribe,
    decode, encode,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, DuplexStream, ReadBuf},
    task::JoinHandle,
    time::timeout,
};

mod cluster;

const Q0: QoS = QoS::AtMostOnce;
const Q1: QoS = QoS::AtLeastOnce;
const Q2: QoS = QoS::ExactlyOnce;
const WAIT: Duration = Duration::from_secs(3);

struct Client {
    io: DuplexStream,
    buffer: BytesMut,
    version: Version,
}

impl Client {
    fn spawn(broker: &Broker, info: ConnectionInfo) -> (Self, JoinHandle<Result<(), BrokerError>>) {
        let (io, server) = tokio::io::duplex(64 * 1024);
        let broker = broker.clone();
        (
            Self {
                io,
                buffer: BytesMut::new(),
                version: Version::V311,
            },
            tokio::spawn(async move { broker.serve(server, info).await }),
        )
    }

    async fn send(&mut self, packet: Packet) {
        let mut bytes = BytesMut::new();
        encode(&packet, &mut bytes).unwrap();
        self.io.write_all(&bytes).await.unwrap();
    }

    async fn recv(&mut self) -> Option<Packet> {
        timeout(WAIT, async {
            loop {
                if let Some(packet) = decode(
                    &mut self.buffer,
                    DecodeContext::for_client(0, Some(self.version)),
                )
                .unwrap()
                {
                    return Some(packet);
                }
                if self.io.read_buf(&mut self.buffer).await.unwrap() == 0 {
                    assert!(self.buffer.is_empty());
                    return None;
                }
            }
        })
        .await
        .expect("broker did not send a packet or close the session")
    }

    async fn expect(&mut self, packet: Packet) {
        assert_eq!(self.recv().await, Some(packet));
    }

    async fn connect(&mut self, connect: Connect, code: Code, session_present: bool) {
        self.version = connect.protocol;
        self.send(Packet::Connect(connect)).await;
        self.expect(Packet::ConnAck(ConnAck {
            session_present,
            code,
        }))
        .await;
    }

    async fn subscribe(&mut self, filters: &[(&str, QoS)], expected: &[QoS]) {
        self.send(Packet::Subscribe(Subscribe {
            packet_id: mid(10),
            filters: filters.iter().map(|(s, q)| ((*s).to_owned(), *q)).collect(),
        }))
        .await;
        self.expect(Packet::SubAck(SubAck {
            packet_id: mid(10),
            return_codes: expected
                .iter()
                .copied()
                .map(SubscribeReturnCode::Success)
                .collect(),
        }))
        .await;
    }

    async fn ping(&mut self) {
        self.send(Packet::PingReq).await;
        self.expect(Packet::PingResp).await;
    }

    async fn disconnect(mut self) {
        self.send(Packet::Disconnect).await;
        assert_eq!(self.recv().await, None);
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

fn request(id: &str, clean: bool) -> Connect {
    Connect {
        protocol: Version::V311,
        clean_session: clean,
        is_bridge: false,
        keep_alive: 0,
        client_id: id.into(),
        will: None,
        username: None,
        password: None,
    }
}

fn publish(topic: &str, payload: &'static [u8], qos: QoS, id: u16) -> Publish {
    Publish {
        dup: false,
        qos,
        retain: false,
        topic: topic.into(),
        packet_id: (id != 0).then(|| mid(id)),
        payload: Bytes::from_static(payload),
    }
}

fn will(topic: &str) -> LastWill {
    LastWill {
        topic: topic.into(),
        payload: Bytes::from_static(b"gone"),
        qos: Q0,
        retain: false,
    }
}

async fn connected(broker: &Broker, id: &str, clean: bool, present: bool) -> Client {
    let (mut io, _) = Client::spawn(broker, ConnectionInfo::default());
    io.connect(request(id, clean), Code::Accepted, present)
        .await;
    io
}

// test/broker/01-bad-initial-packets.py and handle_connect.c: handle__connect.
#[tokio::test]
async fn connect_is_required_and_may_not_be_repeated() {
    let broker = broker(BrokerConfig::default());
    let (mut first, task) = Client::spawn(&broker, ConnectionInfo::default());
    first.io.write_all(&[0xc0]).await.unwrap();
    assert_eq!(first.recv().await, None);
    assert!(matches!(task.await.unwrap(), Err(BrokerError::Protocol)));
    let mut client = connected(&broker, "duplicate", true, false).await;
    client
        .send(Packet::Connect(request("duplicate", true)))
        .await;
    assert_eq!(client.recv().await, None);
}

// test/broker/01-connect-zero-length-id.py; handle_connect.c: clientid_gen.
#[tokio::test]
async fn auto_ids_are_prefixed_and_v31_and_persistent_empty_ids_are_refused() {
    let broker = broker(BrokerConfig {
        clientid_prefixes: Some("generated-".into()),
        ..BrokerConfig::default()
    });
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            auto_id_prefix: Some("generated-".into()),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut one, _) = Client::spawn(&broker, info.clone());
    one.connect(request("", true), Code::Accepted, false).await;
    let (mut two, _) = Client::spawn(&broker, info.clone());
    two.connect(request("", true), Code::Accepted, false).await;
    one.ping().await;
    let (mut persistent, _) = Client::spawn(&broker, info.clone());
    persistent
        .connect(request("", false), Code::IdentifierRejected, false)
        .await;
    let (mut old, _) = Client::spawn(&broker, info);
    old.connect(
        Connect {
            protocol: Version::V31,
            ..request("", true)
        },
        Code::IdentifierRejected,
        false,
    )
    .await;
    let (mut long, _) = Client::spawn(&broker, ConnectionInfo::default());
    long.connect(
        Connect {
            protocol: Version::V31,
            ..request("generated-much-longer-than-twenty-three-characters", false)
        },
        Code::Accepted,
        false,
    )
    .await;
}

// test/broker/01-connect-uname-or-anon.py and 08-ssl-connect-no-identity.py;
// handle_connect.c: handle_username_as_clientid_option uses the mapped identity.
#[tokio::test]
async fn certificate_replaces_credentials_and_empty_credentials_are_anonymous() {
    let broker = Broker::new(BrokerConfig::default());
    let file = PasswordFile::parse(b"test:$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==\n").unwrap();
    let security = SecurityHandle::new(Some(file), None);
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            allow_anonymous: Some(true),
            security: security.clone(),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut anonymous, _) = Client::spawn(&broker, info.clone());
    anonymous
        .connect(
            Connect {
                username: Some(String::new()),
                password: Some(Bytes::new()),
                ..request("anon", true)
            },
            Code::Accepted,
            false,
        )
        .await;
    let (mut denied, _) = Client::spawn(&broker, info.clone());
    denied
        .connect(
            Connect {
                username: Some("test".into()),
                password: Some(Bytes::new()),
                ..request("denied", true)
            },
            Code::NotAuthorized,
            false,
        )
        .await;
    let (mut password, _) = Client::spawn(&broker, info);
    password
        .connect(
            Connect {
                username: Some("test".into()),
                password: Some(Bytes::from_static(b"test")),
                ..request("password", true)
            },
            Code::Accepted,
            false,
        )
        .await;

    let tls = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            use_username_as_clientid: true,
            security,
            ..ListenerPolicy::default()
        }),
        cert_identity: CertIdentity::Username("cert-name".into()),
        peer_addr: None,
    };
    let (mut first, _) = Client::spawn(&broker, tls.clone());
    first
        .connect(
            Connect {
                username: Some("nonexistent".into()),
                ..request("first", false)
            },
            Code::Accepted,
            false,
        )
        .await;
    let (mut second, _) = Client::spawn(&broker, tls.clone());
    second
        .connect(request("second", false), Code::Accepted, true)
        .await;
    assert_eq!(first.recv().await, None);
    let (mut missing, _) = Client::spawn(
        &broker,
        ConnectionInfo {
            cert_identity: CertIdentity::MissingOrInvalid,
            ..tls
        },
    );
    missing
        .connect(
            request("missing", false),
            Code::BadUserNameOrPassword,
            false,
        )
        .await;
}

// test/broker/01-connect-max-keepalive.py and keepalive.c: keepalive__check.
#[tokio::test(start_paused = true)]
async fn keepalive_rejects_zero_above_cap_and_resets_on_packets() {
    let broker = broker(BrokerConfig {
        max_keepalive: 2,
        ..BrokerConfig::default()
    });
    for keep_alive in [0, 3] {
        let (mut peer, _) = Client::spawn(&broker, ConnectionInfo::default());
        peer.connect(
            Connect {
                keep_alive,
                ..request("refused", true)
            },
            Code::IdentifierRejected,
            false,
        )
        .await;
        assert_eq!(peer.recv().await, None);
    }
    let (mut peer, _) = Client::spawn(&broker, ConnectionInfo::default());
    peer.connect(
        Connect {
            keep_alive: 2,
            ..request("keepalive", true)
        },
        Code::Accepted,
        false,
    )
    .await;
    tokio::time::advance(Duration::from_secs(2)).await;
    peer.ping().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    peer.ping().await;
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(peer.recv().await, None);
}

// test/broker/01-connect-max-connections.py and 01-connect-global-max-clients.py.
#[tokio::test]
async fn listener_counts_pre_connect_sockets_and_global_clients_counts_offline_sessions() {
    let broker = broker(BrokerConfig {
        global_max_clients: 1,
        ..BrokerConfig::default()
    });
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            max_connections: 1,
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (first, task) = Client::spawn(&broker, info.clone());
    tokio::task::yield_now().await;
    let (mut too_many, _) = Client::spawn(&broker, info);
    assert_eq!(too_many.recv().await, None);
    drop(first);
    task.await.unwrap().unwrap();
    connected(&broker, "offline", false, false)
        .await
        .disconnect()
        .await;
    let (mut another, _) = Client::spawn(&broker, ConnectionInfo::default());
    another
        .send(Packet::Connect(request("another", true)))
        .await;
    assert_eq!(another.recv().await, None);
    connected(&broker, "offline", false, true)
        .await
        .ping()
        .await;
}

// test/broker/07-will-takeover.py and 07-will-reconnect-1273.py.
#[tokio::test]
async fn takeover_sends_old_will_iff_either_connection_is_clean() {
    let broker = broker(BrokerConfig::default());
    let mut observer = connected(&broker, "observer", true, false).await;
    observer.subscribe(&[("will", Q0)], &[Q0]).await;
    for (index, (old_clean, new_clean)) in
        [(false, false), (false, true), (true, false), (true, true)]
            .into_iter()
            .enumerate()
    {
        let id = format!("client-{index}");
        let (mut previous, _) = Client::spawn(&broker, ConnectionInfo::default());
        previous
            .connect(
                Connect {
                    will: Some(will("will")),
                    ..request(&id, old_clean)
                },
                Code::Accepted,
                false,
            )
            .await;
        let mut successor = connected(&broker, &id, new_clean, !old_clean && !new_clean).await;
        assert_eq!(previous.recv().await, None);
        if old_clean || new_clean {
            observer
                .expect(Packet::Publish(publish("will", b"gone", Q0, 0)))
                .await;
        }
        observer.ping().await;
        successor.ping().await;
    }
}

// test/broker/07-will-qos0.py; context.c: context__send_will; handle_disconnect.c.
#[tokio::test(start_paused = true)]
async fn will_fires_on_eof_and_timeout_but_not_on_disconnect_or_acl_denial() {
    let broker = broker(BrokerConfig::default());
    let mut observer = connected(&broker, "observer", true, false).await;
    observer.subscribe(&[("will", Q0)], &[Q0]).await;
    let (mut clean, _) = Client::spawn(&broker, ConnectionInfo::default());
    clean
        .connect(
            Connect {
                will: Some(will("will")),
                ..request("clean", true)
            },
            Code::Accepted,
            false,
        )
        .await;
    clean.disconnect().await;
    observer.ping().await;
    let (mut eof, finished) = Client::spawn(&broker, ConnectionInfo::default());
    eof.connect(
        Connect {
            will: Some(will("will")),
            ..request("eof", true)
        },
        Code::Accepted,
        false,
    )
    .await;
    drop(eof);
    finished.await.unwrap().unwrap();
    observer
        .expect(Packet::Publish(publish("will", b"gone", Q0, 0)))
        .await;
    let (mut timed, _) = Client::spawn(&broker, ConnectionInfo::default());
    timed
        .connect(
            Connect {
                keep_alive: 1,
                will: Some(will("will")),
                ..request("timeout", true)
            },
            Code::Accepted,
            false,
        )
        .await;
    tokio::time::advance(Duration::from_millis(1500)).await;
    assert_eq!(timed.recv().await, None);
    observer
        .expect(Packet::Publish(publish("will", b"gone", Q0, 0)))
        .await;
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            security: SecurityHandle::new(
                None,
                Some(AclFile::parse(b"topic read will\n").unwrap()),
            ),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut denied, finished) = Client::spawn(&broker, info);
    denied
        .connect(
            Connect {
                will: Some(will("will")),
                ..request("denied", true)
            },
            Code::Accepted,
            false,
        )
        .await;
    drop(denied);
    let _ = finished.await.unwrap();
    observer.ping().await;
}

// test/broker/02-subpub-qos1-oversize-payload.py; handle_publish.c:
// process_bad_message completes the handshake for size/ACL rejections.
#[tokio::test]
async fn rejected_publishes_complete_qos_without_fanout_or_retention() {
    let broker = broker(BrokerConfig {
        message_size_limit: 5,
        ..BrokerConfig::default()
    });
    let mut sink = connected(&broker, "sink", true, false).await;
    sink.subscribe(&[("#", Q2)], &[Q2]).await;
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            security: SecurityHandle::new(
                None,
                Some(AclFile::parse(b"topic write allowed\n").unwrap()),
            ),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut source, _) = Client::spawn(&broker, info);
    source
        .connect(request("source", true), Code::Accepted, false)
        .await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("blocked", b"no", Q2, 1)
        }))
        .await;
    source.expect(Packet::PubRec(mid(1))).await;
    source.send(Packet::PubRel(mid(1))).await;
    source.expect(Packet::PubComp(mid(1))).await;
    source
        .send(Packet::Publish(publish("allowed", b"too long", Q1, 2)))
        .await;
    source.expect(Packet::PubAck(mid(2))).await;
    sink.subscribe(&[("#", Q2)], &[Q2]).await;
    sink.ping().await;
}

// test/broker/03-publish-qos1-retain-disabled.py; handle_subscribe.c clamps QoS.
#[tokio::test]
async fn listener_qos_caps_suback_and_disconnects_high_qos_or_disabled_retain() {
    let broker = broker(BrokerConfig {
        retain_available: false,
        ..BrokerConfig::default()
    });
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            max_qos: Q1,
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut subscriber, _) = Client::spawn(&broker, info.clone());
    subscriber
        .connect(request("sub", true), Code::Accepted, false)
        .await;
    subscriber.subscribe(&[("topic", Q2)], &[Q1]).await;
    subscriber
        .send(Packet::Publish(publish("topic", b"unsupported", Q2, 1)))
        .await;
    assert_eq!(subscriber.recv().await, None);
    let (mut source, _) = Client::spawn(&broker, info);
    source
        .connect(request("source", true), Code::Accepted, false)
        .await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("topic", b"unsupported", Q1, 1)
        }))
        .await;
    assert_eq!(source.recv().await, None);
}

// test/broker/03-publish-qos2-reuse-mid.py; handle_publish.c:
// handle__accepted_publish and lib/handle_pubrel.c: handle__pubrel.
#[tokio::test]
async fn qos2_duplicate_is_suppressed_and_reused_identifier_replaces_payload() {
    let broker = broker(BrokerConfig::default());
    let mut sink = connected(&broker, "sink", true, false).await;
    sink.subscribe(&[("qos", Q1)], &[Q1]).await;
    let mut src = connected(&broker, "src", false, false).await;
    let pending = publish("qos", b"pending", Q2, 12);
    src.send(Packet::Publish(pending.clone())).await;
    src.expect(Packet::PubRec(mid(12))).await;
    src.send(Packet::Publish(Publish {
        dup: true,
        ..pending
    }))
    .await;
    src.expect(Packet::PubRec(mid(12))).await;
    src.send(Packet::Publish(publish("qos", b"replacement", Q2, 12)))
        .await;
    src.expect(Packet::PubRec(mid(12))).await;
    sink.ping().await;
    src.disconnect().await;
    let mut src = connected(&broker, "src", false, true).await;
    for _ in 0..2 {
        src.send(Packet::PubRel(mid(12))).await;
        src.expect(Packet::PubComp(mid(12))).await;
    }
    sink.expect(Packet::Publish(publish("qos", b"replacement", Q1, 1)))
        .await;
    sink.ping().await;
}

// test/broker/04-retain-clear-multiple.py and 04-retain-upgrade-outgoing-qos.py.
#[tokio::test]
async fn retained_replay_sets_retain_and_upgrades_qos_without_changing_live_retain_flag() {
    let broker = broker(BrokerConfig {
        upgrade_outgoing_qos: true,
        ..BrokerConfig::default()
    });
    let mut source = connected(&broker, "source", true, false).await;
    let mut sink = connected(&broker, "sink", true, false).await;
    sink.subscribe(&[("retained/#", Q1)], &[Q1]).await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("retained", b"stored", Q1, 12)
        }))
        .await;
    source.expect(Packet::PubAck(mid(12))).await;
    sink.expect(Packet::Publish(publish("retained", b"stored", Q1, 1)))
        .await;
    sink.send(Packet::PubAck(mid(1))).await;
    sink.subscribe(&[("retained/#", Q2)], &[Q2]).await;
    sink.expect(Packet::Publish(Publish {
        retain: true,
        ..publish("retained", b"stored", Q2, 2)
    }))
    .await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("retained", b"", Q1, 13)
        }))
        .await;
    source.expect(Packet::PubAck(mid(13))).await;
    sink.expect(Packet::Publish(publish("retained", b"", Q2, 3)))
        .await;
    sink.subscribe(&[("retained/#", Q0)], &[Q0]).await;
    sink.ping().await;
}

// test/broker/04-retain-check-source.py and 23-security-acl-file-reload.py.
#[tokio::test]
async fn retained_replay_checks_current_acl_for_original_source_and_subscriber() {
    let broker = broker(BrokerConfig::default());
    let acl = |data: &[u8]| Some(AclFile::parse(data).unwrap());
    let security = SecurityHandle::new(None, acl(b"topic write history\n"));
    let source = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            security: security.clone(),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut source, _) = Client::spawn(&broker, source);
    source
        .connect(request("source", true), Code::Accepted, false)
        .await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("history", b"data", Q1, 10)
        }))
        .await;
    source.expect(Packet::PubAck(mid(10))).await;
    source.disconnect().await;
    let reader = SecurityHandle::new(None, acl(b"topic write history\n"));
    let (mut sink, _) = Client::spawn(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                security: reader.clone(),
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    sink.connect(request("sink", true), Code::Accepted, false)
        .await;
    sink.subscribe(&[("history", Q1)], &[Q1]).await;
    sink.ping().await;
    reader.replace(None, acl(b"topic read history\n"));
    security.replace(None, acl(b"topic read history\n"));
    sink.subscribe(&[("history", Q1)], &[Q1]).await;
    sink.ping().await;
    security.replace(None, acl(b"topic write history\n"));
    sink.subscribe(&[("history", Q1)], &[Q1]).await;
    sink.expect(Packet::Publish(Publish {
        retain: true,
        ..publish("history", b"data", Q1, 1)
    }))
    .await;
}

// subs.c: sub__search routes literal before #; database.c:
// db__message_insert_outgoing suppresses duplicates after allocating a MID.
#[tokio::test]
async fn overlapping_routes_consume_packet_ids_even_when_deduplicated() {
    for duplicates in [false, true] {
        let broker = broker(BrokerConfig {
            allow_duplicate_messages: duplicates,
            ..BrokerConfig::default()
        });
        let mut sink = connected(&broker, "sink", true, false).await;
        sink.subscribe(&[("#", Q1), ("exact", Q2)], &[Q1, Q2]).await;
        let mut source = connected(&broker, "source", true, false).await;
        source
            .send(Packet::Publish(publish("exact", b"payload", Q2, 10)))
            .await;
        source.expect(Packet::PubRec(mid(10))).await;
        source.send(Packet::PubRel(mid(10))).await;
        source.expect(Packet::PubComp(mid(10))).await;
        sink.expect(Packet::Publish(publish("exact", b"payload", Q2, 1)))
            .await;
        if duplicates {
            sink.expect(Packet::Publish(publish("exact", b"payload", Q1, 2)))
                .await;
        }
        sink.send(Packet::Unsubscribe(Unsubscribe {
            packet_id: mid(11),
            filters: vec!["exact".into()],
        }))
        .await;
        sink.expect(Packet::UnsubAck(mid(11))).await;
        source
            .send(Packet::Publish(publish("exact", b"again", Q1, 13)))
            .await;
        source.expect(Packet::PubAck(mid(13))).await;
        sink.expect(Packet::Publish(publish("exact", b"again", Q1, 3)))
            .await;
    }
}

// subs.c: subs__shared_process applies to both MQTT 3.x versions; retained
// delivery is skipped for $share filters (retain.c: retain__queue).
#[tokio::test]
async fn shared_v311_filters_rotate_members_and_do_not_replay_retained() {
    let broker = broker(BrokerConfig::default());
    let mut source = connected(&broker, "source", true, false).await;
    let mut a = connected(&broker, "a", true, false).await;
    let mut b = connected(&broker, "b", true, false).await;
    source
        .send(Packet::Publish(Publish {
            retain: true,
            ..publish("shared", b"old", Q1, 1)
        }))
        .await;
    source.expect(Packet::PubAck(mid(1))).await;
    for sink in [&mut a, &mut b] {
        sink.subscribe(&[("$share/work/shared", Q1)], &[Q1]).await;
        sink.ping().await;
    }
    for (index, sink) in [&mut a, &mut b].into_iter().enumerate() {
        let id = u16::try_from(index + 2).unwrap();
        source
            .send(Packet::Publish(publish("shared", b"new", Q1, id)))
            .await;
        source.expect(Packet::PubAck(mid(id))).await;
        sink.expect(Packet::Publish(publish("shared", b"new", Q1, 1)))
            .await;
    }
}

// test/broker/03-publish-b2c-disconnect-qos1.py and database.c:
// db__message_reconnect_reset_outgoing resends in-flight before queued.
#[tokio::test]
async fn persistent_in_flight_and_offline_queue_resume_in_packet_id_order() {
    let broker = broker(BrokerConfig {
        max_inflight_messages: 1,
        max_queued_messages: 2,
        ..BrokerConfig::default()
    });
    let mut sink = connected(&broker, "sink", false, false).await;
    sink.subscribe(&[("queue", Q1)], &[Q1]).await;
    let mut source = connected(&broker, "source", true, false).await;
    source
        .send(Packet::Publish(publish("queue", b"sent", Q1, 1)))
        .await;
    source.expect(Packet::PubAck(mid(1))).await;
    sink.expect(Packet::Publish(publish("queue", b"sent", Q1, 1)))
        .await;
    sink.disconnect().await;
    for (index, payload) in [b"keep".as_slice(), b"keep", b"drop"]
        .into_iter()
        .enumerate()
    {
        let id = u16::try_from(index + 2).unwrap();
        source
            .send(Packet::Publish(publish("queue", payload, Q1, id)))
            .await;
        source.expect(Packet::PubAck(mid(id))).await;
    }
    let mut sink = connected(&broker, "sink", false, true).await;
    sink.expect(Packet::Publish(Publish {
        dup: true,
        ..publish("queue", b"sent", Q1, 1)
    }))
    .await;
    for id in 2..=3 {
        sink.send(Packet::PubAck(mid(id - 1))).await;
        sink.expect(Packet::Publish(publish("queue", b"keep", Q1, id)))
            .await;
    }
    sink.send(Packet::PubAck(mid(3))).await;
    sink.ping().await;
    source
        .send(Packet::Publish(publish("queue", b"live", Q1, 5)))
        .await;
    source.expect(Packet::PubAck(mid(5))).await;
    sink.expect(Packet::Publish(publish("queue", b"live", Q1, 5)))
        .await;
}

// database.c: db__message_reconnect_reset_outgoing resends PUBREL, not PUBLISH.
#[tokio::test]
async fn outbound_qos2_resumes_from_pubrel_after_pubrec() {
    let broker = broker(BrokerConfig::default());
    let mut sink = connected(&broker, "sink", false, false).await;
    sink.subscribe(&[("qos", Q2)], &[Q2]).await;
    let mut source = connected(&broker, "source", true, false).await;
    source
        .send(Packet::Publish(publish("qos", b"payload", Q2, 1)))
        .await;
    source.expect(Packet::PubRec(mid(1))).await;
    source.send(Packet::PubRel(mid(1))).await;
    source.expect(Packet::PubComp(mid(1))).await;
    sink.expect(Packet::Publish(publish("qos", b"payload", Q2, 1)))
        .await;
    sink.send(Packet::PubRec(mid(1))).await;
    sink.expect(Packet::PubRel(mid(1))).await;
    sink.disconnect().await;
    let mut sink = connected(&broker, "sink", false, true).await;
    sink.expect(Packet::PubRel(mid(1))).await;
    sink.send(Packet::PubComp(mid(1))).await;
    sink.ping().await;
}

// session_expiry.c: session_expiry__add; database.c: db__message_insert_outgoing.
#[tokio::test(start_paused = true)]
async fn offline_qos0_is_queued_only_when_configured_and_expiry_removes_session() {
    for enabled in [true, false] {
        let broker = broker(BrokerConfig {
            queue_qos0_messages: enabled,
            persistent_client_expiration: Some(Duration::from_secs(10)),
            ..BrokerConfig::default()
        });
        let mut sink = connected(&broker, "sink", false, false).await;
        sink.subscribe(&[("offline", Q0)], &[Q0]).await;
        sink.disconnect().await;
        let mut source = connected(&broker, "source", true, false).await;
        source
            .send(Packet::Publish(publish("offline", b"offline", Q1, 1)))
            .await;
        source.expect(Packet::PubAck(mid(1))).await;
        let mut sink = connected(&broker, "sink", false, true).await;
        if enabled {
            sink.expect(Packet::Publish(publish("offline", b"offline", Q0, 0)))
                .await;
        }
        sink.ping().await;
        sink.disconnect().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        connected(&broker, "sink", false, false).await.ping().await;
    }
}

// test/broker/23-security-password-file-reload.py; security_default.c:
// mosquitto_security_apply_default disconnects without publishing the will.
#[tokio::test]
async fn password_reload_closes_existing_invalidated_clients_without_a_will() {
    let broker = broker(BrokerConfig::default());
    let security = SecurityHandle::default();
    let mut observer = connected(&broker, "observer", true, false).await;
    observer.subscribe(&[("will", Q0)], &[Q0]).await;
    let (mut client, _) = Client::spawn(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                security: security.clone(),
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    client
        .connect(
            Connect {
                username: Some("user".into()),
                will: Some(will("will")),
                ..request("revoked", true)
            },
            Code::Accepted,
            false,
        )
        .await;
    security.replace(Some(PasswordFile::parse(b"").unwrap()), None);
    assert_eq!(client.recv().await, None);
    observer.ping().await;
}

// handle_connect.c: connect__on_authorised reports no session flag in MQTT 3.1.
#[tokio::test]
async fn v31_resumes_subscriptions_but_never_sets_session_present() {
    let broker = broker(BrokerConfig::default());
    let (mut sink, _) = Client::spawn(&broker, ConnectionInfo::default());
    let packet = Connect {
        protocol: Version::V31,
        ..request("old", false)
    };
    sink.connect(packet.clone(), Code::Accepted, false).await;
    sink.subscribe(&[("legacy", Q1)], &[Q1]).await;
    sink.disconnect().await;
    let (mut sink, _) = Client::spawn(&broker, ConnectionInfo::default());
    sink.connect(packet, Code::Accepted, false).await;
    let mut source = connected(&broker, "source", true, false).await;
    source
        .send(Packet::Publish(publish("legacy", b"still here", Q1, 1)))
        .await;
    source.expect(Packet::PubAck(mid(1))).await;
    sink.expect(Packet::Publish(publish("legacy", b"still here", Q1, 1)))
        .await;
}

// lib/packet_mosq.c: packet__check_in_packet_oversize rejects on the header
// alone; handle_connect.c: check_protocol_version applies per-listener flags.
#[tokio::test]
async fn oversized_frames_and_disabled_versions_close_without_waiting_for_payload() {
    let broker = broker(BrokerConfig {
        max_packet_size: 100,
        ..BrokerConfig::default()
    });
    let mut good = connected(&broker, "good", true, false).await;
    good.io.write_all(&[0x30, 101]).await.unwrap();
    assert_eq!(good.recv().await, None);
    let (mut old, _) = Client::spawn(
        &broker,
        ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                disable_protocol_v3: true,
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        },
    );
    old.connect(
        Connect {
            protocol: Version::V31,
            ..request("old", true)
        },
        Code::UnacceptableProtocolVersion,
        false,
    )
    .await;
    broker.shutdown();
}

struct BufferedTransport {
    io: BufWriter<DuplexStream>,
    closed: Arc<AtomicBool>,
}

impl AsyncRead for BufferedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for BufferedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.closed.store(true, Ordering::Relaxed);
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

// lib/packet_mosq.c: packet__write makes each response available to the
// transport. Buffered TLS/WS transports also need an explicit shutdown.
#[tokio::test]
async fn buffered_transport_flushes_mqtt_replies_and_receives_shutdown() {
    let broker = broker(BrokerConfig::default());
    let (io, server) = tokio::io::duplex(4096);
    let closed = Arc::new(AtomicBool::new(false));
    let transport = BufferedTransport {
        io: BufWriter::new(server),
        closed: closed.clone(),
    };
    let serving = broker.clone();
    let task =
        tokio::spawn(async move { serving.serve(transport, ConnectionInfo::default()).await });
    let mut peer = Client {
        io,
        buffer: BytesMut::new(),
        version: Version::V311,
    };
    peer.connect(request("buffered", true), Code::Accepted, false)
        .await;
    peer.ping().await;
    broker.shutdown();
    assert_eq!(peer.recv().await, None);
    task.await.unwrap().unwrap();
    assert!(closed.load(Ordering::Relaxed));
}

// plugin_acl_check.c: acl__check_dollar prevents client writes to $SYS and
// $share before a configured ACL could allow them.
#[tokio::test]
async fn reserved_topics_acknowledge_without_publishing() {
    let broker = broker(BrokerConfig::default());
    let mut observer = connected(&broker, "observer", true, false).await;
    observer
        .subscribe(&[("$SYS/#", Q1), ("topic", Q1)], &[Q1, Q1])
        .await;
    let mut source = connected(&broker, "source", true, false).await;
    for (id, topic) in [(1, "$SYS/invalid"), (2, "$share/group/topic")] {
        source
            .send(Packet::Publish(publish(topic, b"not forwarded", Q1, id)))
            .await;
        source.expect(Packet::PubAck(mid(id))).await;
    }
    observer.ping().await;
}

// test/broker/10-listener-mount-point.py; send_publish.c: send__publish.
#[tokio::test]
async fn listener_mount_points_are_internal_and_stripped_for_the_destination() {
    let broker = broker(BrokerConfig::default());
    let info = ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            mount_point: Some("mount/".into()),
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    };
    let (mut mounted, _) = Client::spawn(&broker, info.clone());
    mounted
        .connect(request("mounted", true), Code::Accepted, false)
        .await;
    mounted.subscribe(&[("#", Q1)], &[Q1]).await;
    let mut ordinary = connected(&broker, "ordinary", true, false).await;
    ordinary.subscribe(&[("#", Q1)], &[Q1]).await;
    let (mut source, _) = Client::spawn(&broker, info);
    source
        .connect(request("source", true), Code::Accepted, false)
        .await;
    source
        .send(Packet::Publish(publish("readings", b"value", Q1, 1)))
        .await;
    source.expect(Packet::PubAck(mid(1))).await;
    mounted
        .expect(Packet::Publish(publish("readings", b"value", Q1, 1)))
        .await;
    ordinary
        .expect(Packet::Publish(publish("mount/readings", b"value", Q1, 1)))
        .await;
}

// handle_publish.c: handle__accepted_publish and send_mosq.c: send__pubcomp.
// Mosquitto 2.1.4's v3.1.1 broker responds to an over-quota publish but does
// not deliver it when the PUBREL arrives.
#[tokio::test]
async fn inbound_qos2_over_quota_completes_without_delivery() {
    let broker = broker(BrokerConfig {
        max_inflight_messages: 1,
        ..BrokerConfig::default()
    });
    let mut observer = connected(&broker, "observer", true, false).await;
    observer.subscribe(&[("quota", Q0)], &[Q0]).await;
    let mut source = connected(&broker, "source", false, false).await;
    for (id, payload) in [(1, b"kept".as_slice()), (2, b"drop")] {
        source
            .send(Packet::Publish(publish("quota", payload, Q2, id)))
            .await;
        source.expect(Packet::PubRec(mid(id))).await;
    }
    for id in [2, 1] {
        source.send(Packet::PubRel(mid(id))).await;
        source.expect(Packet::PubComp(mid(id))).await;
    }
    observer
        .expect(Packet::Publish(publish("quota", b"kept", Q0, 0)))
        .await;
    observer.ping().await;
}

// context.c: context__init starts the initial timeout on socket accept,
// before any PROXY / TLS / WebSocket handshake.
#[tokio::test(start_paused = true)]
async fn transport_handshake_consumes_the_initial_connect_budget() {
    let broker = broker(BrokerConfig::default());
    let (mut peer, stream) = tokio::io::duplex(4096);
    let accepted = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(29)).await;
    let task = tokio::spawn(async move {
        broker
            .serve_accepted(stream, ConnectionInfo::default(), accepted)
            .await
    });
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        timeout(Duration::from_millis(1), peer.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    task.await.unwrap().unwrap();
}
