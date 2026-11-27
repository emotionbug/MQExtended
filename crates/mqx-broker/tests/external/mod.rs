use std::{collections::HashMap, sync::Mutex};

use mqx_auth::external::{
    AclAccess, AclIdentity, Authorization, BoxFuture, ExternalSecurity, Subject, Verdict,
};
use tokio::sync::{Notify, Semaphore};

use super::*;

mod wire_v5;

const PLUGIN_ID: u32 = 71;
const TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Rule {
    answer: Authorization,
    gate: Option<Arc<Gate>>,
}

type AclCall = (String, String, AclAccess);
type BasicCall = (String, Option<String>, Option<Bytes>);

pub(super) struct Scripted {
    deny_special_chars: bool,
    connect_only: bool,
    basic: Mutex<HashMap<String, Verdict>>,
    basic_calls: Mutex<Vec<BasicCall>>,
    acl: Mutex<HashMap<AclCall, Rule>>,
    acl_calls: Mutex<Vec<AclCall>>,
}

impl Scripted {
    pub(super) fn new() -> Arc<Self> {
        Self::with_connect_only(false)
    }

    fn with_connect_only(connect_only: bool) -> Arc<Self> {
        Arc::new(Self {
            deny_special_chars: true,
            connect_only,
            basic: Mutex::default(),
            basic_calls: Mutex::default(),
            acl: Mutex::default(),
            acl_calls: Mutex::default(),
        })
    }

    pub(super) fn security(self: &Arc<Self>) -> SecurityHandle {
        SecurityHandle::default().with_external(PLUGIN_ID, self.clone())
    }

    fn basic(&self, id: &str, verdict: Verdict) {
        self.basic.lock().unwrap().insert(id.into(), verdict);
    }

    fn rule(
        &self,
        id: &str,
        topic: &str,
        access: AclAccess,
        verdict: Verdict,
        ttl: Duration,
        gate: Option<Arc<Gate>>,
    ) {
        self.acl.lock().unwrap().insert(
            (id.into(), topic.into(), access),
            Rule {
                answer: Authorization {
                    verdict,
                    reuse_for: ttl,
                },
                gate,
            },
        );
    }

    pub(super) fn set(&self, id: &str, topic: &str, access: AclAccess, verdict: Verdict) {
        self.rule(id, topic, access, verdict, TTL, None);
    }

    pub(super) fn delay(
        &self,
        id: &str,
        topic: &str,
        access: AclAccess,
        verdict: Verdict,
    ) -> Arc<Gate> {
        let gate = Arc::new(Gate::new());
        self.rule(id, topic, access, verdict, TTL, Some(gate.clone()));
        gate
    }

    pub(super) fn count(&self, id: &str, topic: &str, access: AclAccess) -> usize {
        self.acl_calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(client, name, kind)| client == id && name == topic && *kind == access)
            .count()
    }

    fn total(&self) -> usize {
        self.acl_calls.lock().unwrap().len()
    }
}

impl ExternalSecurity for Scripted {
    fn deny_special_chars(&self) -> bool {
        self.deny_special_chars
    }

    fn connect_only_authentication(&self) -> bool {
        self.connect_only
    }

    fn authenticate<'a>(
        &'a self,
        client_id: &'a str,
        username: Option<&'a str>,
        password: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            self.basic_calls.lock().unwrap().push((
                client_id.into(),
                username.map(str::to_owned),
                password.map(Bytes::copy_from_slice),
            ));
            self.basic
                .lock()
                .unwrap()
                .get(client_id)
                .copied()
                .unwrap_or(Verdict::Defer)
        })
    }

    fn acl_identity(&self, subject: Subject<'_>) -> Option<AclIdentity> {
        if self.connect_only {
            return None;
        }
        Some(AclIdentity {
            client_id: Some(if subject.binding.synthetic {
                format!("synthetic:{}", subject.client_id).into()
            } else {
                subject.client_id.into()
            }),
            username: subject.username.map(Into::into),
        })
    }

    fn authorize<'a>(
        &'a self,
        identity: &'a AclIdentity,
        topic: &'a str,
        access: AclAccess,
    ) -> BoxFuture<'a, Authorization> {
        Box::pin(async move {
            let call = (
                identity.client_id.as_deref().unwrap().into(),
                topic.into(),
                access,
            );
            let rule = self.acl.lock().unwrap().get(&call).cloned();
            self.acl_calls.lock().unwrap().push(call);
            if let Some(rule) = rule {
                if let Some(gate) = rule.gate {
                    gate.started.notify_one();
                    let _ = gate.release.acquire().await;
                }
                rule.answer
            } else {
                Authorization {
                    verdict: Verdict::Allow,
                    reuse_for: TTL,
                }
            }
        })
    }
}

pub(super) struct Gate {
    started: Notify,
    release: Semaphore,
}

impl Gate {
    fn new() -> Self {
        Self {
            started: Notify::new(),
            release: Semaphore::new(0),
        }
    }

    pub(super) async fn entered(&self) {
        timeout(WAIT, self.started.notified())
            .await
            .expect("authorization did not start");
    }

    pub(super) fn resolve(&self) {
        self.release.close();
    }
}

pub(super) fn listener(security: SecurityHandle) -> ConnectionInfo {
    ConnectionInfo {
        listener: Arc::new(ListenerPolicy {
            security,
            ..ListenerPolicy::default()
        }),
        ..ConnectionInfo::default()
    }
}

pub(super) async fn connect_external(
    broker: &Broker,
    info: &ConnectionInfo,
    id: &str,
    clean: bool,
    present: bool,
) -> Client {
    let (mut client, _) = Client::spawn(broker, info.clone());
    client
        .connect(request(id, clean), Code::Accepted, present)
        .await;
    client
}

pub(super) async fn silent(client: &mut Client) {
    assert!(client.buffer.is_empty(), "unexpected buffered packet bytes");
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(25), client.io.read(&mut byte))
            .await
            .is_err(),
        "unexpected packet or connection close"
    );
}

pub(super) async fn send_qos1(client: &mut Client, topic: &str, payload: &'static [u8], id: u16) {
    client
        .send(Packet::Publish(publish(topic, payload, Q1, id)))
        .await;
    client.expect(Packet::PubAck(mid(id))).await;
}

async fn setup(config: BrokerConfig, plugin: &Arc<Scripted>) -> (Broker, ConnectionInfo) {
    let broker = broker(config);
    let handle = plugin.security();
    broker.register_security(&handle).await.unwrap();
    (broker, listener(handle))
}

fn subscribe_packet(filters: &[&str]) -> Packet {
    Packet::Subscribe(Subscribe {
        packet_id: mid(10),
        filters: filters
            .iter()
            .map(|filter| ((*filter).into(), Q1))
            .collect(),
    })
}

#[tokio::test]
async fn connect_only_authentication_keeps_clients_and_reloads_native_acl() {
    let broker = broker(BrokerConfig::default());
    let plugin = Scripted::with_connect_only(true);
    let acl = |text: &[u8]| Some(AclFile::parse(text).unwrap());
    let security = SecurityHandle::new(None, acl(b"user sensor\ntopic read sensor/old\n"))
        .with_external(PLUGIN_ID, plugin.clone());
    broker.register_security(&security).await.unwrap();
    let (mut sink, _) = Client::spawn(&broker, listener(security.clone()));
    plugin.basic("sensor.unit", Verdict::Allow);
    sink.connect(
        Connect {
            username: Some("sensor".into()),
            password: Some(Bytes::from_static(b"short-lived")),
            ..request("sensor.unit", true)
        },
        Code::Accepted,
        false,
    )
    .await;
    sink.subscribe(&[("sensor/#", Q0)], &[Q0]).await;
    let mut source = connected(&broker, "source", true, false).await;
    send_qos1(&mut source, "sensor/new", b"blocked", 1).await;
    send_qos1(&mut source, "sensor/old", b"allowed", 2).await;
    sink.expect(Packet::Publish(publish("sensor/old", b"allowed", Q0, 0)))
        .await;

    // The token would now fail authentication; a new ACL takes effect anyway.
    plugin.basic("sensor.unit", Verdict::Deny);
    security.replace(None, acl(b"user sensor\ntopic read sensor/new\n"));
    sink.ping().await;
    send_qos1(&mut source, "sensor/old", b"blocked", 3).await;
    send_qos1(&mut source, "sensor/new", b"allowed", 4).await;
    sink.expect(Packet::Publish(publish("sensor/new", b"allowed", Q0, 0)))
        .await;
    assert_eq!(plugin.basic_calls.lock().unwrap().len(), 1);
    assert_eq!(plugin.total(), 0);
}

// plugin_basic_auth.c: mosquitto_basic_auth; handle_connect.c: handle__connect.
#[tokio::test]
async fn external_connect_only_defer_reaches_password_file_or_anonymous() {
    let plugin = Scripted::new();
    let broker = broker(BrokerConfig::default());
    let password_file = PasswordFile::parse(b"test:$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==\n").unwrap();
    let security =
        SecurityHandle::new(Some(password_file), None).with_external(PLUGIN_ID, plugin.clone());
    broker.register_security(&security).await.unwrap();
    let good = Some(("test", b"test".as_slice()));
    let bad = Some(("test", b"bad".as_slice()));
    let missing = Some(("missing", b"bad".as_slice()));
    let cases = [
        (
            "plugin-allow",
            missing,
            false,
            Verdict::Allow,
            Some(Code::Accepted),
        ),
        (
            "plugin-deny",
            good,
            true,
            Verdict::Deny,
            Some(Code::NotAuthorized),
        ),
        ("plugin-error", good, true, Verdict::Error, None),
        (
            "file-allow",
            good,
            false,
            Verdict::Defer,
            Some(Code::Accepted),
        ),
        (
            "file-deny",
            bad,
            true,
            Verdict::Defer,
            Some(Code::NotAuthorized),
        ),
        (
            "anonymous-allow",
            None,
            true,
            Verdict::Defer,
            Some(Code::Accepted),
        ),
        (
            "anonymous-deny",
            None,
            false,
            Verdict::Defer,
            Some(Code::NotAuthorized),
        ),
        (
            "anonymous-override",
            None,
            false,
            Verdict::Allow,
            Some(Code::Accepted),
        ),
        (
            "anonymous-plugin-deny",
            None,
            true,
            Verdict::Deny,
            Some(Code::NotAuthorized),
        ),
        ("anonymous-plugin-error", None, true, Verdict::Error, None),
    ];
    for (id, credentials, anonymous, verdict, expected) in cases {
        plugin.basic(id, verdict);
        let info = ConnectionInfo {
            listener: Arc::new(ListenerPolicy {
                security: security.clone(),
                allow_anonymous: Some(anonymous),
                ..ListenerPolicy::default()
            }),
            ..ConnectionInfo::default()
        };
        let (mut client, _) = Client::spawn(&broker, info);
        let (username, password) = credentials.map_or((None, None), |(user, pass)| {
            (Some(user.to_owned()), Some(Bytes::from_static(pass)))
        });
        let connect = Connect {
            username: username.clone(),
            password: password.clone(),
            ..request(id, true)
        };
        if let Some(code) = expected {
            client.connect(connect, code, false).await;
            if code == Code::Accepted {
                client.disconnect().await;
            } else {
                assert_eq!(client.recv().await, None, "{id}");
            }
        } else {
            client.send(Packet::Connect(connect)).await;
            assert_eq!(
                client.recv().await,
                None,
                "{id} got a CONNACK on plugin error"
            );
        }
        assert_eq!(
            plugin.basic_calls.lock().unwrap().last(),
            Some(&(id.to_owned(), username, password))
        );
    }
    assert_eq!(plugin.basic_calls.lock().unwrap().len(), cases.len());

    let security = plugin.security();
    broker.register_security(&security).await.unwrap();
    let (mut deferred, _) = Client::spawn(&broker, listener(security));
    deferred
        .connect(
            Connect {
                username: Some("missing".into()),
                ..request("no-password-file", true)
            },
            Code::NotAuthorized,
            false,
        )
        .await;
}

// handle_publish.c: handle__publish ACKs a denial, but returns immediately on other ACL errors.
#[tokio::test]
async fn external_write_allow_delivers_deny_acks_and_error_closes_without_ack() {
    let plugin = Scripted::new();
    plugin.set("writer", "write/deny", AclAccess::Write, Verdict::Deny);
    plugin.set("writer", "write/error", AclAccess::Write, Verdict::Error);
    plugin.set("writer", "write/file", AclAccess::Write, Verdict::Defer);
    plugin.set("writer", "write/closed", AclAccess::Write, Verdict::Defer);
    let broker = broker(BrokerConfig::default());
    let file =
        AclFile::parse(b"topic deny write/allow\ntopic write write/file\ntopic write write/deny\n")
            .unwrap();
    let security = SecurityHandle::new(None, Some(file)).with_external(PLUGIN_ID, plugin.clone());
    broker.register_security(&security).await.unwrap();
    let info = listener(security);
    let mut writer = connect_external(&broker, &info, "writer", true, false).await;
    let mut reader = connected(&broker, "reader", true, false).await;
    reader.subscribe(&[("write/#", Q1)], &[Q1]).await;

    send_qos1(&mut writer, "write/deny", b"denied", 10).await;
    send_qos1(&mut writer, "write/closed", b"all callbacks deferred", 14).await;
    send_qos1(&mut writer, "write/allow", b"allowed", 11).await;
    reader
        .expect(Packet::Publish(publish("write/allow", b"allowed", Q1, 1)))
        .await;
    send_qos1(&mut writer, "write/file", b"allowed by file", 15).await;
    reader
        .expect(Packet::Publish(publish(
            "write/file",
            b"allowed by file",
            Q1,
            2,
        )))
        .await;
    writer
        .send(Packet::Publish(publish("write/error", b"error", Q1, 12)))
        .await;
    assert_eq!(writer.recv().await, None);
    let mut barrier = connected(&broker, "barrier", true, false).await;
    send_qos1(&mut barrier, "write/barrier", b"after", 13).await;
    reader
        .expect(Packet::Publish(publish("write/barrier", b"after", Q1, 3)))
        .await;
    assert_eq!(plugin.total(), 5);
}

#[tokio::test]
async fn qos2_pubrel_does_not_repeat_the_publish_write_check() {
    let plugin = Scripted::new();
    plugin.rule(
        "writer",
        "write/qos2",
        AclAccess::Write,
        Verdict::Allow,
        Duration::ZERO,
        None,
    );
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut writer = connect_external(&broker, &info, "writer", true, false).await;
    let mut reader = connected(&broker, "reader", true, false).await;
    reader.subscribe(&[("write/qos2", Q1)], &[Q1]).await;
    writer
        .send(Packet::Publish(publish("write/qos2", b"allowed", Q2, 10)))
        .await;
    writer.expect(Packet::PubRec(mid(10))).await;
    assert_eq!(plugin.count("writer", "write/qos2", AclAccess::Write), 1);
    // Mosquitto's database.c: db__message_release_incoming routes the
    // previously admitted message, even if WRITE policy changed since PUBLISH.
    plugin.set("writer", "write/qos2", AclAccess::Write, Verdict::Deny);
    writer.send(Packet::PubRel(mid(10))).await;
    writer.expect(Packet::PubComp(mid(10))).await;
    reader
        .expect(Packet::Publish(publish("write/qos2", b"allowed", Q1, 1)))
        .await;
    assert_eq!(plugin.count("writer", "write/qos2", AclAccess::Write), 1);
}

// handle_subscribe.c: handle__subscribe applies filters individually, before SUBACK.
#[tokio::test]
async fn external_subscribe_denial_reports_one_failure_but_error_keeps_only_earlier_filters() {
    let plugin = Scripted::new();
    plugin.set(
        "subscriber",
        "sub/deny",
        AclAccess::Subscribe,
        Verdict::Deny,
    );
    plugin.set(
        "subscriber",
        "sub/error",
        AclAccess::Subscribe,
        Verdict::Error,
    );
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut sink = connect_external(&broker, &info, "subscriber", false, false).await;
    sink.send(subscribe_packet(&["sub/deny", "sub/ok"])).await;
    sink.expect(Packet::SubAck(SubAck {
        packet_id: mid(10),
        return_codes: vec![
            SubscribeReturnCode::Failure,
            SubscribeReturnCode::Success(Q1),
        ],
    }))
    .await;
    sink.send(subscribe_packet(&["sub/kept", "sub/error", "sub/skipped"]))
        .await;
    assert_eq!(sink.recv().await, None);
    assert_eq!(broker.metrics().subscriptions, 2);

    let mut sink = connect_external(&broker, &info, "subscriber", false, true).await;
    let mut source = connected(&broker, "source", true, false).await;
    for (id, topic) in ["sub/deny", "sub/error", "sub/skipped", "sub/kept", "sub/ok"]
        .into_iter()
        .enumerate()
    {
        send_qos1(&mut source, topic, b"live", 30 + id as u16).await;
    }
    for (topic, id) in [("sub/kept", 1), ("sub/ok", 2)] {
        sink.expect(Packet::Publish(publish(topic, b"live", Q1, id)))
            .await;
    }
}

// src/subs.c: subs__send checks READ per recipient. A pending verdict must not
// let later cached deliveries overtake it or consume packet IDs for denied items.
#[tokio::test]
async fn external_live_reads_park_in_order_without_blocking_other_subscribers() {
    let plugin = Scripted::new();
    let gate = plugin.delay("sink", "live/first", AclAccess::Read, Verdict::Allow);
    plugin.set("sink", "live/deny", AclAccess::Read, Verdict::Deny);
    plugin.set("sink", "live/error", AclAccess::Read, Verdict::Error);
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut sink = connect_external(&broker, &info, "sink", true, false).await;
    sink.subscribe(&[("live/#", Q1)], &[Q1]).await;
    let mut observer = connected(&broker, "observer", true, false).await;
    observer.subscribe(&[("live/#", Q1)], &[Q1]).await;
    let mut source = connected(&broker, "source", true, false).await;

    send_qos1(&mut source, "live/ready", b"warm cache", 10).await;
    sink.expect(Packet::Publish(publish("live/ready", b"warm cache", Q1, 1)))
        .await;
    observer
        .expect(Packet::Publish(publish("live/ready", b"warm cache", Q1, 1)))
        .await;
    send_qos1(&mut source, "live/first", b"head", 11).await;
    gate.entered().await;
    observer
        .expect(Packet::Publish(publish("live/first", b"head", Q1, 2)))
        .await;
    for (id, topic) in [(3, "live/deny"), (4, "live/error"), (5, "live/ready")] {
        send_qos1(&mut source, topic, b"behind", id + 10).await;
        observer
            .expect(Packet::Publish(publish(topic, b"behind", Q1, id)))
            .await;
    }
    silent(&mut sink).await;
    gate.resolve();
    sink.expect(Packet::Publish(publish("live/first", b"head", Q1, 2)))
        .await;
    sink.expect(Packet::Publish(publish("live/ready", b"behind", Q1, 3)))
        .await;
    sink.ping().await;
    for topic in ["live/first", "live/deny", "live/error", "live/ready"] {
        assert_eq!(plugin.count("sink", topic, AclAccess::Read), 1, "{topic}");
    }

    // Denial is reusable, but an error must make another backend request.
    for (id, topic) in [(20, "live/deny"), (21, "live/error"), (22, "live/ready")] {
        send_qos1(&mut source, topic, b"again", id).await;
    }
    sink.expect(Packet::Publish(publish("live/ready", b"again", Q1, 4)))
        .await;
    assert_eq!(plugin.count("sink", "live/deny", AclAccess::Read), 1);
    assert_eq!(plugin.count("sink", "live/error", AclAccess::Read), 2);
}

// retain.c: retain__process checks the reader and then the synthetic source.
// handle_subscribe.c: handle__subscribe stops on either error, without SUBACK.
#[tokio::test]
async fn retained_read_or_source_write_error_preserves_earlier_replay_without_suback() {
    for failing_access in [AclAccess::Read, AclAccess::Write] {
        let plugin = Scripted::new();
        let failing_identity = if failing_access == AclAccess::Read {
            "sink"
        } else {
            "synthetic:source"
        };
        let gate = plugin.delay(
            failing_identity,
            "retain/error",
            failing_access,
            Verdict::Error,
        );
        let (broker, info) = setup(
            BrokerConfig {
                check_retain_source: true,
                ..BrokerConfig::default()
            },
            &plugin,
        )
        .await;
        let mut source = connect_external(&broker, &info, "source", true, false).await;
        for (id, topic) in [(1, "retain/ok"), (2, "retain/error"), (3, "retain/skipped")] {
            source
                .send(Packet::Publish(Publish {
                    retain: true,
                    ..publish(topic, b"stored", Q1, id)
                }))
                .await;
            source.expect(Packet::PubAck(mid(id))).await;
        }
        assert_eq!(
            plugin.count("synthetic:source", "retain/error", AclAccess::Write),
            0
        );
        source.disconnect().await;

        let mut sink = connect_external(&broker, &info, "sink", true, false).await;
        sink.send(subscribe_packet(&[
            "retain/ok",
            "retain/error",
            "retain/skipped",
        ]))
        .await;
        gate.entered().await;
        silent(&mut sink).await;
        assert_eq!(
            broker.metrics().subscriptions,
            0,
            "retained checks must run before applying SUBSCRIBE"
        );
        gate.resolve();
        sink.expect(Packet::Publish(Publish {
            retain: true,
            ..publish("retain/ok", b"stored", Q1, 1)
        }))
        .await;
        sink.ping().await;
        assert_eq!(broker.metrics().subscriptions, 2);
        assert_eq!(plugin.count("sink", "retain/ok", AclAccess::Read), 1);
        assert_eq!(
            plugin.count("synthetic:source", "retain/ok", AclAccess::Write),
            1
        );
        assert_eq!(
            plugin.count(failing_identity, "retain/error", failing_access),
            1
        );
    }
}

// context.c: context__send_will checks WRITE at disconnect, not at CONNECT.
#[tokio::test]
async fn external_wills_wait_for_write_and_skip_deny_and_error() {
    let plugin = Scripted::new();
    let gate = plugin.delay("first", "will/first", AclAccess::Write, Verdict::Allow);
    plugin.set("denied", "will/deny", AclAccess::Write, Verdict::Deny);
    plugin.set("failed", "will/error", AclAccess::Write, Verdict::Error);
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut sink = connected(&broker, "sink", true, false).await;
    sink.subscribe(&[("will/#", Q0)], &[Q0]).await;
    let mut clients = Vec::new();
    for (id, topic) in [
        ("first", "will/first"),
        ("denied", "will/deny"),
        ("failed", "will/error"),
        ("last", "will/last"),
    ] {
        let (mut client, task) = Client::spawn(&broker, info.clone());
        client
            .connect(
                Connect {
                    will: Some(will(topic)),
                    ..request(id, true)
                },
                Code::Accepted,
                false,
            )
            .await;
        clients.push((client, task));
    }
    assert_eq!(plugin.total(), 0);
    for (index, (client, task)) in clients.into_iter().enumerate() {
        drop(client);
        if index == 0 {
            gate.entered().await;
        }
        timeout(WAIT, task)
            .await
            .expect("connection waited on parked will")
            .unwrap()
            .unwrap();
    }
    silent(&mut sink).await;
    gate.resolve();
    for topic in ["will/first", "will/last"] {
        sink.expect(Packet::Publish(publish(topic, b"gone", Q0, 0)))
            .await;
    }
    sink.ping().await;
    assert_eq!(plugin.total(), 4);
}

// database.c: db__check_acl_of_all_messages removes previously admitted messages
// if their READ verdict on reconnect is now a denial or a backend error.
#[tokio::test(start_paused = true)]
async fn reconnect_rechecks_inflight_and_queued_deliveries_before_resending() {
    let plugin = Scripted::new();
    let (broker, info) = setup(
        BrokerConfig {
            max_inflight_messages: 1,
            ..BrokerConfig::default()
        },
        &plugin,
    )
    .await;
    let mut sink = connect_external(&broker, &info, "durable", false, false).await;
    sink.subscribe(&[("resume/#", Q1)], &[Q1]).await;
    let mut source = connected(&broker, "source", true, false).await;
    let topics = [
        (1, "resume/revoked"),
        (2, "resume/error"),
        (3, "resume/kept"),
    ];
    // Warm the three READ verdicts first. The later PUBACKs on the source
    // then fence inbox admission, even for packets behind the in-flight limit.
    for (id, topic) in topics {
        send_qos1(&mut source, topic, b"warm", 10 + id).await;
        sink.expect(Packet::Publish(publish(topic, b"warm", Q1, id)))
            .await;
        sink.send(Packet::PubAck(mid(id))).await;
    }
    sink.ping().await;
    for (id, topic) in topics {
        send_qos1(&mut source, topic, b"pending", 20 + id).await;
    }
    sink.expect(Packet::Publish(publish(
        "resume/revoked",
        b"pending",
        Q1,
        4,
    )))
    .await;
    sink.disconnect().await;
    plugin.set("durable", "resume/revoked", AclAccess::Read, Verdict::Deny);
    plugin.set("durable", "resume/error", AclAccess::Read, Verdict::Error);
    tokio::time::advance(TTL + Duration::from_secs(1)).await;

    let mut sink = connect_external(&broker, &info, "durable", false, true).await;
    sink.expect(Packet::Publish(publish("resume/kept", b"pending", Q1, 6)))
        .await;
    sink.send(Packet::PubAck(mid(6))).await;
    sink.ping().await;
    for (_, topic) in topics {
        assert_eq!(
            plugin.count("durable", topic, AclAccess::Read),
            2,
            "{topic}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn external_write_verdict_is_reused_through_its_deadline_but_not_after() {
    let plugin = Scripted::new();
    let ttl = Duration::from_secs(5);
    plugin.rule(
        "writer",
        "cache",
        AclAccess::Write,
        Verdict::Allow,
        ttl,
        None,
    );
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut source = connect_external(&broker, &info, "writer", true, false).await;
    let mut sink = connected(&broker, "sink", true, false).await;
    sink.subscribe(&[("cache", Q1)], &[Q1]).await;

    send_qos1(&mut source, "cache", b"first", 10).await;
    sink.expect(Packet::Publish(publish("cache", b"first", Q1, 1)))
        .await;
    plugin.set("writer", "cache", AclAccess::Write, Verdict::Deny);
    tokio::time::advance(ttl).await;
    send_qos1(&mut source, "cache", b"still allowed", 11).await;
    sink.expect(Packet::Publish(publish("cache", b"still allowed", Q1, 2)))
        .await;
    assert_eq!(plugin.count("writer", "cache", AclAccess::Write), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    send_qos1(&mut source, "cache", b"now denied", 12).await;
    sink.ping().await;
    assert_eq!(plugin.count("writer", "cache", AclAccess::Write), 2);
}

// plugin_acl_check.c: acl__pre_check denies these subjects before consulting a v4 callback.
#[tokio::test]
async fn dangerous_id_and_username_are_rejected_before_the_external_acl_callback() {
    let plugin = Scripted::new();
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut sink = connected(&broker, "sink", true, false).await;
    sink.subscribe(&[("guard", Q1)], &[Q1]).await;
    for (id, username) in [
        ("id+", None),
        ("id#", None),
        ("id/", None),
        ("user-plus", Some("u+")),
        ("user-hash", Some("u#")),
        ("user-slash", Some("u/")),
    ] {
        plugin.basic(id, Verdict::Allow);
        let (mut client, _) = Client::spawn(&broker, info.clone());
        client
            .connect(
                Connect {
                    username: username.map(str::to_owned),
                    ..request(id, true)
                },
                Code::Accepted,
                false,
            )
            .await;
        client.send(subscribe_packet(&["guard"])).await;
        client
            .expect(Packet::SubAck(SubAck {
                packet_id: mid(10),
                return_codes: vec![SubscribeReturnCode::Failure],
            }))
            .await;
        send_qos1(&mut client, "guard", b"denied", 11).await;
        client.disconnect().await;
    }
    sink.ping().await;
    assert_eq!(plugin.total(), 0);

    let mut opt_out = Scripted::new();
    Arc::get_mut(&mut opt_out).unwrap().deny_special_chars = false;
    let security = SecurityHandle::default().with_external(PLUGIN_ID + 1, opt_out.clone());
    broker.register_security(&security).await.unwrap();
    let mut client = connect_external(&broker, &listener(security), "id/", true, false).await;
    send_qos1(&mut client, "guard", b"allowed", 12).await;
    sink.expect(Packet::Publish(publish("guard", b"allowed", Q1, 1)))
        .await;
    assert_eq!(opt_out.count("id/", "guard", AclAccess::Write), 1);
}

// plugin_v4.c: ACL UNSUBSCRIBE is granted by the wrapper, not the plugin.
#[tokio::test(start_paused = true)]
async fn unsubscribe_removes_subscription_without_external_callback() {
    let plugin = Scripted::new();
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;
    let mut sink = connect_external(&broker, &info, "sink", true, false).await;
    sink.subscribe(&[("leave", Q1), ("stay", Q1)], &[Q1, Q1])
        .await;
    tokio::time::advance(TTL + Duration::from_secs(1)).await;
    sink.send(Packet::Unsubscribe(Unsubscribe {
        packet_id: mid(10),
        filters: vec!["leave".into()],
    }))
    .await;
    sink.expect(Packet::UnsubAck(mid(10))).await;
    assert_eq!(plugin.total(), 2);
    let mut source = connected(&broker, "source", true, false).await;
    send_qos1(&mut source, "leave", b"unsubscribed", 11).await;
    send_qos1(&mut source, "stay", b"subscribed", 12).await;
    sink.expect(Packet::Publish(publish("stay", b"subscribed", Q1, 1)))
        .await;
    assert_eq!(plugin.total(), 3);
}
