use mqx_auth::external::{Authorization, BoxFuture};

use super::*;

struct Plugin {
    shared_identity: bool,
}

impl ExternalSecurity for Plugin {
    fn deny_special_chars(&self) -> bool {
        true
    }

    fn authenticate<'a>(
        &'a self,
        _client_id: &'a str,
        _username: Option<&'a str>,
        _password: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Verdict> {
        panic!("state must not authenticate")
    }

    fn acl_identity(&self, subject: Subject<'_>) -> Option<AclIdentity> {
        Some(AclIdentity {
            client_id: (!self.shared_identity && !subject.binding.synthetic)
                .then(|| subject.client_id.into()),
            username: subject.username.map(Into::into),
        })
    }

    fn authorize<'a>(
        &'a self,
        _identity: &'a AclIdentity,
        _topic: &'a str,
        _access: AclAccess,
    ) -> BoxFuture<'a, Authorization> {
        panic!("state must not call the backend")
    }
}

const PLUGIN: u32 = 7;
const NOW: Duration = Duration::from_secs(9);

fn state(config: BrokerConfig) -> State {
    let state = State::new(Arc::new(config));
    state.external_plugins().insert(
        PLUGIN,
        Arc::new(Plugin {
            shared_identity: false,
        }),
    );
    state
}

fn claim(id: &str, clean_start: bool, external: bool) -> Claim {
    Claim {
        publisher: Publisher {
            id: id.into(),
            username: Some(id.into()),
            security: 0,
            dynamic_security: None,
            external: external.then_some((PLUGIN, Binding::default())),
        },
        clean_start,
        bridge: false,
        max_qos: QoS::ExactlyOnce,
        will: None,
        v5: None,
        now: NOW,
        internal_bridge: None,
        dynamic_security_revision: None,
        verdicts: Vec::new(),
    }
}

fn connect(state: &mut State, request: Claim) -> Lease {
    connect_on(state, Owner::LOCAL, request)
}

fn connect_on(state: &mut State, owner: Owner, request: Claim) -> Lease {
    let Reply::Claimed { lease, .. } = state
        .apply(Command::Claim {
            owner,
            token: [0; 16],
            request,
        })
        .reply
    else {
        panic!("expected claim to succeed");
    };
    lease
}

fn check(
    id: &str,
    topic: &str,
    access: AclAccess,
    verdict: Verdict,
    expires: Duration,
) -> ResolvedVerdict {
    ResolvedVerdict {
        key: VerdictKey {
            plugin: PLUGIN,
            identity: AclIdentity {
                client_id: Some(id.into()),
                username: Some(id.into()),
            },
            topic: topic.into(),
            access,
        },
        verdict,
        expires,
    }
}

fn receive(topic: &str, retain: bool) -> Operation {
    Operation::Receive(Publication::legacy(
        Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain,
            topic: topic.into(),
            packet_id: None,
            payload: Bytes::from_static(b"payload"),
        },
        NOW,
    ))
}

fn subscribe(filters: &[&str]) -> Operation {
    Operation::subscribe(
        filters
            .iter()
            .map(|filter| SubscriptionRequest::legacy(((*filter).into(), QoS::ExactlyOnce)))
            .collect(),
        NOW,
    )
}

fn entry(lease: &Lease, operations: Vec<Operation>) -> BatchEntry {
    BatchEntry::Act(Mutations {
        lease: lease.clone(),
        operations,
    })
}

fn authorized(lease: &Lease, operation: Operation, verdicts: Vec<ResolvedVerdict>) -> Command {
    Command::Batch(vec![entry(
        lease,
        vec![Operation::Authorize(verdicts), operation],
    )])
}

fn resolve(state: &mut State, verdicts: Vec<ResolvedVerdict>) -> Outcome {
    resolve_for(state, VerdictTarget::Session(Some(Owner::LOCAL)), verdicts)
}

fn resolve_for(
    state: &mut State,
    target: VerdictTarget,
    verdicts: Vec<ResolvedVerdict>,
) -> Outcome {
    state.apply(Command::ResolveVerdicts {
        now: NOW,
        target,
        verdicts,
    })
}

#[test]
fn parked_deliveries_round_trip_and_do_not_let_cached_deliveries_overtake() {
    let mut state = state(BrokerConfig::default());
    let source = connect(&mut state, claim("source", true, false));
    let subscriber = connect(&mut state, claim("subscriber", true, true));
    let permit_sub = check(
        "subscriber",
        "#",
        AclAccess::Subscribe,
        Verdict::Allow,
        Duration::ZERO,
    );
    state.apply(authorized(&subscriber, subscribe(&["#"]), vec![permit_sub]));

    let read =
        |topic, verdict, expires| check("subscriber", topic, AclAccess::Read, verdict, expires);
    let first = read("first", Verdict::Error, NOW);
    let second = read("second", Verdict::Allow, NOW);
    let parked = state.apply(Command::Act(source.clone(), receive("first", false)));
    assert_eq!(parked.reply, Reply::PublishReason(R::SUCCESS.0));
    assert_eq!(
        parked.effects,
        [Effect::NeedVerdicts {
            target: VerdictTarget::Session(Some(Owner::LOCAL)),
            keys: vec![first.key.clone()],
        }]
    );
    assert!(resolve(&mut state, vec![second.clone()]).effects.is_empty());
    let packet = match receive("second", false) {
        Operation::Receive(publication) => publication.packet,
        _ => unreachable!(),
    };
    assert!(
        state
            .fast_route(Owner::LOCAL, &source, &packet, false, NOW)
            .is_none()
    );
    assert!(
        state
            .apply(Command::Act(source.clone(), receive("second", false)))
            .effects
            .is_empty()
    );

    let before = state.snapshot();
    state.restore(&before).unwrap();
    assert_eq!(
        state.pending_verdicts(NOW),
        [(
            VerdictTarget::Session(Some(Owner::LOCAL)),
            vec![first.key.clone()]
        )]
    );
    let result = resolve(&mut state, vec![first]);
    assert!(
        matches!(&result.effects[..], [Effect::Deliver { owner, packet }]
        if *owner == subscriber.epoch && packet.message.topic.as_ref() == "second")
    );
    assert!(state.pending_verdicts(NOW).is_empty());
    assert_eq!(state.verdicts.entries.len(), 1);
    assert!(
        state
            .fast_route(Owner::LOCAL, &source, &packet, false, NOW)
            .is_some()
    );
    let later = NOW + Duration::from_nanos(1);
    assert!(
        state
            .fast_route(Owner::LOCAL, &source, &packet, false, later)
            .is_none()
    );
    state.apply(Command::Expire(later));
    assert!(state.verdicts.entries.is_empty());
}

#[test]
fn single_use_reads_consume_one_pin_on_the_requesting_owner() {
    let mut state = state(BrokerConfig::default());
    state.external_plugins().insert(
        PLUGIN,
        Arc::new(Plugin {
            shared_identity: true,
        }),
    );
    let other = Owner {
        node: 2,
        incarnation: [2; 16],
    };
    state.apply(Command::Boot {
        owner: other,
        previous: None,
        now: NOW,
    });
    let source = connect(&mut state, claim("source", true, false));
    let mut sub = check("shared", "topic", AclAccess::Subscribe, Verdict::Allow, NOW);
    sub.key.identity.client_id = None;
    let shared = |id| {
        let mut request = claim(id, true, true);
        request.publisher.username = Some("shared".into());
        request
    };
    let a = connect(&mut state, shared("a"));
    let b = connect(&mut state, shared("b"));
    let c = connect_on(&mut state, other, shared("c"));
    for lease in [&a, &b, &c] {
        state.apply(authorized(lease, subscribe(&["topic"]), vec![sub.clone()]));
    }
    let read = ResolvedVerdict {
        key: VerdictKey {
            access: AclAccess::Read,
            ..sub.key
        },
        verdict: Verdict::Allow,
        expires: Duration::ZERO,
    };
    assert_eq!(
        state
            .apply(Command::Act(source, receive("topic", false)))
            .effects
            .len(),
        3
    );
    assert!(matches!(
        &resolve_for(&mut state, VerdictTarget::Session(Some(other)), vec![read.clone()]).effects[..],
        [Effect::Deliver { owner, .. }] if *owner == c.epoch
    ));
    let first = resolve(&mut state, vec![read.clone()]);
    assert!(matches!(&first.effects[..], [
        Effect::Deliver { owner, .. },
        Effect::NeedVerdicts { target: VerdictTarget::Session(Some(Owner::LOCAL)), keys }
    ] if *owner == a.epoch && keys == std::slice::from_ref(&read.key)));
    let second = resolve(&mut state, vec![read]);
    assert!(matches!(&second.effects[..], [Effect::Deliver { owner, .. }] if *owner == b.epoch));
    assert!(state.pending_verdicts(NOW).is_empty());
}

#[test]
fn single_use_subscribe_pins_follow_filter_order_in_preflight_and_apply() {
    let mut state = state(BrokerConfig::default());
    let sink = connect(&mut state, claim("sink", true, true));
    let op = subscribe(&["topic", "topic"]);
    let grant = check(
        "sink",
        "topic",
        AclAccess::Subscribe,
        Verdict::Allow,
        Duration::ZERO,
    );
    let deny = ResolvedVerdict {
        verdict: Verdict::Deny,
        ..grant.clone()
    };
    assert!(matches!(
        &state.operation_verdicts_with(&sink, &op, NOW, std::slice::from_ref(&grant))[..],
        [VerdictRequest::Missing(key)] if key == &grant.key
    ));
    let pins = vec![grant, deny];
    assert!(
        state
            .operation_verdicts_with(&sink, &op, NOW, &pins)
            .is_empty()
    );
    assert_eq!(
        state.apply(authorized(&sink, op, pins)).reply,
        Reply::Batched(vec![vec![Reply::Subscribed(vec![
            SubscribeReturnCode::Success(QoS::ExactlyOnce),
            SubscribeReturnCode::Failure,
        ])]])
    );
}

#[test]
fn single_use_and_error_verdicts_do_not_escape_their_act_on_replay() {
    let mut state = state(BrokerConfig::default());
    let lease = connect(&mut state, claim("source", true, true));
    let write = |verdict| check("source", "topic", AclAccess::Write, verdict, Duration::ZERO);
    let cmd = Command::Batch(vec![
        entry(
            &lease,
            vec![
                Operation::Authorize(vec![write(Verdict::Allow)]),
                receive("topic", true),
            ],
        ),
        entry(&lease, vec![receive("topic", false)]),
        entry(
            &lease,
            vec![
                Operation::Authorize(vec![write(Verdict::Error)]),
                receive("topic", false),
            ],
        ),
    ]);
    let bytes = rmp_serde::to_vec(&cmd).unwrap();
    let outcome = state.apply(rmp_serde::from_slice(&bytes).unwrap());
    assert_eq!(
        outcome.reply,
        Reply::Batched(vec![
            vec![Reply::PublishReason(R::NO_MATCHING_SUBSCRIBERS.0)],
            vec![Reply::ExternalAclError],
            vec![Reply::ExternalAclError],
        ])
    );
    assert_eq!(state.retained.count(), 1);
    assert!(state.verdicts.entries.is_empty());
}

#[test]
fn old_messagepack_claim_defaults_the_external_binding_and_verdicts() {
    let legacy_publisher = ("source", Some("user"), 42_u64);
    let legacy_claim = (
        legacy_publisher,
        false,
        false,
        QoS::ExactlyOnce,
        None::<LastWill>,
    );
    let bytes = rmp_serde::to_vec(&legacy_claim).unwrap();
    let claim: Claim = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(claim.publisher.id.as_ref(), "source");
    assert_eq!(claim.publisher.security, 42);
    assert!(claim.publisher.dynamic_security.is_none());
    assert!(claim.publisher.external.is_none());
    assert!(claim.verdicts.is_empty());
}

#[test]
fn reconnect_rechecks_known_verdicts_and_keeps_unforeseen_queued_messages() {
    let mut state = state(BrokerConfig::default());
    let source = connect(&mut state, claim("source", true, false));
    let subscriber = connect(&mut state, claim("subscriber", false, true));
    state.apply(authorized(
        &subscriber,
        subscribe(&["#"]),
        vec![check(
            "subscriber",
            "#",
            AclAccess::Subscribe,
            Verdict::Allow,
            Duration::ZERO,
        )],
    ));
    let read = |topic, verdict| {
        check(
            "subscriber",
            topic,
            AclAccess::Read,
            verdict,
            Duration::ZERO,
        )
    };
    for topic in ["known", "unforeseen"] {
        state.apply(authorized(
            &source,
            receive(topic, false),
            vec![read(topic, Verdict::Allow)],
        ));
    }
    let mut request = claim("subscriber", false, true);
    let error = read("known", Verdict::Error);
    let unforeseen = read("unforeseen", Verdict::Allow);
    assert!(matches!(&state.claim_verdicts(&request, NOW)[..],
        [VerdictRequest::Missing(first), VerdictRequest::Missing(second)]
            if first == &error.key && second == &unforeseen.key));
    request.verdicts.push(error);
    let encoded = rmp_serde::to_vec(&request).unwrap();
    let lease = connect(&mut state, rmp_serde::from_slice(&encoded).unwrap());
    let mut topics = Vec::new();
    state.sessions[&lease.id]
        .inbox
        .as_ref()
        .unwrap()
        .visit_messages(|message| topics.push(message.topic.to_string()));
    assert_eq!(topics, ["unforeseen"]);
}

#[test]
fn retained_acl_error_keeps_the_filter_and_stops_replay_and_later_filters() {
    let mut state = state(BrokerConfig::default());
    let source = connect(&mut state, claim("source", true, false));
    let subscriber = connect(&mut state, claim("subscriber", true, true));
    for topic in ["retained/first", "retained/error", "retained/unreached"] {
        state.apply(Command::Act(source.clone(), receive(topic, true)));
    }
    let operation = subscribe(&["retained/#", "later"]);
    let allow = check(
        "subscriber",
        "retained/#",
        AclAccess::Subscribe,
        Verdict::Allow,
        Duration::ZERO,
    );
    let first = check(
        "subscriber",
        "retained/first",
        AclAccess::Read,
        Verdict::Allow,
        Duration::ZERO,
    );
    let error = check(
        "subscriber",
        "retained/error",
        AclAccess::Read,
        Verdict::Error,
        Duration::ZERO,
    );
    assert!(
        matches!(&state.operation_verdicts(&subscriber, &operation, NOW)[..],
        [VerdictRequest::Missing(key)] if key == &allow.key)
    );
    assert!(
        matches!(&state.operation_verdicts_with(&subscriber, &operation, NOW, std::slice::from_ref(&allow))[..],
        [VerdictRequest::Missing(key)] if key == &first.key)
    );
    let mut verdicts = vec![allow, first, error];
    ResolvedVerdict::sort(&mut verdicts);
    assert!(
        state
            .operation_verdicts_with(&subscriber, &operation, NOW, &verdicts)
            .is_empty()
    );
    let result = state.apply(authorized(&subscriber, operation, verdicts));
    assert_eq!(
        result.reply,
        Reply::Batched(vec![vec![Reply::RetainedAclError]])
    );
    assert!(
        matches!(&result.effects[..], [Effect::Deliver { packet, .. }]
        if packet.retain && packet.message.topic.as_ref() == "retained/first")
    );
    assert!(
        state.sessions[&subscriber.id]
            .filters
            .contains_key("retained/#")
    );
    assert!(!state.sessions[&subscriber.id].filters.contains_key("later"));
}

#[test]
fn parked_retained_source_uses_synthetic_identity_and_remembers_the_read_grant() {
    let mut state = state(BrokerConfig {
        check_retain_source: true,
        ..BrokerConfig::default()
    });
    let source = connect(&mut state, claim("source", true, true));
    let subscriber = connect(&mut state, claim("subscriber", true, true));
    let write = check("source", "topic", AclAccess::Write, Verdict::Allow, NOW);
    state.apply(authorized(
        &source,
        receive("topic", true),
        vec![write.clone()],
    ));

    let sub = check(
        "subscriber",
        "topic",
        AclAccess::Subscribe,
        Verdict::Allow,
        Duration::ZERO,
    );
    let read = check(
        "subscriber",
        "topic",
        AclAccess::Read,
        Verdict::Allow,
        Duration::ZERO,
    );
    let outcome = state.apply(authorized(&subscriber, subscribe(&["topic"]), vec![sub]));
    assert_eq!(
        outcome.effects,
        [Effect::NeedVerdicts {
            target: VerdictTarget::Session(Some(Owner::LOCAL)),
            keys: vec![read.key.clone()]
        }]
    );
    let mut synthetic = write;
    synthetic.key.identity.client_id = None;
    synthetic.expires = Duration::ZERO;
    assert_eq!(
        resolve(&mut state, vec![read]).effects,
        [Effect::NeedVerdicts {
            target: VerdictTarget::Session(Some(Owner::LOCAL)),
            keys: vec![synthetic.key.clone()],
        }]
    );
    let snapshot = state.snapshot();
    state.restore(&snapshot).unwrap();
    assert!(matches!(&resolve(&mut state, vec![synthetic]).effects[..],
        [Effect::Deliver { packet, .. }] if packet.retain));
}

#[test]
fn parked_wills_and_delivery_survive_raft_snapshot_but_not_standalone_persistence() {
    let mut state = state(BrokerConfig::default());
    let source = connect(&mut state, claim("source", false, false));
    let subscriber = connect(&mut state, claim("subscriber", false, true));
    state.apply(authorized(
        &subscriber,
        subscribe(&["pending"]),
        vec![check(
            "subscriber",
            "pending",
            AclAccess::Subscribe,
            Verdict::Allow,
            NOW,
        )],
    ));
    state.apply(Command::Act(source, receive("pending", false)));

    let will = |topic: &str| LastWill {
        topic: topic.into(),
        payload: Bytes::from_static(b"will"),
        qos: QoS::AtLeastOnce,
        retain: true,
    };
    let disconnect = |id| {
        Command::Act(
            id,
            Operation::Disconnect {
                graceful: false,
                now: NOW,
                expiry: None,
            },
        )
    };
    for (id, topic) in [("first", "will/first"), ("second", "will/second")] {
        let mut request = claim(id, true, true);
        request.will = Some(will(topic));
        let lease = connect(&mut state, request);
        state.apply(disconnect(lease));
    }
    let first = check(
        "first",
        "will/first",
        AclAccess::Write,
        Verdict::Error,
        Duration::ZERO,
    );
    let second = check(
        "second",
        "will/second",
        AclAccess::Write,
        Verdict::Allow,
        NOW,
    );
    assert!(resolve(&mut state, vec![second]).effects.is_empty());
    assert_eq!(state.pending_wills.len(), 2);
    assert!(state.sessions[&subscriber.id].pending.front().is_some());

    let persistent = state.persistent_snapshot(NOW);
    let mut restored = State::new(state.config.clone());
    assert!(restored.restore_persistence(persistent, NOW));
    assert!(restored.pending_verdicts(NOW).is_empty());
    assert!(restored.verdicts.entries.is_empty());
    assert!(
        restored.sessions[&subscriber.id]
            .publisher
            .external
            .is_some()
    );

    let snapshot = state.snapshot();
    state.restore(&snapshot).unwrap();
    assert_eq!(state.pending_wills.len(), 2);
    resolve_for(&mut state, VerdictTarget::Will, vec![first]);
    assert!(state.pending_wills.is_empty());
    assert_eq!(state.retained.count(), 1);
}
