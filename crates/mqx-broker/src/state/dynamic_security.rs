use mqx_auth::{DYNSEC_CONTROL_TOPIC, DYNSEC_RESPONSE_TOPIC, DynsecRequest};

use super::*;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct DynamicPolicy {
    pub(super) revision: u64,
    pub(super) data: Arc<DynamicSecurity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DynamicControl {
    pub(crate) origin: Owner,
    pub(crate) lease: Lease,
    pub(crate) endpoint_registered: bool,
    pub(crate) request: Option<DynsecRequest>,
    pub(crate) payload_len: usize,
    pub(crate) qos: QoS,
    pub(crate) now: Duration,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) verdicts: Vec<ResolvedVerdict>,
}

impl State {
    pub(crate) fn dynamic_policy(&self) -> Option<(u64, &Arc<DynamicSecurity>)> {
        self.dynamic_security
            .as_ref()
            .map(|policy| (policy.revision, &policy.data))
    }

    pub(crate) fn connection_username(&self, lease: &Lease) -> Option<&str> {
        self.sessions
            .get(&lease.id)
            .filter(|session| {
                session.owner.is_some()
                    && session.epoch == lease.epoch
                    && session.internal_bridge.is_none()
            })?
            .publisher
            .username
            .as_deref()
    }

    pub(crate) fn check_dynamic_control(
        &self,
        origin: Owner,
        lease: &Lease,
        payload_len: usize,
        now: Duration,
        verdicts: &[ResolvedVerdict],
    ) -> Result<(), Reply> {
        self.check_control(
            origin,
            lease,
            DYNSEC_CONTROL_TOPIC,
            payload_len,
            now,
            verdicts,
        )?;
        if self.dynamic_security.is_none() {
            Err(Reply::PublishReason(R::IMPLEMENTATION_SPECIFIC_ERROR.0))
        } else {
            Ok(())
        }
    }

    pub(super) fn dynamic_control(
        &mut self,
        control: DynamicControl,
        effects: &mut Vec<Effect>,
    ) -> Reply {
        let DynamicControl {
            origin,
            lease,
            endpoint_registered,
            request,
            payload_len,
            qos,
            now,
            mut verdicts,
        } = control;
        ResolvedVerdict::sort(&mut verdicts);
        let checked = self.check_dynamic_control(origin, &lease, payload_len, now, &verdicts);
        if checked == Err(Reply::Stale) {
            return Reply::Stale;
        }
        self.verdicts.insert(&verdicts, now);
        if checked == Err(Reply::ExternalAclError) {
            return Reply::ExternalAclError;
        }
        let accepted = checked.is_ok() && request.is_some();
        let session = self.sessions.get_mut(&lease.id).unwrap();
        if (qos == QoS::AtLeastOnce
            || (!accepted && qos == QoS::ExactlyOnce && session.v5.is_some()))
            && let Some(inbox) = &mut session.inbox
        {
            inbox.credit_incoming();
        }
        if let Err(reply) = checked {
            return reply;
        }
        if !endpoint_registered {
            return Reply::PublishReason(R::IMPLEMENTATION_SPECIFIC_ERROR.0);
        }
        let Some(request) = request else {
            // The origin declined to prepare a request that was unauthorized
            // there. A later grant cannot make an unprepared request executable.
            return Reply::PublishReason(R::NOT_AUTHORIZED.0);
        };
        let policy = self.dynamic_security.as_mut().unwrap();
        let result = Arc::make_mut(&mut policy.data).apply(request);
        if result.changed {
            policy.revision += 1;
        }

        // control_common.c: mosquitto_control_send_response emits a single
        // non-retained QoS 0 broker publication. Route it in this same entry:
        // each replica delivers only its own transport effects, and a lost
        // proposal reply cannot cause the origin to publish it a second time.
        self.publish_with_verdicts(
            Message {
                source: Publisher {
                    id: Arc::from(""),
                    username: None,
                    security: 0,
                    dynamic_security: None,
                    external: None,
                },
                topic: DYNSEC_RESPONSE_TOPIC.into(),
                payload: Bytes::from(result.response),
                qos: QoS::AtMostOnce,
                retain: false,
                properties: Vec::new(),
                expires: None,
                broker_expires: None,
            }
            .published(now),
            VerdictContext::new(now),
            effects,
        );
        if !result.kicks.is_empty() {
            self.kick_dynamic_clients(&result.kicks, now, effects);
        }
        Reply::ControlAccepted {
            changed: result.changed,
        }
    }

    fn kick_dynamic_clients(
        &mut self,
        usernames: &BTreeSet<Option<String>>,
        now: Duration,
        effects: &mut Vec<Effect>,
    ) {
        let usernames: Vec<_> = usernames.iter().map(Option::as_deref).collect();
        let mut kicked = Vec::new();
        let acl = Acls::new(
            &self.acls,
            self.dynamic_security.as_ref(),
            &self.external_plugins,
            &self.verdicts,
            VerdictContext::new(now),
        );
        for (id, session) in &mut self.sessions {
            if session.owner.is_none()
                || session.internal_bridge.is_some()
                || usernames
                    .binary_search(&session.publisher.username.as_deref())
                    .is_err()
            {
                continue;
            }
            // plugin_public.c: disconnect_client drops unauthorized subscriptions
            // from persistent sessions using the new policy, then discards the will.
            if session.inbox.is_some() {
                session.filters.retain(|filter, _| {
                    if acl.check(&session.publisher, filter, Access::Subscribe, false, None)
                        == AclDecision::Allow
                    {
                        return true;
                    }
                    remove_filter(
                        &mut self.normal,
                        &mut self.shared,
                        &mut self.groups,
                        id,
                        filter,
                    );
                    false
                });
            }
            effects.push(Effect::Kick(session.epoch));
            kicked.push(id.clone());
        }
        for id in kicked {
            self.offline(id, now, true, effects);
        }
    }
}
