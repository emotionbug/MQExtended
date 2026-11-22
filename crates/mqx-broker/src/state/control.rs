use super::*;
use crate::control::{RESPONSE_TOPIC, UNAVAILABLE};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BrokerControl {
    pub(crate) origin: Owner,
    pub(crate) lease: Lease,
    pub(crate) topic: String,
    pub(crate) payload_len: usize,
    pub(crate) qos: QoS,
    pub(crate) now: Duration,
    pub(crate) response: ControlResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum ControlResponse {
    Broadcast(Bytes),
    MissingEndpoint,
    Rejected(u8),
}

impl State {
    pub(crate) fn admit_broker_control(
        &self,
        origin: Owner,
        lease: &Lease,
        topic: &str,
        payload_len: usize,
    ) -> Result<Option<Arc<str>>, Reply> {
        let session = self.check_control(origin, lease, topic, payload_len)?;
        Ok(session.publisher.username.clone())
    }

    pub(super) fn check_control(
        &self,
        origin: Owner,
        lease: &Lease,
        topic: &str,
        payload_len: usize,
    ) -> Result<&Session, Reply> {
        let Some(session) = self
            .sessions
            .get(&lease.id)
            .filter(|session| session.owner == Some(origin) && session.epoch == lease.epoch)
        else {
            return Err(Reply::Stale);
        };
        let acl = Acls::new(&self.acls, self.dynamic_security.as_ref());
        if let Some(reason) = check_publish(&self.config, acl, session, topic, payload_len) {
            return Err(Reply::PublishReason(reason.0));
        }
        Ok(session)
    }

    pub(super) fn broker_control(
        &mut self,
        control: BrokerControl,
        effects: &mut Vec<Effect>,
    ) -> Reply {
        let BrokerControl {
            origin,
            lease,
            topic,
            payload_len,
            qos,
            now,
            response,
        } = control;
        let checked = self
            .check_control(origin, &lease, &topic, payload_len)
            .map(|_| ());
        if checked == Err(Reply::Stale) {
            return Reply::Stale;
        }
        // The issuing node prepares the read-only snapshot; replicas recheck
        // the current ACL before publishing it. A concurrent grant cannot make
        // a request that was rejected at its origin executable.
        let result = checked.and(match response {
            ControlResponse::Rejected(reason) => Err(Reply::PublishReason(reason)),
            response => Ok(response),
        });
        let session = self.sessions.get_mut(&lease.id).unwrap();
        if (qos == QoS::AtLeastOnce
            || (result.is_err() && qos == QoS::ExactlyOnce && session.v5.is_some()))
            && let Some(inbox) = &mut session.inbox
        {
            inbox.credit_incoming();
        }

        let message = |topic: Box<str>, payload| {
            Arc::new(Message {
                source: Publisher {
                    id: Arc::from(""),
                    username: None,
                    security: 0,
                    dynamic_security: None,
                },
                topic,
                payload,
                qos: QoS::AtMostOnce,
                retain: false,
                properties: Vec::new(),
                expires: None,
            })
        };
        match result {
            // control_common.c: mosquitto_control_send_response uses a normal
            // broker publication, subject to subscriptions and their READ ACLs.
            Ok(ControlResponse::Broadcast(payload)) => {
                // Leave room for the response topic in the outgoing PUBLISH.
                if payload.len() <= mqx_codec::MAX_REMAINING_LENGTH - RESPONSE_TOPIC.len() - 3 {
                    self.publish(message(RESPONSE_TOPIC.into(), payload), now, effects);
                }
            }
            // control.c: control__negative_reply addresses the requester alone.
            // loop.c: single_publish bypasses subscriptions, READ and QoS upgrades.
            Ok(ControlResponse::MissingEndpoint) => {
                const SUFFIX: &str = "/response";
                if topic.len() + SUFFIX.len() <= usize::from(u16::MAX) {
                    let mut topic = topic;
                    topic.push_str(SUFFIX);
                    deliver(
                        session,
                        Delivery {
                            message: message(topic.into_boxed_str(), UNAVAILABLE),
                            qos: QoS::AtMostOnce,
                            retain: false,
                            dedup_id: None,
                            subscription_identifier: 0,
                        },
                        &self.config,
                        effects,
                        &mut self.sys_counters,
                        &mut self.persistence_changes,
                    );
                }
            }
            Ok(ControlResponse::Rejected(_)) => unreachable!(),
            Err(reply) => return reply,
        }
        // Native control handlers consume QoS 2 PUBLISH immediately. PUBREL
        // has nothing to release and still gets its ordinary PUBCOMP.
        Reply::ControlAccepted { changed: false }
    }
}
