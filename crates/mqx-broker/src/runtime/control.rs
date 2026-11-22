use super::*;
use crate::{
    ControlInventory,
    control::TOPIC,
    state::{BrokerControl, ControlResponse},
};

impl Broker {
    /// Registers the broker endpoint against the node's bound listeners.
    pub fn register_control_api(&self, inventory: ControlInventory) {
        assert!(
            self.0.control_inventory.set(inventory).is_ok(),
            "broker control API already registered"
        );
    }

    pub(super) async fn receive_control(
        &self,
        live: &Live,
        publication: Publication,
    ) -> Result<Reply, BrokerError> {
        let topic = &publication.packet.topic;
        // control.c: a dynamic-security handler is a separate registration.
        // The replicated policy alone cannot register it on this node.
        if topic == mqx_auth::DYNSEC_CONTROL_TOPIC
            && self.0.runtime.lock().unwrap().dynamic_security_path.is_some()
        {
            return self.receive_dynamic_control(live, publication).await;
        }
        let inventory = self.0.control_inventory.get().filter(|_| topic == TOPIC);
        let packet = publication.packet;
        let origin = match &self.0.log {
            Log::Local { .. } => Owner::LOCAL,
            Log::Replicated(log) => log.owner,
        };
        let payload_len = packet.payload.len();
        let response = if let Some(inventory) = inventory {
            let check = |state: &State| {
                state.admit_broker_control(origin, &live.lease, &packet.topic, payload_len)
            };
            let admission = match &self.0.log {
                Log::Local { .. } => {
                    let mut runtime = self.0.runtime.lock().unwrap();
                    let local = runtime.local.as_mut().unwrap();
                    local.update_security(None);
                    check(&local.state)
                }
                Log::Replicated(log) => log.cluster.read(|machine| check(&machine.state)),
            };
            match admission {
                Ok(username) => ControlResponse::Broadcast(inventory.respond(
                    &packet.payload,
                    &live.lease.id,
                    username.as_deref(),
                )),
                Err(Reply::PublishReason(reason)) => ControlResponse::Rejected(reason),
                Err(reply) => return Ok(reply),
            }
        } else {
            ControlResponse::MissingEndpoint
        };
        let reply = self
            .submit(Command::BrokerControl(BrokerControl {
                origin,
                lease: live.lease.clone(),
                topic: packet.topic,
                payload_len,
                qos: packet.qos,
                now: publication.now,
                response,
            }))
            .await?;
        live.credit_control(packet.qos, &reply);
        Ok(reply)
    }
}

impl Live {
    pub(super) fn credit_control(&self, qos: QoS, reply: &Reply) {
        if let Some(inbox) = &self.inbox {
            let mut inbox = inbox.lock().unwrap();
            if (qos == QoS::AtLeastOnce && *reply != Reply::Stale)
                || (qos == QoS::ExactlyOnce
                    && inbox.receive_maximum.is_some()
                    && matches!(reply, Reply::PublishReason(_)))
            {
                inbox.credit_incoming();
            }
        }
    }
}
