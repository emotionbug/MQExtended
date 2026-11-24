use std::sync::{Arc, Weak};

use mqx_cluster::ClusterError;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::{
    inbox::PublishProperty,
    state::{BatchEntry, Command, Operation, Reply, ResolvedVerdict},
};

use super::{Inner, Log};

// Leave room for MessagePack framing and Raft entry overhead. A single
// larger mutation uses the cluster's existing admission behavior unchanged.
const INPUT_BUDGET: usize = 1536 * 1024;
const MAX_GROUPS: usize = 128;
const MAX_IN_FLIGHT_GROUPS: usize = 64;
const ENVELOPE: usize = 64 * 1024;

pub(super) struct Limits {
    input: usize,
    reply: usize,
}

impl Limits {
    pub(super) fn new(command: usize, append: usize) -> Self {
        Self {
            input: INPUT_BUDGET.min(command.saturating_sub(ENVELOPE)),
            reply: append.saturating_sub(ENVELOPE),
        }
    }
}

pub(super) struct Proposal {
    pub(super) entry: BatchEntry,
    pub(super) result: oneshot::Sender<Result<Vec<Reply>, ClusterError>>,
}

fn publication_cost(payload_len: usize, topic_len: usize, properties: &[PublishProperty]) -> usize {
    payload_len
        + topic_len
        + properties
            .iter()
            .map(|property| {
                32 + match property {
                    PublishProperty::ResponseTopic(value) | PublishProperty::ContentType(value) => {
                        value.len()
                    }
                    PublishProperty::CorrelationData(value) => value.len(),
                    PublishProperty::User(name, value) => name.len() + value.len(),
                    PublishProperty::PayloadFormat(_) => 1,
                }
            })
            .sum::<usize>()
}

fn verdict_cost(verdicts: &[ResolvedVerdict]) -> usize {
    verdicts
        .iter()
        .map(|entry| {
            64 + entry.key.topic.len()
                + entry.key.identity.client_id.as_deref().map_or(0, str::len)
                + entry.key.identity.username.as_deref().map_or(0, str::len)
        })
        .sum()
}

impl Proposal {
    fn can_pipeline(&self) -> bool {
        matches!(&self.entry, BatchEntry::Act(entry) if entry.operations.iter().all(|operation| {
            matches!(
                operation,
                Operation::Receive(_)
                    | Operation::ReceiveAdmitted(_)
                    | Operation::Forward(..)
                    | Operation::Release(..)
                    | Operation::Ack(..)
                    | Operation::ReceivedInFlight(_)
                    | Operation::ReserveOutbound(_)
                    | Operation::ReserveOutboundWithQos0Expiry(_)
                    | Operation::Authorize(_)
            )
        }))
    }

    fn cost(&self) -> (usize, usize) {
        let entry = match &self.entry {
            BatchEntry::Act(entry) => entry,
            BatchEntry::Claim { request, .. } => {
                let id = request.publisher.id.len();
                let username = request
                    .publisher
                    .username
                    .as_ref()
                    .map_or(0, |name| name.len());
                let will = request.will.as_ref().map_or(0, |will| {
                    let properties = request
                        .v5
                        .as_ref()
                        .map_or(&[][..], |v5| v5.will_properties.as_slice());
                    publication_cost(will.payload.len(), will.topic.len(), properties)
                });
                return (
                    512 + id + username + will + verdict_cost(&request.verdicts),
                    256 + id,
                );
            }
        };
        let base = 512 + entry.lease.id.len();
        entry
            .operations
            .iter()
            .fold((base, 0), |(input, reply), operation| {
                let (body, result) = match operation {
                    Operation::Receive(publish)
                    | Operation::ReceiveAdmitted(publish)
                    | Operation::ReceiveBirth {
                        publication: publish,
                        ..
                    } => {
                        let body = publication_cost(
                            publish.packet.payload.len(),
                            publish.packet.topic.len(),
                            &publish.properties,
                        );
                        (body, body + 128 * 1024)
                    }
                    Operation::Forward(message, _) | Operation::ForwardBirth { message, .. } => (
                        publication_cost(
                            message.payload.len(),
                            message.topic.len(),
                            &message.properties,
                        ),
                        0,
                    ),
                    Operation::Subscribe(filters, _)
                    | Operation::SubscribeDollarRoot(filters, _) => (
                        filters.iter().map(|entry| 128 + entry.filter.len()).sum(),
                        32 * filters.len(),
                    ),
                    Operation::Unsubscribe(filters) => (
                        filters.iter().map(|filter| 8 + filter.len()).sum(),
                        8 * filters.len(),
                    ),
                    Operation::Authorize(verdicts) => (verdict_cost(verdicts), 0),
                    _ => (0, 0),
                };
                (input + body + 256, reply + result + 256)
            })
    }
}

pub(super) async fn run(inner: Weak<Inner>, mut requests: mpsc::Receiver<Proposal>) {
    let mut next = None;
    let mut in_flight = JoinSet::new();
    loop {
        while let Some(result) = in_flight.try_join_next() {
            result.expect("broker proposal task panicked");
        }
        if in_flight.len() >= MAX_IN_FLIGHT_GROUPS {
            in_flight
                .join_next()
                .await
                .unwrap()
                .expect("broker proposal task panicked");
        }
        let Some(first) = (match next.take() {
            Some(next) => Some(next),
            None => requests.recv().await,
        }) else {
            while let Some(result) = in_flight.join_next().await {
                result.expect("broker proposal task panicked");
            }
            return;
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let Log::Replicated(log) = &inner.log else {
            unreachable!()
        };
        let limits = &log.batch_limits;
        let eager = first.can_pipeline();
        let (mut input, mut output) = first.cost();
        let mut group = Vec::with_capacity(1 + requests.len().min(MAX_GROUPS - 1));
        group.push(first);
        // Gather other sockets' queued mutations without holding up the
        // first one when there is nothing to batch.
        while group.len() < MAX_GROUPS && input < limits.input && output < limits.reply {
            let Ok(request) = requests.try_recv() else {
                break;
            };
            let (more_input, more_output) = request.cost();
            if request.can_pipeline() != eager
                || input + more_input > limits.input
                || output + more_output > limits.reply
            {
                next = Some(request);
                break;
            }
            input += more_input;
            output += more_output;
            group.push(request);
        }
        // A live connection awaits each mutation, so only independent sockets
        // can have data-plane groups in flight together. Drain before a claim,
        // subscription fence or disconnect (including cancellation cleanup).
        if eager && input <= limits.input {
            in_flight.spawn(submit(inner, group, true));
        } else {
            while let Some(result) = in_flight.join_next().await {
                result.expect("broker proposal task panicked");
            }
            submit(inner, group, eager).await;
        }
    }
}

async fn submit(inner: Arc<Inner>, mut group: Vec<Proposal>, eager: bool) {
    let Log::Replicated(log) = &inner.log else {
        unreachable!()
    };
    if !eager
        && group.len() == 1
        && !matches!(&group[0].entry, BatchEntry::Act(entry) if entry.operations.len() != 1)
    {
        let Proposal { entry, result } = group.pop().unwrap();
        let command = match entry {
            BatchEntry::Claim {
                owner,
                token,
                request,
            } => Command::Claim {
                owner,
                token,
                request: *request,
            },
            BatchEntry::Act(entry) => {
                Command::Act(entry.lease, entry.operations.into_iter().next().unwrap())
            }
        };
        let reply = log.submit(command).await;
        let _ = result.send(reply.map(|reply| vec![reply]).map_err(as_uncertain));
        return;
    }
    let mut waiters = Vec::with_capacity(group.len());
    let batch = group
        .into_iter()
        .map(|Proposal { entry, result }| {
            waiters.push(result);
            entry
        })
        .collect();
    let command = if eager {
        Command::EagerBatch(batch)
    } else {
        Command::Batch(batch)
    };
    match log.submit(command).await {
        Ok(Reply::Batched(replies)) => {
            assert_eq!(waiters.len(), replies.len());
            for (waiter, reply) in waiters.into_iter().zip(replies) {
                let _ = waiter.send(Ok(reply));
            }
        }
        Err(error) => {
            let message = error.to_string();
            for waiter in waiters {
                let _ = waiter.send(Err(ClusterError::WriteUncertain(message.clone())));
            }
        }
        Ok(_) => unreachable!("broker batch did not return its replies"),
    }
}

fn as_uncertain(error: crate::BrokerError) -> ClusterError {
    match error {
        crate::BrokerError::Cluster(error) => error,
        _ => unreachable!("proposal submission only returns cluster errors"),
    }
}
