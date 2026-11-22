use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{Instant, timeout_at};

use crate::transport::{Connection, Limits, Op, invalid_data};

const IN_FLIGHT: usize = 256;

pub(crate) enum CallError {
    Unsent(io::Error),
    Uncertain(io::Error),
    Remote(io::Error),
}

impl From<CallError> for io::Error {
    fn from(value: CallError) -> Self {
        match value {
            CallError::Unsent(error) | CallError::Uncertain(error) | CallError::Remote(error) => {
                error
            }
        }
    }
}

type Reply = oneshot::Sender<Result<Bytes, CallError>>;

struct Call {
    op: Op,
    body: Bytes,
    deadline: Instant,
    response: Option<(Reply, OwnedSemaphorePermit)>,
}

impl Drop for Call {
    fn drop(&mut self) {
        // Queue loss is definitive: the writer has not touched the socket yet.
        if let Some((reply, _permit)) = self.response.take() {
            let _ = reply.send(Err(CallError::Unsent(io::ErrorKind::BrokenPipe.into())));
        }
    }
}

#[derive(Default)]
struct Pending(Mutex<BTreeMap<u64, (Op, Reply, OwnedSemaphorePermit)>>);

pub(crate) struct Client {
    calls: mpsc::Sender<Call>,
    permits: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
    pub(crate) fn start(stream: Connection, limits: Limits) -> Arc<Self> {
        let (calls, rx) = mpsc::channel(IN_FLIGHT);
        let permits = Arc::new(Semaphore::new(IN_FLIGHT));
        let task = tokio::spawn(async move {
            let (rx_socket, tx_socket) = tokio::io::split(stream);
            let pending = Pending::default();
            tokio::select! {
                result = Self::write_calls(tx_socket, rx, &pending) => {
                    if let Err(error) = result { tracing::trace!(%error, "cluster session writer closed"); }
                },
                result = Self::read_replies(rx_socket, limits, &pending) => {
                    if let Err(error) = result { tracing::trace!(%error, "cluster session reader closed"); }
                },
            }
        });
        Arc::new(Self {
            calls,
            permits,
            task,
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.calls.is_closed() || self.task.is_finished()
    }

    pub(crate) fn close(&self) {
        self.task.abort();
    }

    pub(crate) async fn call(
        &self,
        op: Op,
        body: Bytes,
        deadline: Instant,
    ) -> Result<Bytes, CallError> {
        let permit = timeout_at(deadline, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| CallError::Unsent(io::ErrorKind::TimedOut.into()))?
            .map_err(|_| CallError::Unsent(io::ErrorKind::BrokenPipe.into()))?;
        let (reply, result) = oneshot::channel();
        self.calls
            .try_send(Call {
                op,
                body,
                deadline,
                response: Some((reply, permit)),
            })
            .map_err(|_| CallError::Unsent(io::ErrorKind::BrokenPipe.into()))?;
        timeout_at(deadline, result)
            .await
            .map_err(|_| CallError::Uncertain(io::ErrorKind::TimedOut.into()))?
            .map_err(|_| CallError::Uncertain(io::ErrorKind::BrokenPipe.into()))?
    }

    async fn write_calls(
        mut writer: impl AsyncWriteExt + Unpin,
        mut calls: mpsc::Receiver<Call>,
        pending: &Pending,
    ) -> io::Result<()> {
        let mut sequence = 0u64;
        while let Some(mut call) = calls.recv().await {
            let (reply, permit) = call.response.take().unwrap();
            if reply.is_closed() {
                continue;
            }
            if Instant::now() >= call.deadline {
                let _ = reply.send(Err(CallError::Unsent(io::ErrorKind::TimedOut.into())));
                continue;
            }
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("cluster request sequence exhausted"))?;
            let mut header = [0u8; 13];
            header[..8].copy_from_slice(&sequence.to_be_bytes());
            header[8] = call.op as u8;
            header[9..].copy_from_slice(&(call.body.len() as u32).to_be_bytes());
            let flushed = if matches!(call.op, Op::MeshSend) {
                Some((reply, permit))
            } else {
                pending
                    .0
                    .lock()
                    .unwrap()
                    .insert(sequence, (call.op, reply, permit));
                None
            };
            timeout_at(call.deadline, async {
                writer.write_all(&header).await?;
                writer.write_all(&call.body).await?;
                writer.flush().await
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
            if let Some((reply, _permit)) = flushed {
                let _ = reply.send(Ok(Bytes::new()));
            }
        }
        Ok(())
    }

    async fn read_replies(
        mut reader: impl AsyncReadExt + Unpin,
        limits: Limits,
        pending: &Pending,
    ) -> io::Result<()> {
        loop {
            let id = reader.read_u64().await?;
            let (op, reply, _permit) = pending
                .0
                .lock()
                .unwrap()
                .remove(&id)
                .ok_or_else(|| invalid_data("unexpected cluster response id"))?;
            let status = reader.read_u8().await?;
            let max = match status {
                0 => limits.response(op),
                1 => crate::transport::MAX_CONTROL_FRAME,
                _ => return Err(invalid_data("unknown cluster response status")),
            };
            let body = limits.read_frame(&mut reader, max, false).await?;
            let result = if status == 0 {
                Ok(body.bytes)
            } else {
                Err(CallError::Remote(io::Error::other(
                    String::from_utf8_lossy(&body).into_owned(),
                )))
            };
            let _ = reply.send(result);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) struct Response {
    pub(crate) id: u64,
    pub(crate) body: io::Result<Bytes>,
}

pub(crate) async fn write_responses(
    mut writer: impl AsyncWriteExt + Unpin,
    mut responses: mpsc::Receiver<Response>,
    budget: Duration,
) -> io::Result<()> {
    while let Some(response) = responses.recv().await {
        let (status, body) = match response.body {
            Ok(body) => (0, body),
            Err(error) => {
                tracing::debug!(%error, "cluster RPC rejected");
                (1, Bytes::from_static(b"cluster RPC rejected"))
            }
        };
        let mut header = [0u8; 13];
        header[..8].copy_from_slice(&response.id.to_be_bytes());
        header[8] = status;
        header[9..].copy_from_slice(&(body.len() as u32).to_be_bytes());
        tokio::time::timeout(budget, async {
            writer.write_all(&header).await?;
            writer.write_all(&body).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    }
    Ok(())
}
