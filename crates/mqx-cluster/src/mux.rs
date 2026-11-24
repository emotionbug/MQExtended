use std::collections::{BTreeMap, VecDeque};
use std::io;
#[cfg(unix)]
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::transport::{
    Connection, INLINE_FRAME_LEN, Limits, Op, READY_FRAMES, SESSION_HEADER_LEN, SessionFrame,
    decode_session_header, invalid_data, session_header,
};

const IN_FLIGHT: usize = 256;
// The receiver budgets queued frame bodies as well as request slots. Pipeline
// small publications, but keep a large frame alone in this group's window.
const MESH_PIPELINED_BYTES: usize = 128 * 1024;

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

type ReplyResult = Result<Bytes, CallError>;
type Reply = oneshot::Sender<ReplyResult>;

struct Call {
    op: Op,
    body: Bytes,
    deadline: Instant,
    completion_only: bool,
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

struct PendingReply {
    op: Op,
    completion_only: bool,
    reply: Reply,
    _permit: OwnedSemaphorePermit,
    expires: Instant,
}

#[derive(Default)]
struct Pending {
    replies: Mutex<BTreeMap<u64, PendingReply>>,
    ready: Notify,
}

impl Pending {
    fn insert(&self, id: u64, reply: PendingReply) {
        let mut replies = self.replies.lock().unwrap();
        let was_empty = replies.is_empty();
        replies.insert(id, reply);
        if was_empty {
            self.ready.notify_one();
        }
    }

    async fn wait_for_stall(&self) {
        loop {
            // IDs and expiry times both increase in write order. Recheck after
            // sleeping: that reply may have arrived while the timer was armed.
            let oldest = self
                .replies
                .lock()
                .unwrap()
                .first_key_value()
                .map(|(_, reply)| reply.expires);
            match oldest {
                Some(expires) if Instant::now() >= expires => return,
                Some(expires) => sleep_until(expires).await,
                None => self.ready.notified().await,
            }
        }
    }
}

pub(crate) struct Client {
    calls: mpsc::Sender<Call>,
    permits: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
    pub(crate) fn start(
        stream: Connection,
        limits: Limits,
        request_timeout: Duration,
    ) -> Arc<Self> {
        let (calls, rx) = mpsc::channel(IN_FLIGHT);
        let permits = Arc::new(Semaphore::new(IN_FLIGHT));
        // A second descriptor for the same socket, only to look for the
        // peer's FIN without disturbing the TLS reader.
        #[cfg(unix)]
        let probe = stream
            .tcp()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(std::net::TcpStream::from);
        #[cfg(not(unix))]
        let probe = None;
        let task = tokio::spawn(async move {
            let (rx_socket, tx_socket) = stream.split_session();
            let pending = Pending::default();
            // A caller may time out or be dropped before its reply arrives (e.g.
            // Raft's heartbeat deadline). Allow the server's frame read,
            // dispatch, and response write budgets before recycling the session.
            let reply_budget = request_timeout.saturating_mul(3);
            tokio::select! {
                result = Self::write_calls(tx_socket, rx, &pending, probe.as_ref(), reply_budget) => {
                    if let Err(error) = result { tracing::trace!(%error, "cluster session writer closed"); }
                },
                result = Self::read_replies(rx_socket, limits, &pending) => {
                    if let Err(error) = result { tracing::trace!(%error, "cluster session reader closed"); }
                },
                () = pending.wait_for_stall() => {
                    tracing::debug!("cluster session closed after a stalled reply");
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
        let result = self.enqueue(op, body, deadline, false).await?;
        Self::await_reply(deadline, result).await
    }

    pub(crate) async fn call_many(
        &self,
        bodies: Vec<Bytes>,
        deadline: Instant,
    ) -> Result<(), CallError> {
        let mut pending = VecDeque::with_capacity(bodies.len().min(IN_FLIGHT));
        let mut queued_bytes = 0;
        let mut failure = None;
        let mut admission_error = None;
        for body in bodies {
            let size = SESSION_HEADER_LEN + body.len();
            while !pending.is_empty()
                && (pending.len() == IN_FLIGHT || queued_bytes + size > MESH_PIPELINED_BYTES)
            {
                let (reply, size) = pending.pop_front().unwrap();
                queued_bytes -= size;
                if let Err(error) = Self::await_reply(deadline, reply).await {
                    failure = Some(error);
                    break;
                }
            }
            if failure.is_some() {
                break;
            }
            match self.enqueue(Op::MeshRequest, body, deadline, true).await {
                Ok(reply) => {
                    pending.push_back((reply, size));
                    queued_bytes += size;
                }
                Err(error) => {
                    admission_error = Some(error);
                    break;
                }
            }
        }
        // A failed admission does not cancel the prefix already queued on this
        // session. Drain it against the same deadline, even after a rejection.
        for (reply, _) in pending {
            if let Err(error) = Self::await_reply(deadline, reply).await {
                failure.get_or_insert(error);
            }
        }
        failure.or(admission_error).map_or(Ok(()), Err)
    }

    async fn enqueue(
        &self,
        op: Op,
        body: Bytes,
        deadline: Instant,
        completion_only: bool,
    ) -> Result<oneshot::Receiver<ReplyResult>, CallError> {
        let permit = timeout_at(deadline, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| CallError::Unsent(io::ErrorKind::TimedOut.into()))?
            .map_err(|_| CallError::Unsent(io::ErrorKind::BrokenPipe.into()))?;
        if completion_only && Instant::now() >= deadline {
            return Err(CallError::Unsent(io::ErrorKind::TimedOut.into()));
        }
        let (reply, result) = oneshot::channel();
        self.calls
            .try_send(Call {
                op,
                body,
                deadline,
                completion_only,
                response: Some((reply, permit)),
            })
            .map_err(|_| CallError::Unsent(io::ErrorKind::BrokenPipe.into()))?;
        Ok(result)
    }

    async fn await_reply(deadline: Instant, result: oneshot::Receiver<ReplyResult>) -> ReplyResult {
        timeout_at(deadline, result)
            .await
            .map_err(|_| CallError::Uncertain(io::ErrorKind::TimedOut.into()))?
            .map_err(|_| CallError::Uncertain(io::ErrorKind::BrokenPipe.into()))?
    }

    async fn write_calls(
        mut writer: impl AsyncWriteExt + Unpin,
        mut calls: mpsc::Receiver<Call>,
        pending: &Pending,
        probe: Option<&std::net::TcpStream>,
        reply_budget: Duration,
    ) -> io::Result<()> {
        let mut sequence = 0u64;
        let mut frame = SessionFrame::default();
        let mut carry = None;
        while let Some(mut call) = match carry.take() {
            Some(call) => Some(call),
            None => calls.recv().await,
        } {
            let (reply, permit) = call.response.take().unwrap();
            if reply.is_closed() {
                continue;
            }
            if Instant::now() >= call.deadline {
                let _ = reply.send(Err(CallError::Unsent(io::ErrorKind::TimedOut.into())));
                continue;
            }
            // Peers never half-close a session, so once their FIN has arrived
            // nothing written afterwards can be read. A leader killed just
            // before this call is then a definite failure the caller may
            // retry on the next leader, not an uncertain write.
            if probe.is_some_and(peer_closed) {
                let _ = reply.send(Err(CallError::Unsent(
                    io::ErrorKind::ConnectionReset.into(),
                )));
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid_data("cluster request sequence exhausted"))?;
            let flushed = if matches!(call.op, Op::MeshSend) {
                Some((reply, permit))
            } else {
                pending.insert(
                    sequence,
                    PendingReply {
                        op: call.op,
                        completion_only: call.completion_only,
                        reply,
                        _permit: permit,
                        expires: Instant::now() + reply_budget,
                    },
                );
                None
            };
            // Keep ordinary calls on the single-frame path, including when
            // they sit between two pipelined sends on this session.
            let wire_len = SESSION_HEADER_LEN + call.body.len();
            if call.completion_only
                && wire_len + SESSION_HEADER_LEN <= INLINE_FRAME_LEN
                && !calls.is_empty()
            {
                let mut parts = [const { (0, Bytes::new()) }; READY_FRAMES];
                parts[0] = (sequence, std::mem::take(&mut call.body));
                let mut len = 1;
                let mut bytes = wire_len;
                for _ in 1..READY_FRAMES {
                    let Ok(mut next) = calls.try_recv() else {
                        break;
                    };
                    let size = SESSION_HEADER_LEN + next.body.len();
                    if !next.completion_only
                        || next.deadline != call.deadline
                        || bytes + size > INLINE_FRAME_LEN
                    {
                        carry = Some(next);
                        break;
                    }
                    let (reply, permit) = next.response.take().unwrap();
                    if reply.is_closed() {
                        continue;
                    }
                    if Instant::now() >= next.deadline {
                        let _ = reply.send(Err(CallError::Unsent(io::ErrorKind::TimedOut.into())));
                        break;
                    }
                    sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("cluster request sequence exhausted"))?;
                    // Register the entire write before any bytes can reach the peer.
                    pending.insert(
                        sequence,
                        PendingReply {
                            op: next.op,
                            completion_only: true,
                            reply,
                            _permit: permit,
                            expires: Instant::now() + reply_budget,
                        },
                    );
                    parts[len] = (sequence, std::mem::take(&mut next.body));
                    len += 1;
                    bytes += size;
                }
                timeout_at(
                    call.deadline,
                    frame.write_mesh_requests(&mut writer, &parts[..len]),
                )
                .await
                .map_err(|_| io::ErrorKind::TimedOut)??;
                continue;
            }
            timeout_at(
                call.deadline,
                frame.write(&mut writer, sequence, call.op as u8, &call.body),
            )
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
        let mut header = [0; SESSION_HEADER_LEN];
        loop {
            reader.read_exact(&mut header).await?;
            let (id, status, len) = decode_session_header(header);
            // Keep the entry until the entire frame arrives. A connection that
            // stalls after the ID still needs to expire and reclaim its slot.
            let (op, completion_only) = {
                let replies = pending.replies.lock().unwrap();
                let entry = replies
                    .get(&id)
                    .ok_or_else(|| invalid_data("unexpected cluster response id"))?;
                (entry.op, entry.completion_only)
            };
            let max = match status {
                0 => limits.response(op),
                1 => crate::transport::MAX_CONTROL_FRAME,
                _ => return Err(invalid_data("unknown cluster response status")),
            };
            let body = limits.read_frame_body(&mut reader, len, max, false).await?;
            let result = if status == 0 {
                // Completion-only calls have no consumer for the payload.
                Ok(if completion_only {
                    Bytes::new()
                } else {
                    body.bytes
                })
            } else {
                Err(CallError::Remote(io::Error::other(
                    String::from_utf8_lossy(&body).into_owned(),
                )))
            };
            let entry = pending.replies.lock().unwrap().remove(&id).unwrap();
            let _ = entry.reply.send(result);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// The socket is non-blocking. A FIN with nothing left to read peeks as 0
// bytes, and an RST as an error; unread replies hide a later FIN.
fn peer_closed(socket: &std::net::TcpStream) -> bool {
    match socket.peek(&mut [0]) {
        Ok(read) => read == 0,
        Err(error) => !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ),
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
    let mut frame = SessionFrame::default();
    let mut headers = [0; READY_FRAMES * SESSION_HEADER_LEN];
    let mut carry = None;
    while let Some(response) = match carry.take() {
        Some(response) => Some(response),
        None => responses.recv().await,
    } {
        if response.body.as_ref().is_ok_and(Bytes::is_empty) && !responses.is_empty() {
            let mut len = SESSION_HEADER_LEN;
            headers[..len].copy_from_slice(&session_header(response.id, 0, 0));
            for _ in 1..READY_FRAMES {
                let Ok(next) = responses.try_recv() else {
                    break;
                };
                if !next.body.as_ref().is_ok_and(Bytes::is_empty) {
                    carry = Some(next);
                    break;
                }
                let end = len + SESSION_HEADER_LEN;
                headers[len..end].copy_from_slice(&session_header(next.id, 0, 0));
                len = end;
            }
            // Small, ready acknowledgments need one socket write/flush, not
            // one each. Do not hold an acknowledgment waiting for more work.
            tokio::time::timeout(budget, async {
                writer.write_all(&headers[..len]).await?;
                writer.flush().await
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
            continue;
        }
        let (status, body) = match response.body {
            Ok(body) => (0, body),
            Err(error) => {
                tracing::debug!(%error, "cluster RPC rejected");
                (1, Bytes::from_static(b"cluster RPC rejected"))
            }
        };
        tokio::time::timeout(budget, frame.write(&mut writer, response.id, status, &body))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn partial_admission_waits_for_the_admitted_prefix() {
        // A smaller queue than the permit window forces a local enqueue failure
        // while the admitted request still has a live reply sender.
        let (calls, mut queued) = mpsc::channel(1);
        let client = Client {
            calls,
            permits: Arc::new(Semaphore::new(2)),
            task: tokio::spawn(std::future::pending()),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut batch = std::pin::pin!(client.call_many(
            vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")],
            deadline,
        ));
        assert!(futures_util::poll!(&mut batch).is_pending());
        let mut first = queued.try_recv().unwrap();
        assert!(matches!(first.op, Op::MeshRequest));
        assert_eq!(first.body, "first");
        let (reply, _permit) = first.response.take().unwrap();
        assert!(reply.send(Ok(Bytes::new())).is_ok());
        assert!(matches!(
            batch.await,
            Err(CallError::Unsent(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        assert!(matches!(
            queued.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn ready_empty_replies_keep_legacy_boundaries_around_payloads() {
        let (responses, replies) = mpsc::channel(5);
        for (id, body) in [
            (4, Bytes::new()),
            (1, Bytes::new()),
            (3, Bytes::from_static(b"body")),
            (2, Bytes::new()),
            (5, Bytes::new()),
        ] {
            assert!(responses.try_send(Response { id, body: Ok(body) }).is_ok());
        }
        drop(responses);
        let (writer, mut reader) = tokio::io::duplex(7);
        let read = async {
            for (id, body) in [(4, ""), (1, ""), (3, "body"), (2, ""), (5, "")] {
                assert_eq!(reader.read_u64().await.unwrap(), id);
                assert_eq!(reader.read_u8().await.unwrap(), 0);
                assert_eq!(reader.read_u32().await.unwrap() as usize, body.len());
                let mut actual = vec![0; body.len()];
                reader.read_exact(&mut actual).await.unwrap();
                assert_eq!(actual.as_slice(), body.as_bytes());
            }
            assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
        };
        let (written, ()) = tokio::join!(
            write_responses(writer, replies, Duration::from_secs(5)),
            read,
        );
        written.unwrap();
    }

    #[tokio::test]
    async fn fragmented_replies_keep_their_frame_boundaries() {
        let (mut peer, reader) = tokio::io::duplex(7);
        let reader = tokio::io::BufReader::with_capacity(64, reader);
        let limits = Limits {
            command: 1024,
            append: 1024,
            mesh: 1024,
        };
        let pending = Pending::default();
        let permits = Arc::new(Semaphore::new(2));
        let (first, first_reply) = oneshot::channel();
        let (second, second_reply) = oneshot::channel();
        for (id, reply) in [(1, first), (2, second)] {
            pending.insert(
                id,
                PendingReply {
                    op: Op::Write,
                    completion_only: false,
                    reply,
                    _permit: permits.clone().try_acquire_owned().unwrap(),
                    expires: Instant::now() + Duration::from_secs(5),
                },
            );
        }
        let send = async move {
            let mut frame = SessionFrame::default();
            frame.write(&mut peer, 2, 0, b"second").await.unwrap();
            frame.write(&mut peer, 1, 1, b"rejected").await.unwrap();
        };
        let ((), end) = tokio::join!(send, Client::read_replies(reader, limits, &pending));
        assert_eq!(end.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(matches!(
            first_reply.await.unwrap(),
            Err(CallError::Remote(error)) if error.to_string() == "rejected"
        ));
        let second = second_reply
            .await
            .unwrap()
            .map_err(io::Error::from)
            .unwrap();
        assert_eq!(second.as_ref(), b"second");
    }

    #[tokio::test]
    async fn a_stalled_peer_releases_the_call_window_and_reconnects() {
        use std::path::PathBuf;
        use std::pin::pin;

        use futures_util::stream::{FuturesUnordered, StreamExt};
        use tokio::net::TcpListener;
        use tokio::sync::watch;
        use tokio::time::{advance, pause, resume};

        use crate::membership::MembershipStatus;
        use crate::transport::Endpoint;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limits = Limits {
            command: 1024,
            append: 1024,
            mesh: 1024,
        };
        let budget = Duration::from_secs(10);
        let endpoint = |node_id| {
            Endpoint::new(
                node_id,
                BTreeMap::from([(2, address)]),
                (PathBuf::new(), Some([42; 32])),
                watch::channel(MembershipStatus::default()).1,
                None,
                1,
                (limits, budget),
            )
        };
        let (caller, peer) = (endpoint(1), endpoint(2));
        let accept = || async {
            let (socket, _) = listener.accept().await.unwrap();
            let (stream, from, op) = peer.accept(socket).await.unwrap();
            assert_eq!(from, 1);
            assert!(matches!(op, Op::Session));
            stream
        };
        let body = Bytes::from_static(b"command");
        let started = Instant::now();
        let connect = started + Duration::from_secs(5);
        let mut calls = FuturesUnordered::new();
        for i in 0..IN_FLIGHT {
            let deadline = started + Duration::from_secs(if i == 0 { 60 } else { 9 });
            calls.push(caller.call(2, Op::Write, body.clone(), deadline, connect));
        }
        let interrupt = async {
            let mut stream = accept().await;
            let active = peer.accept_session(1, connect).await.unwrap();
            stream.write_u8(0).await.unwrap();
            for id in 1..=IN_FLIGHT as u64 {
                assert_eq!(read_test_write(&mut stream, limits).await, id);
            }
            // Interrupt an ordinary reply mid-frame; the old peer connection
            // doesn't close or notice EOF during the interruption.
            stream.write_u64(1).await.unwrap();
            (stream, active)
        };
        let (old_socket, mut old_session) = tokio::select! {
            _ = calls.next() => panic!("a write completed before the interruption"),
            old = timeout_at(connect, interrupt) => old.unwrap(),
        };

        pause();
        let later = started + Duration::from_secs(120);
        let mut waiting = pin!(caller.call(2, Op::Write, body.clone(), later, later));
        assert!(futures_util::poll!(&mut waiting).is_pending());
        advance(budget).await;
        for _ in 1..IN_FLIGHT {
            assert!(matches!(
                calls.next().await,
                Some(Err(CallError::Uncertain(error))) if error.kind() == io::ErrorKind::TimedOut
            ));
        }
        assert!(futures_util::poll!(&mut waiting).is_pending());
        advance(budget.saturating_mul(3)).await;
        assert!(matches!(
            calls.next().await,
            Some(Err(CallError::Uncertain(_)))
        ));
        assert!(matches!(
            waiting.await,
            Err(CallError::Unsent(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        resume();

        let connect = Instant::now() + Duration::from_secs(5);
        let replacement = async {
            let mut stream = accept().await;
            let mut replacement = pin!(peer.accept_session(1, connect));
            assert!(futures_util::poll!(&mut replacement).is_pending());
            old_session.changed().await.unwrap();
            drop(old_socket);
            drop(old_session);
            let _active = replacement.await.unwrap();
            stream.write_u8(0).await.unwrap();
            let id = read_test_write(&mut stream, limits).await;
            assert_eq!(id, 1);
            stream.write_u64(id).await.unwrap();
            stream.write_u8(0).await.unwrap();
            stream.write_u32(2).await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        };
        let (reply, reconnected) = tokio::join!(
            caller.call(2, Op::Write, body, connect, connect),
            timeout_at(connect, replacement),
        );
        reconnected.unwrap();
        assert_eq!(reply.map_err(io::Error::from).unwrap().as_ref(), b"ok");
    }

    async fn read_test_write(stream: &mut Connection, limits: Limits) -> u64 {
        let id = stream.read_u64().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), Op::Write as u8);
        let body = limits
            .read_frame(stream, limits.command, false)
            .await
            .unwrap();
        assert_eq!(&*body, b"command");
        id
    }

    // A leader that died before the request was written never read it. On a
    // single-threaded runtime the writer and reader of a new session race to
    // notice the closed socket; either way the call must be retryable.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_call_after_the_peer_closed_is_unsent() {
        let limits = Limits {
            command: 1024,
            append: 1024,
            mesh: 1024,
        };
        for _ in 0..32 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            drop(listener.accept().unwrap());
            // Loopback delivers the FIN before this returns.
            let mut probe = [0];
            assert_eq!(stream.peek(&mut probe).unwrap(), 0);
            stream.set_nonblocking(true).unwrap();
            let stream = tokio::net::TcpStream::from_std(stream).unwrap();
            let client = Client::start(Connection::Plain(stream), limits, Duration::from_secs(5));
            let deadline = Instant::now() + Duration::from_secs(5);
            let result = client
                .call(Op::Write, Bytes::from_static(b"command"), deadline)
                .await;
            assert!(
                matches!(result, Err(CallError::Unsent(_))),
                "a write was reported uncertain"
            );
        }
    }
}
