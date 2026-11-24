use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex as SyncMutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::future::BoxFuture;
use futures_util::stream::{BoxStream, Stream, StreamExt, unfold};
use openraft::alias::VoteOf;
use openraft::errors::{RPCError, ReplicationClosed, StreamingError, Timeout, Unreachable};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RPCTypes, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendResult, SnapshotResponse, StreamAppendResult,
    TransferLeaderRequest, TransferLeaderResponse, VoteRequest, VoteResponse,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore, SemaphorePermit, watch};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsStream;

use crate::ClusterError;
use crate::membership::{MemberRole, MembershipStatus};
use crate::mtls::{Tls, certificate_node, node_name};
use crate::mux::{CallError, Client};
use crate::node::Types;
use crate::snapshot::{Snapshot, atomic_write};
use crate::snapshot_file::SnapshotData;
use crate::survivor::{Incarnation, Probe, ProbeRequest, Record};

const MAGIC: &[u8; 4] = b"MQX3";
pub(crate) const CLUSTER_ID_FILE: &str = "cluster.id";
const HEADER_LEN: usize = 53;
pub(crate) const MAX_APPEND_ENTRIES: u64 = 128;
pub(crate) const APPEND_WINDOW: usize = 8;
pub(crate) const MAX_CONTROL_FRAME: usize = 64 * 1024;
const MAX_BODY_CAPACITY: usize = 3 * (crate::MAX_PACKET_SIZE + 2 * crate::PACKET_ENVELOPE);
const BODY_CAPACITY: usize = if MAX_BODY_CAPACITY < Semaphore::MAX_PERMITS {
    MAX_BODY_CAPACITY
} else {
    Semaphore::MAX_PERMITS
};
static BODY_BUDGET: Semaphore = Semaphore::const_new(BODY_CAPACITY);
static CONTROL_RESERVE: Semaphore = Semaphore::const_new(1024 * 1024);

pub(crate) fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(crate) fn encode<T: Serialize>(body: &T) -> io::Result<Vec<u8>> {
    rmp_serde::to_vec_named(body).map_err(invalid_data)
}

pub(crate) fn decode<T: DeserializeOwned>(body: &[u8]) -> io::Result<T> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(body));
    deserializer.set_max_depth(64);
    let value = T::deserialize(&mut deserializer).map_err(invalid_data)?;
    if deserializer.position() != body.len() as u64 {
        return Err(invalid_data("trailing data in MessagePack frame"));
    }
    Ok(value)
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub(crate) enum Op {
    Append = 1,
    Vote,
    PreVote,
    Snapshot,
    Transfer,
    Write,
    ReadIndex,
    Lease,
    MeshRequest,
    MeshSend,
    Session,
    Retired,
    Incarnation,
}

impl TryFrom<u8> for Op {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Append),
            2 => Ok(Self::Vote),
            3 => Ok(Self::PreVote),
            4 => Ok(Self::Snapshot),
            5 => Ok(Self::Transfer),
            6 => Ok(Self::Write),
            7 => Ok(Self::ReadIndex),
            8 => Ok(Self::Lease),
            9 => Ok(Self::MeshRequest),
            10 => Ok(Self::MeshSend),
            11 => Ok(Self::Session),
            12 => Ok(Self::Retired),
            13 => Ok(Self::Incarnation),
            _ => Err(invalid_data("unknown cluster RPC")),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) command: usize,
    pub(crate) append: usize,
    pub(crate) mesh: usize,
}

impl Limits {
    pub(crate) fn request(self, op: Op) -> usize {
        match op {
            Op::Append => self.append,
            Op::Write => self.command,
            Op::MeshRequest | Op::MeshSend => self.mesh,
            _ => MAX_CONTROL_FRAME,
        }
    }

    pub(crate) fn response(self, op: Op) -> usize {
        match op {
            Op::Write => self.append,
            Op::MeshRequest | Op::MeshSend => self.mesh,
            _ => MAX_CONTROL_FRAME,
        }
    }
}

#[derive(Default)]
struct PeerSlot {
    outgoing: Mutex<Option<Arc<Client>>>,
    incoming: Mutex<watch::Sender<()>>,
}

pub(crate) struct Endpoint {
    pub(crate) node_id: u64,
    pub(crate) seeds: BTreeMap<u64, SocketAddr>,
    pub(crate) status: watch::Receiver<MembershipStatus>,
    digest: OnceLock<[u8; 32]>,
    pin: Mutex<()>,
    dir: PathBuf,
    pub(crate) tls: Option<Tls>,
    pub(crate) max_snapshot_size: u64,
    pub(crate) limits: Limits,
    request_timeout: Duration,
    slots: SyncMutex<BTreeMap<u64, Arc<PeerSlot>>>,
    recovery_timeout: Option<Duration>,
    incarnation: Option<Record>,
    mismatch_warned: SyncMutex<BTreeSet<u64>>,
}

impl Endpoint {
    pub(crate) fn new(
        node_id: u64,
        seeds: BTreeMap<u64, SocketAddr>,
        (dir, membership_digest): (PathBuf, Option<[u8; 32]>),
        status: watch::Receiver<MembershipStatus>,
        tls: Option<Tls>,
        max_snapshot_size: u64,
        (limits, request_timeout): (Limits, Duration),
    ) -> Self {
        let digest = OnceLock::new();
        if let Some(membership_digest) = membership_digest {
            let _ = digest.set(membership_digest);
        }
        Self {
            node_id,
            seeds,
            status,
            digest,
            pin: Mutex::new(()),
            dir,
            tls,
            max_snapshot_size,
            limits,
            request_timeout,
            slots: SyncMutex::default(),
            recovery_timeout: None,
            incarnation: None,
            mismatch_warned: SyncMutex::default(),
        }
    }

    pub(crate) fn set_recovery(&mut self, timeout: Option<Duration>, record: Option<Record>) {
        self.recovery_timeout = timeout;
        self.incarnation = record;
    }

    pub(crate) fn digest(&self) -> Option<[u8; 32]> {
        self.digest.get().copied()
    }

    pub(crate) fn identity(&self) -> Option<Incarnation> {
        self.incarnation
            .as_ref()
            .and_then(|record| record.identity.clone())
            .or_else(|| self.digest().map(Incarnation::original))
    }

    pub(crate) fn record(&self) -> Option<&Record> {
        self.incarnation.as_ref()
    }

    pub(crate) fn recovery_timeout(&self) -> Option<Duration> {
        self.recovery_timeout
    }

    fn known_probe_peer(&self, id: u64) -> bool {
        let status = self.status.borrow();
        self.seeds.contains_key(&id)
            || status.members.contains_key(&id)
            || status.desired.contains_key(&id)
    }

    pub(crate) fn observe_recovery_timeout(&self, from: u64, timeout: Option<Duration>) {
        if !self.known_probe_peer(from) {
            return;
        }
        let mut warned = self.mismatch_warned.lock().unwrap();
        if self.recovery_timeout == timeout {
            warned.remove(&from);
        } else if warned.insert(from) {
            tracing::warn!(peer = from, local = ?self.recovery_timeout, remote = ?timeout,
                "Cluster peer has different auto_recover or auto_recover_timeout settings");
        }
    }

    pub(crate) async fn query_incarnation(
        &self,
        id: u64,
        address: SocketAddr,
        repair: bool,
        deadline: Instant,
    ) -> io::Result<Probe> {
        timeout_at(deadline, async {
            let mut stream = self.connect(id, address, deadline).await?;
            self.header(&mut stream, id, Op::Incarnation).await?;
            write_control(
                &mut stream,
                &ProbeRequest {
                    timeout: self.recovery_timeout,
                    digest: self.digest(),
                    repair,
                    reuse_digest: true,
                },
            )
            .await?;
            stream.flush().await?;
            let mut info: Probe = self.limits.read_control(&mut stream).await?;
            info.resolve_history(|| self.identity())?;
            self.observe_recovery_timeout(id, info.timeout);
            Ok(info)
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }

    fn slot(&self, id: u64) -> Arc<PeerSlot> {
        self.slots.lock().unwrap().entry(id).or_default().clone()
    }

    pub(crate) fn address(&self, id: u64) -> Option<SocketAddr> {
        let status = self.status.borrow();
        if status.members.is_empty() {
            self.seeds.get(&id).copied()
        } else {
            status.members.get(&id).map(|member| member.address)
        }
    }

    async fn session(
        &self,
        node_id: u64,
        address: SocketAddr,
        deadline: Instant,
    ) -> io::Result<Arc<Client>> {
        let slot = self.slot(node_id);
        timeout_at(deadline, async {
            let mut session = slot.outgoing.lock().await;
            if let Some(live) = session.as_ref().filter(|client| !client.is_closed()) {
                return Ok(live.clone());
            }
            let mut stream = self.connect(node_id, address, deadline).await?;
            self.header(&mut stream, node_id, Op::Session).await?;
            stream.flush().await?;
            if stream.read_u8().await? != 0 {
                return Err(invalid_data("cluster peer refused session"));
            }
            let live = Client::start(stream, self.limits, self.request_timeout);
            *session = Some(live.clone());
            Ok(live)
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }

    pub(crate) async fn call(
        &self,
        node_id: u64,
        op: Op,
        body: Bytes,
        deadline: Instant,
        connect_deadline: Instant,
    ) -> Result<Bytes, CallError> {
        let address = self
            .address(node_id)
            .ok_or_else(|| CallError::Unsent(invalid_data("unknown peer")))?;
        self.call_at(node_id, address, op, body, deadline, connect_deadline)
            .await
    }

    async fn call_at(
        &self,
        node_id: u64,
        address: SocketAddr,
        op: Op,
        body: Bytes,
        deadline: Instant,
        connect_deadline: Instant,
    ) -> Result<Bytes, CallError> {
        if body.len() > self.limits.request(op) {
            return Err(CallError::Unsent(invalid_data(
                "cluster request exceeds the configured size limit",
            )));
        }
        self.session(node_id, address, connect_deadline)
            .await
            .map_err(CallError::Unsent)?
            .call(op, body, deadline)
            .await
    }

    pub(crate) async fn accept_session(
        &self,
        from: u64,
        deadline: Instant,
    ) -> io::Result<watch::Receiver<()>> {
        let slot = self.slot(from);
        timeout_at(deadline, async {
            let incoming = slot.incoming.lock().await;
            // A dead TCP connection need not report EOF. Retire its runner
            // before admitting any requests from the successor.
            let _ = incoming.send(());
            incoming.closed().await;
            incoming.subscribe()
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut.into())
    }

    pub(crate) async fn close(&self) {
        let slots = std::mem::take(&mut *self.slots.lock().unwrap());
        for slot in slots.into_values() {
            if let Some(client) = slot.outgoing.lock().await.take() {
                client.close();
            }
        }
    }

    pub(crate) async fn query_retired(
        &self,
        id: u64,
        address: SocketAddr,
        deadline: Instant,
    ) -> io::Result<bool> {
        let result = timeout_at(deadline, async {
            let mut stream = self.connect(id, address, deadline).await?;
            self.header(&mut stream, id, Op::Retired).await?;
            stream.flush().await?;
            stream.read_u8().await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        match result {
            0 => Ok(false),
            1 => Ok(true),
            2 => Err(io::ErrorKind::NotConnected.into()),
            _ => Err(invalid_data("invalid retired-node response")),
        }
    }

    async fn connect(
        &self,
        target: u64,
        address: SocketAddr,
        deadline: Instant,
    ) -> io::Result<Connection> {
        timeout_at(deadline, async {
            let stream = TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            Ok(match &self.tls {
                Some(tls) => Connection::Tls(
                    tls.client()
                        .await
                        .connect(node_name(target)?, stream)
                        .await?
                        .into(),
                ),
                None => Connection::Plain(stream),
            })
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }

    pub(crate) async fn accept(&self, stream: TcpStream) -> io::Result<(Connection, u64, Op)> {
        stream.set_nodelay(true)?;
        let (mut stream, authenticated) = if let Some(tls) = &self.tls {
            let stream = tls.server().await.accept(stream).await?;
            let node_id = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .and_then(certificate_node)
                .ok_or_else(|| invalid_data("TLS certificate does not identify a cluster node"))?;
            (Connection::Tls(stream.into()), Some(node_id))
        } else {
            (Connection::Plain(stream), None)
        };
        // Bind the protocol sender to the authenticated TLS identity.
        let mut header = [0; HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let (from, op, digest) = self.check_header(&header, authenticated)?;
        if matches!(op, Op::Incarnation) {
            if authenticated.is_none() && (!self.known_probe_peer(from) || from == self.node_id) {
                return Err(invalid_data(
                    "incarnation probe requires a configured plaintext peer",
                ));
            }
            return Ok((stream, from, op));
        }
        if self.digest.get().is_none() {
            if self.incarnation.is_some() || self.recovery_timeout.is_some() {
                return Err(invalid_data(
                    "recovery must establish the cluster identity before replication",
                ));
            }
            // Only a configured seed can establish a joining node's identity.
            let _pin = self.pin.lock().await;
            if self.digest.get().is_none() {
                if !matches!(op, Op::Session | Op::Snapshot)
                    || !self.seeds.contains_key(&from)
                    || from == self.node_id
                {
                    return Err(invalid_data("join sender is not a configured seed"));
                }
                let dir = self.dir.clone();
                tokio::task::spawn_blocking(move || {
                    atomic_write(&dir, CLUSTER_ID_FILE, |file| {
                        std::io::Write::write_all(file, &digest)
                    })
                })
                .await
                .map_err(io::Error::other)??;
                let _ = self.digest.set(digest);
            }
        }
        if self.digest.get() != Some(&digest) {
            return Err(invalid_data("wrong cluster identity"));
        }
        Ok((stream, from, op))
    }

    pub(crate) async fn header(
        &self,
        stream: &mut Connection,
        target: u64,
        op: Op,
    ) -> io::Result<()> {
        stream.write_all(&self.rpc_header(target, op)?).await
    }

    fn rpc_header(&self, target: u64, op: Op) -> io::Result<[u8; HEADER_LEN]> {
        let mut header = [0; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        if !matches!(op, Op::Incarnation) {
            header[4..36].copy_from_slice(
                self.digest
                    .get()
                    .ok_or_else(|| invalid_data("cluster identity is not established"))?,
            );
        }
        header[36..44].copy_from_slice(&self.node_id.to_be_bytes());
        header[44..52].copy_from_slice(&target.to_be_bytes());
        header[52] = op as u8;
        Ok(header)
    }

    fn check_header(
        &self,
        header: &[u8; HEADER_LEN],
        authenticated: Option<u64>,
    ) -> io::Result<(u64, Op, [u8; 32])> {
        let from = u64::from_be_bytes(header[36..44].try_into().unwrap());
        if authenticated.is_some_and(|id| id != from) {
            return Err(invalid_data(
                "cluster header does not match the TLS peer identity",
            ));
        }
        let op = Op::try_from(header[52])?;
        let digest = header[4..36].try_into().unwrap();
        if &header[..4] != MAGIC
            || (!matches!(op, Op::Incarnation)
                && self.digest.get().is_some_and(|known| *known != digest))
            || header[44..52] != self.node_id.to_be_bytes()
            || from == 0
        {
            return Err(invalid_data("wrong protocol or cluster identity"));
        }
        Ok((from, op, digest))
    }
}

// Inline to avoid a heap allocation for each short-lived Raft connection.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Connection {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Connection {
    pub(crate) fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => stream.get_ref().0,
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn write_control<T: Serialize>(
    stream: &mut Connection,
    message: &T,
) -> io::Result<()> {
    let body = encode(message)?;
    if body.len() > MAX_CONTROL_FRAME {
        return Err(invalid_data("cluster control frame exceeds the size limit"));
    }
    stream.write_u32(body.len() as u32).await?;
    stream.write_all(&body).await
}

pub(crate) struct Frame {
    pub(crate) bytes: Bytes,
    _budget: SemaphorePermit<'static>,
}

impl Deref for Frame {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) async fn read_length(
    stream: &mut (impl AsyncRead + Unpin),
    max: u64,
) -> io::Result<u32> {
    let len = stream.read_u32().await?;
    if u64::from(len) > max {
        return Err(invalid_data("cluster frame exceeds the size limit"));
    }
    Ok(len)
}

impl Limits {
    pub(crate) async fn read_frame(
        self,
        stream: &mut (impl AsyncRead + Unpin),
        max: usize,
        append: bool,
    ) -> io::Result<Frame> {
        let len = read_length(stream, max as u64).await?;
        // The process-wide budget grows with configured packet sizes. Leave room
        // for one AppendEntries batch so admitted client writes can commit.
        let total = (self.append.max(self.mesh) * 3).clamp(32 * 1024 * 1024, BODY_CAPACITY);
        let ceiling = if append { total } else { total - self.append };
        let budget = BODY_BUDGET
            .try_acquire_many(len)
            .ok()
            .filter(|_| BODY_CAPACITY - BODY_BUDGET.available_permits() <= ceiling)
            .or_else(|| {
                (len as usize <= MAX_CONTROL_FRAME)
                    .then(|| CONTROL_RESERVE.try_acquire_many(len).ok())
                    .flatten()
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "cluster frame budget exhausted")
            })?;
        let mut buf = BytesMut::with_capacity(len as usize);
        let mut limited = stream.take(u64::from(len));
        while limited.limit() > 0 {
            if limited.read_buf(&mut buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(Frame {
            bytes: buf.freeze(),
            _budget: budget,
        })
    }

    pub(crate) async fn read_control<T: DeserializeOwned>(
        self,
        stream: &mut Connection,
    ) -> io::Result<T> {
        decode(&self.read_frame(stream, MAX_CONTROL_FRAME, false).await?)
    }
}

pub(crate) struct Network {
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) append_timeout: Duration,
}

pub(crate) struct Peer {
    endpoint: Arc<Endpoint>,
    append_timeout: Duration,
    target: u64,
    address: Option<SocketAddr>,
}

impl RaftNetworkFactory<Types> for Network {
    type Network = Peer;

    async fn new_client(&mut self, target: u64, node: &openraft::BasicNode) -> Peer {
        Peer {
            endpoint: self.endpoint.clone(),
            append_timeout: self.append_timeout,
            target,
            address: node.addr.parse().ok(),
        }
    }
}

impl Peer {
    async fn call<Req, Res, Err>(
        &self,
        op: Op,
        req: &Req,
        option: &RPCOption,
        completion_timeout: Option<Duration>,
    ) -> Result<Res, RPCError<Types>>
    where
        Req: Serialize + Sync,
        Res: DeserializeOwned,
        Err: DeserializeOwned + std::error::Error + 'static,
    {
        let started = Instant::now();
        let connect_timeout = option.soft_ttl();
        let timeout = completion_timeout.unwrap_or(connect_timeout);
        let body = encode(req).map_err(unreachable)?;
        let response = self
            .endpoint
            .call_at(
                self.target,
                self.address().map_err(unreachable)?,
                op,
                body.into(),
                started + timeout,
                started + connect_timeout.min(timeout),
            )
            .await
            .map_err(|error| {
                let error = io::Error::from(error);
                if matches!(op, Op::Append) && error.kind() == io::ErrorKind::TimedOut {
                    RPCError::Timeout(Timeout {
                        action: RPCTypes::AppendEntries,
                        id: self.endpoint.node_id,
                        target: self.target,
                        timeout: started.elapsed(),
                    })
                } else {
                    unreachable(error)
                }
            })?;
        let result: Result<Res, Err> = decode(&response).map_err(unreachable)?;
        result.map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }

    fn address(&self) -> io::Result<SocketAddr> {
        self.address
            .ok_or_else(|| invalid_data("invalid Raft node address"))
    }

    async fn append(
        &self,
        request: AppendEntriesRequest<Types>,
        option: &RPCOption,
        completion_timeout: Option<Duration>,
    ) -> Result<AppendResult<Types>, RPCError<Types>> {
        let reply: StreamAppendResult<Types> = self
            .call::<_, _, openraft::errors::RaftError<Types>>(
                Op::Append,
                &request,
                option,
                completion_timeout,
            )
            .await?;
        Ok(reply.map_err(Into::into))
    }
}

fn unreachable(error: io::Error) -> RPCError<Types> {
    RPCError::Unreachable(Unreachable::new(&error))
}

impl RaftNetworkV2<Types> for Peer {
    type SnapshotData = SnapshotData;

    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<Types>,
        option: RPCOption,
    ) -> Result<AppendResult<Types>, RPCError<Types>> {
        let completion_timeout = (!req.entries.is_empty()).then_some(self.append_timeout);
        self.append(req, &option, completion_timeout).await
    }

    fn stream_append<'s, S>(
        &'s mut self,
        input: S,
        option: RPCOption,
    ) -> BoxFuture<
        's,
        Result<BoxStream<'s, Result<AppendResult<Types>, RPCError<Types>>>, RPCError<Types>>,
    >
    where
        S: Stream<Item = AppendEntriesRequest<Types>> + Send + Unpin + 'static,
    {
        let peer = &*self;
        Box::pin(async move {
            // The server queues append frames by session order. Buffer replies in
            // that order and stop at the first failed or partial acknowledgement.
            // Even an empty commit update or probe can wait behind a WAL
            // flush. HeartbeatWorker separately bounds its one-frame stream.
            let pipeline = input
                .map(move |request| {
                    let option = option.clone();
                    async move {
                        let last = request.last_log_id();
                        (
                            peer.append(request, &option, Some(peer.append_timeout))
                                .await,
                            last,
                        )
                    }
                })
                .buffered(APPEND_WINDOW);
            let output = unfold(Some(Box::pin(pipeline)), |state| async {
                let mut pipeline = state?;
                let (result, last) = pipeline.next().await?;
                let fully_acked = matches!(&result, Ok(Ok(acked)) if *acked == last);
                Some((result, fully_acked.then_some(pipeline)))
            });
            Ok(Box::pin(output) as BoxStream<'s, _>)
        })
    }

    async fn vote(
        &mut self,
        req: VoteRequest<Types>,
        option: RPCOption,
    ) -> Result<VoteResponse<Types>, RPCError<Types>> {
        self.call::<_, _, openraft::errors::RaftError<Types>>(Op::Vote, &req, &option, None)
            .await
    }

    async fn pre_vote(
        &mut self,
        req: VoteRequest<Types>,
        option: RPCOption,
    ) -> Result<VoteResponse<Types>, RPCError<Types>> {
        self.call::<_, _, openraft::errors::RaftError<Types>>(Op::PreVote, &req, &option, None)
            .await
    }

    async fn transfer_leader(
        &mut self,
        req: TransferLeaderRequest<Types>,
        option: RPCOption,
    ) -> Result<TransferLeaderResponse<Types>, RPCError<Types>> {
        self.call::<_, _, openraft::errors::Fatal<Types>>(Op::Transfer, &req, &option, None)
            .await
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<Types>,
        snapshot: Snapshot,
        cancel: impl Future<Output = ReplicationClosed> + Send + 'static,
        option: RPCOption,
    ) -> Result<SnapshotResponse<Types>, StreamingError<Types>> {
        let deadline = Instant::now() + option.soft_ttl();
        let send = async {
            let mut stream = self
                .endpoint
                .connect(self.target, self.address()?, deadline)
                .await?;
            self.endpoint
                .header(&mut stream, self.target, Op::Snapshot)
                .await?;
            write_control(&mut stream, &(vote, snapshot.meta)).await?;
            snapshot
                .snapshot
                .send(&mut stream, self.endpoint.max_snapshot_size)
                .await?;
            stream.flush().await?;
            self.endpoint
                .limits
                .read_control::<Result<SnapshotResponse<Types>, openraft::errors::Fatal<Types>>>(
                    &mut stream,
                )
                .await
        };
        tokio::select! {
            closed = cancel => Err(StreamingError::Closed(closed)),
            response = timeout_at(deadline, send) => {
                let response = response.map_err(|_| unreachable(io::ErrorKind::TimedOut.into()))?.map_err(unreachable)?;
                Ok(response.map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))?)
            }
        }
    }
}

type Handler = dyn Fn(u64, Bytes) -> Pin<Box<dyn Future<Output = Result<Bytes, ClusterError>> + Send>>
    + Send
    + Sync;

/// Direct, unreplicated RPC. Mesh operations do not require a Raft leader or quorum.
#[derive(Clone)]
pub struct Mesh {
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) stop: watch::Sender<bool>,
    handler: Arc<OnceLock<Box<Handler>>>,
    timeout: Duration,
}

impl Mesh {
    pub(crate) fn new(endpoint: Arc<Endpoint>, timeout: Duration) -> Self {
        let (stop, _) = watch::channel(false);
        Self {
            endpoint,
            stop,
            handler: Arc::default(),
            timeout,
        }
    }

    /// Register the sole local mesh handler. It receives the sending node's ID and payload.
    pub fn register_handler<F, Fut>(&self, handler: F) -> Result<(), ClusterError>
    where
        F: Fn(u64, Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Bytes, ClusterError>> + Send + 'static,
    {
        self.handler
            .set(Box::new(move |from, body| Box::pin(handler(from, body))))
            .map_err(|_| ClusterError::MeshHandlerRegistered)
    }

    /// Mesh calls to the same peer are handled in the order queued by the sending node.
    pub async fn request(&self, node_id: u64, body: Bytes) -> Result<Bytes, ClusterError> {
        self.call(node_id, Op::MeshRequest, body).await
    }

    /// Send without waiting for the handler. Success means the bytes were handed
    /// to the socket; it does not prove the handler ran or make retries safe.
    pub async fn send(&self, node_id: u64, body: Bytes) -> Result<(), ClusterError> {
        self.call(node_id, Op::MeshSend, body).await.map(drop)
    }

    async fn call(&self, node_id: u64, op: Op, body: Bytes) -> Result<Bytes, ClusterError> {
        if *self.stop.borrow() {
            return Err(ClusterError::Shutdown);
        }
        let deadline = Instant::now() + self.timeout;
        if self.endpoint.status.borrow().members.is_empty() {
            let mut status = self.endpoint.status.clone();
            timeout_at(
                deadline,
                status.wait_for(|status| !status.members.is_empty()),
            )
            .await
            .map_err(|_| ClusterError::Deadline)?
            .map_err(|_| ClusterError::Shutdown)?;
        }
        if !self
            .endpoint
            .status
            .borrow()
            .members
            .get(&node_id)
            .is_some_and(|m| m.role == MemberRole::Voter)
        {
            return Err(ClusterError::UnknownNode(node_id));
        }
        if body.len() > self.endpoint.limits.mesh {
            return Err(invalid_data("mesh body exceeds the cluster mesh limit").into());
        }
        self.endpoint
            .call(node_id, op, body, deadline, deadline)
            .await
            .map_err(|error| match error {
                CallError::Unsent(source) if source.kind() != io::ErrorKind::TimedOut => {
                    ClusterError::Unreachable { node_id, source }
                }
                CallError::Unsent(_) => ClusterError::MeshTimeout(node_id),
                CallError::Uncertain(source) if source.kind() == io::ErrorKind::TimedOut => {
                    ClusterError::MeshTimeout(node_id)
                }
                CallError::Uncertain(source) => ClusterError::Unreachable { node_id, source },
                CallError::Remote(source) => ClusterError::MeshHandler(source.to_string()),
            })
    }

    pub(crate) async fn handle(&self, from: u64, body: Bytes) -> Result<Bytes, ClusterError> {
        let handler = self
            .handler
            .get()
            .ok_or_else(|| ClusterError::MeshHandler("not registered".into()))?;
        handler(from, body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Leadership, LogId};

    #[test]
    fn a_fork_rejects_old_raft_and_mesh_headers_but_accepts_the_probe() {
        let peers = BTreeMap::from([
            (1, "127.0.0.1:1234".parse().unwrap()),
            (2, "127.0.0.1:1235".parse().unwrap()),
        ]);
        let endpoint = |node, digest| {
            Endpoint::new(
                node,
                peers.clone(),
                (PathBuf::new(), Some(digest)),
                watch::channel(MembershipStatus::default()).1,
                None,
                1,
                (
                    Limits {
                        command: 1024,
                        append: 128 * 1024,
                        mesh: 1024,
                    },
                    Duration::from_secs(2),
                ),
            )
        };
        let original = Incarnation::original([42; 32]);
        let fork = original.clone().fork(2, Some(10)).unwrap();
        let old = endpoint(1, original.digest);
        let new = endpoint(2, fork.digest);
        for op in [
            Op::Session,
            Op::Append,
            Op::Vote,
            Op::Snapshot,
            Op::MeshSend,
            Op::Retired,
        ] {
            assert!(
                new.check_header(&old.rpc_header(2, op).unwrap(), Some(1))
                    .is_err()
            );
        }
        let probe = old.rpc_header(2, Op::Incarnation).unwrap();
        assert!(new.check_header(&probe, Some(1)).is_ok());
        assert!(new.check_header(&probe, Some(2)).is_err());
    }

    #[tokio::test]
    async fn append_stream_waits_for_a_delayed_empty_commit_update() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limits = Limits {
            command: 1024,
            append: 128 * 1024,
            mesh: 1024,
        };
        let endpoint = Arc::new(Endpoint::new(
            1,
            BTreeMap::from([(2, address)]),
            (PathBuf::new(), Some([42; 32])),
            watch::channel(MembershipStatus::default()).1,
            None,
            1,
            (limits, Duration::from_secs(2)),
        ));
        let mut peer = Peer {
            endpoint: endpoint.clone(),
            append_timeout: Duration::from_secs(2),
            target: 2,
            address: Some(address),
        };
        let option = RPCOption::new(Duration::from_millis(100));
        let (finish, finished) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let mut stream = Connection::Plain(stream);
            let mut header = [0; HEADER_LEN];
            stream.read_exact(&mut header).await.unwrap();
            stream.write_u8(0).await.unwrap();
            for expected_entries in [1, 0] {
                let id = stream.read_u64().await.unwrap();
                assert_eq!(stream.read_u8().await.unwrap(), Op::Append as u8);
                let frame = limits
                    .read_frame(&mut stream, limits.append, true)
                    .await
                    .unwrap();
                let append: AppendEntriesRequest<Types> = decode(&frame).unwrap();
                assert_eq!(append.entries.len(), expected_entries);
                if expected_entries == 0 {
                    assert_eq!(append.prev_log_id, append.leader_commit);
                    assert!(append.leader_commit.is_some());
                }
                tokio::time::sleep(Duration::from_millis(125)).await;
                let reply: Result<StreamAppendResult<Types>, openraft::errors::RaftError<Types>> =
                    Ok(Ok(append.last_log_id()));
                stream.write_u64(id).await.unwrap();
                stream.write_u8(0).await.unwrap();
                write_control(&mut stream, &reply).await.unwrap();
            }
            // Stay connected without replying to the next request.
            finished.await.unwrap();
        });
        endpoint
            .session(2, address, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let log_id = LogId::new(
            Leadership {
                term: 1,
                node_id: 1,
            },
            0,
        );
        let append = AppendEntriesRequest::<Types> {
            vote: VoteOf::<Types>::new_committed(1, 1),
            prev_log_id: None,
            entries: vec![openraft::alias::EntryOf::<Types> {
                log_id,
                payload: openraft::alias::EntryPayloadOf::<Types>::Blank,
            }],
            leader_commit: None,
        };
        let commit_update = AppendEntriesRequest {
            vote: append.vote,
            prev_log_id: Some(log_id),
            entries: vec![],
            leader_commit: Some(log_id),
        };
        let mut responses = peer
            .stream_append(
                futures_util::stream::iter([append, commit_update.clone()]),
                option.clone(),
            )
            .await
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                responses.next().await.unwrap().unwrap().unwrap(),
                Some(log_id)
            );
        }
        assert!(responses.next().await.is_none());
        drop(responses);

        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(500),
                peer.append_entries(commit_update, option)
            )
            .await
            .expect("empty append must retain the heartbeat budget"),
            Err(RPCError::Timeout(Timeout {
                action: RPCTypes::AppendEntries,
                id: 1,
                target: 2,
                ..
            }))
        ));
        finish.send(()).unwrap();
        server.await.unwrap();
    }

    #[test]
    fn rpc_header_sender_is_bound_to_the_authenticated_identity() {
        let peers = BTreeMap::from([
            (1, "127.0.0.1:1234".parse().unwrap()),
            (2, "127.0.0.1:1235".parse().unwrap()),
        ]);
        let endpoint = |node_id| {
            Endpoint::new(
                node_id,
                peers.clone(),
                (PathBuf::new(), Some([42; 32])),
                watch::channel(MembershipStatus::default()).1,
                None,
                1,
                (
                    Limits {
                        command: 1024,
                        append: 128 * 1024,
                        mesh: 1024,
                    },
                    Duration::from_secs(2),
                ),
            )
        };
        let header = endpoint(1).rpc_header(2, Op::ReadIndex).unwrap();
        assert!(endpoint(2).check_header(&header, Some(1)).is_ok());
        assert!(endpoint(2).check_header(&header, Some(2)).is_err());
    }
}
