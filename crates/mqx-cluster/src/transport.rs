use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use openraft::alias::VoteOf;
use openraft::errors::{RPCError, ReplicationClosed, StreamingError, Unreachable};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendResult, SnapshotResponse, StreamAppendResult,
    TransferLeaderRequest, TransferLeaderResponse, VoteRequest, VoteResponse,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};

use crate::ClusterError;
use crate::node::Types;
use crate::snapshot::{Snapshot, SnapshotData};

const MAGIC: &[u8; 4] = b"MQX1";
const HEADER_LEN: usize = 53;
pub(crate) const MAX_FRAME: usize = 64 * 1024 * 1024;
pub(crate) const MAX_COMMAND: usize = 8 * 1024 * 1024;
// Leave space for MessagePack entry headers and Raft metadata in each frame.
pub(crate) const MAX_APPEND_ENTRIES: u64 = 4;
pub(crate) const MAX_SNAPSHOT: usize = u32::MAX as usize;

pub(crate) fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(crate) fn encode<T: Serialize>(body: &T) -> io::Result<Vec<u8>> {
    rmp_serde::to_vec_named(body).map_err(invalid_data)
}

pub(crate) fn decode<T: DeserializeOwned>(body: &[u8]) -> io::Result<T> {
    rmp_serde::from_slice(body).map_err(invalid_data)
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
            _ => Err(invalid_data("unknown cluster RPC")),
        }
    }
}

pub(crate) struct Endpoint {
    pub(crate) node_id: u64,
    pub(crate) peers: BTreeMap<u64, SocketAddr>,
    pub(crate) membership_digest: [u8; 32],
}

impl Endpoint {
    pub(crate) async fn connect(&self, target: u64, deadline: Instant) -> io::Result<TcpStream> {
        let address = self
            .peers
            .get(&target)
            .ok_or_else(|| invalid_data("unknown peer"))?;
        let stream = timeout_at(deadline, TcpStream::connect(address))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub(crate) async fn header(
        &self,
        stream: &mut TcpStream,
        target: u64,
        op: Op,
    ) -> io::Result<()> {
        let mut header = [0; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4..36].copy_from_slice(&self.membership_digest);
        header[36..44].copy_from_slice(&self.node_id.to_be_bytes());
        header[44..52].copy_from_slice(&target.to_be_bytes());
        header[52] = op as u8;
        stream.write_all(&header).await
    }

    pub(crate) async fn accept_header(&self, stream: &mut TcpStream) -> io::Result<(u64, Op)> {
        let mut header = [0; HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let from = u64::from_be_bytes(header[36..44].try_into().unwrap());
        if &header[..4] != MAGIC
            || header[4..36] != self.membership_digest
            || header[44..52] != self.node_id.to_be_bytes()
            || !self.peers.contains_key(&from)
        {
            return Err(invalid_data("wrong protocol or cluster membership"));
        }
        Ok((from, Op::try_from(header[52])?))
    }
}

pub(crate) async fn write_frame(stream: &mut TcpStream, body: &[u8], max: usize) -> io::Result<()> {
    if body.len() > max {
        return Err(invalid_data("cluster frame exceeds the size limit"));
    }
    stream.write_u32(body.len() as u32).await?;
    stream.write_all(body).await
}

pub(crate) async fn read_frame(stream: &mut TcpStream, max: usize) -> io::Result<Bytes> {
    let len = stream.read_u32().await? as usize;
    if len > max {
        return Err(invalid_data("cluster frame exceeds the size limit"));
    }
    let mut buf = Vec::with_capacity(len.min(64 * 1024));
    let mut body = stream.take(len as u64);
    while body.limit() != 0 {
        if body.read_buf(&mut buf).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
    Ok(buf.into())
}

pub(crate) async fn write_message<T: Serialize>(
    stream: &mut TcpStream,
    message: &T,
) -> io::Result<()> {
    write_frame(stream, &encode(message)?, MAX_FRAME).await
}

pub(crate) async fn read_message<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<T> {
    decode(&read_frame(stream, MAX_FRAME).await?)
}

pub(crate) struct Network(pub(crate) Arc<Endpoint>);

pub(crate) struct Peer {
    endpoint: Arc<Endpoint>,
    target: u64,
}

impl RaftNetworkFactory<Types> for Network {
    type Network = Peer;

    async fn new_client(&mut self, target: u64, _node: &openraft::BasicNode) -> Peer {
        Peer {
            endpoint: self.0.clone(),
            target,
        }
    }
}

impl Peer {
    async fn call<Req, Res, Err>(
        &self,
        op: Op,
        req: &Req,
        option: &RPCOption,
    ) -> Result<Res, RPCError<Types>>
    where
        Req: Serialize + Sync,
        Res: DeserializeOwned,
        Err: DeserializeOwned + std::error::Error + 'static,
    {
        let deadline = Instant::now() + option.soft_ttl();
        let mut stream = self
            .endpoint
            .connect(self.target, deadline)
            .await
            .map_err(unreachable)?;
        let result: Result<Res, Err> = timeout_at(deadline, async {
            self.endpoint.header(&mut stream, self.target, op).await?;
            write_message(&mut stream, req).await?;
            read_message(&mut stream).await
        })
        .await
        .map_err(|_| unreachable(io::ErrorKind::TimedOut.into()))?
        .map_err(unreachable)?;
        result.map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
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
        let reply: StreamAppendResult<Types> = self
            .call::<_, _, openraft::errors::RaftError<Types>>(Op::Append, &req, &option)
            .await?;
        Ok(reply.map_err(Into::into))
    }

    async fn vote(
        &mut self,
        req: VoteRequest<Types>,
        option: RPCOption,
    ) -> Result<VoteResponse<Types>, RPCError<Types>> {
        self.call::<_, _, openraft::errors::RaftError<Types>>(Op::Vote, &req, &option)
            .await
    }

    async fn pre_vote(
        &mut self,
        req: VoteRequest<Types>,
        option: RPCOption,
    ) -> Result<VoteResponse<Types>, RPCError<Types>> {
        self.call::<_, _, openraft::errors::RaftError<Types>>(Op::PreVote, &req, &option)
            .await
    }

    async fn transfer_leader(
        &mut self,
        req: TransferLeaderRequest<Types>,
        option: RPCOption,
    ) -> Result<TransferLeaderResponse<Types>, RPCError<Types>> {
        self.call::<_, _, openraft::errors::Fatal<Types>>(Op::Transfer, &req, &option)
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
            let mut stream = self.endpoint.connect(self.target, deadline).await?;
            self.endpoint
                .header(&mut stream, self.target, Op::Snapshot)
                .await?;
            write_message(&mut stream, &(vote, snapshot.meta)).await?;
            write_frame(&mut stream, &snapshot.snapshot.leases, MAX_FRAME).await?;
            write_frame(&mut stream, &snapshot.snapshot.app, MAX_SNAPSHOT).await?;
            read_message::<Result<SnapshotResponse<Types>, openraft::errors::Fatal<Types>>>(
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

    pub async fn request(&self, node_id: u64, body: Bytes) -> Result<Bytes, ClusterError> {
        let deadline = Instant::now() + self.timeout;
        let mut stream = self.open(node_id, deadline).await?;
        timeout_at(deadline, async {
            self.endpoint
                .header(&mut stream, node_id, Op::MeshRequest)
                .await?;
            write_frame(&mut stream, &body, MAX_FRAME).await?;
            let status = stream.read_u8().await?;
            let response = read_frame(&mut stream, MAX_FRAME).await?;
            if status == 0 {
                Ok(response)
            } else {
                Err(ClusterError::MeshHandler(
                    String::from_utf8_lossy(&response).into_owned(),
                ))
            }
        })
        .await
        .map_err(|_| ClusterError::MeshTimeout(node_id))?
    }

    /// Send without waiting for a handler result. Success means the bytes were handed
    /// to TCP; it does not prove that the handler ran or that delivery can be retried safely.
    pub async fn send(&self, node_id: u64, body: Bytes) -> Result<(), ClusterError> {
        let deadline = Instant::now() + self.timeout;
        let mut stream = self.open(node_id, deadline).await?;
        timeout_at(deadline, async {
            self.endpoint
                .header(&mut stream, node_id, Op::MeshSend)
                .await?;
            write_frame(&mut stream, &body, MAX_FRAME).await
        })
        .await
        .map_err(|_| ClusterError::MeshTimeout(node_id))??;
        Ok(())
    }

    async fn open(&self, node_id: u64, deadline: Instant) -> Result<TcpStream, ClusterError> {
        if *self.stop.borrow() {
            return Err(ClusterError::Shutdown);
        }
        if !self.endpoint.peers.contains_key(&node_id) {
            return Err(ClusterError::UnknownNode(node_id));
        }
        self.endpoint
            .connect(node_id, deadline)
            .await
            .map_err(|source| ClusterError::Unreachable { node_id, source })
    }

    pub(crate) async fn handle(&self, from: u64, body: Bytes) -> Result<Bytes, ClusterError> {
        let handler = self
            .handler
            .get()
            .ok_or_else(|| ClusterError::MeshHandler("not registered".into()))?;
        handler(from, body).await
    }
}
