//! Script MQTT 3.1/3.1.1 clients against isolated broker processes.

mod process;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use mqx_codec::{DecodeContext, DecodeError, EncodeError, Packet, ProtocolVersion, decode, encode};
pub use process::{ClusterConfig, Placement};
use thiserror::Error;

use process::Brokers;

const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy)]
pub enum BrokerKind {
    Mosquitto,
    MqExtended,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("set MOSQUITTO_BUILD_DIR to the Mosquitto 2.1.4 build directory")]
    MissingMosquittoBuildDir,
    #[error("{variable}: required executable {} is unavailable: {source}", path.display())]
    Binary {
        variable: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("could not execute {}: {source}", path.display())]
    Spawn { path: PathBuf, source: io::Error },
    #[error("mosquitto_passwd failed with {0}")]
    PasswordFile(ExitStatus),
    #[error("{broker:?} failed to start ({reason}):\n{log}")]
    Startup {
        broker: BrokerKind,
        reason: String,
        log: String,
    },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(
        "connection {connection:?} ended a read with {pending} bytes of an incomplete MQTT packet ({reason})"
    )]
    PartialPacket {
        connection: Connection,
        pending: usize,
        reason: &'static str,
    },
    #[error("node index {index} is outside 1..={nodes}")]
    NodeIndex { index: usize, nodes: usize },
    #[error("node {0} is stopped")]
    NodeStopped(usize),
    #[error("node {0} is already running")]
    NodeRunning(usize),
    #[error("cluster did not agree on a live Raft leader within {timeout:?}:\n{logs}")]
    NoLeader { timeout: Duration, logs: String },
}

/// Configuration directives appended to a loopback listener in an isolated working directory.
#[derive(Default)]
pub struct BrokerConfig<'a> {
    pub conf: &'a str,
    /// Test credentials used to generate and configure a real Mosquitto password file.
    pub passwords: &'a [(&'a str, &'a str)],
    /// When present, writes and configures an ACL file even if its contents are empty.
    pub acl: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connection(usize);

#[derive(Debug, PartialEq, Eq)]
pub enum Reading {
    Received {
        packet: Packet,
        /// The original frame, including flags the decoder may ignore.
        wire: Bytes,
    },
    Closed,
    TimedOut,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub connection: Connection,
    pub reading: Reading,
}

pub type Transcript = Vec<Observation>;

struct Client {
    socket: TcpStream,
    context: DecodeContext,
    decode_buffer: BytesMut,
    wire_buffer: BytesMut,
}

impl Client {
    fn connect(addr: SocketAddr, protocol: ProtocolVersion, timeout: Duration) -> io::Result<Self> {
        let socket = TcpStream::connect_timeout(&addr, timeout)?;
        socket.set_write_timeout(Some(timeout))?;
        socket.set_nodelay(true)?;
        Ok(Self {
            socket,
            context: DecodeContext::for_client(0, Some(protocol)),
            decode_buffer: BytesMut::new(),
            wire_buffer: BytesMut::new(),
        })
    }

    fn receive(&mut self, connection: Connection, timeout: Duration) -> Result<Reading, Error> {
        let deadline = Instant::now() + timeout;
        let mut chunk = [0; 4096];
        loop {
            if let Some(packet) = decode(&mut self.decode_buffer, self.context)? {
                let consumed = self.wire_buffer.len() - self.decode_buffer.len();
                let wire = self.wire_buffer.split_to(consumed).freeze();
                return Ok(Reading::Received { packet, wire });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.finished_read(connection, Reading::TimedOut, "deadline elapsed");
            }
            self.socket.set_read_timeout(Some(remaining))?;
            match self.socket.read(&mut chunk) {
                Ok(0) => return self.finished_read(connection, Reading::Closed, "peer closed"),
                Ok(len) => {
                    self.decode_buffer.extend_from_slice(&chunk[..len]);
                    self.wire_buffer.extend_from_slice(&chunk[..len]);
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return self.finished_read(connection, Reading::TimedOut, "read timed out");
                    }
                    io::ErrorKind::ConnectionReset => {
                        return self.finished_read(connection, Reading::Closed, "peer reset");
                    }
                    _ => return Err(err.into()),
                },
            }
        }
    }

    fn finished_read(
        &self,
        connection: Connection,
        reading: Reading,
        reason: &'static str,
    ) -> Result<Reading, Error> {
        if self.decode_buffer.is_empty() {
            return Ok(reading);
        }
        Err(Error::PartialPacket {
            connection,
            pending: self.decode_buffer.len(),
            reason,
        })
    }
}

/// Owns isolated broker processes, scripted sockets, and observations in script order.
pub struct Harness {
    clients: Vec<Option<Client>>,
    transcript: Transcript,
    brokers: Brokers,
}

impl Harness {
    pub fn start(kind: BrokerKind, config: BrokerConfig<'_>) -> Result<Self, Error> {
        Ok(Self::with_brokers(Brokers::start(kind, config, None)?))
    }

    /// Starts the cluster and waits for an accepted CONNECT on every node.
    pub fn start_cluster(config: BrokerConfig<'_>, cluster: ClusterConfig) -> Result<Self, Error> {
        Ok(Self::with_brokers(Brokers::start(
            BrokerKind::MqExtended,
            config,
            Some(cluster),
        )?))
    }

    fn with_brokers(brokers: Brokers) -> Self {
        Self {
            clients: Vec::new(),
            transcript: Vec::new(),
            brokers,
        }
    }

    /// Opens a socket without sending CONNECT. `protocol` controls receive decoding.
    pub fn open(&mut self, protocol: ProtocolVersion) -> Result<Connection, Error> {
        self.open_on(self.brokers.choose(self.clients.len()), protocol)
    }

    /// Opens a socket on the specified one-based node, overriding the placement policy.
    pub fn open_on(
        &mut self,
        index: usize,
        protocol: ProtocolVersion,
    ) -> Result<Connection, Error> {
        let client = Client::connect(self.brokers.addr(index)?, protocol, WRITE_TIMEOUT)?;
        let connection = Connection(self.clients.len());
        self.clients.push(Some(client));
        Ok(connection)
    }

    /// SIGKILLs and reaps a node. Existing connections remain readable to observe EOF.
    pub fn kill_node(&mut self, index: usize) -> Result<(), Error> {
        self.brokers.kill(index)
    }

    /// Starts a stopped node with the same configuration, ports and data directory.
    pub fn restart_node(&mut self, index: usize) -> Result<(), Error> {
        self.brokers.restart(index)
    }

    /// Waits for all running nodes to report the same live leader in their logs.
    pub fn wait_for_leader(&mut self, timeout: Duration) -> Result<usize, Error> {
        self.brokers.wait_for_leader(timeout)
    }

    pub fn send(&mut self, connection: Connection, packet: &Packet) -> Result<(), Error> {
        let mut wire = BytesMut::new();
        encode(packet, &mut wire)?;
        self.send_raw(connection, &wire)
    }

    pub fn send_raw(&mut self, connection: Connection, wire: &[u8]) -> Result<(), Error> {
        self.client(connection).socket.write_all(wire)?;
        Ok(())
    }

    pub fn receive(
        &mut self,
        connection: Connection,
        timeout: Duration,
    ) -> Result<&Reading, Error> {
        let reading = self.client(connection).receive(connection, timeout)?;
        self.transcript.push(Observation {
            connection,
            reading,
        });
        Ok(&self
            .transcript
            .last()
            .expect("observation was pushed")
            .reading)
    }

    /// Drops the TCP socket without sending DISCONNECT.
    pub fn close_socket(&mut self, connection: Connection) {
        assert!(
            self.clients[connection.0].take().is_some(),
            "socket already closed"
        );
    }

    pub fn into_transcript(self) -> Transcript {
        self.transcript
    }

    fn client(&mut self, connection: Connection) -> &mut Client {
        self.clients[connection.0]
            .as_mut()
            .expect("socket already closed")
    }
}
