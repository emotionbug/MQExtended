//! Script MQTT 3.1/3.1.1 and MQTT 5 clients against isolated broker processes.

mod process;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use mqx_codec::{
    DecodeContext, DecodeError, EncodeError, Packet, ProtocolVersion, decode, encode, v5,
};
pub use process::{ClusterConfig, ClusterReadiness, Placement};
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
    #[error(transparent)]
    EncodeV5(#[from] v5::EncodeError),
    #[error(transparent)]
    DecodeV5(#[from] v5::DecodeError),
    #[error("raw MQTT frame has an invalid Remaining Length encoding")]
    RawRemainingLength,
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
    #[error("node {0} does not have an HTTP status listener")]
    NoHttpStatusListener(usize),
    #[error("node {index} did not exit within {timeout:?} of SIGTERM:\n{log}")]
    StopTimeout {
        index: usize,
        timeout: Duration,
        log: String,
    },
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
    ReceivedV5 {
        packet: v5::Packet,
        /// The original frame, including properties in their original wire order.
        wire: Bytes,
    },
    /// A complete frame read without interpreting its packet body.
    Raw(Bytes),
    Closed,
    TimedOut,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub connection: Connection,
    pub reading: Reading,
}

pub type Transcript = Vec<Observation>;

#[derive(Clone, Copy)]
enum Decoder {
    V3(DecodeContext),
    V5,
}

impl From<ProtocolVersion> for Decoder {
    fn from(protocol: ProtocolVersion) -> Self {
        Self::V3(DecodeContext::for_client(0, Some(protocol)))
    }
}

struct Client {
    socket: TcpStream,
    decoder: Decoder,
    decode_buffer: BytesMut,
    wire_buffer: BytesMut,
}

impl Client {
    fn connect(addr: SocketAddr, decoder: Decoder, timeout: Duration) -> io::Result<Self> {
        let socket = TcpStream::connect_timeout(&addr, timeout)?;
        socket.set_write_timeout(Some(timeout))?;
        socket.set_nodelay(true)?;
        Ok(Self {
            socket,
            decoder,
            decode_buffer: BytesMut::new(),
            wire_buffer: BytesMut::new(),
        })
    }

    fn receive(
        &mut self,
        connection: Connection,
        timeout: Duration,
        raw: bool,
    ) -> Result<Reading, Error> {
        let deadline = Instant::now() + timeout;
        let mut chunk = [0; 4096];
        loop {
            if let Some(reading) = self.read_frame(raw)? {
                return Ok(reading);
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

    fn read_frame(&mut self, raw: bool) -> Result<Option<Reading>, Error> {
        if raw {
            let Some(len) = raw_frame_length(&self.decode_buffer)? else {
                return Ok(None);
            };
            self.decode_buffer.advance(len);
            return Ok(Some(Reading::Raw(self.take_wire())));
        }
        Ok(match self.decoder {
            Decoder::V3(context) => {
                decode(&mut self.decode_buffer, context)?.map(|packet| Reading::Received {
                    packet,
                    wire: self.take_wire(),
                })
            }
            Decoder::V5 => v5::decode(&mut self.decode_buffer, v5::DecodeContext::for_client(0))?
                .map(|packet| Reading::ReceivedV5 {
                    packet,
                    wire: self.take_wire(),
                }),
        })
    }

    fn take_wire(&mut self) -> Bytes {
        let consumed = self.wire_buffer.len() - self.decode_buffer.len();
        self.wire_buffer.split_to(consumed).freeze()
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

fn raw_frame_length(buffer: &[u8]) -> Result<Option<usize>, Error> {
    let mut body_len = 0;
    for (index, &byte) in buffer.iter().skip(1).take(4).enumerate() {
        body_len |= usize::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            let frame_len = 2 + index + body_len;
            return Ok((buffer.len() >= frame_len).then_some(frame_len));
        }
    }
    if buffer.len() >= 5 {
        return Err(Error::RawRemainingLength);
    }
    Ok(None)
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

    /// Starts a standalone broker from an explicit build, e.g. one built with plugins.
    pub fn start_with_binary(
        kind: BrokerKind,
        binary: &Path,
        config: BrokerConfig<'_>,
    ) -> Result<Self, Error> {
        Ok(Self::with_brokers(Brokers::start_with_binary(
            kind,
            binary.canonicalize()?,
            config,
            None,
        )?))
    }

    /// Starts the cluster and waits for the configured readiness check.
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
        self.open_with(index, protocol.into())
    }

    /// Opens an MQTT 5 socket without sending CONNECT.
    pub fn open_v5(&mut self) -> Result<Connection, Error> {
        self.open_v5_on(self.brokers.choose(self.clients.len()))
    }

    /// Opens an MQTT 5 socket on the specified one-based node.
    pub fn open_v5_on(&mut self, index: usize) -> Result<Connection, Error> {
        self.open_with(index, Decoder::V5)
    }

    fn open_with(&mut self, index: usize, decoder: Decoder) -> Result<Connection, Error> {
        let client = Client::connect(self.brokers.addr(index)?, decoder, WRITE_TIMEOUT)?;
        let connection = Connection(self.clients.len());
        self.clients.push(Some(client));
        Ok(connection)
    }

    /// SIGKILLs and reaps a node. Existing connections remain readable to observe EOF.
    pub fn kill_node(&mut self, index: usize) -> Result<(), Error> {
        self.brokers.kill(index)
    }

    /// Pauses a node with SIGSTOP without closing its sockets.
    #[cfg(unix)]
    pub fn suspend_node(&self, index: usize) -> Result<(), Error> {
        self.brokers.signal(index, "STOP")
    }

    /// Sends SIGCONT to a node paused with `suspend_node`.
    #[cfg(unix)]
    pub fn resume_node(&self, index: usize) -> Result<(), Error> {
        self.brokers.signal(index, "CONT")
    }

    /// Starts a stopped node with the same configuration, ports and data directory.
    pub fn restart_node(&mut self, index: usize) -> Result<(), Error> {
        self.brokers.restart(index)
    }

    /// SIGTERMs and reaps a node, as an operator stopping it would. Its ports and
    /// data directory stay reserved for `restart_node`.
    pub fn stop_node(&mut self, index: usize) -> Result<(), Error> {
        self.brokers.stop(index)
    }

    /// Sends SIGUSR1, requesting an immediate persistence backup.
    #[cfg(unix)]
    pub fn backup_node(&self, index: usize) -> Result<(), Error> {
        self.brokers.signal(index, "USR1")
    }

    /// Replaces the scenario's directives in a node's configuration with `conf`
    /// (listener, password/ACL and cluster lines are kept). A running node gets
    /// SIGHUP and applies it asynchronously; a stopped node uses it on restart.
    pub fn reload_node(&mut self, index: usize, conf: &str) -> Result<(), Error> {
        self.brokers.reload(index, conf)
    }

    /// The MQTT listener address of a running node.
    pub fn node_addr(&self, index: usize) -> Result<SocketAddr, Error> {
        self.brokers.addr(index)
    }

    /// Everything the node has logged so far, including before a stop.
    pub fn node_log(&self, index: usize) -> Result<String, Error> {
        self.brokers.log(index)
    }

    /// The Raft storage directory, accessible even while the node is stopped.
    pub fn node_cluster_data_dir(&self, index: usize) -> Result<PathBuf, Error> {
        self.brokers.cluster_data_dir(index)
    }

    /// Waits for all running nodes to report the same live leader.
    pub fn wait_for_leader(&mut self, timeout: Duration) -> Result<usize, Error> {
        self.brokers.wait_for_leader(timeout)
    }

    /// Fetches the cluster status from a node started with `ClusterReadiness::HttpStatus`.
    /// `None` means the probe did not get a cluster status response within `timeout`.
    pub fn node_cluster_status(
        &self,
        index: usize,
        timeout: Duration,
    ) -> Result<Option<serde_json::Value>, Error> {
        self.brokers.cluster_status(index, timeout)
    }

    /// Probes MQTT admission on a node started with `ClusterReadiness::HttpStatus`.
    /// `None` means the HTTP probe did not report readiness within `timeout`.
    pub fn node_mqtt_ready(&self, index: usize, timeout: Duration) -> Result<Option<bool>, Error> {
        self.brokers.mqtt_ready(index, timeout)
    }

    pub fn send(&mut self, connection: Connection, packet: &Packet) -> Result<(), Error> {
        let mut wire = BytesMut::new();
        encode(packet, &mut wire)?;
        self.send_raw(connection, &wire)
    }

    pub fn send_v5(&mut self, connection: Connection, packet: &v5::Packet) -> Result<(), Error> {
        let mut wire = BytesMut::new();
        v5::encode(packet, &mut wire)?;
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
        self.observe(connection, timeout, false)
    }

    /// Records the next complete frame without applying the negotiated version's decoder.
    pub fn receive_raw(
        &mut self,
        connection: Connection,
        timeout: Duration,
    ) -> Result<&Reading, Error> {
        self.observe(connection, timeout, true)
    }

    fn observe(
        &mut self,
        connection: Connection,
        timeout: Duration,
        raw: bool,
    ) -> Result<&Reading, Error> {
        let reading = self.client(connection).receive(connection, timeout, raw)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_read_waits_for_a_complete_frame_and_preserves_its_encoded_length() {
        assert_eq!(raw_frame_length(&[0xd0]).unwrap(), None);
        assert_eq!(raw_frame_length(&[0xd0, 0x80]).unwrap(), None);
        assert_eq!(raw_frame_length(&[0x30, 0x81, 0]).unwrap(), None);
        assert_eq!(
            raw_frame_length(&[0x30, 0x81, 0, 0xff, 0xd0, 0]).unwrap(),
            Some(4),
        );
        assert!(matches!(
            raw_frame_length(&[0x30, 0x80, 0x80, 0x80, 0x80]),
            Err(Error::RawRemainingLength),
        ));
    }
}
