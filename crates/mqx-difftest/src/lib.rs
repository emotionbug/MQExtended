//! Script MQTT 3.1/3.1.1 clients against isolated broker processes.

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use mqx_codec::{DecodeContext, DecodeError, EncodeError, Packet, ProtocolVersion, decode, encode};
use tempfile::TempDir;
use thiserror::Error;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
// Don't let two tests in this process choose the same released port before either child binds.
static STARTUP_LOCK: Mutex<()> = Mutex::new(());

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
}

impl BrokerKind {
    fn binary(self) -> Result<PathBuf, Error> {
        match self {
            Self::Mosquitto => mosquitto_binary("src/mosquitto"),
            Self::MqExtended => {
                let path = env::var_os("MQEXTENDED_BIN").map_or_else(
                    || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/mqextended"),
                    PathBuf::from,
                );
                required_binary("MQEXTENDED_BIN", path)
            }
        }
    }
}

fn required_binary(variable: &'static str, path: PathBuf) -> Result<PathBuf, Error> {
    let resolve = || {
        let binary = path.canonicalize()?;
        if !binary.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file"));
        }
        Ok(binary)
    };
    resolve().map_err(|source| Error::Binary {
        variable,
        path,
        source,
    })
}

fn mosquitto_binary(relative: &str) -> Result<PathBuf, Error> {
    let build = env::var_os("MOSQUITTO_BUILD_DIR").ok_or(Error::MissingMosquittoBuildDir)?;
    required_binary("MOSQUITTO_BUILD_DIR", PathBuf::from(build).join(relative))
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

struct BrokerProcess {
    child: Child,
    dir: TempDir,
    addr: SocketAddr,
}

impl BrokerProcess {
    fn start(kind: BrokerKind, config: BrokerConfig<'_>) -> Result<Self, Error> {
        let bin = kind.binary()?;
        let dir = tempfile::tempdir()?;
        let work_dir = dir.path();
        let mut conf = String::new();
        if !config.passwords.is_empty() {
            generate_password_file(work_dir, config.passwords)?;
            conf.push_str("password_file passwords\n");
        }
        if let Some(acl) = config.acl {
            fs::write(work_dir.join("acl"), acl)?;
            conf.push_str("acl_file acl\n");
        }
        conf.push_str(config.conf);
        let log = File::create(work_dir.join("broker.log"))?;

        let _startup = STARTUP_LOCK.lock().expect("broker startup lock poisoned");
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = reservation.local_addr()?;
        fs::write(
            work_dir.join("mosquitto.conf"),
            format!("listener {} 127.0.0.1\n{conf}\n", addr.port()),
        )?;
        let mut command = Command::new(&bin);
        command
            .args(["-c", "mosquitto.conf"])
            .current_dir(work_dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        drop(reservation);
        let child = command
            .spawn()
            .map_err(|source| Error::Spawn { path: bin, source })?;
        let mut broker = Self { child, dir, addr };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let reason = loop {
            if let Some(status) = broker.child.try_wait()? {
                break status.to_string();
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
                return Ok(broker);
            }
            if Instant::now() >= deadline {
                break format!("did not listen on {addr} within {STARTUP_TIMEOUT:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };
        Err(Error::Startup {
            broker: kind,
            reason,
            log: fs::read_to_string(broker.dir.path().join("broker.log")).unwrap_or_default(),
        })
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn generate_password_file(dir: &Path, users: &[(&str, &str)]) -> Result<(), Error> {
    let bin = mosquitto_binary("apps/mosquitto_passwd/mosquitto_passwd")?;
    for (index, (username, password)) in users.iter().enumerate() {
        let mut command = Command::new(&bin);
        command.arg("-b");
        if index == 0 {
            command.arg("-c");
        }
        let status = command
            .args(["passwords", username, password])
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|source| Error::Spawn {
                path: bin.clone(),
                source,
            })?;
        if !status.success() {
            return Err(Error::PasswordFile(status));
        }
    }
    Ok(())
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

/// Owns one broker, its scripted sockets, and its transcript in script observation order.
pub struct Harness {
    clients: Vec<Option<Client>>,
    transcript: Transcript,
    broker: BrokerProcess,
}

impl Harness {
    pub fn start(kind: BrokerKind, config: BrokerConfig<'_>) -> Result<Self, Error> {
        Ok(Self {
            clients: Vec::new(),
            transcript: Vec::new(),
            broker: BrokerProcess::start(kind, config)?,
        })
    }

    /// Opens a socket without sending CONNECT. `protocol` controls receive decoding.
    pub fn open(&mut self, protocol: ProtocolVersion) -> Result<Connection, Error> {
        let socket = TcpStream::connect_timeout(&self.broker.addr, WRITE_TIMEOUT)?;
        socket.set_write_timeout(Some(WRITE_TIMEOUT))?;
        socket.set_nodelay(true)?;
        let connection = Connection(self.clients.len());
        self.clients.push(Some(Client {
            socket,
            context: DecodeContext::for_client(0, Some(protocol)),
            decode_buffer: BytesMut::new(),
            wire_buffer: BytesMut::new(),
        }));
        Ok(connection)
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
