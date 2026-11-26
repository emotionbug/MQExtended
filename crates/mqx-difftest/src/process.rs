use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use mqx_codec::{Connect, ConnectReturnCode, Packet, ProtocolVersion, encode};
use socket2::{Domain, Socket, Type};
use tempfile::TempDir;

use crate::{BrokerConfig, BrokerKind, Client, Connection, Error, Reading};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const PROBE_TIMEOUT: Duration = Duration::from_millis(350);
// Don't let two tests choose the same released port before either child binds.
static STARTUP_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy)]
pub enum Placement {
    FirstNode,
    RoundRobin,
    /// One-based node ID, as in the generated config.
    Node(usize),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClusterReadiness {
    /// Wait for an accepted anonymous MQTT CONNECT on a separate listener.
    #[default]
    Mqtt,
    /// Wait for the MQTT listeners and a common live Raft leader via HTTP.
    /// Scope auth plugins to the scenario listeners so they do not policy-check
    /// the health request on the separate loopback HTTP API listener.
    HttpStatus,
}

#[derive(Debug, Clone, Copy)]
pub struct ClusterConfig {
    pub nodes: NonZeroUsize,
    pub placement: Placement,
    pub readiness: ClusterReadiness,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            nodes: NonZeroUsize::new(3).unwrap(),
            placement: Placement::RoundRobin,
            readiness: ClusterReadiness::default(),
        }
    }
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

/// Writes the password and ACL files and returns the directives that load them.
fn prepare_files(dir: &Path, config: &BrokerConfig<'_>) -> Result<String, Error> {
    let mut prefix = String::new();
    if !config.passwords.is_empty() {
        generate_password_file(dir, config.passwords)?;
        prefix.push_str("password_file passwords\n");
    }
    if let Some(acl) = config.acl {
        fs::write(dir.join("acl"), acl)?;
        prefix.push_str("acl_file acl\n");
    }
    Ok(prefix)
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

enum Readiness {
    Mqtt(SocketAddr, BytesMut),
    HttpStatus(SocketAddr),
}

struct BrokerProcess {
    child: Option<Child>,
    dir: TempDir,
    addr: SocketAddr,
    readiness: Option<Readiness>,
    /// 1-based node index, its cluster mesh and the password/ACL directives, kept
    /// so that `write_config` can regenerate `mosquitto.conf` for a reload.
    index: usize,
    mesh: Vec<SocketAddr>,
    prefix: String,
}

impl BrokerProcess {
    fn write_config(&self, conf: &str) -> io::Result<()> {
        fs::write(
            self.dir.path().join("mosquitto.conf"),
            node_config(
                self.addr,
                &format!("{}{conf}", self.prefix),
                self.index,
                &self.mesh,
                self.readiness.as_ref().map(|probe| match probe {
                    Readiness::Mqtt(addr, _) => (*addr, ClusterReadiness::Mqtt),
                    Readiness::HttpStatus(addr) => (*addr, ClusterReadiness::HttpStatus),
                }),
            ),
        )
    }

    /// Sends `signal` (a `kill(1)` signal name) to the running child.
    fn signal(&self, signal: &str) -> io::Result<()> {
        let child = self.child.as_ref().expect("signalled broker is running");
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(child.id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "kill -{signal} failed with {status}"
            )))
        }
    }

    fn spawn(&mut self, bin: &Path, kind: BrokerKind) -> Result<(), Error> {
        let log = File::create(self.dir.path().join("broker.log"))?;
        let mut command = Command::new(bin);
        command
            .args(["-c", "mosquitto.conf"])
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        if matches!(kind, BrokerKind::MqExtended) {
            // Integration tests run many processes in parallel; cap runtime threads per node.
            command.env("TOKIO_WORKER_THREADS", "2");
        }
        self.child = Some(command.spawn().map_err(|source| Error::Spawn {
            path: bin.to_owned(),
            source,
        })?);
        Ok(())
    }

    /// `Child::kill` sends SIGKILL on Unix. Reap before reusing the node's ports or data dir.
    fn kill(&mut self) -> io::Result<()> {
        if let Some(child) = &mut self.child {
            if child.try_wait()?.is_none() {
                child.kill()?;
                child.wait()?;
            }
            self.child = None;
        }
        Ok(())
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("broker.log"))
            .unwrap_or_else(|error| format!("could not read broker log: {error}"))
    }

    fn wait_until_listening(
        &mut self,
        kind: BrokerKind,
        index: usize,
        deadline: Instant,
    ) -> Result<(), Error> {
        loop {
            self.check_child(kind, index)?;
            let remaining = time_left(deadline);
            if remaining.is_zero() {
                return Err(self.startup_error(
                    kind,
                    index,
                    format!("did not listen on {}", self.addr),
                ));
            }
            // If the reserved port is ephemeral, connecting to it before the
            // broker binds can connect the socket to itself. That proves
            // nothing and holds the port the broker is about to bind.
            if let Ok(stream) = TcpStream::connect_timeout(&self.addr, PROBE_TIMEOUT.min(remaining))
                && stream.local_addr().ok() != stream.peer_addr().ok()
            {
                return Ok(());
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn wait_until_accepting(
        &mut self,
        kind: BrokerKind,
        index: usize,
        deadline: Instant,
    ) -> Result<(), Error> {
        loop {
            self.check_child(kind, index)?;
            let Some(Readiness::Mqtt(addr, connect)) = &self.readiness else {
                return Ok(());
            };
            let result = probe(*addr, index, connect, deadline);
            if matches!(result, Ok(true)) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(self.startup_error(
                    kind,
                    index,
                    format!("cluster readiness probe did not complete (last result: {result:?})"),
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn check_child(&mut self, kind: BrokerKind, index: usize) -> Result<(), Error> {
        if let Some(status) = self
            .child
            .as_mut()
            .expect("broker was spawned")
            .try_wait()?
        {
            return Err(self.startup_error(kind, index, status.to_string()));
        }
        Ok(())
    }

    fn startup_error(&self, broker: BrokerKind, index: usize, reason: String) -> Error {
        Error::Startup {
            broker,
            reason: format!("node {index}: {reason}"),
            log: self.log(),
        }
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        // The test runner shows this only for the failed test.
        let report = thread::panicking().then(|| match self.child.as_mut().map(Child::try_wait) {
            Some(Ok(None)) => "running".to_owned(),
            Some(Ok(Some(status))) => status.to_string(),
            Some(Err(error)) => error.to_string(),
            None => "stopped".to_owned(),
        });
        let _ = self.kill();
        if let Some(state) = report {
            eprintln!(
                "----- broker {} on {}, {state}; log -----\n{}",
                self.index,
                self.addr,
                self.log()
            );
        }
    }
}

fn time_left(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn probe(addr: SocketAddr, index: usize, connect: &[u8], deadline: Instant) -> Result<bool, Error> {
    use std::io::Write as _;

    let limit = |deadline| {
        PROBE_TIMEOUT
            .min(time_left(deadline))
            .max(Duration::from_millis(1))
    };
    let mut client = Client::connect(addr, ProtocolVersion::V311.into(), limit(deadline))?;
    client.socket.write_all(connect)?;
    let probe_id = Connection(index);
    if !matches!(
        client.receive(probe_id, limit(deadline), false)?,
        Reading::Received { packet: Packet::ConnAck(ack), .. } if ack.code == ConnectReturnCode::Accepted
    ) {
        return Ok(false);
    }
    client.socket.write_all(&[0xe0, 0])?;
    Ok(matches!(
        client.receive(probe_id, limit(deadline), false)?,
        Reading::Closed
    ))
}

pub(super) struct Brokers {
    kind: BrokerKind,
    bin: PathBuf,
    nodes: Vec<BrokerProcess>,
    placement: Placement,
}

impl Brokers {
    pub(super) fn start(
        kind: BrokerKind,
        config: BrokerConfig<'_>,
        cluster: Option<ClusterConfig>,
    ) -> Result<Self, Error> {
        Self::start_with_binary(kind, kind.binary()?, config, cluster)
    }

    pub(super) fn start_with_binary(
        kind: BrokerKind,
        bin: PathBuf,
        config: BrokerConfig<'_>,
        cluster: Option<ClusterConfig>,
    ) -> Result<Self, Error> {
        let (size, placement) = cluster.map_or((1, Placement::FirstNode), |cluster| {
            (cluster.nodes.get(), cluster.placement)
        });
        if let Placement::Node(index) = placement {
            check_index(index, size)?;
        }
        let dirs = (0..size)
            .map(|_| {
                let dir = tempfile::tempdir()?;
                let prefix = prepare_files(dir.path(), &config)?;
                Ok((dir, prefix))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let startup = STARTUP_LOCK.lock().expect("broker startup lock poisoned");
        let cluster_ports = if cluster.is_some() { size } else { 0 };
        let listeners = reserve_ports(size)?;
        let mesh = reserve_ports(cluster_ports)?;
        let mut readiness_listeners = reserve_ports(cluster_ports)?.into_iter();
        let mesh_addrs = mesh.iter().map(|port| port.addr).collect::<Vec<_>>();
        let mut nodes = Vec::with_capacity(size);
        for (offset, ((dir, prefix), listener)) in dirs.into_iter().zip(listeners).enumerate() {
            let addr = listener.addr;
            let readiness_listener = readiness_listeners.next();
            let readiness = match (readiness_listener.as_ref(), cluster) {
                (Some(listener), Some(cluster)) => Some(match cluster.readiness {
                    ClusterReadiness::Mqtt => {
                        Readiness::Mqtt(listener.addr, probe_connect(offset + 1)?)
                    }
                    ClusterReadiness::HttpStatus => Readiness::HttpStatus(listener.addr),
                }),
                _ => None,
            };
            if cluster.is_some() {
                fs::create_dir(dir.path().join("raft-data"))?;
            }
            let node = BrokerProcess {
                child: None,
                dir,
                addr,
                readiness,
                index: offset + 1,
                mesh: mesh_addrs.clone(),
                prefix,
            };
            node.write_config(config.conf)?;
            nodes.push((node, listener, readiness_listener));
        }
        let mut brokers = Self {
            kind,
            bin,
            nodes: Vec::with_capacity(size),
            placement,
        };
        let mut mesh = mesh.into_iter();
        for (mut node, listener, readiness_listener) in nodes {
            drop(listener);
            drop(mesh.next());
            drop(readiness_listener);
            node.spawn(&brokers.bin, kind)?;
            brokers.nodes.push(node);
        }
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        for (offset, node) in brokers.nodes.iter_mut().enumerate() {
            node.wait_until_listening(kind, offset + 1, deadline)?;
        }
        drop(startup);
        for (offset, node) in brokers.nodes.iter_mut().enumerate() {
            node.wait_until_accepting(kind, offset + 1, deadline)?;
        }
        if cluster.is_some_and(|config| config.readiness == ClusterReadiness::HttpStatus) {
            brokers.wait_for_leader(time_left(deadline))?;
        }
        Ok(brokers)
    }

    pub(super) fn choose(&self, opened: usize) -> usize {
        match self.placement {
            Placement::FirstNode => 1,
            Placement::RoundRobin => opened % self.nodes.len() + 1,
            Placement::Node(index) => index,
        }
    }

    pub(super) fn addr(&self, index: usize) -> Result<SocketAddr, Error> {
        let node = &self.nodes[check_index(index, self.nodes.len())?];
        node.child.as_ref().ok_or(Error::NodeStopped(index))?;
        Ok(node.addr)
    }

    pub(super) fn log(&self, index: usize) -> Result<String, Error> {
        Ok(self.nodes[check_index(index, self.nodes.len())?].log())
    }

    pub(super) fn cluster_data_dir(&self, index: usize) -> Result<PathBuf, Error> {
        let node = &self.nodes[check_index(index, self.nodes.len())?];
        if node.mesh.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "node is not clustered").into(),
            );
        }
        Ok(node.dir.path().join("raft-data"))
    }

    #[cfg(unix)]
    pub(super) fn signal(&self, index: usize, signal: &str) -> Result<(), Error> {
        let node = &self.nodes[check_index(index, self.nodes.len())?];
        node.child.as_ref().ok_or(Error::NodeStopped(index))?;
        node.signal(signal)?;
        Ok(())
    }

    pub(super) fn cluster_status(
        &self,
        index: usize,
        timeout: Duration,
    ) -> Result<Option<serde_json::Value>, Error> {
        Ok(probe_status(
            self.http_addr(index)?,
            Instant::now() + timeout,
        ))
    }

    pub(super) fn mqtt_ready(
        &self,
        index: usize,
        timeout: Duration,
    ) -> Result<Option<bool>, Error> {
        Ok(probe_http(
            self.http_addr(index)?,
            "/api/v1/mqx/ready",
            Instant::now() + timeout,
            |code, _| match code {
                200 => Some(true),
                503 => Some(false),
                _ => None,
            },
        ))
    }

    fn http_addr(&self, index: usize) -> Result<SocketAddr, Error> {
        let node = &self.nodes[check_index(index, self.nodes.len())?];
        node.child.as_ref().ok_or(Error::NodeStopped(index))?;
        match node.readiness {
            Some(Readiness::HttpStatus(addr)) => Ok(addr),
            _ => Err(Error::NoHttpStatusListener(index)),
        }
    }

    /// Rewrites a node's configuration with `conf` in place of the scenario's
    /// directives. A running node gets SIGHUP; a stopped one uses it on restart.
    pub(super) fn reload(&mut self, index: usize, conf: &str) -> Result<(), Error> {
        let offset = check_index(index, self.nodes.len())?;
        let node = &mut self.nodes[offset];
        node.write_config(conf)?;
        if node.child.is_some() {
            node.check_child(self.kind, index)?;
            node.signal("HUP")?;
        }
        Ok(())
    }

    /// SIGTERMs a node and reaps it, keeping its ports and data directory for `restart`.
    pub(super) fn stop(&mut self, index: usize) -> Result<(), Error> {
        let offset = check_index(index, self.nodes.len())?;
        let node = &mut self.nodes[offset];
        if node.child.is_none() {
            return Err(Error::NodeStopped(index));
        }
        node.check_child(self.kind, index)?;
        node.signal("TERM")?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        let child = node.child.as_mut().expect("checked above");
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                node.kill()?;
                return Err(Error::StopTimeout {
                    index,
                    timeout: STOP_TIMEOUT,
                    log: node.log(),
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
        node.child = None;
        Ok(())
    }

    pub(super) fn kill(&mut self, index: usize) -> Result<(), Error> {
        let offset = check_index(index, self.nodes.len())?;
        let node = &mut self.nodes[offset];
        if node.child.is_none() {
            return Err(Error::NodeStopped(index));
        }
        node.check_child(self.kind, index)?;
        node.kill()?;
        Ok(())
    }

    pub(super) fn restart(&mut self, index: usize) -> Result<(), Error> {
        let offset = check_index(index, self.nodes.len())?;
        let node = &mut self.nodes[offset];
        if node.child.is_some() {
            return Err(Error::NodeRunning(index));
        }
        let startup = STARTUP_LOCK.lock().expect("broker startup lock poisoned");
        node.spawn(&self.bin, self.kind)?;
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let result = node.wait_until_listening(self.kind, index, deadline);
        drop(startup);
        let result = result.and_then(|()| node.wait_until_accepting(self.kind, index, deadline));
        if result.is_err() {
            let _ = node.kill();
        }
        result
    }

    pub(super) fn wait_for_leader(&mut self, timeout: Duration) -> Result<usize, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut observations = Vec::with_capacity(self.nodes.len());
            for (offset, node) in self.nodes.iter_mut().enumerate() {
                if node.child.is_some() {
                    node.check_child(self.kind, offset + 1)?;
                    observations.push(match node.readiness {
                        Some(Readiness::HttpStatus(addr)) => probe_leader(addr, deadline),
                        _ => observed_leader(&node.log()),
                    });
                }
            }
            if let Some(Some(leader)) = observations.first().copied()
                && self.addr(leader).is_ok()
                && observations.iter().all(|seen| *seen == Some(leader))
            {
                return Ok(leader);
            }
            if Instant::now() >= deadline {
                let logs = self
                    .nodes
                    .iter()
                    .enumerate()
                    .map(|(offset, node)| format!("node {}:\n{}", offset + 1, node.log()))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(Error::NoLeader { timeout, logs });
            }
            thread::sleep(POLL_INTERVAL.min(time_left(deadline)));
        }
    }
}

fn check_index(index: usize, nodes: usize) -> Result<usize, Error> {
    if (1..=nodes).contains(&index) {
        Ok(index - 1)
    } else {
        Err(Error::NodeIndex { index, nodes })
    }
}

/// A loopback port held by a bound socket that does not listen.
///
/// A listening placeholder would accept connections, and a child forked by
/// another thread keeps a copy of it listening until its exec. The startup
/// probe could then connect before the broker runs.
struct Reservation {
    _socket: Socket,
    addr: SocketAddr,
}

impl Reservation {
    fn bind(port: u16) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)).into())?;
        let addr = socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("reserved socket has no IP address"))?;
        Ok(Self {
            _socket: socket,
            addr,
        })
    }
}

/// Reserve loopback ports below the kernel's ephemeral range.
///
/// A reserved port is released just before its broker binds it, and a node
/// restart binds it again later. A port from `bind(0)` is ephemeral, so in
/// between any outbound connect in this process (clients, or cluster nodes
/// redialling a stopped peer) can take it and the broker fails with
/// `AddrInUse`. Outbound connects never get ports outside the ephemeral range;
/// the per-process offset keeps concurrent test binaries apart.
fn reserve_ports(count: usize) -> io::Result<Vec<Reservation>> {
    use std::sync::atomic::{AtomicU32, Ordering};

    const FIRST: u32 = 10_000;
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let ephemeral = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u32>().ok())
        .unwrap_or(32_768);
    if ephemeral <= FIRST + 1_000 {
        return (0..count).map(|_| Reservation::bind(0)).collect();
    }
    let span = ephemeral - FIRST;
    let offset = std::process::id().wrapping_mul(7_919) % span;
    (0..count)
        .map(|_| {
            for _ in 0..span {
                let port = FIRST + (offset + NEXT.fetch_add(1, Ordering::Relaxed)) % span;
                let port = u16::try_from(port).expect("below the ephemeral range");
                if let Ok(reservation) = Reservation::bind(port) {
                    return Ok(reservation);
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "no free port below the ephemeral range",
            ))
        })
        .collect()
}

fn node_config(
    listener: SocketAddr,
    common: &str,
    index: usize,
    mesh: &[SocketAddr],
    readiness: Option<(SocketAddr, ClusterReadiness)>,
) -> String {
    let mut conf = format!("listener {} 127.0.0.1\n{common}\n", listener.port());
    if mesh.is_empty() {
        return conf;
    }
    writeln!(
        conf,
        "cluster_node_id {index}\ncluster_bind {}",
        mesh[index - 1]
    )
    .unwrap();
    for (offset, addr) in mesh.iter().enumerate() {
        writeln!(conf, "cluster_peer {} {addr}", offset + 1).unwrap();
    }
    conf.push_str(concat!(
        "cluster_data_dir raft-data\n",
        // Parallel scenarios share one disk; a 1 GiB reserve per node would fill it.
        "cluster_storage_reserve 0\n",
        "cluster_insecure_plaintext true\n",
        "cluster_heartbeat_interval 30\n",
        "cluster_election_timeout 150 300\n",
        "cluster_lease_interval 200\n",
    ));
    if !common
        .lines()
        .any(|line| line.split_ascii_whitespace().next() == Some("cluster_lease_timeout"))
    {
        conf.push_str("cluster_lease_timeout 2000\n");
    }
    if let Some((addr, mode)) = readiness {
        // Keep the scenario listener's security intact on both probe modes.
        writeln!(
            conf,
            "listener {} 127.0.0.1\nlistener_allow_anonymous true",
            addr.port()
        )
        .unwrap();
        if mode == ClusterReadiness::HttpStatus {
            conf.push_str("protocol http_api\n");
        }
    }
    conf
}

fn probe_connect(index: usize) -> Result<BytesMut, Error> {
    let mut wire = BytesMut::new();
    encode(
        &Packet::Connect(Connect {
            protocol: ProtocolVersion::V311,
            is_bridge: false,
            clean_session: true,
            // All stock scripts allow keepalive 1, even those enabling max_keepalive.
            keep_alive: 1,
            client_id: format!("mqx-difftest-readiness-{index}"),
            will: None,
            username: None,
            password: None,
        }),
        &mut wire,
    )?;
    Ok(wire)
}

fn probe_http<T>(
    addr: SocketAddr,
    path: &str,
    deadline: Instant,
    parse: impl FnOnce(u16, &str) -> Option<T>,
) -> Option<T> {
    let timeout = PROBE_TIMEOUT.min(time_left(deadline));
    if timeout.is_zero() {
        return None;
    }
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.take(64 * 1024).read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    parse(head.split_ascii_whitespace().nth(1)?.parse().ok()?, body)
}

fn probe_status(addr: SocketAddr, deadline: Instant) -> Option<serde_json::Value> {
    probe_http(addr, "/api/v1/mqx/cluster", deadline, |code, body| {
        if code == 200 {
            serde_json::from_str(body).ok()
        } else {
            None
        }
    })
}

fn probe_leader(addr: SocketAddr, deadline: Instant) -> Option<usize> {
    let status = probe_status(addr, deadline)?;
    let raft = &status["raft"];
    if raft["running"].as_bool()? {
        usize::try_from(raft["leader"].as_u64()?).ok()
    } else {
        None
    }
}

fn observed_leader(log: &str) -> Option<usize> {
    log.lines()
        .rev()
        .find(|line| line.contains("cluster raft leader"))?
        .split_whitespace()
        .find_map(|field| field.strip_prefix("leader_id=")?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_config_uses_distinct_listener_and_mesh_with_complete_membership() {
        let mesh = ["127.0.0.1:4021", "127.0.0.1:4022", "127.0.0.1:4023"]
            .map(|addr| addr.parse().unwrap());
        for (offset, mqtt) in ["127.0.0.1:4011", "127.0.0.1:4012", "127.0.0.1:4013"]
            .into_iter()
            .enumerate()
        {
            let index = offset + 1;
            assert_eq!(
                node_config(
                    mqtt.parse().unwrap(),
                    "allow_anonymous false",
                    index,
                    &mesh,
                    Some((
                        SocketAddr::from(([127, 0, 0, 1], 4030 + index as u16)),
                        ClusterReadiness::Mqtt,
                    )),
                ),
                format!(
                    concat!(
                        "listener {} 127.0.0.1\n",
                        "allow_anonymous false\n",
                        "cluster_node_id {}\n",
                        "cluster_bind {}\n",
                        "cluster_peer 1 127.0.0.1:4021\n",
                        "cluster_peer 2 127.0.0.1:4022\n",
                        "cluster_peer 3 127.0.0.1:4023\n",
                        "cluster_data_dir raft-data\n",
                        "cluster_storage_reserve 0\n",
                        "cluster_insecure_plaintext true\n",
                        "cluster_heartbeat_interval 30\n",
                        "cluster_election_timeout 150 300\n",
                        "cluster_lease_interval 200\n",
                        "cluster_lease_timeout 2000\n",
                        "listener {} 127.0.0.1\n",
                        "listener_allow_anonymous true\n",
                    ),
                    4010 + index,
                    index,
                    mesh[offset],
                    4030 + index,
                )
            );
        }
    }

    #[test]
    fn leader_observation_uses_latest_event_not_an_older_leader() {
        let log = concat!(
            "123: cluster raft leader leader_id=2\n",
            "124: connected sensor\n",
            "125: cluster raft leader leader_id=3\n",
            "126: disconnected sensor\n",
        );
        assert_eq!(observed_leader(log), Some(3));
        assert_eq!(observed_leader("127: not a leader event leader_id=2"), None);
    }
}
