use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use mqx_codec::{Connect, ConnectReturnCode, Packet, ProtocolVersion, encode};
use tempfile::TempDir;

use crate::{BrokerConfig, BrokerKind, Client, Connection, Error, Reading};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
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

#[derive(Debug, Clone, Copy)]
pub struct ClusterConfig {
    pub nodes: NonZeroUsize,
    pub placement: Placement,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            nodes: NonZeroUsize::new(3).unwrap(),
            placement: Placement::RoundRobin,
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

fn prepare_config(dir: &Path, config: &BrokerConfig<'_>) -> Result<String, Error> {
    let mut conf = String::new();
    if !config.passwords.is_empty() {
        generate_password_file(dir, config.passwords)?;
        conf.push_str("password_file passwords\n");
    }
    if let Some(acl) = config.acl {
        fs::write(dir.join("acl"), acl)?;
        conf.push_str("acl_file acl\n");
    }
    conf.push_str(config.conf);
    Ok(conf)
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

struct BrokerProcess {
    child: Option<Child>,
    dir: TempDir,
    addr: SocketAddr,
    readiness: Option<(SocketAddr, BytesMut)>,
}

impl BrokerProcess {
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
            if TcpStream::connect_timeout(&self.addr, PROBE_TIMEOUT.min(remaining)).is_ok() {
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
        if self.readiness.is_none() {
            return Ok(());
        }
        loop {
            self.check_child(kind, index)?;
            let (addr, connect) = self.readiness.as_ref().expect("readiness probe configured");
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
        let _ = self.kill();
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
    let mut client = Client::connect(addr, ProtocolVersion::V311, limit(deadline))?;
    client.socket.write_all(connect)?;
    let probe_id = Connection(index);
    if !matches!(
        client.receive(probe_id, limit(deadline))?,
        Reading::Received { packet: Packet::ConnAck(ack), .. } if ack.code == ConnectReturnCode::Accepted
    ) {
        return Ok(false);
    }
    client.socket.write_all(&[0xe0, 0])?;
    Ok(matches!(
        client.receive(probe_id, limit(deadline))?,
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
        let bin = kind.binary()?;
        let (size, placement) = cluster.map_or((1, Placement::FirstNode), |cluster| {
            (cluster.nodes.get(), cluster.placement)
        });
        if let Placement::Node(index) = placement {
            check_index(index, size)?;
        }
        let dirs = (0..size)
            .map(|_| {
                let dir = tempfile::tempdir()?;
                let conf = prepare_config(dir.path(), &config)?;
                Ok((dir, conf))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let startup = STARTUP_LOCK.lock().expect("broker startup lock poisoned");
        let cluster_ports = if cluster.is_some() { size } else { 0 };
        let listeners = reserve_ports(size)?;
        let mesh = reserve_ports(cluster_ports)?;
        let mut readiness_listeners = reserve_ports(cluster_ports)?.into_iter();
        let mesh_addrs = mesh
            .iter()
            .map(TcpListener::local_addr)
            .collect::<io::Result<Vec<_>>>()?;
        let mut nodes = Vec::with_capacity(size);
        for (offset, ((dir, conf), listener)) in dirs.into_iter().zip(listeners).enumerate() {
            let addr = listener.local_addr()?;
            let readiness_listener = readiness_listeners.next();
            let readiness = readiness_listener
                .as_ref()
                .map(|listener| -> Result<_, Error> {
                    Ok((listener.local_addr()?, probe_connect(offset + 1)?))
                })
                .transpose()?;
            if cluster.is_some() {
                fs::create_dir(dir.path().join("raft-data"))?;
            }
            fs::write(
                dir.path().join("mosquitto.conf"),
                node_config(
                    addr,
                    &conf,
                    offset + 1,
                    &mesh_addrs,
                    readiness.as_ref().map(|(addr, _)| *addr),
                ),
            )?;
            nodes.push((
                BrokerProcess {
                    child: None,
                    dir,
                    addr,
                    readiness,
                },
                listener,
                readiness_listener,
            ));
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
                    observations.push(observed_leader(&node.log()));
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

fn reserve_ports(count: usize) -> io::Result<Vec<TcpListener>> {
    (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .collect()
}

fn node_config(
    listener: SocketAddr,
    common: &str,
    index: usize,
    mesh: &[SocketAddr],
    readiness: Option<SocketAddr>,
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
        "cluster_heartbeat_interval 30\n",
        "cluster_election_timeout 150 300\n",
        "cluster_lease_interval 200\n",
        "cluster_lease_timeout 1000\n",
    ));
    if let Some(addr) = readiness {
        // A successful CONNECT must commit a claim, even when the scenario listener
        // refuses anonymous clients. Keep its configuration and password/ACL files intact.
        writeln!(
            conf,
            "listener {} 127.0.0.1\nlistener_allow_anonymous true",
            addr.port()
        )
        .unwrap();
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
                    Some(SocketAddr::from(([127, 0, 0, 1], 4030 + index as u16))),
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
                        "cluster_heartbeat_interval 30\n",
                        "cluster_election_timeout 150 300\n",
                        "cluster_lease_interval 200\n",
                        "cluster_lease_timeout 1000\n",
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
