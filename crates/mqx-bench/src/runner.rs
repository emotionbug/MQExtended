use std::{
    env,
    fmt::{self, Write as _},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use serde::Serialize;
use tempfile::TempDir;
use tokio::time::{Instant, sleep, timeout};

use crate::{Error, Load, LoadResult, load, mqtt::Client};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Broker {
    Mosquitto,
    Standalone,
    Cluster,
}

impl fmt::Display for Broker {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Mosquitto => "Mosquitto 2.1.4",
            Self::Standalone => "MQExtended standalone",
            Self::Cluster => "MQExtended 3-node",
        })
    }
}

#[derive(Debug, Clone)]
pub struct ComparisonOptions {
    /// Directory on the filesystem to benchmark. Cluster WALs are fresh for every row.
    pub state_dir: PathBuf,
    pub cluster_wal_direct_io: bool,
    pub broker_workers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub broker: Broker,
    pub workload: Load,
    pub result: LoadResult,
}

/// Launch fresh processes per row and run each workload against all three brokers.
pub async fn compare(
    options: &ComparisonOptions,
    workloads: &[Load],
) -> Result<Vec<Comparison>, Error> {
    if options.broker_workers == 0 || workloads.is_empty() {
        return Err(Error::Configuration(
            "comparison needs broker workers and workloads",
        ));
    }
    let mosquitto = mosquitto_binary()?;
    let mqextended = mqextended_binary()?;
    let output = timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(&mosquitto)
            .arg("-h")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| Error::Timeout("checking the Mosquitto reference version"))??;
    let banner = String::from_utf8_lossy(&output.stdout);
    let version = banner.lines().next().unwrap_or("");
    if version != "mosquitto version 2.1.4" {
        return Err(Error::MosquittoVersion {
            path: mosquitto,
            version: version.to_owned(),
        });
    }
    let mut results = Vec::with_capacity(workloads.len() * 3);
    for workload in workloads {
        for (broker, binary) in [
            (Broker::Mosquitto, &mosquitto),
            (Broker::Standalone, &mqextended),
            (Broker::Cluster, &mqextended),
        ] {
            let processes = Processes::start(broker, binary, options).await?;
            let result = load(&processes.addresses, workload)
                .await
                .map_err(|source| {
                    let mut logs = String::new();
                    for (idx, node) in processes.nodes.iter().enumerate() {
                        writeln!(logs, "Node {}:\n{}", idx + 1, node.log_tail()).unwrap();
                    }
                    Error::Workload {
                        broker,
                        pattern: workload.pattern,
                        qos: workload.qos,
                        source: Box::new(source),
                        logs,
                    }
                })?;
            results.push(Comparison {
                broker,
                workload: workload.clone(),
                result,
            });
        }
    }
    Ok(results)
}

fn binary(path: PathBuf) -> Result<PathBuf, Error> {
    let check = || {
        let resolved = path.canonicalize()?;
        if !resolved.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file"));
        }
        Ok(resolved)
    };
    check().map_err(|source| Error::Binary { path, source })
}

fn mosquitto_binary() -> Result<PathBuf, Error> {
    let dir = env::var_os("MOSQUITTO_BUILD_DIR").ok_or(Error::Configuration(
        "set MOSQUITTO_BUILD_DIR to the Mosquitto 2.1.4 build directory",
    ))?;
    binary(PathBuf::from(dir).join("src/mosquitto"))
}

fn mqextended_binary() -> Result<PathBuf, Error> {
    let path = env::var_os("MQEXTENDED_RELEASE_BIN").map_or_else(
        || {
            env::var_os("CARGO_TARGET_DIR")
                .map_or_else(
                    || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
                    PathBuf::from,
                )
                .join("release/mqextended")
        },
        PathBuf::from,
    );
    binary(path)
}

struct Node {
    child: Child,
    log: PathBuf,
}

impl Node {
    fn error(&self, broker: Broker, node: usize, reason: String) -> Error {
        Error::Startup {
            broker,
            node,
            reason,
            log: self.log_tail(),
        }
    }

    fn log_tail(&self) -> String {
        (|| {
            let mut file = File::open(&self.log)?;
            let start = file.metadata()?.len().saturating_sub(16 * 1024);
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.take(16 * 1024).read_to_end(&mut bytes)?;
            Ok::<_, io::Error>(String::from_utf8_lossy(&bytes).into_owned())
        })()
        .unwrap_or_else(|error| error.to_string())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// A fresh CA for each comparison cluster. Its signing key never leaves memory.
fn cluster_ca(dir: &Path) -> io::Result<CertifiedIssuer<'static, KeyPair>> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().map_err(io::Error::other)?;
    let ca = CertifiedIssuer::self_signed(params, key).map_err(io::Error::other)?;
    fs::write(dir.join("ca.pem"), ca.pem())?;
    Ok(ca)
}

fn node_credentials(dir: &Path, node: usize, ca: &CertifiedIssuer<'_, KeyPair>) -> io::Result<()> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("mqx-node-{node}"));
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let key = KeyPair::generate().map_err(io::Error::other)?;
    let leaf = params.signed_by(&key, ca).map_err(io::Error::other)?;
    fs::write(dir.join("cert.pem"), leaf.pem())?;
    fs::write(dir.join("key.pem"), key.serialize_pem())
}

struct Processes {
    nodes: Vec<Node>,
    addresses: Vec<SocketAddr>,
    // Declaration order drops the processes before removing their configuration and WALs.
    _state: TempDir,
}

impl Processes {
    async fn start(
        broker: Broker,
        binary: &Path,
        options: &ComparisonOptions,
    ) -> Result<Self, Error> {
        let nodes = if matches!(broker, Broker::Cluster) {
            3
        } else {
            1
        };
        let sockets = (0..if nodes == 3 { nodes * 2 } else { nodes })
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .collect::<io::Result<Vec<_>>>()?;
        let binds = sockets
            .iter()
            .map(TcpListener::local_addr)
            .collect::<io::Result<Vec<_>>>()?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("mqx-bench-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let state = builder.tempdir_in(&options.state_dir)?;
        let ca = (nodes == 3).then(|| cluster_ca(state.path())).transpose()?;
        let mut processes = Self {
            nodes: Vec::with_capacity(nodes),
            addresses: binds[..nodes].to_vec(),
            _state: state,
        };
        let workers = options.broker_workers.to_string();
        for (idx, address) in processes.addresses.iter().enumerate() {
            let node = idx + 1;
            let dir = processes._state.path().join(node.to_string());
            fs::create_dir(&dir)?;
            let mut config = format!(
                "listener {} 127.0.0.1\nallow_anonymous true\npersistence false\nconnection_messages false\nlog_type warning\nlog_type error\n",
                address.port()
            );
            if let Some(ca) = &ca {
                node_credentials(&dir, node, ca)?;
                writeln!(
                    config,
                    "cluster_node_id {node}\ncluster_bind {}\ncluster_data_dir raft\ncluster_cafile ../ca.pem\ncluster_certfile cert.pem\ncluster_keyfile key.pem",
                    binds[nodes + idx]
                )
                .unwrap();
                if options.cluster_wal_direct_io {
                    config.push_str("cluster_wal_direct_io true\n");
                }
                for (peer_idx, peer) in binds[nodes..].iter().enumerate() {
                    writeln!(config, "cluster_peer {} {peer}", peer_idx + 1).unwrap();
                }
            }
            fs::write(dir.join("mosquitto.conf"), config)?;
        }
        drop(sockets);
        for idx in 0..nodes {
            let node = idx + 1;
            let dir = processes._state.path().join(node.to_string());
            let log = dir.join("broker.log");
            let output = File::create(&log)?;
            let mut command = Command::new(binary);
            command
                .args(["-c", "mosquitto.conf"])
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(output.try_clone()?)
                .stderr(output);
            if !matches!(broker, Broker::Mosquitto) {
                command.env("TOKIO_WORKER_THREADS", &workers);
            }
            let child = command.spawn().map_err(|source| Error::Binary {
                path: binary.to_owned(),
                source,
            })?;
            processes.nodes.push(Node { child, log });
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        for (idx, (node, &address)) in processes
            .nodes
            .iter_mut()
            .zip(&processes.addresses)
            .enumerate()
        {
            loop {
                if let Some(status) = node.child.try_wait()? {
                    return Err(node.error(broker, idx + 1, status.to_string()));
                }
                let probe = timeout(
                    Duration::from_millis(500),
                    Client::connect(address, format!("bench-readiness-{idx}"), true),
                )
                .await;
                if let Ok(Ok((mut client, _, _))) = probe {
                    client.disconnect().await?;
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(node.error(
                        broker,
                        idx + 1,
                        format!("no MQTT CONNACK from {address}"),
                    ));
                }
                sleep(Duration::from_millis(25)).await;
            }
        }
        Ok(processes)
    }
}
