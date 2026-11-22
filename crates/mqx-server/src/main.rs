mod dynsec_config;
mod persistence;
mod process;

use std::{
    ffi::OsString,
    ops::ControlFlow,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use mqx_auth::{AclFileError, PasswordFile};
use mqx_bridge::Bridges;
use mqx_broker::{Broker, BrokerConfig, ConnectionInfo, ListenerPolicy, SecurityHandle};
use mqx_cluster::ClusterError;
use mqx_codec::QoS;
use mqx_server::{
    BrokerSignal, HttpApi, ListenerConfig, ListenerProtocol, LogConfig, LogTopics, Logging,
    SecurityConfig, Server, ServerConfig, ServerError, connect_bridge_tls, init_logging,
    parse_command_line_port, startup_log,
};

use persistence::Persistence;
use process::{PidFile, StartupError, TERMINATING};

const USAGE: &str =
    "Usage: mqextended [-c <mosquitto.conf>] [-d] [-p <port>]... [-q] [-v] [--test-config] [--version] [-h]";

#[derive(Default)]
struct Cli {
    file: Option<PathBuf>,
    ports: Vec<u16>,
    verbose: bool,
    quiet: bool,
    daemon: bool,
    test_config: bool,
}

impl Cli {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<ControlFlow<&'static str, Self>, ServerError> {
        let mut args = args.into_iter();
        let mut cli = Self::default();
        let error = |message: &str| ServerError::Arguments(format!("Error: {message}"));
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("-h" | "--help") => return Ok(ControlFlow::Break(USAGE)),
                Some("--version") => return Ok(ControlFlow::Break(concat!("mqextended ", env!("CARGO_PKG_VERSION")))),
                Some("-c" | "--config-file") => {
                    let file = args
                        .next()
                        .ok_or_else(|| error("-c argument given, but no config file specified."))?;
                    if cli.file.replace(PathBuf::from(file)).is_some() {
                        return Err(error(
                            "Only one config file can be specified; use include_dir to load additional config files.",
                        ));
                    }
                }
                Some("-p" | "--port") => {
                    let value = args
                        .next()
                        .ok_or_else(|| error("-p argument given, but no port specified."))?;
                    cli.ports.push(parse_command_line_port(
                        &value.to_string_lossy(),
                        cli.ports.len(),
                    )?);
                }
                Some("-v" | "--verbose") => cli.verbose = true,
                Some("-q" | "--quiet") => cli.quiet = true,
                Some("-d" | "--daemon") => cli.daemon = true,
                Some("--test-config") => cli.test_config = true,
                Some("--tls-keylog") => {
                    return Err(error(&format!(
                        "Unsupported Mosquitto option '{}'.",
                        arg.to_string_lossy()
                    )));
                }
                _ => {
                    return Err(error(&format!(
                        "Unknown option '{}'.",
                        arg.to_string_lossy()
                    )));
                }
            }
        }
        Ok(ControlFlow::Continue(cli))
    }

    fn override_log_types(&self, log: &mut LogConfig) {
        // Mosquitto src/conf.c: config__parse_args and config__read.
        if self.quiet {
            log.types.clear();
        } else if self.verbose {
            log.verbose();
        }
    }
}

fn main() -> ExitCode {
    let result = start();
    match result {
        Ok(code) => code,
        Err(error) => {
            let log = LogConfig::default();
            startup_log(&log, format_args!("{}", error.message));
            startup_log(&log, format_args!("{TERMINATING}"));
            error.code
        }
    }
}

fn start() -> Result<ExitCode, StartupError> {
    let cli = match Cli::parse(std::env::args_os().skip(1))
        .map_err(|error| StartupError::invalid(error.to_string()))? {
        ControlFlow::Continue(cli) => cli,
        ControlFlow::Break(text) => {
            println!("{text}");
            return Ok(ExitCode::SUCCESS);
        }
    };
    let mut config = match cli.file.as_deref() {
        Some(file) => {
            ServerConfig::load(file).map_err(|error| StartupError::invalid(error.to_string()))?
        }
        None => ServerConfig::default(),
    }
    .with_command_line_ports(&cli.ports);
    // Mosquitto src/conf.c: config__parse_args overrides the configured location.
    if let Some(location) = std::env::var_os("MOSQUITTO_PERSISTENCE_LOCATION") {
        config.persistence.location = Some(location.into());
    }
    cli.override_log_types(&mut config.log);
    for notice in &config.notices {
        startup_log(&config.log, format_args!("{notice}"));
    }
    // Mosquitto src/mosquitto.c: main tests configuration before any
    // privilege, daemon, pid-file or log-destination changes.
    if cli.test_config {
        let code = if cli.file.is_some() {
            startup_log(&config.log, format_args!("Configuration file is OK."));
            ExitCode::SUCCESS
        } else {
            startup_log(
                &config.log,
                format_args!("Please provide a configuration file to test."),
            );
            ExitCode::from(3)
        };
        startup_log(&config.log, format_args!("{TERMINATING}"));
        return Ok(code);
    }

    let run = || {
        process::drop_privileges(&config.user, &config.log)?;
        process::set_umask()?;
        if cli.daemon {
            process::daemonise(&config.log)?;
        }
        config.pid_file.as_deref().map(PidFile::write).transpose()
    };
    let _pid_file = match run() {
        Ok(pid_file) => pid_file,
        Err(error) => {
            startup_log(&config.log, format_args!("{}", error.message));
            // mosquitto__daemonise exits directly on error without cleanup.
            if error.code != ExitCode::FAILURE {
                startup_log(&config.log, format_args!("{TERMINATING}"));
            }
            return Ok(error.code);
        }
    };

    let log_error = |error: &dyn std::fmt::Display| StartupError::invalid(error.to_string());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| log_error(&error))?;
    let (logging, log_topics) = init_logging(&config.log).map_err(|error| log_error(&error))?;
    report_startup(cli.file.as_deref());
    let mut shutdown = ShutdownLog::default();
    let result = runtime.block_on(run_broker(
        &cli,
        config,
        &logging,
        log_topics,
        &mut shutdown,
    ));
    shutdown.finish(&result);
    Ok(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    })
}

#[derive(Default)]
struct ShutdownLog(bool);

impl ShutdownLog {
    // Mosquitto src/mosquitto.c: post_shutdown_cleanup logs before saving
    // final persistence state. Startup failures take the same path.
    fn finish(&mut self, result: &Result<(), ServerError>) {
        if !std::mem::replace(&mut self.0, true) {
            if let Err(error) = result {
                tracing::error!("{error}");
            }
            tracing::info!("{TERMINATING}");
        }
    }
}

fn report_startup(file: Option<&Path>) {
    // Mosquitto src/mosquitto.c: main and report_features.
    tracing::info!("mosquitto version 2.1.4 starting");
    if let Some(file) = file {
        tracing::info!("Config loaded from {}.", file.display());
    } else {
        tracing::info!("Using default config.");
    }
    tracing::info!("Bridge support available.");
    tracing::info!("Persistence support available.");
    tracing::info!("TLS support available.");
    tracing::info!("TLS-PSK support NOT available.");
    tracing::info!("Websockets support available.");
    if std::env::var_os("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS").is_some() {
        tracing::info!(target: "mqx::notice", "MOSQUITTO_UNSAFE_ALLOW_SYMLINKS is set, loading of sensitive files through symbolic links is allowed.");
    }
}

fn add_local_http(config: &mut ServerConfig) {
    if config.local_only {
        // Mosquitto src/listeners.c: listeners__start_local_only adds
        // the HTTP endpoint after default MQTT listeners, including with -p.
        config.listeners.push(ListenerConfig {
            port: 9883,
            host: Some("127.0.0.1".into()),
            protocol: ListenerProtocol::HttpApi,
            security: SecurityConfig {
                allow_anonymous: config.security.allow_anonymous,
                ..SecurityConfig::default()
            },
            dynamic_security: config
                .listeners
                .first()
                .and_then(|listener| listener.dynamic_security.clone()),
            ..ListenerConfig::default()
        });
    }
}

fn reload_config(path: &Path, cli: &Cli, bound: &ServerConfig) -> Result<ServerConfig, ServerError> {
    let mut fresh = ServerConfig::load(path)?.with_command_line_ports(&cli.ports);
    add_local_http(&mut fresh);
    if let Some(location) = std::env::var_os("MOSQUITTO_PERSISTENCE_LOCATION") {
        fresh.persistence.location = Some(location.into());
    }
    let changed_layout = || ServerError::Arguments(
        "Changing listeners or per_listener_settings requires a restart.".into()
    );
    if bound.per_listener_settings != fresh.per_listener_settings || bound.listeners.len() != fresh.listeners.len() {
        return Err(changed_layout());
    }
    // conf.c: config__read_file_core matches a reloaded listener by endpoint,
    // not file order. Keep listener indices (including replicated ACL ids) stable.
    for (i, old) in bound.listeners.iter().enumerate() {
        let offset = fresh.listeners[i..].iter().position(|l|
            (l.port, &l.host, &l.unix_socket_path, l.protocol)
                == (old.port, &old.host, &old.unix_socket_path, old.protocol)
        ).ok_or_else(changed_layout)?;
        fresh.listeners.swap(i, i + offset);
    }
    Ok(fresh)
}

async fn run_broker(
    cli: &Cli,
    mut config: ServerConfig,
    logging: &Logging,
    log_topics: LogTopics,
    shutdown: &mut ShutdownLog,
) -> Result<(), ServerError> {
    add_local_http(&mut config);
    let live_log = std::cell::RefCell::new(config.log.clone());
    let security = Arc::new(security_handles(&config)?);
    let policies: Arc<Vec<Arc<ListenerPolicy>>> = Arc::new(
        config
            .listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| {
                Arc::new(listener_policy(
                    &config,
                    listener,
                    security.for_listener(index),
                ))
            })
            .collect(),
    );
    let cluster = config.cluster.take();
    let cluster_identity = cluster
        .as_ref()
        .map(|cluster| (cluster.node_id, cluster.state_format));
    let joining = cluster.as_ref().is_some_and(|cluster| cluster.join);
    let persistence = cluster
        .is_none()
        .then(|| Arc::new(Persistence::new(config.persistence.clone())));
    let (broker, membership, server) = if let Some(mut cluster) = cluster {
        let server = Server::bind(&config).await?;
        let limits = &config.limits;
        let packet_limit = if limits.max_packet_size == 0 {
            0
        } else {
            limits.max_packet_size.max(limits.message_size_limit)
        };
        cluster
            .set_packet_limit(packet_limit)
            .map_err(mqx_broker::BrokerError::from)
            .map_err(ServerError::Cluster)?;
        let request_timeout = cluster.request_timeout;
        // One deterministic bootstrap candidate, even if several empty
        // voters race to initialize the same Raft membership.
        let bootstrap_node = !joining
            && cluster
                .peers
                .first_key_value()
                .is_some_and(|(&id, _)| id == cluster.node_id);
        let migration_node = bootstrap_node && cluster.membership_generation == 0;
        let broker = Broker::clustered(broker_config(&config), cluster)
            .await
            .map_err(ServerError::Cluster)?;
        let membership = broker
            .cluster_membership()
            .expect("the clustered broker owns membership control");
        if !joining {
            let ready = async {
                tokio::time::timeout(request_timeout, membership.wait_serving())
                    .await
                    .unwrap_or(Err(ClusterError::Deadline))
                    .map_err(mqx_broker::BrokerError::from)
                    .map_err(ServerError::Cluster)?;
                security.register(&broker).await?;
                dynsec_config::register(&broker, config.dynamic_security.as_ref(), bootstrap_node)
                    .await?;
                if migration_node {
                    persistence::migrate_cluster(&broker, &config).await?;
                }
                Ok(())
            };
            if let Err(error) = ready.await {
                if let Err(error) = broker.shutdown_cluster().await {
                    tracing::error!("Cluster shutdown failed: {error}");
                }
                return Err(error);
            }
        }
        (broker, Some(membership), server)
    } else {
        let broker = Broker::new(broker_config(&config));
        security.register(&broker).await?;
        dynsec_config::register(&broker, config.dynamic_security.as_ref(), true).await?;
        // mosquitto.c: plugin initializers run before the listener opens.
        let server = Server::bind(&config).await?;
        if let Some(persistence) = &persistence {
            persistence.restore(&broker, &config).await?;
        }
        (broker, None, server)
    };
    let (stop_autosave, stop) = tokio::sync::watch::channel(false);
    let autosave = persistence.as_ref().map(|persistence| {
        let (persistence, broker) = (persistence.clone(), broker.clone());
        tokio::spawn(async move { persistence.autosave(&broker, stop).await })
    });
    let registered = Arc::new(AtomicBool::new(!joining));
    let membership_watch = membership.as_ref().map(|membership| {
        let membership = membership.clone();
        let broker = broker.clone();
        let security = security.clone();
        let dynamic_security = config.dynamic_security.clone();
        let registered = registered.clone();
        tokio::spawn(async move {
            if joining {
                while membership.wait_serving().await.is_ok() {
                    let result = async {
                        security.register(&broker).await?;
                        dynsec_config::register(&broker, dynamic_security.as_ref(), false).await
                    }
                    .await;
                    match result {
                        Ok(()) => {
                            registered.store(true, Ordering::Release);
                            break;
                        }
                        Err(error) => {
                            tracing::warn!("Joining node could not register security: {error}")
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            membership.wait_removed().await;
            // Leave the HTTP diagnostics available, but close existing MQTT clients.
            broker.shutdown();
        })
    });
    let serving_membership = membership.clone();
    let serving_registered = registered.clone();
    let ready = Arc::new(move || {
        serving_registered.load(Ordering::Acquire)
            && serving_membership.as_ref().is_none_or(|m| m.lease_valid_until().is_some())
    });
    // retain.c: retain__queue rechecks the source with an ordinary context
    // and no listener, even if the live publication came from a bridge.
    let bridge_security = if config.per_listener_settings {
        SecurityHandle::with_id(u64::MAX, None, Some(b"topic deny #\n".to_vec()))
            .expect("valid ACL for a synthetic source without a listener")
    } else {
        security.for_listener(0)
    };
    let mut bridges = Bridges::new(
        broker.clone(),
        bridge_security,
        config.set_tcp_nodelay,
        connect_bridge_tls,
    );
    bridges.start(std::mem::take(&mut config.bridges));
    let bridges = std::cell::RefCell::new(bridges);
    broker.start_sys_tree(config.sys_interval);
    let log_topics = tokio::spawn(log_topics.serve(broker.clone()));
    let serving = broker.clone();
    let http = Arc::new(HttpApi::new(&config, &server));
    let http_inventory = http.clone();
    let result = server
        .with_broker_observation(broker.clone())
        .run_with_signals(
            move |connection| {
                let broker = serving.clone();
                let policies = policies.clone();
                let http = http.clone();
                let ready = ready.clone();
                async move {
                    if connection.listener.protocol == ListenerProtocol::HttpApi {
                        let policy = &policies[connection.listener_index];
                        if let Err(error) = http.serve(connection, &broker, &policy.security, &*ready).await
                        {
                            tracing::debug!("HTTP connection ended: {error}");
                        }
                        return;
                    }
                    if !ready() {
                        return;
                    }
                    let info = ConnectionInfo {
                        peer_addr: connection.peer_addr,
                        listener: policies[connection.listener_index].clone(),
                        cert_identity: connection.cert_identity.into(),
                    };
                    if let Err(error) = broker
                        .serve_accepted(connection.stream, info, connection.accepted_at)
                        .await
                        && broker.connection_messages()
                    {
                        tracing::debug!(
                            "Connection from {:?} ended: {error}",
                            connection.peer_addr
                        );
                    }
                }
            },
            || async {
                if let Some(path) = &cli.file {
                    match reload_config(path, cli, &config) {
                        Ok(mut fresh) => {
                            // signals.c: reload configuration before opening credential files.
                            security.reload(&fresh)?;
                            if membership.as_ref().is_none_or(|membership| membership.is_serving())
                                && registered.load(Ordering::Acquire)
                            {
                                security.register(&broker).await?;
                            }
                            http_inventory.reload_access(&config, &fresh);
                            cli.override_log_types(&mut fresh.log);
                            broker.set_connection_messages(fresh.log.connection_messages);
                            logging.reload(&fresh.log);
                            live_log.replace(fresh.log);
                            if let Some(persistence) = &persistence {
                                persistence.reload(fresh.persistence);
                            }
                            broker.start_sys_tree(fresh.sys_interval);
                            bridges.borrow_mut().reload(fresh.bridges);
                            if let Some((membership, (node_id, format))) =
                                membership.as_ref().zip(cluster_identity)
                            {
                                match fresh.cluster {
                                    Some(cluster) if cluster.node_id == node_id && cluster.state_format == format => {
                                        if cluster.membership_generation != 0
                                            && let Err(error) = membership.configure(cluster.membership_generation, cluster.peers)
                                        {
                                            tracing::warn!("Cluster membership reload refused: {error}");
                                        }
                                    }
                                    _ => tracing::warn!("Changing cluster identity or state format requires a restart"),
                                }
                            }
                        }
                        Err(error) => {
                            tracing::warn!("Unable to reload configuration: {error}");
                            logging.reload(&live_log.borrow());
                        }
                    }
                } else {
                    logging.reload(&live_log.borrow());
                }
                Ok::<_, ServerError>(())
            },
            || {
                // Mosquitto src/mosquitto.c: main calls signal__setup
                // before announcing readiness to logs and systemd.
                tracing::info!("mosquitto version 2.1.4 running");
                process::notify_ready();
            },
            async |signal| match signal {
                // Mosquitto src/signals.c: persist__backup is a no-op when
                // standalone persistence is disabled.
                BrokerSignal::Backup => {
                    if let Some(persistence) = &persistence {
                        let _ = persistence.backup(&broker, false).await;
                    }
                }
                BrokerSignal::Diagnostics => {
                    use std::io::Write as _;
                    let _ = std::io::stdout().lock().write_all(broker.subscription_tree().as_bytes());
                }
                BrokerSignal::Rotate => logging.reload(&live_log.borrow()),
                BrokerSignal::Reload => unreachable!("handled by the listener"),
            },
            || broker.shutdown(),
        )
        .await;
    shutdown.finish(&result);
    stop_autosave.send_replace(true);
    if let Some(task) = autosave {
        let _ = task.await;
    }
    broker.shutdown();
    bridges.into_inner().shutdown().await;
    let result = if let Some(persistence) = &persistence {
        result.and(persistence.backup(&broker, true).await.map(|_| ()))
    } else {
        result
    };
    log_topics.abort();
    if let Some(task) = membership_watch {
        task.abort();
    }
    if membership.is_some() {
        return result.and(
            broker
                .shutdown_cluster()
                .await
                .map_err(ServerError::Cluster),
        );
    }
    result
}

fn broker_config(config: &ServerConfig) -> BrokerConfig {
    let limits = &config.limits;
    BrokerConfig {
        allow_anonymous: config.security.allow_anonymous.unwrap_or(false),
        allow_zero_length_clientid: config.security.allow_zero_length_clientid,
        auto_id_prefix: config
            .security
            .auto_id_prefix
            .clone()
            .unwrap_or_else(|| BrokerConfig::default().auto_id_prefix),
        clientid_prefixes: limits.clientid_prefixes.clone(),
        max_keepalive: limits.max_keepalive,
        max_inflight_messages: usize::from(limits.max_inflight_messages),
        max_inflight_bytes: limits.max_inflight_bytes,
        max_queued_messages: limits.max_queued_messages,
        max_queued_bytes: limits.max_queued_bytes,
        queue_qos0_messages: limits.queue_qos0_messages,
        message_size_limit: limits.message_size_limit,
        max_packet_size: limits.max_packet_size,
        retain_expiry_interval: limits.retain_expiry_interval,
        persistent_client_expiration: limits.persistent_client_expiration,
        retain_available: limits.retain_available,
        upgrade_outgoing_qos: limits.upgrade_outgoing_qos,
        allow_duplicate_messages: limits.allow_duplicate_messages,
        check_retain_source: limits.check_retain_source,
        // The listener layer enforces connection caps at accept time, before TLS, as
        // Mosquitto's net__socket_accept does; the broker must not count them again.
        global_max_connections: 0,
        global_max_clients: limits.global_max_clients,
        connection_messages: config.log.connection_messages,
    }
}

fn listener_policy(
    config: &ServerConfig,
    listener: &ListenerConfig,
    security: SecurityHandle,
) -> ListenerPolicy {
    let source = config.security_for(listener);
    let security = match &listener.dynamic_security {
        Some(dynamic) => security.with_dynamic_security(dynamic.before_file),
        None => security,
    };
    ListenerPolicy {
        allow_anonymous: Some(config.allow_anonymous_for(listener)),
        allow_zero_length_clientid: Some(source.allow_zero_length_clientid),
        auto_id_prefix: listener.security.auto_id_prefix.clone(),
        max_qos: match listener.max_qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            _ => QoS::ExactlyOnce,
        },
        max_connections: 0,
        use_username_as_clientid: listener.use_username_as_clientid,
        disable_protocol_v3: listener.disable_protocol_v3,
        disable_protocol_v4: listener.disable_protocol_v4,
        disable_protocol_v5: listener.disable_protocol_v5,
        max_topic_alias: listener.max_topic_alias,
        max_topic_alias_broker: listener.max_topic_alias_broker,
        mount_point: listener.mount_point.clone(),
        security,
    }
}

/// One handle per listener with `per_listener_settings true`, otherwise one handle shared
/// by every listener.
struct SecurityHandles {
    handles: Vec<SecurityHandle>,
    per_listener: bool,
}

impl SecurityHandles {
    fn for_listener(&self, index: usize) -> SecurityHandle {
        let (group, slot) = if self.per_listener { (index, 0) } else { (0, index) };
        self.handles[group].clone().for_listener(slot)
    }

    fn reload(&self, config: &ServerConfig) -> Result<(), ServerError> {
        let fresh = load_credentials(config)?;
        for (index, (handle, credentials)) in self.handles.iter().zip(fresh).enumerate() {
            let anonymous = if self.per_listener {
                Box::from([config.allow_anonymous_for(&config.listeners[index])]) as Box<[bool]>
            } else {
                config.listeners.iter().map(|l| config.allow_anonymous_for(l)).collect()
            };
            credentials.install(|password, acl| handle.replace_text(password, acl, anonymous))?;
        }
        Ok(())
    }

    async fn register(&self, broker: &Broker) -> Result<(), ServerError> {
        for handle in &self.handles {
            broker
                .register_security(handle)
                .await
                .map_err(ServerError::Cluster)?;
        }
        Ok(())
    }
}

fn security_handles(config: &ServerConfig) -> Result<SecurityHandles, ServerError> {
    Ok(SecurityHandles {
        handles: load_credentials(config)?
            .into_iter()
            .enumerate()
            .map(|(index, credentials)| {
                credentials.install(|password, acl| {
                    // Listeners use the same security IDs on every cluster node. Zero is reserved.
                    SecurityHandle::with_id(index as u64 + 1, password, acl)
                })
            })
            .collect::<Result<_, _>>()?,
        per_listener: config.per_listener_settings,
    })
}

struct Credentials<'a> {
    password: Option<PasswordFile>,
    acl: Option<(&'a Path, Vec<u8>)>,
}

impl Credentials<'_> {
    fn install<R>(
        self,
        import: impl FnOnce(Option<PasswordFile>, Option<Vec<u8>>) -> Result<R, AclFileError>,
    ) -> Result<R, ServerError> {
        let (path, acl) = match self.acl {
            Some((path, text)) => (Some(path), Some(text)),
            None => (None, None),
        };
        import(self.password, acl).map_err(|source| ServerError::AclFile {
            path: path
                .expect("ACL parsing failed only when an ACL was supplied")
                .into(),
            source,
        })
    }
}

fn load_credentials(config: &ServerConfig) -> Result<Vec<Credentials<'_>>, ServerError> {
    fn load(security: &SecurityConfig) -> Result<Credentials<'_>, ServerError> {
        let password = security
            .password_file
            .as_ref()
            .map(|path| {
                PasswordFile::load(path).map_err(|source| ServerError::PasswordFile {
                    path: path.clone(),
                    source,
                })
            })
            .transpose()?;
        let acl = security
            .acl_file
            .as_deref()
            .map(|path| {
                std::fs::read(path)
                    .map(|data| (path, data))
                    .map_err(|source| ServerError::AclFile {
                        path: path.into(),
                        source: AclFileError::Io {
                            path: path.into(),
                            source,
                        },
                    })
            })
            .transpose()?;
        Ok(Credentials { password, acl })
    }
    if config.per_listener_settings {
        config
            .listeners
            .iter()
            .map(|listener| load(config.security_for(listener)))
            .collect()
    } else {
        Ok(vec![load(&config.security)?])
    }
}
