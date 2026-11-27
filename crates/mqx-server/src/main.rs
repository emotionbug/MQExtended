mod dynsec_config;
mod file_security;
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

use mqx_auth::external::ExternalSecurity;
use mqx_bridge::Bridges;
use mqx_broker::{
    Broker, BrokerConfig, ConnectionInfo, ListenerPolicy, ReloadableLimits, SecurityHandle,
};
use mqx_cluster::{ClusterError, SurvivorReason};
use mqx_codec::QoS;
use mqx_server::{
    BrokerSignal, CertificateReloader, HttpApi, ListenerConfig, ListenerProtocol, LogConfig,
    LogTopics, Logging, SecurityConfig, Server, ServerConfig, ServerError, connect_bridge_tls,
    init_logging, parse_command_line_port, run_kubernetes_rollout, startup_log,
};

use file_security::{PolicyWatch, SecurityHandles};
use persistence::Persistence;
use process::{PidFile, StartupError, TERMINATING};

const USAGE: &str = "Usage: mqextended [-c <mosquitto.conf>] [-d] [-p <port>]... [-q] [-v] [--test-config] [--version] [-h]";

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
    fn parse(
        args: impl IntoIterator<Item = OsString>,
    ) -> Result<ControlFlow<&'static str, Self>, ServerError> {
        let mut args = args.into_iter();
        let mut cli = Self::default();
        let error = |message: &str| ServerError::Arguments(format!("Error: {message}"));
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("-h" | "--help") => return Ok(ControlFlow::Break(USAGE)),
                Some("--version") => {
                    return Ok(ControlFlow::Break(concat!(
                        "mqextended ",
                        env!("CARGO_PKG_VERSION")
                    )));
                }
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
        .map_err(|error| StartupError::invalid(error.to_string()))?
    {
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
        if cli.daemon && (!config.auto_recover || !already_daemonised()) {
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
    if matches!(
        &result,
        Err(ServerError::Cluster(mqx_broker::BrokerError::Cluster(
            ClusterError::Restart
        )))
    ) {
        drop(runtime);
        tracing::error!(error = %reexec(), "Unable to re-exec MQExtended after cluster recovery");
        shutdown.finish(&result);
        return Ok(ExitCode::FAILURE);
    }
    shutdown.finish(&result);
    Ok(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(ServerError::Listen(_) | ServerError::PluginAbort) => ExitCode::FAILURE,
        Err(ServerError::File { operation, .. })
            if [persistence::RESTORE_FAILED, persistence::IMPORT_FAILED].contains(&operation) =>
        {
            ExitCode::FAILURE
        }
        Err(_) => ExitCode::from(3),
    })
}

#[cfg(unix)]
fn already_daemonised() -> bool {
    use nix::unistd::{getpid, getsid};
    getsid(None).is_ok_and(|id| id == getpid())
}

#[cfg(not(unix))]
fn already_daemonised() -> bool {
    false
}

fn reexec() -> std::io::Error {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let program = match std::env::current_exe() {
            Ok(program) => program,
            Err(error) => return error,
        };
        let mut argv = std::env::args_os();
        let mut command = std::process::Command::new(program);
        if let Some(arg0) = argv.next() {
            command.arg0(arg0);
        }
        command.args(argv).exec()
    }
    #[cfg(not(unix))]
    std::io::Error::new(std::io::ErrorKind::Unsupported, "re-exec requires Unix")
}

#[derive(Default)]
struct ShutdownLog(bool);

impl ShutdownLog {
    // Mosquitto src/mosquitto.c: post_shutdown_cleanup logs before saving
    // final persistence state. Startup failures take the same path.
    fn finish(&mut self, result: &Result<(), ServerError>) {
        if !std::mem::replace(&mut self.0, true) {
            match result {
                // auth-plug log.c: _fatal calls exit(1) after its own lines.
                Err(ServerError::PluginAbort) => return,
                // A recovery switch re-execs; it is not a failure.
                Err(ServerError::Cluster(mqx_broker::BrokerError::Cluster(
                    ClusterError::Restart,
                ))) => {}
                Err(error) => tracing::error!("{error}"),
                Ok(()) => {}
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
            // Only a global plugin can apply without configured listeners.
            external_plugin: config
                .listeners
                .first()
                .and_then(|listener| listener.external_plugin),
            sparkplug_aware: config.sparkplug_aware,
            ..ListenerConfig::default()
        });
    }
}

/// Mosquitto src/plugin_init.c: plugin__load_all initializes plugins before
/// any listener opens; plugin_v4.c: plugin__load_v4 logs the callbacks it
/// found and registers them.
async fn load_external_plugins(
    config: &ServerConfig,
) -> Result<Vec<Arc<dyn ExternalSecurity>>, ServerError> {
    let mut loaded = Vec::with_capacity(config.external_plugins.len());
    for plugin in &config.external_plugins {
        tracing::info!("Loading plugin: {}", plugin.path);
        mqx_extauth::announce(plugin.library);
        tracing::info!(" ├── Username/password checking enabled.");
        tracing::info!(" ├── TLS-PSK checking enabled.");
        tracing::info!(" └── Extended authentication not enabled.");
        let security = mqx_extauth::load(
            plugin.library,
            plugin.options.clone(),
            plugin.deny_special_chars,
        )
        .await
        .map_err(|_| ServerError::PluginAbort)?;
        for event in ["reload", "basic-auth", "acl-check", "psk-key"] {
            tracing::info!("Plugin has registered to receive '{event}' events.");
        }
        loaded.push(security);
    }
    Ok(loaded)
}

/// Broker-wide options Mosquitto 2.1.4 rereads on SIGHUP but never applies:
/// conf.c: config__read parses them into a temporary configuration and
/// config__copy leaves them out. Both brokers keep the startup values.
fn startup_only_changes(running: &ServerConfig, fresh: &ServerConfig) -> Vec<&'static str> {
    let (old, new) = (&running.limits, &fresh.limits);
    [
        (
            "global_max_clients",
            old.global_max_clients != new.global_max_clients,
        ),
        (
            "global_max_connections",
            old.global_max_connections != new.global_max_connections,
        ),
        (
            "max_inflight_messages",
            old.max_inflight_messages != new.max_inflight_messages,
        ),
        (
            "max_inflight_bytes",
            old.max_inflight_bytes != new.max_inflight_bytes,
        ),
        (
            "max_queued_messages",
            old.max_queued_messages != new.max_queued_messages,
        ),
        (
            "max_queued_bytes",
            old.max_queued_bytes != new.max_queued_bytes,
        ),
        ("max_keepalive", old.max_keepalive != new.max_keepalive),
        (
            "max_packet_size",
            old.max_packet_size != new.max_packet_size,
        ),
        (
            "check_retain_source",
            old.check_retain_source != new.check_retain_source,
        ),
        (
            "retain_expiry_interval",
            old.retain_expiry_interval != new.retain_expiry_interval,
        ),
        (
            "retain_available",
            old.retain_available != new.retain_available,
        ),
        (
            "set_tcp_nodelay",
            running.set_tcp_nodelay != fresh.set_tcp_nodelay,
        ),
        ("auto_recover", running.auto_recover != fresh.auto_recover),
        (
            "auto_recover_timeout",
            running.auto_recover_timeout != fresh.auto_recover_timeout,
        ),
    ]
    .into_iter()
    .filter_map(|(name, changed)| changed.then_some(name))
    .collect()
}

/// In a cluster, SIGHUP commits the reloadable limits for every node and a
/// restart keeps them. Tell the operator when this node's file disagrees.
fn warn_on_committed_limits(broker: &Broker, file: &ReloadableLimits) {
    let running = broker.reloadable_limits();
    let differences: Vec<_> = [
        (
            "message_size_limit",
            running.message_size_limit != file.message_size_limit,
        ),
        (
            "persistent_client_expiration",
            running.persistent_client_expiration != file.persistent_client_expiration,
        ),
        (
            "retain_max_age",
            running.retain_max_age != file.retain_max_age,
        ),
        (
            "queue_qos0_messages",
            running.queue_qos0_messages != file.queue_qos0_messages,
        ),
        (
            "upgrade_outgoing_qos",
            running.upgrade_outgoing_qos != file.upgrade_outgoing_qos,
        ),
        (
            "allow_duplicate_messages",
            running.allow_duplicate_messages != file.allow_duplicate_messages,
        ),
        (
            "clientid_prefixes",
            running.clientid_prefixes != file.clientid_prefixes,
        ),
    ]
    .into_iter()
    .filter_map(|(name, differs)| differs.then_some(name))
    .collect();
    if !differences.is_empty() {
        tracing::warn!(
            "The cluster's committed {} differ from this node's configuration; send SIGHUP to apply the file's values.",
            differences.join(", ")
        );
    }
}

fn reload_config(
    path: &Path,
    cli: &Cli,
    bound: &ServerConfig,
) -> Result<ServerConfig, ServerError> {
    let mut fresh = ServerConfig::load_for_reload(path)?.with_command_line_ports(&cli.ports);
    add_local_http(&mut fresh);
    if let Some(location) = std::env::var_os("MOSQUITTO_PERSISTENCE_LOCATION") {
        fresh.persistence.location = Some(location.into());
    }
    let changed_layout = || {
        ServerError::Arguments(
            "Changing listeners or per_listener_settings requires a restart.".into(),
        )
    };
    if bound.per_listener_settings != fresh.per_listener_settings
        || bound.listeners.len() != fresh.listeners.len()
    {
        return Err(changed_layout());
    }
    // conf.c: config__read_file_core matches a reloaded listener by endpoint,
    // not file order. Keep listener indices (including replicated ACL ids) stable.
    for (i, old) in bound.listeners.iter().enumerate() {
        let offset = fresh.listeners[i..]
            .iter()
            .position(|l| {
                (l.port, &l.host, &l.unix_socket_path, l.protocol)
                    == (old.port, &old.host, &old.unix_socket_path, old.protocol)
            })
            .ok_or_else(changed_layout)?;
        fresh.listeners.swap(i, i + offset);
    }
    fresh.retain_startup_plugins(bound)?;
    Ok(fresh)
}

async fn run_broker(
    cli: &Cli,
    config: ServerConfig,
    logging: &Logging,
    log_topics: LogTopics,
    shutdown: &mut ShutdownLog,
) -> Result<(), ServerError> {
    let external = load_external_plugins(&config).await?;
    let result = serve_broker(config, cli, logging, log_topics, shutdown, &external).await;
    // Mosquitto plugin_v4.c: plugin__cleanup_v4 runs each plugin's cleanup
    // only after serving has stopped.
    for plugin in external {
        plugin.halt().await;
    }
    result
}

async fn serve_broker(
    mut config: ServerConfig,
    cli: &Cli,
    logging: &Logging,
    log_topics: LogTopics,
    shutdown: &mut ShutdownLog,
    external: &[Arc<dyn ExternalSecurity>],
) -> Result<(), ServerError> {
    add_local_http(&mut config);
    let live_config = std::cell::RefCell::new(None);
    let has_plugin_files = config.security.file_plugins.paths() != (None, None)
        || config
            .listeners
            .iter()
            .any(|listener| listener.security.file_plugins.paths() != (None, None));
    let policy_watch = std::cell::RefCell::new(PolicyWatch::new(&config));
    let security = Arc::new(SecurityHandles::new(&config, external)?);
    let listener_policies = |config: &ServerConfig| -> Vec<Arc<ListenerPolicy>> {
        config
            .listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| {
                Arc::new(listener_policy(
                    config,
                    listener,
                    security.for_listener(index),
                ))
            })
            .collect()
    };
    // Mosquitto src/conf.c: config__read_file_core rewrites each listener in
    // place on reload, so new connections see the reread listener settings.
    let policies = Arc::new(std::sync::RwLock::new(listener_policies(&config)));
    let policy = |policies: &std::sync::RwLock<Vec<Arc<ListenerPolicy>>>, index: usize| {
        policies.read().unwrap_or_else(|e| e.into_inner())[index].clone()
    };
    let cluster = config.cluster.take();
    let cluster_identity = cluster
        .as_ref()
        .map(|cluster| (cluster.node_id, cluster.state_format));
    let joining = cluster.as_ref().is_some_and(|cluster| cluster.join);
    let deferred = joining || cluster.as_ref().is_some_and(|cluster| cluster.auto_recover);
    let bootstrap_node = !joining
        && cluster.as_ref().is_some_and(|cluster| {
            cluster
                .peers
                .first_key_value()
                .is_some_and(|(&id, _)| id == cluster.node_id)
        });
    let migration_node = bootstrap_node
        && cluster
            .as_ref()
            .is_some_and(|cluster| cluster.membership_generation == 0);
    let persistence = cluster
        .is_none()
        .then(|| Arc::new(Persistence::new(config.persistence.clone())));
    let (broker, membership, server) = if let Some(mut cluster) = cluster {
        let server = Server::bind(&config)
            .await
            .map_err(|error| ServerError::Listen(Box::new(error)))?;
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
        let broker =
            Broker::clustered_with_security(broker_config(&config), cluster, &security.handles())
                .await
                .map_err(ServerError::Cluster)?;
        let membership = broker
            .cluster_membership()
            .expect("the clustered broker owns membership control");
        if !deferred {
            let ready = async {
                // A cold peer can start later than an individual Raft request
                // deadline. Stay fenced and let the live election converge.
                membership
                    .wait_serving()
                    .await
                    .map_err(mqx_broker::BrokerError::from)
                    .map_err(ServerError::Cluster)?;
                security.register(&broker).await?;
                dynsec_config::register(&broker, config.dynamic_security.as_ref(), bootstrap_node)
                    .await?;
                if migration_node {
                    persistence::migrate_cluster(&broker, &config).await?;
                }
                warn_on_committed_limits(&broker, &broker_config(&config).reloadable_limits());
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
        let server = Server::bind(&config)
            .await
            .map_err(|error| ServerError::Listen(Box::new(error)))?;
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
    let registered = Arc::new(AtomicBool::new(!deferred));
    let membership_watch = membership.as_ref().map(|membership| {
        let membership = membership.clone();
        let broker = broker.clone();
        let security = security.clone();
        let dynamic_security = config.dynamic_security.clone();
        let file_limits = broker_config(&config).reloadable_limits();
        let registered = registered.clone();
        let migration =
            (deferred && migration_node && config.persistence.enabled).then(|| config.clone());
        tokio::spawn(async move {
            if deferred {
                while membership.wait_serving().await.is_ok() {
                    let result = async {
                        security.register(&broker).await?;
                        let event = broker
                            .raft_metrics()
                            .and_then(|metrics| metrics.last_survivor_event);
                        let bootstrap = match event {
                            None => bootstrap_node,
                            Some(event) => event.reason == SurvivorReason::PeerUnreachable,
                        };
                        dynsec_config::register(&broker, dynamic_security.as_ref(), bootstrap)
                            .await?;
                        if event.is_none()
                            && let Some(config) = &migration
                        {
                            persistence::migrate_cluster(&broker, config).await?;
                        }
                        Ok::<_, ServerError>(())
                    }
                    .await;
                    match result {
                        Ok(()) => {
                            registered.store(true, Ordering::Release);
                            warn_on_committed_limits(&broker, &file_limits);
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
            && serving_membership
                .as_ref()
                .is_none_or(|m| m.lease_valid_until().is_some())
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
    if config.enable_control_api {
        // conf.c: config__copy does not copy enable_control_api on SIGHUP.
        broker.register_control_api(server.control_inventory(&config));
    }
    let log_topics = tokio::spawn(log_topics.serve(broker.clone()));
    let rollout = match (
        config.cluster_kubernetes_rollout.take(),
        &membership,
        cluster_identity,
    ) {
        (Some(sets), Some(membership), Some((node_id, _))) => Some(tokio::spawn(
            run_kubernetes_rollout(node_id, sets, membership.clone()),
        )),
        _ => None,
    };
    let serving = broker.clone();
    let http = Arc::new(HttpApi::new(&config, &server));
    let http_inventory = http.clone();
    let reload_policies = policies.clone();
    let reload_security = |fresh: &ServerConfig| {
        security.reload(fresh, || {
            *reload_policies.write().unwrap_or_else(|e| e.into_inner()) = listener_policies(fresh);
            // Updating a credential handle wakes existing connections;
            // publish the validated inventory before the first wakeup.
            http_inventory.reload_access(&config, fresh);
        })
    };
    let register_security = async || {
        if membership
            .as_ref()
            .is_none_or(|membership| membership.is_serving())
            && registered.load(Ordering::Acquire)
        {
            security.register(&broker).await?;
        }
        Ok::<_, ServerError>(())
    };
    let serve = server
        .with_broker_observation(broker.clone())
        .with_watchdog(process::watchdog())
        .run_with_signals(
            move |connection| {
                let broker = serving.clone();
                let policies = policies.clone();
                let http = http.clone();
                let ready = ready.clone();
                async move {
                    if connection.listener.protocol == ListenerProtocol::HttpApi {
                        let policy = policy(&policies, connection.listener_index);
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
                        listener: policy(&policies, connection.listener_index),
                        cert_identity: connection.cert_identity.into(),
                    };
                    if let Err(error) = broker
                        .serve_accepted_with(
                            connection.stream,
                            info,
                            connection.accepted_at,
                            mqx_broker::PeerTransport {
                                address: connection.peer_text.as_deref(),
                                tls: connection
                                    .tls
                                    .as_ref()
                                    .map(|(version, cipher)| (version.as_str(), cipher.as_str())),
                            },
                        )
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
            async |certificates: &mut CertificateReloader| {
                if let Some(path) = &cli.file {
                    match reload_config(path, cli, &config) {
                        Ok(mut fresh) => {
                            let reloaded_limits = broker_config(&fresh).reloadable_limits();
                            let unapplied = startup_only_changes(&config, &fresh);
                            if !unapplied.is_empty() {
                                tracing::warn!(
                                    "Changing {} requires a restart; the running values are kept.",
                                    unapplied.join(", ")
                                );
                            }
                            // signals.c: reload configuration before opening credential files.
                            certificates.refresh(Some(&fresh));
                            let watch = PolicyWatch::new(&fresh);
                            reload_security(&fresh)?;
                            policy_watch.replace(watch);
                            register_security().await?;
                            cli.override_log_types(&mut fresh.log);
                            broker.set_connection_messages(fresh.log.connection_messages);
                            logging.reload(&fresh.log);
                            if let Some(persistence) = &persistence {
                                persistence.reload(std::mem::take(&mut fresh.persistence));
                            }
                            broker.start_sys_tree(fresh.sys_interval);
                            bridges.borrow_mut().reload(std::mem::take(&mut fresh.bridges));
                            if let Some((membership, (node_id, format))) =
                                membership.as_ref().zip(cluster_identity)
                            {
                                match fresh.cluster.take() {
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
                            // conf.c: config__copy limits and MQExtended's retained age limit.
                            if let Err(error) = broker.reload_limits(reloaded_limits).await {
                                tracing::warn!("Unable to apply reloaded broker limits: {error}");
                            }
                            live_config.replace(Some(fresh));
                        }
                        Err(error) => {
                            tracing::warn!("Unable to reload configuration: {error}");
                            certificates.refresh(None);
                            let reload = {
                                let old = live_config.borrow();
                                let old = old.as_ref().unwrap_or(&config);
                                logging.reload(&old.log);
                                // signals.c still calls plugin reload callbacks
                                // when the configuration reread fails.
                                if has_plugin_files {
                                    let watch = PolicyWatch::new(old);
                                    security.reload(old, || {})?;
                                    policy_watch.replace(watch);
                                }
                                has_plugin_files
                            };
                            if reload {
                                register_security().await?;
                            }
                        }
                    }
                } else {
                    certificates.refresh(None);
                    logging.reload(&config.log);
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
                BrokerSignal::Rotate => {
                    let live = live_config.borrow();
                    logging.reload(&live.as_ref().unwrap_or(&config).log);
                }
                BrokerSignal::Watchdog => process::notify_watchdog(),
                BrokerSignal::PolicyCheck => {
                    if policy_watch.borrow_mut().stable_change() {
                        tracing::info!("Password or ACL file changed; reloading policies.");
                        let result = {
                            let live = live_config.borrow();
                            reload_security(live.as_ref().unwrap_or(&config))
                        };
                        // Unlike an explicit SIGHUP, a bad replacement must
                        // not shut down the broker or displace a working policy.
                        if let Err(error) = result {
                            tracing::error!("Automatic policy reload failed: {error}");
                        } else if let Err(error) = register_security().await {
                            tracing::error!("Unable to register reloaded policies: {error}");
                        }
                    }
                }
                BrokerSignal::Reload => unreachable!("handled by the listener"),
            },
            || broker.shutdown(),
        )
        ;
    let result = tokio::select! {
        result = serve => result,
        // The node stopped itself: report its failure, or the recovery switch
        // that `start` re-execs for.
        () = async {
            match &membership {
                Some(membership) => membership.wait_restart().await,
                None => std::future::pending().await,
            }
        } => broker.shutdown_cluster().await.map_err(ServerError::Cluster),
    };
    if let Some(task) = rollout {
        task.abort();
    }
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
        retain_max_age: limits.retain_max_age,
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
        cluster_qos1_replay_batch: config.cluster_qos1_replay_batch,
        sparkplug_aware: config.sparkplug_aware,
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
        sparkplug_aware: listener.sparkplug_aware,
        security,
    }
}
