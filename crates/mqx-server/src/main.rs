use std::{ffi::OsString, path::PathBuf, process::ExitCode, sync::Arc};

use mqx_auth::{AclFile, PasswordFile};
use mqx_broker::{Broker, BrokerConfig, ConnectionInfo, ListenerPolicy, SecurityHandle};
use mqx_codec::QoS;
use mqx_server::{
    CertIdentity, ListenerConfig, SecurityConfig, Server, ServerConfig, ServerError,
    parse_command_line_port,
};

const USAGE: &str = "Usage: mqextended [-c <mosquitto.conf>] [-p <port>]... [-v] [-h]";

#[derive(Default)]
struct Cli {
    file: Option<PathBuf>,
    ports: Vec<u16>,
    verbose: bool,
}

impl Cli {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Self>, ServerError> {
        let mut args = args.into_iter();
        let mut cli = Self::default();
        let error = |message: &str| ServerError::Arguments(format!("Error: {message}"));
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("-h" | "--help") => return Ok(None),
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
                Some(
                    "-d" | "--daemon" | "-q" | "--quiet" | "--test-config" | "--tls-keylog"
                    | "--version",
                ) => {
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
        Ok(Some(cli))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(3)
        }
    }
}

async fn run() -> Result<(), ServerError> {
    let Some(cli) = Cli::parse(std::env::args_os().skip(1))? else {
        println!("{USAGE}");
        return Ok(());
    };
    let mut config = match cli.file {
        Some(file) => ServerConfig::load(file)?,
        None => ServerConfig::default(),
    }
    .with_command_line_ports(&cli.ports);
    if cli.verbose {
        config.log.verbose();
    }
    mqx_server::init_logging(&config.log)?;
    for message in &config.notices {
        tracing::info!(target: "mqx::notice", "{message}");
    }
    let security = security_handles(&config)?;
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
    let broker = Broker::new(broker_config(&config));
    let log_connections = config.log.connection_messages;
    let serving = broker.clone();
    Server::bind(&config)
        .await?
        .run_with_shutdown(
            move |connection| {
                let broker = serving.clone();
                let policies = policies.clone();
                async move {
                    if log_connections {
                        // Mosquitto src/net.c: net__socket_accept.
                        tracing::info!(
                            "New connection from {} on port {}.",
                            connection.peer_addr,
                            connection.listener.port
                        );
                    }
                    let info = ConnectionInfo {
                        peer_addr: Some(connection.peer_addr),
                        listener: policies[connection.listener_index].clone(),
                        cert_identity: match connection.cert_identity {
                            CertIdentity::None => mqx_broker::CertIdentity::None,
                            CertIdentity::Username(name) => {
                                mqx_broker::CertIdentity::Username(name)
                            }
                            CertIdentity::MissingOrInvalid => {
                                mqx_broker::CertIdentity::MissingOrInvalid
                            }
                        },
                    };
                    if let Err(error) = broker.serve(connection.stream, info).await {
                        tracing::debug!("Connection from {} ended: {error}", connection.peer_addr);
                    }
                }
            },
            || async {
                // Mosquitto src/signals.c: SIGHUP rereads the credential files even when their
                // paths are unchanged; a malformed file stops the broker (exit 3).
                security.reload(&config)
            },
            || broker.shutdown(),
        )
        .await
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
        self.handles[if self.per_listener { index } else { 0 }].clone()
    }

    fn reload(&self, config: &ServerConfig) -> Result<(), ServerError> {
        let fresh = load_credentials(config)?;
        for (handle, (password, acl)) in self.handles.iter().zip(fresh) {
            handle.replace(password, acl);
        }
        Ok(())
    }
}

fn security_handles(config: &ServerConfig) -> Result<SecurityHandles, ServerError> {
    Ok(SecurityHandles {
        handles: load_credentials(config)?
            .into_iter()
            .map(|(password, acl)| SecurityHandle::new(password, acl))
            .collect(),
        per_listener: config.per_listener_settings,
    })
}

type Credentials = (Option<PasswordFile>, Option<AclFile>);

fn load_credentials(config: &ServerConfig) -> Result<Vec<Credentials>, ServerError> {
    let load = |security: &SecurityConfig| {
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
            .as_ref()
            .map(|path| {
                AclFile::load(path).map_err(|source| ServerError::AclFile {
                    path: path.clone(),
                    source,
                })
            })
            .transpose()?;
        Ok((password, acl))
    };
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
