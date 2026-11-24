mod config;
mod http_api;
mod listener;
mod logging;
mod tls;
mod transport;

use std::{io, path::PathBuf};

pub use config::{
    BrokerLimits, DynamicSecurityConfig, ExternalPluginConfig, FilePlugins, ListenerConfig,
    ListenerProtocol, LogConfig, LogDestination, LogType, PersistenceConfig, ProxyProtocol,
    SecurityConfig, ServerConfig, SocketDomain, TlsConfig, TlsVersion, parse_command_line_port,
};
pub use http_api::HttpApi;
pub use listener::{BrokerSignal, CertIdentity, CertificateReloader, Connection, Server};
pub use logging::{LogTopics, Logging, init_logging, startup_log};
pub use tls::connect_bridge_tls;
pub use transport::ConnectionStream;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("{message} (at {path}:{line})")]
    Config {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error("{0}")]
    Arguments(String),
    #[error("{operation} '{path}': {source}")]
    File {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("listener {endpoint}: {source}")]
    Bind {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("TLS configuration for listener {port}: {message}")]
    Tls { port: u16, message: String },
    #[error("Security reload failed: {0}")]
    SecurityReload(String),
    #[error("Unable to load password_file '{path}': {source}")]
    PasswordFile {
        path: PathBuf,
        #[source]
        source: mqx_auth::PasswordFileError,
    },
    #[error("Unable to load acl_file '{path}': {source}")]
    AclFile {
        path: PathBuf,
        #[source]
        source: mqx_auth::AclFileError,
    },
    #[error("signal registration: {0}")]
    Signal(#[source] io::Error),
    #[error("initialize logging: {0}")]
    Logging(#[source] tracing::subscriber::SetGlobalDefaultError),
    #[error("Cluster broker: {0}")]
    Cluster(#[source] mqx_broker::BrokerError),
    /// A listener failed to open; Mosquitto src/mosquitto.c: main returns
    /// listeners__start's status 1 for bind, address and TLS load failures.
    #[error(transparent)]
    Listen(Box<ServerError>),
    /// An auth plugin stopped initialization after reporting why itself, as
    /// auth-plug's `log.c: _fatal` does before `exit(1)`.
    #[error("auth plugin initialization aborted")]
    PluginAbort,
    /// A listener stopped accepting connections without a shutdown request.
    #[error("Listener task stopped: {0}")]
    ListenerTask(String),
}
