use std::{
    cmp::Ordering,
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::ServerError;

const DEFAULT_PORT: u16 = 1883;
pub(crate) const CMD_PORT_LIMIT: usize = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub listeners: Vec<ListenerConfig>,
    pub local_only: bool,
    pub per_listener_settings: bool,
    pub set_tcp_nodelay: bool,
    pub security: SecurityConfig,
    pub limits: BrokerLimits,
    pub log: LogConfig,
    /// Parse-time operator notices, emitted after the logging destinations are configured.
    pub notices: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerLimits {
    pub global_max_clients: usize,
    pub global_max_connections: usize,
    pub max_inflight_messages: u16,
    pub max_inflight_bytes: usize,
    pub max_queued_messages: usize,
    pub max_queued_bytes: usize,
    pub max_keepalive: u16,
    pub max_packet_size: usize,
    pub message_size_limit: usize,
    pub persistent_client_expiration: Option<Duration>,
    pub queue_qos0_messages: bool,
    pub retain_available: bool,
    pub upgrade_outgoing_qos: bool,
    pub allow_duplicate_messages: bool,
    pub check_retain_source: bool,
    pub clientid_prefixes: Option<String>,
    pub packet_buffer_size: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    pub port: u16,
    pub host: Option<String>,
    pub socket_domain: SocketDomain,
    pub protocol: ListenerProtocol,
    /// Zero is unlimited, including the negative values accepted by Mosquitto.
    pub max_connections: usize,
    pub max_qos: u8,
    pub disable_protocol_v3: bool,
    pub disable_protocol_v4: bool,
    pub use_username_as_clientid: bool,
    pub mount_point: Option<String>,
    pub security: SecurityConfig,
    pub tls: TlsConfig,
    pub bind_interface: Option<String>,
    pub websockets_origins: Vec<String>,
    pub http_dir: Option<PathBuf>,
    pub enable_proxy_protocol: Option<ProxyProtocol>,
    pub proxy_protocol_v2_require_tls: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SocketDomain {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerProtocol {
    Mqtt,
    Websockets,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocol {
    V1,
    V2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityConfig {
    /// `None` on a listener inherits the global policy unless per-listener settings are enabled.
    pub allow_anonymous: Option<bool>,
    pub allow_zero_length_clientid: bool,
    pub auto_id_prefix: Option<String>,
    pub password_file: Option<PathBuf>,
    pub acl_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsConfig {
    pub cafile: Option<PathBuf>,
    pub capath: Option<PathBuf>,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub require_certificate: bool,
    pub use_identity_as_username: bool,
    pub use_subject_as_username: bool,
    pub version: TlsVersion,
    pub ciphers: Option<String>,
    pub ciphers_tls13: Option<String>,
    pub crlfile: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TlsVersion {
    #[default]
    Tls12OrNewer,
    Tls13,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogConfig {
    pub destinations: BTreeSet<LogDestination>,
    pub types: BTreeSet<LogType>,
    pub connection_messages: bool,
    pub timestamp: bool,
    pub timestamp_format: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LogDestination {
    Stderr,
    Stdout,
    File(PathBuf),
    Syslog,
    Topic,
    Dlt,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LogType {
    Error,
    Warning,
    Notice,
    Information,
    Debug,
    Subscribe,
    Unsubscribe,
    Internal,
    Websockets,
}

impl Default for BrokerLimits {
    // Mosquitto src/conf.c: config__init_reload.
    fn default() -> Self {
        Self {
            global_max_clients: 0,
            global_max_connections: 0,
            max_inflight_messages: 20,
            max_inflight_bytes: 0,
            max_queued_messages: 1000,
            max_queued_bytes: 0,
            max_keepalive: 0,
            max_packet_size: 2_000_000,
            message_size_limit: 0,
            persistent_client_expiration: None,
            queue_qos0_messages: false,
            retain_available: true,
            upgrade_outgoing_qos: false,
            allow_duplicate_messages: true,
            check_retain_source: true,
            clientid_prefixes: None,
            packet_buffer_size: 4096,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: None,
            allow_zero_length_clientid: true,
            auto_id_prefix: None,
            password_file: None,
            acl_file: None,
        }
    }
}

impl Default for ListenerConfig {
    // Mosquitto src/listeners.c: listener__set_defaults; src/conf.c: config__create_default_listener.
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            host: None,
            protocol: ListenerProtocol::Mqtt,
            socket_domain: SocketDomain::Any,
            max_connections: 0,
            max_qos: 2,
            disable_protocol_v3: false,
            disable_protocol_v4: false,
            use_username_as_clientid: false,
            mount_point: None,
            security: SecurityConfig::default(),
            tls: TlsConfig::default(),
            bind_interface: None,
            websockets_origins: Vec::new(),
            http_dir: None,
            enable_proxy_protocol: None,
            proxy_protocol_v2_require_tls: false,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            destinations: BTreeSet::from([LogDestination::Stderr, LogDestination::Dlt]),
            types: BTreeSet::from([
                LogType::Error,
                LogType::Warning,
                LogType::Notice,
                LogType::Information,
            ]),
            connection_messages: true,
            timestamp: true,
            timestamp_format: None,
        }
    }
}

impl LogConfig {
    pub fn verbose(&mut self) {
        self.types = BTreeSet::from([
            LogType::Error,
            LogType::Warning,
            LogType::Notice,
            LogType::Information,
            LogType::Debug,
            LogType::Subscribe,
            LogType::Unsubscribe,
            LogType::Internal,
            LogType::Websockets,
        ]);
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Parser::default()
            .finish()
            .expect("default configuration is valid")
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let mut parser = Parser::default();
        parser.read_file(path.as_ref(), false)?;
        parser.finish()
    }

    /// Parses the main configuration; relative filenames resolve from the working directory.
    pub fn parse(input: &str) -> Result<Self, ServerError> {
        let mut parser = Parser::default();
        parser.read(input.as_bytes(), Path::new("<config>"), false)?;
        parser.finish()
    }

    /// In Mosquitto 2.1.4, repeated `-p` selects local-only ports and never overrides `listener`.
    /// See src/conf.c: config__parse_args; src/listeners.c: listeners__start_local_only.
    pub fn with_command_line_ports(mut self, ports: &[u16]) -> Self {
        if self.local_only && !ports.is_empty() {
            self.listeners = ports
                .iter()
                .copied()
                .map(|port| {
                    let mut listener = Self::local_listener(port);
                    listener.security.allow_anonymous = self.security.allow_anonymous;
                    listener
                })
                .collect();
        }
        self
    }

    /// Returns the source of the listener's password file, ACL, and zero-length client id policy.
    pub fn security_for<'a>(&'a self, listener: &'a ListenerConfig) -> &'a SecurityConfig {
        if self.per_listener_settings {
            &listener.security
        } else {
            &self.security
        }
    }

    // Mosquitto src/plugin_basic_auth.c: mosquitto_basic_auth.
    pub fn allow_anonymous_for(&self, listener: &ListenerConfig) -> bool {
        listener.security.allow_anonymous.unwrap_or_else(|| {
            !self.per_listener_settings && self.security.allow_anonymous.unwrap_or(false)
        })
    }

    fn local_listener(port: u16) -> ListenerConfig {
        ListenerConfig {
            port,
            security: SecurityConfig {
                auto_id_prefix: Some("auto-".into()),
                ..SecurityConfig::default()
            },
            ..ListenerConfig::default()
        }
    }
}

struct Parser {
    config: ServerConfig,
    default_listener: Option<usize>,
    security_seen: bool,
    log_dest_seen: bool,
    log_type_seen: bool,
    log_file_seen: bool,
    pid_file_seen: bool,
    persistence_file_seen: bool,
    persistence_location_seen: bool,
    persistence_enabled_at: Option<(PathBuf, usize, &'static str)>,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            config: ServerConfig {
                listeners: Vec::new(),
                local_only: true,
                per_listener_settings: false,
                set_tcp_nodelay: false,
                security: SecurityConfig::default(),
                limits: BrokerLimits::default(),
                log: LogConfig::default(),
                notices: Vec::new(),
            },
            default_listener: None,
            security_seen: false,
            log_dest_seen: false,
            log_type_seen: false,
            log_file_seen: false,
            pid_file_seen: false,
            persistence_file_seen: false,
            persistence_location_seen: false,
            persistence_enabled_at: None,
        }
    }
}

impl Parser {
    fn finish(mut self) -> Result<ServerConfig, ServerError> {
        if let Some((path, line, directive)) = self.persistence_enabled_at {
            return Err(unsupported(directive, "on-disk persistence").at(&path, line));
        }
        for listener in &self.config.listeners {
            let tls = &listener.tls;
            // Mosquitto src/conf.c: config__check_proxy.
            if listener.enable_proxy_protocol == Some(ProxyProtocol::V2) {
                let message = if tls.use_subject_as_username {
                    Some("use_subject_as_username cannot be used with `enable_proxy_protocol 2`.")
                } else if tls.certfile.is_some() || tls.keyfile.is_some() {
                    Some("certfile and keyfile cannot be used with `enable_proxy_protocol 2`.")
                } else {
                    None
                };
                if let Some(message) = message {
                    return Err(ServerError::Arguments(format!("Error: {message}")));
                }
            }
            let message = match (&tls.certfile, &tls.keyfile) {
                (Some(_), None) | (None, Some(_)) => {
                    "Both certfile and keyfile must be provided to enable a TLS listener."
                }
                (None, None) if tls.cafile.is_some() => {
                    "cafile specified without certfile and keyfile."
                }
                (None, None) if tls.capath.is_some() => {
                    "capath specified without certfile and keyfile."
                }
                _ => continue,
            };
            return Err(ServerError::Tls {
                port: listener.port,
                message: message.into(),
            });
        }

        // Mosquitto src/conf.c: config__read/config__check; src/listeners.c: listeners__add_local.
        let config = &mut self.config;
        if config.local_only {
            config.security.allow_anonymous.get_or_insert(true);
            let mut listener = ServerConfig::local_listener(DEFAULT_PORT);
            listener.security.allow_anonymous = config.security.allow_anonymous;
            config.listeners = vec![listener];
        } else {
            if !config.per_listener_settings {
                config.security.allow_anonymous.get_or_insert(false);
            }
            for listener in &mut config.listeners {
                if config.per_listener_settings {
                    listener.security.allow_anonymous.get_or_insert(false);
                }
                listener.security.auto_id_prefix.get_or_insert_with(|| {
                    config
                        .security
                        .auto_id_prefix
                        .clone()
                        .unwrap_or_else(|| "auto-".into())
                });
            }
        }
        Ok(self.config)
    }

    fn read_file(&mut self, path: &Path, included: bool) -> Result<(), ServerError> {
        let bytes = fs::read(path).map_err(|source| ServerError::File {
            operation: "Unable to open config file",
            path: path.into(),
            source,
        })?;
        self.read(&bytes, path, included)
    }

    // Mosquitto src/conf.c: config__read_file_core. Includes don't inherit the caller's current listener.
    fn read(&mut self, input: &[u8], path: &Path, included: bool) -> Result<(), ServerError> {
        let mut current = None;
        for (index, raw) in input.split(|&byte| byte == b'\n').enumerate() {
            if matches!(raw.first(), None | Some(b'#' | b'\r')) {
                continue;
            }
            let err = |message: ParseError| message.at(path, index + 1);
            let line = std::str::from_utf8(raw)
                .map_err(|_| err(ParseError::from("Malformed UTF-8 in configuration.")))?
                .trim_end_matches('\r')
                .trim_start_matches(' ');
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(' ').unwrap_or((line, ""));
            if name == "include_dir" {
                if included {
                    return Err(err(
                        "The include_dir option is only valid in the main configuration file."
                            .into(),
                    ));
                }
                if value.is_empty() {
                    return Err(err(empty(name)));
                }
                for file in include_files(Path::new(value))? {
                    self.read_file(&file, true)?;
                }
            } else if matches!(name, "persistence" | "retained_persistence") {
                self.persistence_enabled_at =
                    Value { name, value }.boolean().map_err(err)?.then(|| {
                        (
                            path.into(),
                            index + 1,
                            if name == "persistence" {
                                "persistence"
                            } else {
                                "retained_persistence"
                            },
                        )
                    });
            } else {
                self.directive(Value { name, value }, &mut current)
                    .map_err(err)?;
            }
        }
        Ok(())
    }

    fn push_listener(&mut self, listener: ListenerConfig) -> usize {
        let index = self.config.listeners.len();
        self.config.listeners.push(listener);
        index
    }

    fn implicit_listener(&mut self, current: &mut Option<usize>, name: &str) -> usize {
        if let Some(index) = *current {
            return index;
        }
        let index = if let Some(index) = self.default_listener {
            index
        } else {
            self.config.notices.push(format!(
                "Creating default listener due to '{name}' option. Define a 'listener' first."
            ));
            let index = self.push_listener(ListenerConfig::default());
            self.default_listener = Some(index);
            index
        };
        *current = Some(index);
        index
    }

    fn directive(&mut self, v: Value<'_>, current: &mut Option<usize>) -> ParseResult<()> {
        let name = v.name;
        match name {
            "listener" => {
                let mut words = v.words();
                let mut port_value = v;
                port_value.name = "listener port";
                let port = port_value.integer()?;
                words.next();
                let host = words.next().filter(|word| !word.starts_with('#'));
                if port == 0 {
                    return Err(if host.is_some() {
                        unsupported(name, "Unix socket listeners (port 0)")
                    } else {
                        "A listener with port 0 must provide a Unix socket path.".into()
                    });
                }
                let port = checked_port(port)?;
                self.config.local_only = false;
                *current = Some(self.push_listener(ListenerConfig {
                    port,
                    host: host.map(str::to_owned),
                    ..ListenerConfig::default()
                }));
            }
            "port" | "bind_address" => {
                self.deprecated(name, "Please use 'listener' instead.");
                let mut default = None;
                let index = self.implicit_listener(&mut default, name);
                *current = Some(index);
                self.config.local_only = false;
                let listener = &mut self.config.listeners[index];
                if name == "port" {
                    listener.port = checked_port(v.integer()?)?;
                } else {
                    let value = Value {
                        name: "default listener bind_address",
                        ..v
                    };
                    listener.host = Some(value.unique_string(listener.host.is_some())?);
                }
            }
            "per_listener_settings" => {
                self.deprecated(name, "Use listener-specific security settings instead.");
                if !self.config.per_listener_settings {
                    let enable = v.boolean()?;
                    if enable && self.security_seen {
                        return Err(
                            "per_listener_settings must be set before any other security settings."
                                .into(),
                        );
                    }
                    self.config.per_listener_settings = enable;
                }
            }
            "allow_anonymous"
            | "allow_zero_length_clientid"
            | "auto_id_prefix"
            | "password_file"
            | "acl_file" => {
                if name == "auto_id_prefix" {
                    self.deprecated(name, "Please use 'listener_auto_id_prefix' instead.");
                }
                let security = if self.config.per_listener_settings {
                    let index = require_listener(*current, name)?;
                    if name == "allow_anonymous" {
                        self.config.notices.push("You are using the 'allow_anonymous' option with 'per_listener_settings true'. Please replace this with 'listener_allow_anonymous'.".into());
                    }
                    &mut self.config.listeners[index].security
                } else {
                    &mut self.config.security
                };
                self.security_seen = true;
                match name {
                    "allow_anonymous" => security.allow_anonymous = Some(v.boolean()?),
                    "allow_zero_length_clientid" => {
                        security.allow_zero_length_clientid = v.boolean()?
                    }
                    "auto_id_prefix" => {
                        security.auto_id_prefix = Some(v.prefix(security.auto_id_prefix.is_some())?)
                    }
                    "password_file" => security.password_file = Some(v.path()?),
                    "acl_file" => security.acl_file = Some(v.path()?),
                    _ => unreachable!(),
                }
            }
            "listener_allow_anonymous"
            | "listener_auto_id_prefix"
            | "mount_point"
            | "accept_protocol_versions"
            | "cafile"
            | "tls_version"
            | "http_dir"
            | "websockets_origin"
            | "enable_proxy_protocol"
            | "proxy_protocol_v2_require_tls" => {
                let explicit = if name == "accept_protocol_versions" {
                    current.filter(|index| Some(*index) != self.default_listener)
                } else {
                    *current
                };
                let index = require_listener(explicit, name)?;
                let listener = &mut self.config.listeners[index];
                match name {
                    "listener_allow_anonymous" => {
                        listener.security.allow_anonymous = Some(v.boolean()?)
                    }
                    "listener_auto_id_prefix" => {
                        listener.security.auto_id_prefix =
                            Some(v.prefix(listener.security.auto_id_prefix.is_some())?)
                    }
                    "mount_point" => {
                        let mount = v.string()?;
                        mqx_topic::validate_topic_name(&mount).map_err(|_| {
                            ParseError(format!("Invalid 'mount_point' value ({mount}). Does it contain a wildcard character?"))
                        })?;
                        listener.mount_point = Some(mount);
                    }
                    "accept_protocol_versions" => {
                        let mut versions = v
                            .value
                            .split([',', ' ', '\t'])
                            .filter(|word| !word.is_empty())
                            .peekable();
                        if versions.peek().is_none() {
                            return Err(empty(name));
                        }
                        listener.disable_protocol_v3 = true;
                        listener.disable_protocol_v4 = true;
                        for version in versions {
                            match version {
                                "3" => listener.disable_protocol_v3 = false,
                                "4" => listener.disable_protocol_v4 = false,
                                "5" => return Err(unsupported(name, "MQTT 5")),
                                _ => (),
                            }
                        }
                    }
                    "cafile" => listener.tls.cafile = Some(v.path()?),
                    "tls_version" => {
                        let version = v.string()?;
                        listener.tls.version = match version.as_str() {
                            "tlsv1.2" => TlsVersion::Tls12OrNewer,
                            "tlsv1.3" => TlsVersion::Tls13,
                            _ => {
                                let error = format!("Unsupported tls_version \"{version}\".");
                                return Err(error.into());
                            }
                        };
                    }
                    "websockets_origin" => listener.websockets_origins.push(v.string()?),
                    "http_dir" => {
                        let path = PathBuf::from(v.unique_string(listener.http_dir.is_some())?);
                        listener.http_dir = Some(path.canonicalize().map_err(|error| {
                            ParseError(format!(
                                "Unable to resolve 'http_dir' '{}': {error}",
                                path.display()
                            ))
                        })?);
                    }
                    "enable_proxy_protocol" => {
                        listener.enable_proxy_protocol = Some(match v.integer()? {
                            1 => ProxyProtocol::V1,
                            2 => ProxyProtocol::V2,
                            _ => return Err("enable_proxy_protocol must be 1 or 2.".into()),
                        })
                    }
                    "proxy_protocol_v2_require_tls" => {
                        listener.proxy_protocol_v2_require_tls = v.boolean()?
                    }
                    _ => unreachable!(),
                }
            }
            "protocol"
            | "socket_domain"
            | "max_connections"
            | "max_qos"
            | "maximum_qos"
            | "bind_interface"
            | "capath"
            | "certfile"
            | "keyfile"
            | "ciphers"
            | "ciphers_tls1.3"
            | "crlfile"
            | "require_certificate"
            | "use_identity_as_username"
            | "use_subject_as_username"
            | "use_username_as_clientid" => {
                let index = self.implicit_listener(current, name);
                let listener = &mut self.config.listeners[index];
                match name {
                    "protocol" => match v.word()? {
                        "mqtt" => listener.protocol = ListenerProtocol::Mqtt,
                        "websockets" => listener.protocol = ListenerProtocol::Websockets,
                        "http_api" => return Err(unsupported(name, "http_api")),
                        value => return Err(invalid(name, value)),
                    },
                    "socket_domain" => {
                        listener.socket_domain = match v.word()? {
                            "ipv4" => SocketDomain::Ipv4,
                            "ipv6" => SocketDomain::Ipv6,
                            value => {
                                return Err(format!(
                                    "Invalid 'socket_domain' value '{value}' in configuration."
                                )
                                .into());
                            }
                        }
                    }
                    "max_connections" => listener.max_connections = v.nonnegative()?,
                    "max_qos" | "maximum_qos" => {
                        listener.max_qos =
                            v.range(0, 2, "'max_qos' must be between 0 and 2 inclusive.")? as u8
                    }
                    "bind_interface" => {
                        if !cfg!(target_os = "linux") {
                            return Err(unsupported(name, "interface binding on this platform"));
                        }
                        listener.bind_interface =
                            Some(v.unique_string(listener.bind_interface.is_some())?);
                    }
                    "capath" => listener.tls.capath = Some(v.path()?),
                    "certfile" => listener.tls.certfile = Some(v.path()?),
                    "keyfile" => listener.tls.keyfile = Some(v.path()?),
                    "ciphers" => listener.tls.ciphers = Some(v.string()?),
                    "ciphers_tls1.3" => listener.tls.ciphers_tls13 = Some(v.string()?),
                    "crlfile" => listener.tls.crlfile = Some(v.path()?),
                    "require_certificate" => listener.tls.require_certificate = v.boolean()?,
                    "use_identity_as_username" => {
                        listener.tls.use_identity_as_username = v.boolean()?
                    }
                    "use_subject_as_username" => {
                        listener.tls.use_subject_as_username = v.boolean()?
                    }
                    "use_username_as_clientid" => {
                        listener.use_username_as_clientid = v.boolean()?
                    }
                    _ => unreachable!(),
                }
            }
            "clientid_prefixes" => {
                self.deprecated(name, "");
                self.config.limits.clientid_prefixes = Some(v.string()?);
            }
            "allow_duplicate_messages" => {
                self.deprecated(name, "The behaviour will default to true.");
                self.config.limits.allow_duplicate_messages = v.boolean()?;
            }
            "global_max_clients" => self.config.limits.global_max_clients = v.nonnegative()?,
            "global_max_connections" => {
                self.config.limits.global_max_connections = v.nonnegative()?
            }
            "max_inflight_bytes" => self.config.limits.max_inflight_bytes = v.nonnegative()?,
            "max_inflight_messages" => {
                let value = v.integer()?;
                self.config.limits.max_inflight_messages = match value {
                    ..=0 | 65535 => 0,
                    1..=65534 => value as u16,
                    _ => return Err("'max_inflight_messages' must be <= 65535.".into()),
                };
            }
            "max_keepalive" => self.config.limits.max_keepalive = v.uint16()?,
            "max_packet_size" => {
                self.config.limits.max_packet_size =
                    v.range(20, i32::MAX, "'max_packet_size' must be >= 20.")? as usize
            }
            "max_queued_bytes" => self.config.limits.max_queued_bytes = v.nonnegative()?,
            "max_queued_messages" => self.config.limits.max_queued_messages = v.nonnegative()?,
            "message_size_limit" => {
                self.config.notices.push(
                    "It is recommended to replace `message_size_limit` with `max_packet_size`."
                        .into(),
                );
                let value = v.integer()? as u32;
                if value > 268_435_455 {
                    return Err(invalid(name, value));
                }
                self.config.limits.message_size_limit = value as usize;
            }
            "persistent_client_expiration" => {
                let value = v.word()?;
                let unit = match value.as_bytes().last() {
                    Some(b's') => 1,
                    Some(b'h') => 3600,
                    Some(b'd') => 86400,
                    Some(b'w') => 86400 * 7,
                    Some(b'm') => 86400 * 30,
                    Some(b'y') => 86400 * 365,
                    _ => 0,
                };
                let seconds = if unit == 0 {
                    0
                } else {
                    i64::from(atoi(&value[..value.len() - 1])) * unit
                };
                if seconds <= 0 {
                    return Err(
                        "Invalid 'persistent_client_expiration' duration in configuration.".into(),
                    );
                }
                self.config.limits.persistent_client_expiration =
                    Some(Duration::from_secs(seconds as u64));
            }
            "queue_qos0_messages" => self.config.limits.queue_qos0_messages = v.boolean()?,
            "retain_available" => self.config.limits.retain_available = v.boolean()?,
            "upgrade_outgoing_qos" => self.config.limits.upgrade_outgoing_qos = v.boolean()?,
            "check_retain_source" => self.config.limits.check_retain_source = v.boolean()?,
            "set_tcp_nodelay" => self.config.set_tcp_nodelay = v.boolean()?,
            "packet_buffer_size" | "websockets_headers_size" => {
                self.config.limits.packet_buffer_size = v.range(
                    0,
                    65535,
                    "Packet buffer size must be between 0 and 65535 inclusive.",
                )? as u16;
            }
            "log_dest" => self.log_dest(v)?,
            "log_type" => self.log_type(v)?,
            "connection_messages" => self.config.log.connection_messages = v.boolean()?,
            "log_timestamp" => self.config.log.timestamp = v.boolean()?,
            "log_timestamp_format" => {
                self.config.log.timestamp_format =
                    Some(v.unique_string(self.config.log.timestamp_format.is_some())?)
            }
            // These options have no effect on MQTT 3.x clients. Keep Mosquitto's value checks.
            "sys_interval" => {
                v.uint16()?;
            }
            "log_facility" => {
                let value = v.integer()?;
                if !(0..=7).contains(&value) {
                    return Err(invalid(name, value));
                }
            }
            "retain_expiry_interval" => {
                if v.integer()? < 1 {
                    return Err("retain_expiry_interval must be >= 1.".into());
                }
            }
            "autosave_interval" | "websockets_log_level" => {
                v.integer()?;
            }
            "autosave_on_changes" => {
                v.boolean()?;
            }
            "user" => {
                v.string()?;
            }
            "pid_file" => {
                v.unique_string(self.pid_file_seen)?;
                self.pid_file_seen = true;
            }
            "persistence_file" => {
                v.unique_string(self.persistence_file_seen)?;
                self.persistence_file_seen = true;
            }
            "persistence_location" => {
                v.unique_string(self.persistence_location_seen)?;
                self.persistence_location_seen = true;
            }
            "dhparamfile" => self
                .config
                .notices
                .push("Warning: dhparamfile is no longer required.".into()),
            "retry_interval" => self
                .config
                .notices
                .push("Warning: The 'retry_interval' option is no longer available.".into()),
            "memory_limit" => {
                // Mosquitto's conf__parse_ssize_t uses atol, unlike ordinary integers.
                let value = decimal_prefix(v.word()?).unwrap_or(0);
                if value < 0 {
                    return Err(invalid(name, value));
                }
                if value > 0 {
                    return Err(unsupported(name, "a process-wide allocation limit"));
                }
            }
            "enable_control_api" | "disable_client_cert_date_checks" => {
                if name == "disable_client_cert_date_checks" {
                    require_listener(*current, name)?;
                }
                if v.boolean()? {
                    return Err(unsupported(name, "enabling this feature"));
                }
            }
            "tls_keyform" => {
                if v.string()? == "engine" {
                    return Err(unsupported(name, "OpenSSL engine keys"));
                }
                self.implicit_listener(current, name);
            }
            "max_topic_alias" | "max_topic_alias_broker" => {
                require_listener(*current, name)?;
                v.range(
                    0,
                    65535,
                    &format!("Invalid '{name}' value in configuration."),
                )?;
                return Err(unsupported(name, "MQTT 5 topic aliases"));
            }
            "psk_file" | "psk_hint" => return Err(unsupported(name, "TLS PSK")),
            "tls_engine" | "tls_engine_kpass_sha1" => {
                return Err(unsupported(name, "OpenSSL engines"));
            }
            "auth_plugin"
            | "auth_plugin_deny_special_chars"
            | "plugin"
            | "global_plugin"
            | "plugin_load"
            | "plugin_use" => return Err(unsupported(name, "plugins")),
            _ if name.starts_with("auth_opt_") || name.starts_with("plugin_opt_") => {
                return Err(unsupported(name, "plugins"));
            }
            "connection"
            | "address"
            | "addresses"
            | "clientid"
            | "remote_clientid"
            | "local_clientid"
            | "cleansession"
            | "local_cleansession"
            | "idle_timeout"
            | "keepalive_interval"
            | "local_password"
            | "local_username"
            | "notifications"
            | "notifications_local_only"
            | "notification_topic"
            | "password"
            | "remote_password"
            | "restart_timeout"
            | "round_robin"
            | "start_type"
            | "threshold"
            | "topic"
            | "try_private"
            | "username"
            | "remote_username"
            | "bridge_attempt_unsubscribe"
            | "bridge_cafile"
            | "bridge_alpn"
            | "bridge_ciphers"
            | "bridge_ciphers_tls1.3"
            | "bridge_bind_address"
            | "bridge_capath"
            | "bridge_certfile"
            | "bridge_identity"
            | "bridge_insecure"
            | "bridge_require_ocsp"
            | "bridge_max_packet_size"
            | "bridge_max_topic_alias"
            | "bridge_outgoing_retain"
            | "bridge_keyfile"
            | "bridge_protocol_version"
            | "bridge_psk"
            | "bridge_receive_maximum"
            | "bridge_reload_type"
            | "bridge_session_expiry_interval"
            | "bridge_tcp_keepalive"
            | "bridge_tcp_user_timeout"
            | "bridge_tls_use_os_certs"
            | "bridge_tls_version" => return Err(unsupported(name, "bridges")),
            _ => return Err(format!("Unknown configuration variable '{name}'.").into()),
        }
        Ok(())
    }

    fn deprecated(&mut self, name: &str, alternative: &str) {
        self.config.notices.push(format!("The '{name}' option is now deprecated and will be removed in version 3.0. {alternative}").trim_end().into());
    }

    fn log_dest(&mut self, v: Value<'_>) -> ParseResult<()> {
        let dest = v.word()?;
        if !self.log_dest_seen {
            self.log_dest_seen = true;
            self.config.log.destinations.clear();
        }
        let dest = match dest {
            "none" => {
                self.config.log.destinations.clear();
                return Ok(());
            }
            "stderr" => LogDestination::Stderr,
            "stdout" => LogDestination::Stdout,
            "syslog" => LogDestination::Syslog,
            "topic" => LogDestination::Topic,
            "dlt" => LogDestination::Dlt,
            "file" => {
                if self.log_file_seen {
                    return Err("Duplicate \"log_dest file\" value.".into());
                }
                self.log_file_seen = true;
                let rest = v
                    .value
                    .trim_start_matches(' ')
                    .strip_prefix("file")
                    .expect("first word is file");
                let path = rest.trim_start_matches([' ', '\t']);
                if path.is_empty() {
                    return Err("Empty \"log_dest file\" value in configuration.".into());
                }
                LogDestination::File(path.into())
            }
            _ => return Err(invalid(v.name, dest)),
        };
        self.config.log.destinations.insert(dest);
        Ok(())
    }

    fn log_type(&mut self, v: Value<'_>) -> ParseResult<()> {
        let kind = v.word()?;
        if !self.log_type_seen {
            self.log_type_seen = true;
            self.config.log.types.clear();
        }
        let kind = match kind {
            "none" => {
                self.config.log.types.clear();
                return Ok(());
            }
            "all" => {
                self.config.log.verbose();
                return Ok(());
            }
            "error" => LogType::Error,
            "warning" => LogType::Warning,
            "notice" => LogType::Notice,
            "information" => LogType::Information,
            "debug" => LogType::Debug,
            "subscribe" => LogType::Subscribe,
            "unsubscribe" => LogType::Unsubscribe,
            "internal" => LogType::Internal,
            "websockets" => LogType::Websockets,
            _ => return Err(invalid(v.name, kind)),
        };
        self.config.log.types.insert(kind);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Value<'a> {
    name: &'a str,
    value: &'a str,
}

impl<'a> Value<'a> {
    fn words(self) -> impl Iterator<Item = &'a str> {
        self.value.split(' ').filter(|word| !word.is_empty())
    }

    fn word(self) -> ParseResult<&'a str> {
        self.words().next().ok_or_else(|| empty(self.name))
    }

    // Mosquitto src/conf.c: conf__parse_bool/conf__parse_int/conf__parse_string.
    // Only space separates tokens; strtol skips leading ASCII whitespace and uses base zero.
    fn boolean(self) -> ParseResult<bool> {
        match self.word()? {
            "false" | "0" => Ok(false),
            "true" | "1" => Ok(true),
            value => Err(invalid(self.name, value)),
        }
    }

    fn integer(self) -> ParseResult<i32> {
        let word = self.word()?.trim_start_matches(c_space);
        let (negative, digits) = if let Some(digits) = word.strip_prefix('-') {
            (true, digits)
        } else {
            (false, word.strip_prefix('+').unwrap_or(word))
        };
        let (base, digits) = if let Some(digits) = digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
        {
            (16, digits)
        } else if digits.starts_with('0') {
            (8, digits)
        } else {
            (10, digits)
        };
        if digits.is_empty() || !digits.bytes().all(|byte| char::from(byte).is_digit(base)) {
            return Err(format!("'{}' value not a number.", self.name).into());
        }
        let out_of_range = || ParseError(format!("'{}' value out of range.", self.name));
        let absolute = i64::from_str_radix(digits, base).map_err(|_| out_of_range())?;
        i32::try_from(if negative { -absolute } else { absolute }).map_err(|_| out_of_range())
    }

    fn range(self, min: i32, max: i32, message: &str) -> ParseResult<i32> {
        let value = self.integer()?;
        if (min..=max).contains(&value) {
            Ok(value)
        } else {
            Err(message.into())
        }
    }

    fn uint16(self) -> ParseResult<u16> {
        let value = self.integer()?;
        u16::try_from(value).map_err(|_| invalid(self.name, value))
    }

    fn nonnegative(self) -> ParseResult<usize> {
        Ok(self.integer()?.max(0) as usize)
    }

    fn string(self) -> ParseResult<String> {
        self.unique_string(false)
    }

    fn unique_string(self, defined: bool) -> ParseResult<String> {
        if defined && !self.value.is_empty() {
            return Err(format!("Duplicate '{}' value in configuration.", self.name).into());
        }
        let value = self.value.trim_matches(c_space);
        if value.is_empty() {
            return Err(empty(self.name));
        }
        if value.len() > usize::from(u16::MAX)
            || mqx_codec::validate_utf8(value.as_bytes()).is_err()
        {
            return Err("Malformed UTF-8 in configuration.".into());
        }
        Ok(value.into())
    }

    fn path(self) -> ParseResult<PathBuf> {
        self.string().map(PathBuf::from)
    }

    fn prefix(self, defined: bool) -> ParseResult<String> {
        let prefix = self.unique_string(defined)?;
        if prefix.len() > 50 {
            return Err(format!("'{}' length must be <= 50.", self.name).into());
        }
        Ok(prefix)
    }
}

fn c_space(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n' | '\u{000b}' | '\u{000c}')
}

pub fn parse_command_line_port(value: &str, already_specified: usize) -> Result<u16, ServerError> {
    // Mosquitto src/conf.c: config__parse_args uses decimal atoi(), not the config's strtol().
    let port = atoi(value);
    let port = u16::try_from(port)
        .ok()
        .filter(|&port| port != 0)
        .ok_or_else(|| {
            ServerError::Arguments(format!("Error: Invalid port specified ({port})."))
        })?;
    if already_specified >= CMD_PORT_LIMIT {
        return Err(ServerError::Arguments(format!(
            "Error: Only {CMD_PORT_LIMIT} ports can be specified on the command line."
        )));
    }
    Ok(port)
}

fn atoi(s: &str) -> i32 {
    decimal_prefix(s).unwrap_or(0) as i32
}

fn decimal_prefix(s: &str) -> Option<i64> {
    let s = s.trim_start_matches(c_space);
    let start = usize::from(s.starts_with(['-', '+']));
    let count = s.as_bytes()[start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if count == 0 {
        return None;
    }
    Some(s[..start + count].parse().unwrap_or_else(|_| {
        if s.starts_with('-') {
            i64::MIN
        } else {
            i64::MAX
        }
    }))
}

fn checked_port(port: i32) -> ParseResult<u16> {
    match u16::try_from(port) {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(invalid("port", port)),
    }
}

fn include_files(path: &Path) -> Result<Vec<PathBuf>, ServerError> {
    let fail = |source| ServerError::File {
        operation: "Unable to open include_dir",
        path: path.into(),
        source,
    };
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        if entry.path().extension() == Some(OsStr::new("conf")) {
            files.push(entry.path());
        }
    }
    // Mosquitto src/conf_includedir.c: scmp_p compares case-insensitively, then case, *per byte*.
    files.sort_unstable_by(|left, right| {
        let left = left.as_os_str().as_encoded_bytes();
        let right = right.as_os_str().as_encoded_bytes();
        for (a, b) in left.iter().zip(right) {
            let order = a
                .to_ascii_uppercase()
                .cmp(&b.to_ascii_uppercase())
                .then_with(|| (*a as i8).cmp(&(*b as i8)));
            if order != Ordering::Equal {
                return order;
            }
        }
        left.len().cmp(&right.len())
    });
    Ok(files)
}

struct ParseError(String);
type ParseResult<T> = Result<T, ParseError>;

impl<T: Into<String>> From<T> for ParseError {
    fn from(message: T) -> Self {
        Self(message.into())
    }
}

impl ParseError {
    fn at(self, path: &Path, line: usize) -> ServerError {
        ServerError::Config {
            path: path.into(),
            line,
            message: format!("Error: {}", self.0),
        }
    }
}

fn empty(name: &str) -> ParseError {
    format!("Empty '{name}' value in configuration.").into()
}

fn invalid(name: &str, value: impl std::fmt::Display) -> ParseError {
    format!("Invalid '{name}' value ({value}).").into()
}

fn unsupported(name: &str, feature: &str) -> ParseError {
    format!(
        "Unsupported configuration directive '{name}': MQExtended does not implement {feature}."
    )
    .into()
}

fn require_listener(current: Option<usize>, name: &str) -> ParseResult<usize> {
    current.ok_or_else(|| {
        format!("The '{name}' option requires a listener to be defined first.").into()
    })
}
