mod bridge;
mod plugin;

pub use plugin::FilePlugins;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use mqx_bridge::BridgeConfig;
use mqx_cluster::{ClusterConfig, ClusterSecurity, MAX_SNAPSHOT_SIZE};

use crate::ServerError;

const DEFAULT_PORT: u16 = 1883;
pub(crate) const CMD_PORT_LIMIT: usize = 10;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listeners: Vec<ListenerConfig>,
    pub bridges: Vec<BridgeConfig>,
    pub local_only: bool,
    pub per_listener_settings: bool,
    pub set_tcp_nodelay: bool,
    pub security: SecurityConfig,
    /// The active plugin, even when it is not attached to a listener.
    pub dynamic_security: Option<DynamicSecurityConfig>,
    pub sparkplug_aware: bool,
    /// Explicit plugins in initialization order.
    pub plugin_inventory: Vec<&'static str>,
    /// Natively implemented third-party auth plugins in declaration order.
    /// A listener refers to one by its index.
    pub external_plugins: Vec<ExternalPluginConfig>,
    pub limits: BrokerLimits,
    pub log: LogConfig,
    pub user: String,
    pub pid_file: Option<PathBuf>,
    pub sys_interval: u16,
    pub enable_control_api: bool,
    pub persistence: PersistenceConfig,
    pub cluster: Option<ClusterConfig>,
    /// Parse-time operator notices, emitted after the logging destinations are configured.
    pub notices: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSecurityConfig {
    pub config_file: PathBuf,
    pub password_init_file: Option<PathBuf>,
    /// Whether the plugin's callbacks run before the built-in file callbacks.
    pub before_file: bool,
}

/// A third-party auth plugin (`auth_plugin`/`plugin` naming a library that
/// `mqx_extauth` implements) and its options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPluginConfig {
    pub path: String,
    pub library: mqx_extauth::Library,
    /// `auth_opt_*`/`plugin_opt_*` with the prefix removed, in order.
    pub options: Vec<(String, String)>,
    /// `auth_plugin_deny_special_chars`.
    pub deny_special_chars: bool,
}

#[derive(Clone, Debug)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub file: Option<PathBuf>,
    pub location: Option<PathBuf>,
    pub autosave_interval: u32,
    pub autosave_on_changes: bool,
}

impl Default for PersistenceConfig {
    // Mosquitto src/conf.c: config__init_reload and config__check.
    fn default() -> Self {
        Self {
            enabled: false,
            file: None,
            location: None,
            autosave_interval: 1800,
            autosave_on_changes: false,
        }
    }
}

impl PersistenceConfig {
    pub fn mosquitto_path(&self) -> PathBuf {
        let file = self
            .file
            .as_deref()
            .unwrap_or_else(|| Path::new("mosquitto.db"));
        let Some(location) = self.location.as_ref().filter(|p| !p.as_os_str().is_empty()) else {
            return file.into();
        };
        // config__check concatenates even if persistence_file begins with '/'.
        let mut path = location.as_os_str().to_owned();
        path.push(std::path::MAIN_SEPARATOR_STR);
        path.push(file.as_os_str());
        path.into()
    }
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
    pub retain_expiry_interval: Option<Duration>,
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
    pub unix_socket_path: Option<PathBuf>,
    pub socket_domain: SocketDomain,
    pub protocol: ListenerProtocol,
    /// Zero is unlimited, including the negative values accepted by Mosquitto.
    pub max_connections: usize,
    pub max_qos: u8,
    pub disable_protocol_v3: bool,
    pub disable_protocol_v4: bool,
    pub disable_protocol_v5: bool,
    pub max_topic_alias: u16,
    pub max_topic_alias_broker: u16,
    pub use_username_as_clientid: bool,
    pub mount_point: Option<String>,
    pub security: SecurityConfig,
    pub dynamic_security: Option<DynamicSecurityConfig>,
    /// Index into [`ServerConfig::external_plugins`].
    pub external_plugin: Option<usize>,
    pub sparkplug_aware: bool,
    pub tls: TlsConfig,
    pub bind_interface: Option<String>,
    pub websockets_origins: Vec<String>,
    pub http_dir: Option<PathBuf>,
    /// Trusts source addresses and (in v2) TLS authentication from the proxy.
    /// Restrict access to this listener to trusted proxy hosts.
    pub enable_proxy_protocol: Option<ProxyProtocol>,
    pub proxy_protocol_v2_require_tls: bool,
}

impl ListenerConfig {
    pub(crate) fn proxy_options(&self) -> Result<Option<mqx_proxy::ProxyOptions>, ServerError> {
        let Some(version) = self.enable_proxy_protocol else {
            return Ok(None);
        };
        let options = mqx_proxy::ProxyOptions {
            version,
            require_tls: self.proxy_protocol_v2_require_tls,
            require_certificate: self.tls.require_certificate,
            use_identity_as_username: self.tls.use_identity_as_username,
        };
        // Mosquitto src/conf.c: config__check_proxy. V2 gets its TLS policy
        // from the upstream proxy, not a second TLS session.
        options
            .validate_listener(
                self.tls.use_subject_as_username,
                self.tls.certfile.is_some(),
                self.tls.keyfile.is_some(),
            )
            .map_err(|error| {
                let message = match error {
                    mqx_proxy::ProxyError::SubjectUsernameWithV2 => {
                        "use_subject_as_username cannot be used with `enable_proxy_protocol 2`."
                    }
                    mqx_proxy::ProxyError::ListenerTlsWithV2 => {
                        "certfile and keyfile cannot be used with `enable_proxy_protocol 2`."
                    }
                    _ => return ServerError::Arguments(format!("Error: {error}")),
                };
                ServerError::Arguments(format!("Error: {message}"))
            })?;
        Ok(Some(options))
    }
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
    HttpApi,
}

pub use mqx_proxy::ProxyVersion as ProxyProtocol;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityConfig {
    /// `None` on a listener inherits the global policy unless per-listener settings are enabled.
    pub allow_anonymous: Option<bool>,
    pub allow_zero_length_clientid: bool,
    pub auto_id_prefix: Option<String>,
    pub password_file: Option<PathBuf>,
    pub acl_file: Option<PathBuf>,
    pub file_plugins: FilePlugins,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsConfig {
    pub cafile: Option<PathBuf>,
    pub capath: Option<PathBuf>,
    pub certfile: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub require_certificate: bool,
    pub disable_client_cert_date_checks: bool,
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
    /// Syslog facility number, before shifting it into the PRI field.
    pub facility: u8,
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
            retain_expiry_interval: None,
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
            file_plugins: FilePlugins::default(),
        }
    }
}

impl Default for ListenerConfig {
    // Mosquitto src/listeners.c: listener__set_defaults; src/conf.c: config__create_default_listener.
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            host: None,
            unix_socket_path: None,
            protocol: ListenerProtocol::Mqtt,
            socket_domain: SocketDomain::Any,
            max_connections: 0,
            max_qos: 2,
            disable_protocol_v3: false,
            disable_protocol_v4: false,
            disable_protocol_v5: false,
            max_topic_alias: 10,
            max_topic_alias_broker: 10,
            use_username_as_clientid: false,
            mount_point: None,
            security: SecurityConfig::default(),
            dynamic_security: None,
            external_plugin: None,
            sparkplug_aware: false,
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
            facility: 3, // LOG_DAEMON; conf.c: config__init_reload.
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

    /// Reads reloadable directives without parsing startup-only plugin declarations.
    pub fn load_for_reload(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let mut parser = Parser {
            reloading: true,
            ..Parser::default()
        };
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
            let dynamic_security = self
                .listeners
                .first()
                .and_then(|listener| listener.dynamic_security.as_ref());
            self.listeners = ports
                .iter()
                .copied()
                .map(|port| {
                    let mut listener = Self::local_listener(port);
                    listener.security.allow_anonymous = self.security.allow_anonymous;
                    listener.dynamic_security = dynamic_security.cloned();
                    listener.sparkplug_aware = self.sparkplug_aware;
                    listener
                })
                .collect();
        }
        self
    }

    /// Returns the source of the built-in file directives and zero-length client ID policy.
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
    tls_version_seen: BTreeSet<usize>,
    security_seen: bool,
    plugins: Vec<plugin::Plugin>,
    reloading: bool,
    log_dest_seen: bool,
    log_type_seen: bool,
    log_file_seen: bool,
    cluster: Option<((PathBuf, usize), ClusterSection)>,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            config: ServerConfig {
                listeners: Vec::new(),
                bridges: Vec::new(),
                local_only: true,
                per_listener_settings: false,
                set_tcp_nodelay: false,
                security: SecurityConfig::default(),
                dynamic_security: None,
                sparkplug_aware: false,
                plugin_inventory: Vec::new(),
                external_plugins: Vec::new(),
                limits: BrokerLimits::default(),
                log: LogConfig::default(),
                // Mosquitto src/conf.c: config__parse_args.
                user: "mosquitto".into(),
                pid_file: None,
                sys_interval: 10,
                enable_control_api: false,
                persistence: PersistenceConfig::default(),
                cluster: None,
                notices: Vec::new(),
            },
            default_listener: None,
            tls_version_seen: BTreeSet::new(),
            security_seen: false,
            plugins: Vec::new(),
            reloading: false,
            log_dest_seen: false,
            log_type_seen: false,
            log_file_seen: false,
            cluster: None,
        }
    }
}

impl Parser {
    fn finish(mut self) -> Result<ServerConfig, ServerError> {
        bridge::finish(&mut self.config.bridges)
            .map_err(|error| ServerError::Arguments(format!("Error: {}", error.0)))?;
        if let Some(((path, line), section)) = self.cluster.take() {
            self.config.cluster = Some(section.finish().map_err(|error| error.at(&path, line))?);
            if self.config.persistence.enabled {
                self.config.notices.push(
                    "Ignoring standalone persistence in cluster mode; state is durable in Raft."
                        .into(),
                );
            }
        }
        // Mosquitto src/conf.c: config__check_bridges validates TLS file pairs
        // for every listener and config__check_proxy checks PROXY v2 separately.
        for listener in &self.config.listeners {
            let tls = &listener.tls;
            listener.proxy_options()?;
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
        self.finish_plugins()?;
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
    // The current plugin is likewise per-file, but named loads can be used by later files.
    fn read(&mut self, input: &[u8], path: &Path, included: bool) -> Result<(), ServerError> {
        let mut current = None;
        let mut connection = None;
        let mut plugin = None;
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
            } else if name.starts_with("cluster_") {
                let (_, section) = self
                    .cluster
                    .get_or_insert_with(|| ((path.into(), index + 1), ClusterSection::default()));
                section.directive(Value { name, value }).map_err(err)?;
            } else if name == "connection" {
                let name = Value { name, value }.word().map_err(err)?;
                if self.config.bridges.iter().any(|bridge| bridge.name == name) {
                    return Err(err(format!("Duplicate bridge name '{name}'.").into()));
                }
                connection = Some(self.config.bridges.len());
                self.config.bridges.push(BridgeConfig::new(name.into()));
            } else if bridge::is_directive(name) {
                let index = connection.ok_or_else(|| {
                    err(
                        format!("The '{name}' option requires a bridge to be defined first.")
                            .into(),
                    )
                })?;
                bridge::directive(
                    &mut self.config.bridges[index],
                    Value { name, value },
                    &mut self.config.notices,
                )
                .map_err(err)?;
            } else {
                self.directive(Value { name, value }, &mut current, &mut plugin)
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

    fn directive(
        &mut self,
        v: Value<'_>,
        current: &mut Option<usize>,
        plugin: &mut Option<usize>,
    ) -> ParseResult<()> {
        let name = v.name;
        match name {
            "listener" => {
                let mut words = v.words();
                let mut port_value = v;
                port_value.name = "listener port";
                let port = port_value.integer()?;
                words.next();
                let endpoint = words.next().filter(|word| !word.starts_with('#'));
                // Mosquitto src/conf.c: config__read_file_core stores a port-zero
                // endpoint as a Unix socket path, not a TCP bind hostname.
                let (port, host, unix_socket_path) = if cfg!(unix) && port == 0 {
                    let path = endpoint
                        .and_then(|word| word.split('\0').next())
                        .filter(|path| !path.is_empty())
                        .ok_or("A listener with port 0 must provide a Unix socket path.")?;
                    (0, None, Some(PathBuf::from(path)))
                } else {
                    (checked_port(port)?, endpoint.map(str::to_owned), None)
                };
                self.config.local_only = false;
                *current = Some(self.push_listener(ListenerConfig {
                    port,
                    host,
                    unix_socket_path,
                    ..ListenerConfig::default()
                }));
            }
            "port" | "bind_address" => {
                // src/conf.c: config__read_file_core gives only `port` an alternative.
                self.deprecated(
                    name,
                    if name == "port" {
                        "Please use 'listener' instead."
                    } else {
                        ""
                    },
                );
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
                self.deprecated(
                    name,
                    "Please see the documentation for how to achieve the same effect.",
                );
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
            | "max_topic_alias"
            | "max_topic_alias_broker"
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
                        listener.disable_protocol_v5 = true;
                        for version in versions {
                            match version {
                                "3" => listener.disable_protocol_v3 = false,
                                "4" => listener.disable_protocol_v4 = false,
                                "5" => listener.disable_protocol_v5 = false,
                                _ => (),
                            }
                        }
                    }
                    "max_topic_alias" | "max_topic_alias_broker" => {
                        let maximum = v.range(
                            0,
                            i32::from(u16::MAX),
                            &format!("Invalid '{name}' value in configuration."),
                        )? as u16;
                        if name == "max_topic_alias" {
                            listener.max_topic_alias = maximum;
                        } else {
                            listener.max_topic_alias_broker = maximum;
                        }
                    }
                    "cafile" => listener.tls.cafile = Some(v.path()?),
                    "tls_version" => {
                        let version = v.unique_string(!self.tls_version_seen.insert(index))?;
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
                        listener.enable_proxy_protocol =
                            Some(ProxyProtocol::try_from(v.integer()?).map_err(|_| {
                                ParseError::from("enable_proxy_protocol must be 1 or 2.")
                            })?);
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
                        "http_api" => listener.protocol = ListenerProtocol::HttpApi,
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
                    "Note: It is recommended to replace `message_size_limit` with `max_packet_size`."
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
            "sys_interval" => self.config.sys_interval = v.uint16()?,
            "log_facility" => {
                let value = v.integer()?;
                if !(0..=7).contains(&value) {
                    return Err(invalid(name, value));
                }
                // Mosquitto src/conf.c: config__read_file_core maps 0–7 to LOG_LOCAL0–7.
                self.config.log.facility = 16 + value as u8;
            }
            // conf.c: config__read_file_core caps the interval in minutes.
            "retain_expiry_interval" => {
                let minutes = v.integer()?;
                if minutes < 1 {
                    return Err("retain_expiry_interval must be >= 1.".into());
                }
                if minutes > 10_000_000 {
                    self.config
                        .notices
                        .push("Warning: retain_expiry_interval being capped at 19 years.".into());
                }
                self.config.limits.retain_expiry_interval =
                    Some(Duration::from_secs(minutes.min(10_000_000) as u64 * 60));
            }
            // conf.c: config__read_file_core clamps negative values to zero.
            "autosave_interval" => {
                self.config.persistence.autosave_interval = v.integer()?.max(0) as u32;
            }
            // Mosquitto src/conf.c: config__read_file_core only parses this
            // directive when built with libwebsockets.
            "websockets_log_level" => {}
            "autosave_on_changes" => {
                self.config.persistence.autosave_on_changes = v.boolean()?;
            }
            // Mosquitto src/conf.c: config__read_file_core; user is last-wins,
            // pid_file is unique. Neither is reread into the live process.
            "user" => self.config.user = v.string()?,
            "pid_file" => {
                self.config.pid_file =
                    Some(v.unique_string(self.config.pid_file.is_some())?.into());
            }
            // conf.c: config__read_file_core uses one flag for both spellings.
            "persistence" | "retained_persistence" => {
                self.config.persistence.enabled = v.boolean()?;
            }
            "persistence_file" => {
                self.config.persistence.file = Some(
                    v.unique_string(self.config.persistence.file.is_some())?
                        .into(),
                );
            }
            "persistence_location" => {
                self.config.persistence.location = Some(
                    v.unique_string(self.config.persistence.location.is_some())?
                        .into(),
                );
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
            "enable_control_api" => self.config.enable_control_api = v.boolean()?,
            "disable_client_cert_date_checks" => {
                let index = require_listener(*current, name)?;
                self.config.listeners[index]
                    .tls
                    .disable_client_cert_date_checks = v.boolean()?;
            }
            "tls_keyform" => {
                if v.string()? == "engine" {
                    return Err(unsupported(name, "OpenSSL engine keys"));
                }
                self.implicit_listener(current, name);
            }
            "psk_file" | "psk_hint" => return Err(unsupported(name, "TLS PSK")),
            "tls_engine" | "tls_engine_kpass_sha1" => {
                return Err(unsupported(name, "OpenSSL engines"));
            }
            _ if plugin::is_directive(name) => self.plugin_directive(v, *current, plugin)?,
            _ => return Err(format!("Unknown configuration variable '{name}'.").into()),
        }
        Ok(())
    }

    fn deprecated(&mut self, name: &str, alternative: &str) {
        // src/conf.c: OPTION_DEPRECATED keeps the space before an empty alternative.
        self.config.notices.push(format!(
            "The '{name}' option is now deprecated and will be removed in version 3.0. {alternative}"
        ));
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

#[derive(Default)]
struct ClusterSection {
    node_id: Option<u64>,
    bind: Option<SocketAddr>,
    peers: BTreeMap<u64, SocketAddr>,
    join: Option<bool>,
    membership_generation: Option<u64>,
    state_format: Option<u16>,
    data_dir: Option<PathBuf>,
    heartbeat: Option<Duration>,
    election: Option<(Duration, Duration)>,
    lease_interval: Option<Duration>,
    lease_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    cafile: Option<PathBuf>,
    certfile: Option<PathBuf>,
    keyfile: Option<PathBuf>,
    insecure_plaintext: Option<bool>,
    max_snapshot_size: Option<u64>,
}

impl ClusterSection {
    fn directive(&mut self, value: Value<'_>) -> ParseResult<()> {
        let name = value.name;
        let positive = |word: &str| -> ParseResult<u64> {
            word.parse()
                .ok()
                .filter(|number| *number > 0)
                .ok_or_else(|| invalid(name, word))
        };
        let duration = |word| positive(word).map(Duration::from_millis);
        let address = |word: &str| -> ParseResult<SocketAddr> {
            word.parse::<SocketAddr>()
                .ok()
                .filter(|addr| addr.port() != 0)
                .ok_or_else(|| invalid(name, word))
        };
        let path = match name {
            "cluster_data_dir" => Some(&mut self.data_dir),
            "cluster_cafile" => Some(&mut self.cafile),
            "cluster_certfile" => Some(&mut self.certfile),
            "cluster_keyfile" => Some(&mut self.keyfile),
            _ => None,
        };
        if let Some(path) = path {
            *path = Some(PathBuf::from(value.unique_string(path.is_some())?));
            return Ok(());
        }
        let count = match name {
            "cluster_peer" | "cluster_election_timeout" => 2,
            "cluster_node_id"
            | "cluster_bind"
            | "cluster_join"
            | "cluster_membership_generation"
            | "cluster_state_format"
            | "cluster_heartbeat_interval"
            | "cluster_lease_interval"
            | "cluster_lease_timeout"
            | "cluster_request_timeout"
            | "cluster_insecure_plaintext"
            | "cluster_max_snapshot_size" => 1,
            _ => return Err(format!("Unknown configuration variable '{name}'.").into()),
        };
        let mut words = value.words().take_while(|word| !word.starts_with('#'));
        let first = words.next().ok_or_else(|| empty(name))?;
        let second = words.next();
        if second.is_some() != (count == 2) || words.next().is_some() {
            return Err(format!("'{name}' requires {count} value(s).").into());
        }
        let duplicate = || ParseError(format!("Duplicate '{name}' value in configuration."));
        match name {
            "cluster_node_id" if self.node_id.is_none() => self.node_id = Some(positive(first)?),
            "cluster_bind" if self.bind.is_none() => self.bind = Some(address(first)?),
            "cluster_join" if self.join.is_none() => self.join = Some(value.boolean()?),
            "cluster_membership_generation" if self.membership_generation.is_none() => {
                self.membership_generation = Some(first.parse().map_err(|_| invalid(name, first))?);
            }
            "cluster_state_format" if self.state_format.is_none() => {
                self.state_format = Some(match first {
                    "1" => 1,
                    "2" => 2,
                    _ => return Err(invalid(name, first)),
                });
            }
            "cluster_peer" => {
                let id = positive(first)?;
                let addr = address(second.expect("two arguments"))?;
                if addr.ip().is_unspecified() {
                    return Err(format!("'cluster_peer' address {addr} must be routable.").into());
                }
                if self.peers.contains_key(&id) {
                    return Err(format!("Duplicate 'cluster_peer' node id {id}.").into());
                }
                if self.peers.values().any(|other| *other == addr) {
                    return Err(format!("Duplicate 'cluster_peer' address {addr}.").into());
                }
                self.peers.insert(id, addr);
            }
            "cluster_heartbeat_interval" if self.heartbeat.is_none() => {
                self.heartbeat = Some(duration(first)?)
            }
            "cluster_election_timeout" if self.election.is_none() => {
                self.election = Some((duration(first)?, duration(second.expect("two arguments"))?));
            }
            "cluster_lease_interval" if self.lease_interval.is_none() => {
                self.lease_interval = Some(duration(first)?)
            }
            "cluster_lease_timeout" if self.lease_timeout.is_none() => {
                self.lease_timeout = Some(duration(first)?)
            }
            "cluster_request_timeout" if self.request_timeout.is_none() => {
                self.request_timeout = Some(duration(first)?)
            }
            "cluster_insecure_plaintext" if self.insecure_plaintext.is_none() => {
                self.insecure_plaintext = Some(value.boolean()?);
            }
            "cluster_max_snapshot_size" if self.max_snapshot_size.is_none() => {
                let size = positive(first)?;
                if size > MAX_SNAPSHOT_SIZE {
                    return Err(format!(
                        "'{name}' must be between 1 and {MAX_SNAPSHOT_SIZE} bytes."
                    )
                    .into());
                }
                self.max_snapshot_size = Some(size);
            }
            _ => return Err(duplicate()),
        }
        Ok(())
    }

    fn finish(self) -> ParseResult<ClusterConfig> {
        let requires = |option| ParseError(format!("Cluster configuration requires '{option}'."));
        let id = self.node_id.ok_or_else(|| requires("cluster_node_id"))?;
        let bind = self.bind.ok_or_else(|| requires("cluster_bind"))?;
        let data_dir = self.data_dir.ok_or_else(|| requires("cluster_data_dir"))?;
        let join = self.join.unwrap_or(false);
        let generation = self.membership_generation.unwrap_or(0);
        if (join || generation == 0) && !self.peers.contains_key(&id) {
            return Err(format!(
                "Cluster configuration requires a 'cluster_peer' entry for node {id}."
            )
            .into());
        }
        if self.peers.is_empty() || (join && self.peers.len() < 2) {
            return Err("Cluster configuration requires peers, including an existing seed for 'cluster_join true'.".into());
        }
        if self.state_format == Some(1) && (join || generation != 0) {
            return Err("Dynamic membership requires 'cluster_state_format 2'.".into());
        }
        let allow_plaintext = self.insecure_plaintext == Some(true);
        let security = match (self.cafile, self.certfile, self.keyfile) {
            (Some(_), Some(_), Some(_)) if allow_plaintext => {
                return Err(
                    "'cluster_insecure_plaintext true' cannot be used with cluster TLS files."
                        .into(),
                );
            }
            (Some(ca_file), Some(cert_file), Some(key_file)) => ClusterSecurity::Tls {
                ca_file,
                cert_file,
                key_file,
            },
            (None, None, None) if allow_plaintext => {
                // A plaintext opt-in is not an opt-in to exposing it on every interface.
                if bind.ip().to_canonical().is_unspecified() {
                    return Err("A wildcard 'cluster_bind' requires cluster TLS.".into());
                }
                ClusterSecurity::InsecurePlaintext
            }
            (None, None, None) => {
                return Err("Cluster transport requires 'cluster_cafile', 'cluster_certfile', and 'cluster_keyfile'. Use peer certificates with Common Name mqx-node-<id>, or explicitly set 'cluster_insecure_plaintext true' on an isolated network.".into());
            }
            _ => {
                return Err("Cluster TLS requires 'cluster_cafile', 'cluster_certfile', and 'cluster_keyfile' together.".into());
            }
        };
        let mut config = ClusterConfig::new(id, bind, self.peers, data_dir, security);
        config.join = join;
        config.membership_generation = generation;
        if let Some(format) = self.state_format {
            config.state_format = format;
        }
        if let Some(interval) = self.heartbeat {
            config.heartbeat_interval = interval;
        }
        if let Some((min, max)) = self.election {
            config.election_timeout_min = min;
            config.election_timeout_max = max;
        }
        if config.election_timeout_min >= config.election_timeout_max {
            return Err("'cluster_election_timeout' minimum must be less than its maximum.".into());
        }
        if config.election_timeout_min <= config.heartbeat_interval {
            return Err(
                "'cluster_election_timeout' minimum must exceed 'cluster_heartbeat_interval'."
                    .into(),
            );
        }
        if let Some(interval) = self.lease_interval {
            config.lease_interval = interval;
        }
        if let Some(timeout) = self.lease_timeout {
            config.lease_timeout = timeout;
        }
        if config.lease_timeout <= config.lease_interval {
            return Err("'cluster_lease_timeout' must exceed 'cluster_lease_interval'.".into());
        }
        if let Some(timeout) = self.request_timeout {
            config.request_timeout = timeout;
        }
        if let Some(size) = self.max_snapshot_size {
            config.max_snapshot_size = size;
        }
        Ok(config)
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
