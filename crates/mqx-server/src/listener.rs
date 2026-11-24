use std::{
    fmt::Display,
    future::{Future, pending},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::PathBuf,
    sync::Mutex,
};

use mqx_broker::{ControlInventory, ControlListener};
use mqx_proxy::{PROXY_HEADER_TIMEOUT, ProxyOptions};
use mqx_ws::WsOptions;
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    net::{TcpListener, lookup_host},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout_at},
};

use crate::{
    ConnectionStream, ListenerConfig, ListenerProtocol, ServerConfig, ServerError, SocketDomain,
    tls::{self, ListenerAcceptor},
    transport::{self, PeerAddress, SocketStream},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertIdentity {
    None,
    /// Identity from the client's certificate on the locally verified TLS connection.
    Username(String),
    /// A client certificate on the locally verified TLS connection, with no
    /// username mapping; CONNECT credentials still authenticate the client.
    Presented,
    /// Common Name asserted by the upstream PROXY peer, not locally authenticated.
    ForwardedUsername(String),
    /// The transport is valid, but the broker must refuse CONNECT as bad credentials.
    MissingOrInvalid,
}

impl From<CertIdentity> for mqx_broker::CertIdentity {
    fn from(identity: CertIdentity) -> Self {
        match identity {
            CertIdentity::None => Self::None,
            CertIdentity::Username(name) => Self::Username(name),
            CertIdentity::Presented => Self::Presented,
            CertIdentity::ForwardedUsername(name) => Self::ForwardedUsername(name),
            CertIdentity::MissingOrInvalid => Self::MissingOrInvalid,
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    pub stream: ConnectionStream,
    pub listener: Arc<ListenerConfig>,
    /// Position of `listener` in [`ServerConfig::listeners`].
    pub listener_index: usize,
    /// Effective source IP address; direct and proxied Unix peers have no IP address.
    pub peer_addr: Option<SocketAddr>,
    /// The shared initial keepalive begins at socket accept, before any upgrade.
    pub accepted_at: Instant,
    pub cert_identity: CertIdentity,
    /// Mosquitto's `context->address` where it is not the inet_ntop form of
    /// `peer_addr`: a Unix socket path or a PROXY v1 source token as sent.
    pub peer_text: Option<String>,
    /// The negotiated TLS version and OpenSSL cipher name, when this listener
    /// terminated TLS itself.
    pub tls: Option<(String, String)>,
}

pub struct Server {
    listeners: Vec<BoundListener>,
    global_limit: Option<Arc<Semaphore>>,
    set_tcp_nodelay: bool,
    connection_messages: bool,
    observed_broker: Option<mqx_broker::Broker>,
    watchdog: Option<Duration>,
}

/// Non-terminating Unix process signals dispatched by the listener loop.
pub enum BrokerSignal {
    Reload,
    Backup,
    Diagnostics,
    Rotate,
    /// The service manager's watchdog period elapsed; see [`Server::with_watchdog`].
    Watchdog,
}

struct BoundListener {
    sockets: Vec<ListeningSocket>,
    options: Arc<ListenerOptions>,
}

enum ListeningSocket {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix {
        _path: UnixSocketPath,
        socket: UnixListener,
    },
}

impl ListeningSocket {
    async fn accept(&self) -> io::Result<(SocketStream, Option<SocketAddr>)> {
        match self {
            Self::Tcp(socket) => {
                let (stream, address) = socket.accept().await?;
                Ok((SocketStream::Tcp(stream), Some(address)))
            }
            #[cfg(unix)]
            Self::Unix { socket, .. } => {
                let (stream, _) = socket.accept().await?;
                Ok((SocketStream::Unix(stream), None))
            }
        }
    }
}

struct ListenerOptions {
    config: Arc<ListenerConfig>,
    index: usize,
    limit: Option<Arc<Semaphore>>,
    live: watch::Sender<LiveTls>,
    websockets: Option<WsOptions>,
}

/// Listener settings Mosquitto reads from the listener on every connection,
/// so a configuration reload changes them for new connections.
#[derive(Clone)]
struct LiveTls {
    acceptor: Option<ListenerAcceptor>,
    tls: Arc<crate::TlsConfig>,
    proxy: Option<ProxyOptions>,
}

/// Replaces certificates and per-connection TLS options on bound MQTT
/// listeners without rebinding sockets.
pub struct CertificateReloader(Vec<Arc<ListenerOptions>>);

impl CertificateReloader {
    /// Apply listener TLS settings from a successfully parsed configuration.
    /// With no new configuration, reread the most recently selected paths.
    pub fn refresh(&mut self, fresh: Option<&ServerConfig>) {
        for listener in &self.0 {
            let live = listener.live.borrow().clone();
            let mut tls = (*live.tls).clone();
            let mut proxy = live.proxy;
            if let Some(fresh) = fresh {
                let new = &fresh.listeners[listener.index].tls;
                // Mosquitto src/conf.c: config__read_file_core keeps a path the
                // reloaded file omits; listener__set_defaults resets the flags.
                for (active, next) in [
                    (&mut tls.certfile, &new.certfile),
                    (&mut tls.keyfile, &new.keyfile),
                    (&mut tls.crlfile, &new.crlfile),
                ] {
                    if next.is_some() && active != next {
                        active.clone_from(next);
                    }
                }
                tls.require_certificate = new.require_certificate;
                tls.use_identity_as_username = new.use_identity_as_username;
                tls.use_subject_as_username = new.use_subject_as_username;
                tls.disable_client_cert_date_checks = new.disable_client_cert_date_checks;
                if let Some(proxy) = &mut proxy {
                    proxy.require_certificate = new.require_certificate;
                    proxy.use_identity_as_username = new.use_identity_as_username;
                }
            }
            // Mosquitto src/listeners.c: listeners__reload_all_certificates
            // reloads only listeners that opened an SSL context at startup,
            // with the paths read by config__read; src/net.c:
            // net__load_certificates also reapplies require_certificate and
            // loads the reread crlfile.
            let acceptor = if live.acceptor.is_some() {
                match tls::mqtt_acceptor(listener.config.port, &tls) {
                    Ok(acceptor) => acceptor,
                    Err(error) => {
                        tracing::error!("Certificate reload failed: {error}");
                        continue;
                    }
                }
            } else {
                None
            };
            listener.live.send_replace(LiveTls {
                acceptor,
                tls: Arc::new(tls),
                proxy,
            });
        }
    }
}

impl Server {
    /// Resolves hosts, builds TLS state, and binds all sockets before serving any clients.
    pub async fn bind(config: &ServerConfig) -> Result<Self, ServerError> {
        let mut listeners = Vec::new();
        let mut first_failure = None;
        if config.local_only {
            tracing::warn!(
                "Starting in local only mode. Connections will only be possible from clients running on this machine."
            );
            // Mosquitto src/listeners.c: listeners__start_local_only.
            tracing::warn!(
                "Create a configuration file which defines a listener to allow remote access."
            );
            tracing::warn!(
                "For more details see https://mosquitto.org/documentation/authentication-methods/"
            );
        }
        for (index, listener) in config.listeners.iter().enumerate() {
            let http = listener.protocol == ListenerProtocol::HttpApi;
            // Mosquitto src/listeners.c: listeners__start_local_only starts
            // the optional HTTP endpoint only after an MQTT socket has opened.
            if config.local_only && http && listeners.is_empty() {
                break;
            }
            let proxy = if http {
                None
            } else {
                listener.proxy_options()?
            };
            let websockets =
                (listener.protocol == ListenerProtocol::Websockets).then(|| WsOptions {
                    packet_buffer_size: config.limits.packet_buffer_size,
                    origins: listener.websockets_origins.clone(),
                });
            // Mosquitto src/listeners.c: listeners__start ignores
            // http_api__start's result, so an HTTP listener that cannot load
            // its certificate, resolve its host or bind is skipped.
            let acceptor = match tls::acceptor(listener) {
                Ok(acceptor) => acceptor,
                Err(error) if http => {
                    tracing::error!("{error}");
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut sockets = Vec::new();
            // Mosquitto src/net.c: net__socket_listen selects AF_UNIX for port 0;
            // src/http_api.c: http_api__start uses its separate TCP bind path.
            if let Some(path) = listener.unix_socket_path.as_deref()
                && listener.port == 0
                && !http
            {
                sockets.push(bind_unix_socket(path).map_err(|source| ServerError::Bind {
                    endpoint: path.display().to_string(),
                    source,
                })?);
            } else {
                let addresses = match listener_addresses(listener, config.local_only).await {
                    Ok(addresses) => addresses,
                    Err(error) if http => {
                        tracing::error!("Unable to start http api listener ({error}).");
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                for address in addresses {
                    let dual_stack = http && listener.host.is_none();
                    // Mosquitto src/listeners.c: built-in websockets share
                    // net.c's IPv4/IPv6 socket path, unlike libwebsockets.
                    if !http {
                        tracing::info!(
                            "Opening {} listen socket on port {}.",
                            if address.is_ipv4() { "ipv4" } else { "ipv6" },
                            address.port()
                        );
                    }
                    match bind_socket(address, dual_stack) {
                        Ok(socket) => {
                            if http {
                                tracing::info!(
                                    "Opening http api listen socket on port {}.",
                                    address.port()
                                );
                            }
                            sockets.push(ListeningSocket::Tcp(socket));
                        }
                        // http_api.c: http_api__start does not log
                        // MHD_start_daemon failing to bind.
                        Err(_) if http => {}
                        Err(source) => {
                            let unavailable_family = source.kind() == io::ErrorKind::Unsupported;
                            let error = ServerError::Bind {
                                endpoint: address.to_string(),
                                source,
                            };
                            if !config.local_only && !unavailable_family {
                                return Err(error);
                            }
                            tracing::warn!("{error}");
                            first_failure.get_or_insert(error);
                        }
                    }
                }
            }
            if !sockets.is_empty() {
                let (live, _) = watch::channel(LiveTls {
                    acceptor,
                    tls: Arc::new(listener.tls.clone()),
                    proxy,
                });
                listeners.push(BoundListener {
                    sockets,
                    options: Arc::new(ListenerOptions {
                        config: Arc::new(listener.clone()),
                        index,
                        limit: (!http && listener.max_connections > 0)
                            .then(|| Arc::new(Semaphore::new(listener.max_connections))),
                        live,
                        websockets,
                    }),
                });
            } else if !config.local_only && !http {
                return Err(first_failure.expect("no address bound"));
            }
        }
        // Mosquitto src/listeners.c: listeners__start counts only MQTT
        // sockets; the HTTP API alone does not keep the broker running.
        if listeners
            .iter()
            .all(|listener| listener.options.config.protocol == ListenerProtocol::HttpApi)
        {
            return Err(first_failure.unwrap_or_else(|| {
                ServerError::Arguments(
                    "Error: Unable to start any listening sockets, exiting.".into(),
                )
            }));
        }
        Ok(Self {
            listeners,
            global_limit: (config.limits.global_max_connections > 0)
                .then(|| Arc::new(Semaphore::new(config.limits.global_max_connections))),
            set_tcp_nodelay: config.set_tcp_nodelay,
            connection_messages: config.log.connection_messages,
            observed_broker: None,
            watchdog: None,
        })
    }

    /// Emit [`BrokerSignal::Watchdog`] from the serve loop, first one second
    /// after `ready` and then every `period`, so a stalled loop stops pinging.
    pub fn with_watchdog(mut self, period: Option<Duration>) -> Self {
        self.watchdog = period;
        self
    }

    pub fn with_broker_observation(mut self, broker: mqx_broker::Broker) -> Self {
        self.observed_broker = Some(broker);
        self
    }

    /// Returns the bound TCP addresses; Unix listeners are identified by their paths.
    pub fn local_addrs(&self) -> impl Iterator<Item = io::Result<SocketAddr>> + '_ {
        self.listeners
            .iter()
            .flat_map(|listener| listener.sockets.iter())
            .filter_map(|socket| match socket {
                ListeningSocket::Tcp(socket) => Some(socket.local_addr()),
                #[cfg(unix)]
                ListeningSocket::Unix { .. } => None,
            })
    }

    pub(crate) fn listener_socket_count(&self, index: usize) -> usize {
        self.listeners
            .iter()
            .find(|listener| listener.options.index == index)
            .map_or(0, |listener| listener.sockets.len())
    }

    /// Snapshot of the listeners and plugins the broker control API can expose.
    pub fn control_inventory(&self, config: &ServerConfig) -> ControlInventory {
        let mut listeners = Vec::with_capacity(self.listeners.len());
        for bound in &self.listeners {
            let listener = &bound.options.config;
            // src/listeners.c: listeners__start_local_only adds a config entry
            // for each successful IPv4 or IPv6 loopback socket.
            if config.local_only && listener.protocol == ListenerProtocol::Mqtt {
                for address in bound.sockets.iter().filter_map(|socket| match socket {
                    ListeningSocket::Tcp(socket) => socket.local_addr().ok(),
                    #[cfg(unix)]
                    ListeningSocket::Unix { .. } => None,
                }) {
                    listeners.push(ControlListener {
                        port: address.port(),
                        protocol: Some("mqtt"),
                        bind_address: Some(address.ip().to_string()),
                        socket_path: None,
                        tls: false,
                    });
                }
                continue;
            }
            // src/broker_control.c: add_listener reports ssl_ctx, not whether
            // an HTTP listener serves HTTPS through its separate TLS stack.
            let protocol = match listener.protocol {
                ListenerProtocol::Mqtt => Some("mqtt"),
                ListenerProtocol::Websockets => Some("mqtt+websockets"),
                ListenerProtocol::HttpApi => None,
            };
            listeners.push(ControlListener {
                port: listener.port,
                protocol,
                bind_address: listener.host.clone(),
                socket_path: listener
                    .unix_socket_path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                tls: protocol.is_some() && bound.options.live.borrow().acceptor.is_some(),
            });
        }
        ControlInventory::new(listeners, &config.plugin_inventory)
    }

    pub async fn run<H, F, R, RF, E>(self, handler: H, reload: R) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        R: Fn() -> RF,
        RF: Future<Output = Result<(), E>>,
        E: Display,
    {
        self.run_with_signals(
            handler,
            async |certificates: &mut CertificateReloader| {
                certificates.refresh(None);
                reload().await
            },
            || {},
            async |_| {},
            || {},
        )
        .await
    }

    /// Installs signal handlers before calling `ready`. The reload callback
    /// refreshes certificates without rebinding sockets; `shutdown` asks the
    /// broker to close clients.
    pub async fn run_with_signals<H, F, E, S>(
        self,
        handler: H,
        reload: impl AsyncFn(&mut CertificateReloader) -> Result<(), E>,
        ready: impl FnOnce(),
        auxiliary: impl AsyncFn(BrokerSignal),
        shutdown: S,
    ) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        E: Display,
        S: FnOnce(),
    {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut interrupt = signal(SignalKind::interrupt()).map_err(ServerError::Signal)?;
            let mut terminate = signal(SignalKind::terminate()).map_err(ServerError::Signal)?;
            let mut hangup = signal(SignalKind::hangup()).map_err(ServerError::Signal)?;
            let mut backup = signal(SignalKind::user_defined1()).map_err(ServerError::Signal)?;
            let mut diagnostics =
                signal(SignalKind::user_defined2()).map_err(ServerError::Signal)?;
            #[cfg(any(target_os = "android", target_os = "linux"))]
            let mut rotate =
                signal(SignalKind::from_raw(nix::libc::SIGRTMIN())).map_err(ServerError::Signal)?;
            let mut rotation = async || {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                {
                    rotate.recv().await;
                }
                #[cfg(not(any(target_os = "android", target_os = "linux")))]
                pending::<()>().await;
            };
            let stop = async {
                tokio::select! {
                    _ = interrupt.recv() => (),
                    _ = terminate.recv() => (),
                }
            };
            // Mosquitto src/loop.c: mosquitto_main_loop calls watchdog__check
            // on every iteration, after main has sent READY=1.
            let mut watchdog = self.watchdog.map(|period| {
                let start = tokio::time::Instant::now() + Duration::from_secs(1);
                let mut ticks = tokio::time::interval_at(start, period);
                ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticks
            });
            let signals = async || {
                // Mosquitto src/signals.c: signal__flag_check processes
                // these flags between iterations of the main loop.
                tokio::select! {
                    biased;
                    _ = backup.recv() => BrokerSignal::Backup,
                    () = rotation() => BrokerSignal::Rotate,
                    _ = hangup.recv() => BrokerSignal::Reload,
                    _ = diagnostics.recv() => BrokerSignal::Diagnostics,
                    _ = async {
                        match &mut watchdog {
                            Some(ticks) => ticks.tick().await,
                            None => pending().await,
                        }
                    } => BrokerSignal::Watchdog,
                }
            };
            ready();
            self.serve(handler, reload, signals, auxiliary, stop, shutdown)
                .await
        }
        #[cfg(not(unix))]
        {
            // There is no SIGHUP or SIGTERM on Windows.
            let _ = reload;
            let signal_error = std::cell::Cell::new(None);
            let stop = async {
                signal_error.set(tokio::signal::ctrl_c().await.err());
            };
            ready();
            self.serve(
                handler,
                async |_: &mut CertificateReloader| Ok::<_, E>(()),
                async || pending().await,
                auxiliary,
                stop,
                shutdown,
            )
            .await;
            signal_error
                .into_inner()
                .map_or(Ok(()), |error| Err(ServerError::Signal(error)))
        }
    }

    /// Runs the listeners until a caller-managed shutdown signal resolves.
    pub async fn run_until<H, F, U, S>(
        self,
        handler: H,
        stop: U,
        shutdown: S,
    ) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        U: Future<Output = ()>,
        S: FnOnce(),
    {
        self.serve(
            handler,
            async |_: &mut CertificateReloader| Ok::<_, io::Error>(()),
            async || pending().await,
            async |_| {},
            stop,
            shutdown,
        )
        .await
    }

    async fn serve<H, F, E, U, S>(
        self,
        handler: H,
        reload: impl AsyncFn(&mut CertificateReloader) -> Result<(), E>,
        mut signals: impl AsyncFnMut() -> BrokerSignal,
        auxiliary: impl AsyncFn(BrokerSignal),
        stop: U,
        shutdown: S,
    ) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        E: Display,
        U: Future<Output = ()>,
        S: FnOnce(),
    {
        let (cancel, _) = watch::channel(false);
        let mut serving = JoinSet::new();
        let handler = Arc::new(handler);
        let mut certificates = CertificateReloader(Vec::new());
        for listener in self.listeners {
            let mqtt = listener.options.config.protocol != ListenerProtocol::HttpApi;
            if mqtt {
                certificates.0.push(listener.options.clone());
            }
            for socket in listener.sockets {
                let worker = SocketWorker {
                    socket,
                    options: listener.options.clone(),
                    global_limit: if mqtt {
                        self.global_limit.clone()
                    } else {
                        None
                    },
                    set_tcp_nodelay: self.set_tcp_nodelay,
                    connection_messages: mqtt && self.connection_messages,
                    observed_broker: if mqtt {
                        self.observed_broker.clone()
                    } else {
                        None
                    },
                };
                serving.spawn(worker.run(handler.clone(), cancel.subscribe()));
            }
        }

        tokio::pin!(stop);
        let result = loop {
            tokio::select! {
                biased;
                () = &mut stop => break Ok(()),
                Some(result) = serving.join_next() => {
                    // A worker only returns on cancellation. One that ended
                    // otherwise left its socket unserved; exit non-zero so the
                    // service manager restarts the broker with every listener.
                    let error = match result {
                        Err(error) => error.to_string(),
                        Ok(()) => "accept loop ended".into(),
                    };
                    break Err(ServerError::ListenerTask(error));
                }
                event = signals() => {
                    if !matches!(event, BrokerSignal::Reload) {
                        auxiliary(event).await;
                        continue;
                    }
                    // Mosquitto src/signals.c: signal__flag_check; configuration reload
                    // refreshes certificates without rebinding any listening socket.
                    tracing::info!("Reloading config.");
                    if let Err(error) = reload(&mut certificates).await {
                        // Mosquitto src/signals.c: signal__flag_check stops on security init failure.
                        break Err(ServerError::SecurityReload(error.to_string()));
                    }
                }
            }
        };

        cancel.send_replace(true);
        shutdown();
        if tokio::time::timeout(Duration::from_secs(5), async {
            while serving.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            serving.shutdown().await;
        }
        result
    }
}

struct SocketWorker {
    socket: ListeningSocket,
    options: Arc<ListenerOptions>,
    global_limit: Option<Arc<Semaphore>>,
    set_tcp_nodelay: bool,
    connection_messages: bool,
    observed_broker: Option<mqx_broker::Broker>,
}

impl SocketWorker {
    async fn run<H, F>(self, handler: Arc<H>, mut cancel: watch::Receiver<bool>)
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let mut connections = JoinSet::new();
        let Self {
            socket,
            options,
            global_limit,
            set_tcp_nodelay,
            connection_messages,
            observed_broker,
        } = self;
        loop {
            tokio::select! {
                biased;
                _ = cancel.changed() => break,
                Some(result) = connections.join_next() => {
                    if let Err(error) = result {
                        tracing::error!("Connection task failed: {error}");
                    }
                }
                accepted = socket.accept() => {
                    let (stream, peer_addr) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!("Listener accept failed: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    if let Some(broker) = &observed_broker {
                        broker.record_socket_accept();
                    }
                    let accepted_at = Instant::now();
                    // Mosquitto src/net.c: net__socket_accept checks both caps before starting TLS.
                    let (Ok(local), Ok(global)) = (
                        options.limit.clone().map(Semaphore::try_acquire_owned).transpose(),
                        global_limit.clone().map(Semaphore::try_acquire_owned).transpose(),
                    ) else {
                        if observed_broker.as_ref().map_or(connection_messages, mqx_broker::Broker::connection_messages) {
                            match peer_addr {
                                Some(peer_addr) => tracing::info!(target: "mqx::notice", "Client connection from {} denied: max_connections exceeded.", mqx_broker::inet_ntop(peer_addr.ip())),
                                None => {
                                    if let Some(path) = &options.config.unix_socket_path {
                                        tracing::info!(target: "mqx::notice", "Client connection from {} denied: max_connections exceeded.", path.display());
                                    }
                                }
                            }
                        }
                        continue;
                    };
                    // src/net.c: net__socket_accept only sets TCP_NODELAY on TCP listeners.
                    if set_tcp_nodelay && let Err(error) = stream.set_tcp_nodelay() {
                        tracing::warn!("Unable to set TCP_NODELAY: {error}");
                    }
                    let handler = handler.clone();
                    let options = options.clone();
                    let mut cancel = cancel.clone();
                    let observation = observed_broker.as_ref().map(mqx_broker::Broker::track_socket);
                    connections.spawn(async move {
                        let _permits = (local, global);
                        let connection_messages = || observation.as_ref().map_or(
                            connection_messages,
                            mqx_broker::SocketObservation::connection_messages,
                        );
                        let LiveTls { acceptor, tls, proxy } = options.live.borrow().clone();
                        let mut peer = match peer_addr {
                            Some(address) => PeerAddress::Ip(address, None),
                            None => PeerAddress::LocalUnix(
                                options.config.unix_socket_path.as_deref()
                                    .expect("Unix listener has a socket path"),
                            ),
                        };
                        let listener = &options.config;
                        // Mosquitto src/net.c: net__socket_accept logs direct
                        // transport sockets before negotiation, not PROXY sockets.
                        if connection_messages() && proxy.is_none() {
                            tracing::info!(target: "mqx::notice", "New connection from {peer} on port {}.", listener.port);
                        }
                        let (stream, cert_identity, tls_session) = if proxy.is_some()
                            || acceptor.is_some() || options.websockets.is_some()
                        {
                            // Mosquitto src/context.c: context__init and src/keepalive.c:
                            // keepalive__check. Layer upgrades share one pre-CONNECT budget.
                            let negotiated = tokio::select! {
                                biased;
                                _ = cancel.changed() => return,
                                result = timeout_at(accepted_at + PROXY_HEADER_TIMEOUT, transport::negotiate(
                                    stream, &mut peer, proxy, acceptor, &tls, options.websockets.as_ref(),
                                )) => result,
                            };
                            match negotiated {
                                Ok(Ok(Some(transport))) => transport,
                                Ok(Ok(None)) => return,
                                Ok(Err(error)) => {
                                    if connection_messages() {
                                        tracing::debug!("Connection from {peer} ended: {error}");
                                    }
                                    return;
                                }
                                Err(_) => {
                                    if connection_messages() {
                                        tracing::debug!("Handshake from {peer} exceeded the initial keepalive");
                                    }
                                    return;
                                }
                            }
                        } else {
                            (ConnectionStream::plain(stream), transport::plain_identity(&tls), None)
                        };
                        handler(Connection {
                            stream,
                            listener: listener.clone(),
                            listener_index: options.index,
                            peer_addr: peer.ip(),
                            accepted_at,
                            cert_identity,
                            peer_text: peer.text(),
                            tls: tls_session,
                        }).await;
                    });
                }
            }
        }
        drop(socket);
        while connections.join_next().await.is_some() {}
    }
}

async fn listener_addresses(
    listener: &ListenerConfig,
    local_only: bool,
) -> Result<Vec<SocketAddr>, ServerError> {
    let port = listener.port;
    let endpoint = listener
        .host
        .as_deref()
        .map_or_else(|| format!("port {port}"), |host| format!("{host}:{port}"));
    let bind_error = |source| ServerError::Bind {
        endpoint: endpoint.clone(),
        source,
    };
    if listener.protocol == ListenerProtocol::HttpApi {
        // http_api.c: http_api__start takes getaddrinfo's first TCP address
        // for an explicit host and opens one dual-stack socket otherwise.
        let address = if let Some(host) = &listener.host {
            lookup_host((host.as_str(), port))
                .await
                .map_err(bind_error)?
                .next()
                .ok_or_else(|| bind_error(io::ErrorKind::AddrNotAvailable.into()))?
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))
        };
        return Ok(vec![address]);
    }
    let mut addresses = if let Some(host) = &listener.host {
        lookup_host((host.as_str(), port))
            .await
            .map_err(bind_error)?
            .collect::<Vec<_>>()
    } else {
        let (ip4, ip6) = if local_only {
            (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST)
        } else {
            (Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
        };
        vec![SocketAddr::from((ip4, port)), SocketAddr::from((ip6, port))]
    };
    addresses.retain(|address| match listener.socket_domain {
        SocketDomain::Any => true,
        SocketDomain::Ipv4 => address.is_ipv4(),
        SocketDomain::Ipv6 => address.is_ipv6(),
    });
    if let Some(interface) = &listener.bind_interface {
        addresses = interface_addresses(addresses, interface, listener.host.is_some())
            .map_err(bind_error)?;
    }
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(bind_error(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no address matching socket_domain/bind_interface",
        )));
    }
    Ok(addresses)
}

#[cfg(unix)]
fn interface_addresses(
    addresses: Vec<SocketAddr>,
    interface: &str,
    explicit_host: bool,
) -> io::Result<Vec<SocketAddr>> {
    // Mosquitto src/net.c: net__bind_interface binds the interface address, not SO_BINDTODEVICE.
    let mut found = false;
    let mut interface_addrs = Vec::new();
    for entry in nix::ifaddrs::getifaddrs()? {
        if !entry.interface_name.eq_ignore_ascii_case(interface) {
            continue;
        }
        found = true;
        if let Some(address) = entry.address {
            if let Some(v4) = address.as_sockaddr_in() {
                interface_addrs.push(SocketAddr::from(*v4));
            } else if let Some(v6) = address.as_sockaddr_in6() {
                interface_addrs.push(SocketAddr::from(*v6));
            }
        }
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Interface {interface} does not exist."),
        ));
    }
    let mut bound = Vec::new();
    for address in addresses {
        if let Some(mut entry) = interface_addrs
            .iter()
            .copied()
            .find(|entry| entry.is_ipv4() == address.is_ipv4())
        {
            if explicit_host && entry.ip() != address.ip() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Interface address for {interface} does not match specified listener address ({address})."
                    ),
                ));
            }
            entry.set_port(address.port());
            bound.push(entry);
        }
    }
    Ok(bound)
}

#[cfg(not(unix))]
fn interface_addresses(_: Vec<SocketAddr>, _: &str, _: bool) -> io::Result<Vec<SocketAddr>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bind_interface is unsupported on this platform",
    ))
}

fn bind_socket(address: SocketAddr, dual_stack: bool) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(!dual_stack)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(100)?;
    TcpListener::from_std(socket.into())
}

#[cfg(unix)]
fn bind_unix_socket(path: &Path) -> io::Result<ListeningSocket> {
    use nix::sys::stat::{Mode, umask};
    use socket2::SockAddr;

    // Mosquitto src/net.c: net__socket_listen_unix replaces stale sockets
    // and listens with backlog 10. Never unlink a file or a serving listener.
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in Unix socket path",
        ));
    }
    let address = SockAddr::unix(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Path to unix socket is too long \"{}\".", path.display()),
        )
    })?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Unix listener path exists and is not a socket",
                ));
            }
            let probe = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            probe.set_nonblocking(true)?;
            match probe.connect(&address) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    unlink_same_socket(path, metadata.dev(), metadata.ino())?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(()) => return Err(io::ErrorKind::AddrInUse.into()),
                Err(error) => return Err(error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    tracing::info!("Opening unix listen socket on path {}.", path.display());
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    {
        // Mosquitto creates the socket under umask 0007, not chmod after bind.
        // Serialize this process-global change with other Unix listener binds.
        static BIND_UMASK: Mutex<()> = Mutex::new(());
        let _guard = BIND_UMASK.lock().expect("Unix listener bind lock poisoned");
        let old_mask = umask(Mode::S_IRWXO);
        let result = socket.bind(&address);
        umask(old_mask);
        result?;
    }
    let metadata = fs::symlink_metadata(path)?;
    let path = UnixSocketPath {
        path: path.to_owned(),
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    socket.listen(10)?;
    socket.set_nonblocking(true)?;
    let socket = UnixListener::from_std(socket.into())?;
    Ok(ListeningSocket::Unix {
        _path: path,
        socket,
    })
}

#[cfg(not(unix))]
fn bind_unix_socket(_: &Path) -> io::Result<ListeningSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix socket listeners are unsupported on this platform",
    ))
}

#[cfg(unix)]
struct UnixSocketPath {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
fn unlink_same_socket(path: &Path, dev: u64, ino: u64) -> io::Result<()> {
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_socket() && (current.dev(), current.ino()) == (dev, ino) {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
impl Drop for UnixSocketPath {
    fn drop(&mut self) {
        // A replacement listener may already be serving at our former pathname.
        let _ = unlink_same_socket(&self.path, self.dev, self.ino);
    }
}
