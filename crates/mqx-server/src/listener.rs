use std::{
    fmt::Display,
    future::{Future, pending},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use mqx_proxy::{PROXY_HEADER_TIMEOUT, ProxyOptions};
use mqx_ws::WsOptions;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpListener, lookup_host},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsAcceptor;

use crate::{
    ConnectionStream, ListenerConfig, ListenerProtocol, ServerConfig, ServerError, SocketDomain,
    tls,
    transport::{self, PeerAddress},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertIdentity {
    None,
    /// Identity from the client's certificate on the locally verified TLS connection.
    Username(String),
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
    /// Effective source address; a proxied Unix peer has no IP address.
    pub peer_addr: Option<SocketAddr>,
    /// The shared initial keepalive begins at TCP accept, before any upgrade.
    pub accepted_at: Instant,
    pub cert_identity: CertIdentity,
}

pub struct Server {
    listeners: Vec<BoundListener>,
    global_limit: Option<Arc<Semaphore>>,
    set_tcp_nodelay: bool,
    connection_messages: bool,
}

struct BoundListener {
    sockets: Vec<TcpListener>,
    options: Arc<ListenerOptions>,
}

struct ListenerOptions {
    config: Arc<ListenerConfig>,
    index: usize,
    limit: Option<Arc<Semaphore>>,
    tls: watch::Sender<Option<TlsAcceptor>>,
    proxy: Option<ProxyOptions>,
    websockets: Option<WsOptions>,
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
        }
        for (index, listener) in config.listeners.iter().enumerate() {
            let proxy = listener.proxy_options()?;
            let websockets =
                (listener.protocol == ListenerProtocol::Websockets).then(|| WsOptions {
                    packet_buffer_size: config.limits.packet_buffer_size,
                    origins: listener.websockets_origins.clone(),
                });
            let acceptor = tls::acceptor(listener)?;
            let addresses = listener_addresses(listener, config.local_only).await?;
            let mut sockets = Vec::new();
            for address in addresses {
                match bind_socket(address) {
                    Ok(socket) => {
                        tracing::info!(
                            "Opening {} listen socket on port {}.",
                            if address.is_ipv4() { "ipv4" } else { "ipv6" },
                            address.port()
                        );
                        sockets.push(socket);
                    }
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
            if !sockets.is_empty() {
                let (tls, _) = watch::channel(acceptor);
                listeners.push(BoundListener {
                    sockets,
                    options: Arc::new(ListenerOptions {
                        config: Arc::new(listener.clone()),
                        index,
                        limit: (listener.max_connections > 0)
                            .then(|| Arc::new(Semaphore::new(listener.max_connections))),
                        tls,
                        proxy,
                        websockets,
                    }),
                });
            } else if !config.local_only {
                return Err(first_failure.expect("no address bound"));
            }
        }
        if listeners.is_empty() {
            return Err(first_failure
                .unwrap_or_else(|| ServerError::Arguments("No TCP listeners configured.".into())));
        }
        Ok(Self {
            listeners,
            global_limit: (config.limits.global_max_connections > 0)
                .then(|| Arc::new(Semaphore::new(config.limits.global_max_connections))),
            set_tcp_nodelay: config.set_tcp_nodelay,
            connection_messages: config.log.connection_messages,
        })
    }

    pub fn local_addrs(&self) -> impl Iterator<Item = io::Result<SocketAddr>> + '_ {
        self.listeners
            .iter()
            .flat_map(|listener| listener.sockets.iter().map(TcpListener::local_addr))
    }

    pub async fn run<H, F, R, RF, E>(self, handler: H, reload: R) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        R: Fn() -> RF,
        RF: Future<Output = Result<(), E>>,
        E: Display,
    {
        self.run_with_shutdown(handler, reload, || {}).await
    }

    /// The reload callback replaces broker auth state and can recheck connected clients.
    /// `shutdown` asks the broker to close its clients before the server drains their tasks.
    pub async fn run_with_shutdown<H, F, R, RF, E, S>(
        self,
        handler: H,
        reload: R,
        shutdown: S,
    ) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        R: Fn() -> RF,
        RF: Future<Output = Result<(), E>>,
        E: Display,
        S: FnOnce(),
    {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut interrupt = signal(SignalKind::interrupt()).map_err(ServerError::Signal)?;
            let mut terminate = signal(SignalKind::terminate()).map_err(ServerError::Signal)?;
            let mut hangup = signal(SignalKind::hangup()).map_err(ServerError::Signal)?;
            let stop = async {
                tokio::select! {
                    _ = interrupt.recv() => (),
                    _ = terminate.recv() => (),
                }
            };
            let reloading = async || {
                hangup.recv().await;
            };
            self.serve(handler, reload, reloading, stop, shutdown).await
        }
        #[cfg(not(unix))]
        {
            // There is no SIGHUP or SIGTERM on Windows.
            let _ = reload;
            let signal_error = std::cell::Cell::new(None);
            let stop = async {
                signal_error.set(tokio::signal::ctrl_c().await.err());
            };
            self.serve(
                handler,
                || async { Ok::<_, E>(()) },
                async || pending().await,
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
            || async { Ok::<_, io::Error>(()) },
            async || pending().await,
            stop,
            shutdown,
        )
        .await
    }

    async fn serve<H, F, R, RF, E, U, S>(
        self,
        handler: H,
        reload: R,
        mut reload_signal: impl AsyncFnMut(),
        stop: U,
        shutdown: S,
    ) -> Result<(), ServerError>
    where
        H: Fn(Connection) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
        R: Fn() -> RF,
        RF: Future<Output = Result<(), E>>,
        E: Display,
        U: Future<Output = ()>,
        S: FnOnce(),
    {
        let (cancel, _) = watch::channel(false);
        let mut serving = JoinSet::new();
        let handler = Arc::new(handler);
        let mut reload_listeners = Vec::new();
        for listener in self.listeners {
            if listener.options.tls.borrow().is_some() {
                reload_listeners.push(listener.options.clone());
            }
            for socket in listener.sockets {
                let worker = SocketWorker {
                    socket,
                    options: listener.options.clone(),
                    global_limit: self.global_limit.clone(),
                    set_tcp_nodelay: self.set_tcp_nodelay,
                    connection_messages: self.connection_messages,
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
                    if let Err(error) = result {
                        tracing::error!("Listener task failed: {error}");
                    }
                    if serving.is_empty() {
                        break Ok(());
                    }
                }
                () = reload_signal() => {
                    // Mosquitto src/signals.c: signal__flag_check; configuration reload
                    // refreshes certificates without rebinding any listening socket.
                    tracing::info!("Reloading config.");
                    for listener in &reload_listeners {
                        match tls::acceptor(&listener.config) {
                            Ok(acceptor) => { listener.tls.send_replace(acceptor); }
                            Err(error) => tracing::error!("Certificate reload failed: {error}"),
                        }
                    }
                    if let Err(error) = reload().await {
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
    socket: TcpListener,
    options: Arc<ListenerOptions>,
    global_limit: Option<Arc<Semaphore>>,
    set_tcp_nodelay: bool,
    connection_messages: bool,
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
                            tracing::warn!("TCP accept failed: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let accepted_at = Instant::now();
                    // Mosquitto src/net.c: net__socket_accept checks both caps before starting TLS.
                    let (Ok(local), Ok(global)) = (
                        options.limit.clone().map(Semaphore::try_acquire_owned).transpose(),
                        global_limit.clone().map(Semaphore::try_acquire_owned).transpose(),
                    ) else {
                        if connection_messages {
                            tracing::info!(target: "mqx::notice", "Client connection from {} denied: max_connections exceeded.", peer_addr.ip());
                        }
                        continue;
                    };
                    if set_tcp_nodelay && let Err(error) = stream.set_nodelay(true) {
                        tracing::warn!("Unable to set TCP_NODELAY: {error}");
                    }
                    let handler = handler.clone();
                    let options = options.clone();
                    let mut cancel = cancel.clone();
                    connections.spawn(async move {
                        let _permits = (local, global);
                        let acceptor = options.tls.borrow().clone();
                        let mut peer = PeerAddress::Ip(peer_addr);
                        let listener = &options.config;
                        let (stream, cert_identity) = if options.proxy.is_some()
                            || acceptor.is_some() || options.websockets.is_some()
                        {
                            // Mosquitto src/context.c: context__init and src/keepalive.c:
                            // keepalive__check. Layer upgrades share one pre-CONNECT budget.
                            let negotiated = tokio::select! {
                                biased;
                                _ = cancel.changed() => return,
                                result = timeout_at(accepted_at + PROXY_HEADER_TIMEOUT, transport::negotiate(
                                    stream, &mut peer, options.proxy, acceptor, &listener.tls, options.websockets.as_ref(),
                                )) => result,
                            };
                            match negotiated {
                                Ok(Ok(Some(transport))) => transport,
                                Ok(Ok(None)) => return,
                                Ok(Err(error)) => {
                                    if connection_messages {
                                        tracing::debug!("Connection from {peer} ended: {error}");
                                    }
                                    return;
                                }
                                Err(_) => {
                                    if connection_messages {
                                        tracing::debug!("Handshake from {peer} exceeded the initial keepalive");
                                    }
                                    return;
                                }
                            }
                        } else {
                            (ConnectionStream::tcp(stream), transport::plain_identity(&listener.tls))
                        };
                        if connection_messages {
                            tracing::info!(target: "mqx::notice", "New connection from {peer} on port {}.", listener.port);
                        }
                        handler(Connection {
                            stream,
                            listener: listener.clone(),
                            listener_index: options.index,
                            peer_addr: peer.ip(),
                            accepted_at,
                            cert_identity,
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

fn bind_socket(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(100)?;
    TcpListener::from_std(socket.into())
}
