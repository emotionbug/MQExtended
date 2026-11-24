#![allow(
    dead_code,
    reason = "the two plugin test binaries use different subsets of the shared fixtures"
)]

include!("../auth_plug/services.rs");

pub(super) fn go_auth_path(variable: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(variable).unwrap_or_else(|| {
        panic!("set {variable} by sourcing the output of scripts/go-auth-reference.sh")
    }));
    assert!(
        path.is_absolute() && path.exists(),
        "invalid {variable}: {path:?}"
    );
    path
}

pub(super) fn mongo() -> u16 {
    static SERVER: LazyLock<Daemon> = LazyLock::new(|| {
        let port = port();
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(
            Command::new(go_auth_path("MONGOD"))
                .args([
                    "--bind_ip",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--nounixsocket",
                    "--dbpath",
                ])
                .arg(dir.path()),
            dir,
            port,
        );
        run(Command::new(go_auth_path("MOSQUITTO_GO_AUTH_SEED")).args([
            "mongo",
            &format!("mongodb://127.0.0.1:{port}"),
            HASH,
        ]));
        daemon
    });
    SERVER.port
}

pub(super) struct RedisMonitor(BufReader<TcpStream>);

impl RedisMonitor {
    pub(super) fn start(port: u16) -> Self {
        let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        socket.write_all(b"MONITOR\r\n").unwrap();
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "+OK\r\n");
        Self(reader)
    }

    pub(super) fn take(mut self, port: u16) -> Vec<String> {
        // MONITOR records commands before sending their replies. Issue a known
        // command after the final MQTT observation to delimit the stream.
        redis_command(port, &["ECHO", "go-auth-end-of-trace"]);
        let mut observed = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                self.0.read_line(&mut line).unwrap(),
                0,
                "Redis MONITOR closed"
            );
            let (_, command) = line.trim().split_once("] ").unwrap();
            let words: Vec<_> = command.split('"').collect();
            match (
                words[1].to_ascii_uppercase().as_str(),
                words.get(3).copied(),
            ) {
                ("ECHO", Some("go-auth-end-of-trace")) => return observed,
                (op @ "GET", Some(key @ ("alice" | "unknown" | "alice:su"))) => {
                    observed.push(format!("{op} {key}"));
                }
                (op @ "SMEMBERS", Some(key))
                    if key.starts_with("alice:") || key.starts_with("common:") =>
                {
                    observed.push(format!("{op} {key}"));
                }
                _ => (),
            }
        }
    }
}

pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) body: &'static str,
}

type GoAuthRespond = Box<dyn FnMut(&Request) -> Reply + Send>;

pub(super) struct HttpWithBody {
    pub(super) port: u16,
    state: Mutex<Option<(GoAuthRespond, Vec<Request>)>>,
}

impl HttpWithBody {
    pub(super) fn start(respond: impl FnMut(&Request) -> Reply + Send + 'static) -> &'static Self {
        static SERVER: LazyLock<HttpWithBody> = LazyLock::new(|| {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                for socket in listener.incoming() {
                    let mut socket = socket.unwrap();
                    let request = read_request(&mut socket);
                    let mut lock = SERVER.state.lock().unwrap();
                    let (respond, requests) = lock.as_mut().expect("unscripted HTTP request");
                    let Reply { status, body } = respond(&request);
                    requests.push(request);
                    write!(
                        socket,
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    ).unwrap();
                }
            });
            HttpWithBody {
                port,
                state: Mutex::new(None),
            }
        });
        *SERVER.state.lock().unwrap() = Some((Box::new(respond), Vec::new()));
        &SERVER
    }

    pub(super) fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut self.state.lock().unwrap().as_mut().unwrap().1)
    }
}
