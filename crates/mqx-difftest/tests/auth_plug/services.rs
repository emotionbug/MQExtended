use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};

pub(super) const HASH: &str =
    "PBKDF2$sha256$100$mqx-difftest$V0vJIN0tlWq4ZWFVbZpwzOfSBAHpiTEx0yPw5ZxqBM8=";
pub(super) const SECRET: &str = "secret";

pub(super) fn path(variable: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(variable).unwrap_or_else(|| {
        panic!("set {variable} by sourcing the output of scripts/auth-plug-reference.sh")
    }));
    assert!(
        path.is_absolute() && path.exists(),
        "invalid {variable}: {path:?}"
    );
    path
}

fn root() -> PathBuf {
    path("MOSQUITTO_AUTH_PLUG_ROOT")
}

pub(super) fn tool(relative: &str) -> Command {
    Command::new(root().join(relative))
}

pub(super) fn run(command: &mut Command) {
    let output = command
        .output()
        .unwrap_or_else(|err| panic!("{command:?}: {err}"));
    assert!(
        output.status.success(),
        "{command:?}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Daemon {
    port: u16,
    log: PathBuf,
    // Closing the test binary's stdin pipes on exit also cleans up after a panic.
    _lease: ChildStdin,
}

impl Daemon {
    fn start(command: &Command, dir: tempfile::TempDir, port: u16) -> Self {
        let log = dir.path().join("server.log");
        let mut supervisor = Command::new("sh")
            .args([
                "-c",
                // The daemon is a child of the supervisor, so it can be reaped after the
                // static fixture's pipe closes. The daemon must not inherit that pipe.
                "dir=$1; shift; \"$@\" </dev/null >\"$dir/server.log\" 2>&1 & \
                 child=$!; cat >/dev/null; kill -TERM \"$child\" 2>/dev/null; \
                 wait \"$child\"; rm -rf -- \"$dir\"",
                "auth-plug-fixture",
            ])
            .arg(dir.path())
            .arg(command.get_program())
            .args(command.get_args())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("{command:?}: {err}"));
        let _ = dir.keep();
        let lease = supervisor.stdin.take().unwrap();
        let cleanup = thread::spawn(move || supervisor.wait());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .is_ok_and(|s| s.local_addr().ok() != s.peer_addr().ok())
            {
                return Self {
                    port,
                    log,
                    _lease: lease,
                };
            }
            if Instant::now() >= deadline {
                let output = fs::read_to_string(log).unwrap_or_default();
                drop(lease);
                let _ = cleanup.join();
                panic!("{command:?} did not listen on port {port}\n{output}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

pub(super) fn redis() -> u16 {
    static SERVER: LazyLock<Daemon> = LazyLock::new(|| {
        let port = port();
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(
            tool("usr/bin/redis-server")
                .args([
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                    "--dir",
                ])
                .arg(dir.path()),
            dir,
            port,
        );
        redis_command(port, &["SET", "alice", HASH]);
        redis_command(port, &["SET", "acl:alice:allowed", "4"]);
        daemon
    });
    SERVER.port
}

pub(super) fn redis_command(port: u16, args: &[&str]) {
    run(tool("usr/bin/redis-cli")
        .args(["-e", "-h", "127.0.0.1", "-p", &port.to_string()])
        .args(args));
}

pub(super) fn memcached() -> u16 {
    static SERVER: LazyLock<Daemon> = LazyLock::new(|| {
        let port = port();
        let daemon = Daemon::start(
            tool("usr/bin/memcached").args(["-l", "127.0.0.1", "-p", &port.to_string(), "-U", "0"]),
            tempfile::tempdir().unwrap(),
            port,
        );
        let mut socket = BufReader::new(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap());
        socket
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        for (key, value) in [
            ("alice", HASH),
            ("alice-allowed", "4"),
            ("alice-denied", "0"),
        ] {
            write!(
                socket.get_mut(),
                "set {key} 0 0 {}\r\n{value}\r\n",
                value.len()
            )
            .unwrap();
            let mut response = String::new();
            socket.read_line(&mut response).unwrap();
            assert_eq!(response, "STORED\r\n");
        }
        daemon
    });
    SERVER.port
}

fn sql_seed() -> String {
    format!(
        "CREATE TABLE users (name VARCHAR(64) PRIMARY KEY, hash VARCHAR(255) NOT NULL, admin INTEGER NOT NULL);\
         INSERT INTO users VALUES ('alice', '{HASH}', 0), ('db-admin', '{HASH}', 1);\
         CREATE TABLE acl (name VARCHAR(64), access INTEGER, topic VARCHAR(255));\
         INSERT INTO acl VALUES ('alice', 1, 'allowed'), ('alice', 2, 'allowed'), ('alice', 4, 'allowed'),\
           ('alice', 2, 'owned/%u/%c');"
    )
}

pub(super) fn postgres() -> u16 {
    static SERVER: LazyLock<Daemon> = LazyLock::new(|| start_postgres(false));
    SERVER.port
}

#[allow(dead_code)] // Used by the go_auth test binary.
pub(super) fn traced_postgres() -> (u16, &'static std::path::Path) {
    static SERVER: LazyLock<Daemon> = LazyLock::new(|| start_postgres(true));
    (SERVER.port, &SERVER.log)
}

fn start_postgres(trace: bool) -> Daemon {
    let bin = path("MOSQUITTO_AUTH_PLUG_POSTGRES");
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    run(Command::new(bin.join("initdb"))
        .args([
            "--auth=trust",
            "--username=mqx",
            "--no-locale",
            "--encoding=UTF8",
            "-D",
        ])
        .arg(&data));
    let port = port();
    let mut command = Command::new(bin.join("postgres"));
    command
        .args(["-h", "127.0.0.1", "-p", &port.to_string(), "-k", "", "-D"])
        .arg(&data);
    if trace {
        command.args(["-c", "log_statement=all"]);
    }
    let daemon = Daemon::start(&command, dir, port);
    // PostgreSQL can listen before startup completes and reject the first
    // database connection. Wait for the server's protocol readiness signal.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = Command::new(bin.join("pg_isready"));
    ready.args([
        "-q",
        "-h",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-U",
        "mqx",
        "-d",
        "postgres",
    ]);
    while !ready.status().unwrap().success() {
        assert!(
            Instant::now() < deadline,
            "PostgreSQL did not become ready:\n{}",
            fs::read_to_string(&daemon.log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(20));
    }
    run(Command::new(bin.join("psql")).args([
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-U",
        "mqx",
        "-d",
        "postgres",
        "-c",
        &sql_seed(),
    ]));
    daemon
}

pub(super) fn mysql() -> u16 {
    static SERVER: LazyLock<(Daemon, PathBuf)> = LazyLock::new(|| start_mysql(false));
    SERVER.0.port
}

#[allow(dead_code)] // Used by the go_auth test binary.
pub(super) fn traced_mysql() -> (u16, &'static std::path::Path) {
    static SERVER: LazyLock<(Daemon, PathBuf)> = LazyLock::new(|| start_mysql(true));
    (SERVER.0.port, &SERVER.1)
}

fn start_mysql(trace: bool) -> (Daemon, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let usr = root().join("usr");
    let data = dir.path().join("data");
    let socket = dir.path().join("server.sock");
    let basedir = format!("--basedir={}", usr.display());
    let datadir = format!("--datadir={}", data.display());
    let tmpdir = format!("--tmpdir={}", dir.path().display());
    let socket = format!("--socket={}", socket.display());
    let user = Command::new("id").arg("-un").output().unwrap();
    assert!(user.status.success());
    let user = std::str::from_utf8(&user.stdout).unwrap().trim();
    run(tool("usr/bin/mariadb-install-db").args([
        "--no-defaults",
        &basedir,
        &datadir,
        &tmpdir,
        &format!("--auth-root-socket-user={user}"),
        "--skip-test-db",
        "--skip-name-resolve",
    ]));
    let port = port();
    let log = dir.path().join("queries.log");
    let mut command = tool("usr/sbin/mariadbd");
    command.args([
        "--no-defaults",
        &basedir,
        &datadir,
        &tmpdir,
        &socket,
        "--bind-address=127.0.0.1",
        "--skip-name-resolve",
        &format!("--pid-file={}/server.pid", dir.path().display()),
        &format!("--port={port}"),
    ]);
    if trace {
        command
            .arg("--general-log")
            .arg(format!("--general-log-file={}", log.display()));
    }
    let daemon = Daemon::start(&command, dir, port);
    let sql = format!(
        "CREATE DATABASE mqtt; CREATE USER 'mqx'@'127.0.0.1' IDENTIFIED BY 'fixture';\
             GRANT SELECT ON mqtt.* TO 'mqx'@'127.0.0.1'; USE mqtt; {}",
        sql_seed()
    );
    run(tool("usr/bin/mariadb").args([
        "--no-defaults",
        "--protocol=socket",
        &socket,
        "-u",
        user,
        "-e",
        &sql,
    ]));
    (daemon, log)
}

pub(super) fn ldap() -> u16 {
    static SERVER: LazyLock<Daemon> = LazyLock::new(|| {
        let dir = tempfile::tempdir().unwrap();
        let root = root();
        let config = dir.path().join("slapd.conf");
        let ldif = dir.path().join("fixture.ldif");
        fs::write(
            &config,
            format!(
                "include {root}/etc/ldap/schema/core.schema\n\
             pidfile {dir}/slapd.pid\nargsfile {dir}/slapd.args\n\
             modulepath {root}/usr/lib/ldap\nmoduleload back_mdb\n\
             database mdb\nsuffix dc=example,dc=test\nrootdn cn=admin,dc=example,dc=test\n\
             rootpw fixture\ndirectory {dir}\naccess to * by * read\n",
                root = root.display(),
                dir = dir.path().display(),
            ),
        )
        .unwrap();
        fs::write(
            &ldif,
            format!(
                "dn: dc=example,dc=test\nobjectClass: organization\nobjectClass: dcObject\n\
             dc: example\no: MQTT fixture\n\n\
             dn: cn=alice,dc=example,dc=test\nobjectClass: organizationalRole\n\
             objectClass: simpleSecurityObject\ncn: alice\nuserPassword: {SECRET}\n"
            ),
        )
        .unwrap();
        run(tool("usr/sbin/slapadd")
            .arg("-f")
            .arg(&config)
            .arg("-l")
            .arg(ldif));
        let port = port();
        Daemon::start(
            tool("usr/sbin/slapd")
                .args(["-d", "0", "-h", &format!("ldap://127.0.0.1:{port}")])
                .arg("-f")
                .arg(config),
            dir,
            port,
        )
    });
    SERVER.port
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Request {
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) version: String,
    headers: Vec<(String, String)>,
    pub(super) body: String,
}

impl Request {
    pub(super) fn header(&self, key: &str) -> &str {
        self.headers
            .iter()
            .find(|(name, _)| name == key)
            .map_or("", |(_, value)| value)
    }

    pub(super) fn param(&self, key: &str) -> &str {
        self.body
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| *name == key)
            .map_or("", |(_, value)| value)
    }
}

type Respond = fn(&Request) -> u16;

pub(super) struct Http {
    pub(super) port: u16,
    state: Mutex<Option<(Respond, Vec<Request>)>>,
}

impl Http {
    pub(super) fn start(respond: Respond) -> &'static Self {
        static SERVER: LazyLock<Http> = LazyLock::new(|| {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                for socket in listener.incoming() {
                    let mut socket = socket.unwrap();
                    let request = read_request(&mut socket);
                    let mut lock = SERVER.state.lock().unwrap();
                    let (respond, requests) = lock.as_mut().expect("unscripted HTTP request");
                    let status = respond(&request);
                    requests.push(request);
                    write!(socket, "HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                }
            });
            Http {
                port,
                state: Mutex::new(None),
            }
        });
        *SERVER.state.lock().unwrap() = Some((respond, Vec::new()));
        &SERVER
    }

    pub(super) fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut self.state.lock().unwrap().as_mut().unwrap().1)
    }
}

fn read_request(socket: &mut TcpStream) -> Request {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next().unwrap().into();
    let uri = parts.next().unwrap().into();
    let version = parts.next().unwrap().into();
    let mut headers = Vec::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.push((name.to_ascii_lowercase(), value.trim().into()));
    }
    headers.sort_unstable();
    let mut request = Request {
        method,
        uri,
        version,
        headers,
        body: String::new(),
    };
    let mut body = vec![0; request.header("content-length").parse().unwrap()];
    reader.read_exact(&mut body).unwrap();
    request.body = String::from_utf8(body).unwrap();
    request
}
