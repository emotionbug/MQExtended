//! Database back-end differential tests (run as a non-root user):
//! `cargo test --locked -p mqx-extauth --test database_reference -- --ignored`
//!
//! Source the environment from `scripts/auth-plug-reference.sh`. The tests
//! use `MOSQUITTO_AUTH_PLUG_ROOT`, `MOSQUITTO_AUTH_PLUG_POSTGRES`,
//! `MOSQUITTO_AUTH_PLUG_BINARY`, `MOSQUITTO_AUTH_PLUG_SO` and `LD_LIBRARY_PATH`.
//! Set `MONGOD` to the mongod executable for the MongoDB test. The reference
//! plugin is not built with MongoDB; that test uses verdicts from be-mongo.c.

use std::{
    env,
    fs::{self, File},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use mongodb::{
    Client,
    bson::{doc, oid::ObjectId},
};
use mqx_auth::external::{AclAccess, Binding, ExternalSecurity, Subject, Verdict};
use mqx_extauth::{Library, load};
use tempfile::TempDir;

const HOST: &str = "127.0.0.1";
const PASSWORD: &str = "password";
const HASH: &str = "PBKDF2$sha256$100$auth-test$mprt70FjB9LGypn+1U3ug+NB5AHCAtXMQB3xHqySLvQ=";
type Options = Vec<(String, String)>;

struct Fixtures {
    root: PathBuf,
    usr: PathBuf,
    binary: PathBuf,
    plugin: PathBuf,
}

fn path(var: &str) -> PathBuf {
    PathBuf::from(env::var_os(var).unwrap_or_else(|| panic!("set {var} for reference tests")))
}

impl Fixtures {
    fn new() -> Self {
        let root = path("MOSQUITTO_AUTH_PLUG_ROOT");
        let binary = path("MOSQUITTO_AUTH_PLUG_BINARY");
        let plugin = path("MOSQUITTO_AUTH_PLUG_SO");
        let usr = root.join("usr");
        Self {
            root,
            usr,
            binary,
            plugin,
        }
    }

    fn command(&self, binary: impl AsRef<Path>) -> Command {
        let mut command = Command::new(binary.as_ref());
        command.env(
            "LD_LIBRARY_PATH",
            env::var_os("LD_LIBRARY_PATH")
                .expect("source the auth-plug reference environment to set LD_LIBRARY_PATH"),
        );
        command
    }

    fn reference(&self, options: &Options) -> (Process, u16) {
        let dir = tempfile::tempdir().unwrap();
        let port = port();
        let config = dir.path().join("mosquitto.conf");
        let mut text = format!(
            "listener {port} {HOST}\nallow_anonymous false\nauth_plugin {}\n",
            self.plugin.display()
        );
        for (key, value) in options {
            text.push_str(&format!("auth_opt_{key} {value}\n"));
        }
        fs::write(&config, text).unwrap();
        let mut command = self.command(&self.binary);
        command.arg("-c").arg(config);
        (Process::start(dir, &mut command, port), port)
    }
}

struct Process {
    child: Child,
    dir: TempDir,
}

impl Process {
    fn start(dir: TempDir, command: &mut Command, port: u16) -> Self {
        let log = File::create(dir.path().join("service.log")).unwrap();
        let child = command
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {:?}: {error}", command.get_program()));
        let mut process = Self { child, dir };
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if process.child.try_wait().unwrap().is_some() {
                panic!("{:?} exited: {}", command.get_program(), process.log());
            }
            if TcpStream::connect((HOST, port)).is_ok() {
                return process;
            }
            assert!(
                Instant::now() < end,
                "{:?} did not start: {}",
                command.get_program(),
                process.log()
            );
            thread::sleep(Duration::from_millis(30));
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("service.log")).unwrap_or_default()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run(command: &mut Command, stdin: Option<&str>) {
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {:?}: {error}", command.get_program()));
    if let Some(stdin) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{:?} failed: {}\n{}",
        command.get_program(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn port() -> u16 {
    TcpListener::bind((HOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn options(backend: &str, values: &[(&str, &str)]) -> Options {
    [
        ("backends", backend),
        ("acl_cacheseconds", "0"),
        ("log_quiet", "true"),
    ]
    .into_iter()
    .chain(values.iter().copied())
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

fn text(payload: &mut Vec<u8>, value: &str) {
    payload.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    payload.extend_from_slice(value.as_bytes());
}

fn send(socket: &mut TcpStream, packet_type: u8, data: &[u8]) {
    let len = u8::try_from(data.len()).unwrap();
    assert!(
        len < 128,
        "test packet exceeds one-byte MQTT remaining length"
    );
    socket.write_all(&[packet_type, len]).unwrap();
    socket.write_all(data).unwrap();
}

fn receive(socket: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; 2];
    if let Err(error) = socket.read_exact(&mut header) {
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        return None;
    }
    assert!(header[1] < 128);
    let mut payload = vec![0; header[1] as usize];
    socket.read_exact(&mut payload).unwrap();
    Some((header[0], payload))
}

fn connect(port: u16, user: &str, password: &str) -> (Verdict, TcpStream) {
    let mut socket = TcpStream::connect((HOST, port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut packet = b"\x00\x04MQTT\x04\xc2\x00\x0a".to_vec();
    for value in ["dbtest", user, password] {
        text(&mut packet, value);
    }
    send(&mut socket, 0x10, &packet);
    let verdict = match receive(&mut socket) {
        Some((0x20, value)) if value == [0, 0] => Verdict::Allow,
        Some((0x20, value)) if value == [0, 5] => Verdict::Deny,
        None => Verdict::Error,
        unexpected => panic!("unexpected CONNECT response: {unexpected:?}"),
    };
    (verdict, socket)
}

async fn acl(plugin: &dyn ExternalSecurity, user: &str, topic: &str, access: AclAccess) -> Verdict {
    let identity = plugin
        .acl_identity(Subject {
            client_id: "dbtest",
            username: Some(user),
            binding: Binding {
                credentials: true,
                ..Binding::default()
            },
        })
        .unwrap();
    plugin.authorize(&identity, topic, access).await.verdict
}

async fn parity(fixtures: &Fixtures, opts: &Options, user: &str, topics: &[(&str, Verdict)]) {
    let plugin = load(Library::AuthPlug, opts.clone(), true).await.unwrap();
    let (server, port) = fixtures.reference(opts);
    for (username, password, expected) in [
        (user, PASSWORD, Verdict::Allow),
        (user, "wrong", Verdict::Defer),
        ("missing", PASSWORD, Verdict::Defer),
    ] {
        let native = plugin
            .authenticate("dbtest", Some(username), Some(password.as_bytes()))
            .await;
        assert_eq!(native, expected);
        let (wire, mut socket) = connect(port, username, password);
        assert_eq!(
            wire,
            if native == Verdict::Defer {
                Verdict::Deny
            } else {
                native
            },
            "{}",
            server.log()
        );
        if wire == Verdict::Allow {
            for (i, &(topic, expected)) in topics.iter().enumerate() {
                let native = acl(&*plugin, username, topic, AclAccess::Subscribe).await;
                assert_eq!(native, expected, "native subscribe to {topic:?}");
                let id = u16::try_from(i + 1).unwrap().to_be_bytes();
                let mut packet = id.to_vec();
                text(&mut packet, topic);
                packet.push(0);
                send(&mut socket, 0x82, &packet);
                let wire = match receive(&mut socket) {
                    Some((0x90, value)) if value == [id[0], id[1], 0] => Verdict::Allow,
                    Some((0x90, value)) if value == [id[0], id[1], 0x80] => Verdict::Deny,
                    None => Verdict::Error,
                    unexpected => panic!("unexpected SUBSCRIBE response: {unexpected:?}"),
                };
                assert_eq!(
                    wire,
                    if native == Verdict::Defer {
                        Verdict::Deny
                    } else {
                        native
                    },
                    "{topic:?}: {}",
                    server.log()
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires auth-plug.so and Mosquitto 2.1.4 reference binaries"]
async fn sqlite_matches_auth_plug() {
    let fixtures = Fixtures::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("users.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE users(name, hash)").unwrap();
    db.execute(
        "INSERT INTO users VALUES (?1, ?2), (?1, 'second-row')",
        ("al'ice", HASH),
    )
    .unwrap();
    let opts = options(
        "sqlite",
        &[
            ("dbpath", path.to_str().unwrap()),
            (
                "sqliteuserquery",
                "SELECT hash, name FROM users WHERE name=?1 ORDER BY rowid",
            ),
        ],
    );
    parity(&fixtures, &opts, "al'ice", &[("any/topic", Verdict::Allow)]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Mosquitto 2.1.4 reference binaries"]
async fn postgres_matches_auth_plug() {
    let fixtures = Fixtures::new();
    let binaries = path("MOSQUITTO_AUTH_PLUG_POSTGRES");
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let port = port();
    run(
        fixtures
            .command(binaries.join("initdb"))
            .args([
                "--no-sync",
                "--no-locale",
                "--encoding=UTF8",
                "--auth=trust",
                "--username=mqtt",
                "-D",
            ])
            .arg(&data),
        None,
    );
    let mut command = fixtures.command(binaries.join("postgres"));
    command
        .arg("-D")
        .arg(&data)
        .args(["-h", HOST, "-p", &port.to_string(), "-k", ""]);
    let postgres = Process::start(dir, &mut command, port);
    // The listening socket may appear before the database accepts queries.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = fixtures.command(binaries.join("pg_isready"));
    ready.args([
        "-q",
        "-h",
        HOST,
        "-p",
        &port.to_string(),
        "-U",
        "mqtt",
        "-d",
        "postgres",
    ]);
    while !ready.status().unwrap().success() {
        assert!(
            Instant::now() < deadline,
            "PostgreSQL did not become ready:\n{}",
            postgres.log()
        );
        thread::sleep(Duration::from_millis(20));
    }
    let sql = format!(
        "CREATE TABLE users (name text, hash text, admin integer);\nINSERT INTO users VALUES ('al''ice', '{HASH}', 0);\nCREATE TABLE acl (name text, topic text, acc integer);\nINSERT INTO acl VALUES ('al''ice', 'units/%u', 4), ('al''ice', 'write', 2);\n"
    );
    run(
        fixtures.command(binaries.join("psql")).args([
            "-h",
            HOST,
            "-p",
            &port.to_string(),
            "-U",
            "mqtt",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
        ]),
        Some(&sql),
    );
    let mut opts = options(
        "postgres",
        &[
            ("host", HOST),
            ("port", &port.to_string()),
            ("user", "mqtt"),
            ("dbname", "postgres"),
            ("userquery", "SELECT hash FROM users WHERE name = $1"),
            ("superquery", "SELECT admin FROM users WHERE name = $1"),
            (
                "aclquery",
                "SELECT topic FROM acl WHERE name = $1 AND acc = $2",
            ),
        ],
    );
    parity(
        &fixtures,
        &opts,
        "al'ice",
        &[
            ("units/al'ice", Verdict::Allow),
            ("elsewhere", Verdict::Defer),
            ("write", Verdict::Defer),
        ],
    )
    .await;
    // Without a second SQL callback, the disconnecting operation must fail
    // before the later operation can use the reset connection.
    opts.retain(|(key, _)| key != "superquery");
    let plugin = load(Library::AuthPlug, opts, true).await.unwrap();
    assert_eq!(
        acl(&*plugin, "al'ice", "write", AclAccess::Write).await,
        Verdict::Allow
    );
    run(
        fixtures.command(binaries.join("psql")).args([
            "-h",
            HOST,
            "-p",
            &port.to_string(),
            "-U",
            "mqtt",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
        ]),
        Some(
            "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity WHERE usename='mqtt' AND pid<>pg_backend_pid();",
        ),
    );
    assert_eq!(
        acl(&*plugin, "al'ice", "write", AclAccess::Write).await,
        Verdict::Error
    );
    assert_eq!(
        acl(&*plugin, "al'ice", "write", AclAccess::Write).await,
        Verdict::Allow
    );
    drop(postgres);
    assert_eq!(
        plugin
            .authenticate("dbtest", Some("al'ice"), Some(PASSWORD.as_bytes()))
            .await,
        Verdict::Defer
    );
    assert_eq!(
        acl(&*plugin, "al'ice", "write", AclAccess::Write).await,
        Verdict::Error
    );
}

#[tokio::test]
#[ignore = "requires MariaDB and Mosquitto 2.1.4 reference binaries"]
async fn mysql_matches_auth_plug() {
    let fixtures = Fixtures::new();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let socket = dir.path().join("mariadb.sock");
    let pid = dir.path().join("mariadb.pid");
    let port = port();
    let location = format!("--basedir={}", fixtures.usr.display());
    let data = format!("--datadir={}", data.display());
    let tmpdir = format!("--tmpdir={}", dir.path().display());
    let socket = format!("--socket={}", socket.display());
    let pid = format!("--pid-file={}", pid.display());
    run(
        fixtures
            .command(fixtures.usr.join("bin/mariadb-install-db"))
            .args([
                "--no-defaults",
                &location,
                &data,
                &tmpdir,
                "--skip-test-db",
                "--force",
                "--auth-root-authentication-method=normal",
            ]),
        None,
    );
    let mut command = fixtures.command(fixtures.usr.join("sbin/mariadbd"));
    command.args([
        "--no-defaults",
        &location,
        &data,
        &tmpdir,
        &socket,
        &pid,
        "--bind-address",
        HOST,
        "--port",
        &port.to_string(),
        "--skip-name-resolve",
    ]);
    let database = Process::start(dir, &mut command, port);
    let sql = format!(
        "CREATE DATABASE mqtt; USE mqtt;\nCREATE TABLE users (name VARCHAR(80), client VARCHAR(80), hash VARCHAR(128), admin INT);\nINSERT INTO users VALUES ('al''ice', 'dbtest', '{HASH}', 0);\nCREATE TABLE acl (name VARCHAR(80), topic VARCHAR(100), acc integer);\nINSERT INTO acl VALUES ('al''ice', 'units/%u', 4), ('al''ice', 'write', 2);\nCREATE USER 'mqtt'@'127.0.0.1' IDENTIFIED BY 'db-password';\nGRANT SELECT ON mqtt.* TO 'mqtt'@'127.0.0.1';\n"
    );
    run(
        fixtures.command(fixtures.usr.join("bin/mariadb")).args([
            "--no-defaults",
            &socket,
            "-u",
            "root",
        ]),
        Some(&sql),
    );
    let opts = options(
        "mysql",
        &[
            ("host", HOST),
            ("port", &port.to_string()),
            ("user", "mqtt"),
            ("pass", "db-password"),
            ("dbname", "mqtt"),
            (
                "userquery",
                "SELECT hash FROM users WHERE name='%s' AND client='%s'",
            ),
            ("superquery", "SELECT admin FROM users WHERE name='%s'"),
            (
                "aclquery",
                "SELECT topic FROM acl WHERE name='%s' AND acc=%d",
            ),
        ],
    );
    parity(
        &fixtures,
        &opts,
        "al'ice",
        &[
            ("units/al'ice", Verdict::Allow),
            ("elsewhere", Verdict::Defer),
            ("write", Verdict::Defer),
        ],
    )
    .await;
    let plugin = load(Library::AuthPlug, opts, true).await.unwrap();
    run(
        fixtures.command(fixtures.usr.join("bin/mariadb")).args([
            "--no-defaults",
            &socket,
            "-u",
            "root",
        ]),
        Some("KILL USER mqtt;"),
    );
    assert_eq!(
        acl(&*plugin, "al'ice", "write", AclAccess::Write).await,
        Verdict::Allow
    );
    drop(database);
    assert_eq!(
        plugin
            .authenticate("dbtest", Some("al'ice"), Some(PASSWORD.as_bytes()))
            .await,
        Verdict::Error
    );
}

#[tokio::test]
#[ignore = "requires OpenLDAP and Mosquitto 2.1.4 reference binaries"]
async fn ldap_matches_auth_plug() {
    let fixtures = Fixtures::new();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    fs::create_dir(&data).unwrap();
    let conf = dir.path().join("slapd.conf");
    let service = "cn=service,dc=test";
    let schema = fixtures.root.join("etc/ldap/schema");
    let module = fixtures.usr.join("lib/ldap");
    let port = port();
    fs::write(&conf, format!("include {}/core.schema\ninclude {}/cosine.schema\nmodulepath {}\nmoduleload back_mdb\npidfile {}/slapd.pid\nargsfile {}/slapd.args\ndatabase mdb\nmaxsize 10485760\nsuffix dc=test\nrootdn {service}\nrootpw service-password\ndirectory {}\n",
        schema.display(), schema.display(), module.display(), dir.path().display(), dir.path().display(), data.display())).unwrap();
    let url = format!("ldap://{HOST}:{port}");
    let mut command = fixtures.command(fixtures.usr.join("sbin/slapd"));
    command.arg("-f").arg(conf).args(["-d", "0", "-h", &url]);
    let _directory = Process::start(dir, &mut command, port);
    let ldif = format!(
        "dn: dc=test\nobjectClass: top\nobjectClass: domain\ndc: test\n\ndn: cn=alice,dc=test\nobjectClass: top\nobjectClass: person\ncn: alice\nsn: User\nuserPassword: {PASSWORD}\n"
    );
    run(
        fixtures.command(fixtures.usr.join("bin/ldapadd")).args([
            "-x",
            "-H",
            &url,
            "-D",
            service,
            "-w",
            "service-password",
        ]),
        Some(&ldif),
    );
    let search = format!("{url}/dc=test?cn?sub?(cn=@)");
    let opts = options(
        "ldap,files",
        &[
            ("ldap_uri", &search),
            ("binddn", service),
            ("bindpw", "service-password"),
            ("ldap_acl_deny", "true"),
        ],
    );
    // The v4 plug-in turns a backend DENY into DEFER, but must stop before
    // the files backend's unconditional ACL allow.
    parity(&fixtures, &opts, "alice", &[("any/topic", Verdict::Defer)]).await;
    let opts = options(
        "ldap",
        &[
            ("ldap_uri", &search),
            ("binddn", service),
            ("bindpw", "service-password"),
        ],
    );
    parity(&fixtures, &opts, "alice", &[("any/topic", Verdict::Allow)]).await;
    let bad_base = format!("{url}/dc=absent??sub?(cn=@)");
    let opts = options(
        "ldap",
        &[
            ("ldap_uri", &bad_base),
            ("binddn", service),
            ("bindpw", "service-password"),
        ],
    );
    let plugin = load(Library::AuthPlug, opts, true).await.unwrap();
    assert_eq!(
        plugin
            .authenticate("dbtest", Some("alice"), Some(PASSWORD.as_bytes()))
            .await,
        Verdict::Error
    );
}

#[tokio::test]
#[ignore = "requires mongod fixture; no C MongoDB reference backend"]
async fn mongodb_matches_c_source_verdicts() {
    let fixtures = Fixtures::new();
    let binary = path("MONGOD");
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    fs::create_dir(&data).unwrap();
    let port = port();
    let mut command = fixtures.command(binary);
    command
        .args([
            "--bind_ip",
            HOST,
            "--port",
            &port.to_string(),
            "--nounixsocket",
            "--dbpath",
        ])
        .arg(data);
    let database = Process::start(dir, &mut command, port);
    let uri = format!("mongodb://{HOST}:{port}/?serverSelectionTimeoutMS=500");
    let client = Client::with_uri_str(&uri).await.unwrap();
    let db = client.database("mqGate");
    let foreign = ObjectId::new();
    db.collection("users").insert_many([
        doc! {"username":"alice", "password":HASH, "superuser":0, "topics":{"read/#":"r", "write/#":"w", "all/%u":"rw"}, "foreign":foreign},
        doc! {"username":"array", "password":HASH, "topics":["public/#"], "foreign": 7},
        doc! {"username":"text", "password":HASH, "foreign":"text-list"},
        doc! {"username":"admin", "password":HASH, "superuser":""},
        doc! {"username":"zero", "password":HASH, "foreign":0},
    ]).await.unwrap();
    db.collection("topics")
        .insert_many([
            doc! {"_id":foreign, "topics":{"foreign/#":"rw"}},
            doc! {"_id":7_i64, "topics":["number/#"]},
            doc! {"_id":"text-list", "topics":["string/#"]},
            doc! {"_id":0, "topics":["forbidden/#"]},
        ])
        .await
        .unwrap();
    let opts = options(
        "mongo",
        &[
            ("mongo_uri", &uri),
            ("mongo_host", "invalid"),
            ("mongo_user_topiclist_fk_prop", "foreign"),
        ],
    );
    let plugin = load(Library::AuthPlug, opts, true).await.unwrap();
    assert_eq!(
        plugin
            .authenticate("dbtest", Some("alice"), Some(PASSWORD.as_bytes()))
            .await,
        Verdict::Allow
    );
    assert_eq!(
        plugin
            .authenticate("dbtest", Some("missing"), Some(PASSWORD.as_bytes()))
            .await,
        Verdict::Defer
    );
    for (user, topic, access, expected) in [
        ("alice", "read/one", AclAccess::Read, Verdict::Allow),
        ("alice", "read/one", AclAccess::Subscribe, Verdict::Defer),
        ("alice", "write/one", AclAccess::Write, Verdict::Allow),
        ("alice", "write/one", AclAccess::Subscribe, Verdict::Defer),
        ("alice", "all/alice", AclAccess::Subscribe, Verdict::Allow),
        ("alice", "foreign/one", AclAccess::Subscribe, Verdict::Allow),
        ("array", "public/one", AclAccess::Subscribe, Verdict::Allow),
        ("array", "number/one", AclAccess::Subscribe, Verdict::Allow),
        ("text", "string/one", AclAccess::Subscribe, Verdict::Allow),
        ("admin", "any/topic", AclAccess::Subscribe, Verdict::Allow),
        ("zero", "forbidden/one", AclAccess::Read, Verdict::Defer),
    ] {
        assert_eq!(acl(&*plugin, user, topic, access).await, expected);
    }
    drop(database);
    assert_eq!(
        plugin
            .authenticate("dbtest", Some("alice"), Some(PASSWORD.as_bytes()))
            .await,
        Verdict::Defer
    );
}
