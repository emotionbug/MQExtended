//! Differential test: the real Mosquitto 2.1.4 broker and `AclFile::check`
//! must make the same read/write decisions for the same `acl_file`.
//!
//! Decisions are observed through retained messages so no timing is involved:
//! a read is allowed iff the subscriber receives the retained message, a write
//! is allowed iff the published retained message is stored.
//!
//! Run with `MOSQUITTO_BUILD_DIR=/path/to/mosquitto/build cargo test -p mqx-auth -- --ignored`.

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mqx_auth::{Access, AclFile, BasicAuth, PasswordFile};

const ACL: &str = "\
topic read public/#
topic write anon/out
topic deny public/secret

user alice
topic readwrite alice/#
topic read shared/+/data
topic deny alice/private

user bob
topic read bob/in
topic write bob/out

user writer
topic write #
topic write $test/#

user observer
topic read #
topic read $test/#

pattern readwrite devices/%c/#
pattern read users/%u/inbox
pattern deny devices/%c/locked
";

const PASSWORD: &str = "pw";

struct Bins {
    broker: PathBuf,
    publish: PathBuf,
    subscribe: PathBuf,
    passwd: PathBuf,
}

impl Bins {
    fn from_env() -> Self {
        let dir = PathBuf::from(
            std::env::var("MOSQUITTO_BUILD_DIR")
                .expect("set MOSQUITTO_BUILD_DIR to a Mosquitto 2.1.4 build directory"),
        );
        let bins = Self {
            broker: dir.join("src/mosquitto"),
            publish: dir.join("client/mosquitto_pub"),
            subscribe: dir.join("client/mosquitto_sub"),
            passwd: dir.join("apps/mosquitto_passwd/mosquitto_passwd"),
        };
        for bin in [&bins.broker, &bins.publish, &bins.subscribe, &bins.passwd] {
            assert!(bin.is_file(), "missing Mosquitto binary {}", bin.display());
        }
        bins
    }
}

struct Broker {
    child: Child,
    port: u16,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy)]
struct Identity<'a> {
    client_id: &'a str,
    username: Option<&'a str>,
}

const WRITER: Identity<'static> = Identity {
    client_id: "acl-writer",
    username: Some("writer"),
};
const OBSERVER: Identity<'static> = Identity {
    client_id: "acl-observer",
    username: Some("observer"),
};

fn auth_args(cmd: &mut Command, port: u16, who: Identity<'_>) {
    cmd.args([
        "-h",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-i",
        who.client_id,
    ]);
    if let Some(user) = who.username {
        cmd.args(["-u", user, "-P", PASSWORD]);
    }
}

fn publish_retained(bins: &Bins, port: u16, who: Identity<'_>, topic: &str, payload: Option<&str>) {
    let mut cmd = Command::new(&bins.publish);
    auth_args(&mut cmd, port, who);
    cmd.args(["-q", "1", "-r", "-t", topic]);
    match payload {
        Some(p) => cmd.args(["-m", p]),
        None => cmd.arg("-n"),
    };
    let status = cmd.status().expect("run mosquitto_pub");
    assert!(status.success(), "mosquitto_pub failed for {topic}");
}

fn receives_retained(
    bins: &Bins,
    port: u16,
    who: Identity<'_>,
    topic: &str,
    payload: &str,
) -> bool {
    let mut cmd = Command::new(&bins.subscribe);
    auth_args(&mut cmd, port, who);
    cmd.args(["-q", "1", "-C", "1", "-W", "1", "-t", topic]);
    let out = cmd
        .stderr(Stdio::null())
        .output()
        .expect("run mosquitto_sub");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l == payload)
}

fn start_broker(bins: &Bins, dir: &Path) -> Broker {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let pwfile = dir.join("passwords");
    for (i, user) in ["alice", "bob", "carol", "writer", "observer", "a+b"]
        .iter()
        .enumerate()
    {
        let mut cmd = Command::new(&bins.passwd);
        if i == 0 {
            cmd.arg("-c");
        }
        let status = cmd
            .args(["-b"])
            .arg(&pwfile)
            .args([user, PASSWORD])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
    std::fs::write(dir.join("acl"), ACL).unwrap();
    let conf = dir.join("mosquitto.conf");
    std::fs::write(
        &conf,
        format!(
            "listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\nlog_dest none\npassword_file {}\nacl_file {}\n",
            pwfile.display(),
            dir.join("acl").display()
        ),
    )
    .unwrap();
    let child = Command::new(&bins.broker)
        .arg("-c")
        .arg(&conf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start mosquitto");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "mosquitto did not start listening"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Broker { child, port }
}

#[test]
#[ignore = "needs MOSQUITTO_BUILD_DIR"]
fn acl_decisions_match_mosquitto() {
    let bins = Bins::from_env();
    let dir = std::env::temp_dir().join(format!("mqx-acl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let broker = start_broker(&bins, &dir);
    let port = broker.port;

    let acl = AclFile::parse(ACL.as_bytes()).unwrap();
    let passwords = PasswordFile::load(&dir.join("passwords")).unwrap();

    let anon = |client_id| Identity {
        client_id,
        username: None,
    };
    let user = |client_id, username| Identity {
        client_id,
        username: Some(username),
    };
    let cases: &[(Identity<'_>, &str, Access)] = &[
        (anon("a1"), "public/x", Access::Read),
        (anon("a1"), "public/x", Access::Write),
        (anon("a1"), "public/secret", Access::Read),
        (anon("a1"), "anon/out", Access::Write),
        (anon("a1"), "alice/x", Access::Read),
        (anon("dev1"), "devices/dev1/t", Access::Write),
        (anon("dev1"), "devices/dev2/t", Access::Write),
        (anon("dev1"), "devices/dev1/locked", Access::Write),
        (anon("dev1"), "users/dev1/inbox", Access::Read),
        (anon("dev+"), "devices/devx/t", Access::Write),
        (user("c-alice", "alice"), "alice/x", Access::Write),
        (user("c-alice", "alice"), "alice/private", Access::Read),
        (user("c-alice", "alice"), "shared/a/data", Access::Read),
        (user("c-alice", "alice"), "shared/a/b/data", Access::Read),
        (user("c-alice", "alice"), "public/x", Access::Read),
        (user("c-alice", "alice"), "users/alice/inbox", Access::Read),
        (user("c-alice", "alice"), "users/bob/inbox", Access::Read),
        (user("c-alice", "alice"), "$test/x", Access::Read),
        (user("c-bob", "bob"), "bob/in", Access::Read),
        (user("c-bob", "bob"), "bob/in", Access::Write),
        (user("c-bob", "bob"), "bob/out", Access::Write),
        (user("c-carol", "carol"), "devices/c-carol/x", Access::Write),
        (user("c-carol", "carol"), "public/x", Access::Read),
        (user("c-ab", "a+b"), "anon/out", Access::Write),
    ];

    let mut mismatches = Vec::new();
    for (i, &(who, topic, access)) in cases.iter().enumerate() {
        if let Some(name) = who.username {
            assert_eq!(
                passwords.check(Some(name), Some(PASSWORD.as_bytes())),
                BasicAuth::Allow
            );
        }
        let payload = format!("case-{i}");
        let mosquitto = match access {
            Access::Read => {
                publish_retained(&bins, port, WRITER, topic, Some(&payload));
                receives_retained(&bins, port, who, topic, &payload)
            }
            Access::Write => {
                publish_retained(&bins, port, who, topic, Some(&payload));
                receives_retained(&bins, port, OBSERVER, topic, &payload)
            }
            Access::Subscribe | Access::Unsubscribe => unreachable!(),
        };
        publish_retained(&bins, port, WRITER, topic, None);
        let ours = acl.check(who.client_id, who.username, topic, access);
        if ours != mosquitto {
            mismatches.push(format!(
                "{} {:?} {topic} {access:?}: mosquitto={mosquitto} ours={ours}",
                who.client_id, who.username
            ));
        }
    }
    drop(broker);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        mismatches.is_empty(),
        "ACL decisions differ:\n{}",
        mismatches.join("\n")
    );
}
