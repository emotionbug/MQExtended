use std::fs;
use std::path::Path;
use std::process::Command;

use super::*;
use services::{HASH, RedisMonitor};

const FILE_ACL: &str = "user alice\ntopic readwrite allowed\ntopic deny denied\n";

// Use separate subscriber and publisher connections so the cluster placement
// policy exercises ACLs for remote delivery as well as the original write.
fn exercise(target: Target, backend: &str, options: &str, allowed: &str) -> Harness {
    let mut h = broker(target, backend, options);
    let reader = connect(&mut h, "reader", "alice", SECRET, R::SUCCESS);
    connect(&mut h, "wrong", "alice", "wrong", R::NOT_AUTHORIZED);
    connect(&mut h, "unknown", "unknown", SECRET, R::NOT_AUTHORIZED);
    subscribe(&mut h, reader, 1, allowed, R::SUCCESS);
    subscribe(&mut h, reader, 2, "denied", R::NOT_AUTHORIZED);
    let writer = connect(&mut h, "writer", "alice", SECRET, R::SUCCESS);
    publish(&mut h, writer, 1, allowed, false, R::SUCCESS);
    delivery(&mut h, reader, allowed, b"value", false);
    publish(&mut h, writer, 2, "denied", false, R::NOT_AUTHORIZED);
    h
}

fn transcript(h: Harness) -> Trace {
    Trace {
        mqtt: h.into_transcript(),
        ..Trace::default()
    }
}

scenario!(files_backend, file_backend);
fn file_backend(target: Target) -> Trace {
    let dir = tempfile::tempdir().unwrap();
    transcript(exercise(target, "files", &files(&dir, FILE_ACL), "allowed"))
}

scenario!(sqlite_backend, sqlite);
fn sqlite(target: Target) -> Trace {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("auth.sqlite");
    services::run(
        Command::new(services::go_auth_path("MOSQUITTO_GO_AUTH_SEED"))
            .arg("sqlite")
            .arg(&source)
            .arg(HASH),
    );
    let options = format!(
        "auth_opt_sqlite_source {}\n\
         auth_opt_sqlite_userquery SELECT hash FROM users WHERE name = ?\n\
         auth_opt_sqlite_aclquery SELECT topic FROM acl WHERE name = ? AND access = ?\n",
        source.display(),
    );
    transcript(exercise(target, "sqlite", &options, "allowed"))
}

scenario!(postgres_backend, postgres);
fn postgres(target: Target) -> Trace {
    let (port, log) = services::traced_postgres();
    let options = format!(
        "auth_opt_pg_host 127.0.0.1\nauth_opt_pg_port {port}\n\
         auth_opt_pg_dbname postgres\nauth_opt_pg_user mqx\nauth_opt_pg_password fixture\n\
         auth_opt_pg_sslmode disable\n\
         auth_opt_pg_userquery SELECT hash FROM users WHERE name = $1 /* go-auth:user */\n\
         auth_opt_pg_superquery SELECT admin FROM users WHERE name = $1 /* go-auth:super */\n\
         auth_opt_pg_aclquery SELECT topic FROM acl WHERE name = $1 AND access = $2 /* go-auth:acl */\n"
    );
    trace_sql(target, "postgres", &options, log, |line| {
        line.contains("LOG:  statement: ") || line.contains("LOG:  execute ")
    })
}

scenario!(mysql_backend, mysql);
fn mysql(target: Target) -> Trace {
    let (port, log) = services::traced_mysql();
    let options = format!(
        "auth_opt_mysql_host 127.0.0.1\nauth_opt_mysql_port {port}\n\
         auth_opt_mysql_dbname mqtt\nauth_opt_mysql_user mqx\nauth_opt_mysql_password fixture\n\
         auth_opt_mysql_allow_native_passwords true\n\
         auth_opt_mysql_userquery SELECT hash FROM users WHERE name = ? /* go-auth:user */\n\
         auth_opt_mysql_superquery SELECT admin FROM users WHERE name = ? /* go-auth:super */\n\
         auth_opt_mysql_aclquery SELECT topic FROM acl WHERE name = ? AND access = ? /* go-auth:acl */\n"
    );
    trace_sql(target, "mysql", &options, log, |line| {
        line.contains(" Query\t") || line.contains(" Execute\t")
    })
}

fn trace_sql(
    target: Target,
    backend: &str,
    options: &str,
    log: &Path,
    is_execution: impl Fn(&str) -> bool,
) -> Trace {
    let start = fs::metadata(log).unwrap().len() as usize;
    let h = exercise(target, backend, options, "allowed");
    let output = fs::read_to_string(log).unwrap();
    // Statement text labels distinguish logical requests from prepares, init
    // queries, and differing wire representations of bound parameters.
    let queries: Vec<_> = output[start..]
        .lines()
        .filter(|line| is_execution(line))
        .filter_map(|line| line.split_once("/* go-auth:"))
        .map(|(_, tail)| tail.strip_suffix(" */").unwrap().to_owned())
        .collect();
    if matches!(target, Target::Mosquitto) {
        let mut expected = vec!["user"; 4];
        expected.extend(["acl"; 5]);
        expected.extend(["super"; 5]);
        let mut actual: Vec<_> = queries.iter().map(String::as_str).collect();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected, "{backend}: {}", &output[start..]);
    }
    Trace {
        queries,
        ..transcript(h)
    }
}

scenario!(redis_backend, redis);
fn redis(target: Target) -> Trace {
    let port = services::redis();
    services::redis_command(port, &["SADD", "alice:sacls", "allowed"]);
    services::redis_command(port, &["SADD", "common:rwacls", "%u/%c", "allowed"]);
    let monitor = RedisMonitor::start(port);
    let h = exercise(
        target,
        "redis",
        &format!(
            "auth_opt_redis_host 127.0.0.1\nauth_opt_redis_port {port}\nauth_opt_redis_db 0\n"
        ),
        "allowed",
    );
    let queries = monitor.take(port);
    if matches!(target, Target::Mosquitto) {
        let mut expected = vec!["GET alice"; 3];
        expected.push("GET unknown");
        expected.extend(["GET alice:su"; 5]);
        for key in ["alice", "common"] {
            expected.extend(std::iter::repeat_n(
                if key == "alice" {
                    "SMEMBERS alice:sacls"
                } else {
                    "SMEMBERS common:sacls"
                },
                2,
            ));
            expected.extend(std::iter::repeat_n(
                if key == "alice" {
                    "SMEMBERS alice:wacls"
                } else {
                    "SMEMBERS common:wacls"
                },
                2,
            ));
            expected.extend(std::iter::repeat_n(
                if key == "alice" {
                    "SMEMBERS alice:rwacls"
                } else {
                    "SMEMBERS common:rwacls"
                },
                3,
            ));
        }
        expected.extend(["SMEMBERS alice:racls", "SMEMBERS common:racls"]);
        let mut actual: Vec<_> = queries.iter().map(String::as_str).collect();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }
    Trace {
        queries,
        ..transcript(h)
    }
}

scenario!(mongo_backend, mongo);
fn mongo(target: Target) -> Trace {
    transcript(exercise(
        target,
        "mongo",
        &format!(
            "auth_opt_mongo_host 127.0.0.1\nauth_opt_mongo_port {}\n",
            services::mongo()
        ),
        "allowed",
    ))
}

scenario!(ldap_backend, ldap);
fn ldap(target: Target) -> Trace {
    transcript(exercise(
        target,
        "ldap",
        &format!(
            "auth_opt_ldap_url ldap://127.0.0.1:{}\n\
         auth_opt_ldap_user_dn dc=example,dc=test\nauth_opt_ldap_bind_dn cn=admin,dc=example,dc=test\n\
         auth_opt_ldap_bind_password fixture\nauth_opt_ldap_user_filter (cn=%s)\n\
         auth_opt_ldap_group_dn dc=example,dc=test\nauth_opt_ldap_group_filter (cn=%s)\n\
         auth_opt_ldap_acl_topic_pattern_attribute cn\n",
            services::ldap()
        ),
        "alice",
    ))
}
