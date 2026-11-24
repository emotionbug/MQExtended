use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use serde_json::{Value, json};

use super::*;
use services::{HttpWithBody, Reply};

fn options(port: u16, extra: &str) -> String {
    format!(
        "auth_opt_http_host 127.0.0.1\nauth_opt_http_port {port}\n\
         auth_opt_http_getuser_uri /user\nauth_opt_http_aclcheck_uri /acl\n{extra}"
    )
}

fn parse(request: &Request) -> Value {
    serde_json::from_str(&request.body).unwrap_or_else(|err| panic!("{request:?}: {err}"))
}

fn status(allowed: bool) -> Reply {
    Reply {
        status: if allowed { 200 } else { 403 },
        body: "",
    }
}

fn finish(h: Harness, server: &HttpWithBody) -> Trace {
    let requests = server.take_requests();
    Trace {
        mqtt: h.into_transcript(),
        requests,
        ..Trace::default()
    }
}

fn assert_json_requests(target: Target, trace: &Trace, expected: &[(&str, Value)]) {
    if !matches!(target, Target::Mosquitto) {
        return;
    }
    let mut actual: Vec<_> = trace
        .requests
        .iter()
        .map(|req| (req.uri.as_str(), parse(req).to_string()))
        .collect();
    let mut expected: Vec<_> = expected
        .iter()
        .map(|(uri, value)| (*uri, value.to_string()))
        .collect();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn user(username: &str, password: &str, clientid: &str) -> (&'static str, Value) {
    (
        "/user",
        json!({"username":username,"password":password,"clientid":clientid}),
    )
}

fn acl(username: &str, clientid: &str, topic: &str, acc: u8) -> (&'static str, Value) {
    (
        "/acl",
        json!({"username":username,"clientid":clientid,"topic":topic,"acc":acc}),
    )
}

scenario!(http_status_and_access_values, access_values);
fn access_values(target: Target) -> Trace {
    let server = HttpWithBody::start(|req| {
        let data = parse(req);
        status(match req.uri.as_str() {
            "/user" => data["password"] == SECRET,
            "/acl" => data["topic"] != "denied",
            _ => false,
        })
    });
    let mut h = broker(target, "http", &options(server.port, ""));
    let reader = connect(&mut h, "reader", "alice", SECRET, R::SUCCESS);
    let sender = connect_with(
        &mut h,
        "sender",
        Some("bob"),
        Some(SECRET),
        Some(v5::LastWill {
            properties: Vec::new(),
            topic: "events/will".into(),
            payload: Bytes::from_static(b"will"),
            qos: QoS::AtMostOnce,
            retain: false,
        }),
        R::SUCCESS,
    );
    subscribe(&mut h, reader, 1, "events/#", R::SUCCESS);
    subscribe(&mut h, reader, 2, "denied", R::NOT_AUTHORIZED);
    publish(&mut h, sender, 3, "events/data", false, R::SUCCESS);
    delivery(&mut h, reader, "events/data", b"value", false);
    publish(&mut h, sender, 4, "denied", false, R::NOT_AUTHORIZED);
    h.close_socket(sender);
    delivery(&mut h, reader, "events/will", b"will", false);
    unsubscribe(&mut h, reader, 5, "events/#");
    let trace = finish(h, server);
    assert_json_requests(
        target,
        &trace,
        &[
            user("alice", SECRET, "reader"),
            user("bob", SECRET, "sender"),
            acl("alice", "reader", "events/#", 4),
            acl("alice", "reader", "denied", 4),
            acl("bob", "sender", "events/data", 2),
            acl("alice", "reader", "events/data", 1),
            acl("bob", "sender", "denied", 2),
            acl("bob", "sender", "events/will", 2),
            acl("alice", "reader", "events/will", 1),
        ],
    );
    trace
}

scenario!(http_json_get, json_get);
fn json_get(target: Target) -> Trace {
    let server = HttpWithBody::start(|req| Reply {
        status: 200,
        body: if (req.uri == "/user" && parse(req)["password"] == SECRET)
            || (req.uri == "/acl" && parse(req)["topic"] == "allowed")
        {
            r#"{"ok":true}"#
        } else {
            r#"{"ok":false,"error":"denied"}"#
        },
    });
    let mut h = broker(
        target,
        "http",
        &options(
            server.port,
            "auth_opt_http_response_mode json\nauth_opt_http_method GET\nauth_opt_http_user_agent fixture-go-auth\n",
        ),
    );
    let c = connect(&mut h, "json", "alice", SECRET, R::SUCCESS);
    connect(&mut h, "wrong", "alice", "wrong", R::NOT_AUTHORIZED);
    subscribe(&mut h, c, 1, "allowed", R::SUCCESS);
    subscribe(&mut h, c, 2, "denied", R::NOT_AUTHORIZED);
    let trace = finish(h, server);
    if matches!(target, Target::Mosquitto) {
        for req in &trace.requests {
            assert_eq!(req.method, "GET");
            assert_eq!(req.header("content-type"), "application/json");
            assert_eq!(req.header("user-agent"), "fixture-go-auth");
        }
    }
    assert_json_requests(
        target,
        &trace,
        &[
            user("alice", SECRET, "json"),
            user("alice", "wrong", "wrong"),
            acl("alice", "json", "allowed", 4),
            acl("alice", "json", "denied", 4),
        ],
    );
    trace
}

scenario!(http_text_form, text_form);
fn text_form(target: Target) -> Trace {
    let server = HttpWithBody::start(|req| Reply {
        status: 200,
        body: if req.uri == "/user" { "ok" } else { "ok\n" },
    });
    let mut h = broker(
        target,
        "http",
        &options(
            server.port,
            "auth_opt_http_response_mode text\nauth_opt_http_params_mode form\nauth_opt_http_method PUT\nauth_opt_http_user_agent ignored-in-form-mode\n",
        ),
    );
    let c = connect(&mut h, "form", "alice", "s p+%&=", R::SUCCESS);
    subscribe(&mut h, c, 1, "some/topic/#", R::NOT_AUTHORIZED);
    let trace = finish(h, server);
    if matches!(target, Target::Mosquitto) {
        let body = |uri: &str| {
            trace
                .requests
                .iter()
                .find(|r| r.uri == uri)
                .unwrap()
                .body
                .as_str()
        };
        assert_eq!(trace.requests.len(), 2);
        assert_eq!(
            body("/user"),
            "clientid=form&password=s+p%2B%25%26%3D&username=alice"
        );
        assert_eq!(
            body("/acl"),
            "acc=4&clientid=form&topic=some%2Ftopic%2F%23&username=alice"
        );
        for req in &trace.requests {
            // backends/http.go: httpRequest uses PostForm even when PUT is configured.
            assert_eq!(req.method, "POST");
            assert_eq!(
                req.header("content-type"),
                "application/x-www-form-urlencoded"
            );
            assert_eq!(req.header("user-agent"), "Go-http-client/1.1");
        }
    }
    trace
}

scenario!(jwt_remote, jwt);
fn jwt(target: Target) -> Trace {
    let server = HttpWithBody::start(|req| {
        status(req.uri != "/su" && req.header("authorization") == "Bearer stub.jwt.token")
    });
    let mut h = broker(
        target,
        "jwt",
        &format!(
            "auth_opt_jwt_mode remote\nauth_opt_jwt_host 127.0.0.1\nauth_opt_jwt_port {}\n\
         auth_opt_jwt_getuser_uri /user\nauth_opt_jwt_aclcheck_uri /acl\nauth_opt_jwt_superuser_uri /su\n",
            server.port
        ),
    );
    let c = connect(&mut h, "jwt", "stub.jwt.token", "not-validated", R::SUCCESS);
    connect(&mut h, "bad", "bad.token", SECRET, R::NOT_AUTHORIZED);
    subscribe(&mut h, c, 1, "allowed", R::SUCCESS);
    let trace = finish(h, server);
    assert_json_requests(
        target,
        &trace,
        &[
            ("/user", Value::Null),
            ("/user", Value::Null),
            ("/su", Value::Null),
            ("/acl", json!({"clientid":"jwt","topic":"allowed","acc":4})),
        ],
    );
    trace
}

scenario!(null_credentials, null_credentials);
fn null_credentials(target: Target) -> Trace {
    let server = HttpWithBody::start(|_| status(true));
    let mut h = broker(target, "http", &options(server.port, ""));
    // auth-plugin.c: mosquitto_auth_unpwd_check refuses each NULL independently
    // before the backend can grant, despite allow_anonymous true.
    connect_with(&mut h, "anonymous", None, None, None, R::NOT_AUTHORIZED);
    connect_with(
        &mut h,
        "no-password",
        Some("alice"),
        None,
        None,
        R::NOT_AUTHORIZED,
    );
    connect_with(
        &mut h,
        "no-username",
        None,
        Some(SECRET),
        None,
        R::NOT_AUTHORIZED,
    );
    let trace = finish(h, server);
    assert_json_requests(target, &trace, &[]);
    trace
}

scenario!(strip_prefix, prefix);
fn prefix(target: Target) -> Trace {
    let server = HttpWithBody::start(|req| {
        let user = parse(req)["username"].clone();
        status(user == "alice" || user == "other_alice")
    });
    let dir = tempfile::tempdir().unwrap();
    let files = files(&dir, "user alice\ntopic readwrite allowed\n");
    let mut h = broker(
        target,
        "files,http",
        &options(
            server.port,
            &format!(
                "{files}auth_opt_check_prefix true\nauth_opt_prefixes local,net\nauth_opt_strip_prefix true\n"
            ),
        ),
    );
    let local = connect(&mut h, "local", "local_alice", SECRET, R::SUCCESS);
    let remote = connect(&mut h, "remote", "net_alice", SECRET, R::SUCCESS);
    let fallback = connect(&mut h, "fallback", "other_alice", SECRET, R::SUCCESS);
    subscribe(&mut h, local, 1, "allowed", R::SUCCESS);
    subscribe(&mut h, remote, 1, "allowed", R::SUCCESS);
    subscribe(&mut h, fallback, 1, "allowed", R::SUCCESS);
    let trace = finish(h, server);
    assert_json_requests(
        target,
        &trace,
        &[
            user("alice", SECRET, "remote"),
            user("other_alice", SECRET, "fallback"),
            acl("alice", "remote", "allowed", 4),
            acl("other_alice", "fallback", "allowed", 4),
        ],
    );
    trace
}

scenario!(superusers_first, |target| checker_order(target, false));
scenario!(exhaust_backend_first, |target| checker_order(target, true));
fn checker_order(target: Target, exhaust: bool) -> Trace {
    let server = HttpWithBody::start(|_| status(false));
    let dir = tempfile::tempdir().unwrap();
    let files = files(&dir, "user alice\ntopic readwrite allowed\n");
    let mut h = broker(
        target,
        "files,http",
        &options(
            server.port,
            &format!(
                "{files}auth_opt_http_superuser_uri /su\nauth_opt_exhaust_backend_first {exhaust}\n"
            ),
        ),
    );
    let c = connect(&mut h, "subscriber", "alice", SECRET, R::SUCCESS);
    subscribe(&mut h, c, 1, "allowed", R::SUCCESS);
    let trace = finish(h, server);
    let expected = [("/su", json!({"username":"alice"}))];
    assert_json_requests(target, &trace, if exhaust { &[] } else { &expected });
    trace
}

scenario!(retry_count, retry);
fn retry(target: Target) -> Trace {
    let mut auth_retried = false;
    let mut acl_retried = false;
    let server = HttpWithBody::start(move |req| {
        if req.uri == "/user" && parse(req)["password"] != SECRET {
            return status(false);
        }
        let retried = if req.uri == "/user" {
            &mut auth_retried
        } else {
            &mut acl_retried
        };
        if std::mem::replace(retried, true) {
            status(true)
        } else {
            Reply {
                status: 503,
                body: "temporarily unavailable",
            }
        }
    });
    let mut h = broker(
        target,
        "http",
        &options(server.port, "auth_opt_retry_count 1\n"),
    );
    let c = connect(&mut h, "retry", "alice", SECRET, R::SUCCESS);
    subscribe(&mut h, c, 1, "allowed", R::SUCCESS);
    connect(&mut h, "wrong", "alice", "wrong", R::NOT_AUTHORIZED);
    let trace = finish(h, server);
    assert_json_requests(
        target,
        &trace,
        &[
            user("alice", SECRET, "retry"),
            user("alice", SECRET, "retry"),
            acl("alice", "retry", "allowed", 4),
            acl("alice", "retry", "allowed", 4),
            user("alice", "wrong", "wrong"),
        ],
    );
    trace
}

scenario!(use_clientid_as_username, clientid);
fn clientid(target: Target) -> Trace {
    let server = HttpWithBody::start(|req| status(parse(req)["username"] == "effective"));
    let mut h = broker(
        target,
        "http",
        &options(server.port, "auth_opt_use_clientid_as_username true\n"),
    );
    let c = connect(&mut h, "effective", "supplied", SECRET, R::SUCCESS);
    subscribe(&mut h, c, 1, "allowed", R::SUCCESS);
    let trace = finish(h, server);
    assert_json_requests(
        target,
        &trace,
        &[
            user("effective", SECRET, "effective"),
            acl("effective", "effective", "allowed", 4),
        ],
    );
    trace
}

scenario!(memory_acl_cache, cache);
fn cache(target: Target) -> Trace {
    let revoked = Arc::new(AtomicBool::new(false));
    let state = Arc::clone(&revoked);
    let server =
        HttpWithBody::start(move |req| status(req.uri == "/user" || !state.load(Ordering::SeqCst)));
    let mut h = broker(
        target,
        "http",
        &options(
            server.port,
            "auth_opt_cache true\nauth_opt_cache_type memory\nauth_opt_acl_cache_seconds 2\n",
        ),
    );
    let c = connect(&mut h, "cached", "alice", SECRET, R::SUCCESS);
    subscribe(&mut h, c, 1, "cached", R::SUCCESS);
    revoked.store(true, Ordering::SeqCst);
    subscribe(&mut h, c, 2, "cached", R::SUCCESS);
    // Expire the previous decision; SUBACK observes the new backend decision.
    thread::sleep(Duration::from_millis(2200));
    subscribe(&mut h, c, 3, "cached", R::NOT_AUTHORIZED);
    let trace = finish(h, server);
    assert_json_requests(
        target,
        &trace,
        &[
            user("alice", SECRET, "cached"),
            acl("alice", "cached", "cached", 4),
            acl("alice", "cached", "cached", 4),
        ],
    );
    trace
}

scenario!(retained_source_recheck_on, |target| retained(target, true));
scenario!(retained_source_recheck_off, |target| retained(
    target, false
));
fn retained(target: Target, recheck: bool) -> Trace {
    let revoked = Arc::new(AtomicBool::new(false));
    let state = Arc::clone(&revoked);
    let server = HttpWithBody::start(move |req| {
        let data = parse(req);
        status(
            !(req.uri == "/acl"
                && data["clientid"] == "source"
                && data["acc"] == 2
                && state.load(Ordering::SeqCst)),
        )
    });
    let mut h = broker(
        target,
        "http",
        &options(server.port, &format!("check_retain_source {recheck}\n")),
    );
    let source = connect(&mut h, "source", "bob", SECRET, R::SUCCESS);
    publish(
        &mut h,
        source,
        1,
        "retained",
        true,
        R::NO_MATCHING_SUBSCRIBERS,
    );
    revoked.store(true, Ordering::SeqCst);
    let reader = connect(&mut h, "reader", "alice", SECRET, R::SUCCESS);
    subscribe(&mut h, reader, 1, "retained", R::SUCCESS);
    if !recheck {
        delivery(&mut h, reader, "retained", b"value", true);
    }
    // A live publication on the same stream is the barrier; a replay of the
    // revoked retained publish would arrive before this and fail the check.
    let marker = connect(&mut h, "marker", "alice", SECRET, R::SUCCESS);
    publish(&mut h, marker, 2, "retained", false, R::SUCCESS);
    delivery(&mut h, reader, "retained", b"value", false);
    let trace = finish(h, server);
    let mut expected = vec![
        user("bob", SECRET, "source"),
        user("alice", SECRET, "reader"),
        user("alice", SECRET, "marker"),
        acl("bob", "source", "retained", 2),
        acl("alice", "reader", "retained", 4),
        acl("alice", "reader", "retained", 1),
        acl("alice", "marker", "retained", 2),
        acl("alice", "reader", "retained", 1),
    ];
    if recheck {
        expected.push(acl("bob", "source", "retained", 2));
    }
    assert_json_requests(target, &trace, &expected);
    trace
}
