//! go-auth's backend configuration and ordered checks.

use std::collections::HashMap;

use crate::backend::LoadError;

use super::{
    backend::{Backend, BackendError, Init, Level, Log, Options},
    backends, exact_true, hashing, spaces_true,
};

pub(super) struct Routing {
    backends: HashMap<&'static str, Box<dyn Backend>>,
    order: Vec<&'static str>,
    user: Vec<&'static str>,
    superuser: Vec<&'static str>,
    acl: Vec<&'static str>,
    prefixes: Vec<(String, &'static str)>,
    strip_prefix: bool,
    exhaust_first: bool,
    log: Log,
}

// backends/backends.go: allowedBackendsOptsPrefix.
fn backend_option(name: &str) -> Option<(&'static str, &'static str)> {
    Some(match name {
        "postgres" => ("postgres", "pg"),
        "jwt" => ("jwt", "jwt"),
        "redis" => ("redis", "redis"),
        "http" => ("http", "http"),
        "files" => ("files", "files"),
        "mysql" => ("mysql", "mysql"),
        "sqlite" => ("sqlite", "sqlite"),
        "mongo" => ("mongo", "mongo"),
        "plugin" => ("plugin", "plugin"),
        "grpc" => ("grpc", "grpc"),
        "js" => ("js", "js"),
        "ldap" => ("ldap", "ldap"),
        _ => return None,
    })
}

impl Routing {
    pub(super) async fn new(options: &Options, level: Level, log: Log) -> Result<Self, LoadError> {
        // backends/backends.go: Initialize validates the entire list before
        // initializing any backend. Duplicates are parsed and created again.
        let parsed = (|| {
            let configured = options
                .get("backends")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LoadError::new("missing or blank option backends"))?;
            configured
                .replace(' ', "")
                .split(',')
                .map(|name| {
                    backend_option(name)
                        .ok_or_else(|| LoadError::new(format!("unknown backend {name}")))
                })
                .collect::<Result<Vec<_>, _>>()
        })();
        let parsed = parsed.inspect_err(|err| init_error(&log, err))?;
        let mut routing = Self {
            backends: HashMap::with_capacity(parsed.len()),
            order: Vec::with_capacity(parsed.len()),
            user: Vec::new(),
            superuser: Vec::new(),
            acl: Vec::new(),
            prefixes: Vec::new(),
            strip_prefix: false,
            exhaust_first: exact_true(options, "exhaust_backend_first"),
            log,
        };
        for &(name, prefix) in &parsed {
            // backends/backends.go: addBackends creates a hasher before the
            // selected constructor sets logrus's level (except gRPC).
            let hasher = hashing::new(options, prefix, &routing.log);
            if name != "grpc" && name != "plugin" {
                routing.log.set_level(level);
            }
            let headline = if name == "postgres" {
                "backend"
            } else {
                "Backend"
            };
            let init = Init {
                options,
                hasher,
                log: routing.log.clone(),
                // auth-plugin.c: mosquitto_auth_plugin_init uses the
                // libmosquitto header version (2.1.0 in Mosquitto 2.1.4).
                version: "2.1.0",
            };
            let result = match name {
                "js" => Err(LoadError::new(
                    "the js backend is not supported by MQExtended",
                )),
                "plugin" => Err(LoadError::new(
                    "custom Go plugin shared objects are not supported by MQExtended",
                )),
                "jwt" if options.get("jwt_mode").is_some_and(|mode| mode == "js") => {
                    Err(LoadError::new("jwt_mode js is not supported by MQExtended"))
                }
                _ => backends::create(name, init).await,
            };
            let backend = result.inspect_err(|err| {
                routing.log.log(Level::Fatal, format_args!(
                    "{headline} register error: couldn't initialize {name} backend with error {err}."
                ));
            })?;
            if routing.log.enabled(Level::Info) {
                routing
                    .log
                    .info(format_args!("{headline} registered: {}", backend.name()));
            }
            routing.order.push(name);
            routing.backends.insert(name, backend);
        }
        routing
            .set_checkers(options, &parsed)
            .inspect_err(|err| init_error(&routing.log, err))?;
        routing.set_prefixes(options);
        Ok(routing)
    }

    // backends/backends.go: setCheckers. Each checker list retains repeated
    // backend entries and repeated checker options; exhaust mode tests membership.
    fn set_checkers(
        &mut self,
        options: &Options,
        parsed: &[(&'static str, &'static str)],
    ) -> Result<(), LoadError> {
        let disable_superuser = exact_true(options, "disable_superuser");
        for &(name, prefix) in parsed {
            let configured = options
                .get(&format!("{prefix}_register"))
                .map(|value| value.replace(' ', ""));
            for check in configured
                .as_deref()
                .unwrap_or("acl,user,superuser")
                .split(',')
            {
                match check {
                    "acl" => &mut self.acl,
                    "user" => &mut self.user,
                    "superuser" if !disable_superuser => &mut self.superuser,
                    "superuser" => continue,
                    _ => {
                        return Err(LoadError::new(format!(
                            "unsupported check {check} found for backend {name}"
                        )));
                    }
                }
                .push(name);
                self.log
                    .info(format_args!("registered {check} checker: {name}"));
            }
        }
        if self.user.is_empty() && self.acl.is_empty() {
            return Err(LoadError::new("no backends registered"));
        }
        Ok(())
    }

    // backends/backends.go: setPrefixes, lookupPrefix, getPrefixForBackend.
    fn set_prefixes(&mut self, options: &Options) {
        if !spaces_true(options, "check_prefix") {
            return;
        }
        let Some(prefixes) = options.get("prefixes") else {
            self.log.warn(format_args!(
                "Error: prefixes enabled but no options given, defaulting to prefixes disabled."
            ));
            return;
        };
        let stripped = prefixes.replace(' ', "");
        let count = stripped.split(',').count();
        if count != self.order.len() {
            self.log.error(format_args!(
                "Error: got {} backends and {count} prefixes, defaulting to prefixes disabled.",
                self.order.len()
            ));
            return;
        }
        self.strip_prefix = exact_true(options, "strip_prefix");
        for (prefix, &name) in stripped.split(',').zip(&self.order) {
            if let Some((_, backend)) = self.prefixes.iter_mut().find(|(key, _)| key == prefix) {
                *backend = name;
            } else {
                self.prefixes.push((prefix.to_owned(), name));
            }
        }
        self.log.info(format_args!(
            "prefixes enabled for backends {} with prefixes {prefixes}.",
            options["backends"]
        ));
    }

    fn for_prefix<'a>(&self, username: &'a str) -> Option<(&'static str, &'a str)> {
        if self.prefixes.is_empty() {
            return None;
        }
        let (prefix, rest) = username.split_once('_')?;
        if prefix.is_empty() {
            return None;
        }
        let name = self.prefixes.iter().find(|(key, _)| key == prefix)?.1;
        self.log.debug(format_args!(
            "Found prefix for user {username}, using backend {name}."
        ));
        // Go chooses an arbitrary reverse mapping if a backend has several
        // prefixes. Choose the first configured mapping that survives overwrites.
        let strip = (name == "jwt" || self.strip_prefix)
            && self
                .prefixes
                .iter()
                .find(|(_, backend)| *backend == name)
                .is_some_and(|(key, _)| key == prefix);
        Some((name, if strip { rest } else { username }))
    }

    // backends/backends.go: AuthUnpwdCheck, checkAuth.
    pub(super) async fn check_user(
        &self,
        username: &str,
        password: &[u8],
        client_id: &str,
    ) -> Result<bool, BackendError> {
        if let Some((name, username)) = self.for_prefix(username) {
            if !self.user.contains(&name) {
                return Err(BackendError::new(format!(
                    "backend {name} not registered to check users"
                )));
            }
            return self
                .user_check(name, username, password, client_id, false)
                .await;
        }
        let mut error = None;
        for &name in &self.user {
            if granted(
                self.user_check(name, username, password, client_id, true)
                    .await,
                &mut error,
            ) {
                return Ok(true);
            }
        }
        error.map_or(Ok(false), Err)
    }

    async fn user_check(
        &self,
        name: &str,
        username: &str,
        password: &[u8],
        client_id: &str,
        report_start: bool,
    ) -> Result<bool, BackendError> {
        let backend = &self.backends[name];
        if report_start && self.log.enabled(Level::Debug) {
            self.log.debug(format_args!(
                "checking user {username} with backend {}",
                backend.name()
            ));
        }
        let result = backend.get_user(username, password, client_id).await;
        if result == Ok(true) && self.log.enabled(Level::Debug) {
            self.log.debug(format_args!(
                "user {username} authenticated with backend {}",
                backend.name()
            ));
        }
        result
    }

    // backends/backends.go: AuthAclCheck, exhaustBackendsInOrder, checkSuperuserThenACL.
    pub(super) async fn check_acl(
        &self,
        username: &str,
        topic: &str,
        client_id: &str,
        access: i32,
    ) -> (bool, Option<BackendError>) {
        let mut error = None;
        if let Some((name, username)) = self.for_prefix(username) {
            let mut allowed = self.superuser.contains(&name)
                && granted(self.super_check(name, username, true).await, &mut error);
            if !allowed {
                if !self.acl.contains(&name) {
                    return (
                        false,
                        Some(BackendError::new(format!(
                            "backend {name} not registered to check acls"
                        ))),
                    );
                }
                allowed = granted(
                    self.acl_check(name, username, topic, client_id, access, true)
                        .await,
                    &mut error,
                );
            }
            self.log
                .debug(format_args!("Acl is {allowed} for user {username}"));
            return (allowed, error);
        }
        if self.exhaust_first {
            for &name in &self.order {
                if self.superuser.contains(&name)
                    && granted(self.super_check(name, username, false).await, &mut error)
                {
                    return (true, None);
                }
                if self.acl.contains(&name)
                    && granted(
                        self.acl_check(name, username, topic, client_id, access, false)
                            .await,
                        &mut error,
                    )
                {
                    return (true, None);
                }
            }
        } else {
            for &name in &self.superuser {
                if granted(self.super_check(name, username, false).await, &mut error) {
                    return (true, None);
                }
            }
            for &name in &self.acl {
                if granted(
                    self.acl_check(name, username, topic, client_id, access, true)
                        .await,
                    &mut error,
                ) {
                    return (true, None);
                }
            }
        }
        (false, error)
    }

    async fn super_check(
        &self,
        name: &str,
        username: &str,
        capitalized: bool,
    ) -> Result<bool, BackendError> {
        let backend = &self.backends[name];
        if self.log.enabled(Level::Debug) {
            let label = if capitalized {
                "Superuser"
            } else {
                "superuser"
            };
            self.log.debug(format_args!(
                "{label} check with backend {}",
                backend.name()
            ));
        }
        let result = backend.get_superuser(username).await;
        if result == Ok(true) && self.log.enabled(Level::Debug) {
            self.log.debug(format_args!(
                "superuser {username} acl authenticated with backend {}",
                backend.name()
            ));
        }
        result
    }

    async fn acl_check(
        &self,
        name: &str,
        username: &str,
        topic: &str,
        client_id: &str,
        access: i32,
        capitalized: bool,
    ) -> Result<bool, BackendError> {
        let backend = &self.backends[name];
        if self.log.enabled(Level::Debug) {
            let label = if capitalized { "Acl" } else { "acl" };
            self.log.debug(format_args!(
                "{label} check with backend {}",
                backend.name()
            ));
        }
        let result = backend.check_acl(username, topic, client_id, access).await;
        if result == Ok(true) && self.log.enabled(Level::Debug) {
            self.log.debug(format_args!(
                "user {username} acl authenticated with backend {}",
                backend.name()
            ));
        }
        result
    }

    // backends/backends.go: Halt uses the map, not the backend order.
    pub(super) async fn halt(&self) {
        for backend in self.backends.values() {
            backend.halt().await;
        }
    }
}

fn init_error(log: &Log, error: &LoadError) {
    log.log(
        Level::Fatal,
        format_args!("error initializing backends: {error}"),
    );
}

fn granted(result: Result<bool, BackendError>, error: &mut Option<BackendError>) -> bool {
    match result {
        Ok(value) => value,
        Err(err) => {
            if error.is_none() {
                *error = Some(err);
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use mqx_auth::external::BoxFuture;

    use super::*;
    use crate::goauth::retry;

    type CallLog = Arc<Mutex<Vec<(&'static str, &'static str, String)>>>;
    type Decision = Result<bool, BackendError>;

    struct Fake {
        name: &'static str,
        calls: CallLog,
        superuser: Decision,
        acl: Decision,
    }

    impl Fake {
        fn call<'a>(
            &'a self,
            check: &'static str,
            username: &str,
            result: Decision,
        ) -> BoxFuture<'a, Decision> {
            self.calls
                .lock()
                .unwrap()
                .push((self.name, check, username.to_owned()));
            Box::pin(std::future::ready(result))
        }
    }

    impl Backend for Fake {
        fn name(&self) -> String {
            self.name.to_owned()
        }

        fn get_user<'a>(
            &'a self,
            username: &'a str,
            password: &'a [u8],
            client_id: &'a str,
        ) -> BoxFuture<'a, Decision> {
            let result = if self.name == "files" {
                Err(BackendError::new("user error"))
            } else {
                Ok(password == b"pw" && client_id == "cid")
            };
            self.call("user", username, result)
        }

        fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Decision> {
            self.call("superuser", username, self.superuser.clone())
        }

        fn check_acl<'a>(
            &'a self,
            username: &'a str,
            _: &'a str,
            _: &'a str,
            _: i32,
        ) -> BoxFuture<'a, Decision> {
            self.call("acl", username, self.acl.clone())
        }
    }

    fn routing(options: &[(&str, &str)], calls: &CallLog) -> Routing {
        let mut options: Options = options
            .iter()
            .map(|&(key, value)| (key.into(), value.into()))
            .collect();
        options
            .entry("backends".into())
            .or_insert_with(|| "files,jwt".to_owned());
        let parsed: Vec<_> = options["backends"]
            .split(',')
            .map(|name| backend_option(name).unwrap())
            .collect();
        let mut routing = Routing {
            backends: [
                (
                    "files",
                    Box::new(Fake {
                        name: "files",
                        calls: calls.clone(),
                        superuser: Err(BackendError::new("superuser error")),
                        acl: Ok(true),
                    }) as Box<dyn Backend>,
                ),
                (
                    "jwt",
                    Box::new(Fake {
                        name: "jwt",
                        calls: calls.clone(),
                        superuser: Ok(true),
                        acl: Ok(false),
                    }) as Box<dyn Backend>,
                ),
            ]
            .into_iter()
            .collect(),
            order: parsed.iter().map(|&(name, _)| name).collect(),
            user: Vec::new(),
            acl: Vec::new(),
            superuser: Vec::new(),
            prefixes: Vec::new(),
            strip_prefix: false,
            exhaust_first: exact_true(&options, "exhaust_backend_first"),
            log: Log::new(Level::Panic, Box::new(std::io::sink())),
        };
        routing.set_checkers(&options, &parsed).unwrap();
        routing.set_prefixes(&options);
        routing
    }

    #[tokio::test]
    async fn ordered_grants_override_errors_but_prefix_keeps_superuser_error() {
        let calls = CallLog::default();
        for (exhaust, next_check) in [("false", ("jwt", "superuser")), ("true", ("files", "acl"))] {
            let router = routing(
                &[
                    ("exhaust_backend_first", exhaust),
                    ("check_prefix", " tr ue "),
                    ("prefixes", " f , j "),
                ],
                &calls,
            );
            assert_eq!(
                router.check_user("unknown_user", b"pw", "cid").await,
                Ok(true)
            );
            assert_eq!(
                router.check_acl("unknown_user", "a", "cid", 4).await,
                (true, None)
            );
            let history = std::mem::take(&mut *calls.lock().unwrap());
            assert_eq!(
                history,
                [
                    ("files", "user", "unknown_user".to_owned()),
                    ("jwt", "user", "unknown_user".to_owned()),
                    ("files", "superuser", "unknown_user".to_owned()),
                    (next_check.0, next_check.1, "unknown_user".to_owned()),
                ]
            );
            assert_eq!(router.check_user("j_token", b"pw", "cid").await, Ok(true));
            assert_eq!(
                router.check_acl("f_user", "a", "cid", 4).await,
                (true, Some(BackendError::new("superuser error")))
            );
            assert_eq!(
                *calls.lock().unwrap(),
                [
                    ("jwt", "user", "token".to_owned()),
                    ("files", "superuser", "f_user".to_owned()),
                    ("files", "acl", "f_user".to_owned()),
                ]
            );
            calls.lock().unwrap().clear();
        }
    }

    #[tokio::test]
    async fn duplicate_checkers_retry_whole_auth_and_missing_prefix_checker_errors() {
        let calls = CallLog::default();
        let router = routing(
            &[
                ("backends", "files,files,jwt"),
                ("files_register", "user ,user, acl"),
                ("jwt_register", "acl"),
                ("check_prefix", "true"),
                ("prefixes", " f, f, j"),
                ("strip_prefix", "true"),
                ("disable_superuser", "true"),
            ],
            &calls,
        );
        assert_eq!(
            router.check_user("j_token", b"pw", "cid").await,
            Err(BackendError::new(
                "backend jwt not registered to check users"
            ))
        );
        assert_eq!(
            retry(-1, false, || router.check_user("name", b"pw", "cid")).await,
            Ok(false)
        );
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(
            retry(2, false, || router.check_user("name", b"pw", "cid")).await,
            Err(BackendError::new("user error"))
        );
        assert_eq!(calls.lock().unwrap().len(), 12);
        calls.lock().unwrap().clear();
        assert_eq!(
            retry(2, false, || router.check_user("f_name", b"pw", "cid")).await,
            Err(BackendError::new("user error"))
        );
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            [
                ("files", "user", "name".to_owned()),
                ("files", "user", "name".to_owned()),
                ("files", "user", "name".to_owned())
            ]
        );
    }
}
