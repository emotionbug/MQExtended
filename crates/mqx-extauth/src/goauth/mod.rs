//! iegomez/mosquitto-go-auth, as Mosquitto 2.1.4 loads `go-auth.so` through
//! its v4 wrapper (`src/plugin_v4.c`) and the plugin's C shim
//! (`auth-plugin.c`).

pub(crate) mod backend;
pub(crate) mod backends;
mod cache;
mod hashing;
mod log;
pub(crate) mod redis;
mod routing;
pub(crate) mod topics;

use std::{
    fs::OpenOptions,
    io::{IsTerminal, Write as _},
    sync::Arc,
    time::Duration,
};

use mqx_auth::external::{
    AclAccess, AclIdentity, Authorization, BoxFuture, ExternalSecurity, Subject, Verdict,
};

use crate::backend::LoadError;

use self::{
    backend::{BackendError, Options},
    cache::Cache,
    log::{Level, Log},
    routing::Routing,
};

struct Plugin {
    routing: Routing,
    cache: Cache,
    retry_count: i64,
    use_clientid_as_username: bool,
    deny_special_chars: bool,
    log: Log,
}

// go-auth.go: AuthPluginInit. Its startup options are logged at the initial
// level; backend constructors can set the configured level when called.
pub(super) async fn load(
    options: Vec<(String, String)>,
    deny_special_chars: bool,
) -> Result<Arc<dyn ExternalSecurity>, LoadError> {
    let options: Options = options.into_iter().collect();
    let log = Log::stderr();
    let retry_count = options.get("retry_count").map_or(0, |value| {
        value.parse::<i64>().unwrap_or_else(|error| {
            let reason = parse_int_error(&error);
            log.warn(format_args!("couldn't parse retryCount (err: strconv.ParseInt: parsing {value:?}: {reason}), defaulting to 0"));
            0
        })
    });
    let use_clientid_as_username = spaces_true(&options, "use_clientid_as_username");
    if use_clientid_as_username {
        log.info(format_args!("clientid will be used as username on checks"));
    }
    let level = match options
        .get("log_level")
        .map(|value| value.replace(' ', ""))
        .as_deref()
    {
        Some("debug") => Level::Debug,
        None | Some("info") => Level::Info,
        Some("warn") => Level::Warn,
        Some("error") => Level::Error,
        Some("fatal") => Level::Fatal,
        Some("panic") => Level::Panic,
        Some(_) => {
            log.info(format_args!("log_level unkwown, using default info level"));
            Level::Info
        }
    };
    match options.get("log_dest").map(String::as_str) {
        Some("stdout") => {
            let stdout = std::io::stdout();
            let terminal = stdout.is_terminal();
            log.set_output(Box::new(stdout), terminal);
        }
        Some("file") => {
            if let Some(path) = options.get("log_file") {
                let mut file = OpenOptions::new();
                file.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    file.mode(0o644);
                }
                match file.open(path) {
                    Ok(file) => {
                        let terminal = file.is_terminal();
                        log.set_output(Box::new(file), terminal);
                    }
                    Err(err) => log.error(format_args!(
                        "failed to log to file, using default stderr: open {path}: {}",
                        os_error(&err)
                    )),
                }
            }
        }
        None => {}
        Some(_) => log.info(format_args!("log_dest unknown, using default stderr")),
    }
    let routing = Routing::new(&options, level, log.clone()).await?;
    let cache = Cache::new(&options, &log).await;
    Ok(Arc::new(Plugin {
        routing,
        cache,
        retry_count,
        use_clientid_as_username,
        deny_special_chars,
        log,
    }))
}

fn exact_true(options: &Options, key: &str) -> bool {
    options.get(key).is_some_and(|value| value == "true")
}

fn spaces_true(options: &Options, key: &str) -> bool {
    options
        .get(key)
        .is_some_and(|value| value.bytes().filter(|&byte| byte != b' ').eq(*b"true"))
}

fn parse_int_error(error: &std::num::ParseIntError) -> &'static str {
    if matches!(
        error.kind(),
        std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
    ) {
        "value out of range"
    } else {
        "invalid syntax"
    }
}

// Go's os.PathError prints strerror without Rust's "(os error N)" suffix.
fn os_error(error: &std::io::Error) -> String {
    let mut detail = error.to_string();
    if let Some(start) = detail.rfind(" (os error ") {
        detail.truncate(start);
    }
    if let Some(first) = detail.get_mut(..1) {
        first.make_ascii_lowercase();
    }
    detail
}

// go-auth.go: AuthUnpwdCheck, AuthAclCheck. Retry the entire operation on
// error; the inclusive range has no attempts for a negative retry count.
async fn retry<V, F: Future<Output = Result<V, BackendError>>>(
    count: i64,
    default: V,
    mut operation: impl FnMut() -> F,
) -> Result<V, BackendError> {
    let mut result = Ok(default);
    for _ in 0..=count {
        result = operation().await;
        if result.is_ok() {
            break;
        }
    }
    result
}

impl Plugin {
    // go-auth.go: setUsername.
    fn username<'a>(&self, username: &'a str, client_id: &'a str) -> &'a str {
        if self.use_clientid_as_username {
            client_id
        } else {
            username
        }
    }

    // go-auth.go: authUnpwdCheck. Redis write errors, unlike read errors,
    // fail the whole operation; retry starts with another cache lookup.
    async fn check_user(
        &self,
        username: &str,
        password: &[u8],
        client_id: &str,
    ) -> Result<bool, BackendError> {
        let record = self.cache.auth_record(username, password, &self.log);
        if let Some(record) = &record
            && let Some(allowed) = self.cache.get_auth(record, &self.log).await
        {
            self.log.debug(format_args!("found in cache: {username}"));
            return Ok(allowed);
        }
        let allowed = self
            .routing
            .check_user(username, password, client_id)
            .await?;
        if let Some(record) = record {
            self.log
                .debug(format_args!("setting auth cache for {username}"));
            self.cache
                .put_auth(record, allowed, &self.log)
                .await
                .inspect_err(|err| {
                    self.log.error(format_args!("set auth cache: {err}"));
                })?;
        }
        Ok(allowed)
    }

    // go-auth.go: authAclCheck.
    async fn check_acl(
        &self,
        username: &str,
        topic: &str,
        client_id: &str,
        access: i32,
    ) -> Result<bool, BackendError> {
        let record = self
            .cache
            .acl_record(username, topic, client_id, access, &self.log);
        if let Some(record) = &record
            && let Some(allowed) = self.cache.get_acl(record, &self.log).await
        {
            self.log.debug(format_args!("found in cache: {username}"));
            return Ok(allowed);
        }
        let (allowed, error) = self
            .routing
            .check_acl(username, topic, client_id, access)
            .await;
        if let Some(record) = &record
            && error.is_none()
        {
            self.log.debug(format_args!(
                "setting acl cache (granted = {allowed}) for {username}"
            ));
            self.cache
                .put_acl(record, allowed, &self.log)
                .await
                .inspect_err(|err| {
                    self.log.error(format_args!("set acl cache: {err}"));
                })?;
        }
        self.log
            .debug(format_args!("Acl is {allowed} for user {username}"));
        error.map_or(Ok(allowed), Err)
    }

    fn verdict(&self, result: Result<bool, BackendError>) -> Verdict {
        match result {
            Ok(true) => Verdict::Allow,
            Ok(false) => Verdict::Deny,
            Err(err) => {
                self.log.error(format_args!("{err}"));
                Verdict::Error
            }
        }
    }
}

impl ExternalSecurity for Plugin {
    fn deny_special_chars(&self) -> bool {
        self.deny_special_chars
    }

    fn authenticate<'a>(
        &'a self,
        client_id: &'a str,
        username: Option<&'a str>,
        password: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            // auth-plugin.c: mosquitto_auth_unpwd_check.
            let (Some(username), Some(password)) = (username, password) else {
                shim_error("error: received null username or password for unpwd check");
                return Verdict::Deny;
            };
            let password = password.split(|&byte| byte == 0).next().unwrap_or_default();
            let username = self.username(username, client_id);
            self.verdict(
                retry(self.retry_count, false, || {
                    self.check_user(username, password, client_id)
                })
                .await,
            )
        })
    }

    fn acl_identity(&self, subject: Subject<'_>) -> Option<AclIdentity> {
        // auth-plugin.c: mosquitto_auth_acl_check sees the original identity,
        // including for retained-source checks (Mosquitto retain.c: retain__process).
        Some(AclIdentity {
            client_id: Some(Arc::from(subject.client_id)),
            username: subject.username.map(Arc::from),
        })
    }

    fn authorize<'a>(
        &'a self,
        identity: &'a AclIdentity,
        topic: &'a str,
        access: AclAccess,
    ) -> BoxFuture<'a, Authorization> {
        Box::pin(async move {
            // auth-plugin.c: mosquitto_auth_acl_check. Rust guarantees a
            // non-null topic and positive access via its argument types.
            let (Some(client_id), Some(username)) =
                (identity.client_id.as_deref(), identity.username.as_deref())
            else {
                shim_error(
                    "error: received null username, clientid or topic, or access is equal or less than 0 for acl check",
                );
                return Authorization {
                    verdict: Verdict::Deny,
                    reuse_for: Duration::ZERO,
                };
            };
            let username = self.username(username, client_id);
            let verdict = self.verdict(
                retry(self.retry_count, false, || {
                    self.check_acl(username, topic, client_id, access.value())
                })
                .await,
            );
            let reuse_for = if verdict == Verdict::Error {
                Duration::ZERO
            } else {
                self.cache.acl_reuse()
            };
            Authorization { verdict, reuse_for }
        })
    }
    // go-auth.go: AuthPluginCleanup.
    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {
            self.log.info(format_args!("Cleaning up plugin"));
            self.cache.close();
            self.routing.halt().await;
        })
    }
}

fn shim_error(message: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{message}");
    let _ = stdout.flush();
}
