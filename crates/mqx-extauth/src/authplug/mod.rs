//! jpmens/mosquitto-auth-plug (`auth-plug.c`, `cache.c`, `pbkdf2-check.c`).

mod cache;
mod pattern;
mod pbkdf2;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mqx_auth::external::{
    AclAccess, AclIdentity, Authorization, BoxFuture, ExternalSecurity, Subject, Verdict,
};

use crate::backend::{Backend, BackendResult, LoadError, Options};
use crate::backends;
use cache::{AuthCache, Lifetime};

pub(crate) use cache::c_string;

static QUIET: AtomicBool = AtomicBool::new(false);

// log.h uses Mosquitto's numeric priorities: both LOG_NOTICE and LOG_DEBUG
// are <= LOG_DEBUG. log.c: __log, _fatal.
pub(crate) fn log(message: fmt::Arguments<'_>) {
    if log_enabled() {
        eprintln!("{}: |-- {message}", cache::now());
    }
}

pub(crate) fn log_enabled() -> bool {
    !QUIET.load(Ordering::Relaxed)
}

pub(crate) fn announce() {
    // auth-plug.c: mosquitto_auth_plugin_version runs before init.
    log(format_args!("*** auth-plug: startup"));
}

fn fatal(error: LoadError) -> LoadError {
    eprintln!("|-- {error}\n|-- *** ABORT.");
    error
}

// strtol/atol on the reference's POSIX platform: a signed decimal prefix,
// saturating at LONG_MIN/LONG_MAX. atoi then narrows the result to int.
fn atol(input: &[u8]) -> i64 {
    let start = input
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'..=b'\r'));
    let Some(mut rest) = start.map(|index| &input[index..]) else {
        return 0;
    };
    let negative = rest[0] == b'-';
    if matches!(rest[0], b'+' | b'-') {
        rest = &rest[1..];
    }
    rest.iter()
        .take_while(|b| b.is_ascii_digit())
        .fold(0i64, |value, b| {
            let digit = i64::from(b - b'0');
            let value = value.saturating_mul(10);
            if negative {
                value.saturating_sub(digit)
            } else {
                value.saturating_add(digit)
            }
        })
}

pub(crate) fn atoi(input: &[u8]) -> i32 {
    atol(input) as i32
}

#[derive(Debug)]
struct Settings {
    superusers: Option<String>,
    anonymous: String,
    acl: Lifetime,
    auth: Lifetime,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            superusers: None,
            anonymous: "anonymous".into(),
            acl: Lifetime {
                seconds: 300,
                jitter: 0,
            },
            auth: Lifetime {
                seconds: 0,
                jitter: 0,
            },
        }
    }
}

impl Settings {
    // auth-plug.c: mosquitto_auth_plugin_init. The two ACL aliases share one
    // slot, so their ordering in the configuration matters.
    fn parse(options: &[(String, String)]) -> Self {
        let mut settings = Self::default();
        for (key, value) in options {
            match key.as_str() {
                "superusers" => settings.superusers = Some(value.clone()),
                "anonusername" => settings.anonymous.clone_from(value),
                "cacheseconds" | "acl_cacheseconds" => {
                    settings.acl.seconds = atol(value.as_bytes())
                }
                "auth_cacheseconds" => settings.auth.seconds = atol(value.as_bytes()),
                "acl_cachejitter" => settings.acl.jitter = atol(value.as_bytes()),
                "auth_cacheijitter" => settings.auth.jitter = atol(value.as_bytes()),
                "log_quiet" => match value.as_str() {
                    "false" | "0" => QUIET.store(false, Ordering::Relaxed),
                    "true" | "1" => QUIET.store(true, Ordering::Relaxed),
                    _ => log(format_args!("Error: Invalid log_quiet value ({value}).")),
                },
                _ => (),
            }
        }
        settings
    }
}

struct AuthPlug {
    settings: Settings,
    backends: Vec<Box<dyn Backend>>,
    auth_cache: AuthCache,
    deny_special_chars: bool,
    redact_username: bool,
}

pub(crate) async fn load(
    options: Vec<(String, String)>,
    deny_special_chars: bool,
) -> Result<Arc<dyn ExternalSecurity>, LoadError> {
    let settings = Settings::parse(&options);
    let options = Options::new(options);
    let order = options
        .get("backends")
        .ok_or_else(|| fatal(LoadError::new("No backends configured.")))?;
    log(format_args!("** Configured order: {order}\n"));
    let mut chain = Vec::new();
    for name in backend_names(order) {
        chain.push(backends::create(name, &options).await.map_err(fatal)?);
    }
    let redact_username = chain.iter().any(|backend| backend.name() == "jwt");
    Ok(Arc::new(AuthPlug {
        settings,
        backends: chain,
        auth_cache: AuthCache::default(),
        deny_special_chars,
        redact_username,
    }))
}

pub(crate) fn backend_names(order: &str) -> impl Iterator<Item = &str> {
    // auth-plug.c: mosquitto_auth_plugin_init stops at the first empty field.
    order.split(',').take(5).take_while(|name| !name.is_empty())
}

impl ExternalSecurity for AuthPlug {
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
            // auth-plug.c: mosquitto_auth_unpwd_check. MOSQ_DENY_AUTH is
            // MOSQ_ERR_PLUGIN_DEFER in v4, even after a backend's DENY.
            let Some(username) = username.filter(|s| !s.is_empty()) else {
                return Verdict::Defer;
            };
            let Some(password) = password.map(cache::c_string).filter(|s| !s.is_empty()) else {
                return Verdict::Defer;
            };
            let log_user = self.log_user(username);
            log(format_args!("mosquitto_auth_unpwd_check({log_user})"));
            let key = (self.settings.auth.seconds > 0)
                .then(|| cache::key([username.as_bytes(), b":", password]));
            if let Some(verdict) =
                key.and_then(|key| self.auth_cache.query(key, log_user, cache::now()))
            {
                let granted = i32::from(verdict == Verdict::Allow);
                log(format_args!("getuser({log_user}) CACHEDAUTH: {granted}"));
                return verdict;
            }
            let mut error = false;
            let mut allowed = false;
            let mut backend_name = "none";
            for backend in &self.backends {
                log(format_args!("** checking backend {}", backend.name()));
                let result = backend.getuser(username, password, client_id).await;
                match result.result {
                    BackendResult::Allow => {
                        allowed = true;
                        backend_name = backend.name();
                        break;
                    }
                    BackendResult::Deny => {
                        backend_name = backend.name();
                        break;
                    }
                    BackendResult::Error => error = true,
                    BackendResult::Defer => {
                        if let Some(hash) = result.hash {
                            let password = password.to_vec();
                            if matches!(
                                tokio::task::spawn_blocking(move || pbkdf2::check(
                                    &password, &hash
                                ))
                                .await,
                                Ok(true)
                            ) {
                                allowed = true;
                                backend_name = backend.name();
                                break;
                            }
                        }
                    }
                }
            }
            let authenticated = i32::from(allowed);
            log(format_args!(
                "getuser({log_user}) AUTHENTICATED={authenticated} by {backend_name}"
            ));
            let verdict = if allowed {
                Verdict::Allow
            } else if error {
                log(format_args!(
                    "getuser({log_user}) AUTHENTICATED=N HAS_ERROR=Y => ERR_UNKNOWN"
                ));
                Verdict::Error
            } else {
                Verdict::Defer
            };
            if let Some(key) = key {
                let lifetime = self.settings.auth.duration();
                if !lifetime.is_zero() {
                    self.auth_cache.insert(
                        key,
                        log_user,
                        verdict,
                        cache::now(),
                        lifetime.as_secs(),
                    );
                }
            }
            verdict
        })
    }

    fn acl_identity(&self, subject: Subject<'_>) -> Option<AclIdentity> {
        // auth-plug.c: mosquitto_auth_unpwd_check records the placeholder
        // client ID. mosquitto_auth_acl_check otherwise uses TLS identity.
        if subject.binding.synthetic {
            return None;
        }
        let username = subject.username?;
        let client_id = if subject.binding.credentials && !username.is_empty() {
            "client id not available"
        } else if subject.binding.certificate {
            subject.client_id
        } else {
            return None;
        };
        Some(AclIdentity {
            client_id: Some(client_id.into()),
            username: Some(username.into()),
        })
    }

    fn authorize<'a>(
        &'a self,
        identity: &'a AclIdentity,
        topic: &'a str,
        access: AclAccess,
    ) -> BoxFuture<'a, Authorization> {
        Box::pin(async move {
            let started = cache::wall_time();
            let username = identity
                .username
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&self.settings.anonymous);
            let log_user = self.log_user(username);
            let client_id = identity.client_id.as_deref();
            // auth-plug.c: mosquitto_auth_acl_check. This check is separate
            // from the broker's (decisive) acl__pre_check; it does not cache.
            if username.contains(['+', '#', '/']) {
                log(format_args!(
                    "ACL denying access to client with dangerous username \"{log_user}\""
                ));
                return Authorization {
                    verdict: Verdict::Defer,
                    reuse_for: Duration::ZERO,
                };
            }
            if let Some(id) = client_id.filter(|s| s.contains(['+', '#', '/'])) {
                log(format_args!(
                    "ACL denying access to client with dangerous client id \"{id}\""
                ));
                return Authorization {
                    verdict: Verdict::Defer,
                    reuse_for: Duration::ZERO,
                };
            }
            let label = if access == AclAccess::Read {
                "MOSQ_ACL_READ"
            } else {
                "MOSQ_ACL_WRITE"
            };
            let access = access.value();
            log(format_args!(
                "mosquitto_auth_acl_check(..., {}, {log_user}, {topic}, {label})",
                client_id.unwrap_or("NULL")
            ));
            let verdict = self
                .acl_chain(client_id.unwrap_or_default(), username, topic, access)
                .await;
            // cache.c: acl_cache. The broker owns the reusable ACL verdict;
            // do not shadow it with a second process-local cache.
            let reuse_for = client_id.map_or(Duration::ZERO, |id| {
                let ttl = self.settings.acl.duration();
                if !ttl.is_zero() && log_enabled() {
                    if self.redact_username {
                        log(format_args!(
                            " Cached  [<redacted>] for ({id},{log_user},{access})"
                        ));
                    } else {
                        let key = cache::key([
                            id.as_bytes(),
                            b":",
                            username.as_bytes(),
                            b":",
                            topic.as_bytes(),
                            b":",
                            access.to_string().as_bytes(),
                        ]);
                        log(format_args!(
                            " Cached  [{}] for ({id},{log_user},{access})",
                            cache::Hex(&key)
                        ));
                    }
                }
                cache::acl_reuse(ttl, started)
            });
            Authorization { verdict, reuse_for }
        })
    }
}

impl AuthPlug {
    fn log_user<'a>(&self, username: &'a str) -> &'a str {
        if self.redact_username {
            "<redacted>"
        } else {
            username
        }
    }

    // auth-plug.c: mosquitto_auth_acl_check. All superuser checks precede
    // all ACL checks; the backend that authenticated the user is not stored.
    async fn acl_chain(
        &self,
        client_id: &str,
        username: &str,
        topic: &str,
        access: i32,
    ) -> Verdict {
        if username.is_empty() || topic.is_empty() {
            return Verdict::Defer;
        }
        let log_user = self.log_user(username);
        if self
            .settings
            .superusers
            .as_deref()
            .is_some_and(|glob| pattern::matches(glob.as_bytes(), username.as_bytes()))
        {
            log(format_args!(
                "aclcheck({log_user}, {topic}, {access}) GLOBAL SUPERUSER=Y"
            ));
            return Verdict::Allow;
        }
        let mut error = false;
        for backend in &self.backends {
            let name = backend.name();
            match backend.superuser(username).await {
                BackendResult::Allow => {
                    log(format_args!(
                        "aclcheck({log_user}, {topic}, {access}) SUPERUSER=Y by {name}"
                    ));
                    return Verdict::Allow;
                }
                BackendResult::Deny => {
                    log(format_args!(
                        "aclcheck({log_user}, {topic}, {access}) SUPERUSER=N by {name}"
                    ));
                    return Self::acl_denied(log_user, topic, access, error);
                }
                BackendResult::Error => {
                    log(format_args!(
                        "aclcheck({log_user}, {topic}, {access}) HAS_ERROR=Y by {name}"
                    ));
                    error = true;
                }
                BackendResult::Defer => (),
            }
        }
        let mut allowed = false;
        let mut backend_name = "none";
        for backend in &self.backends {
            let name = backend.name();
            match backend.aclcheck(client_id, username, topic, access).await {
                BackendResult::Allow => {
                    backend_name = name;
                    log(format_args!(
                        "aclcheck({log_user}, {topic}, {access}) trying to acl with {name}"
                    ));
                    allowed = true;
                    break;
                }
                BackendResult::Deny => {
                    backend_name = name;
                    break;
                }
                BackendResult::Error => {
                    log(format_args!(
                        "aclcheck({log_user}, {topic}, {access}) HAS_ERROR=Y by {name}"
                    ));
                    error = true;
                }
                BackendResult::Defer => (),
            }
        }
        let authorized = i32::from(allowed);
        log(format_args!(
            "aclcheck({log_user}, {topic}, {access}) AUTHORIZED={authorized} by {backend_name}"
        ));
        if allowed {
            Verdict::Allow
        } else {
            Self::acl_denied(log_user, topic, access, error)
        }
    }

    fn acl_denied(username: &str, topic: &str, access: i32, error: bool) -> Verdict {
        if error {
            log(format_args!(
                "aclcheck({username}, {topic}, {access}) AUTHORIZED=N HAS_ERROR=Y => ERR_UNKNOWN"
            ));
            Verdict::Error
        } else {
            Verdict::Defer
        }
    }
}

#[cfg(test)]
mod tests;
