//! The auth-plug back-end contract (`backends.h`).

use mqx_auth::external::BoxFuture;
use thiserror::Error;

/// A plugin initialization failure. The message is logged as Mosquitto logs a
/// plugin that fails to load, and the broker exits with status 1.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct LoadError(pub String);

impl LoadError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// `BACKEND_DEFER`, `BACKEND_ALLOW`, `BACKEND_ERROR` and `BACKEND_DENY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendResult {
    Defer,
    Allow,
    Error,
    Deny,
}

/// The result of `getuser`: a decision, or `Defer` with the PBKDF2 string the
/// core verifies against the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GetUser {
    pub(crate) result: BackendResult,
    pub(crate) hash: Option<String>,
}

impl GetUser {
    pub(crate) fn result(result: BackendResult) -> Self {
        Self { result, hash: None }
    }

    pub(crate) fn hash(hash: String) -> Self {
        Self {
            result: BackendResult::Defer,
            hash: Some(hash),
        }
    }
}

/// One configured back-end. Implementations hold their own connections and
/// must not block the async runtime; wrap blocking I/O in
/// `tokio::task::spawn_blocking`.
pub(crate) trait Backend: Send + Sync {
    /// The name used in `auth_opt_backends` and in log lines.
    fn name(&self) -> &'static str;

    /// `be_*_getuser(conf, username, password, &phash, clientid)`. `password`
    /// is the C string the plugin receives (CONNECT password up to its first
    /// NUL); `client_id` is `mosquitto_client_id(client)`.
    fn getuser<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        client_id: &'a str,
    ) -> BoxFuture<'a, GetUser>;

    /// `be_*_superuser(conf, username)`.
    fn superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, BackendResult>;

    /// `be_*_aclcheck(conf, clientid, username, topic, access)`.
    fn aclcheck<'a>(
        &'a self,
        client_id: &'a str,
        username: &'a str,
        topic: &'a str,
        access: i32,
    ) -> BoxFuture<'a, BackendResult>;
}

/// The plugin options, prefix removed, in configuration order.
#[derive(Debug, Clone, Default)]
pub(crate) struct Options(Vec<(String, String)>);

impl Options {
    pub(crate) fn new(options: Vec<(String, String)>) -> Self {
        Self(options)
    }

    /// `p_stab(key)`: the value auth-plug's option table returns for `key`.
    /// `uthash.h: HASH_ADD_TO_BKT` prepends to the bucket and `HASH_FIND`
    /// returns the first match, so a repeated option keeps its last value
    /// (bucket expansion needs ten keys in one bucket).
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}
