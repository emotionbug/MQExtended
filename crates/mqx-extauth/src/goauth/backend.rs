//! The go-auth back-end contract (`backends/backends.go: Backend`).

use std::{collections::HashMap, sync::Arc};

use mqx_auth::external::BoxFuture;
use thiserror::Error;

pub(crate) use super::log::{Level, Log};

/// `authOpts`: the plugin options, prefix removed. go-auth builds a Go map in
/// configuration order (`go-auth.go: AuthPluginInit`), so a repeated option
/// keeps its last value.
pub(crate) type Options = HashMap<String, String>;

/// The `error` a back-end check returns. go-auth turns it into
/// `MOSQ_ERR_UNKNOWN` (`go-auth.go: AuthUnpwdCheck`, `AuthAclCheck`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub(crate) struct BackendError(pub(crate) String);

impl BackendError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// `hashing.HashComparer`, built for one back-end
/// (`hashing/hashing.go: NewHasher(authOpts, "<backend>")`).
pub(crate) trait Hasher: Send + Sync {
    /// `Compare(password, savedHash)`. `password` holds the bytes the C shim
    /// passes to Go: the CONNECT password up to its first NUL.
    fn compare(&self, password: &[u8], saved: &str) -> bool;

    /// File hashes can contain arbitrary salt bytes with `utf-8` encoding.
    fn compare_bytes(&self, password: &[u8], saved: &[u8]) -> bool {
        std::str::from_utf8(saved).is_ok_and(|saved| self.compare(password, saved))
    }
}

/// What a back-end constructor receives
/// (`backends/backends.go: addBackends`).
pub(crate) struct Init<'a> {
    pub(crate) options: &'a Options,
    /// The hasher go-auth builds for this back-end's option prefix.
    pub(crate) hasher: Arc<dyn Hasher>,
    pub(crate) log: Log,
    /// The libmosquitto version the C shim reports, `major.minor.revision`.
    pub(crate) version: &'a str,
}

/// One configured back-end. Implementations hold their own connections and
/// must not block the async runtime; wrap blocking I/O in
/// `tokio::task::spawn_blocking`.
pub(crate) trait Backend: Send + Sync {
    /// `GetName()`, as printed in `Backend registered: <name>`.
    fn name(&self) -> String;

    /// `GetUser(username, password, clientid)`. `password` holds the bytes the
    /// C shim passes to Go: the CONNECT password up to its first NUL.
    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        client_id: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>>;

    /// `GetSuperuser(username)`.
    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>>;

    /// `CheckAcl(username, topic, clientid, acc)`.
    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        client_id: &'a str,
        acc: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>>;

    /// `Halt()`, called once when the plugin is cleaned up.
    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }
}
