//! The contract between the broker and natively reimplemented third-party
//! Mosquitto auth plugins (`auth_plugin`/`plugin` + `auth_opt_*`).
//!
//! Mosquitto 2.1.4 loads such libraries through its v2-v4 wrapper
//! (`src/plugin_v4.c`) and calls them synchronously. Their checks can wait on
//! HTTP or database servers, so the broker never awaits them inside its
//! replicated state machine. It calls the pure methods there and runs
//! [`ExternalSecurity::authenticate`] and [`ExternalSecurity::authorize`] on a
//! node, committing the verdicts it then relies on.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A callback result as Mosquitto's callback chain sees it
/// (`plugin_basic_auth.c`, `plugin_acl_check.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Verdict {
    /// `MOSQ_ERR_SUCCESS`: a decisive grant.
    Allow,
    /// `MOSQ_ERR_AUTH` or `MOSQ_ERR_ACL_DENIED`: a decisive refusal.
    Deny,
    /// `MOSQ_ERR_PLUGIN_DEFER`: later callbacks decide.
    Defer,
    /// Any other result, such as `MOSQ_ERR_UNKNOWN` after a backend failure.
    /// The caller handles it like Mosquitto handles a non-ACL error code.
    Error,
}

/// `MOSQ_ACL_*` values a v2-v4 plugin receives. Unsubscribe never reaches it:
/// `plugin_acl_check.c: acl__pre_check` grants it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AclAccess {
    Read = 1,
    Write = 2,
    Subscribe = 4,
}

impl AclAccess {
    /// The integer passed to the plugin (`include/mosquitto/broker_plugin.h`).
    pub fn value(self) -> i32 {
        self as i32
    }
}

/// What a v2-v4 plugin can observe about the `struct mosquitto` it is given.
/// The broker records these facts when a session is claimed, so every node
/// derives the same [`AclIdentity`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Binding {
    /// This plugin's username/password callback ran for the connection with a
    /// non-empty username and a password whose first byte is not NUL.
    pub credentials: bool,
    /// The connection presented a TLS client certificate.
    pub certificate: bool,
    /// Not a connection: the context Mosquitto builds to recheck the original
    /// publisher of a retained message (`retain.c: retain__process`).
    pub synthetic: bool,
}

/// The client a check is made for.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    pub client_id: &'a str,
    pub username: Option<&'a str>,
    pub binding: Binding,
}

/// The identity under which a plugin evaluates and caches ACL checks. Two
/// subjects with the same identity always receive the same verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AclIdentity {
    pub client_id: Option<Arc<str>>,
    pub username: Option<Arc<str>>,
}

/// The result of an ACL check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorization {
    pub verdict: Verdict,
    /// How long the verdict may be reused for the same identity, topic and
    /// access, counted from the moment the check started. Zero limits it to
    /// the check it was made for. Ignored for [`Verdict::Error`].
    pub reuse_for: Duration,
}

/// A natively implemented third-party auth plugin.
pub trait ExternalSecurity: Send + Sync + 'static {
    /// The plugin's `auth_plugin_deny_special_chars` setting, which the broker
    /// applies before every ACL callback (`plugin_acl_check.c: acl__pre_check`).
    fn deny_special_chars(&self) -> bool;

    /// `MOSQ_EVT_BASIC_AUTH`. `password` holds the bytes of the CONNECT
    /// password; a C plugin sees them up to the first NUL.
    fn authenticate<'a>(
        &'a self,
        client_id: &'a str,
        username: Option<&'a str>,
        password: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Verdict>;

    /// Pure and deterministic: the broker calls it inside the replicated state
    /// machine on every node. `None` means the plugin defers every ACL check
    /// for this subject without contacting a backend.
    fn acl_identity(&self, subject: Subject<'_>) -> Option<AclIdentity>;

    /// `MOSQ_EVT_ACL_CHECK` for an identity returned by
    /// [`ExternalSecurity::acl_identity`].
    fn authorize<'a>(
        &'a self,
        identity: &'a AclIdentity,
        topic: &'a str,
        access: AclAccess,
    ) -> BoxFuture<'a, Authorization>;

    /// Plugin cleanup after listeners and broker tasks have shut down.
    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }
}
