//! Native implementations of third-party Mosquitto auth plugins.
//!
//! A configuration that names one of these libraries in `auth_plugin`,
//! `plugin` or `global_plugin` runs the Rust implementation here; nothing at
//! the library path is opened. Each implementation follows the original C
//! plugin as Mosquitto 2.1.4 loads it through its v4 wrapper
//! (`src/plugin_v4.c`). The broker side of the contract is
//! [`mqx_auth::external`].

mod authplug;
mod backend;
mod backends;
mod goauth;
mod net;

use std::sync::Arc;

use mqx_auth::external::ExternalSecurity;

pub use backend::LoadError;

/// A third-party plugin library implemented by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Library {
    /// jpmens/mosquitto-auth-plug, built as `auth-plug.so`.
    AuthPlug,
    /// iegomez/mosquitto-go-auth, built as `go-auth.so`.
    GoAuth,
}

impl Library {
    /// The library a plugin path names, by its distribution file name.
    pub fn from_path(path: &str) -> Option<Self> {
        let basename = path.rsplit(std::path::is_separator).next().unwrap_or(path);
        match basename.rsplit_once('.') {
            Some(("auth-plug", "so" | "dylib" | "dll")) => Some(Self::AuthPlug),
            Some(("go-auth", "so" | "dylib" | "dll")) => Some(Self::GoAuth),
            _ => None,
        }
    }

    /// The name used in diagnostics and the broker control plugin inventory.
    pub fn label(self) -> &'static str {
        match self {
            Self::AuthPlug => "auth-plug",
            Self::GoAuth => "go-auth",
        }
    }
}

/// Announce the plugin's version phase before initializing its backends.
pub fn announce(library: Library) {
    match library {
        Library::AuthPlug => authplug::announce(),
        // auth-plugin.c: mosquitto_auth_plugin_version silently returns 4.
        Library::GoAuth => {}
    }
}

/// Initialize a plugin with its `auth_opt_*`/`plugin_opt_*` options, prefix
/// removed, in configuration order (`mosquitto_auth_plugin_init` and
/// `mosquitto_auth_security_init`). Backends that connect at initialization
/// do so here; an error stops the broker like a failed plugin load.
pub async fn load(
    library: Library,
    options: Vec<(String, String)>,
    deny_special_chars: bool,
) -> Result<Arc<dyn ExternalSecurity>, LoadError> {
    match library {
        Library::AuthPlug => authplug::load(options, deny_special_chars).await,
        Library::GoAuth => goauth::load(options, deny_special_chars).await,
    }
}
