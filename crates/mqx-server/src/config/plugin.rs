use super::{
    DynamicSecurityConfig, ExternalPluginConfig, ListenerConfig, ParseResult, Parser, Path,
    PathBuf, ServerConfig, ServerError, Value, empty, require_listener, unsupported,
};

/// Startup-only file callbacks declared through the plugin directives.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilePlugins {
    password_file: Option<PathBuf>,
    acl_file: Option<PathBuf>,
    // With no file the ACL plugin ignores read/write, but still allows sub/unsub.
    acl_declared: bool,
}

impl FilePlugins {
    pub fn paths(&self) -> (Option<&Path>, Option<&Path>) {
        (self.password_file.as_deref(), self.acl_file.as_deref())
    }

    fn is_declared(&self) -> bool {
        self.password_file.is_some() || self.acl_declared
    }
}

impl ServerConfig {
    /// Returns the effective credential files after validating callback composition.
    pub fn credential_paths_for<'a>(
        &'a self,
        listener: &'a ListenerConfig,
    ) -> (Option<&'a Path>, Option<&'a Path>) {
        let (local_password, local_acl) = listener.security.file_plugins.paths();
        let (global_password, global_acl) = self.security.file_plugins.paths();
        let builtin = self.security_for(listener);
        (
            local_password
                .or(global_password)
                .or(builtin.password_file.as_deref()),
            local_acl.or(global_acl).or(builtin.acl_file.as_deref()),
        )
    }

    /// Keeps the initialized plugins after matching the freshly parsed listeners to
    /// the bound listeners in startup order.
    pub fn retain_startup_plugins(&mut self, bound: &Self) -> Result<(), ServerError> {
        self.security.file_plugins = bound.security.file_plugins.clone();
        self.sparkplug_aware = bound.sparkplug_aware;
        self.plugin_inventory.clone_from(&bound.plugin_inventory);
        self.external_plugins.clone_from(&bound.external_plugins);
        self.dynamic_security = bound.dynamic_security.clone();
        for (fresh, bound) in self.listeners.iter_mut().zip(&bound.listeners) {
            fresh.security.file_plugins = bound.security.file_plugins.clone();
            fresh.dynamic_security = bound.dynamic_security.clone();
            fresh.external_plugin = bound.external_plugin;
            fresh.sparkplug_aware = bound.sparkplug_aware;
        }
        self.validate_file_plugins()
    }

    fn validate_file_plugins(&self) -> Result<(), ServerError> {
        let global = &self.security.file_plugins;
        for listener in &self.listeners {
            let local = &listener.security.file_plugins;
            if (local.is_declared() || global.is_declared()) && listener.dynamic_security.is_some()
            {
                return Err(ServerError::Arguments(format!(
                    "Cannot combine a file plugin with Dynamic Security on listener {}: their auth or ACL callbacks overlap.",
                    listener.port,
                )));
            }
            // plugin_init.c: mosquitto_security_init registers plugin callbacks in
            // declaration order. Only an external plugin followed by the built-in
            // password_file/acl_file callbacks has a fixed, replicable order here.
            if listener.external_plugin.is_some()
                && (local.is_declared()
                    || global.is_declared()
                    || listener.dynamic_security.is_some())
            {
                return Err(ServerError::Arguments(format!(
                    "Cannot combine an auth plugin with Dynamic Security or a file plugin on listener {}; use the password_file and acl_file options instead of the file plugins.",
                    listener.port,
                )));
            }
            let builtin = self.security_for(listener);
            check_paths(
                "password_file",
                [
                    global.password_file.as_deref(),
                    local.password_file.as_deref(),
                    builtin.password_file.as_deref(),
                ],
            )?;
            check_paths(
                "acl_file",
                [
                    global.acl_file.as_deref(),
                    local.acl_file.as_deref(),
                    builtin.acl_file.as_deref(),
                ],
            )?;
        }
        Ok(())
    }
}

// plugin_basic_auth.c and plugin_acl_check.c: a v5 file callback's decisive
// result stops the chain. Do not discard different files whose load failures or
// callback ordering matter. Repeated callbacks using the very same file can be
// represented by one policy; the ACL callback without a file is inert here.
fn check_paths<const N: usize>(name: &str, paths: [Option<&Path>; N]) -> Result<(), ServerError> {
    let mut paths = paths.into_iter().flatten();
    if let Some(first) = paths.next()
        && paths.any(|other| other.as_os_str() != first.as_os_str())
    {
        return Err(ServerError::Arguments(format!(
            "Cannot combine different '{name}' paths in overlapping file plugin or built-in callbacks."
        )));
    }
    Ok(())
}

pub(super) struct Plugin {
    name: Option<String>,
    kind: Kind,
    global: bool,
    listeners: Vec<usize>,
}

enum Kind {
    DynamicSecurity {
        config_file: Option<PathBuf>,
        password_init_file: Option<PathBuf>,
    },
    PasswordFile(Option<PathBuf>),
    AclFile(Option<PathBuf>),
    SparkplugAware,
    External(ExternalPluginConfig),
}

impl Kind {
    fn label(&self) -> &'static str {
        match self {
            Self::DynamicSecurity { .. } => "dynamic-security",
            Self::PasswordFile(_) => "password-file",
            Self::AclFile(_) => "acl-file",
            Self::SparkplugAware => "sparkplug-aware",
            Self::External(plugin) => plugin.library.label(),
        }
    }

    fn set_option(&mut self, key: &str, value: &str) -> ParseResult<()> {
        match self {
            Self::DynamicSecurity {
                config_file,
                password_init_file,
            } => {
                if key.eq_ignore_ascii_case("config_file") {
                    *config_file = Some(value.into());
                } else if key.eq_ignore_ascii_case("password_init_file") {
                    *password_init_file = Some(value.into());
                }
            }
            // plugins/{password-file,acl-file}/plugin.c: handle_options compares
            // keys case-sensitively and keeps the last value for its one option.
            Self::PasswordFile(file) if key == "password_file" => *file = Some(value.into()),
            Self::AclFile(file) if key == "acl_file" => *file = Some(value.into()),
            Self::SparkplugAware => {}
            // plugin_v4.c: plugin__load_v4 hands every option to the library.
            Self::External(plugin) => plugin.options.push((key.into(), value.into())),
            other => return Err(format!("{}: Unknown option '{key}'.", other.label()).into()),
        }
        Ok(())
    }
}

fn option_key(name: &str) -> Option<&str> {
    name.strip_prefix("plugin_opt_")
        .or_else(|| name.strip_prefix("auth_opt_"))
}

pub(super) fn is_directive(name: &str) -> bool {
    matches!(
        name,
        "auth_plugin"
            | "plugin"
            | "global_plugin"
            | "plugin_load"
            | "plugin_use"
            | "auth_plugin_deny_special_chars"
    ) || option_key(name).is_some()
}

impl Parser {
    // src/conf.c: config__read_file_core: plugin declarations, attachments, and
    // options are ignored on reload; the initialized plugin retains its options.
    pub(super) fn plugin_directive(
        &mut self,
        v: Value<'_>,
        listener: Option<usize>,
        current: &mut Option<usize>,
    ) -> ParseResult<()> {
        if self.reloading {
            return Ok(());
        }
        let name = v.name;
        match name {
            "auth_plugin" | "plugin" | "global_plugin" => {
                let listener = if name == "global_plugin" || !self.config.per_listener_settings {
                    None
                } else {
                    Some(require_listener(listener, name)?)
                };
                let index = self.load_plugin(name, None, v.value)?;
                let loaded = &mut self.plugins[index];
                if let Some(listener) = listener {
                    loaded.listeners.push(listener);
                } else {
                    loaded.global = true;
                }
                self.security_seen = true;
                *current = Some(index);
            }
            "plugin_load" => {
                let declaration = v.value.trim_start_matches(' ');
                let (plugin_name, path) = declaration.split_once(' ').unwrap_or((declaration, ""));
                if plugin_name.is_empty() {
                    return Err(empty(name));
                }
                *current = Some(self.load_plugin(name, Some(plugin_name), path)?);
            }
            "plugin_use" => {
                let explicit = listener.filter(|index| Some(*index) != self.default_listener);
                let listener = require_listener(explicit, name)?;
                let plugin_name = v.string()?;
                let index = self
                    .find_plugin(&plugin_name)
                    .ok_or_else(|| format!("Plugin '{plugin_name}' not previously loaded."))?;
                let loaded = &mut self.plugins[index];
                if loaded.listeners.contains(&listener) {
                    // plugin_callbacks.c: a callback cannot register twice in one scope.
                    if matches!(&loaded.kind, Kind::DynamicSecurity { .. }) {
                        return Err(
                            "Dynamic security plugin can currently only be loaded once.".into()
                        );
                    }
                    return Err(format!(
                        "Plugin '{plugin_name}' is already attached to this listener."
                    )
                    .into());
                }
                loaded.listeners.push(listener);
                *current = Some(index);
            }
            "auth_plugin_deny_special_chars" => {
                let Some(index) = *current else {
                    return Err("An auth_plugin_deny_special_chars option exists in the config file without a plugin.".into());
                };
                let deny = v.boolean()?;
                // plugin_acl_check.c: acl__pre_check applies it to v2-v4 plugins
                // only; v5 callbacks ignore it.
                if let Kind::External(plugin) = &mut self.plugins[index].kind {
                    plugin.deny_special_chars = deny;
                }
            }
            _ => {
                let index = current.ok_or_else(|| {
                    format!("The '{name}' option requires plugin/global_plugin/plugin_load to be defined first.")
                })?;
                let key = option_key(name).expect("plugin option prefix");
                if key.len() < 3 {
                    return Err("Invalid 'plugin_opt_' config option.".into());
                }
                let value = v.value.trim_start_matches([' ', '\t']);
                if value.is_empty() {
                    return Err(empty(key));
                }
                self.plugins[index].kind.set_option(key, value)?;
            }
        }
        Ok(())
    }

    fn find_plugin(&self, name: &str) -> Option<usize> {
        self.plugins
            .iter()
            .position(|plugin| plugin.name.as_deref() == Some(name))
    }

    fn load_plugin(
        &mut self,
        directive: &str,
        name: Option<&str>,
        path: &str,
    ) -> ParseResult<usize> {
        if let Some(name) = name
            && self.find_plugin(name).is_some()
        {
            return Err(format!("Duplicate plugin name '{name}'.").into());
        }
        if path.is_empty() {
            return Err(match name {
                Some(name) => format!("Missing plugin path for plugin name '{name}'.").into(),
                None => empty(directive),
            });
        }
        if path.contains('\0') {
            return Err(unsupported(directive, "plugin path contains a NUL byte"));
        }
        // The distribution basename selects a Rust implementation; nothing at
        // the library path is opened. plugins/*/CMakeLists.txt and plugin.mk.
        let basename = path.rsplit(std::path::is_separator).next().unwrap_or(path);
        let kind = match basename.rsplit_once('.') {
            Some(("mosquitto_dynamic_security", "so" | "dll" | "dylib")) => Kind::DynamicSecurity {
                config_file: None,
                password_init_file: None,
            },
            Some(("mosquitto_password_file", "so" | "dll")) => Kind::PasswordFile(None),
            Some(("mosquitto_acl_file", "so" | "dll")) => Kind::AclFile(None),
            Some(("mosquitto_sparkplug_aware", "so" | "dll")) => Kind::SparkplugAware,
            _ => match mqx_extauth::Library::from_path(path) {
                Some(library) => Kind::External(ExternalPluginConfig {
                    path: path.into(),
                    library,
                    options: Vec::new(),
                    // conf.c: config__plugin_load sets the default.
                    deny_special_chars: true,
                }),
                None => return Err(unsupported(directive, &format!("plugin '{path}'"))),
            },
        };
        let index = self.plugins.len();
        self.plugins.push(Plugin {
            name: name.map(str::to_owned),
            kind,
            global: false,
            listeners: Vec::new(),
        });
        Ok(index)
    }

    pub(super) fn finish_plugins(&mut self) -> Result<(), ServerError> {
        let config = &mut self.config;
        for plugin in self.plugins.drain(..) {
            let label = plugin.kind.label();
            // plugin_init.c skips library loading for unused names, then rejects
            // their uninitialized plugin version during security initialization.
            if !plugin.global && plugin.listeners.is_empty() {
                let name = plugin.name.as_deref().unwrap_or(label);
                return Err(ServerError::Arguments(format!(
                    "Plugin '{name}' must be attached to a listener with plugin_use."
                )));
            }
            if config.local_only
                && !plugin.global
                && !matches!(&plugin.kind, Kind::DynamicSecurity { .. })
            {
                // listeners.c: listeners__start_local_only replaces implicit
                // listeners rather than activating their configured callbacks.
                return Err(ServerError::Arguments(format!(
                    "Plugin '{label}' requires an active listener."
                )));
            }
            let local = if config.local_only {
                &[][..]
            } else {
                plugin.listeners.as_slice()
            };
            match plugin.kind {
                Kind::DynamicSecurity {
                    config_file,
                    password_init_file,
                } => {
                    let Some(config_file) = config_file else {
                        config.notices.push("Warning: Dynamic security plugin has no plugin_opt_config_file defined. The plugin will not be activated.".into());
                        continue;
                    };
                    if config.dynamic_security.is_some() {
                        return Err(ServerError::Arguments(
                            "Error: Dynamic security plugin can currently only be loaded once."
                                .into(),
                        ));
                    }
                    let dynamic = DynamicSecurityConfig {
                        config_file,
                        password_init_file,
                        // plugin_basic_auth.c and plugin_acl_check.c call global
                        // callbacks first; mosquitto.c loads v5 plugins before built-ins.
                        before_file: plugin.global || config.per_listener_settings,
                    };
                    for (index, listener) in config.listeners.iter_mut().enumerate() {
                        if plugin.global || local.contains(&index) {
                            listener.dynamic_security = Some(dynamic.clone());
                        }
                    }
                    config.dynamic_security = Some(dynamic);
                }
                Kind::SparkplugAware => {
                    for (index, listener) in config.listeners.iter_mut().enumerate() {
                        if plugin.global || local.contains(&index) {
                            if listener.sparkplug_aware {
                                return Err(ServerError::Arguments(format!(
                                    "Cannot combine overlapping sparkplug-aware plugins on listener {}.",
                                    listener.port,
                                )));
                            }
                            listener.sparkplug_aware = true;
                        }
                    }
                    config.sparkplug_aware |= plugin.global;
                }
                Kind::External(external) => {
                    let id = config.external_plugins.len();
                    for (index, listener) in config.listeners.iter_mut().enumerate() {
                        if plugin.global || local.contains(&index) {
                            if listener.external_plugin.is_some() {
                                return Err(ServerError::Arguments(format!(
                                    "Cannot combine two auth plugins on listener {}.",
                                    listener.port,
                                )));
                            }
                            listener.external_plugin = Some(id);
                        }
                    }
                    config.external_plugins.push(external);
                    // broker_control.c: add_plugin_info skips plugins without a
                    // name, which v2-v4 libraries never set.
                    continue;
                }
                kind => {
                    let apply = |files: &mut FilePlugins| {
                        match &kind {
                            Kind::PasswordFile(path) => {
                                let Some(path) = path else {
                                    return Err(ServerError::Arguments(
                                        "password-file requires 'plugin_opt_password_file'.".into(),
                                    ));
                                };
                                check_paths(
                                    "password_file",
                                    [files.password_file.as_deref(), Some(path)],
                                )?;
                                files.password_file.get_or_insert_with(|| path.clone());
                            }
                            Kind::AclFile(path) => {
                                files.acl_declared = true;
                                check_paths(
                                    "acl_file",
                                    [files.acl_file.as_deref(), path.as_deref()],
                                )?;
                                if let Some(path) = path {
                                    files.acl_file.get_or_insert_with(|| path.clone());
                                }
                            }
                            _ => unreachable!(),
                        }
                        Ok(())
                    };
                    if plugin.global {
                        apply(&mut config.security.file_plugins)?;
                    } else {
                        for &index in local {
                            apply(&mut config.listeners[index].security.file_plugins)?;
                        }
                    }
                }
            }
            // broker_control.c lists db.plugins in declaration order. Explicit
            // v5 plugins do not set pid->listener, even for a listener attachment.
            config.plugin_inventory.push(label);
        }
        config.validate_file_plugins()
    }
}
