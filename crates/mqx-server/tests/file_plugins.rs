use std::{fs, path::Path};

use mqx_server::ServerConfig;

const PASSWORD: &str = "mosquitto_password_file.so";
const ACL: &str = "mosquitto_acl_file.so";
const DYNAMIC: &str = "mosquitto_dynamic_security.so";
const SPARKPLUG: &str = "mosquitto_sparkplug_aware.so";

#[test]
fn global_and_legacy_declarations_select_stock_file_policies() {
    let config = ServerConfig::parse(&format!(
        "listener 1888\nauth_plugin /usr/lib/{PASSWORD}\n\
         plugin_opt_password_file unused path\nauth_opt_password_file \t files/active password\n\
         listener 1889\nplugin /usr/lib/{ACL}\nplugin_opt_acl_file \tfiles/access policy \n\
         auth_plugin_deny_special_chars false\n"
    ))
    .unwrap();
    for listener in &config.listeners {
        assert_eq!(
            config.credential_paths_for(listener),
            (
                Some(Path::new("files/active password")),
                Some(Path::new("files/access policy ")),
            ),
        );
    }
}

#[test]
fn global_plugin_and_legacy_listener_scope_work_together() {
    let config = ServerConfig::parse(&format!(
        "per_listener_settings true\nglobal_plugin {PASSWORD}\nplugin_opt_password_file global.pw\n\
         listener 1888\nplugin {ACL}\nplugin_opt_acl_file first.acl\n\
         listener 1889\nacl_file second.acl\nlistener 1890\n"
    ))
    .unwrap();
    for (listener, expected) in
        config
            .listeners
            .iter()
            .zip([Some("first.acl"), Some("second.acl"), None])
    {
        assert_eq!(
            config.credential_paths_for(listener),
            (Some(Path::new("global.pw")), expected.map(Path::new)),
        );
    }
}

#[test]
fn named_loads_follow_explicit_listeners_and_share_their_last_option() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("plugins.conf"),
        format!("plugin_load login {PASSWORD}\nplugin_opt_password_file initial.pw\nplugin_load topics {ACL}\n"),
    )
    .unwrap();
    let config = ServerConfig::parse(&format!(
        "include_dir {}\nlistener 1888\nplugin_use login\nplugin_use topics\n\
         auth_opt_acl_file access.acl\nlistener 1889\nlistener 1890\n\
         plugin_use login\nplugin_opt_password_file final.pw\n",
        dir.path().display(),
    ))
    .unwrap();
    assert_eq!(
        config.credential_paths_for(&config.listeners[0]),
        (Some(Path::new("final.pw")), Some(Path::new("access.acl")))
    );
    assert_eq!(
        config.credential_paths_for(&config.listeners[1]),
        (None, None)
    );
    assert_eq!(
        config.credential_paths_for(&config.listeners[2]),
        (Some(Path::new("final.pw")), None)
    );
}

#[test]
fn rejects_unknown_options_modules_and_invalid_attachments() {
    for (input, expected) in [
        (
            format!("plugin {PASSWORD}"),
            "requires 'plugin_opt_password_file'",
        ),
        (
            format!("plugin {PASSWORD}\nplugin_opt_PASSWORD_FILE users"),
            "Unknown option 'PASSWORD_FILE'",
        ),
        (
            format!("plugin {ACL}\nplugin_opt_password_file users"),
            "Unknown option 'password_file'",
        ),
        (
            format!("plugin {ACL}\nplugin_opt_acl_file   \t"),
            "Empty 'acl_file'",
        ),
        (format!("plugin /opt/custom/lib{PASSWORD}"), "Unsupported"),
        (format!("plugin /opt/custom/{PASSWORD}.1"), "Unsupported"),
        (
            format!("plugin /opt/custom/{PASSWORD}/wrapper.so"),
            "Unsupported",
        ),
        (
            format!("plugin_load {PASSWORD} /unrelated/auth.so"),
            "Unsupported",
        ),
        (
            format!("per_listener_settings true\nplugin {ACL}"),
            "requires a listener",
        ),
        (
            format!("plugin_load topics {ACL}\nport 1888\nplugin_use topics"),
            "requires a listener",
        ),
        (
            format!("plugin_load topics {ACL}\nlistener 1888"),
            "must be attached",
        ),
        (
            format!("plugin_load shared {ACL}\nplugin_load shared {PASSWORD}"),
            "Duplicate plugin name",
        ),
        (
            format!(
                "plugin_load topics {ACL}\nlistener 1888\nplugin_use topics\nplugin_use topics"
            ),
            "already attached",
        ),
    ] {
        let error = ServerConfig::parse(&input).unwrap_err().to_string();
        assert!(error.contains(expected), "{input:?}: {error}");
    }
}

#[test]
fn rejects_distinct_files_with_overlapping_callbacks() {
    for (input, expected) in [
        (
            format!(
                "password_file direct.pw\nplugin {PASSWORD}\nplugin_opt_password_file plugin.pw"
            ),
            "different 'password_file' paths",
        ),
        (
            format!(
                "acl_file direct.acl\nplugin_load local {ACL}\nplugin_opt_acl_file plugin.acl\nlistener 1888\nplugin_use local"
            ),
            "different 'acl_file' paths",
        ),
        (
            format!(
                "plugin_load local {PASSWORD}\nplugin_opt_password_file plugin.pw\nlistener 1888\nplugin_use local\nglobal_plugin {PASSWORD}\nplugin_opt_password_file global.pw"
            ),
            "different 'password_file' paths",
        ),
        (
            format!(
                "plugin {ACL}\nplugin_opt_acl_file first.acl\nplugin {ACL}\nplugin_opt_acl_file second.acl"
            ),
            "different 'acl_file' paths",
        ),
        (
            format!("plugin {ACL}\nplugin {DYNAMIC}\nplugin_opt_config_file security.json"),
            "Cannot combine a file plugin with Dynamic Security",
        ),
    ] {
        let error = ServerConfig::parse(&input).unwrap_err().to_string();
        assert!(error.contains(expected), "{input:?}: {error}");
    }
}

#[test]
fn permits_redundant_and_disjoint_file_policies() {
    let config = ServerConfig::parse(&format!(
        "plugin_load first {ACL}\nplugin_opt_acl_file first.acl\n\
         plugin_load second {ACL}\nplugin_opt_acl_file second.acl\n\
         password_file same.pw\nplugin {PASSWORD}\nplugin_opt_password_file same.pw\n\
         listener 1888\nplugin_use first\nlistener 1889\nplugin_use second\n"
    ))
    .unwrap();
    for (listener, acl) in config.listeners.iter().zip(["first.acl", "second.acl"]) {
        assert_eq!(
            config.credential_paths_for(listener),
            (Some(Path::new("same.pw")), Some(Path::new(acl)))
        );
    }
    let config = ServerConfig::parse(&format!(
        "plugin_load acl {ACL}\nplugin_load ds {DYNAMIC}\nplugin_opt_config_file security.json\n\
         listener 1888\nplugin_use acl\nlistener 1889\nplugin_use ds\n"
    ))
    .unwrap();
    assert_eq!(
        config.credential_paths_for(&config.listeners[0]),
        (None, None)
    );
    assert!(config.listeners[0].dynamic_security.is_none());
    assert!(config.listeners[1].dynamic_security.is_some());
}

#[test]
fn reload_preserves_initialized_paths_and_rejects_new_overlap() {
    let bound = ServerConfig::parse(&format!(
        "plugin {PASSWORD}\nplugin_opt_password_file active.pw\nlistener 1888\n"
    ))
    .unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        file.path(),
        "plugin /unsupported.so\nplugin_opt_unknown option\nlistener 1888\n",
    )
    .unwrap();
    let mut fresh = ServerConfig::load_for_reload(file.path()).unwrap();
    fresh.retain_startup_plugins(&bound).unwrap();
    assert_eq!(
        fresh.credential_paths_for(&fresh.listeners[0]).0,
        Some(Path::new("active.pw"))
    );
    assert_eq!(fresh.plugin_inventory, ["password-file"]);

    fs::write(file.path(), "listener 1888\npassword_file conflicting.pw\n").unwrap();
    let mut fresh = ServerConfig::load_for_reload(file.path()).unwrap();
    let error = fresh
        .retain_startup_plugins(&bound)
        .unwrap_err()
        .to_string();
    assert!(error.contains("different 'password_file' paths"), "{error}");
}

#[test]
fn sparkplug_scope_matches_the_declaration_and_multiple_callbacks_are_rejected() {
    let config = ServerConfig::parse(&format!(
        "global_plugin {SPARKPLUG}\nplugin_opt_ignored yes"
    ))
    .unwrap()
    .with_command_line_ports(&[1888, 1889]);
    assert!(config.sparkplug_aware);
    assert!(config.listeners.iter().all(|l| l.sparkplug_aware));

    let config = ServerConfig::parse(&format!(
        "plugin_load sparkplug {SPARKPLUG}\nlistener 1888\nplugin_use sparkplug\nlistener 1889"
    ))
    .unwrap();
    assert!(!config.sparkplug_aware);
    assert!(config.listeners[0].sparkplug_aware);
    assert!(!config.listeners[1].sparkplug_aware);

    let error = ServerConfig::parse(&format!(
        "plugin_load sparkplug {SPARKPLUG}\nlistener 1888\nplugin_use sparkplug\nplugin {SPARKPLUG}"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("overlapping sparkplug-aware plugins"),
        "{error}"
    );
}

#[test]
fn plugin_inventory_is_in_load_order_and_excludes_builtins_and_inactive_dynsec() {
    let config = ServerConfig::parse(&format!(
        "plugin_load topics {ACL}\nlistener 1888\nplugin {PASSWORD}\n\
         plugin_opt_password_file login.pw\npassword_file login.pw\n\
         plugin {DYNAMIC}\nplugin_use topics\nplugin {SPARKPLUG}\n"
    ))
    .unwrap();
    assert_eq!(
        config.plugin_inventory,
        ["acl-file", "password-file", "sparkplug-aware"]
    );
}

#[test]
fn bad_plugin_policy_data_fails_startup_not_config_syntax_check() {
    use std::{net::TcpListener, process::Command};

    let dir = tempfile::tempdir().unwrap();
    // If loading is accidentally skipped, the child must still exit rather
    // than waiting for a connection on a listener this test cannot manage.
    let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = occupied.local_addr().unwrap().port();
    let file = dir.path().join("mosquitto.conf");
    let policy = dir.path().join("policy");
    for (module, option, bad) in [
        (PASSWORD, "password_file", "sensor:bad\n"),
        (ACL, "acl_file", "topic readwrite invalid#\n"),
    ] {
        fs::write(&policy, bad).unwrap();
        fs::write(
            &file,
            format!(
                "user root\nlistener {port} 127.0.0.1\nplugin {module}\n\
                 plugin_opt_{option} {}\nlog_dest stderr\n",
                policy.display(),
            ),
        )
        .unwrap();
        let command = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_mqextended"));
            command
                .arg("-c")
                .arg(&file)
                .env("TOKIO_WORKER_THREADS", "2");
            command
        };
        assert!(
            command()
                .arg("--test-config")
                .output()
                .unwrap()
                .status
                .success()
        );
        let output = command().output().unwrap();
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(&format!("Unable to load {option}")),
            "{error}"
        );
    }
}
