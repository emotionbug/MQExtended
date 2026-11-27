use std::{fs, path::Path};

use mqx_extauth::Library;
use mqx_server::ServerConfig;

const CONFIG: &str = "listener 8883 127.0.0.1\n\
                     certfile broker.pem\nkeyfile broker-key.pem\n\
                     allow_anonymous false\nallow_zero_length_clientid false\n\
                     acl_file clients.acl\n\
                     plugin /usr/lib/mqext_kms.so\n\
                     plugin_opt_audience broker.example\n\
                     plugin_opt_public_key_sensor sensor.pem\n";

#[test]
fn kms_requires_an_effective_tls_listener_and_native_acl_without_identity_bypasses() {
    let config = ServerConfig::parse(CONFIG).unwrap();
    assert_eq!(config.external_plugins[0].library, Library::Kms);
    assert_eq!(config.listeners[0].external_plugin, Some(0));
    assert_eq!(
        config.credential_paths_for(&config.listeners[0]),
        (None, Some(Path::new("clients.acl")))
    );
    for (from, to, expected) in [
        (
            "acl_file clients.acl\n",
            "",
            "requires an explicit acl_file",
        ),
        (
            "certfile broker.pem\nkeyfile broker-key.pem\n",
            "",
            "with certfile and keyfile",
        ),
        (
            "allow_anonymous false",
            "allow_anonymous true",
            "anonymous access",
        ),
        (
            "allow_zero_length_clientid false\n",
            "",
            "requires allow_zero_length_clientid false",
        ),
        (
            "acl_file clients.acl",
            "acl_file clients.acl\npassword_file clients.pw",
            "cannot be combined with password_file",
        ),
        (
            "listener 8883 127.0.0.1",
            "listener 8883 127.0.0.1\nprotocol http_api",
            "requires an MQTT or WebSocket listener",
        ),
    ] {
        let error = ServerConfig::parse(&CONFIG.replace(from, to))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
    for option in [
        "use_username_as_clientid",
        "use_identity_as_username",
        "use_subject_as_username",
    ] {
        let error = ServerConfig::parse(&format!("{CONFIG}{option} true\n"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("username or client ID rewriting"), "{error}");
    }
    let error = ServerConfig::parse(&format!("{CONFIG}auth_plugin_deny_special_chars false\n"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("does not accept auth_plugin_deny_special_chars"),
        "{error}"
    );
}

#[test]
fn named_kms_listener_validation_does_not_apply_to_other_listeners() {
    let config = ServerConfig::parse(
        "per_listener_settings true\n\
         plugin_load kms mqext_kms.so\n\
         plugin_opt_audience broker.example\n\
         plugin_opt_public_key_sensor sensor.pem\n\
         listener 8883\nprotocol websockets\nplugin_use kms\n\
         certfile broker.pem\nkeyfile broker-key.pem\n\
         listener_allow_anonymous false\nallow_zero_length_clientid false\nacl_file clients.acl\n\
         listener 1883\nlistener_allow_anonymous true\n",
    )
    .unwrap();
    assert_eq!(config.listeners[0].external_plugin, Some(0));
    assert_eq!(config.listeners[1].external_plugin, None);
    assert!(config.allow_anonymous_for(&config.listeners[1]));
}

#[test]
fn kms_revalidates_reload_settings_against_the_startup_plugin() {
    let bound = ServerConfig::parse(CONFIG).unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    for (replacement, expected) in [
        (
            "listener_allow_anonymous true\nacl_file clients.acl\n",
            "anonymous access",
        ),
        ("", "requires an explicit acl_file"),
        (
            "use_identity_as_username true\nacl_file clients.acl\n",
            "username or client ID rewriting",
        ),
    ] {
        fs::write(
            file.path(),
            CONFIG.replace("acl_file clients.acl\n", replacement),
        )
        .unwrap();
        let mut fresh = ServerConfig::load_for_reload(file.path()).unwrap();
        let error = fresh
            .retain_startup_plugins(&bound)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
    let changed = CONFIG
        .replace("broker.example", "ignored.example")
        .replace("sensor.pem", "ignored.pem");
    fs::write(file.path(), changed).unwrap();
    let mut fresh = ServerConfig::load_for_reload(file.path()).unwrap();
    fresh.retain_startup_plugins(&bound).unwrap();
    assert_eq!(
        fresh.external_plugins[0].options,
        bound.external_plugins[0].options
    );
}
