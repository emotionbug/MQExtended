use std::{fs, path::Path, time::Duration};

use mqx_server::{
    ListenerProtocol, LogDestination, LogType, ProxyProtocol, ServerConfig, parse_command_line_port,
};

#[test]
fn invalid_values_produce_reference_startup_diagnostics() {
    // Cases from Mosquitto v2.1.4 test/broker/16-config-parse-errors-without-tls.py.
    for (input, expected) in [
        (
            "unknown_option unknown",
            "Unknown configuration variable 'unknown_option'",
        ),
        ("user", "Empty 'user' value in configuration."),
        ("user ", "Empty 'user' value in configuration."),
        ("user  ", "Empty 'user' value in configuration."),
        (
            "pid_file /tmp/pid\npid_file /tmp/pid",
            "Duplicate 'pid_file' value in configuration.",
        ),
        (
            "memory_limit",
            "Empty 'memory_limit' value in configuration.",
        ),
        (
            "accept_protocol_versions 3",
            "The 'accept_protocol_versions' option requires a listener to be defined first.",
        ),
        (
            "listener 1888\naccept_protocol_versions",
            "Empty 'accept_protocol_versions' value in configuration.",
        ),
        (
            "allow_anonymous",
            "Empty 'allow_anonymous' value in configuration.",
        ),
        (
            "allow_anonymous falst",
            "Invalid 'allow_anonymous' value (falst).",
        ),
        (
            "autosave_interval",
            "Empty 'autosave_interval' value in configuration.",
        ),
        (
            "autosave_interval string",
            "'autosave_interval' value not a number.",
        ),
        ("listener", "Empty 'listener port' value in configuration."),
        (
            "mount_point test/",
            "The 'mount_point' option requires a listener to be defined first.",
        ),
        (
            "listener 1888\nmount_point test/+/",
            "Invalid 'mount_point' value (test/+/). Does it contain a wildcard character?",
        ),
        ("listener 100000", "Invalid 'port' value (100000)."),
        (
            "listener 0",
            "A listener with port 0 must provide a Unix socket path.",
        ),
        (
            "listener 1888\nprotocol",
            "Empty 'protocol' value in configuration.",
        ),
        (
            "listener 1888\nprotocol test",
            "Invalid 'protocol' value (test).",
        ),
        (
            "maximum_qos 3",
            "'max_qos' must be between 0 and 2 inclusive.",
        ),
        (
            "maximum_qos -1",
            "'max_qos' must be between 0 and 2 inclusive.",
        ),
        (
            "max_inflight_messages 65536",
            "'max_inflight_messages' must be <= 65535.",
        ),
        ("max_packet_size 19", "'max_packet_size' must be >= 20."),
        (
            "message_size_limit 556000000",
            "Invalid 'message_size_limit' value (556000000).",
        ),
        (
            "max_keepalive 65536",
            "Invalid 'max_keepalive' value (65536).",
        ),
        ("max_keepalive -1", "Invalid 'max_keepalive' value (-1)."),
        (
            "listener 1888\nmax_topic_alias 65536",
            "Invalid 'max_topic_alias' value in configuration.",
        ),
        (
            "listener 1888\nmax_topic_alias_broker -1",
            "Invalid 'max_topic_alias_broker' value in configuration.",
        ),
        (
            "listener 1888\nlistener_auto_id_prefix",
            "Empty 'listener_auto_id_prefix' value in configuration.",
        ),
        (
            "websockets_headers_size 65536",
            "Packet buffer size must be between 0 and 65535 inclusive.",
        ),
        ("memory_limit -1", "Invalid 'memory_limit' value (-1)."),
        (
            "sys_interval 65536",
            "Invalid 'sys_interval' value (65536).",
        ),
        // Mosquitto test/broker/16-config-parse-errors-tls.py.
        (
            "listener 1888\ncertfile",
            "Empty 'certfile' value in configuration.",
        ),
        (
            "listener 1888\nkeyfile",
            "Empty 'keyfile' value in configuration.",
        ),
        (
            "listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ntls_version invalid",
            "Unsupported tls_version \"invalid\".",
        ),
        // Mosquitto test/broker/21-proxy-v2-bad-config.py.
        (
            "listener 1888\nenable_proxy_protocol 2\nuse_subject_as_username true",
            "use_subject_as_username cannot be used with `enable_proxy_protocol 2`.",
        ),
        (
            "listener 1888\nenable_proxy_protocol 2\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key",
            "certfile and keyfile cannot be used with `enable_proxy_protocol 2`.",
        ),
    ] {
        let error = ServerConfig::parse(input).unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "{input:?}: {error:?} did not contain {expected:?}"
        );
    }
}

#[test]
fn commented_sample_binds_loopback_but_configured_listener_does_not_allow_anonymous() {
    // Commented settings excerpted from Mosquitto v2.1.4 mosquitto.conf.
    let sample = "#max_packet_size 0\n#listener\n#listener_allow_anonymous\n#listener_auto_id_prefix auto-\n#persistence false\n#persistence_file mosquitto.db\n#persistence_location\n#log_type error\n#log_type warning\n#log_type notice\n#log_type information\n#allow_anonymous false\n#include_dir\n";
    let config = ServerConfig::parse(sample).unwrap();
    assert!(config.local_only);
    assert!(config.allow_anonymous_for(&config.listeners[0]));
    let config = ServerConfig::parse("listener 1888 localhost # never an inline host\n").unwrap();
    assert!(!config.local_only);
    assert!(!config.allow_anonymous_for(&config.listeners[0]));
    assert_eq!(config.listeners[0].host.as_deref(), Some("localhost"));
}

#[test]
fn queued_bytes_config_has_no_message_count_cap() {
    // Exact content of Mosquitto test/broker/03-publish-qos1-queued-bytes.conf.
    let config = ServerConfig::parse(
        "sys_interval 1\nmax_queued_messages 0\nmax_queued_bytes 400\nport 1888\n",
    )
    .unwrap();
    assert_eq!(config.limits.max_queued_messages, 0);
    assert_eq!(config.limits.max_queued_bytes, 400);
    assert_eq!(config.listeners[0].port, 1888);
    assert!(!config.local_only);
}

#[test]
fn strings_and_numbers_have_distinct_tokenization() {
    let config = ServerConfig::parse("  listener 0x7f0 # ignored\r\nmax_qos 02\r\nmax_keepalive \t+37 rest\npassword_file  /path containing spaces\t\r\nacl_file /different # literal path\nmax_inflight_messages 65535\npersistent_client_expiration 2m\n").unwrap();
    assert_eq!(config.listeners[0].port, 0x7f0);
    assert_eq!(config.listeners[0].max_qos, 2);
    assert_eq!(config.limits.max_keepalive, 37);
    assert_eq!(config.limits.max_inflight_messages, 0);
    assert_eq!(
        config.limits.persistent_client_expiration,
        Some(Duration::from_secs(2 * 30 * 86400))
    );
    assert_eq!(
        config.security.password_file.as_deref(),
        Some(Path::new("/path containing spaces"))
    );
    assert_eq!(
        config.security.acl_file.as_deref(),
        Some(Path::new("/different # literal path"))
    );
    for input in [
        "  # indented comment",
        "\tlistener 1888",
        "listener\t1888",
        "max_keepalive 08",
        "allow_anonymous \ttrue",
    ] {
        assert!(ServerConfig::parse(input).is_err(), "{input:?}");
    }
}

#[test]
fn command_line_ports_are_repeatable_only_in_local_only_mode() {
    // Mosquitto test/broker/16-cmd-args.py, src/listeners.c: listeners__start_local_only.
    for (argument, number) in [("0", 0), ("65536", 65536)] {
        assert_eq!(
            parse_command_line_port(argument, 0)
                .unwrap_err()
                .to_string(),
            format!("Error: Invalid port specified ({number}).")
        );
    }
    assert!(parse_command_line_port("1234", 10).is_err());
    assert_eq!(parse_command_line_port("01884extra", 0).unwrap(), 1884);
    let config = ServerConfig::parse("per_listener_settings true")
        .unwrap()
        .with_command_line_ports(&[1884, 1885]);
    assert_eq!(
        config
            .listeners
            .iter()
            .map(|listener| listener.port)
            .collect::<Vec<_>>(),
        [1884, 1885]
    );
    assert!(
        config
            .listeners
            .iter()
            .all(|listener| config.allow_anonymous_for(listener))
    );
    let config = ServerConfig::parse("listener 1886")
        .unwrap()
        .with_command_line_ports(&[1885]);
    assert_eq!(config.listeners[0].port, 1886);
}

#[test]
fn include_files_are_ordered_and_do_not_share_a_current_listener() {
    // Mosquitto test/broker/16-config-includedir.py: one file defines a listener, the next
    // enables anonymous connection. Non-.conf entries and nested include_dir are not loaded.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("A2.conf"), "allow_anonymous false\n").unwrap();
    fs::write(
        dir.path().join("a1.conf"),
        "listener 1888\nallow_anonymous true\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("not-a-config.CONF"),
        "not_a_config_option\n",
    )
    .unwrap();
    let root = format!("include_dir {}\n", dir.path().display());
    let config = ServerConfig::parse(&root).unwrap();
    assert!(config.allow_anonymous_for(&config.listeners[0]));
    fs::write(
        dir.path().join("ZZ.conf"),
        "listener_auto_id_prefix example-\n",
    )
    .unwrap();
    let err = ServerConfig::parse(&root).unwrap_err().to_string();
    assert!(err.contains("requires a listener"));
    assert!(err.contains("ZZ.conf:1"));
    fs::write(dir.path().join("ZZ.conf"), &root).unwrap();
    assert!(
        ServerConfig::parse(&root)
            .unwrap_err()
            .to_string()
            .contains("only valid in the main configuration file")
    );
}

#[test]
fn security_scope_preserves_per_listener_anonymous_override_and_prefix() {
    // Mosquitto test/broker/01-connect-listener-allow-anonymous.py; src/conf.c:
    // conf__set_cur_security_options, config__check, PER_LISTENER_ALTERNATIVE.
    let global = ServerConfig::parse("allow_anonymous true\npassword_file global.pass\nauto_id_prefix global-\nlistener 1888\nlistener_allow_anonymous false\nlistener 1889\nlistener_auto_id_prefix device-\n").unwrap();
    assert!(!global.allow_anonymous_for(&global.listeners[0]));
    assert!(global.allow_anonymous_for(&global.listeners[1]));
    assert_eq!(
        global
            .security_for(&global.listeners[1])
            .password_file
            .as_deref(),
        Some(Path::new("global.pass"))
    );
    assert_eq!(
        global.listeners[0].security.auto_id_prefix.as_deref(),
        Some("global-")
    );
    assert_eq!(
        global.listeners[1].security.auto_id_prefix.as_deref(),
        Some("device-")
    );
    let per_listener = ServerConfig::parse("per_listener_settings true\nlistener 1888\nallow_anonymous true\npassword_file listener.pass\nallow_zero_length_clientid false\nper_listener_settings false\nlistener 1889\n").unwrap();
    assert!(per_listener.allow_anonymous_for(&per_listener.listeners[0]));
    assert!(!per_listener.allow_anonymous_for(&per_listener.listeners[1]));
    assert!(
        !per_listener
            .security_for(&per_listener.listeners[0])
            .allow_zero_length_clientid
    );
    assert!(
        per_listener
            .security_for(&per_listener.listeners[1])
            .password_file
            .is_none()
    );
    assert!(
        per_listener
            .notices
            .iter()
            .any(|message| message.contains("Please replace this with 'listener_allow_anonymous'"))
    );
    assert!(ServerConfig::parse("allow_anonymous true\nper_listener_settings true").is_err());
}

#[test]
fn unsupported_features_are_not_silently_ignored() {
    for (input, directive) in [
        ("persistence true", "persistence"),
        ("retained_persistence true", "retained_persistence"),
        ("listener 1888\nprotocol http_api", "protocol"),
        ("psk_file secret.txt", "psk_file"),
        ("connection upstream", "connection"),
        (
            "bridge_protocol_version mqttv311",
            "bridge_protocol_version",
        ),
        ("plugin_opt_verbose true", "plugin_opt_verbose"),
        ("auth_plugin my_plugin.so", "auth_plugin"),
        ("listener 0 /tmp/mqtt.sock", "listener"),
    ] {
        let error = ServerConfig::parse(input).unwrap_err().to_string();
        assert!(
            error.contains(directive) && error.contains("Unsupported"),
            "{error}"
        );
    }
}

#[test]
fn later_transport_options_are_preserved_in_configuration() {
    let config = ServerConfig::parse("websockets_headers_size 8192\nlistener 1888\nprotocol websockets\nwebsockets_origin https://first.example\nwebsockets_origin https://second.example\nhttp_dir .\nenable_proxy_protocol 2\nproxy_protocol_v2_require_tls true\n").unwrap();
    let listener = &config.listeners[0];
    assert_eq!(listener.protocol, ListenerProtocol::Websockets);
    assert_eq!(
        listener.websockets_origins,
        ["https://first.example", "https://second.example"]
    );
    assert!(listener.http_dir.as_ref().unwrap().is_absolute());
    assert_eq!(listener.enable_proxy_protocol, Some(ProxyProtocol::V2));
    assert!(listener.proxy_protocol_v2_require_tls);
    assert_eq!(config.limits.packet_buffer_size, 8192);
}

#[test]
fn log_none_clears_previous_selections_but_not_following_selections() {
    let config = ServerConfig::parse("log_type error\nlog_type none\nlog_type notice\nlog_dest stderr\nlog_dest none\nlog_dest stdout\nlog_dest file  /tmp/broker logs\nconnection_messages false\n").unwrap();
    assert_eq!(
        config.log.types.into_iter().collect::<Vec<_>>(),
        [LogType::Notice]
    );
    assert_eq!(
        config.log.destinations.into_iter().collect::<Vec<_>>(),
        [
            LogDestination::Stdout,
            LogDestination::File("/tmp/broker logs".into())
        ]
    );
    assert!(!config.log.connection_messages);
}
