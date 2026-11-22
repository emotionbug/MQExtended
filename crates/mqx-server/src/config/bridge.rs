use mqx_bridge::{BridgeConfig, Direction, Protocol, Restart, Start, Topic};
use mqx_codec::QoS;

use super::{ParseResult, Value, atoi, empty, invalid, unsupported};

pub(super) fn is_directive(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "addresses"
            | "clientid"
            | "remote_clientid"
            | "local_clientid"
            | "cleansession"
            | "local_cleansession"
            | "idle_timeout"
            | "keepalive_interval"
            | "local_password"
            | "local_username"
            | "notifications"
            | "notifications_local_only"
            | "notification_topic"
            | "password"
            | "remote_password"
            | "restart_timeout"
            | "round_robin"
            | "start_type"
            | "threshold"
            | "topic"
            | "try_private"
            | "username"
            | "remote_username"
            | "bridge_attempt_unsubscribe"
            | "bridge_cafile"
            | "bridge_alpn"
            | "bridge_ciphers"
            | "bridge_ciphers_tls1.3"
            | "bridge_bind_address"
            | "bridge_capath"
            | "bridge_certfile"
            | "bridge_identity"
            | "bridge_insecure"
            | "bridge_require_ocsp"
            | "bridge_max_packet_size"
            | "bridge_max_topic_alias"
            | "bridge_outgoing_retain"
            | "bridge_keyfile"
            | "bridge_protocol_version"
            | "bridge_psk"
            | "bridge_receive_maximum"
            | "bridge_reload_type"
            | "bridge_session_expiry_interval"
            | "bridge_tcp_keepalive"
            | "bridge_tcp_user_timeout"
            | "bridge_tls_use_os_certs"
            | "bridge_tls_version"
    )
}

// Mosquitto src/conf.c: config__read/config__check_bridges.
pub(super) fn finish(bridges: &mut [BridgeConfig]) -> ParseResult<()> {
    let mut ids = std::collections::BTreeSet::new();
    for bridge in bridges {
        if bridge.addresses.is_empty() {
            return Err("Invalid bridge configuration: no remote addresses defined.".into());
        }
        if bridge.topics.is_empty() {
            return Err("Invalid bridge configuration: no topics defined.".into());
        }
        if bridge.remote_clientid.is_empty() {
            bridge.default_remote_clientid = true;
            bridge.remote_clientid = format!(
                "{}.{}",
                gethostname::gethostname().to_string_lossy(),
                bridge.name
            );
        }
        if bridge.local_clientid.is_empty() {
            bridge.default_local_clientid = true;
            bridge.local_clientid = format!("local.{}", bridge.remote_clientid);
        }
        if !ids.insert(&bridge.local_clientid) {
            return Err(format!("Bridge local_clientid '{}' is not unique. Try changing or setting the local_clientid value for one of the bridges.", bridge.local_clientid).into());
        }
    }
    Ok(())
}

// Mosquitto src/conf.c: config__read_file_core, including the separate atoi paths.
pub(super) fn directive(
    bridge: &mut BridgeConfig,
    value: Value<'_>,
    notices: &mut Vec<String>,
) -> ParseResult<()> {
    let name = value.name;
    let string = |label, defined| {
        Value {
            name: label,
            ..value
        }
        .unique_string(defined)
    };
    let tls = &mut bridge.tls;
    match name {
        "address" | "addresses" => {
            if !bridge.addresses.is_empty() {
                return Err("Invalid bridge configuration, 'address' only allowed once.".into());
            }
            for address in value.words().take_while(|word| !word.starts_with('#')) {
                let (host, port) = address
                    .rsplit_once(':')
                    .map_or((address, 1883), |(host, port)| (host, atoi(port)));
                let port = u16::try_from(port)
                    .ok()
                    .filter(|&port| port != 0)
                    .ok_or_else(|| format!("Invalid bridge port value ({port})."))?;
                bridge.addresses.push((host.into(), port));
            }
            if bridge.addresses.is_empty() {
                return Err(empty("address"));
            }
        }
        "clientid" | "remote_clientid" => {
            bridge.remote_clientid =
                string("bridge remote clientid", !bridge.remote_clientid.is_empty())?
        }
        "local_clientid" => {
            bridge.local_clientid =
                string("bridge local clientd", !bridge.local_clientid.is_empty())?
        }
        "local_username" => {
            bridge.local_username = Some(string(
                "bridge local_username",
                bridge.local_username.is_some(),
            )?)
        }
        "local_password" => {
            bridge.local_password = Some(string(
                "bridge local_password",
                bridge.local_password.is_some(),
            )?)
        }
        "username" | "remote_username" => {
            bridge.remote_username = Some(string(
                "bridge remote_username",
                bridge.remote_username.is_some(),
            )?)
        }
        "password" | "remote_password" => {
            bridge.remote_password = Some(string(
                "bridge remote_password",
                bridge.remote_password.is_some(),
            )?)
        }
        "cleansession" => bridge.clean_session = value.boolean()?,
        "local_cleansession" => bridge.local_clean_session = Some(value.boolean()?),
        "notifications" => bridge.notifications = value.boolean()?,
        "notifications_local_only" => bridge.notifications_local_only = value.boolean()?,
        "notification_topic" => {
            bridge.notification_topic = Some(string(name, bridge.notification_topic.is_some())?)
        }
        "round_robin" => bridge.round_robin = value.boolean()?,
        "try_private" => bridge.try_private = value.boolean()?,
        "bridge_attempt_unsubscribe" => bridge.attempt_unsubscribe = value.boolean()?,
        "bridge_outgoing_retain" => bridge.outgoing_retain = value.boolean()?,
        "keepalive_interval" => {
            let interval = value.integer()?;
            if interval < 5 {
                notices.push("keepalive interval too low, using 5 seconds.".into());
            }
            bridge.keepalive =
                u16::try_from(interval.max(5)).map_err(|_| "Bridge keepalive value too high.")?;
        }
        "idle_timeout" => {
            let interval = value.integer()?;
            if interval < 1 {
                notices.push("idle_timeout interval too low, using 1 second.".into());
            }
            bridge.idle_timeout = interval.max(1) as u64;
        }
        "threshold" => {
            let threshold = value.integer()?;
            if threshold < 1 {
                notices.push("threshold too low, using 1 message.".into());
            }
            bridge.threshold = threshold.max(1) as usize;
        }
        "start_type" => {
            bridge.start = match value.word()? {
                "automatic" => Start::Automatic,
                "lazy" => Start::Lazy,
                "once" => Start::Once,
                "manual" => return Err("Manual start_type not supported.".into()),
                bad => {
                    return Err(
                        format!("Invalid 'start_type' value in configuration ({bad}).").into(),
                    );
                }
            }
        }
        "restart_timeout" => bridge.restart = restart(value, notices)?,
        "bridge_protocol_version" => {
            bridge.protocol = match value.value {
                "mqttv31" => Protocol::V31,
                "mqttv311" => Protocol::V311,
                "mqttv50" => Protocol::V5,
                "" => return Err(empty(name)),
                bad => return Err(invalid(name, bad)),
            }
        }
        "bridge_reload_type" => {
            bridge.reload_immediate = match value.word()? {
                "immediate" => true,
                "lazy" => false,
                bad => {
                    return Err(format!(
                        "Invalid 'bridge_reload_type' value in configuration ({bad})."
                    )
                    .into());
                }
            }
        }
        "bridge_receive_maximum" => {
            let n = value.integer()?;
            if n < 1 {
                return Err("bridge_receive_maximum must be greater than 0.".into());
            }
            bridge.receive_maximum =
                u16::try_from(n).map_err(|_| "bridge_receive_maximum must be lower than 65535.")?;
        }
        "bridge_session_expiry_interval" => {
            bridge.session_expiry = u32::try_from(value.integer()?)
                .map_err(|_| "bridge_session_expiry_interval must not be negative.")?
        }
        "bridge_max_topic_alias" => {
            bridge.max_topic_alias = u16::try_from(value.integer()?)
                .map_err(|_| "bridge_max_topic_alias must be > 0 and <= 65535.")?
        }
        "bridge_max_packet_size" => bridge.max_packet_size = value.nonnegative()?,
        "bridge_tcp_keepalive" => {
            let mut words = value.words();
            let mut field = |name, label| -> ParseResult<u32> {
                let n = Value {
                    name,
                    value: words.next().unwrap_or(""),
                }
                .integer()?;
                if n <= 0 {
                    return Err(format!("invalid TCP keepalive {label} value.").into());
                }
                Ok(n as u32)
            };
            bridge.tcp_keepalive = Some((
                field("bridge_tcp_keepalive_idle", "idle")?,
                field("bridge_tcp_keepalive_interval", "interval")?,
                field("bridge_tcp_keepalive_counter", "counter")?,
            ));
        }
        "bridge_tcp_user_timeout" => {
            bridge.tcp_user_timeout = Some(
                u32::try_from(value.integer()?).map_err(|_| "invalid TCP user timeout value.")?,
            )
        }
        "bridge_bind_address" => {
            bridge.bind_address = Some(string(name, bridge.bind_address.is_some())?)
        }
        "bridge_cafile" | "bridge_capath" | "bridge_certfile" | "bridge_keyfile" => {
            let field = match name {
                "bridge_cafile" => &mut tls.cafile,
                "bridge_capath" => &mut tls.capath,
                "bridge_certfile" => &mut tls.certfile,
                _ => &mut tls.keyfile,
            };
            *field = Some(string(name, field.is_some())?.into());
        }
        "bridge_psk" | "bridge_identity" => return Err(unsupported(name, "TLS PSK")),
        "bridge_alpn" => tls.alpn = Some(string(name, tls.alpn.is_some())?),
        "bridge_ciphers" => tls.ciphers = Some(string(name, tls.ciphers.is_some())?),
        "bridge_ciphers_tls1.3" => {
            tls.ciphers_tls13 = Some(string(name, tls.ciphers_tls13.is_some())?)
        }
        "bridge_tls_version" => tls.version = Some(string(name, tls.version.is_some())?),
        "bridge_tls_use_os_certs" => tls.use_os_certs = value.boolean()?,
        "bridge_require_ocsp" => {
            if value.boolean()? {
                return Err(unsupported(name, "TLS OCSP stapling verification"));
            }
        }
        "bridge_insecure" => {
            tls.insecure = value.boolean()?;
            if tls.insecure {
                notices.push(format!(
                    "Warning: Bridge '{}' using insecure mode.",
                    bridge.name
                ));
            }
        }
        "topic" => topic(bridge, value, notices)?,
        _ => unreachable!("checked bridge directive"),
    }
    Ok(())
}

fn restart(value: Value<'_>, notices: &mut Vec<String>) -> ParseResult<Restart> {
    let mut words = value.words();
    let mut base = atoi(words.next().ok_or_else(|| empty(value.name))?);
    if base < 1 {
        notices.push("restart_timeout interval too low, using 1 second.".into());
    }
    if base > 3600 {
        notices.push("restart_timeout interval too high, using 3600 seconds.".into());
    }
    base = base.clamp(1, 3600);
    let cap = words.next().map(atoi);
    if cap.is_some_and(|cap| cap < base) {
        return Err("backoff cap is lower than the base in restart_timeout.".into());
    }
    if cap.is_some_and(|cap| cap > 7200) {
        notices.push("Error: backoff cap too high, using 7200 seconds.".into());
    }
    let stable = cap.and_then(|_| words.next()).map_or(0, atoi);
    if stable < 0 {
        return Err("stable connection period cannot be negative.".into());
    }
    Ok(Restart {
        initial_ms: base as u64 * 1000,
        base_ms: base as u64 * 1000,
        cap_ms: cap.unwrap_or(0).min(7200) as u64 * 1000,
        stable_secs: stable as u64,
    })
}

fn topic(
    bridge: &mut BridgeConfig,
    value: Value<'_>,
    notices: &mut Vec<String>,
) -> ParseResult<()> {
    let line = value.value.trim_start_matches(' ');
    let first = value.word()?;
    let rest = &line[first.len()..];
    let (pattern, rest) = if first.starts_with('"') && !first.starts_with("\"\"") {
        let (tail, rest) = rest
            .strip_prefix(' ')
            .unwrap_or(rest)
            .split_once('"')
            .ok_or_else(|| {
                format!(
                    "Missing closing quote in topic value ({}).",
                    rest.strip_prefix(' ').unwrap_or(rest)
                )
            })?;
        (Some(format!("{} {tail}", &first[1..])), rest)
    } else {
        ((first != "\"\"").then(|| first.to_owned()), rest)
    };
    let mut words = rest.split(' ').filter(|word| !word.is_empty());
    let direction = match words.next() {
        None => Direction::Out,
        Some(word) if word.eq_ignore_ascii_case("out") => Direction::Out,
        Some(word) if word.eq_ignore_ascii_case("in") => Direction::In,
        Some(word) if word.eq_ignore_ascii_case("both") => Direction::Both,
        Some(word) => return Err(format!("Invalid bridge topic direction '{word}'.").into()),
    };
    let mut args = words.take_while(|word| !word.starts_with('#'));
    let level = args.next().unwrap_or("0");
    let qos = match atoi(level) as u8 {
        0 => QoS::AtMostOnce,
        1 => QoS::AtLeastOnce,
        2 => QoS::ExactlyOnce,
        _ => return Err(format!("Invalid bridge QoS level '{level}'.").into()),
    };
    let local_prefix = args.next().filter(|s| *s != "\"\"").map(str::to_owned);
    let remote_prefix = args.next().filter(|s| *s != "\"\"").map(str::to_owned);
    for (prefix, which) in [(&local_prefix, "local"), (&remote_prefix, "remote")] {
        if let Some(prefix) = prefix
            && mqx_topic::validate_topic_name(prefix).is_err()
        {
            return Err(format!("Invalid bridge topic {which} prefix '{prefix}'.").into());
        }
    }
    if pattern.is_none() && (local_prefix.is_none() || remote_prefix.is_none()) {
        return Err("Invalid bridge remapping.".into());
    }
    // bridge_topic.c: bridge__find_topic compares fields only if both are non-NULL.
    let equal = |a: &Option<String>, b: &Option<String>| a.is_none() || b.is_none() || a == b;
    if bridge.topics.iter().any(|old| {
        old.direction == direction
            && old.qos == qos
            && (old.pattern.is_none() || old.pattern == pattern)
            && equal(&old.local_prefix, &local_prefix)
            && equal(&old.remote_prefix, &remote_prefix)
    }) {
        notices.push(format!(
            "Duplicate bridge topic '{}', skipping",
            pattern.as_deref().unwrap_or("\"\"")
        ));
        return Ok(());
    }
    let filter = |prefix: &Option<String>| -> ParseResult<String> {
        let filter = format!(
            "{}{}",
            prefix.as_deref().unwrap_or(""),
            pattern.as_deref().unwrap_or("")
        );
        if prefix.is_some() && mqx_topic::validate_topic_filter(&filter).is_err() {
            // bridge__add_topic passes `local` even for the remote combination.
            return Err(format!(
                "Invalid bridge topic local prefix and pattern combination '{filter}'."
            )
            .into());
        }
        Ok(filter)
    };
    let local_filter = filter(&local_prefix)?;
    let remote_filter = filter(&remote_prefix)?;
    bridge.topics.push(Topic {
        pattern,
        direction,
        qos,
        local_prefix,
        remote_prefix,
        local_filter,
        remote_filter,
    });
    Ok(())
}
