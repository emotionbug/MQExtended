use super::*;

// test/broker/01-connect-accept-protocol.py and data/CONNECT.json.
scenario!(protocol_and_long_client_id, config(ANONYMOUS));
fn protocol_and_long_client_id(h: &mut Harness) {
    for protocol in [V31, V311] {
        let client = connect_with(
            h,
            Connect {
                protocol,
                ..options("p")
            },
            false,
        );
        ping(h, client);
        disconnect(h, client);
    }
    // src/handle_connect.c: read_and_verify_clientid_from_packet does not enforce the 3.1
    // specification's 23-character limit.
    for len in [23, 24, 256] {
        let client = connect_with(
            h,
            Connect {
                protocol: V31,
                ..options(&"x".repeat(len))
            },
            false,
        );
        ping(h, client);
        disconnect(h, client);
    }
}

// test/broker/01-connect-zero-length-id.py and data/CONNECT.json.
scenario!(
    empty_client_id_allowed,
    config("allow_anonymous true\nallow_zero_length_clientid true")
);
fn empty_client_id_allowed(h: &mut Harness) {
    empty_client_ids(h, true);
}

scenario!(
    empty_client_id_denied,
    config("allow_anonymous true\nallow_zero_length_clientid false")
);
fn empty_client_id_denied(h: &mut Harness) {
    empty_client_ids(h, false);
}

fn empty_client_ids(h: &mut Harness, allowed: bool) {
    // src/handle_connect.c: handle_zero_length_clientid only accepts clean v3.1.1 clients.
    for protocol in [V31, V311] {
        for clean_session in [false, true] {
            let settings = Connect {
                protocol,
                clean_session,
                ..options("")
            };
            if protocol == V311 && clean_session && allowed {
                // Two simultaneous anonymous client ids must not take over each other.
                let first = connect_with(h, settings.clone(), false);
                let second = connect_with(h, settings, false);
                ping(h, first);
                ping(h, second);
                disconnect(h, first);
                disconnect(h, second);
            } else {
                let client = h.open(protocol).unwrap();
                send(h, client, Packet::Connect(settings));
                connack(h, client, IdentifierRejected, false);
                closed(h, client);
            }
        }
    }
}

// test/broker/data/CONNECT.json (wrong protocol, reserved byte/flag and credential flag cases).
scenario!(malformed_connect, config(ANONYMOUS));
fn malformed_connect(h: &mut Harness) {
    for (protocol, other_level) in [(V31, 4), (V311, 3)] {
        let normal = connect_frame(options("p"), protocol);
        let level_index = 4 + usize::from(normal[3]);
        let flags_index = level_index + 1;
        let mut wrong_name = normal.clone();
        wrong_name[4] = b'X';
        rejected_raw(h, protocol, &wrong_name, None);
        let mut wrong_level = normal.clone();
        wrong_level[level_index] = other_level;
        rejected_raw(h, protocol, &wrong_level, Some(UnacceptableProtocolVersion));

        // src/handle_connect.c: read_and_verify_protocol_version and
        // read_and_verify_connect_flags accept reserved flags for MQTT 3.1.
        let mut reserved_fixed_header = normal.clone();
        reserved_fixed_header[0] |= 1;
        let mut reserved_connect_flag = normal;
        reserved_connect_flag[flags_index] |= 1;
        for frame in [reserved_fixed_header, reserved_connect_flag] {
            if protocol == V31 {
                let client = h.open(protocol).unwrap();
                raw(h, client, &frame);
                connack(h, client, Accepted, false);
                ping(h, client);
                disconnect(h, client);
            } else {
                rejected_raw(h, protocol, &frame, None);
            }
        }

        // src/handle_connect.c: read_and_verify_client_credentials_from_packet rejects
        // password flag without username flag in both supported versions.
        let mut password_only = connect_frame(options("p"), protocol);
        password_only[flags_index] |= 0x40;
        password_only[1] += 3;
        password_only.extend_from_slice(b"\0\x01p");
        rejected_raw(h, protocol, &password_only, None);

        // src/handle_connect.c: set_username_from_packet ignores a missing username in 3.1.
        let mut missing_username = connect_frame(options("p"), protocol);
        missing_username[flags_index] |= 0x80;
        if protocol == V31 {
            let client = h.open(protocol).unwrap();
            raw(h, client, &missing_username);
            connack(h, client, Accepted, false);
            disconnect(h, client);
        } else {
            rejected_raw(h, protocol, &missing_username, None);
        }
    }
}

fn connect_frame(settings: Connect, protocol: ProtocolVersion) -> BytesMut {
    let mut wire = BytesMut::new();
    encode(
        &Packet::Connect(Connect {
            protocol,
            ..settings
        }),
        &mut wire,
    )
    .unwrap();
    wire
}

#[track_caller]
fn rejected_raw(
    h: &mut Harness,
    protocol: ProtocolVersion,
    frame: &[u8],
    code: Option<ConnectReturnCode>,
) {
    let client = h.open(protocol).unwrap();
    raw(h, client, frame);
    if let Some(code) = code {
        connack(h, client, code, false);
    }
    closed(h, client);
}

// test/broker/data/CONNECT.json (duplicate CONNECT).
scenario!(second_connect, config(ANONYMOUS));
fn second_connect(h: &mut Harness) {
    for protocol in [V31, V311] {
        let settings = Connect {
            protocol,
            ..options("connect-twice")
        };
        let client = connect_with(h, settings.clone(), false);
        send(h, client, Packet::Connect(settings));
        closed(h, client);
    }
}

// test/broker/01-bad-initial-packets.py and data/PUBLISH.json; small valid packets, not memory tests.
scenario!(first_packet_must_be_connect, config(ANONYMOUS));
fn first_packet_must_be_connect(h: &mut Harness) {
    for packet in [
        Packet::PingReq,
        Packet::Publish(publish("first", b"payload", Q0, 0)),
    ] {
        let client = h.open(V311).unwrap();
        send(h, client, packet);
        closed(h, client);
    }
}

// test/broker/01-connect-max-keepalive.py. src/handle_connect.c: connect__on_authorised
// rejects v3.x keepalive above the configured maximum, including unlimited (zero).
scenario!(
    keepalive_limit,
    config("allow_anonymous true\nmax_keepalive 2")
);
fn keepalive_limit(h: &mut Harness) {
    for protocol in [V31, V311] {
        for (keep_alive, code) in [
            (1, Accepted),
            (2, Accepted),
            (3, IdentifierRejected),
            (0, IdentifierRejected),
        ] {
            let client = h.open(protocol).unwrap();
            send(
                h,
                client,
                Packet::Connect(Connect {
                    protocol,
                    keep_alive,
                    ..options("keepalive")
                }),
            );
            connack(h, client, code, false);
            if code == Accepted {
                ping(h, client);
                disconnect(h, client);
            } else {
                closed(h, client);
            }
        }
    }
}

// test/broker/01-connect-uname-or-anon.py, 01-connect-uname-no-password-denied.py,
// 01-connect-uname-password-denied.py and data/CONNECT.json (zero-length username).
scenario!(credentials_allow_anonymous, auth_config(true));
fn credentials_allow_anonymous(h: &mut Harness) {
    credentials(h, true);
}

scenario!(credentials_require_auth, auth_config(false));
fn credentials_require_auth(h: &mut Harness) {
    credentials(h, false);
}

fn auth_config(anonymous: bool) -> BrokerConfig<'static> {
    BrokerConfig {
        conf: if anonymous {
            ANONYMOUS
        } else {
            "allow_anonymous false"
        },
        passwords: &[("user", "password")],
        acl: None,
    }
}

fn credentials(h: &mut Harness, anonymous: bool) {
    // lib/packet_datatypes.c: packet__read_binary treats zero-length fields as absent.
    let anon_code = if anonymous { Accepted } else { NotAuthorized };
    let empty_password: &[u8] = b"";
    let cases = [
        (None, None, anon_code),
        (Some(""), None, anon_code),
        (Some(""), Some(empty_password), anon_code),
        (Some(""), Some(b"password"), anon_code),
        (Some("user"), Some(b"password"), Accepted),
        (Some("user"), None, NotAuthorized),
        (Some("user"), Some(empty_password), NotAuthorized),
        (Some("user"), Some(b"wrong"), NotAuthorized),
        (Some("unknown"), Some(b"password"), NotAuthorized),
    ];
    for protocol in [V31, V311] {
        for (username, password, code) in cases {
            let client = h.open(protocol).unwrap();
            send(
                h,
                client,
                Packet::Connect(Connect {
                    protocol,
                    username: username.map(str::to_owned),
                    password: password.map(Bytes::from_static),
                    ..options("credentials")
                }),
            );
            connack(h, client, code, false);
            if code == Accepted {
                disconnect(h, client);
            } else {
                closed(h, client);
            }
        }
    }
}
