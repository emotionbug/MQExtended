use super::*;

// test/broker/09-acl-access-variants.py, adapted to separate reader and writer permissions.
scenario!(acl_read_and_write, acl_config());
fn acl_read_and_write(h: &mut Harness) {
    let login = |username: &str, password: &'static [u8]| Connect {
        username: Some(username.into()),
        password: Some(Bytes::from_static(password)),
        ..options(username)
    };
    let reader = connect_with(h, login("reader", b"reader-test-password"), false);
    let writer = connect_with(h, login("writer", b"writer-test-password"), false);
    // src/plugin_acl_check.c: mosquitto_acl_check allows subscriptions for acl_file;
    // src/subs.c: subs__send applies READ when delivering each message.
    subscribe(h, reader, 1, &[("acl/#", Q1)]);
    subscribe(h, writer, 1, &[("acl/#", Q1)]);

    publish_from(h, writer, publish("acl/allowed", b"delivered", Q1, 10));
    accept_publish(h, reader, publish("acl/allowed", b"delivered", Q1, 1));
    ping(h, writer); // No self-delivery for a write-only user.

    // src/handle_publish.c: process_bad_message still acks a denied QoS 1 publish.
    publish_from(h, writer, publish("acl/blocked-write", b"no write", Q1, 11));
    publish_from(h, writer, publish("acl/blocked-read", b"no read", Q1, 12));
    publish_from(h, reader, publish("acl/allowed", b"read-only user", Q1, 13));
    publish_from(h, writer, publish("acl/allowed", b"still works", Q1, 14));
    accept_publish(h, reader, publish("acl/allowed", b"still works", Q1, 2));
    disconnect(h, reader);
    disconnect(h, writer);
}

fn acl_config() -> BrokerConfig<'static> {
    BrokerConfig {
        conf: "allow_anonymous false",
        passwords: &[
            ("reader", "reader-test-password"),
            ("writer", "writer-test-password"),
        ],
        acl: Some(concat!(
            "user reader\n",
            "topic read acl/#\n",
            "topic deny acl/blocked-read\n",
            "user writer\n",
            "topic write acl/#\n",
            "topic deny acl/blocked-write\n",
        )),
    }
}

fn sparkplug_config() -> String {
    let build = std::path::PathBuf::from(
        std::env::var_os("MOSQUITTO_PLUGIN_BUILD_DIR").expect("set MOSQUITTO_PLUGIN_BUILD_DIR"),
    );
    let module = build.join(format!(
        "plugins/sparkplug-aware/mosquitto_sparkplug_aware.{}",
        if cfg!(windows) { "dll" } else { "so" }
    ));
    format!("allow_anonymous true\nplugin {}", module.display())
}

// plugins/sparkplug-aware/on_message.c and test/broker/20-sparkplug-aware.py.
scenario!(
    sparkplug_certificates,
    BrokerConfig {
        conf: &sparkplug_config(),
        acl: Some("topic read $sparkplug/#\ntopic readwrite spBv1.0/group/#\n"),
        ..BrokerConfig::default()
    }
);
fn sparkplug_certificates(h: &mut Harness) {
    let reader = client(h, "certificate-reader");
    let publisher = client(h, "edge-node");
    let node = "spBv1.0/group/NBIRTH/node";
    let node_cert = "$sparkplug/certificates/spBv1.0/group/NBIRTH/node";
    let device = "spBv1.0/group/DBIRTH/node/device";
    let device_cert = "$sparkplug/certificates/spBv1.0/group/DBIRTH/node/device";
    subscribe(h, reader, 1, &[("$sparkplug/certificates/#", Q1)]);
    for ignored in [
        "spBv1.0/group/NDATA/node",
        "spBv1.0/group/DBIRTH/node",
        "spBv1.0/group/NBIRTH/node/extra",
        "spBv1.0/denied/NBIRTH/node",
    ] {
        publish_from(h, publisher, publish(ignored, b"not a certificate", Q1, 1));
    }
    // The plugin observes the incoming QoS 2 PUBLISH, not its later PUBREL.
    send(
        h,
        publisher,
        Packet::Publish(publish(node, b"\0birth", Q2, 2)),
    );
    received(h, publisher, Packet::PubRec(id(2)));
    accept_publish(h, reader, publish(node_cert, b"\0birth", Q1, 1));
    // Keep the QoS 2 flight pending while the same client sends a QoS 1 birth.
    publish_from(h, publisher, publish(device, b"first device", Q1, 8));
    accept_publish(h, reader, publish(device_cert, b"first device", Q1, 2));
    send(h, publisher, Packet::PubRel(id(2)));
    received(h, publisher, Packet::PubComp(id(2)));
    publish_from(h, publisher, publish(device, b"device", Q0, 0));
    accept_publish(h, reader, publish(device_cert, b"device", Q0, 0));

    // An empty BIRTH clears its retained copy without touching the other one.
    publish_from(h, publisher, publish(node, b"", Q1, 3));
    accept_publish(h, reader, publish(node_cert, b"", Q1, 3));
    let late = client(h, "late-reader");
    subscribe(h, late, 1, &[("$sparkplug/certificates/#", Q1)]);
    accept_publish(
        h,
        late,
        Publish {
            retain: true,
            ..publish(device_cert, b"device", Q0, 0)
        },
    );
    ping(h, late);
}

// test/broker/03-pattern-matching.py: # includes its parent; + matches an empty level.
scenario!(wildcard_matching, config(ANONYMOUS));
fn wildcard_matching(h: &mut Harness) {
    let subscriber = client(h, "patterns");
    let publisher = client(h, "publisher");
    subscribe(h, subscriber, 312, &[("foo/#", Q0), ("bar/+/baz", Q0)]);
    for (topic, matches) in [
        ("foo", true),
        ("foo/", true),
        ("foo/bar/baz", true),
        ("bar//baz", true),
        ("bar/xx/baz", true),
        ("bar/baz", false),
        ("bar/xx/yy/baz", false),
        ("foobar", false),
    ] {
        publish_from(h, publisher, publish(topic, b"message", Q0, 0));
        if matches {
            accept_publish(h, subscriber, publish(topic, b"message", Q0, 0));
        } else {
            ping(h, subscriber);
        }
    }
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// Extends test/broker/03-pattern-matching.py; src/topic_tok.c: sub__topic_tokenise separates $ roots.
scenario!(dollar_topics, config(ANONYMOUS));
fn dollar_topics(h: &mut Harness) {
    let wildcard = client(h, "wildcard");
    let dollar = client(h, "dollar");
    let publisher = client(h, "publisher");
    // src/retain.c: at level zero, "$app/#" replays the parent only if
    // retain__search also visited a child. Exact "$app" still has a value.
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish("$app", b"root", Q1, 7)
        },
    );
    subscribe(h, wildcard, 1, &[("#", Q0), ("+/status", Q0)]);
    subscribe(h, dollar, 1, &[("$app/#", Q0)]);
    ping(h, dollar);
    // Application-owned $ topics avoid nondeterministic broker-generated $SYS counters.
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish("$app/status", b"app", Q1, 8)
        },
    );
    accept_publish(h, dollar, publish("$app/status", b"app", Q0, 0));
    subscribe(h, dollar, 2, &[("$app/#", Q0)]);
    for (topic, value) in [("$app/status", &b"app"[..]), ("$app", &b"root"[..])] {
        accept_publish(
            h,
            dollar,
            Publish {
                retain: true,
                ..publish(topic, value, Q0, 0)
            },
        );
    }
    ping(h, wildcard);
    publish_from(h, publisher, publish("ordinary/topic", b"ordinary", Q0, 0));
    accept_publish(h, wildcard, publish("ordinary/topic", b"ordinary", Q0, 0));
    ping(h, dollar);
    disconnect(h, wildcard);
    disconnect(h, dollar);
    disconnect(h, publisher);
}

// Extends test/broker/03-pattern-matching.py.
scenario!(overlapping_subscriptions, config(ANONYMOUS));
fn overlapping_subscriptions(h: &mut Harness) {
    overlapping(h, true);
}

scenario!(
    overlapping_subscriptions_deduplicated,
    config("allow_anonymous true\nallow_duplicate_messages false")
);
fn overlapping_subscriptions_deduplicated(h: &mut Harness) {
    overlapping(h, false);
}

fn overlapping(h: &mut Harness, duplicates: bool) {
    let subscriber = client(h, "overlap");
    let publisher = client(h, "publisher");
    let topic = "overlap/leaf";
    subscribe(h, subscriber, 1, &[("overlap/#", Q1), (topic, Q2)]);
    publish_from(h, publisher, publish(topic, b"overlap", Q2, 55));
    // src/subs.c: sub__search visits literal matches before #; src/database.c:
    // db__message_insert_outgoing only suppresses duplicates when explicitly configured.
    received(
        h,
        subscriber,
        Packet::Publish(publish(topic, b"overlap", Q2, 1)),
    );
    if duplicates {
        accept_publish(h, subscriber, publish(topic, b"overlap", Q1, 2));
    }
    send(h, subscriber, Packet::PubRec(id(1)));
    received(h, subscriber, Packet::PubRel(id(1)));
    send(h, subscriber, Packet::PubComp(id(1)));
    ping(h, subscriber);
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// Extends test/broker/03-publish-b2c-qos1-len.py. src/subs.c: subs__send caps to subscribed QoS.
scenario!(outgoing_qos_capped, config(ANONYMOUS));
fn outgoing_qos_capped(h: &mut Harness) {
    let subscriber = client(h, "subscriber");
    let publisher = client(h, "publisher");
    let topic = "qos/capped";
    subscribe(h, subscriber, 1, &[(topic, Q1)]);
    publish_from(h, publisher, publish(topic, b"downgraded", Q2, 21));
    accept_publish(h, subscriber, publish(topic, b"downgraded", Q1, 1));
    publish_from(h, publisher, publish(topic, b"not upgraded", Q0, 0));
    accept_publish(h, subscriber, publish(topic, b"not upgraded", Q0, 0));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/04-retain-upgrade-outgoing-qos.py, plus live delivery.
scenario!(
    outgoing_qos_upgraded,
    config("allow_anonymous true\nupgrade_outgoing_qos true")
);
fn outgoing_qos_upgraded(h: &mut Harness) {
    let publisher = client(h, "publisher");
    let subscriber = client(h, "subscriber");
    let topic = "retain/qos0/test";
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(topic, b"stored", Q0, 0)
        },
    );
    subscribe(h, subscriber, 16, &[(topic, Q1)]);
    accept_publish(
        h,
        subscriber,
        Publish {
            retain: true,
            ..publish(topic, b"stored", Q1, 1)
        },
    );
    publish_from(h, publisher, publish(topic, b"live", Q0, 0));
    accept_publish(h, subscriber, publish(topic, b"live", Q1, 2));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/03-pattern-matching.py and 02-subpub-qos0-send-retain.py.
scenario!(retain_live_and_replay, config(ANONYMOUS));
fn retain_live_and_replay(h: &mut Harness) {
    let live = client(h, "live");
    let publisher = client(h, "publisher");
    let topic = "retain/flag";
    subscribe(h, live, 1, &[(topic, Q1)]);
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(topic, b"stored", Q1, 42)
        },
    );
    accept_publish(h, live, publish(topic, b"stored", Q1, 1));
    let late = client(h, "late");
    subscribe(h, late, 2, &[(topic, Q1)]);
    accept_publish(
        h,
        late,
        Publish {
            retain: true,
            ..publish(topic, b"stored", Q1, 1)
        },
    );
    disconnect(h, late);
    disconnect(h, live);
    disconnect(h, publisher);
}

// test/broker/15-persist-retain-clear.py, without persistence across a broker restart.
scenario!(retained_clear, config(ANONYMOUS));
fn retained_clear(h: &mut Harness) {
    let live = client(h, "live");
    let publisher = client(h, "publisher");
    let topic = "retain/clear";
    subscribe(h, live, 1, &[(topic, Q0)]);
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(topic, b"old", Q0, 0)
        },
    );
    accept_publish(h, live, publish(topic, b"old", Q0, 0));
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish(topic, b"", Q0, 0)
        },
    );
    accept_publish(h, live, publish(topic, b"", Q0, 0));
    publish_from(
        h,
        publisher,
        Publish {
            retain: true,
            ..publish("retain/keep", b"keep", Q0, 0)
        },
    );
    let late = client(h, "late");
    subscribe(h, late, 1, &[("retain/#", Q0)]);
    accept_publish(
        h,
        late,
        Publish {
            retain: true,
            ..publish("retain/keep", b"keep", Q0, 0)
        },
    );
    ping(h, late);
    disconnect(h, late);
    disconnect(h, live);
    disconnect(h, publisher);
}

// test/broker/02-subpub-qos0-oversize-payload.py and 02-subpub-qos1-oversize-payload.py.
scenario!(
    message_size_limit,
    config("allow_anonymous true\nmessage_size_limit 1")
);
fn message_size_limit(h: &mut Harness) {
    let subscriber = client(h, "subscriber");
    let publisher = client(h, "publisher");
    let topic = "payload/limit";
    subscribe(h, subscriber, 1, &[(topic, Q2)]);
    for (qos, mid) in [(Q0, 0), (Q1, 10), (Q2, 11)] {
        // src/handle_publish.c: process_bad_message discards the payload but still acks QoS 1/2.
        publish_from(
            h,
            publisher,
            Publish {
                retain: true,
                ..publish(topic, b"AB", qos, mid)
            },
        );
    }
    publish_from(h, publisher, publish(topic, b"A", Q1, 12));
    accept_publish(h, subscriber, publish(topic, b"A", Q1, 1));
    let late = client(h, "late");
    subscribe(h, late, 2, &[(topic, Q2)]);
    ping(h, late); // The oversized retained messages were not stored.
    disconnect(h, late);
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/data/PUBLISH.json, SUBSCRIBE.json and UNSUBSCRIBE.json.
scenario!(invalid_topics_and_filters, config(ANONYMOUS));
fn invalid_topics_and_filters(h: &mut Harness) {
    let frames: &[&[u8]] = &[
        b"\x30\x09\0\0payload", // Empty PUBLISH topic
        b"\x30\x0e\0\x05+opicpayload",
        b"\x30\x0e\0\x05#opicpayload",
        b"\x30\x0e\0\x05top\0\0payload",
        b"\x82\x0a\x12\x34\0\x05ab/+e\0", // Invalid SUBSCRIBE filter
        b"\xA2\x09\x12\x34\0\x05ab/+e",   // Invalid UNSUBSCRIBE filter
    ];
    for frame in frames {
        let client = client(h, "invalid");
        raw(h, client, frame);
        closed(h, client);
    }
}

// test/broker/03-publish-b2c-qos1-len.py and data/PUBLISH.json (QoS 1 flow).
scenario!(qos1_roundtrip, config(ANONYMOUS));
fn qos1_roundtrip(h: &mut Harness) {
    let subscriber = client(h, "subscriber");
    let publisher = client(h, "publisher");
    let topic = "qos/one";
    subscribe(h, subscriber, 17, &[(topic, Q1)]);
    for (source_mid, dest_mid, payload) in [(31, 1, &b"first\0"[..]), (32, 2, &b"second\xff"[..])] {
        publish_from(h, publisher, publish(topic, payload, Q1, source_mid));
        accept_publish(h, subscriber, publish(topic, payload, Q1, dest_mid));
    }
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// lib/packet_mosq.c: packet__read_single refreshes keepalive while the body
// of a large packet is still arriving, not just when the packet is complete.
scenario!(keepalive_during_large_publish, config(ANONYMOUS));
fn keepalive_during_large_publish(h: &mut Harness) {
    const PAYLOAD: &[u8] = &[0x5a; 16 * 1024];
    let sub = client(h, "telemetry-reader");
    let topic = "telemetry/sample";
    subscribe(h, sub, 1, &[(topic, Q1)]);
    let publisher = connect_with(
        h,
        Connect {
            keep_alive: 2,
            ..options("meter")
        },
        false,
    );
    let mut frame = BytesMut::new();
    encode(
        &Packet::Publish(publish(topic, PAYLOAD, Q1, 42)),
        &mut frame,
    )
    .unwrap();
    // One valid publication spread over four seconds (keepalive grace is three).
    for (index, fragment) in frame.chunks(2048).enumerate() {
        if index != 0 {
            std::thread::sleep(Duration::from_millis(500));
        }
        raw(h, publisher, fragment);
    }
    received(h, publisher, Packet::PubAck(id(42)));
    accept_publish(h, sub, publish(topic, PAYLOAD, Q1, 1));
}

// test/broker/03-publish-b2c-qos2-len.py and data/PUBLISH.json (duplicate before PUBREL).
scenario!(qos2_roundtrip_and_duplicate, config(ANONYMOUS));
fn qos2_roundtrip_and_duplicate(h: &mut Harness) {
    let subscriber = client(h, "subscriber");
    let publisher = client(h, "publisher");
    let topic = "qos/two";
    subscribe(h, subscriber, 17, &[(topic, Q2)]);
    let message = publish(topic, b"once", Q2, 41);
    send(h, publisher, Packet::Publish(message.clone()));
    received(h, publisher, Packet::PubRec(id(41)));
    send(
        h,
        publisher,
        Packet::Publish(Publish {
            dup: true,
            ..message
        }),
    );
    received(h, publisher, Packet::PubRec(id(41)));
    silent(h, subscriber);
    send(h, publisher, Packet::PubRel(id(41)));
    received(h, publisher, Packet::PubComp(id(41)));
    accept_publish(h, subscriber, publish(topic, b"once", Q2, 1));
    ping(h, subscriber); // Fails if the duplicate made it to the subscriber.
    disconnect(h, subscriber);
    disconnect(h, publisher);
}

// test/broker/03-pattern-matching.py (unsubscribe); extended to confirm independent filters survive.
scenario!(unsubscribe_stops_delivery, config(ANONYMOUS));
fn unsubscribe_stops_delivery(h: &mut Harness) {
    let subscriber = client(h, "subscriber");
    let publisher = client(h, "publisher");
    subscribe(h, subscriber, 312, &[("remove/#", Q0), ("keep/#", Q0)]);
    publish_from(h, publisher, publish("remove/leaf", b"before", Q0, 0));
    accept_publish(h, subscriber, publish("remove/leaf", b"before", Q0, 0));
    unsubscribe(h, subscriber, 234, "remove/#");
    unsubscribe(h, subscriber, 235, "remove/#");
    publish_from(h, publisher, publish("remove/leaf", b"after", Q0, 0));
    publish_from(h, publisher, publish("keep/leaf", b"kept", Q0, 0));
    accept_publish(h, subscriber, publish("keep/leaf", b"kept", Q0, 0));
    disconnect(h, subscriber);
    disconnect(h, publisher);
}
