use std::{fs, path::Path, thread};

use super::*;
use crate::{BrokerKind, compare};

const KEEP: &str = "store/keep";
const EXPIRE: &str = "store/expire";

fn configuration(path: &Path) -> String {
    format!(
        "{ANONYMOUS}\nuser root\npersistence true\npersistence_location {}\nautosave_interval 0",
        path.display()
    )
}

fn configured(conf: &str) -> BrokerConfig<'_> {
    BrokerConfig {
        conf,
        ..BrokerConfig::default()
    }
}

fn durable(client_id: &str, clean_start: bool, expiry: u32) -> Connect {
    Connect {
        clean_start,
        properties: vec![Property::SessionExpiryInterval(expiry)],
        ..options(client_id)
    }
}

fn saved_properties() -> Vec<Property> {
    vec![
        Property::PayloadFormatIndicator(1),
        Property::ContentType("text/plain".into()),
        Property::ResponseTopic("another/topic".into()),
        Property::CorrelationData(Bytes::from_static(b"id\0\x01")),
        Property::UserProperty("key".into(), "first".into()),
        Property::UserProperty("key".into(), "second".into()),
    ]
}

// Mosquitto test/broker/15-persist-publish-properties-v5-0.py,
// 15-persist-client-expired-session.py and 15-persist-client-drop-expired-messages.py.
fn populate(h: &mut Harness) {
    let subscriber = connect_with(h, durable("permanent", false, u32::MAX), false);
    subscribe_with(
        h,
        subscriber,
        11,
        vec![Subscription {
            no_local: true,
            retain_as_published: true,
            ..subscription("store/#", Q1)
        }],
        vec![Property::SubscriptionIdentifier(16384)],
    );
    subscribe(h, subscriber, 12, "$share/group/shared-topic", Q1);
    disconnect(h, subscriber, R::SUCCESS, vec![]);
    connect_with(h, durable("clean-start", true, u32::MAX), false);
    let expiring = connect_with(h, durable("expiring", false, 1), false);
    disconnect(h, expiring, R::SUCCESS, vec![]);
    let publisher = client(h, "publisher");
    publish_qos1(
        h,
        publisher,
        Publish {
            properties: saved_properties(),
            retain: true,
            ..publication(KEEP, b"survives", Q1, 1)
        },
        R::SUCCESS,
    );
    publish_qos1(
        h,
        publisher,
        Publish {
            properties: vec![Property::MessageExpiryInterval(1)],
            retain: true,
            ..publication(EXPIRE, b"expires while shut down", Q1, 2)
        },
        R::SUCCESS,
    );
}

fn resume(h: &mut Harness) {
    let subscriber = connect_with(h, durable("permanent", false, u32::MAX), true);
    let mut props = saved_properties();
    props.push(Property::SubscriptionIdentifier(16384));
    received(
        h,
        subscriber,
        Packet::Publish(Publish {
            properties: props,
            retain: true,
            ..publication(KEEP, b"survives", Q1, 1)
        }),
    );
    send(h, subscriber, Packet::PubAck(ack(1, R::SUCCESS)));
    ping(h, subscriber);
    // An expired message is gone from both the queue and retained tree, but
    // its already allocated packet ID must not be given to the next message.
    publish_qos1(
        h,
        subscriber,
        publication("store/self", b"no local delivery", Q1, 11),
        R::SUCCESS,
    );
    ping(h, subscriber);
    connect_with(h, durable("clean-start", false, u32::MAX), false);
    connect_with(h, durable("expiring", false, u32::MAX), false);
    let reader = client(h, "reader");
    subscribe(h, reader, 2, "store/#", Q1);
    received(
        h,
        reader,
        Packet::Publish(Publish {
            properties: saved_properties(),
            retain: true,
            ..publication(KEEP, b"survives", Q1, 1)
        }),
    );
    send(h, reader, Packet::PubAck(ack(1, R::SUCCESS)));
    ping(h, reader);
    let publisher = client(h, "fresh-publisher");
    // Mosquitto's built-in file writer drops shared subscription leaves.
    publish_qos1(
        h,
        publisher,
        publication("shared-topic", b"not delivered", Q1, 2),
        R::NO_MATCHING_SUBSCRIBERS,
    );
    ping(h, subscriber);
    publish_qos1(
        h,
        publisher,
        publication("store/new", b"new packet id", Q1, 3),
        R::SUCCESS,
    );
    received(
        h,
        subscriber,
        Packet::Publish(Publish {
            properties: vec![Property::SubscriptionIdentifier(16384)],
            ..publication("store/new", b"new packet id", Q1, 3)
        }),
    );
}

#[test]
#[ignore = "requires real Mosquitto 2.1.4 and mqextended binaries"]
fn persistence_v5_expiry_and_subscription_properties_survive_native_and_import_restarts() {
    let original = tempfile::tempdir().unwrap();
    let native = tempfile::tempdir().unwrap();
    let import = tempfile::tempdir().unwrap();
    let source_conf = configuration(original.path());
    let native_conf = configuration(native.path());
    let import_conf = configuration(import.path());
    for (kind, conf) in [
        (BrokerKind::Mosquitto, &source_conf),
        (BrokerKind::MqExtended, &native_conf),
    ] {
        let mut writer = Harness::start(kind, configured(conf)).unwrap();
        populate(&mut writer);
        writer.stop_node(1).unwrap();
    }
    fs::copy(
        original.path().join("mosquitto.db"),
        import.path().join("mosquitto.db"),
    )
    .unwrap();
    thread::sleep(Duration::from_secs(3));
    let restored = |kind, conf| {
        let mut receiver = Harness::start(kind, configured(conf)).unwrap();
        resume(&mut receiver);
        receiver.into_transcript()
    };
    let expected = restored(BrokerKind::Mosquitto, &source_conf);
    compare(&expected, &restored(BrokerKind::MqExtended, &native_conf));
    compare(&expected, &restored(BrokerKind::MqExtended, &import_conf));
}
