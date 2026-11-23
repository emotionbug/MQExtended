use mqx_codec::v5::{
    self as codec, ConnAck, Connect, LastWill, Packet, Property, Publish, PublishAck,
    ReasonCode as R, ReasonProperties, RetainHandling, Subscribe, Subscription, SubscriptionAck,
    Unsubscribe,
};

use super::{
    ANONYMOUS, BrokerConfig, Bytes, BytesMut, Connection, Duration, Harness, Q0, Q1, Q2, QoS,
    RESPONSE, Reading, Transcript, closed, config, id, raw, read, silent,
};

mod connect;
mod engine;
mod persistence;
mod publish;
mod sessions;
mod subscriptions;

const PACKET_SIZE: u32 = 2_000_000;

fn connack_properties() -> Vec<Property> {
    vec![
        Property::TopicAliasMaximum(10),
        Property::MaximumPacketSize(PACKET_SIZE),
        Property::ReceiveMaximum(20),
    ]
}

fn options(client_id: &str) -> Connect {
    Connect {
        private_protocol_bit: false,
        clean_start: true,
        keep_alive: 0,
        properties: Vec::new(),
        client_id: client_id.into(),
        will: None,
        username: None,
        password: None,
    }
}

#[track_caller]
fn send(h: &mut Harness, client: Connection, packet: Packet) {
    h.send_v5(client, &packet)
        .unwrap_or_else(|err| panic!("{client:?}: MQTT 5 send failed: {err}; packet: {packet:?}"));
}

#[track_caller]
fn received(h: &mut Harness, client: Connection, expected: Packet) {
    received_within(h, client, expected, RESPONSE);
}

#[track_caller]
fn received_within(h: &mut Harness, client: Connection, expected: Packet, timeout: Duration) {
    match read(h, client, timeout) {
        Reading::ReceivedV5 { packet, .. } => assert_eq!(packet, &expected, "{client:?}"),
        reading => panic!("{client:?}: expected {expected:?}, observed {reading:?}"),
    }
}

#[track_caller]
fn open(h: &mut Harness, settings: Connect) -> Connection {
    let client = h.open_v5().unwrap();
    send(h, client, Packet::Connect(settings));
    client
}

#[track_caller]
fn connack(h: &mut Harness, client: Connection, session_present: bool, properties: Vec<Property>) {
    received(
        h,
        client,
        Packet::ConnAck(ConnAck {
            session_present,
            reason: R::SUCCESS,
            properties,
        }),
    );
}

#[track_caller]
fn connect_with(h: &mut Harness, settings: Connect, session_present: bool) -> Connection {
    let client = open(h, settings);
    connack(h, client, session_present, connack_properties());
    client
}

#[track_caller]
fn client(h: &mut Harness, client_id: &str) -> Connection {
    connect_with(h, options(client_id), false)
}

fn subscription(filter: &str, qos: QoS) -> Subscription {
    Subscription {
        filter: filter.into(),
        qos,
        no_local: false,
        retain_as_published: false,
        retain_handling: RetainHandling::SendAlways,
    }
}

#[track_caller]
fn subscribe(h: &mut Harness, client: Connection, mid: u16, filter: &str, qos: QoS) {
    subscribe_with(h, client, mid, vec![subscription(filter, qos)], vec![]);
}

#[track_caller]
fn subscribe_with(
    h: &mut Harness,
    client: Connection,
    mid: u16,
    subscriptions: Vec<Subscription>,
    properties: Vec<Property>,
) {
    let packet_id = id(mid);
    let reasons = subscriptions.iter().map(|s| R(s.qos as u8)).collect();
    send(
        h,
        client,
        Packet::Subscribe(Subscribe {
            packet_id,
            properties,
            subscriptions,
        }),
    );
    received(
        h,
        client,
        Packet::SubAck(SubscriptionAck {
            packet_id,
            properties: Vec::new(),
            reasons,
        }),
    );
}

fn publication(topic: &str, payload: &'static [u8], qos: QoS, mid: u16) -> Publish {
    assert_eq!(mid == 0, qos == Q0);
    Publish {
        dup: false,
        retain: false,
        qos,
        topic: topic.into(),
        packet_id: codec::PacketId::new(mid),
        properties: Vec::new(),
        payload: Bytes::from_static(payload),
    }
}

fn ack(mid: u16, reason: R) -> PublishAck {
    PublishAck {
        packet_id: id(mid),
        reason,
        properties: Vec::new(),
    }
}

#[track_caller]
fn publish_qos1(h: &mut Harness, sender: Connection, message: Publish, reason: R) {
    assert_eq!(message.qos, Q1);
    let mid = message.packet_id.unwrap().get();
    send(h, sender, Packet::Publish(message));
    received(h, sender, Packet::PubAck(ack(mid, reason)));
}

#[track_caller]
fn ping(h: &mut Harness, client: Connection) {
    send(h, client, Packet::PingReq);
    received(h, client, Packet::PingResp);
}

#[track_caller]
fn disconnect(h: &mut Harness, client: Connection, reason: R, properties: Vec<Property>) {
    send(
        h,
        client,
        Packet::Disconnect(ReasonProperties { reason, properties }),
    );
    closed(h, client);
}

#[track_caller]
fn expect_disconnect(h: &mut Harness, client: Connection, reason: R) {
    received(
        h,
        client,
        Packet::Disconnect(ReasonProperties {
            reason,
            properties: vec![],
        }),
    );
    closed(h, client);
}

// These two properties carry random or wall-clock data. Each scenario asserts its values;
// require canonical original frames before masking just the variable value for comparison.
fn compare_variable_property(
    expected: &Transcript,
    actual: &Transcript,
    normalize: fn(&mut Packet),
) {
    assert_eq!(expected.len(), actual.len(), "transcript length");
    for (index, (left, right)) in expected.iter().zip(actual).enumerate() {
        if left == right {
            continue;
        }
        assert_eq!(left.connection, right.connection, "observation #{index}");
        let (
            Reading::ReceivedV5 {
                packet: lp,
                wire: lw,
            },
            Reading::ReceivedV5 {
                packet: rp,
                wire: rw,
            },
        ) = (&left.reading, &right.reading)
        else {
            panic!("observation #{index}: expected {left:?}, observed {right:?}");
        };
        for (packet, wire) in [(lp, lw), (rp, rw)] {
            let mut canonical = BytesMut::new();
            codec::encode(packet, &mut canonical).unwrap();
            assert_eq!(
                &canonical[..],
                &wire[..],
                "noncanonical wire at observation #{index}"
            );
        }
        let (mut lp, mut rp) = (lp.clone(), rp.clone());
        normalize(&mut lp);
        normalize(&mut rp);
        assert_eq!(lp, rp, "observation #{index}");
    }
}
