use bytes::Bytes;
use mqx_codec::v5::{self, Packet, ReasonCode as R};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    AclAccess, BrokerConfig, BytesMut, Client, Scripted, Verdict, WAIT, mid, setup, timeout,
};

async fn send(client: &mut Client, packet: Packet) {
    let mut raw = BytesMut::new();
    v5::encode(&packet, &mut raw).unwrap();
    client.io.write_all(&raw).await.unwrap();
}

async fn receive(client: &mut Client) -> Option<Packet> {
    timeout(WAIT, async {
        loop {
            if let Some(packet) =
                v5::decode(&mut client.buffer, v5::DecodeContext::for_client(0)).unwrap()
            {
                return Some(packet);
            }
            if client.io.read_buf(&mut client.buffer).await.unwrap() == 0 {
                assert!(client.buffer.is_empty());
                return None;
            }
        }
    })
    .await
    .expect("broker did not respond or close the connection")
}

fn connect(id: &str) -> Packet {
    Packet::Connect(v5::Connect {
        client_id: id.into(),
        clean_start: true,
        keep_alive: 0,
        private_protocol_bit: false,
        properties: Vec::new(),
        will: None,
        username: None,
        password: None,
    })
}

// Mosquitto's v5 handlers distinguish an authorization denial (0x87) from
// a backend error (no CONNACK or PUBACK).
#[tokio::test]
async fn mqtt5_external_denials_send_not_authorized_and_backend_errors_close() {
    let plugin = Scripted::new();
    plugin.basic("denied", Verdict::Deny);
    plugin.basic("errored", Verdict::Error);
    plugin.set("active", "deny", AclAccess::Subscribe, Verdict::Deny);
    plugin.set("active", "deny", AclAccess::Write, Verdict::Deny);
    plugin.set("active", "error", AclAccess::Write, Verdict::Error);
    let (broker, info) = setup(BrokerConfig::default(), &plugin).await;

    let (mut denied, _) = Client::spawn(&broker, info.clone());
    send(&mut denied, connect("denied")).await;
    assert!(
        matches!(receive(&mut denied).await, Some(Packet::ConnAck(ack)) if ack.reason == R::NOT_AUTHORIZED)
    );
    assert_eq!(receive(&mut denied).await, None);
    let (mut errored, _) = Client::spawn(&broker, info.clone());
    send(&mut errored, connect("errored")).await;
    assert_eq!(receive(&mut errored).await, None);
    let (mut client, _) = Client::spawn(&broker, info);
    send(&mut client, connect("active")).await;
    assert!(
        matches!(receive(&mut client).await, Some(Packet::ConnAck(ack)) if ack.reason == R::SUCCESS)
    );

    let subscriptions = ["deny", "allow"]
        .into_iter()
        .map(|filter| v5::Subscription {
            filter: filter.into(),
            qos: v5::QoS::AtLeastOnce,
            no_local: false,
            retain_as_published: false,
            retain_handling: v5::RetainHandling::SendAlways,
        })
        .collect();
    send(
        &mut client,
        Packet::Subscribe(v5::Subscribe {
            packet_id: mid(10),
            properties: Vec::new(),
            subscriptions,
        }),
    )
    .await;
    assert_eq!(
        receive(&mut client).await,
        Some(Packet::SubAck(v5::SubscriptionAck {
            packet_id: mid(10),
            properties: Vec::new(),
            reasons: vec![R::NOT_AUTHORIZED, R(1)],
        }))
    );

    for (id, topic) in [(11, "deny"), (12, "error")] {
        send(
            &mut client,
            Packet::Publish(v5::Publish {
                dup: false,
                retain: false,
                qos: v5::QoS::AtLeastOnce,
                topic: topic.into(),
                packet_id: Some(mid(id)),
                properties: Vec::new(),
                payload: Bytes::from_static(b"data"),
            }),
        )
        .await;
        if topic == "deny" {
            assert_eq!(
                receive(&mut client).await,
                Some(Packet::PubAck(v5::PublishAck {
                    packet_id: mid(id),
                    reason: R::NOT_AUTHORIZED,
                    properties: Vec::new(),
                }))
            );
        }
    }
    assert_eq!(receive(&mut client).await, None);
}
