"""Run Eclipse Paho Python clients: python paho_interop.py HOST PUB_PORT SUB_PORT."""

import argparse
from contextlib import contextmanager
from queue import Empty, Queue
from uuid import uuid4

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

TIMEOUT = 10


def expect(actual, expected, operation):
    if actual != expected:
        raise AssertionError(f"{operation}: expected {expected!r}, got {actual!r}")


class Peer:
    def __init__(self, protocol, client_id, clean_session):
        self.label = f"{protocol.name} {client_id}"
        self.acks = Queue()
        # A subscription's PUBLISH can arrive before its SUBACK.
        self.messages = Queue()
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=protocol,
            clean_session=clean_session,
            reconnect_on_failure=False,  # Do not let Paho downgrade 3.1.1 to 3.1.
        )
        self.client.connect_timeout = TIMEOUT
        self.client.on_connect = lambda c, u, flags, reason, props: self.acks.put(
            ("CONNACK", reason.value, flags.session_present)
        )
        self.client.on_subscribe = lambda c, u, mid, reasons, props: self.acks.put(
            ("SUBACK", mid, [reason.value for reason in reasons])
        )
        self.client.on_publish = lambda c, u, mid, reason, props: self.acks.put(
            ("PUBLISH completion", mid, reason.value)
        )
        self.client.on_disconnect = lambda c, u, flags, reason, props: self.acks.put(
            ("DISCONNECT", reason.value, flags.is_disconnect_packet_from_server)
        )
        self.client.on_message = lambda c, u, message: self.messages.put(message)

    def wait(self, events, operation):
        try:
            return events.get(timeout=TIMEOUT)
        except Empty:
            raise AssertionError(f"{self.label}: timed out waiting for {operation}") from None

    def expect_ack(self, *expected):
        operation = expected[0]
        expect(self.wait(self.acks, operation), expected, f"{self.label}: {operation}")

    def subscribe(self, topic_filter, qos):
        rc, mid = self.client.subscribe(topic_filter, qos=qos)
        expect(rc, mqtt.MQTT_ERR_SUCCESS, f"{self.label}: subscribe to {topic_filter}")
        self.expect_ack("SUBACK", mid, [qos])

    def publish(self, topic, payload, qos, *, retain=False, properties=None):
        info = self.client.publish(topic, payload, qos=qos, retain=retain, properties=properties)
        expect(info.rc, mqtt.MQTT_ERR_SUCCESS, f"{self.label}: publish to {topic}")
        self.expect_ack("PUBLISH completion", info.mid, 0)

    def receive(self, topic, payload, qos, *, retained=False):
        message = self.wait(self.messages, f"PUBLISH on {topic}")
        expect(
            (message.topic, message.payload, message.qos, message.retain),
            (topic, payload, qos, retained),
            f"{self.label}: received PUBLISH (topic, payload, QoS, RETAIN)",
        )
        return message


@contextmanager
def connected(endpoint, protocol, client_id, *, clean_session=None, session_present=False):
    peer = Peer(protocol, client_id, clean_session)
    options = {"clean_start": True} if protocol == mqtt.MQTTv5 else {}
    rc = peer.client.connect(*endpoint, **options)
    expect(rc, mqtt.MQTT_ERR_SUCCESS, f"{peer.label}: connect to {endpoint}")
    try:
        expect(peer.client.loop_start(), mqtt.MQTT_ERR_SUCCESS, f"{peer.label}: start loop")
        peer.expect_ack("CONNACK", 0, session_present)
        yield peer
    except BaseException:
        peer.client.disconnect()
        raise
    else:
        # In Paho's threaded loop, _packet_queue can wake the writer, which
        # sends DISCONNECT and closes the socket before disconnect() returns.
        # Require the successful, locally initiated callback in either case.
        rc = peer.client.disconnect()
        if rc not in (mqtt.MQTT_ERR_SUCCESS, mqtt.MQTT_ERR_NO_CONN):
            raise AssertionError(f"{peer.label}: disconnect: {rc}")
        peer.expect_ack("DISCONNECT", 0, False)
    finally:
        peer.client.loop_stop()


def mqtt31(pub_endpoint, sub_endpoint, token, root):
    topic = f"{root}/31/value"
    with connected(pub_endpoint, mqtt.MQTTv31, f"paho31pub{token}") as publisher:
        publisher.publish(topic, b"\x00retained\xff", qos=2, retain=True)
        with connected(sub_endpoint, mqtt.MQTTv31, f"paho31sub{token}") as subscriber:
            subscriber.subscribe(f"{root}/31/+", qos=2)
            subscriber.receive(topic, b"\x00retained\xff", qos=2, retained=True)
            # A new retained publish to an established subscription is live, not a replay.
            publisher.publish(topic, b"replacement", qos=2, retain=True)
            subscriber.receive(topic, b"replacement", qos=2)
        publisher.publish(topic, b"", qos=2, retain=True)


def mqtt311(pub_endpoint, sub_endpoint, token, root):
    # MQTT 3.1.1 §§3.1.2.4 and 3.2.2.2; Mosquitto 05-clean-session-qos1.py.
    topic = f"{root}/311/session"
    subscriber_id = f"paho311sub{token}"
    with connected(pub_endpoint, mqtt.MQTTv311, subscriber_id, clean_session=False) as subscriber:
        subscriber.subscribe(topic, qos=1)
    # The old client has disconnected and cannot acknowledge this PUBLISH.
    # Wait for PUBACK before resuming the subscription, without re-subscribing.
    with connected(pub_endpoint, mqtt.MQTTv311, f"paho311pub{token}") as publisher:
        publisher.publish(topic, b"queued for session", qos=1)
        with connected(
            sub_endpoint, mqtt.MQTTv311, subscriber_id, clean_session=False, session_present=True
        ) as resumed:
            resumed.receive(topic, b"queued for session", qos=1)
            publisher.publish(topic, b"live after resume", qos=1)
            resumed.receive(topic, b"live after resume", qos=1)
    with connected(sub_endpoint, mqtt.MQTTv311, subscriber_id, clean_session=True):
        pass  # Clear the durable session and require Session Present = 0.


def mqtt5(pub_endpoint, sub_endpoint, token, root):
    # MQTT 5 §§3.3.2.3.5–6 and 4.10; Mosquitto property__process_publish.
    request_topic = f"{root}/5/request"
    response_topic = f"{root}/5/response"
    correlation = b"\x00\xffpaho\x80\x00"
    with connected(pub_endpoint, mqtt.MQTTv5, f"paho5req{token}") as requester, connected(
        sub_endpoint, mqtt.MQTTv5, f"paho5res{token}"
    ) as responder:
        requester.subscribe(response_topic, qos=1)
        responder.subscribe(request_topic, qos=1)
        properties = Properties(PacketTypes.PUBLISH)
        properties.ResponseTopic = response_topic
        properties.CorrelationData = correlation
        requester.publish(request_topic, b"status?", qos=1, properties=properties)

        request = responder.receive(request_topic, b"status?", qos=1)
        reply_to = getattr(request.properties, "ResponseTopic", None)
        reply_correlation = getattr(request.properties, "CorrelationData", None)
        expect(reply_to, response_topic, "MQTT 5 request Response Topic")
        expect(reply_correlation, correlation, "MQTT 5 request Correlation Data")
        response_properties = Properties(PacketTypes.PUBLISH)
        response_properties.CorrelationData = reply_correlation
        responder.publish(reply_to, b"ready", qos=1, properties=response_properties)

        response = requester.receive(response_topic, b"ready", qos=1)
        expect(
            getattr(response.properties, "CorrelationData", None),
            correlation,
            "MQTT 5 response Correlation Data",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("pub_port", type=int)
    parser.add_argument("sub_port", type=int)
    args = parser.parse_args()
    pub_endpoint = (args.host, args.pub_port)
    sub_endpoint = (args.host, args.sub_port)
    token = uuid4().hex[:12]
    root = f"mqx-interop/paho/{token}"
    mqtt31(pub_endpoint, sub_endpoint, token, root)
    mqtt311(pub_endpoint, sub_endpoint, token, root)
    mqtt5(pub_endpoint, sub_endpoint, token, root)
    print("Paho MQTT 3.1, 3.1.1 and 5.0 interoperability passed")


if __name__ == "__main__":
    main()
