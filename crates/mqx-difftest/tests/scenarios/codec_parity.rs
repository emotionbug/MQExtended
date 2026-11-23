use super::*;
use mqx_codec::v5::{Packet as Packet5, ReasonCode};

// lib/packet_mosq.c: packet__read_single rejects a fifth length byte, not the
// four-byte incomplete prefix. Give the broker time to respond before byte five.
scenario!(remaining_length_waits_for_fifth_byte, config(ANONYMOUS));
fn remaining_length_waits_for_fifth_byte(h: &mut Harness) {
    for protocol in [V31, V311] {
        let mut settings = options("partial-length");
        settings.protocol = protocol;
        let c = connect_with(h, settings, false);
        raw(h, c, b"\x30\x80\x80\x80\x80");
        silent(h, c);
        raw(h, c, b"\0");
        closed(h, c);
    }
}

// lib/property_mosq.c: property__read_all checks the property value before
// finding the length mismatch. src/read_handle.c does not reply to bad UTF-8.
scenario!(property_utf8_before_length_error, config(ANONYMOUS));
fn property_utf8_before_length_error(h: &mut Harness) {
    for len in [3, 5] {
        let c = h.open_v5().unwrap();
        raw(h, c, b"\x10\x0e\0\x04MQTT\x05\x02\0\0\0\0\x01i");
        assert!(matches!(
            read(h, c, RESPONSE),
            Reading::ReceivedV5 { packet: Packet5::ConnAck(ack), .. } if ack.reason == ReasonCode::SUCCESS
        ));
        raw(h, c, &[0x30, 8, 0, 1, b't', len, 0x03, 0, 1, 0]);
        closed(h, c);
    }
}

const LEGACY_CONTROL_WILL: &[u8] = b"\x10\x1c\0\x04MQTT\x04\x06\0\0\0\x01i\0\x0b$CONTROL/op\0\0";
const V5_CONTROL_WILL: &[u8] = b"\x10\x1e\0\x04MQTT\x05\x06\0\0\0\0\x01i\0\0\x0b$CONTROL/op\0\0";

// src/handle_connect.c: will__read denies the control namespace only after
// adding the mount point, which can move the Will into an ordinary namespace.
scenario!(
    control_will_after_mount,
    config("allow_anonymous true\nmount_point prefix/")
);
fn control_will_after_mount(h: &mut Harness) {
    let legacy = h.open(V311).unwrap();
    raw(h, legacy, LEGACY_CONTROL_WILL);
    connack(h, legacy, Accepted, false);
    disconnect(h, legacy);

    let v5 = h.open_v5().unwrap();
    raw(h, v5, V5_CONTROL_WILL);
    assert!(matches!(
        read(h, v5, RESPONSE),
        Reading::ReceivedV5 { packet: Packet5::ConnAck(ack), .. } if ack.reason == ReasonCode::SUCCESS
    ));
    raw(h, v5, b"\xe0\0");
    closed(h, v5);
}

// src/handle_connect.c: handle__connect sends no CONNACK for a Will which
// will__read rejects with MOSQ_ERR_ACL_DENIED.
scenario!(
    unmounted_control_will_closes_without_connack,
    config(ANONYMOUS)
);
fn unmounted_control_will_closes_without_connack(h: &mut Harness) {
    let legacy = h.open(V311).unwrap();
    raw(h, legacy, LEGACY_CONTROL_WILL);
    closed(h, legacy);

    let v5 = h.open_v5().unwrap();
    raw(h, v5, V5_CONTROL_WILL);
    closed(h, v5);
}
