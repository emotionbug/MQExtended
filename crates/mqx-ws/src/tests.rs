use std::future::{Future, poll_fn};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf, duplex};
use tokio::time::timeout;

use crate::{WsError, WsOptions, WsStream, accept};

mod differential;

// Mosquitto test/broker/13-websocket-bad-origin.py (same key and response).
const REQUEST: &str = concat!(
    "GET /mqtt HTTP/1.1\r\n",
    "Host: localhost\r\n",
    "Upgrade: websocket\r\n",
    "Connection: Upgrade\r\n",
    "Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n",
    "Sec-WebSocket-Protocol: mqtt\r\n",
    "Sec-WebSocket-Version: 13\r\n",
    "Origin: example.org\r\n",
    "\r\n",
);
const RESPONSE: &str = concat!(
    "HTTP/1.1 101 Switching Protocols\r\n",
    "Upgrade: WebSocket\r\n",
    "Connection: Upgrade\r\n",
    "Sec-WebSocket-Accept: Ako91O0lxiq8gN0+b9YCijMx8lk=\r\n",
    "Sec-WebSocket-Protocol: mqtt\r\n",
    "\r\n",
);

fn options() -> WsOptions {
    WsOptions {
        packet_buffer_size: 4096,
        origins: vec!["example.org".into(), "localhost:8000".into()],
    }
}

async fn response<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    while let Some(byte) = read_byte(io).await? {
        result.push(byte);
        if result.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(result)
}

async fn read_byte<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Option<u8>> {
    let mut buf = [0];
    Ok((io.read(&mut buf).await? == 1).then_some(buf[0]))
}

async fn handshake(
    request: &[u8],
    options: &WsOptions,
    chunk_size: usize,
) -> (Result<WsStream<DuplexStream>, WsError>, Vec<u8>) {
    let (mut client, server) = duplex(8192);
    let connect = async {
        for chunk in request.chunks(chunk_size) {
            if client.write_all(chunk).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let _ = client.shutdown().await;
        response(&mut client).await.unwrap()
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(accept(server, options), connect)
    })
    .await
    .expect("WebSocket handshake timed out")
}

#[tokio::test]
async fn upgrade_response_matches_builtin_websocket() {
    // src/http_serv.c: http__read; no path routing or HTTP minor version check.
    for first in [
        "GET /mqtt HTTP/1.1\r\n",
        "HEAD /file.txt HTTP/1.0\r\n",
        "G /*?x=y HTTP/1.9\r\n",
        "\r\nGET  https://any/path  HTTP/1.1\n",
    ] {
        let raw = REQUEST.replacen("GET /mqtt HTTP/1.1\r\n", first, 1);
        let (server, reply) = handshake(raw.as_bytes(), &options(), 1).await;
        assert!(server.is_ok(), "{first:?}: {server:?}");
        assert_eq!(reply, RESPONSE.as_bytes());
    }
}

#[tokio::test]
async fn subprotocol_requires_a_case_sensitive_prefix_not_a_token_list() {
    // src/http_serv.c: http__read uses strncmp with the requested value length.
    for protocol in ["mqtt", "mqttv3.1", "mqttv", "m", ""] {
        let raw = REQUEST.replace("Protocol: mqtt", &format!("Protocol: {protocol}"));
        let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
        assert!(server.is_ok(), "{server:?}");
        let expected = RESPONSE.replace("Protocol: mqtt", &format!("Protocol: {protocol}"));
        assert_eq!(reply, expected.as_bytes());
    }
    for protocol in ["MQTT", "graphql-ws", "mqtt, mqttv3.1", "other, mqtt"] {
        let raw = REQUEST.replace("Protocol: mqtt", &format!("Protocol: {protocol}"));
        let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
        assert!(matches!(server, Err(WsError::Subprotocol)));
        assert!(reply.is_empty());
    }
}

#[tokio::test]
async fn required_headers_and_permissive_header_comparisons() {
    // src/http_serv.c: http__read uses incoming header-name lengths, ignores
    // absent Host/Version, and the Connection loop always accepts a value.
    let raw = REQUEST
        .replace("Host: localhost\r\n", "")
        .replace("Sec-WebSocket-Version: 13\r\n", "")
        .replace("Upgrade: websocket", "uP: \tWeB\t")
        .replace("Connection: Upgrade", "CoNn: keep-alive");
    let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
    assert!(server.is_ok(), "{server:?}");
    assert_eq!(reply, RESPONSE.as_bytes());

    for line in [
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==",
    ] {
        let raw = REQUEST.replace(&format!("{line}\r\n"), "");
        let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
        assert!(
            matches!(server, Err(WsError::MissingUpgrade)),
            "{line}: {server:?}"
        );
        assert!(reply.is_empty());
    }
    let raw = REQUEST.replace("Version: 13", "Version: 12");
    let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
    assert!(matches!(server, Err(WsError::Version)));
    assert!(reply.is_empty());

    // lib/net_ws.c: ws__create_accept_key hashes an arbitrary nonempty value.
    let raw = REQUEST.replace("1JaITHdgDZVd/4OE2AzTTA==", "test");
    let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
    assert!(server.is_ok(), "{server:?}");
    assert_eq!(
        reply,
        RESPONSE
            .replace(
                "Ako91O0lxiq8gN0+b9YCijMx8lk=",
                "tNpbgC8ZQDOcSkHAWopKzQjJ1hI="
            )
            .as_bytes()
    );
}

#[tokio::test]
async fn origin_filter_applies_to_every_present_origin() {
    // src/http_serv.c: http__read checks every Origin against case-sensitive
    // configured prefixes, but does not require an Origin header.
    for value in [
        "",
        "Origin: example\r\n",
        "Origin: localhost:8000\r\nOrigin: example.org\r\n",
    ] {
        let raw = REQUEST.replace("Origin: example.org\r\n", value);
        let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
        assert!(server.is_ok(), "{server:?}");
        assert_eq!(reply, RESPONSE.as_bytes());
    }
    for value in [
        "Origin: Example.org\r\n",
        "Origin: example.org.evil\r\n",
        "Origin: example.org\r\nOrigin: unrelated\r\n",
    ] {
        let raw = REQUEST.replace("Origin: example.org\r\n", value);
        let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
        assert!(matches!(server, Err(WsError::Origin)));
        assert!(reply.is_empty());
    }
}

#[tokio::test]
async fn non_upgrades_and_invalid_requests_get_no_http_response() {
    // src/http_serv.c: http__read has neither error responses nor http_dir
    // serving. deps/picohttpparser/picohttpparser.c rejects space before colon.
    for raw in [
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
        REQUEST.replace("GET /", "POST /"),
        REQUEST.replace("Upgrade:", "Upgrade :"),
        REQUEST.replace("HTTP/1.1", "HTTP/2.0"),
        format!("{REQUEST}pipelined"),
    ] {
        let (server, reply) = handshake(raw.as_bytes(), &options(), 8192).await;
        assert!(server.is_err(), "unexpected upgrade for {raw:?}");
        assert!(reply.is_empty());
    }
}

#[tokio::test]
async fn packet_buffer_reserves_one_byte_and_headers_are_counted() {
    // src/http_serv.c: http__read NUL-terminates the buffer and calls the
    // parser with room for 100 headers.
    let mut options = options();
    options.packet_buffer_size = REQUEST.len() as u16 + 1;
    let (server, reply) = handshake(REQUEST.as_bytes(), &options, 8192).await;
    assert!(server.is_ok(), "{server:?}");
    assert_eq!(reply, RESPONSE.as_bytes());
    options.packet_buffer_size -= 1;
    let (server, reply) = handshake(REQUEST.as_bytes(), &options, 1).await;
    assert!(matches!(server, Err(WsError::HeaderLimit)));
    assert!(reply.is_empty());

    options.packet_buffer_size = 4096;
    for count in [93, 94] {
        let raw = format!(
            "{}{}\r\n",
            &REQUEST[..REQUEST.len() - 2],
            "X: y\r\n".repeat(count)
        );
        let (server, reply) = handshake(raw.as_bytes(), &options, 8192).await;
        assert_eq!(server.is_ok(), count == 93, "{server:?}");
        assert_eq!(reply.is_empty(), count == 94);
    }
}

#[tokio::test]
async fn upgrade_discards_overread_if_latest_read_is_smaller_than_header() {
    // src/http_serv.c: http__read compares the total header size with only the
    // last read, then resets the input buffer without replaying trailing data.
    let (mut client, server) = duplex(8192);
    let options = options();
    let mut upgrade = std::pin::pin!(accept(server, &options));
    client
        .write_all(&REQUEST.as_bytes()[..REQUEST.len() - 2])
        .await
        .unwrap();
    // Poll the server on the partial request before making the rest readable.
    poll_fn(|cx| {
        assert!(upgrade.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let server = async {
        let mut stream = upgrade.await.unwrap();
        let mut data = [0];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(data, [b'B']);
    };
    let client = async {
        client.write_all(b"\r\n\x82\x01A").await.unwrap();
        assert_eq!(response(&mut client).await.unwrap(), RESPONSE.as_bytes());
        client.write_all(b"\x82\x01B").await.unwrap();
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
}

fn frame(first: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut result = vec![first];
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n @ 0..=125 => result.push(mask_bit | n as u8),
        n @ 126..=65_535 => {
            result.push(mask_bit | 126);
            result.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            result.push(mask_bit | 127);
            result.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if let Some(mask) = mask {
        result.extend_from_slice(&mask);
        result.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i % 4]),
        );
    } else {
        result.extend_from_slice(payload);
    }
    result
}

#[tokio::test]
async fn binary_stream_joins_frames_and_ignores_empty_data_and_pong() {
    // lib/net_ws.c: read_ws_opcode and net__read_ws ignore data-frame FIN
    // ordering and do not pass empty frames or WebSocket pong to MQTT.
    let (mut client, server) = duplex(1024);
    let mut server = WsStream::new(server);
    let mask = Some(*b"key!");
    for (first, data) in [
        (0x80, &b"a"[..]), // continuation with no preceding initial fragment
        (0x02, &b"bc"[..]),
        (0x82, &b""[..]),
        (0x8a, &b"skip"[..]),
        (0x82, &b"def"[..]),
        (0x80, &b"g"[..]),
    ] {
        client.write_all(&frame(first, data, mask)).await.unwrap();
    }
    let mut result = [0; 7];
    server.read_exact(&mut result).await.unwrap();
    assert_eq!(&result, b"abcdefg");
}

#[tokio::test]
async fn ping_echo_and_mask_reuse_match_builtin() {
    // lib/net_ws.c: net__read_ws applies the installed XOR key even when
    // a later frame omits its masking bit; ws__prepare_packet sends a pong.
    let (mut client, server) = duplex(1024);
    let mut server = WsStream::new(server);
    client
        .write_all(&frame(0x89, b"before", None))
        .await
        .unwrap();
    client
        .write_all(&frame(0x89, b"ping", Some([1, 2, 3, 4])))
        .await
        .unwrap();
    client.write_all(&frame(0x89, b"rust", None)).await.unwrap();
    client.write_all(&frame(0x89, b"", None)).await.unwrap();
    client
        .write_all(&frame(0x82, b"MQTT", Some([7, 2, 9, 4])))
        .await
        .unwrap();
    let mut data = [0; 4];
    server.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"MQTT");
    let expected = [
        b"\x8a\x06before".as_slice(),
        b"\x8a\x04ping",
        b"\x8a\x04swpp",
        b"\x8a\x00",
    ]
    .concat();
    let mut result = vec![0; expected.len()];
    client.read_exact(&mut result).await.unwrap();
    assert_eq!(result, expected);
}

#[tokio::test]
async fn peer_close_is_ignored_but_local_shutdown_sends_close() {
    // lib/net_ws.c: net__read_ws discards peer close; src/context.c:
    // context__disconnect writes a close with its own status on teardown.
    let (mut client, server) = duplex(1024);
    let mut server = WsStream::new(server);
    client
        .write_all(&frame(0x88, b"\x03\xe9reason", None))
        .await
        .unwrap();
    client.write_all(&frame(0x88, b"", None)).await.unwrap();
    client.write_all(&frame(0x82, b"data", None)).await.unwrap();
    let mut data = [0; 4];
    server.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"data");
    assert!(
        poll_fn(|cx| {
            let mut byte = [0];
            Poll::Ready(
                Pin::new(&mut client)
                    .poll_read(cx, &mut ReadBuf::new(&mut byte))
                    .is_pending(),
            )
        })
        .await
    );
    server.shutdown().await.unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).await.unwrap();
    assert_eq!(wire, b"\x88\x02\x03\xe8");
}

#[tokio::test]
async fn invalid_frames_send_mosquitto_close_codes() {
    // lib/net_ws.c: read_ws_opcode and net__read_ws set disconnect reason;
    // src/context.c: context__disconnect writes it as a WebSocket close code.
    for (wire, code) in [
        (&b"\x81"[..], 0xeb),                                     // text
        (&b"\x87"[..], 0xea),                                     // reserved opcode
        (&b"\xc2"[..], 0xea),                                     // RSV1
        (&b"\x09"[..], 0xea),                                     // fragmented ping
        (&b"\x88\x01"[..], 0xea),                                 // one-byte close
        (&b"\x89\x7e\x00\x7e"[..], 0xea),                         // 126-byte ping
        (&b"\x82\x7f\x00\x00\x00\x00\x10\x00\x00\x00"[..], 0xe8), // limit + 1
    ] {
        let (mut client, server) = duplex(1024);
        let mut server = WsStream::new(server);
        client.write_all(wire).await.unwrap();
        assert_eq!(
            server.read(&mut [0]).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        let mut output = Vec::new();
        client.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, [0x88, 2, 0x03, code]);
    }
}

#[tokio::test]
async fn extended_lengths_and_mask_are_read_across_short_io() {
    // lib/net_ws.c: read_ws_payloadlen_extended and read_ws_mask decode
    // big-endian extended lengths and use the frame-relative XOR offset.
    for size in [126, 65_536] {
        let (mut client, server) = duplex(4);
        let mut server = WsStream::new(server);
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let wire = frame(0x82, &payload, Some([0xaa, 0x09, 0x32, 0x7f]));
        let send = async { client.write_all(&wire).await.unwrap() };
        let receive = async {
            let mut data = vec![0; size];
            server.read_exact(&mut data).await.unwrap();
            assert_eq!(data, payload);
        };
        timeout(Duration::from_secs(3), async {
            tokio::join!(send, receive)
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn outbound_frame_survives_partial_write_and_flush() {
    // lib/net_ws.c: ws__prepare_packet chooses the canonical length encoding
    // and sends server data unmasked, including for lengths over 65535.
    for size in [125, 126, 65_536] {
        let (mut client, server) = duplex(31);
        let mut server = WsStream::new(server);
        let data = vec![1; size];
        let expected = frame(0x82, &data, None);
        let send = async {
            server.write_all(&data).await.unwrap();
            server.flush().await.unwrap();
        };
        let read = async {
            let mut wire = vec![0; expected.len()];
            client.read_exact(&mut wire).await.unwrap();
            assert_eq!(wire, expected);
        };
        timeout(Duration::from_secs(3), async { tokio::join!(send, read) })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn split_io_serializes_automatic_pong_after_pending_binary() {
    // lib/packet_mosq.c: packet__queue queues a lib/net_ws.c pong behind
    // pending data. Separate read/write tasks must not strand either waker.
    let (mut client, server) = duplex(8);
    let (mut read, mut write) = tokio::io::split(WsStream::new(server));
    let (sent, started) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(async move {
        write.write_all(b"outbound bytes").await.unwrap();
        sent.send(()).unwrap();
        write.flush().await.unwrap();
    });
    let reader = tokio::spawn(async move {
        let mut inbound = [0; 4];
        read.read_exact(&mut inbound).await.unwrap();
        assert_eq!(&inbound, b"MQTT");
    });
    timeout(Duration::from_secs(3), async {
        started.await.unwrap();
        client.write_all(b"\x89\x01p").await.unwrap();
        let mut first = [0; 16];
        client.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"\x82\x0eoutbound bytes");
        let mut pong = [0; 3];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"\x8a\x01p");
        client.write_all(b"\x82\x04MQTT").await.unwrap();
        writer.await.unwrap();
        reader.await.unwrap();
    })
    .await
    .unwrap();
}
