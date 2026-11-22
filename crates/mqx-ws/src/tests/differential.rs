use std::env;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use bytes::BytesMut;
use mqx_codec::{ConnAck, ConnectReturnCode, DecodeContext, Packet, decode, encode};
use tokio::net::{TcpListener, TcpStream};

use super::*;

struct Reference(Child);

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UpgradeOutcome {
    Response(Vec<u8>),
    Closed,
    NoResponseYet,
}

async fn probe(addr: SocketAddr, request: &[u8]) -> UpgradeOutcome {
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket.write_all(request).await.unwrap();
    match timeout(Duration::from_millis(500), response(&mut socket)).await {
        Ok(Ok(reply)) if reply.is_empty() => UpgradeOutcome::Closed,
        Ok(Ok(reply)) => UpgradeOutcome::Response(reply),
        Ok(Err(err)) if err.kind() == ErrorKind::ConnectionReset => UpgradeOutcome::Closed,
        Ok(Err(err)) => panic!("unexpected socket error: {err}"),
        Err(_) => {
            socket.shutdown().await.unwrap();
            let reply = timeout(Duration::from_secs(3), response(&mut socket)).await;
            assert!(
                reply.unwrap().unwrap().is_empty(),
                "oversize response after EOF"
            );
            UpgradeOutcome::NoResponseYet
        }
    }
}

const CONNECT: &[u8] = b"\x10\x0e\x00\x04MQTT\x04\x02\x00\x00\x00\x02ws";

async fn mqtt_connect(addr: SocketAddr) -> Vec<u8> {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(REQUEST.as_bytes()).await.unwrap();
    assert_eq!(response(&mut client).await.unwrap(), RESPONSE.as_bytes());
    // test/broker/01-connect-websocket-empty-frame.py: keep a partial MQTT
    // CONNECT across WebSocket frame boundaries with an empty data frame.
    let mask = Some(*b"keys");
    client
        .write_all(&frame(0x02, &CONNECT[..CONNECT.len() - 4], mask))
        .await
        .unwrap();
    client.write_all(&frame(0x82, b"", mask)).await.unwrap();
    client
        .write_all(&frame(0x80, &CONNECT[CONNECT.len() - 4..], mask))
        .await
        .unwrap();
    let mut connack = vec![0; 6];
    client.read_exact(&mut connack).await.unwrap();
    connack
}

async fn serve(listener: TcpListener, options: WsOptions) {
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let options = options.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = accept(stream, &options).await else {
                return;
            };
            let mut mqtt = BytesMut::with_capacity(32);
            let connect = loop {
                if stream.read_buf(&mut mqtt).await.unwrap() == 0 {
                    return;
                }
                if let Some(packet) = decode(&mut mqtt, DecodeContext::default()).unwrap() {
                    break packet;
                }
            };
            let Packet::Connect(connect) = connect else {
                panic!("expected MQTT CONNECT")
            };
            assert_eq!(connect.client_id, "ws");
            encode(
                &Packet::ConnAck(ConnAck {
                    session_present: false,
                    code: ConnectReturnCode::Accepted,
                }),
                &mut mqtt,
            )
            .unwrap();
            stream.write_all(&mqtt).await.unwrap();
            stream.flush().await.unwrap();
        });
    }
}

#[tokio::test]
#[ignore = "requires Mosquitto v2.1.4 with WITH_WEBSOCKETS_BUILTIN; set MOSQUITTO_WS_BUILD_DIR"]
async fn builtin_mosquitto_upgrade_outcomes_and_connect_connack() {
    let build = env::var_os("MOSQUITTO_WS_BUILD_DIR")
        .expect("set MOSQUITTO_WS_BUILD_DIR to a built-in WebSockets-enabled Mosquitto build");
    let binary = PathBuf::from(build).join("src/mosquitto");
    assert!(
        binary.is_file(),
        "missing reference binary: {}",
        binary.display()
    );
    let version = Command::new(&binary).arg("-h").output().unwrap();
    assert!(
        String::from_utf8_lossy(&version.stdout).starts_with("mosquitto version 2.1.4\n"),
        "wrong Mosquitto version: {}",
        String::from_utf8_lossy(&version.stdout)
    );

    let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reference_addr = reserve.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("index.html"),
        "not served by the built-in transport",
    )
    .unwrap();
    let mut config = tempfile::NamedTempFile::new().unwrap();
    let mut options = options();
    options.packet_buffer_size = 512;
    writeln!(config,
        "listener {} 127.0.0.1\nprotocol websockets\npacket_buffer_size {}\nallow_anonymous true\nhttp_dir {}",
        reference_addr.port(), options.packet_buffer_size, dir.path().display()
    ).unwrap();
    for origin in &options.origins {
        writeln!(config, "websockets_origin {origin}").unwrap();
    }
    drop(reserve);
    let mut reference = Reference(
        Command::new(binary)
            .arg("-c")
            .arg(config.path())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    timeout(Duration::from_secs(3), async {
        loop {
            assert!(
                reference.0.try_wait().unwrap().is_none(),
                "reference broker exited while starting; check WITH_WEBSOCKETS_BUILTIN"
            );
            if TcpStream::connect(reference_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reference broker did not bind its WebSocket listener");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let ours_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(listener, options));

    // src/http_serv.c: http__read. Compare the entire response head, preserving
    // status line, header spelling and values, or compare connection outcomes.
    let capacity_request = |len| {
        let prefix = &REQUEST[..REQUEST.len() - 2];
        format!(
            "{prefix}X: {}\r\n\r\n",
            "a".repeat(len - (prefix.len() + 7))
        )
    };
    for (name, raw, upgrades) in [
        ("valid", REQUEST.to_owned(), true),
        (
            "HEAD arbitrary path",
            REQUEST.replace("GET /mqtt HTTP/1.1", "HEAD /any/path?t=1 HTTP/1.0"),
            true,
        ),
        (
            "legacy subprotocol",
            REQUEST.replace("Protocol: mqtt", "Protocol: mqttv3.1"),
            true,
        ),
        (
            "wrong subprotocol",
            REQUEST.replace("Protocol: mqtt", "Protocol: not-mqtt"),
            false,
        ),
        (
            "subprotocol list",
            REQUEST.replace("Protocol: mqtt", "Protocol: mqtt, mqttv3.1"),
            false,
        ),
        (
            "missing Host and Version",
            REQUEST
                .replace("Host: localhost\r\n", "")
                .replace("Sec-WebSocket-Version: 13\r\n", ""),
            true,
        ),
        (
            "missing Connection",
            REQUEST.replace("Connection: Upgrade\r\n", ""),
            false,
        ),
        (
            "missing Upgrade",
            REQUEST.replace("Upgrade: websocket\r\n", ""),
            false,
        ),
        (
            "missing key",
            REQUEST.replace("Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n", ""),
            false,
        ),
        (
            "Connection is presence only",
            REQUEST.replace("Connection: Upgrade", "Connection: close"),
            true,
        ),
        (
            "bad version",
            REQUEST.replace("Version: 13", "Version: 12"),
            false,
        ),
        (
            "bad origin",
            REQUEST.replace("Origin: example.org", "Origin: example.org.evil"),
            false,
        ),
        (
            "prefix Origin",
            REQUEST.replace("Origin: example.org", "Origin: example"),
            true,
        ),
        ("last byte reserved (fits)", capacity_request(511), true),
        (
            "last byte reserved (one too many)",
            capacity_request(512),
            false,
        ),
        ("oversize headers", capacity_request(768), false),
        (
            "plain GET with http_dir",
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
            false,
        ),
    ] {
        let (expected, actual) = tokio::join!(
            probe(reference_addr, raw.as_bytes()),
            probe(ours_addr, raw.as_bytes())
        );
        assert_eq!(
            matches!(&expected, UpgradeOutcome::Response(_)),
            upgrades,
            "unexpected reference outcome for {name}: {expected:?}"
        );
        assert_eq!(actual, expected, "{name}");
    }

    let (expected, actual) = timeout(Duration::from_secs(3), async {
        tokio::join!(mqtt_connect(reference_addr), mqtt_connect(ours_addr))
    })
    .await
    .expect("MQTT CONNECT/CONNACK did not complete over WebSocket");
    assert_eq!(expected, b"\x82\x04\x20\x02\x00\x00");
    assert_eq!(actual, expected);
    server.abort();
}
