use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use mqx_codec::{
    ConnAck, Connect, ConnectReturnCode, DecodeContext, LastWill, Packet, ProtocolVersion, QoS,
    decode, encode,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const TOPIC: &str = "wire/é/publish";
const PAYLOAD: &str = "client packet payload";
const WILL_TOPIC: &str = "wire/last-will";
const WILL_PAYLOAD: &str = "unexpected disconnect";
const CLIENT_ID: &str = "mqx-wire-test";
const USERNAME: &str = "wire-user";
const PASSWORD: &str = "wire pass";

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "mosquitto_pub didn't connect");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept mosquitto_pub: {error}"),
        }
    }
}

fn read_packet(
    socket: &mut TcpStream,
    input: &mut BytesMut,
    context: DecodeContext,
) -> Option<Packet> {
    let mut block = [0; 4096];
    loop {
        if let Some(packet) = decode(input, context).unwrap() {
            return Some(packet);
        }
        let n = socket.read(&mut block).unwrap();
        if n == 0 {
            assert!(input.is_empty(), "mosquitto_pub sent a partial packet");
            return None;
        }
        input.extend_from_slice(&block[..n]);
    }
}

fn send_packet(socket: &mut TcpStream, packet: Packet) {
    let mut output = BytesMut::new();
    encode(&packet, &mut output).unwrap();
    socket.write_all(&output).unwrap();
}

fn serve(listener: &TcpListener, protocol: ProtocolVersion, qos: QoS, retain: bool) {
    let mut socket = accept(listener);
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    let mut input = BytesMut::new();
    assert_eq!(
        read_packet(&mut socket, &mut input, DecodeContext::new(4096, None)).expect("CONNECT"),
        Packet::Connect(Connect {
            protocol,
            is_bridge: false,
            clean_session: true,
            keep_alive: 17,
            client_id: CLIENT_ID.into(),
            will: Some(LastWill {
                topic: WILL_TOPIC.into(),
                payload: Bytes::from_static(WILL_PAYLOAD.as_bytes()),
                qos: QoS::AtLeastOnce,
                retain: true,
            }),
            username: Some(USERNAME.into()),
            password: Some(Bytes::from_static(PASSWORD.as_bytes())),
        }),
    );
    send_packet(
        &mut socket,
        Packet::ConnAck(ConnAck {
            session_present: false,
            code: ConnectReturnCode::Accepted,
        }),
    );

    let context = DecodeContext::new(4096, Some(protocol));
    let Some(Packet::Publish(publish)) = read_packet(&mut socket, &mut input, context) else {
        panic!("mosquitto_pub did not send PUBLISH");
    };
    assert_eq!(publish.qos, qos);
    assert_eq!(publish.topic, TOPIC);
    assert_eq!(publish.payload, PAYLOAD.as_bytes());
    assert_eq!(publish.retain, retain);
    assert!(!publish.dup);
    match qos {
        QoS::AtMostOnce => assert_eq!(publish.packet_id, None),
        QoS::AtLeastOnce => send_packet(&mut socket, Packet::PubAck(publish.packet_id.unwrap())),
        QoS::ExactlyOnce => {
            let id = publish.packet_id.unwrap();
            send_packet(&mut socket, Packet::PubRec(id));
            assert_eq!(
                read_packet(&mut socket, &mut input, context),
                Some(Packet::PubRel(id))
            );
            send_packet(&mut socket, Packet::PubComp(id));
        }
    }
    // client/pub_client.c: pub_other_loop exits once DISCONNECT is queued,
    // so the client can close successfully without flushing it.
    assert!(matches!(
        read_packet(&mut socket, &mut input, context),
        None | Some(Packet::Disconnect)
    ));
    assert!(input.is_empty());
}

fn run_case(binary: &Path, version_arg: Option<&str>, protocol: ProtocolVersion, qos: QoS) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let retain = qos != QoS::AtLeastOnce;
    let mut command = Command::new(binary);
    command
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port,
            "-i",
            CLIENT_ID,
            "-k",
            "17",
            "-t",
            TOPIC,
            "-m",
            PAYLOAD,
            "-q",
            &(qos as u8).to_string(),
            "--will-topic",
            WILL_TOPIC,
            "--will-payload",
            WILL_PAYLOAD,
            "--will-qos",
            "1",
            "--will-retain",
            "-u",
            USERNAME,
            "-P",
            PASSWORD,
        ]);
    if let Some(version) = version_arg {
        command.args(["-V", version]);
    }
    if retain {
        command.arg("-r");
    }
    let mut client = command.spawn().expect("launch real mosquitto_pub");
    let server = thread::spawn(move || serve(&listener, protocol, qos, retain));
    let result = server.join();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if client.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = client.kill();
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let Output {
        status,
        stderr,
        stdout,
    } = client.wait_with_output().unwrap();
    assert!(
        result.is_ok() && status.success(),
        "wire exchange with {version_arg:?} at {qos:?} failed ({status})\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 built under MOSQUITTO_BUILD_DIR"]
fn mosquitto_pub_wire() {
    let build = PathBuf::from(env::var_os("MOSQUITTO_BUILD_DIR").expect("set MOSQUITTO_BUILD_DIR"));
    let binary = build.join("client/mosquitto_pub");
    // Mosquitto 2.1.4's client/client_shared.c:init_config defaults to 3.1.1.
    // Exercise explicit 3.1 as well as the actual default and explicit 3.1.1.
    for (version_arg, protocol) in [
        (None, ProtocolVersion::V311),
        (Some("mqttv31"), ProtocolVersion::V31),
        (Some("mqttv311"), ProtocolVersion::V311),
    ] {
        for qos in [QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce] {
            run_case(&binary, version_arg, protocol, qos);
        }
    }
}
