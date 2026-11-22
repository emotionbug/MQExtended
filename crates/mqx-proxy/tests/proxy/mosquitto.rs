use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    CONNECT, ProxyInfo, ProxyOptions, ProxyVersion, V1_IPV4, V1_IPV6, V2_IPV4, identity_options,
    parse_proxy_header, ssl, tlv, v2, v2_ssl,
};

struct Broker {
    child: Child,
    log: PathBuf,
    _directory: tempfile::TempDir,
}

impl Broker {
    fn start<const N: usize>(options: [ProxyOptions; N]) -> (Self, [u16; N]) {
        let binary = PathBuf::from(
            std::env::var_os("MOSQUITTO_BUILD_DIR")
                .expect("set MOSQUITTO_BUILD_DIR to the Mosquitto 2.1.4 build directory"),
        )
        .join("src/mosquitto");
        assert!(binary.is_file(), "missing {}", binary.display());
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("mosquitto.conf");
        let log = directory.path().join("broker.log");
        let reservations: [TcpListener; N] =
            std::array::from_fn(|_| TcpListener::bind(("127.0.0.1", 0)).unwrap());
        let ports = std::array::from_fn(|i| reservations[i].local_addr().unwrap().port());
        let mut config = String::from("log_dest stderr\nlog_type all\n");
        for (port, policy) in ports.into_iter().zip(options) {
            writeln!(config, "listener {port} 127.0.0.1\nenable_proxy_protocol {}\nlistener_allow_anonymous true", policy.version as u8).unwrap();
            if policy.version == ProxyVersion::V2 {
                writeln!(config, "proxy_protocol_v2_require_tls {}\nrequire_certificate {}\nuse_identity_as_username {}", policy.require_tls, policy.require_certificate, policy.use_identity_as_username).unwrap();
            }
        }
        fs::write(&config_path, config).unwrap();
        drop(reservations);
        let child = Command::new(&binary)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(File::create(&log).unwrap())
            .spawn()
            .unwrap_or_else(|err| panic!("running {}: {err}", binary.display()));
        let mut broker = Self {
            child,
            log,
            _directory: directory,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = broker.child.try_wait().unwrap();
            assert!(
                status.is_none(),
                "Mosquitto exited with {status:?}: {}",
                broker.log()
            );
            if ports
                .iter()
                .all(|&port| TcpStream::connect(("127.0.0.1", port)).is_ok())
            {
                return (broker, ports);
            }
            assert!(
                Instant::now() < deadline,
                "Mosquitto did not start: {}",
                broker.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn connack(port: u16, input: &[u8], end_of_input: bool) -> std::io::Result<Option<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(input)?;
    if end_of_input {
        stream.shutdown(Shutdown::Write)?;
    }
    let mut packet = [0; 4];
    match stream.read(&mut packet) {
        Ok(0) => return Ok(None),
        Ok(len) => stream.read_exact(&mut packet[len..])?,
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    assert_eq!(&packet[..3], b"\x20\x02\x00", "expected MQTT 3.1.1 CONNACK");
    Ok(Some(packet[3]))
}

#[test]
#[ignore = "requires Mosquitto 2.1.4 with TLS and PROXY support under MOSQUITTO_BUILD_DIR"]
fn matches_mosquitto_connack_or_drop() {
    let options = [
        ProxyVersion::V1.into(),
        ProxyVersion::V2.into(),
        ProxyOptions {
            require_tls: true,
            ..ProxyVersion::V2.into()
        },
        identity_options(),
    ];
    let (broker, ports) = Broker::start(options);
    let compare = |name: &str, listener: usize, header: &[u8], end_of_input| {
        // Submit each header + CONNECT together: the C socket readers are
        // sensitive to fragmentation; this compares complete wire frames.
        let input = [header, CONNECT].concat();
        let policy = options[listener];
        let expected = match parse_proxy_header(&input, policy) {
            Ok(Some((ProxyInfo::Local, _))) | Ok(None) | Err(_) => None,
            Ok(Some((info, tail))) => {
                assert_eq!(tail, CONNECT);
                if policy.uses_forwarded_username()
                    && matches!(info, ProxyInfo::Proxied { tls: Some(tls), .. } if tls.common_name.is_none())
                {
                    // src/handle_connect.c:handle_username_from_cert_options
                    // accepts the transport, then refuses missing identity.
                    Some(4)
                } else {
                    Some(0)
                }
            }
        };
        let observed = connack(ports[listener], &input, end_of_input)
            .unwrap_or_else(|err| panic!("{name}: {err}\n{}", broker.log()));
        assert_eq!(observed, expected, "{name}\n{}", broker.log());
    };

    compare("TCP4", 0, V1_IPV4, false);
    compare("TCP6", 0, V1_IPV6, false);
    compare("UNKNOWN with space", 0, b"PROXY UNKNOWN \r\n", false);
    compare("UNKNOWN without space", 0, b"PROXY UNKNOWN\r\n", false);
    compare(
        "atoi and strtok quirks",
        0,
        b"PROXY TCP4  192.0.2.5 127.0.0.1  +06275junk 1234 \r\n",
        false,
    );
    compare(
        "port zero",
        0,
        b"PROXY TCP4 192.0.2.5 127.0.0.1 0 1234\r\n",
        false,
    );
    compare("v1 exceeds 108 bytes", 0, &[b'x'; 108], false);

    compare("LOCAL health check", 1, &v2(0x20, 0, &[]), false);
    compare(
        "overlong LOCAL health check",
        1,
        &v2(0x20, 0, &[0; 501]),
        false,
    );
    compare("LOCAL with IPv4", 1, &v2(0x20, 0x11, V2_IPV4), false);
    compare("PROXY IPv4", 1, &v2(0x21, 0x11, V2_IPV4), false);
    let mut ipv6 = Ipv6Addr::LOCALHOST.octets().to_vec();
    ipv6.extend(Ipv6Addr::UNSPECIFIED.octets());
    ipv6.extend([0; 4]);
    compare("PROXY IPv6", 1, &v2(0x21, 0x21, &ipv6), false);
    compare("short UNIX", 1, &v2(0x21, 0x31, b"/path"), false);
    compare("standard padded UNIX", 1, &v2(0x21, 0x31, &[0; 216]), false);
    compare("unsupported family", 1, &v2(0x21, 0x12, V2_IPV4), false);
    compare("ignored CRC32c", 1, &v2_ssl(&[&tlv(0x03, b"x")]), false);
    compare("overlong IPv4", 1, &v2(0x21, 0x11, &[0; 501]), false);
    compare("short IPv4", 1, &v2(0x21, 0x11, &[0; 11]), false);
    let mut incomplete = v2(0x21, 0x11, V2_IPV4);
    incomplete[15] = 60;
    compare("truncated payload at EOF", 1, &incomplete, true);
    let mut bad_magic = v2(0x21, 0x11, V2_IPV4);
    bad_magic[11] = 0x0b;
    compare("bad signature", 1, &bad_magic, false);
    compare("short SSL TLV", 1, &v2_ssl(&[&tlv(0x20, &[1])]), false);

    compare("missing SSL indication", 2, &v2_ssl(&[]), false);
    compare(
        "SSL TLV without any flag",
        2,
        &v2_ssl(&[&ssl(0, 1, &[])]),
        false,
    );
    compare(
        "no verified session certificate",
        3,
        &v2_ssl(&[&ssl(3, 0, &[])]),
        false,
    );
    compare(
        "verified certificate without CN",
        3,
        &v2_ssl(&[&ssl(5, 0, &[])]),
        false,
    );
    let cn = tlv(0x22, b"ppppppp");
    compare(
        "verified certificate with CN",
        3,
        &v2_ssl(&[&ssl(5, 0, &[&tlv(0x21, b"TLSv1.3"), &cn])]),
        false,
    );
    compare(
        "duplicate CN",
        3,
        &v2_ssl(&[&ssl(5, 0, &[&cn, &cn])]),
        false,
    );
    compare(
        "embedded NUL in CN",
        3,
        &v2_ssl(&[&ssl(5, 0, &[&tlv(0x22, b"x\0y")])]),
        false,
    );
}
