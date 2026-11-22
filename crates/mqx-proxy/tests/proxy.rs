use mqx_proxy::{
    ProxyAddresses, ProxyError, ProxyInfo, ProxyOptions, ProxyTls, ProxyVersion, parse_proxy_header,
};
use proptest::prelude::*;

const V1_IPV4: &[u8] = b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234\r\n";
const V1_IPV6: &[u8] = b"PROXY TCP6 2001:db8:506:708:900::1 ::1 6275 1234\r\n";
const V2_MAGIC: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
const V2_IPV4: &[u8] = b"\xc0\x00\x02\x05\0\0\0\0\x18\x83\0\0";
const CONNECT: &[u8] = b"\x10\x11\x00\x04MQTT\x04\x02\x00\x2a\x00\x05proxy";

fn v2(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
    let mut header = V2_MAGIC.to_vec();
    header.extend([command, family]);
    header.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    header.extend(body);
    header
}

fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend(value);
    bytes
}

fn ssl(client: u8, verify: u32, children: &[&[u8]]) -> Vec<u8> {
    let mut value = vec![client];
    value.extend(verify.to_be_bytes());
    value.extend(children.iter().flat_map(|bytes| bytes.iter().copied()));
    tlv(0x20, &value)
}

fn v2_ssl(records: &[&[u8]]) -> Vec<u8> {
    let mut body = V2_IPV4.to_vec();
    body.extend(records.iter().flat_map(|bytes| bytes.iter().copied()));
    v2(0x21, 0x11, &body)
}

fn identity_options() -> ProxyOptions {
    ProxyOptions {
        require_tls: true,
        require_certificate: true,
        use_identity_as_username: true,
        ..ProxyVersion::V2.into()
    }
}

fn ip(source: &str, destination: &str) -> ProxyInfo {
    ProxyInfo::Proxied {
        addresses: ProxyAddresses::Ip {
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
        },
        tls: None,
    }
}

#[test]
fn v1_reports_addresses_and_keeps_mqtt_bytes() {
    // Mosquitto test/broker/21-proxy-v1-success.py; src/proxy_v1.c:proxy_v1__decode.
    for (header, expected) in [
        (V1_IPV4, ip("192.0.2.5:6275", "127.0.0.1:1234")),
        (V1_IPV6, ip("[2001:db8:506:708:900::1]:6275", "[::1]:1234")),
        (b"PROXY UNKNOWN \r\n", ProxyInfo::Unknown),
        (b"PROXY UNKNOWN ignored\xff\0\r\n", ProxyInfo::Unknown),
    ] {
        let input = [header, CONNECT].concat();
        assert_eq!(
            parse_proxy_header(&input, ProxyVersion::V1).unwrap(),
            Some((expected, CONNECT))
        );
    }
}

#[test]
fn v1_uses_c_tokens_and_decimal_port_prefixes() {
    // Mosquitto src/proxy_v1.c:proxy_v1__decode uses strtok_r and atoi.
    let expected = ip("192.0.2.5:6275", "127.0.0.1:1234");
    for header in [
        &b"PROXY TCP4  192.0.2.5 127.0.0.1  \t+06275junk 1234 \r\n"[..],
        &b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234\0 ignored\r\n"[..],
    ] {
        assert_eq!(
            parse_proxy_header(header, ProxyVersion::V1).unwrap(),
            Some((expected.clone(), &[][..]))
        );
    }
    for header in [
        &b"PROXY TCP3 192.0.2.5 127.0.0.1 6275 1234\r\n"[..],
        b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234  \r\n",
        b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234 extra\r\n",
        b"PROXY TCP4 192.0.2.5 127.0.0.1 6275\r\n",
        b"PROXY TCP4 192.0.2.5 127.0.0.256 6275 1234\r\n",
        b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 0\r\n",
        b"PROXY TCP4 192.0.2.5 127.0.0.1 65536 1234\r\n",
        b"PROXY TCP6 192.0.2.5 ::1 6275 1234\r\n",
        b"PROXY UNKNOWN\r\n",
    ] {
        assert!(
            matches!(
                parse_proxy_header(header, ProxyVersion::V1),
                Err(ProxyError::MalformedHeader)
            ),
            "{header:?}"
        );
    }
}

#[test]
fn v1_accepts_crlf_at_byte_108_but_not_later() {
    // Mosquitto src/proxy_v1.c:proxy_v1__read applies its cap before decoding.
    let mut header = b"PROXY UNKNOWN ".to_vec();
    header.resize(106, b'x');
    header.extend(b"\r\n");
    assert!(
        parse_proxy_header(&header[..107], ProxyVersion::V1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        parse_proxy_header(&header, ProxyVersion::V1).unwrap(),
        Some((ProxyInfo::Unknown, &[][..]))
    );
    header.insert(106, b'x');
    assert!(matches!(
        parse_proxy_header(&header, ProxyVersion::V1),
        Err(ProxyError::TooLong)
    ));
}

#[test]
fn v2_reads_ipv4_ipv6_and_local() {
    // Mosquitto src/proxy_v2.c:proxy_v2__read reads the advertised address
    // even for LOCAL when the address family isn't UNSPEC.
    let mut ipv6 = "2001:db8::5"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    ipv6.extend(std::net::Ipv6Addr::LOCALHOST.octets());
    ipv6.extend(b"\x18\x83\0\x01");
    for (header, expected) in [
        (v2(0x21, 0x11, V2_IPV4), ip("192.0.2.5:6275", "0.0.0.0:0")),
        (v2(0x20, 0x11, V2_IPV4), ip("192.0.2.5:6275", "0.0.0.0:0")),
        (v2(0x21, 0x21, &ipv6), ip("[2001:db8::5]:6275", "[::1]:1")),
        (v2(0x20, 0x00, b""), ProxyInfo::Local),
        (v2(0x20, 0x00, &[0xff; 501]), ProxyInfo::Local),
    ] {
        let input = [header.as_slice(), CONNECT].concat();
        assert_eq!(
            parse_proxy_header(&input, ProxyVersion::V2).unwrap(),
            Some((expected, CONNECT))
        );
    }
}

#[test]
fn v2_unix_uses_mosquittos_109_byte_tlv_offset() {
    // Mosquitto test/broker/21-proxy-v2-unix.py and src/proxy_v2.c:proxy_v2__read.
    let header = v2(0x21, 0x31, b"/path");
    let expected = ProxyInfo::Proxied {
        addresses: ProxyAddresses::Unix {
            source: (&b"/path"[..]).into(),
            destination: Box::default(),
        },
        tls: None,
    };
    assert_eq!(
        parse_proxy_header(&header, ProxyVersion::V2).unwrap(),
        Some((expected, &[][..]))
    );

    let mut body = b"/src\0".to_vec();
    body.resize(216, 0);
    body[108..112].copy_from_slice(b"/dst");
    assert!(matches!(
        parse_proxy_header(&v2(0x21, 0x31, &body), ProxyVersion::V2),
        Err(ProxyError::MalformedTlv)
    ));

    // The same bytes from 109 are also read as a single opaque TLV.
    body[110..112].copy_from_slice(&104u16.to_be_bytes());
    let header = v2(0x21, 0x31, &body);
    let expected = ProxyInfo::Proxied {
        addresses: ProxyAddresses::Unix {
            source: (&b"/src"[..]).into(),
            destination: (&b"/d"[..]).into(),
        },
        tls: None,
    };
    assert_eq!(
        parse_proxy_header(&header, ProxyVersion::V2).unwrap(),
        Some((expected, &[][..]))
    );
}

#[test]
fn v2_rejects_bad_framing_and_waits_for_truncated_payload() {
    // Mosquitto test/broker/21-proxy-v2-{bad-header,long-tlv,lost-connection}.py;
    // src/proxy_v2.c:proxy_v2__read and read_tlv.
    let valid = v2(0x21, 0x11, V2_IPV4);
    for end in 0..valid.len() {
        assert!(
            parse_proxy_header(&valid[..end], ProxyVersion::V2)
                .unwrap()
                .is_none()
        );
    }
    let mut wrong_signature = valid;
    wrong_signature[11] = 0x0b;
    for header in [
        wrong_signature,
        v2(0x31, 0x11, V2_IPV4),
        v2(0x23, 0x11, V2_IPV4),
        v2(0x21, 0x00, V2_IPV4),
        v2(0x21, 0x12, V2_IPV4),
        v2(0x21, 0x11, &[0; 11]),
        v2(0x21, 0x21, &[0; 35]),
        v2(0x21, 0x31, &[]),
    ] {
        assert!(
            matches!(
                parse_proxy_header(&header, ProxyVersion::V2),
                Err(ProxyError::MalformedHeader)
            ),
            "{header:?}"
        );
    }
    for family in [0x11, 0x21, 0x31] {
        let header = v2(0x21, family, &[0; 501]);
        assert!(matches!(
            parse_proxy_header(&header[..16], ProxyVersion::V2),
            Err(ProxyError::TooLong)
        ));
    }
    let boundary = v2_ssl(&[&tlv(0x04, &[0; 485])]);
    assert!(
        parse_proxy_header(&boundary, ProxyVersion::V2)
            .unwrap()
            .is_some()
    );
    for record in [
        &b"\x01\0"[..],
        b"\x03\0\x04\0\0\0",
        b"\x20\0\x01\x05",
        b"\x20\0\x05\x05\0\0\0",
        // Nested value exceeds the SSL TLV even though another TLV follows.
        b"\x20\0\x08\x05\0\0\0\0\x22\0\x01\x04\0\0",
    ] {
        let header = v2_ssl(&[record]);
        assert!(
            matches!(
                parse_proxy_header(&header, ProxyVersion::V2),
                Err(ProxyError::MalformedTlv)
            ),
            "{record:?}"
        );
    }
}

#[test]
fn v2_reports_ssl_fields_and_ignores_crc32c() {
    // Mosquitto src/proxy_v2.c:read_tlv skips all non-SSL types. read_tlv_ssl
    // uses the last TLS version/cipher and ignores signature/key algorithms.
    let first = ssl(
        5,
        0,
        &[
            &tlv(0x21, b"TLSv1.2"),
            &tlv(0x22, b"ppppppp"),
            &tlv(0x23, b"old cipher"),
        ],
    );
    let second = ssl(
        0,
        2,
        &[
            &tlv(0x21, b"TLSv1.3"),
            &tlv(0x23, b"TLS_AES_256_GCM_SHA384"),
            &tlv(0x24, b"\xff"),
            &tlv(0x25, b"\xff"),
        ],
    );
    let header = v2_ssl(&[
        &tlv(0x03, b"not a CRC"),
        &first,
        &tlv(0x01, b"mqtt"),
        &second,
    ]);
    let (ProxyInfo::Proxied { tls: Some(tls), .. }, leftover) =
        parse_proxy_header(&header, identity_options())
            .unwrap()
            .unwrap()
    else {
        panic!("missing TLS metadata")
    };
    assert!(leftover.is_empty());
    assert_eq!(
        tls,
        ProxyTls {
            certificate_verified: true,
            version: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_256_GCM_SHA384".into()),
            common_name: Some("ppppppp".into()),
        }
    );
}

#[test]
fn v2_rejects_only_the_ssl_fields_mosquitto_uses() {
    // Mosquitto src/proxy_v2.c:read_tlv_ssl ignores CN without the identity
    // option, but validates the version/cipher on TLS-enabled builds.
    for kind in [0x21, 0x22, 0x23] {
        for value in [&b"a\0b"[..], b"\xff", b"\x1f", "\u{ffff}".as_bytes()] {
            let header = v2_ssl(&[&ssl(5, 0, &[&tlv(kind, value)])]);
            assert!(
                matches!(parse_proxy_header(&header, identity_options()), Err(ProxyError::InvalidTlsString { kind: rejected, .. }) if rejected == kind)
            );
            if kind == 0x22 {
                let (ProxyInfo::Proxied { tls: Some(tls), .. }, _) =
                    parse_proxy_header(&header, ProxyVersion::V2)
                        .unwrap()
                        .unwrap()
                else {
                    panic!("missing TLS metadata")
                };
                assert_eq!(tls.common_name, None);
            }
        }
    }
    let first = ssl(5, 0, &[&tlv(0x22, b"")]);
    let second = ssl(5, 0, &[&tlv(0x22, b"extra")]);
    let header = v2_ssl(&[&first, &second]);
    assert!(
        parse_proxy_header(&header, ProxyVersion::V2)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        parse_proxy_header(&header, identity_options()),
        Err(ProxyError::DuplicateCommonName)
    ));
    let (ProxyInfo::Proxied { tls: Some(tls), .. }, _) =
        parse_proxy_header(&v2_ssl(&[&first]), identity_options())
            .unwrap()
            .unwrap()
    else {
        panic!("missing TLS metadata")
    };
    assert_eq!(tls.common_name.as_deref(), Some(""));
}

#[test]
fn v2_applies_tls_and_certificate_policy_in_transport_not_connect() {
    // Mosquitto src/proxy_v2.c:read_tlv_ssl and proxy_v2__read. No SSL is
    // a TLS-policy failure; any well-framed SSL satisfies it. Verification
    // requires SSL + CERT_SESS + verify=0. An absent CN is deferred until
    // MQTT CONNECT under src/handle_connect.c:handle_username_from_cert_options.
    let options = identity_options();
    assert!(matches!(
        parse_proxy_header(&v2_ssl(&[]), options),
        Err(ProxyError::TlsRequired)
    ));
    let tls_only = ProxyOptions {
        require_certificate: false,
        ..options
    };
    assert!(
        parse_proxy_header(&v2_ssl(&[&ssl(0, 42, &[])]), tls_only)
            .unwrap()
            .is_some()
    );
    for (client, verify) in [(1, 0), (3, 0), (4, 0), (5, 1)] {
        assert!(matches!(
            parse_proxy_header(&v2_ssl(&[&ssl(client, verify, &[])]), options),
            Err(ProxyError::CertificateRequired)
        ));
    }
    let (ProxyInfo::Proxied { tls: Some(tls), .. }, _) =
        parse_proxy_header(&v2_ssl(&[&ssl(5, 0, &[])]), options)
            .unwrap()
            .unwrap()
    else {
        panic!("missing TLS metadata")
    };
    assert!(tls.certificate_verified && tls.common_name.is_none());
    assert!(options.uses_forwarded_username());
    assert!(!tls_only.uses_forwarded_username());
    assert!(
        parse_proxy_header(
            V1_IPV4,
            ProxyOptions {
                version: ProxyVersion::V1,
                ..options
            }
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn v2_listener_disallows_native_tls_files_and_subject_username() {
    // Mosquitto src/conf.c:config__read_file_core and config__check_proxy;
    // test/broker/21-proxy-bad-version.py and 21-proxy-v2-bad-config.py.
    let options = identity_options();
    assert!(matches!(
        options.validate_listener(true, false, false),
        Err(ProxyError::SubjectUsernameWithV2)
    ));
    for (cert, key) in [(true, false), (false, true), (true, true)] {
        assert!(matches!(
            options.validate_listener(false, cert, key),
            Err(ProxyError::ListenerTlsWithV2)
        ));
    }
    assert!(options.validate_listener(false, false, false).is_ok());
    assert!(
        ProxyOptions::from(ProxyVersion::V1)
            .validate_listener(true, true, true)
            .is_ok()
    );
    for version in [0, 3] {
        assert!(
            matches!(ProxyVersion::try_from(version), Err(ProxyError::InvalidVersion(got)) if got == version)
        );
    }
}

fn assert_chunked(input: &[u8], version: ProxyVersion, chunks: &[usize]) {
    let whole = parse_proxy_header(input, version);
    let mut filled = 0;
    // A prefix can complete the header before the rest of the MQTT stream
    // arrives; combine the already buffered leftover with the unread suffix.
    for n in chunks.iter().copied().chain(std::iter::once(input.len())) {
        filled = (filled + n).min(input.len());
        match (parse_proxy_header(&input[..filled], version), &whole) {
            (Ok(None), _) if filled < input.len() => continue,
            (Ok(None), Ok(None)) => return,
            (Ok(Some((info, tail))), Ok(Some((expected, leftover)))) => {
                assert_eq!(&info, expected);
                assert_eq!(&input[filled - tail.len()..], *leftover);
                return;
            }
            (Err(actual), Err(expected)) => {
                assert_eq!(
                    std::mem::discriminant(&actual),
                    std::mem::discriminant(expected)
                );
                return;
            }
            (actual, expected) => panic!("chunked {actual:?} != whole {expected:?}"),
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_and_chunked_input_matches_whole(
        input in prop::collection::vec(any::<u8>(), 0..800),
        chunks in prop::collection::vec(1usize..40, 0..40),
    ) {
        assert_chunked(&input, ProxyVersion::V1, &chunks);
        assert_chunked(&input, ProxyVersion::V2, &chunks);
        // Random input past the v2 preamble exercises lengths and TLVs.
        let v2_input = v2(0x21, 0x31, &input);
        assert_chunked(&v2_input, ProxyVersion::V2, &chunks);
    }

    #[test]
    fn chunking_valid_frames_does_not_lose_mqtt_bytes(
        input in prop::collection::vec(any::<u8>(), 0..500),
        chunks in prop::collection::vec(1usize..15, 0..60),
    ) {
        let v2_header = v2_ssl(&[&ssl(5, 0, &[&tlv(0x21, b"TLSv1.3")]), &tlv(0x04, &input[..input.len().min(400)])]);
        assert_chunked(&[V1_IPV6, &input].concat(), ProxyVersion::V1, &chunks);
        assert_chunked(&[&v2_header, input.as_slice()].concat(), ProxyVersion::V2, &chunks);
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_helper_preserves_both_buffered_and_unread_bytes() {
    use mqx_proxy::read_proxy_header;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let input = [V1_IPV4, CONNECT].concat();
    let (info, leftover) = read_proxy_header(&mut input.as_slice(), ProxyVersion::V1)
        .await
        .unwrap();
    assert_eq!(info, ip("192.0.2.5:6275", "127.0.0.1:1234"));
    assert_eq!(leftover.as_ref(), CONNECT);

    let header = v2(0x21, 0x11, V2_IPV4);
    let (mut reader, mut writer) = tokio::io::duplex(1);
    let write = async {
        writer
            .write_all(&[header.as_slice(), CONNECT].concat())
            .await
            .unwrap();
    };
    let read = async {
        let (info, leftover) = read_proxy_header(&mut reader, ProxyVersion::V2)
            .await
            .unwrap();
        assert_eq!(info, ip("192.0.2.5:6275", "0.0.0.0:0"));
        let mut collected = leftover.to_vec();
        collected.resize(CONNECT.len(), 0);
        reader
            .read_exact(&mut collected[leftover.len()..])
            .await
            .unwrap();
        assert_eq!(collected, CONNECT);
    };
    tokio::join!(write, read);

    let local = [v2(0x20, 0x00, &[0; 600]).as_slice(), CONNECT].concat();
    let mut stream = local.as_slice();
    let (info, leftover) = read_proxy_header(&mut stream, ProxyVersion::V2)
        .await
        .unwrap();
    assert_eq!(info, ProxyInfo::Local);
    assert_eq!(leftover.as_ref(), b"");
    assert_eq!(stream, CONNECT);

    let err = read_proxy_header(&mut &header[..header.len() - 1], ProxyVersion::V2)
        .await
        .unwrap_err();
    assert!(matches!(err, ProxyError::Io(err) if err.kind() == std::io::ErrorKind::UnexpectedEof));
}

#[path = "proxy/mosquitto.rs"]
mod mosquitto;
