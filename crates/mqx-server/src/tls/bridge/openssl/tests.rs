use std::{fs, time::Duration};

use ::openssl::{
    hash::hash,
    pkey::Private,
    sign::Signer,
    ssl::{AlpnError, NameType, select_next_proto},
};
use chrono::{TimeDelta, Utc};
use mqx_bridge::Transport;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::{net::TcpListener, time::timeout};

use super::*;
use crate::tls::{connect_bridge_tls, der_header};

struct Pki {
    root: CertifiedIssuer<'static, KeyPair>,
    server: X509,
    server_key: PKey<Private>,
}

fn root(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

impl Pki {
    fn new() -> Self {
        let root = root("OCSP test root");
        let mut params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        params.serial_number = Some(1u64.into());
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let server = params.signed_by(&key, &root).unwrap();
        Self {
            root,
            server: X509::from_der(server.der()).unwrap(),
            server_key: PKey::private_key_from_der(&key.serialize_der()).unwrap(),
        }
    }

    fn acceptor(&self, staple: Option<Vec<u8>>) -> SslContextBuilder {
        let mut ctx = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
        // Do not send the root (also omit it from issuer-signed OCSP responses).
        ctx.set_certificate(&self.server).unwrap();
        ctx.set_private_key(&self.server_key).unwrap();
        ctx.set_num_tickets(0).unwrap();
        if let Some(staple) = staple {
            ctx.set_status_callback(move |ssl| {
                ssl.set_ocsp_status(&staple)?;
                Ok(true)
            })
            .unwrap();
        }
        ctx
    }

    fn answer(
        &self,
        serial: u8,
        hash_index: usize,
        status: &[u8],
        dates: (i64, Option<i64>),
    ) -> Vec<u8> {
        let (oid, digest) = CERT_ID_HASHES[hash_index];
        let issuer = X509::from_der(self.root.der()).unwrap();
        let name_hash = hash(digest(), &issuer.subject_name().to_der().unwrap()).unwrap();
        let key_hash = hash(digest(), self.root.key().public_key_raw()).unwrap();
        let id = der(
            0x30,
            &[
                &der(0x30, &[&der(0x06, &[oid]), b"\x05\x00"]),
                &der(0x04, &[&name_hash]),
                &der(0x04, &[&key_hash]),
                &[0x02, 0x01, serial],
            ],
        );
        let expires = dates.1.map(|hours| der(0xa0, &[&time(hours)]));
        der(
            0x30,
            &[
                &id,
                status,
                &time(dates.0),
                expires.as_deref().unwrap_or_default(),
            ],
        )
    }

    fn staple(&self, answers: &[&[u8]]) -> Vec<u8> {
        signed_staple(self.root.der(), self.root.key(), answers, false)
    }
}

fn der(tag: u8, pieces: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    der_header(&mut output, tag, pieces.iter().map(|piece| piece.len()).sum());
    for piece in pieces {
        output.extend_from_slice(piece);
    }
    output
}

fn time(hours_from_now: i64) -> Vec<u8> {
    let value = (Utc::now() + TimeDelta::hours(hours_from_now))
        .format("%Y%m%d%H%M%SZ")
        .to_string();
    der(0x18, &[value.as_bytes()])
}

fn signed_staple(cert: &[u8], key: &KeyPair, answers: &[&[u8]], embed_signer: bool) -> Vec<u8> {
    // RFC 6960: sign DER ResponseData, then wrap it in a BasicOCSPResponse.
    let signer = X509::from_der(cert).unwrap();
    let name = signer.subject_name().to_der().unwrap();
    let data = der(0x30, &[&der(0xa1, &[&name]), &time(0), &der(0x30, answers)]);
    let key = PKey::private_key_from_der(&key.serialize_der()).unwrap();
    let signature = Signer::new(MessageDigest::sha256(), &key)
        .unwrap()
        .sign_oneshot_to_vec(&data)
        .unwrap();
    let certificates = embed_signer.then(|| der(0xa0, &[&der(0x30, &[cert])]));
    let basic = der(
        0x30,
        &[
            &data,
            b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02", // ECDSA with SHA-256
            &der(0x03, &[&[0], &signature]),
            certificates.as_deref().unwrap_or_default(),
        ],
    );
    let bytes = der(
        0x30,
        &[
            b"\x06\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x01", // id-pkix-ocsp-basic
            &der(0x04, &[&basic]),
        ],
    );
    der(0x30, &[b"\x0a\x01\x00", &der(0xa0, &[&bytes])])
}

async fn dial(
    context: SslContextBuilder,
    host: &str,
    tls: &TlsConfig,
) -> (
    io::Result<Box<dyn Transport>>,
    Result<SslStream<TcpStream>, ::openssl::ssl::Error>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let ssl = Ssl::new(&context.build()).unwrap();
    let mut socket = SslStream::new(ssl, server).unwrap();
    let (client, server) = timeout(Duration::from_secs(5), async {
        tokio::join!(connect_bridge_tls(client, host, tls), Pin::new(&mut socket).accept())
    })
    .await
    .unwrap();
    (client, server.map(|()| socket))
}

const GOOD: &[u8] = b"\x80\x00";

#[tokio::test]
async fn bridge_ocsp_checks_signed_status_for_the_verified_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new();
    let other = root("Unrelated OCSP signer");
    let ca = dir.path().join("roots.pem");
    fs::write(&ca, format!("{}{}", pki.root.pem(), other.pem())).unwrap();
    let tls = TlsConfig {
        cafile: Some(ca),
        require_ocsp: true,
        ..TlsConfig::default()
    };
    let current = (-1, Some(1));
    let good = pki.answer(1, 0, GOOD, current);
    let other_hash = pki.answer(1, 2, GOOD, current);
    let wrong_leaf = pki.answer(2, 0, GOOD, current);
    let revoked = pki.answer(1, 0, &der(0xa1, &[&time(-2)]), current);
    let unknown = pki.answer(1, 0, b"\x82\x00", current);
    let stale = pki.answer(1, 0, GOOD, (-2, Some(-1)));
    let future = pki.answer(1, 0, GOOD, (1, Some(2)));
    let undated = pki.answer(1, 0, GOOD, (-1, None));
    let good_staple = pki.staple(&[&good]);
    let mut bad_signature = good_staple.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut trailing = good_staple.clone();
    trailing.push(0);
    let trusted_but_unauthorized = signed_staple(other.der(), other.key(), &[&good], true);
    let mut responder = CertificateParams::default();
    responder
        .distinguished_name
        .push(DnType::CommonName, "Delegated OCSP signer");
    responder.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
    let responder_key = KeyPair::generate().unwrap();
    let responder = responder.signed_by(&responder_key, &pki.root).unwrap();
    let delegated = signed_staple(responder.der(), &responder_key, &[&good], true);

    for (case, staple, expected_error) in [
        ("valid root-issued SHA1 ID", Some(good_staple), None),
        (
            "valid SHA256 ID with another certificate",
            Some(pki.staple(&[&other_hash, &wrong_leaf])),
            None,
        ),
        ("delegated signer", Some(delegated), None),
        ("missing staple", None, Some("Missing stapled OCSP")),
        ("malformed DER", Some(vec![0xab]), Some("")),
        ("invalid signature", Some(bad_signature), Some("signature")),
        ("trailing data", Some(trailing), Some("Malformed")),
        (
            "wrong leaf",
            Some(pki.staple(&[&wrong_leaf])),
            Some("does not cover"),
        ),
        ("revoked", Some(pki.staple(&[&revoked])), Some("GOOD")),
        ("unknown", Some(pki.staple(&[&unknown])), Some("GOOD")),
        ("stale", Some(pki.staple(&[&stale])), Some("not current")),
        ("future", Some(pki.staple(&[&future])), Some("not current")),
        ("no expiry", Some(pki.staple(&[&undated])), Some("not current")),
        (
            "duplicate ID",
            Some(pki.staple(&[&good, &revoked])),
            Some("ambiguous"),
        ),
        (
            "two matching IDs",
            Some(pki.staple(&[&good, &other_hash])),
            Some("ambiguous"),
        ),
        (
            "trusted but unauthorized signer",
            Some(trusted_but_unauthorized),
            Some(""),
        ),
    ] {
        let (client, server) = dial(pki.acceptor(staple), "localhost", &tls).await;
        // The certificate's TLS handshake succeeds; only the staple decides
        // whether the bridge gets an MQTT stream.
        assert!(server.is_ok(), "{case}: {:?}", server.err());
        match expected_error {
            None => assert!(client.is_ok(), "{case}: {:?}", client.err()),
            Some(reason) => {
                let err = client
                    .err()
                    .unwrap_or_else(|| panic!("{case}: unexpectedly accepted"));
                assert!(err.to_string().contains(reason), "{case}: {err}");
            }
        }
    }
}

#[tokio::test]
async fn bridge_ocsp_preserves_tls_identity_and_bridge_settings() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new();
    let issuer = X509::from_der(pki.root.der()).unwrap();
    fs::write(
        dir.path()
            .join(format!("{:08x}.0", issuer.subject_name_hash())),
        pki.root.pem(),
    )
    .unwrap();
    let client_pem = dir.path().join("client.pem");
    let key_pem = dir.path().join("client.key");
    let params = CertificateParams {
        extended_key_usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
        ..CertificateParams::default()
    };
    let key = KeyPair::generate().unwrap();
    fs::write(&client_pem, params.signed_by(&key, &pki.root).unwrap().pem()).unwrap();
    fs::write(&key_pem, key.serialize_pem()).unwrap();
    let mut tls = TlsConfig {
        capath: Some(dir.path().to_owned()),
        certfile: Some(client_pem),
        keyfile: Some(key_pem),
        alpn: Some("mqtt".into()),
        ciphers: Some("ECDHE-ECDSA-AES128-GCM-SHA256".into()),
        ciphers_tls13: Some("TLS_AES_128_GCM_SHA256".into()),
        require_ocsp: true,
        ..TlsConfig::default()
    };
    let good = pki.answer(1, 0, GOOD, (-1, Some(1)));
    for (host, insecure, version, accepted) in [
        ("localhost.", false, SslVersion::TLS1_2, true),
        ("127.0.0.1", false, SslVersion::TLS1_3, true),
        ("127.0.0.2", false, SslVersion::TLS1_3, false),
        ("wrong.test", false, SslVersion::TLS1_3, false),
        ("wrong.test", true, SslVersion::TLS1_3, true),
    ] {
        tls.insecure = insecure;
        tls.version = Some(
            if version == SslVersion::TLS1_3 {
                "tlsv1.3"
            } else {
                "tlsv1.2"
            }
            .into(),
        );
        let mut acceptor = pki.acceptor(Some(pki.staple(&[&good])));
        acceptor.set_max_proto_version(Some(version)).unwrap();
        acceptor.cert_store_mut().add_cert(issuer.clone()).unwrap();
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        acceptor.set_alpn_select_callback(|_, client| {
            select_next_proto(b"\x04mqtt", client).ok_or(AlpnError::NOACK)
        });
        let (client, server) = dial(acceptor, host, &tls).await;
        assert_eq!(client.is_ok(), accepted, "{host}: {:?}", client.err());
        if accepted {
            let server = server.unwrap();
            assert!(server.ssl().peer_certificate().is_some());
            assert_eq!(server.ssl().selected_alpn_protocol(), Some(&b"mqtt"[..]));
            assert_eq!(server.ssl().version2(), Some(version));
            let cipher = if version == SslVersion::TLS1_3 {
                "TLS_AES_128_GCM_SHA256"
            } else {
                "ECDHE-ECDSA-AES128-GCM-SHA256"
            };
            assert_eq!(server.ssl().current_cipher().unwrap().name(), cipher);
            assert_eq!(
                server.ssl().servername(NameType::HOST_NAME),
                host.parse::<IpAddr>()
                    .is_err()
                    .then(|| host.trim_end_matches('.'))
            );
        }
    }
    // `bridge_insecure` skips the hostname, not trust or the staple.
    let (result, _) = dial(pki.acceptor(None), "wrong.test", &tls).await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("Missing stapled OCSP")
    );
    tls.capath = Some(dir.path().join("untrusted"));
    fs::create_dir(tls.capath.as_ref().unwrap()).unwrap();
    let (result, _) = dial(pki.acceptor(Some(pki.staple(&[&good]))), "wrong.test", &tls).await;
    assert!(result.is_err());
}
