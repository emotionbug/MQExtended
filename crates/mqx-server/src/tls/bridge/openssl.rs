use std::{borrow::Cow, collections::HashSet, io, net::IpAddr, path::Path, pin::Pin};

use ::openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus},
    pkey::PKey,
    ssl::{
        Ssl, SslContextBuilder, SslMethod, SslMode, SslOptions, SslRef, SslVerifyMode, SslVersion,
        StatusType,
    },
    x509::X509VerifyResult,
};
use mqx_bridge::TlsConfig;
use rustls::pki_types::{PrivateKeyDer, ServerName, pem::PemObject};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use x509_parser::asn1_rs::{Any, Class, FromDer, Tag};

pub(super) async fn connect(
    stream: TcpStream,
    host: &str,
    tls: &TlsConfig,
) -> io::Result<SslStream<TcpStream>> {
    let mut context = SslContextBuilder::new(SslMethod::tls_client()).map_err(io::Error::other)?;
    context.set_options(SslOptions::NO_COMPRESSION | SslOptions::NO_RENEGOTIATION);
    context.set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
    // Mosquitto lib/net_mosq.c: net__init_ssl_ctx treats the version as a floor,
    // except for external PSK, which can only negotiate TLS 1.2.
    let minimum = match tls.version.as_deref() {
        None | Some("tlsv1.2") => SslVersion::TLS1_2,
        Some("tlsv1.3") => SslVersion::TLS1_3,
        Some(version) => {
            return Err(io::Error::other(format!(
                "Protocol {version} not supported"
            )));
        }
    };
    context
        .set_min_proto_version(Some(minimum))
        .map_err(io::Error::other)?;
    if tls.psk.is_some() {
        context
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(io::Error::other)?;
    }
    // Mosquitto lib/net_mosq.c: net__init_ssl_ctx keeps OpenSSL's default list
    // for certificate bridges and selects "PSK" for PSK bridges.
    let cipher_list = match (tls.ciphers.as_deref(), tls.psk.is_some()) {
        (Some(ciphers), _) if ciphers.contains('\0') => {
            return Err(io::Error::other("bridge_ciphers contains a NUL"));
        }
        (Some(ciphers), _) => Some(Cow::Owned(format!("{ciphers}:!aNULL:!eNULL"))),
        (None, true) => Some(Cow::Borrowed("PSK:!aNULL:!eNULL")),
        (None, false) => None,
    };
    if let Some(cipher_list) = cipher_list {
        context
            .set_cipher_list(&cipher_list)
            .map_err(io::Error::other)?;
    }
    if let Some(ciphers) = &tls.ciphers_tls13 {
        if ciphers.contains('\0') {
            return Err(io::Error::other("bridge_ciphers_tls1.3 contains a NUL"));
        }
        let ciphers = if ciphers.contains([' ', ',']) {
            Cow::Owned(ciphers.replace([' ', ','], ":"))
        } else {
            Cow::Borrowed(ciphers.as_str())
        };
        context
            .set_ciphersuites(&ciphers)
            .map_err(io::Error::other)?;
    }
    if let Some(alpn) = &tls.alpn {
        let len = alpn.len().min(254);
        let mut wire = [0; 255];
        wire[0] = len as u8;
        wire[1..len + 1].copy_from_slice(&alpn.as_bytes()[..len]);
        context
            .set_alpn_protos(&wire[..=len])
            .map_err(io::Error::other)?;
    }

    // Requiring peer verification also rules out certificate-based fallback
    // with PSK credentials: this branch has no trusted certificate roots.
    context.set_verify(SslVerifyMode::PEER);
    if let (Some(psk), Some(identity)) = (&tls.psk, &tls.identity) {
        let (psk, identity) = (psk.clone(), identity.clone());
        // Mosquitto lib/net_mosq.c: psk_client_callback ignores the server hint.
        context.set_psk_client_callback(move |_, _, identity_out, key_out| {
            let (identity, key) = (identity.as_bytes(), psk.as_bytes());
            if identity.len() >= identity_out.len() || key.len() > key_out.len() {
                return Ok(0);
            }
            identity_out[..identity.len()].copy_from_slice(identity);
            identity_out[identity.len()] = 0;
            key_out[..key.len()].copy_from_slice(key);
            Ok(key.len())
        });
    } else {
        certificate_context(&mut context, tls)?;
    }
    let mut ssl = Ssl::new(&context.build()).map_err(io::Error::other)?;
    match ServerName::try_from(host).map_err(io::Error::other)? {
        ServerName::DnsName(name) => {
            let name = name.as_ref();
            let name = name.strip_suffix('.').unwrap_or(name);
            ssl.set_hostname(name).map_err(io::Error::other)?;
            if tls.psk.is_none() && !tls.insecure {
                // lib/tls_mosq.c: tls__set_verify_hostname uses OpenSSL's
                // default host flags: partial wildcards are allowed and the
                // subject CN is checked when there are no DNS SANs.
                ssl.param_mut().set_host(name).map_err(io::Error::other)?;
            }
        }
        ServerName::IpAddress(ip) if tls.psk.is_none() && !tls.insecure => {
            ssl.param_mut()
                .set_ip(IpAddr::from(ip))
                .map_err(io::Error::other)?;
        }
        _ => {}
    }
    if tls.require_ocsp {
        ssl.set_status_type(StatusType::OCSP)
            .map_err(io::Error::other)?;
    }
    let mut stream = SslStream::new(ssl, stream).map_err(io::Error::other)?;
    Pin::new(&mut stream)
        .connect()
        .await
        .map_err(io::Error::other)?;
    if tls.require_ocsp {
        verify_staple(stream.ssl())?;
    } else if tls.psk.is_some()
        && stream.ssl().psk_identity() != tls.identity.as_deref().map(str::as_bytes)
    {
        return Err(io::Error::other("Peer did not negotiate bridge TLS-PSK"));
    }
    Ok(stream)
}

fn certificate_context(context: &mut SslContextBuilder, tls: &TlsConfig) -> io::Result<()> {
    if tls.use_os_certs {
        // lib/net_mosq.c: net__tls_load_ca ignores a failure to load OpenSSL's
        // default trust locations; the handshake then fails verification.
        let _ = context.set_default_verify_paths();
    }
    if tls.cafile.is_some() || tls.capath.is_some() {
        let cafile = checked_path(tls.cafile.as_deref(), "bridge_cafile")?;
        let capath = checked_path(tls.capath.as_deref(), "bridge_capath")?;
        context
            .load_verify_locations(cafile, capath)
            .map_err(io::Error::other)?;
    }
    if tls.certfile.is_some() != tls.keyfile.is_some() {
        return Err(io::Error::other(
            "Both bridge_certfile and bridge_keyfile must be provided.",
        ));
    }
    if let (Some(certfile), Some(keyfile)) = (&tls.certfile, &tls.keyfile) {
        checked_path(Some(certfile), "bridge_certfile")?;
        context
            .set_certificate_chain_file(certfile)
            .map_err(io::Error::other)?;
        // Parse the same unencrypted PEM key forms as rustls without OpenSSL's
        // default password prompt for encrypted key files.
        let key = PrivateKeyDer::from_pem_file(keyfile).map_err(|error| {
            io::Error::other(format!("bridge_keyfile '{}': {error}", keyfile.display()))
        })?;
        let key = PKey::private_key_from_der(key.secret_der()).map_err(io::Error::other)?;
        context.set_private_key(&key).map_err(io::Error::other)?;
        context.check_private_key().map_err(io::Error::other)?;
    }
    Ok(())
}

fn checked_path<'a>(path: Option<&'a Path>, directive: &str) -> io::Result<Option<&'a Path>> {
    // openssl's path APIs require UTF-8 and internally unwrap CString creation.
    if path.is_some_and(|path| path.to_str().is_none_or(|path| path.contains('\0'))) {
        return Err(io::Error::other(format!(
            "{directive}: expected a UTF-8 path without NUL"
        )));
    }
    Ok(path)
}

type CertIdHash = (&'static [u8], fn() -> MessageDigest);

// DER contents of the standard SHA-family hash OIDs used in OCSP CertIDs.
const CERT_ID_HASHES: [CertIdHash; 5] = [
    (b"\x2b\x0e\x03\x02\x1a", MessageDigest::sha1),
    (
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x04",
        MessageDigest::sha224,
    ),
    (
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x01",
        MessageDigest::sha256,
    ),
    (
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x02",
        MessageDigest::sha384,
    ),
    (
        b"\x60\x86\x48\x01\x65\x03\x04\x02\x03",
        MessageDigest::sha512,
    ),
];

fn verify_staple(ssl: &SslRef) -> io::Result<()> {
    let error = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    // Like Mosquitto lib/net_mosq_ocsp.c: mosquitto__verify_ocsp_status_cb, ask
    // for a staple and verify its signature locally. Unlike that callback, an
    // unrelated GOOD status cannot satisfy the check. Use the verified chain
    // rather than what the peer sent, which generally omits a root issuer.
    let der = ssl
        .ocsp_status()
        .ok_or_else(|| error("Missing stapled OCSP response"))?;
    let response = OcspResponse::from_der(der).map_err(io::Error::other)?;
    if response.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(error("Unsuccessful stapled OCSP response"));
    }
    let hashes = response_hashes(der)
        .ok_or_else(|| error("Malformed or ambiguous stapled OCSP response"))?;
    let chain = ssl
        .verified_chain()
        .filter(|_| ssl.verify_result() == X509VerifyResult::OK)
        .ok_or_else(|| error("No verified peer chain for stapled OCSP response"))?;
    let (Some(leaf), Some(issuer)) = (chain.get(0), chain.get(1)) else {
        return Err(error("No verified issuer for stapled OCSP response"));
    };
    let basic = response.basic().map_err(io::Error::other)?;
    // Do not accept an unrelated responder granted explicit trust: the signer
    // must be the certificate's issuer or a responder that issuer delegated.
    basic
        .verify(chain, ssl.ssl_context().cert_store(), OcspFlag::NO_EXPLICIT)
        .map_err(io::Error::other)?;
    let mut matched = false;
    for (index, (_, hash)) in CERT_ID_HASHES.into_iter().enumerate() {
        if hashes & (1 << index) == 0 {
            continue;
        }
        let id = OcspCertId::from_cert(hash(), leaf, issuer).map_err(io::Error::other)?;
        if let Some(status) = basic.find_status(&id) {
            if matched || status.status != OcspCertStatus::GOOD {
                return Err(error(
                    "Stapled OCSP response does not show an unambiguous GOOD leaf status",
                ));
            }
            if status.next_update().is_none() || status.check_validity(0, None).is_err() {
                return Err(error("Stapled OCSP leaf status is not current"));
            }
            matched = true;
        }
    }
    if !matched {
        return Err(error(
            "Stapled OCSP response does not cover the verified leaf",
        ));
    }
    Ok(())
}

// OpenSSL's safe find_status API only returns the first answer for a CertID.
// Reject duplicate IDs rather than let a GOOD entry hide a conflicting one.
// OpenSSL parses and verifies the response; this DER walk only checks framing
// and uniqueness, ignoring the hash AlgorithmIdentifier's optional parameters.
fn response_hashes(der: &[u8]) -> Option<u8> {
    fn take<'a>(data: &mut &'a [u8], tag: Tag) -> Option<&'a [u8]> {
        let (rest, item) = Any::from_der(data).ok()?;
        *data = rest;
        (item.tag() == tag).then_some(item.data)
    }
    let mut tail = der;
    let mut response = take(&mut tail, Tag::Sequence)?;
    take(&mut response, Tag::Enumerated)?;
    let mut explicit = take(&mut response, Tag(0))?;
    let mut bytes = take(&mut explicit, Tag::Sequence)?;
    take(&mut bytes, Tag::Oid)?;
    let mut inner = take(&mut bytes, Tag::OctetString)?;
    let mut basic = take(&mut inner, Tag::Sequence)?;
    if !(tail.is_empty()
        && response.is_empty()
        && explicit.is_empty()
        && bytes.is_empty()
        && inner.is_empty())
    {
        return None;
    }
    let mut tbs = take(&mut basic, Tag::Sequence)?;
    let (mut rest, mut responder) = Any::from_der(tbs).ok()?;
    if responder.class() == Class::ContextSpecific && responder.tag() == Tag(0) {
        (rest, responder) = Any::from_der(rest).ok()?;
    }
    if responder.class() != Class::ContextSpecific || !matches!(responder.tag(), Tag(1 | 2)) {
        return None;
    }
    tbs = rest;
    take(&mut tbs, Tag::GeneralizedTime)?;
    let mut responses = take(&mut tbs, Tag::Sequence)?;
    let mut ids = HashSet::new();
    let mut first = None;
    let mut hashes = 0;
    while !responses.is_empty() {
        let mut single = take(&mut responses, Tag::Sequence)?;
        let mut id = take(&mut single, Tag::Sequence)?;
        let mut algorithm = take(&mut id, Tag::Sequence)?;
        let id = (take(&mut algorithm, Tag::Oid)?, id);
        if let Some(index) = CERT_ID_HASHES.iter().position(|(oid, _)| *oid == id.0) {
            hashes |= 1 << index;
        }
        if first.is_none() {
            first = Some(id);
        } else if first == Some(id) || !ids.insert(id) {
            return None;
        }
    }
    first.map(|_| hashes)
}

#[cfg(test)]
mod tests;
