mod bridge;

pub use bridge::connect_bridge_tls;

use std::{
    borrow::Cow,
    fmt::{Display, Write as _},
    fs,
    path::Path,
    sync::Arc,
};

use ::ring::digest::{Context as DigestContext, SHA1_FOR_LEGACY_USE_ONLY};
use openssl::{
    error::ErrorStack,
    pkey::PKey,
    ssl::{
        SslContext, SslContextBuilder, SslFiletype, SslMethod, SslMode, SslOptions,
        SslSessionCacheMode, SslVerifyMode, SslVersion,
    },
    stack::Stack,
    x509::{X509, store::X509Lookup, verify::X509VerifyFlags},
};

use rustls::{
    RootCertStore, ServerConfig, SupportedCipherSuite,
    crypto::ring,
    pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
    version::{TLS12, TLS13},
};
use tokio_rustls::TlsAcceptor;
use x509_parser::{
    asn1_rs::{Tag, ToDer},
    prelude::parse_x509_certificate,
    x509::{AttributeTypeAndValue, X509Name},
};

use crate::{CertIdentity, ListenerConfig, ListenerProtocol, ServerError, TlsConfig, TlsVersion};

#[derive(Clone)]
pub(crate) enum ListenerAcceptor {
    Rustls(TlsAcceptor),
    OpenSsl(SslContext),
}

pub(crate) fn acceptor(listener: &ListenerConfig) -> Result<Option<ListenerAcceptor>, ServerError> {
    let http_tls;
    let tls = if listener.protocol == ListenerProtocol::HttpApi {
        // http_api.c: http_api__start passes only cert/key into libmicrohttpd.
        // require_certificate still appears in the listener inventory.
        if listener.tls.certfile.is_none() || listener.tls.keyfile.is_none() {
            return Ok(None);
        }
        http_tls = TlsConfig {
            certfile: listener.tls.certfile.clone(),
            keyfile: listener.tls.keyfile.clone(),
            ..TlsConfig::default()
        };
        &http_tls
    } else {
        &listener.tls
    };
    mqtt_acceptor(listener.port, tls)
}

pub(crate) fn mqtt_acceptor(
    port: u16,
    tls: &TlsConfig,
) -> Result<Option<ListenerAcceptor>, ServerError> {
    let error = |message| ServerError::Tls { port, message };
    let (certfile, keyfile) = match (&tls.certfile, &tls.keyfile) {
        (Some(certfile), Some(keyfile)) => (certfile, keyfile),
        (None, None) => return Ok(None),
        _ => return Err(error("both certfile and keyfile are required".into())),
    };
    if tls.require_certificate && tls.disable_client_cert_date_checks {
        return openssl_acceptor(tls, certfile, keyfile)
            .map(|acceptor| Some(ListenerAcceptor::OpenSsl(acceptor)))
            .map_err(error);
    }

    let chain = pem_contents::<CertificateDer<'static>>(certfile, "certfile").map_err(error)?;
    let key = PrivateKeyDer::from_pem_file(keyfile)
        .map_err(|e| error(format!("keyfile '{}': {e}", keyfile.display())))?;
    let mut roots = RootCertStore::empty();
    client_roots(tls, |cert| roots.add(cert)).map_err(error)?;
    let crls = if let Some(path) = &tls.crlfile {
        let lists = pem_contents::<CertificateRevocationListDer<'static>>(path, "crlfile")
            .map_err(error)?;
        for list in &lists {
            x509_parser::parse_x509_crl(list.as_ref())
                .map_err(|e| error(format!("crlfile '{}': {e}", path.display())))?;
        }
        lists
    } else {
        Vec::new()
    };

    // Mosquitto src/net.c: net__tls_server_ctx, net__load_certificates, net__load_crl_file.
    let provider = Arc::new(
        cipher_provider(tls.ciphers.as_deref(), tls.ciphers_tls13.as_deref()).map_err(error)?,
    );
    let versions = match tls.version {
        TlsVersion::Tls12OrNewer => &[&TLS13, &TLS12][..],
        TlsVersion::Tls13 => &[&TLS13][..],
    };
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .map_err(|e| error(format!("tls_version: {e}")))?;
    let builder = if tls.require_certificate {
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .with_crls(crls)
            .only_check_end_entity_revocation()
            .enforce_revocation_expiration()
            .build()
            .map_err(|e| {
                error(format!(
                    "require_certificate (check cafile, capath and crlfile): {e}"
                ))
            })?;
        builder.with_client_cert_verifier(verifier)
    } else {
        // SSL_VERIFY_NONE doesn't send a CertificateRequest, even if a CA is configured.
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .map_err(|e| error(format!("certfile/keyfile: {e}")))?;
    config.ignore_client_order = true;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    Ok(Some(ListenerAcceptor::Rustls(acceptor)))
}

fn openssl_acceptor(
    tls: &TlsConfig,
    certfile: &Path,
    keyfile: &Path,
) -> Result<SslContext, String> {
    let ssl_error = |e: ErrorStack| e.to_string();
    let mut context = SslContextBuilder::new(SslMethod::tls_server()).map_err(ssl_error)?;
    context.set_options(
        SslOptions::NO_COMPRESSION
            | SslOptions::NO_RENEGOTIATION
            | SslOptions::CIPHER_SERVER_PREFERENCE
            | SslOptions::NO_TICKET,
    );
    // Recheck trust and CRL freshness on every connection.
    context.set_session_cache_mode(SslSessionCacheMode::OFF);
    context.set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
    let minimum = match tls.version {
        TlsVersion::Tls12OrNewer => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    };
    context
        .set_min_proto_version(Some(minimum))
        .map_err(|e| format!("tls_version: {e}"))?;

    // Keep the normal listener's cipher selection for certificate-based TLS.
    let provider = cipher_provider(tls.ciphers.as_deref(), tls.ciphers_tls13.as_deref())?;
    let (mut tls12, mut tls13) = (String::new(), String::new());
    for suite in provider.cipher_suites {
        let (name, _) = cipher_names(suite).expect("known ring cipher suite");
        let list = if suite.version() == &TLS13 {
            &mut tls13
        } else {
            &mut tls12
        };
        if !list.is_empty() {
            list.push(':');
        }
        list.push_str(name);
    }
    if minimum == SslVersion::TLS1_2 {
        context
            .set_cipher_list(&tls12)
            .map_err(|e| format!("ciphers: {e}"))?;
    }
    context
        .set_ciphersuites(&tls13)
        .map_err(|e| format!("ciphers_tls1.3: {e}"))?;

    let mut names = Stack::new().map_err(ssl_error)?;
    client_roots(tls, |der| {
        let cert = X509::from_der(der.as_ref())?;
        names.push(cert.subject_name().to_owned()?)?;
        context.cert_store_mut().add_cert(cert)
    })?;
    if names.is_empty() {
        return Err("require_certificate (check cafile and capath): no trust roots".into());
    }
    context.set_client_ca_list(names);

    if let Some(path) = &tls.crlfile {
        // The safe OpenSSL file lookup requires a UTF-8 C string.
        if path.to_str().is_none_or(|path| path.contains('\0')) {
            return Err("crlfile: expected a UTF-8 path without NUL".into());
        }
        let crl_error = |e| format!("crlfile '{}': {e}", path.display());
        let store = context.cert_store_mut();
        store
            .add_lookup(X509Lookup::file())
            .and_then(|lookup| lookup.load_crl_file(path, SslFiletype::PEM))
            .map_err(crl_error)?;
        // Mosquitto src/net.c: net__load_crl_file checks the leaf.
        store
            .set_flags(X509VerifyFlags::CRL_CHECK)
            .map_err(crl_error)?;
    }

    // Mosquitto src/net.c: client_certificate_verify. In particular, do not
    // set NO_CHECK_TIME: that would also disable checks on CRL validity.
    // The safe openssl crate exposes these x509_vfy.h codes only as raw values.
    const X509_V_ERR_CERT_NOT_YET_VALID: i32 = 9;
    const X509_V_ERR_CERT_HAS_EXPIRED: i32 = 10;
    context.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |ok, cert| {
            ok || matches!(
                cert.error().as_raw(),
                X509_V_ERR_CERT_NOT_YET_VALID | X509_V_ERR_CERT_HAS_EXPIRED
            )
        },
    );

    let cert_error = |e: ErrorStack| format!("certfile '{}': {e}", certfile.display());
    for (index, der) in pem_contents::<CertificateDer<'static>>(certfile, "certfile")?
        .into_iter()
        .enumerate()
    {
        let cert = X509::from_der(der.as_ref()).map_err(cert_error)?;
        if index == 0 {
            context.set_certificate(&cert).map_err(cert_error)?;
        } else {
            context.add_extra_chain_cert(cert).map_err(cert_error)?;
        }
    }
    // Parse the same key forms as rustls without OpenSSL's password prompt.
    let key = PrivateKeyDer::from_pem_file(keyfile)
        .map_err(|e| format!("keyfile '{}': {e}", keyfile.display()))?;
    let key = PKey::private_key_from_der(key.secret_der())
        .map_err(|e| format!("keyfile '{}': {e}", keyfile.display()))?;
    context
        .set_private_key(&key)
        .map_err(|e| format!("keyfile '{}': {e}", keyfile.display()))?;
    context
        .check_private_key()
        .map_err(|e| format!("certfile/keyfile: {e}"))?;
    Ok(context.build())
}

fn cipher_provider(
    ciphers: Option<&str>,
    ciphers_tls13: Option<&str>,
) -> Result<rustls::crypto::CryptoProvider, String> {
    let mut provider = ring::default_provider();
    if ciphers.is_some() || ciphers_tls13.is_some() {
        let mut suites = Vec::new();
        let (tls13, tls12) = provider.cipher_suites.split_at(3);
        if let Some(config) = ciphers_tls13 {
            suites.extend(cipher_list(tls13, config, "ciphers_tls1.3")?);
        } else {
            suites.extend_from_slice(tls13);
        }
        if let Some(config) = ciphers {
            suites.extend(cipher_list(tls12, config, "ciphers")?);
        } else {
            suites.extend_from_slice(tls12);
        }
        provider.cipher_suites = suites;
    }
    Ok(provider)
}

fn pem_contents<T: PemObject>(path: &Path, directive: &str) -> Result<Vec<T>, String> {
    let error = |message| format!("{directive} '{}': {message}", path.display());
    let entries = T::pem_file_iter(path)
        .and_then(|items| items.collect::<Result<Vec<_>, _>>())
        .map_err(|e| error(e.to_string()))?;
    if entries.is_empty() {
        return Err(error("no matching PEM entries".into()));
    }
    Ok(entries)
}

fn client_roots<E: Display>(
    tls: &TlsConfig,
    mut add: impl FnMut(CertificateDer<'static>) -> Result<(), E>,
) -> Result<(), String> {
    if let Some(path) = &tls.cafile {
        add_ca_file(path, "cafile", &mut add)?;
    }
    if let Some(directory) = &tls.capath {
        add_capath(directory, add)?;
    }
    Ok(())
}

fn add_ca_file<E: Display>(
    path: &Path,
    directive: &str,
    mut add: impl FnMut(CertificateDer<'static>) -> Result<(), E>,
) -> Result<(), String> {
    for cert in pem_contents::<CertificateDer<'static>>(path, directive)? {
        add(cert).map_err(|e| format!("{directive} '{}': {e}", path.display()))?;
    }
    Ok(())
}

fn add_capath<E: Display>(
    directory: &Path,
    mut add: impl FnMut(CertificateDer<'static>) -> Result<(), E>,
) -> Result<(), String> {
    // Mosquitto src/net.c: net__tls_load_verify delegates to OpenSSL's hashed
    // CA directory lookup. Don't trust unindexed or mismatched PEMs there.
    let err = |error: std::io::Error| format!("capath '{}': {error}", directory.display());
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).map_err(err)? {
        let entry = entry.map_err(err)?;
        let name = entry.file_name();
        let Some((hash, index)) = name.to_str().and_then(|name| name.split_once('.')) else {
            continue;
        };
        if hash.len() != 8
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !index.bytes().all(|b| b.is_ascii_digit())
            || (index.len() > 1 && index.starts_with('0'))
        {
            continue;
        }
        if let Ok(index) = index.parse::<u32>() {
            let hash = u32::from_str_radix(hash, 16).expect("eight hex digits");
            files.push((hash, index, entry.path()));
        }
    }
    files.sort_unstable();
    let mut previous = None;
    for (hash, index, file) in files {
        if index > 0 && previous != Some((hash, index - 1)) {
            continue;
        }
        previous = Some((hash, index));
        for der in pem_contents::<CertificateDer<'static>>(&file, "capath")? {
            let (_, cert) = parse_x509_certificate(der.as_ref())
                .map_err(|error| format!("capath '{}': {error}", file.display()))?;
            let actual = subject_name_hash(cert.subject())
                .ok_or_else(|| format!("capath '{}': invalid subject name", file.display()))?;
            if hash == actual {
                add(der).map_err(|error| format!("capath '{}': {error}", file.display()))?;
            }
        }
    }
    Ok(())
}

fn subject_name_hash(name: &X509Name<'_>) -> Option<u32> {
    // OpenSSL crypto/x509/x_name.c: x509_name_canon and i2d_name_canon hash
    // canonical DER SETs without the outer sequence. SHA-1 is only a file index.
    let mut hash = DigestContext::new(&SHA1_FOR_LEGACY_USE_ONLY);
    let mut set = Vec::new();
    for rdn in name.iter_rdn() {
        let mut entries = Vec::new();
        for attr in rdn.iter() {
            let mut content = attr.attr_type().to_der_vec().ok()?;
            if matches!(
                attr.attr_value().tag(),
                Tag::Utf8String
                    | Tag::BmpString
                    | Tag::UniversalString
                    | Tag::PrintableString
                    | Tag::TeletexString
                    | Tag::Ia5String
                    | Tag::VisibleString
            ) {
                let value = attribute_utf8(attr)??;
                let mut canon = Vec::new();
                for word in value
                    .split(|byte| matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12))
                    .filter(|word| !word.is_empty())
                {
                    if !canon.is_empty() {
                        canon.push(b' ');
                    }
                    canon.extend(word.iter().map(u8::to_ascii_lowercase));
                }
                der_header(&mut content, 0x0c, canon.len());
                content.extend(canon);
            } else {
                content.extend(attr.attr_value().to_der_vec().ok()?);
            }
            let mut entry = Vec::new();
            der_header(&mut entry, 0x30, content.len());
            entry.extend(content);
            entries.push(entry);
        }
        entries.sort_unstable();
        set.clear();
        der_header(&mut set, 0x31, entries.iter().map(Vec::len).sum());
        for entry in entries {
            set.extend(entry);
        }
        hash.update(&set);
    }
    let digest = hash.finish();
    Some(u32::from_le_bytes(
        digest.as_ref()[..4]
            .try_into()
            .expect("SHA-1 digest length"),
    ))
}

fn der_header(out: &mut Vec<u8>, tag: u8, len: usize) {
    out.push(tag);
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.len() - (usize::BITS - len.leading_zeros()).div_ceil(8) as usize;
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
}

fn cipher_list(
    available: &[SupportedCipherSuite],
    list: &str,
    directive: &str,
) -> Result<Vec<SupportedCipherSuite>, String> {
    let mut selected = Vec::new();
    let mut excluded = Vec::new();
    for rule in list.split([':', ',', ' ']).filter(|rule| !rule.is_empty()) {
        if directive == "ciphers" && rule == "@STRENGTH" {
            selected.sort_by_key(|suite| std::cmp::Reverse(cipher_strength(*suite)));
            continue;
        }
        let (action, name) = match rule.as_bytes()[0] {
            b'!' | b'-' | b'+' if directive == "ciphers" => (rule.as_bytes()[0], &rule[1..]),
            _ => (0, rule),
        };
        let mut matched = Vec::new();
        for suite in available.iter().copied() {
            let mut matches = true;
            for selector in name.split('+') {
                let accepts =
                    cipher_matches(suite, selector, directive == "ciphers").ok_or_else(|| {
                        format!("unsupported '{directive}' cipher or selector '{selector}'")
                    })?;
                matches &= accepts;
            }
            if matches {
                matched.push(suite);
            }
        }
        let contains = |suites: &[SupportedCipherSuite], suite: SupportedCipherSuite| {
            suites.iter().any(|entry| entry.suite() == suite.suite())
        };
        match action {
            b'!' | b'-' => {
                selected.retain(|suite| !contains(&matched, *suite));
                if action == b'!' {
                    excluded.extend(matched);
                }
            }
            b'+' => {
                let mut moved = Vec::new();
                selected.retain(|suite| {
                    if contains(&matched, *suite) {
                        moved.push(*suite);
                        false
                    } else {
                        true
                    }
                });
                selected.extend(moved);
            }
            _ => {
                for suite in matched {
                    if !contains(&excluded, suite) && !contains(&selected, suite) {
                        selected.push(suite);
                    }
                }
            }
        }
    }
    if selected.is_empty() {
        Err(format!(
            "'{directive}' does not enable any supported cipher suites"
        ))
    } else {
        Ok(selected)
    }
}

fn cipher_strength(suite: SupportedCipherSuite) -> u16 {
    use rustls::CipherSuite::*;
    match suite.suite() {
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 128,
        _ => 256,
    }
}

fn cipher_names(suite: SupportedCipherSuite) -> Option<(&'static str, &'static str)> {
    use rustls::CipherSuite::*;
    Some(match suite.suite() {
        TLS13_AES_128_GCM_SHA256 => ("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"),
        TLS13_AES_256_GCM_SHA384 => ("TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"),
        TLS13_CHACHA20_POLY1305_SHA256 => (
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => (
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => (
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => (
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => (
            "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => (
            "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => (
            "ECDHE-RSA-CHACHA20-POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        _ => return None,
    })
}

fn cipher_matches(suite: SupportedCipherSuite, selector: &str, ssl12: bool) -> Option<bool> {
    let (openssl, iana) = cipher_names(suite)?;
    // Recognize known suite names even when looking at a different suite.
    const TLS12_NAMES: &[&str] = &[
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ];
    const TLS13_NAMES: &[&str] = &[
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ];
    if (if ssl12 { TLS12_NAMES } else { TLS13_NAMES }).contains(&selector) {
        return Some(openssl == selector || iana == selector);
    }
    if !ssl12 {
        return None;
    }
    Some(match selector {
        "DEFAULT" | "ALL" | "HIGH" | "ECDHE" | "kECDHE" | "kEECDH" | "EECDH" | "TLSv1.2" => true,
        "aECDSA" | "ECDSA" => openssl.contains("-ECDSA-"),
        "aRSA" => openssl.contains("-RSA-"),
        "AES" | "AESGCM" | "GCM" => openssl.contains("-GCM-"),
        "AES128" => openssl.contains("-AES128-"),
        "AES256" => openssl.contains("-AES256-"),
        "CHACHA20" => openssl.contains("-CHACHA20-"),
        "aNULL" | "eNULL" | "NULL" | "LOW" | "MEDIUM" | "EXPORT" | "SSLv2" | "SSLv3" | "TLSv1"
        | "MD5" | "SHA1" | "3DES" | "RC4" | "PSK" | "DHE" | "EDH" | "kRSA" | "RSA" => false,
        _ => return None,
    })
}

pub(crate) fn identity(tls: &TlsConfig, peer: Option<&[u8]>) -> CertIdentity {
    if !tls.use_identity_as_username && !tls.use_subject_as_username {
        return CertIdentity::None;
    }
    let identity = || {
        let (_, cert) = parse_x509_certificate(peer?).ok()?;
        let name = cert.subject();
        // Mosquitto src/handle_connect.c: handle_username_from_cert_options,
        // set_username_from_cert_identity, set_username_from_cert_subject_name.
        // CN wins when both options are set; deliberately use raw ASN.1 content bytes.
        if tls.use_identity_as_username {
            let cn = name.iter_common_name().next()?.as_slice();
            Some(mqx_codec::validate_utf8(cn).ok()?.to_owned())
        } else {
            let subject = rfc2253(name)?;
            mqx_codec::validate_utf8(subject.as_bytes()).ok()?;
            Some(subject)
        }
    };
    identity().map_or(CertIdentity::MissingOrInvalid, CertIdentity::Username)
}

fn rfc2253(name: &X509Name<'_>) -> Option<String> {
    let mut output = String::new();
    // OpenSSL crypto/asn1/a_strex.c: do_name_ex reverses the entire entry list,
    // including entries within a single RDN. do_print_ex hex-escapes non-ASCII
    // UTF-8 and DER-dumps unknown attribute OIDs.
    let mut entries = name
        .iter_rdn()
        .flat_map(|rdn| {
            rdn.iter()
                .enumerate()
                .map(|(index, attr)| (index == 0, attr))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .peekable();
    while let Some((first_in_rdn, attr)) = entries.next() {
        let oid = attr.attr_type().to_id_string();
        let short = short_name(&oid);
        output.push_str(short.unwrap_or(&oid));
        output.push('=');
        if short.is_none() {
            append_der(&mut output, attr)?;
        } else if let Some(value) = attribute_utf8(attr)? {
            for (index, byte) in value.iter().copied().enumerate() {
                match byte {
                    0..=31 | 127..=255 => write!(output, "\\{byte:02X}").ok()?,
                    b',' | b'+' | b'"' | b'\\' | b'<' | b'>' | b';' => {
                        output.push('\\');
                        output.push(char::from(byte));
                    }
                    b' ' if index == 0 || index + 1 == value.len() => output.push_str("\\ "),
                    b'#' if index == 0 => output.push_str("\\#"),
                    _ => output.push(char::from(byte)),
                }
            }
        } else {
            append_der(&mut output, attr)?;
        }
        if entries.peek().is_some() {
            output.push(if first_in_rdn { ',' } else { '+' });
        }
    }
    Some(output)
}

fn append_der(output: &mut String, attr: &AttributeTypeAndValue<'_>) -> Option<()> {
    output.push('#');
    for byte in attr.attr_value().to_der_vec().ok()? {
        write!(output, "{byte:02X}").ok()?;
    }
    Some(())
}

fn attribute_utf8<'a>(attr: &'a AttributeTypeAndValue<'_>) -> Option<Option<Cow<'a, [u8]>>> {
    let bytes = attr.as_slice();
    Some(match attr.attr_value().tag() {
        Tag::Utf8String => Some(Cow::Borrowed(bytes)),
        Tag::PrintableString
        | Tag::Ia5String
        | Tag::NumericString
        | Tag::VisibleString
        | Tag::TeletexString
        | Tag::UtcTime
        | Tag::GeneralizedTime => Some(if bytes.is_ascii() {
            Cow::Borrowed(bytes)
        } else {
            let text: String = bytes.iter().copied().map(char::from).collect();
            Cow::Owned(text.into_bytes())
        }),
        Tag::BmpString => {
            let (units, remainder) = bytes.as_chunks::<2>();
            if !remainder.is_empty() {
                return None;
            }
            let text: Result<String, _> =
                char::decode_utf16(units.iter().copied().map(u16::from_be_bytes)).collect();
            Some(Cow::Owned(text.ok()?.into_bytes()))
        }
        Tag::UniversalString => {
            let (units, remainder) = bytes.as_chunks::<4>();
            if !remainder.is_empty() {
                return None;
            }
            let text: Option<String> = units
                .iter()
                .copied()
                .map(u32::from_be_bytes)
                .map(char::from_u32)
                .collect();
            Some(Cow::Owned(text?.into_bytes()))
        }
        _ => None,
    })
}

fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.13" => "description",
        "2.5.4.15" => "businessCategory",
        "2.5.4.16" => "postalAddress",
        "2.5.4.17" => "postalCode",
        "2.5.4.18" => "postOfficeBox",
        "2.5.4.19" => "physicalDeliveryOfficeName",
        "2.5.4.20" => "telephoneNumber",
        "2.5.4.41" => "name",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.45" => "x500UniqueIdentifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        _ => return None,
    })
}
