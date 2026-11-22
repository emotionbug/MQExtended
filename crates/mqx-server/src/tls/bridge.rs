use std::{io, sync::Arc};

use mqx_bridge::{TlsConfig, TlsFuture, Transport};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::ParsedCertificate,
    version::{TLS12, TLS13},
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{add_capath, add_roots, cipher_provider, pem_contents};

mod openssl;

/// Upgrade a connected outgoing MQTT bridge, using OpenSSL only for PSK or OCSP.
pub fn connect_bridge_tls<'a>(
    stream: TcpStream,
    host: &'a str,
    tls: &'a TlsConfig,
) -> TlsFuture<'a> {
    Box::pin(async move {
        tls.validate().map_err(io::Error::other)?;
        if tls.psk.is_some() || tls.require_ocsp {
            return Ok(Box::new(openssl::connect(stream, host, tls).await?) as Box<dyn Transport>);
        }
        let config = Arc::new(client_config(tls).map_err(io::Error::other)?);
        let host = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let stream = TlsConnector::from(config).connect(host, stream).await?;
        Ok(Box::new(stream) as Box<dyn Transport>)
    })
}

// Mosquitto lib/net_mosq.c: net__init_ssl_ctx. Both configured trust sources
// and the OS trust store, when requested, may authenticate the server.
fn client_config(tls: &TlsConfig) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    if tls.use_os_certs {
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        if roots.is_empty()
            && tls.cafile.is_none()
            && tls.capath.is_none()
            && !native.errors.is_empty()
        {
            return Err(format!(
                "Unable to load OS certificates: {:?}",
                native.errors
            ));
        }
    }
    if let Some(path) = &tls.cafile {
        add_roots(&mut roots, path, "bridge_cafile")?;
    }
    if let Some(path) = &tls.capath {
        add_capath(&mut roots, path)?;
    }
    let provider = cipher_provider(tls.ciphers.as_deref(), tls.ciphers_tls13.as_deref())?;
    let signatures = provider.signature_verification_algorithms;
    let versions = match tls.version.as_deref() {
        None | Some("tlsv1.2") => &[&TLS13, &TLS12][..],
        Some("tlsv1.3") => &[&TLS13][..],
        Some(version) => return Err(format!("Protocol {version} not supported")),
    };
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|error| error.to_string())?;
    let builder = if tls.insecure {
        // lib/tls_mosq.c: mosquitto__server_certificate_verify skips the
        // hostname check only; CA and handshake signatures still apply.
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerifyChain { roots, signatures }))
    } else {
        builder.with_root_certificates(roots)
    };
    let mut config = match (&tls.certfile, &tls.keyfile) {
        (Some(certfile), Some(keyfile)) => {
            let chain = pem_contents(certfile, "bridge_certfile")?;
            let key = PrivateKeyDer::from_pem_file(keyfile)
                .map_err(|error| format!("bridge_keyfile '{}': {error}", keyfile.display()))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|error| error.to_string())?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => return Err("Both bridge_certfile and bridge_keyfile must be provided".into()),
    };
    if let Some(alpn) = &tls.alpn {
        config
            .alpn_protocols
            .push(alpn.as_bytes()[..alpn.len().min(254)].to_vec());
    }
    Ok(config)
}

#[derive(Debug)]
struct VerifyChain {
    roots: RootCertStore,
    signatures: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for VerifyChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            &self.roots,
            intermediates,
            now,
            self.signatures.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, signed, &self.signatures)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signed, &self.signatures)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signatures.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ListenerConfig, TlsConfig as ListenerTls};

    #[tokio::test]
    async fn insecure_bridge_skips_hostname_but_not_chain_verification() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = directory.path().join("server.pem");
        let key = directory.path().join("server.key");
        let wrong_ca = directory.path().join("wrong-ca.pem");
        std::fs::write(&certificate, trusted.cert.pem()).unwrap();
        std::fs::write(&key, trusted.signing_key.serialize_pem()).unwrap();
        std::fs::write(&wrong_ca, other.cert.pem()).unwrap();
        let acceptor = super::super::acceptor(&ListenerConfig {
            tls: ListenerTls {
                certfile: Some(certificate.clone()),
                keyfile: Some(key),
                ..ListenerTls::default()
            },
            ..ListenerConfig::default()
        })
        .unwrap()
        .unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        for (host, insecure, ca, accepted) in [
            ("localhost", false, &certificate, true),
            ("wrong.example", false, &certificate, false),
            ("wrong.example", true, &certificate, true),
            ("localhost", true, &wrong_ca, false),
        ] {
            let tls = TlsConfig {
                cafile: Some(ca.clone()),
                insecure,
                ..TlsConfig::default()
            };
            let client = TcpStream::connect(address).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let (result, _) = tokio::join!(
                connect_bridge_tls(client, host, &tls),
                acceptor.accept(server)
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "{host}, insecure={insecure}, {}",
                ca.display()
            );
        }
    }
}
