use std::fs::File;
use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::parse_x509_certificate;

use crate::transport::invalid_data;
use crate::{ClusterError, ClusterSecurity};

const NODE_PREFIX: &str = "mqx-node-";

pub(crate) struct Tls {
    pub(crate) client: TlsConnector,
    pub(crate) server: TlsAcceptor,
}

impl Tls {
    pub(crate) fn load(
        security: &ClusterSecurity,
        node_id: u64,
    ) -> Result<Option<Self>, ClusterError> {
        let ClusterSecurity::Tls {
            ca_file,
            cert_file,
            key_file,
        } = security
        else {
            tracing::warn!(
                node_id,
                "INSECURE cluster transport: peer traffic is unencrypted and unauthenticated"
            );
            return Ok(None);
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_reader_iter(File::open(ca_file)?) {
            roots
                .add(cert.map_err(invalid_data)?)
                .map_err(invalid_data)?;
        }
        let roots = Arc::new(roots);
        let chain: Vec<_> = CertificateDer::pem_reader_iter(File::open(cert_file)?)
            .collect::<Result<_, _>>()
            .map_err(invalid_data)?;
        if chain.first().and_then(certificate_node) != Some(node_id) {
            return Err(ClusterError::InvalidConfig(format!(
                "cluster leaf certificate needs one Common Name: {NODE_PREFIX}{node_id}"
            )));
        }
        let key = PrivateKeyDer::from_pem_reader(File::open(key_file)?).map_err(invalid_data)?;
        let client_auth =
            WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
                .build()
                .map_err(invalid_data)?;
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(invalid_data)?
            .with_client_cert_verifier(client_auth)
            .with_single_cert(chain.clone(), key.clone_key())
            .map_err(invalid_data)?;
        // Each connection authenticates its certificate and proves possession afresh.
        server.send_tls13_tickets = 0;
        let verifier = NodeVerifier {
            roots,
            algorithms: provider.signature_verification_algorithms,
        };
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(invalid_data)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(chain, key)
            .map_err(invalid_data)?;
        client.enable_sni = false;
        client.resumption = rustls::client::Resumption::disabled();
        Ok(Some(Self {
            client: Arc::new(client).into(),
            server: Arc::new(server).into(),
        }))
    }
}

pub(crate) fn node_name(id: u64) -> io::Result<ServerName<'static>> {
    ServerName::try_from(format!("{NODE_PREFIX}{id}")).map_err(invalid_data)
}

pub(crate) fn certificate_node(cert: &CertificateDer<'_>) -> Option<u64> {
    let (trailing, parsed) = parse_x509_certificate(cert.as_ref()).ok()?;
    let mut names = parsed.subject().iter_common_name();
    let name = names.next()?.as_str().ok()?;
    (trailing.is_empty() && names.next().is_none()).then_some(())?;
    parse_node_name(name)
}

fn parse_node_name(name: &str) -> Option<u64> {
    let id = name.strip_prefix(NODE_PREFIX)?;
    if (id.starts_with('0') && id.len() > 1) || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    id.parse().ok()
}

#[derive(Debug)]
struct NodeVerifier {
    roots: Arc<RootCertStore>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NodeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        // `name` is an internal node-id carrier, not DNS or an IP from the socket.
        let expected = match name {
            ServerName::DnsName(name) => parse_node_name(name.as_ref()),
            _ => None,
        };
        if expected.is_none() || certificate_node(end_entity) != expected {
            return Err(CertificateError::NotValidForName.into());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    #[test]
    fn trusted_ca_is_not_enough_without_the_expected_node_identity() {
        let mut ca = CertificateParams::default();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(ca.self_signed(&key).unwrap().der().clone())
            .unwrap();
        let issuer = Issuer::new(ca, key);
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "mqx-node-7");
        let leaf = params
            .signed_by(&KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        let verifier = NodeVerifier {
            roots: Arc::new(roots),
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };
        let now = UnixTime::now();
        assert!(
            verifier
                .verify_server_cert(leaf.der(), &[], &node_name(7).unwrap(), &[], now)
                .is_ok()
        );
        assert_eq!(
            verifier
                .verify_server_cert(leaf.der(), &[], &node_name(8).unwrap(), &[], now)
                .unwrap_err(),
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        );
    }
}
