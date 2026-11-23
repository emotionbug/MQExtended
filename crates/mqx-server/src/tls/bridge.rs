use std::io;

use mqx_bridge::{TlsConfig, TlsFuture, Transport};
use tokio::net::TcpStream;

mod openssl;

/// Upgrade an outgoing MQTT bridge with Mosquitto's OpenSSL TLS semantics.
pub fn connect_bridge_tls<'a>(
    stream: TcpStream,
    host: &'a str,
    tls: &'a TlsConfig,
) -> TlsFuture<'a> {
    Box::pin(async move {
        tls.validate().map_err(io::Error::other)?;
        Ok(Box::new(openssl::connect(stream, host, tls).await?) as Box<dyn Transport>)
    })
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
        let crate::tls::ListenerAcceptor::Rustls(acceptor) = acceptor else {
            panic!("the default listener must not opt in to the date exception");
        };
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
