//! TLS connection handling functionality when using the `rustls` crate for
//! handling TLS.

use std::convert::TryFrom;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::Error;

use super::{Connection, HttpStream};

pub type SecuredStream = StreamOwned<ClientConnection, TcpStream>;

#[derive(Debug)]
struct AcceptAnyCertVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

static CONFIG: std::sync::LazyLock<Arc<ClientConfig>> = std::sync::LazyLock::new(|| {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("failed to set protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier(provider)))
        .with_no_client_auth();
    Arc::new(config)
});

pub fn create_secured_stream(conn: &Connection) -> Result<HttpStream, Error> {
    // Rustls setup
    #[cfg(feature = "log")]
    log::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let dns_name = ServerName::try_from(conn.request.url.host.as_str())
        .map_err(|err| Error::IoError(io::Error::new(io::ErrorKind::Other, err)))?
        .to_owned();
    let sess =
        ClientConnection::new(CONFIG.clone(), dns_name).map_err(Error::RustlsCreateConnection)?;

    // Connect
    #[cfg(feature = "log")]
    log::trace!("Establishing TCP connection to {}.", conn.request.url.host);
    let tcp = conn.connect()?;

    // Send request
    #[cfg(feature = "log")]
    log::trace!("Establishing TLS session to {}.", conn.request.url.host);
    let mut tls = StreamOwned::new(sess, tcp);

    // Verify certificate pin if configured
    #[cfg(feature = "cert-pin")]
    if let Some(expected_pin) = &conn.request.config.cert_pin {
        let certs = tls.conn.peer_certificates().ok_or_else(|| {
            Error::IoError(io::Error::new(
                io::ErrorKind::Other,
                "no peer certificate available",
            ))
        })?;
        let cert_der = certs.first().ok_or_else(|| {
            Error::IoError(io::Error::new(
                io::ErrorKind::Other,
                "empty certificate chain",
            ))
        })?;
        crate::cert_pin::verify_pin(cert_der.as_ref(), expected_pin)
            .map_err(|err| Error::IoError(io::Error::new(io::ErrorKind::Other, err)))?;
    }

    #[cfg(feature = "log")]
    log::trace!("Writing HTTPS request to {}.", conn.request.url.host);
    let _ = tls.get_ref().set_write_timeout(conn.timeout()?);
    tls.write_all(&conn.request.as_bytes())?;

    Ok(HttpStream::create_secured(tls, conn.timeout_at))
}
