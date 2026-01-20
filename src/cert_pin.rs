//! Certificate pinning support via SPKI (Subject Public Key Info) hash verification.

use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Computes the SHA-256 hash of the certificate's SPKI (Subject Public Key Info).
pub fn compute_spki_hash(cert_der: &[u8]) -> Result<[u8; 32], &'static str> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|_| "failed to parse certificate")?;

    let spki_der = cert.public_key().raw;
    let hash = Sha256::digest(spki_der);

    Ok(hash.into())
}

/// Verifies that the certificate's SPKI hash matches the expected pin.
pub fn verify_pin(cert_der: &[u8], expected: &[u8; 32]) -> Result<(), &'static str> {
    let actual = compute_spki_hash(cert_der)?;

    if &actual == expected {
        Ok(())
    } else {
        Err("certificate SPKI hash does not match pinned value")
    }
}
