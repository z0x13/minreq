//! Certificate pinning support via SPKI (Subject Public Key Info) hash verification.

use sha2::{Digest, Sha256};

const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xA0;

/// Minimal DER reader
struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos)?;
        self.pos += 1;
        Some(*b)
    }

    /// Read DER length field, returns (length, was_valid)
    fn read_length(&mut self) -> Option<usize> {
        let first = self.read_byte()?;

        if first < 0x80 {
            // Short form: length is directly encoded
            Some(first as usize)
        } else if first == 0x80 {
            // Indefinite length - not valid in DER
            None
        } else {
            // Long form: first byte indicates number of length octets
            let num_octets = (first & 0x7F) as usize;
            if num_octets > 4 {
                // Too long for our purposes
                return None;
            }

            let mut length: usize = 0;
            for _ in 0..num_octets {
                let b = self.read_byte()?;
                length = length.checked_mul(256)?.checked_add(b as usize)?;
            }
            Some(length)
        }
    }

    /// Read tag and length, return content slice and advance past it
    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.read_byte()?;
        let length = self.read_length()?;
        let content = self.data.get(self.pos..self.pos.checked_add(length)?)?;
        self.pos = self.pos.checked_add(length)?;
        Some((tag, content))
    }

    /// Skip one TLV element
    fn skip_tlv(&mut self) -> Option<()> {
        let _ = self.read_tlv()?;
        Some(())
    }

    /// Read a SEQUENCE, return reader for its content
    fn read_sequence(&mut self) -> Option<DerReader<'a>> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return None;
        }
        Some(DerReader::new(content))
    }
}

/// Extract raw SPKI bytes (including tag and length) from a DER-encoded X.509 certificate.
///
/// X.509 structure:
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
///
/// TBSCertificate ::= SEQUENCE {
///     version         [0]  EXPLICIT Version DEFAULT v1,  -- optional
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,  <-- we need this
///     ...
/// }
/// ```
fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let mut cert_reader = DerReader::new(cert_der);

    // Certificate SEQUENCE
    let mut tbs_reader = cert_reader.read_sequence()?.read_sequence()?;

    // Skip optional version [0]
    if tbs_reader.peek_tag() == Some(TAG_CONTEXT_0) {
        tbs_reader.skip_tlv()?;
    }

    // Skip: serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        tbs_reader.skip_tlv()?;
    }

    // Now we're at subjectPublicKeyInfo - capture raw bytes including tag+length
    let spki_start = tbs_reader.pos;
    tbs_reader.skip_tlv()?;
    let spki_end = tbs_reader.pos;

    tbs_reader.data.get(spki_start..spki_end)
}

/// Computes the SHA-256 hash of the certificate's SPKI (Subject Public Key Info).
pub fn compute_spki_hash(cert_der: &[u8]) -> Result<[u8; 32], &'static str> {
    let spki = extract_spki(cert_der).ok_or("failed to parse certificate")?;
    Ok(Sha256::digest(spki).into())
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
