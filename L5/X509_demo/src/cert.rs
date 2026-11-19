// Small helpers around the x509-parser crate: load certificates from a file and print their fields.
// Read the functions below to see where each field comes from in the certificate.

use sha2::{Digest, Sha256};
use std::fmt;
use x509_parser::{
    certificate::X509Certificate,
    extensions::GeneralName,
    objects::{oid2sn, oid_registry},
    oid_registry::Oid,
    pem::Pem,
    public_key::PublicKey,
};

#[derive(Debug)]
pub enum CertError {
    Io(std::io::Error),
    InvalidPem,
    InvalidCertificate,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Cannot read file: {error}"),
            Self::InvalidPem => write!(f, "Invalid PEM block"),
            Self::InvalidCertificate => write!(f, "Invalid X.509 certificate"),
        }
    }
}

impl std::error::Error for CertError {}

// Returns the DER bytes of each certificate in the file.
// PEM: one or more blocks -----BEGIN CERTIFICATE----- Base64(DER) -----END CERTIFICATE-----.
// A file without PEM blocks is treated as one DER certificate (common for .cer/.crt files).
pub fn load_certificates(path: &str) -> Result<Vec<Vec<u8>>, CertError> {
    let data = std::fs::read(path).map_err(CertError::Io)?;
    let mut certificates = Vec::new();
    for block in Pem::iter_from_buffer(&data) {
        let block = block.map_err(|_| CertError::InvalidPem)?;
        if block.label == "CERTIFICATE" {
            certificates.push(block.contents); // Base64 is already decoded: this is DER.
        }
    }
    if certificates.is_empty() {
        certificates.push(data); // No PEM block: try the file as DER.
    }
    Ok(certificates)
}

// Parse DER bytes. The certificate borrows from `der`, so keep the bytes alive while using it.
pub fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>, CertError> {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, certificate)) => Ok(certificate),
        Err(_) => Err(CertError::InvalidCertificate),
    }
}

// Short name of an object identifier (OID), e.g. 1.2.840.10045.4.3.3 -> ecdsa-with-SHA384.
fn oid_name(oid: &Oid) -> String {
    match oid2sn(oid, oid_registry()) {
        Ok(name) => name.to_string(),
        Err(_) => oid.to_id_string(), // Unknown OID: print the dotted numbers.
    }
}

pub fn print_certificate(certificate: &X509Certificate, der: &[u8]) {
    println!("Subject: {}", certificate.subject());
    println!("Issuer: {}", certificate.issuer()); // Subject == issuer for a self-signed root.
    println!("Version: v{}", certificate.version().0 + 1); // X.509 encodes v3 as the number 2.
    println!(
        "Serial number (hex): {}",
        certificate.raw_serial_as_string()
    );
    println!("Valid from: {}", certificate.validity().not_before);
    println!("Valid until: {}", certificate.validity().not_after);
    println!("Valid now: {}", certificate.validity().is_valid());

    // Subject public key: the key this certificate vouches for.
    let spki = certificate.public_key();
    let algorithm = oid_name(&spki.algorithm.algorithm);
    match spki.parsed() {
        Ok(PublicKey::EC(point)) => {
            // For EC keys, the parameters field names the curve.
            let curve = match spki.algorithm.parameters.as_ref().map(|p| p.as_oid()) {
                Some(Ok(oid)) => oid_name(&oid),
                _ => "unknown curve".to_string(),
            };
            println!(
                "Public key: {algorithm}, {curve}, {} bits",
                point.key_size()
            );
        }
        Ok(PublicKey::RSA(rsa)) => println!("Public key: {algorithm}, {} bits", rsa.key_size()),
        Ok(_) | Err(_) => println!("Public key: {algorithm}"),
    }

    // Signature by the issuer over the certificate body (TBSCertificate).
    // X.509 stores an ECDSA signature as DER SEQUENCE { r, s }, not as r || s as in L4/Signature_demo,
    // so its length varies by a few bytes. An RSA signature is as long as the issuer's modulus.
    println!(
        "Signature algorithm: {}",
        oid_name(&certificate.signature_algorithm.algorithm)
    );
    println!(
        "Signature ({} bytes)",
        certificate.signature_value.data.len()
    );

    // Extensions (X.509 v3).
    if let Ok(Some(extension)) = certificate.basic_constraints() {
        println!("CA certificate: {}", extension.value.ca); // May this key sign other certificates?
    }
    if let Ok(Some(extension)) = certificate.key_usage() {
        println!("Key usage: {}", extension.value);
    }
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        let mut names = Vec::new();
        for name in &extension.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push(*dns);
            }
        }
        println!("Subject alternative names (DNS): {}", names.join(", "));
    }

    // A fingerprint is a hash of the whole DER certificate, not a field inside it.
    println!("SHA-256 fingerprint: {}", hex::encode(Sha256::digest(der)));
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/certs/letsencrypt_org_chain.pem"
    );
    const ROOT_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/certs/isrg_root_x1.pem");

    #[test]
    fn reads_the_example_certificates() {
        let chain = load_certificates(CHAIN_FILE).unwrap();
        assert_eq!(chain.len(), 4);
        let leaf = parse_certificate(&chain[0]).unwrap();
        assert_eq!(leaf.subject().to_string(), "CN=letsencrypt.org");
        assert_eq!(leaf.version().0, 2); // v3
        assert_eq!(leaf.public_key().parsed().unwrap().key_size(), 256);
        assert_eq!(
            oid_name(&leaf.signature_algorithm.algorithm),
            "ecdsa-with-SHA384"
        );
        assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);

        let root = load_certificates(ROOT_FILE).unwrap();
        assert_eq!(root.len(), 1);
        let root = parse_certificate(&root[0]).unwrap();
        assert_eq!(root.subject(), root.issuer()); // Self-signed.
        assert!(root.basic_constraints().unwrap().unwrap().value.ca);
    }

    #[test]
    fn reads_a_der_file() {
        let der = load_certificates(ROOT_FILE).unwrap().remove(0);
        let path = std::env::temp_dir().join("x509_demo_test_root.der");
        std::fs::write(&path, &der).unwrap();
        let loaded = load_certificates(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(loaded, vec![der]);
    }

    #[test]
    fn missing_file_or_non_certificate_is_an_error() {
        assert!(matches!(
            load_certificates("no/such/file.pem"),
            Err(CertError::Io(_))
        ));
        let not_a_certificate =
            load_certificates(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        assert!(matches!(
            parse_certificate(&not_a_certificate[0]),
            Err(CertError::InvalidCertificate)
        ));
    }
}
