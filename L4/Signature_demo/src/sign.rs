// A small signature wrapper: generate a key pair, export its public key, sign, and verify.
// ECDSA P-256 and P-384 share the RustCrypto API; Ed25519 uses ed25519-dalek.
// Read the match branches below to see the underlying library calls.

use p256::ecdsa::signature::{RandomizedSigner, Signer, Verifier};
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use std::fmt;

#[derive(Clone, Copy)]
pub enum Scheme {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
}

#[derive(Debug)]
pub enum SignError {
    Random(rand::Error),
    Signing,
    RandomizedUnsupported,
    InvalidPublicKey,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(error) => write!(f, "Random key generation failed: {error}"),
            Self::Signing => write!(f, "Signing failed"),
            Self::RandomizedUnsupported => write!(f, "This scheme has no randomized signing"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

impl std::error::Error for SignError {}

enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    pub fn generate(scheme: Scheme) -> Result<Self, SignError> {
        let mut rng = StdRng::from_rng(OsRng).map_err(SignError::Random)?; // Handle OS randomness errors here.
        let signing_key = match scheme {
            Scheme::Ed25519 => SigningKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
            Scheme::EcdsaP256 => SigningKey::P256(p256::ecdsa::SigningKey::random(&mut rng)),
            Scheme::EcdsaP384 => SigningKey::P384(p384::ecdsa::SigningKey::random(&mut rng)),
        };
        Ok(Self { signing_key })
    }

    // Ed25519: 32-byte encoded point. P-256/P-384: compressed SEC1 point encoding.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.signing_key {
            SigningKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
            SigningKey::P256(key) => key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            SigningKey::P384(key) => key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        }
    }

    // Unlike the ephemeral DH secret in DH_handshake_demo, a signing key is long-term: &self allows many signatures.
    // Ed25519: R || S (64 bytes). ECDSA: r || s (64 bytes for P-256, 96 bytes for P-384).
    // ECDSA hashes the message first: SHA-256 for P-256, SHA-384 for P-384.
    // Deterministic for all three schemes: the nonce is derived from the secret key and message
    // (Ed25519: RFC 8032; ECDSA: RFC 6979), so the same message always gives the same signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        match &self.signing_key {
            SigningKey::Ed25519(key) => {
                let signature: ed25519_dalek::Signature =
                    key.try_sign(message).map_err(|_| SignError::Signing)?; // Return errors instead of panicking.
                Ok(signature.to_bytes().to_vec())
            }
            SigningKey::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    key.try_sign(message).map_err(|_| SignError::Signing)?;
                Ok(signature.to_bytes().to_vec())
            }
            SigningKey::P384(key) => {
                let signature: p384::ecdsa::Signature =
                    key.try_sign(message).map_err(|_| SignError::Signing)?;
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    // Randomized ECDSA: fresh random bytes are mixed into the nonce derivation for every signature,
    // so the same message gives a different signature each time. Both kinds verify the same way.
    // Ed25519 (RFC 8032) defines only deterministic signing, and ed25519-dalek has no randomized
    // signing function to call, so this wrapper returns RandomizedUnsupported for Ed25519.
    pub fn sign_randomized(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let mut rng = StdRng::from_rng(OsRng).map_err(SignError::Random)?; // Handle OS randomness errors here.
        match &self.signing_key {
            SigningKey::Ed25519(_) => Err(SignError::RandomizedUnsupported),
            SigningKey::P256(key) => {
                let signature: p256::ecdsa::Signature = key
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| SignError::Signing)?;
                Ok(signature.to_bytes().to_vec())
            }
            SigningKey::P384(key) => {
                let signature: p384::ecdsa::Signature = key
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| SignError::Signing)?;
                Ok(signature.to_bytes().to_vec())
            }
        }
    }
}

// Verification needs only the public key, not the KeyPair.
// Returns Ok(true) for a valid signature, Ok(false) for an invalid one,
// or Err if the public key cannot be decoded.
pub fn verify(
    scheme: Scheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignError> {
    match scheme {
        Scheme::Ed25519 => {
            let mut bytes = [0u8; 32];
            if public_key.len() != bytes.len() {
                return Err(SignError::InvalidPublicKey); // Reject a public key with the wrong length.
            }
            bytes.copy_from_slice(public_key);
            let public = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|_| SignError::InvalidPublicKey)?; // Validate the received point.
            let signature = match ed25519_dalek::Signature::from_slice(signature) {
                Ok(signature) => signature,
                Err(_) => return Ok(false), // A malformed signature is an invalid signature.
            };
            Ok(public.verify_strict(message, &signature).is_ok()) // Strict checks reject weak keys and non-canonical signatures.
        }
        Scheme::EcdsaP256 => {
            let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| SignError::InvalidPublicKey)?;
            let signature = match p256::ecdsa::Signature::from_slice(signature) {
                Ok(signature) => signature,
                Err(_) => return Ok(false),
            };
            Ok(public.verify(message, &signature).is_ok())
        }
        Scheme::EcdsaP384 => {
            let public = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| SignError::InvalidPublicKey)?;
            let signature = match p384::ecdsa::Signature::from_slice(signature) {
                Ok(signature) => signature,
                Err(_) => return Ok(false),
            };
            Ok(public.verify(message, &signature).is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{verify, KeyPair, Scheme, SignError, SigningKey};

    const SCHEMES: [Scheme; 3] = [Scheme::Ed25519, Scheme::EcdsaP256, Scheme::EcdsaP384];

    #[test]
    fn sign_and_verify_on_each_scheme() {
        for (scheme, public_len, signature_len) in [
            (Scheme::Ed25519, 32, 64),
            (Scheme::EcdsaP256, 33, 64),
            (Scheme::EcdsaP384, 49, 96),
        ] {
            let alice = KeyPair::generate(scheme).unwrap();
            let public = alice.public_key();
            let signature = alice.sign(b"hello").unwrap();
            assert_eq!(public.len(), public_len);
            assert_eq!(signature.len(), signature_len);
            assert!(verify(scheme, &public, b"hello", &signature).unwrap());
        }
    }

    #[test]
    fn modified_message_or_signature_fails() {
        for scheme in SCHEMES {
            let alice = KeyPair::generate(scheme).unwrap();
            let public = alice.public_key();
            let signature = alice.sign(b"Pay Bob 100 EUR").unwrap();
            assert!(!verify(scheme, &public, b"Pay Bob 900 EUR", &signature).unwrap());

            for byte_index in [0, signature.len() - 1] {
                let mut modified_signature = signature.clone();
                modified_signature[byte_index] ^= 0x01; // flip a bit
                assert!(!verify(scheme, &public, b"Pay Bob 100 EUR", &modified_signature).unwrap());
            }
        }
    }

    #[test]
    fn another_public_key_fails() {
        for scheme in SCHEMES {
            let alice = KeyPair::generate(scheme).unwrap();
            let mallory = KeyPair::generate(scheme).unwrap();
            let signature = alice.sign(b"hello").unwrap();
            assert!(!verify(scheme, &mallory.public_key(), b"hello", &signature).unwrap());
        }
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        for scheme in SCHEMES {
            let alice = KeyPair::generate(scheme).unwrap();
            let public = alice.public_key();
            let signature = alice.sign(b"hello").unwrap();
            assert!(matches!(
                verify(scheme, &[], b"hello", &signature),
                Err(SignError::InvalidPublicKey)
            ));
            assert!(!verify(scheme, &public, b"hello", &[]).unwrap());
            assert!(!verify(scheme, &public, b"hello", &signature[1..]).unwrap());
        }
    }

    #[test]
    fn deterministic_signing_twice_gives_the_same_signature() {
        for scheme in SCHEMES {
            let alice = KeyPair::generate(scheme).unwrap();
            assert_eq!(alice.sign(b"hello").unwrap(), alice.sign(b"hello").unwrap());
        }
    }

    #[test]
    fn randomized_ecdsa_signatures_differ_and_verify() {
        for scheme in [Scheme::EcdsaP256, Scheme::EcdsaP384] {
            let alice = KeyPair::generate(scheme).unwrap();
            let public = alice.public_key();
            let deterministic = alice.sign(b"hello").unwrap();
            let randomized1 = alice.sign_randomized(b"hello").unwrap();
            let randomized2 = alice.sign_randomized(b"hello").unwrap();
            assert_ne!(randomized1, randomized2);
            assert_ne!(randomized1, deterministic);
            assert!(verify(scheme, &public, b"hello", &randomized1).unwrap());
            assert!(verify(scheme, &public, b"hello", &randomized2).unwrap());
        }
    }

    #[test]
    fn ed25519_has_no_randomized_signing() {
        let alice = KeyPair::generate(Scheme::Ed25519).unwrap();
        assert!(matches!(
            alice.sign_randomized(b"hello"),
            Err(SignError::RandomizedUnsupported)
        ));
    }

    // RFC 8032, section 7.1, TEST 1 (empty message).
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
    #[test]
    fn rfc8032_ed25519_test_1() {
        let secret: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let alice = KeyPair {
            signing_key: SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&secret)),
        };
        assert_eq!(
            hex::encode(alice.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let signature = alice.sign(b"").unwrap();
        assert_eq!(
            hex::encode(&signature),
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        assert!(verify(Scheme::Ed25519, &alice.public_key(), b"", &signature).unwrap());
    }

    // RFC 6979, appendix A.2.5: P-256 with SHA-256, message "sample".
    // https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5
    #[test]
    fn rfc6979_p256_sha256_sample() {
        let secret =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();
        let alice = KeyPair {
            signing_key: SigningKey::P256(p256::ecdsa::SigningKey::from_slice(&secret).unwrap()),
        };
        let signature = alice.sign(b"sample").unwrap();
        assert_eq!(
            hex::encode(&signature),
            concat!(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
            )
        );
        assert!(verify(
            Scheme::EcdsaP256,
            &alice.public_key(),
            b"sample",
            &signature
        )
        .unwrap());
    }
}
