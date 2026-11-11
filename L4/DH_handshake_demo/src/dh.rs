// A small DH wrapper: generate a key pair, export its public key, and agree on a shared secret.
// P-256 and P-384 share the RustCrypto API; X25519 uses a different API.
// Read the match branches below to see the underlying library calls.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use std::fmt;

#[derive(Clone, Copy)]
pub enum Curve {
    X25519,
    P256,
    P384,
}

#[derive(Debug)]
pub enum DhError {
    Random(rand::Error),
    InvalidPublicKey,
}

impl fmt::Display for DhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(error) => write!(f, "Random key generation failed: {error}"),
            Self::InvalidPublicKey => write!(f, "Invalid peer public key"),
        }
    }
}

impl std::error::Error for DhError {}

enum Secret {
    X25519(x25519_dalek::EphemeralSecret),
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
}

pub struct KeyPair {
    secret: Secret,
}

impl KeyPair {
    pub fn generate(curve: Curve) -> Result<Self, DhError> {
        let mut rng = StdRng::from_rng(OsRng).map_err(DhError::Random)?; // Handle OS randomness errors here.
        let secret = match curve {
            Curve::X25519 => {
                Secret::X25519(x25519_dalek::EphemeralSecret::random_from_rng(&mut rng))
            }
            Curve::P256 => Secret::P256(p256::ecdh::EphemeralSecret::random(&mut rng)),
            Curve::P384 => Secret::P384(p384::ecdh::EphemeralSecret::random(&mut rng)),
        };
        Ok(Self { secret })
    }

    // X25519: 32-byte u-coordinate. P-256/P-384: compressed SEC1 point encoding.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.secret {
            Secret::X25519(secret) => x25519_dalek::PublicKey::from(secret).as_bytes().to_vec(),
            Secret::P256(secret) => secret
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            Secret::P384(secret) => secret
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        }
    }

    // Consuming self prevents reuse of this ephemeral key pair.
    // The returned bytes encode the shared point's coordinate, not the complete point.
    pub fn agree(self, peer_public: &[u8]) -> Result<Vec<u8>, DhError> {
        match self.secret {
            Secret::X25519(secret) => {
                let mut bytes = [0u8; 32];
                if peer_public.len() != bytes.len() {
                    return Err(DhError::InvalidPublicKey); // Reject a public key with the wrong length.
                }
                bytes.copy_from_slice(peer_public);
                let public = x25519_dalek::PublicKey::from(bytes);
                let shared = secret.diffie_hellman(&public);
                if !shared.was_contributory() {
                    return Err(DhError::InvalidPublicKey); // Reject an all-zero shared secret.
                }
                Ok(shared.as_bytes().to_vec())
            }
            Secret::P256(secret) => {
                let public = p256::PublicKey::from_sec1_bytes(peer_public)
                    .map_err(|_| DhError::InvalidPublicKey)?; // Validate the received point.
                let shared = secret.diffie_hellman(&public);
                Ok(shared.raw_secret_bytes().to_vec())
            }
            Secret::P384(secret) => {
                let public = p384::PublicKey::from_sec1_bytes(peer_public)
                    .map_err(|_| DhError::InvalidPublicKey)?;
                let shared = secret.diffie_hellman(&public);
                Ok(shared.raw_secret_bytes().to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Curve, DhError, KeyPair};

    #[test]
    fn both_sides_agree_on_each_curve() {
        for (curve, public_len, shared_len) in [
            (Curve::X25519, 32, 32),
            (Curve::P256, 33, 32),
            (Curve::P384, 49, 48),
        ] {
            let alice = KeyPair::generate(curve).unwrap();
            let bob = KeyPair::generate(curve).unwrap();
            let alice_public = alice.public_key();
            let bob_public = bob.public_key();
            assert_eq!(alice_public.len(), public_len);
            assert_eq!(bob_public.len(), public_len);

            let alice_shared = alice.agree(&bob_public).unwrap();
            let bob_shared = bob.agree(&alice_public).unwrap();
            assert_eq!(alice_shared.len(), shared_len);
            assert_eq!(alice_shared, bob_shared);
        }
    }

    #[test]
    fn empty_public_keys_are_rejected() {
        for curve in [Curve::X25519, Curve::P256, Curve::P384] {
            let alice = KeyPair::generate(curve).unwrap();
            assert!(matches!(alice.agree(&[]), Err(DhError::InvalidPublicKey)));
        }
    }

    #[test]
    fn x25519_rejects_a_low_order_public_key() {
        let alice = KeyPair::generate(Curve::X25519).unwrap();
        assert!(matches!(
            alice.agree(&[0u8; 32]),
            Err(DhError::InvalidPublicKey)
        ));
    }

    #[test]
    fn invalid_points_are_rejected() {
        for (curve, public_len) in [(Curve::P256, 33), (Curve::P384, 49)] {
            let alice = KeyPair::generate(curve).unwrap();
            let mut invalid_public = vec![0xff; public_len];
            invalid_public[0] = 2; // A compressed point with an out-of-range x-coordinate.
            assert!(matches!(
                alice.agree(&invalid_public),
                Err(DhError::InvalidPublicKey)
            ));
        }
    }
}
