// ECDSA over P-256 with SHA-256, written out step by step.
// The p256 crate provides the group: points (Point) and integers modulo the group order n (Scalar).
// Everything ECDSA-specific (nonce, r, s, verification) is implemented below.
//
// Notation: G is the generator, n is the group order, d is the secret key, Q = dG is the public key,
// k is the per-signature nonce, and h = H(m) is the message hash as a scalar.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::{
    ops::Reduce, point::AffineCoordinates, rand_core::CryptoRngCore, PrimeField,
};
use p256::{NonZeroScalar, U256};
use sha2::{Digest, Sha256};

pub type Scalar = p256::Scalar; // Integer modulo n. +, -, * already reduce modulo n.
pub type Point = p256::ProjectivePoint; // Point on P-256. Point * Scalar is scalar multiplication.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EcdsaError {
    InvalidNonce, // k = 0, or k gives r = 0 or s = 0: choose another nonce.
}

// ---------- Helper operations (also needed for the attack) ----------

// h = SHA-256(message), interpreted as a big-endian integer and reduced modulo n.
pub fn hash_message(message: &[u8]) -> Scalar {
    let digest = Sha256::digest(message);
    <Scalar as Reduce<U256>>::reduce_bytes(&digest)
}

// Modular inverse a^-1 mod n. Zero has no inverse, so this returns None for a = 0.
pub fn inverse(a: &Scalar) -> Option<Scalar> {
    Option::from(a.invert())
}

// The x-coordinate of a point, reduced modulo n. ECDSA uses this to compute r.
pub fn x_coordinate(point: &Point) -> Scalar {
    let x = point.to_affine().x(); // 32-byte big-endian field element.
    <Scalar as Reduce<U256>>::reduce_bytes(&x)
}

// A uniformly random nonzero scalar, used for secret keys and random nonces.
pub fn random_scalar(rng: &mut impl CryptoRngCore) -> Scalar {
    *NonZeroScalar::random(rng)
}

// 32-byte big-endian hex encoding, for printing.
pub fn to_hex(a: &Scalar) -> String {
    hex::encode(a.to_bytes())
}

// ---------- Key generation, signing, and verification ----------

// Q = dG.
pub fn public_key(secret_key: &Scalar) -> Point {
    Point::GENERATOR * secret_key
}

// Shared by both signing functions:
// R = kG, r = x(R) mod n, s = k^-1 (h + r d) mod n.
fn sign_with_nonce(
    secret_key: &Scalar,
    message: &[u8],
    nonce: &Scalar,
) -> Result<Signature, EcdsaError> {
    let k_inv = inverse(nonce).ok_or(EcdsaError::InvalidNonce)?; // Rejects k = 0.
    let r = x_coordinate(&(Point::GENERATOR * nonce));
    if r == Scalar::ZERO {
        return Err(EcdsaError::InvalidNonce);
    }
    let h = hash_message(message);
    let s = k_inv * (h + r * secret_key);
    if s == Scalar::ZERO {
        return Err(EcdsaError::InvalidNonce);
    }
    Ok(Signature { r, s })
}

// Randomized ECDSA (FIPS 186): the caller supplies the nonce k.
// k must be secret, uniformly random, and never reused. This function cannot check that.
pub fn sign_randomized(
    secret_key: &Scalar,
    message: &[u8],
    nonce: &Scalar,
) -> Result<Signature, EcdsaError> {
    sign_with_nonce(secret_key, message, nonce)
}

// Simplified RFC 6979: k = HMAC-SHA256(key = d, data = H(m) || counter).
// Same idea as RFC 6979: k depends on the secret key and the message, so it stays secret,
// and the same message always gives the same k. RFC 6979 uses HMAC-DRBG for retries instead of a counter.
pub fn deterministic_nonce(secret_key: &Scalar, message: &[u8]) -> Scalar {
    let digest = Sha256::digest(message);
    // counter counts retries inside this one call; it is not kept across signatures.
    // Every call starts at 0, so every message (different or not) first tries counter = 0.
    // Different messages get different k because H(m) differs, not because of counter.
    // Why retry at all: HMAC gives a 256-bit value, but k must be in [1, n-1] and n < 2^256.
    // If the value is out of range, recomputing with the same input would give the same value again,
    // so the input is changed by appending the next counter value. This happens with probability
    // about 2^-32, so counter is almost always 0. The retries are deterministic too:
    // the same key and message always stop at the same counter value and give the same k.
    // Example: sign(m1): counter 0 -> valid -> k1.  sign(m2): counter 0 -> valid -> k2.
    //          sign(m3): counter 0 -> out of range; counter 1 -> valid -> k3 (again k3 next time).
    let mut counter: u32 = 0;
    loop {
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret_key.to_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(&digest);
        mac.update(&counter.to_be_bytes());
        let candidate = mac.finalize().into_bytes();

        // Accept only 1 <= k < n, as in RFC 6979; otherwise retry with the next counter value (almost never needed).
        // Rejecting (instead of reducing mod n) keeps k uniform.
        let k: Option<Scalar> = Option::from(Scalar::from_repr(candidate));
        if let Some(k) = k {
            if k != Scalar::ZERO {
                return k;
            }
        }
        counter += 1;
    }
}

// Deterministic ECDSA: no randomness needed at signing time.
pub fn sign_deterministic(secret_key: &Scalar, message: &[u8]) -> Result<Signature, EcdsaError> {
    let nonce = deterministic_nonce(secret_key, message);
    sign_with_nonce(secret_key, message, &nonce)
}

// w = s^-1, u1 = h w, u2 = r w, R = u1 G + u2 Q. Valid if R is not the identity and x(R) mod n = r.
pub fn verify(public_key: &Point, message: &[u8], signature: &Signature) -> bool {
    if signature.r == Scalar::ZERO {
        return false; // r and s must be in [1, n-1].
    }
    let w = match inverse(&signature.s) {
        Some(w) => w,
        None => return false, // s = 0.
    };
    let h = hash_message(message);
    let u1 = h * w;
    let u2 = signature.r * w;
    let point = Point::GENERATOR * u1 + *public_key * u2;
    if point == Point::IDENTITY {
        return false;
    }
    x_coordinate(&point) == signature.r
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer, Verifier};
    use rand::rngs::OsRng;

    #[test]
    fn both_signing_functions_verify() {
        let d = random_scalar(&mut OsRng);
        let q = public_key(&d);
        let deterministic = sign_deterministic(&d, b"hello").unwrap();
        let randomized = sign_randomized(&d, b"hello", &random_scalar(&mut OsRng)).unwrap();
        assert!(verify(&q, b"hello", &deterministic));
        assert!(verify(&q, b"hello", &randomized));
    }

    #[test]
    fn modified_message_signature_or_key_fails() {
        let d = random_scalar(&mut OsRng);
        let q = public_key(&d);
        let signature = sign_deterministic(&d, b"Pay Bob 100 EUR").unwrap();
        assert!(!verify(&q, b"Pay Bob 900 EUR", &signature));

        let modified = Signature {
            r: signature.r,
            s: signature.s + Scalar::ONE,
        };
        assert!(!verify(&q, b"Pay Bob 100 EUR", &modified));

        let other_q = public_key(&random_scalar(&mut OsRng));
        assert!(!verify(&other_q, b"Pay Bob 100 EUR", &signature));

        let zero = Signature {
            r: Scalar::ZERO,
            s: Scalar::ZERO,
        };
        assert!(!verify(&q, b"Pay Bob 100 EUR", &zero));
    }

    #[test]
    fn deterministic_is_repeatable_and_randomized_is_not() {
        let d = random_scalar(&mut OsRng);
        assert_eq!(
            sign_deterministic(&d, b"hello").unwrap(),
            sign_deterministic(&d, b"hello").unwrap()
        );
        assert_ne!(
            deterministic_nonce(&d, b"hello"),
            deterministic_nonce(&d, b"hello!")
        );
        let s1 = sign_randomized(&d, b"hello", &random_scalar(&mut OsRng)).unwrap();
        let s2 = sign_randomized(&d, b"hello", &random_scalar(&mut OsRng)).unwrap();
        assert_ne!(s1.r, s2.r);
    }

    #[test]
    fn zero_nonce_is_rejected() {
        let d = random_scalar(&mut OsRng);
        assert_eq!(
            sign_randomized(&d, b"hello", &Scalar::ZERO),
            Err(EcdsaError::InvalidNonce)
        );
    }

    #[test]
    fn scalar_helpers() {
        let a = Scalar::from(7u64);
        let b = Scalar::from(3u64);
        assert_eq!(b * inverse(&b).unwrap(), Scalar::ONE);
        assert_eq!(inverse(&Scalar::ZERO), None);
        assert_eq!(b - a + a, b); // Subtraction wraps modulo n.
        assert_eq!(public_key(&Scalar::ONE), Point::GENERATOR);
    }

    // Our signatures verify with the p256 library, and the library's signatures verify with ours.
    #[test]
    fn matches_the_p256_library() {
        let d = random_scalar(&mut OsRng);
        let q = public_key(&d);
        let signing_key = p256::ecdsa::SigningKey::from_bytes(&d.to_bytes()).unwrap();
        let verifying_key = p256::ecdsa::VerifyingKey::from_affine(q.to_affine()).unwrap();

        let ours = sign_deterministic(&d, b"interop").unwrap();
        let ours =
            p256::ecdsa::Signature::from_scalars(ours.r.to_bytes(), ours.s.to_bytes()).unwrap();
        assert!(verifying_key.verify(b"interop", &ours).is_ok());

        let library: p256::ecdsa::Signature = signing_key.sign(b"interop");
        let (r, s) = library.split_scalars();
        let library = Signature { r: *r, s: *s };
        assert!(verify(&q, b"interop", &library));
    }
}
