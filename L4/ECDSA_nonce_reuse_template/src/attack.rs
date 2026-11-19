// Nonce reuse attack on ECDSA.
// If two signatures on different messages use the same nonce k, they share r = x(kG) mod n:
//   s1 = k^-1 (h1 + r d)
//   s2 = k^-1 (h2 + r d)
// Subtracting removes the secret key: s1 - s2 = k^-1 (h1 - h2).
// Solve for k first, then use either signature to solve for d.
//
// All values are Scalars, so +, -, * are already modulo n. Division is multiplication by inverse(..).

use crate::ecdsa_demo::{hash_message, inverse, Scalar, Signature};

#[derive(Debug, PartialEq, Eq)]
pub enum AttackError {
    DifferentNonces, // r1 != r2: the two signatures did not reuse a nonce.
    NotInvertible,   // A value to be inverted is zero, for example the same message signed twice.
}

// Step 1: k = (h1 - h2) / (s1 - s2) mod n.
pub fn recover_nonce(
    message1: &[u8],
    signature1: &Signature,
    message2: &[u8],
    signature2: &Signature,
) -> Result<Scalar, AttackError> {
    if signature1.r != signature2.r {
        return Err(AttackError::DifferentNonces); // Same k gives the same r.
    }

    // TODO: Compute h1 and h2 with hash_message.
    // Compute (s1 - s2)^-1 with inverse; return NotInvertible if it returns None.
    // Return (h1 - h2) * (s1 - s2)^-1.
    let _ = (message1, message2, hash_message, inverse); // Remove this placeholder when implementing the function.
    todo!("Recover the reused nonce k.")
}

// Step 2: from s = k^-1 (h + r d), solve for d = (s k - h) / r mod n.
pub fn recover_secret_key(
    message: &[u8],
    signature: &Signature,
    nonce: &Scalar,
) -> Result<Scalar, AttackError> {
    // TODO: Compute h with hash_message and r^-1 with inverse (NotInvertible if r = 0).
    // Return (s * k - h) * r^-1.
    let _ = (message, signature, nonce); // Remove this placeholder when implementing the function.
    todo!("Recover the secret key d.")
}
