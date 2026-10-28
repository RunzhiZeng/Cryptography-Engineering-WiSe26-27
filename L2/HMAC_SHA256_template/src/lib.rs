pub const BLOCK_LEN: usize = 64; // SHA-256 block length in bytes.
pub const HASH_LEN: usize = 32; // SHA-256 output length in bytes.

// Implement HMAC here; HKDF will call this public function through a path dependency.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
    // TODO: Use sha2::{Digest, Sha256} for hashing.
    // (1) Hash keys longer than BLOCK_LEN, then zero-pad the key to BLOCK_LEN.
    // (2) XOR the padded key with ipad (0x36) and opad (0x5c).
    // (3) Return SHA256(opad_key || SHA256(ipad_key || message)).
    let _ = (key, message); // Remove this placeholder when implementing the function.
    todo!("Implement HMAC-SHA256 using SHA-256.")
}
