use hmac_sha256_template::{hmac_sha256, HASH_LEN}; // Reuse the HMAC implementation from the other package.

pub const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN; // HKDF-SHA256 allows at most 8160 output bytes.

#[derive(Debug, PartialEq, Eq)]
pub enum HkdfError {
    OutputTooLong,
}

// Extract is one call to your HMAC function: PRK = HMAC(salt, IKM).
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; HASH_LEN] {
    let zero_salt = [0u8; HASH_LEN];
    let salt = match salt {
        Some(salt) => salt,
        None => &zero_salt, // No salt means HashLen zero bytes.
    };
    hmac_sha256(salt, ikm)
}

// The PRK comes from hkdf_extract and is exactly 32 bytes in this exercise.
pub fn hkdf_expand(
    prk: &[u8; HASH_LEN],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, HkdfError> {
    if out_len > MAX_OUTPUT_LEN {
        return Err(HkdfError::OutputTooLong); // Check the length before allocating output.
    }
    if out_len == 0 {
        return Ok(Vec::new());
    }

    // TODO: Use the imported hmac_sha256 for every output block.
    // T(0) is empty; T(i) = HMAC(PRK, T(i-1) || info || counter).
    // The counter is one byte, starting at 1 (not the text "1").
    // Concatenate T(1), T(2), ... and return the first out_len bytes.
    let _ = (prk, info); // Remove this placeholder when implementing the function.
    todo!("Implement HKDF-Expand using your HMAC-SHA256 interface.")
}

// Full HKDF reuses the Extract and Expand interfaces above.
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, HkdfError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, out_len)
}
