use hkdf::Hkdf;

// Change the hash type and its display name together.
// Examples: sha3::Sha3_256, sha3::Sha3_512, sha2::Sha256, sha2::Sha512.
type Hash = sha3::Sha3_256;
pub const HASH_NAME: &str = "SHA3-256";
type HkdfHash = Hkdf<Hash>; // HKDF using the selected hash

/// Derive `out_len` bytes using HKDF with the selected hash.
/// - `seed`  → IKM (input keying material)
/// - `salt`  → optional salt (None uses RFC 5869 "zeros" salt)
/// - `info`  → context string / auxiliary data
pub fn derive_key(seed: &[u8], salt: Option<&[u8]>, info: &[u8], out_len: usize)
    -> Result<Vec<u8>, hkdf::InvalidLength>
{
    if out_len > 255 * <Hash as sha3::Digest>::output_size() {
        return Err(hkdf::InvalidLength); // Reject before allocation to avoid a panic.
    }
    let hk = HkdfHash::new(salt, seed);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)?;
    Ok(okm)
}


/// Derive a 32-byte key for AES-256-GCM.
pub fn derive_aes256gcm_key(
    seed: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; 32], hkdf::InvalidLength> {
    let hk = HkdfHash::new(salt, seed);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_inputs() {
        let seed = b"supersecret";
        let info = b"session-1";
        let k1 = derive_aes256gcm_key(seed, None, info).unwrap();
        let k2 = derive_aes256gcm_key(seed, None, info).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_info_gives_different_keys() {
        let seed = b"supersecret";
        let k1 = derive_aes256gcm_key(seed, None, b"A").unwrap();
        let k2 = derive_aes256gcm_key(seed, None, b"B").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn rejects_output_above_hkdf_limit() {
        use sha3::Digest;
        let too_long = 255 * <Hash as Digest>::output_size() + 1;
        assert!(derive_key(b"seed", None, b"context", too_long).is_err());
        assert!(derive_key(b"seed", None, b"context", usize::MAX).is_err());
    }

    #[test]
    fn length_generic() {
        let seed = b"x";
        let okm = derive_key(seed, None, b"", 48).unwrap();
        assert_eq!(okm.len(), 48);
    }
}
