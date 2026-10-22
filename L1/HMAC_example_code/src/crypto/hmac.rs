use hmac::{digest::InvalidLength, Hmac, Mac};

// Change the hash type and its display name together.
// Examples: sha3::Sha3_256, sha3::Sha3_512, sha2::Sha256, sha2::Sha512.
type Hash = sha2::Sha256;
pub const HASH_NAME: &str = "SHA2-256";
type HmacHash = Hmac<Hash>; // HMAC using the selected hash

/// Computes HMAC using the selected hash; initialization errors are returned.
pub fn compute_hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>, InvalidLength> {
    let mut mac = HmacHash::new_from_slice(key)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Returns Ok(true) for a valid tag, Ok(false) for an invalid tag,
/// or Err if HMAC initialization fails. Tag comparison is constant-time.
pub fn verify_hmac(key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, InvalidLength> {
    let mut mac = HmacHash::new_from_slice(key)?;
    mac.update(message);
    Ok(mac.verify_slice(tag).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_basic_correctness() {
        let key = b"secretkey";
        let msg = b"hello";
        let tag = compute_hmac(key, msg).unwrap();
        assert!(verify_hmac(key, msg, &tag).unwrap());
    }

    #[test]
    fn hmac_rejects_wrong_tag() {
        let key = b"secretkey";
        let msg = b"hello";
        let mut tag = compute_hmac(key, msg).unwrap();
        tag[0] ^= 0x01; // flip a bit
        assert!(!verify_hmac(key, msg, &tag).unwrap());
    }

    #[test]
    fn hmac_rejects_wrong_length() {
        let key = b"secretkey";
        let msg = b"hello";
        let tag = compute_hmac(key, msg).unwrap();
        assert!(!verify_hmac(key, msg, &tag[..tag.len() - 1]).unwrap());
        let mut extended = tag;
        extended.push(0);
        assert!(!verify_hmac(key, msg, &extended).unwrap());
    }

    #[test]
    fn hmac_different_message_fails() {
        let key = b"secretkey";
        let msg1 = b"hello";
        let msg2 = b"world";
        let tag = compute_hmac(key, msg1).unwrap();
        assert!(!verify_hmac(key, msg2, &tag).unwrap());
    }
}
