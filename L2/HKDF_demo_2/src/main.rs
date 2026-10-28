use hkdf::Hkdf;
use sha2::Digest; // SHA-2 and SHA-3 share this trait.

// Change the hash type and its display name together.
// Examples: sha2::Sha256, sha2::Sha512, sha3::Sha3_256, sha3::Sha3_512.
type Hash = sha2::Sha256;
const HASH_NAME: &str = "SHA-256";
type HkdfHash = Hkdf<Hash>;

fn main() -> Result<(), hkdf::InvalidLength> {
    let ikm = b"example input key material"; // Input keying material (fixed for this demo).
    let salt = b"example salt";
    let info = b"L2 HKDF demo"; // Context for the derived key.
    println!("HKDF ({HASH_NAME})");

    // (1) Explicit Extract, followed by Expand.
    let (prk, hk) = HkdfHash::extract(Some(salt), ikm); // Returns the PRK and an object ready for Expand. hk is the stateful object that includes the information of prk, salt, and the hash function. It can be used to derive multiple keys with different info values.
    let mut okm_extract_then_expand = [0u8; 32]; // Output keying material (the derived key).
    hk.expand(info, &mut okm_extract_then_expand)?; // Return an error if the output length is invalid. In the Rust implementation of HKDF, you do not need to include the prk in the expand function because the hk object already contains the prk. The expand function uses the prk stored in the hk object to derive the output keying material (okm) based on the provided info and output length.
    println!("\nExtract then Expand:");
    println!("PRK (hex): {}", hex::encode(&prk));
    println!("Key (hex): {}", hex::encode(okm_extract_then_expand));

    // (2) The convenience API performs Extract inside new; expand produces the key.
    let hk = HkdfHash::new(Some(salt), ikm);
    let mut okm_new_then_expand = [0u8; 32];
    hk.expand(info, &mut okm_new_then_expand)?;
    println!("\nnew then expand:");
    println!("Key (hex): {}", hex::encode(okm_new_then_expand));
    println!(
        "Same key: {}",
        okm_extract_then_expand == okm_new_then_expand
    ); // Same IKM, salt, info, and output length.

    // (3) No salt is equivalent to HashLen zero bytes in Extract (RFC 5869).
    let zero_salt = vec![0u8; Hash::output_size()]; // HashLen is 32 bytes for SHA-256.
    let hk = HkdfHash::new(None, ikm); // Extract still runs with the default zero salt.
    let mut okm_no_salt = [0u8; 32];
    hk.expand(info, &mut okm_no_salt)?;

    let (_, hk) = HkdfHash::extract(Some(&zero_salt), ikm);
    let mut okm_zero_salt = [0u8; 32];
    hk.expand(info, &mut okm_zero_salt)?;
    println!("\nNo salt versus {} zero bytes:", zero_salt.len());
    println!("No salt key (hex): {}", hex::encode(okm_no_salt));
    println!("Zero salt key (hex): {}", hex::encode(okm_zero_salt));
    println!("Same key: {}", okm_no_salt == okm_zero_salt);

    Ok(())
}
