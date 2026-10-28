use hkdf_sha256_template::{hkdf_expand, hkdf_extract, hkdf_sha256, HkdfError};

fn main() -> Result<(), HkdfError> {
    let ikm = b"example input key material";
    let salt = b"example salt";
    let info = b"L2 HKDF exercise";
    let out_len = 42; // More than one SHA-256 output block.

    let prk = hkdf_extract(Some(salt), ikm);
    let okm_extract_then_expand = hkdf_expand(&prk, info, out_len)?;
    let okm_hkdf = hkdf_sha256(Some(salt), ikm, info, out_len)?;

    println!("PRK (hex): {}", hex::encode(prk));
    println!(
        "Extract then Expand (hex): {}",
        hex::encode(&okm_extract_then_expand)
    );
    println!("Full HKDF (hex): {}", hex::encode(&okm_hkdf));
    println!("Same OKM: {}", okm_extract_then_expand == okm_hkdf);
    Ok(())
}
