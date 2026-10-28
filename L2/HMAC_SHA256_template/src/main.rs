use hmac_sha256_template::hmac_sha256;
use sha2::{Digest, Sha256};

fn main() {
    let key = b"Jefe";
    let message = b"what do ya want for nothing?";

    let digest = Sha256::digest(message); // Start with the SHA-256 API from HashUpdate_demo.
    println!("SHA-256 (hex): {}", hex::encode(digest));

    let tag = hmac_sha256(key, message); // Calls your implementation in src/lib.rs.
    println!("HMAC-SHA256 (hex): {}", hex::encode(tag));
}
