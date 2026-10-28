use sha3::Digest; // SHA-2 and SHA-3 share this Digest trait.

// Change the hash type and its display name together.
// For SHA-256, use sha2::Sha256 and "SHA-256"; the API below stays the same.
type Hash = sha3::Sha3_512;
const HASH_NAME: &str = "SHA3-512";

fn main() {
    let parts = ["Hello", ", ", "this is ", "a hash ", "demo."];
    println!("Hash: {HASH_NAME}");
    println!("Input parts: {parts:?}");

    // Each update appends bytes to the same hash computation.
    let mut hasher = Hash::new();
    hasher.update(parts[0].as_bytes());
    hasher.update(parts[1].as_bytes());
    hasher.update(parts[2].as_bytes());
    hasher.update(parts[3].as_bytes());
    hasher.update(parts[4].as_bytes());
    let incremental_digest = hasher.finalize(); // Finish the computation and consume the hasher.

    // Concatenate the same bytes in the same order, without adding separators.
    let input = parts.concat();
    println!("Combined input: {input}");
    let mut hasher = Hash::new();
    hasher.update(input.as_bytes());
    let single_digest = hasher.finalize();

    println!("Five updates (hex): {}", hex::encode(&incremental_digest));
    println!("One update   (hex): {}", hex::encode(&single_digest));
    println!("Same digest: {}", incremental_digest == single_digest);
}
