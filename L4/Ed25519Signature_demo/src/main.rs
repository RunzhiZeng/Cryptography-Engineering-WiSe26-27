use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};

fn main() {
    let mut rng = match StdRng::from_rng(OsRng) {
        Ok(rng) => rng,
        Err(error) => {
            eprintln!("Random key generation failed: {error}");
            std::process::exit(1);
        }
    };

    // (1) Alice generates a key pair: a secret signing key and a public verifying key.
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key(); // Alice publishes this key.

    // (2) Alice signs the message with her secret key.
    let message = b"Pay Bob 100 EUR";
    let signature: Signature = signing_key.sign(message);

    println!("Ed25519 signature");
    println!("Message: {}", String::from_utf8_lossy(message));
    println!(
        "Alice public key (Base64, 32 bytes): {}",
        STANDARD.encode(verifying_key.as_bytes())
    );
    println!(
        "Signature (Base64, 64 bytes): {}",
        STANDARD.encode(signature.to_bytes())
    );

    // (3) Bob verifies with Alice's public key; he needs no secret.
    let valid = verifying_key.verify(message, &signature).is_ok();
    println!("Verify with Alice's public key: {valid}");

    // (4) Modify the message; keep the signature unchanged.
    let modified_message = b"Pay Bob 900 EUR";
    let valid = verifying_key.verify(modified_message, &signature).is_ok();
    println!(
        "Modify message to '{}' → verify: {valid}",
        String::from_utf8_lossy(modified_message)
    );
    // Unlike HMAC, only Alice can sign, but anyone with her public key can verify.
}
