use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() -> Result<(), hkdf::InvalidLength> {
    let mut rng = match StdRng::from_rng(OsRng) {
        Ok(rng) => rng,
        Err(error) => {
            eprintln!("Random key generation failed: {error}");
            std::process::exit(1);
        }
    };

    // (1) Alice chooses x and computes her public key.
    let alice_secret = EphemeralSecret::random_from_rng(&mut rng);
    let alice_public = PublicKey::from(&alice_secret);

    // (2) Bob chooses y and computes his public key.
    let bob_secret = EphemeralSecret::random_from_rng(&mut rng);
    let bob_public = PublicKey::from(&bob_secret);

    // (3) Exchange public keys; each side computes the same shared secret.
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    println!("X25519 DH handshake");
    // g^x, g^y, g^xy are DH notation; EC uses xG, yG, xyG.
    // X25519 returns the u-coordinate, not an encoding of the complete point.
    println!(
        "Alice public g^x (Base64): {}",
        STANDARD.encode(alice_public.as_bytes())
    );
    println!(
        "Bob public g^y (Base64): {}",
        STANDARD.encode(bob_public.as_bytes())
    );
    println!(
        "Alice shared g^xy (Base64): {}",
        STANDARD.encode(alice_shared.as_bytes())
    );
    println!(
        "Bob shared g^xy (Base64): {}",
        STANDARD.encode(bob_shared.as_bytes())
    );
    println!(
        "Same shared secret: {}",
        alice_shared.as_bytes() == bob_shared.as_bytes()
    );

    // (4) Derive an AES-256 key from the shared secret using HKDF-SHA256.
    let info = b"L4 X25519 AES-256 key"; // Both sides use the same context.
    let hk_alice = Hkdf::<Sha256>::new(None, alice_shared.as_bytes()); // None uses the default zero salt.
    let mut alice_key = [0u8; 32]; // 32 bytes = 256 bits; usable as an AES-256 key.
    hk_alice.expand(info, &mut alice_key)?; // Return an error if the output length is invalid.

    let hk_bob = Hkdf::<Sha256>::new(None, bob_shared.as_bytes());
    let mut bob_key = [0u8; 32];
    hk_bob.expand(info, &mut bob_key)?;

    println!("\nHKDF-SHA256:");
    println!("Alice AES-256 key (Base64): {}", STANDARD.encode(alice_key));
    println!("Bob AES-256 key (Base64): {}", STANDARD.encode(bob_key));
    println!("Same key: {}", alice_key == bob_key);
    // This demo prints secret values for teaching; the exchange still has no authentication.
    Ok(())
}
