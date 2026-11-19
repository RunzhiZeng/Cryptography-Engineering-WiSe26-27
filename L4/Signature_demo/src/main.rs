mod sign;

use base64::{engine::general_purpose::STANDARD, Engine};
use sign::{verify, KeyPair, Scheme, SignError};
use std::io::{self, Write};

fn show_signature(scheme: Scheme) -> Result<(), SignError> {
    let message = b"Pay Bob 100 EUR";

    // (1) Alice generates a key pair and publishes her public key.
    let alice = KeyPair::generate(scheme)?;
    let alice_public = alice.public_key();

    // (2) Alice signs the message with her secret key.
    let signature = alice.sign(message)?;

    println!("Message: {}", String::from_utf8_lossy(message));
    println!(
        "Alice public key (Base64, {} bytes): {}",
        alice_public.len(),
        STANDARD.encode(&alice_public)
    );
    println!(
        "Signature (Base64, {} bytes): {}",
        signature.len(),
        STANDARD.encode(&signature)
    );

    // (3) Anyone with Alice's public key can verify; no secret is needed.
    let valid = verify(scheme, &alice_public, message, &signature)?;
    println!("Verify with Alice's public key: {valid}");

    // (4) Modify the message; keep the signature unchanged.
    let modified_message = b"Pay Bob 900 EUR";
    let valid = verify(scheme, &alice_public, modified_message, &signature)?;
    println!(
        "Modify message to '{}' → verify: {valid}",
        String::from_utf8_lossy(modified_message)
    );

    // (5) Flip one bit of the signature; keep the message unchanged.
    let mut modified_signature = signature.clone();
    modified_signature[0] ^= 0x01;
    let valid = verify(scheme, &alice_public, message, &modified_signature)?;
    println!("Modify signature → verify: {valid}");

    // (6) Mallory signs the modified message with her own key, then claims it is from Alice.
    let mallory = KeyPair::generate(scheme)?;
    let mallory_signature = mallory.sign(modified_message)?;
    let valid = verify(scheme, &alice_public, modified_message, &mallory_signature)?;
    println!("Mallory's signature, verified with Alice's public key → verify: {valid}");

    // (7) Sign the same message twice.
    // Ed25519 is always deterministic: the nonce is derived from the secret key and message (RFC 8032).
    // ECDSA can be either: sign derives the nonce from the key and message (RFC 6979),
    // while sign_randomized mixes fresh random bytes into every nonce.
    println!("\nSign the same message twice:");
    match scheme {
        Scheme::Ed25519 => println!("Ed25519 signing is always deterministic (RFC 8032)."),
        Scheme::EcdsaP256 | Scheme::EcdsaP384 => {
            println!("ECDSA signing can be deterministic (RFC 6979) or randomized.")
        }
    }
    let signature_again = alice.sign(message)?;
    print_signature_pair("Deterministic", &signature, &signature_again);

    if let Scheme::EcdsaP256 | Scheme::EcdsaP384 = scheme {
        // Use sign_randomized to produce a different signature for the same message.
        // Using sign again would produce the same signature as before, because it is deterministic function.
        let randomized1 = alice.sign_randomized(message)?;
        let randomized2 = alice.sign_randomized(message)?;
        print_signature_pair("Randomized", &randomized1, &randomized2);
        let valid1 = verify(scheme, &alice_public, message, &randomized1)?;
        let valid2 = verify(scheme, &alice_public, message, &randomized2)?;
        println!(
            "Randomized: both verify with Alice's public key: {}",
            valid1 && valid2
        );
    }
    Ok(())
}

// Print two signatures of the same message and whether they are equal.
fn print_signature_pair(label: &str, signature1: &[u8], signature2: &[u8]) {
    println!(
        "{label} signature 1 (Base64): {}",
        STANDARD.encode(signature1)
    );
    println!(
        "{label} signature 2 (Base64): {}",
        STANDARD.encode(signature2)
    );
    println!("{label}: same signature: {}", signature1 == signature2);
}

fn main() -> io::Result<()> {
    println!("Digital signature demo");
    println!("The secret key signs; the public key verifies.");
    // Unlike HMAC, the verifier cannot create a valid signature, because it holds only the public key.

    loop {
        println!("\n1: Ed25519\n2: ECDSA P-256\n3: ECDSA P-384");
        print!("Choose a scheme (or exit): ");
        io::stdout().flush()?; // Return output errors instead of panicking.

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            break; // EOF ends the demo; read errors are returned by ?.
        }
        let (scheme, name) = match input.trim() {
            "1" => (Scheme::Ed25519, "Ed25519"),
            "2" => (Scheme::EcdsaP256, "ECDSA P-256"),
            "3" => (Scheme::EcdsaP384, "ECDSA P-384"),
            "exit" => break,
            _ => {
                eprintln!("Invalid choice. Enter 1, 2, 3, or exit.");
                continue;
            }
        };

        println!("\n{name}:");
        match show_signature(scheme) {
            Ok(()) => {}
            Err(error) => eprintln!("Signature demo failed: {error}"),
        }
    }
    Ok(())
}
