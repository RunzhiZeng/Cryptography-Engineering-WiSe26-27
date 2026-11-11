mod dh;

use base64::{engine::general_purpose::STANDARD, Engine};
use dh::{Curve, DhError, KeyPair};
use std::io::{self, Write};

fn show_handshake(curve: Curve) -> Result<(), DhError> {
    let alice = KeyPair::generate(curve)?;
    let bob = KeyPair::generate(curve)?;
    let alice_public = alice.public_key();
    let bob_public = bob.public_key();

    // Exchange public keys; each side uses its own secret and the other's public key.
    let alice_shared = alice.agree(&bob_public)?;
    let bob_shared = bob.agree(&alice_public)?;

    println!(
        "Alice public g^x (Base64): {}",
        STANDARD.encode(&alice_public)
    );
    println!("Bob public g^y (Base64): {}", STANDARD.encode(&bob_public));
    println!(
        "Alice shared g^xy (Base64): {}",
        STANDARD.encode(&alice_shared)
    );
    println!("Bob shared g^xy (Base64): {}", STANDARD.encode(&bob_shared));
    println!("Same shared secret: {}", alice_shared == bob_shared);
    Ok(())
}

fn main() -> io::Result<()> {
    println!("DH handshake demo");
    println!("DH notation g^x, g^y, g^xy corresponds to EC points xG, yG, xyG.");
    println!("The outputs below are the library's public-key and shared-secret encodings.");
    // This exchange has no authentication. In a protocol, feed the shared secret into HKDF.

    loop {
        println!("\n1: X25519\n2: P-256\n3: P-384");
        print!("Choose a curve (or exit): ");
        io::stdout().flush()?; // Return output errors instead of panicking.

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            break; // EOF ends the demo; read errors are returned by ?.
        }
        let (curve, name) = match input.trim() {
            "1" => (Curve::X25519, "X25519"),
            "2" => (Curve::P256, "P-256"),
            "3" => (Curve::P384, "P-384"),
            "exit" => break,
            _ => {
                eprintln!("Invalid choice. Enter 1, 2, 3, or exit.");
                continue;
            }
        };

        println!("\n{name}:");
        match show_handshake(curve) {
            Ok(()) => {}
            Err(error) => eprintln!("Handshake failed: {error}"),
        }
    }
    Ok(())
}
