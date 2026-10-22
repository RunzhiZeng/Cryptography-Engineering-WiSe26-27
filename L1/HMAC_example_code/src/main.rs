mod crypto;
mod io;
mod utils;
use crate::crypto::hmac::{compute_hmac, verify_hmac, HASH_NAME};
use crate::io::readline::read_line;
use crate::utils::encode::decode_b64_flex;
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;

fn main() {
    let mut key = [0u8; 32];
    if let Err(error) = OsRng.try_fill_bytes(&mut key) {
        eprintln!("Random key generation failed: {error}");
        return;
    }

    println!("HMAC-{HASH_NAME} demo — Base64 key: {}", general_purpose::STANDARD.encode(&key));

    loop {
        let msg = match read_line("\nMessage> ") {
            Ok(Some(s)) => s,
            Ok(None) => break,
            Err(error) => { eprintln!("Input error: {error}"); break; }
        };
        if msg.eq_ignore_ascii_case("exit") { break; }

        let tag = match compute_hmac(&key, msg.as_bytes()) {
            Ok(tag) => tag,
            Err(error) => { eprintln!("HMAC computation failed: {error}"); return; }
        };
        println!("HMAC-{HASH_NAME} (Base64): {}", general_purpose::STANDARD.encode(&tag));

        let input = match read_line("Verify MAC (Base64)> ") {
            Ok(Some(s)) => s,
            Ok(None) => break,
            Err(error) => { eprintln!("Input error: {error}"); break; }
        };
        if input.eq_ignore_ascii_case("exit") { break; }

        let provided = match decode_b64_flex(&input) {
            Ok(b) => b,
            Err(error) => { eprintln!("Invalid Base64: {error}"); continue; }
        };

        let ok = match verify_hmac(&key, msg.as_bytes(), &provided) {
            Ok(ok) => ok,
            Err(error) => { eprintln!("HMAC verification failed: {error}"); return; }
        };
        println!("{}", if ok { "Valid tag" } else { "Invalid MAC tag" });
    }
}
