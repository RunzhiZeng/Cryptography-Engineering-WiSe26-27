use sha3::Digest; // This trait is shared by SHA-2 and SHA-3.
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::io::{self, Read, Write};

// Change the hash type and its display name together.
// Examples: sha3::Sha3_256, sha3::Sha3_512, sha2::Sha256, sha2::Sha512.
type Hash = sha2::Sha256;
const HASH_NAME: &str = "SHA2-256";

fn main() -> io::Result<()> {
    println!("{HASH_NAME} File Hasher");
    println!("Type a filename to hash (or 'exit' to quit):");

    loop {
        print!("> ");
        // flush stdout so prompt appears immediately
        io::stdout().flush()?; // Propagate flush errors instead of panicking.

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break,
            Ok(_) => {},
            Err(error) => return Err(error), // Stop retrying an unreadable input stream.
        }

        let filename = input.trim(); // Remove the \n
        if filename.eq_ignore_ascii_case("exit") {
            println!("Exit.");
            break;
        }

        match File::open(filename) {
            Ok(mut file) => {
                let mut buffer = Vec::new();
                if let Err(e) = file.read_to_end(&mut buffer) {
                    eprintln!("Failed to read '{}': {}", filename, e);
                    continue;
                }

                // Compute the selected hash
                let mut hasher = Hash::new();
                hasher.update(&buffer);
                let result = hasher.finalize();
                println!("{HASH_NAME} hex code: {:x}", result);
                println!("{HASH_NAME} Base64 code: {}", general_purpose::STANDARD.encode(result));
                println!("{HASH_NAME}({}) = {:?}", filename, result); // Print the bytes, not the base64 code
            }
            Err(e) => {
                eprintln!("Cannot open '{}': {}", filename, e);
            }
        }
    }

    Ok(())
}
