mod aes_ctr;

use aes_ctr::{
    decrypt, encrypt, encrypt_block_by_block, make_counter_block, CounterBlock, Key,
    StreamCipherError,
};
use rand::{rngs::OsRng, RngCore};

// Show the nonce and counter halves of a complete counter block.
fn print_counter_block(label: &str, block: &CounterBlock) {
    println!(
        "{label} (nonce || counter, hex): {} || {}",
        hex::encode(&block[..8]),
        hex::encode(&block[8..])
    );
}

fn main() -> Result<(), StreamCipherError> {
    let mut key: Key = [0u8; 32];
    match OsRng.try_fill_bytes(&mut key) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("Random key generation failed: {error}");
            std::process::exit(1);
        }
    }

    // (1) Basic encryption and decryption with two starting block constructions.
    let mut random_initial_block: CounterBlock = [0u8; 16];
    match OsRng.try_fill_bytes(&mut random_initial_block) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("Random initial counter block generation failed: {error}");
            std::process::exit(1);
        }
    }

    let message_initial_block = make_counter_block(1, 0); // Message number 1; counter starts at 0.

    let plaintext = b"I want to encrypt this LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG LONG meesage using AES-256 in CTR mode!";
    println!("AES-256-CTR demo");
    println!("Key (hex): {}", hex::encode(key)); // Print the key only for this teaching demo.
    println!("Initial counter block = nonce (8 bytes) || initial counter (8 bytes, big-endian).");
    println!("Within a message, the nonce stays fixed and the counter advances per 16-byte block.");
    println!("\n(1) Basic encryption and decryption:");
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    for (name, initial_counter_block) in [
        ("Random starting block", random_initial_block),
        ("Message 1 nonce, counter 0", message_initial_block),
    ] {
        println!("\n{name}:");
        print_counter_block("Initial counter block", &initial_counter_block);

        // Call the wrapper with the key, starting block, and plaintext.
        let ciphertext = encrypt(&key, &initial_counter_block, plaintext)?;
        println!("Ciphertext (hex): {}", hex::encode(&ciphertext));

        // Use the same key and starting block to recover the plaintext.
        let decrypted = decrypt(&key, &initial_counter_block, &ciphertext)?;
        println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
        println!("Matches plaintext: {}", decrypted == plaintext);
    }

    // (2) Show how the counter advances once per plaintext block.
    let nonce = 4;
    let initial_counter = 1;
    let plaintext = b"0123456789abcdef0123456789abcdef01234567"; // 40 bytes: 16 + 16 + 8.
    let initial_counter_block = make_counter_block(nonce, initial_counter);
    let steps = encrypt_block_by_block(&key, nonce, initial_counter, plaintext)?;
    let mut ciphertext_blocks = Vec::new();
    println!("\n(2) Counter increment, block by block:");
    println!("Nonce: {nonce}; initial counter: {initial_counter}");
    print_counter_block("Initial counter block", &initial_counter_block);
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    for (block_index, step) in steps.iter().enumerate() {
        println!(
            "\nBlock {} ({} bytes):",
            block_index + 1,
            step.plaintext.len()
        );
        println!("Counter (decimal): {}", step.counter);
        print_counter_block("Counter block", &step.counter_block);
        println!("AES keystream (hex): {}", hex::encode(step.keystream));
        println!("Plaintext (hex): {}", hex::encode(&step.plaintext));
        println!("Ciphertext (hex): {}", hex::encode(&step.ciphertext));
        ciphertext_blocks.extend_from_slice(&step.ciphertext);
    }
    let ciphertext_library = encrypt(&key, &initial_counter_block, plaintext)?;
    println!(
        "\nBlock-by-block ciphertext (hex): {}",
        hex::encode(&ciphertext_blocks)
    );
    println!(
        "CTR library ciphertext (hex):   {}",
        hex::encode(&ciphertext_library)
    );
    println!(
        "Same ciphertext: {}",
        ciphertext_blocks == ciphertext_library
    );

    // (3) Reuse an all-zero starting block under the same key: the keystream repeats.
    let zero_initial_block: CounterBlock = [0u8; 16];
    let plaintext1 = b"Attack Alice";
    let plaintext2 = b"Attack Bobby";
    let ciphertext1 = encrypt(&key, &zero_initial_block, plaintext1)?;
    let ciphertext2 = encrypt(&key, &zero_initial_block, plaintext2)?;

    let common_len = plaintext1.len().min(plaintext2.len()); // Compare the common prefix if lengths differ.
    let mut ciphertext_xor = Vec::new();
    let mut plaintext_xor = Vec::new();
    for i in 0..common_len {
        ciphertext_xor.push(ciphertext1[i] ^ ciphertext2[i]);
        plaintext_xor.push(plaintext1[i] ^ plaintext2[i]);
    }
    println!("\n(3) Reusing the same key and starting block: Reveal the XOR bias of the two message blocks");
    print_counter_block("Reused starting block", &zero_initial_block);
    println!("Plaintext 1: {}", String::from_utf8_lossy(plaintext1));
    println!("Plaintext 2: {}", String::from_utf8_lossy(plaintext2));
    println!("Ciphertext 1 (hex): {}", hex::encode(&ciphertext1));
    println!("Ciphertext 2 (hex): {}", hex::encode(&ciphertext2));
    println!("C1 XOR C2 (hex): {}", hex::encode(&ciphertext_xor));
    println!("P1 XOR P2 (hex): {}", hex::encode(&plaintext_xor));
    println!(
        "C1 XOR C2 == P1 XOR P2: {}",
        ciphertext_xor == plaintext_xor
    );

    // (4) Different starting blocks can still use overlapping counter blocks.
    let initial_block_a = make_counter_block(3, 0); // Nonce 3; initial counter 0.
    let initial_block_b = make_counter_block(3, 1); // Nonce 3; initial counter 1.
    let keystream_message_a = encrypt(&key, &initial_block_a, &[0u8; 32])?; // Two zero blocks reveal two keystream blocks.
    let keystream_message_b = encrypt(&key, &initial_block_b, &[0u8; 16])?; // One zero block reveals one keystream block.

    println!("\n(4) Different starting blocks, overlapping counter blocks:");
    println!("Message A: 32 zero bytes (2 blocks).");
    print_counter_block("Message A starting block", &initial_block_a);
    println!("Message B: 16 zero bytes (1 block).");
    print_counter_block("Message B starting block", &initial_block_b);
    println!("Message A counter blocks (nonce || counter): [3 || 0] -> [3 || 1]");
    println!("Message B counter blocks (nonce || counter): [3 || 1]");
    println!("The starting blocks differ, but both messages use counter block [3 || 1].");
    println!("Message A, block 2 and message B, block 1 therefore reuse the same keystream block.");
    print_counter_block("Repeated counter block", &initial_block_b);
    println!(
        "Message A, block 2 keystream (hex): {}",
        hex::encode(&keystream_message_a[16..])
    );
    println!(
        "Message B, block 1 keystream (hex): {}",
        hex::encode(&keystream_message_b)
    );
    println!(
        "Same keystream block: {}",
        keystream_message_a[16..] == keystream_message_b
    );
    println!("Different starting blocks do not guarantee non-overlapping counter blocks.");
    println!("When encrypting under the same key, no counter block may repeat within or across messages.");
    Ok(())
}
