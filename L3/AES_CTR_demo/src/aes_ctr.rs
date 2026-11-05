// Simple wrappers around the aes and ctr crates for AES-256-CTR.
// main.rs supplies the key, initial counter block, and input bytes; these functions return the output bytes.
// Read this file to see the cipher setup and library calls.

pub use aes::cipher::StreamCipherError;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};

pub type Key = [u8; 32]; // AES-256 key.
pub type CounterBlock = [u8; 16]; // Ctr64BE: 8-byte nonce || 8-byte counter.
type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

// Construct a counter block: 8-byte nonce || 8-byte big-endian counter.
pub fn make_counter_block(nonce: u64, counter: u64) -> CounterBlock {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&nonce.to_be_bytes());
    block[8..].copy_from_slice(&counter.to_be_bytes());
    block
}

// Each call starts a fresh cipher at the supplied initial counter block. CTR needs no padding.
// For streaming input, keep one cipher instance, as shown in the tests below.
// The ctr crate calls the initial counter block an IV in its KeyIvInit API.
pub fn encrypt(
    key: &Key,
    initial_counter_block: &CounterBlock,
    plaintext: &[u8],
) -> Result<Vec<u8>, StreamCipherError> {
    let mut ciphertext = plaintext.to_vec(); // The library modifies this buffer in place.
    let mut cipher = Aes256Ctr::new(key.into(), initial_counter_block.into());
    cipher.try_apply_keystream(&mut ciphertext)?; // Return stream length errors instead of panicking.
    Ok(ciphertext)
}

// Decryption applies the same XOR operation, starting again from the same key and initial counter block.
pub fn decrypt(
    key: &Key,
    initial_counter_block: &CounterBlock,
    ciphertext: &[u8],
) -> Result<Vec<u8>, StreamCipherError> {
    encrypt(key, initial_counter_block, ciphertext)
}

// One step records the counter block, full keystream block, and actual input/output bytes.
pub struct CounterStep {
    pub counter: u64,
    pub counter_block: CounterBlock,
    pub keystream: [u8; 16],
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// Reconstruct CTR one block at a time for teaching, then compare with encrypt in main.rs.
// This function returns the intermediate values; it does not inspect the ctr object's state.
pub fn encrypt_block_by_block(
    key: &Key,
    nonce: u64,
    initial_counter: u64,
    plaintext: &[u8],
) -> Result<Vec<CounterStep>, StreamCipherError> {
    let cipher = aes::Aes256::new(key.into());
    let mut counter = initial_counter;
    let mut steps = Vec::new();

    for (block_index, plaintext_block) in plaintext.chunks(16).enumerate() {
        if block_index > 0 {
            counter = counter.checked_add(1).ok_or(StreamCipherError)?; // Stop instead of wrapping the counter to zero.
        }
        let counter_block = make_counter_block(nonce, counter);
        let mut keystream = counter_block; // Keep this as a [u8; 16] array.
        cipher.encrypt_block((&mut keystream).into()); // Convert the reference only at the library call.
        let mut ciphertext = Vec::new();
        for i in 0..plaintext_block.len() {
            ciphertext.push(plaintext_block[i] ^ keystream[i]); // Use only the bytes needed by the final block.
        }

        steps.push(CounterStep {
            counter,
            counter_block,
            keystream,
            plaintext: plaintext_block.to_vec(),
            ciphertext,
        });
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt, encrypt, encrypt_block_by_block, make_counter_block, Aes256Ctr, CounterBlock, Key,
    };
    use aes::cipher::{KeyIvInit, StreamCipher};

    #[test]
    fn nist_aes256_ctr_vector() {
        // NIST SP 800-38A, section F.5.5; these blocks do not wrap the 64-bit counter.
        let key: Key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let initial_counter_block: CounterBlock = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let plaintext = hex::decode(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ))
        .unwrap();
        let ciphertext = encrypt(&key, &initial_counter_block, &plaintext).unwrap();
        assert_eq!(
            hex::encode(&ciphertext),
            concat!(
                "601ec313775789a5b7a7f504bbf3d228",
                "f443e3ca4d62b59aca84e990cacaf5c5",
                "2b0930daa23de94ce87017ba2d84988d",
                "dfc9c58db67aada613c2dd08457941a6"
            )
        );
        let decrypted = decrypt(&key, &initial_counter_block, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chunked_encryption_matches_one_call() {
        let key = [0x42; 32];
        let initial_counter_block = [0x24; 16];
        let plaintext = b"CTR also works with partial blocks and streaming input.";
        let one_call = encrypt(&key, &initial_counter_block, plaintext).unwrap();

        let mut chunked = plaintext.to_vec();
        let mut cipher = Aes256Ctr::new(&key.into(), &initial_counter_block.into());
        for chunk in chunked.chunks_mut(5) {
            cipher.try_apply_keystream(chunk).unwrap();
        }
        assert_eq!(chunked, one_call);

        let decrypted = decrypt(&key, &initial_counter_block, &chunked).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn counter_steps_match_ctr_across_a_carry_and_partial_block() {
        let key = [0x42; 32];
        let plaintext = b"0123456789abcdef0123456789abcdef01234567";
        let steps = encrypt_block_by_block(&key, 4, 254, plaintext).unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].counter, 254);
        assert_eq!(steps[1].counter, 255);
        assert_eq!(steps[2].counter, 256);
        assert_eq!(steps[2].counter_block, make_counter_block(4, 256));
        assert_eq!(steps[2].plaintext.len(), 8);
        assert_eq!(steps[2].ciphertext.len(), 8);

        let mut ciphertext_blocks = Vec::new();
        for step in &steps {
            ciphertext_blocks.extend_from_slice(&step.ciphertext);
        }
        let ciphertext_library = encrypt(&key, &make_counter_block(4, 254), plaintext).unwrap();
        assert_eq!(ciphertext_blocks, ciphertext_library);
    }

    #[test]
    fn counter_steps_stop_before_wrap() {
        let key = [0x42; 32];
        let steps = encrypt_block_by_block(&key, 4, u64::MAX, &[0u8; 16]).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].counter, u64::MAX);
        assert!(encrypt_block_by_block(&key, 4, u64::MAX, &[0u8; 17]).is_err());
    }

    #[test]
    fn empty_input_has_no_counter_steps() {
        let steps = encrypt_block_by_block(&[0u8; 32], 4, 254, b"").unwrap();
        assert!(steps.is_empty());
    }
}
