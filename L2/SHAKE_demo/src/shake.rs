// Simple wrappers around SHAKE128 and SHAKE256 from the sha3 crate.
// Each wrapper takes a seed and an output length, then returns the output bytes.
// Read these functions to see how to use the underlying SHAKE API.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

// SHAKE has a variable output length; out_len is measured in bytes.
pub fn shake128(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(seed); // Absorb the seed into SHAKE.
    let mut reader = hasher.finalize_xof(); // Finish the input and start reading output.
    let mut output = vec![0u8; out_len];
    reader.read(&mut output); // Read out_len bytes from the output stream.
    output
}

// The same steps, using SHAKE256.
pub fn shake256(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; out_len];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::{shake128, shake256};

    #[test]
    fn shake128_outputs_share_a_prefix() {
        for seed in [b"seed A", b"seed B"] {
            let output32 = shake128(seed, 32);
            let output64 = shake128(seed, 64);
            let output128 = shake128(seed, 128);
            assert_eq!(output32.len(), 32);
            assert_eq!(output64.len(), 64);
            assert_eq!(output128.len(), 128);
            assert_eq!(output32, output64[..32]);
            assert_eq!(output64, output128[..64]);
        }
    }

    #[test]
    fn shake256_outputs_share_a_prefix() {
        for seed in [b"seed A", b"seed B"] {
            let output32 = shake256(seed, 32);
            let output64 = shake256(seed, 64);
            let output128 = shake256(seed, 128);
            assert_eq!(output32.len(), 32);
            assert_eq!(output64.len(), 64);
            assert_eq!(output128.len(), 128);
            assert_eq!(output32, output64[..32]);
            assert_eq!(output64, output128[..64]);
        }
    }
}
