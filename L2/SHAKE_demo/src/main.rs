mod shake;

use shake::{shake128, shake256};

fn main() {
    let seeds = ["seed A", "seed B"]; // Change the seeds here.
    let output_lengths = [32, 64, 128]; // Output lengths are in bytes, not bits.

    // Generate output for each seed and each requested length.
    for seed in seeds {
        println!("\nSeed: {seed}");
        for out_len in output_lengths {
            let output = shake128(seed.as_bytes(), out_len);
            println!("SHAKE128, {out_len} bytes (hex): {}", hex::encode(&output));

            let output = shake256(seed.as_bytes(), out_len);
            println!("SHAKE256, {out_len} bytes (hex): {}", hex::encode(&output));
        }
    }

    // Compare lengths within each algorithm, using the same seed each time.
    let seed = seeds[0];
    println!("\nPrefix comparison (seed: {seed}):");

    let output32 = shake128(seed.as_bytes(), 32);
    let output64 = shake128(seed.as_bytes(), 64);
    let output128 = shake128(seed.as_bytes(), 128);
    println!(
        "SHAKE128: 32-byte output matches the first 32 bytes of the 64-byte output: {}",
        output64.starts_with(&output32)
    );
    println!(
        "SHAKE128: 64-byte output matches the first 64 bytes of the 128-byte output: {}",
        output128.starts_with(&output64)
    );

    let output32 = shake256(seed.as_bytes(), 32);
    let output64 = shake256(seed.as_bytes(), 64);
    let output128 = shake256(seed.as_bytes(), 128);
    println!(
        "SHAKE256: 32-byte output matches the first 32 bytes of the 64-byte output: {}",
        output64.starts_with(&output32)
    );
    println!(
        "SHAKE256: 64-byte output matches the first 64 bytes of the 128-byte output: {}",
        output128.starts_with(&output64)
    );
}
