# Lecture 1

Basic Rust examples and demonstrations of hashing, message authentication, key derivation, and authenticated encryption.

- [AddMul](AddMul/): Functions, modules, visibility, and multiplication through repeated addition.
- [SubDiv](SubDiv/): Division through repeated subtraction, with `Result`, `match`, and `?` for error handling.
- [ReadFileandHash](ReadFileandHash/): Compute a file's digest with the selected hash and display it as bytes, hexadecimal, and Base64.
- [HMAC_example_code](HMAC_example_code/): Generate and verify HMAC tags using the selected hash.
- [HKDF_demo](HKDF_demo/): Derive an AES-256-GCM key using HKDF with the selected hash.
- [AEAD_example_code](AEAD_example_code/): AES-256-GCM encryption, decryption, associated data, and tamper detection.

## Choosing a hash

ReadFileandHash defines `Hash` and `HASH_NAME` near the top of `src/main.rs`. HMAC and HKDF define them in their `src/crypto/` module. Change both together, then rebuild. For example, for SHA3-512, set `type Hash = sha3::Sha3_512;` and `HASH_NAME` to `"SHA3-512"`. ReadFileandHash and HMAC default to SHA-256; HKDF defaults to SHA3-256.

Both `sha2` and `sha3` are included. Choices include `sha2::Sha256`, `sha2::Sha512`, `sha3::Sha3_256`, and `sha3::Sha3_512`. Digest and HMAC tag lengths adapt automatically. HKDF still derives a 32-byte AES-256 key.

## Running

Each example is an independent Cargo package. From this directory, for example:

```bash
cd AEAD_example_code
cargo test
cargo run
```

Run commands inside the selected package directory so relative file paths resolve correctly.
