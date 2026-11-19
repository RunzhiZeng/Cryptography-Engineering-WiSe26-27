# ECDSA nonce reuse exercise

`src/ecdsa_demo.rs` implements ECDSA over P-256 with SHA-256. The `p256` crate provides only the group arithmetic: points and integers modulo the group order n. Key generation, signing, and verification are written out in the file.

It provides two signing functions:

- `sign_randomized` takes the nonce k as an extra input, as in textbook ECDSA (FIPS 186). The caller must supply a fresh random k for every signature.
- `sign_deterministic` derives k from the secret key and the message with HMAC-SHA256. This is a simplified version of [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html), which uses HMAC-DRBG for retries instead of a counter. The function keeps no state: the same key and message always give the same k.

Implement `recover_nonce` and `recover_secret_key` in `src/attack.rs`. Given two signatures on different messages that reuse the same k, recover k and then the secret key d. The formulas are in the comments. Use only the messages and signatures, not the secret values.

`src/main.rs` shows the operations you need: scalar `+`, `-`, `*`, `inverse`, and `hash_message`. Scalars are already reduced modulo n.

```bash
cargo test
cargo run
```

The template compiles. Tests and the last part of `cargo run` fail at `todo!()` until you implement the attack. The tests for `ecdsa_demo.rs` already pass and check the implementation against the `p256` library's ECDSA.
