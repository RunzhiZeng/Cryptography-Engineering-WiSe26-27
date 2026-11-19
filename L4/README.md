# Lecture 4

- [X25519_demo](X25519_demo/): A simple DH handshake using X25519.
- [DH_handshake_demo](DH_handshake_demo/): A DH wrapper with a choice of X25519, P-256, or P-384.
- [Signature_demo](Signature_demo/): Digital signatures with a choice of Ed25519, ECDSA P-256, or ECDSA P-384.
- [ECDSA_nonce_reuse_template](ECDSA_nonce_reuse_template/): ECDSA over P-256 with deterministic and randomized signing, and a template for the nonce reuse attack.

```bash
cd X25519_demo # Or DH_handshake_demo.
cargo run
```

## Signatures

The secret key signs; anyone with the public key can verify. Unlike HMAC, the verifier cannot create a valid signature.

ECDSA hashes the message first: SHA-256 for P-256, SHA-384 for P-384.

Every signature uses a secret per-signature nonce. How the nonce is chosen decides whether signing is deterministic or randomized:

- Ed25519 is always deterministic ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)): the nonce is derived from the secret key and message. It has no randomized mode.
- ECDSA can be either. In textbook ECDSA (FIPS 186) the nonce is random, and many libraries sign this way by default. In Signature_demo, `sign` is deterministic ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html)); `sign_randomized` mixes fresh random bytes into the nonce.

Signing the same message twice gives the same signature in deterministic mode and different signatures in randomized mode. Both verify with the same public key.

```bash
cd Signature_demo # Or ECDSA_nonce_reuse_template.
cargo test
cargo run
```

For the exercise, implement `src/attack.rs` in ECDSA_nonce_reuse_template. It compiles, but tests involving unfinished functions fail at `todo!()` until you implement them.
