# Lecture 2

- [SHAKE_demo](SHAKE_demo/): SHAKE128 and SHAKE256 with different seeds and 32-, 64-, and 128-byte outputs. For each algorithm, the same seed gives the same output prefix.
- [HashUpdate_demo](HashUpdate_demo/): SHA3-512 with five `update` calls or one call on the concatenated input. Both produce the same digest.
- [HKDF_demo_2](HKDF_demo_2/): Explicit Extract then Expand, the convenience API, and the equivalence between no salt and a zero salt.
- [HMAC_SHA256_template](HMAC_SHA256_template/): Template for implementing HMAC using SHA-256.
- [HKDF_SHA256_template](HKDF_SHA256_template/): Template for implementing HKDF-Expand using your HMAC package through a local Cargo dependency.

The functions in [shake.rs](SHAKE_demo/src/shake.rs) are simple wrappers around the `sha3` crate. Read them to see how to feed a seed into SHAKE and read the requested number of output bytes.

SHA-2 and SHA-3 implement the same `Digest` trait (`new`, `update`, `finalize`), so HashUpdate_demo uses the same API for both. To switch to SHA-256, change `type Hash` to `sha2::Sha256` and `HASH_NAME` to `"SHA-256"` in `src/main.rs`.

HKDF_demo_2 compares `extract` + `expand` with `new` + `expand`; `new` performs Extract internally. With no salt (`None`), Extract uses HashLen zero bytes, where HashLen is the selected hash's output length ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2)).

## Running

Each example has its own Cargo package. From this directory, for example:

```bash
cd SHAKE_demo
cargo test
cargo run
```

For SHAKE_demo, change `seeds` and `output_lengths` in `src/main.rs` to try other inputs and output lengths. Lengths are in bytes.

For the exercises, complete HMAC_SHA256_template first, then HKDF_SHA256_template. Both compile, but tests involving unfinished functions fail at `todo!()` until you implement them.
