# HKDF-SHA256 exercise

Complete HMAC_SHA256_template first. Then implement `hkdf_expand` in `src/lib.rs` using the imported `hmac_sha256` function. Extract and full HKDF are provided to show how the interfaces fit together.

Cargo.toml uses a local `path` dependency on `../HMAC_SHA256_template`. Keep the two folders next to each other. Reuse that package; do not copy HMAC or use the `hmac` or `hkdf` crates here.

```bash
cargo test
cargo run
```

The template compiles. Tests that reach unfinished functions fail at `todo!()` until you implement them. Tests cover [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A), zero salt, multiple output blocks, and the 8160-byte output limit. The PRK interface accepts exactly 32 bytes.
