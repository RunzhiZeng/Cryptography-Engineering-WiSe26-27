# HMAC-SHA256 exercise

Implement `hmac_sha256` in `src/lib.rs` using the SHA-256 API from HashUpdate_demo. SHA-256 has a 64-byte block and a 32-byte output. Do not use the `hmac` crate.

Keep the public function signature: the HKDF exercise calls it from this package.

```bash
cargo test
cargo run
```

The template compiles. Calls to the unfinished function panic at `todo!()` until you implement it. Tests use [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html#section-4), including a key longer than the hash block.
