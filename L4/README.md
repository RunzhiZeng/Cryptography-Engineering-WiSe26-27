# Lecture 4

- [Group_demo](Group_demo/): Group operations in an integer group (mod p) and on the elliptic curve P-256, and one DH function in generic notation g^x for both.
- [X25519_demo](X25519_demo/): A simple DH handshake using X25519.
- [DH_handshake_demo](DH_handshake_demo/): A DH wrapper with a choice of X25519, P-256, or P-384.
- [Ed25519Signature_demo](Ed25519Signature_demo/): A simple digital signature using Ed25519: sign, verify, and reject a modified message.
- [Signature_demo](Signature_demo/): Digital signatures with a choice of Ed25519, ECDSA P-256, or ECDSA P-384.

```bash
cd Group_demo # Or X25519_demo, DH_handshake_demo, Ed25519Signature_demo, Signature_demo.
cargo test
cargo run
```

## Notation

`g^x` means: apply the group operation x times to g. It is the integer power only if the group operation is integer multiplication, and the integer group here also reduces modulo p after every step. On an elliptic curve the group operation is point addition, so the same idea is written `xG = G + ... + G`.

Papers and slides usually write DH and signatures for any group with `g^x`, and you plug in a concrete group later. For an EC group, read `g^x` as `xG`. In Group_demo, `group::dh` is written only with `g^x` (the `Group` interface: `generator()` is g, `exp(g, x)` is g^x) and runs unchanged on the integer group and on P-256. The table at the end of `cargo run` translates the generic notation into each group.

In Group_demo, `zp::repeat` and `ec::repeat` are the same loop; only the identity and the group operation differ. Real implementations use square-and-multiply (double-and-add) instead of the loop, with the same result.

The modulus and the order are different numbers. In Group_demo the modulus is p = 23, so Z_23^* has p - 1 = 22 elements, and each element's order divides 22: 1 has order 1, 22 has order 2, g = 4 has order q = 11, and 5 has order 22. No element has order 23. In the example, we use g = 4: **exponents are reduced mod q = 11, results mod p = 23**. On P-256 likewise, point coordinates are integers mod the field prime p, while scalars are integers mod the group order n; both have 256 bits but differ.

## Signatures

The secret key signs; anyone with the public key can verify. Unlike HMAC, the verifier cannot create a valid signature.

ECDSA hashes the message first: SHA-256 for P-256, SHA-384 for P-384.

Every signature uses a secret per-signature nonce. How the nonce is chosen decides whether signing is deterministic or randomized:

- Ed25519 is always deterministic ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)): the nonce is derived from the secret key and message. It has no randomized mode.
- ECDSA can be either. In textbook ECDSA (FIPS 186) the nonce is random, and many libraries sign this way by default. In Signature_demo, `sign` is deterministic ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html)); `sign_randomized` mixes fresh random bytes into the nonce.

Signing the same message twice gives the same signature in deterministic mode and different signatures in randomized mode. Both verify with the same public key.

```bash
cd Signature_demo
cargo test
cargo run
```
