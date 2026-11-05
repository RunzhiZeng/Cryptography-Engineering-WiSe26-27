# Lecture 3

- [AES_CTR_demo](AES_CTR_demo/): AES-256-CTR encryption and decryption, counter increments, and key/starting block reuse.

The demo has four parts:

1. Basic encryption and decryption with a random starting block and one built from a message number.
2. Counter increments, with the block-by-block ciphertext checked against the CTR library.
3. Reuse of the same key and an all-zero starting block, revealing the XOR of the plaintexts.
4. Different starting blocks can still use overlapping counter blocks. Message A uses `[3 || 0]` and `[3 || 1]`, while message B uses `[3 || 1]` (`nonce || counter`).

The initial counter block determines where encryption starts; the message length determines how many successive counter blocks are used. Different starting blocks can therefore lead to overlapping counter blocks.

This example uses `Ctr64BE`: each 16-byte counter block consists of an 8-byte nonce and an 8-byte big-endian counter. Within a message, the nonce stays fixed and only the counter increments. Between messages, a unique message number can be used as the nonce. The output separates both halves with `||`.

Starting blocks do not need to be secret or unpredictable; no counter block may repeat within or across messages encrypted with the same key ([NIST SP 800-38A, appendix B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)). Use a different message number for each message under a key, and do not wrap the counter. Random starting blocks can collide or produce overlapping counter ranges. The reuse example deliberately uses an all-zero starting block.

`main.rs` calls the simple `encrypt`, `decrypt`, and `make_counter_block` wrappers in [aes_ctr.rs](AES_CTR_demo/src/aes_ctr.rs). Read that file for the cipher setup and `try_apply_keystream` calls. Each call starts from the supplied `initial_counter_block`; decryption uses the same key and starting block as encryption. CTR does not authenticate ciphertexts ([ctr API](https://docs.rs/ctr/0.9.2/ctr/)).

`encrypt_block_by_block` reconstructs the counter blocks and calls single-block AES, returning each step for `main.rs` to print. The counter starts at `initial_counter` in `main.rs` and advances once per block. A 40-byte input uses three blocks; the last block uses 8 keystream bytes. Its ciphertext is checked against the CTR library. This teaching function rejects counter wrap.

## Running

From this directory:

```bash
cd AES_CTR_demo
cargo test
cargo run
```
