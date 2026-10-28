use hmac_sha256_template::hmac_sha256;

// HMAC-SHA256 test vectors from RFC 4231, cases 1, 2, and 6.
// https://www.rfc-editor.org/rfc/rfc4231.html#section-4
#[test]
fn rfc4231_case_1() {
    let tag = hmac_sha256(&[0x0b; 20], b"Hi There");
    assert_eq!(
        hex::encode(tag),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn rfc4231_case_2() {
    let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex::encode(tag),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn rfc4231_case_6_long_key() {
    let tag = hmac_sha256(
        &[0xaa; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    );
    assert_eq!(
        hex::encode(tag),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

// Boundary values checked independently with Python hmac and hashlib.sha256.
#[test]
fn keys_at_the_sha256_block_boundary() {
    let key64: Vec<u8> = (0..64).collect();
    let key65: Vec<u8> = (0..65).collect();
    assert_eq!(
        hex::encode(hmac_sha256(&key64, b"block boundary")),
        "7731706bc2a4a6ce8247c91afa5f0527538aeb8b0d65171920507c90b5ea1bd6"
    );
    assert_eq!(
        hex::encode(hmac_sha256(&key65, b"block boundary")),
        "3ee36119c3fb00e5778df37be9f56c514cd2b5e1bb07199e998954f0bdf8af99"
    );
}
