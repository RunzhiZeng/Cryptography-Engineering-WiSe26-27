use hkdf_sha256_template::{hkdf_expand, hkdf_extract, hkdf_sha256, HkdfError, MAX_OUTPUT_LEN};

// HKDF-SHA256 test vectors from RFC 5869, appendix A.1-A.3.
// https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A
#[test]
fn rfc5869_case_1() {
    let ikm = [0x0b; 22];
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let prk = hkdf_extract(Some(&salt), &ikm);
    assert_eq!(
        hex::encode(prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let okm_extract_then_expand = hkdf_expand(&prk, &info, 42).unwrap();
    let okm_hkdf = hkdf_sha256(Some(&salt), &ikm, &info, 42).unwrap();
    assert_eq!(
        hex::encode(&okm_extract_then_expand),
        concat!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865"
        )
    );
    assert_eq!(okm_extract_then_expand, okm_hkdf);
}

#[test]
fn rfc5869_case_2_long_inputs_and_output() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let prk = hkdf_extract(Some(&salt), &ikm);
    assert_eq!(
        hex::encode(prk),
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    );
    let okm = hkdf_expand(&prk, &info, 82).unwrap();
    assert_eq!(
        hex::encode(okm),
        concat!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
}

#[test]
fn rfc5869_case_3_no_salt_and_empty_info() {
    let ikm = [0x0b; 22];
    let prk = hkdf_extract(None, &ikm);
    assert_eq!(
        hex::encode(prk),
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    );
    let okm_no_salt = hkdf_sha256(None, &ikm, b"", 42).unwrap();
    let okm_zero_salt = hkdf_sha256(Some(&[0u8; 32]), &ikm, b"", 42).unwrap();
    let okm_empty_salt = hkdf_sha256(Some(b""), &ikm, b"", 42).unwrap();
    assert_eq!(
        hex::encode(&okm_no_salt),
        concat!(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
            "9d201395faa4b61a96c8"
        )
    );
    assert_eq!(okm_no_salt, okm_zero_salt);
    assert_eq!(okm_no_salt, okm_empty_salt);
}

#[test]
fn zero_output_length_is_allowed() {
    assert_eq!(hkdf_expand(&[0u8; 32], b"info", 0), Ok(Vec::new()));
}

#[test]
fn maximum_output_length_is_allowed() {
    let prk = hkdf_extract(None, b"input key material");
    let okm = hkdf_expand(&prk, b"info", MAX_OUTPUT_LEN).unwrap();
    assert_eq!(okm.len(), MAX_OUTPUT_LEN);
}

#[test]
fn rejects_output_above_the_limit() {
    assert_eq!(
        hkdf_expand(&[0u8; 32], b"info", MAX_OUTPUT_LEN + 1),
        Err(HkdfError::OutputTooLong)
    );
    assert_eq!(
        hkdf_expand(&[0u8; 32], b"info", usize::MAX),
        Err(HkdfError::OutputTooLong)
    );
}
