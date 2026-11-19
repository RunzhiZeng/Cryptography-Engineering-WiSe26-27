use ecdsa_nonce_reuse_template::attack::{recover_nonce, recover_secret_key, AttackError};
use ecdsa_nonce_reuse_template::ecdsa_demo::{
    public_key, random_scalar, sign_deterministic, sign_randomized, verify,
};
use rand::rngs::OsRng;

#[test]
fn recovers_nonce_and_secret_key_from_reuse() {
    for _ in 0..10 {
        let d = random_scalar(&mut OsRng);
        let k = random_scalar(&mut OsRng);
        let signature1 = sign_randomized(&d, b"message one", &k).unwrap();
        let signature2 = sign_randomized(&d, b"message two", &k).unwrap();

        let recovered_k =
            recover_nonce(b"message one", &signature1, b"message two", &signature2).unwrap();
        assert_eq!(recovered_k, k);

        // Either signature gives the same secret key.
        assert_eq!(
            recover_secret_key(b"message one", &signature1, &recovered_k),
            Ok(d)
        );
        assert_eq!(
            recover_secret_key(b"message two", &signature2, &recovered_k),
            Ok(d)
        );
    }
}

#[test]
fn recovered_key_forges_signatures() {
    let d = random_scalar(&mut OsRng);
    let q = public_key(&d);
    let k = random_scalar(&mut OsRng);
    let signature1 = sign_randomized(&d, b"A", &k).unwrap();
    let signature2 = sign_randomized(&d, b"B", &k).unwrap();

    let recovered_k = recover_nonce(b"A", &signature1, b"B", &signature2).unwrap();
    let recovered_d = recover_secret_key(b"A", &signature1, &recovered_k).unwrap();
    let forged = sign_deterministic(&recovered_d, b"forged").unwrap();
    assert!(verify(&q, b"forged", &forged));
}

#[test]
fn different_nonces_are_rejected() {
    let d = random_scalar(&mut OsRng);
    let signature1 = sign_randomized(&d, b"A", &random_scalar(&mut OsRng)).unwrap();
    let signature2 = sign_randomized(&d, b"B", &random_scalar(&mut OsRng)).unwrap();
    assert_eq!(
        recover_nonce(b"A", &signature1, b"B", &signature2),
        Err(AttackError::DifferentNonces)
    );
}

#[test]
fn same_message_twice_is_not_enough() {
    // Same message and same k give the same signature: s1 - s2 = 0 has no inverse.
    let d = random_scalar(&mut OsRng);
    let k = random_scalar(&mut OsRng);
    let signature = sign_randomized(&d, b"A", &k).unwrap();
    assert_eq!(
        recover_nonce(b"A", &signature, b"A", &signature),
        Err(AttackError::NotInvertible)
    );
}
