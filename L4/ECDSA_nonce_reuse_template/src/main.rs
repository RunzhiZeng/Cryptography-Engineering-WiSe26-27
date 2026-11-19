use ecdsa_nonce_reuse_template::attack::{recover_nonce, recover_secret_key};
use ecdsa_nonce_reuse_template::ecdsa_demo::{
    hash_message, inverse, public_key, random_scalar, sign_deterministic, sign_randomized, to_hex,
    verify, x_coordinate, EcdsaError, Point, Scalar,
};
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};

fn main() -> Result<(), EcdsaError> {
    let mut rng = match StdRng::from_rng(OsRng) {
        Ok(rng) => rng,
        Err(error) => {
            eprintln!("Random generator setup failed: {error}");
            std::process::exit(1);
        }
    };

    // (1) Scalar arithmetic: every operation is modulo the group order n.
    let a = Scalar::from(7u64);
    let b = Scalar::from(3u64);
    println!("(1) Scalar arithmetic modulo n (hex, 32 bytes):");
    println!("a = 7:      {}", to_hex(&a));
    println!("b = 3:      {}", to_hex(&b));
    println!("a + b:      {}", to_hex(&(a + b)));
    println!("a * b:      {}", to_hex(&(a * b)));
    println!("b - a:      {}", to_hex(&(b - a))); // -4 mod n, i.e. n - 4.
    match inverse(&b) {
        Some(b_inv) => {
            println!("b^-1:       {}", to_hex(&b_inv));
            println!("b * b^-1 == 1: {}", b * b_inv == Scalar::ONE);
        }
        None => println!("b has no inverse"),
    }
    println!("0^-1 exists: {}", inverse(&Scalar::ZERO).is_some()); // Zero has no inverse.
    println!("H(\"hello\") mod n: {}", to_hex(&hash_message(b"hello")));

    // (2) Points: Q = dG, and the x-coordinate of a point as a scalar.
    let secret_key = random_scalar(&mut rng);
    let public = public_key(&secret_key);
    println!("\n(2) Key pair:");
    println!("Secret key d: {}", to_hex(&secret_key)); // Printed only for this teaching demo.
    println!("x(Q) mod n:   {}", to_hex(&x_coordinate(&public)));
    println!(
        "2G == G + G:  {}",
        Point::GENERATOR * Scalar::from(2u64) == Point::GENERATOR + Point::GENERATOR
    );

    // (3) Deterministic signing: same message, same nonce, same signature.
    let message1 = b"Pay Bob 100 EUR";
    let signature_a = sign_deterministic(&secret_key, message1)?;
    let signature_b = sign_deterministic(&secret_key, message1)?;
    println!("\n(3) Deterministic signing, same message twice:");
    println!("r: {}", to_hex(&signature_a.r));
    println!("s: {}", to_hex(&signature_a.s));
    println!("Same signature: {}", signature_a == signature_b);
    println!("Verify: {}", verify(&public, message1, &signature_a));

    // (4) Randomized signing: a fresh random nonce each time gives a different r.
    let signature_a = sign_randomized(&secret_key, message1, &random_scalar(&mut rng))?;
    let signature_b = sign_randomized(&secret_key, message1, &random_scalar(&mut rng))?;
    println!("\n(4) Randomized signing, same message, fresh nonces:");
    println!("r1: {}", to_hex(&signature_a.r));
    println!("r2: {}", to_hex(&signature_b.r));
    println!("Same signature: {}", signature_a == signature_b);
    println!(
        "Both verify: {}",
        verify(&public, message1, &signature_a) && verify(&public, message1, &signature_b)
    );

    // (5) Nonce reuse: two different messages, the same nonce k.
    let message2 = b"Pay Bob 900 EUR";
    let reused_nonce = random_scalar(&mut rng);
    let signature1 = sign_randomized(&secret_key, message1, &reused_nonce)?;
    let signature2 = sign_randomized(&secret_key, message2, &reused_nonce)?;
    println!("\n(5) Nonce reuse, two different messages:");
    println!("r1: {}", to_hex(&signature1.r));
    println!("r2: {}", to_hex(&signature2.r));
    println!(
        "Same r (visible to anyone): {}",
        signature1.r == signature2.r
    );

    // The attacker sees only the messages, the signatures, and the public key.
    // These calls panic at todo!() until you implement src/attack.rs.
    let recovered_nonce = match recover_nonce(message1, &signature1, message2, &signature2) {
        Ok(k) => k,
        Err(error) => {
            eprintln!("Nonce recovery failed: {error:?}");
            return Ok(());
        }
    };
    let recovered_key = match recover_secret_key(message1, &signature1, &recovered_nonce) {
        Ok(d) => d,
        Err(error) => {
            eprintln!("Key recovery failed: {error:?}");
            return Ok(());
        }
    };
    println!("Recovered k:  {}", to_hex(&recovered_nonce));
    println!("Recovered d:  {}", to_hex(&recovered_key));
    println!("Same nonce:   {}", recovered_nonce == reused_nonce);
    println!("Same key:     {}", recovered_key == secret_key);

    // With d, the attacker can sign any message as Alice.
    let forged = sign_deterministic(&recovered_key, b"Pay Mallory 1000000 EUR")?;
    println!(
        "Forged signature verifies with Alice's public key: {}",
        verify(&public, b"Pay Mallory 1000000 EUR", &forged)
    );
    Ok(())
}
