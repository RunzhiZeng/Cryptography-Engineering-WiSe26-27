mod ec;
mod group;
mod zp;

use ec::{Point, Scalar};
use group::{dh, IntegerGroup, P256};

fn main() {
    // (1) Integer group: multiplicative notation, g^x.
    println!(
        "(1) Integer group: p = {}, g = {}, order q = {}",
        zp::P,
        zp::G,
        zp::Q
    );
    println!("Group operation: a * b mod {}; identity: 1", zp::P);
    for x in 0..=zp::Q + 1 {
        println!("g^{x:<2} = {}", zp::repeat(zp::G, x));
    }
    println!(
        "g^11 is the identity, so g^12 = g: exponents work modulo q = {}.",
        zp::Q
    );

    // g^x in the group is not the integer power: every step reduces modulo p.
    for x in [5u64, 20] {
        let integer_power = zp::G.pow(x as u32);
        println!(
            "Integer 4^{x} = {integer_power}; group g^{x} = {} (= {integer_power} mod {})",
            zp::repeat(zp::G, x),
            zp::P
        );
    }
    println!("g^20 = g^(20 mod 11) = g^9 = {}", zp::repeat(zp::G, 9));

    // The modulus p and the order q are different numbers.
    // Z_23^* = {1, ..., 22} has p - 1 = 22 elements; each element's order divides 22.
    println!("\nModulus vs. order:");
    println!(
        "Z_{}^* has {} elements; the modulus is p = {}.",
        zp::P,
        zp::P - 1,
        zp::P
    );
    for a in [1, zp::P - 1, zp::G, 5] {
        println!("order({a}) = {}", zp::order(a));
    }
    let subgroup: Vec<u64> = (0..zp::Q).map(|x| zp::repeat(zp::G, x)).collect();
    println!(
        "g = {} generates {} of the {} elements: {subgroup:?}",
        zp::G,
        subgroup.len(),
        zp::P - 1
    );
    // DH uses a subgroup of prime order q: exponents live mod q, results live mod p.

    // (2) Elliptic curve group: additive notation, xG.
    let g = Point::GENERATOR;
    println!("\n(2) P-256: group operation: point addition; identity: point at infinity");
    println!("G  = {}", ec::to_hex(&g));
    println!("2G = G + G = {}", ec::to_hex(&ec::op(&g, &g)));
    println!("3G = {}", ec::to_hex(&ec::repeat(&g, 3)));

    // Repeated addition gives the same point as the library's scalar multiplication.
    // The library uses double-and-add, so it also works for 256-bit scalars.
    let x = 1000;
    println!(
        "{x}G by repeated addition == library G * {x}: {}",
        ec::repeat(&g, x) == g * Scalar::from(x)
    );

    let n_minus_1 = Scalar::ZERO - Scalar::ONE; // n - 1, where n is the order of G.
    println!(
        "nG = (n-1)G + G = {} (identity), like g^q = 1",
        ec::to_hex(&ec::op(&(g * n_minus_1), &g))
    );

    // Here too, the modulus and the order differ: coordinates live mod p, scalars live mod n.
    println!("Field modulus p (coordinates): {}", ec::FIELD_MODULUS_HEX);
    println!("Group order n (scalars):       {}", ec::GROUP_ORDER_HEX);

    // There is no "point times point": only point + point and scalar * point.
    // let wrong = g * g; // Uncomment to see the compile error.

    // (3) Papers and slides write DH for any group with g^x. group::dh is written that way once,
    // and runs unchanged on both groups. On P-256, read g^a as aG.
    let (a, b) = (3, 7);
    println!("\n(3) One DH function in generic notation g^x, with a = {a}, b = {b}:");
    let (alice, bob) = dh(&IntegerGroup, a, b);
    println!("Same shared value: {}", alice == bob);
    println!();
    let (alice, bob) = dh(&P256, a, b);
    println!("Same shared value: {}", alice == bob);

    // (4) The generic notation and what it means in each group.
    println!("\n(4) Notation:");
    let rows = [
        (
            "Generic (any group)",
            "Integer group (mod p)",
            "EC group (additive)",
        ),
        ("a · b", "a * b mod p", "P + Q"),
        ("1", "1", "O (point at infinity)"),
        ("g^x", "g * ... * g mod p", "xG = G + ... + G"),
        ("g^a · g^b = g^(a+b)", "g^a * g^b mod p", "aG + bG = (a+b)G"),
        ("(g^a)^b = g^(ab)", "(g^a)^b mod p", "b(aG) = (ab)G"),
        ("g^q = 1", "g^q mod p = 1", "nG = O"),
    ];
    for (generic, integer, ec) in rows {
        println!("{generic:<23}{integer:<25}{ec}");
    }
}
