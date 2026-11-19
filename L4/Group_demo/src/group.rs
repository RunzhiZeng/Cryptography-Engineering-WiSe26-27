// One interface for every group, in the generic notation used for DH and signatures:
// generator() is g, and exp(g, x) is g^x ("apply the group operation x times").
// Integer group: g^x = g * ... * g mod p (zp::repeat).
// P-256:         g^x = G + ... + G (ec::repeat), written xG in additive notation.
// Code written against this interface works for both groups unchanged.

use crate::ec::{self, Point};
use crate::zp;

pub trait Group {
    type Element: Copy + PartialEq;
    fn name(&self) -> &'static str;
    fn generator(&self) -> Self::Element; // g
    fn exp(&self, g: Self::Element, x: u64) -> Self::Element; // g^x
    fn encode(&self, element: Self::Element) -> String; // For printing.
}

pub struct IntegerGroup; // The subgroup of order q = 11 in Z_23^*, from zp.rs.
pub struct P256; // From ec.rs.

impl Group for IntegerGroup {
    type Element = u64;
    fn name(&self) -> &'static str {
        "Integer group (p = 23, q = 11)"
    }
    fn generator(&self) -> u64 {
        zp::G
    }
    fn exp(&self, g: u64, x: u64) -> u64 {
        zp::repeat(g, x) // g * ... * g mod p
    }
    fn encode(&self, element: u64) -> String {
        element.to_string()
    }
}

impl Group for P256 {
    type Element = Point;
    fn name(&self) -> &'static str {
        "P-256"
    }
    fn generator(&self) -> Point {
        Point::GENERATOR
    }
    fn exp(&self, g: Point, x: u64) -> Point {
        ec::repeat(&g, x) // G + ... + G, i.e. xG
    }
    fn encode(&self, element: Point) -> String {
        ec::to_hex(&element)
    }
}

// DH written once, only with g^x. The same function runs on both groups.
// Returns (Alice's shared value, Bob's shared value).
pub fn dh<G: Group>(group: &G, a: u64, b: u64) -> (G::Element, G::Element) {
    let g = group.generator();
    let g_a = group.exp(g, a); // Alice sends g^a.
    let g_b = group.exp(g, b); // Bob sends g^b.
    let alice_shared = group.exp(g_b, a); // (g^b)^a
    let bob_shared = group.exp(g_a, b); // (g^a)^b

    println!("{}:", group.name());
    println!("g^a     = {}", group.encode(g_a));
    println!("g^b     = {}", group.encode(g_b));
    println!("(g^b)^a = {}", group.encode(alice_shared));
    println!("(g^a)^b = {}", group.encode(bob_shared));
    (alice_shared, bob_shared)
}

#[cfg(test)]
mod tests {
    use super::{dh, Group, IntegerGroup, P256};
    use crate::ec::{Point, Scalar};

    fn both_sides_agree<G: Group>(group: &G) {
        for (a, b) in [(3, 7), (10, 4), (1, 1)] {
            let (alice, bob) = dh(group, a, b);
            assert!(alice == bob);
            assert!(alice == group.exp(group.generator(), a * b)); // g^(ab)
        }
    }

    #[test]
    fn dh_agrees_in_both_groups() {
        both_sides_agree(&IntegerGroup);
        both_sides_agree(&P256);
    }

    #[test]
    fn exp_on_p256_is_scalar_multiplication() {
        assert_eq!(
            P256.exp(Point::GENERATOR, 21),
            Point::GENERATOR * Scalar::from(21u64)
        );
    }
}
