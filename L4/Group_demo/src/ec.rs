// An elliptic curve group: P-256 from the p256 crate.
// The group operation is point addition; the identity is the point at infinity.
// G is the standard generator; its order n is a 256-bit prime.

use p256::elliptic_curve::sec1::ToEncodedPoint;

pub type Point = p256::ProjectivePoint;
pub type Scalar = p256::Scalar; // Integer modulo n.

// Point coordinates are integers modulo the field prime p; scalars are integers modulo the order n.
// Both have 256 bits, but they are different numbers (FIPS 186-5 / SP 800-186).
pub const FIELD_MODULUS_HEX: &str =
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
pub const GROUP_ORDER_HEX: &str =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

// The group operation: point addition.
pub fn op(a: &Point, b: &Point) -> Point {
    *a + b
}

// "xG" means: apply the group operation x times, starting from the identity.
// Same loop as zp::repeat; only the identity and the operation differ.
pub fn repeat(point: &Point, x: u64) -> Point {
    let mut result = Point::IDENTITY; // Point at infinity.
    for _ in 0..x {
        result = op(&result, point);
    }
    result
}

// Compressed SEC1 encoding (hex): 02/03 || x-coordinate. The identity encodes as 00.
pub fn to_hex(point: &Point) -> String {
    hex::encode(point.to_affine().to_encoded_point(true).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{op, repeat, Point, Scalar};

    #[test]
    fn repeat_matches_library_scalar_multiplication() {
        for x in 0..20u64 {
            assert_eq!(
                repeat(&Point::GENERATOR, x),
                Point::GENERATOR * Scalar::from(x)
            );
        }
    }

    #[test]
    fn n_times_g_is_the_identity() {
        let n_minus_1 = Scalar::ZERO - Scalar::ONE; // n - 1 as a scalar.
        let point = Point::GENERATOR * n_minus_1;
        assert_eq!(op(&point, &Point::GENERATOR), Point::IDENTITY);
    }

    #[test]
    fn order_constant_matches_the_library() {
        // n - 1 is the largest scalar; its last byte is one less than n's (0x51 -> 0x50).
        let n_minus_1 = hex::encode((Scalar::ZERO - Scalar::ONE).to_bytes());
        assert_eq!(&n_minus_1[..62], &super::GROUP_ORDER_HEX[..62]);
        assert_eq!(&n_minus_1[62..], "50");
        assert_ne!(super::GROUP_ORDER_HEX, super::FIELD_MODULUS_HEX);
    }

    #[test]
    fn addition_rule() {
        let a = Scalar::from(1234u64);
        let b = Scalar::from(5678u64);
        let g = Point::GENERATOR;
        assert_eq!(g * (a + b), op(&(g * a), &(g * b)));
    }
}
