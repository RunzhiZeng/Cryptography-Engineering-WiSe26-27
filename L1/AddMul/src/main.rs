// Load the functions defined in src/arithmetic.rs.
mod arithmetic;

// Program execution starts here. No return type means `()` (unit).
fn main() {
    let a: u32 = 3;
    let b: u32 = 4;

    println!("{a} * {b} = {}", arithmetic::multiply(a, b));

    // Intentional compile error (E0603): `add` is private to `arithmetic`.
    // Comment out the following line, then use `cargo run` to run the demo.
    // println!("{a} + {b} = {}", arithmetic::add(a, b));
}
