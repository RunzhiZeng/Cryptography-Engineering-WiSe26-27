mod arithmetic;

// Run `cargo run` for division examples and `cargo test` for subtraction cases.
fn main() {
    let a: u32 = 10;
    let b: u32 = 3;

    // Unlike AddMul, these operations can return an error.
    // `match` separates the successful value from the error value.
    match arithmetic::divide(a, b) {
        Ok(quotient) => println!("{a} / {b} = {quotient} (integer division)"),
        Err(error) => eprintln!("Division failed: {error:?}"),
    }

    let b: u32 = 0;

    // An expected failure is handled explicitly, and the program continues.
    match arithmetic::divide(a, b) {
        Ok(quotient) => println!("{a} / {b} = {quotient}"),
        Err(error) => {
            // Same error value: Debug uses :?, while Display uses no suffix.
            eprintln!("Debug:   Cannot divide {a} by {b}: {error:?}");
            eprintln!("Display: Cannot divide {a} by {b}: {error}");
        }
    }

    println!("Demo finished.");
}
