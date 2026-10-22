// Basic functions using nonnegative integers (u32).

// Private by default: only this module and its descendants can call `add`.
// `a` and `b` are parameters; `-> u32` specifies the return type.
fn add(a: u32, b: u32) -> u32 {
    // The last expression, without a semicolon, is the return value.
    a + b
}

// `pub` allows `main` to call this function through the module.
// Compute a * b by adding a to the result b times.
pub fn multiply(a: u32, b: u32) -> u32 {
    // `mut` allows these variables to change inside the loop.
    let mut result: u32 = 0;
    let mut count: u32 = 0;

    loop {
        if count == b {
            break;
        }

        result = add(result, a); // Calling `add` inside its module is allowed.
        count += 1;
    }

    result
}
