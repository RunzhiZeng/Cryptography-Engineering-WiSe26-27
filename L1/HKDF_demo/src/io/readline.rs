use std::io::{self, Write};

/// Print a prompt and read one trimmed line; return UnexpectedEof at EOF.
pub fn read_line_prompt(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Input ended.")); // EOF is missing input, not an empty line.
    }
    Ok(input.trim().to_string())
}