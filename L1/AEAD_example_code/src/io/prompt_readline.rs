use std::io::{self, Write};

/// Print a prompt and read one trimmed line from stdin; return None at EOF.
pub fn read_line_prompt(prompt: &str) -> io::Result<Option<String>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Ok(None);
    }
    Ok(Some(input.trim().to_string()))
}
