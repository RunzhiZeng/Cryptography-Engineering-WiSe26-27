mod cert;

use cert::{load_certificates, parse_certificate, print_certificate};
use std::io::{self, Write};

fn main() -> io::Result<()> {
    println!("X.509 Certificate Reader");
    println!("Type a certificate file (PEM or DER) to read (or 'exit' to quit).");
    println!("Separate several files with commas. Paths are relative to this package directory.");
    println!("Examples: certs/letsencrypt_org_chain.pem, certs/isrg_root_x1.pem");

    loop {
        print!("> ");
        io::stdout().flush()?; // Propagate flush errors instead of panicking.

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            break; // EOF ends the demo; read errors are returned by ?.
        }

        let input = input.trim(); // Remove the \n
        if input.eq_ignore_ascii_case("exit") {
            println!("Exit.");
            break;
        }

        // Read each comma-separated file in turn.
        for path in input
            .split(',')
            .map(str::trim)
            .filter(|path| !path.is_empty())
        {
            let certificates = match load_certificates(path) {
                Ok(certificates) => certificates,
                Err(error) => {
                    eprintln!("'{path}': {error}");
                    continue;
                }
            };

            // A PEM file may hold several certificates, e.g. a chain sent by a server (leaf first).
            for (index, der) in certificates.iter().enumerate() {
                println!(
                    "\n{path}: certificate {} of {}",
                    index + 1,
                    certificates.len()
                );
                match parse_certificate(der) {
                    Ok(certificate) => print_certificate(&certificate, der),
                    Err(error) => eprintln!("{error}"),
                }
            }
        }
    }
    Ok(())
}
