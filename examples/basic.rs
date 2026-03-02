//! Basic secret scanning example.
//!
//! Demonstrates using the default 222-rule scanner to detect secrets in text
//! and print findings.
//!
//! Run with: `cargo run --example basic`

use gitleaks_rs::Scanner;

fn main() {
    // Create a scanner with the built-in 222-rule gitleaks config.
    // No configuration files needed.
    let scanner = Scanner::default();
    println!("Loaded {} rules\n", scanner.rule_count());

    // Sample text with embedded secrets.
    let text = r#"# Application Config
DATABASE_URL=postgres://localhost/myapp

# AWS credentials
export AWS_ACCESS_KEY_ID=AKIAQWERTYUIO2QBKPXN

# GitHub personal access token
GITHUB_TOKEN=ghp_xK4mN8pQ2rT6vW0yB3dF5hJ7lO9sU1wE3a5b

# Safe values — these should NOT trigger findings
API_VERSION=v2
DEBUG=true
LOG_LEVEL=info
"#;

    println!("--- Scanning text for secrets ---\n");

    let findings = scanner.scan_text(text, None);

    if findings.is_empty() {
        println!("No secrets found.");
    } else {
        for f in &findings {
            println!("  Rule:        {}", f.rule_id);
            println!("  Description: {}", f.description);
            println!("  Line:        {}", f.line_number.unwrap());
            println!("  Secret:      {}", f.secret);
            if let Some(entropy) = f.entropy {
                println!("  Entropy:     {:.2}", entropy);
            }
            println!();
        }
        println!("Found {} secret(s)", findings.len());
    }
}
