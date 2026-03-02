//! Advanced secret scanning example.
//!
//! Demonstrates custom TOML configs, programmatic rule building with
//! `ConfigBuilder`, extending defaults, custom redaction strings, and
//! path-based filtering.
//!
//! Run with: `cargo run --example advanced`

use gitleaks_rs::{Config, ConfigBuilder, Rule, Scanner};

fn main() {
    // ---------------------------------------------------------------
    // 1. Custom config from TOML
    // ---------------------------------------------------------------
    println!("=== 1. Custom TOML Config ===\n");

    let config = Config::from_toml(
        r#"
        [[rules]]
        id = "internal-api-key"
        description = "Internal API key"
        regex = '''api_key\s*=\s*"([^"]+)"'''
        keywords = ["api_key"]
        "#,
    )
    .expect("valid TOML config");

    let scanner = Scanner::new(config).unwrap();
    let findings = scanner.scan_text(r#"api_key = "sk_live_a1b2c3d4e5f6""#, None);

    for f in &findings {
        println!("  [{}] secret: {}", f.rule_id, f.secret);
    }
    println!();

    // ---------------------------------------------------------------
    // 2. Programmatic rules with ConfigBuilder
    // ---------------------------------------------------------------
    println!("=== 2. ConfigBuilder ===\n");

    let config = ConfigBuilder::new()
        .title("my project rules")
        .add_rule(Rule {
            id: "internal-token".into(),
            description: Some("Internal service token".into()),
            regex: Some(r"INTERNAL_[A-Z0-9]{32}".into()),
            keywords: vec!["internal_".into()],
            ..Default::default()
        })
        .build()
        .expect("valid config");

    let scanner = Scanner::new(config).unwrap();
    let findings = scanner.scan_text("auth = INTERNAL_ABCDEFGHIJKLMNOP0123456789ABCDEF\n", None);

    for f in &findings {
        println!("  [{}] {}: {}", f.rule_id, f.description, f.secret);
    }
    println!();

    // ---------------------------------------------------------------
    // 3. Extending the default rules with custom additions
    // ---------------------------------------------------------------
    println!("=== 3. Extending Defaults ===\n");

    let defaults = Config::default().expect("embedded config is valid");
    let custom = ConfigBuilder::new()
        .add_rule(Rule {
            id: "acme-corp-token".into(),
            description: Some("ACME Corp internal token".into()),
            regex: Some(r"ACME_[a-zA-Z0-9]{24}".into()),
            keywords: vec!["acme_".into()],
            ..Default::default()
        })
        .build()
        .unwrap();

    let merged = defaults.extend(custom);
    let scanner = Scanner::new(merged).unwrap();

    println!(
        "  Scanner loaded with {} rules (defaults + custom)",
        scanner.rule_count()
    );

    let text = "token = ACME_aB3cD4eF5gH6iJ7kL8mN9oP0q\n";
    let findings = scanner.scan_text(text, None);

    for f in &findings {
        println!("  [{}] {}", f.rule_id, f.secret);
    }
    println!();

    // ---------------------------------------------------------------
    // 4. Redaction with a custom replacement string
    // ---------------------------------------------------------------
    println!("=== 4. Custom Redaction ===\n");

    let config = Config::from_toml(
        r#"
        [[rules]]
        id = "password-field"
        description = "Password in config"
        regex = '''password\s*=\s*"([^"]+)"'''
        keywords = ["password"]
        "#,
    )
    .unwrap();

    let scanner = Scanner::new(config).unwrap();
    let input = "password = \"hunter2\"\nusername = \"admin\"\n";

    // Default redaction (replaces with "REDACTED")
    let result = scanner.redact_text(input, None);
    println!("  Default:  {}", result.content.trim());

    // Custom replacement string
    let result = scanner.redact_text_with(input, None, "***MASKED***");
    println!("  Custom:   {}", result.content.trim());
    println!("  Redacted: {} secret(s)", result.redaction_count);
    println!();

    // ---------------------------------------------------------------
    // 5. Path-based filtering
    // ---------------------------------------------------------------
    println!("=== 5. Path-Based Filtering ===\n");

    let scanner = Scanner::default();
    let line = "GITHUB_TOKEN=ghp_xK4mN8pQ2rT6vW0yB3dF5hJ7lO9sU1wE3a5b";

    // Scan without a path — finds the secret
    let findings = scanner.scan_text(line, None);
    println!("  Without path: {} finding(s)", findings.len());

    // Scan with a path — path-only rules can match on the filename
    let findings = scanner.scan_text(line, Some("config/secrets.env"));
    println!("  With path:    {} finding(s)", findings.len());
}
