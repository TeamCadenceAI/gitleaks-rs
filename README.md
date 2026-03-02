# gitleaks-rs

[![Crates.io](https://img.shields.io/crates/v/gitleaks-rs.svg)](https://crates.io/crates/gitleaks-rs)
[![docs.rs](https://docs.rs/gitleaks-rs/badge.svg)](https://docs.rs/gitleaks-rs)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust implementation of the [gitleaks](https://github.com/gitleaks/gitleaks) secret detection rule engine. Ships with the official 222-rule config embedded at compile time — zero configuration required.

## Features

- **222 built-in rules** — the official gitleaks rule set is embedded at compile time
- **Keyword pre-filtering** — Aho-Corasick automaton skips rules whose keywords are absent, reducing regex evaluations by >95%
- **Shannon entropy filtering** — discards low-randomness matches (placeholders, examples)
- **Global and per-rule allowlists** — suppress findings by path, regex, or stopword
- **Secret redaction** — replace detected secrets with a configurable replacement string
- **Custom configs** — load your own TOML rules, build configs programmatically, or extend the defaults
- **Zero non-Rust dependencies** — no Go binary, no FFI
- **Thread-safe** — `Scanner` is `Send + Sync`

## Quick Start

```rust
use gitleaks_rs::{Config, Scanner};

// Load the embedded official gitleaks rule set
let config = Config::default().expect("embedded config is valid");
let scanner = Scanner::new(config).unwrap();

// Scan a string for secrets
let findings = scanner.scan_text(input_text, None);

for f in &findings {
    println!("[{}] line {} — {}", f.rule_id, f.line_number.unwrap(), f.secret);
}
```

Or use `Scanner::default()` to skip the explicit config step:

```rust
use gitleaks_rs::Scanner;

let scanner = Scanner::default();
assert!(scanner.rule_count() >= 222);
```

## Redaction

```rust
use gitleaks_rs::{Config, Scanner};

let config = Config::from_toml(r#"
[[rules]]
id = "api-key"
description = "API key"
regex = '''api_key\s*=\s*"([^"]+)"'''
keywords = ["api_key"]
"#).unwrap();
let scanner = Scanner::new(config).unwrap();
let result = scanner.redact_text(
    "api_key = \"sk_live_a1b2c3d4e5f6\"\n",
    None,
);
assert!(result.content.contains("REDACTED"));
```

## Custom Config

Build rules programmatically with `ConfigBuilder`:

```rust
use gitleaks_rs::{ConfigBuilder, Rule, Scanner};

let config = ConfigBuilder::new()
    .title("my project rules")
    .add_rule(Rule {
        id: "internal-token".into(),
        description: Some("Internal API token".into()),
        regex: Some(r"INTERNAL_[A-Z0-9]{32}".into()),
        keywords: vec!["internal_".into()],
        ..Default::default()
    })
    .build()
    .expect("valid config");

let scanner = Scanner::new(config).unwrap();
```

Or extend the built-in rules with your own:

```rust
use gitleaks_rs::{Config, ConfigBuilder, Rule, Scanner};

let defaults = Config::default().unwrap();
let custom = ConfigBuilder::new()
    .add_rule(Rule {
        id: "my-rule".into(),
        regex: Some(r"MY_SECRET_[a-zA-Z0-9]{16}".into()),
        keywords: vec!["my_secret_".into()],
        ..Default::default()
    })
    .build()
    .unwrap();

let merged = defaults.extend(custom);
let scanner = Scanner::new(merged).unwrap();
assert!(scanner.rule_count() > 222);
```

## API Overview

| Type | Purpose |
|------|---------|
| [`Config`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.Config.html) | Parsed gitleaks TOML config (rules + allowlists) |
| [`Scanner`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.Scanner.html) | Precompiled rule engine — `scan_line`, `scan_text`, `scan_file`, `redact_*` |
| [`Finding`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.Finding.html) | A detected secret (rule ID, secret value, offsets, entropy) |
| [`RedactResult`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.RedactResult.html) | Redacted text + findings + replacement count |
| [`ConfigBuilder`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.ConfigBuilder.html) | Programmatic config construction (no TOML needed) |
| [`Error`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/enum.Error.html) | Parse, validation, I/O, and regex errors |

## Upstream

This crate implements the rule engine from [gitleaks](https://github.com/gitleaks/gitleaks) by Zach Rice. The embedded rule set is from gitleaks v8.25.0.

## License

MIT
