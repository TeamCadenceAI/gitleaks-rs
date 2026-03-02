# gitleaks-rs

[![CI](https://github.com/TeamCadenceAI/gitleaks-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/TeamCadenceAI/gitleaks-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[GitHub](https://github.com/TeamCadenceAI/gitleaks-rs)

## Overview

`gitleaks-rs` is a Rust implementation of the [gitleaks](https://github.com/gitleaks/gitleaks) secret detection rule engine. It parses the gitleaks TOML config format and provides a fast, library-first API for detecting and redacting secrets in text.

The crate ships with the **official 222-rule gitleaks config embedded at compile time** — zero configuration required. Just create a `Scanner` and start scanning.

**How it works:**

1. **Keyword pre-filter** — an Aho-Corasick automaton checks each line for rule keywords, skipping >95% of regex evaluations
2. **Regex matching** — only rules whose keywords appear in the line are evaluated
3. **Entropy filtering** — Shannon entropy discards low-randomness matches (placeholders, examples)
4. **Allowlists** — global and per-rule allowlists suppress false positives by path, regex, or stopword

## Installation

Add `gitleaks-rs` to your `Cargo.toml`:

```toml
[dependencies]
gitleaks-rs = "0.1"
```

## Example

```rust
use gitleaks_rs::Scanner;

fn main() {
    let scanner = Scanner::default();

    let text = r#"
export AWS_ACCESS_KEY_ID=AKIAQWERTYUIO2QBKPXN
export GITHUB_TOKEN=ghp_xK4mN8pQ2rT6vW0yB3dF5hJ7lO9sU1wE3a5b
safe_variable = "hello world"
"#;

    let findings = scanner.scan_text(text, None);

    for f in &findings {
        println!(
            "[{}] line {} — {} (secret: {})",
            f.rule_id,
            f.line_number.unwrap(),
            f.description,
            f.secret,
        );
    }

    println!("\n{} secret(s) found", findings.len());
}
```

## More Examples

The [`examples/`](examples/) directory contains runnable examples:

| Example | Description |
|---------|-------------|
| [`basic`](examples/basic.rs) | Scan a string for secrets and print findings |
| [`advanced`](examples/advanced.rs) | Custom rules, extending defaults, redaction, path filtering |

```sh
cargo run --example basic
cargo run --example advanced
```

## Features

- **222 built-in rules** — the official gitleaks rule set is embedded at compile time
- **Keyword pre-filtering** — Aho-Corasick automaton skips rules whose keywords are absent, reducing regex evaluations by >95%
- **Shannon entropy filtering** — discards low-randomness matches (placeholders, examples)
- **Global and per-rule allowlists** — suppress findings by path, regex, or stopword
- **Secret redaction** — replace detected secrets with a configurable replacement string
- **Custom configs** — load your own TOML rules, build configs programmatically with `ConfigBuilder`, or extend the defaults
- **File scanning** — scan files from disk with path-based rule matching
- **Zero non-Rust dependencies** — no Go binary, no FFI
- **Thread-safe** — `Scanner` is `Send + Sync`, shareable via `Arc<Scanner>`

## API Overview

| Type | Purpose |
|------|---------|
| [`Config`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.Config.html) | Parsed gitleaks TOML config (rules + allowlists) |
| [`Scanner`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.Scanner.html) | Precompiled rule engine — `scan_line`, `scan_text`, `scan_file`, `redact_*` |
| [`Finding`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.Finding.html) | A detected secret (rule ID, secret value, offsets, entropy) |
| [`RedactResult`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.RedactResult.html) | Redacted text + findings + replacement count |
| [`ConfigBuilder`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/struct.ConfigBuilder.html) | Programmatic config construction (no TOML needed) |
| [`Error`](https://docs.rs/gitleaks-rs/latest/gitleaks_rs/enum.Error.html) | Parse, validation, I/O, and regex errors |

## Performance

`gitleaks-rs` is designed for embedding in latency-sensitive tools:

- **Keyword pre-filtering** eliminates >95% of regex evaluations — most lines never touch the regex engine
- **One-time compilation** — all regexes and the Aho-Corasick automaton are built once at `Scanner::new()`, not per scan
- **Design goal: <100ms** to scan 1 MB of text with all 222 rules (not yet benchmarked)
- **Design goal: <100ms** for `Scanner::new()` cold start (not yet benchmarked)

## Getting Help

- **API docs:** <https://docs.rs/gitleaks-rs>
- **Bug reports & feature requests:** [GitHub Issues](https://github.com/TeamCadenceAI/gitleaks-rs/issues)

## Contributing

Contributions are welcome! Please open an issue to discuss your idea before submitting a pull request. See [GitHub Issues](https://github.com/TeamCadenceAI/gitleaks-rs/issues) for known work items.

## Supported Rust Versions

`gitleaks-rs` is built against the latest stable Rust release. No MSRV policy has been established yet.

## Related Projects

- **[gitleaks](https://github.com/gitleaks/gitleaks)** — the upstream Go implementation by Zach Rice. `gitleaks-rs` implements the same rule engine and uses the same TOML config format (v8.25.0).
- **[ripsecrets](https://github.com/sirwart/ripsecrets)** — a Rust secret scanner with its own pattern set. Does not parse the gitleaks config format.
- **[secretscan](https://crates.io/crates/secretscan)** — another Rust secret scanner with a custom rule engine. Does not support the gitleaks rule set.

`gitleaks-rs` differs by implementing the full gitleaks rule engine (keywords, entropy, allowlists, `secretGroup`, `regexTarget`, `condition`) and embedding the official 222-rule config.

## License

MIT
