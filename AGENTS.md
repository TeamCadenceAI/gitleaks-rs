# AGENTS.md

## Project Overview

`gitleaks-rs` is a Rust library crate that implements the [gitleaks](https://github.com/gitleaks/gitleaks) secret detection rule engine. It parses the gitleaks TOML config format and provides a fast API for detecting and redacting secrets in text. The official 222-rule gitleaks config is embedded at compile time.

**Stack**: Pure Rust (no FFI, no Go dependency). Dependencies: `regex`, `aho-corasick`, `serde`, `toml`.

## Crate Layout

```
src/
  lib.rs              — Public re-exports and crate-level docs
  config.rs           — TOML config parsing, Rule/Allowlist types, validation
  scanner.rs          — Compiled rule engine (regex + Aho-Corasick keyword index)
  builder.rs          — Programmatic ConfigBuilder (no TOML needed)
  finding.rs          — Finding type (detected secret result)
  redact.rs           — RedactResult type and replacement mechanics
  entropy.rs          — Shannon entropy calculator
  error.rs            — Error enum (Validation, Toml, Regex, Io)
  default_config.toml — Embedded official gitleaks rule set (222 rules)
examples/
  basic.rs            — Simple: scan text, print findings
  advanced.rs         — Custom configs, ConfigBuilder, redaction, path filtering
tests/
  builder_api.rs      — Integration tests for ConfigBuilder
  entropy_api.rs      — Integration tests for entropy API
  redact_api.rs       — Integration tests for redaction
  scan_file_api.rs    — Integration tests for file scanning
```

Entry point: `src/lib.rs` (library crate, no binary).

## Quick Commands

### Build

```bash
cargo build                # debug build
cargo build --release      # release build
```

### Test

```bash
cargo test                 # run all tests (unit + integration + doc-tests)
cargo test scanner         # run tests matching "scanner"
cargo test --test scan_file_api  # run a specific integration test file
```

### Examples

```bash
cargo run --example basic     # scan text for secrets, print findings
cargo run --example advanced  # custom configs, redaction, path filtering
```

### Docs

```bash
cargo doc --no-deps --open   # build and open API docs
```

### Lint & Format

```bash
cargo fmt                  # format code
cargo fmt -- --check       # check formatting (CI mode)
cargo clippy               # lint
```

## Using the cargo-agent Skill

When the `cargo-agent` skill is available (in Claude Code), **always prefer it** over raw `cargo` commands for checking, linting, formatting, and testing. It wraps `cargo fmt`, `cargo clippy`, and `cargo test` into a single command with structured, agent-friendly output that highlights diagnostics clearly.

```bash
# Run all checks (fmt + clippy + test):
cargo-agent

# Run only tests:
cargo-agent test

# Run specific tests:
cargo-agent test scanner

# Run only clippy:
cargo-agent clippy

# Run only fmt check:
cargo-agent fmt
```

The skill produces structured output with clear pass/fail summaries. Use it as the default for any verify/check/lint/test workflow.

## Workflow Rules

### Definition of Done

1. **Write tests.** Every change must include tests — unit tests in `#[cfg(test)]` modules, integration tests in `tests/`.
2. **Run checks.** Use `cargo-agent` (if available) or `cargo fmt --check && cargo clippy && cargo test`. Resolve all warnings and errors.
3. **Commit.** Each logical change gets its own commit.

### Code Style

- Follow existing patterns in the codebase
- `#![deny(missing_docs)]` is enabled — all public items must have doc comments
- Keep dependencies minimal — this is a library crate meant for embedding

### Guardrails

- Do not add binary targets — this is a library-only crate
- Do not add non-Rust dependencies (no FFI, no build scripts calling external tools)
- Do not modify `src/default_config.toml` unless upgrading the upstream gitleaks rule set
- Keep the public API surface small — only re-export types that downstream users need
