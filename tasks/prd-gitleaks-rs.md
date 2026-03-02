# PRD: `gitleaks-rs` — Gitleaks Rule Engine for Rust

## Introduction

[Gitleaks](https://github.com/gitleaks/gitleaks) is the industry-standard open-source secret scanner, with 222 rules covering API keys, tokens, passwords, and credentials from 100+ services. It is written in Go and its rule set is defined in a TOML config file (`config/gitleaks.toml`).

There is no Rust crate that implements the gitleaks rule engine. Existing Rust alternatives ([ripsecrets](https://github.com/sirwart/ripsecrets), [secretscan](https://crates.io/crates/secretscan)) use their own limited pattern sets and do not parse the gitleaks config format.

`gitleaks-rs` is a standalone Rust library crate that:
- Parses the gitleaks TOML config format (rules, allowlists, keywords, entropy thresholds)
- Embeds the official gitleaks rule set as a compile-time default
- Provides a fast, library-first API for detecting and redacting secrets in text
- Supports all gitleaks rule features: regex patterns, path filtering, Shannon entropy, keyword pre-filtering, capture group selection (`secretGroup`), and multi-layer allowlists (global + per-rule, with `regexTarget` and `condition` modifiers)

The crate is designed for embedding in other tools (like Cadence CLI) but is independently useful as a general-purpose secret detection library for any Rust project.

## Goals

- Implement a complete, spec-compliant gitleaks rule engine in Rust
- Parse and apply the official `gitleaks.toml` config format (all 222 rules, all features)
- Ship with the official gitleaks rule set embedded at compile time — zero configuration required
- Provide a clean, well-documented public API: load rules, scan text, get findings, redact secrets
- Achieve performance parity or better vs. the Go implementation through keyword pre-filtering and compiled regex caching
- Publish to crates.io as an independent crate with no Cadence-specific dependencies
- Support custom configs: users can load their own gitleaks.toml or extend the defaults

## User Stories

### US-001: TOML config parser

**Description:** As a developer, I need to parse gitleaks.toml config files into Rust data structures so that the rule engine can operate on them.

**Acceptance Criteria:**
- [ ] `Config` struct deserializable from gitleaks TOML format via `serde` + `toml` crate
- [ ] `Rule` struct with all fields:
  - `id: String` — unique rule identifier (required)
  - `description: String` — human-readable description (required)
  - `regex: Option<String>` — content-matching regex pattern
  - `path: Option<String>` — file path regex pattern
  - `entropy: Option<f64>` — Shannon entropy threshold for matched capture group
  - `keywords: Vec<String>` — lowercase pre-filter strings
  - `secret_group: Option<usize>` — which capture group is the secret (default: 0 = entire match, or 1 if groups exist)
  - `allowlists: Vec<RuleAllowlist>` — per-rule allowlists
- [ ] `Allowlist` struct (global) with fields:
  - `paths: Vec<String>` — file path regex patterns to skip
  - `regexes: Vec<String>` — patterns matched against captured secret values
  - `stopwords: Vec<String>` — substring matches that exempt a finding
- [ ] `RuleAllowlist` struct (per-rule) with fields:
  - `description: Option<String>`
  - `regexes: Vec<String>`
  - `regex_target: RegexTarget` — enum: `Secret` (default), `Match`, `Line`
  - `paths: Vec<String>`
  - `stopwords: Vec<String>`
  - `condition: Condition` — enum: `Or` (default), `And`
- [ ] `Config::from_toml(s: &str) -> Result<Config>` parses a TOML string
- [ ] `Config::from_file(path: &Path) -> Result<Config>` reads and parses a file
- [ ] `Config::default()` returns the embedded official gitleaks config
- [ ] Validation: error if a rule has neither `regex` nor `path`
- [ ] Validation: error if `secret_group` exceeds capture group count in regex
- [ ] Unit test: parse the official `gitleaks.toml` — all 222 rules load without error
- [ ] Unit test: parse a minimal config with one rule
- [ ] Unit test: parse a rule with all optional fields set
- [ ] Unit test: parse a rule with multiple allowlist blocks
- [ ] Unit test: reject a rule with neither `regex` nor `path`
- [ ] Unit test: reject invalid TOML

### US-002: Compiled rule engine

**Description:** As a developer, I need compiled regex patterns and keyword indexes so that rule matching is fast enough for scanning large files.

**Acceptance Criteria:**
- [ ] `Scanner` struct created from a `Config` — compiles all regexes at construction time
- [ ] `Scanner::new(config: Config) -> Result<Scanner>` compiles all rule regexes, path regexes, and allowlist regexes; returns error on invalid regex
- [ ] `Scanner::default()` builds from the embedded config
- [ ] Keyword index: a lookup structure (e.g., `AhoCorasick` automaton or `HashMap<&str, Vec<usize>>`) mapping keywords to rule indices for O(1) pre-filtering
- [ ] For each line being scanned: check keywords first, only run regexes for rules whose keywords appear in the line
- [ ] Rules without keywords (e.g., `pkcs12-file` path-only rule) are skipped during content scanning (they only apply to path filtering)
- [ ] Regex compilation happens once at `Scanner::new()`, not per-scan
- [ ] `Scanner` is `Send + Sync` — safe for concurrent use from multiple threads
- [ ] Unit test: `Scanner::default()` compiles all 222 rules without error
- [ ] Unit test: keyword pre-filtering correctly skips non-matching rules
- [ ] Benchmark: scanning 1 MB of text completes in < 100ms

### US-003: Shannon entropy calculator

**Description:** As a developer, I need a Shannon entropy function so that rules with entropy thresholds can filter low-randomness matches.

**Acceptance Criteria:**
- [ ] `fn shannon_entropy(s: &str) -> f64` computes Shannon entropy over the byte frequency distribution
- [ ] Formula: `-Σ p(x) × log₂(p(x))` where `p(x)` is the frequency of each distinct byte
- [ ] Empty string returns 0.0
- [ ] Single-character repeated string returns 0.0
- [ ] When a rule specifies `entropy`, the entropy of the captured secret group is checked against the threshold; if below, the match is discarded
- [ ] Unit test: `shannon_entropy("")` == 0.0
- [ ] Unit test: `shannon_entropy("aaaaaaaaaa")` ≈ 0.0
- [ ] Unit test: `shannon_entropy("abcdefghij")` > 3.0
- [ ] Unit test: `shannon_entropy("AKIAIOSFODNN7EXAMPLE")` > 3.5
- [ ] Unit test: entropy check discards a low-entropy match correctly

### US-004: Secret detection — line scanning

**Description:** As a developer, I need to scan individual lines of text and get back a list of findings so that I can detect secrets in any text input.

**Acceptance Criteria:**
- [ ] `Scanner::scan_line(line: &str, path: Option<&str>) -> Vec<Finding>` scans a single line
- [ ] `Finding` struct contains:
  - `rule_id: String` — which rule matched
  - `description: String` — the rule's description
  - `secret: String` — the matched secret value (from the appropriate capture group)
  - `match_text: String` — the full regex match text
  - `start: usize` — byte offset of the secret within the line
  - `end: usize` — byte offset of the end of the secret
  - `entropy: Option<f64>` — computed entropy of the secret (if rule has entropy threshold)
  - `line_number: Option<usize>` — populated by multi-line scanning functions
- [ ] Keyword pre-filtering: only rules whose keywords appear in the line are evaluated
- [ ] Regex matching: for each candidate rule, apply the compiled regex; if it matches, extract the secret from `secret_group` (default: first capture group, or entire match if no groups)
- [ ] Entropy check: if the rule has an `entropy` threshold, compute Shannon entropy of the secret; discard if below threshold
- [ ] Global allowlist check: if the secret matches any global allowlist regex, or contains any global stopword, discard the finding
- [ ] Per-rule allowlist check: evaluate each rule's allowlists with their `regex_target` and `condition` settings; discard the finding if any allowlist matches
- [ ] Path filtering: if `path` is provided and a rule has a `path` pattern, only apply the rule if the path matches
- [ ] Multiple findings per line are supported (different rules can match different secrets)
- [ ] Unit test: line containing `AKIAIOSFODNN7EXAMPLE` produces a finding with `rule_id = "aws-access-token"`
- [ ] Unit test: line containing `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` produces a finding with `rule_id = "github-pat"`
- [ ] Unit test: line containing no secrets produces zero findings
- [ ] Unit test: allowlisted secret (e.g., template variable `{{API_KEY}}`) produces zero findings
- [ ] Unit test: low-entropy match is discarded when rule has entropy threshold
- [ ] Unit test: per-rule allowlist with `regex_target = "line"` correctly exempts a line
- [ ] Unit test: per-rule allowlist with `condition = "AND"` requires both path and regex to match

### US-005: Secret detection — multi-line and file scanning

**Description:** As a developer, I need to scan multi-line text and files to get findings with line numbers.

**Acceptance Criteria:**
- [ ] `Scanner::scan_text(text: &str, path: Option<&str>) -> Vec<Finding>` splits on newlines, scans each line, populates `line_number` (1-indexed)
- [ ] `Scanner::scan_file(path: &Path) -> Result<Vec<Finding>>` reads a file and scans it, using the file path for path-based rules
- [ ] Path-only rules (like `pkcs12-file`): `scan_file` checks the file path against path-only rules and produces findings without content matching
- [ ] Global allowlist path filtering: files matching global allowlist paths are skipped entirely by `scan_file`
- [ ] Lines with multiple findings report all of them
- [ ] Blank lines are skipped (no regex evaluation)
- [ ] Unit test: scan multi-line text with secrets on different lines, verify line numbers
- [ ] Unit test: `scan_file` on a `.p12` file produces a `pkcs12-file` finding
- [ ] Unit test: `scan_file` on a file matching a global allowlist path produces zero findings

### US-006: Secret redaction

**Description:** As a developer, I need to redact detected secrets from text, replacing them with a placeholder while preserving the surrounding text.

**Acceptance Criteria:**
- [ ] `Scanner::redact_line(line: &str, path: Option<&str>) -> RedactResult` detects and replaces secrets in a single line
- [ ] `Scanner::redact_text(text: &str, path: Option<&str>) -> RedactResult` processes multi-line text
- [ ] `RedactResult` struct contains:
  - `content: String` — the redacted text
  - `findings: Vec<Finding>` — what was found and redacted
  - `redaction_count: usize` — number of replacements made
- [ ] Default replacement: `REDACTED`
- [ ] `Scanner::redact_line_with(line: &str, path: Option<&str>, replacement: &str) -> RedactResult` allows custom replacement text
- [ ] Replacement is applied to the **secret** portion only (from `Finding::start` to `Finding::end`), preserving the surrounding line text
- [ ] Multiple secrets in one line are all redacted (process from right to left to preserve byte offsets)
- [ ] Redaction is idempotent: redacting already-redacted text produces the same output
- [ ] Unit test: line with AWS key is redacted, surrounding text preserved
- [ ] Unit test: line with two secrets has both redacted
- [ ] Unit test: already-redacted line round-trips unchanged
- [ ] Unit test: custom replacement string works

### US-007: Embedded default config

**Description:** As a developer, I want the official gitleaks rule set available out-of-the-box so that consumers of the crate don't need to manage config files.

**Acceptance Criteria:**
- [ ] The official `gitleaks.toml` is embedded at compile time via `include_str!()` or `include_bytes!()`
- [ ] The embedded config is vendored into the crate's source tree (e.g., `src/default_config.toml`) with a comment noting the upstream source and version
- [ ] `Config::default()` parses the embedded config
- [ ] `Scanner::default()` uses the embedded config
- [ ] A `build.rs` or CI script documents how to update the vendored config from upstream
- [ ] The vendored config version is recorded (e.g., `pub const GITLEAKS_CONFIG_VERSION: &str = "v8.25.0"`)
- [ ] Unit test: `Config::default()` loads all 222 rules
- [ ] Unit test: `Scanner::default()` compiles all rules without error

### US-008: Custom config support

**Description:** As a developer, I want to load custom configs, merge with defaults, or build configs programmatically.

**Acceptance Criteria:**
- [ ] `Config::from_toml(s: &str)` loads a custom config, completely replacing the defaults
- [ ] `Config::default().extend(other: Config)` merges another config on top: adds new rules, appends to global allowlist
- [ ] `ConfigBuilder` for programmatic rule construction:
  - `ConfigBuilder::new()` starts empty
  - `.add_rule(Rule)` adds a rule
  - `.set_allowlist(Allowlist)` sets the global allowlist
  - `.build() -> Result<Config>` validates and produces a config
- [ ] Rules can be added individually: `config.rules.push(rule)` (fields are public)
- [ ] Unit test: custom config with one rule works
- [ ] Unit test: `extend` adds new rules without removing defaults
- [ ] Unit test: `ConfigBuilder` produces a valid config

### US-009: Public API documentation and crate packaging

**Description:** As a crate author, I need the public API well-documented and the crate properly packaged for crates.io.

**Acceptance Criteria:**
- [ ] All public types, functions, and methods have `///` doc comments with examples
- [ ] Crate-level documentation (`//!` in `lib.rs`) with:
  - Overview and motivation
  - Quick-start example: `Scanner::default()` → `scan_text()` → print findings
  - Redaction example: `Scanner::default()` → `redact_text()` → output
  - Custom config example
- [ ] `Cargo.toml` configured for crates.io publishing:
  - `name = "gitleaks-rs"`
  - `license = "MIT"` (or MIT/Apache-2.0 dual, matching gitleaks's MIT license)
  - `description`, `repository`, `keywords`, `categories` set
  - `readme = "README.md"`
- [ ] `README.md` with usage examples, feature list, and link to gitleaks upstream
- [ ] `#![deny(missing_docs)]` enforced
- [ ] `cargo doc --no-deps` builds cleanly
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes

## Functional Requirements

- FR-1: The crate must parse the official gitleaks TOML config format, including all rule fields (`id`, `description`, `regex`, `path`, `entropy`, `keywords`, `secretGroup`), global allowlists (`paths`, `regexes`, `stopwords`), and per-rule allowlists (`regexes`, `regex_target`, `paths`, `stopwords`, `condition`)
- FR-2: All 222 rules from the official `gitleaks.toml` must load and compile without error
- FR-3: Keyword pre-filtering must be applied before regex evaluation — rules whose keywords do not appear in the input line must be skipped
- FR-4: Shannon entropy must be computed on the captured secret group and compared against the rule's `entropy` threshold; matches below the threshold are discarded
- FR-5: `secretGroup` must select which regex capture group contains the secret; default behavior is to use the first capture group (or entire match if no groups)
- FR-6: Global allowlists must be evaluated before per-rule allowlists; a match on either discards the finding
- FR-7: Per-rule allowlists must support `regexTarget` values `Secret`, `Match`, and `Line`, and `condition` values `Or` and `And`
- FR-8: Redaction must replace only the secret portion of a match, preserving surrounding text
- FR-9: The crate must ship with the official gitleaks rule set embedded at compile time
- FR-10: The `Scanner` must be `Send + Sync` for safe concurrent use
- FR-11: The crate must have zero non-Rust dependencies (no Go binary, no FFI)

## Non-Goals

- CLI binary — this crate is library-only; consumers build their own CLI or embed it
- Git history scanning — the crate scans text, not git diffs or commit history (consumers can feed git content to it)
- Gitleaks output format compatibility (JSON report format) — consumers format findings however they want
- Automatic config updates from upstream gitleaks — the vendored config is updated manually
- `minVersion` enforcement — the crate does not validate the `minVersion` field against a gitleaks binary version
- Scanning directories or walking file trees — consumers handle filesystem traversal and pass content to the scanner
- Network-based rule fetching or rule update checking

## Technical Considerations

- **Crate dependencies:**
  - `toml` + `serde` + `serde_derive` — config parsing
  - `regex` — pattern matching (the `regex` crate compiles to DFA, which is fast for many patterns)
  - `aho-corasick` — keyword pre-filtering (multi-pattern string search in O(n) time; the `regex` crate already depends on this transitively)
  - No other dependencies required

- **Regex compilation cost:** Compiling 222 regexes takes ~10-50ms. This is a one-time cost at `Scanner::new()`. Individual `RegexSet` won't work here because we need per-rule capture groups and entropy checks. Instead, compile each rule's regex individually and store as `Vec<CompiledRule>`.

- **Keyword pre-filtering performance:** The 221 rules with keywords produce ~300-400 total keywords. An `AhoCorasick` automaton over these keywords enables single-pass O(n) matching against each input line. On a typical line (< 200 bytes), this takes < 1μs. Only rules whose keywords matched are evaluated with their (more expensive) regexes. This is the same strategy gitleaks uses in Go.

- **Entropy computation:** Shannon entropy is O(n) over the secret string length. Since secrets are typically < 100 characters, this is negligible.

- **Allowlist evaluation order:** For each potential finding: (1) check global stopwords, (2) check global regexes, (3) check per-rule allowlists. Short-circuit on first match.

- **`secretGroup` semantics:** Gitleaks defaults to the entire match (group 0) when `secretGroup` is not specified, but in practice most rules have a single capture group and use group 1. The Go code defaults to the highest-numbered capture group if `secretGroup` is 0. We should match this behavior exactly.

- **Redaction byte offset handling:** When redacting multiple secrets in one line, process findings from right to left so that byte offsets remain valid after each replacement.

- **Config versioning:** The vendored `gitleaks.toml` should be pinned to a specific upstream commit or release tag. Include a comment in the file and a `GITLEAKS_CONFIG_VERSION` constant. Document the update process (fetch latest from upstream, replace file, run tests, bump crate version).

- **License:** `gitleaks-rs` is MIT-licensed. Gitleaks upstream is also MIT-licensed, so vendoring its TOML config file is fully compatible.

- **Crate location:** This crate lives in its own repository (e.g., `github.com/TeamCadenceAI/gitleaks-rs`) and is published to crates.io. Cadence CLI depends on it as an external crate. It does NOT live inside the cadence-cli repo.

- **Testing against upstream:** Include a test that parses the vendored `gitleaks.toml`, runs all rules against the gitleaks project's own test fixtures (if available), and verifies detection of known secret patterns from the gitleaks README examples.

## Success Metrics

- All 222 rules from the official `gitleaks.toml` parse and compile without error
- Detection of the top 20 secret types matches gitleaks Go implementation (validated against shared test vectors)
- Keyword pre-filtering reduces regex evaluations by > 95% on typical source code
- Scanning 1 MB of text completes in < 100ms on a modern machine
- `Scanner::new()` (compile time) completes in < 100ms
- Zero false negatives on gitleaks's own test cases (where available)
- Crate published to crates.io with > 90% doc coverage

## Open Questions

*All resolved — using best judgement:*

| Question | Resolution |
|----------|-----------|
| Should this be a workspace crate inside cadence-cli? | **No**. Separate repo and crate. It's independently useful and should not depend on cadence internals. Cadence depends on it, not the other way around. |
| Which gitleaks config version to vendor? | **Latest stable at time of implementation** (currently v8.25.0+). Pin to a specific commit hash. |
| Should we support gitleaks's `[extend]` directive? | **Not in v1**. The `extend` directive lets gitleaks configs inherit from other files/URLs. We support `Config::extend()` programmatically, but not the TOML `[extend]` syntax. |
| Should we expose individual rule matching? | **Yes**. `Scanner::scan_line` returns `Vec<Finding>` with `rule_id` — consumers can filter by rule. We should also expose `Scanner::rules()` to list available rules. |
| `aho-corasick` vs `HashMap` for keyword index? | **`aho-corasick`**. It's already a transitive dependency, and its multi-pattern matching is purpose-built for this use case. |
| Should we support the `tags` field on rules? | **No**. The current gitleaks.toml has no `tags` fields. If upstream adds them later, we can add support in a future version. |
