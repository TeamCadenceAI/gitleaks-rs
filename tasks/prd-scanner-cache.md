# PRD: Disk-Cached DFA Serialization (`Scanner::new_with_cache`)

## Introduction

`Scanner::new()` eagerly compiles all 222 regex patterns from the embedded gitleaks config, taking ~30-40 seconds. This makes repeated Scanner construction (e.g., across process restarts, CLI invocations, or test runs) painfully slow.

This feature adds `Scanner::new_with_cache(cache_path)` — a feature-gated constructor that serializes compiled DFA automata to disk via `regex-automata` and loads them in constant time on subsequent runs. The API always uses the default embedded config and requires only a file path for the cache location.

### Core Technical Challenge

`regex::Regex` is not serializable. `regex-automata` sparse DFAs are serializable but cannot extract capture groups. The scanner's content regexes use `captures_iter()` for secret extraction. The solution is a **hybrid DFA + lazy Regex** approach: serialize DFAs for fast `is_match()` prefiltering, and lazily compile `regex::Regex` via `OnceLock` only when captures are actually needed (typically 3-10 of 222 rules per scan).

## Goals

- Provide `Scanner::new_with_cache(path)` that is near-instant on cache hit (< 1 second)
- Automatic cache invalidation when embedded config or crate version changes
- Graceful fallback to full compilation on any cache failure (corrupt, missing, I/O error)
- Zero impact on existing `Scanner::new()` behavior
- Feature-gated behind `cache` Cargo feature to keep default dependency footprint minimal
- All new public API items documented (`#![deny(missing_docs)]` enforced)

## User Stories

**Definition of Done (applies to all stories):**
- All acceptance criteria met
- `cargo fmt -- --check` passes
- `cargo clippy --features cache` passes with no warnings
- Tests written and passing (`cargo test` without feature + `cargo test --features cache`)
- Code formatted

### US-001: Add `cache` feature flag and optional dependencies

**Description:** As a library consumer, I need the cache functionality gated behind an opt-in Cargo feature so my default build isn't burdened with extra dependencies.

**Acceptance Criteria:**
- [ ] `[features]` section added to `Cargo.toml` with `cache = ["dep:regex-automata", "dep:sha2", "dep:bincode"]`
- [ ] `regex-automata = { version = "0.4", features = ["dfa-build", "dfa-search", "syntax"], optional = true }`
- [ ] `sha2 = { version = "0.10", optional = true }`
- [ ] `bincode = { version = "1", optional = true }`
- [ ] `cargo build` succeeds without `--features cache` (no regressions to existing behavior)
- [ ] `cargo build --features cache` succeeds

### US-002: Add `Cache` error variant

**Description:** As a developer implementing the cache, I need a dedicated error variant for cache-specific failures so they can be caught internally and trigger graceful fallback to `Scanner::new()`.

**Acceptance Criteria:**
- [ ] `Error::Cache(String)` variant added to `src/error.rs`, gated behind `#[cfg(feature = "cache")]`
- [ ] `Display` impl outputs `"cache error: {msg}"`
- [ ] `source()` returns `None` for the `Cache` variant
- [ ] Existing error tests still pass without `--features cache`
- [ ] New unit test for `Cache` variant display

### US-003: Add `ContentRegex` wrapper type

**Description:** As a developer implementing the cache, I need a wrapper type for content regexes that supports both eager compilation (existing `Scanner::new()` path) and cached DFA + lazy Regex (cache hit path). Content regexes need capture group extraction, which DFAs cannot provide — so the wrapper uses a DFA for fast `is_match()` prefiltering and lazily compiles a `regex::Regex` only when captures are needed.

**Acceptance Criteria:**
- [ ] `ContentRegex` enum defined in `src/scanner.rs` with variants:
  - `Eager(Regex)` — standard compiled regex (non-cached path)
  - `Cached { dfa_bytes: Vec<u8>, pattern: String, regex: OnceLock<Regex> }` — `#[cfg(feature = "cache")]`
  - `LazyOnly { pattern: String, regex: OnceLock<Regex> }` — `#[cfg(feature = "cache")]`, for patterns where DFA build failed
- [ ] `is_match(&self, text: &str) -> bool` implemented:
  - `Eager`: delegates to `Regex::is_match()`
  - `Cached`: deserializes sparse DFA via safe `from_bytes()`, runs `try_search_fwd()`
  - `LazyOnly`: lazily compiles regex, delegates to `Regex::is_match()`
- [ ] `captures_iter(&self, text: &str)` implemented:
  - `Eager`: delegates directly to `Regex::captures_iter()`
  - `Cached`/`LazyOnly`: lazily compiles `regex::Regex` via `OnceLock::get_or_init()`, then delegates
- [ ] `Debug` impl shows variant name + pattern string
- [ ] Type is `Send + Sync` (verified by compile-time assertion or test)
- [ ] Unit tests: `Eager` variant `is_match()` and `captures_iter()` delegate correctly

### US-004: Add `MatchOnlyRegex` wrapper type

**Description:** As a developer implementing the cache, I need a wrapper for path regexes and allowlist regexes that only supports `is_match()`, backed by either an eager `Regex` or a serialized sparse DFA.

**Acceptance Criteria:**
- [ ] `MatchOnlyRegex` enum defined in `src/scanner.rs` with variants:
  - `Eager(Regex)` — standard compiled regex
  - `Dfa(Vec<u8>)` — `#[cfg(feature = "cache")]`, serialized sparse DFA bytes
- [ ] `is_match(&self, text: &str) -> bool` implemented:
  - `Eager`: delegates to `Regex::is_match()`
  - `Dfa`: deserializes sparse DFA via safe `from_bytes()`, runs `try_search_fwd()`
- [ ] `Debug` impl
- [ ] Type is `Send + Sync`
- [ ] Unit tests for each variant

### US-005: Refactor scanner internals to use wrapper types

**Description:** As a developer, I need to swap all internal `Regex` fields to the new wrapper types and update all call sites so the scanner works identically through the wrapper layer, with zero behavior change when the `cache` feature is not enabled.

**Acceptance Criteria:**
- [ ] Field type changes (all `pub(crate)`, no public API impact):
  - `CompiledRule.content_regex`: `Option<Regex>` -> `Option<ContentRegex>`
  - `CompiledRule.path_regex`: `Option<Regex>` -> `Option<MatchOnlyRegex>`
  - `CompiledRuleAllowlist.regexes` / `.paths`: `Vec<Regex>` -> `Vec<MatchOnlyRegex>`
  - `CompiledGlobalAllowlist.regexes` / `.paths`: `Vec<Regex>` -> `Vec<MatchOnlyRegex>`
- [ ] Compilation functions updated to wrap results in `::Eager` variants:
  - `compile_rule()`, `compile_regex_list()`, `compile_regex_with_context()`, `compile_rule_allowlist()`, `compile_global_allowlist()`
- [ ] All call sites updated to use `.is_match()` and `.captures_iter()` through wrappers:
  - `scan_line()`, `is_globally_allowlisted()`, `is_rule_allowlisted()`, `allowlist_entry_matches()`, `evaluate_path_only_rules()`, `is_global_path_allowlisted()`
- [ ] `scan_line()` adds DFA prefilter: `if !content_regex.is_match(line) { continue; }` before `captures_iter()`
- [ ] All existing tests pass with zero behavior change (no `--features cache` needed)
- [ ] `Scanner` remains `Send + Sync` (existing compile-time assertion at `scanner.rs:113` still passes)

### US-006: Implement cache serialization (write path)

**Description:** As a developer implementing the cache, I need a module that computes a config hash from the embedded TOML, builds sparse DFAs from regex patterns, and writes the cache file to disk.

**Acceptance Criteria:**
- [ ] New `src/cache.rs` module, conditionally compiled with `#[cfg(feature = "cache")]`
- [ ] `compute_config_hash() -> [u8; 32]`: SHA-256 hashes the embedded `default_config.toml` string (`include_str!` constant from `config.rs`)
- [ ] `try_build_sparse_dfa(pattern: &str) -> Option<Vec<u8>>`:
  - Applies `go_re2_compat()` preprocessing before DFA construction
  - Builds dense DFA via `regex_automata::dfa::dense::Builder` with 10MB `dfa_size_limit` / 20MB `determinize_size_limit`
  - Converts to sparse DFA, serializes via `to_bytes_native_endian()`
  - Returns `None` on DFA build failure (state explosion, size limit exceeded)
- [ ] `try_save(path, config_hash, config) -> Result<()>`: writes cache file with binary format:
  - Header: magic `b"GLRS_DFA"` (8 bytes), format version `u16 LE`, SHA-256 hash (32 bytes), crate version null-padded to 16 bytes
  - Metadata: `u32 LE` length prefix + bincode-encoded `CacheMetadata` struct containing:
    - Per-rule: id, description, has_content_dfa, content_pattern (post-`go_re2_compat`), has_path_dfa, entropy, secret_group, keywords, allowlist metadata (dfa_count, regex_target, stopwords, condition)
    - Keywords list, keyword_to_rules mapping, path_only_indices
    - Global allowlist metadata
  - DFA blobs: each preceded by `u32 LE` length (0 = no DFA for this slot), deterministic order: per rule (content DFA, path DFA, per-allowlist regex DFAs + path DFAs), then global allowlist DFAs
- [ ] Unit tests:
  - Config hash is deterministic (same output across calls)
  - Simple pattern builds DFA successfully
  - Pathological pattern (state explosion) returns `None`

### US-007: Implement cache deserialization (read path)

**Description:** As a developer implementing the cache, I need the cache module to read a cache file, validate its header, and reconstruct a full `Scanner` from cached DFAs and metadata — without compiling any regexes upfront.

**Acceptance Criteria:**
- [ ] `try_load(path, config_hash) -> Result<Scanner>`: reads cache file, validates header
- [ ] Returns `Error::Cache` on any of: missing file, wrong magic bytes, wrong format version, config hash mismatch, crate version mismatch, truncated file, bincode deserialization failure, DFA `from_bytes()` validation failure
- [ ] On valid cache, reconstructs `Scanner` with:
  - `ContentRegex::Cached` (DFA + pattern) or `ContentRegex::LazyOnly` (pattern only) for content regexes
  - `MatchOnlyRegex::Dfa` for path regexes and all allowlist regexes
  - `AhoCorasick` rebuilt from stored keyword strings (not cached — fast <1ms rebuild)
  - `keyword_to_rules` and `path_only_indices` restored from cached metadata
- [ ] Unit tests:
  - Roundtrip: save then load produces a Scanner that finds secrets correctly
  - Wrong config hash returns `Error::Cache`
  - Wrong crate version returns `Error::Cache`
  - Corrupt magic bytes returns `Error::Cache`
  - Truncated file returns `Error::Cache`

### US-008: Add `Scanner::new_with_cache(path)` public constructor

**Description:** As a library consumer, I want a simple `Scanner::new_with_cache(cache_path)` that uses the default embedded config and transparently manages a disk cache, so my app starts near-instantly after the first run.

**Acceptance Criteria:**
- [ ] Signature: `#[cfg(feature = "cache")] pub fn new_with_cache(cache_path: impl AsRef<Path>) -> Result<Self>`
- [ ] Always uses `Config::default()` (the embedded 222-rule config)
- [ ] On cache hit: loads from disk, returns `Scanner` (near-instant, no regex compilation)
- [ ] On cache miss: calls `Scanner::new(Config::default())`, writes cache to `cache_path` (best-effort, I/O errors silently ignored), returns `Scanner`
- [ ] On cache failure (corrupt file, wrong version, any `Error::Cache`): silently falls back to `Scanner::new(Config::default())`
- [ ] Doc comment with `# Example` block (using `no_run`):
  ```rust
  let scanner = Scanner::new_with_cache("/tmp/gitleaks.cache").unwrap();
  let findings = scanner.scan_text("AKIAIOSFODNN7EXAMPLE", None);
  ```
- [ ] `#[cfg(feature = "cache")] pub(crate) mod cache;` added to `src/lib.rs`
- [ ] `#![deny(missing_docs)]` satisfied for all new public items

### US-009: Integration tests and performance validation

**Description:** As a developer, I need comprehensive integration tests proving cached and uncached scanners produce identical results, plus a benchmark showing cache-hit construction is under 1 second.

**Acceptance Criteria:**
- [ ] New `tests/cache_api.rs` with `#![cfg(feature = "cache")]`
- [ ] **Correctness tests:**
  - [ ] `new_with_cache` with default config produces identical `scan_text` findings as `Scanner::new(Config::default())`
  - [ ] Cache file is created on disk after first call
  - [ ] Second call loads from cache successfully (file exists, returns without error)
  - [ ] Corrupt cache file (write garbage bytes) falls back to `Scanner::new()` without returning error
  - [ ] Truncated cache file (write partial header) falls back gracefully
  - [ ] Missing parent directory for cache path falls back gracefully (no panic)
  - [ ] Redaction through cached scanner produces correct output (secrets replaced with `REDACTED`)
  - [ ] Allowlist filtering through cached scanner works (known allowlisted patterns suppressed)
  - [ ] Entropy filtering through cached scanner works (low-entropy matches filtered)
  - [ ] Path regex filtering through cached scanner works (`scan_file` with path-matching rules)
  - [ ] `scan_file()` through cached scanner produces identical findings to uncached scanner
- [ ] **Performance test:**
  - [ ] Measure `Scanner::new(Config::default())` construction time (baseline)
  - [ ] Measure `Scanner::new_with_cache(path)` on cache hit (second call)
  - [ ] Assert cache-hit construction completes in < 1 second for the default 222-rule config
  - [ ] Document observed cache file size in test comments

## Functional Requirements

- FR-1: `Scanner::new_with_cache(path)` must be gated behind the `cache` Cargo feature
- FR-2: The cache file format must include a header with magic bytes, format version, config content hash, and crate version for invalidation
- FR-3: DFA construction must apply `go_re2_compat()` preprocessing to all patterns before building
- FR-4: DFA construction must enforce a 10MB size limit per pattern; patterns exceeding this fall back to lazy `regex::Regex` compilation
- FR-5: Cache I/O failures must never prevent scanning — all failures silently fall back to `Scanner::new()`
- FR-6: The AhoCorasick keyword automaton must be rebuilt from stored keyword strings on cache load (not serialized)
- FR-7: Content regexes loaded from cache must use DFA for `is_match()` prefiltering and lazily compile `regex::Regex` for capture group extraction
- FR-8: Path regexes and allowlist regexes loaded from cache must use DFA-only matching (no `regex::Regex` needed)
- FR-9: The existing `Scanner::new()` constructor must remain unchanged in behavior
- FR-10: Cache files are endian-dependent (native endian) — not portable across architectures. This must be documented.
- FR-11: `Scanner` must remain `Send + Sync` with the new wrapper types

## Non-Goals (Out of Scope)

- Changing the existing `Scanner::new()` behavior
- Supporting custom configs with `new_with_cache` (always uses default embedded config)
- Cache directory creation or management (caller provides the full file path)
- Cross-architecture portable cache format (native endian only)
- Async I/O for cache reads/writes
- Pre-compiled cache embedded in the binary at build time
- Cache file locking for concurrent process access
- Any binary targets (this is a library-only crate)

## Technical Considerations

### Dependencies (feature-gated)
- `regex-automata 0.4` — DFA building + serialization. Already in `Cargo.lock` as transitive dep of `regex 1.x`. Monorepo at `rust-lang/regex`, actively maintained. Requires features: `dfa-build`, `dfa-search`, `syntax`.
- `sha2 0.10` — SHA-256 hashing for cache invalidation
- `bincode 1` — Fast binary serialization for cache metadata

### Key Source Files
- `src/scanner.rs` — Core modifications: wrapper types, field type changes, call site updates, `new_with_cache()`
- `src/cache.rs` — New module: cache format, serialization, deserialization, DFA building, config hashing
- `src/error.rs` — New `Cache` error variant
- `src/lib.rs` — Conditional module declaration
- `Cargo.toml` — Feature flag and optional deps
- `tests/cache_api.rs` — New integration test file

### Key Existing Functions to Reuse
- `go_re2_compat()` (`scanner.rs`) — Go RE2 pattern compatibility preprocessing, must be applied before DFA construction
- `compile_rule()`, `compile_regex_with_context()`, `compile_regex_list()` (`scanner.rs`) — Existing compilation functions, wrapped in `::Eager` variants
- `build_keyword_index()` (`scanner.rs`) — Rebuilds AhoCorasick + keyword_to_rules on cache load
- `Config::default()` (`config.rs`) — Embedded TOML config loader
- `DEFAULT_CONFIG_TOML` (`config.rs`) — The `include_str!` constant to hash for cache invalidation

### DFA Size Estimates
- Most rules: sparse DFAs < 100KB each
- Complex rules (e.g., `generic-api-key`): may exceed 10MB limit, fall back to `LazyOnly`
- Expected total cache file size: 5-50MB for the default 222-rule config (to be measured in US-009)

## Success Metrics

- Cache-hit `Scanner::new_with_cache()` completes in < 1 second (vs. 30-40s for `Scanner::new()`)
- Cached scanner produces byte-identical findings to uncached scanner on all test inputs
- Cache miss (first run) adds < 5 seconds overhead to normal compilation time (DFA building is parallel-friendly internally)
- `cargo build` without `--features cache` has zero compile-time regression

## Open Questions

None — all decisions resolved during investigation phase.
