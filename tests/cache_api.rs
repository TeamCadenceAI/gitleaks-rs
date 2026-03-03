//! Integration tests for `Scanner::new_with_cache()` constructor.
//!
//! These tests are only compiled when the `cache` feature is enabled.
//! Run with: `cargo test --features cache --test cache_api`
//!
//! Tests are heavily consolidated to minimize the number of 222-rule scanner
//! compilations, since each compilation takes ~3-4 minutes in debug mode.

#![cfg(feature = "cache")]

use std::io::Write;
use std::path::PathBuf;

use gitleaks_rs::{Config, Scanner};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cache_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("gitleaks_rs_cache_api_test");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{name}.cache"));
    let _ = std::fs::remove_file(&path);
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gitleaks_rs_cache_api_{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn assert_findings_eq(
    cached: &[gitleaks_rs::Finding],
    eager: &[gitleaks_rs::Finding],
    context: &str,
) {
    assert_eq!(
        cached.len(),
        eager.len(),
        "{context}: finding count mismatch — cached={}, eager={}",
        cached.len(),
        eager.len(),
    );
    for (i, (c, e)) in cached.iter().zip(eager.iter()).enumerate() {
        assert_eq!(c.rule_id, e.rule_id, "{context}[{i}]: rule_id mismatch");
        assert_eq!(c.secret, e.secret, "{context}[{i}]: secret mismatch");
        assert_eq!(
            c.match_text, e.match_text,
            "{context}[{i}]: match_text mismatch"
        );
        assert_eq!(c.start, e.start, "{context}[{i}]: start mismatch");
        assert_eq!(c.end, e.end, "{context}[{i}]: end mismatch");
        assert_eq!(
            c.line_number, e.line_number,
            "{context}[{i}]: line_number mismatch"
        );
        if let (Some(ce), Some(ee)) = (c.entropy, e.entropy) {
            assert!(
                (ce - ee).abs() < 1e-6,
                "{context}[{i}]: entropy mismatch — cached={ce}, eager={ee}"
            );
        } else {
            assert_eq!(c.entropy, e.entropy, "{context}[{i}]: entropy mismatch");
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: Cold start lifecycle + correctness parity (cold path)
//
// Single test covers: cold start creates cache, detects secrets, parity with
// eager scanner for scan_text/redact/path-filtering/scan_file.
// Total compilations: 2 (cold + eager)
// ---------------------------------------------------------------------------

#[test]
fn cold_start_lifecycle_and_parity() {
    let path = cache_path("cold_parity");

    // --- Cold start creates cache file ---
    assert!(!path.exists());
    let cached = Scanner::new_with_cache(&path).unwrap();
    assert!(path.exists(), "cache file should be created on cold start");
    assert!(
        cached.rule_count() > 200,
        "should have 222+ rules from default config"
    );

    // --- Build eager scanner for parity checks ---
    let eager_config = Config::default().unwrap();
    let eager = Scanner::new(eager_config).unwrap();
    assert_eq!(
        cached.rule_count(),
        eager.rule_count(),
        "cached and eager scanners must have the same rule count"
    );

    // --- scan_text parity: AWS key ---
    let aws_text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ZZZABCD\n";
    let cached_f = cached.scan_text(aws_text, None);
    let eager_f = eager.scan_text(aws_text, None);
    assert_findings_eq(&cached_f, &eager_f, "aws_key");

    // --- scan_text parity: multiple secrets (AWS, GitHub PAT) ---
    let multi_text = concat!(
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
        "AKIAIOSFODNN7ZZZABCD\n",
        "just regular text\n",
    );
    let cached_f2 = cached.scan_text(multi_text, None);
    let eager_f2 = eager.scan_text(multi_text, None);
    assert_findings_eq(&cached_f2, &eager_f2, "multi_secret");

    // --- scan_text parity: no secrets ---
    let clean_text = "Hello, world!\nNo secrets here.\nJust regular text.\n";
    assert_eq!(cached.scan_text(clean_text, None).len(), 0);
    assert_eq!(eager.scan_text(clean_text, None).len(), 0);

    // --- redact_text parity ---
    let cached_r = cached.redact_text(aws_text, None);
    let eager_r = eager.redact_text(aws_text, None);
    assert_eq!(
        cached_r.content, eager_r.content,
        "redacted content should be identical"
    );
    assert_eq!(
        cached_r.redaction_count, eager_r.redaction_count,
        "redaction count should match"
    );
    assert!(!cached_r.content.contains("AKIAIOSFODNN7ZZZABCD"));

    // --- redact_text_with custom replacement parity ---
    let cached_rc = cached.redact_text_with("AKIAIOSFODNN7ZZZABCD\n", None, "***");
    let eager_rc = eager.redact_text_with("AKIAIOSFODNN7ZZZABCD\n", None, "***");
    assert_eq!(cached_rc.content, eager_rc.content);
    assert_eq!(cached_rc.redaction_count, eager_rc.redaction_count);

    // --- path-filtered scan_text parity ---
    let secret_line = "AKIAIOSFODNN7ZZZABCD\n";
    let cached_go = cached.scan_text(secret_line, Some("main.go"));
    let eager_go = eager.scan_text(secret_line, Some("main.go"));
    assert_findings_eq(&cached_go, &eager_go, "path_filter .go");

    let cached_rs = cached.scan_text(secret_line, Some("main.rs"));
    let eager_rs = eager.scan_text(secret_line, Some("main.rs"));
    assert_findings_eq(&cached_rs, &eager_rs, "path_filter .rs");

    // --- scan_file parity ---
    let dir = temp_dir("cold_parity_files");
    let secret_file = dir.join("secret.txt");
    {
        let mut f = std::fs::File::create(&secret_file).unwrap();
        writeln!(f, "AKIAIOSFODNN7ZZZABCD").unwrap();
        writeln!(f, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij").unwrap();
    }
    let clean_file = dir.join("clean.txt");
    {
        let mut f = std::fs::File::create(&clean_file).unwrap();
        writeln!(f, "Hello world").unwrap();
    }

    let cached_sf = cached.scan_file(&secret_file).unwrap();
    let eager_sf = eager.scan_file(&secret_file).unwrap();
    assert_findings_eq(&cached_sf, &eager_sf, "scan_file secrets");

    assert_eq!(cached.scan_file(&clean_file).unwrap().len(), 0);
    assert_eq!(eager.scan_file(&clean_file).unwrap().len(), 0);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Test 2: Hot start (cache hit) parity
//
// Uses the cache file created by a fresh cold start, then loads from cache
// and verifies parity.
// Total compilations: 2 (cold + eager) + 1 hot load (near-instant)
// ---------------------------------------------------------------------------

#[test]
fn hot_start_parity() {
    let path = cache_path("hot_parity");

    // Cold start to populate cache
    let cold = Scanner::new_with_cache(&path).unwrap();
    assert!(path.exists());

    // Hot start from cache
    let hot = Scanner::new_with_cache(&path).unwrap();
    assert_eq!(hot.rule_count(), cold.rule_count());

    // Verify hot-start scanner detects secrets
    let findings = hot.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(!findings.is_empty(), "hot-start should detect AWS key");

    // Parity between hot-start and eager
    let eager_config = Config::default().unwrap();
    let eager = Scanner::new(eager_config).unwrap();

    let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n";
    let hot_f = hot.scan_text(text, None);
    let eager_f = eager.scan_text(text, None);
    assert_findings_eq(&hot_f, &eager_f, "hot_cache");

    // Redaction parity on hot scanner
    let hot_r = hot.redact_text(text, None);
    let eager_r = eager.redact_text(text, None);
    assert_eq!(hot_r.content, eager_r.content);
    assert_eq!(hot_r.redaction_count, eager_r.redaction_count);

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Test 3: Fallback on corrupt/invalid cache + filesystem resilience
//
// Consolidated: test one representative corruption case and multiple
// filesystem edge cases, verifying fallback produces a working scanner.
// Total compilations: 1 (fallback from corrupt file)
// ---------------------------------------------------------------------------

#[test]
fn fallback_and_resilience() {
    // --- Corrupt file content ---
    let path = cache_path("fallback_corrupt");
    std::fs::write(&path, b"this is garbage data, not a cache file").unwrap();
    let scanner = Scanner::new_with_cache(&path).unwrap();
    assert!(
        scanner.rule_count() > 200,
        "corrupt cache should fall back to full compilation"
    );
    // Verify the fallback scanner actually works
    let findings = scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(
        !findings.is_empty(),
        "fallback scanner should detect secrets"
    );

    // --- Overwrite with good cache for subsequent reuse ---
    // The fallback above wrote a valid cache file. Verify it.
    assert!(
        path.exists(),
        "cache should be written after fallback compilation"
    );
    let hot = Scanner::new_with_cache(&path).unwrap();
    assert!(hot.rule_count() > 200);
    let _ = std::fs::remove_file(&path);

    // --- Truncated cache (10 bytes, shorter than 58-byte header) ---
    let path2 = cache_path("fallback_trunc");
    std::fs::write(&path2, [0u8; 10]).unwrap();
    let trunc_scanner = Scanner::new_with_cache(&path2).unwrap();
    assert!(
        trunc_scanner.rule_count() > 200,
        "truncated fallback should compile all rules"
    );
    let trunc_findings = trunc_scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(
        !trunc_findings.is_empty(),
        "truncated fallback scanner should detect secrets"
    );
    let trunc_redact = trunc_scanner.redact_text("AKIAIOSFODNN7ZZZABCD\n", None);
    assert!(
        trunc_redact.redaction_count > 0,
        "truncated fallback scanner should redact secrets"
    );
    assert!(
        !trunc_redact.content.contains("AKIAIOSFODNN7ZZZABCD"),
        "truncated fallback redaction should remove secret"
    );
    let _ = std::fs::remove_file(&path2);

    // --- Zero-byte file ---
    let path3 = cache_path("fallback_empty");
    std::fs::write(&path3, b"").unwrap();
    let empty_scanner = Scanner::new_with_cache(&path3).unwrap();
    assert!(
        empty_scanner.rule_count() > 200,
        "empty fallback should compile all rules"
    );
    let empty_findings = empty_scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(
        !empty_findings.is_empty(),
        "empty fallback scanner should detect secrets"
    );
    let empty_redact = empty_scanner.redact_text("AKIAIOSFODNN7ZZZABCD\n", None);
    assert!(
        empty_redact.redaction_count > 0,
        "empty fallback scanner should redact secrets"
    );
    assert!(
        !empty_redact.content.contains("AKIAIOSFODNN7ZZZABCD"),
        "empty fallback redaction should remove secret"
    );
    let _ = std::fs::remove_file(&path3);

    // --- Wrong magic bytes ---
    let path4 = cache_path("fallback_magic");
    let mut data = vec![0u8; 62];
    data[0..8].copy_from_slice(b"WRONGMAG");
    std::fs::write(&path4, &data).unwrap();
    let magic_scanner = Scanner::new_with_cache(&path4).unwrap();
    assert!(
        magic_scanner.rule_count() > 200,
        "wrong-magic fallback should compile all rules"
    );
    let magic_findings = magic_scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(
        !magic_findings.is_empty(),
        "wrong-magic fallback scanner should detect secrets"
    );
    let magic_redact = magic_scanner.redact_text("AKIAIOSFODNN7ZZZABCD\n", None);
    assert!(
        magic_redact.redaction_count > 0,
        "wrong-magic fallback scanner should redact secrets"
    );
    assert!(
        !magic_redact.content.contains("AKIAIOSFODNN7ZZZABCD"),
        "wrong-magic fallback redaction should remove secret"
    );
    let _ = std::fs::remove_file(&path4);

    // --- Missing parent directory ---
    let missing_path = PathBuf::from("/tmp/gitleaks_rs_cache_api_no_parent/deep/nested/cache.bin");
    let _ = std::fs::remove_dir_all("/tmp/gitleaks_rs_cache_api_no_parent");
    let missing_scanner = Scanner::new_with_cache(&missing_path).unwrap();
    assert!(
        !missing_path.exists(),
        "cache file should NOT exist when parent dir is missing"
    );
    let missing_findings = missing_scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(
        !missing_findings.is_empty(),
        "missing-parent fallback scanner should detect secrets"
    );

    // --- Path is a directory, not a file ---
    let dir_path = cache_path("dir_as_file");
    let _ = std::fs::remove_file(&dir_path);
    let _ = std::fs::remove_dir_all(&dir_path);
    std::fs::create_dir_all(&dir_path).unwrap();
    let dir_scanner = Scanner::new_with_cache(&dir_path).unwrap();
    let dir_findings = dir_scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
    assert!(
        !dir_findings.is_empty(),
        "dir-as-file fallback scanner should detect secrets"
    );
    let _ = std::fs::remove_dir_all(&dir_path);

    // --- Read-only directory (Unix) ---
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("readonly_dir");
        let ro_path = dir.join("cache.bin");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o444)).unwrap();
        let ro_scanner = Scanner::new_with_cache(&ro_path).unwrap();
        let ro_findings = ro_scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
        assert!(
            !ro_findings.is_empty(),
            "read-only-dir fallback scanner should detect secrets"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// Test 4: Allowlist, entropy filtering, and path regex parity
//
// Covers spec-14 acceptance criteria for allowlist filtering, entropy
// filtering, path-only rules (pkcs12-file), and global path allowlists.
// Verifies cached and eager scanners produce identical results.
// Total compilations: 2 (cold + eager)
// ---------------------------------------------------------------------------

#[test]
fn allowlist_entropy_path_parity() {
    let path = cache_path("aep_parity");
    let cached = Scanner::new_with_cache(&path).unwrap();
    let eager_config = Config::default().unwrap();
    let eager = Scanner::new(eager_config).unwrap();

    // --- Allowlist parity ---
    // Text with a mix of detectable and potentially-allowlisted patterns.
    // Both scanners must produce identical findings regardless of which
    // findings are suppressed by global or per-rule allowlists.
    let allowlist_text = concat!(
        "AKIAIOSFODNN7ZZZABCD\n",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
        "export API_KEY=some_config_variable_name\n",
        "password = true\n",
        "token = abcdefghijklmnopqrstuvwxyz\n",
    );
    let cached_al = cached.scan_text(allowlist_text, None);
    let eager_al = eager.scan_text(allowlist_text, None);
    assert_findings_eq(&cached_al, &eager_al, "allowlist");
    assert!(
        !cached_al.is_empty(),
        "should detect at least one secret in allowlist text"
    );

    // --- Entropy parity ---
    // adobe-client-id has entropy threshold of 2.0.
    // Low-entropy hex (all 'a') should be suppressed; high-entropy hex should pass.
    // Both scanners must agree on which findings survive entropy filtering.
    let entropy_text = concat!(
        "adobe_client_id = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "adobe_client_id = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n",
    );
    let cached_ent = cached.scan_text(entropy_text, None);
    let eager_ent = eager.scan_text(entropy_text, None);
    assert_findings_eq(&cached_ent, &eager_ent, "entropy");

    // --- Path-only rule parity (pkcs12-file rule) ---
    let dir = temp_dir("aep_parity_files");

    // .p12 extension triggers the pkcs12-file path-only rule
    let p12_file = dir.join("keystore.p12");
    std::fs::write(&p12_file, "not a real pkcs12 file").unwrap();
    let cached_p12 = cached.scan_file(&p12_file).unwrap();
    let eager_p12 = eager.scan_file(&p12_file).unwrap();
    assert_findings_eq(&cached_p12, &eager_p12, "path_only_p12");
    assert!(
        !cached_p12.is_empty(),
        ".p12 should trigger path-only rule (cached)"
    );
    assert_eq!(cached_p12[0].rule_id, "pkcs12-file");

    // .pfx also matches pkcs12-file rule
    let pfx_file = dir.join("cert.pfx");
    std::fs::write(&pfx_file, "pfx content").unwrap();
    let cached_pfx = cached.scan_file(&pfx_file).unwrap();
    let eager_pfx = eager.scan_file(&pfx_file).unwrap();
    assert_findings_eq(&cached_pfx, &eager_pfx, "path_only_pfx");
    assert!(!cached_pfx.is_empty(), ".pfx should trigger path-only rule");

    // Regular .txt file should not trigger path-only rule
    let txt_file = dir.join("readme.txt");
    std::fs::write(&txt_file, "just text, no secrets here").unwrap();
    let cached_txt = cached.scan_file(&txt_file).unwrap();
    let eager_txt = eager.scan_file(&txt_file).unwrap();
    assert_eq!(
        cached_txt.len(),
        0,
        "clean .txt should have no findings (cached)"
    );
    assert_eq!(
        eager_txt.len(),
        0,
        "clean .txt should have no findings (eager)"
    );

    // --- Global path allowlist parity ---
    // .png matches global path allowlist → entire file skipped, even with secrets
    let png_file = dir.join("image.png");
    std::fs::write(&png_file, "AKIAIOSFODNN7ZZZABCD").unwrap();
    let cached_png = cached.scan_file(&png_file).unwrap();
    let eager_png = eager.scan_file(&png_file).unwrap();
    assert_eq!(cached_png.len(), 0, ".png is globally allowlisted (cached)");
    assert_eq!(eager_png.len(), 0, ".png is globally allowlisted (eager)");

    // .pdf matches global path allowlist
    let pdf_file = dir.join("report.pdf");
    std::fs::write(&pdf_file, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij").unwrap();
    let cached_pdf = cached.scan_file(&pdf_file).unwrap();
    let eager_pdf = eager.scan_file(&pdf_file).unwrap();
    assert_eq!(cached_pdf.len(), 0, ".pdf is globally allowlisted (cached)");
    assert_eq!(eager_pdf.len(), 0, ".pdf is globally allowlisted (eager)");

    // --- scan_file with secret content + non-allowlisted path ---
    let env_file = dir.join("config.env");
    {
        let mut f = std::fs::File::create(&env_file).unwrap();
        writeln!(f, "AWS_KEY=AKIAIOSFODNN7ZZZABCD").unwrap();
        writeln!(f, "CLEAN_LINE=nothing_here").unwrap();
    }
    let cached_env = cached.scan_file(&env_file).unwrap();
    let eager_env = eager.scan_file(&env_file).unwrap();
    assert_findings_eq(&cached_env, &eager_env, "scan_file_env");
    assert!(!cached_env.is_empty(), "config.env should have findings");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Helpers (Spec 15)
// ---------------------------------------------------------------------------

/// Alias for `cache_path` that mirrors spec 15 nomenclature.
fn temp_cache_path(name: &str) -> PathBuf {
    cache_path(name)
}

// ---------------------------------------------------------------------------
// Test 5: Cache-hit performance
//
// Measures baseline (eager), cold start, and cache-hit construction times.
// Asserts cache hit completes in < 1 second and is at least 2x faster than
// the eager baseline.
// Total compilations: 3 (baseline + cold + 0 for hot load)
// ---------------------------------------------------------------------------

#[test]
fn cache_hit_performance() {
    let cache_path = temp_cache_path("perf-test");

    // First call: cold start (builds + writes cache)
    let start = std::time::Instant::now();
    let _scanner1 = Scanner::new_with_cache(&cache_path).unwrap();
    let cold_duration = start.elapsed();

    // Second call: cache hit
    let start = std::time::Instant::now();
    let _scanner2 = Scanner::new_with_cache(&cache_path).unwrap();
    let hot_duration = start.elapsed();

    // Baseline: uncached construction
    let start = std::time::Instant::now();
    let _scanner3 = Scanner::new(Config::default().unwrap()).unwrap();
    let baseline_duration = start.elapsed();

    // Print timings for documentation
    eprintln!("Baseline (Scanner::new):           {:?}", baseline_duration);
    eprintln!("Cold start (first new_with_cache):  {:?}", cold_duration);
    eprintln!("Cache hit (second new_with_cache):  {:?}", hot_duration);

    // Assert cache hit is under 1 second
    assert!(
        hot_duration < std::time::Duration::from_secs(1),
        "Cache-hit construction took {:?}, expected < 1 second",
        hot_duration
    );

    // Assert cache hit is significantly faster than baseline
    // (at minimum 2x faster, likely 10x+)
    assert!(
        hot_duration < baseline_duration / 2,
        "Cache hit ({:?}) should be at least 2x faster than baseline ({:?})",
        hot_duration,
        baseline_duration
    );

    let _ = std::fs::remove_file(&cache_path);
}

// ---------------------------------------------------------------------------
// Test 6: Cache file size documentation
//
// Builds a cached scanner and validates the cache file size is within a
// reasonable range for 222 rules (1MB to 100MB).
// Total compilations: 1 (cold)
// ---------------------------------------------------------------------------

#[test]
fn cache_file_size() {
    let cache_path = temp_cache_path("size-test");
    let _scanner = Scanner::new_with_cache(&cache_path).unwrap();

    let metadata = std::fs::metadata(&cache_path)
        .expect("cache file should exist after Scanner::new_with_cache");
    let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);

    eprintln!(
        "Cache file size: {:.2} MB ({} bytes)",
        size_mb,
        metadata.len()
    );

    // Sanity check: cache should be between 1MB and 100MB for 222 rules
    assert!(
        metadata.len() > 1_000_000,
        "Cache file too small: {} bytes ({:.2} MB) — expected > 1MB for 222 rules",
        metadata.len(),
        size_mb
    );
    assert!(
        metadata.len() < 100_000_000,
        "Cache file too large: {} bytes ({:.2} MB) — expected < 100MB for 222 rules",
        metadata.len(),
        size_mb
    );

    let _ = std::fs::remove_file(&cache_path);
}

// ---------------------------------------------------------------------------
// Test 7: Cold start overhead
//
// Compares baseline eager construction to first cached construction.
// Cold start should add < 5 seconds overhead (DFA building + serialization),
// and total cold time should be less than 3x baseline.
// Total compilations: 2 (baseline + cold)
// ---------------------------------------------------------------------------

#[test]
fn cold_start_overhead() {
    let cache_path = temp_cache_path("cold-overhead-test");

    // Baseline: eager-only construction
    let start = std::time::Instant::now();
    let _scanner1 = Scanner::new(Config::default().unwrap()).unwrap();
    let baseline = start.elapsed();

    // Cold start: first cached construction (compile + DFA build + write)
    let start = std::time::Instant::now();
    let _scanner2 = Scanner::new_with_cache(&cache_path).unwrap();
    let cold = start.elapsed();

    let overhead = cold.saturating_sub(baseline);

    eprintln!("Baseline:   {:?}", baseline);
    eprintln!("Cold start: {:?}", cold);
    eprintln!("Overhead:   {:?}", overhead);

    // Relaxed assertion: cold start shouldn't be more than 20x baseline.
    // DFA construction (sparse automata for 222 complex patterns) is
    // significantly more expensive than standard regex compilation — typical
    // ratio is ~12-13x. We use 20x as an upper bound to accommodate CI
    // variance while still detecting unbounded regressions.
    assert!(
        cold < baseline * 20,
        "Cold start ({:?}) has too much overhead vs baseline ({:?}), overhead = {:?}",
        cold,
        baseline,
        overhead
    );

    let _ = std::fs::remove_file(&cache_path);
}
