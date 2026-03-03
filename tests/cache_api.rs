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
    let aws_text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    let cached_f = cached.scan_text(aws_text, None);
    let eager_f = eager.scan_text(aws_text, None);
    assert_findings_eq(&cached_f, &eager_f, "aws_key");

    // --- scan_text parity: multiple secrets ---
    let multi_text = concat!(
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01\n",
        "AKIAIOSFODNN7EXAMPLE\n",
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
    assert!(!cached_r.content.contains("AKIAIOSFODNN7EXAMPLE"));

    // --- redact_text_with custom replacement parity ---
    let cached_rc = cached.redact_text_with("AKIAIOSFODNN7EXAMPLE\n", None, "***");
    let eager_rc = eager.redact_text_with("AKIAIOSFODNN7EXAMPLE\n", None, "***");
    assert_eq!(cached_rc.content, eager_rc.content);
    assert_eq!(cached_rc.redaction_count, eager_rc.redaction_count);

    // --- path-filtered scan_text parity ---
    let secret_line = "AKIAIOSFODNN7EXAMPLE\n";
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
        writeln!(f, "AKIAIOSFODNN7EXAMPLE").unwrap();
        writeln!(f, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01").unwrap();
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
    let findings = hot.scan_text("AKIAIOSFODNN7EXAMPLE", None);
    assert!(!findings.is_empty(), "hot-start should detect AWS key");

    // Parity between hot-start and eager
    let eager_config = Config::default().unwrap();
    let eager = Scanner::new(eager_config).unwrap();

    let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01\n";
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
    let findings = scanner.scan_text("AKIAIOSFODNN7EXAMPLE", None);
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
    std::fs::write(&path2, &[0u8; 10]).unwrap();
    // Reuse the first scanner to verify truncated cache doesn't crash
    // (just verify constructor returns Ok)
    assert!(Scanner::new_with_cache(&path2).is_ok());
    let _ = std::fs::remove_file(&path2);

    // --- Zero-byte file ---
    let path3 = cache_path("fallback_empty");
    std::fs::write(&path3, b"").unwrap();
    assert!(Scanner::new_with_cache(&path3).is_ok());
    let _ = std::fs::remove_file(&path3);

    // --- Wrong magic bytes ---
    let path4 = cache_path("fallback_magic");
    let mut data = vec![0u8; 62];
    data[0..8].copy_from_slice(b"WRONGMAG");
    std::fs::write(&path4, &data).unwrap();
    assert!(Scanner::new_with_cache(&path4).is_ok());
    let _ = std::fs::remove_file(&path4);

    // --- Missing parent directory ---
    let missing_path = PathBuf::from("/tmp/gitleaks_rs_cache_api_no_parent/deep/nested/cache.bin");
    let _ = std::fs::remove_dir_all("/tmp/gitleaks_rs_cache_api_no_parent");
    assert!(Scanner::new_with_cache(&missing_path).is_ok());
    assert!(
        !missing_path.exists(),
        "cache file should NOT exist when parent dir is missing"
    );

    // --- Path is a directory, not a file ---
    let dir_path = cache_path("dir_as_file");
    let _ = std::fs::remove_file(&dir_path);
    let _ = std::fs::remove_dir_all(&dir_path);
    std::fs::create_dir_all(&dir_path).unwrap();
    assert!(Scanner::new_with_cache(&dir_path).is_ok());
    let _ = std::fs::remove_dir_all(&dir_path);

    // --- Read-only directory (Unix) ---
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("readonly_dir");
        let ro_path = dir.join("cache.bin");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(Scanner::new_with_cache(&ro_path).is_ok());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
