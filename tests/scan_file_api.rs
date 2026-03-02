//! Integration tests for `Scanner::scan_text` and `Scanner::scan_file`.

use std::io::Write;
use std::path::Path;

use gitleaks_rs::{Config, Scanner};

fn test_scanner() -> Scanner {
    let config = Config::from_toml(
        r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
    )
    .unwrap();
    Scanner::new(config).unwrap()
}

/// Create a unique temp directory for a test.
fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("gitleaks_rs_integ_{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn scan_file_missing_file_returns_io_error() {
    let scanner = test_scanner();
    let result = scanner.scan_file(Path::new("/nonexistent/gitleaks_rs_test/missing.txt"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, gitleaks_rs::Error::Io(_)),
        "expected Io error, got: {err}"
    );
}

#[test]
fn scan_file_no_secrets_returns_empty() {
    let scanner = test_scanner();
    let dir = temp_dir("no_secrets");
    let file_path = dir.join("clean.txt");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, "just regular text").unwrap();
        writeln!(f, "nothing secret here").unwrap();
    }

    let findings = scanner.scan_file(&file_path).unwrap();
    assert!(findings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_file_multiple_secrets_with_line_numbers() {
    let scanner = test_scanner();
    let dir = temp_dir("multi_secrets");
    let file_path = dir.join("secrets.txt");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, "nothing here").unwrap();
        writeln!(f, r#"key = "first_secret""#).unwrap();
        writeln!(f, "blank line").unwrap();
        writeln!(f).unwrap();
        writeln!(f, r#"key = "second_secret""#).unwrap();
    }

    let findings = scanner.scan_file(&file_path).unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].line_number, Some(2));
    assert_eq!(findings[0].secret, "first_secret");
    assert_eq!(findings[1].line_number, Some(5));
    assert_eq!(findings[1].secret, "second_secret");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_file_global_path_allowlist_skips_file() {
    let config = Config::from_toml(
        r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]

[allowlist]
description = "global"
paths = ['''vendor/''']
"#,
    )
    .unwrap();
    let scanner = Scanner::new(config).unwrap();

    let dir = temp_dir("path_allow");
    let vendor_dir = dir.join("vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let file_path = vendor_dir.join("lib.txt");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, r#"key = "should_not_find""#).unwrap();
    }

    let findings = scanner.scan_file(&file_path).unwrap();
    assert!(
        findings.is_empty(),
        "global path allowlist should suppress all findings"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_file_path_only_rule_matches() {
    let config = Config::from_toml(
        r#"
[[rules]]
id = "pkcs12-detect"
description = "PKCS12 file detected"
path = '''\.p12$'''
"#,
    )
    .unwrap();
    let scanner = Scanner::new(config).unwrap();

    let dir = temp_dir("path_only");
    let file_path = dir.join("cert.p12");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, "binary content").unwrap();
    }

    let findings = scanner.scan_file(&file_path).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "pkcs12-detect");
    assert_eq!(findings[0].description, "PKCS12 file detected");
    assert_eq!(findings[0].secret, "");
    assert_eq!(findings[0].start, 0);
    assert_eq!(findings[0].end, 0);
    assert_eq!(findings[0].line_number, None);
    assert_eq!(findings[0].entropy, None);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_file_path_only_and_content_combined() {
    let config = Config::from_toml(
        r#"
[[rules]]
id = "pem-file"
description = "PEM file"
path = '''\.pem$'''

[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
    )
    .unwrap();
    let scanner = Scanner::new(config).unwrap();

    let dir = temp_dir("combined");
    let file_path = dir.join("keys.pem");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, r#"key = "secret_val""#).unwrap();
    }

    let findings = scanner.scan_file(&file_path).unwrap();
    // Path-only finding + content finding
    assert_eq!(findings.len(), 2);
    // Path-only first
    assert_eq!(findings[0].rule_id, "pem-file");
    assert_eq!(findings[0].line_number, None);
    // Content second
    assert_eq!(findings[1].rule_id, "test-key");
    assert_eq!(findings[1].line_number, Some(1));

    let _ = std::fs::remove_dir_all(&dir);
}
