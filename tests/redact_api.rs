//! Integration tests for the redaction API.
//!
//! Validates that `RedactResult` is publicly exported from the crate root
//! and that end-to-end redaction works from the consumer's perspective.

use gitleaks_rs::{Config, RedactResult, Scanner};

fn test_scanner() -> Scanner {
    let config = Config::from_toml(
        r#"
        [[rules]]
        id = "test-tok"
        description = "Test token"
        regex = '''TOK_[A-Z0-9]{10}'''
        keywords = ["tok_"]
    "#,
    )
    .unwrap();
    Scanner::new(config).unwrap()
}

#[test]
fn redact_result_is_publicly_exported() {
    // This test verifies that RedactResult is accessible from gitleaks_rs root.
    let scanner = test_scanner();
    let result: RedactResult = scanner.redact_line("no secrets", None);
    assert_eq!(result.redaction_count, 0);
}

#[test]
fn redact_line_end_to_end() {
    let scanner = test_scanner();
    let result = scanner.redact_line("key=TOK_AAAAAAAAAA", None);
    assert_eq!(result.redaction_count, 1);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "test-tok");
    assert!(result.content.contains("REDACTED"));
    assert!(!result.content.contains("TOK_AAAAAAAAAA"));
    assert!(result.content.starts_with("key="));
}

#[test]
fn redact_line_with_custom_replacement_end_to_end() {
    let scanner = test_scanner();
    let result = scanner.redact_line_with("key=TOK_AAAAAAAAAA", None, "***");
    assert_eq!(result.content, "key=***");
    assert_eq!(result.redaction_count, 1);
}

#[test]
fn redact_text_end_to_end() {
    let scanner = test_scanner();
    let text = "line one\nkey=TOK_AAAAAAAAAA\n\nkey=TOK_BBBBBBBBBB\nline five";
    let result = scanner.redact_text(text, None);
    assert_eq!(result.redaction_count, 2);
    assert_eq!(result.findings.len(), 2);
    assert_eq!(result.findings[0].line_number, Some(2));
    assert_eq!(result.findings[1].line_number, Some(4));
    assert!(!result.content.contains("TOK_AAAAAAAAAA"));
    assert!(!result.content.contains("TOK_BBBBBBBBBB"));
    // Line shape preserved.
    let lines: Vec<&str> = result.content.split('\n').collect();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0], "line one");
    assert_eq!(lines[2], "");
    assert_eq!(lines[4], "line five");
}

#[test]
fn redact_text_with_custom_replacement_end_to_end() {
    let scanner = test_scanner();
    let text = "a=TOK_AAAAAAAAAA\nb=TOK_BBBBBBBBBB";
    let result = scanner.redact_text_with(text, None, "[HIDDEN]");
    assert_eq!(result.content, "a=[HIDDEN]\nb=[HIDDEN]");
    assert_eq!(result.redaction_count, 2);
}

#[test]
fn redact_text_no_secrets_returns_unchanged() {
    let scanner = test_scanner();
    let text = "just\nsome\nnormal\ntext";
    let result = scanner.redact_text(text, None);
    assert_eq!(result.content, text);
    assert_eq!(result.redaction_count, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn redact_with_path_aware_rule() {
    let config = Config::from_toml(
        r#"
        [[rules]]
        id = "env-tok"
        description = "Env token"
        regex = '''ENV_TOK_[A-Z0-9]{10}'''
        keywords = ["env_tok_"]
        path = '''\.env$'''
    "#,
    )
    .unwrap();
    let scanner = Scanner::new(config).unwrap();
    let line = "ENV_TOK_AAAAAAAAAA";

    // No path match → no redaction.
    let result = scanner.redact_line(line, Some("config.yml"));
    assert_eq!(result.content, line);

    // Path matches → redacted.
    let result = scanner.redact_line(line, Some("prod.env"));
    assert!(result.content.contains("REDACTED"));
    assert_eq!(result.redaction_count, 1);
}
