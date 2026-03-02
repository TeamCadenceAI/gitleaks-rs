//! Integration tests for `ConfigBuilder`, `Config::extend`, and custom config
//! flows through `Scanner`.

use gitleaks_rs::{Allowlist, Config, ConfigBuilder, Rule, Scanner};

// ---------------------------------------------------------------------------
// ConfigBuilder -> Scanner end-to-end
// ---------------------------------------------------------------------------

#[test]
fn config_builder_custom_rule_detects_secret() {
    let config = ConfigBuilder::new()
        .title("custom")
        .add_rule(Rule {
            id: "custom-token".into(),
            regex: Some(r"CUSTOMTOKEN_[A-Za-z0-9]{16}".into()),
            keywords: vec!["customtoken".into()],
            ..Default::default()
        })
        .build()
        .unwrap();

    let scanner = Scanner::new(config).unwrap();
    let findings = scanner.scan_line("auth = CUSTOMTOKEN_abcdefgh12345678", Some("test.rs"));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "custom-token");
    assert_eq!(findings[0].secret, "CUSTOMTOKEN_abcdefgh12345678");
}

#[test]
fn config_builder_with_allowlist_suppresses_match() {
    let config = ConfigBuilder::new()
        .add_rule(Rule {
            id: "key-finder".into(),
            regex: Some(r"KEY_[A-Z]{8}".into()),
            keywords: vec!["key".into()],
            ..Default::default()
        })
        .set_allowlist(Allowlist {
            stopwords: vec!["KEY_TESTTEST".into()],
            ..Default::default()
        })
        .build()
        .unwrap();

    let scanner = Scanner::new(config).unwrap();

    // Should be suppressed by stopword.
    let findings = scanner.scan_line("value = KEY_TESTTEST", Some("test.rs"));
    assert!(findings.is_empty(), "stopword should suppress finding");

    // Different value should still match.
    let findings = scanner.scan_line("value = KEY_ABCDEFGH", Some("test.rs"));
    assert_eq!(findings.len(), 1);
}

// ---------------------------------------------------------------------------
// Config::extend with Scanner
// ---------------------------------------------------------------------------

#[test]
fn extend_default_with_custom_detects_both() {
    let default_config = Config::default().unwrap();
    let default_rule_count = default_config.rules.len();

    let custom = ConfigBuilder::new()
        .add_rule(Rule {
            id: "my-custom-secret".into(),
            regex: Some(r"MYCUSTOMSECRET_[a-f0-9]{32}".into()),
            keywords: vec!["mycustomsecret".into()],
            ..Default::default()
        })
        .build()
        .unwrap();

    let merged = default_config.extend(custom);
    assert_eq!(merged.rules.len(), default_rule_count + 1);

    let scanner = Scanner::new(merged).unwrap();

    // Custom rule should detect custom secret.
    let findings = scanner.scan_line(
        "token = MYCUSTOMSECRET_deadbeef1234567890abcdef12345678",
        Some("config.rs"),
    );
    let custom_finding = findings.iter().find(|f| f.rule_id == "my-custom-secret");
    assert!(
        custom_finding.is_some(),
        "custom rule should detect custom secret"
    );
}

#[test]
fn extend_allowlist_merge_suppresses_with_both() {
    let base = ConfigBuilder::new()
        .add_rule(Rule {
            id: "tok".into(),
            regex: Some(r"TOKEN_[A-Z]{10}".into()),
            keywords: vec!["token".into()],
            ..Default::default()
        })
        .set_allowlist(Allowlist {
            stopwords: vec!["TOKEN_AAAAAAAAAA".into()],
            ..Default::default()
        })
        .build()
        .unwrap();

    let extension = ConfigBuilder::new()
        .set_allowlist(Allowlist {
            stopwords: vec!["TOKEN_BBBBBBBBBB".into()],
            ..Default::default()
        })
        .build()
        .unwrap();

    let merged = base.extend(extension);
    let al = merged.allowlist.as_ref().unwrap();
    assert_eq!(al.stopwords.len(), 2);

    let scanner = Scanner::new(merged).unwrap();

    // Both stopwords should suppress.
    assert!(scanner
        .scan_line("x = TOKEN_AAAAAAAAAA", Some("t"))
        .is_empty());
    assert!(scanner
        .scan_line("x = TOKEN_BBBBBBBBBB", Some("t"))
        .is_empty());

    // Other tokens still detected.
    assert_eq!(
        scanner.scan_line("x = TOKEN_CCCCCCCCCC", Some("t")).len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Public API re-export checks
// ---------------------------------------------------------------------------

#[test]
fn config_builder_is_publicly_exported() {
    // This test verifies the re-export path compiles.
    let _builder: ConfigBuilder = ConfigBuilder::new();
}

#[test]
fn rule_default_is_usable_from_crate_root() {
    let rule = Rule {
        id: "test".into(),
        regex: Some("x".into()),
        ..Default::default()
    };
    assert_eq!(rule.id, "test");
}
