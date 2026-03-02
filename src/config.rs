use std::collections::HashSet;
use std::path::Path;

use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::error::{Error, Result};

/// Version of the upstream gitleaks config snapshot vendored in this crate.
pub const GITLEAKS_CONFIG_VERSION: &str = "v8.25.0";

/// Embedded official gitleaks config TOML.
const DEFAULT_CONFIG_TOML: &str = include_str!("default_config.toml");

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Target that a per-rule allowlist regex is tested against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RegexTarget {
    /// Test against the captured secret value (default).
    #[default]
    Secret,
    /// Test against the full regex match.
    Match,
    /// Test against the entire source line.
    Line,
}

impl<'de> Deserialize<'de> for RegexTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_ascii_lowercase().as_str() {
            "secret" => Ok(RegexTarget::Secret),
            "match" => Ok(RegexTarget::Match),
            "line" => Ok(RegexTarget::Line),
            other => Err(de::Error::unknown_variant(
                other,
                &["secret", "match", "line"],
            )),
        }
    }
}

/// Logical condition for combining multiple allowlist entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Condition {
    /// Any allowlist entry matching suppresses the finding (default).
    #[default]
    Or,
    /// All allowlist entries must match to suppress the finding.
    And,
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_ascii_lowercase().as_str() {
            "or" => Ok(Condition::Or),
            "and" => Ok(Condition::And),
            other => Err(de::Error::unknown_variant(other, &["or", "and"])),
        }
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Top-level gitleaks configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Optional config title.
    pub title: Option<String>,

    /// Minimum gitleaks version required by this config (informational).
    #[serde(rename = "minVersion")]
    pub min_version: Option<String>,

    /// Detection rules.
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Global allowlist applied to all rules.
    pub allowlist: Option<Allowlist>,

    /// Warnings collected during validation (not deserialized from TOML).
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// A single detection rule.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    /// Unique rule identifier.
    pub id: String,

    /// Human-readable description of what the rule detects.
    pub description: Option<String>,

    /// Content-matching regex pattern.
    pub regex: Option<String>,

    /// File-path-matching regex pattern.
    pub path: Option<String>,

    /// Minimum Shannon entropy threshold for the matched secret.
    pub entropy: Option<f64>,

    /// Keywords that must appear in a line for the rule to be considered.
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Which regex capture group contains the secret (1-indexed).
    #[serde(rename = "secretGroup")]
    pub secret_group: Option<u32>,

    /// Per-rule allowlists.
    #[serde(default)]
    pub allowlists: Vec<RuleAllowlist>,
}

/// Global allowlist: patterns that suppress findings across all rules.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Allowlist {
    /// Description of this allowlist.
    pub description: Option<String>,

    /// Path regexes — findings in matching file paths are suppressed.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Content regexes — matching findings are suppressed.
    #[serde(default)]
    pub regexes: Vec<String>,

    /// Stop-words — findings containing any of these strings are suppressed.
    #[serde(default)]
    pub stopwords: Vec<String>,
}

/// Per-rule allowlist entry attached to an individual rule.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleAllowlist {
    /// Description of this allowlist entry.
    pub description: Option<String>,

    /// What the allowlist regexes are tested against.
    #[serde(rename = "regexTarget", default)]
    pub regex_target: RegexTarget,

    /// Regex patterns for suppressing findings.
    #[serde(default)]
    pub regexes: Vec<String>,

    /// Path regex patterns for suppressing findings.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Stop-words for suppressing findings.
    #[serde(default)]
    pub stopwords: Vec<String>,

    /// Logical condition for combining allowlist fields.
    #[serde(default)]
    pub condition: Condition,
}

// ---------------------------------------------------------------------------
// Parsing & Validation
// ---------------------------------------------------------------------------

impl Config {
    /// Parse a gitleaks config from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self> {
        let mut config: Config = toml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    /// Parse a gitleaks config from a TOML file on disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Load the embedded official gitleaks rule set.
    ///
    /// This parses the vendored `default_config.toml` that ships with the
    /// crate. Returns an error only if the embedded TOML is somehow invalid
    /// (which would indicate a build-time packaging bug).
    ///
    /// Note: this is intentionally *not* the `Default` trait because loading
    /// the embedded config is fallible.
    ///
    /// # Example
    ///
    /// ```
    /// use gitleaks_rs::Config;
    /// let config = Config::default().expect("embedded config is valid");
    /// assert!(config.rules.len() >= 222);
    /// ```
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Result<Self> {
        Self::from_toml(DEFAULT_CONFIG_TOML)
    }

    /// Alias for [`Config::default()`]. Prefer `Config::default()`.
    #[deprecated(since = "0.1.0", note = "use Config::default() instead")]
    pub fn default_config() -> Result<Self> {
        Self::default()
    }

    /// Run all post-parse validation checks, collecting warnings for
    /// non-fatal issues (e.g. duplicate rule IDs).
    ///
    /// This is `pub(crate)` so that `ConfigBuilder::build` can reuse the
    /// same validation logic, preventing drift between the TOML parse path
    /// and the programmatic build path.
    pub(crate) fn validate(&mut self) -> Result<()> {
        let mut seen_ids = HashSet::new();

        for rule in &self.rules {
            // Every rule must have at least one matching target.
            if rule.regex.is_none() && rule.path.is_none() {
                return Err(Error::Validation(format!(
                    "rule '{}' has neither `regex` nor `path`",
                    rule.id
                )));
            }

            // Validate regex syntax for every rule that has one.
            // Use a generous size limit since some upstream rules (e.g.
            // generic-api-key) produce large compiled automata that exceed
            // the default 10 MB limit. The scanner will apply its own
            // limits at compile time.
            if let Some(pattern) = rule.regex.as_deref() {
                let re = regex::RegexBuilder::new(pattern)
                    .size_limit(100 * (1 << 20)) // 100 MB — validation only
                    .build()
                    .map_err(|e| {
                        Error::Validation(format!(
                            "rule '{}': invalid regex '{}': {e}",
                            rule.id, pattern
                        ))
                    })?;

                // If secret_group is set, verify the regex has enough
                // capture groups.
                if let Some(group) = rule.secret_group {
                    if group > 0 {
                        let num_groups = re.captures_len() - 1; // captures_len includes group 0
                        if (group as usize) > num_groups {
                            return Err(Error::Validation(format!(
                                "rule '{}': secretGroup {} exceeds capture group count {} in regex",
                                rule.id, group, num_groups
                            )));
                        }
                    }
                }
            }

            // Track duplicate IDs as warnings.
            if !seen_ids.insert(&rule.id) {
                self.warnings
                    .push(format!("duplicate rule id '{}'", rule.id));
            }
        }

        Ok(())
    }

    /// Merge another config on top of this one and return the combined result.
    ///
    /// - **Rules:** `other.rules` are appended after `self.rules` (no
    ///   deduplication — the consumer is responsible for avoiding duplicates).
    /// - **Global allowlist:** vectors (`paths`, `regexes`, `stopwords`) from
    ///   `other` are appended to `self`. If only one side has an allowlist, it
    ///   is used as-is. `self.allowlist.description` is preserved when present.
    /// - **Title:** `self.title` is preserved (not overwritten by `other`).
    /// - **Warnings:** warnings from both sides are concatenated.
    pub fn extend(mut self, other: Config) -> Self {
        // Append rules (order: self first, then other).
        self.rules.extend(other.rules);

        // Merge warnings.
        self.warnings.extend(other.warnings);

        // Merge global allowlists.
        match (&mut self.allowlist, other.allowlist) {
            (Some(self_al), Some(other_al)) => {
                self_al.paths.extend(other_al.paths);
                self_al.regexes.extend(other_al.regexes);
                self_al.stopwords.extend(other_al.stopwords);
            }
            (None, Some(other_al)) => {
                self.allowlist = Some(other_al);
            }
            _ => { /* self already has allowlist or neither side does */ }
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // ----- Parsing tests -----

    #[test]
    fn parse_minimal_rule() {
        let toml = r#"
[[rules]]
id = "test-rule"
description = "A test"
regex = '''secret_[a-z]+'''
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "test-rule");
        assert_eq!(config.rules[0].description.as_deref(), Some("A test"));
        assert_eq!(config.rules[0].regex.as_deref(), Some("secret_[a-z]+"));
        assert!(config.rules[0].path.is_none());
        assert!(config.rules[0].entropy.is_none());
        assert!(config.rules[0].keywords.is_empty());
        assert!(config.rules[0].secret_group.is_none());
        assert!(config.rules[0].allowlists.is_empty());
    }

    #[test]
    fn parse_all_optional_fields() {
        let toml = r#"
[[rules]]
id = "full-rule"
description = "Full test"
regex = '''(secret)_([a-z]+)'''
path = '''\.env$'''
entropy = 3.5
keywords = ["secret", "key"]
secretGroup = 2

[[rules.allowlists]]
description = "ignore tests"
regexTarget = "match"
regexes = ["test_.*"]
paths = ["tests/"]
stopwords = ["example"]
condition = "AND"
"#;
        let config = Config::from_toml(toml).unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.id, "full-rule");
        assert_eq!(rule.regex.as_deref(), Some("(secret)_([a-z]+)"));
        assert_eq!(rule.path.as_deref(), Some(r"\.env$"));
        assert_eq!(rule.entropy, Some(3.5));
        assert_eq!(rule.keywords, vec!["secret", "key"]);
        assert_eq!(rule.secret_group, Some(2));

        assert_eq!(rule.allowlists.len(), 1);
        let al = &rule.allowlists[0];
        assert_eq!(al.description.as_deref(), Some("ignore tests"));
        assert_eq!(al.regex_target, RegexTarget::Match);
        assert_eq!(al.regexes, vec!["test_.*"]);
        assert_eq!(al.paths, vec!["tests/"]);
        assert_eq!(al.stopwords, vec!["example"]);
        assert_eq!(al.condition, Condition::And);
    }

    #[test]
    fn parse_multiple_allowlists() {
        let toml = r#"
[[rules]]
id = "multi-al"
description = "Multiple allowlists"
regex = '''key_[a-z]+'''

[[rules.allowlists]]
regexes = ["ignore_1"]

[[rules.allowlists]]
regexes = ["ignore_2"]
paths = ["vendor/"]
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].allowlists.len(), 2);
        assert_eq!(config.rules[0].allowlists[0].regexes, vec!["ignore_1"]);
        assert_eq!(config.rules[0].allowlists[1].regexes, vec!["ignore_2"]);
        assert_eq!(config.rules[0].allowlists[1].paths, vec!["vendor/"]);
    }

    #[test]
    fn parse_path_only_rule() {
        let toml = r#"
[[rules]]
id = "path-only"
description = "Matches by path"
path = '''\.p12$'''
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].id, "path-only");
        assert!(config.rules[0].regex.is_none());
        assert_eq!(config.rules[0].path.as_deref(), Some(r"\.p12$"));
    }

    #[test]
    fn parse_global_allowlist() {
        let toml = r#"
[allowlist]
description = "global"
paths = ["vendor/", "node_modules/"]
regexes = ["EXAMPLE"]
stopwords = ["test"]

[[rules]]
id = "r1"
description = "test"
regex = '''x'''
"#;
        let config = Config::from_toml(toml).unwrap();
        let al = config.allowlist.as_ref().unwrap();
        assert_eq!(al.description.as_deref(), Some("global"));
        assert_eq!(al.paths, vec!["vendor/", "node_modules/"]);
        assert_eq!(al.regexes, vec!["EXAMPLE"]);
        assert_eq!(al.stopwords, vec!["test"]);
    }

    #[test]
    fn parse_title_and_min_version() {
        let toml = r#"
title = "my config"
minVersion = "v8.25.0"

[[rules]]
id = "r1"
description = "test"
regex = '''x'''
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.title.as_deref(), Some("my config"));
        assert_eq!(config.min_version.as_deref(), Some("v8.25.0"));
    }

    // ----- Enum parsing tests -----

    #[test]
    fn regex_target_case_insensitive() {
        for (input, expected) in [
            ("secret", RegexTarget::Secret),
            ("SECRET", RegexTarget::Secret),
            ("Secret", RegexTarget::Secret),
            ("match", RegexTarget::Match),
            ("MATCH", RegexTarget::Match),
            ("line", RegexTarget::Line),
            ("LINE", RegexTarget::Line),
        ] {
            let toml = format!(
                r#"
[[rules]]
id = "t"
description = "t"
regex = '''x'''

[[rules.allowlists]]
regexTarget = "{input}"
regexes = ["x"]
"#
            );
            let config = Config::from_toml(&toml).unwrap();
            assert_eq!(
                config.rules[0].allowlists[0].regex_target, expected,
                "failed for input: {input}"
            );
        }
    }

    #[test]
    fn condition_case_insensitive() {
        for (input, expected) in [
            ("or", Condition::Or),
            ("OR", Condition::Or),
            ("and", Condition::And),
            ("AND", Condition::And),
            ("And", Condition::And),
        ] {
            let toml = format!(
                r#"
[[rules]]
id = "t"
description = "t"
regex = '''x'''

[[rules.allowlists]]
condition = "{input}"
regexes = ["x"]
"#
            );
            let config = Config::from_toml(&toml).unwrap();
            assert_eq!(
                config.rules[0].allowlists[0].condition, expected,
                "failed for input: {input}"
            );
        }
    }

    #[test]
    fn default_regex_target_is_secret() {
        let toml = r#"
[[rules]]
id = "t"
description = "t"
regex = '''x'''

[[rules.allowlists]]
regexes = ["x"]
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(
            config.rules[0].allowlists[0].regex_target,
            RegexTarget::Secret
        );
    }

    #[test]
    fn default_condition_is_or() {
        let toml = r#"
[[rules]]
id = "t"
description = "t"
regex = '''x'''

[[rules.allowlists]]
regexes = ["x"]
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].allowlists[0].condition, Condition::Or);
    }

    // ----- Validation error tests -----

    #[test]
    fn reject_no_regex_or_path() {
        let toml = r#"
[[rules]]
id = "bad-rule"
description = "no match target"
"#;
        let err = Config::from_toml(toml).unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad-rule"), "expected rule id in msg: {msg}");
                assert!(msg.contains("neither"), "expected 'neither' in msg: {msg}");
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn reject_invalid_toml() {
        let err = Config::from_toml("{{not valid toml").unwrap_err();
        assert!(matches!(err, Error::TomlParse(_)));
    }

    #[test]
    fn reject_secret_group_exceeding_capture_count() {
        let toml = r#"
[[rules]]
id = "bad-group"
description = "group too high"
regex = '''no_groups_here'''
secretGroup = 1
"#;
        let err = Config::from_toml(toml).unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad-group"));
                assert!(msg.contains("secretGroup"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn accept_secret_group_within_range() {
        let toml = r#"
[[rules]]
id = "ok-group"
description = "group in range"
regex = '''(first)(second)'''
secretGroup = 2
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].secret_group, Some(2));
    }

    #[test]
    fn secret_group_zero_skips_group_count_check() {
        let toml = r#"
[[rules]]
id = "zero-group"
description = "group zero"
regex = '''no_groups'''
secretGroup = 0
"#;
        // secretGroup = 0 means "use the whole match", no capture group needed.
        // But the regex itself is still validated for syntax.
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].secret_group, Some(0));
    }

    #[test]
    fn reject_invalid_regex_without_secret_group() {
        // R-002: even without secretGroup, an invalid regex must fail.
        let toml = r#"
[[rules]]
id = "bad-regex"
description = "invalid regex, no secretGroup"
regex = '''[unclosed'''
"#;
        let err = Config::from_toml(toml).unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad-regex"), "expected rule id in msg: {msg}");
                assert!(
                    msg.contains("invalid regex"),
                    "expected 'invalid regex' in msg: {msg}"
                );
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn reject_invalid_regex_with_secret_group_zero() {
        // Even with secretGroup = 0, the regex must compile.
        let toml = r#"
[[rules]]
id = "bad-regex-sg0"
description = "invalid regex with sg=0"
regex = '''(unclosed'''
secretGroup = 0
"#;
        let err = Config::from_toml(toml).unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad-regex-sg0"));
                assert!(msg.contains("invalid regex"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    // ----- Duplicate ID warning tests -----

    #[test]
    fn duplicate_ids_produce_warnings() {
        let toml = r#"
[[rules]]
id = "dup"
description = "first"
regex = '''a'''

[[rules]]
id = "dup"
description = "second"
regex = '''b'''

[[rules]]
id = "unique"
description = "third"
regex = '''c'''

[[rules]]
id = "dup"
description = "third dup"
regex = '''d'''
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 4);
        // Two duplicate occurrences (second and fourth with id "dup")
        assert_eq!(config.warnings.len(), 2);
        assert!(config.warnings[0].contains("dup"));
        assert!(config.warnings[1].contains("dup"));
    }

    #[test]
    fn no_warnings_for_unique_ids() {
        let toml = r#"
[[rules]]
id = "a"
description = "a"
regex = '''x'''

[[rules]]
id = "b"
description = "b"
regex = '''y'''
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(config.warnings.is_empty());
    }

    // ----- Default config tests -----

    #[test]
    fn default_config_parses() {
        let config = Config::default().unwrap();
        assert!(
            config.rules.len() >= 222,
            "expected at least 222 rules, got {}",
            config.rules.len()
        );
    }

    #[test]
    fn default_config_has_global_allowlist() {
        let config = Config::default().unwrap();
        assert!(config.allowlist.is_some());
    }

    #[test]
    fn config_version_constant() {
        assert!(GITLEAKS_CONFIG_VERSION.starts_with('v'));
    }

    // ----- Roundtrip / sanity checks on known rules -----

    #[test]
    fn roundtrip_aws_access_token() {
        let config = Config::default().unwrap();
        let rule = config
            .rules
            .iter()
            .find(|r| r.id == "aws-access-token")
            .expect("aws-access-token rule not found");

        assert!(rule.regex.is_some());
        assert!(rule.description.is_some());
        assert!(!rule.keywords.is_empty());
    }

    #[test]
    fn roundtrip_github_pat() {
        let config = Config::default().unwrap();
        let rule = config
            .rules
            .iter()
            .find(|r| r.id == "github-pat")
            .expect("github-pat rule not found");

        assert!(rule.regex.is_some());
        assert!(!rule.keywords.is_empty());
    }

    #[test]
    fn roundtrip_pkcs12_file_path_only() {
        let config = Config::default().unwrap();
        let rule = config
            .rules
            .iter()
            .find(|r| r.id == "pkcs12-file")
            .expect("pkcs12-file rule not found");

        assert!(rule.regex.is_none(), "pkcs12-file should have no regex");
        assert!(rule.path.is_some(), "pkcs12-file should have a path");
    }

    #[test]
    fn roundtrip_sonar_api_token_secret_group() {
        let config = Config::default().unwrap();
        let rule = config
            .rules
            .iter()
            .find(|r| r.id == "sonar-api-token")
            .expect("sonar-api-token rule not found");

        assert_eq!(rule.secret_group, Some(2));
    }

    #[test]
    fn roundtrip_generic_api_key_has_allowlists() {
        let config = Config::default().unwrap();
        let rule = config
            .rules
            .iter()
            .find(|r| r.id == "generic-api-key")
            .expect("generic-api-key rule not found");

        assert!(
            rule.allowlists.len() >= 2,
            "generic-api-key should have multiple allowlists, got {}",
            rule.allowlists.len()
        );
    }

    #[test]
    fn roundtrip_rules_with_entropy() {
        let config = Config::default().unwrap();
        let with_entropy = config.rules.iter().filter(|r| r.entropy.is_some()).count();
        assert!(
            with_entropy >= 100,
            "expected at least 100 rules with entropy, got {with_entropy}"
        );
    }

    // ----- from_file tests -----

    #[test]
    fn from_file_success() {
        let dir = std::env::temp_dir().join("gitleaks_rs_test_from_file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "file-rule"
description = "from file"
regex = '''x'''
"#,
        )
        .unwrap();

        let config = Config::from_file(&path).unwrap();
        assert_eq!(config.rules[0].id, "file-rule");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_file_not_found() {
        let err = Config::from_file(Path::new("/nonexistent/gitleaks.toml")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    // ----- Edge case tests -----

    #[test]
    fn empty_rules_vec() {
        let toml = r#"
title = "empty"
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(config.rules.is_empty());
    }

    #[test]
    fn rule_with_empty_allowlists() {
        let toml = r#"
[[rules]]
id = "empty-al"
description = "no allowlist entries"
regex = '''x'''
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(config.rules[0].allowlists.is_empty());
    }

    #[test]
    fn entropy_as_integer() {
        let toml = r#"
[[rules]]
id = "int-entropy"
description = "entropy as int"
regex = '''x'''
entropy = 4
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].entropy, Some(4.0));
    }

    #[test]
    fn entropy_as_float() {
        let toml = r#"
[[rules]]
id = "float-entropy"
description = "entropy as float"
regex = '''x'''
entropy = 3.5
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].entropy, Some(3.5));
    }

    #[test]
    fn invalid_regex_target_variant() {
        let toml = r#"
[[rules]]
id = "t"
description = "t"
regex = '''x'''

[[rules.allowlists]]
regexTarget = "bogus"
regexes = ["x"]
"#;
        let err = Config::from_toml(toml).unwrap_err();
        assert!(matches!(err, Error::TomlParse(_)));
    }

    #[test]
    fn invalid_condition_variant() {
        let toml = r#"
[[rules]]
id = "t"
description = "t"
regex = '''x'''

[[rules.allowlists]]
condition = "xor"
regexes = ["x"]
"#;
        let err = Config::from_toml(toml).unwrap_err();
        assert!(matches!(err, Error::TomlParse(_)));
    }

    #[test]
    fn rule_with_path_and_entropy_no_regex() {
        // A rule with `path` should pass validation even without `regex`.
        let toml = r#"
[[rules]]
id = "path-entropy"
description = "path with entropy"
path = '''\.env$'''
entropy = 3.0
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(config.rules[0].regex.is_none());
        assert_eq!(config.rules[0].entropy, Some(3.0));
    }

    #[test]
    fn secret_group_without_regex_passes() {
        // secret_group validation only fires when regex is present.
        let toml = r#"
[[rules]]
id = "sg-no-regex"
description = "secret group but path only"
path = '''\.key$'''
secretGroup = 5
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].secret_group, Some(5));
    }

    // ----- Default impl tests -----

    #[test]
    fn rule_default_has_empty_fields() {
        let rule = Rule::default();
        assert_eq!(rule.id, "");
        assert!(rule.description.is_none());
        assert!(rule.regex.is_none());
        assert!(rule.path.is_none());
        assert!(rule.entropy.is_none());
        assert!(rule.keywords.is_empty());
        assert!(rule.secret_group.is_none());
        assert!(rule.allowlists.is_empty());
    }

    #[test]
    fn allowlist_default_has_empty_fields() {
        let al = Allowlist::default();
        assert!(al.description.is_none());
        assert!(al.paths.is_empty());
        assert!(al.regexes.is_empty());
        assert!(al.stopwords.is_empty());
    }

    #[test]
    fn rule_allowlist_default_has_correct_enums() {
        let ral = RuleAllowlist::default();
        assert!(ral.description.is_none());
        assert_eq!(ral.regex_target, RegexTarget::Secret);
        assert_eq!(ral.condition, Condition::Or);
        assert!(ral.regexes.is_empty());
        assert!(ral.paths.is_empty());
        assert!(ral.stopwords.is_empty());
    }

    #[test]
    fn rule_struct_update_syntax_with_default() {
        let rule = Rule {
            id: "custom".into(),
            regex: Some("secret_[a-z]+".into()),
            ..Default::default()
        };
        assert_eq!(rule.id, "custom");
        assert_eq!(rule.regex.as_deref(), Some("secret_[a-z]+"));
        assert!(rule.path.is_none());
        assert!(rule.keywords.is_empty());
    }

    // ----- Config::extend tests -----

    #[test]
    fn extend_appends_rules() {
        let base = Config::from_toml(
            r#"
[[rules]]
id = "a"
regex = '''x'''
"#,
        )
        .unwrap();

        let other = Config::from_toml(
            r#"
[[rules]]
id = "b"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        assert_eq!(merged.rules.len(), 2);
        assert_eq!(merged.rules[0].id, "a");
        assert_eq!(merged.rules[1].id, "b");
    }

    #[test]
    fn extend_does_not_deduplicate_rules() {
        let base = Config::from_toml(
            r#"
[[rules]]
id = "same"
regex = '''x'''
"#,
        )
        .unwrap();

        let other = Config::from_toml(
            r#"
[[rules]]
id = "same"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        assert_eq!(merged.rules.len(), 2);
        assert_eq!(merged.rules[0].id, "same");
        assert_eq!(merged.rules[1].id, "same");
    }

    #[test]
    fn extend_preserves_rule_order() {
        let base = Config::from_toml(
            r#"
[[rules]]
id = "first"
regex = '''a'''

[[rules]]
id = "second"
regex = '''b'''
"#,
        )
        .unwrap();

        let other = Config::from_toml(
            r#"
[[rules]]
id = "third"
regex = '''c'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        let ids: Vec<&str> = merged.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["first", "second", "third"]);
    }

    #[test]
    fn extend_self_no_allowlist_other_has_allowlist() {
        let base = Config::from_toml(
            r#"
[[rules]]
id = "a"
regex = '''x'''
"#,
        )
        .unwrap();
        assert!(base.allowlist.is_none());

        let other = Config::from_toml(
            r#"
[allowlist]
paths = ["vendor/"]
regexes = ["EXAMPLE"]
stopwords = ["test"]

[[rules]]
id = "b"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        let al = merged.allowlist.as_ref().unwrap();
        assert_eq!(al.paths, vec!["vendor/"]);
        assert_eq!(al.regexes, vec!["EXAMPLE"]);
        assert_eq!(al.stopwords, vec!["test"]);
    }

    #[test]
    fn extend_merges_both_allowlists() {
        let base = Config::from_toml(
            r#"
[allowlist]
description = "base allowlist"
paths = ["base_path/"]
regexes = ["BASE"]
stopwords = ["base_word"]

[[rules]]
id = "a"
regex = '''x'''
"#,
        )
        .unwrap();

        let other = Config::from_toml(
            r#"
[allowlist]
description = "other allowlist"
paths = ["other_path/"]
regexes = ["OTHER"]
stopwords = ["other_word"]

[[rules]]
id = "b"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        let al = merged.allowlist.as_ref().unwrap();
        // Vectors are concatenated.
        assert_eq!(al.paths, vec!["base_path/", "other_path/"]);
        assert_eq!(al.regexes, vec!["BASE", "OTHER"]);
        assert_eq!(al.stopwords, vec!["base_word", "other_word"]);
        // Self description is preserved.
        assert_eq!(al.description.as_deref(), Some("base allowlist"));
    }

    #[test]
    fn extend_self_has_allowlist_other_does_not() {
        let base = Config::from_toml(
            r#"
[allowlist]
paths = ["keep/"]

[[rules]]
id = "a"
regex = '''x'''
"#,
        )
        .unwrap();

        let other = Config::from_toml(
            r#"
[[rules]]
id = "b"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        let al = merged.allowlist.as_ref().unwrap();
        assert_eq!(al.paths, vec!["keep/"]);
    }

    #[test]
    fn extend_preserves_self_title() {
        let base = Config::from_toml(
            r#"
title = "base title"

[[rules]]
id = "a"
regex = '''x'''
"#,
        )
        .unwrap();
        // Ensure title is set.
        assert_eq!(base.title.as_deref(), Some("base title"));

        let other = Config::from_toml(
            r#"
title = "other title"

[[rules]]
id = "b"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        assert_eq!(merged.title.as_deref(), Some("base title"));
    }

    #[test]
    fn extend_concatenates_warnings() {
        let base = Config::from_toml(
            r#"
[[rules]]
id = "dup"
regex = '''a'''

[[rules]]
id = "dup"
regex = '''b'''
"#,
        )
        .unwrap();
        assert_eq!(base.warnings.len(), 1);

        let other = Config::from_toml(
            r#"
[[rules]]
id = "dup2"
regex = '''c'''

[[rules]]
id = "dup2"
regex = '''d'''
"#,
        )
        .unwrap();
        assert_eq!(other.warnings.len(), 1);

        let merged = base.extend(other);
        assert_eq!(merged.warnings.len(), 2);
    }

    #[test]
    fn extend_with_empty_allowlist_vectors() {
        let base = Config::from_toml(
            r#"
[allowlist]
paths = ["a/"]

[[rules]]
id = "r"
regex = '''x'''
"#,
        )
        .unwrap();

        let other = Config::from_toml(
            r#"
[allowlist]

[[rules]]
id = "s"
regex = '''y'''
"#,
        )
        .unwrap();

        let merged = base.extend(other);
        let al = merged.allowlist.as_ref().unwrap();
        assert_eq!(al.paths, vec!["a/"]);
        assert!(al.regexes.is_empty());
    }

    #[test]
    fn extend_chaining() {
        let a = Config::from_toml("[[rules]]\nid = \"a\"\nregex = '''x'''").unwrap();
        let b = Config::from_toml("[[rules]]\nid = \"b\"\nregex = '''y'''").unwrap();
        let c = Config::from_toml("[[rules]]\nid = \"c\"\nregex = '''z'''").unwrap();

        let merged = a.extend(b).extend(c);
        let ids: Vec<&str> = merged.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn extend_neither_has_allowlist() {
        let a = Config::from_toml("[[rules]]\nid = \"a\"\nregex = '''x'''").unwrap();
        let b = Config::from_toml("[[rules]]\nid = \"b\"\nregex = '''y'''").unwrap();
        let merged = a.extend(b);
        assert!(merged.allowlist.is_none());
    }
}
