use crate::config::{Allowlist, Config, Rule};
use crate::error::Result;

/// Programmatic builder for constructing a [`Config`] without TOML.
///
/// `ConfigBuilder` lets you assemble rules and allowlists in code and
/// produces a validated `Config` that can be passed directly to
/// [`Scanner::new`](crate::scanner::Scanner::new).
///
/// # Example
///
/// ```
/// use gitleaks_rs::{ConfigBuilder, Rule};
///
/// let config = ConfigBuilder::new()
///     .title("my custom config")
///     .add_rule(Rule {
///         id: "custom-key".into(),
///         regex: Some(r"custom_key_[a-zA-Z0-9]{32}".into()),
///         keywords: vec!["custom_key".into()],
///         ..Default::default()
///     })
///     .build()
///     .expect("valid config");
///
/// assert_eq!(config.rules.len(), 1);
/// ```
pub struct ConfigBuilder {
    rules: Vec<Rule>,
    allowlist: Option<Allowlist>,
    title: Option<String>,
}

impl ConfigBuilder {
    /// Create an empty builder with no rules, no allowlist, and no title.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            allowlist: None,
            title: None,
        }
    }

    /// Set the config title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Append a rule to the builder.
    pub fn add_rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Set the global allowlist (replaces any previously set allowlist).
    pub fn set_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// Consume the builder and produce a validated [`Config`].
    ///
    /// Runs the same validation as [`Config::from_toml`], so invalid regexes,
    /// missing match targets, and bad `secret_group` references are caught
    /// before the config reaches [`Scanner::new`](crate::scanner::Scanner::new).
    pub fn build(self) -> Result<Config> {
        let mut config = Config {
            title: self.title,
            min_version: None,
            rules: self.rules,
            allowlist: self.allowlist,
            warnings: Vec::new(),
        };
        config.validate()?;
        Ok(config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleAllowlist;
    use crate::error::Error;

    #[test]
    fn builder_new_and_default_equivalent() {
        let from_new = ConfigBuilder::new();
        let from_default = ConfigBuilder::default();
        assert!(from_new.rules.is_empty());
        assert!(from_new.allowlist.is_none());
        assert!(from_new.title.is_none());
        assert!(from_default.rules.is_empty());
        assert!(from_default.allowlist.is_none());
        assert!(from_default.title.is_none());
    }

    #[test]
    fn builder_title_sets_config_title() {
        let config = ConfigBuilder::new()
            .title("test config")
            .add_rule(Rule {
                id: "r1".into(),
                regex: Some("x".into()),
                ..Default::default()
            })
            .build()
            .unwrap();
        assert_eq!(config.title.as_deref(), Some("test config"));
    }

    #[test]
    fn builder_add_rule_basic() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "a".into(),
                regex: Some("x".into()),
                ..Default::default()
            })
            .add_rule(Rule {
                id: "b".into(),
                path: Some(r"\.env$".into()),
                ..Default::default()
            })
            .build()
            .unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].id, "a");
        assert_eq!(config.rules[1].id, "b");
    }

    #[test]
    fn builder_set_allowlist() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "r".into(),
                regex: Some("x".into()),
                ..Default::default()
            })
            .set_allowlist(Allowlist {
                paths: vec!["vendor/".into()],
                ..Default::default()
            })
            .build()
            .unwrap();
        let al = config.allowlist.as_ref().unwrap();
        assert_eq!(al.paths, vec!["vendor/"]);
    }

    #[test]
    fn builder_set_allowlist_replaces_previous() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "r".into(),
                regex: Some("x".into()),
                ..Default::default()
            })
            .set_allowlist(Allowlist {
                paths: vec!["first/".into()],
                ..Default::default()
            })
            .set_allowlist(Allowlist {
                paths: vec!["second/".into()],
                ..Default::default()
            })
            .build()
            .unwrap();
        let al = config.allowlist.as_ref().unwrap();
        assert_eq!(al.paths, vec!["second/"]);
    }

    #[test]
    fn builder_rejects_rule_without_regex_or_path() {
        let err = ConfigBuilder::new()
            .add_rule(Rule {
                id: "bad".into(),
                ..Default::default()
            })
            .build()
            .unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad"));
                assert!(msg.contains("neither"));
            }
            other => panic!("expected Validation, got: {other}"),
        }
    }

    #[test]
    fn builder_rejects_invalid_regex() {
        let err = ConfigBuilder::new()
            .add_rule(Rule {
                id: "bad-re".into(),
                regex: Some("[unclosed".into()),
                ..Default::default()
            })
            .build()
            .unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad-re"));
                assert!(msg.contains("invalid regex"));
            }
            other => panic!("expected Validation, got: {other}"),
        }
    }

    #[test]
    fn builder_rejects_secret_group_exceeding_captures() {
        let err = ConfigBuilder::new()
            .add_rule(Rule {
                id: "bad-sg".into(),
                regex: Some("no_groups".into()),
                secret_group: Some(1),
                ..Default::default()
            })
            .build()
            .unwrap_err();
        match &err {
            Error::Validation(msg) => {
                assert!(msg.contains("bad-sg"));
                assert!(msg.contains("secretGroup"));
            }
            other => panic!("expected Validation, got: {other}"),
        }
    }

    #[test]
    fn builder_accepts_path_only_rule() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "path-only".into(),
                path: Some(r"\.p12$".into()),
                ..Default::default()
            })
            .build()
            .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(config.rules[0].regex.is_none());
    }

    #[test]
    fn builder_accepts_secret_group_zero() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "sg0".into(),
                regex: Some("no_groups".into()),
                secret_group: Some(0),
                ..Default::default()
            })
            .build()
            .unwrap();
        assert_eq!(config.rules[0].secret_group, Some(0));
    }

    #[test]
    fn builder_empty_rules_succeeds() {
        let config = ConfigBuilder::new().build().unwrap();
        assert!(config.rules.is_empty());
        assert!(config.allowlist.is_none());
    }

    #[test]
    fn builder_duplicate_ids_produce_warnings() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "dup".into(),
                regex: Some("a".into()),
                ..Default::default()
            })
            .add_rule(Rule {
                id: "dup".into(),
                regex: Some("b".into()),
                ..Default::default()
            })
            .build()
            .unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.warnings.len(), 1);
        assert!(config.warnings[0].contains("dup"));
    }

    #[test]
    fn builder_min_version_is_none() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "r".into(),
                regex: Some("x".into()),
                ..Default::default()
            })
            .build()
            .unwrap();
        assert!(config.min_version.is_none());
    }

    #[test]
    fn builder_rule_default_fields() {
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
    fn builder_allowlist_default_fields() {
        let al = Allowlist::default();
        assert!(al.description.is_none());
        assert!(al.paths.is_empty());
        assert!(al.regexes.is_empty());
        assert!(al.stopwords.is_empty());
    }

    #[test]
    fn builder_rule_allowlist_default_fields() {
        let ral = RuleAllowlist::default();
        assert!(ral.description.is_none());
        assert_eq!(ral.regex_target, crate::config::RegexTarget::Secret);
        assert!(ral.regexes.is_empty());
        assert!(ral.paths.is_empty());
        assert!(ral.stopwords.is_empty());
        assert_eq!(ral.condition, crate::config::Condition::Or);
    }

    #[test]
    fn builder_with_rule_allowlist() {
        let config = ConfigBuilder::new()
            .add_rule(Rule {
                id: "r".into(),
                regex: Some("x".into()),
                allowlists: vec![RuleAllowlist {
                    regexes: vec!["ignore".into()],
                    ..Default::default()
                }],
                ..Default::default()
            })
            .build()
            .unwrap();
        assert_eq!(config.rules[0].allowlists.len(), 1);
        assert_eq!(config.rules[0].allowlists[0].regexes, vec!["ignore"]);
    }
}
