//! # gitleaks-rs
//!
//! A Rust implementation of the [gitleaks](https://github.com/gitleaks/gitleaks)
//! secret detection rule engine. Ships with the official 222-rule config
//! embedded at compile time — zero configuration required.
//!
//! # Quick Start
//!
//! ```rust
//! use gitleaks_rs::{Config, Scanner};
//!
//! // Load the embedded official gitleaks rule set
//! let config = Config::default().expect("embedded config is valid");
//! let scanner = Scanner::new(config).unwrap();
//!
//! // Scan a string for secrets
//! let findings = scanner.scan_text(
//!     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
//!     None,
//! );
//!
//! for f in &findings {
//!     println!("[{}] {}", f.rule_id, f.secret);
//! }
//! ```
//!
//! # Redaction
//!
//! ```rust
//! use gitleaks_rs::{Config, Scanner};
//!
//! let config = Config::from_toml(r#"
//! [[rules]]
//! id = "test-secret"
//! description = "Test secret"
//! regex = '''secret_key\s*=\s*"([^"]+)"'''
//! keywords = ["secret_key"]
//! "#).unwrap();
//! let scanner = Scanner::new(config).unwrap();
//! let result = scanner.redact_text(
//!     "secret_key = \"super_secret_value\"\n",
//!     None,
//! );
//! assert!(result.content.contains("REDACTED"));
//! assert!(!result.content.contains("super_secret_value"));
//! ```
//!
//! # Custom Config
//!
//! ```rust
//! use gitleaks_rs::{ConfigBuilder, Rule, Scanner};
//!
//! let config = ConfigBuilder::new()
//!     .title("my project rules")
//!     .add_rule(Rule {
//!         id: "internal-token".into(),
//!         description: Some("Internal API token".into()),
//!         regex: Some(r"INTERNAL_[A-Z0-9]{32}".into()),
//!         keywords: vec!["internal_".into()],
//!         ..Default::default()
//!     })
//!     .build()
//!     .expect("valid config");
//!
//! let scanner = Scanner::new(config).unwrap();
//! let findings = scanner.scan_line("token=INTERNAL_ABCDEFGH0123456789ABCDEFGH012345", None);
//! assert_eq!(findings.len(), 1);
//! ```
//!
//! # Extending the Default Rules
//!
//! ```rust
//! use gitleaks_rs::{Config, ConfigBuilder, Rule, Scanner};
//!
//! let defaults = Config::default().unwrap();
//! let custom = ConfigBuilder::new()
//!     .add_rule(Rule {
//!         id: "my-custom-rule".into(),
//!         regex: Some(r"MY_SECRET_[a-zA-Z0-9]{16}".into()),
//!         keywords: vec!["my_secret_".into()],
//!         ..Default::default()
//!     })
//!     .build()
//!     .unwrap();
//!
//! let merged = defaults.extend(custom);
//! let scanner = Scanner::new(merged).unwrap();
//! assert!(scanner.rule_count() > 222);
//! ```

#![deny(missing_docs)]

/// Configuration parsing and validation for the gitleaks TOML format.
pub mod config;

/// Programmatic configuration builder (no TOML required).
pub mod builder;

/// Shannon entropy calculator for secret detection filtering.
pub mod entropy;

/// Error types used throughout the crate.
pub mod error;

/// Detection result types.
pub mod finding;

/// Secret redaction utilities.
pub mod redact;

/// Precompiled rule engine for secret detection.
pub mod scanner;

/// Disk-based DFA cache for near-instant `Scanner` construction.
#[cfg(feature = "cache")]
pub(crate) mod cache;

pub use builder::ConfigBuilder;
pub use config::{
    Allowlist, Condition, Config, RegexTarget, Rule, RuleAllowlist, GITLEAKS_CONFIG_VERSION,
};
pub use entropy::shannon_entropy;
pub use error::{Error, Result};
pub use finding::Finding;
pub use redact::RedactResult;
pub use scanner::Scanner;
