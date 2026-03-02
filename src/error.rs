use std::fmt;

/// Errors produced by gitleaks-rs config parsing and rule operations.
#[derive(Debug)]
pub enum Error {
    /// TOML deserialization failed.
    TomlParse(toml::de::Error),
    /// File I/O error.
    Io(std::io::Error),
    /// Post-parse validation failure (e.g. missing regex/path, bad secret_group).
    Validation(String),
    /// Regex compilation error (e.g. invalid pattern in a rule).
    Regex(regex::Error),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TomlParse(e) => write!(f, "TOML parse error: {e}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Validation(msg) => write!(f, "validation error: {msg}"),
            Error::Regex(e) => write!(f, "regex error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::TomlParse(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Regex(e) => Some(e),
            Error::Validation(_) => None,
        }
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::TomlParse(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Self {
        Error::Regex(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_validation_error() {
        let err = Error::Validation("rule 'foo' has neither regex nor path".into());
        assert_eq!(
            err.to_string(),
            "validation error: rule 'foo' has neither regex nor path"
        );
    }

    #[test]
    fn display_toml_error() {
        let toml_err = toml::from_str::<toml::Value>("{{invalid").unwrap_err();
        let err = Error::from(toml_err);
        assert!(err.to_string().starts_with("TOML parse error:"));
    }

    #[test]
    fn display_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err = Error::from(io_err);
        assert!(err.to_string().starts_with("I/O error:"));
    }

    #[test]
    #[allow(clippy::invalid_regex)]
    fn display_regex_error() {
        let re_err = regex::Regex::new(r"[invalid").unwrap_err();
        let err = Error::from(re_err);
        assert!(err.to_string().starts_with("regex error:"));
    }

    #[test]
    fn error_source_chains() {
        use std::error::Error as StdError;

        let toml_err = toml::from_str::<toml::Value>("{{").unwrap_err();
        let err = Error::from(toml_err);
        assert!(err.source().is_some());

        let val_err = Error::Validation("test".into());
        assert!(val_err.source().is_none());
    }
}
