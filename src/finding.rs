/// A detected secret finding from scanning text.
///
/// Each `Finding` represents a single match of a detection rule against
/// input text. All string fields are owned values, making findings safe
/// to collect, store, and return across API boundaries.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The rule ID that produced this finding.
    pub rule_id: String,
    /// Human-readable description of the matched rule.
    pub description: String,
    /// The extracted secret value (from the appropriate capture group).
    pub secret: String,
    /// The full regex match text.
    pub match_text: String,
    /// Byte offset of the match start within the scanned line.
    pub start: usize,
    /// Byte offset of the match end within the scanned line.
    pub end: usize,
    /// Shannon entropy of the secret, if the rule has an entropy threshold.
    pub entropy: Option<f64>,
    /// Line number (1-indexed), populated by text/file scanning (spec 05).
    /// `None` when using `scan_line` directly.
    pub line_number: Option<usize>,
}
