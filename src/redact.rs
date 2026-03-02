//! Secret redaction utilities.
//!
//! This module provides [`RedactResult`] and internal helpers for replacing
//! detected secrets in text while preserving surrounding content. The public
//! redaction API lives on [`crate::Scanner`]; this module owns the data types
//! and low-level replacement mechanics.

use std::ops::Range;

use crate::finding::Finding;

/// The result of a redaction operation.
///
/// Contains the redacted text, the findings that were detected, and the
/// number of secrets that were actually replaced.
#[derive(Debug, Clone)]
pub struct RedactResult {
    /// The text after redaction. Secrets are replaced with the replacement
    /// string (default `"REDACTED"`).
    pub content: String,
    /// All findings detected during scanning (before redaction).
    pub findings: Vec<Finding>,
    /// Number of secret replacements actually performed. This may be less
    /// than `findings.len()` if overlapping spans caused some replacements
    /// to be skipped.
    pub redaction_count: usize,
}

/// Resolve the byte range of the secret within the scanned line.
///
/// `Finding.start`/`Finding.end` are full-match offsets. The secret is a
/// substring of `match_text`. We locate the secret within `match_text` and
/// offset by `finding.start` to get absolute byte positions in the line.
///
/// Returns `None` if the secret cannot be located or the span is degenerate.
pub(crate) fn secret_range(finding: &Finding) -> Option<Range<usize>> {
    let secret = &finding.secret;
    if secret.is_empty() {
        return None;
    }
    // Find the secret within the full match text.
    let offset_in_match = finding.match_text.find(secret.as_str())?;
    let start = finding.start + offset_in_match;
    let end = start + secret.len();
    Some(start..end)
}

/// Check whether `candidate` overlaps any range in `applied`.
fn overlaps_any(candidate: &Range<usize>, applied: &[Range<usize>]) -> bool {
    applied
        .iter()
        .any(|r| candidate.start < r.end && r.start < candidate.end)
}

/// Apply secret replacements to a line, given pre-computed findings.
///
/// Findings are sorted right-to-left by secret start offset so that
/// earlier byte offsets remain valid as later portions of the string
/// are replaced. Overlapping ranges are skipped.
///
/// Returns `(redacted_content, redaction_count)`.
pub(crate) fn apply_replacements(
    line: &str,
    findings: &[Finding],
    replacement: &str,
) -> (String, usize) {
    // Build (secret_range, finding_index) pairs, filtering out unresolvable spans.
    let mut spans: Vec<(Range<usize>, usize)> = findings
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let range = secret_range(f)?;
            // Validate range is within the line's byte length.
            if range.end > line.len() || range.start > line.len() {
                return None;
            }
            // Validate that the range falls on UTF-8 char boundaries.
            if !line.is_char_boundary(range.start) || !line.is_char_boundary(range.end) {
                return None;
            }
            Some((range, i))
        })
        .collect();

    // Sort by start offset descending (right-to-left).
    spans.sort_by(|a, b| b.0.start.cmp(&a.0.start));

    let mut result = line.to_string();
    let mut applied: Vec<Range<usize>> = Vec::new();
    let mut count = 0usize;

    for (range, _) in &spans {
        if overlaps_any(range, &applied) {
            continue;
        }
        result.replace_range(range.clone(), replacement);
        applied.push(range.clone());
        count += 1;
    }

    (result, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(secret: &str, match_text: &str, start: usize, end: usize) -> Finding {
        Finding {
            rule_id: "test-rule".to_string(),
            description: "test".to_string(),
            secret: secret.to_string(),
            match_text: match_text.to_string(),
            start,
            end,
            entropy: None,
            line_number: None,
        }
    }

    #[test]
    fn secret_range_basic() {
        // match_text = "key=SECRET123", match starts at byte 4 in the line
        let f = make_finding("SECRET123", "key=SECRET123", 4, 17);
        let range = secret_range(&f).unwrap();
        assert_eq!(range, 8..17); // 4 + 4 ("key=".len()) = 8
    }

    #[test]
    fn secret_range_empty_secret_returns_none() {
        let f = make_finding("", "key=val", 0, 7);
        assert!(secret_range(&f).is_none());
    }

    #[test]
    fn secret_range_secret_not_in_match_returns_none() {
        let f = make_finding("MISSING", "key=val", 0, 7);
        assert!(secret_range(&f).is_none());
    }

    #[test]
    fn apply_replacements_single() {
        let line = "export AWS_KEY=AKIAIOSFODNN7EXAMPLE";
        let f = make_finding(
            "AKIAIOSFODNN7EXAMPLE",
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            7,
            35,
        );
        let (result, count) = apply_replacements(line, &[f], "REDACTED");
        assert_eq!(result, "export AWS_KEY=REDACTED");
        assert_eq!(count, 1);
    }

    #[test]
    fn apply_replacements_multiple_non_overlapping() {
        // Two secrets on one line.
        let line = "A=SECRET1 B=SECRET2";
        let f1 = make_finding("SECRET1", "A=SECRET1", 0, 9);
        let f2 = make_finding("SECRET2", "B=SECRET2", 10, 19);
        let (result, count) = apply_replacements(line, &[f1, f2], "REDACTED");
        assert_eq!(result, "A=REDACTED B=REDACTED");
        assert_eq!(count, 2);
    }

    #[test]
    fn apply_replacements_overlapping_skips_wider() {
        let line = "OVERLAP_SECRET_HERE";
        // First finding covers bytes 0..19 (wider)
        let f1 = make_finding("OVERLAP_SECRET_HERE", "OVERLAP_SECRET_HERE", 0, 19);
        // Second finding overlaps — covers bytes 8..19 (narrower, further right)
        let f2 = make_finding("SECRET_HERE", "SECRET_HERE", 8, 19);
        let (result, count) = apply_replacements(line, &[f1, f2], "REDACTED");
        // Right-to-left: f2 (8..19) is replaced first, f1 (0..19) overlaps and is skipped.
        assert_eq!(result, "OVERLAP_REDACTED");
        assert_eq!(count, 1);
    }

    #[test]
    fn apply_replacements_no_findings() {
        let line = "nothing here";
        let (result, count) = apply_replacements(line, &[], "REDACTED");
        assert_eq!(result, "nothing here");
        assert_eq!(count, 0);
    }

    #[test]
    fn apply_replacements_out_of_bounds_skipped() {
        let line = "short";
        let f = make_finding("secret", "secret", 100, 106);
        let (result, count) = apply_replacements(line, &[f], "REDACTED");
        assert_eq!(result, "short");
        assert_eq!(count, 0);
    }

    #[test]
    fn apply_replacements_custom_replacement() {
        let line = "key=SECRET";
        let f = make_finding("SECRET", "key=SECRET", 0, 10);
        let (result, count) = apply_replacements(line, &[f], "***");
        assert_eq!(result, "key=***");
        assert_eq!(count, 1);
    }

    #[test]
    fn apply_replacements_utf8_text() {
        // Ensure byte-safe indexing with multi-byte characters.
        let line = "clé=SECRET après";
        let key_eq_len = "clé=".len(); // 5 bytes (é is 2 bytes)
        let f = make_finding("SECRET", "clé=SECRET", 0, key_eq_len + 6);
        let (result, count) = apply_replacements(line, &[f], "REDACTED");
        assert_eq!(result, "clé=REDACTED après");
        assert_eq!(count, 1);
    }
}
