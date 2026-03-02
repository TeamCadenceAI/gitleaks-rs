//! Shannon entropy calculator for secret detection filtering.
//!
//! Rules with an `entropy` threshold use Shannon entropy to discard
//! low-randomness matches (placeholders, common strings). The calculation
//! operates on raw bytes, matching the upstream gitleaks Go implementation.

/// Computes the Shannon entropy of a string, operating on raw bytes.
///
/// Returns a value in the range `[0.0, 8.0]` where 0.0 indicates no
/// randomness (empty or single-distinct-byte input) and 8.0 is the
/// theoretical maximum for byte-level entropy.
///
/// # Examples
///
/// ```
/// use gitleaks_rs::shannon_entropy;
///
/// assert_eq!(shannon_entropy(""), 0.0);
/// assert!(shannon_entropy("abcdefghij") > 3.0);
/// ```
pub fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }

    let total = len as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Returns `true` if the secret passes the entropy threshold check.
///
/// - If `threshold` is `None`, always returns `true` (no entropy filtering).
/// - If `threshold` is `Some(t)`, computes Shannon entropy and returns
///   `true` only when entropy >= threshold.
pub(crate) fn passes_entropy_check(secret: &str, threshold: Option<f64>) -> bool {
    match threshold {
        None => true,
        Some(t) => shannon_entropy(secret) >= t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- shannon_entropy tests ---

    #[test]
    fn empty_string_returns_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_byte_repeated_returns_zero() {
        // log2(1) = 0, so entropy of a uniform string is 0.0
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
    }

    #[test]
    fn two_distinct_bytes_equal_frequency() {
        // "ab" → p=0.5 each → -2*(0.5 * log2(0.5)) = 1.0
        let e = shannon_entropy("ab");
        assert!((e - 1.0).abs() < 1e-10, "expected 1.0, got {e}");
    }

    #[test]
    fn four_distinct_bytes_equal_frequency() {
        // "abcd" → p=0.25 each → -4*(0.25 * log2(0.25)) = 2.0
        let e = shannon_entropy("abcd");
        assert!((e - 2.0).abs() < 1e-10, "expected 2.0, got {e}");
    }

    #[test]
    fn ten_distinct_bytes() {
        // "abcdefghij" → 10 distinct → log2(10) ≈ 3.3219
        let e = shannon_entropy("abcdefghij");
        assert!(e > 3.0, "expected > 3.0, got {e}");
        assert!(
            (e - 10.0_f64.log2()).abs() < 1e-10,
            "expected log2(10), got {e}"
        );
    }

    #[test]
    fn real_aws_key_has_high_entropy() {
        let e = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(e > 3.5, "expected > 3.5 for AWS key, got {e}");
    }

    #[test]
    fn high_entropy_alphanumeric() {
        let e = shannon_entropy("a1b2c3d4e5f6g7h8");
        assert!(e > 3.5, "expected > 3.5, got {e}");
    }

    #[test]
    fn single_character_string() {
        assert_eq!(shannon_entropy("x"), 0.0);
    }

    #[test]
    fn two_byte_string_same_char() {
        assert_eq!(shannon_entropy("zz"), 0.0);
    }

    #[test]
    fn non_ascii_bytes() {
        // UTF-8 multibyte: "ü" is 0xC3 0xBC → 2 distinct bytes, equal freq → entropy = 1.0
        let e = shannon_entropy("ü");
        assert!(
            (e - 1.0).abs() < 1e-10,
            "expected 1.0 for 2-byte UTF-8 char, got {e}"
        );
    }

    #[test]
    fn non_ascii_repeated() {
        // "üü" = [0xC3, 0xBC, 0xC3, 0xBC] → 2 distinct bytes, equal freq → 1.0
        let e = shannon_entropy("üü");
        assert!((e - 1.0).abs() < 1e-10, "expected 1.0, got {e}");
    }

    #[test]
    fn entropy_is_non_negative() {
        // Property: entropy is always >= 0
        for s in ["", "a", "ab", "abc", "aaab", "AKIAIOSFODNN7EXAMPLE"] {
            assert!(shannon_entropy(s) >= 0.0, "entropy was negative for {s:?}");
        }
    }

    #[test]
    fn entropy_bounded_by_eight() {
        // Max byte-level entropy is 8.0 (256 equally distributed bytes)
        let e = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(e <= 8.0, "entropy exceeded 8.0: {e}");
    }

    #[test]
    fn max_entropy_256_distinct_bytes() {
        // Build a string with all 256 byte values (not valid UTF-8, so test the algorithm directly)
        // Instead, test with a large varied ASCII set
        let s: String = (0x20..=0x7E).map(|b: u8| b as char).collect(); // 95 printable ASCII
        let e = shannon_entropy(&s);
        let expected = (s.len() as f64).log2();
        assert!(
            (e - expected).abs() < 1e-10,
            "expected log2({}) = {expected}, got {e}",
            s.len()
        );
    }

    #[test]
    fn skewed_distribution() {
        // "aaab" → a:3/4, b:1/4 → -(3/4 * log2(3/4) + 1/4 * log2(1/4)) ≈ 0.8113
        let e = shannon_entropy("aaab");
        assert!(e > 0.8, "expected > 0.8, got {e}");
        assert!(e < 0.82, "expected < 0.82, got {e}");
    }

    // --- passes_entropy_check tests ---

    #[test]
    fn none_threshold_always_passes() {
        assert!(passes_entropy_check("anything", None));
        assert!(passes_entropy_check("", None));
        assert!(passes_entropy_check("aaaa", None));
    }

    #[test]
    fn low_entropy_fails_high_threshold() {
        assert!(!passes_entropy_check("aaaaaaa", Some(3.0)));
    }

    #[test]
    fn high_entropy_passes_threshold() {
        assert!(passes_entropy_check("AKIAIOSFODNN7EXAMPLE", Some(3.0)));
    }

    #[test]
    fn entropy_exactly_at_threshold_passes() {
        // "ab" has entropy exactly 1.0
        assert!(passes_entropy_check("ab", Some(1.0)));
    }

    #[test]
    fn entropy_just_below_threshold_fails() {
        // "ab" has entropy 1.0, threshold 1.0 + epsilon should fail
        assert!(!passes_entropy_check("ab", Some(1.0 + 1e-9)));
    }

    #[test]
    fn zero_threshold_always_passes() {
        // Entropy of non-empty string is always >= 0.0
        assert!(passes_entropy_check("a", Some(0.0)));
        assert!(passes_entropy_check("aaaa", Some(0.0)));
        assert!(passes_entropy_check("abc", Some(0.0)));
    }

    #[test]
    fn empty_secret_with_threshold_fails() {
        // Empty string has entropy 0.0, any positive threshold should fail
        assert!(!passes_entropy_check("", Some(0.1)));
    }

    #[test]
    fn empty_secret_with_zero_threshold_passes() {
        // Empty string entropy = 0.0, threshold = 0.0 → 0.0 >= 0.0 → true
        assert!(passes_entropy_check("", Some(0.0)));
    }

    #[test]
    fn negative_threshold_always_passes() {
        // Entropy is always >= 0.0, so any negative threshold passes
        assert!(passes_entropy_check("", Some(-1.0)));
        assert!(passes_entropy_check("a", Some(-5.0)));
    }
}
