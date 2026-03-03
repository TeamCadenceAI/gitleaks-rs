use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::config::{Allowlist, Condition, Config, RegexTarget, RuleAllowlist};
use crate::entropy;
use crate::error::{Error, Result};
use crate::finding::Finding;
use crate::redact::{self, RedactResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size limit for compiled regexes (100 MB).
///
/// Matches the policy used by `Config::validate()` — some upstream rules
/// (e.g. `generic-api-key`) produce large compiled automata that exceed the
/// default 10 MB limit.
const REGEX_SIZE_LIMIT: usize = 100 * (1 << 20);

// ---------------------------------------------------------------------------
// Internal compiled types
// ---------------------------------------------------------------------------

/// A compiled per-rule allowlist entry.
#[derive(Debug)]
pub(crate) struct CompiledRuleAllowlist {
    #[allow(dead_code)] // Metadata; used by downstream specs for reporting.
    pub(crate) description: Option<String>,
    pub(crate) regexes: Vec<MatchOnlyRegex>,
    pub(crate) regex_target: RegexTarget,
    pub(crate) paths: Vec<MatchOnlyRegex>,
    pub(crate) stopwords: Vec<String>,
    pub(crate) condition: Condition,
}

/// A compiled global allowlist.
#[derive(Debug)]
pub(crate) struct CompiledGlobalAllowlist {
    #[allow(dead_code)] // Metadata; used by downstream specs for reporting.
    pub(crate) description: Option<String>,
    pub(crate) regexes: Vec<MatchOnlyRegex>,
    pub(crate) paths: Vec<MatchOnlyRegex>,
    pub(crate) stopwords: Vec<String>,
}

/// Wrapper around content regexes that supports both eager compilation
/// (existing `Scanner::new()` path) and cached DFA + lazy Regex
/// (cache hit path).
pub(crate) enum ContentRegex {
    /// Eagerly compiled `regex::Regex` — the default construction path.
    Eager(Regex),
    /// Cached DFA bytes for fast `is_match()` + lazily compiled `Regex` for captures.
    #[cfg(feature = "cache")]
    Cached {
        /// Serialized sparse DFA bytes for prefiltering.
        dfa_bytes: Vec<u8>,
        /// Original regex pattern (post `go_re2_compat`) for lazy `Regex` compilation.
        pattern: String,
        /// Lazily compiled `regex::Regex` for capture group extraction.
        regex: std::sync::OnceLock<Regex>,
    },
    /// Pattern where DFA build failed; lazily compiles a `regex::Regex`.
    #[cfg(feature = "cache")]
    LazyOnly {
        /// Original regex pattern (post `go_re2_compat`).
        pattern: String,
        /// Lazily compiled `regex::Regex`.
        regex: std::sync::OnceLock<Regex>,
    },
}

impl ContentRegex {
    /// Returns `true` if the text matches this content regex.
    pub(crate) fn is_match(&self, text: &str) -> bool {
        match self {
            ContentRegex::Eager(re) => re.is_match(text),
            #[cfg(feature = "cache")]
            ContentRegex::Cached { dfa_bytes, .. } => crate::cache::dfa_is_match(dfa_bytes, text),
            #[cfg(feature = "cache")]
            ContentRegex::LazyOnly { pattern, regex } => {
                lazy_init_regex(pattern, regex).is_match(text)
            }
        }
    }

    /// Returns an iterator over successive non-overlapping capture matches.
    ///
    /// For `Cached` and `LazyOnly` variants, lazily compiles the `regex::Regex`
    /// via `OnceLock::get_or_init()` on first call.
    pub(crate) fn captures_iter<'r, 't>(&'r self, text: &'t str) -> regex::CaptureMatches<'r, 't> {
        match self {
            ContentRegex::Eager(re) => re.captures_iter(text),
            #[cfg(feature = "cache")]
            ContentRegex::Cached { pattern, regex, .. }
            | ContentRegex::LazyOnly { pattern, regex } => {
                lazy_init_regex(pattern, regex).captures_iter(text)
            }
        }
    }
}

/// Lazily initializes a `Regex` from a pattern string and an `OnceLock`, using
/// the crate's standard size limit. Used by cached `ContentRegex` variants to
/// avoid compiling regexes until captures are actually needed.
#[cfg(feature = "cache")]
fn lazy_init_regex<'a>(pattern: &str, lock: &'a std::sync::OnceLock<Regex>) -> &'a Regex {
    lock.get_or_init(|| {
        regex::RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .expect("cached pattern should compile")
    })
}

impl fmt::Debug for ContentRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentRegex::Eager(re) => write!(f, "ContentRegex::Eager({:?})", re.as_str()),
            #[cfg(feature = "cache")]
            ContentRegex::Cached { pattern, .. } => {
                write!(f, "ContentRegex::Cached({:?})", pattern)
            }
            #[cfg(feature = "cache")]
            ContentRegex::LazyOnly { pattern, .. } => {
                write!(f, "ContentRegex::LazyOnly({:?})", pattern)
            }
        }
    }
}

// Compile-time assertion: ContentRegex must be Send + Sync.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn _check() {
        assert_send_sync::<ContentRegex>();
    }
};

/// Wrapper around path and allowlist regexes that only need `is_match()`
/// (no capture groups). Supports eager compilation and DFA-backed matching.
pub(crate) enum MatchOnlyRegex {
    /// Eagerly compiled `regex::Regex` — the default construction path.
    Eager(Regex),
    /// Serialized sparse DFA bytes for fast `is_match()`.
    #[cfg(feature = "cache")]
    Dfa(Vec<u8>),
}

impl MatchOnlyRegex {
    /// Returns `true` if the text matches this regex.
    pub(crate) fn is_match(&self, text: &str) -> bool {
        match self {
            MatchOnlyRegex::Eager(re) => re.is_match(text),
            #[cfg(feature = "cache")]
            MatchOnlyRegex::Dfa(bytes) => crate::cache::dfa_is_match(bytes, text),
        }
    }
}

impl fmt::Debug for MatchOnlyRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchOnlyRegex::Eager(re) => write!(f, "MatchOnlyRegex::Eager({:?})", re.as_str()),
            #[cfg(feature = "cache")]
            MatchOnlyRegex::Dfa(bytes) => {
                write!(f, "MatchOnlyRegex::Dfa({} bytes)", bytes.len())
            }
        }
    }
}

// Compile-time assertion: MatchOnlyRegex must be Send + Sync.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn _check() {
        assert_send_sync::<MatchOnlyRegex>();
    }
};

/// A fully compiled detection rule.
#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) content_regex: Option<ContentRegex>,
    pub(crate) path_regex: Option<MatchOnlyRegex>,
    pub(crate) entropy: Option<f64>,
    pub(crate) secret_group: Option<usize>,
    pub(crate) keywords: Vec<String>,
    pub(crate) allowlists: Vec<CompiledRuleAllowlist>,
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Precompiled rule engine for secret detection.
///
/// `Scanner` compiles all regex patterns and builds a keyword index at
/// construction time. All subsequent scanning operations use the precompiled
/// state — no regex compilation happens at scan time.
///
/// # Thread Safety
///
/// `Scanner` is `Send + Sync` and can be shared across threads via `&Scanner`
/// or wrapped in an `Arc<Scanner>`.
///
/// # Example
///
/// ```
/// use gitleaks_rs::Scanner;
///
/// let scanner = Scanner::default();
/// assert!(scanner.rule_count() >= 222);
/// ```
pub struct Scanner {
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) keyword_automaton: AhoCorasick,
    /// Maps each keyword pattern index in the automaton to the set of rule
    /// indices whose keyword list contains that keyword.
    pub(crate) keyword_to_rules: Vec<Vec<usize>>,
    pub(crate) global_allowlist: Option<CompiledGlobalAllowlist>,
    /// Indices into `rules` for rules excluded from keyword-based content
    /// scanning. This includes true path-only rules (no `content_regex`) and
    /// content rules with no keywords.
    pub(crate) path_only_indices: Vec<usize>,
}

impl fmt::Debug for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner")
            .field("rule_count", &self.rules.len())
            .field("keyword_count", &self.keyword_automaton.patterns_len())
            .field("path_only_count", &self.path_only_indices.len())
            .finish()
    }
}

// Compile-time assertion: Scanner must be Send + Sync for safe concurrent use.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn _check() {
        assert_send_sync::<Scanner>();
    }
};

impl Scanner {
    /// Compile a `Scanner` from a parsed `Config`.
    ///
    /// All rule regexes, path patterns, and allowlist patterns are compiled
    /// eagerly. The keyword index (AhoCorasick automaton) is built from all
    /// rule keywords. Returns an error on the first invalid regex encountered.
    pub fn new(config: Config) -> Result<Self> {
        let mut compiled_rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            compiled_rules.push(compile_rule(rule)?);
        }

        let (keyword_automaton, keyword_to_rules, path_only_indices) =
            build_keyword_index(&compiled_rules)?;

        let global_allowlist = config
            .allowlist
            .as_ref()
            .map(compile_global_allowlist)
            .transpose()?;

        Ok(Scanner {
            rules: compiled_rules,
            keyword_automaton,
            keyword_to_rules,
            global_allowlist,
            path_only_indices,
        })
    }

    /// Construct a `Scanner` using the default embedded config with disk-based
    /// DFA caching for near-instant startup on cache hit.
    ///
    /// Always uses [`Config::default()`] (the embedded 222-rule config). On the
    /// first call, compiles all regexes normally and writes a cache file to
    /// `cache_path`. On subsequent calls with the same cache file, loads
    /// pre-compiled DFAs from disk — avoiding regex compilation entirely.
    ///
    /// Cache files are **endian-dependent** (native endian) and not portable
    /// across architectures.
    ///
    /// # Fallback Behavior
    ///
    /// On any cache failure (corrupt file, version mismatch, I/O error), this
    /// method silently falls back to `Scanner::new(Config::default())`. Cache
    /// write failures after a miss are silently ignored.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use gitleaks_rs::Scanner;
    ///
    /// let scanner = Scanner::new_with_cache("/tmp/gitleaks.cache").unwrap();
    /// let findings = scanner.scan_text("AKIAIOSFODNN7EXAMPLE", None);
    /// ```
    #[cfg(feature = "cache")]
    pub fn new_with_cache(cache_path: impl AsRef<Path>) -> Result<Self> {
        let cache_path = cache_path.as_ref();
        let config_hash = crate::cache::compute_config_hash();

        // Try loading from cache first.
        match crate::cache::try_load(cache_path, &config_hash) {
            Ok(scanner) => return Ok(scanner),
            Err(_) => {
                // Cache miss or failure — fall through to full compilation.
            }
        }

        // Full compilation.
        let config = Config::default()?;
        let scanner = Scanner::new(config.clone())?;

        // Best-effort cache write — silently ignore any I/O errors.
        let _ = crate::cache::try_save(cache_path, &config_hash, &scanner, &config);

        Ok(scanner)
    }

    /// Total number of compiled rules (including path-only rules).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Iterator over the IDs of all compiled rules, in compilation order.
    pub fn rule_ids(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.id.as_str())
    }

    /// Access compiled rules (crate-internal, used by downstream specs).
    #[allow(dead_code)]
    pub(crate) fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Scan a single line of text and return all detected findings.
    ///
    /// Applies keyword pre-filtering, regex matching, secret group extraction,
    /// entropy checking, and allowlist evaluation. If `path` is provided, rules
    /// with a `path` regex will only fire when the path matches.
    ///
    /// Findings have `line_number` set to `None`. Use `scan_text` (spec 05)
    /// for line-numbered results.
    ///
    /// # Example
    ///
    /// ```
    /// use gitleaks_rs::{Config, Scanner};
    ///
    /// let config = Config::from_toml(r#"
    /// [[rules]]
    /// id = "test-secret"
    /// description = "Test secret"
    /// regex = '''secret_key\s*=\s*"([^"]+)"'''
    /// keywords = ["secret_key"]
    /// "#).unwrap();
    /// let scanner = Scanner::new(config).unwrap();
    /// let findings = scanner.scan_line(r#"secret_key = "my_token_value""#, None);
    /// assert_eq!(findings.len(), 1);
    /// assert_eq!(findings[0].rule_id, "test-secret");
    /// ```
    pub fn scan_line(&self, line: &str, path: Option<&str>) -> Vec<Finding> {
        if line.is_empty() {
            return Vec::new();
        }

        // Step 1: keyword pre-filtering — collect candidate rule indices.
        let lower = line.to_lowercase();
        let mut candidate_set = vec![false; self.rules.len()];
        for mat in self.keyword_automaton.find_iter(&lower) {
            let kw_idx = mat.pattern().as_usize();
            for &rule_idx in &self.keyword_to_rules[kw_idx] {
                candidate_set[rule_idx] = true;
            }
        }

        let mut findings = Vec::new();

        for (rule_idx, is_candidate) in candidate_set.iter().enumerate() {
            if !*is_candidate {
                continue;
            }

            // Skip path-only rules (handled in spec 05).
            if self.path_only_indices.contains(&rule_idx) {
                continue;
            }

            let rule = &self.rules[rule_idx];

            let content_regex = match &rule.content_regex {
                Some(re) => re,
                None => continue,
            };

            // Step 2: path filtering — if rule has a path regex and path is
            // provided, only proceed if the path matches.
            if let Some(path_re) = &rule.path_regex {
                if let Some(p) = path {
                    if !path_re.is_match(p) {
                        continue;
                    }
                }
            }

            // Step 3: DFA prefilter — skip rule if content regex doesn't match.
            // For the Eager variant this is redundant with captures_iter, but
            // for future Cached variants the DFA is_match is much faster.
            if !content_regex.is_match(line) {
                continue;
            }

            // Step 4: regex match loop — evaluate all matches in the line.
            for caps in content_regex.captures_iter(line) {
                let full_match = caps.get(0).unwrap();
                let match_text = full_match.as_str();

                // Step 5: secret group extraction.
                let secret = extract_secret(rule, &caps, match_text);

                // Step 6: entropy check.
                if !entropy::passes_entropy_check(&secret, rule.entropy) {
                    continue;
                }

                // Step 7: global allowlist check.
                if self.is_globally_allowlisted(&secret) {
                    continue;
                }

                // Step 8: per-rule allowlist check.
                if is_rule_allowlisted(rule, &secret, match_text, line, path) {
                    continue;
                }

                // Step 9: emit finding.
                let measured_entropy = if rule.entropy.is_some() {
                    Some(entropy::shannon_entropy(&secret))
                } else {
                    None
                };

                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    secret,
                    match_text: match_text.to_string(),
                    start: full_match.start(),
                    end: full_match.end(),
                    entropy: measured_entropy,
                    line_number: None,
                });
            }
        }

        findings
    }

    /// Check if a secret is suppressed by the global allowlist.
    fn is_globally_allowlisted(&self, secret: &str) -> bool {
        let gal = match &self.global_allowlist {
            Some(gal) => gal,
            None => return false,
        };

        // Stopword check: case-insensitive substring match.
        let secret_lower = secret.to_lowercase();
        for sw in &gal.stopwords {
            if secret_lower.contains(&sw.to_lowercase()) {
                return true;
            }
        }

        // Regex check against the secret.
        for re in &gal.regexes {
            if re.is_match(secret) {
                return true;
            }
        }

        false
    }

    /// Scan multi-line text and return all detected findings with line numbers.
    ///
    /// Splits `text` on `\n`, skips blank or whitespace-only lines, and calls
    /// [`scan_line`](Self::scan_line) for each remaining line. Each resulting
    /// finding gets a 1-indexed `line_number`.
    ///
    /// If `path` is provided, it is forwarded to `scan_line` for path-based
    /// rule filtering. Path-only rules are **not** evaluated here — use
    /// [`scan_file`](Self::scan_file) for that.
    ///
    /// # Example
    ///
    /// ```
    /// use gitleaks_rs::{Config, Scanner};
    ///
    /// let config = Config::from_toml(r#"
    /// [[rules]]
    /// id = "test-secret"
    /// description = "Test secret"
    /// regex = '''secret_key\s*=\s*"([^"]+)"'''
    /// keywords = ["secret_key"]
    /// "#).unwrap();
    /// let scanner = Scanner::new(config).unwrap();
    /// let text = "line one\nsecret_key = \"my_value\"\nline three";
    /// let findings = scanner.scan_text(text, None);
    /// assert_eq!(findings.len(), 1);
    /// assert_eq!(findings[0].line_number, Some(2));
    /// ```
    pub fn scan_text(&self, text: &str, path: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (idx, line) in text.split('\n').enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_number = idx + 1; // 1-indexed
            for mut finding in self.scan_line(line, path) {
                finding.line_number = Some(line_number);
                findings.push(finding);
            }
        }
        findings
    }

    /// Scan a file and return all detected findings.
    ///
    /// Reads the file at `path` as UTF-8 text. Before scanning content, checks
    /// the file path against the global allowlist — if matched, returns an empty
    /// vector immediately. Then evaluates path-only rules against the file path,
    /// and finally delegates content scanning to [`scan_text`](Self::scan_text).
    ///
    /// Path-only findings have `line_number = None`, `start = 0`, `end = 0`,
    /// and `secret` set to an empty string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be
    /// read (missing, permission denied, invalid UTF-8, etc.).
    pub fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let path_str = path.to_string_lossy();

        // Step 1: global path allowlist — skip entire file if matched.
        if self.is_global_path_allowlisted(&path_str) {
            return Ok(Vec::new());
        }

        // Step 2: path-only rules — emit findings for matching file paths.
        let mut findings = self.evaluate_path_only_rules(&path_str);

        // Step 3: read file contents and scan text.
        let contents = std::fs::read_to_string(path)?;
        let mut content_findings = self.scan_text(&contents, Some(&path_str));
        findings.append(&mut content_findings);

        Ok(findings)
    }

    // ------------------------------------------------------------------
    // Redaction API
    // ------------------------------------------------------------------

    /// Redact detected secrets in a single line, replacing each secret with
    /// `"REDACTED"`.
    ///
    /// Delegates to [`scan_line`](Self::scan_line) for detection, then
    /// replaces only the secret portion of each match (preserving surrounding
    /// text). When multiple secrets are found, replacements are applied
    /// right-to-left to keep byte offsets valid. Overlapping ranges are
    /// skipped to avoid double-replacement.
    ///
    /// # Examples
    ///
    /// ```
    /// use gitleaks_rs::{Config, Scanner};
    ///
    /// let config = Config::from_toml(r#"
    /// [[rules]]
    /// id = "test-secret"
    /// description = "Test secret"
    /// regex = '''secret_key\s*=\s*"([^"]+)"'''
    /// keywords = ["secret_key"]
    /// "#).unwrap();
    /// let scanner = Scanner::new(config).unwrap();
    /// let result = scanner.redact_line(r#"secret_key = "my_token""#, None);
    /// assert!(result.content.contains("REDACTED"));
    /// assert!(!result.content.contains("my_token"));
    /// ```
    pub fn redact_line(&self, line: &str, path: Option<&str>) -> RedactResult {
        self.redact_line_with(line, path, "REDACTED")
    }

    /// Redact detected secrets in a single line using a custom replacement
    /// string.
    ///
    /// Behaves identically to [`redact_line`](Self::redact_line) except that
    /// the caller chooses the replacement token.
    pub fn redact_line_with(
        &self,
        line: &str,
        path: Option<&str>,
        replacement: &str,
    ) -> RedactResult {
        let findings = self.scan_line(line, path);
        let (content, redaction_count) = redact::apply_replacements(line, &findings, replacement);
        RedactResult {
            content,
            findings,
            redaction_count,
        }
    }

    /// Redact detected secrets across multi-line text, replacing each secret
    /// with `"REDACTED"`.
    ///
    /// Splits `text` on `\n`, redacts each line independently, populates
    /// 1-indexed `line_number` on every finding, and joins the redacted
    /// lines back with `\n`.
    ///
    /// # Examples
    ///
    /// ```
    /// use gitleaks_rs::{Config, Scanner};
    ///
    /// let config = Config::from_toml(r#"
    /// [[rules]]
    /// id = "test-secret"
    /// description = "Test secret"
    /// regex = '''secret_key\s*=\s*"([^"]+)"'''
    /// keywords = ["secret_key"]
    /// "#).unwrap();
    /// let scanner = Scanner::new(config).unwrap();
    /// let text = "line one\nsecret_key = \"my_token\"\nline three";
    /// let result = scanner.redact_text(text, None);
    /// assert_eq!(result.redaction_count, 1);
    /// assert!(result.content.contains("REDACTED"));
    /// ```
    pub fn redact_text(&self, text: &str, path: Option<&str>) -> RedactResult {
        self.redact_text_with(text, path, "REDACTED")
    }

    /// Redact detected secrets across multi-line text using a custom
    /// replacement string.
    ///
    /// Behaves identically to [`redact_text`](Self::redact_text) except that
    /// the caller chooses the replacement token.
    pub fn redact_text_with(
        &self,
        text: &str,
        path: Option<&str>,
        replacement: &str,
    ) -> RedactResult {
        let mut all_findings = Vec::new();
        let mut total_count = 0usize;
        let mut redacted_lines = Vec::new();

        for (idx, line) in text.split('\n').enumerate() {
            let line_number = idx + 1; // 1-indexed
            let mut line_result = self.redact_line_with(line, path, replacement);

            // Stamp line numbers on findings.
            for f in &mut line_result.findings {
                f.line_number = Some(line_number);
            }

            total_count += line_result.redaction_count;
            all_findings.append(&mut line_result.findings);
            redacted_lines.push(line_result.content);
        }

        RedactResult {
            content: redacted_lines.join("\n"),
            findings: all_findings,
            redaction_count: total_count,
        }
    }

    /// Check if a file path is suppressed by the global allowlist path patterns.
    fn is_global_path_allowlisted(&self, path_str: &str) -> bool {
        let gal = match &self.global_allowlist {
            Some(gal) => gal,
            None => return false,
        };

        for re in &gal.paths {
            if re.is_match(path_str) {
                return true;
            }
        }

        false
    }

    /// Evaluate path-only rules against a file path and return any findings.
    fn evaluate_path_only_rules(&self, path_str: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for &rule_idx in &self.path_only_indices {
            let rule = &self.rules[rule_idx];
            // Only evaluate rules that have a path regex but no content regex
            // (true path-only rules). Rules with content regex but no keywords
            // are also in path_only_indices but should not produce path-only
            // findings — they just can't be reached via keyword prefilter.
            if rule.content_regex.is_some() {
                continue;
            }
            let path_re = match &rule.path_regex {
                Some(re) => re,
                None => continue,
            };
            if path_re.is_match(path_str) {
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    secret: String::new(),
                    match_text: path_str.to_string(),
                    start: 0,
                    end: 0,
                    entropy: None,
                    line_number: None,
                });
            }
        }
        findings
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Scanner::new(Config::default().expect("embedded config should always be valid"))
            .expect("embedded config should always compile")
    }
}

// ---------------------------------------------------------------------------
// Private compile helpers
// ---------------------------------------------------------------------------

/// Compile a regex pattern with the standard size limit policy.
///
/// Applies Go RE2 compatibility preprocessing so that patterns from the
/// upstream gitleaks config (which uses Go's regexp syntax) compile correctly
/// in the Rust regex engine.
fn compile_regex_with_context(pattern: &str, context: &str) -> Result<Regex> {
    let compat = go_re2_compat(pattern);
    regex::RegexBuilder::new(&compat)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| Error::Validation(format!("{context}: {e}")))
}

/// Compile a list of regex patterns into `MatchOnlyRegex::Eager` wrappers,
/// failing on the first invalid pattern.
fn compile_regex_list(patterns: &[String], context: &str) -> Result<Vec<MatchOnlyRegex>> {
    patterns
        .iter()
        .map(|p| compile_regex_with_context(p, context).map(MatchOnlyRegex::Eager))
        .collect()
}

/// Make a Go RE2 regex pattern compatible with the Rust regex crate.
///
/// Go's RE2 engine treats `{` as a literal character when it is not followed
/// by a valid quantifier (`{n}`, `{n,}`, or `{n,m}`). Rust's regex crate is
/// stricter and raises an error for bare `{`. This function escapes bare `{`
/// to `\{` when it does not start a valid quantifier.
pub(crate) fn go_re2_compat(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains('{') {
        return Cow::Borrowed(pattern);
    }

    let bytes = pattern.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len + 8);
    let mut i = 0;
    let mut in_class = false;
    let mut modified = false;

    while i < len {
        let b = bytes[i];

        // Handle backslash-escaped characters: pass through unchanged.
        if b == b'\\' && i + 1 < len {
            out.push(b);
            out.push(bytes[i + 1]);
            i += 2;
            continue;
        }

        // Track character class state (`[...]`).
        if b == b'[' && !in_class {
            in_class = true;
        } else if b == b']' && in_class {
            in_class = false;
        }

        // Inside character classes, `{` is always literal.
        if !in_class && b == b'{' && !is_valid_quantifier_at(bytes, i) {
            out.push(b'\\');
            out.push(b'{');
            modified = true;
            i += 1;
            continue;
        }

        out.push(b);
        i += 1;
    }

    if modified {
        // SAFETY: only ASCII bytes (`\` and `{`) were inserted into a valid
        // UTF-8 sequence, so the result is still valid UTF-8.
        Cow::Owned(String::from_utf8(out).expect("inserted only ASCII bytes"))
    } else {
        Cow::Borrowed(pattern)
    }
}

/// Check if the `{` at byte position `pos` starts a valid regex quantifier.
///
/// Valid quantifiers: `{n}`, `{n,}`, `{n,m}` where n and m are decimal integers.
fn is_valid_quantifier_at(bytes: &[u8], pos: usize) -> bool {
    let len = bytes.len();
    let mut i = pos + 1;

    // Must start with at least one digit.
    if i >= len || !bytes[i].is_ascii_digit() {
        return false;
    }
    while i < len && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i >= len {
        return false;
    }

    // `{n}` case
    if bytes[i] == b'}' {
        return true;
    }

    // Must be comma for `{n,}` or `{n,m}`.
    if bytes[i] != b',' {
        return false;
    }
    i += 1;
    if i >= len {
        return false;
    }

    // `{n,}` case
    if bytes[i] == b'}' {
        return true;
    }

    // `{n,m}` case — digits then `}`.
    if !bytes[i].is_ascii_digit() {
        return false;
    }
    while i < len && bytes[i].is_ascii_digit() {
        i += 1;
    }
    i < len && bytes[i] == b'}'
}

/// Compile a single config `Rule` into a `CompiledRule`.
fn compile_rule(rule: &crate::config::Rule) -> Result<CompiledRule> {
    let ctx = format!("rule '{}'", rule.id);

    let content_regex = rule
        .regex
        .as_deref()
        .map(|p| {
            compile_regex_with_context(p, &format!("{ctx}: invalid content regex"))
                .map(ContentRegex::Eager)
        })
        .transpose()?;

    let path_regex = rule
        .path
        .as_deref()
        .map(|p| {
            compile_regex_with_context(p, &format!("{ctx}: invalid path regex"))
                .map(MatchOnlyRegex::Eager)
        })
        .transpose()?;

    let allowlists = rule
        .allowlists
        .iter()
        .enumerate()
        .map(|(i, al)| compile_rule_allowlist(al, &format!("{ctx}, allowlist[{i}]")))
        .collect::<Result<Vec<_>>>()?;

    // Normalize keywords: lowercase, trim, skip empties.
    let keywords: Vec<String> = rule
        .keywords
        .iter()
        .map(|k| k.trim().to_lowercase())
        .filter(|k| !k.is_empty())
        .collect();

    Ok(CompiledRule {
        id: rule.id.clone(),
        description: rule.description.clone().unwrap_or_default(),
        content_regex,
        path_regex,
        entropy: rule.entropy,
        secret_group: rule.secret_group.map(|g| g as usize),
        keywords,
        allowlists,
    })
}

/// Compile a per-rule allowlist entry.
fn compile_rule_allowlist(al: &RuleAllowlist, context: &str) -> Result<CompiledRuleAllowlist> {
    Ok(CompiledRuleAllowlist {
        description: al.description.clone(),
        regexes: compile_regex_list(&al.regexes, &format!("{context}: invalid allowlist regex"))?,
        regex_target: al.regex_target,
        paths: compile_regex_list(
            &al.paths,
            &format!("{context}: invalid allowlist path regex"),
        )?,
        stopwords: al.stopwords.clone(),
        condition: al.condition,
    })
}

/// Compile the global allowlist.
fn compile_global_allowlist(al: &Allowlist) -> Result<CompiledGlobalAllowlist> {
    Ok(CompiledGlobalAllowlist {
        description: al.description.clone(),
        regexes: compile_regex_list(&al.regexes, "global allowlist: invalid regex")?,
        paths: compile_regex_list(&al.paths, "global allowlist: invalid path regex")?,
        stopwords: al.stopwords.clone(),
    })
}

/// Build the AhoCorasick keyword automaton and keyword-to-rules mapping.
///
/// Rules are classified as "path-only" (excluded from keyword-based content
/// scanning) if they lack a `content_regex` or have no keywords.
pub(crate) fn build_keyword_index(
    rules: &[CompiledRule],
) -> Result<(AhoCorasick, Vec<Vec<usize>>, Vec<usize>)> {
    let mut keyword_to_index: HashMap<String, usize> = HashMap::new();
    let mut keywords: Vec<String> = Vec::new();
    let mut kw_to_rules: Vec<Vec<usize>> = Vec::new();
    let mut path_only_indices: Vec<usize> = Vec::new();

    for (rule_idx, rule) in rules.iter().enumerate() {
        if rule.content_regex.is_none() || rule.keywords.is_empty() {
            path_only_indices.push(rule_idx);
            continue;
        }

        for kw in &rule.keywords {
            if kw.is_empty() {
                continue;
            }

            let kw_idx = if let Some(&idx) = keyword_to_index.get(kw.as_str()) {
                idx
            } else {
                let idx = keywords.len();
                keywords.push(kw.clone());
                keyword_to_index.insert(kw.clone(), idx);
                kw_to_rules.push(Vec::new());
                idx
            };

            if !kw_to_rules[kw_idx].contains(&rule_idx) {
                kw_to_rules[kw_idx].push(rule_idx);
            }
        }
    }

    let automaton = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&keywords)
        .map_err(|e| Error::Validation(format!("failed to build keyword automaton: {e}")))?;

    Ok((automaton, kw_to_rules, path_only_indices))
}

// ---------------------------------------------------------------------------
// Scanning helpers
// ---------------------------------------------------------------------------

/// Extract the secret from a regex match according to gitleaks `secretGroup` semantics.
///
/// Precedence:
/// 1. If `secret_group` is explicitly set to N > 0, use capture group N.
/// 2. If `secret_group` is unset/None and the regex has capture groups, use
///    the **last** (highest-numbered) capture group.
/// 3. If `secret_group` is explicitly 0, or there are no capture groups, use
///    the entire match.
fn extract_secret(rule: &CompiledRule, caps: &regex::Captures<'_>, full_match: &str) -> String {
    match rule.secret_group {
        Some(n) if n > 0 => {
            // Explicit group N — validated at compile time to be in range.
            caps.get(n)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| full_match.to_string())
        }
        Some(_) => {
            // Explicit group 0 — use entire match.
            full_match.to_string()
        }
        None => {
            // Default: use last capture group if any, otherwise full match.
            let num_groups = caps.len(); // includes group 0
            if num_groups > 1 {
                // Last capture group (highest index).
                let last_idx = num_groups - 1;
                caps.get(last_idx)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| full_match.to_string())
            } else {
                full_match.to_string()
            }
        }
    }
}

/// Check if a finding is suppressed by any of the rule's per-rule allowlists.
fn is_rule_allowlisted(
    rule: &CompiledRule,
    secret: &str,
    match_text: &str,
    line: &str,
    path: Option<&str>,
) -> bool {
    for al in &rule.allowlists {
        if allowlist_entry_matches(al, secret, match_text, line, path) {
            return true;
        }
    }
    false
}

/// Evaluate a single per-rule allowlist entry against a finding.
///
/// Returns `true` if the allowlist suppresses the finding.
fn allowlist_entry_matches(
    al: &CompiledRuleAllowlist,
    secret: &str,
    match_text: &str,
    line: &str,
    path: Option<&str>,
) -> bool {
    // Determine the target string for regex checks based on regex_target.
    let target = match al.regex_target {
        RegexTarget::Secret => secret,
        RegexTarget::Match => match_text,
        RegexTarget::Line => line,
    };

    match al.condition {
        Condition::Or => {
            // Any matching category suppresses.
            if al.regexes.iter().any(|re| re.is_match(target)) {
                return true;
            }
            let secret_lower = secret.to_lowercase();
            if al
                .stopwords
                .iter()
                .any(|sw| secret_lower.contains(&sw.to_lowercase()))
            {
                return true;
            }
            if let Some(p) = path {
                if al.paths.iter().any(|re| re.is_match(p)) {
                    return true;
                }
            }
            false
        }
        Condition::And => {
            // All non-empty categories must match for suppression.
            let has_regexes = !al.regexes.is_empty();
            let has_stopwords = !al.stopwords.is_empty();
            let has_paths = !al.paths.is_empty();

            // If no categories are configured, don't suppress.
            if !has_regexes && !has_stopwords && !has_paths {
                return false;
            }

            if has_regexes && !al.regexes.iter().any(|re| re.is_match(target)) {
                return false;
            }
            if has_stopwords {
                let secret_lower = secret.to_lowercase();
                if !al
                    .stopwords
                    .iter()
                    .any(|sw| secret_lower.contains(&sw.to_lowercase()))
                {
                    return false;
                }
            }
            if has_paths {
                match path {
                    Some(p) => {
                        if !al.paths.iter().any(|re| re.is_match(p)) {
                            return false;
                        }
                    }
                    // Path required but not provided — category doesn't match.
                    None => return false,
                }
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    // --- Helper: parse a minimal config from TOML ---

    fn config_from_toml(toml: &str) -> Config {
        Config::from_toml(toml).expect("test config should parse")
    }

    // ----- Default config compilation tests -----

    #[test]
    fn default_compiles_all_rules() {
        let scanner = Scanner::default();
        assert!(
            scanner.rule_count() >= 222,
            "expected at least 222 rules, got {}",
            scanner.rule_count()
        );
    }

    #[test]
    fn default_keyword_automaton_is_populated() {
        let scanner = Scanner::default();
        assert!(
            scanner.keyword_automaton.patterns_len() > 0,
            "keyword automaton should contain patterns"
        );
    }

    #[test]
    fn default_keyword_to_rules_mapping_is_populated() {
        let scanner = Scanner::default();
        assert!(
            !scanner.keyword_to_rules.is_empty(),
            "keyword-to-rules mapping should not be empty"
        );
        // Every keyword should map to at least one rule.
        for (i, rule_indices) in scanner.keyword_to_rules.iter().enumerate() {
            assert!(
                !rule_indices.is_empty(),
                "keyword[{i}] should map to at least one rule"
            );
        }
    }

    #[test]
    fn default_has_path_only_rule() {
        let scanner = Scanner::default();
        // pkcs12-file is path-only (no regex), so it should appear in path_only_indices.
        let pkcs12_idx = scanner
            .rules
            .iter()
            .position(|r| r.id == "pkcs12-file")
            .expect("pkcs12-file rule should exist");
        assert!(
            scanner.path_only_indices.contains(&pkcs12_idx),
            "pkcs12-file should be in path_only_indices"
        );
    }

    #[test]
    fn default_has_global_allowlist() {
        let scanner = Scanner::default();
        assert!(
            scanner.global_allowlist.is_some(),
            "default config should have a global allowlist"
        );
    }

    #[test]
    fn default_rule_ids_match_count() {
        let scanner = Scanner::default();
        let ids: Vec<&str> = scanner.rule_ids().collect();
        assert_eq!(ids.len(), scanner.rule_count());
    }

    // ----- Constructor success tests -----

    #[test]
    fn empty_rules_config_compiles() {
        let config = config_from_toml("title = \"empty\"\n");
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rule_count(), 0);
        assert_eq!(scanner.keyword_automaton.patterns_len(), 0);
        assert!(scanner.keyword_to_rules.is_empty());
        assert!(scanner.path_only_indices.is_empty());
    }

    #[test]
    fn path_only_rule_compiles() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "path-only"
description = "Path only"
path = '''\.p12$'''
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rule_count(), 1);
        assert!(scanner.rules[0].content_regex.is_none());
        assert!(scanner.rules[0].path_regex.is_some());
        assert_eq!(scanner.path_only_indices, vec![0]);
    }

    #[test]
    fn content_rule_with_keywords_compiles() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-rule"
description = "Test"
regex = '''secret_[a-z]+'''
keywords = ["secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rule_count(), 1);
        assert!(scanner.rules[0].content_regex.is_some());
        assert_eq!(scanner.keyword_automaton.patterns_len(), 1);
        assert_eq!(scanner.keyword_to_rules.len(), 1);
        assert_eq!(scanner.keyword_to_rules[0], vec![0]);
        assert!(scanner.path_only_indices.is_empty());
    }

    #[test]
    fn keywordless_content_rule_is_path_only() {
        // A rule with regex but no keywords should be classified as path-only
        // (excluded from keyword-based content scanning).
        let config = config_from_toml(
            r#"
[[rules]]
id = "no-keywords"
description = "Has regex but no keywords"
regex = '''secret_[a-z]+'''
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rule_count(), 1);
        assert!(scanner.rules[0].content_regex.is_some());
        assert!(scanner.rules[0].keywords.is_empty());
        assert_eq!(scanner.path_only_indices, vec![0]);
        assert_eq!(scanner.keyword_automaton.patterns_len(), 0);
    }

    #[test]
    fn rule_with_both_path_and_regex() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "both"
description = "Both path and regex"
regex = '''secret_[a-z]+'''
path = '''\.env$'''
keywords = ["secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert!(scanner.rules[0].content_regex.is_some());
        assert!(scanner.rules[0].path_regex.is_some());
        assert!(scanner.path_only_indices.is_empty());
    }

    #[test]
    fn rule_with_secret_group_preserved() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "sg-rule"
description = "Has secret group"
regex = '''(secret)_([a-z]+)'''
keywords = ["secret"]
secretGroup = 2
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].secret_group, Some(2));
    }

    #[test]
    fn rule_with_entropy_preserved() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "entropy-rule"
description = "Has entropy"
regex = '''[a-zA-Z0-9]+'''
keywords = ["key"]
entropy = 3.5
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].entropy, Some(3.5));
    }

    #[test]
    fn rule_with_allowlists_compiles() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "al-rule"
description = "With allowlists"
regex = '''secret_[a-z]+'''
keywords = ["secret"]

[[rules.allowlists]]
description = "test allowlist"
regexTarget = "match"
regexes = ["test_.*"]
paths = ["tests/"]
stopwords = ["example"]
condition = "AND"

[[rules.allowlists]]
regexes = ["ignore_.*"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].allowlists.len(), 2);

        let al0 = &scanner.rules[0].allowlists[0];
        assert_eq!(al0.description.as_deref(), Some("test allowlist"));
        assert_eq!(al0.regex_target, RegexTarget::Match);
        assert_eq!(al0.regexes.len(), 1);
        assert_eq!(al0.paths.len(), 1);
        assert_eq!(al0.stopwords, vec!["example"]);
        assert_eq!(al0.condition, Condition::And);

        let al1 = &scanner.rules[0].allowlists[1];
        assert_eq!(al1.regexes.len(), 1);
        assert_eq!(al1.regex_target, RegexTarget::Secret);
        assert_eq!(al1.condition, Condition::Or);
    }

    #[test]
    fn global_allowlist_compiles() {
        let config = config_from_toml(
            r#"
[allowlist]
description = "global"
paths = ["vendor/", "node_modules/"]
regexes = ["EXAMPLE"]
stopwords = ["test"]

[[rules]]
id = "r1"
description = "test"
regex = '''x'''
keywords = ["x"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let gal = scanner.global_allowlist.as_ref().unwrap();
        assert_eq!(gal.description.as_deref(), Some("global"));
        assert_eq!(gal.paths.len(), 2);
        assert_eq!(gal.regexes.len(), 1);
        assert_eq!(gal.stopwords, vec!["test"]);
    }

    // ----- Keyword normalization and deduplication tests -----

    #[test]
    fn keywords_are_lowercased() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "upper"
description = "Uppercase keywords"
regex = '''SECRET_[A-Z]+'''
keywords = ["SECRET", "Key", "TOKEN"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].keywords, vec!["secret", "key", "token"]);
    }

    #[test]
    fn keywords_are_trimmed() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "trimmed"
description = "Whitespace keywords"
regex = '''secret'''
keywords = ["  secret  ", "key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].keywords, vec!["secret", "key"]);
    }

    #[test]
    fn empty_keywords_are_filtered() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "empty-kw"
description = "Empty keyword"
regex = '''secret'''
keywords = ["", "  ", "valid"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].keywords, vec!["valid"]);
        // Only "valid" should be in the automaton.
        assert_eq!(scanner.keyword_automaton.patterns_len(), 1);
    }

    #[test]
    fn duplicate_keywords_across_rules_are_deduplicated() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "rule-a"
description = "First"
regex = '''a_secret'''
keywords = ["secret", "key"]

[[rules]]
id = "rule-b"
description = "Second"
regex = '''b_secret'''
keywords = ["secret", "token"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // "secret" appears in both rules but should be deduplicated in automaton.
        // Unique keywords: "secret", "key", "token" = 3
        assert_eq!(scanner.keyword_automaton.patterns_len(), 3);
        assert_eq!(scanner.keyword_to_rules.len(), 3);

        // Find the "secret" keyword index and verify it maps to both rules.
        // Keywords are inserted in first-seen order: "secret"=0, "key"=1, "token"=2
        assert_eq!(scanner.keyword_to_rules[0], vec![0, 1]); // "secret" -> rule 0, 1
        assert_eq!(scanner.keyword_to_rules[1], vec![0]); // "key" -> rule 0
        assert_eq!(scanner.keyword_to_rules[2], vec![1]); // "token" -> rule 1
    }

    #[test]
    fn duplicate_keywords_within_rule_are_deduplicated_in_mapping() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "dup-kw"
description = "Duplicate keywords within rule"
regex = '''secret'''
keywords = ["secret", "SECRET", "Secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // After lowercasing, all three become "secret" -> one automaton pattern.
        // Note: the rule's keywords Vec will have 3 entries (all "secret")
        // but the automaton deduplicates them.
        assert_eq!(scanner.keyword_automaton.patterns_len(), 1);
        assert_eq!(scanner.keyword_to_rules[0], vec![0]);
    }

    // ----- Constructor failure tests -----

    #[test]
    fn invalid_content_regex_fails() {
        // Config::from_toml validates regexes, so bypass it by constructing
        // a Config manually with an invalid regex.
        let config = Config {
            title: None,
            min_version: None,
            rules: vec![crate::config::Rule {
                id: "bad-regex".into(),
                description: Some("Invalid regex".into()),
                regex: Some("[unclosed".into()),
                path: None,
                entropy: None,
                keywords: vec!["bad".into()],
                secret_group: None,
                allowlists: vec![],
            }],
            allowlist: None,
            warnings: vec![],
        };
        let err = Scanner::new(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bad-regex"),
            "error should mention rule id: {msg}"
        );
        assert!(
            msg.contains("content regex"),
            "error should mention content regex: {msg}"
        );
    }

    #[test]
    fn invalid_path_regex_fails() {
        let config = Config {
            title: None,
            min_version: None,
            rules: vec![crate::config::Rule {
                id: "bad-path".into(),
                description: Some("Invalid path regex".into()),
                regex: None,
                path: Some("[unclosed".into()),
                entropy: None,
                keywords: vec![],
                secret_group: None,
                allowlists: vec![],
            }],
            allowlist: None,
            warnings: vec![],
        };
        let err = Scanner::new(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bad-path"),
            "error should mention rule id: {msg}"
        );
        assert!(
            msg.contains("path regex"),
            "error should mention path regex: {msg}"
        );
    }

    #[test]
    fn invalid_rule_allowlist_regex_fails() {
        let config = Config {
            title: None,
            min_version: None,
            rules: vec![crate::config::Rule {
                id: "bad-al".into(),
                description: Some("Bad allowlist".into()),
                regex: Some("ok".into()),
                path: None,
                entropy: None,
                keywords: vec!["ok".into()],
                secret_group: None,
                allowlists: vec![crate::config::RuleAllowlist {
                    description: None,
                    regex_target: RegexTarget::Secret,
                    regexes: vec!["[unclosed".into()],
                    paths: vec![],
                    stopwords: vec![],
                    condition: Condition::Or,
                }],
            }],
            allowlist: None,
            warnings: vec![],
        };
        let err = Scanner::new(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bad-al"),
            "error should mention rule id: {msg}"
        );
        assert!(
            msg.contains("allowlist"),
            "error should mention allowlist: {msg}"
        );
    }

    #[test]
    fn invalid_rule_allowlist_path_regex_fails() {
        let config = Config {
            title: None,
            min_version: None,
            rules: vec![crate::config::Rule {
                id: "bad-al-path".into(),
                description: Some("Bad allowlist path".into()),
                regex: Some("ok".into()),
                path: None,
                entropy: None,
                keywords: vec!["ok".into()],
                secret_group: None,
                allowlists: vec![crate::config::RuleAllowlist {
                    description: None,
                    regex_target: RegexTarget::Secret,
                    regexes: vec![],
                    paths: vec!["[unclosed".into()],
                    stopwords: vec![],
                    condition: Condition::Or,
                }],
            }],
            allowlist: None,
            warnings: vec![],
        };
        let err = Scanner::new(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bad-al-path"),
            "error should mention rule id: {msg}"
        );
        assert!(
            msg.contains("allowlist path"),
            "error should mention allowlist path: {msg}"
        );
    }

    #[test]
    fn invalid_global_allowlist_regex_fails() {
        let config = Config {
            title: None,
            min_version: None,
            rules: vec![crate::config::Rule {
                id: "ok".into(),
                description: Some("Ok rule".into()),
                regex: Some("ok".into()),
                path: None,
                entropy: None,
                keywords: vec!["ok".into()],
                secret_group: None,
                allowlists: vec![],
            }],
            allowlist: Some(crate::config::Allowlist {
                description: None,
                paths: vec![],
                regexes: vec!["[unclosed".into()],
                stopwords: vec![],
            }),
            warnings: vec![],
        };
        let err = Scanner::new(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("global allowlist"),
            "error should mention global allowlist: {msg}"
        );
    }

    #[test]
    fn invalid_global_allowlist_path_regex_fails() {
        let config = Config {
            title: None,
            min_version: None,
            rules: vec![crate::config::Rule {
                id: "ok".into(),
                description: Some("Ok rule".into()),
                regex: Some("ok".into()),
                path: None,
                entropy: None,
                keywords: vec!["ok".into()],
                secret_group: None,
                allowlists: vec![],
            }],
            allowlist: Some(crate::config::Allowlist {
                description: None,
                paths: vec!["[unclosed".into()],
                regexes: vec![],
                stopwords: vec![],
            }),
            warnings: vec![],
        };
        let err = Scanner::new(config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("global allowlist"),
            "error should mention global allowlist: {msg}"
        );
    }

    // ----- Edge case tests -----

    #[test]
    fn rule_with_empty_allowlist_vectors() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "empty-vecs"
description = "Empty allowlist vectors"
regex = '''x'''
keywords = ["x"]

[[rules.allowlists]]
regexes = []
paths = []
stopwords = []
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].allowlists.len(), 1);
        assert!(scanner.rules[0].allowlists[0].regexes.is_empty());
        assert!(scanner.rules[0].allowlists[0].paths.is_empty());
        assert!(scanner.rules[0].allowlists[0].stopwords.is_empty());
    }

    #[test]
    fn missing_description_defaults_to_empty() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "no-desc"
regex = '''x'''
keywords = ["x"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.rules[0].description, "");
    }

    #[test]
    fn multiple_rules_preserve_order() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "alpha"
description = "First"
regex = '''a'''
keywords = ["a"]

[[rules]]
id = "beta"
description = "Second"
regex = '''b'''
keywords = ["b"]

[[rules]]
id = "gamma"
description = "Third"
regex = '''c'''
keywords = ["c"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let ids: Vec<&str> = scanner.rule_ids().collect();
        assert_eq!(ids, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn scanner_new_from_default_config() {
        // Explicit test that Scanner::new(Config::default()) works.
        let config = Config::default().unwrap();
        let scanner = Scanner::new(config).unwrap();
        assert!(scanner.rule_count() >= 222);
    }

    // =====================================================================
    // scan_line tests
    // =====================================================================

    // --- Positive detection tests ---

    #[test]
    fn scan_line_detects_simple_secret() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-secret"
description = "A secret"
regex = '''secret_key\s*=\s*"([^"]+)"'''
keywords = ["secret_key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line(r#"secret_key = "my_token""#, None);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "test-secret");
        assert_eq!(f.description, "A secret");
        assert_eq!(f.secret, "my_token"); // last capture group
        assert_eq!(f.match_text, r#"secret_key = "my_token""#);
        assert_eq!(f.start, 0);
        assert_eq!(f.end, 23);
        assert!(f.entropy.is_none()); // no entropy threshold
        assert!(f.line_number.is_none()); // scan_line always None
    }

    #[test]
    fn scan_line_finding_spans_correct_byte_offsets() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "key"
description = "Key"
regex = '''KEY_[A-Z]+'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let line = "prefix KEY_ABC suffix";
        let findings = scanner.scan_line(line, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].start, 7);
        assert_eq!(findings[0].end, 14);
        assert_eq!(&line[7..14], "KEY_ABC");
    }

    #[test]
    fn scan_line_no_secrets_returns_empty() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test"
description = "Test"
regex = '''secret_[a-z]+'''
keywords = ["secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("const greeting = \"hello world\"", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_line_empty_line_returns_empty() {
        let scanner = Scanner::default();
        let findings = scanner.scan_line("", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_line_multiple_findings_per_line() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "tok"
description = "Token"
regex = '''tok_[a-z0-9]+'''
keywords = ["tok_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("tok_abc and tok_xyz", None);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].secret, "tok_abc");
        assert_eq!(findings[1].secret, "tok_xyz");
        // Verify non-overlapping spans
        assert!(findings[0].end <= findings[1].start);
    }

    // --- Secret group extraction tests ---

    #[test]
    fn secret_group_explicit_selects_group() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "sg2"
description = "Group 2"
regex = '''(first)(second)'''
keywords = ["first"]
secretGroup = 2
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("firstsecond", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "second");
        assert_eq!(findings[0].match_text, "firstsecond");
    }

    #[test]
    fn secret_group_zero_uses_full_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "sg0"
description = "Group 0"
regex = '''(first)(second)'''
keywords = ["first"]
secretGroup = 0
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("firstsecond", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "firstsecond");
    }

    #[test]
    fn secret_group_default_uses_last_capture_group() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "default-sg"
description = "Default SG"
regex = '''(aaa)(bbb)(ccc)'''
keywords = ["aaa"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("aaabbbccc", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "ccc"); // last capture group
    }

    #[test]
    fn secret_group_no_captures_uses_full_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "no-groups"
description = "No groups"
regex = '''secret_[a-z]+'''
keywords = ["secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("secret_abc", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "secret_abc");
        assert_eq!(findings[0].match_text, "secret_abc");
    }

    // --- Entropy filtering tests ---

    #[test]
    fn scan_line_entropy_filters_low_entropy_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "ent"
description = "Entropy rule"
regex = '''key_([a-zA-Z0-9]+)'''
keywords = ["key_"]
entropy = 3.5
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // "aaaa" has entropy 0.0 — below 3.5 threshold
        let findings = scanner.scan_line("key_aaaa", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_line_entropy_passes_high_entropy_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "ent"
description = "Entropy rule"
regex = '''key_([a-zA-Z0-9]+)'''
keywords = ["key_"]
entropy = 3.0
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // "a1b2c3d4e5" has high entropy
        let findings = scanner.scan_line("key_a1b2c3d4e5", None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].entropy.is_some());
        assert!(findings[0].entropy.unwrap() > 3.0);
    }

    #[test]
    fn scan_line_no_entropy_threshold_does_not_set_entropy_field() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "no-ent"
description = "No entropy"
regex = '''tok_[a-z]+'''
keywords = ["tok_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("tok_abc", None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].entropy.is_none());
    }

    // --- Global allowlist tests ---

    #[test]
    fn scan_line_global_stopword_suppresses() {
        let config = config_from_toml(
            r#"
[allowlist]
stopwords = ["example"]

[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("key_example", None);
        assert!(
            findings.is_empty(),
            "global stopword 'example' should suppress"
        );
    }

    #[test]
    fn scan_line_global_stopword_case_insensitive() {
        let config = config_from_toml(
            r#"
[allowlist]
stopwords = ["EXAMPLE"]

[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-zA-Z]+)'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("key_ExAmPlE", None);
        assert!(
            findings.is_empty(),
            "stopword check should be case-insensitive"
        );
    }

    #[test]
    fn scan_line_global_regex_suppresses() {
        let config = config_from_toml(
            r#"
[allowlist]
regexes = ["^test_"]

[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z_]+)'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("key_test_value", None);
        assert!(
            findings.is_empty(),
            "global regex should suppress secret starting with test_"
        );
    }

    #[test]
    fn scan_line_global_allowlist_does_not_suppress_non_matching() {
        let config = config_from_toml(
            r#"
[allowlist]
stopwords = ["example"]
regexes = ["^test_"]

[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("key_realvalue", None);
        assert_eq!(findings.len(), 1, "non-matching should not be suppressed");
    }

    // --- Template/placeholder allowlist tests ---

    #[test]
    fn scan_line_template_placeholder_suppressed() {
        let config = config_from_toml(
            r#"
[allowlist]
regexes = ['''\{\{[^}]+\}\}''']

[[rules]]
id = "r1"
description = "Rule"
regex = '''api_key\s*=\s*"([^"]+)"'''
keywords = ["api_key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line(r#"api_key = "{{API_KEY}}""#, None);
        assert!(
            findings.is_empty(),
            "template placeholder should be suppressed"
        );
    }

    // --- Per-rule allowlist tests ---

    #[test]
    fn scan_line_per_rule_allowlist_or_regex_suppresses() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''secret_([a-z_]+)'''
keywords = ["secret_"]

[[rules.allowlists]]
regexes = ["ignore_me"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("secret_ignore_me", None);
        assert!(findings.is_empty(), "per-rule regex should suppress");
    }

    #[test]
    fn scan_line_per_rule_allowlist_or_stopword_suppresses() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
stopwords = ["fake"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("key_fake", None);
        assert!(findings.is_empty(), "per-rule stopword should suppress");
    }

    #[test]
    fn scan_line_per_rule_allowlist_or_path_suppresses() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
paths = ["tests/"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // With matching path
        let findings = scanner.scan_line("key_abc", Some("tests/test_file.rs"));
        assert!(findings.is_empty(), "path match should suppress with Or");

        // Without matching path
        let findings = scanner.scan_line("key_abc", Some("src/main.rs"));
        assert_eq!(findings.len(), 1, "non-matching path should not suppress");
    }

    #[test]
    fn scan_line_per_rule_allowlist_regex_target_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''(secret)_([a-z]+)'''
keywords = ["secret"]

[[rules.allowlists]]
regexTarget = "match"
regexes = ["secret_test"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("secret_test", None);
        assert!(
            findings.is_empty(),
            "match-target regex should suppress based on full match"
        );
    }

    #[test]
    fn scan_line_per_rule_allowlist_regex_target_line() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
regexTarget = "line"
regexes = ["^#.*comment"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Line-level allowlist should check the entire line
        let findings = scanner.scan_line("# this is a comment key_abc", None);
        assert!(
            findings.is_empty(),
            "line-target regex should suppress based on full line"
        );

        // Non-matching line
        let findings = scanner.scan_line("key_abc", None);
        assert_eq!(findings.len(), 1, "non-matching line should not suppress");
    }

    #[test]
    fn scan_line_per_rule_allowlist_condition_and_all_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
condition = "AND"
regexes = ["test"]
paths = ["tests/"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Both regex and path match → suppress
        let findings = scanner.scan_line("key_test", Some("tests/foo.rs"));
        assert!(
            findings.is_empty(),
            "AND condition: both regex and path match → should suppress"
        );
    }

    #[test]
    fn scan_line_per_rule_allowlist_condition_and_partial_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
condition = "AND"
regexes = ["test"]
paths = ["tests/"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Regex matches but path doesn't → no suppress
        let findings = scanner.scan_line("key_test", Some("src/main.rs"));
        assert_eq!(
            findings.len(),
            1,
            "AND condition: only regex matches → should NOT suppress"
        );

        // Path matches but regex doesn't → no suppress
        let findings = scanner.scan_line("key_real", Some("tests/foo.rs"));
        assert_eq!(
            findings.len(),
            1,
            "AND condition: only path matches → should NOT suppress"
        );
    }

    #[test]
    fn scan_line_per_rule_allowlist_condition_and_no_path_provided() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
condition = "AND"
regexes = ["test"]
paths = ["tests/"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Regex matches but path is None → AND cannot satisfy path category
        let findings = scanner.scan_line("key_test", None);
        assert_eq!(
            findings.len(),
            1,
            "AND condition: path required but None provided → should NOT suppress"
        );
    }

    #[test]
    fn scan_line_per_rule_allowlist_empty_criteria_does_not_suppress() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "r1"
description = "Rule"
regex = '''key_([a-z]+)'''
keywords = ["key_"]

[[rules.allowlists]]
regexes = []
paths = []
stopwords = []
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("key_abc", None);
        assert_eq!(
            findings.len(),
            1,
            "empty allowlist should not suppress anything"
        );
    }

    // --- Path filtering tests ---

    #[test]
    fn scan_line_path_regex_filters_non_matching_path() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "env-rule"
description = "Env rule"
regex = '''KEY_([a-z]+)'''
path = '''\.env$'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Matching path
        let findings = scanner.scan_line("KEY_secret", Some("config/.env"));
        assert_eq!(findings.len(), 1, "matching path should produce finding");

        // Non-matching path
        let findings = scanner.scan_line("KEY_secret", Some("src/main.rs"));
        assert!(
            findings.is_empty(),
            "non-matching path should filter out rule"
        );
    }

    #[test]
    fn scan_line_path_none_still_matches_with_path_regex() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "env-rule"
description = "Env rule"
regex = '''KEY_([a-z]+)'''
path = '''\.env$'''
keywords = ["key_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // No path provided — rule with path regex should still match content
        let findings = scanner.scan_line("KEY_secret", None);
        assert_eq!(
            findings.len(),
            1,
            "no path provided should still match content"
        );
    }

    #[test]
    fn scan_line_rule_without_path_regex_matches_regardless_of_path() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "no-path"
description = "No path"
regex = '''tok_([a-z]+)'''
keywords = ["tok_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.scan_line("tok_abc", Some("any/path.txt"));
        assert_eq!(
            findings.len(),
            1,
            "rule without path regex should always match"
        );
    }

    // --- Keyword pre-filter tests ---

    #[test]
    fn scan_line_keyword_prefilter_skips_non_matching_rules() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "rule-a"
description = "Rule A"
regex = '''secret_[a-z]+'''
keywords = ["secret"]

[[rules]]
id = "rule-b"
description = "Rule B"
regex = '''token_[a-z]+'''
keywords = ["token"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Only "token" keyword is in the line
        let findings = scanner.scan_line("token_abc", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "rule-b");
    }

    #[test]
    fn scan_line_keyword_prefilter_case_insensitive() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test"
description = "Test"
regex = '''SECRET_[A-Z]+'''
keywords = ["secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Keywords are matched case-insensitively
        let findings = scanner.scan_line("SECRET_ABC", None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_line_path_only_rule_ignored_in_line_scan() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "path-only"
description = "Path only"
path = '''\.p12$'''

[[rules]]
id = "content"
description = "Content"
regex = '''tok_[a-z]+'''
keywords = ["tok_"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Path-only rule should not be evaluated in scan_line
        let findings = scanner.scan_line("tok_abc", Some("cert.p12"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "content");
    }

    // --- Default config detection tests ---

    #[test]
    fn scan_line_default_detects_github_pat() {
        let scanner = Scanner::default();
        // ghp_ + 36 alphanumeric chars with high entropy
        let findings = scanner.scan_line("token = ghp_xK7nR2pQm4sLwYv8jH3dTz5bFcA9eNuGiC0q", None);
        assert!(
            findings.iter().any(|f| f.rule_id.contains("github")),
            "should detect GitHub PAT in default config, found: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scan_line_default_no_findings_for_normal_text() {
        let scanner = Scanner::default();
        let findings = scanner.scan_line("const greeting = \"hello world\"", None);
        assert!(findings.is_empty());
    }

    // ===== scan_text tests =====

    #[test]
    fn scan_text_line_numbers_correct() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Secrets on lines 2 and 5, other lines are non-matching.
        let text =
            "line one\nkey = \"secret_val_1\"\nline three\nline four\nkey = \"secret_val_2\"";
        let findings = scanner.scan_text(text, None);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line_number, Some(2));
        assert_eq!(findings[0].secret, "secret_val_1");
        assert_eq!(findings[1].line_number, Some(5));
        assert_eq!(findings[1].secret, "secret_val_2");
    }

    #[test]
    fn scan_text_blank_lines_skipped() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        // Blank lines (empty, spaces, tabs) should be skipped.
        let text = "\n  \n\t\nkey = \"val\"\n\n";
        let findings = scanner.scan_text(text, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, Some(4));
    }

    #[test]
    fn scan_text_empty_input() {
        let scanner = Scanner::default();
        let findings = scanner.scan_text("", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_text_no_secrets() {
        let scanner = Scanner::default();
        let text = "line one\nline two\nline three";
        let findings = scanner.scan_text(text, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_text_all_line_numbers_are_set() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let text = "key = \"a\"\nkey = \"b\"\nkey = \"c\"";
        let findings = scanner.scan_text(text, None);
        assert_eq!(findings.len(), 3);
        for f in &findings {
            assert!(
                f.line_number.is_some(),
                "all findings must have line_number set"
            );
        }
        assert_eq!(findings[0].line_number, Some(1));
        assert_eq!(findings[1].line_number, Some(2));
        assert_eq!(findings[2].line_number, Some(3));
    }

    #[test]
    fn scan_text_trailing_newline_does_not_produce_finding() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let text = "key = \"val\"\n";
        let findings = scanner.scan_text(text, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, Some(1));
    }

    #[test]
    fn scan_text_with_path_filters_rules() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "js-secret"
description = "JS secret"
regex = '''secret\s*=\s*"([^"]+)"'''
path = '''\.js$'''
keywords = ["secret"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let text = "secret = \"val\"";

        // With matching path
        let findings = scanner.scan_text(text, Some("app.js"));
        assert_eq!(findings.len(), 1);

        // With non-matching path
        let findings = scanner.scan_text(text, Some("app.py"));
        assert!(findings.is_empty());
    }

    // ===== scan_file helper tests (unit level) =====

    #[test]
    fn global_path_allowlist_blocks_file() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]

[allowlist]
description = "global"
paths = ['''\.lock$''']
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert!(scanner.is_global_path_allowlisted("Cargo.lock"));
        assert!(!scanner.is_global_path_allowlisted("Cargo.toml"));
    }

    #[test]
    fn global_path_allowlist_empty_does_not_block() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]

[allowlist]
description = "global"
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert!(!scanner.is_global_path_allowlisted("anything.txt"));
    }

    #[test]
    fn no_global_allowlist_does_not_block() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert!(!scanner.is_global_path_allowlisted("anything.txt"));
    }

    #[test]
    fn path_only_rule_produces_finding() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "pkcs12-detect"
description = "PKCS12 file"
path = '''\.p12$'''
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.evaluate_path_only_rules("certs/server.p12");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "pkcs12-detect");
        assert_eq!(findings[0].description, "PKCS12 file");
        assert_eq!(findings[0].secret, "");
        assert_eq!(findings[0].match_text, "certs/server.p12");
        assert_eq!(findings[0].start, 0);
        assert_eq!(findings[0].end, 0);
        assert_eq!(findings[0].entropy, None);
        assert_eq!(findings[0].line_number, None);
    }

    #[test]
    fn path_only_rule_no_match() {
        let config = config_from_toml(
            r#"
[[rules]]
id = "pkcs12-detect"
description = "PKCS12 file"
path = '''\.p12$'''
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        let findings = scanner.evaluate_path_only_rules("certs/server.pem");
        assert!(findings.is_empty());
    }

    #[test]
    fn path_only_skips_content_rules_without_keywords() {
        // A rule with content_regex but no keywords is in path_only_indices
        // but should NOT produce path-only findings.
        let config = config_from_toml(
            r#"
[[rules]]
id = "no-kw-rule"
description = "Content rule with no keywords"
regex = '''secret_[a-z]+'''
"#,
        );
        let scanner = Scanner::new(config).unwrap();
        assert_eq!(scanner.path_only_indices, vec![0]);
        let findings = scanner.evaluate_path_only_rules("any/path.txt");
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_file_missing_file_returns_io_error() {
        let scanner = Scanner::default();
        let result = scanner.scan_file(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Io(_) => {} // expected
            other => panic!("expected Error::Io, got: {other}"),
        }
    }

    #[test]
    fn scan_file_reads_and_scans() {
        use std::io::Write;

        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();

        let dir = std::env::temp_dir().join("gitleaks_rs_test_scan_file_reads");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            writeln!(f, "nothing here").unwrap();
            writeln!(f, "key = \"my_secret\"").unwrap();
            writeln!(f, "also nothing").unwrap();
        }

        let findings = scanner.scan_file(&file_path).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "test-key");
        assert_eq!(findings[0].line_number, Some(2));
        assert_eq!(findings[0].secret, "my_secret");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_file_global_path_allowlist_skips() {
        use std::io::Write;

        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]

[allowlist]
description = "global"
paths = ['''test_allow''']
"#,
        );
        let scanner = Scanner::new(config).unwrap();

        let dir = std::env::temp_dir().join("gitleaks_rs_test_path_allow");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_allow.txt");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            writeln!(f, "key = \"should_not_find\"").unwrap();
        }

        let findings = scanner.scan_file(&file_path).unwrap();
        assert!(
            findings.is_empty(),
            "global path allowlist should suppress all findings"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_file_path_only_and_content_merged() {
        use std::io::Write;

        let config = config_from_toml(
            r#"
[[rules]]
id = "cert-file"
description = "Certificate file"
path = '''\.pem$'''

[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();

        let dir = std::env::temp_dir().join("gitleaks_rs_test_merged");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("config.pem");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            writeln!(f, "key = \"secret_val\"").unwrap();
        }

        let findings = scanner.scan_file(&file_path).unwrap();
        // Should have path-only finding + content finding
        assert_eq!(findings.len(), 2);
        // Path-only comes first
        assert_eq!(findings[0].rule_id, "cert-file");
        assert_eq!(findings[0].line_number, None);
        assert_eq!(findings[0].secret, "");
        // Content finding comes second
        assert_eq!(findings[1].rule_id, "test-key");
        assert_eq!(findings[1].line_number, Some(1));
        assert_eq!(findings[1].secret, "secret_val");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_file_no_secrets() {
        use std::io::Write;

        let config = config_from_toml(
            r#"
[[rules]]
id = "test-key"
description = "Test key"
regex = '''key\s*=\s*"([^"]+)"'''
keywords = ["key"]
"#,
        );
        let scanner = Scanner::new(config).unwrap();

        let dir = std::env::temp_dir().join("gitleaks_rs_test_no_secrets");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("clean.txt");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            writeln!(f, "nothing to see here").unwrap();
            writeln!(f, "just regular text").unwrap();
        }

        let findings = scanner.scan_file(&file_path).unwrap();
        assert!(findings.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Performance sanity test ---

    #[test]
    fn scan_line_perf_many_lines() {
        let scanner = Scanner::default();
        let lines: Vec<String> = (0..1000)
            .map(|i| format!("line {i}: const value = \"nothing_secret_here\";"))
            .collect();

        let start = std::time::Instant::now();
        let mut total_findings = 0;
        for line in &lines {
            total_findings += scanner.scan_line(line, None).len();
        }
        let elapsed = start.elapsed();

        // 1000 lines should complete in under 5 seconds even on slow CI
        assert!(
            elapsed.as_secs() < 5,
            "scanning 1000 lines took {elapsed:?}, expected < 5s"
        );
        // Most lines should produce no findings
        assert!(
            total_findings < 100,
            "expected few false positives, got {total_findings}"
        );
    }

    // ----- Redaction tests -----

    /// Helper: build a scanner with a simple token rule.
    fn simple_token_scanner() -> Scanner {
        let config = config_from_toml(
            r#"
            title = "test"
            [[rules]]
            id = "test-tok"
            description = "Test token"
            regex = '''secret_key\s*=\s*"([^"]+)"'''
            keywords = ["secret_key"]
        "#,
        );
        Scanner::new(config).unwrap()
    }

    #[test]
    fn redact_line_single_secret() {
        let scanner = simple_token_scanner();
        let line = r#"secret_key = "my_token_value""#;
        let result = scanner.redact_line(line, None);
        assert!(
            result.content.contains("REDACTED"),
            "expected REDACTED in output: {}",
            result.content
        );
        assert!(
            !result.content.contains("my_token_value"),
            "secret should be removed from output: {}",
            result.content
        );
        assert_eq!(result.redaction_count, 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "test-tok");
    }

    #[test]
    fn redact_line_preserves_surrounding_text() {
        let scanner = simple_token_scanner();
        let line = r#"export secret_key = "my_token_value" # comment"#;
        let result = scanner.redact_line(line, None);
        assert!(
            result.content.starts_with("export "),
            "prefix should be preserved: {}",
            result.content
        );
        assert!(
            result.content.ends_with(" # comment"),
            "suffix should be preserved: {}",
            result.content
        );
    }

    #[test]
    fn redact_line_no_secrets_unchanged() {
        let scanner = simple_token_scanner();
        let line = "nothing secret here at all";
        let result = scanner.redact_line(line, None);
        assert_eq!(result.content, line);
        assert_eq!(result.redaction_count, 0);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn redact_line_empty_input() {
        let scanner = simple_token_scanner();
        let result = scanner.redact_line("", None);
        assert_eq!(result.content, "");
        assert_eq!(result.redaction_count, 0);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn redact_line_with_custom_replacement() {
        let scanner = simple_token_scanner();
        let line = r#"secret_key = "my_token_value""#;
        let result = scanner.redact_line_with(line, None, "***");
        assert!(
            result.content.contains("***"),
            "custom replacement should be used: {}",
            result.content
        );
        assert!(
            !result.content.contains("REDACTED"),
            "default replacement should not appear: {}",
            result.content
        );
        assert!(
            !result.content.contains("my_token_value"),
            "secret should be removed: {}",
            result.content
        );
        assert_eq!(result.redaction_count, 1);
    }

    #[test]
    fn redact_line_multiple_secrets() {
        let toml = r#"
            title = "test"
            [[rules]]
            id = "tok-a"
            description = "Token A"
            regex = '''TOKA_[A-Z0-9]{10}'''
            keywords = ["toka_"]

            [[rules]]
            id = "tok-b"
            description = "Token B"
            regex = '''TOKB_[A-Z0-9]{10}'''
            keywords = ["tokb_"]
        "#;
        let config = config_from_toml(toml);
        let scanner = Scanner::new(config).unwrap();
        let line = "a=TOKA_ABCDEFGHIJ b=TOKB_0123456789";
        let result = scanner.redact_line(line, None);
        assert_eq!(result.redaction_count, 2);
        assert!(
            !result.content.contains("TOKA_ABCDEFGHIJ"),
            "first secret should be redacted: {}",
            result.content
        );
        assert!(
            !result.content.contains("TOKB_0123456789"),
            "second secret should be redacted: {}",
            result.content
        );
        // Surrounding text preserved.
        assert!(result.content.contains("a="));
        assert!(result.content.contains(" b="));
    }

    #[test]
    fn redact_text_multiline() {
        let scanner = simple_token_scanner();
        let text = "line one\nsecret_key = \"my_token_value\"\nline three";
        let result = scanner.redact_text(text, None);
        assert_eq!(result.redaction_count, 1);
        assert!(result.content.contains("REDACTED"));
        assert!(!result.content.contains("my_token_value"));
        // Lines are preserved.
        let lines: Vec<&str> = result.content.split('\n').collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line one");
        assert_eq!(lines[2], "line three");
    }

    #[test]
    fn redact_text_line_numbers_correct() {
        let scanner = simple_token_scanner();
        let text = "clean\nsecret_key = \"my_token_value\"\nalso clean";
        let result = scanner.redact_text(text, None);
        assert_eq!(result.findings.len(), 1);
        // Secret is on line 2 (1-indexed).
        assert_eq!(result.findings[0].line_number, Some(2));
    }

    #[test]
    fn redact_text_multiple_lines_with_secrets() {
        let toml = r#"
            title = "test"
            [[rules]]
            id = "tok"
            description = "Token"
            regex = '''TOK_[A-Z0-9]{10}'''
            keywords = ["tok_"]
        "#;
        let config = config_from_toml(toml);
        let scanner = Scanner::new(config).unwrap();
        let text = "a=TOK_AAAAAAAAAA\nclean\nb=TOK_BBBBBBBBBB";
        let result = scanner.redact_text(text, None);
        assert_eq!(result.redaction_count, 2);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].line_number, Some(1));
        assert_eq!(result.findings[1].line_number, Some(3));
        assert!(!result.content.contains("TOK_AAAAAAAAAA"));
        assert!(!result.content.contains("TOK_BBBBBBBBBB"));
    }

    #[test]
    fn redact_text_preserves_blank_lines() {
        let scanner = simple_token_scanner();
        let text = "line one\n\n\nline four";
        let result = scanner.redact_text(text, None);
        // All lines including blanks are preserved.
        let lines: Vec<&str> = result.content.split('\n').collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1], "");
        assert_eq!(lines[2], "");
    }

    #[test]
    fn redact_text_trailing_newline_preserved() {
        let scanner = simple_token_scanner();
        let text = "line one\nline two\n";
        let result = scanner.redact_text(text, None);
        assert!(
            result.content.ends_with('\n'),
            "trailing newline should be preserved: {:?}",
            result.content
        );
    }

    #[test]
    fn redact_text_with_custom_replacement() {
        let scanner = simple_token_scanner();
        let text = "secret_key = \"my_token_value\"";
        let result = scanner.redact_text_with(text, None, "[HIDDEN]");
        assert!(result.content.contains("[HIDDEN]"));
        assert!(!result.content.contains("my_token_value"));
        assert_eq!(result.redaction_count, 1);
    }

    #[test]
    fn redact_line_idempotent() {
        // Use a fixed-format token pattern where "REDACTED" won't re-match.
        let config = config_from_toml(
            r#"
            title = "test"
            [[rules]]
            id = "tok"
            description = "Token"
            regex = '''TOK_[A-Z0-9]{10}'''
            keywords = ["tok_"]
        "#,
        );
        let scanner = Scanner::new(config).unwrap();
        let line = "key=TOK_AAAAAAAAAA";
        let first = scanner.redact_line(line, None);
        assert_eq!(first.redaction_count, 1);
        // Redacting the already-redacted output should be a no-op.
        let second = scanner.redact_line(&first.content, None);
        assert_eq!(second.content, first.content);
        assert_eq!(second.redaction_count, 0);
        assert!(second.findings.is_empty());
    }

    #[test]
    fn redact_text_idempotent() {
        let config = config_from_toml(
            r#"
            title = "test"
            [[rules]]
            id = "tok"
            description = "Token"
            regex = '''TOK_[A-Z0-9]{10}'''
            keywords = ["tok_"]
        "#,
        );
        let scanner = Scanner::new(config).unwrap();
        let text = "line\nkey=TOK_AAAAAAAAAA\nend";
        let first = scanner.redact_text(text, None);
        let second = scanner.redact_text(&first.content, None);
        assert_eq!(second.content, first.content);
        assert_eq!(second.redaction_count, 0);
    }

    #[test]
    fn redact_line_with_path_filtering() {
        let toml = r#"
            title = "test"
            [[rules]]
            id = "path-tok"
            description = "Path-restricted token"
            regex = '''PTOK_[A-Z0-9]{10}'''
            keywords = ["ptok_"]
            path = '''\.env$'''
        "#;
        let config = config_from_toml(toml);
        let scanner = Scanner::new(config).unwrap();
        let line = "key=PTOK_ABCDEFGHIJ";

        // Without matching path — no redaction.
        let result = scanner.redact_line(line, Some("config.yaml"));
        assert_eq!(result.redaction_count, 0);
        assert_eq!(result.content, line);

        // With matching path — should redact.
        let result = scanner.redact_line(line, Some("app.env"));
        assert_eq!(result.redaction_count, 1);
        assert!(result.content.contains("REDACTED"));
    }

    #[test]
    fn redact_text_empty_input() {
        let scanner = simple_token_scanner();
        let result = scanner.redact_text("", None);
        assert_eq!(result.content, "");
        assert_eq!(result.redaction_count, 0);
        // Empty text split on \n yields one empty segment.
        assert!(result.findings.is_empty());
    }

    #[test]
    fn redact_line_redaction_count_matches_actual_replacements() {
        let toml = r#"
            title = "test"
            [[rules]]
            id = "tok"
            description = "Token"
            regex = '''TOK_[A-Z0-9]{10}'''
            keywords = ["tok_"]
        "#;
        let config = config_from_toml(toml);
        let scanner = Scanner::new(config).unwrap();
        let line = "x=TOK_AAAAAAAAAA y=TOK_BBBBBBBBBB";
        let result = scanner.redact_line(line, None);
        let redacted_occurrences = result.content.matches("REDACTED").count();
        assert_eq!(
            result.redaction_count, redacted_occurrences,
            "redaction_count ({}) should match actual REDACTED occurrences ({})",
            result.redaction_count, redacted_occurrences
        );
    }

    #[test]
    fn redact_line_overlapping_findings_handled() {
        // Two rules where one matches a substring of the other.
        let toml = r#"
            title = "test"
            [[rules]]
            id = "wide"
            description = "Wide match"
            regex = '''WIDE_[A-Z0-9]{20}'''
            keywords = ["wide_"]

            [[rules]]
            id = "narrow"
            description = "Narrow match"
            regex = '''[A-Z0-9]{15}'''
            keywords = ["wide_"]
        "#;
        let config = config_from_toml(toml);
        let scanner = Scanner::new(config).unwrap();
        let line = "x=WIDE_ABCDEFGHIJ0123456789";
        let result = scanner.redact_line(line, None);
        // Should not panic. Overlapping replacement should be skipped.
        assert!(result.redaction_count >= 1);
        // Content should still make sense (no double-replacement gibberish).
        assert!(!result.content.contains("WIDE_ABCDEFGHIJ0123456789"));
    }

    // ----- ContentRegex wrapper tests -----

    #[test]
    fn content_regex_eager_is_match() {
        let re = Regex::new(r"secret_[a-z]+").unwrap();
        let cr = ContentRegex::Eager(re);
        assert!(cr.is_match("my secret_key here"));
        assert!(!cr.is_match("no match here"));
    }

    #[test]
    fn content_regex_eager_captures_iter() {
        let re = Regex::new(r"(key)_(\d+)").unwrap();
        let cr = ContentRegex::Eager(re);

        let caps: Vec<_> = cr.captures_iter("key_1 and key_42").collect();
        assert_eq!(caps.len(), 2);

        // First match
        assert_eq!(caps[0].get(0).unwrap().as_str(), "key_1");
        assert_eq!(caps[0].get(1).unwrap().as_str(), "key");
        assert_eq!(caps[0].get(2).unwrap().as_str(), "1");

        // Second match
        assert_eq!(caps[1].get(0).unwrap().as_str(), "key_42");
        assert_eq!(caps[1].get(1).unwrap().as_str(), "key");
        assert_eq!(caps[1].get(2).unwrap().as_str(), "42");
    }

    #[test]
    fn content_regex_eager_debug() {
        let re = Regex::new(r"secret_[a-z]+").unwrap();
        let cr = ContentRegex::Eager(re);
        let debug = format!("{:?}", cr);
        assert!(
            debug.contains("ContentRegex::Eager"),
            "expected variant name in debug output: {debug}"
        );
        assert!(
            debug.contains("secret_"),
            "expected pattern text in debug output: {debug}"
        );
    }

    // ----- MatchOnlyRegex wrapper tests -----

    #[test]
    fn match_only_regex_eager_is_match() {
        let re = Regex::new(r"\.go$").unwrap();
        let mr = MatchOnlyRegex::Eager(re);

        // Positive match
        assert!(mr.is_match("main.go"));
        assert!(mr.is_match("path/to/file.go"));

        // Negative match
        assert!(!mr.is_match("main.rs"));
        assert!(!mr.is_match(""));
        assert!(!mr.is_match("go"));
    }

    #[test]
    fn match_only_regex_eager_is_match_with_metacharacters() {
        let re = Regex::new(r"secret\[\d+\]").unwrap();
        let mr = MatchOnlyRegex::Eager(re);

        assert!(mr.is_match("secret[42]"));
        assert!(mr.is_match("prefix secret[0] suffix"));
        assert!(!mr.is_match("secret[]"));
        assert!(!mr.is_match("secret[abc]"));
    }

    #[test]
    fn match_only_regex_eager_is_match_dot_pattern() {
        // Dot matches any character — verify semantics inherited from regex::Regex
        let re = Regex::new(r".").unwrap();
        let mr = MatchOnlyRegex::Eager(re);

        assert!(mr.is_match("x"));
        assert!(mr.is_match(" "));
        assert!(!mr.is_match(""));
    }

    #[test]
    fn match_only_regex_eager_debug() {
        let re = Regex::new(r"\.go$").unwrap();
        let mr = MatchOnlyRegex::Eager(re);
        let debug = format!("{:?}", mr);
        assert!(
            debug.contains("MatchOnlyRegex::Eager"),
            "expected variant name in debug output: {debug}"
        );
        assert!(
            debug.contains(r"\.go"),
            "expected pattern fragment in debug output: {debug}"
        );
    }

    // ----- MatchOnlyRegex Dfa variant tests -----

    #[cfg(feature = "cache")]
    mod match_only_regex_dfa {
        use super::*;
        use crate::cache::try_build_sparse_dfa;

        #[test]
        fn dfa_is_match_with_valid_dfa() {
            let pattern = r"\.go$";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let mr = MatchOnlyRegex::Dfa(dfa_bytes);

            // Positive matches
            assert!(mr.is_match("main.go"));
            assert!(mr.is_match("path/to/file.go"));

            // Negative matches
            assert!(!mr.is_match("main.rs"));
            assert!(!mr.is_match(""));
            assert!(!mr.is_match("go"));
        }

        #[test]
        fn dfa_is_match_agrees_with_eager() {
            // DFA and eager regex must agree on match results.
            let pattern = r"secret\[\d+\]";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let dfa_mr = MatchOnlyRegex::Dfa(dfa_bytes);
            let eager_mr = MatchOnlyRegex::Eager(Regex::new(pattern).unwrap());

            let cases = [
                "secret[42]",
                "prefix secret[0] suffix",
                "secret[]",
                "secret[abc]",
                "no match",
                "",
            ];
            for text in &cases {
                assert_eq!(
                    dfa_mr.is_match(text),
                    eager_mr.is_match(text),
                    "DFA/eager disagreement for: {text:?}"
                );
            }
        }

        #[test]
        fn dfa_is_match_with_invalid_dfa_bytes() {
            // Corrupt DFA bytes must return false (graceful fallback), not panic.
            let mr = MatchOnlyRegex::Dfa(vec![0, 1, 2, 3]);
            assert!(!mr.is_match("anything"));
            assert!(!mr.is_match("main.go"));
            assert!(!mr.is_match(""));
        }

        #[test]
        fn dfa_is_match_with_empty_dfa_bytes() {
            // Empty byte slice must not panic, just return false.
            let mr = MatchOnlyRegex::Dfa(vec![]);
            assert!(!mr.is_match("anything"));
            assert!(!mr.is_match(""));
        }

        #[test]
        fn dfa_debug_output() {
            let pattern = r"\.go$";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let byte_count = dfa_bytes.len();
            let mr = MatchOnlyRegex::Dfa(dfa_bytes);
            let debug = format!("{:?}", mr);
            assert!(
                debug.contains("MatchOnlyRegex::Dfa"),
                "expected variant name in debug output: {debug}"
            );
            assert!(
                debug.contains(&format!("{byte_count} bytes")),
                "expected byte count in debug output: {debug}"
            );
        }

        #[test]
        fn dfa_repeated_calls_stable() {
            // Repeated is_match() calls must be deterministic.
            let pattern = r"test_\w+";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let mr = MatchOnlyRegex::Dfa(dfa_bytes);

            for _ in 0..10 {
                assert!(mr.is_match("test_abc"));
                assert!(!mr.is_match("no match"));
            }
        }
    }

    // ----- ContentRegex cached variant tests -----

    #[cfg(feature = "cache")]
    mod cached_content_regex {
        use super::*;
        use crate::cache::try_build_sparse_dfa;
        use std::sync::OnceLock;

        #[test]
        fn cached_is_match_with_valid_dfa() {
            let pattern = r"secret_[a-z]+";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let cr = ContentRegex::Cached {
                dfa_bytes,
                pattern: pattern.to_string(),
                regex: OnceLock::new(),
            };
            assert!(cr.is_match("my secret_key here"));
            assert!(!cr.is_match("no match here"));
        }

        #[test]
        fn cached_is_match_with_invalid_dfa_bytes() {
            // Invalid DFA bytes should return false (graceful fallback), not panic.
            let cr = ContentRegex::Cached {
                dfa_bytes: vec![0, 1, 2, 3],
                pattern: r"secret_[a-z]+".to_string(),
                regex: OnceLock::new(),
            };
            assert!(!cr.is_match("my secret_key here"));
        }

        #[test]
        fn cached_is_match_with_empty_dfa_bytes() {
            // Empty byte slice should not panic, just return false.
            let cr = ContentRegex::Cached {
                dfa_bytes: vec![],
                pattern: r"secret".to_string(),
                regex: OnceLock::new(),
            };
            assert!(!cr.is_match("secret here"));
        }

        #[test]
        fn cached_captures_iter_lazily_compiles() {
            let pattern = r"(key)_(\d+)";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let cr = ContentRegex::Cached {
                dfa_bytes,
                pattern: pattern.to_string(),
                regex: OnceLock::new(),
            };

            let caps: Vec<_> = cr.captures_iter("key_1 and key_42").collect();
            assert_eq!(caps.len(), 2);
            assert_eq!(caps[0].get(0).unwrap().as_str(), "key_1");
            assert_eq!(caps[0].get(1).unwrap().as_str(), "key");
            assert_eq!(caps[0].get(2).unwrap().as_str(), "1");
            assert_eq!(caps[1].get(0).unwrap().as_str(), "key_42");
            assert_eq!(caps[1].get(1).unwrap().as_str(), "key");
            assert_eq!(caps[1].get(2).unwrap().as_str(), "42");
        }

        #[test]
        fn cached_is_match_agrees_with_captures_iter() {
            // DFA-based is_match and lazy regex captures_iter must agree.
            let pattern = r"api[_-]?key[:\s]*[A-Za-z0-9]{16,}";
            let dfa_bytes = try_build_sparse_dfa(pattern).expect("DFA should build");
            let cr = ContentRegex::Cached {
                dfa_bytes,
                pattern: pattern.to_string(),
                regex: OnceLock::new(),
            };

            let cases = [
                ("api_key: ABCDEFGHIJ0123456789", true),
                ("apikey:abc123", false),
                ("no secret here", false),
            ];
            for (text, expected) in &cases {
                assert_eq!(
                    cr.is_match(text),
                    *expected,
                    "is_match mismatch for: {text}"
                );
                let has_captures = cr.captures_iter(text).next().is_some();
                assert_eq!(
                    has_captures, *expected,
                    "captures_iter mismatch for: {text}"
                );
            }
        }

        #[test]
        fn cached_debug_output() {
            let cr = ContentRegex::Cached {
                dfa_bytes: vec![],
                pattern: "secret_[a-z]+".to_string(),
                regex: OnceLock::new(),
            };
            let debug = format!("{:?}", cr);
            assert!(
                debug.contains("ContentRegex::Cached"),
                "expected variant name in debug output: {debug}"
            );
            assert!(
                debug.contains("secret_"),
                "expected pattern text in debug output: {debug}"
            );
        }

        #[test]
        fn lazy_only_is_match() {
            let cr = ContentRegex::LazyOnly {
                pattern: r"secret_[a-z]+".to_string(),
                regex: OnceLock::new(),
            };
            assert!(cr.is_match("my secret_key here"));
            assert!(!cr.is_match("no match here"));
        }

        #[test]
        fn lazy_only_captures_iter() {
            let cr = ContentRegex::LazyOnly {
                pattern: r"(key)_(\d+)".to_string(),
                regex: OnceLock::new(),
            };

            let caps: Vec<_> = cr.captures_iter("key_1 and key_42").collect();
            assert_eq!(caps.len(), 2);
            assert_eq!(caps[0].get(0).unwrap().as_str(), "key_1");
            assert_eq!(caps[0].get(1).unwrap().as_str(), "key");
            assert_eq!(caps[0].get(2).unwrap().as_str(), "1");
            assert_eq!(caps[1].get(0).unwrap().as_str(), "key_42");
        }

        #[test]
        fn lazy_only_debug_output() {
            let cr = ContentRegex::LazyOnly {
                pattern: "secret_[a-z]+".to_string(),
                regex: OnceLock::new(),
            };
            let debug = format!("{:?}", cr);
            assert!(
                debug.contains("ContentRegex::LazyOnly"),
                "expected variant name in debug output: {debug}"
            );
            assert!(
                debug.contains("secret_"),
                "expected pattern text in debug output: {debug}"
            );
        }

        #[test]
        fn lazy_only_repeated_calls_stable() {
            // OnceLock initializes once; repeated calls should be stable.
            let cr = ContentRegex::LazyOnly {
                pattern: r"(tok)_(\w+)".to_string(),
                regex: OnceLock::new(),
            };
            assert!(cr.is_match("tok_abc"));
            assert!(cr.is_match("tok_xyz"));
            assert!(!cr.is_match("no match"));

            // Captures should work correctly after repeated is_match calls.
            let caps: Vec<_> = cr.captures_iter("tok_one tok_two").collect();
            assert_eq!(caps.len(), 2);
        }
    }

    // ----- new_with_cache constructor tests -----

    #[cfg(feature = "cache")]
    mod new_with_cache_tests {
        use super::*;
        use std::path::PathBuf;

        fn unique_cache_path(name: &str) -> PathBuf {
            std::env::temp_dir()
                .join("gitleaks_rs_scanner_nwc_test")
                .join(format!("{name}.cache"))
        }

        fn setup_dir(name: &str) -> PathBuf {
            let path = unique_cache_path(name);
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            let _ = std::fs::remove_file(&path);
            path
        }

        #[test]
        fn new_with_cache_cold_start_succeeds() {
            let cache_path = setup_dir("cold_start");
            let scanner = Scanner::new_with_cache(&cache_path).unwrap();
            assert!(
                scanner.rule_count() > 200,
                "expected 222+ rules from default config"
            );
            let _ = std::fs::remove_file(&cache_path);
        }

        #[test]
        fn new_with_cache_creates_cache_file() {
            let cache_path = setup_dir("creates_file");
            assert!(!cache_path.exists());
            let _scanner = Scanner::new_with_cache(&cache_path).unwrap();
            assert!(
                cache_path.exists(),
                "cache file should be created on cold start"
            );
            let _ = std::fs::remove_file(&cache_path);
        }

        #[test]
        fn new_with_cache_hot_start_loads_from_cache() {
            let cache_path = setup_dir("hot_start");
            // Cold start: creates cache
            let _scanner1 = Scanner::new_with_cache(&cache_path).unwrap();
            assert!(cache_path.exists());

            // Hot start: loads from cache
            let scanner2 = Scanner::new_with_cache(&cache_path).unwrap();
            assert!(scanner2.rule_count() > 200);
            let _ = std::fs::remove_file(&cache_path);
        }

        #[test]
        fn new_with_cache_finds_secrets() {
            let cache_path = setup_dir("finds_secrets");
            let scanner = Scanner::new_with_cache(&cache_path).unwrap();
            let findings = scanner.scan_text("AKIAIOSFODNN7ZZZABCD", None);
            assert!(!findings.is_empty(), "should detect AWS key");
            let _ = std::fs::remove_file(&cache_path);
        }

        #[test]
        fn new_with_cache_corrupt_file_fallback() {
            let cache_path = setup_dir("corrupt_fallback");
            // Write garbage to cache path
            std::fs::write(&cache_path, b"not a valid cache file").unwrap();

            // Should fall back to full compilation without error
            let scanner = Scanner::new_with_cache(&cache_path).unwrap();
            assert!(scanner.rule_count() > 200);
            let _ = std::fs::remove_file(&cache_path);
        }

        #[test]
        fn new_with_cache_missing_parent_dir_fallback() {
            // Parent directory doesn't exist — save will fail, but constructor succeeds
            let path = PathBuf::from("/tmp/gitleaks_rs_nonexistent_parent_dir_test/sub/cache.bin");
            let scanner = Scanner::new_with_cache(&path).unwrap();
            assert!(scanner.rule_count() > 200);
        }

        #[test]
        fn new_with_cache_uses_default_config() {
            let cache_path = setup_dir("default_config");
            let scanner_cached = Scanner::new_with_cache(&cache_path).unwrap();
            let config = Config::default().unwrap();
            let scanner_eager = Scanner::new(config).unwrap();
            assert_eq!(
                scanner_cached.rule_count(),
                scanner_eager.rule_count(),
                "cached scanner should have same rule count as eager scanner"
            );
            let _ = std::fs::remove_file(&cache_path);
        }
    }
}
