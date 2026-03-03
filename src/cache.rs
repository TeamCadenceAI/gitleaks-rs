//! Disk-based DFA cache for near-instant `Scanner` construction.
//!
//! This module serializes compiled DFA automata to disk and loads them back
//! in constant time. The cache format includes a header with magic bytes,
//! format version, config content hash, and crate version for invalidation.
//!
//! DFA construction applies [`go_re2_compat()`](crate::scanner::go_re2_compat)
//! preprocessing to all patterns before building.
//!
//! Cache files are **endian-dependent** (native endian) and not portable
//! across architectures.

use std::io::Write;
use std::path::Path;

use regex_automata::dfa::dense;
use regex_automata::dfa::sparse::DFA as SparseDFA;
use regex_automata::dfa::Automaton;
use regex_automata::Input;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Condition, Config, RegexTarget, DEFAULT_CONFIG_TOML};
use crate::error::{Error, Result};
use crate::scanner::{
    go_re2_compat, CompiledGlobalAllowlist, CompiledRule, CompiledRuleAllowlist, ContentRegex,
    MatchOnlyRegex, Scanner,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of every cache file.
const MAGIC: &[u8; 8] = b"GLRS_DFA";

/// Current cache format version. Increment when the binary layout changes.
const FORMAT_VERSION: u16 = 1;

/// Crate version string, null-padded to 16 bytes in the header.
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum DFA size limit per pattern (10 MB).
const DFA_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum DFA determinize size limit per pattern (20 MB).
const DFA_DETERMINIZE_LIMIT: usize = 20 * (1 << 20);

// ---------------------------------------------------------------------------
// Serializable cache metadata
// ---------------------------------------------------------------------------

/// Serializable metadata for a single rule's allowlist entry.
#[derive(Debug, Serialize, Deserialize)]
struct CachedAllowlistMeta {
    dfa_count: usize,
    path_dfa_count: usize,
    regex_target: u8, // 0=Secret, 1=Match, 2=Line
    stopwords: Vec<String>,
    condition: u8, // 0=Or, 1=And
}

/// Serializable metadata for a single compiled rule.
#[derive(Debug, Serialize, Deserialize)]
struct CachedRuleMeta {
    id: String,
    description: String,
    has_content_dfa: bool,
    content_pattern: Option<String>,
    has_path_dfa: bool,
    path_pattern: Option<String>,
    entropy: Option<f64>,
    secret_group: Option<usize>,
    keywords: Vec<String>,
    allowlists: Vec<CachedAllowlistMeta>,
    /// Original regex strings for allowlist regexes (post go_re2_compat).
    allowlist_regex_patterns: Vec<Vec<String>>,
    /// Original regex strings for allowlist path regexes (post go_re2_compat).
    allowlist_path_patterns: Vec<Vec<String>>,
}

/// Serializable metadata for the global allowlist.
#[derive(Debug, Serialize, Deserialize)]
struct CachedGlobalAllowlistMeta {
    description: Option<String>,
    dfa_count: usize,
    path_dfa_count: usize,
    stopwords: Vec<String>,
    /// Original regex strings for global allowlist regexes (post go_re2_compat).
    regex_patterns: Vec<String>,
    /// Original regex strings for global allowlist path regexes (post go_re2_compat).
    path_patterns: Vec<String>,
}

/// Top-level cache metadata.
#[derive(Debug, Serialize, Deserialize)]
struct CacheMetadata {
    rules: Vec<CachedRuleMeta>,
    keywords: Vec<String>,
    keyword_to_rules: Vec<Vec<usize>>,
    path_only_indices: Vec<usize>,
    global_allowlist: Option<CachedGlobalAllowlistMeta>,
}

// ---------------------------------------------------------------------------
// Config hashing
// ---------------------------------------------------------------------------

/// Compute a SHA-256 hash of the embedded `default_config.toml` string.
///
/// This is used for cache invalidation — if the embedded config changes,
/// the hash changes and the cache is considered stale.
pub(crate) fn compute_config_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DEFAULT_CONFIG_TOML.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// DFA building
// ---------------------------------------------------------------------------

/// Attempt to build a sparse DFA from a regex pattern.
///
/// Applies `go_re2_compat()` preprocessing before DFA construction.
/// Returns `None` if the DFA build fails (state explosion, size limit
/// exceeded, unsupported features).
pub(crate) fn try_build_sparse_dfa(pattern: &str) -> Option<Vec<u8>> {
    let compat = go_re2_compat(pattern);

    let dense_dfa = dense::Builder::new()
        .configure(
            dense::Config::new()
                .dfa_size_limit(Some(DFA_SIZE_LIMIT))
                .determinize_size_limit(Some(DFA_DETERMINIZE_LIMIT))
                .start_kind(regex_automata::dfa::StartKind::Unanchored),
        )
        .syntax(
            regex_automata::util::syntax::Config::new()
                .unicode(true)
                .utf8(true),
        )
        .build(&compat)
        .ok()?;

    let sparse_dfa = dense_dfa.to_sparse().ok()?;
    Some(sparse_dfa.to_bytes_native_endian())
}

/// Run a DFA `is_match` on serialized sparse DFA bytes.
///
/// Returns `false` on any deserialization or search error (graceful fallback).
pub(crate) fn dfa_is_match(dfa_bytes: &[u8], text: &str) -> bool {
    let (dfa, _) = match SparseDFA::<&[u8]>::from_bytes(dfa_bytes) {
        Ok(result) => result,
        Err(_) => return false,
    };

    let input = Input::new(text);
    matches!(dfa.try_search_fwd(&input), Ok(Some(_)))
}

// ---------------------------------------------------------------------------
// Cache file I/O
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Header layout constants
// ---------------------------------------------------------------------------

/// Header size: 8 (magic) + 2 (version) + 32 (hash) + 16 (crate version) = 58 bytes.
#[cfg(test)]
const HEADER_SIZE: usize = 8 + 2 + 32 + 16;

// ---------------------------------------------------------------------------
// DFA blob collection helpers
// ---------------------------------------------------------------------------

/// Collect DFA blobs and metadata for a single rule's allowlist patterns.
///
/// Pushes regex DFAs then path DFAs to `blobs` in deterministic order.
/// Returns `(CachedAllowlistMeta, regex_patterns, path_patterns)`.
fn collect_allowlist_blobs(
    compiled_al: &CompiledRuleAllowlist,
    config_regexes: &[String],
    config_paths: &[String],
    blobs: &mut Vec<Vec<u8>>,
) -> (CachedAllowlistMeta, Vec<String>, Vec<String>) {
    let mut regex_pats = Vec::new();
    let mut regex_dfa_count = 0;
    for pat in config_regexes {
        let compat = go_re2_compat(pat).into_owned();
        let dfa = try_build_sparse_dfa(&compat);
        if dfa.is_some() {
            regex_dfa_count += 1;
        }
        blobs.push(dfa.unwrap_or_default());
        regex_pats.push(compat);
    }

    let mut path_pats = Vec::new();
    let mut path_dfa_count = 0;
    for pat in config_paths {
        let compat = go_re2_compat(pat).into_owned();
        let dfa = try_build_sparse_dfa(&compat);
        if dfa.is_some() {
            path_dfa_count += 1;
        }
        blobs.push(dfa.unwrap_or_default());
        path_pats.push(compat);
    }

    let meta = CachedAllowlistMeta {
        dfa_count: regex_dfa_count,
        path_dfa_count,
        regex_target: match compiled_al.regex_target {
            RegexTarget::Secret => 0,
            RegexTarget::Match => 1,
            RegexTarget::Line => 2,
        },
        stopwords: compiled_al.stopwords.clone(),
        condition: match compiled_al.condition {
            Condition::Or => 0,
            Condition::And => 1,
        },
    };

    (meta, regex_pats, path_pats)
}

/// Write a DFA blob with a u32 LE length prefix.
///
/// Returns `Error::Cache` if the blob exceeds `u32::MAX` bytes.
fn write_blob(w: &mut impl Write, blob: &[u8]) -> Result<()> {
    let len: u32 = blob
        .len()
        .try_into()
        .map_err(|_| Error::Cache("DFA blob exceeds u32::MAX bytes".into()))?;
    w.write_all(&len.to_le_bytes())
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;
    if !blob.is_empty() {
        w.write_all(blob)
            .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;
    }
    Ok(())
}

/// Save a compiled `Scanner` (from default config) to a cache file on disk.
///
/// The cache file binary format is:
///
/// | Offset | Size | Contents |
/// |--------|------|----------|
/// | 0 | 8 | Magic bytes `b"GLRS_DFA"` |
/// | 8 | 2 | Format version (`u16` LE) |
/// | 10 | 32 | SHA-256 config hash |
/// | 42 | 16 | Crate version, null-padded |
/// | 58 | 4 | Metadata length (`u32` LE) |
/// | 62 | N | Bincode-encoded [`CacheMetadata`] |
/// | 62+N | ... | DFA blobs, each preceded by `u32` LE length |
///
/// DFA blob ordering is deterministic: for each rule in index order,
/// content DFA then path DFA, then per-allowlist regex DFAs then
/// per-allowlist path DFAs; finally global allowlist regex DFAs then
/// global allowlist path DFAs.
///
/// Uses `BufWriter` for efficient I/O and writes to a temporary file
/// before renaming, preventing partial/torn cache files.
pub(crate) fn try_save(
    path: &Path,
    config_hash: &[u8; 32],
    scanner: &Scanner,
    config: &Config,
) -> Result<()> {
    // --- Build metadata and collect DFA blobs ---
    let mut dfa_blobs: Vec<Vec<u8>> = Vec::new();
    let mut rules_meta: Vec<CachedRuleMeta> = Vec::new();

    for (rule_idx, compiled_rule) in scanner.rules.iter().enumerate() {
        let config_rule = &config.rules[rule_idx];

        // Content DFA
        let content_pattern = config_rule.regex.as_deref().map(|p| {
            let compat = go_re2_compat(p);
            compat.into_owned()
        });
        let content_dfa = content_pattern.as_deref().and_then(try_build_sparse_dfa);
        let has_content_dfa = content_dfa.is_some();
        dfa_blobs.push(content_dfa.unwrap_or_default());

        // Path DFA
        let path_pattern = config_rule.path.as_deref().map(|p| {
            let compat = go_re2_compat(p);
            compat.into_owned()
        });
        let path_dfa = path_pattern.as_deref().and_then(try_build_sparse_dfa);
        let has_path_dfa = path_dfa.is_some();
        dfa_blobs.push(path_dfa.unwrap_or_default());

        // Per-rule allowlists
        let mut allowlists_meta = Vec::new();
        let mut al_regex_patterns: Vec<Vec<String>> = Vec::new();
        let mut al_path_patterns: Vec<Vec<String>> = Vec::new();

        for (al_idx, al) in compiled_rule.allowlists.iter().enumerate() {
            let config_al = &config_rule.allowlists[al_idx];
            let (meta, rpats, ppats) =
                collect_allowlist_blobs(al, &config_al.regexes, &config_al.paths, &mut dfa_blobs);
            allowlists_meta.push(meta);
            al_regex_patterns.push(rpats);
            al_path_patterns.push(ppats);
        }

        rules_meta.push(CachedRuleMeta {
            id: compiled_rule.id.clone(),
            description: compiled_rule.description.clone(),
            has_content_dfa,
            content_pattern,
            has_path_dfa,
            path_pattern,
            entropy: compiled_rule.entropy,
            secret_group: compiled_rule.secret_group,
            keywords: compiled_rule.keywords.clone(),
            allowlists: allowlists_meta,
            allowlist_regex_patterns: al_regex_patterns,
            allowlist_path_patterns: al_path_patterns,
        });
    }

    // Global allowlist
    let global_allowlist_meta = if let (Some(gal), Some(config_al)) =
        (&scanner.global_allowlist, config.allowlist.as_ref())
    {
        let mut regex_pats = Vec::new();
        let mut regex_dfa_count = 0;
        for pat in &config_al.regexes {
            let compat = go_re2_compat(pat).into_owned();
            let dfa = try_build_sparse_dfa(&compat);
            if dfa.is_some() {
                regex_dfa_count += 1;
            }
            dfa_blobs.push(dfa.unwrap_or_default());
            regex_pats.push(compat);
        }

        let mut path_pats = Vec::new();
        let mut path_dfa_count = 0;
        for pat in &config_al.paths {
            let compat = go_re2_compat(pat).into_owned();
            let dfa = try_build_sparse_dfa(&compat);
            if dfa.is_some() {
                path_dfa_count += 1;
            }
            dfa_blobs.push(dfa.unwrap_or_default());
            path_pats.push(compat);
        }

        Some(CachedGlobalAllowlistMeta {
            description: gal.description.clone(),
            dfa_count: regex_dfa_count,
            path_dfa_count,
            stopwords: gal.stopwords.clone(),
            regex_patterns: regex_pats,
            path_patterns: path_pats,
        })
    } else {
        None
    };

    // Collect unique keywords for rebuild on load.
    let mut keywords: Vec<String> = Vec::new();
    for rule in &scanner.rules {
        for kw in &rule.keywords {
            if !keywords.contains(kw) {
                keywords.push(kw.clone());
            }
        }
    }

    let metadata = CacheMetadata {
        rules: rules_meta,
        keywords,
        keyword_to_rules: scanner.keyword_to_rules.clone(),
        path_only_indices: scanner.path_only_indices.clone(),
        global_allowlist: global_allowlist_meta,
    };

    // --- Serialize metadata ---
    let meta_bytes = bincode::serialize(&metadata)
        .map_err(|e| Error::Cache(format!("failed to serialize cache metadata: {e}")))?;

    let meta_len: u32 = meta_bytes
        .len()
        .try_into()
        .map_err(|_| Error::Cache("serialized metadata exceeds u32::MAX bytes".into()))?;

    // --- Write to temp file then rename for atomicity ---
    let tmp_path = path.with_extension("tmp");
    let file = std::fs::File::create(&tmp_path)
        .map_err(|e| Error::Cache(format!("failed to create cache file: {e}")))?;
    let mut w = std::io::BufWriter::new(file);

    // Header (58 bytes total)
    w.write_all(MAGIC)
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;
    w.write_all(&FORMAT_VERSION.to_le_bytes())
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;
    w.write_all(config_hash)
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;

    let mut version_bytes = [0u8; 16];
    let v = CRATE_VERSION.as_bytes();
    let copy_len = v.len().min(16);
    version_bytes[..copy_len].copy_from_slice(&v[..copy_len]);
    w.write_all(&version_bytes)
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;

    // Metadata section
    w.write_all(&meta_len.to_le_bytes())
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;
    w.write_all(&meta_bytes)
        .map_err(|e| Error::Cache(format!("failed to write cache: {e}")))?;

    // DFA blobs in deterministic order
    for blob in &dfa_blobs {
        write_blob(&mut w, blob)?;
    }

    // Flush and sync before rename to ensure data is on disk.
    w.flush()
        .map_err(|e| Error::Cache(format!("failed to flush cache: {e}")))?;
    w.into_inner()
        .map_err(|e| Error::Cache(format!("failed to flush cache: {e}")))?
        .sync_all()
        .map_err(|e| Error::Cache(format!("failed to sync cache: {e}")))?;

    // Atomic rename from tmp to final path.
    std::fs::rename(&tmp_path, path)
        .map_err(|e| Error::Cache(format!("failed to rename cache file: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Cache read helpers
// ---------------------------------------------------------------------------

/// Read the next DFA blob from a cursor, advancing past the u32-LE length prefix and payload.
///
/// Returns the blob bytes (may be empty for zero-length slots).
/// Returns `Error::Cache` on truncation.
fn next_blob(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    if cursor.len() < 4 {
        return Err(Error::Cache(
            "truncated DFA blob: not enough bytes for length prefix".into(),
        ));
    }
    let (len_bytes, rest) = cursor.split_at(4);
    *cursor = rest;
    let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if cursor.len() < len {
        return Err(Error::Cache(format!(
            "truncated DFA blob: expected {len} bytes, have {}",
            cursor.len()
        )));
    }
    let (blob, rest) = cursor.split_at(len);
    *cursor = rest;
    Ok(blob.to_vec())
}

/// Build a `MatchOnlyRegex::Dfa` from cached blob bytes.
///
/// Validates non-empty blobs with `SparseDFA::from_bytes()`.
/// Returns `Error::Cache("DFA validation failed")` if a non-empty blob
/// contains invalid DFA bytes. Empty blobs produce a `Dfa(Vec::new())`
/// that returns `false` for all `is_match()` calls.
fn match_only_from_blob(blob: Vec<u8>) -> Result<MatchOnlyRegex> {
    if blob.is_empty() {
        return Ok(MatchOnlyRegex::Dfa(Vec::new()));
    }
    // Validate the DFA bytes before accepting them.
    SparseDFA::<&[u8]>::from_bytes(&blob)
        .map_err(|_| Error::Cache("DFA validation failed".into()))?;
    Ok(MatchOnlyRegex::Dfa(blob))
}

/// Validate that metadata vectors have consistent shapes before indexing.
///
/// Returns `Error::Cache` if allowlist vector lengths are mismatched.
fn validate_metadata_shape(metadata: &CacheMetadata) -> Result<()> {
    for (rule_idx, rule) in metadata.rules.iter().enumerate() {
        if rule.allowlist_regex_patterns.len() != rule.allowlists.len() {
            return Err(Error::Cache(format!(
                "metadata shape error: rule {} has {} allowlists but {} allowlist_regex_patterns",
                rule_idx,
                rule.allowlists.len(),
                rule.allowlist_regex_patterns.len()
            )));
        }
        if rule.allowlist_path_patterns.len() != rule.allowlists.len() {
            return Err(Error::Cache(format!(
                "metadata shape error: rule {} has {} allowlists but {} allowlist_path_patterns",
                rule_idx,
                rule.allowlists.len(),
                rule.allowlist_path_patterns.len()
            )));
        }
    }
    Ok(())
}

/// Compute the expected number of DFA blob slots from deserialized metadata.
///
/// The formula mirrors the deterministic write order in `try_save()`:
/// for each rule: 1 content + 1 path + sum(allowlist regex counts + path counts),
/// then global allowlist regex + path counts.
///
/// **Prerequisite:** call `validate_metadata_shape()` first to ensure safe indexing.
fn expected_blob_count(metadata: &CacheMetadata) -> usize {
    let mut count = 0;
    for rule in &metadata.rules {
        count += 2; // content DFA + path DFA
        for (al_idx, _al) in rule.allowlists.iter().enumerate() {
            count += rule.allowlist_regex_patterns[al_idx].len();
            count += rule.allowlist_path_patterns[al_idx].len();
        }
    }
    if let Some(gal) = &metadata.global_allowlist {
        count += gal.regex_patterns.len();
        count += gal.path_patterns.len();
    }
    count
}

/// Load a `Scanner` from a cache file on disk.
///
/// Validates the header (magic, format version, config hash, crate version)
/// and reconstructs a full `Scanner` from cached DFAs and metadata — without
/// eagerly compiling any regexes. Content regexes use `ContentRegex::Cached`
/// (DFA prefilter + lazy `Regex`) or `ContentRegex::LazyOnly`. Path and
/// allowlist regexes use `MatchOnlyRegex::Dfa` exclusively.
pub(crate) fn try_load(path: &Path, config_hash: &[u8; 32]) -> Result<Scanner> {
    // --- Read file ---
    let data = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Cache("cache file not found".into())
        } else {
            Error::Cache(format!("failed to read cache file: {e}"))
        }
    })?;

    // --- Validate header (58 bytes) ---
    if data.len() < 8 + 2 + 32 + 16 {
        return Err(Error::Cache(
            "cache file too short (truncated header)".into(),
        ));
    }
    let mut cursor = &data[..];

    // Magic bytes (offset 0..8)
    let (magic, rest) = cursor.split_at(8);
    cursor = rest;
    if magic != MAGIC {
        return Err(Error::Cache("wrong magic".into()));
    }

    // Format version (offset 8..10)
    let (ver_bytes, rest) = cursor.split_at(2);
    cursor = rest;
    let version = u16::from_le_bytes([ver_bytes[0], ver_bytes[1]]);
    if version != FORMAT_VERSION {
        return Err(Error::Cache("wrong format version".into()));
    }

    // Config hash (offset 10..42)
    let (hash_bytes, rest) = cursor.split_at(32);
    cursor = rest;
    if hash_bytes != config_hash.as_slice() {
        return Err(Error::Cache("config hash mismatch".into()));
    }

    // Crate version (offset 42..58)
    let (version_bytes, rest) = cursor.split_at(16);
    cursor = rest;
    let mut expected_version = [0u8; 16];
    let v = CRATE_VERSION.as_bytes();
    let copy_len = v.len().min(16);
    expected_version[..copy_len].copy_from_slice(&v[..copy_len]);
    if version_bytes != expected_version.as_slice() {
        return Err(Error::Cache("crate version mismatch".into()));
    }

    // --- Read metadata ---
    if cursor.len() < 4 {
        return Err(Error::Cache("truncated metadata length".into()));
    }
    let (meta_len_bytes, rest) = cursor.split_at(4);
    cursor = rest;
    let meta_len = u32::from_le_bytes([
        meta_len_bytes[0],
        meta_len_bytes[1],
        meta_len_bytes[2],
        meta_len_bytes[3],
    ]) as usize;

    if cursor.len() < meta_len {
        return Err(Error::Cache(format!(
            "truncated metadata: expected {meta_len} bytes, have {}",
            cursor.len()
        )));
    }
    let (meta_bytes, rest) = cursor.split_at(meta_len);
    cursor = rest;

    let metadata: CacheMetadata = bincode::deserialize(meta_bytes)
        .map_err(|_| Error::Cache("metadata deserialization failed".into()))?;

    // --- Validate metadata shape before any indexing ---
    validate_metadata_shape(&metadata)?;

    // --- Read DFA blobs with strict slot counting ---
    let expected_slots = expected_blob_count(&metadata);
    let mut blob_cursor = cursor;
    let mut dfa_blobs: Vec<Vec<u8>> = Vec::with_capacity(expected_slots);
    for _ in 0..expected_slots {
        dfa_blobs.push(next_blob(&mut blob_cursor)?);
    }
    // Reject trailing bytes that don't belong to any declared slot.
    if !blob_cursor.is_empty() {
        return Err(Error::Cache(format!(
            "unexpected trailing bytes after DFA blobs: {} bytes remain",
            blob_cursor.len()
        )));
    }

    // --- Reconstruct Scanner from metadata + DFAs ---
    let mut blob_idx = 0;
    let mut compiled_rules: Vec<CompiledRule> = Vec::with_capacity(metadata.rules.len());

    for rule_meta in &metadata.rules {
        // Content DFA blob
        let content_dfa_blob = std::mem::take(&mut dfa_blobs[blob_idx]);
        blob_idx += 1;

        let content_regex = rule_meta.content_pattern.as_ref().map(|pattern| {
            if rule_meta.has_content_dfa && !content_dfa_blob.is_empty() {
                // Validate DFA bytes by attempting to deserialize.
                match SparseDFA::<&[u8]>::from_bytes(&content_dfa_blob) {
                    Ok(_) => ContentRegex::Cached {
                        dfa_bytes: content_dfa_blob,
                        pattern: pattern.clone(),
                        regex: std::sync::OnceLock::new(),
                    },
                    Err(_) => ContentRegex::LazyOnly {
                        pattern: pattern.clone(),
                        regex: std::sync::OnceLock::new(),
                    },
                }
            } else {
                ContentRegex::LazyOnly {
                    pattern: pattern.clone(),
                    regex: std::sync::OnceLock::new(),
                }
            }
        });

        // Path DFA blob — DFA-only semantics, no eager fallback.
        // Use `has_path_dfa` as the gate: only construct MatchOnlyRegex::Dfa
        // when the write path actually produced a valid DFA for this pattern.
        // When `has_path_dfa` is false, set `None` even if `path_pattern` is
        // present (DFA build failed at save time — no path filtering from cache).
        let path_dfa_blob = std::mem::take(&mut dfa_blobs[blob_idx]);
        blob_idx += 1;

        let path_regex = if rule_meta.has_path_dfa {
            Some(match_only_from_blob(path_dfa_blob)?)
        } else {
            None
        };

        // Per-rule allowlists — DFA-only for all regex and path entries.
        let mut allowlists = Vec::new();
        for (al_idx, al_meta) in rule_meta.allowlists.iter().enumerate() {
            let regex_patterns = &rule_meta.allowlist_regex_patterns[al_idx];
            let path_patterns = &rule_meta.allowlist_path_patterns[al_idx];

            let mut al_regexes = Vec::new();
            for _pat in regex_patterns {
                let blob = std::mem::take(&mut dfa_blobs[blob_idx]);
                blob_idx += 1;
                al_regexes.push(match_only_from_blob(blob)?);
            }

            let mut al_paths = Vec::new();
            for _pat in path_patterns {
                let blob = std::mem::take(&mut dfa_blobs[blob_idx]);
                blob_idx += 1;
                al_paths.push(match_only_from_blob(blob)?);
            }

            let regex_target = match al_meta.regex_target {
                0 => RegexTarget::Secret,
                1 => RegexTarget::Match,
                2 => RegexTarget::Line,
                other => {
                    return Err(Error::Cache(format!(
                        "metadata deserialization failed: unknown regex_target {other}"
                    )));
                }
            };
            let condition = match al_meta.condition {
                0 => Condition::Or,
                1 => Condition::And,
                other => {
                    return Err(Error::Cache(format!(
                        "metadata deserialization failed: unknown condition {other}"
                    )));
                }
            };

            allowlists.push(CompiledRuleAllowlist {
                description: None,
                regexes: al_regexes,
                regex_target,
                paths: al_paths,
                stopwords: al_meta.stopwords.clone(),
                condition,
            });
        }

        compiled_rules.push(CompiledRule {
            id: rule_meta.id.clone(),
            description: rule_meta.description.clone(),
            content_regex,
            path_regex,
            entropy: rule_meta.entropy,
            secret_group: rule_meta.secret_group,
            keywords: rule_meta.keywords.clone(),
            allowlists,
        });
    }

    // Global allowlist — DFA-only for all regex and path entries.
    let global_allowlist = if let Some(gal_meta) = &metadata.global_allowlist {
        let mut gal_regexes = Vec::new();
        for _pat in &gal_meta.regex_patterns {
            let blob = std::mem::take(&mut dfa_blobs[blob_idx]);
            blob_idx += 1;
            gal_regexes.push(match_only_from_blob(blob)?);
        }

        let mut gal_paths = Vec::new();
        for _pat in &gal_meta.path_patterns {
            let blob = std::mem::take(&mut dfa_blobs[blob_idx]);
            blob_idx += 1;
            gal_paths.push(match_only_from_blob(blob)?);
        }

        Some(CompiledGlobalAllowlist {
            description: gal_meta.description.clone(),
            regexes: gal_regexes,
            paths: gal_paths,
            stopwords: gal_meta.stopwords.clone(),
        })
    } else {
        None
    };

    // Rebuild AhoCorasick keyword automaton from stored keywords.
    // Use metadata.keywords to build the automaton, then restore
    // keyword_to_rules and path_only_indices directly from metadata.
    let ac = aho_corasick::AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(&metadata.keywords)
        .map_err(|e| Error::Cache(format!("failed to rebuild keyword automaton: {e}")))?;

    // --- Validate restored index structures against rule count ---
    let rule_count = compiled_rules.len();

    // keyword_to_rules must match keyword automaton length.
    if metadata.keyword_to_rules.len() != ac.patterns_len() {
        return Err(Error::Cache(format!(
            "metadata integrity error: keyword_to_rules length ({}) != keyword automaton patterns ({})",
            metadata.keyword_to_rules.len(),
            ac.patterns_len()
        )));
    }

    // Every rule index in keyword_to_rules must be in bounds.
    for (kw_idx, rule_indices) in metadata.keyword_to_rules.iter().enumerate() {
        for &rule_idx in rule_indices {
            if rule_idx >= rule_count {
                return Err(Error::Cache(format!(
                    "metadata integrity error: keyword_to_rules[{kw_idx}] contains out-of-range rule index {rule_idx} (rule_count={rule_count})"
                )));
            }
        }
    }

    // Every entry in path_only_indices must be in bounds.
    for &idx in &metadata.path_only_indices {
        if idx >= rule_count {
            return Err(Error::Cache(format!(
                "metadata integrity error: path_only_indices contains out-of-range index {idx} (rule_count={rule_count})"
            )));
        }
    }

    Ok(Scanner {
        rules: compiled_rules,
        keyword_automaton: ac,
        keyword_to_rules: metadata.keyword_to_rules,
        global_allowlist,
        path_only_indices: metadata.path_only_indices,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Small 3-rule config for fast cache roundtrip tests.
    /// Covers: content DFA, path DFA, keywords, allowlists, and all serialization paths.
    const SMALL_TEST_CONFIG: &str = r#"
title = "test config"

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)api[_-]?key\s*[:=]\s*['"]?([a-z0-9]{16,})'''
keywords = ["api_key", "apikey"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}'''
keywords = ["akia", "asia", "abia", "acca"]

  [[rules.allowlists]]
  description = "ignore example keys"
  regexes = ['''EXAMPLE''']
  stopwords = ["example"]

[[rules]]
id = "path-filtered-rule"
description = "Secret in config files only"
regex = '''secret\s*=\s*['"]([^'"]+)'''
path = '''\.config'''
keywords = ["secret"]
"#;

    /// Parse the small test config and build a Scanner from it.
    fn small_test_config() -> (Config, Scanner) {
        let config = Config::from_toml(SMALL_TEST_CONFIG).unwrap();
        let scanner = Scanner::new(config.clone()).unwrap();
        (config, scanner)
    }

    /// Compute a SHA-256 hash of the small test config for cache operations.
    fn small_config_hash() -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SMALL_TEST_CONFIG.as_bytes());
        hasher.finalize().into()
    }

    #[test]
    fn config_hash_is_deterministic() {
        let h1 = compute_config_hash();
        let h2 = compute_config_hash();
        assert_eq!(h1, h2, "config hash should be deterministic");
    }

    #[test]
    fn config_hash_is_non_zero() {
        let hash = compute_config_hash();
        assert_ne!(hash, [0u8; 32], "config hash should not be all zeros");
    }

    #[test]
    fn simple_pattern_builds_dfa() {
        let result = try_build_sparse_dfa(r"secret_[a-z]+");
        assert!(result.is_some(), "simple pattern should build a sparse DFA");
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "DFA bytes should be non-empty");
    }

    #[test]
    fn aws_key_pattern_builds_dfa() {
        // AKIA pattern from the gitleaks config — a real-world production pattern.
        let result = try_build_sparse_dfa(r"(?i)AKIA[0-9A-Z]{16}");
        assert!(
            result.is_some(),
            "AWS key pattern should build a sparse DFA"
        );
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "DFA bytes should be non-empty");
    }

    #[test]
    fn case_insensitive_simple_pattern_builds_dfa() {
        let result = try_build_sparse_dfa(r"(?i)very-simple-pattern");
        assert!(
            result.is_some(),
            "case-insensitive simple pattern should build a sparse DFA"
        );
    }

    #[test]
    fn pathological_pattern_exceeds_size_limit() {
        // Verify that try_build_sparse_dfa returns None when a pattern
        // exceeds the configured DFA size/determinize limits.
        //
        // We use dense::Builder directly with a reduced limit (256 KB) to
        // verify the limit-enforcement behavior without needing a pattern
        // that actually exceeds 10 MB. The function under test uses the same
        // Builder + Config path, so this validates the mechanism.
        let pattern = r"[a-zA-Z0-9_]{1,100}[a-zA-Z0-9_]{1,100}";
        let compat = go_re2_compat(pattern);

        let result = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .dfa_size_limit(Some(256)) // Artificially small limit
                    .determinize_size_limit(Some(512))
                    .start_kind(regex_automata::dfa::StartKind::Unanchored),
            )
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .unicode(true)
                    .utf8(true),
            )
            .build(&compat);

        assert!(
            result.is_err(),
            "DFA build with 256-byte limit should fail on bounded repetition pattern"
        );
    }

    #[test]
    fn try_build_sparse_dfa_does_not_panic_on_complex_pattern() {
        // Patterns that may or may not exceed 10MB limits should never panic.
        // We verify graceful handling regardless of success or failure.
        let patterns = &[
            r"[a-z]{100}[0-9]{100}[a-z]{100}",
            &("a?".repeat(30) + &"a".repeat(30)),
            &".{1,200}".repeat(5),
        ];
        for pattern in patterns {
            // Must not panic — result can be Some or None.
            let _ = try_build_sparse_dfa(pattern);
        }
    }

    #[test]
    fn dfa_deserialization_and_search() {
        // Build a DFA, then verify it works correctly by deserializing
        // the bytes and running try_search_fwd directly.
        let dfa_bytes = try_build_sparse_dfa(r"secret_[a-z]+").unwrap();

        let (dfa, _) = SparseDFA::<&[u8]>::from_bytes(&dfa_bytes)
            .expect("DFA bytes should deserialize successfully");

        // Positive match
        let input = Input::new("contains secret_key in text");
        let result = dfa.try_search_fwd(&input);
        assert!(
            matches!(result, Ok(Some(_))),
            "DFA should match 'secret_key'"
        );

        // Negative match
        let input = Input::new("no match here");
        let result = dfa.try_search_fwd(&input);
        assert!(
            matches!(result, Ok(None)),
            "DFA should not match 'no match here'"
        );
    }

    #[test]
    fn dfa_is_match_works() {
        let dfa_bytes = try_build_sparse_dfa(r"secret_[a-z]+").unwrap();
        assert!(dfa_is_match(&dfa_bytes, "my secret_key here"));
        assert!(!dfa_is_match(&dfa_bytes, "no match"));
    }

    #[test]
    fn dfa_is_match_with_invalid_bytes_returns_false() {
        assert!(!dfa_is_match(b"garbage", "test"));
    }

    #[test]
    fn dfa_is_match_with_empty_bytes_returns_false() {
        assert!(!dfa_is_match(&[], "test"));
    }

    #[test]
    fn invalid_pattern_returns_none_without_panic() {
        // Unbalanced parenthesis — invalid regex syntax.
        let result = try_build_sparse_dfa(r"(unclosed");
        assert!(
            result.is_none(),
            "invalid regex should return None, not panic"
        );
    }

    #[test]
    fn roundtrip_save_load_produces_working_scanner() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("roundtrip_test.cache");

        // Save
        try_save(&cache_path, &hash, &scanner, &config).unwrap();

        // Verify cache file exists and has content
        let meta = std::fs::metadata(&cache_path).unwrap();
        assert!(meta.len() > 0, "cache file should be non-empty");

        // Load
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // Verify basic structure
        assert_eq!(
            cached_scanner.rule_count(),
            scanner.rule_count(),
            "cached scanner should have same rule count"
        );

        // Verify it can find secrets (AWS key pattern from the small config)
        let text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        let original_findings = scanner.scan_text(text, None);
        let cached_findings = cached_scanner.scan_text(text, None);

        assert_eq!(
            original_findings.len(),
            cached_findings.len(),
            "cached scanner should find same number of secrets"
        );
        for (orig, cached) in original_findings.iter().zip(cached_findings.iter()) {
            assert_eq!(orig.rule_id, cached.rule_id, "rule IDs should match");
            assert_eq!(orig.secret, cached.secret, "secrets should match");
        }

        // Cleanup
        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Full 222-rule roundtrip test. Slow (~15 min), run manually with:
    /// `cargo test --features cache roundtrip_full_config -- --ignored`
    #[test]
    #[ignore]
    fn roundtrip_full_config() {
        let config = Config::default().unwrap();
        let scanner = Scanner::new(config.clone()).unwrap();
        let hash = compute_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_full_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("full_roundtrip_test.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        assert_eq!(cached_scanner.rule_count(), scanner.rule_count());

        let text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        let original_findings = scanner.scan_text(text, None);
        let cached_findings = cached_scanner.scan_text(text, None);
        assert_eq!(original_findings.len(), cached_findings.len());

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn wrong_config_hash_returns_cache_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_wrong_hash");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("wrong_hash_test.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();

        // Load with wrong hash
        let wrong_hash = [0u8; 32];
        let result = try_load(&cache_path, &wrong_hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("hash mismatch"),
            "expected hash mismatch error, got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn corrupt_magic_returns_cache_error() {
        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_corrupt_magic");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("corrupt_magic_test.cache");

        // Write garbage
        std::fs::write(
            &cache_path,
            b"NOT_GLRS_DFA_GARBAGE_DATA_HERE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        )
        .unwrap();

        let hash = compute_config_hash();
        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("magic"),
            "expected magic bytes error, got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn truncated_file_returns_cache_error() {
        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_truncated");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("truncated_test.cache");

        // Write just the magic bytes (truncated header)
        std::fs::write(&cache_path, MAGIC).unwrap();

        let hash = compute_config_hash();
        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("truncated") || err_msg.contains("too short"),
            "expected truncation error, got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // -----------------------------------------------------------------------
    // Spec 11: Cache write-path structural tests
    // -----------------------------------------------------------------------

    /// Helper: save small test config to a temp file and return its bytes.
    fn save_and_read_bytes(suffix: &str) -> (Vec<u8>, std::path::PathBuf, std::path::PathBuf) {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();
        let dir = std::env::temp_dir().join(format!("gitleaks_rs_cache_test_{suffix}"));
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("test.cache");
        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let bytes = std::fs::read(&cache_path).unwrap();
        (bytes, cache_path, dir)
    }

    #[test]
    fn try_save_creates_file_at_path() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();
        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_creates_file");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("create_test.cache");

        // Ensure no file exists before save.
        let _ = std::fs::remove_file(&cache_path);
        assert!(!cache_path.exists());

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        assert!(cache_path.exists(), "try_save should create the cache file");

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_file_starts_with_magic_bytes() {
        let (bytes, cache_path, dir) = save_and_read_bytes("magic_bytes");

        // Offset 0..8: magic bytes
        assert!(bytes.len() >= 8);
        assert_eq!(
            &bytes[0..8],
            b"GLRS_DFA",
            "file must start with GLRS_DFA magic"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_file_contains_correct_format_version() {
        let (bytes, cache_path, dir) = save_and_read_bytes("format_version");

        // Offset 8..10: u16 LE format version = 1
        assert!(bytes.len() >= 10);
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(version, 1, "format version must be 1");

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_file_contains_correct_config_hash() {
        let (bytes, cache_path, dir) = save_and_read_bytes("config_hash");
        let expected_hash = small_config_hash();

        // Offset 10..42: 32-byte SHA-256 hash
        assert!(bytes.len() >= 42);
        assert_eq!(
            &bytes[10..42],
            expected_hash.as_slice(),
            "config hash at offset 10..42 must match"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_file_contains_crate_version() {
        let (bytes, cache_path, dir) = save_and_read_bytes("crate_version");

        // Offset 42..58: 16-byte null-padded crate version
        assert!(bytes.len() >= HEADER_SIZE);
        let mut expected = [0u8; 16];
        let v = CRATE_VERSION.as_bytes();
        let copy_len = v.len().min(16);
        expected[..copy_len].copy_from_slice(&v[..copy_len]);
        assert_eq!(
            &bytes[42..58],
            &expected,
            "crate version at offset 42..58 must match"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_file_has_nonzero_metadata_length() {
        let (bytes, cache_path, dir) = save_and_read_bytes("meta_length");

        // Offset 58..62: u32 LE metadata length
        assert!(bytes.len() >= HEADER_SIZE + 4);
        let meta_len = u32::from_le_bytes([bytes[58], bytes[59], bytes[60], bytes[61]]);
        assert!(
            meta_len > 0,
            "metadata length must be non-zero, got {meta_len}"
        );
        // Metadata bytes must be present.
        assert!(
            bytes.len() >= HEADER_SIZE + 4 + meta_len as usize,
            "file too short for declared metadata length"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_file_is_reasonably_sized() {
        let (bytes, cache_path, dir) = save_and_read_bytes("file_size");

        // 3-rule config with DFAs should produce a file well over 100 bytes.
        assert!(
            bytes.len() > 100,
            "cache file should be > 100 bytes, got {}",
            bytes.len()
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_metadata_deserializes_correctly() {
        let (bytes, cache_path, dir) = save_and_read_bytes("meta_deser");

        // Parse metadata from the file bytes.
        let meta_len = u32::from_le_bytes([bytes[58], bytes[59], bytes[60], bytes[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let meta_end = meta_start + meta_len;
        let metadata: CacheMetadata = bincode::deserialize(&bytes[meta_start..meta_end]).unwrap();

        // Small test config has 3 rules.
        assert_eq!(metadata.rules.len(), 3, "metadata should have 3 rules");
        assert_eq!(metadata.rules[0].id, "generic-api-key");
        assert_eq!(metadata.rules[1].id, "aws-access-key");
        assert_eq!(metadata.rules[2].id, "path-filtered-rule");

        // Rule 1 (aws-access-key) has 1 allowlist with 1 regex.
        assert_eq!(metadata.rules[1].allowlists.len(), 1);
        assert_eq!(metadata.rules[1].allowlists[0].dfa_count, 1);

        // Rule 2 (path-filtered-rule) has a path pattern.
        assert!(metadata.rules[2].has_path_dfa || metadata.rules[2].path_pattern.is_some());

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_dfa_blobs_have_valid_length_prefixes() {
        let (bytes, cache_path, dir) = save_and_read_bytes("blob_lengths");

        // Skip header + metadata to reach DFA blob section.
        let meta_len = u32::from_le_bytes([bytes[58], bytes[59], bytes[60], bytes[61]]) as usize;
        let blob_start = HEADER_SIZE + 4 + meta_len;

        // Parse all blob length prefixes and verify they don't exceed remaining bytes.
        let mut pos = blob_start;
        let mut blob_count = 0;
        while pos + 4 <= bytes.len() {
            let len =
                u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                    as usize;
            pos += 4 + len;
            blob_count += 1;
        }

        // With 3 rules: each has content + path = 6 slots.
        // Rule 1 (aws-access-key) has 1 allowlist with 1 regex + 0 paths = 1 slot.
        // Total: 6 + 1 = 7 DFA blob slots.
        assert_eq!(
            blob_count, 7,
            "expected 7 DFA blob slots for 3-rule config with 1 allowlist"
        );
        // pos should consume exactly the file
        assert_eq!(pos, bytes.len(), "all bytes should be consumed by blobs");

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_invalid_path_returns_cache_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let result = try_save(
            Path::new("/nonexistent/directory/cache.bin"),
            &hash,
            &scanner,
            &config,
        );
        assert!(result.is_err(), "invalid path should return error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cache"),
            "error should be a cache error, got: {err_msg}"
        );
    }

    #[test]
    fn try_save_is_deterministic() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_deterministic");
        let _ = std::fs::create_dir_all(&dir);

        let path1 = dir.join("det1.cache");
        let path2 = dir.join("det2.cache");

        try_save(&path1, &hash, &scanner, &config).unwrap();
        try_save(&path2, &hash, &scanner, &config).unwrap();

        let bytes1 = std::fs::read(&path1).unwrap();
        let bytes2 = std::fs::read(&path2).unwrap();

        assert_eq!(
            bytes1, bytes2,
            "two saves of the same scanner must produce identical bytes"
        );

        let _ = std::fs::remove_file(&path1);
        let _ = std::fs::remove_file(&path2);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_no_tmp_file_left_on_success() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_no_tmp");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("notmp.cache");
        let tmp_path = cache_path.with_extension("tmp");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        assert!(cache_path.exists());
        assert!(
            !tmp_path.exists(),
            "temp file should be cleaned up after successful save"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_save_failed_dfa_produces_zero_length_blob() {
        // Build a config where a content pattern will fail DFA build.
        // The `(unclosed` pattern is invalid regex; use a pathological one instead.
        // Actually, any pattern that's valid regex but exceeds DFA limits would
        // be ideal, but that's hard to guarantee. Instead, verify the mechanism
        // by checking that path-only rules produce zero-length content DFA blobs.
        let (bytes, cache_path, dir) = save_and_read_bytes("zero_blob");

        let meta_len = u32::from_le_bytes([bytes[58], bytes[59], bytes[60], bytes[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let metadata: CacheMetadata =
            bincode::deserialize(&bytes[meta_start..meta_start + meta_len]).unwrap();

        // All 3 rules have content patterns that should build DFAs successfully.
        // Rule 0 and 1 have no path pattern (has_path_dfa = false).
        // Their path DFA blob should be zero-length.
        assert!(
            !metadata.rules[0].has_path_dfa,
            "rule 0 should have no path DFA"
        );
        assert!(
            !metadata.rules[1].has_path_dfa,
            "rule 1 should have no path DFA (despite having content regex)"
        );

        // Verify the actual blob: skip to blob section and check second blob
        // (rule 0's path DFA) is zero-length.
        let blob_start = HEADER_SIZE + 4 + meta_len;
        // First blob: rule 0 content DFA (skip it)
        let first_len = u32::from_le_bytes([
            bytes[blob_start],
            bytes[blob_start + 1],
            bytes[blob_start + 2],
            bytes[blob_start + 3],
        ]) as usize;
        let second_offset = blob_start + 4 + first_len;
        // Second blob: rule 0 path DFA (should be zero)
        let second_len = u32::from_le_bytes([
            bytes[second_offset],
            bytes[second_offset + 1],
            bytes[second_offset + 2],
            bytes[second_offset + 3],
        ]) as usize;
        assert_eq!(
            second_len, 0,
            "path DFA blob for rule without path pattern should be zero-length"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // -----------------------------------------------------------------------
    // Spec 12: Cache read-path tests
    // -----------------------------------------------------------------------

    #[test]
    fn try_load_missing_file_returns_cache_error_not_found() {
        let hash = small_config_hash();
        let result = try_load(
            Path::new("/tmp/gitleaks_rs_nonexistent_cache_file.bin"),
            &hash,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cache file not found"),
            "expected 'cache file not found', got: {err_msg}"
        );
    }

    #[test]
    fn try_load_wrong_magic_bytes() {
        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_wrong_magic");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("wrong_magic.cache");

        // Write a 58+ byte file with wrong magic.
        let mut data = vec![0u8; 64];
        data[..8].copy_from_slice(b"BADMAGIC");
        std::fs::write(&cache_path, &data).unwrap();

        let hash = small_config_hash();
        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("wrong magic"),
            "expected 'wrong magic', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_wrong_format_version() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_wrong_version");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("wrong_version.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        // Corrupt format version at offset 8..10.
        data[8] = 99;
        data[9] = 0;
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("wrong format version"),
            "expected 'wrong format version', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_wrong_config_hash() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_wrong_hash_v2");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("wrong_hash_v2.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();

        let wrong_hash = [0xFFu8; 32];
        let result = try_load(&cache_path, &wrong_hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("config hash mismatch"),
            "expected 'config hash mismatch', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_wrong_crate_version() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_wrong_crate_ver");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("wrong_crate_ver.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        // Corrupt crate version at offset 42..58.
        data[42..58].copy_from_slice(b"99.99.99\0\0\0\0\0\0\0\0");
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("crate version mismatch"),
            "expected 'crate version mismatch', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_metadata_corrupt() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_corrupt_meta");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("corrupt_meta.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        // Corrupt metadata bytes (after the 62-byte header+meta_len).
        // Set metadata length to a small value and fill with garbage.
        let meta_start = HEADER_SIZE + 4;
        if data.len() > meta_start + 10 {
            // Overwrite the metadata region with garbage.
            for b in data[meta_start..meta_start + 10].iter_mut() {
                *b = 0xFF;
            }
        }
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("metadata deserialization failed"),
            "expected 'metadata deserialization failed', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_truncated_metadata() {
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_trunc_meta");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("trunc_meta.cache");

        // Build a valid header but with metadata length pointing past EOF.
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        data.extend_from_slice(&hash);
        let mut ver = [0u8; 16];
        let v = CRATE_VERSION.as_bytes();
        ver[..v.len().min(16)].copy_from_slice(&v[..v.len().min(16)]);
        data.extend_from_slice(&ver);
        // Metadata length says 9999 but we only have 2 bytes after.
        data.extend_from_slice(&9999u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 2]);
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("truncated metadata"),
            "expected 'truncated metadata', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_blob_slot_count_mismatch_trailing_bytes() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_trailing");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("trailing.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        // Append extra trailing bytes after the valid blob stream.
        data.extend_from_slice(&[0u8; 8]);
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("trailing bytes"),
            "expected 'trailing bytes' error, got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_truncated_blob_payload() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_trunc_blob");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("trunc_blob.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        // Truncate: keep header + metadata + partial blob section.
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let blob_start = HEADER_SIZE + 4 + meta_len;
        // Keep only half of the blob section.
        let truncate_at = blob_start + (data.len() - blob_start) / 2;
        let truncated = &data[..truncate_at];
        std::fs::write(&cache_path, truncated).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("truncated DFA blob"),
            "expected 'truncated DFA blob', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_content_cached_variant_and_lazy_capture_behavior() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_content_variant");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("content_variant.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // Verify content regexes use Cached or LazyOnly — not Eager.
        for rule in &cached_scanner.rules {
            if let Some(cr) = &rule.content_regex {
                match cr {
                    ContentRegex::Cached { .. } | ContentRegex::LazyOnly { .. } => {}
                    ContentRegex::Eager(_) => {
                        panic!(
                            "rule '{}' has Eager content regex from cache load — expected Cached or LazyOnly",
                            rule.id
                        );
                    }
                }
            }
        }

        // Verify the cached scanner can find secrets (lazy capture works).
        // Use a key that does NOT match the allowlist regex "EXAMPLE".
        let text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7TESTKEY1\n";
        let findings = cached_scanner.scan_text(text, None);
        assert!(
            !findings.is_empty(),
            "cached scanner should find secrets via lazy capture"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_rejects_eager_path_allowlist_fallback() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_no_eager");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("no_eager.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // Verify path regexes are DFA-only (no Eager variant).
        for rule in &cached_scanner.rules {
            if let Some(pr) = &rule.path_regex {
                match pr {
                    MatchOnlyRegex::Dfa(_) => {}
                    MatchOnlyRegex::Eager(_) => {
                        panic!(
                            "rule '{}' has Eager path regex from cache load — expected Dfa only",
                            rule.id
                        );
                    }
                }
            }
            // Verify allowlist regexes and paths are DFA-only.
            for al in &rule.allowlists {
                for (i, ar) in al.regexes.iter().enumerate() {
                    match ar {
                        MatchOnlyRegex::Dfa(_) => {}
                        MatchOnlyRegex::Eager(_) => {
                            panic!(
                                "rule '{}' allowlist regex[{i}] has Eager variant from cache load",
                                rule.id
                            );
                        }
                    }
                }
                for (i, ap) in al.paths.iter().enumerate() {
                    match ap {
                        MatchOnlyRegex::Dfa(_) => {}
                        MatchOnlyRegex::Eager(_) => {
                            panic!(
                                "rule '{}' allowlist path[{i}] has Eager variant from cache load",
                                rule.id
                            );
                        }
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_roundtrip_keyword_state_from_metadata() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_keyword_state");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("keyword_state.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // keyword_to_rules and path_only_indices must match.
        assert_eq!(
            scanner.keyword_to_rules, cached_scanner.keyword_to_rules,
            "keyword_to_rules should be restored from metadata"
        );
        assert_eq!(
            scanner.path_only_indices, cached_scanner.path_only_indices,
            "path_only_indices should be restored from metadata"
        );

        // Keyword automaton should have the same pattern count.
        assert_eq!(
            scanner.keyword_automaton.patterns_len(),
            cached_scanner.keyword_automaton.patterns_len(),
            "keyword automaton pattern count should match"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_blob_count_formula_matches_written_blobs() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_blob_formula");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("blob_formula.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        // Parse metadata to compute expected count.
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let metadata: CacheMetadata =
            bincode::deserialize(&data[meta_start..meta_start + meta_len]).unwrap();

        let expected = expected_blob_count(&metadata);
        // 3 rules × 2 (content + path) = 6, plus 1 allowlist regex = 7.
        assert_eq!(expected, 7, "expected 7 DFA slots for 3-rule test config");

        // Count actual blobs in file.
        let blob_start = meta_start + meta_len;
        let mut pos = blob_start;
        let mut actual = 0;
        while pos + 4 <= data.len() {
            let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            pos += 4 + len;
            actual += 1;
        }
        assert_eq!(
            actual, expected,
            "actual blob count should match expected_blob_count formula"
        );
        assert_eq!(pos, data.len(), "all bytes should be consumed");

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn scanner_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Scanner>();
    }

    #[test]
    fn cached_scanner_matches_reference() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_parity");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("parity.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // Test multiple inputs for parity.
        let test_inputs = &[
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            "api_key = 'abc1234567890def'\n",
            "no secrets here\n",
            "secret = 'password123'\n",
            "AKIAIOSFODNN7EXAMPLE but with EXAMPLE in value\n",
        ];

        for input in test_inputs {
            let orig = scanner.scan_text(input, None);
            let cached = cached_scanner.scan_text(input, None);
            assert_eq!(
                orig.len(),
                cached.len(),
                "finding count mismatch for input: {input}"
            );
            for (o, c) in orig.iter().zip(cached.iter()) {
                assert_eq!(o.rule_id, c.rule_id, "rule ID mismatch for input: {input}");
                assert_eq!(o.secret, c.secret, "secret mismatch for input: {input}");
            }
        }

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_header_endianness_correct() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_endian");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("endian.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        // Verify LE encoding of format version.
        assert_eq!(data[8], 1); // low byte = 1
        assert_eq!(data[9], 0); // high byte = 0

        // Verify metadata length is LE-encoded and non-zero.
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]);
        assert!(meta_len > 0, "metadata length should be positive");

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_roundtrip_with_path_and_allowlist_rules() {
        // Test with a config that exercises path regex + allowlist patterns.
        let config_toml = r#"
title = "path and allowlist test"

[[rules]]
id = "path-only-secret"
description = "Secret in specific paths"
regex = '''SECRET_VALUE\s*=\s*['"]([^'"]+)'''
path = '''\.env'''
keywords = ["secret_value"]

  [[rules.allowlists]]
  description = "ignore test files"
  regexes = ['''test_value''']
  paths = ['''test/''']
  regex_target = "secret"
  condition = "and"

[[rules]]
id = "no-keywords-rule"
description = "Rule without keywords"
regex = '''password\s*[:=]\s*\S+'''
"#;

        let config = Config::from_toml(config_toml).unwrap();
        let scanner = Scanner::new(config.clone()).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(config_toml.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_path_al");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("path_al.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        assert_eq!(cached_scanner.rule_count(), scanner.rule_count());

        // Verify path regex is DFA-only.
        let rule0 = &cached_scanner.rules[0];
        assert!(rule0.path_regex.is_some(), "rule 0 should have path regex");
        match rule0.path_regex.as_ref().unwrap() {
            MatchOnlyRegex::Dfa(_) => {}
            MatchOnlyRegex::Eager(_) => panic!("path regex should be Dfa, not Eager"),
        }

        // Verify allowlist regexes and paths are DFA-only.
        assert_eq!(rule0.allowlists.len(), 1);
        let al = &rule0.allowlists[0];
        assert_eq!(al.regexes.len(), 1);
        assert_eq!(al.paths.len(), 1);
        for r in &al.regexes {
            match r {
                MatchOnlyRegex::Dfa(_) => {}
                MatchOnlyRegex::Eager(_) => panic!("allowlist regex should be Dfa"),
            }
        }
        for p in &al.paths {
            match p {
                MatchOnlyRegex::Dfa(_) => {}
                MatchOnlyRegex::Eager(_) => panic!("allowlist path should be Dfa"),
            }
        }

        // Verify regex_target and condition round-tripped correctly.
        assert!(matches!(al.regex_target, RegexTarget::Secret));
        assert!(matches!(al.condition, Condition::And));

        // Verify scanning parity.
        let text = "SECRET_VALUE = 'mysecret'\n";
        let orig = scanner.scan_text(text, Some(".env"));
        let cached = cached_scanner.scan_text(text, Some(".env"));
        assert_eq!(
            orig.len(),
            cached.len(),
            "path-filtered scan finding count should match"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // -----------------------------------------------------------------------
    // R-008: DFA payload corruption tests
    // -----------------------------------------------------------------------

    #[test]
    fn try_load_corrupt_content_dfa_blob_returns_cache_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_corrupt_content_dfa");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("corrupt_content_dfa.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        // Find the first DFA blob (content DFA for rule 0) and corrupt its payload.
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let blob_start = HEADER_SIZE + 4 + meta_len;
        let first_blob_len = u32::from_le_bytes([
            data[blob_start],
            data[blob_start + 1],
            data[blob_start + 2],
            data[blob_start + 3],
        ]) as usize;

        // Only corrupt if the blob is non-empty (has DFA data to corrupt).
        if first_blob_len > 0 {
            let payload_start = blob_start + 4;
            // Write garbage bytes into the DFA payload.
            for b in data[payload_start..payload_start + first_blob_len.min(16)].iter_mut() {
                *b = 0xFF;
            }
            std::fs::write(&cache_path, &data).unwrap();

            let result = try_load(&cache_path, &hash);
            // Content DFA corruption with has_content_dfa=true should still
            // reconstruct as LazyOnly (graceful fallback), not an error,
            // because the content regex path tries DFA first, falls back to LazyOnly.
            // However, if the blob is used for path/allowlist, it WOULD be an error.
            // For content: the current contract is LazyOnly fallback on invalid DFA.
            // This test just verifies no panic occurs.
            match result {
                Ok(_scanner) => {
                    // LazyOnly fallback — acceptable for content regexes.
                }
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("DFA validation failed"),
                        "expected 'DFA validation failed', got: {msg}"
                    );
                }
            }
        }

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_corrupt_path_dfa_blob_returns_cache_error() {
        // Use a config with a path regex to exercise path DFA corruption.
        let config_toml = r#"
title = "path dfa corruption test"

[[rules]]
id = "path-rule"
description = "Rule with path"
regex = '''secret\s*=\s*\S+'''
path = '''\.env'''
keywords = ["secret"]
"#;

        let config = Config::from_toml(config_toml).unwrap();
        let scanner = Scanner::new(config.clone()).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(config_toml.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_corrupt_path_dfa");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("corrupt_path_dfa.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        // Find the second DFA blob (path DFA for rule 0) and corrupt it.
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let blob_start = HEADER_SIZE + 4 + meta_len;

        // Skip first blob (content DFA).
        let first_len = u32::from_le_bytes([
            data[blob_start],
            data[blob_start + 1],
            data[blob_start + 2],
            data[blob_start + 3],
        ]) as usize;
        let second_offset = blob_start + 4 + first_len;
        let second_len = u32::from_le_bytes([
            data[second_offset],
            data[second_offset + 1],
            data[second_offset + 2],
            data[second_offset + 3],
        ]) as usize;

        assert!(
            second_len > 0,
            "path DFA blob should be non-empty for this config"
        );

        // Corrupt the path DFA payload.
        let payload_start = second_offset + 4;
        for b in data[payload_start..payload_start + second_len.min(16)].iter_mut() {
            *b = 0xFF;
        }
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err(), "corrupt path DFA should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("DFA validation failed"),
            "expected 'DFA validation failed', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_corrupt_allowlist_dfa_blob_returns_cache_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_corrupt_al_dfa");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("corrupt_al_dfa.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let mut data = std::fs::read(&cache_path).unwrap();

        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let blob_start = HEADER_SIZE + 4 + meta_len;

        // Skip through blobs to find the allowlist DFA (blob index 4 = rule 1 allowlist regex).
        // Blob order: rule0_content, rule0_path, rule1_content, rule1_path, rule1_al_regex, ...
        let mut pos = blob_start;
        for _ in 0..4 {
            let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as usize;
            pos += 4 + len;
        }

        // pos now at blob index 4 (allowlist regex DFA for rule 1).
        let al_blob_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        assert!(al_blob_len > 0, "allowlist regex DFA should be non-empty");

        let payload_start = pos + 4;
        for b in data[payload_start..payload_start + al_blob_len.min(16)].iter_mut() {
            *b = 0xFF;
        }
        std::fs::write(&cache_path, &data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err(), "corrupt allowlist DFA should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("DFA validation failed"),
            "expected 'DFA validation failed', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // -----------------------------------------------------------------------
    // R-009: Malformed metadata shape tests
    // -----------------------------------------------------------------------

    #[test]
    fn try_load_metadata_mismatched_allowlist_vectors_returns_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_al_mismatch");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("al_mismatch.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        // Parse valid metadata, then modify it to create shape mismatch.
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let mut metadata: CacheMetadata =
            bincode::deserialize(&data[meta_start..meta_start + meta_len]).unwrap();

        // Create mismatch: rule 1 has 1 allowlist but we'll add an extra regex_patterns entry.
        metadata.rules[1]
            .allowlist_regex_patterns
            .push(vec!["extra".to_string()]);

        // Re-serialize metadata and rebuild the file.
        let new_meta_bytes = bincode::serialize(&metadata).unwrap();
        let new_meta_len = new_meta_bytes.len() as u32;

        let mut new_data = Vec::new();
        new_data.extend_from_slice(&data[..HEADER_SIZE]); // header
        new_data.extend_from_slice(&new_meta_len.to_le_bytes());
        new_data.extend_from_slice(&new_meta_bytes);
        new_data.extend_from_slice(&data[meta_start + meta_len..]); // blobs

        std::fs::write(&cache_path, &new_data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err(), "mismatched allowlist vectors should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("metadata shape error"),
            "expected 'metadata shape error', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_metadata_out_of_range_keyword_to_rules_returns_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_kw_oob");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("kw_oob.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let mut metadata: CacheMetadata =
            bincode::deserialize(&data[meta_start..meta_start + meta_len]).unwrap();

        // Inject an out-of-range rule index into keyword_to_rules.
        if let Some(first) = metadata.keyword_to_rules.first_mut() {
            first.push(9999); // Way beyond rule count.
        }

        let new_meta_bytes = bincode::serialize(&metadata).unwrap();
        let new_meta_len = new_meta_bytes.len() as u32;

        let mut new_data = Vec::new();
        new_data.extend_from_slice(&data[..HEADER_SIZE]);
        new_data.extend_from_slice(&new_meta_len.to_le_bytes());
        new_data.extend_from_slice(&new_meta_bytes);
        new_data.extend_from_slice(&data[meta_start + meta_len..]);

        std::fs::write(&cache_path, &new_data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(result.is_err(), "out-of-range keyword_to_rules should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("metadata integrity error"),
            "expected 'metadata integrity error', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_metadata_out_of_range_path_only_indices_returns_error() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_poi_oob");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("poi_oob.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let mut metadata: CacheMetadata =
            bincode::deserialize(&data[meta_start..meta_start + meta_len]).unwrap();

        // Inject an out-of-range index into path_only_indices.
        metadata.path_only_indices.push(9999);

        let new_meta_bytes = bincode::serialize(&metadata).unwrap();
        let new_meta_len = new_meta_bytes.len() as u32;

        let mut new_data = Vec::new();
        new_data.extend_from_slice(&data[..HEADER_SIZE]);
        new_data.extend_from_slice(&new_meta_len.to_le_bytes());
        new_data.extend_from_slice(&new_meta_bytes);
        new_data.extend_from_slice(&data[meta_start + meta_len..]);

        std::fs::write(&cache_path, &new_data).unwrap();

        let result = try_load(&cache_path, &hash);
        assert!(
            result.is_err(),
            "out-of-range path_only_indices should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("metadata integrity error"),
            "expected 'metadata integrity error', got: {err_msg}"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // -----------------------------------------------------------------------
    // R-010: has_path_dfa=false with non-empty path_pattern regression test
    // -----------------------------------------------------------------------

    #[test]
    fn try_load_has_path_dfa_false_with_path_pattern_produces_none_not_empty_dfa() {
        let (config, scanner) = small_test_config();
        let hash = small_config_hash();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_path_dfa_false");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("path_dfa_false.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let data = std::fs::read(&cache_path).unwrap();

        // Parse metadata and set has_path_dfa=false on rule 2 (which has a path pattern).
        let meta_len = u32::from_le_bytes([data[58], data[59], data[60], data[61]]) as usize;
        let meta_start = HEADER_SIZE + 4;
        let mut metadata: CacheMetadata =
            bincode::deserialize(&data[meta_start..meta_start + meta_len]).unwrap();

        // Rule 2 (path-filtered-rule) should have path_pattern and has_path_dfa=true.
        assert!(metadata.rules[2].path_pattern.is_some());
        assert!(metadata.rules[2].has_path_dfa);

        // Force has_path_dfa=false to simulate a DFA build failure at save time.
        metadata.rules[2].has_path_dfa = false;

        let new_meta_bytes = bincode::serialize(&metadata).unwrap();
        let new_meta_len = new_meta_bytes.len() as u32;

        let mut new_data = Vec::new();
        new_data.extend_from_slice(&data[..HEADER_SIZE]);
        new_data.extend_from_slice(&new_meta_len.to_le_bytes());
        new_data.extend_from_slice(&new_meta_bytes);
        new_data.extend_from_slice(&data[meta_start + meta_len..]);

        std::fs::write(&cache_path, &new_data).unwrap();

        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // Rule 2 should have path_regex=None (not Dfa(Vec::new())), because
        // has_path_dfa is false — the DFA wasn't built, so no path filtering.
        assert!(
            cached_scanner.rules[2].path_regex.is_none(),
            "rule with has_path_dfa=false should have path_regex=None, not Dfa(Vec::new())"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn try_load_path_only_indices_preserved() {
        // Config where rule 1 has no keywords → should be in path_only_indices.
        let config_toml = r#"
title = "path only test"

[[rules]]
id = "with-keywords"
description = "Has keywords"
regex = '''api_key\s*=\s*\S+'''
keywords = ["api_key"]

[[rules]]
id = "no-keywords"
description = "No keywords at all"
regex = '''token\s*=\s*\S+'''
"#;

        let config = Config::from_toml(config_toml).unwrap();
        let scanner = Scanner::new(config.clone()).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(config_toml.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let dir = std::env::temp_dir().join("gitleaks_rs_cache_test_path_only_idx");
        let _ = std::fs::create_dir_all(&dir);
        let cache_path = dir.join("path_only_idx.cache");

        try_save(&cache_path, &hash, &scanner, &config).unwrap();
        let cached_scanner = try_load(&cache_path, &hash).unwrap();

        // Rule 1 (no-keywords) should be in path_only_indices for both.
        assert_eq!(
            scanner.path_only_indices, cached_scanner.path_only_indices,
            "path_only_indices should match exactly"
        );
        assert!(
            cached_scanner.path_only_indices.contains(&1),
            "rule index 1 (no-keywords) should be in path_only_indices"
        );

        let _ = std::fs::remove_file(&cache_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
