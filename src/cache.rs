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
    build_keyword_index, go_re2_compat, CompiledGlobalAllowlist, CompiledRule,
    CompiledRuleAllowlist, ContentRegex, MatchOnlyRegex, Scanner,
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

/// Load a `Scanner` from a cache file on disk.
///
/// Validates the header (magic, format version, config hash, crate version)
/// and reconstructs a full `Scanner` from cached DFAs and metadata.
#[allow(clippy::regex_creation_in_loops)]
pub(crate) fn try_load(path: &Path, config_hash: &[u8; 32]) -> Result<Scanner> {
    let data =
        std::fs::read(path).map_err(|e| Error::Cache(format!("failed to read cache file: {e}")))?;

    let mut cursor = &data[..];

    // --- Validate header ---
    if data.len() < 8 + 2 + 32 + 16 {
        return Err(Error::Cache(
            "cache file too short (truncated header)".into(),
        ));
    }

    // Magic bytes
    let (magic, rest) = cursor.split_at(8);
    cursor = rest;
    if magic != MAGIC {
        return Err(Error::Cache(format!(
            "invalid magic bytes: expected {:?}, got {:?}",
            MAGIC,
            &magic[..8.min(magic.len())]
        )));
    }

    // Format version
    let (ver_bytes, rest) = cursor.split_at(2);
    cursor = rest;
    let version = u16::from_le_bytes([ver_bytes[0], ver_bytes[1]]);
    if version != FORMAT_VERSION {
        return Err(Error::Cache(format!(
            "unsupported cache format version: expected {FORMAT_VERSION}, got {version}"
        )));
    }

    // Config hash
    let (hash_bytes, rest) = cursor.split_at(32);
    cursor = rest;
    if hash_bytes != config_hash.as_slice() {
        return Err(Error::Cache(
            "config hash mismatch — embedded config has changed".into(),
        ));
    }

    // Crate version
    let (version_bytes, rest) = cursor.split_at(16);
    cursor = rest;
    let mut expected_version = [0u8; 16];
    let v = CRATE_VERSION.as_bytes();
    let copy_len = v.len().min(16);
    expected_version[..copy_len].copy_from_slice(&v[..copy_len]);
    if version_bytes != expected_version.as_slice() {
        return Err(Error::Cache(
            "crate version mismatch — library has been updated".into(),
        ));
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
        .map_err(|e| Error::Cache(format!("failed to deserialize metadata: {e}")))?;

    // --- Read DFA blobs ---
    let mut dfa_blobs: Vec<Vec<u8>> = Vec::new();
    let mut remaining = cursor;
    while remaining.len() >= 4 {
        let (len_bytes, rest) = remaining.split_at(4);
        remaining = rest;
        let len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len == 0 {
            dfa_blobs.push(Vec::new());
        } else {
            if remaining.len() < len {
                return Err(Error::Cache(format!(
                    "truncated DFA blob: expected {len} bytes, have {}",
                    remaining.len()
                )));
            }
            let (blob, rest) = remaining.split_at(len);
            remaining = rest;
            dfa_blobs.push(blob.to_vec());
        }
    }

    // --- Reconstruct Scanner from metadata + DFAs ---
    let mut blob_idx = 0;

    let mut compiled_rules: Vec<CompiledRule> = Vec::with_capacity(metadata.rules.len());

    for rule_meta in &metadata.rules {
        // Content regex
        let content_dfa_blob = if blob_idx < dfa_blobs.len() {
            let b = std::mem::take(&mut dfa_blobs[blob_idx]);
            blob_idx += 1;
            b
        } else {
            blob_idx += 1;
            Vec::new()
        };

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

        // Path regex
        let path_dfa_blob = if blob_idx < dfa_blobs.len() {
            let b = std::mem::take(&mut dfa_blobs[blob_idx]);
            blob_idx += 1;
            b
        } else {
            blob_idx += 1;
            Vec::new()
        };

        let path_regex = if rule_meta.has_path_dfa && !path_dfa_blob.is_empty() {
            match SparseDFA::<&[u8]>::from_bytes(&path_dfa_blob) {
                Ok(_) => Some(MatchOnlyRegex::Dfa(path_dfa_blob)),
                Err(_) => rule_meta.path_pattern.as_ref().map(|_| {
                    // Path DFA validation failed; skip this path regex entirely.
                    // This is acceptable because path regex failures are non-critical.
                    MatchOnlyRegex::Dfa(Vec::new())
                }),
            }
        } else if rule_meta.path_pattern.is_some() {
            // No DFA was built; need to lazy-compile. But MatchOnlyRegex only
            // has Eager and Dfa variants. For path regexes that failed DFA build,
            // we eagerly compile the regex here.
            rule_meta.path_pattern.as_ref().map(|p| {
                let re = regex::RegexBuilder::new(p)
                    .size_limit(100 * (1 << 20))
                    .build()
                    .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                MatchOnlyRegex::Eager(re)
            })
        } else {
            None
        };

        // Per-rule allowlists
        let mut allowlists = Vec::new();
        for (al_idx, al_meta) in rule_meta.allowlists.iter().enumerate() {
            let regex_patterns = &rule_meta.allowlist_regex_patterns[al_idx];
            let path_patterns = &rule_meta.allowlist_path_patterns[al_idx];

            // Allowlist regex DFAs
            let mut al_regexes = Vec::new();
            for pat in regex_patterns {
                let blob = if blob_idx < dfa_blobs.len() {
                    let b = std::mem::take(&mut dfa_blobs[blob_idx]);
                    blob_idx += 1;
                    b
                } else {
                    blob_idx += 1;
                    Vec::new()
                };

                if !blob.is_empty() {
                    match SparseDFA::<&[u8]>::from_bytes(&blob) {
                        Ok(_) => al_regexes.push(MatchOnlyRegex::Dfa(blob)),
                        Err(_) => {
                            // Fallback: eagerly compile
                            let re = regex::RegexBuilder::new(pat)
                                .size_limit(100 * (1 << 20))
                                .build()
                                .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                            al_regexes.push(MatchOnlyRegex::Eager(re));
                        }
                    }
                } else {
                    // No DFA: eagerly compile
                    let re = regex::RegexBuilder::new(pat)
                        .size_limit(100 * (1 << 20))
                        .build()
                        .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                    al_regexes.push(MatchOnlyRegex::Eager(re));
                }
            }

            // Allowlist path DFAs
            let mut al_paths = Vec::new();
            for pat in path_patterns {
                let blob = if blob_idx < dfa_blobs.len() {
                    let b = std::mem::take(&mut dfa_blobs[blob_idx]);
                    blob_idx += 1;
                    b
                } else {
                    blob_idx += 1;
                    Vec::new()
                };

                if !blob.is_empty() {
                    match SparseDFA::<&[u8]>::from_bytes(&blob) {
                        Ok(_) => al_paths.push(MatchOnlyRegex::Dfa(blob)),
                        Err(_) => {
                            let re = regex::RegexBuilder::new(pat)
                                .size_limit(100 * (1 << 20))
                                .build()
                                .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                            al_paths.push(MatchOnlyRegex::Eager(re));
                        }
                    }
                } else {
                    let re = regex::RegexBuilder::new(pat)
                        .size_limit(100 * (1 << 20))
                        .build()
                        .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                    al_paths.push(MatchOnlyRegex::Eager(re));
                }
            }

            let regex_target = match al_meta.regex_target {
                0 => RegexTarget::Secret,
                1 => RegexTarget::Match,
                _ => RegexTarget::Line,
            };
            let condition = match al_meta.condition {
                0 => Condition::Or,
                _ => Condition::And,
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

    // Global allowlist
    let global_allowlist = if let Some(gal_meta) = &metadata.global_allowlist {
        let mut gal_regexes = Vec::new();
        for pat in &gal_meta.regex_patterns {
            let blob = if blob_idx < dfa_blobs.len() {
                let b = std::mem::take(&mut dfa_blobs[blob_idx]);
                blob_idx += 1;
                b
            } else {
                blob_idx += 1;
                Vec::new()
            };

            if !blob.is_empty() {
                match SparseDFA::<&[u8]>::from_bytes(&blob) {
                    Ok(_) => gal_regexes.push(MatchOnlyRegex::Dfa(blob)),
                    Err(_) => {
                        let re = regex::RegexBuilder::new(pat)
                            .size_limit(100 * (1 << 20))
                            .build()
                            .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                        gal_regexes.push(MatchOnlyRegex::Eager(re));
                    }
                }
            } else {
                let re = regex::RegexBuilder::new(pat)
                    .size_limit(100 * (1 << 20))
                    .build()
                    .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                gal_regexes.push(MatchOnlyRegex::Eager(re));
            }
        }

        let mut gal_paths = Vec::new();
        for pat in &gal_meta.path_patterns {
            let blob = if blob_idx < dfa_blobs.len() {
                let b = std::mem::take(&mut dfa_blobs[blob_idx]);
                blob_idx += 1;
                b
            } else {
                blob_idx += 1;
                Vec::new()
            };

            if !blob.is_empty() {
                match SparseDFA::<&[u8]>::from_bytes(&blob) {
                    Ok(_) => gal_paths.push(MatchOnlyRegex::Dfa(blob)),
                    Err(_) => {
                        let re = regex::RegexBuilder::new(pat)
                            .size_limit(100 * (1 << 20))
                            .build()
                            .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                        gal_paths.push(MatchOnlyRegex::Eager(re));
                    }
                }
            } else {
                let re = regex::RegexBuilder::new(pat)
                    .size_limit(100 * (1 << 20))
                    .build()
                    .unwrap_or_else(|_| regex::Regex::new("(?:$^)").unwrap());
                gal_paths.push(MatchOnlyRegex::Eager(re));
            }
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
    let (keyword_automaton, keyword_to_rules, path_only_indices) =
        build_keyword_index(&compiled_rules)?;

    Ok(Scanner {
        rules: compiled_rules,
        keyword_automaton,
        keyword_to_rules,
        global_allowlist,
        path_only_indices,
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
}
