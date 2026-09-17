use std::sync::LazyLock;

use regex::Regex;

use super::credential::normalize_key;
use super::{Detection, Detector, LeafContext};

/// Candidate tokens. `/` is excluded so whole file paths are not treated as a
/// single token; high-entropy path segments are still found individually.
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+_=-]{10,}").unwrap());

/// Key segments that mark a structured field as likely holding a secret.
const SENSITIVE_SEGMENTS: &[&str] = &[
    "key", "secret", "token", "pass", "password", "passwd", "pwd",
];

/// Full key names that contain a sensitive segment but are structural, not
/// credentials. Matched exactly or as a suffix (`user_foreign_key`).
const STRUCTURAL_KEYS: &[&str] = &[
    "foreign_key",
    "primary_key",
    "sort_key",
    "partition_key",
    "lookup_key",
    "cache_key",
    "public_key",
    "idempotency_key",
];

/// Flags long alphanumeric tokens whose Shannon entropy exceeds a threshold.
///
/// The default threshold of 4.5 bits per byte is high enough to skip ordinary
/// words and identifiers while catching typical API keys and tokens, which
/// usually score above 5.
///
/// When the value sits under a sensitive key (`api_key`, `client_secret`,
/// `token`, …), [`sensitive_threshold`](Self::sensitive_threshold) is used
/// instead so hex digests and other medium-entropy secrets are still caught.
/// Structural keys such as `foreign_key` keep [`threshold`](Self::threshold).
#[derive(Debug, Clone, Copy)]
pub struct EntropyDetector {
    /// Bits-per-byte required for tokens with no sensitive key.
    pub threshold: f64,
    /// Bits-per-byte required when [`LeafContext::key`] looks like a secret
    /// field. Below the hex-alphabet ceiling of 4.0 so MD5/SHA-shaped values
    /// qualify.
    pub sensitive_threshold: f64,
}

impl EntropyDetector {
    pub const DEFAULT_THRESHOLD: f64 = 4.5;

    /// Default [`sensitive_threshold`](Self::sensitive_threshold).
    pub const SENSITIVE_THRESHOLD: f64 = 3.5;

    pub fn new(threshold: f64, sensitive_threshold: f64) -> Self {
        Self {
            threshold,
            sensitive_threshold,
        }
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    pub fn sensitive_threshold(&self) -> f64 {
        self.sensitive_threshold
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::new(Self::DEFAULT_THRESHOLD, Self::SENSITIVE_THRESHOLD)
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy"
    }

    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let sensitive = ctx.key.is_some_and(is_sensitive_key);
        let threshold = if sensitive {
            self.sensitive_threshold
        } else {
            self.threshold
        };
        for m in TOKEN.find_iter(value) {
            let token = m.as_str();
            if shannon_entropy(token.as_bytes()) > threshold || (sensitive && is_hex_digest(token))
            {
                out.push(Detection::new(m.range(), self.name()));
            }
        }
    }
}

/// Whether `key` names a field that is likely to hold a secret.
fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(&split_camel(key));
    if STRUCTURAL_KEYS.iter().any(|name| {
        normalized == *name
            || normalized
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('_'))
    }) {
        return false;
    }
    normalized
        .split('_')
        .any(|seg| SENSITIVE_SEGMENTS.contains(&seg))
}

/// Insert `_` at camelCase boundaries so `apiKey` and `foreignKey` tokenize
/// the same as `api_key` and `foreign_key`.
fn split_camel(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let mut out = String::with_capacity(chars.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && c.is_uppercase() {
            let prev_lower = chars[i - 1].is_lowercase();
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if prev_lower || next_lower {
                out.push('_');
            }
        }
        out.push(c);
    }
    out
}

/// MD5 (32), SHA-1 (40), or SHA-256 (64) hex digest, any case.
fn is_hex_digest(token: &str) -> bool {
    matches!(token.len(), 32 | 40 | 64) && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Shannon entropy of `bytes`, in bits per byte.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "b65cc3551e470d5abe2448d41429daa2";

    fn detect(s: &str) -> Vec<&str> {
        detect_key(None, s)
    }

    fn detect_key<'a>(key: Option<&str>, s: &'a str) -> Vec<&'a str> {
        let mut out = Vec::new();
        let ctx = LeafContext {
            key,
            ..LeafContext::default()
        };
        EntropyDetector::default().detect(s, &ctx, &mut out);
        out.iter().map(|d| &s[d.range.clone()]).collect()
    }

    #[test]
    fn entropy_values() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn flags_high_entropy_tokens() {
        assert_eq!(
            detect("my key is aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz ok"),
            ["aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz"]
        );
    }

    #[test]
    fn ignores_words_and_short_tokens() {
        assert!(detect("hello world, this is a normal sentence").is_empty());
        assert!(detect("abc123XYZ").is_empty());
    }

    #[test]
    fn file_paths_are_not_one_token() {
        assert!(detect("/usr/local/bin/some-program-name").is_empty());
        assert!(detect("src/components/controller/handler.go").is_empty());
    }

    #[test]
    fn hex_digest_is_ignored_without_a_sensitive_key() {
        assert!(detect(HEX).is_empty());
        assert!(detect_key(Some("note"), HEX).is_empty());
        assert!(detect_key(Some("foreign_key"), HEX).is_empty());
        assert!(detect_key(Some("public_key"), HEX).is_empty());
        assert!(detect_key(Some("user_foreign_key"), HEX).is_empty());
    }

    #[test]
    fn hex_digest_is_flagged_under_a_sensitive_key() {
        for key in [
            "api_key",
            "apiKey",
            "API-KEY",
            "client_secret",
            "AWS_SECRET_ACCESS_KEY",
            "token",
            "db-password",
        ] {
            assert_eq!(detect_key(Some(key), HEX), [HEX], "{key}");
        }
    }

    #[test]
    fn ordinary_words_are_not_flagged_under_a_sensitive_key() {
        assert!(detect_key(Some("api_key"), "production").is_empty());
        assert!(detect_key(Some("api_key"), "changeme12").is_empty());
    }

    #[test]
    fn sensitive_key_matching() {
        for key in [
            "key",
            "api_key",
            "apiKey",
            "clientSecret",
            "secretAccessKey",
            "TOKEN",
            "passwd",
            "mysql.root.password",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
        for key in [
            "note",
            "foreign_key",
            "foreignKey",
            "primary_key",
            "sort_key",
            "public_key",
            "idempotency_key",
            "keyboard",
        ] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn hex_digest_lengths() {
        assert!(is_hex_digest(HEX));
        assert!(is_hex_digest(&"a".repeat(40)));
        assert!(is_hex_digest(&"A".repeat(64)));
        assert!(!is_hex_digest(&"a".repeat(31)));
        assert!(!is_hex_digest(&"g".repeat(32)));
    }

    #[test]
    fn thresholds_are_fields() {
        let detector = EntropyDetector::new(5.0, 2.0);
        assert_eq!(detector.threshold(), 5.0);
        assert_eq!(detector.sensitive_threshold(), 2.0);

        let mut out = Vec::new();
        let ctx = LeafContext {
            key: Some("note"),
            ..LeafContext::default()
        };
        detector.detect(HEX, &ctx, &mut out);
        assert!(
            out.is_empty(),
            "5.0 should miss hex without a sensitive key"
        );

        out.clear();
        let ctx = LeafContext {
            key: Some("api_key"),
            ..LeafContext::default()
        };
        EntropyDetector::new(5.0, 3.5).detect(HEX, &ctx, &mut out);
        assert_eq!(out.len(), 1);
    }
}
