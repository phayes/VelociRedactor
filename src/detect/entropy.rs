use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;
use serde::Deserialize;

use super::credential::normalize_key;
use super::{Detection, Detector, LeafContext};
use crate::Error;

/// The `entropy` detector's settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct EntropyConfig {
    pub threshold: f64,
    pub sensitive_threshold: f64,
    pub min_token_length: usize,
    /// Single lowercase words marking a key as holding a secret.
    pub sensitive_segments: Vec<String>,
    /// Key names that merely look sensitive and keep the ordinary threshold.
    pub structural_keys: Vec<String>,
    pub hex_digest_lengths: Vec<usize>,
}

#[derive(Debug)]
struct Compiled {
    token: Regex,
    sensitive_segments: HashSet<String>,
    structural_keys: Vec<String>,
    hex_digest_lengths: Vec<usize>,
}

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
#[derive(Debug, Clone)]
pub struct EntropyDetector {
    /// Bits-per-byte required for tokens with no sensitive key.
    pub threshold: f64,
    /// Bits-per-byte required when [`LeafContext::key`] looks like a secret
    /// field. Below the hex-alphabet ceiling of 4.0 so MD5/SHA-shaped values
    /// qualify.
    pub sensitive_threshold: f64,
    /// The key vocabulary and token pattern, shared between clones.
    inner: Arc<Compiled>,
}

impl EntropyDetector {
    /// Validate and compile `config`.
    pub fn new(config: &EntropyConfig) -> Result<Self, Error> {
        // Segments are compared against one `_`-delimited piece of a key, so
        // an entry containing `_` could never match.
        for segment in &config.sensitive_segments {
            if segment.contains('_') || segment.is_empty() {
                return Err(Error::Config(format!(
                    "entropy.sensitive-segments: {segment:?} is not a single word, \
                     so it can never match a key segment"
                )));
            }
        }
        if config.structural_keys.iter().any(String::is_empty) {
            return Err(Error::Config(
                "entropy.structural-keys: an empty entry matches everything".into(),
            ));
        }
        // `{0,}` and `{1,}` make the token pattern match at every position.
        if config.min_token_length < 2 {
            return Err(Error::Config(
                "entropy.min-token-length must be at least 2".into(),
            ));
        }

        Ok(Self {
            threshold: config.threshold,
            sensitive_threshold: config.sensitive_threshold,
            inner: Arc::new(Compiled {
                token: token_regex(config.min_token_length)?,
                sensitive_segments: config
                    .sensitive_segments
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect(),
                structural_keys: config
                    .structural_keys
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect(),
                hex_digest_lengths: config.hex_digest_lengths.clone(),
            }),
        })
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    pub fn sensitive_threshold(&self) -> f64 {
        self.sensitive_threshold
    }

    /// Whether `key` names a field that is likely to hold a secret.
    fn is_sensitive_key(&self, key: &str) -> bool {
        // The camelCase split has to come first: normalizing lowercases the
        // key, after which `apiKey` is one segment instead of two.
        let normalized = normalize_key(&split_camel(key));
        // A structural key vetoes the segment scan below, where `public_key`
        // would otherwise match on `key`.
        if self.inner.structural_keys.iter().any(|name| {
            normalized == *name
                || normalized
                    .strip_suffix(name)
                    .is_some_and(|prefix| prefix.ends_with('_'))
        }) {
            return false;
        }
        // Whole segments, not substrings, so `keyboard` is not sensitive.
        normalized
            .split('_')
            .any(|seg| self.inner.sensitive_segments.contains(seg))
    }

    /// An MD5, SHA-1, or SHA-256 hex digest, any case.
    fn is_hex_digest(&self, token: &str) -> bool {
        self.inner.hex_digest_lengths.contains(&token.len())
            && token.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy"
    }

    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let sensitive = ctx.key.is_some_and(|key| self.is_sensitive_key(key));
        let threshold = if sensitive {
            self.sensitive_threshold
        } else {
            self.threshold
        };
        for m in self.inner.token.find_iter(value) {
            let token = m.as_str();
            if shannon_entropy(token.as_bytes()) > threshold
                || (sensitive && self.is_hex_digest(token))
            {
                out.push(Detection::new(m.range(), self.name()));
            }
        }
    }
}

/// The candidate-token pattern. `/` is excluded so a whole file path is not
/// treated as one token; high-entropy segments are still found individually.
fn token_regex(min_length: usize) -> Result<Regex, Error> {
    Regex::new(&format!(r"[A-Za-z0-9+_=-]{{{min_length},}}")).map_err(|_| {
        Error::Config(format!(
            "entropy.min-token-length: {min_length} does not make a valid pattern"
        ))
    })
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
    use crate::detect::DetectorConfig;

    const HEX: &str = "b65cc3551e470d5abe2448d41429daa2";

    /// A detector with the vocabulary the built-in configuration gives it.
    fn d() -> EntropyDetector {
        EntropyDetector::new(&config()).unwrap()
    }

    fn config() -> EntropyConfig {
        crate::config::Config::builtin()
            .detectors
            .iter()
            .find_map(|d| match d {
                DetectorConfig::Entropy(config) => Some(config.clone()),
                _ => None,
            })
            .expect("the built-in configuration lists the entropy detector")
    }

    fn detect(s: &str) -> Vec<&str> {
        detect_key(None, s)
    }

    fn detect_key<'a>(key: Option<&str>, s: &'a str) -> Vec<&'a str> {
        let mut out = Vec::new();
        let ctx = LeafContext {
            key,
            ..LeafContext::default()
        };
        d().detect(s, &ctx, &mut out);
        out.iter().map(|d| &s[d.range.clone()]).collect()
    }

    #[test]
    fn entropy_values() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn the_builtin_settings_are_the_documented_ones() {
        assert_eq!(d().threshold(), 4.5);
        assert_eq!(d().sensitive_threshold(), 3.5);
        assert_eq!(d().inner.token.as_str(), r"[A-Za-z0-9+_=-]{10,}");
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
            assert!(d().is_sensitive_key(key), "{key} should be sensitive");
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
            assert!(!d().is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn hex_digest_lengths() {
        assert!(d().is_hex_digest(HEX));
        assert!(d().is_hex_digest(&"a".repeat(40)));
        assert!(d().is_hex_digest(&"A".repeat(64)));
        assert!(!d().is_hex_digest(&"a".repeat(31)));
        assert!(!d().is_hex_digest(&"g".repeat(32)));
    }

    /// The thresholds are public fields, so a library user can raise them on
    /// a detector built from any configuration.
    #[test]
    fn thresholds_are_fields() {
        let mut detector = d();
        detector.threshold = 5.0;
        detector.sensitive_threshold = 2.0;
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
        detector.sensitive_threshold = 3.5;
        let ctx = LeafContext {
            key: Some("api_key"),
            ..LeafContext::default()
        };
        detector.detect(HEX, &ctx, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn multi_word_sensitive_segments_are_rejected() {
        let mut config = config();
        config.sensitive_segments.push("api_key".into());
        let err = EntropyDetector::new(&config).unwrap_err().to_string();
        assert!(err.contains("single word"), "{err}");
    }

    #[test]
    fn a_tiny_min_token_length_is_rejected() {
        let mut config = config();
        config.min_token_length = 1;
        let err = EntropyDetector::new(&config).unwrap_err().to_string();
        assert!(err.contains("at least 2"), "{err}");
    }

    #[test]
    fn the_vocabulary_comes_from_the_configuration() {
        let mut config = config();
        config.structural_keys.retain(|k| k != "public_key");
        let detector = EntropyDetector::new(&config).unwrap();
        assert!(detector.is_sensitive_key("public_key"));
    }
}
