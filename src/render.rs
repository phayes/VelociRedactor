use std::collections::HashSet;
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::Finding;
use crate::detect::Detection;

/// Salt used for redaction keys unless another is configured.
pub const DEFAULT_SALT: &str = "stripsecret";

/// Every replacement token starts with this.
pub const TOKEN_PREFIX: &str = "[REDACTION|";

static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[REDACTION\|[^|\[\]\s]*\|[0-9]+\|[0-9a-f]{64}\]").unwrap());

/// The key that identifies a secret: the BLAKE3 hash of `salt` followed by
/// the secret, as 64 lowercase hex digits.
///
/// Keys are stable for a given salt, so they can be used to allow a known
/// false positive across runs without revealing its value.
pub fn redaction_key(salt: &[u8], secret: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt);
    hasher.update(secret.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// The replacement text for a secret: `[REDACTION|<detector>|<len>|<key>]`,
/// where `len` is the secret's length in bytes.
///
/// Characters that would make the token ambiguous (`|`, `[`, `]`, and
/// whitespace) are replaced with `_` in the detector name.
pub fn token(detector: &str, len: usize, key: &str) -> String {
    let detector: String = detector
        .chars()
        .map(|c| {
            if matches!(c, '|' | '[' | ']') || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect();
    format!("{TOKEN_PREFIX}{detector}|{len}|{key}]")
}

/// Whether `s` is exactly a replacement token.
pub fn is_redaction_token(s: &str) -> bool {
    TOKEN.find(s).is_some_and(|m| m.range() == (0..s.len()))
}

/// The key inside a replacement token, if `s` is one.
pub fn token_key(s: &str) -> Option<&str> {
    is_redaction_token(s).then(|| &s[s.len() - 65..s.len() - 1])
}

/// Byte ranges of the replacement tokens in `s`.
pub fn find_tokens(s: &str) -> impl Iterator<Item = Range<usize>> + '_ {
    TOKEN.find_iter(s).map(|m| m.range())
}

/// Secrets to leave in place, identified by key or by value.
#[derive(Debug, Clone, Default)]
pub struct Allow {
    keys: HashSet<String>,
    values: HashSet<String>,
}

impl Allow {
    /// Redact everything.
    pub fn none() -> Self {
        Self::default()
    }

    /// Leave secrets with these keys unredacted. A full replacement token is
    /// also accepted in place of a key.
    pub fn keys<S: AsRef<str>>(keys: impl IntoIterator<Item = S>) -> Self {
        Self::none().with_keys(keys)
    }

    /// Leave these exact secret values unredacted.
    pub fn values<S: Into<String>>(values: impl IntoIterator<Item = S>) -> Self {
        Self::none().with_values(values)
    }

    pub fn with_keys<S: AsRef<str>>(mut self, keys: impl IntoIterator<Item = S>) -> Self {
        for key in keys {
            let key = key.as_ref().trim();
            let key = token_key(key).unwrap_or(key);
            self.keys.insert(key.to_ascii_lowercase());
        }
        self
    }

    pub fn with_values<S: Into<String>>(mut self, values: impl IntoIterator<Item = S>) -> Self {
        self.values.extend(values.into_iter().map(Into::into));
        self
    }

    /// Whether `finding` should be left unredacted.
    pub fn allows(&self, finding: &Finding) -> bool {
        self.keys.contains(&finding.key) || self.values.contains(&finding.secret)
    }

    /// Keys in this list that match none of `findings`.
    pub fn unmatched_keys<'a>(&'a self, findings: &'a [Finding]) -> impl Iterator<Item = &'a str> {
        self.keys
            .iter()
            .filter(|k| !findings.iter().any(|f| &f.key == *k))
            .map(String::as_str)
    }

    /// Number of values in this list that match none of `findings`.
    pub fn unmatched_value_count(&self, findings: &[Finding]) -> usize {
        self.values
            .iter()
            .filter(|v| !findings.iter().any(|f| &f.secret == *v))
            .count()
    }
}

/// Normalize detections for one value: widen to character boundaries, drop
/// empty ranges and ranges inside existing replacement tokens, then merge
/// overlapping or touching ranges.
///
/// When ranges overlap, the merged range keeps the label of the one that
/// starts first (and, for equal starts, the longer one).
pub(crate) fn merge(value: &str, mut detections: Vec<Detection>) -> Vec<Detection> {
    for d in &mut detections {
        d.range = snap(value, d.range.clone());
    }
    let tokens: Vec<Range<usize>> = if value.contains(TOKEN_PREFIX) {
        find_tokens(value).collect()
    } else {
        Vec::new()
    };
    detections.retain(|d| {
        !d.range.is_empty()
            && !tokens
                .iter()
                .any(|t| t.start <= d.range.start && d.range.end <= t.end)
    });
    detections.sort_by(|a, b| {
        a.range
            .start
            .cmp(&b.range.start)
            .then(b.range.end.cmp(&a.range.end))
            .then_with(|| a.label.cmp(&b.label))
    });

    let mut merged: Vec<Detection> = Vec::with_capacity(detections.len());
    for d in detections {
        match merged.last_mut() {
            Some(last) if d.range.start <= last.range.end => {
                last.range.end = last.range.end.max(d.range.end);
            }
            _ => merged.push(d),
        }
    }
    merged
}

fn snap(value: &str, range: Range<usize>) -> Range<usize> {
    let mut start = range.start.min(value.len());
    let mut end = range.end.clamp(start, value.len());
    while !value.is_char_boundary(start) {
        start -= 1;
    }
    while !value.is_char_boundary(end) {
        end += 1;
    }
    start..end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(range: Range<usize>, label: &str) -> Detection {
        Detection::new(range, label)
    }

    #[test]
    fn keys_are_salted_blake3_hex() {
        let key = redaction_key(b"stripsecret", "hunter2");
        assert_eq!(key.len(), 64);
        assert_eq!(key, blake3::hash(b"stripsecrethunter2").to_hex().as_str());
        assert_ne!(key, redaction_key(b"other", "hunter2"));
    }

    #[test]
    fn tokens() {
        let key = redaction_key(DEFAULT_SALT.as_bytes(), "a@b.com");
        let t = token("pii:email", 7, &key);
        assert_eq!(t, format!("[REDACTION|pii:email|7|{key}]"));
        assert!(is_redaction_token(&t));
        assert_eq!(token_key(&t), Some(key.as_str()));
        assert!(!is_redaction_token(&format!("x{t}")));
        assert!(!is_redaction_token("[REDACTION|x|1|abc]"));
        assert_eq!(
            token("my rule|v[2]", 3, &key),
            format!("[REDACTION|my_rule_v_2_|3|{key}]")
        );
    }

    #[test]
    fn allow_accepts_keys_and_tokens() {
        let key = redaction_key(b"s", "v");
        let finding = Finding {
            key: key.clone(),
            secret: "v".into(),
            detector: "d".into(),
            len: 1,
            field: None,
            offsets: vec![],
            occurrences: 1,
        };
        assert!(Allow::keys([&key]).allows(&finding));
        assert!(Allow::keys([key.to_uppercase()]).allows(&finding));
        assert!(Allow::keys([token("d", 1, &key)]).allows(&finding));
        assert!(Allow::values(["v"]).allows(&finding));
        assert!(!Allow::values(["w"]).allows(&finding));
        assert!(!Allow::none().allows(&finding));
    }

    #[test]
    fn merges_overlapping_and_adjacent_ranges() {
        let value = "0123456789abcdef";
        let merged = merge(
            value,
            vec![
                d(6..8, "c"),
                d(0..3, "a"),
                d(2..5, "b"),
                d(5..6, "d"),
                d(10..12, "e"),
            ],
        );
        assert_eq!(merged, vec![d(0..8, "a"), d(10..12, "e")]);
    }

    #[test]
    fn longer_range_wins_label_on_equal_start() {
        let merged = merge("0123456789", vec![d(0..3, "short"), d(0..6, "long")]);
        assert_eq!(merged, vec![d(0..6, "long")]);
    }

    #[test]
    fn snaps_to_char_boundaries_and_drops_ranges_inside_tokens() {
        let t = token("entropy", 5, &redaction_key(b"", "x"));
        let value = format!("é {t}");
        let hex = value.len() - 65..value.len() - 1;
        let merged = merge(
            &value,
            vec![d(1..2, "x"), d(hex, "y"), d(3..value.len(), "z")],
        );
        assert_eq!(merged, vec![d(0..2, "x")]);
    }
}
