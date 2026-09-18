use std::collections::HashSet;
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::Finding;
use crate::detect::Detection;

/// Every replacement token starts with this.
pub const TOKEN_PREFIX: &str = "REDACTION-";

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bREDACTION-[1-9][0-9]*\b").unwrap());

/// The replacement text for a secret: `REDACTION-<n>`, where `n` is the
/// 1-based id of the distinct value in this document.
pub fn token(id: usize) -> String {
    format!("{TOKEN_PREFIX}{id}")
}

/// Whether `s` is exactly a replacement token.
pub fn is_redaction_token(s: &str) -> bool {
    TOKEN.find(s).is_some_and(|m| m.range() == (0..s.len()))
}

/// Byte ranges of the replacement tokens in `s`.
pub fn find_tokens(s: &str) -> impl Iterator<Item = Range<usize>> + '_ {
    TOKEN.find_iter(s).map(|m| m.range())
}

/// Secrets to leave in place, identified by exact value.
#[derive(Debug, Clone, Default)]
pub struct Allow {
    values: HashSet<String>,
}

impl Allow {
    /// Redact everything.
    pub fn none() -> Self {
        Self::default()
    }

    /// Leave these exact secret values unredacted.
    pub fn values<S: Into<String>>(values: impl IntoIterator<Item = S>) -> Self {
        Self::none().with_values(values)
    }

    pub fn with_values<S: Into<String>>(mut self, values: impl IntoIterator<Item = S>) -> Self {
        self.values.extend(values.into_iter().map(Into::into));
        self
    }

    /// Whether `finding` should be left unredacted.
    pub fn allows(&self, finding: &Finding) -> bool {
        self.values.contains(&finding.secret)
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

    fn finding(secret: &str) -> Finding {
        Finding {
            id: 1,
            secret: secret.into(),
            detector: "d".into(),
            len: secret.len(),
            field: None,
            offsets: vec![],
            occurrences: 1,
        }
    }

    #[test]
    fn tokens() {
        let t = token(1);
        assert_eq!(t, "REDACTION-1");
        assert!(is_redaction_token(&t));
        assert_eq!(token(12), "REDACTION-12");
        assert!(is_redaction_token("REDACTION-12"));
        assert!(!is_redaction_token("xREDACTION-1"));
        assert!(!is_redaction_token("REDACTION-01"));
        assert!(!is_redaction_token("REDACTION-0"));
        assert!(!is_redaction_token("[REDACTION|x|1|abc]"));
    }

    #[test]
    fn allow_accepts_values() {
        let finding = finding("v");
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
        let t = token(1);
        let value = format!("é {t}");
        let token_range = 3..value.len();
        let merged = merge(
            &value,
            vec![d(1..2, "x"), d(token_range, "y"), d(3..value.len(), "z")],
        );
        assert_eq!(merged, vec![d(0..2, "x")]);
    }
}
