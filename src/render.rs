use std::collections::HashSet;
use std::ops::Range;

use crate::detect::Detection;

/// Prefix of every replacement token. Tokens look like `REDACTION-7`.
pub const TOKEN_PREFIX: &str = "REDACTION-";

/// The replacement text for redaction `id`.
pub fn token(id: u32) -> String {
    format!("{TOKEN_PREFIX}{id}")
}

/// Whether `s` is exactly a replacement token.
pub fn is_redaction_token(s: &str) -> bool {
    s.strip_prefix(TOKEN_PREFIX)
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Redaction ids to leave in place.
#[derive(Debug, Clone, Default)]
pub struct Allow {
    ids: HashSet<u32>,
}

impl Allow {
    /// Redact everything.
    pub fn none() -> Self {
        Self::default()
    }

    /// Leave the given redaction ids unredacted.
    pub fn ids(ids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }

    pub fn contains(&self, id: u32) -> bool {
        self.ids.contains(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.ids.iter().copied()
    }
}

/// Normalize detections for one value: widen to character boundaries, drop
/// empty ranges and ranges that are already replacement tokens, then merge
/// overlapping or touching ranges.
///
/// When ranges overlap, the merged range keeps the label of the one that
/// starts first (and, for equal starts, the longer one).
pub(crate) fn merge(value: &str, mut detections: Vec<Detection>) -> Vec<Detection> {
    for d in &mut detections {
        d.range = snap(value, d.range.clone());
    }
    detections.retain(|d| !d.range.is_empty() && !is_redaction_token(&value[d.range.clone()]));
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
    fn tokens() {
        assert_eq!(token(3), "REDACTION-3");
        assert!(is_redaction_token("REDACTION-42"));
        assert!(!is_redaction_token("REDACTION-"));
        assert!(!is_redaction_token("REDACTION-4x"));
        assert!(!is_redaction_token("xREDACTION-4"));
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
    fn snaps_to_char_boundaries_and_drops_tokens() {
        let value = "é REDACTION-1";
        let merged = merge(value, vec![d(1..2, "x"), d(3..15, "y")]);
        assert_eq!(merged, vec![d(0..2, "x")]);
    }
}
