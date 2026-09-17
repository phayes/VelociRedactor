use std::ops::Range;

use memchr::memmem;

use super::Replacement;

/// Builds a rewritten document by replacing byte ranges of the original.
///
/// Formats whose parser reports where each value sits in the input use this
/// to change only redacted characters, leaving everything else byte-for-byte
/// identical.
pub struct Splicer<'a> {
    input: &'a [u8],
    edits: Vec<(Range<usize>, Vec<u8>)>,
}

impl<'a> Splicer<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            edits: Vec::new(),
        }
    }

    /// Apply `replacement` to a scalar.
    ///
    /// `raw` is the whole scalar in the input (including any quotes) and
    /// `content` is the part between the quotes. `value` is the decoded value
    /// that the replacement was computed from.
    ///
    /// When the redacted text appears verbatim in the input, only those bytes
    /// are replaced. Otherwise (for example when the value contains escape
    /// sequences) the whole scalar is replaced by `encode(new_value)`.
    pub fn apply(
        &mut self,
        raw: Range<usize>,
        content: Range<usize>,
        value: &str,
        replacement: &Replacement,
        encode: impl FnOnce(&str) -> String,
    ) {
        if let Some(mapped) = self.map_edits(content, value, replacement) {
            self.edits.extend(mapped);
        } else {
            self.edits
                .push((raw, encode(&replacement.value).into_bytes()));
        }
    }

    /// Replace `range` of the input with `bytes`.
    pub fn replace(&mut self, range: Range<usize>, bytes: impl Into<Vec<u8>>) {
        self.edits.push((range, bytes.into()));
    }

    /// Whether any replacements have been recorded.
    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.edits.is_empty() {
            return self.input.to_vec();
        }
        self.edits.sort_by_key(|(r, _)| (r.start, r.end));
        let mut out = Vec::with_capacity(self.input.len());
        let mut prev = 0;
        for (range, bytes) in self.edits {
            if range.start < prev {
                continue;
            }
            out.extend_from_slice(&self.input[prev..range.start]);
            out.extend_from_slice(&bytes);
            prev = range.end;
        }
        out.extend_from_slice(&self.input[prev..]);
        out
    }

    fn map_edits(
        &self,
        content: Range<usize>,
        value: &str,
        replacement: &Replacement,
    ) -> Option<Vec<(Range<usize>, Vec<u8>)>> {
        let raw = self.input.get(content.clone())?;
        if raw == value.as_bytes() {
            return Some(
                replacement
                    .edits
                    .iter()
                    .map(|e| {
                        (
                            content.start + e.range.start..content.start + e.range.end,
                            e.text.clone().into_bytes(),
                        )
                    })
                    .collect(),
            );
        }

        // The raw text differs from the decoded value (escapes, indentation,
        // line folding). A redacted substring can still be edited in place if
        // it occurs exactly once in both, since it then refers to the same
        // characters.
        let mut mapped = Vec::with_capacity(replacement.edits.len());
        for edit in &replacement.edits {
            let original = &value[edit.range.clone()];
            if original.is_empty() || original.contains(['\n', '\r']) {
                return None;
            }
            if value.matches(original).nth(1).is_some() {
                return None;
            }
            let mut hits = memmem::find_iter(raw, original.as_bytes());
            let at = hits.next()?;
            if hits.next().is_some() {
                return None;
            }
            let start = content.start + at;
            mapped.push((
                start..start + original.len(),
                edit.text.clone().into_bytes(),
            ));
        }
        Some(mapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Edit;

    fn repl(value: &str, range: Range<usize>, text: &str) -> Replacement {
        let edits = vec![Edit {
            range,
            text: text.into(),
        }];
        Replacement {
            value: crate::format::apply_edits(value, &edits),
            edits,
        }
    }

    #[test]
    fn splices_verbatim_values_in_place() {
        let input = br#"{"a": "xx SECRET yy"}"#;
        let mut s = Splicer::new(input);
        s.apply(
            6..20,
            7..19,
            "xx SECRET yy",
            &repl("xx SECRET yy", 3..9, "R-1"),
            |_| unreachable!(),
        );
        assert_eq!(s.finish(), br#"{"a": "xx R-1 yy"}"#);
    }

    #[test]
    fn maps_unique_substrings_through_escapes() {
        let input = br#"{"a": "x\ty SECRET"}"#;
        let value = "x\ty SECRET";
        let mut s = Splicer::new(input);
        s.apply(
            6..19,
            7..18,
            value,
            &repl(value, 4..10, "R-1"),
            |_| unreachable!(),
        );
        assert_eq!(s.finish(), br#"{"a": "x\ty R-1"}"#);
    }

    #[test]
    fn re_encodes_when_substring_is_not_verbatim() {
        // `S` is an escaped `S`, so the raw text never contains "SECRET".
        let input = format!(r#"{{"a": "{}u0053ECRET"}}"#, '\\');
        let input = input.as_bytes();
        let value = "SECRET";
        let mut s = Splicer::new(input);
        s.apply(6..19, 7..18, value, &repl(value, 0..6, "R-1"), |v| {
            format!("{v:?}")
        });
        assert_eq!(s.finish(), br#"{"a": "R-1"}"#);
    }

    #[test]
    fn unchanged_without_edits() {
        let input = b"hello";
        assert_eq!(Splicer::new(input).finish(), b"hello");
    }
}
