use std::collections::HashSet;
use std::fmt::Write;
use std::ops::Range;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::detect::{Detection, describe_regex_error};
use crate::{Error, Finding};

/// The built-in replacement template: `[REDACTED-{n}]`.
pub const DEFAULT_REPLACEMENT: &str = "[REDACTED-{n}]";

fn builtin_replacement() -> &'static ReplacementFormat {
    static DEFAULT: LazyLock<ReplacementFormat> = LazyLock::new(|| {
        ReplacementFormat::parse(DEFAULT_REPLACEMENT)
            .expect("the default replacement format is valid")
    });
    &DEFAULT
}

/// Format a replacement token using `format`.
pub fn token(format: &ReplacementFormat, id: usize, reason: &str) -> Result<String, Error> {
    format.token(id, reason)
}

/// Whether `s` is exactly a replacement token under `format`.
pub fn is_redaction_token(format: &ReplacementFormat, s: &str) -> bool {
    format.is_token(s)
}

/// Byte ranges of the replacement tokens in `s` under `format`.
pub fn find_tokens<'a>(
    format: &'a ReplacementFormat,
    s: &'a str,
) -> impl Iterator<Item = Range<usize>> + 'a {
    format.find_tokens(s)
}

/// How a redacted secret is written back: a format string with `{n}` and
/// `{reason}` as replacement values.
///
/// `{n}` is the 1-based number of this distinct value in the document. The
/// same text always shares a number. `{reason}` is why it was redacted: the
/// detector label (`entropy`, `ruleset:github-pat`, `credential_key`, …).
/// Double a brace to write it literally (`{{` / `}}`).
///
/// A format must contain exactly one `{n}`, at most one `{reason}`, nonempty
/// literal text at both ends, and literal text between placeholders. The
/// literal immediately after `{reason}` must begin with a character that
/// cannot occur in a reason, making token discovery unambiguous.
///
/// Reasons use the detector-label alphabet: ASCII letters, digits, `_`, `.`,
/// `:`, `/`, and `-`, starting with an ASCII letter, digit, or `_`.
///
/// The default, [`DEFAULT_REPLACEMENT`], produces `[REDACTED-1]`,
/// `[REDACTED-2]`, and so on.
#[derive(Debug, Clone)]
pub struct ReplacementFormat {
    template: String,
    parts: Arc<[Part]>,
    finder: Regex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Number,
    Reason,
}

impl Default for ReplacementFormat {
    fn default() -> Self {
        builtin_replacement().clone()
    }
}

impl PartialEq for ReplacementFormat {
    fn eq(&self, other: &Self) -> bool {
        self.template == other.template
    }
}

impl Eq for ReplacementFormat {}

impl ReplacementFormat {
    /// Parse a replacement format.
    ///
    /// Unknown placeholders, an unclosed `{`, or a stray `}` are errors.
    pub fn parse(template: impl AsRef<str>) -> Result<Self, Error> {
        let template = template.as_ref();
        let parts = parse_parts(template)?;
        validate_parts(&parts)?;
        let finder = compile_finder(&parts);
        Ok(Self {
            template: template.to_owned(),
            parts: parts.into(),
            finder,
        })
    }

    /// The format string as written.
    pub fn as_str(&self) -> &str {
        &self.template
    }

    /// The token for distinct secret `n` (1-based), found for `reason`.
    pub fn token(&self, n: usize, reason: &str) -> Result<String, Error> {
        if n == 0 {
            return Err(Error::Replacement(
                "the redaction number must be at least 1".into(),
            ));
        }
        if self.parts.contains(&Part::Reason) && !valid_reason(reason) {
            return Err(Error::Replacement(format!("the reason {REASON_RULE}")));
        }
        let mut out = String::new();
        for part in self.parts.iter() {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Number => {
                    let _ = write!(out, "{n}");
                }
                Part::Reason => out.push_str(reason),
            }
        }
        Ok(out)
    }

    /// Whether `s` is exactly one token of this format.
    pub fn is_token(&self, s: &str) -> bool {
        self.finder
            .find(s)
            .is_some_and(|m| m.range() == (0..s.len()))
    }

    /// Byte ranges of the tokens of this format in `s`.
    pub fn find_tokens<'a>(&'a self, s: &'a str) -> impl Iterator<Item = Range<usize>> + 'a {
        self.finder.find_iter(s).map(|m| m.range())
    }
}

impl<'de> Deserialize<'de> for ReplacementFormat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let template = String::deserialize(deserializer)?;
        Self::parse(&template).map_err(de::Error::custom)
    }
}

fn parse_parts(template: &str) -> Result<Vec<Part>, Error> {
    let chars: Vec<(usize, char)> = template.char_indices().collect();
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut idx = 0;

    let flush = |literal: &mut String, parts: &mut Vec<Part>| {
        if !literal.is_empty() {
            parts.push(Part::Literal(std::mem::take(literal)));
        }
    };

    while idx < chars.len() {
        let c = chars[idx].1;
        if c == '{' {
            if chars.get(idx + 1).is_some_and(|(_, next)| *next == '{') {
                literal.push('{');
                idx += 2;
                continue;
            }
            let start = idx + 1;
            let mut end = start;
            while end < chars.len() && chars[end].1 != '}' {
                end += 1;
            }
            if end == chars.len() {
                return Err(Error::Config(
                    "replacement: unclosed '{' in format string".into(),
                ));
            }
            let name = if start == end {
                ""
            } else {
                &template[chars[start].0..chars[end].0]
            };
            flush(&mut literal, &mut parts);
            match name {
                "n" => parts.push(Part::Number),
                "reason" => parts.push(Part::Reason),
                _ => {
                    return Err(Error::Config(format!(
                        "replacement: unknown placeholder {{{name}}}; available values are {{n}} and {{reason}}"
                    )));
                }
            }
            idx = end + 1;
        } else if c == '}' {
            if chars.get(idx + 1).is_some_and(|(_, next)| *next == '}') {
                literal.push('}');
                idx += 2;
                continue;
            }
            return Err(Error::Config(
                "replacement: unmatched '}' in format string".into(),
            ));
        } else {
            literal.push(c);
            idx += 1;
        }
    }
    flush(&mut literal, &mut parts);
    Ok(parts)
}

const REASON_PATTERN: &str = r"[A-Za-z0-9_][A-Za-z0-9_.:/-]*";

fn reason_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '-')
}

/// What [`valid_reason`] requires, to follow "the reason" or "a label".
pub(crate) const REASON_RULE: &str = "must start with an ASCII letter, digit, or `_` and contain only ASCII letters, digits, `_`, `.`, `:`, `/`, and `-`";

/// Whether `reason` can be written as `{reason}` and found again.
pub(crate) fn valid_reason(reason: &str) -> bool {
    let mut chars = reason.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && chars.all(reason_char)
}

fn validate_parts(parts: &[Part]) -> Result<(), Error> {
    let numbers = parts.iter().filter(|part| **part == Part::Number).count();
    if numbers != 1 {
        return Err(Error::Replacement(
            "the format must contain exactly one `{n}`".into(),
        ));
    }
    if parts.iter().filter(|part| **part == Part::Reason).count() > 1 {
        return Err(Error::Replacement(
            "the format may contain `{reason}` at most once".into(),
        ));
    }
    if !matches!(parts.first(), Some(Part::Literal(text)) if !text.is_empty())
        || !matches!(parts.last(), Some(Part::Literal(text)) if !text.is_empty())
    {
        return Err(Error::Replacement(
            "the format must begin and end with literal text".into(),
        ));
    }
    if parts
        .windows(2)
        .any(|pair| !matches!(pair[0], Part::Literal(_)) && !matches!(pair[1], Part::Literal(_)))
    {
        return Err(Error::Replacement(
            "placeholders must be separated by literal text".into(),
        ));
    }
    if let Some(index) = parts.iter().position(|part| *part == Part::Reason) {
        let Part::Literal(after) = &parts[index + 1] else {
            unreachable!("the structural checks require a literal after `{{reason}}`");
        };
        if after.chars().next().is_some_and(reason_char) {
            return Err(Error::Replacement(
                "the literal after `{reason}` must begin with a character that cannot occur in a reason".into(),
            ));
        }
    }
    Ok(())
}

fn compile_finder(parts: &[Part]) -> Regex {
    let mut pattern = String::new();
    for part in parts {
        match part {
            Part::Literal(text) => pattern.push_str(&regex::escape(text)),
            Part::Number => pattern.push_str("[1-9][0-9]*"),
            Part::Reason => pattern.push_str(REASON_PATTERN),
        }
    }
    Regex::new(&pattern).expect("a replacement finder compiled from literals compiles")
}

/// Secrets to leave in place, identified by exact value or by a pattern the
/// whole value matches.
///
/// An allowed value stays in the document whatever found it: allowing is the
/// last word over every detector.
#[derive(Debug, Clone, Default)]
pub struct Allow {
    values: HashSet<String>,
    regexes: Vec<Regex>,
    /// Leave every secret in place, for files allowed whole.
    everything: bool,
}

impl Allow {
    /// Redact everything.
    pub fn none() -> Self {
        Self::default()
    }

    /// Redact nothing.
    pub fn all() -> Self {
        Self {
            everything: true,
            ..Self::default()
        }
    }

    /// Leave these exact secret values unredacted.
    pub fn values<S: Into<String>>(values: impl IntoIterator<Item = S>) -> Self {
        Self::none().with_values(values)
    }

    /// Leave unredacted every secret that one of these patterns matches in
    /// full (Rust `regex` syntax).
    pub fn regexes<S: AsRef<str>>(patterns: impl IntoIterator<Item = S>) -> Result<Self, Error> {
        Self::none().with_regexes(patterns)
    }

    /// Add exact secret values to this allow list.
    pub fn with_values<S: Into<String>>(mut self, values: impl IntoIterator<Item = S>) -> Self {
        self.values.extend(values.into_iter().map(Into::into));
        self
    }

    /// Add patterns that a secret must match in full to be allowed.
    ///
    /// Compile errors deliberately omit the pattern text, since a pattern may
    /// itself contain the secret it refers to.
    pub fn with_regexes<S: AsRef<str>>(
        mut self,
        patterns: impl IntoIterator<Item = S>,
    ) -> Result<Self, Error> {
        for pattern in patterns {
            let anchored = format!("^(?s:{})$", pattern.as_ref());
            let regex = Regex::new(&anchored).map_err(|err| Error::InvalidPattern {
                name: "allow-regex".into(),
                message: describe_regex_error(&err),
            })?;
            self.regexes.push(regex);
        }
        Ok(self)
    }

    /// Whether `finding` should be left unredacted.
    pub fn allows(&self, finding: &Finding) -> bool {
        self.everything
            || self.values.contains(&finding.secret)
            || self.regexes.iter().any(|r| r.is_match(&finding.secret))
    }
}

/// Normalize detections for one value: widen to character boundaries, drop
/// empty ranges and ranges inside existing replacement tokens, then merge
/// overlapping or touching ranges.
///
/// When ranges overlap, the merged range keeps the label of the one that
/// starts first (and, for equal starts, the longer one).
pub(crate) fn merge(
    value: &str,
    mut detections: Vec<Detection>,
    format: &ReplacementFormat,
) -> Vec<Detection> {
    for d in &mut detections {
        d.range = snap(value, d.range.clone());
    }
    let tokens: Vec<Range<usize>> = format.find_tokens(value).collect();
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
        let format = ReplacementFormat::default();
        Finding {
            id: 1,
            secret: secret.into(),
            detector: "d".into(),
            token: token(&format, 1, "d").unwrap(),
            len: secret.len(),
            field: None,
            path: None,
            offsets: vec![],
            occurrences: 1,
        }
    }

    fn merged(value: &str, detections: Vec<Detection>) -> Vec<Detection> {
        merge(value, detections, &ReplacementFormat::default())
    }

    #[test]
    fn tokens() {
        let format = ReplacementFormat::default();
        let t = token(&format, 1, "entropy").unwrap();
        assert_eq!(t, "[REDACTED-1]");
        assert!(is_redaction_token(&format, &t));
        assert_eq!(
            token(&format, 12, "credential_key").unwrap(),
            "[REDACTED-12]"
        );
        assert!(is_redaction_token(&format, "[REDACTED-12]"));
        assert!(!is_redaction_token(&format, "x[REDACTED-1]"));
        assert!(!is_redaction_token(&format, "[REDACTED-01]"));
        assert!(!is_redaction_token(&format, "[REDACTED-0]"));
        assert!(!is_redaction_token(&format, "[REDACTED]"));
    }

    #[test]
    fn replacement_format_substitutes_n_and_reason() {
        let format = ReplacementFormat::parse("[REDACTED-{n}:{reason}]").unwrap();
        assert_eq!(format.token(1, "entropy").unwrap(), "[REDACTED-1:entropy]");
        assert_eq!(
            format.token(12, "ruleset:github-pat").unwrap(),
            "[REDACTED-12:ruleset:github-pat]"
        );
        assert!(format.is_token("[REDACTED-1:entropy]"));
        assert!(!format.is_token("[REDACTED-1]"));
        let text = "a [REDACTED-1:entropy] b [REDACTED-12:ruleset:github-pat]";
        assert_eq!(
            find_tokens(&format, text).collect::<Vec<_>>(),
            vec![2..22, 25..57]
        );
        assert!(is_redaction_token(
            &format,
            "[REDACTED-12:ruleset:github-pat]"
        ));
    }

    #[test]
    fn replacement_format_escapes_braces() {
        let format = ReplacementFormat::parse("{{n}}={n};").unwrap();
        assert_eq!(format.token(3, "ignored").unwrap(), "{n}=3;");
    }

    #[test]
    fn replacement_format_rejects_unknown_placeholders() {
        let err = ReplacementFormat::parse("{id}").unwrap_err().to_string();
        assert!(err.contains("{id}"), "{err}");
        assert!(err.contains("{n}"), "{err}");
        assert!(err.contains("{reason}"), "{err}");
    }

    #[test]
    fn replacement_format_rejects_unbalanced_braces() {
        let err = ReplacementFormat::parse("[REDACTED-{n]")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unclosed"), "{err}");
        let err = ReplacementFormat::parse("REDACTED-}")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unmatched"), "{err}");
    }

    #[test]
    fn replacement_format_requires_an_unambiguous_structure() {
        for (template, message) in [
            ("[REDACTED]", "exactly one"),
            ("{n}", "begin and end"),
            ("[{n}{reason}]", "separated"),
            ("[{n}:{reason}suffix]", "cannot occur in a reason"),
            ("[{n}:{reason}:{reason}]", "at most once"),
        ] {
            let err = ReplacementFormat::parse(template).unwrap_err().to_string();
            assert!(err.contains(message), "{template:?}: {err}");
        }
    }

    #[test]
    fn replacement_reasons_have_a_bounded_alphabet() {
        let format = ReplacementFormat::parse("[REDACTED-{n}:{reason}]").unwrap();
        assert!(format.token(1, "ruleset:github-pat").is_ok());
        assert!(format.token(1, "pii:email").is_ok());
        assert!(format.token(1, "bad]reason").is_err());
        assert!(format.token(1, "bad reason").is_err());
        assert!(format.token(0, "entropy").is_err());
    }

    #[test]
    fn allow_accepts_values() {
        let finding = finding("v");
        assert!(Allow::values(["v"]).allows(&finding));
        assert!(!Allow::values(["w"]).allows(&finding));
        assert!(!Allow::none().allows(&finding));
    }

    #[test]
    fn allow_regexes_must_match_the_whole_secret() {
        let finding = finding("EMP-123456");
        assert!(Allow::regexes([r"EMP-\d{6}"]).unwrap().allows(&finding));
        assert!(Allow::regexes([r"EMP-\d+"]).unwrap().allows(&finding));
        assert!(!Allow::regexes([r"EMP-\d{3}"]).unwrap().allows(&finding));
        assert!(!Allow::regexes([r"\d{6}"]).unwrap().allows(&finding));
        assert!(Allow::regexes([".*"]).unwrap().allows(&finding));
    }

    #[test]
    fn allow_regexes_match_across_lines() {
        assert!(Allow::regexes(["a.b"]).unwrap().allows(&finding("a\nb")));
    }

    #[test]
    fn invalid_allow_regex_does_not_echo_the_pattern() {
        let err = Allow::regexes(["sk-live-SECRET("]).unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");
    }

    #[test]
    fn merges_overlapping_and_adjacent_ranges() {
        let value = "0123456789abcdef";
        let merged = merged(
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
        let merged = merged("0123456789", vec![d(0..3, "short"), d(0..6, "long")]);
        assert_eq!(merged, vec![d(0..6, "long")]);
    }

    #[test]
    fn snaps_to_char_boundaries_and_drops_ranges_inside_tokens() {
        let t = token(&ReplacementFormat::default(), 1, "d").unwrap();
        let value = format!("é {t}");
        let token_range = 3..value.len();
        let merged = merged(
            &value,
            vec![d(1..2, "x"), d(token_range, "y"), d(3..value.len(), "z")],
        );
        assert_eq!(merged, vec![d(0..2, "x")]);
    }
}
