use regex::Regex;
use serde::Deserialize;

use super::{Detection, Detector, LeafContext};
use crate::Error;

/// The `regex` detector's settings.
///
/// One entry compiles one detector per pattern. List `regex` as many times as
/// you like, each with its own entry `label`, to keep unrelated groups of
/// patterns apart:
///
/// ```yaml
/// - regex:
///     label: provider_token
///     patterns:
///       - 'sb_secret_[A-Za-z0-9_-]{20,}'
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegexConfig {
    /// Rust `regex` syntax. Every match of every pattern is redacted.
    pub patterns: Vec<String>,
}

impl RegexConfig {
    /// Compile one detector per pattern, each reporting as `regex`.
    pub fn detectors(&self) -> Result<Vec<RegexDetector>, Error> {
        self.patterns
            .iter()
            .map(|pattern| RegexDetector::new("regex", pattern))
            .collect()
    }
}

/// Redacts every match of a user-supplied regular expression.
#[derive(Debug, Clone)]
pub struct RegexDetector {
    name: String,
    regex: Regex,
}

impl RegexDetector {
    /// Compile `pattern` (Rust `regex` syntax). `name` is shown in reports.
    ///
    /// Compile errors deliberately omit the pattern text, since a pattern may
    /// itself contain the secret it is meant to redact.
    pub fn new(name: impl Into<String>, pattern: &str) -> Result<Self, Error> {
        let name = name.into();
        let regex = Regex::new(pattern).map_err(|err| Error::InvalidPattern {
            name: name.clone(),
            message: describe_regex_error(&err),
        })?;
        Ok(Self { name, regex })
    }

    /// Return the compiled regular expression used by this detector.
    pub fn regex(&self) -> &Regex {
        &self.regex
    }
}

impl Detector for RegexDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in self.regex.find_iter(value) {
            if !m.is_empty() {
                out.push(Detection::new(m.range(), &self.name));
            }
        }
    }
}

pub(crate) fn describe_regex_error(err: &regex::Error) -> String {
    match err {
        regex::Error::CompiledTooBig(_) => "pattern is too large".into(),
        _ => "pattern does not compile".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_matches() {
        let d = RegexDetector::new("employee-id", r"EMP-\d{6}").unwrap();
        let mut out = Vec::new();
        d.detect(
            "id EMP-123456 and EMP-654321",
            &LeafContext::default(),
            &mut out,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].label, "employee-id");
    }

    #[test]
    fn invalid_pattern_error_does_not_echo_pattern() {
        let err = RegexDetector::new("bad", "sk-live-SECRET(").unwrap_err();
        assert!(!err.to_string().contains("SECRET"));
    }
}
