use regex::Regex;

use super::{Detection, Detector, LeafContext};
use crate::Error;

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

fn describe_regex_error(err: &regex::Error) -> String {
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
