use aho_corasick::AhoCorasick;

use super::{Detection, Detector, LeafContext};
use crate::Error;

/// Redacts every occurrence of a set of literal strings.
///
/// The strings are matched anywhere in a value, so a value that merely
/// contains one is redacted in part.
#[derive(Debug, Clone)]
pub struct ValueDetector {
    matcher: Option<AhoCorasick>,
}

impl ValueDetector {
    /// Build a detector for `values`. Empty strings are ignored.
    ///
    /// Errors deliberately omit the values, which are secrets themselves.
    pub fn new(values: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self, Error> {
        let values: Vec<String> = values
            .into_iter()
            .map(|v| v.as_ref().to_owned())
            .filter(|v| !v.is_empty())
            .collect();
        if values.is_empty() {
            return Ok(Self { matcher: None });
        }
        let matcher = AhoCorasick::new(&values).map_err(|_| Error::InvalidPattern {
            name: "value".into(),
            message: "too many values to match".into(),
        })?;
        Ok(Self {
            matcher: Some(matcher),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.matcher.is_none()
    }
}

impl Detector for ValueDetector {
    fn name(&self) -> &str {
        "value"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let Some(matcher) = &self.matcher else { return };
        for m in matcher.find_iter(value) {
            out.push(Detection::new(m.range(), self.name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(detector: &ValueDetector, value: &str) -> Vec<Detection> {
        let mut out = Vec::new();
        detector.detect(value, &LeafContext::default(), &mut out);
        out
    }

    #[test]
    fn finds_every_occurrence() {
        let d = ValueDetector::new(["hunter2", "acme"]).unwrap();
        assert_eq!(
            detect(&d, "hunter2 and acme and hunter2"),
            vec![
                Detection::new(0..7, "value"),
                Detection::new(12..16, "value"),
                Detection::new(21..28, "value"),
            ]
        );
    }

    #[test]
    fn empty_list_detects_nothing() {
        let d = ValueDetector::new([""; 0]).unwrap();
        assert!(d.is_empty());
        assert!(detect(&d, "anything").is_empty());
        assert!(ValueDetector::new([""]).unwrap().is_empty());
    }
}
