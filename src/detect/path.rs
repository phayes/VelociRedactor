use super::{Detection, Detector, LeafContext};
use crate::glob::{Glob, any_match};

/// Redacts every value whose key path matches one of a set of globs,
/// whatever the value contains.
///
/// The key path of a value is the keys of the objects containing it, joined
/// with `.`; array nesting adds nothing. See [`Glob::new`] for the pattern
/// syntax.
#[derive(Debug, Clone, Default)]
pub struct PathDetector {
    globs: Vec<Glob>,
}

impl PathDetector {
    pub fn new(patterns: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            globs: patterns
                .into_iter()
                .map(|p| Glob::new(p.as_ref()))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.globs.is_empty()
    }
}

impl Detector for PathDetector {
    fn name(&self) -> &str {
        "path"
    }

    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        if !value.is_empty() && any_match(&self.globs, ctx.path) {
            out.push(Detection::new(0..value.len(), self.name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(detector: &PathDetector, value: &str, path: &str) -> Vec<Detection> {
        let ctx = LeafContext {
            path,
            ..LeafContext::default()
        };
        let mut out = Vec::new();
        detector.detect(value, &ctx, &mut out);
        out
    }

    #[test]
    fn redacts_the_whole_value_at_a_matching_path() {
        let d = PathDetector::new(["db.*.password"]);
        assert_eq!(
            detect(&d, "plain", "db.main.password"),
            vec![Detection::new(0..5, "path")]
        );
        assert!(detect(&d, "plain", "db.main.user").is_empty());
        assert!(detect(&d, "", "db.main.password").is_empty());
    }

    #[test]
    fn no_patterns_detects_nothing() {
        assert!(detect(&PathDetector::default(), "x", "a").is_empty());
    }
}
