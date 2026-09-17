use std::sync::LazyLock;

use regex::Regex;

use super::{Detection, Detector, LeafContext};

/// A URL whose userinfo includes a password, such as
/// `postgres://user:pass@host/db` or `redis://:pass@host/0`.
static CREDENTIALED_URI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?-u:\b)[a-z][a-z0-9+.-]{1,31}://[^\s/?#@"'`<>:]*:[^\s/?#@"'`<>]+@[^\s"'`<>]+"#,
    )
    .unwrap()
});

/// Detects URLs with embedded passwords. Such passwords often have moderate
/// entropy and no vendor-specific format, so other detectors miss them.
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialedUriDetector;

impl Detector for CredentialedUriDetector {
    fn name(&self) -> &str {
        "credentialed-uri"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in CREDENTIALED_URI.find_iter(value) {
            out.push(Detection::new(m.range(), self.name()));
        }
    }
}
