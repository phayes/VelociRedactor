use std::sync::LazyLock;

use regex::Regex;

use super::placeholder::Placeholders;
use super::{Detection, Detector, LeafContext};

/// A URL whose userinfo includes a password, such as
/// `postgres://user:pass@host/db` or `redis://:pass@host/0`.
///
/// Group 1 is the password alone. The user name cannot contain `:` and the
/// password cannot contain `@`, so the two are unambiguous even though the
/// password itself may contain `:`.
static CREDENTIALED_URI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?-u:\b)[a-z][a-z0-9+.-]{1,31}://[^\s/?#@"'`<>:]*:([^\s/?#@"'`<>]+)@[^\s"'`<>]+"#,
    )
    .unwrap()
});

/// Detects URLs with embedded passwords. Such passwords often have moderate
/// entropy and no vendor-specific format, so other detectors miss them.
///
/// The whole URL is reported, since the host and user name beside a real
/// password are usually sensitive too. URLs whose password is a placeholder
/// are ignored, as decided by `placeholders`: `postgres://user:${PGPASS}@db/x`
/// and `redis://:<password>@host/0` are documentation, not credentials.
#[derive(Debug, Clone, Default)]
pub struct CredentialedUriDetector {
    placeholders: Placeholders,
}

impl CredentialedUriDetector {
    pub fn new(placeholders: &Placeholders) -> Self {
        Self {
            placeholders: placeholders.clone(),
        }
    }
}

impl Detector for CredentialedUriDetector {
    fn name(&self) -> &str {
        "credentialed-uri"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for caps in CREDENTIALED_URI.captures_iter(value) {
            let (uri, [password]) = caps.extract();
            if self.placeholders.has_real_value(password) {
                let start = caps.get(0).expect("group 0 always participates").start();
                out.push(Detection::new(start..start + uri.len(), self.name()));
            }
        }
    }
}
