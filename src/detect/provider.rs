use std::sync::LazyLock;

use regex::Regex;

use super::{Detection, Detector, LeafContext};

/// Credential formats identified purely by prefix and length, independent of
/// entropy or surrounding keys, so low-entropy keys are still caught.
///
/// - `sb_secret_…`: Supabase secret API key (bypasses row-level security).
/// - `sbp_…`: Supabase personal access token.
///
/// Supabase publishable keys (`sb_publishable_…`) are meant to be embedded in
/// client code and are deliberately not matched.
///
/// The patterns are not anchored to a word boundary, so a key glued to a
/// preceding identifier (`FOO_sb_secret_…`) is still found. The cost is that
/// long identifiers that merely start with a prefix, such as
/// `sb_secret_key_rotation_handler`, are also redacted.
static PATTERNS: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [
        Regex::new(r"sb_secret_[A-Za-z0-9_-]{20,}").unwrap(),
        Regex::new(r"sbp_[a-z0-9_-]{20,}").unwrap(),
    ]
});

/// Detects provider tokens with fixed prefixes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderTokenDetector;

impl Detector for ProviderTokenDetector {
    fn name(&self) -> &str {
        "provider-token"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for pattern in PATTERNS.iter() {
            for m in pattern.find_iter(value) {
                out.push(Detection::new(m.range(), self.name()));
            }
        }
    }
}
