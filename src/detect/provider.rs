use super::data::DetectionData;
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
/// Detects provider tokens with fixed prefixes.
#[derive(Debug, Clone)]
pub struct ProviderTokenDetector {
    data: DetectionData,
}

impl ProviderTokenDetector {
    pub fn new(data: &DetectionData) -> Self {
        Self { data: data.clone() }
    }
}

impl Default for ProviderTokenDetector {
    fn default() -> Self {
        Self::new(DetectionData::builtin())
    }
}

impl Detector for ProviderTokenDetector {
    fn name(&self) -> &str {
        "provider-token"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for pattern in &self.data.get().provider_patterns {
            for m in pattern.find_iter(value) {
                out.push(Detection::new(m.range(), self.name()));
            }
        }
    }
}
