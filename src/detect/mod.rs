//! Secret and PII detectors.
//!
//! A [`Detector`] looks at one value at a time and reports the byte ranges it
//! considers sensitive. Implement it and register it with
//! [`RedactorBuilder::detector`](crate::RedactorBuilder::detector) to add
//! your own detection logic.

use std::ops::Range;

mod connstr;
mod credential;
mod data;
mod entropy;
mod pack;
mod path;
mod pii;
mod placeholder;
mod provider;
mod regex;
mod ruleset;
mod uri;
mod value;

pub use connstr::ConnectionStringDetector;
pub(crate) use credential::normalize_key as credential_key_normalize;
pub use credential::{CredentialAssignmentDetector, CredentialKeyDetector};
pub use data::{
    CredentialContextConfig, DetectionData, EntropyConfig, PlaceholderConfig, PolicyConfig,
    ProvidersConfig, SkipObjectConfig,
};
pub use entropy::{EntropyDetector, shannon_entropy};
pub use pack::{
    LoadedPacks, MAX_PACK_FILE_BYTES, MAX_PACK_FILES, Pack, PackRule, PackSample, load_pack_dir,
};
pub use path::PathDetector;
pub use pii::{AddressDetector, EmailDetector, PhoneDetector, Pii};
pub use placeholder::{Placeholders, is_placeholder};
pub use provider::ProviderTokenDetector;
pub use regex::RegexDetector;
pub(crate) use regex::describe_regex_error;
pub use ruleset::RulesetDetector;
pub use uri::CredentialedUriDetector;
pub use value::ValueDetector;

/// Finds sensitive ranges within a single value.
pub trait Detector: Send + Sync {
    /// A short identifier shown in reports, such as `entropy` or `pii:email`.
    fn name(&self) -> &str;

    /// Append the byte ranges of `value` that should be redacted to `out`.
    ///
    /// Ranges may overlap and need not be sorted.
    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>);
}

/// Where a value was found.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeafContext<'a> {
    /// The key the value is stored under, if any.
    pub key: Option<&'a str>,
    /// The keys of the containing objects joined with `.`, ending in the
    /// value's own key. Empty at the root of a document, and for formats that
    /// have no keys. Array nesting adds nothing to the path.
    pub path: &'a str,
    /// Whether an enclosing object looks like connection settings (it has
    /// both a host-like and a user-like key), which makes a bare `password`
    /// key sensitive.
    pub credential_context: bool,
}

/// A sensitive byte range reported by a detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub range: Range<usize>,
    /// What found it; see [`Detector::name`]. Rule-based detectors may report
    /// a more specific label, such as the matching rule's id.
    pub label: String,
}

impl Detection {
    pub fn new(range: Range<usize>, label: impl Into<String>) -> Self {
        Self {
            range,
            label: label.into(),
        }
    }
}

/// The detectors enabled by default, using the built-in detection data:
/// everything except PII and user rules.
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    detectors_from(DetectionData::builtin())
}

/// The same detectors, taking their vocabulary from `data`.
pub fn detectors_from(data: &DetectionData) -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(EntropyDetector::from_data(data)),
        Box::new(RulesetDetector::default_rules().clone().with_data(data)),
        Box::new(ProviderTokenDetector::new(data)),
        Box::new(CredentialedUriDetector),
        Box::new(ConnectionStringDetector),
        Box::new(CredentialAssignmentDetector),
        Box::new(CredentialKeyDetector),
    ]
}
