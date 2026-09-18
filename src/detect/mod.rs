//! Secret and PII detectors.
//!
//! A [`Detector`] looks at one value at a time and reports the byte ranges it
//! considers sensitive. Implement it and register it with
//! [`RedactorBuilder::detector`](crate::RedactorBuilder::detector) to add
//! your own detection logic.
//!
//! Which detectors run, and what each one is told, is configuration: the
//! `detectors` list of a [`Config`](crate::config::Config) is a list of
//! [`DetectorConfig`], and each entry names one of the detectors below.

use std::ops::Range;
use std::path::Path;

use serde::Deserialize;

mod connstr;
mod credential;
mod entropy;
mod path;
mod pii;
mod placeholder;
mod regex;
mod ruleset;
mod uri;
mod value;

pub use connstr::ConnectionStringDetector;
pub(crate) use credential::normalize_key as credential_key_normalize;
pub use credential::{CredentialAssignmentDetector, CredentialKeyDetector};
pub use entropy::{EntropyConfig, EntropyDetector, shannon_entropy};
pub use path::{PathConfig, PathDetector};
pub use pii::{AddressDetector, EmailConfig, EmailDetector, PhoneDetector};
pub use placeholder::{PlaceholderConfig, Placeholders, is_placeholder};
pub(crate) use regex::describe_regex_error;
pub use regex::{RegexConfig, RegexDetector};
pub use ruleset::{BETTERLEAKS_RULESET, RuleSource, RulesetConfig, RulesetDetector};
pub use uri::CredentialedUriDetector;
pub use value::{ValueConfig, ValueDetector};

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

/// One entry of a configuration's `detectors` list: which detector to run,
/// and what to tell it.
///
/// In YAML a detector that takes settings is a single-key map and one that
/// takes none is a bare name:
///
/// ```yaml
/// detectors:
///   - entropy:
///       threshold: 4.5
///       # ...
///   - credentialed-uri
/// ```
#[derive(Debug, Clone)]
pub enum DetectorConfig {
    /// [`EntropyDetector`]
    Entropy(EntropyConfig),
    /// [`RulesetDetector`]
    Ruleset(RulesetConfig),
    /// A [`RegexDetector`] per pattern, all under one label.
    Regex(RegexConfig),
    /// [`ValueDetector`]
    Value(ValueConfig),
    /// [`PathDetector`]
    Path(PathConfig),
    /// [`CredentialedUriDetector`]
    CredentialedUri,
    /// [`ConnectionStringDetector`]
    ConnectionString,
    /// [`CredentialAssignmentDetector`]
    CredentialAssignment,
    /// [`CredentialKeyDetector`]
    CredentialKey,
    /// [`EmailDetector`]
    PiiEmail(EmailConfig),
    /// [`PhoneDetector`]
    PiiPhone,
    /// [`AddressDetector`]
    PiiAddress,
}

/// Build a one-detector list, or an empty one when `skip`.
fn boxed_unless(skip: bool, detector: impl Detector + 'static) -> Vec<Box<dyn Detector>> {
    if skip {
        Vec::new()
    } else {
        vec![Box::new(detector)]
    }
}

/// Every detector name a configuration may use, in the order the built-in
/// configuration lists them.
pub const DETECTOR_NAMES: &[&str] = &[
    "entropy",
    "ruleset",
    "regex",
    "value",
    "path",
    "credentialed-uri",
    "connection-string",
    "credential-assignment",
    "credential-key",
    "pii:email",
    "pii:phone",
    "pii:address",
];

/// A detector entry is a bare name when it takes no settings, and a map of
/// one name to its settings when it does.
///
/// Written by hand rather than derived because serde's own external tagging
/// spells a variant as a YAML tag (`!entropy`), and because naming the
/// detector in the error is worth far more here than the derive saves.
impl<'de> Deserialize<'de> for DetectorConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DetectorVisitor)
    }
}

struct DetectorVisitor;

/// The detectors that take settings, and so cannot be written as a bare name.
const CONFIGURED: [&str; 6] = ["entropy", "ruleset", "regex", "value", "path", "pii:email"];

fn unknown_detector<E: serde::de::Error>(name: &str) -> E {
    E::custom(format!(
        "unknown detector {name:?} (expected one of {})",
        DETECTOR_NAMES.join(", ")
    ))
}

impl<'de> serde::de::Visitor<'de> for DetectorVisitor {
    type Value = DetectorConfig;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a detector name, or a map of one detector name to its settings")
    }

    fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<Self::Value, E> {
        match name {
            "credentialed-uri" => Ok(DetectorConfig::CredentialedUri),
            "connection-string" => Ok(DetectorConfig::ConnectionString),
            "credential-assignment" => Ok(DetectorConfig::CredentialAssignment),
            "credential-key" => Ok(DetectorConfig::CredentialKey),
            "pii:phone" => Ok(DetectorConfig::PiiPhone),
            "pii:address" => Ok(DetectorConfig::PiiAddress),
            name if CONFIGURED.contains(&name) => Err(E::custom(format!(
                "the {name} detector needs settings: write `{name}:` and indent them under it"
            ))),
            other => Err(unknown_detector(other)),
        }
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;

        let Some(name) = map.next_key::<String>()? else {
            return Err(A::Error::custom("an empty map names no detector"));
        };
        let detector = match name.as_str() {
            "entropy" => DetectorConfig::Entropy(map.next_value()?),
            "ruleset" => DetectorConfig::Ruleset(map.next_value()?),
            "regex" => DetectorConfig::Regex(map.next_value()?),
            "value" => DetectorConfig::Value(map.next_value()?),
            "path" => DetectorConfig::Path(map.next_value()?),
            "pii:email" => DetectorConfig::PiiEmail(map.next_value()?),
            // A detector that takes no settings, written `- name:` with
            // nothing under it.
            other => {
                let detector = self.visit_str(other)?;
                map.next_value::<serde::de::IgnoredAny>()?;
                detector
            }
        };
        if map.next_key::<String>()?.is_some() {
            return Err(A::Error::custom(format!(
                "{name}: each entry of `detectors` names one detector; \
                 start the next one with its own `-`"
            )));
        }
        Ok(detector)
    }
}

impl DetectorConfig {
    /// The name this entry is written under, which is also the name the
    /// detectors it builds report themselves as.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Entropy(_) => "entropy",
            Self::Ruleset(_) => "ruleset",
            Self::Regex(_) => "regex",
            Self::Value(_) => "value",
            Self::Path(_) => "path",
            Self::CredentialedUri => "credentialed-uri",
            Self::ConnectionString => "connection-string",
            Self::CredentialAssignment => "credential-assignment",
            Self::CredentialKey => "credential-key",
            Self::PiiEmail(_) => "pii:email",
            Self::PiiPhone => "pii:phone",
            Self::PiiAddress => "pii:address",
        }
    }

    /// Build this entry's detectors.
    ///
    /// `placeholders` is the configuration's shared vocabulary of values that
    /// look like credentials but are not. Entries that do not consult it
    /// ignore the argument.
    pub fn detectors(
        &self,
        placeholders: &Placeholders,
    ) -> Result<Vec<Box<dyn Detector>>, crate::Error> {
        Ok(match self {
            Self::Entropy(config) => vec![Box::new(EntropyDetector::new(config)?)],
            Self::Ruleset(config) => vec![Box::new(RulesetDetector::new(config, placeholders)?)],
            Self::Regex(config) => config
                .detectors()?
                .into_iter()
                .map(|d| Box::new(d) as Box<dyn Detector>)
                .collect(),
            Self::Value(config) => {
                let detector = ValueDetector::new(&config.values)?;
                // An empty list would otherwise add a detector that can never
                // match, and show up in reports as one that ran.
                boxed_unless(detector.is_empty(), detector)
            }
            Self::Path(config) => {
                let detector = PathDetector::new(&config.paths);
                boxed_unless(detector.is_empty(), detector)
            }
            Self::CredentialedUri => vec![Box::new(CredentialedUriDetector::new(placeholders))],
            Self::ConnectionString => vec![Box::new(ConnectionStringDetector::new(placeholders))],
            Self::CredentialAssignment => {
                vec![Box::new(CredentialAssignmentDetector::new(placeholders))]
            }
            Self::CredentialKey => vec![Box::new(CredentialKeyDetector::new(placeholders))],
            Self::PiiEmail(config) => vec![Box::new(EmailDetector::new(config))],
            Self::PiiPhone => vec![Box::new(PhoneDetector)],
            Self::PiiAddress => vec![Box::new(AddressDetector)],
        })
    }

    /// Resolve the file paths this entry names against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        if let Self::Ruleset(config) = self {
            for source in &mut config.rules {
                if let RuleSource::Path(path) = source
                    && path.is_relative()
                {
                    *path = base.join(&*path);
                }
            }
        }
    }
}
