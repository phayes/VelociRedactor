//! One entry of a configuration's `detectors` list, and how it is read.
//!
//! An entry is a [`DetectorConfig`] plus two settings every detector
//! accepts: whether it runs (`enabled`), and what its findings are reported
//! as (`label`). They belong to the entry rather than to any detector, so
//! they are taken out of the entry's settings while it is read, and the
//! detector's own settings type never sees them.

use std::marker::PhantomData;
use std::path::Path;

use serde::Deserialize;
use serde::de::value::{MapAccessDeserializer, MapDeserializer, StringDeserializer};
use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, Visitor};

use super::{
    DETECTOR_NAMES, Detection, Detector, DetectorConfig, DocumentValue, LeafContext, Placeholders,
};
use crate::render::{REASON_RULE, valid_reason};

/// One entry of a configuration's `detectors` list: a detector, whether it
/// runs, and what its findings are reported as.
///
/// ```yaml
/// detectors:
///   - credential_key               # no settings: a bare name
///   - regex:
///       label: provider_token      # reported as `provider_token`
///       patterns: ['sb_secret_[A-Za-z0-9_-]{20,}']
///   - privacy_filter:
///       enabled: false             # runs only when asked for by name
/// ```
#[derive(Debug, Clone)]
pub struct DetectorEntry {
    /// Whether the entry runs. A disabled entry is read and kept, but builds
    /// no detectors until [`Config::enable_detectors`] turns it on.
    ///
    /// [`Config::enable_detectors`]: crate::config::Config::enable_detectors
    pub enabled: bool,
    /// What findings are reported as, in place of the detector's
    /// [`id`](DetectorConfig::id). A detector that reports a more specific
    /// label (`ruleset:github-pat`) keeps its suffix (`mine:github-pat`).
    pub label: Option<String>,
    /// The detector, and its own settings.
    pub config: DetectorConfig,
}

impl From<DetectorConfig> for DetectorEntry {
    /// An enabled entry reported under the detector's own id.
    fn from(config: DetectorConfig) -> Self {
        Self {
            enabled: true,
            label: None,
            config,
        }
    }
}

impl DetectorEntry {
    /// What this entry's findings are reported as: its `label`, or else the
    /// detector's id.
    pub fn label(&self) -> &str {
        self.label.as_deref().unwrap_or(self.config.id())
    }

    /// Whether `name` picks out this entry: its label or its detector's id.
    pub fn matches(&self, name: &str) -> bool {
        name == self.label() || name == self.config.id()
    }

    /// Build this entry's detectors, reporting under its label. Whether the
    /// entry is enabled is the caller's to check.
    pub fn detectors(
        &self,
        placeholders: &Placeholders,
    ) -> Result<Vec<Box<dyn Detector>>, crate::Error> {
        let detectors = self.config.detectors(placeholders)?;
        let id = self.config.id();
        Ok(match &self.label {
            Some(label) if label != id => detectors
                .into_iter()
                .map(|inner| {
                    Box::new(Relabeled {
                        inner,
                        id,
                        label: label.clone(),
                    }) as Box<dyn Detector>
                })
                .collect(),
            _ => detectors,
        })
    }

    /// Resolve the file paths this entry names against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        self.config.resolve_paths(base);
    }
}

/// A detector whose findings are reported under another label.
struct Relabeled {
    inner: Box<dyn Detector>,
    /// The label prefix the inner detector reports.
    id: &'static str,
    label: String,
}

impl Relabeled {
    /// Swap `id` for `label` at the front of each of `detections`, keeping a
    /// more specific suffix such as `:github-pat`.
    fn relabel(&self, detections: &mut [Detection]) {
        for detection in detections {
            if let Some(rest) = detection.label.strip_prefix(self.id)
                && (rest.is_empty() || rest.starts_with(':'))
            {
                detection.label = format!("{}{rest}", self.label);
            }
        }
    }
}

impl Detector for Relabeled {
    fn name(&self) -> &str {
        &self.label
    }

    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let start = out.len();
        self.inner.detect(value, ctx, out);
        self.relabel(&mut out[start..]);
    }

    fn document_scope(&self) -> bool {
        self.inner.document_scope()
    }

    fn detect_document(
        &self,
        values: &[DocumentValue<'_>],
        out: &mut [Vec<Detection>],
    ) -> Result<(), crate::Error> {
        // `out` already holds what earlier detectors found; leave it alone.
        let starts: Vec<usize> = out.iter().map(Vec::len).collect();
        self.inner.detect_document(values, out)?;
        for (out, start) in out.iter_mut().zip(starts) {
            self.relabel(&mut out[start..]);
        }
        Ok(())
    }
}

/// A detector entry is a bare name when it takes no settings, and a map of
/// one name to its settings when it does.
///
/// Written by hand rather than derived because serde's own external tagging
/// spells a variant as a YAML tag (`!entropy`), because naming the detector
/// in the error is worth far more here than the derive saves, and because
/// `enabled` and `label` sit among the detector's settings without being any
/// of them.
impl<'de> Deserialize<'de> for DetectorEntry {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(EntryVisitor)
    }
}

struct EntryVisitor;

/// The detectors that take settings, and so cannot be written as a bare name.
const CONFIGURED: [&str; 6] = ["entropy", "ruleset", "regex", "value", "path", "pii:email"];

#[cfg(not(feature = "privacy-filter"))]
const PRIVACY_FILTER_MISSING: &str = "the privacy_filter detector is not compiled into this build \
     (it needs the `privacy-filter` feature)";

fn unknown_detector<E: de::Error>(name: &str) -> E {
    E::custom(format!(
        "unknown detector {name:?} (expected one of {})",
        DETECTOR_NAMES.join(", ")
    ))
}

/// The detector `name` names when written without settings.
fn bare<E: de::Error>(name: &str) -> Result<DetectorConfig, E> {
    match name {
        "credentialed_uri" => Ok(DetectorConfig::CredentialedUri),
        "connection_string" => Ok(DetectorConfig::ConnectionString),
        "credential_assignment" => Ok(DetectorConfig::CredentialAssignment),
        "credential_key" => Ok(DetectorConfig::CredentialKey),
        "pii:phone" => Ok(DetectorConfig::PiiPhone),
        "pii:address" => Ok(DetectorConfig::PiiAddress),
        #[cfg(feature = "privacy-filter")]
        "privacy_filter" => Ok(DetectorConfig::PrivacyFilter(Box::default())),
        #[cfg(not(feature = "privacy-filter"))]
        "privacy_filter" => Err(E::custom(PRIVACY_FILTER_MISSING)),
        name if CONFIGURED.contains(&name) => Err(E::custom(format!(
            "the {name} detector needs settings: write `{name}:` and indent them under it"
        ))),
        other => Err(unknown_detector(other)),
    }
}

impl<'de> Visitor<'de> for EntryVisitor {
    type Value = DetectorEntry;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a detector name, or a map of one detector name to its settings")
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<Self::Value, E> {
        bare(name).map(DetectorEntry::from)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;

        let Some(name) = map.next_key::<String>()? else {
            return Err(A::Error::custom("an empty map names no detector"));
        };
        let (meta, config) = match name.as_str() {
            "entropy" => settings(&mut map, DetectorConfig::Entropy)?,
            "ruleset" => settings(&mut map, DetectorConfig::Ruleset)?,
            "regex" => settings(&mut map, DetectorConfig::Regex)?,
            "value" => settings(&mut map, DetectorConfig::Value)?,
            "path" => settings(&mut map, DetectorConfig::Path)?,
            "pii:email" => settings(&mut map, DetectorConfig::PiiEmail)?,
            #[cfg(feature = "privacy-filter")]
            "privacy_filter" => settings(&mut map, |config| {
                DetectorConfig::PrivacyFilter(Box::new(config))
            })?,
            #[cfg(not(feature = "privacy-filter"))]
            "privacy_filter" => return Err(A::Error::custom(PRIVACY_FILTER_MISSING)),
            // A detector that takes no settings, written as a map to give it
            // `enabled` or `label`, or as `- name:` with nothing under it.
            other => {
                let config = bare(other)?;
                settings(&mut map, |NoSettings {}| config)?
            }
        };
        if map.next_key::<String>()?.is_some() {
            return Err(A::Error::custom(format!(
                "{name}: each entry of `detectors` names one detector; \
                 start the next one with its own `-`"
            )));
        }
        Ok(DetectorEntry {
            enabled: meta.enabled.unwrap_or(true),
            label: meta.label,
            config,
        })
    }
}

/// The settings of a detector that takes none.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoSettings {}

/// The settings every entry accepts, whichever detector it names.
#[derive(Default)]
struct Meta {
    enabled: Option<bool>,
    label: Option<String>,
}

/// Read the value under a detector's name: its `T` settings, with the entry's
/// own settings taken out first.
fn settings<'de, A: MapAccess<'de>, T: Deserialize<'de>>(
    map: &mut A,
    wrap: impl FnOnce(T) -> DetectorConfig,
) -> Result<(Meta, DetectorConfig), A::Error> {
    let (meta, settings) = map.next_value_seed(Settings(PhantomData))?;
    Ok((meta, wrap(settings)))
}

/// A detector's settings, read as a `T` and the entry's [`Meta`].
struct Settings<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for Settings<T> {
    type Value = (Meta, T);

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for Settings<T> {
    type Value = (Meta, T);

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the detector's settings")
    }

    /// `- name:` with nothing under it: no settings, so every one takes its
    /// default, and a required one is reported missing.
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        let empty = MapDeserializer::<_, E>::new(std::iter::empty::<(String, String)>());
        Ok((Meta::default(), T::deserialize(empty)?))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        let mut meta = Meta::default();
        let settings = T::deserialize(MapAccessDeserializer::new(StripMeta {
            inner: map,
            meta: &mut meta,
        }))?;
        Ok((meta, settings))
    }
}

/// A detector's settings map with `enabled` and `label` taken out into
/// `meta`, so the detector's own type, which may deny unknown fields, never
/// sees them. Values pass straight through, keeping their error positions.
struct StripMeta<'m, A> {
    inner: A,
    meta: &'m mut Meta,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for StripMeta<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        use serde::de::Error;

        while let Some(key) = self.inner.next_key::<String>()? {
            match key.as_str() {
                "enabled" => {
                    let enabled = self.inner.next_value()?;
                    if self.meta.enabled.replace(enabled).is_some() {
                        return Err(A::Error::duplicate_field("enabled"));
                    }
                }
                "label" => {
                    let label: String = self.inner.next_value()?;
                    if !valid_reason(&label) {
                        return Err(A::Error::custom(format!(
                            "label {label:?}: a label {REASON_RULE}"
                        )));
                    }
                    if self.meta.label.replace(label).is_some() {
                        return Err(A::Error::duplicate_field("label"));
                    }
                }
                _ => {
                    let key: StringDeserializer<A::Error> = key.into_deserializer();
                    return seed.deserialize(key).map(Some);
                }
            }
        }
        Ok(None)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, A::Error> {
        self.inner.next_value_seed(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(yaml: &str) -> Result<DetectorEntry, String> {
        serde_yaml_ng::from_str(yaml).map_err(|e| e.to_string())
    }

    #[test]
    fn a_bare_name_is_enabled_under_its_id() {
        let entry = entry("credential_key").unwrap();
        assert!(entry.enabled);
        assert_eq!(entry.label, None);
        assert_eq!(entry.label(), "credential_key");
    }

    #[test]
    fn a_detector_without_settings_takes_enabled_and_label() {
        let entry = entry("pii:phone: {enabled: false, label: phone}").unwrap();
        assert!(!entry.enabled);
        assert_eq!(entry.label(), "phone");
        assert!(matches!(entry.config, DetectorConfig::PiiPhone));

        let entry = self::entry("pii:phone:").unwrap();
        assert!(entry.enabled);
    }

    #[test]
    fn a_detector_without_settings_rejects_any_other() {
        let err = entry("credential_key: {nonsense: 1}").unwrap_err();
        assert!(err.contains("nonsense"), "{err}");
    }

    #[test]
    fn enabled_and_label_sit_among_a_detectors_settings() {
        let entry =
            entry("regex:\n  enabled: false\n  label: acme\n  patterns: ['ACME-[0-9]{4}']\n")
                .unwrap();
        assert!(!entry.enabled);
        assert_eq!(entry.label(), "acme");
        let DetectorConfig::Regex(regex) = &entry.config else {
            panic!("{entry:?}");
        };
        assert_eq!(regex.patterns, ["ACME-[0-9]{4}"]);
    }

    #[test]
    fn a_detectors_own_settings_still_deny_unknown_fields() {
        let err = entry("entropy:\n  enabled: true\n  thresold: 4.5\n").unwrap_err();
        assert!(err.contains("thresold"), "{err}");
    }

    #[test]
    fn empty_settings_are_the_defaults_or_name_what_is_missing() {
        let entry = entry("pii:email:").unwrap();
        assert!(matches!(&entry.config, DetectorConfig::PiiEmail(e) if e.allowlist.is_empty()));

        let err = self::entry("entropy:").unwrap_err();
        assert!(err.contains("missing field"), "{err}");
    }

    #[test]
    fn a_label_must_be_a_valid_reason() {
        let err = entry("credential_key: {label: 'two words'}").unwrap_err();
        assert!(err.contains("two words"), "{err}");
    }

    #[test]
    fn enabled_may_be_given_once() {
        let err = entry("regex:\n  enabled: true\n  patterns: []\n  enabled: false\n").unwrap_err();
        assert!(err.contains("enabled"), "{err}");
    }

    #[test]
    fn an_entry_matches_its_label_and_its_id() {
        let entry = entry("regex: {label: acme, patterns: []}").unwrap();
        assert!(entry.matches("acme"));
        assert!(entry.matches("regex"));
        assert!(!entry.matches("entropy"));
    }

    fn detections(entry: &DetectorEntry, value: &str) -> Vec<String> {
        let placeholders =
            Placeholders::new(&crate::config::Config::builtin().placeholder).unwrap();
        let mut out = Vec::new();
        for detector in entry.detectors(&placeholders).unwrap() {
            detector.detect(value, &LeafContext::default(), &mut out);
        }
        out.into_iter().map(|d| d.label).collect()
    }

    #[test]
    fn findings_are_reported_under_the_label() {
        let entry = entry("regex: {label: acme, patterns: ['ACME-[0-9]{4}']}").unwrap();
        assert_eq!(detections(&entry, "id ACME-1234"), ["acme"]);

        let entry = self::entry("regex: {patterns: ['ACME-[0-9]{4}']}").unwrap();
        assert_eq!(detections(&entry, "id ACME-1234"), ["regex"]);
    }

    #[test]
    fn relabelling_keeps_a_specific_suffix_and_only_touches_its_own() {
        let relabeled = Relabeled {
            inner: Box::new(crate::detect::PhoneDetector),
            id: "ruleset",
            label: "mine".into(),
        };
        let mut found = vec![
            Detection::new(0..1, "ruleset:github-pat"),
            Detection::new(0..1, "ruleset"),
            Detection::new(0..1, "rulesetx"),
        ];
        relabeled.relabel(&mut found);
        let labels: Vec<_> = found.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(labels, ["mine:github-pat", "mine", "rulesetx"]);

        // What earlier detectors found is left alone.
        let mut out = vec![vec![Detection::new(0..1, "ruleset")]];
        let values = [DocumentValue {
            value: "",
            ctx: LeafContext::default(),
        }];
        relabeled.detect_document(&values, &mut out).unwrap();
        assert_eq!(out[0][0].label, "ruleset");
    }
}
