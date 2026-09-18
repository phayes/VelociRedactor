//! The configuration: everything velociredactor knows, as data.
//!
//! A [`Config`] says which values are looked at ([`policy`](Config::policy)),
//! which of them are documentation rather than secrets
//! ([`placeholder`](Config::placeholder)), which detectors run and what each
//! one is told ([`detectors`](Config::detectors)), which input formats are
//! recognized ([`formats`](Config::formats)), and what to spare whatever
//! found it ([`allow`](Config::allow)). The one built into the binary is
//! [`Config::builtin`].
//!
//! There is no matching `disallow` section: always redacting a value, a
//! pattern, or a key path is what the `value`, `regex`, and `path` detectors
//! do, so it is written in `detectors` like any other detection.
//!
//! A configuration read from a file **replaces** the built-in one. Nothing is
//! merged and nothing is inherited, so the way to write one is to start from a
//! copy:
//!
//! ```text
//! velociredactor config > my-config.yml
//! ```
//!
//! The sections that decide what is scanned are required for that reason:
//! omitting one would otherwise mean an empty list, which weakens redaction
//! without saying so.
//!
//! Relative paths inside `detectors` — a `ruleset` file — are resolved
//! against the directory of the file they were read from, so a configuration
//! can be moved around with the rules it names.

use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use serde::Deserialize;

use crate::detect::{DetectorConfig, PlaceholderConfig, Placeholders};
use crate::format::{self, FormatRegistry};
use crate::policy::{ConfigPolicy, PolicyConfig};
use crate::{Allow, Error, Redactor, RedactorBuilder};

/// The configuration built into this binary.
const DEFAULT_CONFIG: &str = include_str!("../default_config.yml");

/// Everything velociredactor knows: what to scan, what looks for secrets in it,
/// and the rules over the result.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Scan comments as well as values, in formats that have them.
    #[serde(default)]
    pub comments: bool,
    /// Input formats to recognize, in detection priority order. Plain text is
    /// always available whether or not it is listed.
    pub formats: Vec<String>,
    /// Which values are scanned at all.
    pub policy: PolicyConfig,
    /// Values that look like credentials but are not.
    pub placeholder: PlaceholderConfig,
    /// What looks for secrets, in the order listed.
    pub detectors: Vec<DetectorConfig>,
    /// What to leave unredacted. The last word over every detector.
    #[serde(default)]
    pub allow: AllowRules,
}

/// Values, patterns, and key paths that survive redaction.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowRules {
    /// Exact values.
    pub values: Vec<String>,
    /// Regular expressions a secret must match in full (Rust `regex` syntax).
    pub regexes: Vec<String>,
    /// Key-path globs never scanned at all; see
    /// [`Glob::new`](crate::Glob::new).
    pub paths: Vec<String>,
}

impl Default for Config {
    /// The built-in configuration.
    fn default() -> Self {
        Self::builtin().clone()
    }
}

impl Config {
    /// The configuration built into this binary.
    pub fn builtin() -> &'static Config {
        // This initializer must do nothing but parse: anything that reaches
        // back into `builtin()` would deadlock the lock it is holding.
        static DEFAULT: LazyLock<Config> = LazyLock::new(|| {
            Config::from_yaml(DEFAULT_CONFIG).expect("the built-in configuration is valid")
        });
        &DEFAULT
    }

    /// The text of the built-in configuration, comments and all.
    pub fn builtin_source() -> &'static str {
        DEFAULT_CONFIG
    }

    /// Read a configuration from a YAML file, replacing the built-in one.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
        let mut config: Self = serde_yaml_ng::from_str(&source)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        if let Some(base) = path.parent() {
            config.resolve_paths(base);
        }
        Ok(config)
    }

    /// Parse a configuration from YAML text. Relative paths in it are left as
    /// written; [`Config::from_path`] resolves them instead.
    pub fn from_yaml(source: &str) -> Result<Self, Error> {
        serde_yaml_ng::from_str(source).map_err(|e| Error::Config(e.to_string()))
    }

    /// Resolve the relative paths this configuration names against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        for detector in &mut self.detectors {
            detector.resolve_paths(base);
        }
    }

    /// The secrets this configuration leaves in place.
    pub fn allow(&self) -> Result<Allow, Error> {
        Allow::values(self.allow.values.iter().cloned()).with_regexes(&self.allow.regexes)
    }

    /// Build the redactor this configuration describes, along with any
    /// warnings raised while loading it.
    pub fn redactor(&self) -> Result<(Redactor, Vec<String>), Error> {
        let mut warnings = Vec::new();
        // From an empty builder, never `Redactor::builder()`, which would add
        // a second copy of every detector the built-in configuration lists.
        let builder = self.apply(RedactorBuilder::new(), &mut warnings)?;
        Ok((builder.build(), warnings))
    }

    /// Add everything this configuration describes to `builder`.
    ///
    /// Problems that do not prevent redacting — a format this build lacks —
    /// are appended to `warnings` instead of returned.
    pub fn apply(
        &self,
        builder: RedactorBuilder,
        warnings: &mut Vec<String>,
    ) -> Result<RedactorBuilder, Error> {
        let placeholders = Placeholders::new(&self.placeholder)?;
        let mut builder = builder
            .policy(ConfigPolicy::new(&self.policy)?)
            .comments(self.comments)
            .allow_paths(&self.allow.paths);

        let available = FormatRegistry::default();
        for name in &self.formats {
            if !format::ALL_NAMES.contains(&name.as_str()) {
                return Err(Error::UnknownFormat(name.clone()));
            }
            match available.get(name) {
                Some(format) => builder = builder.shared_format(format),
                None => warnings.push(format!(
                    "format {name:?} is not compiled into this build; skipping it"
                )),
            }
        }

        for detector in &self.detectors {
            for detector in detector.detectors(&placeholders)? {
                builder = builder.boxed_detector(detector);
            }
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FormatHint;
    use crate::detect::{PathConfig, RegexConfig};

    #[cfg(feature = "json")]
    fn redact(config: &Config, input: &str) -> String {
        let (redactor, _) = config.redactor().unwrap();
        let redaction = redactor
            .redact(input.as_bytes(), FormatHint::Name("json"))
            .unwrap();
        String::from_utf8(redaction.render(&config.allow().unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn the_builtin_configuration_carries_no_rules() {
        let config = Config::builtin();
        assert!(!config.comments, "comments are off by default");
        assert!(config.allow.values.is_empty());
        assert!(config.allow.regexes.is_empty());
        assert!(config.allow.paths.is_empty());
    }

    /// The detectors the built-in configuration lists, which is what
    /// `Redactor::builder()` produces.
    #[test]
    fn the_builtin_configuration_lists_the_documented_detectors() {
        let names: Vec<_> = Config::builtin()
            .detectors
            .iter()
            .map(DetectorConfig::name)
            .collect();
        assert_eq!(
            names,
            [
                "entropy",
                "ruleset",
                "regex",
                "credentialed_uri",
                "connection_string",
                "credential_assignment",
                "credential_key",
            ],
            "personal data stays off by default"
        );
    }

    #[test]
    fn the_builtin_configuration_lists_every_format() {
        assert_eq!(Config::builtin().formats, format::ALL_NAMES);
    }

    #[cfg(feature = "json")]
    #[test]
    fn the_builtin_configuration_redacts_like_the_default_redactor() {
        let input = r#"{"api_key":"sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA","id":"x"}"#;
        let (redactor, warnings) = Config::builtin().redactor().unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");

        let with_config = redactor
            .redact(input.as_bytes(), FormatHint::Name("json"))
            .unwrap();
        let with_default = crate::Redactor::builder()
            .build()
            .redact(input.as_bytes(), FormatHint::Name("json"))
            .unwrap();
        assert_eq!(
            with_config.render(&Allow::none()).unwrap(),
            with_default.render(&Allow::none()).unwrap()
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn rules_apply_on_top_of_the_configured_detectors() {
        let mut config = Config::builtin().clone();
        config.allow.paths = vec!["build.**".into()];
        config.detectors.push(DetectorConfig::Path(PathConfig {
            paths: vec!["**.customer".into()],
        }));
        config.detectors.push(DetectorConfig::Regex(RegexConfig {
            patterns: vec!["ACME-[0-9]{4}".into()],
            ..RegexConfig::default()
        }));

        let out = redact(
            &config,
            r#"{"customer":"Jane","note":"ACME-1234","build":{"key":"hunter2"}}"#,
        );
        assert_eq!(
            out,
            r#"{"customer":"REDACTION-1","note":"REDACTION-2","build":{"key":"hunter2"}}"#
        );
    }

    #[test]
    fn a_missing_section_is_an_error() {
        let err = Config::from_yaml("allow:\n  values: [x]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("formats"), "{err}");

        let err = Config::from_yaml("{}").unwrap_err().to_string();
        assert!(err.contains("missing field"), "{err}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_yaml(&edited("comments: false", "nonsense: 1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nonsense"), "{err}");
    }

    #[test]
    fn an_unknown_detector_is_rejected() {
        let err = Config::from_yaml(&edited("  - credentialed_uri", "  - pii:ssn"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("pii:ssn"), "{err}");
    }

    /// A build made with fewer Cargo features still uses the built-in
    /// configuration: a format it lacks is reported and skipped.
    #[cfg(not(feature = "csv"))]
    #[test]
    fn a_format_this_build_lacks_is_a_warning_not_an_error() {
        let (_, warnings) = Config::builtin()
            .redactor()
            .expect("the built-in configuration still loads");
        assert!(warnings.iter().any(|w| w.contains("csv")), "{warnings:?}");
    }

    #[test]
    fn an_unknown_format_is_rejected() {
        let mut config = Config::builtin().clone();
        config.formats.push("jsn".into());
        let err = config
            .redactor()
            .err()
            .expect("a format velociredactor does not know is an error")
            .to_string();
        assert!(err.contains("jsn"), "{err}");
    }

    #[test]
    fn an_unknown_builtin_ruleset_is_rejected() {
        let err = Config::from_yaml(&edited(
            "        - builtin:betterleaks",
            "        - builtin:nope",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("nope"), "{err}");
    }

    /// The built-in configuration with one line swapped for another.
    fn edited(from: &str, to: &str) -> String {
        let source = Config::builtin_source();
        assert!(source.contains(from), "{from:?} is no longer in the file");
        source.replacen(from, to, 1)
    }
}
