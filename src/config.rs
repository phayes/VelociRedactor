//! The configuration: everything stripsecret knows, as data.
//!
//! A [`Config`] holds the detection data (which keys are skipped, which look
//! sensitive, which values are placeholders) together with the rules layered
//! on top (what to always redact, what to never redact). The one built into
//! the binary is [`Config::builtin`].
//!
//! A configuration read from a file **replaces** the built-in one. Nothing is
//! merged and nothing is inherited, so the way to write one is to start from a
//! copy:
//!
//! ```text
//! stripsecret config > my-config.yml
//! ```
//!
//! The detection sections are required for that reason: omitting one would
//! otherwise mean an empty list, which weakens redaction without saying so.
//!
//! Relative paths in `ruleset.path` and `rules-packs` are resolved against the
//! directory of the file they were read from, so a configuration can be moved
//! around with the rules it names.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::Deserialize;

use crate::detect::{
    DetectionData, EntropyConfig, Pack, Pii, PlaceholderConfig, PolicyConfig, ProvidersConfig,
    RegexDetector, RulesetDetector, ValueDetector, load_pack_dir,
};
use crate::{Allow, Error, Redactor, RedactorBuilder};

/// The configuration built into this binary.
const DEFAULT_CONFIG: &str = include_str!("../default_config.yml");

/// Everything stripsecret knows: detection data plus the rules over it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Scan comments as well as values, in formats that have them.
    #[serde(default)]
    pub comments: bool,
    /// Which values are scanned at all.
    pub policy: PolicyConfig,
    /// Thresholds and key vocabulary for entropy detection.
    pub entropy: EntropyConfig,
    /// Values that look like credentials but are not.
    pub placeholder: PlaceholderConfig,
    /// Credentials identified by prefix and length alone.
    pub providers: ProvidersConfig,
    /// Personal data.
    pub pii: PiiConfig,
    /// The bundled ruleset and how to override it.
    pub ruleset: RulesetConfig,
    /// Switching detection off.
    #[serde(default)]
    pub detectors: DetectorsConfig,
    /// Rule pack files, or directories of packs.
    #[serde(default)]
    pub rules_packs: Vec<PathBuf>,
    /// What to leave unredacted. The last word over everything else.
    #[serde(default)]
    pub allow: Rules,
    /// What to redact whatever it contains.
    #[serde(default)]
    pub disallow: Rules,
}

/// Personal data: which categories to redact, and which addresses are
/// automation rather than people.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PiiConfig {
    #[serde(default)]
    pub categories: Vec<Pii>,
    pub email_allowlist: Vec<String>,
}

/// The betterleaks/gitleaks ruleset.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RulesetConfig {
    /// Comments marking a line as intentionally containing a secret.
    pub allow_signatures: Vec<String>,
    /// A ruleset to use instead of the bundled one.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// Detectors to switch off.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct DetectorsConfig {
    /// Globs matching detector names or the labels they report.
    pub exclude: Vec<String>,
}

/// Values, patterns, and key paths that a rule applies to.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Exact values.
    pub values: Vec<String>,
    /// Regular expressions (Rust `regex` syntax).
    pub regexes: Vec<String>,
    /// Key-path globs; see [`Glob::new`](crate::Glob::new).
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

    /// Resolve the relative rule paths in this configuration against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        let resolve = |path: &PathBuf| {
            if path.is_relative() {
                base.join(path)
            } else {
                path.clone()
            }
        };
        self.ruleset.path = self.ruleset.path.as_ref().map(&resolve);
        self.rules_packs = self.rules_packs.iter().map(resolve).collect();
    }

    /// The secrets this configuration leaves in place.
    pub fn allow(&self) -> Result<Allow, Error> {
        Allow::values(self.allow.values.iter().cloned()).with_regexes(&self.allow.regexes)
    }

    /// Build the redactor, along with any warnings raised while loading rule
    /// packs.
    pub fn redactor(&self) -> Result<(Redactor, Vec<String>), Error> {
        let mut warnings = Vec::new();
        let data = DetectionData::compile(self)?;

        // From an empty builder, not `Redactor::builder()`, which would add a
        // second copy of every built-in detector and keep the built-in
        // vocabulary in the slots this one wants to fill.
        let mut builder = RedactorBuilder::new()
            .defaults_from(&data)
            .pii(self.pii.categories.iter().copied())
            .comments(self.comments)
            .allow_paths(&self.allow.paths)
            .disallow_paths(&self.disallow.paths)
            .exclude_detectors(&self.detectors.exclude);

        if let Some(path) = &self.ruleset.path {
            builder = builder.ruleset(RulesetDetector::from_path(path)?.with_data(&data));
        }
        for pattern in &self.disallow.regexes {
            builder = builder.detector(RegexDetector::new("regex", pattern)?);
        }
        let values = ValueDetector::new(&self.disallow.values)?;
        if !values.is_empty() {
            builder = builder.detector(values);
        }
        for path in &self.rules_packs {
            for pack in load_packs(path, &mut warnings)? {
                let (detectors, pack_warnings) = pack.detectors();
                warnings.extend(pack_warnings);
                for detector in detectors {
                    builder = builder.detector(detector);
                }
            }
        }
        Ok((builder.build(), warnings))
    }
}

/// Load a pack file, or every pack in a directory.
fn load_packs(path: &Path, warnings: &mut Vec<String>) -> Result<Vec<Pack>, Error> {
    if path.is_dir() {
        let loaded = load_pack_dir(path)?;
        warnings.extend(loaded.warnings);
        return Ok(loaded.packs);
    }
    let source = fs::read_to_string(path)
        .map_err(|e| Error::Pack(format!("reading {}: {e}", path.display())))?;
    Ok(vec![Pack::parse(&source, path)?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FormatHint;

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
        assert!(config.pii.categories.is_empty());
        assert!(config.detectors.exclude.is_empty());
        assert!(config.rules_packs.is_empty());
        assert!(config.ruleset.path.is_none());
        for rules in [&config.allow, &config.disallow] {
            assert!(rules.values.is_empty());
            assert!(rules.regexes.is_empty());
            assert!(rules.paths.is_empty());
        }
    }

    #[test]
    fn the_builtin_configuration_redacts_like_the_default_redactor() {
        let input = r#"{"api_key":"sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA","id":"x"}"#;
        let (redactor, warnings) = Config::builtin().redactor().unwrap();
        assert!(warnings.is_empty());

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

    #[test]
    fn rules_apply_on_top_of_the_builtin_detection_data() {
        let mut config = Config::builtin().clone();
        config.allow.paths = vec!["build.**".into()];
        config.disallow.paths = vec!["**.customer".into()];
        config.disallow.regexes = vec!["ACME-[0-9]{4}".into()];

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
    fn a_missing_detection_section_is_an_error() {
        let err = Config::from_yaml("allow:\n  values: [x]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy"), "{err}");

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
    fn an_unknown_pii_category_is_rejected() {
        let err = Config::from_yaml(&edited("categories: []", "categories: [nope]"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown PII"), "{err}");
    }

    /// The built-in configuration with one line swapped for another.
    fn edited(from: &str, to: &str) -> String {
        let source = Config::builtin_source();
        assert!(source.contains(from), "{from:?} is no longer in the file");
        source.replacen(from, to, 1)
    }
}
