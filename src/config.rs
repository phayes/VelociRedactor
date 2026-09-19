//! The configuration: everything Veloci Redactor knows, as data.
//!
//! A [`Config`] says which values are looked at ([`policy`](Config::policy)),
//! which of them are documentation rather than secrets
//! ([`placeholder`](Config::placeholder)), which detectors run and what each
//! one is told ([`detectors`](Config::detectors)), which input formats are
//! recognized ([`formats`](Config::formats)), how a redacted secret is written
//! back ([`replacement`](Config::replacement)), and what to spare whatever
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
//! veloci config show > my-config.yml
//! ```
//!
//! The CLI reads that file from `--config`, then `$VELOCIREDACTOR_CONFIG`,
//! then a `veloci.yml` discovered by walking from the current
//! directory, then the built-in configuration.
//!
//! The sections that decide what is scanned are required for that reason:
//! omitting one would otherwise mean an empty list, which weakens redaction
//! without saying so.
//!
//! Relative paths inside `detectors` — a `ruleset` file — are resolved
//! against the directory of the file they were read from, so a configuration
//! can be moved around with the rules it names.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::Deserialize;

use crate::agent::AgentConfig;
use crate::detect::{DetectorEntry, PlaceholderConfig, Placeholders};
use crate::files::{FileGlobs, FileKeyPaths};
use crate::format::{self, FormatRegistry};
use crate::policy::{ConfigPolicy, PolicyConfig};
use crate::{Allow, Error, Redactor, RedactorBuilder, ReplacementFormat};

/// The configuration built into this binary.
const DEFAULT_CONFIG: &str = include_str!("../default_config.yml");

/// Everything Veloci Redactor knows: what to scan, what looks for secrets in it,
/// and the rules over the result.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Scan comments as well as values, in formats that have them.
    #[serde(default)]
    pub comments: bool,
    /// How a redacted secret is written back. `{n}` is the 1-based redaction
    /// number; `{reason}` is the detector label. Defaults to
    /// [`DEFAULT_REPLACEMENT`](crate::DEFAULT_REPLACEMENT).
    #[serde(default)]
    pub replacement: ReplacementFormat,
    /// Input formats to recognize, in detection priority order. Plain text is
    /// always available whether or not it is listed.
    pub formats: Vec<String>,
    /// Which values are scanned at all.
    pub policy: PolicyConfig,
    /// Values that look like credentials but are not.
    pub placeholder: PlaceholderConfig,
    /// What looks for secrets, in the order listed. Only the enabled
    /// entries run; see [`Config::enable_detectors`].
    pub detectors: Vec<DetectorEntry>,
    /// What to leave unredacted. The last word over every detector.
    #[serde(default)]
    pub allow: AllowRules,
    /// Files AI coding agents must read redacted. Absent until a project
    /// chooses them.
    #[serde(default)]
    pub agent: Option<AgentConfig>,
}

/// Values, patterns, key paths, and files that survive redaction.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowRules {
    /// Exact values.
    pub values: Vec<String>,
    /// Regular expressions a secret must match in full (Rust `regex` syntax).
    pub regexes: Vec<String>,
    /// Regular expressions matched against the whole value holding a secret;
    /// a secret lying entirely inside a match is left in place. See
    /// [`RedactorBuilder::allow_within`].
    pub within: Vec<String>,
    /// Key-path globs never scanned at all; see
    /// [`Glob::new`](crate::Glob::new).
    pub paths: Vec<String>,
    /// Path globs, relative to the directory holding the configuration, of
    /// files never redacted; see [`FileGlobs`] for the syntax.
    pub files: Vec<String>,
    /// Key paths never scanned in some files only, as
    /// `FILE#KEY.PATH`; see [`FileKeyPaths`].
    pub file_paths: Vec<String>,
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

    /// Turn on every disabled detector entry `names` picks out, by label or
    /// by detector id. Returns the names that picked out no entry at all.
    pub fn enable_detectors<'n>(&mut self, names: &'n [String]) -> Vec<&'n str> {
        let mut unmatched = Vec::new();
        for name in names {
            let mut matched = false;
            for entry in self.detectors.iter_mut().filter(|e| e.matches(name)) {
                entry.enabled = true;
                matched = true;
            }
            if !matched {
                unmatched.push(name.as_str());
            }
        }
        unmatched
    }

    /// The files this configuration never redacts, with `allow.files`
    /// relative to `base`: the directory holding the configuration.
    pub fn allowed_files(&self, base: impl Into<PathBuf>) -> FileGlobs {
        FileGlobs::new(&self.allow.files, &[] as &[String], base)
    }

    /// The key paths this configuration never scans in particular files,
    /// with `allow.file_paths` relative to `base`: the directory holding the
    /// configuration.
    pub fn allowed_file_paths(&self, base: impl Into<PathBuf>) -> Result<FileKeyPaths, Error> {
        FileKeyPaths::new(&self.allow.file_paths, base)
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

    /// Check every part of this configuration that can fail independently.
    ///
    /// The configuration must already have been parsed. Returns the problems
    /// that prevent it from being used, and the warnings [`Config::redactor`]
    /// would raise, each in the order they appear.
    pub fn validate(&self) -> (Vec<String>, Vec<String>) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let placeholders = match Placeholders::new(&self.placeholder) {
            Ok(placeholders) => Some(placeholders.with_replacement(self.replacement.clone())),
            Err(error) => {
                errors.push(error.to_string());
                None
            }
        };
        if let Err(error) = ConfigPolicy::new(&self.policy) {
            errors.push(error.to_string());
        }

        let available = FormatRegistry::default();
        for name in &self.formats {
            if !format::ALL_NAMES.contains(&name.as_str()) {
                errors.push(Error::UnknownFormat(name.clone()).to_string());
            } else if available.get(name).is_none() {
                warnings.push(format!(
                    "format {name:?} is not compiled into this build; skipping it"
                ));
            }
        }

        // A disabled entry is not built: the privacy_filter model, say, may
        // well not be downloaded, which is why it was disabled.
        if let Some(placeholders) = &placeholders {
            for detector in self.detectors.iter().filter(|e| e.enabled) {
                if let Err(error) = detector.detectors(placeholders) {
                    errors.push(error.to_string());
                }
            }
        }

        if let Err(error) = self.allow() {
            errors.push(error.to_string());
        }
        if let Err(error) = RedactorBuilder::new().allow_within(&self.allow.within) {
            errors.push(error.to_string());
        }
        if let Err(error) = self.allowed_file_paths(PathBuf::new()) {
            errors.push(error.to_string());
        }

        if self
            .agent
            .as_ref()
            .is_some_and(|agent| agent.protected.is_empty())
        {
            warnings.push("the agent section protects no files".to_owned());
        }

        (errors, warnings)
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
        let placeholders =
            Placeholders::new(&self.placeholder)?.with_replacement(self.replacement.clone());
        let mut builder = builder
            .policy(ConfigPolicy::new(&self.policy)?)
            .comments(self.comments)
            .replacement(self.replacement.clone())
            .allow_paths(&self.allow.paths)
            .allow_within(&self.allow.within)?;

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

        for detector in self.detectors.iter().filter(|e| e.enabled) {
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
    #[cfg(feature = "json")]
    use crate::FormatHint;
    #[cfg(feature = "json")]
    use crate::detect::PathConfig;
    use crate::detect::{DetectorConfig, RegexConfig};

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
        assert_eq!(config.replacement.as_str(), crate::DEFAULT_REPLACEMENT);
        assert!(config.allow.values.is_empty());
        assert!(config.allow.regexes.is_empty());
        assert!(config.allow.within.is_empty());
        assert!(config.allow.paths.is_empty());
        assert!(config.allow.files.is_empty());
        assert!(config.allow.file_paths.is_empty());
    }

    /// The detectors the built-in configuration lists, which is what
    /// `Redactor::builder()` produces.
    #[test]
    fn the_builtin_configuration_lists_the_documented_detectors() {
        let names: Vec<_> = Config::builtin()
            .detectors
            .iter()
            .map(|entry| entry.config.id())
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

    #[test]
    fn an_invalid_replacement_format_is_rejected() {
        let err = Config::from_yaml(&edited(
            r#"replacement: "[REDACTED-{n}]""#,
            r#"replacement: "[REDACTED-{id}]""#,
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("{id}"), "{err}");
        assert!(err.contains("{n}"), "{err}");
    }

    #[cfg(feature = "json")]
    #[test]
    fn a_custom_replacement_format_uses_number_and_reason() {
        let config = Config::from_yaml(&edited(
            r#"replacement: "[REDACTED-{n}]""#,
            r#"replacement: "[{n}:{reason}]""#,
        ))
        .unwrap();
        let out = redact(&config, r#"{"db_password":"hunter2","note":"ACME-0000"}"#);
        assert_eq!(
            out,
            r#"{"db_password":"[1:credential_key]","note":"ACME-0000"}"#
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn the_builtin_configuration_redacts_like_the_default_redactor() {
        let input = r#"{"api_key":"sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA","id":"x"}"#;
        let (redactor, warnings) = Config::builtin().redactor().unwrap();
        assert_eq!(warnings, missing_format_warnings());

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
        config.detectors.push(
            DetectorConfig::Path(PathConfig {
                paths: vec!["**.customer".into()],
            })
            .into(),
        );
        config.detectors.push(
            DetectorConfig::Regex(RegexConfig {
                patterns: vec!["ACME-[0-9]{4}".into()],
            })
            .into(),
        );

        let out = redact(
            &config,
            r#"{"customer":"Jane","note":"ACME-1234","build":{"key":"hunter2"}}"#,
        );
        assert_eq!(
            out,
            r#"{"customer":"[REDACTED-1]","note":"[REDACTED-2]","build":{"key":"hunter2"}}"#
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

    #[test]
    fn the_builtin_configuration_chooses_no_agent_files() {
        assert!(Config::builtin().agent.is_none());
    }

    /// The commented-out `agent` section, uncommented, parses as shown.
    #[test]
    fn the_documented_agent_section_parses() {
        let source = Config::builtin_source();
        let start = source.find("# agent:").expect("the example is documented");
        let example: String = source[start..]
            .lines()
            .map(|line| line.strip_prefix("# ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        let config = Config::from_yaml(&format!("{source}\n{example}\n")).unwrap();
        let agent = config.agent.as_ref().expect("the section is present");
        assert_eq!(agent.protected, [".env*", "*.pem", "secrets/"]);
        assert_eq!(agent.exclude, [".env.example"]);
        assert!(!agent.enforce);
        let (errors, warnings) = config.validate();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(warnings, missing_format_warnings(), "none of its own");
    }

    #[test]
    fn an_agent_section_protecting_nothing_is_a_warning() {
        let config = Config::from_yaml(&format!(
            "{}\nagent:\n  enforce: true\n",
            Config::builtin_source()
        ))
        .unwrap();
        let (errors, warnings) = config.validate();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(warnings.iter().any(|w| w.contains("agent")), "{warnings:?}");
    }

    #[test]
    fn unknown_agent_keys_are_rejected() {
        let err = Config::from_yaml(&format!(
            "{}\nagent:\n  protect: [.env]\n",
            Config::builtin_source()
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("protect"), "{err}");
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

    /// The commented-out `privacy_filter` entry, uncommented, parses to the
    /// defaults it claims to show.
    #[cfg(feature = "privacy-filter")]
    #[test]
    fn the_documented_privacy_filter_entry_is_the_default() {
        use crate::detect::PrivacyFilterConfig;

        let source = Config::builtin_source();
        let start = source.find("  # - privacy_filter:").unwrap();
        let entry: String = source[start..]
            .lines()
            .take_while(|l| !l.is_empty())
            .map(|l| l.replacen("  # ", "  ", 1) + "\n")
            .collect();
        let config = Config::from_yaml(&edited("  - credential_key\n", &entry)).unwrap();
        let Some(DetectorConfig::PrivacyFilter(documented)) =
            config.detectors.last().map(|e| &e.config)
        else {
            panic!("expected a privacy_filter entry in:\n{entry}");
        };
        let default = PrivacyFilterConfig::default();
        assert_eq!(
            documented.model_dir.as_deref(),
            Some(Path::new("./privacy-filter"))
        );
        assert_eq!(documented.device, default.device);
        assert_eq!(documented.context, default.context);
        assert_eq!(documented.min_score, default.min_score);
        assert_eq!(documented.categories, default.categories);
        assert_eq!(documented.max_tokens, default.max_tokens);

        // And the bare name is a complete entry.
        let config =
            Config::from_yaml(&edited("  - credential_key\n", "  - privacy_filter\n")).unwrap();
        assert!(matches!(
            config.detectors.last().map(|e| &e.config),
            Some(DetectorConfig::PrivacyFilter(c)) if c.model_dir.is_none()
        ));
    }

    /// A disabled entry is read but never built, so a disabled
    /// privacy_filter whose model is not downloaded is no problem until it
    /// is turned on.
    #[cfg(feature = "privacy-filter")]
    #[test]
    fn a_disabled_detector_is_not_built_until_enabled() {
        let mut config = Config::from_yaml(&edited(
            "  - credential_key\n",
            "  - privacy_filter:\n      enabled: false\n      model_dir: /nonexistent\n",
        ))
        .unwrap();
        let (errors, _) = config.validate();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(config.redactor().is_ok());

        assert!(
            config
                .enable_detectors(&["privacy_filter".into()])
                .is_empty()
        );
        let (errors, _) = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("privacy_filter")),
            "{errors:?}"
        );
    }

    #[cfg(not(feature = "privacy-filter"))]
    #[test]
    fn privacy_filter_without_the_feature_says_so() {
        let err = Config::from_yaml(&edited(
            "  - credentialed_uri",
            "  - privacy_filter:\n      model_dir: m",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("`privacy-filter` feature"), "{err}");
    }

    #[test]
    fn an_unknown_format_is_rejected() {
        let mut config = Config::builtin().clone();
        config.formats.push("jsn".into());
        let err = config
            .redactor()
            .err()
            .expect("a format Veloci Redactor does not know is an error")
            .to_string();
        assert!(err.contains("jsn"), "{err}");
    }

    #[test]
    fn validate_accepts_the_builtin_configuration() {
        let (errors, warnings) = Config::builtin().validate();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(warnings, missing_format_warnings());
    }

    #[test]
    fn validate_reports_independent_problems_together() {
        let mut config = Config::builtin().clone();
        config.formats.push("jsn".into());
        config.detectors.push(
            DetectorConfig::Regex(RegexConfig {
                patterns: vec!["unclosed(".into()],
            })
            .into(),
        );
        config.allow.regexes.push("unclosed(".into());
        config.allow.within.push("unclosed(".into());

        let (errors, _) = config.validate();
        assert!(errors.iter().any(|e| e.contains("jsn")), "{errors:?}");
        assert!(
            errors.iter().any(|e| e.contains("does not compile")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("allow-regex")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("allow-within")),
            "{errors:?}"
        );
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

    /// What the built-in configuration warns about in this build: each format
    /// it lists that the build was made without.
    fn missing_format_warnings() -> Vec<String> {
        let available = FormatRegistry::default();
        Config::builtin()
            .formats
            .iter()
            .filter(|name| available.get(name).is_none())
            .map(|name| format!("format {name:?} is not compiled into this build; skipping it"))
            .collect()
    }

    /// The built-in configuration with one line swapped for another.
    fn edited(from: &str, to: &str) -> String {
        let source = Config::builtin_source();
        assert!(source.contains(from), "{from:?} is no longer in the file");
        source.replacen(from, to, 1)
    }
}
