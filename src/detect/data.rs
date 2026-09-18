//! The detection data that would otherwise be hardcoded: which keys are
//! skipped, which look sensitive, which values are placeholders.
//!
//! The sections of [`Config`] spell this out; [`DetectionData`] is the
//! compiled, validated form the detectors hold. Every
//! fallible step — compiling a pattern, rejecting a list entry that could
//! never match — happens in [`DetectionData::compile`], so building a
//! [`Redactor`](crate::Redactor) afterwards cannot fail.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde::Deserialize;

use crate::Error;
use crate::config::Config;

/// Which values are scanned at all.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PolicyConfig {
    /// Key suffixes that are skipped, compared in lowercase.
    pub skip_key_suffixes: Vec<String>,
    /// Keys skipped by exact lowercase name.
    pub skip_keys: Vec<String>,
    pub skip_object: SkipObjectConfig,
    pub credential_context: CredentialContextConfig,
}

/// Objects skipped by the value of one of their fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SkipObjectConfig {
    /// The field to look at, compared exactly as the document spells it.
    pub key: String,
    /// Skip when the field's value starts with one of these.
    pub prefixes: Vec<String>,
    /// Skip when the field's value is one of these.
    pub values: Vec<String>,
}

/// The vocabulary that identifies an object as connection settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CredentialContextConfig {
    pub host_keys: Vec<String>,
    pub user_keys: Vec<String>,
}

/// Thresholds and key vocabulary for entropy detection.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct EntropyConfig {
    pub threshold: f64,
    pub sensitive_threshold: f64,
    pub min_token_length: usize,
    /// Single lowercase words marking a key as holding a secret.
    pub sensitive_segments: Vec<String>,
    /// Key names that merely look sensitive and keep the ordinary threshold.
    pub structural_keys: Vec<String>,
    pub hex_digest_lengths: Vec<usize>,
}

/// Values that look like credentials but are not.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PlaceholderConfig {
    /// Compared in lowercase, so entries must be lowercase.
    pub values: Vec<String>,
    /// One string, one character per masking character.
    pub mask_characters: String,
    pub mask_min_length: usize,
    pub bracket_min_length: usize,
}

/// Credentials identified by prefix and length alone.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProvidersConfig {
    pub token_patterns: Vec<String>,
}

/// Compiled detection data. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct DetectionData {
    inner: Arc<Compiled>,
}

#[derive(Debug)]
pub(crate) struct Compiled {
    pub policy: CompiledPolicy,
    pub entropy: CompiledEntropy,
    pub placeholder: CompiledPlaceholder,
    pub provider_patterns: Vec<Regex>,
    pub email_allowlist: Vec<String>,
    pub allow_signatures: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct CompiledPolicy {
    pub skip_key_suffixes: Vec<String>,
    pub skip_keys: HashSet<String>,
    pub skip_object_key: String,
    pub skip_object_prefixes: Vec<String>,
    pub skip_object_values: HashSet<String>,
    pub host_keys: HashSet<String>,
    pub user_keys: HashSet<String>,
}

#[derive(Debug)]
pub(crate) struct CompiledEntropy {
    pub threshold: f64,
    pub sensitive_threshold: f64,
    pub token: Regex,
    pub sensitive_segments: HashSet<String>,
    pub structural_keys: Vec<String>,
    pub hex_digest_lengths: Vec<usize>,
}

#[derive(Debug)]
pub(crate) struct CompiledPlaceholder {
    pub values: HashSet<String>,
    pub mask_characters: Vec<u8>,
    pub mask_min_length: usize,
    pub bracket_min_length: usize,
}

impl DetectionData {
    /// Validate and compile the detection data of `config`.
    pub fn compile(config: &Config) -> Result<Self, Error> {
        let policy = &config.policy;
        let entropy = &config.entropy;
        let placeholder = &config.placeholder;

        // An empty suffix or prefix matches everything, which would skip the
        // whole document without reporting anything.
        check_no_empty(&policy.skip_key_suffixes, "policy.skip-key-suffixes")?;
        check_no_empty(&policy.skip_keys, "policy.skip-keys")?;
        check_no_empty(&policy.skip_object.prefixes, "policy.skip-object.prefixes")?;
        check_no_empty(&placeholder.values, "placeholder.values")?;

        // Segments are compared against one `_`-delimited piece of a key, so
        // an entry containing `_` could never match.
        for segment in &entropy.sensitive_segments {
            if segment.contains('_') || segment.is_empty() {
                return Err(Error::Config(format!(
                    "entropy.sensitive-segments: {segment:?} is not a single word, \
                     so it can never match a key segment"
                )));
            }
        }
        check_no_empty(&entropy.structural_keys, "entropy.structural-keys")?;

        // `{0,}` and `{1,}` make the token pattern match at every position.
        if entropy.min_token_length < 2 {
            return Err(Error::Config(
                "entropy.min-token-length must be at least 2".into(),
            ));
        }

        Ok(Self {
            inner: Arc::new(Compiled {
                policy: CompiledPolicy {
                    skip_key_suffixes: lowercased(&policy.skip_key_suffixes),
                    skip_keys: lowercased(&policy.skip_keys).into_iter().collect(),
                    skip_object_key: policy.skip_object.key.clone(),
                    skip_object_prefixes: policy.skip_object.prefixes.clone(),
                    skip_object_values: policy.skip_object.values.iter().cloned().collect(),
                    host_keys: normalized(&policy.credential_context.host_keys),
                    user_keys: normalized(&policy.credential_context.user_keys),
                },
                entropy: CompiledEntropy {
                    threshold: entropy.threshold,
                    sensitive_threshold: entropy.sensitive_threshold,
                    token: token_regex(entropy.min_token_length)?,
                    sensitive_segments: lowercased(&entropy.sensitive_segments)
                        .into_iter()
                        .collect(),
                    structural_keys: lowercased(&entropy.structural_keys),
                    hex_digest_lengths: entropy.hex_digest_lengths.clone(),
                },
                placeholder: CompiledPlaceholder {
                    values: lowercased(&placeholder.values).into_iter().collect(),
                    mask_characters: placeholder.mask_characters.bytes().collect(),
                    mask_min_length: placeholder.mask_min_length,
                    bracket_min_length: placeholder.bracket_min_length,
                },
                provider_patterns: compile_patterns(&config.providers.token_patterns)?,
                email_allowlist: lowercased(&config.pii.email_allowlist),
                allow_signatures: config.ruleset.allow_signatures.clone(),
            }),
        })
    }

    /// The data built into this binary.
    pub fn builtin() -> &'static DetectionData {
        static DATA: LazyLock<DetectionData> = LazyLock::new(|| {
            DetectionData::compile(Config::builtin()).expect("the built-in configuration is valid")
        });
        &DATA
    }

    pub(crate) fn get(&self) -> &Compiled {
        &self.inner
    }
}

/// The candidate-token pattern. `/` is excluded so a whole file path is not
/// treated as one token; high-entropy segments are still found individually.
fn token_regex(min_length: usize) -> Result<Regex, Error> {
    Regex::new(&format!(r"[A-Za-z0-9+_=-]{{{min_length},}}")).map_err(|_| {
        Error::Config(format!(
            "entropy.min-token-length: {min_length} does not make a valid pattern"
        ))
    })
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>, Error> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|err| Error::InvalidPattern {
                name: "providers.token-patterns".into(),
                message: crate::detect::describe_regex_error(&err),
            })
        })
        .collect()
}

fn check_no_empty(values: &[String], field: &str) -> Result<(), Error> {
    if values.iter().any(|v| v.is_empty()) {
        return Err(Error::Config(format!(
            "{field}: an empty entry matches everything"
        )));
    }
    Ok(())
}

fn lowercased(values: &[String]) -> Vec<String> {
    values.iter().map(|v| v.to_lowercase()).collect()
}

fn normalized(values: &[String]) -> HashSet<String> {
    values
        .iter()
        .map(|v| super::credential::normalize_key(v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::builtin().clone()
    }

    #[test]
    fn builtin_compiles() {
        let data = DetectionData::builtin().get();
        assert_eq!(data.entropy.threshold, 4.5);
        assert_eq!(data.entropy.sensitive_threshold, 3.5);
        assert_eq!(data.entropy.token.as_str(), r"[A-Za-z0-9+_=-]{10,}");
        assert_eq!(data.entropy.hex_digest_lengths, [32, 40, 64]);
        assert_eq!(data.provider_patterns.len(), 2);
        assert!(data.policy.skip_keys.contains("cwd"));
        assert!(data.policy.host_keys.contains("data_source"));
        assert!(data.placeholder.values.contains("changeme"));
        assert_eq!(data.placeholder.mask_characters, b"*x.-");
    }

    #[test]
    fn empty_entries_are_rejected() {
        let mut cfg = config();
        cfg.policy.skip_key_suffixes.push(String::new());
        let err = DetectionData::compile(&cfg).unwrap_err().to_string();
        assert!(err.contains("matches everything"), "{err}");
    }

    #[test]
    fn multi_word_sensitive_segments_are_rejected() {
        let mut cfg = config();
        cfg.entropy.sensitive_segments.push("api_key".into());
        let err = DetectionData::compile(&cfg).unwrap_err().to_string();
        assert!(err.contains("single word"), "{err}");
    }

    #[test]
    fn a_tiny_min_token_length_is_rejected() {
        let mut cfg = config();
        cfg.entropy.min_token_length = 1;
        let err = DetectionData::compile(&cfg).unwrap_err().to_string();
        assert!(err.contains("at least 2"), "{err}");
    }

    #[test]
    fn an_invalid_provider_pattern_is_rejected_without_echoing_it() {
        let mut cfg = config();
        cfg.providers.token_patterns.push("sk-SECRET(".into());
        let err = DetectionData::compile(&cfg).unwrap_err().to_string();
        assert!(err.contains("token-patterns"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
    }
}
