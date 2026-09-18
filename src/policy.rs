//! Rules for which values in structured data are scanned at all.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use serde::Deserialize;

use crate::Error;
use crate::config::Config;
use crate::detect::credential_key_normalize;
use crate::format::Object;

/// Decides which parts of a structured document are scanned.
///
/// Values under a skipped key or inside a skipped object are never redacted.
pub trait LeafPolicy: Send + Sync {
    /// Whether values stored under `key` (including nested containers) are skipped.
    fn skip_key(&self, key: &str) -> bool;

    /// Whether an entire object is skipped.
    fn skip_object(&self, object: &Object<'_>) -> bool;

    /// Whether an object describes connection settings, so that a bare
    /// `password` key inside it (or its descendants) is treated as sensitive.
    fn credential_context(&self, object: &Object<'_>) -> bool;
}

/// The `policy` section of a configuration.
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
///
/// The field name and its value are both compared ignoring ASCII case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SkipObjectConfig {
    /// The field to look at.
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

/// The default policy: the one from the configuration built into the binary.
///
/// It skips values that are structural and high-entropy by nature, which
/// would otherwise be redacted by entropy detection and break the document:
///
/// - keys ending in `id` or `ids` (identifiers, UUIDs, hashes);
/// - keys ending in `signature` (cryptographic signatures, such as the
///   thinking-block signatures in LLM transcripts, which must survive intact
///   for the transcript to be replayed);
/// - path-like keys: `path`, `file_path`, `filepath`, `cwd`, `root`, `dir`,
///   `directory`;
/// - objects whose `type` starts with `image`, or is `base64` (inline image
///   and binary payloads), with the key and value matched ignoring case.
///
/// Objects that have both a host-like key (`host`, `server`, `address`, ...)
/// and a user-like key (`user`, `username`, `uid`, ...) are treated as
/// connection settings.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPolicy;

impl LeafPolicy for DefaultPolicy {
    fn skip_key(&self, key: &str) -> bool {
        ConfigPolicy::builtin().skip_key(key)
    }

    fn skip_object(&self, object: &Object<'_>) -> bool {
        ConfigPolicy::builtin().skip_object(object)
    }

    fn credential_context(&self, object: &Object<'_>) -> bool {
        ConfigPolicy::builtin().credential_context(object)
    }
}

#[derive(Debug)]
struct Compiled {
    skip_key_suffixes: Vec<String>,
    skip_keys: HashSet<String>,
    skip_object_key: String,
    skip_object_prefixes: Vec<String>,
    /// A list rather than a set: the entries are compared ignoring case, and
    /// there are only ever a handful of them.
    skip_object_values: Vec<String>,
    host_keys: HashSet<String>,
    user_keys: HashSet<String>,
}

/// A policy driven by the `policy` section of a configuration. Cloning is
/// cheap.
///
/// [`DefaultPolicy`] is this one, built from the configuration compiled into
/// the binary.
#[derive(Debug, Clone)]
pub struct ConfigPolicy {
    inner: Arc<Compiled>,
}

impl ConfigPolicy {
    /// Validate and compile `config`.
    pub fn new(config: &PolicyConfig) -> Result<Self, Error> {
        // An empty suffix or prefix matches every key, which would skip the
        // whole document without reporting anything.
        check_no_empty(&config.skip_key_suffixes, "policy.skip-key-suffixes")?;
        check_no_empty(&config.skip_keys, "policy.skip-keys")?;
        check_no_empty(&config.skip_object.prefixes, "policy.skip-object.prefixes")?;

        Ok(Self {
            inner: Arc::new(Compiled {
                skip_key_suffixes: lowercased(&config.skip_key_suffixes),
                skip_keys: lowercased(&config.skip_keys).into_iter().collect(),
                skip_object_key: config.skip_object.key.clone(),
                skip_object_prefixes: config.skip_object.prefixes.clone(),
                skip_object_values: config.skip_object.values.clone(),
                // Normalized with the function `credential_context` compares
                // with, which is not the one `skip_key` compares with.
                host_keys: normalized(&config.credential_context.host_keys),
                user_keys: normalized(&config.credential_context.user_keys),
            }),
        })
    }

    /// The policy from the configuration built into the binary.
    pub fn builtin() -> &'static ConfigPolicy {
        static POLICY: LazyLock<ConfigPolicy> = LazyLock::new(|| {
            ConfigPolicy::new(&Config::builtin().policy)
                .expect("the built-in configuration is valid")
        });
        &POLICY
    }
}

impl Default for ConfigPolicy {
    fn default() -> Self {
        Self::builtin().clone()
    }
}

impl LeafPolicy for ConfigPolicy {
    fn skip_key(&self, key: &str) -> bool {
        // Only lowercased, deliberately: `file-path` and `file path` are not
        // the same key as `file_path` here, unlike in `credential_context`.
        let lower = key.to_lowercase();
        self.inner.skip_keys.contains(&lower)
            || self
                .inner
                .skip_key_suffixes
                .iter()
                .any(|suffix| lower.ends_with(suffix))
    }

    fn skip_object(&self, object: &Object<'_>) -> bool {
        // Both the key and the value are matched ignoring case: a document
        // may write `"Type": "Image"` as readily as `"type": "image"`.
        object
            .get_str(&self.inner.skip_object_key)
            .is_some_and(|value| {
                self.inner
                    .skip_object_values
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(value))
                    || self
                        .inner
                        .skip_object_prefixes
                        .iter()
                        .any(|prefix| starts_with_ignoring_case(value, prefix))
            })
    }

    fn credential_context(&self, object: &Object<'_>) -> bool {
        let (mut host, mut user) = (false, false);
        for key in object.keys() {
            let key = credential_key_normalize(key);
            host |= self.inner.host_keys.contains(&key);
            user |= self.inner.user_keys.contains(&key);
            if host && user {
                return true;
            }
        }
        false
    }
}

/// A policy that scans every value.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanAll;

impl LeafPolicy for ScanAll {
    fn skip_key(&self, _key: &str) -> bool {
        false
    }

    fn skip_object(&self, _object: &Object<'_>) -> bool {
        false
    }

    fn credential_context(&self, _object: &Object<'_>) -> bool {
        false
    }
}

/// Whether `value` begins with `prefix`, ignoring ASCII case.
fn starts_with_ignoring_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn check_no_empty(values: &[String], field: &str) -> Result<(), Error> {
    if values.iter().any(String::is_empty) {
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
    values.iter().map(|v| credential_key_normalize(v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_keys() {
        let p = DefaultPolicy;
        for key in [
            "id",
            "ID",
            "userId",
            "session_id",
            "toolUseIds",
            "ids",
            "signature",
            "thinkingSignature",
            "filepath",
            "file_path",
            "cwd",
            "root",
            "directory",
            "dir",
            "path",
            "PATH",
        ] {
            assert!(p.skip_key(key), "{key} should be skipped");
        }
        for key in [
            "content", "text", "idea", "paths", "api_key", "token", "message",
        ] {
            assert!(!p.skip_key(key), "{key} should not be skipped");
        }
    }

    #[test]
    fn skipped_objects() {
        let p = DefaultPolicy;
        let obj = |t: &'static str| Object::from_iter([("type", Some(t))]);
        assert!(p.skip_object(&obj("image")));
        assert!(p.skip_object(&obj("image_url")));
        assert!(p.skip_object(&obj("base64")));
        assert!(!p.skip_object(&obj("text")));
        assert!(!p.skip_object(&Object::from_iter([("type", None)])));

        // Neither the key nor the value is case-sensitive.
        assert!(p.skip_object(&obj("Image")));
        assert!(p.skip_object(&obj("IMAGE_URL")));
        assert!(p.skip_object(&obj("Base64")));
        assert!(p.skip_object(&Object::from_iter([("Type", Some("image"))])));
        assert!(p.skip_object(&Object::from_iter([("TYPE", Some("BASE64"))])));
        assert!(!p.skip_object(&Object::from_iter([("Type", Some("text"))])));
    }

    #[test]
    fn credential_objects() {
        let p = DefaultPolicy;
        let keys = |ks: &[&'static str]| ks.iter().map(|k| (*k, None)).collect::<Object<'_>>();
        assert!(p.credential_context(&keys(&["host", "user", "password"])));
        assert!(p.credential_context(&keys(&["Data Source", "User-Id", "pwd"])));
        assert!(!p.credential_context(&keys(&["host", "password"])));
        assert!(!p.credential_context(&keys(&["user", "password"])));
    }

    #[test]
    fn an_empty_suffix_is_rejected() {
        let mut config = Config::builtin().policy.clone();
        config.skip_key_suffixes.push(String::new());
        let err = ConfigPolicy::new(&config).unwrap_err().to_string();
        assert!(err.contains("matches everything"), "{err}");
    }

    #[test]
    fn skipped_keys_come_from_the_configuration() {
        let mut config = Config::builtin().policy.clone();
        config.skip_key_suffixes.retain(|s| s != "id");
        let policy = ConfigPolicy::new(&config).unwrap();
        assert!(!policy.skip_key("session_id"));
        assert!(policy.skip_key("cwd"));
    }
}
