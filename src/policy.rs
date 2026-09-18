//! Rules for which values in structured data are scanned at all.

use std::sync::LazyLock;

use crate::detect::{DetectionData, credential_key_normalize};
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

/// The default policy.
///
/// Skips values that are structural and high-entropy by nature, which would
/// otherwise be redacted by entropy detection and break the document:
///
/// - keys ending in `id` or `ids` (identifiers, UUIDs, hashes);
/// - keys ending in `signature` (cryptographic signatures, such as the
///   thinking-block signatures in LLM transcripts, which must survive intact
///   for the transcript to be replayed);
/// - path-like keys: `path`, `file_path`, `filepath`, `cwd`, `root`, `dir`,
///   `directory`;
/// - objects whose `type` starts with `image`, or is `base64`
///   (inline image and binary payloads).
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

/// A policy driven by the `policy` section of a configuration.
///
/// [`DefaultPolicy`] is this one, built from the configuration compiled into
/// the binary.
#[derive(Debug, Clone)]
pub struct ConfigPolicy {
    data: DetectionData,
}

impl ConfigPolicy {
    pub fn new(data: &DetectionData) -> Self {
        Self { data: data.clone() }
    }

    /// The policy from the configuration built into the binary.
    pub fn builtin() -> &'static ConfigPolicy {
        static POLICY: LazyLock<ConfigPolicy> =
            LazyLock::new(|| ConfigPolicy::new(DetectionData::builtin()));
        &POLICY
    }
}

impl LeafPolicy for ConfigPolicy {
    fn skip_key(&self, key: &str) -> bool {
        let policy = &self.data.get().policy;
        // Only lowercased, deliberately: `file-path` and `file path` are not
        // the same key as `file_path` here, unlike in `credential_context`.
        let lower = key.to_lowercase();
        policy.skip_keys.contains(&lower)
            || policy
                .skip_key_suffixes
                .iter()
                .any(|suffix| lower.ends_with(suffix))
    }

    fn skip_object(&self, object: &Object<'_>) -> bool {
        let policy = &self.data.get().policy;
        object
            .get_str(&policy.skip_object_key)
            .is_some_and(|value| {
                policy.skip_object_values.contains(value)
                    || policy
                        .skip_object_prefixes
                        .iter()
                        .any(|prefix| value.starts_with(prefix))
            })
    }

    fn credential_context(&self, object: &Object<'_>) -> bool {
        let policy = &self.data.get().policy;
        let (mut host, mut user) = (false, false);
        for key in object.keys() {
            let key = credential_key_normalize(key);
            host |= policy.host_keys.contains(&key);
            user |= policy.user_keys.contains(&key);
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
}
