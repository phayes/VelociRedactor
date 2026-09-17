//! Rules for which values in structured data are scanned at all.

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
        let lower = key.to_lowercase();
        lower.ends_with("signature")
            || lower.ends_with("id")
            || lower.ends_with("ids")
            || matches!(
                lower.as_str(),
                "filepath" | "file_path" | "cwd" | "root" | "directory" | "dir" | "path"
            )
    }

    fn skip_object(&self, object: &Object<'_>) -> bool {
        object
            .get_str("type")
            .is_some_and(|t| t.starts_with("image") || t == "base64")
    }

    fn credential_context(&self, object: &Object<'_>) -> bool {
        let (mut host, mut user) = (false, false);
        for key in object.keys() {
            match credential_key_normalize(key).as_str() {
                "host" | "hostname" | "server" | "addr" | "address" | "datasource"
                | "data_source" => host = true,
                "user" | "username" | "userid" | "user_id" | "uid" => user = true,
                _ => {}
            }
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
