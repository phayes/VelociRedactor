use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde::Deserialize;

use crate::Error;
use crate::config::Config;
use crate::render::is_redaction_token;

/// Lowercase words joined by `-` or `_`. Digits, capitals, and other
/// characters are excluded so `<hunter2>` or `<RealPassword>` still count as
/// secrets.
static BRACKETED_INTERIOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z_-]*$").unwrap());

/// The `placeholder` section of a configuration: values that look like
/// credentials but are not.
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

/// Whether a credential-shaped value is obviously not a real secret,
/// according to the configuration built into the binary.
///
/// Recognizes empty values, earlier redactions (including this crate's
/// `REDACTION-N` tokens), common documentation placeholders such as
/// `changeme` or `<password>`, `${VAR}` expansions, and masks such as `****`.
pub fn is_placeholder(value: &str) -> bool {
    Placeholders::builtin().is_placeholder(value)
}

#[derive(Debug)]
struct Compiled {
    values: HashSet<String>,
    mask_characters: Vec<u8>,
    mask_min_length: usize,
    bracket_min_length: usize,
}

/// A compiled placeholder vocabulary. Cloning is cheap.
///
/// Every detector that reports a value because of the key or syntax around it
/// — rather than because of the value itself — checks it against one of
/// these first.
#[derive(Debug, Clone)]
pub struct Placeholders {
    inner: Arc<Compiled>,
}

impl Placeholders {
    /// Validate and compile `config`.
    pub fn new(config: &PlaceholderConfig) -> Result<Self, Error> {
        // An empty entry would be compared against every trimmed value.
        if config.values.iter().any(String::is_empty) {
            return Err(Error::Config(
                "placeholder.values: an empty entry matches everything".into(),
            ));
        }
        Ok(Self {
            inner: Arc::new(Compiled {
                values: config.values.iter().map(|v| v.to_lowercase()).collect(),
                mask_characters: config.mask_characters.bytes().collect(),
                mask_min_length: config.mask_min_length,
                bracket_min_length: config.bracket_min_length,
            }),
        })
    }

    /// The vocabulary from the configuration built into the binary.
    pub fn builtin() -> &'static Placeholders {
        static PLACEHOLDERS: LazyLock<Placeholders> = LazyLock::new(|| {
            Placeholders::new(&Config::builtin().placeholder)
                .expect("the built-in configuration is valid")
        });
        &PLACEHOLDERS
    }

    /// Whether a credential-shaped value is obviously not a real secret.
    pub fn is_placeholder(&self, value: &str) -> bool {
        let trimmed = value.trim().trim_matches(['"', '\'']);
        if trimmed.is_empty() || self.is_bracketed(trimmed) || is_redaction_token(trimmed) {
            return true;
        }
        // Both tests below see the lowercased value, which is why `XXXX` is a
        // mask and why the configured values must be lowercase.
        let normalized = trimmed.to_lowercase();
        if normalized.starts_with("${") && normalized.ends_with('}') {
            return true;
        }
        if self.inner.values.contains(&normalized) {
            return true;
        }
        self.is_mask(normalized.as_bytes())
    }

    /// A `<name>` placeholder such as `<password>` or `<your-db-password>`.
    /// The minimum length keeps `<a>` and `<ab>` from qualifying.
    fn is_bracketed(&self, s: &str) -> bool {
        s.len() >= self.inner.bracket_min_length
            && s.starts_with('<')
            && s.ends_with('>')
            && BRACKETED_INTERIOR.is_match(&s[1..s.len() - 1])
    }

    /// A run of one masking character (`***`, `xxxx`, `....`, `----`), long
    /// enough that short values like `x` are not mistaken for masks.
    fn is_mask(&self, s: &[u8]) -> bool {
        match s.split_first() {
            Some((first, rest))
                if s.len() >= self.inner.mask_min_length
                    && self.inner.mask_characters.contains(first) =>
            {
                rest.iter().all(|b| b == first)
            }
            _ => false,
        }
    }

    /// Whether `value` holds something worth redacting.
    pub fn has_real_value(&self, value: &str) -> bool {
        !value.is_empty() && !self.is_placeholder(value)
    }
}

impl Default for Placeholders {
    /// The vocabulary from the configuration built into the binary.
    fn default() -> Self {
        Self::builtin().clone()
    }
}

/// Shrink `range` to exclude one pair of matching surrounding quotes.
pub(crate) fn unquote_range(s: &str, range: std::ops::Range<usize>) -> std::ops::Range<usize> {
    let bytes = &s.as_bytes()[range.clone()];
    match bytes {
        [b'"', .., b'"'] | [b'\'', .., b'\''] if bytes.len() >= 2 => range.start + 1..range.end - 1,
        _ => range,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_placeholders() {
        for v in [
            "",
            "  ",
            "REDACTED",
            "[REDACTED]",
            "<redacted>",
            "REDACTION-1",
            "REDACTION-12",
            "changeme",
            "'changeme'",
            "\"example\"",
            "<password>",
            "<your-db-password>",
            "<your_secret>",
            "${DB_PASSWORD}",
            "***",
            "xxxx",
            "XXXX",
            "....",
            "----",
            "your_password",
            "secret_here",
        ] {
            assert!(is_placeholder(v), "{v:?} should be a placeholder");
        }
    }

    #[test]
    fn real_values_are_not_placeholders() {
        for v in [
            "hunter2",
            "<hunter2>",
            "<RealPassword>",
            "<a>",
            "<ab>",
            "**",
            "x",
            "xxy",
            "REDACTION-0",
            "xREDACTION-1",
            "[REDACTION|entropy|3|abc]",
            "s3cr3t-value",
        ] {
            assert!(!is_placeholder(v), "{v:?} should not be a placeholder");
        }
    }

    #[test]
    fn an_empty_configured_value_is_rejected() {
        let mut config = Config::builtin().placeholder.clone();
        config.values.push(String::new());
        let err = Placeholders::new(&config).unwrap_err().to_string();
        assert!(err.contains("matches everything"), "{err}");
    }

    #[test]
    fn the_vocabulary_comes_from_the_configuration() {
        let mut config = Config::builtin().placeholder.clone();
        config.values.retain(|v| v != "changeme");
        let placeholders = Placeholders::new(&config).unwrap();
        assert!(!placeholders.is_placeholder("changeme"));
        assert!(placeholders.is_placeholder("example"));
    }
}
