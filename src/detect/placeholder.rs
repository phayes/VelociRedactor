use std::sync::LazyLock;

use regex::Regex;

use super::data::DetectionData;
use crate::render::is_redaction_token;

/// Lowercase words joined by `-` or `_`. Digits, capitals, and other
/// characters are excluded so `<hunter2>` or `<RealPassword>` still count as
/// secrets.
static BRACKETED_INTERIOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z_-]*$").unwrap());

/// Whether a credential-shaped value is obviously not a real secret.
///
/// Recognizes empty values, earlier redactions (including this crate's
/// `REDACTION-N` tokens), common documentation placeholders such as
/// `changeme` or `<password>`, `${VAR}` expansions, and masks such as `****`.
pub fn is_placeholder(value: &str) -> bool {
    Placeholders::builtin().is_placeholder(value)
}

/// The placeholder vocabulary from a configuration. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Placeholders {
    data: DetectionData,
}

impl Placeholders {
    pub fn new(data: &DetectionData) -> Self {
        Self { data: data.clone() }
    }

    /// The vocabulary from the configuration built into the binary.
    pub fn builtin() -> &'static Placeholders {
        static PLACEHOLDERS: LazyLock<Placeholders> =
            LazyLock::new(|| Placeholders::new(DetectionData::builtin()));
        &PLACEHOLDERS
    }

    /// Whether a credential-shaped value is obviously not a real secret.
    pub fn is_placeholder(&self, value: &str) -> bool {
        let placeholder = &self.data.get().placeholder;
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
        if placeholder.values.contains(&normalized) {
            return true;
        }
        self.is_mask(normalized.as_bytes())
    }

    /// A `<name>` placeholder such as `<password>` or `<your-db-password>`.
    /// The minimum length keeps `<a>` and `<ab>` from qualifying.
    fn is_bracketed(&self, s: &str) -> bool {
        s.len() >= self.data.get().placeholder.bracket_min_length
            && s.starts_with('<')
            && s.ends_with('>')
            && BRACKETED_INTERIOR.is_match(&s[1..s.len() - 1])
    }

    /// A run of one masking character (`***`, `xxxx`, `....`, `----`), long
    /// enough that short values like `x` are not mistaken for masks.
    fn is_mask(&self, s: &[u8]) -> bool {
        let placeholder = &self.data.get().placeholder;
        match s.split_first() {
            Some((first, rest))
                if s.len() >= placeholder.mask_min_length
                    && placeholder.mask_characters.contains(first) =>
            {
                rest.iter().all(|b| b == first)
            }
            _ => false,
        }
    }

    pub(crate) fn has_real_value(&self, value: &str) -> bool {
        !value.is_empty() && !self.is_placeholder(value)
    }
}

pub(crate) fn has_real_value(value: &str) -> bool {
    Placeholders::builtin().has_real_value(value)
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
}
