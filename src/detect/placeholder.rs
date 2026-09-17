use std::sync::LazyLock;

use regex::Regex;

use crate::render::is_redaction_token;

/// Lowercase values that are documentation placeholders or earlier
/// redactions rather than real credentials.
const PLACEHOLDER_VALUES: &[&str] = &[
    "redacted",
    "[redacted]",
    "<redacted>",
    "changeme",
    "example",
    "placeholder",
    "your_password",
    "your_db_password",
    "your_secret",
    "secret_here",
    "password",
    "db_password",
    "secret",
    "secret_key",
    "api_key",
    "api_secret",
    "api_token",
    "api_secret_key",
];

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
    let trimmed = value.trim().trim_matches(['"', '\'']);
    if trimmed.is_empty() || is_bracketed(trimmed) || is_redaction_token(trimmed) {
        return true;
    }
    let normalized = trimmed.to_lowercase();
    if normalized.starts_with("${") && normalized.ends_with('}') {
        return true;
    }
    if PLACEHOLDER_VALUES.contains(&normalized.as_str()) {
        return true;
    }
    is_mask(normalized.as_bytes())
}

/// A `<name>` placeholder such as `<password>` or `<your-db-password>`. The
/// minimum length keeps `<a>` and `<ab>` from qualifying.
fn is_bracketed(s: &str) -> bool {
    s.len() >= 5
        && s.starts_with('<')
        && s.ends_with('>')
        && BRACKETED_INTERIOR.is_match(&s[1..s.len() - 1])
}

/// A run of one masking character (`***`, `xxxx`, `....`, `----`). At least
/// three characters, so short values like `x` are not mistaken for masks.
fn is_mask(s: &[u8]) -> bool {
    match s {
        [first @ (b'*' | b'x' | b'.' | b'-'), rest @ ..] if s.len() >= 3 => {
            rest.iter().all(|b| b == first)
        }
        _ => false,
    }
}

pub(crate) fn has_real_value(value: &str) -> bool {
    !value.is_empty() && !is_placeholder(value)
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
            "REDACTION-",
            "REDACTION-1a",
            "s3cr3t-value",
        ] {
            assert!(!is_placeholder(v), "{v:?} should not be a placeholder");
        }
    }
}
