use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde::Deserialize;

use super::{Detection, Detector, LeafContext};

/// The `pii:email` detector's settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct EmailConfig {
    /// Addresses belonging to automation rather than to a person. Empty means
    /// every address found is redacted.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?-u:\b)").unwrap()
});

/// US-style phone numbers. Dots are accepted as separators only after a `+1`
/// prefix, so version numbers (`1.234.567.8901`) and dotted IP-like strings
/// are not matched.
static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:",
        r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        r"|",
        r"(?:1[-\s])?\(\d{3}\)\s?\d{3}[-.\s]?\d{4}",
        r"|",
        r"(?:1[-\s])?\d{3}[-\s]\d{3}[-\s]\d{4}",
        r")",
    ))
    .unwrap()
});

static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Pl(?:ace)?|Way|Cir(?:cle)?|Ter(?:race)?|Pkwy|Parkway)\.?").unwrap()
});

/// Bot and no-reply addresses that are public metadata (git authors, CI
/// accounts) rather than personal data. A leading `@` matches the domain
/// suffix; a trailing `@` matches the local-part prefix.
fn is_allowlisted_email(allowlist: &[String], email: &str) -> bool {
    let lower = email.to_lowercase();
    allowlist.iter().any(|pattern| {
        if pattern.starts_with('@') {
            lower.ends_with(pattern)
        } else if pattern.ends_with('@') {
            lower.starts_with(pattern.as_str())
        } else {
            lower == *pattern
        }
    })
}

/// Detects email addresses, except the ones on its allowlist.
///
/// [`Default`] allowlists nothing, so every address found is reported. The
/// commented-out `pii:email` entry in the built-in configuration carries a
/// useful starting allowlist of bot and no-reply addresses.
#[derive(Debug, Clone, Default)]
pub struct EmailDetector {
    allowlist: Arc<[String]>,
}

impl EmailDetector {
    pub fn new(config: &EmailConfig) -> Self {
        Self {
            allowlist: config
                .allowlist
                .iter()
                .map(|a| a.to_lowercase())
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl Detector for EmailDetector {
    fn name(&self) -> &str {
        "pii:email"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in EMAIL.find_iter(value) {
            if !is_allowlisted_email(&self.allowlist, m.as_str()) {
                out.push(Detection::new(m.range(), self.name()));
            }
        }
    }
}

/// Detects US-style phone numbers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn name(&self) -> &str {
        "pii:phone"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in PHONE.find_iter(value) {
            out.push(Detection::new(m.range(), self.name()));
        }
    }
}

/// Detects US-style street addresses (`123 Main Street`).
#[derive(Debug, Clone, Copy, Default)]
pub struct AddressDetector;

impl Detector for AddressDetector {
    fn name(&self) -> &str {
        "pii:address"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in ADDRESS.find_iter(value) {
            out.push(Detection::new(m.range(), self.name()));
        }
    }
}
