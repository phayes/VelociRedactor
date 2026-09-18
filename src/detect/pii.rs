use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;

use super::data::DetectionData;
use super::{Detection, Detector, LeafContext};

/// Built-in categories of personally identifiable information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pii {
    Email,
    Phone,
    Address,
}

impl Pii {
    pub const ALL: [Pii; 3] = [Pii::Email, Pii::Phone, Pii::Address];

    pub fn name(self) -> &'static str {
        match self {
            Pii::Email => "email",
            Pii::Phone => "phone",
            Pii::Address => "address",
        }
    }

    /// The detector for this category, using the built-in vocabulary.
    pub fn detector(self) -> Box<dyn Detector> {
        self.detector_from(DetectionData::builtin())
    }

    /// The detector for this category, taking its vocabulary from `data`.
    pub fn detector_from(self, data: &DetectionData) -> Box<dyn Detector> {
        match self {
            Pii::Email => Box::new(EmailDetector::new(data)),
            Pii::Phone => Box::new(PhoneDetector),
            Pii::Address => Box::new(AddressDetector),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Pii {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = <String as serde::Deserialize>::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for Pii {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Pii::ALL
            .into_iter()
            .find(|p| p.name().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| {
                format!("unknown PII category {s:?} (expected email, phone, or address)")
            })
    }
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

/// Detects email addresses, except well-known bot and no-reply addresses.
#[derive(Debug, Clone)]
pub struct EmailDetector {
    data: DetectionData,
}

impl EmailDetector {
    pub fn new(data: &DetectionData) -> Self {
        Self { data: data.clone() }
    }
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self::new(DetectionData::builtin())
    }
}

impl Detector for EmailDetector {
    fn name(&self) -> &str {
        "pii:email"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for m in EMAIL.find_iter(value) {
            if !is_allowlisted_email(&self.data.get().email_allowlist, m.as_str()) {
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
