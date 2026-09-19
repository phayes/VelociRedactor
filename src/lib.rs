// The README's example redacts JSON, so a build without it has a summary.
#![cfg_attr(feature = "json", doc = include_str!("../README.crate.md"))]
#![cfg_attr(
    not(feature = "json"),
    doc = "Redact secrets and PII from text and structured files, with stable numbered redactions."
)]
#![deny(missing_docs)]

pub mod agent;
pub mod config;
pub mod detect;
mod error;
pub mod files;
pub mod format;
mod glob;
pub mod policy;
mod redactor;
mod render;

pub use error::{Error, FormatError};
pub use glob::Glob;
pub use redactor::{Finding, FormatHint, Redaction, Redactor, RedactorBuilder};
pub use render::{
    Allow, DEFAULT_REPLACEMENT, ReplacementFormat, find_tokens, is_redaction_token, token,
};
