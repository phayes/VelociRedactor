#![doc = include_str!("../README.crate.md")]
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
pub use render::{Allow, TOKEN_PREFIX, find_tokens, is_redaction_token, token};
