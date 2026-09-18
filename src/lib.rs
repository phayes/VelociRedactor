//! Redact secrets and personal data from text and structured files.
//!
//! Each redacted value is replaced with a token `REDACTION-N`, where `N`
//! numbers distinct secrets in order of first appearance. Equal values share
//! a number. A false positive can be let through by value
//! ([`Allow::values`]).
//!
//! Structured formats (JSON, JSONL, YAML, TOML, XML, HCL, INI, dotenv, Java
//! properties, CSV, binary plists) are parsed so that only values are
//! redacted. Keys, comments, and formatting are preserved. [`FormatHint::Raw`]
//! skips that parsing and treats the whole input as plain text.
//!
//! ```
//! use stripsecret::{Allow, FormatHint, Redactor};
//!
//! let redactor = Redactor::builder().build();
//! let input = br#"{"db_password": "hunter2", "note": "hello"}"#;
//!
//! let redaction = redactor.redact(input, FormatHint::Name("json")).unwrap();
//! assert_eq!(redaction.findings()[0].id, 1);
//! assert_eq!(redaction.findings()[0].token(), "REDACTION-1");
//!
//! let output = redaction.render(&Allow::none()).unwrap();
//! assert_eq!(
//!     output,
//!     br#"{"db_password": "REDACTION-1", "note": "hello"}"#
//! );
//!
//! // Let that secret through.
//! assert_eq!(redaction.render(&Allow::values(["hunter2"])).unwrap(), input);
//! ```
//!
//! # Extending
//!
//! - [`detect::Detector`] adds detection logic.
//! - [`format::Format`] adds a file format.
//! - [`policy::LeafPolicy`] changes which structured values are scanned.

pub mod detect;
mod error;
pub mod format;
pub mod policy;
mod redactor;
mod render;

pub use error::{Error, FormatError};
pub use redactor::{Finding, FormatHint, Redaction, Redactor, RedactorBuilder};
pub use render::{Allow, TOKEN_PREFIX, find_tokens, is_redaction_token, token};
