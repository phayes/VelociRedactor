//! Redact secrets and personal data from text and structured files.
//!
//! Each distinct redacted value is replaced with a numbered token such as
//! `REDACTION-3`. Numbers depend only on the input and the configuration, so a
//! false positive can be let through by re-rendering with its number in an
//! [`Allow`] list without renumbering anything else.
//!
//! Structured formats (JSON, JSONL, YAML, TOML, XML, HCL, INI, dotenv, Java
//! properties, CSV, binary plists) are parsed so that only values are
//! redacted. Keys, comments, and formatting are preserved.
//!
//! ```
//! use redactify::{Allow, FormatHint, Redactor};
//!
//! let redactor = Redactor::builder().build();
//! let input = br#"{"db_password": "hunter2", "note": "hello"}"#;
//!
//! let redaction = redactor.redact(input, FormatHint::Name("json")).unwrap();
//! let output = redaction.render(&Allow::none()).unwrap();
//! assert_eq!(output, br#"{"db_password": "REDACTION-1", "note": "hello"}"#);
//!
//! // Let redaction 1 through.
//! let output = redaction.render(&Allow::ids([1])).unwrap();
//! assert_eq!(output, input);
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
pub use render::{Allow, TOKEN_PREFIX, is_redaction_token, token};
