//! Redact secrets and personal data from text and structured files.
//!
//! Each redacted value is replaced with a token of the form
//! `[REDACTION|<detector>|<len>|<key>]`, where `len` is the secret's length in
//! bytes and `key` is the BLAKE3 hash of a salt followed by the secret (see
//! [`redaction_key`]). Keys are stable for a given salt, so a false positive
//! can be let through by key ([`Allow::keys`]) without writing the value down,
//! or by value ([`Allow::values`]).
//!
//! Structured formats (JSON, JSONL, YAML, TOML, XML, HCL, INI, dotenv, Java
//! properties, CSV, binary plists) are parsed so that only values are
//! redacted. Keys, comments, and formatting are preserved.
//!
//! ```
//! use stripsecret::{Allow, FormatHint, Redactor, redaction_key};
//!
//! let redactor = Redactor::builder().salt("my-team").build();
//! let input = br#"{"db_password": "hunter2", "note": "hello"}"#;
//!
//! let redaction = redactor.redact(input, FormatHint::Name("json")).unwrap();
//! let key = redaction_key(b"my-team", "hunter2");
//! assert_eq!(redaction.findings()[0].key, key);
//!
//! let output = redaction.render(&Allow::none()).unwrap();
//! let expected = format!(
//!     r#"{{"db_password": "[REDACTION|credential-key|7|{key}]", "note": "hello"}}"#
//! );
//! assert_eq!(output, expected.as_bytes());
//!
//! // Let that secret through.
//! assert_eq!(redaction.render(&Allow::keys([&key])).unwrap(), input);
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
pub use render::{
    Allow, DEFAULT_SALT, TOKEN_PREFIX, find_tokens, is_redaction_token, redaction_key, token,
    token_key,
};
