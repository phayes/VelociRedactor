//! Redact secrets and personal data from text and structured files.
//!
//! Each redacted value is replaced with a token `REDACTION-N`, where `N`
//! numbers distinct secrets in order of first appearance. Equal values share
//! a number. A false positive can be let through by value
//! ([`Allow::values`]) or by pattern ([`Allow::regexes`]).
//!
//! Structured formats (JSON, JSONL, YAML, TOML, XML, HCL, INI, dotenv, Java
//! properties, CSV, binary plists) are parsed so that only values are
//! redacted. Keys, comments, and formatting are preserved; comments are
//! scanned as well only on request. [`FormatHint::Raw`] skips that parsing
//! and treats the whole input as plain text.
//!
//! Everything velociredactor knows is data, not code: which keys are skipped,
//! which values are documentation placeholders, which detectors run and what
//! each one is told, which formats are recognized, and what survives whatever
//! found it. [`config::Config`] is that data, and
//! [`Config::builtin`](config::Config::builtin) is the copy compiled into the
//! crate. A configuration read from a file **replaces** it — nothing is
//! merged — which is why the way to write one is to edit a copy of the
//! built-in file, printed by `velociredactor config show`. The CLI loads that
//! file from `--config`, then `$VELOCIREDACTOR_CONFIG`, then a discovered
//! `velociredactor.yml`, then the built-in configuration.
//!
//! [`Redactor::builder`] applies the built-in configuration, so the defaults
//! need no configuration at all. [`Config::apply`](config::Config::apply)
//! applies another one to a builder.
//!
//! ```
//! use velociredactor::{Allow, FormatHint, Redactor};
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
//! - [`detect::Detector`] adds detection logic. Register one with
//!   [`RedactorBuilder::detector`]; the bundled ones are ordinary detectors
//!   too, so [`detect::BETTERLEAKS_RULESET`] and
//!   [`detect::EmailDetector`] go in the same way. A detector that needs a
//!   whole document at once opts in with
//!   [`Detector::document_scope`](detect::Detector::document_scope).
//! - [`format::Format`] adds a file format.
//! - [`policy::LeafPolicy`] changes which structured values are scanned.
//!
//! A builder has no special slots: whatever detectors are added are the
//! detectors that run. Start from [`RedactorBuilder::new`] for an empty one,
//! or [`Redactor::builder`] for the built-in set.

pub mod config;
pub mod detect;
mod error;
pub mod format;
mod glob;
pub mod policy;
mod redactor;
mod render;

pub use error::{Error, FormatError};
pub use glob::Glob;
pub use redactor::{Finding, FormatHint, Redaction, Redactor, RedactorBuilder};
pub use render::{Allow, TOKEN_PREFIX, find_tokens, is_redaction_token, token};
