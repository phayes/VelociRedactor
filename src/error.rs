use std::fmt;

/// Errors returned while building a [`Redactor`](crate::Redactor) or redacting input.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A format name was requested that no registered [`Format`](crate::format::Format) provides.
    #[error("unknown format {0:?}")]
    UnknownFormat(String),

    /// A user-supplied pattern failed to compile.
    #[error("invalid pattern for {name:?}: {message}")]
    InvalidPattern {
        /// The detector or setting that owns the pattern.
        name: String,
        /// The sanitized compilation error.
        message: String,
    },

    /// A ruleset file could not be loaded.
    #[error("ruleset: {0}")]
    Ruleset(String),

    /// A configuration file could not be read or understood.
    #[error("config: {0}")]
    Config(String),

    /// A detector failed while looking at the input, so the input cannot be
    /// said to be clean.
    #[error("{name}: {message}")]
    Detector {
        /// The detector that failed.
        name: String,
        /// The detector's error message.
        message: String,
    },

    /// The input could not be processed as the requested format.
    #[error(transparent)]
    Format(#[from] FormatError),

    /// Reading or writing bytes failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A format failed to parse or re-serialize its input.
#[derive(Debug, thiserror::Error)]
#[error("{format}: {message}")]
pub struct FormatError {
    format: String,
    message: String,
}

impl FormatError {
    /// Create an error for `format` from a displayable message.
    pub fn new(format: impl Into<String>, message: impl fmt::Display) -> Self {
        Self {
            format: format.into(),
            message: message.to_string(),
        }
    }

    /// Name of the format that failed.
    pub fn format(&self) -> &str {
        &self.format
    }

    /// The parser or serializer error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
