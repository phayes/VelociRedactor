use super::ini::{LineStyle, rewrite_lines};
use super::{Format, FormatError, LeafVisitor};

/// `.env` files: `KEY=value` lines, optionally prefixed with `export`.
///
/// Values are scanned exactly as written (without surrounding quotes).
/// Variable references such as `${HOME}` are not expanded.
#[derive(Debug, Clone, Copy, Default)]
pub struct Dotenv;

impl Format for Dotenv {
    fn name(&self) -> &str {
        "dotenv"
    }

    fn extensions(&self) -> &[&str] {
        &["env"]
    }

    fn file_names(&self) -> &[&str] {
        &[".env", ".envrc", ".flaskenv"]
    }

    /// Also matches `.env.local`, `.env.production`, and similar.
    fn matches_file_name(&self, name: &str) -> bool {
        self.file_names().contains(&name) || name.starts_with(".env.")
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        rewrite_lines(
            &LineStyle {
                name: "dotenv",
                sections: false,
                export_prefix: true,
            },
            input,
            visitor,
        )
    }
}
