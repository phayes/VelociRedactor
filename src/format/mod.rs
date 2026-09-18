//! Input formats.
//!
//! A [`Format`] knows how to find the user-visible values in a document and how
//! to write the document back with some of those values replaced. It reports
//! values to a [`LeafVisitor`], which decides what (if anything) to replace.
//! Keys and layout are never shown to the visitor, so only values can be
//! redacted. Comments are shown only to a visitor that asks for them with
//! [`LeafVisitor::wants_comments`], and arrive as [`LeafKind::Comment`]
//! leaves before the document's own values.
//!
//! Implement [`Format`] and register it with
//! [`RedactorBuilder::format`](crate::RedactorBuilder::format) to support a new
//! file type.

use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

pub use crate::error::FormatError;

// Which comment scanners are used depends on the formats compiled in; the
// full build still reports anything genuinely unused.
#[cfg_attr(
    not(all(
        feature = "json",
        feature = "yaml",
        feature = "toml",
        feature = "hcl",
        feature = "ini",
        feature = "xml",
        feature = "properties"
    )),
    allow(dead_code)
)]
mod comment;
mod splice;
mod text;

#[cfg(feature = "csv")]
mod csv;
#[cfg(feature = "dotenv")]
mod dotenv;
#[cfg(feature = "hcl")]
mod hcl;
#[cfg(any(feature = "ini", feature = "dotenv"))]
#[cfg_attr(not(feature = "ini"), allow(dead_code))]
mod ini;
#[cfg(feature = "json")]
mod json;
#[cfg(feature = "plist")]
mod plist;
#[cfg(feature = "properties")]
mod properties;
#[cfg(feature = "toml")]
mod toml;
#[cfg(feature = "xml")]
mod xml;
#[cfg(feature = "yaml")]
mod yaml;

pub use splice::Splicer;
pub use text::Text;

#[cfg(feature = "csv")]
pub use self::csv::Csv;
#[cfg(feature = "toml")]
pub use self::toml::Toml;
#[cfg(feature = "dotenv")]
pub use dotenv::Dotenv;
#[cfg(feature = "hcl")]
pub use hcl::Hcl;
#[cfg(feature = "ini")]
pub use ini::Ini;
#[cfg(feature = "json")]
pub use json::{Json, JsonLines};
#[cfg(feature = "plist")]
pub use plist::BinaryPlist;
#[cfg(feature = "properties")]
pub use properties::Properties;
#[cfg(feature = "xml")]
pub use xml::Xml;
#[cfg(feature = "yaml")]
pub use yaml::Yaml;

/// A document format that can report its values and rewrite them.
pub trait Format: Send + Sync {
    /// Short, unique, lowercase name used on the command line (`json`, `yaml`, ...).
    fn name(&self) -> &str;

    /// File extensions (without the dot, lowercase) handled by this format.
    fn extensions(&self) -> &[&str] {
        &[]
    }

    /// Exact file names (lowercase) handled by this format, such as `.npmrc`.
    fn file_names(&self) -> &[&str] {
        &[]
    }

    /// Whether this format claims a file with the given lowercase name.
    ///
    /// The default checks [`file_names`](Format::file_names). Override it for
    /// name patterns such as `.env.local`.
    fn matches_file_name(&self, name: &str) -> bool {
        self.file_names().contains(&name)
    }

    /// Whether `input` looks like this format when no file name is available.
    ///
    /// Only formats that can be recognized reliably from content should
    /// return `true`.
    fn sniff(&self, _input: &[u8]) -> bool {
        false
    }

    /// Walk every value in `input`, offering each to `visitor`, and return the
    /// document with the visitor's replacements applied.
    ///
    /// Implementations must visit values in the same order on every call with
    /// the same input, and must return `input` unchanged when the visitor makes
    /// no replacements.
    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError>;
}

/// What part of a document a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeafKind {
    /// A value of the document itself.
    #[default]
    Value,
    /// A comment, including its marker. Only reported when the visitor asks
    /// for comments with [`LeafVisitor::wants_comments`].
    Comment,
}

/// A single value in a document.
#[derive(Debug, Clone, Copy)]
pub struct Leaf<'a> {
    /// The decoded value (escapes resolved, quotes removed).
    pub value: &'a str,
    /// The key the value is stored under, if it is a direct child of an object.
    /// Array items have no key.
    pub key: Option<&'a str>,
    /// Byte offset in the input where the value's text starts (after any
    /// opening quote), when the format knows it.
    pub offset: Option<usize>,
    /// Whether this is a value or a comment.
    pub kind: LeafKind,
}

impl<'a> Leaf<'a> {
    /// Create a document-value leaf without key or offset metadata.
    pub fn new(value: &'a str) -> Self {
        Self {
            value,
            key: None,
            offset: None,
            kind: LeafKind::Value,
        }
    }

    /// A comment, whose text is `value`.
    pub fn comment(value: &'a str) -> Self {
        Self {
            kind: LeafKind::Comment,
            ..Self::new(value)
        }
    }

    /// Set the key that directly contains this value.
    pub fn with_key(mut self, key: Option<&'a str>) -> Self {
        self.key = key;
        self
    }

    /// Set the byte offset where this value's text starts in the input.
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// A summary of an object's fields, given to the visitor before the object's
/// values are visited.
///
/// Formats list every key, and include the value when it is a plain string.
#[derive(Debug, Default, Clone)]
pub struct Object<'a> {
    fields: Vec<(&'a str, Option<&'a str>)>,
}

impl<'a> Object<'a> {
    /// Create an empty object summary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a field and its value when that value is a string.
    pub fn push(&mut self, key: &'a str, string_value: Option<&'a str>) {
        self.fields.push((key, string_value));
    }

    /// Iterate over field keys in document order.
    pub fn keys(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.fields.iter().map(|(k, _)| *k)
    }

    /// The string value of the first field named `key`, ignoring ASCII case,
    /// since a document may spell a key `type`, `Type`, or `TYPE`.
    pub fn get_str(&self, key: &str) -> Option<&'a str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .and_then(|(_, v)| *v)
    }
}

impl<'a> FromIterator<(&'a str, Option<&'a str>)> for Object<'a> {
    fn from_iter<T: IntoIterator<Item = (&'a str, Option<&'a str>)>>(iter: T) -> Self {
        Self {
            fields: iter.into_iter().collect(),
        }
    }
}

/// A container being entered during a walk.
#[derive(Debug, Clone, Copy)]
pub enum Container<'a, 'b> {
    /// An object summarized before its values are visited.
    Object(&'b Object<'a>),
    /// An array.
    Array,
}

/// Receives the values of a document as a [`Format`] walks it.
///
/// Every [`enter`](LeafVisitor::enter) is matched by an
/// [`exit`](LeafVisitor::exit). `key` is the key the container is stored under
/// in its parent object, or `None` for array items and the document root.
pub trait LeafVisitor {
    /// Enter a container stored under `key`, or the document root when `key` is `None`.
    fn enter(&mut self, key: Option<&str>, container: Container<'_, '_>);
    /// Exit the most recently entered container.
    fn exit(&mut self);
    /// Returns the replacement for this value, or `None` to keep it.
    fn leaf(&mut self, leaf: &Leaf<'_>) -> Option<Replacement>;

    /// Whether comments should be reported as values.
    ///
    /// Formats that have comments check this before locating them, and must
    /// report the same comments, in the same order, whenever it is `true`.
    /// Comments are reported before the document's own values.
    fn wants_comments(&self) -> bool {
        false
    }
}

/// The new text for a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The complete new value.
    pub value: String,
    /// The individual substitutions that turn the original value into
    /// `value`, as non-overlapping ranges of the original, in order.
    ///
    /// Formats that can edit their input in place use these to change only
    /// the redacted characters and keep the original quoting and escapes.
    pub edits: Vec<Edit>,
}

/// One substitution within a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// The byte range to replace within the decoded value.
    pub range: Range<usize>,
    /// The replacement text for the range.
    pub text: String,
}

/// Every format name this crate knows, whether or not the Cargo feature that
/// provides it is enabled in this build.
///
/// A configuration may name any of these. One that this build does not have
/// is reported and skipped, so a configuration written for a full build still
/// works against a smaller one; a name outside this list is an error.
///
/// The order is the one the built-in configuration lists, which is the order
/// formats are tried in when guessing from content. `text` comes last because
/// it is the fallback — though only by name: [`FormatRegistry::text`] finds it
/// wherever it sits, and it is available even to a configuration that leaves
/// it out.
pub const ALL_NAMES: &[&str] = &[
    "json",
    "jsonl",
    "yaml",
    "toml",
    "xml",
    "hcl",
    "ini",
    "dotenv",
    "properties",
    "csv",
    "tsv",
    "psv",
    "bplist",
    "text",
];

/// The formats compiled into this build, in detection priority order.
pub fn builtin() -> Vec<Arc<dyn Format>> {
    #[allow(unused_mut)]
    let mut formats: Vec<Arc<dyn Format>> = vec![Arc::new(Text)];
    #[cfg(feature = "json")]
    {
        formats.push(Arc::new(Json));
        formats.push(Arc::new(JsonLines));
    }
    #[cfg(feature = "yaml")]
    formats.push(Arc::new(Yaml));
    #[cfg(feature = "toml")]
    formats.push(Arc::new(Toml));
    #[cfg(feature = "xml")]
    formats.push(Arc::new(Xml));
    #[cfg(feature = "hcl")]
    formats.push(Arc::new(Hcl));
    #[cfg(feature = "ini")]
    formats.push(Arc::new(Ini));
    #[cfg(feature = "dotenv")]
    formats.push(Arc::new(Dotenv));
    #[cfg(feature = "properties")]
    formats.push(Arc::new(Properties));
    #[cfg(feature = "csv")]
    {
        formats.push(Arc::new(Csv::comma()));
        formats.push(Arc::new(Csv::tab()));
        formats.push(Arc::new(Csv::pipe()));
    }
    #[cfg(feature = "plist")]
    formats.push(Arc::new(BinaryPlist));
    formats
}

/// A set of formats with lookup by name, file name, and content.
///
/// Formats registered later take precedence over earlier ones with the same
/// name, extension, or file name.
#[derive(Clone)]
pub struct FormatRegistry {
    formats: Vec<Arc<dyn Format>>,
}

impl Default for FormatRegistry {
    fn default() -> Self {
        Self { formats: builtin() }
    }
}

impl FormatRegistry {
    /// A registry containing only the plain-text format.
    pub fn text_only() -> Self {
        Self {
            formats: vec![Arc::new(Text)],
        }
    }

    /// Add a format, replacing any existing format with the same name.
    pub fn register(&mut self, format: Arc<dyn Format>) {
        self.formats.retain(|f| f.name() != format.name());
        self.formats.push(format);
    }

    /// Return the registered format named `name`.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Format>> {
        self.formats
            .iter()
            .rev()
            .find(|f| f.name() == name)
            .cloned()
    }

    /// Names of all registered formats, in registration order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.formats.iter().map(|f| f.name())
    }

    /// Iterate over registered formats in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Format>> {
        self.formats.iter()
    }

    /// The format for a path, by exact file name first and then extension.
    pub fn for_path(&self, path: &Path) -> Option<Arc<dyn Format>> {
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if let Some(f) = self
            .formats
            .iter()
            .rev()
            .find(|f| f.matches_file_name(&name))
        {
            return Some(f.clone());
        }
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        self.formats
            .iter()
            .rev()
            .find(|f| f.extensions().contains(&ext.as_str()))
            .cloned()
    }

    /// The first format, in registration order, that recognizes `input`.
    pub fn sniff(&self, input: &[u8]) -> Option<Arc<dyn Format>> {
        self.formats.iter().find(|f| f.sniff(input)).cloned()
    }

    /// The plain-text format.
    pub fn text(&self) -> Arc<dyn Format> {
        self.get(Text::NAME).unwrap_or_else(|| Arc::new(Text))
    }
}

/// Apply `edits` (relative to `value`) and return the new string.
pub(crate) fn apply_edits(value: &str, edits: &[Edit]) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev = 0;
    for edit in edits {
        out.push_str(&value[prev..edit.range.start]);
        out.push_str(&edit.text);
        prev = edit.range.end;
    }
    out.push_str(&value[prev..]);
    out
}
