use std::ops::Range;

use ini_roundtrip::{Item, Parser};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer};

/// INI-style configuration (`.ini`, `.cfg`, `.npmrc`, `.gitconfig`, ...).
///
/// Each section is an object keyed by the section name. Values wrapped in
/// matching quotes are scanned without the quotes. Lines that are neither
/// sections, properties, nor comments are scanned as text.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ini;

impl Format for Ini {
    fn name(&self) -> &str {
        "ini"
    }

    fn extensions(&self) -> &[&str] {
        &[
            "ini",
            "cfg",
            "conf",
            "cnf",
            "inf",
            "desktop",
            "service",
            "editorconfig",
        ]
    }

    fn file_names(&self) -> &[&str] {
        &[
            ".npmrc",
            ".yarnrc",
            ".gitconfig",
            ".gitmodules",
            ".editorconfig",
            ".pypirc",
            ".pgpass",
            ".my.cnf",
            ".s3cfg",
            ".boto",
            "credentials",
            "config",
            "setup.cfg",
            "tox.ini",
            "pip.conf",
        ]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        rewrite_lines(
            &LineStyle {
                name: "ini",
                sections: true,
                export_prefix: false,
            },
            input,
            visitor,
        )
    }
}

/// How a line-oriented `key = value` format is read.
pub(super) struct LineStyle {
    pub name: &'static str,
    /// Whether `[name]` lines start sections.
    pub sections: bool,
    /// Whether keys may be prefixed with `export `.
    pub export_prefix: bool,
}

enum Line<'a> {
    Property {
        key: &'a str,
        /// The value with surrounding quotes removed.
        value: &'a str,
    },
    /// A line that is not a property, scanned as text.
    Text(&'a str),
}

struct Section<'a> {
    name: Option<&'a str>,
    lines: Vec<Line<'a>>,
}

pub(super) fn rewrite_lines(
    style: &LineStyle,
    input: &[u8],
    visitor: &mut dyn LeafVisitor,
) -> Result<Vec<u8>, FormatError> {
    let text = std::str::from_utf8(input).map_err(|e| FormatError::new(style.name, e))?;
    let mut sections = vec![Section {
        name: None,
        lines: Vec::new(),
    }];
    for item in Parser::new(text) {
        let line = match item {
            Item::Section { name, .. } if style.sections => {
                sections.push(Section {
                    name: Some(name),
                    lines: Vec::new(),
                });
                continue;
            }
            Item::Section { raw, .. } | Item::Error(raw) => Line::Text(raw),
            Item::Property {
                key,
                val: Some(val),
                ..
            } => Line::Property {
                key: if style.export_prefix {
                    key.strip_prefix("export")
                        .filter(|rest| rest.starts_with([' ', '\t']))
                        .map_or(key, str::trim_start)
                } else {
                    key
                },
                value: unquote(val),
            },
            Item::Property { raw, val: None, .. } => Line::Text(raw),
            Item::Comment { .. } | Item::Blank { .. } | Item::SectionEnd => continue,
        };
        sections
            .last_mut()
            .expect("root section exists")
            .lines
            .push(line);
    }

    let mut splicer = Splicer::new(input);
    let (root, named) = sections.split_first().expect("root section exists");
    enter_section(visitor, root);
    visit_lines(text, visitor, &mut splicer, &root.lines);
    for section in named {
        enter_section(visitor, section);
        visit_lines(text, visitor, &mut splicer, &section.lines);
        visitor.exit();
    }
    visitor.exit();
    Ok(splicer.finish())
}

fn enter_section(visitor: &mut dyn LeafVisitor, section: &Section<'_>) {
    let summary: Object<'_> = section
        .lines
        .iter()
        .filter_map(|line| match line {
            Line::Property { key, value } => Some((*key, Some(*value))),
            Line::Text(_) => None,
        })
        .collect();
    visitor.enter(section.name, Container::Object(&summary));
}

fn visit_lines(
    text: &str,
    visitor: &mut dyn LeafVisitor,
    splicer: &mut Splicer<'_>,
    lines: &[Line<'_>],
) {
    for line in lines {
        let (key, value) = match line {
            Line::Property { key, value } => (Some(*key), *value),
            Line::Text(raw) => (None, *raw),
        };
        if value.trim().is_empty() {
            continue;
        }
        let range = locate(text, value);
        let leaf = Leaf::new(value).with_key(key).with_offset(range.start);
        if let Some(replacement) = visitor.leaf(&leaf) {
            splicer.apply(range.clone(), range, value, &replacement, str::to_owned);
        }
    }
}

/// Byte range of `part`, which must be a slice of `text`.
fn locate(text: &str, part: &str) -> Range<usize> {
    let start = part.as_ptr() as usize - text.as_ptr() as usize;
    start..start + part.len()
}

fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    match bytes {
        [q @ (b'"' | b'\''), .., last] if bytes.len() >= 2 && last == q => {
            &value[1..value.len() - 1]
        }
        _ => value,
    }
}
