use std::ops::Range;

use jsonc_parser::ast::{ObjectPropName, Value};
use jsonc_parser::common::Ranged;
use jsonc_parser::{CollectOptions, CommentCollectionStrategy, ParseOptions, parse_to_ast};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer, comment};

/// JSON, including JSONC and common JSON5 extensions (comments, trailing
/// commas, single-quoted strings, unquoted keys).
#[derive(Debug, Clone, Copy, Default)]
pub struct Json;

/// JSON Lines / NDJSON: one JSON value per line. Lines that are not valid
/// JSON are scanned as plain text.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonLines;

impl Format for Json {
    fn name(&self) -> &str {
        "json"
    }

    fn extensions(&self) -> &[&str] {
        &[
            "json",
            "jsonc",
            "json5",
            "geojson",
            "har",
            "ipynb",
            "sarif",
            "code-workspace",
            "webmanifest",
        ]
    }

    fn file_names(&self) -> &[&str] {
        &[
            ".babelrc",
            ".eslintrc",
            ".prettierrc",
            ".jshintrc",
            "composer.lock",
            "flake.lock",
        ]
    }

    fn sniff(&self, input: &[u8]) -> bool {
        starts_like_json(input) && std::str::from_utf8(input).is_ok_and(|text| parse(text).is_ok())
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("json", e))?;
        let comments = visitor.wants_comments();
        let result = parse_with(text, comments).map_err(|e| FormatError::new("json", e))?;
        let mut splicer = Splicer::new(input);
        if let Some(map) = &result.comments {
            comment::visit(text, &comment_ranges(map), visitor, &mut splicer);
        }
        if let Some(value) = &result.value {
            walk(value, None, 0, visitor, &mut splicer);
        }
        Ok(splicer.finish())
    }
}

impl Format for JsonLines {
    fn name(&self) -> &str {
        "jsonl"
    }

    fn extensions(&self) -> &[&str] {
        &["jsonl", "ndjson", "jsonlines"]
    }

    /// At least two non-empty lines, the first of which is a JSON object or
    /// array, and the whole input is not a single JSON document.
    fn sniff(&self, input: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(input) else {
            return false;
        };
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let (Some(first), Some(_)) = (lines.next(), lines.next()) else {
            return false;
        };
        starts_like_json(first.as_bytes())
            && parse(first).is_ok_and(|v| v.is_some())
            && parse(text).is_err()
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("jsonl", e))?;
        let mut splicer = Splicer::new(input);
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            let content = line.trim_end_matches(['\n', '\r']);
            if !content.trim().is_empty() {
                match parse(content) {
                    Ok(Some(value)) => walk(&value, None, offset, visitor, &mut splicer),
                    _ => {
                        let leaf = Leaf::new(content).with_offset(offset);
                        if let Some(replacement) = visitor.leaf(&leaf) {
                            let range = offset..offset + content.len();
                            splicer.apply(range.clone(), range, content, &replacement, |v| {
                                v.to_owned()
                            });
                        }
                    }
                }
            }
            offset += line.len();
        }
        Ok(splicer.finish())
    }
}

fn starts_like_json(input: &[u8]) -> bool {
    input
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| matches!(b, b'{' | b'['))
}

fn parse(text: &str) -> Result<Option<Value<'_>>, jsonc_parser::errors::ParseError> {
    parse_with(text, false).map(|r| r.value)
}

fn parse_with(
    text: &str,
    comments: bool,
) -> Result<jsonc_parser::ParseResult<'_>, jsonc_parser::errors::ParseError> {
    let collect = CollectOptions {
        comments: if comments {
            CommentCollectionStrategy::Separate
        } else {
            CommentCollectionStrategy::Off
        },
        tokens: false,
    };
    parse_to_ast(text, &collect, &ParseOptions::default())
}

/// The distinct comment ranges of a parsed document, in document order. The
/// map holds each comment under both the token before and the token after it.
fn comment_ranges(map: &jsonc_parser::CommentMap<'_>) -> Vec<Range<usize>> {
    let mut ranges: Vec<Range<usize>> = map
        .values()
        .flat_map(|comments| comments.iter())
        .map(|c| {
            let range = c.range();
            range.start..range.end
        })
        .collect();
    ranges.sort_by_key(|r| (r.start, r.end));
    ranges.dedup();
    ranges
}

/// Walk `value`, whose ranges are relative to a slice starting at `base` in
/// the full input.
fn walk(
    value: &Value<'_>,
    key: Option<&str>,
    base: usize,
    visitor: &mut dyn LeafVisitor,
    splicer: &mut Splicer<'_>,
) {
    match value {
        Value::StringLit(lit) => {
            let leaf = Leaf::new(&lit.value)
                .with_key(key)
                .with_offset(base + lit.range.start + 1);
            if let Some(replacement) = visitor.leaf(&leaf) {
                let raw = base + lit.range.start..base + lit.range.end;
                let content = raw.start + 1..raw.end - 1;
                splicer.apply(raw, content, &lit.value, &replacement, |v| {
                    serde_json::to_string(v).expect("strings always serialize")
                });
            }
        }
        Value::Object(object) => {
            let summary: Object<'_> = object
                .properties
                .iter()
                .map(|p| {
                    let value = match &p.value {
                        Value::StringLit(lit) => Some(lit.value.as_ref()),
                        _ => None,
                    };
                    (prop_name(&p.name), value)
                })
                .collect();
            visitor.enter(key, Container::Object(&summary));
            for prop in &object.properties {
                walk(
                    &prop.value,
                    Some(prop_name(&prop.name)),
                    base,
                    visitor,
                    splicer,
                );
            }
            visitor.exit();
        }
        Value::Array(array) => {
            visitor.enter(key, Container::Array);
            for element in &array.elements {
                walk(element, None, base, visitor, splicer);
            }
            visitor.exit();
        }
        Value::NumberLit(_) | Value::BooleanLit(_) | Value::NullKeyword(_) => {}
    }
}

fn prop_name<'b>(name: &'b ObjectPropName<'_>) -> &'b str {
    match name {
        ObjectPropName::String(lit) => &lit.value,
        ObjectPropName::Word(word) => word.value,
    }
}
