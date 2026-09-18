use std::borrow::Cow;
use std::ops::Range;

use saphyr_parser::{Event, Parser, ScalarStyle};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer, comment};

/// YAML, including multi-document streams.
///
/// Quoted and block scalars are edited in place. Redacted plain scalars are
/// rewritten as double-quoted strings, as are quoted scalars whose redacted
/// text cannot be mapped back onto the original. Block scalars that cannot be
/// edited in place are rewritten in the same block style.
#[derive(Debug, Clone, Copy, Default)]
pub struct Yaml;

impl Format for Yaml {
    fn name(&self) -> &str {
        "yaml"
    }

    fn extensions(&self) -> &[&str] {
        &["yaml", "yml"]
    }

    fn file_names(&self) -> &[&str] {
        &[".clang-format", ".clang-tidy"]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("yaml", e))?;
        let documents = parse(text)?;
        let mut splicer = Splicer::new(input);
        if visitor.wants_comments() {
            let mut spans = Vec::new();
            for document in &documents {
                collect_spans(document, &mut spans);
            }
            let ranges = comment::hash_outside(text, &mut spans);
            comment::visit(text, &ranges, visitor, &mut splicer);
        }
        for document in &documents {
            walk(document, None, text, visitor, &mut splicer);
        }
        Ok(splicer.finish())
    }
}

enum Node<'a> {
    Scalar {
        value: Cow<'a, str>,
        style: ScalarStyle,
        span: Range<usize>,
    },
    Sequence(Vec<Node<'a>>),
    Mapping(Vec<(Node<'a>, Node<'a>)>),
    Alias,
}

impl Node<'_> {
    fn as_str(&self) -> Option<&str> {
        match self {
            Node::Scalar { value, .. } => Some(value),
            _ => None,
        }
    }
}

/// Maps the parser's character offsets to byte offsets.
struct Offsets {
    /// Byte offset of each character, or empty when the input is ASCII.
    bytes: Vec<usize>,
    len: usize,
}

impl Offsets {
    fn new(text: &str) -> Self {
        let bytes = if text.is_ascii() {
            Vec::new()
        } else {
            text.char_indices().map(|(i, _)| i).collect()
        };
        Self {
            bytes,
            len: text.len(),
        }
    }

    fn byte(&self, char_index: usize) -> usize {
        if self.bytes.is_empty() {
            char_index
        } else {
            self.bytes.get(char_index).copied().unwrap_or(self.len)
        }
    }
}

fn parse(text: &str) -> Result<Vec<Node<'_>>, FormatError> {
    let offsets = Offsets::new(text);
    let mut events = Parser::new_from_str(text).map(|event| {
        event
            .map(|(event, span)| {
                let range = offsets.byte(span.start.index())..offsets.byte(span.end.index());
                (event, range)
            })
            .map_err(|e| FormatError::new("yaml", e))
    });

    let mut documents = Vec::new();
    while let Some(event) = events.next() {
        match event?.0 {
            Event::DocumentStart(_) => {
                if let Some(node) = parse_node(&mut events)? {
                    documents.push(node);
                }
            }
            Event::StreamEnd => break,
            _ => {}
        }
    }
    Ok(documents)
}

/// Parse the next node, or return `None` at the end of a document.
fn parse_node<'a, I>(events: &mut I) -> Result<Option<Node<'a>>, FormatError>
where
    I: Iterator<Item = Result<(Event<'a>, Range<usize>), FormatError>>,
{
    loop {
        let Some(event) = events.next() else {
            return Ok(None);
        };
        let (event, span) = event?;
        return Ok(Some(match event {
            Event::Scalar(value, style, _, _) => Node::Scalar { value, style, span },
            Event::Alias(_) => Node::Alias,
            Event::SequenceStart(..) => {
                let mut items = Vec::new();
                while let Some(item) = parse_node(events)? {
                    items.push(item);
                }
                Node::Sequence(items)
            }
            Event::MappingStart(..) => {
                let mut pairs = Vec::new();
                while let Some(key) = parse_node(events)? {
                    let value = parse_node(events)?
                        .ok_or_else(|| FormatError::new("yaml", "mapping key without a value"))?;
                    pairs.push((key, value));
                }
                Node::Mapping(pairs)
            }
            Event::SequenceEnd | Event::MappingEnd | Event::DocumentEnd | Event::StreamEnd => {
                return Ok(None);
            }
            Event::Nothing | Event::StreamStart | Event::DocumentStart(_) => continue,
        }));
    }
}

/// The byte ranges of every scalar, so that a `#` inside one is not read as
/// the start of a comment.
fn collect_spans(node: &Node<'_>, out: &mut Vec<Range<usize>>) {
    match node {
        Node::Scalar { span, .. } => out.push(span.clone()),
        Node::Sequence(items) => items.iter().for_each(|i| collect_spans(i, out)),
        Node::Mapping(pairs) => {
            for (k, v) in pairs {
                collect_spans(k, out);
                collect_spans(v, out);
            }
        }
        Node::Alias => {}
    }
}

fn walk(
    node: &Node<'_>,
    key: Option<&str>,
    text: &str,
    visitor: &mut dyn LeafVisitor,
    splicer: &mut Splicer<'_>,
) {
    match node {
        Node::Scalar { value, style, span } => {
            let quoted = matches!(style, ScalarStyle::SingleQuoted | ScalarStyle::DoubleQuoted);
            let leaf = Leaf::new(value)
                .with_key(key)
                .with_offset(span.start + usize::from(quoted));
            let Some(replacement) = visitor.leaf(&leaf) else {
                return;
            };
            match style {
                ScalarStyle::SingleQuoted | ScalarStyle::DoubleQuoted => {
                    let content = span.start + 1..span.end.saturating_sub(1).max(span.start + 1);
                    splicer.apply(span.clone(), content, value, &replacement, double_quoted);
                }
                ScalarStyle::Literal | ScalarStyle::Folded => {
                    let raw = &text[span.clone()];
                    let indent = indentation(text, span.start);
                    let folded = matches!(style, ScalarStyle::Folded);
                    splicer.apply(span.clone(), span.clone(), value, &replacement, |v| {
                        block_body(v, raw, indent, folded)
                    });
                }
                ScalarStyle::Plain => {
                    // Replacement tokens contain `[`, `]`, and `|`, which change
                    // the meaning of a plain scalar (a leading `[` starts a flow
                    // sequence), so redacted plain scalars are always quoted.
                    splicer.replace(span.clone(), double_quoted(&replacement.value));
                }
            }
        }
        Node::Sequence(items) => {
            visitor.enter(key, Container::Array);
            for item in items {
                walk(item, None, text, visitor, splicer);
            }
            visitor.exit();
        }
        Node::Mapping(pairs) => {
            let summary: Object<'_> = pairs
                .iter()
                .filter_map(|(k, v)| Some((k.as_str()?, v.as_str())))
                .collect();
            visitor.enter(key, Container::Object(&summary));
            for (k, v) in pairs {
                walk(v, k.as_str(), text, visitor, splicer);
            }
            visitor.exit();
        }
        Node::Alias => {}
    }
}

fn double_quoted(value: &str) -> String {
    serde_json::to_string(value).expect("strings always serialize")
}

/// The whitespace before `offset` on its line.
fn indentation(text: &str, offset: usize) -> &str {
    let line_start = text[..offset].rfind('\n').map_or(0, |i| i + 1);
    let prefix = &text[line_start..offset];
    &prefix[..prefix.len() - prefix.trim_start_matches([' ', '\t']).len()]
}

/// Re-emit a block scalar body. The first line is not indented because the
/// scalar's span starts after the indentation. Trailing line breaks are
/// copied from the original so the chomping indicator keeps its meaning.
fn block_body(value: &str, raw: &str, indent: &str, folded: bool) -> String {
    let trailing = &raw[raw.trim_end_matches(['\n', '\r', ' ', '\t']).len()..];
    let body = value.trim_end_matches('\n');
    // In a folded scalar a single line break reads as a space, so each
    // newline in the value is written as a blank line.
    let separator = if folded {
        format!("\n\n{indent}")
    } else {
        format!("\n{indent}")
    };
    let mut out = body.split('\n').collect::<Vec<_>>().join(&separator);
    out.push_str(trailing);
    out
}
