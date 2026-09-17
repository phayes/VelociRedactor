use java_properties::{LineContent, PropertiesIter};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer};

/// Java `.properties` files.
#[derive(Debug, Clone, Copy, Default)]
pub struct Properties;

impl Format for Properties {
    fn name(&self) -> &str {
        "properties"
    }

    fn extensions(&self) -> &[&str] {
        &["properties"]
    }

    fn file_names(&self) -> &[&str] {
        &["gradle.properties", "local.properties"]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("properties", e))?;
        let mut pairs = Vec::new();
        for line in PropertiesIter::new_with_encoding(input, encoding_rs::UTF_8) {
            let line = line.map_err(|e| FormatError::new("properties", e))?;
            let number = line.line_number();
            if let LineContent::KVPair(key, value) = line.consume_content() {
                pairs.push((number, key, value));
            }
        }

        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(i, _)| i + 1))
            .collect();

        let summary: Object<'_> = pairs
            .iter()
            .map(|(_, k, v)| (k.as_str(), Some(v.as_str())))
            .collect();
        visitor.enter(None, Container::Object(&summary));
        let mut splicer = Splicer::new(input);
        for (number, key, value) in &pairs {
            let Some(&line_start) = line_starts.get(number.saturating_sub(1)) else {
                continue;
            };
            let raw = value_range(text, line_start);
            let leaf = Leaf::new(value).with_key(Some(key)).with_offset(raw.start);
            if let Some(replacement) = visitor.leaf(&leaf) {
                splicer.apply(raw.clone(), raw, value, &replacement, escape);
            }
        }
        visitor.exit();
        Ok(splicer.finish())
    }
}

/// The raw value of the logical line starting at `start`: everything after the
/// key and its separator, through any backslash-continued lines.
fn value_range(text: &str, start: usize) -> std::ops::Range<usize> {
    let bytes = text.as_bytes();
    let mut i = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\x0c') {
        i += 1;
    }
    // Key: up to the first unescaped separator or whitespace.
    while i < bytes.len()
        && !matches!(
            bytes[i],
            b'=' | b':' | b' ' | b'\t' | b'\x0c' | b'\r' | b'\n'
        )
    {
        i += if bytes[i] == b'\\' { 2 } else { 1 };
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\x0c') {
        i += 1;
    }
    if i < bytes.len() && matches!(bytes[i], b'=' | b':') {
        i += 1;
    }
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\x0c') {
        i += 1;
    }
    let value_start = i.min(bytes.len());

    let mut end = value_start;
    loop {
        let line_end = text[end..]
            .find(['\r', '\n'])
            .map_or(text.len(), |n| end + n);
        let trailing_backslashes = bytes[end..line_end]
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        if trailing_backslashes % 2 == 1 && line_end < bytes.len() {
            end = line_end
                + if text[line_end..].starts_with("\r\n") {
                    2
                } else {
                    1
                };
        } else {
            return value_start..line_end;
        }
    }
}

/// Escape a value for a single `.properties` line.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0c' => out.push_str("\\f"),
            ' ' if i == 0 => out.push_str("\\ "),
            _ => out.push(c),
        }
    }
    out
}
