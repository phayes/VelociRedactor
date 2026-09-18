//! Locating comments, and offering them to the visitor as values.
//!
//! Comments are only scanned when the visitor asks for them
//! ([`LeafVisitor::wants_comments`]). Each comment is one value, including
//! its marker, so a detector sees `# password: hunter2` as written. Redacted
//! text inside a comment is spliced in place.

use std::ops::Range;

use super::{Leaf, LeafVisitor, Splicer};

/// Offer each of `ranges` to `visitor` as a comment value, splicing in any
/// replacements. `ranges` must be sorted and must not overlap.
pub(super) fn visit(
    text: &str,
    ranges: &[Range<usize>],
    visitor: &mut dyn LeafVisitor,
    splicer: &mut Splicer<'_>,
) {
    for range in ranges {
        let Some(value) = text.get(range.clone()) else {
            continue;
        };
        let leaf = Leaf::comment(value).with_offset(range.start);
        if let Some(replacement) = visitor.leaf(&leaf) {
            splicer.apply(
                range.clone(),
                range.clone(),
                value,
                &replacement,
                str::to_owned,
            );
        }
    }
}

/// End of the line starting at `from`, not including the line break.
fn line_end(bytes: &[u8], from: usize) -> usize {
    let end = memchr::memchr(b'\n', &bytes[from..]).map_or(bytes.len(), |i| from + i);
    if end > from && bytes[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

/// Comments in TOML: `#` to end of line, outside of strings.
pub(super) fn toml(text: &str) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'#' => {
                let end = line_end(bytes, i);
                out.push(i..end);
                i = end.max(i + 1);
            }
            b'"' | b'\'' => i = skip_string(bytes, i, bytes[i] == b'"', true),
            _ => i += 1,
        }
    }
    out
}

/// Comments in HCL: `#` and `//` to end of line, and `/* */` blocks, outside
/// of strings and heredocs.
pub(super) fn hcl(text: &str) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        match bytes[i] {
            b'#' => {
                let end = line_end(bytes, i);
                out.push(i..end);
                i = end.max(i + 1);
            }
            b'/' if rest.starts_with(b"//") => {
                let end = line_end(bytes, i);
                out.push(i..end);
                i = end.max(i + 1);
            }
            b'/' if rest.starts_with(b"/*") => {
                let end = memchr::memmem::find(&bytes[i + 2..], b"*/")
                    .map_or(bytes.len(), |p| i + 2 + p + 2);
                out.push(i..end);
                i = end;
            }
            b'"' => i = skip_string(bytes, i, true, false),
            b'<' if rest.starts_with(b"<<") => i = skip_heredoc(bytes, i),
            _ => i += 1,
        }
    }
    out
}

/// Comments in Java properties: a logical line whose first non-blank
/// character is `#` or `!`.
pub(super) fn properties(text: &str) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut continued = false;
    while i < bytes.len() {
        let end = line_end(bytes, i);
        let content = &text[i..end];
        let indent = content.len() - content.trim_start_matches([' ', '\t', '\x0c']).len();
        if !continued && content[indent..].starts_with(['#', '!']) {
            out.push(i + indent..end);
            continued = false;
        } else {
            let backslashes = bytes[i..end]
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count();
            continued = backslashes % 2 == 1;
        }
        i = next_line(bytes, end);
    }
    out
}

/// Comments marked by `#`, where the marker must start a line or follow
/// whitespace, and which never start inside one of `spans`.
///
/// `spans` are the byte ranges of the document's scalars, which the caller
/// takes from its parser; they keep a `#` inside a quoted or block scalar
/// from reading as a comment.
pub(super) fn hash_outside(text: &str, spans: &mut Vec<Range<usize>>) -> Vec<Range<usize>> {
    merge_spans(spans);
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(found) = memchr::memchr(b'#', &bytes[i..]) {
        let at = i + found;
        let starts_token = at == 0 || matches!(bytes[at - 1], b' ' | b'\t' | b'\n' | b'\r');
        let end = line_end(bytes, at);
        if starts_token && !covered(spans, at..end) {
            out.push(at..end);
        }
        i = end.max(at + 1);
    }
    out
}

/// Whether `range` overlaps any of the sorted, non-overlapping `spans`.
fn covered(spans: &[Range<usize>], range: Range<usize>) -> bool {
    let next = spans.partition_point(|s| s.end <= range.start);
    spans
        .get(next)
        .is_some_and(|s| s.start < range.end.max(range.start + 1))
}

/// Sort `spans` and merge any that overlap or touch.
fn merge_spans(spans: &mut Vec<Range<usize>>) {
    spans.retain(|s| s.start < s.end);
    spans.sort_by_key(|s| (s.start, s.end));
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(spans.len());
    for span in spans.iter() {
        match merged.last_mut() {
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => merged.push(span.clone()),
        }
    }
    *spans = merged;
}

/// Index just past the string literal starting at `start`.
///
/// `escapes` enables backslash escapes, and `triples` enables `"""` and `'''`
/// multi-line strings.
fn skip_string(bytes: &[u8], start: usize, escapes: bool, triples: bool) -> usize {
    let quote = bytes[start];
    let fence = [quote, quote, quote];
    if triples && bytes[start..].starts_with(&fence) {
        let mut i = start + 3;
        while i < bytes.len() {
            if escapes && bytes[i] == b'\\' {
                i += 2;
            } else if bytes[i..].starts_with(&fence) {
                return i + 3;
            } else {
                i += 1;
            }
        }
        return bytes.len();
    }
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if escapes => i += 2,
            b'\n' => return i,
            b if b == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Index just past the heredoc starting at `start` (which begins `<<`), or
/// just past `<<` when it is not a heredoc.
fn skip_heredoc(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 2;
    if bytes.get(i) == Some(&b'-') {
        i += 1;
    }
    let tag_start = i;
    while bytes
        .get(i)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        i += 1;
    }
    if i == tag_start {
        return start + 2;
    }
    let tag = &bytes[tag_start..i];
    let mut line = next_line(bytes, line_end(bytes, i));
    while line < bytes.len() {
        let end = line_end(bytes, line);
        if bytes[line..end].trim_ascii() == tag {
            return end;
        }
        line = next_line(bytes, end);
    }
    bytes.len()
}

/// Start of the line after the one ending at `end`.
fn next_line(bytes: &[u8], end: usize) -> usize {
    match bytes.get(end) {
        Some(b'\r') if bytes.get(end + 1) == Some(&b'\n') => end + 2,
        Some(_) => end + 1,
        None => end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found<'a>(text: &'a str, ranges: &[Range<usize>]) -> Vec<&'a str> {
        ranges.iter().map(|r| &text[r.clone()]).collect()
    }

    #[test]
    fn toml_comments() {
        let text = "# one\nkey = \"a # b\" # two\nk2 = '''\n# inside\n''' # three\n\"a#b\" = 1\n";
        assert_eq!(
            found(text, &toml(text)),
            ["# one", "# two", "# three"],
            "{:?}",
            toml(text)
        );
    }

    #[test]
    fn hcl_comments() {
        let text = concat!(
            "# one\n",
            "a = \"x # y\" // two\n",
            "/* three\n   still */ b = 1 # four\n",
            "c = <<EOT\n# not a comment\nEOT\n",
            "d = 2 # five\n",
        );
        assert_eq!(
            found(text, &hcl(text)),
            [
                "# one",
                "// two",
                "/* three\n   still */",
                "# four",
                "# five"
            ]
        );
    }

    #[test]
    fn properties_comments() {
        let text = "# one\n  ! two\nkey=value # not a comment\nk2=a\\\n# continued\nk3=b\n";
        assert_eq!(found(text, &properties(text)), ["# one", "! two"]);
    }

    #[test]
    fn hash_comments_outside_spans() {
        let text = "key: value # one\nother: \"a # b\"\n# two\nurl: http://x/#frag\n";
        let quoted = text.find("\"a # b\"").unwrap();
        let mut spans = vec![quoted..quoted + 7, 0..0];
        assert_eq!(
            found(text, &hash_outside(text, &mut spans)),
            ["# one", "# two"]
        );
    }

    #[test]
    fn crlf_comments_exclude_the_line_break() {
        let text = "a = 1 # one\r\nb = 2\r\n";
        assert_eq!(found(text, &toml(text)), ["# one"]);
    }

    #[test]
    fn merges_and_detects_covered_ranges() {
        let mut spans = vec![10..20, 0..5, 4..8];
        merge_spans(&mut spans);
        assert_eq!(spans, vec![0..8, 10..20]);
        assert!(covered(&spans, 7..9));
        assert!(covered(&spans, 19..25));
        assert!(!covered(&spans, 8..10));
    }
}
