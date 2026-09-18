use std::ops::Range;

use quick_xml::Reader;
use quick_xml::escape::{escape, resolve_predefined_entity};
use quick_xml::events::{BytesStart, Event};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer, comment};

/// XML, including XML property lists, SVG, and project files.
///
/// Element text, CDATA sections, and attribute values are scanned. Each
/// element is an object whose fields are its attributes; text is keyed by the
/// enclosing element's name. Inside a property-list `<dict>`, values are keyed
/// by the preceding `<key>` element instead, and the keys themselves are not
/// scanned.
#[derive(Debug, Clone, Copy, Default)]
pub struct Xml;

impl Format for Xml {
    fn name(&self) -> &str {
        "xml"
    }

    fn extensions(&self) -> &[&str] {
        &[
            "xml", "plist", "svg", "xsd", "xsl", "xslt", "csproj", "vbproj", "fsproj", "props",
            "targets", "config", "resx", "xaml", "pom", "wsdl", "rss", "atom", "xhtml",
        ]
    }

    fn file_names(&self) -> &[&str] {
        &["pom.xml", "web.config", "app.config", "nuget.config"]
    }

    fn sniff(&self, input: &[u8]) -> bool {
        input.trim_ascii_start().starts_with(b"<?xml")
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("xml", e))?;
        let mut splicer = Splicer::new(input);
        if visitor.wants_comments() {
            comment::visit(text, &comment_ranges(text)?, visitor, &mut splicer);
        }

        let mut reader = Reader::from_str(text);
        let mut walker = Walker {
            text,
            visitor,
            splicer,
            elements: Vec::new(),
            run: None,
            dict_key: None,
        };

        loop {
            let event = reader.read_event().map_err(|e| {
                FormatError::new("xml", format!("at byte {}: {e}", reader.error_position()))
            })?;
            match event {
                Event::Eof => {
                    walker.flush();
                    break;
                }
                Event::Text(t) => {
                    let range = walker.locate(&t)?;
                    walker.push_text(range, &t.xml_content(Default::default()));
                }
                Event::GeneralRef(r) => {
                    let name = walker.locate(&r)?;
                    let range = name.start - 1..name.end + 1;
                    let raw = &text[range.clone()];
                    let decoded = match r.resolve_char_ref() {
                        Ok(Some(c)) => c.to_string(),
                        _ => resolve_predefined_entity(&text[name])
                            .map_or_else(|| raw.to_owned(), str::to_owned),
                    };
                    walker.push_text(range, &decoded);
                }
                Event::CData(c) => {
                    walker.flush();
                    let content = walker.locate(&c)?;
                    let value = &text[content.clone()];
                    let raw = content.start - "<![CDATA[".len()..content.end + "]]>".len();
                    walker.scalar(raw, content, value, |v| format!("<![CDATA[{v}]]>"));
                }
                Event::Start(start) => {
                    walker.flush();
                    let name = walker.element(&start)?;
                    walker.elements.push(name);
                }
                Event::Empty(start) => {
                    walker.flush();
                    walker.element(&start)?;
                    walker.visitor.exit();
                }
                Event::End(_) => {
                    walker.flush();
                    walker.elements.pop();
                    walker.visitor.exit();
                }
                Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {
                    walker.flush();
                }
            }
        }
        Ok(walker.splicer.finish())
    }
}

/// The byte ranges of the comment bodies in `text`, without the `<!--` and
/// `-->` markers.
fn comment_ranges(text: &str) -> Result<Vec<Range<usize>>, FormatError> {
    let mut reader = Reader::from_str(text);
    let mut ranges = Vec::new();
    loop {
        let at = reader.buffer_position() as usize;
        match reader.read_event().map_err(|e| {
            FormatError::new("xml", format!("at byte {}: {e}", reader.error_position()))
        })? {
            Event::Eof => return Ok(ranges),
            Event::Comment(body) => {
                let end = reader.buffer_position() as usize;
                let start = at + "<!--".len();
                if start + "-->".len() <= end && !body.is_empty() {
                    ranges.push(start..end - "-->".len());
                }
            }
            _ => {}
        }
    }
}

/// Consecutive text and entity references, treated as one value.
struct TextRun {
    range: Range<usize>,
    value: String,
}

struct Walker<'a, 'v> {
    text: &'a str,
    visitor: &'v mut dyn LeafVisitor,
    splicer: Splicer<'a>,
    elements: Vec<String>,
    run: Option<TextRun>,
    /// The most recent `<key>` text inside a property-list `<dict>`.
    dict_key: Option<String>,
}

impl Walker<'_, '_> {
    /// Byte range of a slice borrowed from the input.
    fn locate(&self, part: &str) -> Result<Range<usize>, FormatError> {
        let base = self.text.as_ptr() as usize;
        let start = (part.as_ptr() as usize)
            .checked_sub(base)
            .filter(|s| s + part.len() <= self.text.len())
            .ok_or_else(|| FormatError::new("xml", "event text is not part of the input"))?;
        Ok(start..start + part.len())
    }

    fn push_text(&mut self, range: Range<usize>, decoded: &str) {
        match &mut self.run {
            Some(run) if run.range.end == range.start => {
                run.range.end = range.end;
                run.value.push_str(decoded);
            }
            _ => {
                self.flush();
                self.run = Some(TextRun {
                    range,
                    value: decoded.to_owned(),
                });
            }
        }
    }

    fn flush(&mut self) {
        let Some(run) = self.run.take() else { return };
        if run.value.trim().is_empty() {
            return;
        }
        if self.in_dict() && self.elements.last().is_some_and(|e| e == "key") {
            self.dict_key = Some(run.value);
            return;
        }
        self.scalar(run.range.clone(), run.range, &run.value, |v| {
            escape(v).into_owned()
        });
    }

    fn scalar(
        &mut self,
        raw: Range<usize>,
        content: Range<usize>,
        value: &str,
        encode: impl FnOnce(&str) -> String,
    ) {
        let key = if self.in_dict() {
            self.dict_key.as_deref()
        } else {
            self.elements.last().map(String::as_str)
        };
        let leaf = Leaf::new(value).with_key(key).with_offset(content.start);
        if let Some(replacement) = self.visitor.leaf(&leaf) {
            self.splicer
                .apply(raw, content, value, &replacement, encode);
        }
    }

    /// Whether the current element is a direct child of a `<dict>`.
    fn in_dict(&self) -> bool {
        self.elements.len() >= 2 && self.elements[self.elements.len() - 2] == "dict"
    }

    /// Enter an element and visit its attribute values. Returns its name.
    fn element(&mut self, start: &BytesStart<'_>) -> Result<String, FormatError> {
        let name = start.name().as_ref().to_owned();
        let mut attributes = Vec::new();
        for attr in start.attributes().with_checks(false) {
            let attr = attr.map_err(|e| FormatError::new("xml", e))?;
            let key = attr.key.as_ref().to_owned();
            let content = self.locate(&attr.value)?;
            let value = attr
                .normalized_value(Default::default())
                .map_err(|e| FormatError::new("xml", e))?
                .into_owned();
            attributes.push((key, content, value));
        }

        let summary: Object<'_> = attributes
            .iter()
            .map(|(k, _, v)| (k.as_str(), Some(v.as_str())))
            .collect();
        self.visitor.enter(Some(&name), Container::Object(&summary));
        for (key, content, value) in &attributes {
            let leaf = Leaf::new(value)
                .with_key(Some(key))
                .with_offset(content.start);
            if let Some(replacement) = self.visitor.leaf(&leaf) {
                let raw = content.start - 1..content.end + 1;
                self.splicer
                    .apply(raw, content.clone(), value, &replacement, |v| {
                        format!("\"{}\"", escape(v))
                    });
            }
        }
        Ok(name)
    }
}
