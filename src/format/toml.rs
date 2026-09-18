use toml_edit::{Document, Item, Table, Value};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer, comment};

/// TOML. String values are edited in place.
#[derive(Debug, Clone, Copy, Default)]
pub struct Toml;

impl Format for Toml {
    fn name(&self) -> &str {
        "toml"
    }

    fn extensions(&self) -> &[&str] {
        &["toml"]
    }

    fn file_names(&self) -> &[&str] {
        &[
            "cargo.lock",
            "pipfile",
            "poetry.lock",
            "uv.lock",
            "pdm.lock",
        ]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("toml", e))?;
        let document = Document::parse(text).map_err(|e| FormatError::new("toml", e))?;
        let mut splicer = Splicer::new(input);
        if visitor.wants_comments() {
            comment::visit(text, &comment::toml(text), visitor, &mut splicer);
        }
        let mut walker = Walker {
            text,
            visitor,
            splicer,
        };
        walker.table(document.as_table(), None);
        Ok(walker.splicer.finish())
    }
}

struct Walker<'a, 'v> {
    text: &'a str,
    visitor: &'v mut dyn LeafVisitor,
    splicer: Splicer<'a>,
}

impl Walker<'_, '_> {
    fn table(&mut self, table: &Table, key: Option<&str>) {
        let summary: Object<'_> = table.iter().map(|(k, item)| (k, item.as_str())).collect();
        self.visitor.enter(key, Container::Object(&summary));
        for (k, item) in table.iter() {
            self.item(item, k);
        }
        self.visitor.exit();
    }

    fn item(&mut self, item: &Item, key: &str) {
        match item {
            Item::None => {}
            Item::Value(value) => self.value(value, Some(key)),
            Item::Table(table) => self.table(table, Some(key)),
            Item::ArrayOfTables(tables) => {
                self.visitor.enter(Some(key), Container::Array);
                for table in tables.iter() {
                    self.table(table, None);
                }
                self.visitor.exit();
            }
        }
    }

    fn value(&mut self, value: &Value, key: Option<&str>) {
        match value {
            Value::String(s) => {
                let decoded = s.value();
                let span = value.span();
                let quote = span.as_ref().map_or(1, |span| {
                    let raw = &self.text[span.clone()];
                    if raw.starts_with("\"\"\"") || raw.starts_with("'''") {
                        3
                    } else {
                        1
                    }
                });
                let mut leaf = Leaf::new(decoded).with_key(key);
                if let Some(span) = &span {
                    leaf = leaf.with_offset(span.start + quote);
                }
                let (Some(replacement), Some(span)) = (self.visitor.leaf(&leaf), span) else {
                    return;
                };
                let content = span.start + quote..span.end - quote;
                self.splicer
                    .apply(span, content, decoded, &replacement, |v| {
                        // A JSON string literal is also a valid TOML basic string.
                        serde_json::to_string(v).expect("strings always serialize")
                    });
            }
            Value::Array(array) => {
                self.visitor.enter(key, Container::Array);
                for element in array.iter() {
                    self.value(element, None);
                }
                self.visitor.exit();
            }
            Value::InlineTable(table) => {
                let summary: Object<'_> = table.iter().map(|(k, v)| (k, v.as_str())).collect();
                self.visitor.enter(key, Container::Object(&summary));
                for (k, v) in table.iter() {
                    self.value(v, Some(k));
                }
                self.visitor.exit();
            }
            Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_) => {}
        }
    }
}
