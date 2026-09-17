use std::io::Cursor;

use plist::Value;

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object};

const MAGIC: &[u8] = b"bplist00";

/// Binary property lists. XML property lists are handled by
/// [`Xml`](super::Xml).
///
/// The input is decoded, string values are replaced, and the result is
/// written back as a binary property list.
#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryPlist;

impl Format for BinaryPlist {
    fn name(&self) -> &str {
        "bplist"
    }

    fn sniff(&self, input: &[u8]) -> bool {
        input.starts_with(MAGIC)
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        if !input.starts_with(MAGIC) {
            return Err(FormatError::new("bplist", "not a binary property list"));
        }
        let mut value =
            Value::from_reader(Cursor::new(input)).map_err(|e| FormatError::new("bplist", e))?;
        if !walk(&mut value, None, visitor) {
            return Ok(input.to_vec());
        }
        let mut out = Vec::with_capacity(input.len());
        value
            .to_writer_binary(&mut out)
            .map_err(|e| FormatError::new("bplist", e))?;
        Ok(out)
    }
}

/// Visit `value`, applying replacements in place. Returns whether anything changed.
fn walk(value: &mut Value, key: Option<&str>, visitor: &mut dyn LeafVisitor) -> bool {
    match value {
        Value::String(s) => match visitor.leaf(&Leaf::new(s).with_key(key)) {
            Some(replacement) => {
                *s = replacement.value;
                true
            }
            None => false,
        },
        Value::Array(items) => {
            visitor.enter(key, Container::Array);
            let mut changed = false;
            for item in items {
                changed |= walk(item, None, visitor);
            }
            visitor.exit();
            changed
        }
        Value::Dictionary(dict) => {
            let summary: Object<'_> = dict
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_string()))
                .collect();
            visitor.enter(key, Container::Object(&summary));
            drop(summary);
            let mut changed = false;
            for (k, v) in dict.iter_mut() {
                changed |= walk(v, Some(k), visitor);
            }
            visitor.exit();
            changed
        }
        Value::Boolean(_)
        | Value::Data(_)
        | Value::Date(_)
        | Value::Real(_)
        | Value::Integer(_)
        | Value::Uid(_) => false,
        _ => false,
    }
}
