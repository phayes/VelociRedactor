use super::{Format, FormatError, Leaf, LeafVisitor, Splicer};

/// Plain text. The whole input is one value.
///
/// Bytes that are not valid UTF-8 are passed through untouched; each valid
/// UTF-8 run between them is scanned as a separate value.
#[derive(Debug, Clone, Copy, Default)]
pub struct Text;

impl Text {
    pub const NAME: &'static str = "text";
}

impl Format for Text {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn extensions(&self) -> &[&str] {
        &["txt", "log", "md", "text"]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let mut splicer = Splicer::new(input);
        let mut offset = 0;
        for chunk in input.utf8_chunks() {
            let valid = chunk.valid();
            if !valid.is_empty() {
                let leaf = Leaf::new(valid).with_offset(offset);
                if let Some(replacement) = visitor.leaf(&leaf) {
                    let range = offset..offset + valid.len();
                    splicer.apply(range.clone(), range, valid, &replacement, |v| v.to_owned());
                }
            }
            offset += valid.len() + chunk.invalid().len();
        }
        Ok(splicer.finish())
    }
}
