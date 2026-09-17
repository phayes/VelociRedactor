use csv::{ReaderBuilder, StringRecord, Terminator, WriterBuilder};

use super::{Container, Format, FormatError, Leaf, LeafVisitor, Object, Splicer};

/// Delimiter-separated values.
///
/// The first row is treated as a header: its cells are scanned like any other
/// value and name the cells of later rows. Each row is an object. Rows with a
/// redaction are re-written with standard quoting; other rows are untouched.
#[derive(Debug, Clone, Copy)]
pub struct Csv {
    name: &'static str,
    delimiter: u8,
    extensions: &'static [&'static str],
}

impl Csv {
    pub const fn comma() -> Self {
        Self {
            name: "csv",
            delimiter: b',',
            extensions: &["csv"],
        }
    }

    pub const fn tab() -> Self {
        Self {
            name: "tsv",
            delimiter: b'\t',
            extensions: &["tsv", "tab"],
        }
    }

    pub const fn pipe() -> Self {
        Self {
            name: "psv",
            delimiter: b'|',
            extensions: &["psv"],
        }
    }

    /// A format for another delimiter.
    pub const fn with_delimiter(name: &'static str, delimiter: u8) -> Self {
        Self {
            name,
            delimiter,
            extensions: &[],
        }
    }
}

impl Format for Csv {
    fn name(&self) -> &str {
        self.name
    }

    fn extensions(&self) -> &[&str] {
        self.extensions
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let error = |e: csv::Error| FormatError::new(self.name, e);
        let mut reader = ReaderBuilder::new()
            .delimiter(self.delimiter)
            .has_headers(false)
            .flexible(true)
            .from_reader(input);

        let mut splicer = Splicer::new(input);
        let mut header: Option<StringRecord> = None;
        let mut record = StringRecord::new();
        let mut consumed = 0;
        loop {
            let start = (reader.position().byte() as usize).max(consumed);
            if !reader.read_record(&mut record).map_err(error)? {
                break;
            }
            // The reader stops between the `\r` and `\n` of a CRLF terminator.
            let mut end = reader.position().byte() as usize;
            if input[..end].ends_with(b"\r") && input.get(end) == Some(&b'\n') {
                end += 1;
            }
            consumed = end;

            let keys: Vec<Option<&str>> = (0..record.len())
                .map(|i| header.as_ref().and_then(|h| h.get(i)))
                .collect();
            let summary: Object<'_> = keys
                .iter()
                .zip(record.iter())
                .filter_map(|(k, v)| Some(((*k)?, Some(v))))
                .collect();
            visitor.enter(None, Container::Object(&summary));
            let mut changed = false;
            let mut cells: Vec<String> = Vec::with_capacity(record.len());
            for (i, value) in record.iter().enumerate() {
                let leaf = Leaf::new(value).with_key(keys[i]).with_offset(start);
                match visitor.leaf(&leaf) {
                    Some(replacement) => {
                        changed = true;
                        cells.push(replacement.value);
                    }
                    None => cells.push(value.to_owned()),
                }
            }
            visitor.exit();

            if changed {
                let raw = &input[start..end];
                let terminator = if raw.ends_with(b"\r\n") {
                    Terminator::CRLF
                } else {
                    Terminator::Any(b'\n')
                };
                let mut writer = WriterBuilder::new()
                    .delimiter(self.delimiter)
                    .terminator(terminator)
                    .flexible(true)
                    .from_writer(Vec::new());
                writer.write_record(&cells).map_err(error)?;
                let mut row = writer
                    .into_inner()
                    .map_err(|e| FormatError::new(self.name, e.error()))?;
                if !raw.ends_with(b"\n") {
                    // The last row had no line terminator.
                    while row.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                        row.pop();
                    }
                }
                splicer.replace(start..end, row);
            }
            if header.is_none() {
                header = Some(record.clone());
            }
        }
        Ok(splicer.finish())
    }
}
