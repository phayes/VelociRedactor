//! Extending redactify with a custom detector and a custom file format.
//!
//! Run with `cargo run --example custom`.

use redactify::detect::{Detection, Detector, LeafContext};
use redactify::format::{Format, FormatError, Leaf, LeafVisitor, Splicer};
use redactify::{Allow, FormatHint, Redactor};

/// Flags internal ticket numbers such as `TICKET-1234`.
struct TicketDetector;

impl Detector for TicketDetector {
    fn name(&self) -> &str {
        "ticket"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for (start, _) in value.match_indices("TICKET-") {
            let digits = value[start + 7..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            if digits > 0 {
                out.push(Detection::new(start..start + 7 + digits, self.name()));
            }
        }
    }
}

/// A `key => value` per line format. Only the text after `=>` is a value.
struct Arrow;

impl Format for Arrow {
    fn name(&self) -> &str {
        "arrow"
    }

    fn extensions(&self) -> &[&str] {
        &["arrow"]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("arrow", e))?;
        let mut splicer = Splicer::new(input);
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            if let Some((key, value)) = line.trim_end().split_once(" => ") {
                let start = offset + key.len() + 4;
                let leaf = Leaf::new(value)
                    .with_key(Some(key.trim()))
                    .with_offset(start);
                if let Some(replacement) = visitor.leaf(&leaf) {
                    let range = start..start + value.len();
                    splicer.apply(range.clone(), range, value, &replacement, str::to_owned);
                }
            }
            offset += line.len();
        }
        Ok(splicer.finish())
    }
}

fn main() {
    let redactor = Redactor::builder()
        .detector(TicketDetector)
        .format(Arrow)
        .build();

    let input = "summary => fixes TICKET-4821\nTICKET-9 => not a value\n";
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Path("notes.arrow".as_ref()))
        .expect("valid input");

    for finding in redaction.findings() {
        println!("{} found by {}", finding.key, finding.detector);
    }
    let output = redaction.render(&Allow::none()).expect("renders");
    print!("{}", String::from_utf8_lossy(&output));
}
