use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::detect::{self, Detection, Detector, LeafContext, Pii, RulesetDetector};
use crate::format::{
    Container, Edit, Format, FormatRegistry, Leaf, LeafVisitor, Replacement, apply_edits,
};
use crate::policy::{DefaultPolicy, LeafPolicy};
use crate::render::{self, Allow};

/// Configures a [`Redactor`].
///
/// [`RedactorBuilder::new`] starts empty: no detectors, only the plain-text
/// format, and the [`DefaultPolicy`]. [`Redactor::builder`] starts from
/// [`defaults`](RedactorBuilder::defaults).
pub struct RedactorBuilder {
    detectors: Vec<Box<dyn Detector>>,
    ruleset: Option<RulesetDetector>,
    pii: Vec<Pii>,
    formats: FormatRegistry,
    policy: Arc<dyn LeafPolicy>,
}

impl Default for RedactorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactorBuilder {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
            ruleset: None,
            pii: Vec::new(),
            formats: FormatRegistry::text_only(),
            policy: Arc::new(DefaultPolicy),
        }
    }

    /// Add the built-in secret detectors (including the bundled ruleset), all
    /// formats compiled into this build, and the default policy. PII
    /// detection stays off; enable it with [`pii`](Self::pii).
    pub fn defaults(mut self) -> Self {
        for detector in detect::default_detectors() {
            if detector.name() == "ruleset" {
                self.ruleset
                    .get_or_insert_with(|| RulesetDetector::default_rules().clone());
            } else {
                self.detectors.push(detector);
            }
        }
        for format in crate::format::builtin() {
            self.formats.register(format);
        }
        self.policy = Arc::new(DefaultPolicy);
        self
    }

    /// Add a detector.
    pub fn detector(mut self, detector: impl Detector + 'static) -> Self {
        self.detectors.push(Box::new(detector));
        self
    }

    /// Add a boxed detector.
    pub fn boxed_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Use `ruleset` instead of the bundled one.
    pub fn ruleset(mut self, ruleset: RulesetDetector) -> Self {
        self.ruleset = Some(ruleset);
        self
    }

    /// Enable PII categories.
    pub fn pii(mut self, categories: impl IntoIterator<Item = Pii>) -> Self {
        for category in categories {
            if !self.pii.contains(&category) {
                self.pii.push(category);
            }
        }
        self
    }

    /// Add a format, replacing any registered format with the same name.
    pub fn format(mut self, format: impl Format + 'static) -> Self {
        self.formats.register(Arc::new(format));
        self
    }

    /// Set the policy that decides which structured values are scanned.
    pub fn policy(mut self, policy: impl LeafPolicy + 'static) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    pub fn build(self) -> Redactor {
        let mut detectors = self.detectors;
        if let Some(ruleset) = self.ruleset {
            detectors.push(Box::new(ruleset));
        }
        detectors.extend(self.pii.into_iter().map(Pii::detector));
        Redactor {
            detectors: detectors.into(),
            formats: self.formats,
            policy: self.policy,
        }
    }
}

/// How to choose the format of an input.
#[derive(Debug, Clone, Copy)]
pub enum FormatHint<'a> {
    /// Recognize the format from content, falling back to plain text.
    Auto,
    /// Use the named format.
    Name(&'a str),
    /// Choose by file name or extension, then by content, then plain text.
    Path(&'a Path),
}

/// Finds and redacts secrets. Build one with [`Redactor::builder`].
///
/// A `Redactor` is immutable and can be shared across threads.
#[derive(Clone)]
pub struct Redactor {
    detectors: Arc<[Box<dyn Detector>]>,
    formats: FormatRegistry,
    policy: Arc<dyn LeafPolicy>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Redactor {
    /// A builder preloaded with the defaults.
    pub fn builder() -> RedactorBuilder {
        RedactorBuilder::new().defaults()
    }

    pub fn formats(&self) -> &FormatRegistry {
        &self.formats
    }

    /// Redact `input` as plain text, with every finding replaced.
    pub fn redact_str(&self, input: &str) -> String {
        let redaction = self
            .redact(
                input.as_bytes(),
                FormatHint::Name(crate::format::Text::NAME),
            )
            .expect("plain text always parses");
        let bytes = redaction
            .render(&Allow::none())
            .expect("plain text always renders");
        String::from_utf8(bytes).expect("redacting UTF-8 text yields UTF-8")
    }

    /// Scan `input` and number every finding.
    ///
    /// The returned [`Redaction`] can be rendered any number of times with
    /// different [`Allow`] lists; numbering depends only on the input and
    /// this redactor's configuration.
    ///
    /// If the input does not parse as the chosen format, it is redacted as
    /// plain text instead and a warning is recorded, unless the format was
    /// requested by name, in which case the parse error is returned.
    pub fn redact<'a>(
        &self,
        input: &'a [u8],
        hint: FormatHint<'_>,
    ) -> Result<Redaction<'a>, Error> {
        let (format, explicit) = match hint {
            FormatHint::Name(name) => (
                self.formats
                    .get(name)
                    .ok_or_else(|| Error::UnknownFormat(name.to_owned()))?,
                true,
            ),
            FormatHint::Path(path) => (
                self.formats
                    .for_path(path)
                    .or_else(|| self.formats.sniff(input))
                    .unwrap_or_else(|| self.formats.text()),
                false,
            ),
            FormatHint::Auto => (
                self.formats
                    .sniff(input)
                    .unwrap_or_else(|| self.formats.text()),
                false,
            ),
        };

        let mut warnings = Vec::new();
        let mut collector = Collector::new(self.policy.as_ref());
        let format = match format.rewrite(input, &mut collector) {
            Ok(_) => format,
            Err(err) if !explicit => {
                warnings.push(format!("{err}; treating input as plain text"));
                let text = self.formats.text();
                collector = Collector::new(self.policy.as_ref());
                text.rewrite(input, &mut collector)?;
                text
            }
            Err(err) => return Err(err.into()),
        };

        let detected = self.detect_all(&collector.leaves);
        let mut redaction = Redaction {
            input,
            format,
            leaves: HashMap::new(),
            findings: Vec::new(),
            warnings,
        };
        redaction.number(&collector.leaves, detected);
        Ok(redaction)
    }

    fn detect_all(&self, leaves: &[CollectedLeaf]) -> Vec<Vec<Detection>> {
        let run = |leaf: &CollectedLeaf| {
            let ctx = LeafContext {
                key: leaf.key.as_deref(),
                credential_context: leaf.credential_context,
            };
            let mut out = Vec::new();
            for detector in self.detectors.iter() {
                detector.detect(&leaf.value, &ctx, &mut out);
            }
            render::merge(&leaf.value, out)
        };
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            leaves.par_iter().map(run).collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            leaves.iter().map(run).collect()
        }
    }
}

/// The result of scanning an input: numbered findings, ready to render.
pub struct Redaction<'a> {
    input: &'a [u8],
    format: Arc<dyn Format>,
    /// Redacted ranges and their ids, by leaf index.
    leaves: HashMap<usize, Vec<(Range<usize>, u32)>>,
    findings: Vec<Finding>,
    warnings: Vec<String>,
}

/// One numbered redaction. Every occurrence of the same text shares an id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The number shown in `REDACTION-<id>`, starting at 1.
    pub id: u32,
    /// The redacted text.
    pub secret: String,
    /// What detected the first occurrence.
    pub detector: String,
    /// Key of the value containing the first occurrence, if any.
    pub key: Option<String>,
    /// Byte offset of the first occurrence in the input, when the format
    /// reports value positions. Approximate for values containing escape
    /// sequences.
    pub offset: Option<usize>,
    /// How many times the text was redacted.
    pub occurrences: usize,
}

impl Redaction<'_> {
    /// The format the input was processed as.
    pub fn format(&self) -> &str {
        self.format.name()
    }

    /// Findings ordered by id.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Non-fatal problems, such as falling back to plain text.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// 1-based line and column of a byte offset in the input.
    pub fn line_col(&self, offset: usize) -> (usize, usize) {
        let before = &self.input[..offset.min(self.input.len())];
        let line = memchr::memchr_iter(b'\n', before).count() + 1;
        let line_start = memchr::memrchr(b'\n', before).map_or(0, |i| i + 1);
        (line, offset - line_start + 1)
    }

    /// The input with every finding not in `allow` replaced by its token.
    pub fn render(&self, allow: &Allow) -> Result<Vec<u8>, Error> {
        if self.findings.iter().all(|f| allow.contains(f.id)) {
            return Ok(self.input.to_vec());
        }
        let mut visitor = Renderer {
            leaves: &self.leaves,
            allow,
            index: 0,
        };
        Ok(self.format.rewrite(self.input, &mut visitor)?)
    }

    fn number(&mut self, leaves: &[CollectedLeaf], detected: Vec<Vec<Detection>>) {
        let mut ids: HashMap<String, u32> = HashMap::new();
        for (leaf, detections) in leaves.iter().zip(detected) {
            if detections.is_empty() {
                continue;
            }
            let mut ranges = Vec::with_capacity(detections.len());
            for detection in detections {
                let text = &leaf.value[detection.range.clone()];
                let id = match ids.get(text) {
                    Some(&id) => id,
                    None => {
                        let id = self.findings.len() as u32 + 1;
                        ids.insert(text.to_owned(), id);
                        self.findings.push(Finding {
                            id,
                            secret: text.to_owned(),
                            detector: detection.label,
                            key: leaf.key.clone(),
                            offset: leaf.offset.map(|o| o + detection.range.start),
                            occurrences: 0,
                        });
                        id
                    }
                };
                ranges.push((detection.range, id));
            }
            self.leaves.insert(leaf.index, ranges);
        }

        // A value that exactly equals something redacted elsewhere is the
        // same secret stored under another key, so it is redacted too.
        // Substring matches are not propagated, since short secrets would
        // then match unrelated text.
        for leaf in leaves {
            let Some(&id) = ids.get(leaf.value.as_str()) else {
                continue;
            };
            self.leaves
                .insert(leaf.index, vec![(0..leaf.value.len(), id)]);
        }

        for finding in &mut self.findings {
            finding.occurrences = 0;
        }
        for ranges in self.leaves.values() {
            for (_, id) in ranges {
                self.findings[*id as usize - 1].occurrences += 1;
            }
        }
    }
}

struct CollectedLeaf {
    index: usize,
    value: String,
    key: Option<String>,
    credential_context: bool,
    offset: Option<usize>,
}

#[derive(Clone, Copy)]
struct Frame {
    skipped: bool,
    credential_context: bool,
}

/// Records every scannable leaf, applying the policy.
struct Collector<'p> {
    policy: &'p dyn LeafPolicy,
    stack: Vec<Frame>,
    index: usize,
    leaves: Vec<CollectedLeaf>,
}

impl<'p> Collector<'p> {
    fn new(policy: &'p dyn LeafPolicy) -> Self {
        Self {
            policy,
            stack: Vec::new(),
            index: 0,
            leaves: Vec::new(),
        }
    }

    fn top(&self) -> Frame {
        self.stack.last().copied().unwrap_or(Frame {
            skipped: false,
            credential_context: false,
        })
    }
}

impl LeafVisitor for Collector<'_> {
    fn enter(&mut self, key: Option<&str>, container: Container<'_, '_>) {
        let parent = self.top();
        let mut frame = Frame {
            skipped: parent.skipped || key.is_some_and(|k| self.policy.skip_key(k)),
            credential_context: parent.credential_context,
        };
        if let Container::Object(object) = container {
            frame.skipped |= self.policy.skip_object(object);
            frame.credential_context |= self.policy.credential_context(object);
        }
        self.stack.push(frame);
    }

    fn exit(&mut self) {
        self.stack.pop();
    }

    fn leaf(&mut self, leaf: &Leaf<'_>) -> Option<Replacement> {
        let index = self.index;
        self.index += 1;
        let frame = self.top();
        if frame.skipped || leaf.key.is_some_and(|k| self.policy.skip_key(k)) {
            return None;
        }
        self.leaves.push(CollectedLeaf {
            index,
            value: leaf.value.to_owned(),
            key: leaf.key.map(str::to_owned),
            credential_context: frame.credential_context,
            offset: leaf.offset,
        });
        None
    }
}

/// Replaces recorded ranges with tokens.
struct Renderer<'r> {
    leaves: &'r HashMap<usize, Vec<(Range<usize>, u32)>>,
    allow: &'r Allow,
    index: usize,
}

impl LeafVisitor for Renderer<'_> {
    fn enter(&mut self, _key: Option<&str>, _container: Container<'_, '_>) {}

    fn exit(&mut self) {}

    fn leaf(&mut self, leaf: &Leaf<'_>) -> Option<Replacement> {
        let index = self.index;
        self.index += 1;
        let ranges = self.leaves.get(&index)?;
        let edits: Vec<Edit> = ranges
            .iter()
            .filter(|(range, id)| !self.allow.contains(*id) && range.end <= leaf.value.len())
            .map(|(range, id)| Edit {
                range: range.clone(),
                text: render::token(*id),
            })
            .collect();
        if edits.is_empty() {
            return None;
        }
        Some(Replacement {
            value: apply_edits(leaf.value, &edits),
            edits,
        })
    }
}
