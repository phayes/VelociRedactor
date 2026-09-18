use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::detect::{
    self, Detection, Detector, EntropyDetector, LeafContext, Pii, RulesetDetector,
};
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
    entropy: Option<EntropyDetector>,
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
            entropy: None,
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
            match detector.name() {
                "ruleset" => {
                    self.ruleset
                        .get_or_insert_with(|| RulesetDetector::default_rules().clone());
                }
                "entropy" => {
                    self.entropy.get_or_insert_with(EntropyDetector::default);
                }
                _ => self.detectors.push(detector),
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

    /// Set the entropy threshold for tokens that are not under a sensitive
    /// key (default [`EntropyDetector::DEFAULT_THRESHOLD`]).
    ///
    /// Enables the entropy detector if it is not already present.
    pub fn entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy
            .get_or_insert_with(EntropyDetector::default)
            .threshold = threshold;
        self
    }

    /// Set the entropy threshold for values under a sensitive key (default
    /// [`EntropyDetector::SENSITIVE_THRESHOLD`]).
    ///
    /// Enables the entropy detector if it is not already present.
    pub fn sensitive_threshold(mut self, threshold: f64) -> Self {
        self.entropy
            .get_or_insert_with(EntropyDetector::default)
            .sensitive_threshold = threshold;
        self
    }

    pub fn build(self) -> Redactor {
        let mut detectors = self.detectors;
        if let Some(entropy) = self.entropy {
            detectors.insert(0, Box::new(entropy));
        }
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
    /// Skip format detection and treat the input as plain text.
    Raw,
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
            .redact(input.as_bytes(), FormatHint::Raw)
            .expect("plain text always parses");
        let bytes = redaction
            .render(&Allow::none())
            .expect("plain text always renders");
        String::from_utf8(bytes).expect("redacting UTF-8 text yields UTF-8")
    }

    /// Scan `input` and identify every secret.
    ///
    /// The returned [`Redaction`] can be rendered any number of times with
    /// different [`Allow`] lists.
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
            FormatHint::Raw => (self.formats.text(), true),
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
        redaction.identify(&collector.leaves, detected);
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

/// The result of scanning an input: identified secrets, ready to render.
pub struct Redaction<'a> {
    input: &'a [u8],
    format: Arc<dyn Format>,
    /// Redacted ranges and the index of their finding, by leaf index.
    leaves: HashMap<usize, Vec<(Range<usize>, usize)>>,
    findings: Vec<Finding>,
    warnings: Vec<String>,
}

/// One redacted secret. Every occurrence of the same text shares a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// 1-based id of this distinct value in the document. Same text shares
    /// an id. The replacement token is `REDACTION-<id>`.
    pub id: usize,
    /// The redacted text.
    pub secret: String,
    /// What detected the first occurrence.
    pub detector: String,
    /// Length of the secret in bytes.
    pub len: usize,
    /// Field (object key) of the value containing the first occurrence, if any.
    pub field: Option<String>,
    /// Byte offsets of every occurrence in the input, ascending, when the
    /// format reports value positions. Approximate for values containing
    /// escape sequences.
    pub offsets: Vec<usize>,
    /// How many times the text was redacted.
    pub occurrences: usize,
}

impl Finding {
    /// The replacement token for this secret.
    pub fn token(&self) -> String {
        render::token(self.id)
    }

    /// Byte offset of the first occurrence, when known.
    pub fn offset(&self) -> Option<usize> {
        self.offsets.first().copied()
    }
}

impl Redaction<'_> {
    /// The format the input was processed as.
    pub fn format(&self) -> &str {
        self.format.name()
    }

    /// Findings in order of first appearance.
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
        if self.findings.iter().all(|f| allow.allows(f)) {
            return Ok(self.input.to_vec());
        }
        let tokens: Vec<Option<String>> = self
            .findings
            .iter()
            .map(|f| (!allow.allows(f)).then(|| f.token()))
            .collect();
        let mut visitor = Renderer {
            leaves: &self.leaves,
            tokens: &tokens,
            index: 0,
        };
        Ok(self.format.rewrite(self.input, &mut visitor)?)
    }

    fn identify(&mut self, leaves: &[CollectedLeaf], detected: Vec<Vec<Detection>>) {
        let mut by_secret: HashMap<String, usize> = HashMap::new();
        for (leaf, detections) in leaves.iter().zip(detected) {
            if detections.is_empty() {
                continue;
            }
            let mut ranges = Vec::with_capacity(detections.len());
            for detection in detections {
                let text = &leaf.value[detection.range.clone()];
                let index = *by_secret.entry(text.to_owned()).or_insert_with(|| {
                    self.findings.push(Finding {
                        id: self.findings.len() + 1,
                        secret: text.to_owned(),
                        detector: detection.label,
                        len: text.len(),
                        field: leaf.key.clone(),
                        offsets: Vec::new(),
                        occurrences: 0,
                    });
                    self.findings.len() - 1
                });
                ranges.push((detection.range, index));
            }
            self.leaves.insert(leaf.index, ranges);
        }

        // A value that exactly equals something redacted elsewhere is the
        // same secret stored under another key, so it is redacted too.
        // Substring matches are not propagated, since short secrets would
        // then match unrelated text.
        for leaf in leaves {
            if let Some(&index) = by_secret.get(leaf.value.as_str()) {
                self.leaves
                    .insert(leaf.index, vec![(0..leaf.value.len(), index)]);
            }
        }

        for leaf in leaves {
            let Some(ranges) = self.leaves.get(&leaf.index) else {
                continue;
            };
            for (range, index) in ranges {
                let finding = &mut self.findings[*index];
                finding.occurrences += 1;
                if let Some(offset) = leaf.offset {
                    finding.offsets.push(offset + range.start);
                }
            }
        }
        for finding in &mut self.findings {
            finding.offsets.sort_unstable();
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
    leaves: &'r HashMap<usize, Vec<(Range<usize>, usize)>>,
    /// The token for each finding, or `None` if it is allowed.
    tokens: &'r [Option<String>],
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
            .filter(|(range, _)| range.end <= leaf.value.len())
            .filter_map(|(range, index)| {
                Some(Edit {
                    range: range.clone(),
                    text: self.tokens[*index].clone()?,
                })
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
