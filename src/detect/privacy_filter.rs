//! The `privacy_filter` detector: [OpenAI Privacy Filter], a transformer that
//! labels personal data token by token, run through [`privacy_filter_rs`].
//!
//! The model is contextual, and a run of it is expensive, so the detector is
//! [document-scoped](Detector::document_scope): every scanned value of a
//! document is packed into one text, each value introduced by its key, and the
//! model runs over that text in windows. What it finds is then mapped back to
//! the values it came from. Keys and separators are only context: nothing
//! outside a value is ever reported.
//!
//! Loading the model takes seconds and, at its peak, up to 16 GB of memory,
//! so build one [`Redactor`](crate::Redactor) and reuse it.
//!
//! [OpenAI Privacy Filter]: https://huggingface.co/openai/privacy-filter

use std::fmt;
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;

use burn::prelude::Backend;
use privacy_filter_rs::config::{SPAN_LABELS, label_to_category, label_to_prefix};
use privacy_filter_rs::model::privacy_filter::PrivacyFilterModel;
use privacy_filter_rs::{viterbi, weights};
use serde::Deserialize;
use tokenizers::Tokenizer;

pub use privacy_filter_rs::config::{ModelConfig, ViterbiConfig};

use super::{Detection, Detector, DocumentValue, LeafContext};
use crate::Error;

/// The name the detector is configured and reported under.
const NAME: &str = "privacy_filter";

/// The Hugging Face repository the model is published in.
pub const MODEL_REPO: &str = "eugenehp/privacy-filter-rs";

/// The files a model directory holds, as published on Hugging Face.
pub const MODEL_FILES: &[&str] = &[
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "viterbi_calibration.json",
];

/// Between packed values, so that no value reads as part of the one before.
const SEPARATOR: &str = "\n\n";

/// The `privacy_filter` detector's settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyFilterConfig {
    /// The directory holding the model: `config.json`, `model.safetensors`,
    /// `tokenizer.json`, and optionally `viterbi_calibration.json`. Relative
    /// to the configuration file it was read from. When not given, the copy
    /// in the Hugging Face cache; see [`default_model_dir`].
    #[serde(default)]
    pub model_dir: Option<PathBuf>,
    /// Where to run the model.
    #[serde(default)]
    pub device: Device,
    /// What the model is told about each value besides its text.
    #[serde(default)]
    pub context: Context,
    /// Spans the model is less sure of than this (mean per-token
    /// probability, 0 to 1) are not reported.
    #[serde(default = "default_min_score")]
    pub min_score: f32,
    /// The categories to report, from [`categories`]. All of them by
    /// default.
    #[serde(default = "default_categories")]
    pub categories: Vec<String>,
    /// The most tokens given to the model at once. Longer documents are read
    /// in overlapping windows of this size. Attention memory grows with its
    /// square.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: usize,
    /// How the model's per-token labels are decoded into spans.
    #[serde(default)]
    pub viterbi: Viterbi,
    /// The model's architecture. Read from `config.json` in
    /// [`model_dir`](Self::model_dir) when not given.
    #[serde(default)]
    pub model: Option<ModelConfig>,
}

fn default_min_score() -> f32 {
    0.5
}

fn default_categories() -> Vec<String> {
    SPAN_LABELS.iter().map(|c| c.to_string()).collect()
}

fn default_max_tokens() -> usize {
    1024
}

impl Default for PrivacyFilterConfig {
    /// The model in the Hugging Face cache, with everything else default.
    fn default() -> Self {
        Self {
            model_dir: None,
            device: Device::default(),
            context: Context::default(),
            min_score: default_min_score(),
            categories: default_categories(),
            max_tokens: default_max_tokens(),
            viterbi: Viterbi::default(),
            model: None,
        }
    }
}

impl PrivacyFilterConfig {
    /// Settings for the model in `model_dir`, with everything else default.
    pub fn new(model_dir: impl Into<PathBuf>) -> Self {
        Self {
            model_dir: Some(model_dir.into()),
            ..Self::default()
        }
    }
}

/// Where the model is when no `model_dir` is given: the current snapshot of
/// [`MODEL_REPO`] in the Hugging Face cache, which is where
/// `veloci privacy_filter download` puts it by default.
///
/// The cache is `$HF_HUB_CACHE` when set, then `$HF_HOME/hub`, then
/// `$XDG_CACHE_HOME/huggingface/hub`, then `~/.cache/huggingface/hub`.
pub fn default_model_dir() -> Result<PathBuf, String> {
    let cache = hugging_face_cache().ok_or("cannot find the home directory")?;
    let repo = cache.join(format!("models--{}", MODEL_REPO.replace('/', "--")));
    let commit = std::fs::read_to_string(repo.join("refs").join("main")).map_err(|_| {
        format!(
            "no model_dir given, and the model is not in the Hugging Face cache ({}); \
             download it with `veloci privacy_filter download`",
            cache.display()
        )
    })?;
    Ok(repo.join("snapshots").join(commit.trim()))
}

/// The Hugging Face hub cache, found the way Hugging Face's own tools find it.
fn hugging_face_cache() -> Option<PathBuf> {
    let var = |name| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    var("HF_HUB_CACHE")
        .or_else(|| var("HUGGINGFACE_HUB_CACHE"))
        .or_else(|| var("HF_HOME").map(|home| home.join("hub")))
        .or_else(|| var("XDG_CACHE_HOME").map(|c| c.join("huggingface").join("hub")))
        .or_else(|| std::env::home_dir().map(|h| h.join(".cache").join("huggingface").join("hub")))
}

/// Every category the model reports.
pub fn categories() -> &'static [&'static str] {
    SPAN_LABELS
}

/// Where to run the model.
///
/// Written `auto`, `cpu`, `cuda` (the first GPU), or `cuda:N`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Device {
    /// The first CUDA GPU when this build supports CUDA and one is present,
    /// and the CPU otherwise.
    ///
    /// Nothing else is considered: the model computes in 32-bit floats
    /// (16-bit ones derail its expert routing), and at that precision the
    /// CPU, with the platform's BLAS, beats a unified-memory GPU such as
    /// Apple's.
    #[default]
    Auto,
    /// The CPU.
    Cpu,
    /// The CUDA GPU with this index. Needs the `privacy-filter-cuda` feature.
    Cuda(usize),
}

impl FromStr for Device {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "cpu" => Ok(Self::Cpu),
            "cuda" => Ok(Self::Cuda(0)),
            other => other
                .strip_prefix("cuda:")
                .and_then(|n| n.parse().ok())
                .map(Self::Cuda)
                .ok_or_else(|| {
                    format!("unknown device {other:?} (expected auto, cpu, cuda, or cuda:N)")
                }),
        }
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Cpu => f.write_str("cpu"),
            Self::Cuda(n) => write!(f, "cuda:{n}"),
        }
    }
}

impl<'de> Deserialize<'de> for Device {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl Device {
    /// The device `self` stands for on this machine: [`Device::Auto`]
    /// resolved, the others as they are.
    pub fn resolve(self) -> Self {
        match self {
            Self::Auto if cuda_device_count() > 0 => Self::Cuda(0),
            Self::Auto => Self::Cpu,
            other => other,
        }
    }
}

/// How many CUDA GPUs are usable. Zero when this build lacks CUDA, when the
/// driver library is missing, or when it fails to start: running on a GPU
/// that cannot be reached would panic rather than fail.
#[cfg(feature = "privacy-filter-cuda")]
fn cuda_device_count() -> usize {
    use cudarc::driver::{result, sys};

    // SAFETY: only tries to open the driver library, without calling into it.
    if !unsafe { sys::is_culib_present() } {
        return 0;
    }
    result::init()
        .and_then(|()| result::device::get_count())
        .map_or(0, |n| n.max(0) as usize)
}

#[cfg(not(feature = "privacy-filter-cuda"))]
fn cuda_device_count() -> usize {
    0
}

/// What the model is told about each value besides its text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Context {
    /// The value alone.
    None,
    /// The value introduced by its key (`name: Alice`), when it has one.
    #[default]
    Key,
    /// The value introduced by its key path (`users.name: Alice`), when it
    /// has one.
    Path,
}

/// How the model's per-token labels are decoded into spans.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Viterbi {
    /// An operating point named in the model's `viterbi_calibration.json`.
    /// The `default` point decodes without bias when the file is missing.
    OperatingPoint(String),
    /// Transition biases given outright.
    Biases(#[serde(with = "ViterbiDef")] ViterbiConfig),
}

impl Default for Viterbi {
    fn default() -> Self {
        Self::OperatingPoint("default".into())
    }
}

/// [`ViterbiConfig`] as written in a configuration file.
#[derive(Deserialize)]
#[serde(remote = "ViterbiConfig", deny_unknown_fields)]
struct ViterbiDef {
    transition_bias_background_stay: f64,
    transition_bias_background_to_start: f64,
    transition_bias_inside_to_continue: f64,
    transition_bias_inside_to_end: f64,
    transition_bias_end_to_background: f64,
    transition_bias_end_to_start: f64,
}

impl Viterbi {
    fn load(&self, model_dir: &Path) -> Result<ViterbiConfig, String> {
        let name = match self {
            Self::Biases(config) => return Ok(config.clone()),
            Self::OperatingPoint(name) => name,
        };
        let path = model_dir.join("viterbi_calibration.json");
        if !path.exists() && name == "default" {
            return Ok(ViterbiConfig::default());
        }
        ViterbiConfig::from_file(&path, name).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Finds personal data with OpenAI Privacy Filter. See the [module
/// documentation](self).
pub struct PrivacyFilterDetector {
    worker: Worker,
    device: Device,
    tokenizer: Tokenizer,
    viterbi: ViterbiConfig,
    /// Which of [`SPAN_LABELS`] to report.
    report: [bool; SPAN_LABELS.len()],
    context: Context,
    min_score: f32,
    max_tokens: usize,
    /// Tokens of context each window shares with its neighbours.
    overlap: usize,
}

impl fmt::Debug for PrivacyFilterDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivacyFilterDetector")
            .field("device", &self.device())
            .field("context", &self.context)
            .field("min_score", &self.min_score)
            .field("max_tokens", &self.max_tokens)
            .finish_non_exhaustive()
    }
}

impl PrivacyFilterDetector {
    /// Load the model `config` describes, onto the device it names.
    pub fn new(config: &PrivacyFilterConfig) -> Result<Self, Error> {
        let fail = |message: String| Error::Config(format!("{NAME}: {message}"));
        let dir = &match &config.model_dir {
            Some(dir) => dir.clone(),
            None => default_model_dir().map_err(fail)?,
        };

        if config.categories.is_empty() {
            return Err(fail(
                "categories lists nothing to report; to report nothing, \
                 remove the detector instead"
                    .into(),
            ));
        }
        let mut report = [false; SPAN_LABELS.len()];
        for name in &config.categories {
            let index = SPAN_LABELS.iter().position(|c| c == name).ok_or_else(|| {
                fail(format!(
                    "unknown category {name:?} (expected one of {})",
                    SPAN_LABELS.join(", ")
                ))
            })?;
            report[index] = true;
        }
        if !(0.0..=1.0).contains(&config.min_score) {
            return Err(fail(format!(
                "min_score must be between 0 and 1, not {}",
                config.min_score
            )));
        }

        let model_config = match &config.model {
            Some(model) => model.clone(),
            None => {
                let path = dir.join("config.json");
                ModelConfig::from_file(&path)
                    .map_err(|e| fail(format!("{}: {e}", path.display())))?
            }
        };
        // Each window shares one attention span with each neighbour, so a
        // token near a window's edge still sees what it would have seen
        // without the cut.
        let overlap = model_config.sliding_window;
        if config.max_tokens < 4 * overlap {
            return Err(fail(format!(
                "max_tokens must be at least {} for this model (four times its sliding window)",
                4 * overlap
            )));
        }

        let tokenizer_path = dir.join("tokenizer.json");
        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| fail(format!("{}: {e}", tokenizer_path.display())))?;
        // Windows are cut here, so the tokenizer must see the whole text.
        tokenizer
            .with_truncation(None)
            .map_err(|e| fail(e.to_string()))?;
        tokenizer.with_padding(None);

        let viterbi = config.viterbi.load(dir).map_err(fail)?;
        let weights = dir.join("model.safetensors");
        if !weights.is_file() {
            return Err(fail(format!(
                "{} not found; download the model with `veloci privacy_filter download`",
                weights.display()
            )));
        }
        let device = config.device.resolve();
        let worker = Worker::spawn(device, model_config, weights).map_err(fail)?;

        Ok(Self {
            worker,
            device,
            tokenizer,
            viterbi,
            report,
            context: config.context,
            min_score: config.min_score,
            max_tokens: config.max_tokens,
            overlap,
        })
    }

    /// The device the model runs on, with [`Device::Auto`] resolved.
    pub fn device(&self) -> Device {
        self.device
    }

    /// The spans of `text` the model labels, as token ranges.
    fn spans(&self, ids: &[u32], offsets: &[(usize, usize)]) -> Result<Vec<Span>, String> {
        let mut spans = Vec::new();
        for window in windows(ids.len(), self.max_tokens, self.overlap) {
            let logits = self.worker.logits(ids[window.tokens.clone()].to_vec())?;
            let labels = viterbi::viterbi_decode(&logits, window.tokens.len(), &self.viterbi);
            for span in decode(&labels, &logits) {
                let start = window.tokens.start + span.tokens.start;
                if !window.owned.contains(&start) {
                    continue;
                }
                let end = window.tokens.start + span.tokens.end;
                spans.push(Span {
                    bytes: offsets[start].0..offsets[end - 1].1,
                    ..span
                });
            }
        }
        Ok(spans)
    }
}

impl Detector for PrivacyFilterDetector {
    fn name(&self) -> &str {
        NAME
    }

    /// Looks at `value` alone. The redactor never calls this, preferring
    /// [`detect_document`](Detector::detect_document); it is here for callers
    /// using the detector directly. A failure is reported on standard error,
    /// since this method cannot return one.
    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let values = [DocumentValue { value, ctx: *ctx }];
        let mut found = [Vec::new()];
        match self.detect_document(&values, &mut found) {
            Ok(()) => out.append(&mut found[0]),
            Err(err) => eprintln!("warning: {err}"),
        }
    }

    fn document_scope(&self) -> bool {
        true
    }

    fn detect_document(
        &self,
        values: &[DocumentValue<'_>],
        out: &mut [Vec<Detection>],
    ) -> Result<(), Error> {
        let fail = |message: String| Error::Detector {
            name: NAME.into(),
            message,
        };
        let packed = Packed::new(values, self.context);
        if packed.text.is_empty() {
            return Ok(());
        }
        let encoding = self
            .tokenizer
            .encode(packed.text.as_str(), false)
            .map_err(|e| fail(format!("tokenizing: {e}")))?;

        let spans =
            guarded(|| self.spans(encoding.get_ids(), encoding.get_offsets())).map_err(fail)?;

        for span in spans {
            if span.score < self.min_score || !self.report[span.category] {
                continue;
            }
            let label = format!("{NAME}:{}", SPAN_LABELS[span.category]);
            for (index, range) in packed.locate(span.bytes) {
                let range = trim(values[index].value, range);
                if !range.is_empty() {
                    out[index].push(Detection::new(range, label.clone()));
                }
            }
        }
        Ok(())
    }
}

fn panic_message(panic: &Box<dyn std::any::Any + Send>) -> String {
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown cause");
    format!("the model panicked: {message}")
}

/// A request for the model's scores for some tokens, and where to send them.
type Job = (Vec<u32>, mpsc::SyncSender<Result<Vec<f32>, String>>);

/// The thread the model lives on.
///
/// Burn's modules cannot be shared between threads, and a lock would be
/// worse: the model computes with rayon, and a rayon worker waiting on a lock
/// held by another rayon task can deadlock. So the model lives on a rayon pool
/// of its own, created there and never moved, and callers hand it tokens over
/// a channel. A caller waits on the channel, which takes no part in rayon's
/// scheduling, and the model's own parallel work runs only on its own pool,
/// so no pattern of callers — even redactions run in parallel on the global
/// pool — can starve or deadlock it.
struct Worker {
    // Dropped first: that ends the loop serving it, and then the pool.
    jobs: mpsc::Sender<Job>,
    _pool: rayon::ThreadPool,
}

impl Worker {
    /// Load the model on its own pool, returning once it is ready.
    fn spawn(device: Device, config: ModelConfig, weights: PathBuf) -> Result<Self, String> {
        let pool = rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("{NAME}-{i}"))
            .build()
            .map_err(|e| format!("starting the model's threads: {e}"))?;
        let (jobs, queue) = mpsc::channel::<Job>();
        let (ready, loaded) = mpsc::sync_channel(1);
        pool.spawn(move || {
            let engine = match guarded(|| Engine::load(device, &config, &weights)) {
                Ok(engine) => engine,
                Err(e) => return drop(ready.send(Err(e))),
            };
            drop(config);
            if ready.send(Ok(())).is_err() {
                return;
            }
            // Ends when the detector, and with it the sender, is dropped.
            for (ids, reply) in queue {
                let _ = reply.send(guarded(|| engine.logits(&ids)));
            }
        });
        loaded
            .recv()
            .map_err(|_| "the model's thread exited while loading".to_string())??;
        Ok(Self { jobs, _pool: pool })
    }

    /// The model's scores for `ids`: one row of labels per token.
    fn logits(&self, ids: Vec<u32>) -> Result<Vec<f32>, String> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.jobs
            .send((ids, reply))
            .map_err(|_| "the model's thread has exited".to_string())?;
        answer
            .recv()
            .map_err(|_| "the model's thread exited while running".to_string())?
    }
}

/// Run `f`, turning a panic into an error. The model and its decoder index
/// freely and panic on the unexpected; that must fail one document, not the
/// process.
fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|panic| Err(panic_message(&panic)))
}

/// The loaded model, on one backend.
enum Engine {
    Cpu(Inner<burn::backend::NdArray>),
    #[cfg(feature = "privacy-filter-cuda")]
    Cuda(Inner<burn::backend::Cuda>),
}

struct Inner<B: Backend> {
    model: PrivacyFilterModel<B>,
    device: B::Device,
}

impl Engine {
    fn load(device: Device, config: &ModelConfig, weights: &Path) -> Result<Self, String> {
        let weights = weights.to_str().ok_or("the model path is not UTF-8")?;
        match device {
            Device::Auto | Device::Cpu => {
                Inner::load(config, weights, Default::default()).map(Self::Cpu)
            }
            #[cfg(feature = "privacy-filter-cuda")]
            Device::Cuda(index) => {
                let count = cuda_device_count();
                if index >= count {
                    return Err(format!(
                        "device cuda:{index} does not exist ({count} CUDA device(s) found)"
                    ));
                }
                Inner::load(config, weights, burn::backend::cuda::CudaDevice::new(index))
                    .map(Self::Cuda)
            }
            #[cfg(not(feature = "privacy-filter-cuda"))]
            Device::Cuda(_) => Err(
                "device cuda needs velociredactor built with the `privacy-filter-cuda` feature"
                    .into(),
            ),
        }
    }

    /// The model's scores for `ids`: one row of labels per token.
    fn logits(&self, ids: &[u32]) -> Result<Vec<f32>, String> {
        match self {
            Self::Cpu(inner) => inner.logits(ids),
            #[cfg(feature = "privacy-filter-cuda")]
            Self::Cuda(inner) => inner.logits(ids),
        }
    }
}

impl<B: Backend> Inner<B> {
    fn load(config: &ModelConfig, weights: &str, device: B::Device) -> Result<Self, String> {
        let model = weights::load_model(config, weights, &device).map_err(|e| e.to_string())?;
        Ok(Self { model, device })
    }

    fn logits(&self, ids: &[u32]) -> Result<Vec<f32>, String> {
        self.model
            .forward(ids, &self.device)
            .into_data()
            .convert::<f32>()
            .into_vec()
            .map_err(|e| format!("reading the model's output: {e:?}"))
    }
}

/// A labelled run of tokens.
#[derive(Debug, Clone, PartialEq)]
struct Span {
    /// Index into [`SPAN_LABELS`].
    category: usize,
    /// Mean probability the model gave the chosen label of each token.
    score: f32,
    /// Token indices, relative to the decoded sequence.
    tokens: Range<usize>,
    /// Byte range in the packed text, once known.
    bytes: Range<usize>,
}

/// Group decoded BIOES labels into spans: a `B` followed by `I`s and an `E`
/// of the same category, or a lone `S`.
fn decode(labels: &[usize], logits: &[f32]) -> Vec<Span> {
    let width = if labels.is_empty() {
        0
    } else {
        logits.len() / labels.len()
    };
    let probability = |t: usize| {
        let row = &logits[t * width..(t + 1) * width];
        let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let sum: f32 = row.iter().map(|v| (v - max).exp()).sum();
        (row[labels[t]] - max).exp() / sum
    };
    let category = |label: usize| {
        label_to_category(label).and_then(|c| SPAN_LABELS.iter().position(|l| *l == c))
    };

    let mut spans = Vec::new();
    let mut t = 0;
    while t < labels.len() {
        let (Some(prefix), Some(cat)) = (label_to_prefix(labels[t]), category(labels[t])) else {
            t += 1;
            continue;
        };
        let start = t;
        t += 1;
        if prefix == "B" {
            while t < labels.len() && category(labels[t]) == Some(cat) {
                let tag = label_to_prefix(labels[t]);
                if tag == Some("I") {
                    t += 1;
                } else {
                    if tag == Some("E") {
                        t += 1;
                    }
                    break;
                }
            }
        } else if prefix != "S" {
            // An I or E with no B before it; Viterbi decoding never yields
            // one, and there is nothing sound to report.
            continue;
        }
        let score = (start..t).map(probability).sum::<f32>() / (t - start) as f32;
        spans.push(Span {
            category: cat,
            score,
            tokens: start..t,
            bytes: 0..0,
        });
    }
    spans
}

/// One pass of the model over part of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Window {
    /// The tokens given to the model.
    tokens: Range<usize>,
    /// The tokens whose spans this window reports: those it sees with full
    /// context on both sides. Every token is owned by exactly one window.
    owned: Range<usize>,
}

/// Cut `len` tokens into windows of at most `size`, each sharing `overlap`
/// tokens of context with its neighbours.
fn windows(len: usize, size: usize, overlap: usize) -> Vec<Window> {
    if len <= size {
        return vec![Window {
            tokens: 0..len,
            owned: 0..len,
        }];
    }
    let stride = size - 2 * overlap;
    let mut windows = Vec::new();
    let mut start = 0;
    while start < len {
        let end = (start + stride).min(len);
        windows.push(Window {
            tokens: start.saturating_sub(overlap)..(end + overlap).min(len),
            owned: start..end,
        });
        start = end;
    }
    windows
}

/// A document's values joined into one text for the model.
#[derive(Debug)]
struct Packed {
    text: String,
    /// Where each value sits in `text`, in order.
    values: Vec<Range<usize>>,
}

impl Packed {
    fn new(values: &[DocumentValue<'_>], context: Context) -> Self {
        let mut text = String::new();
        let mut ranges = Vec::with_capacity(values.len());
        for value in values {
            if !text.is_empty() {
                text.push_str(SEPARATOR);
            }
            let prefix = match context {
                Context::None => None,
                Context::Key => value.ctx.key,
                Context::Path => Some(value.ctx.path)
                    .filter(|p| !p.is_empty())
                    .or(value.ctx.key),
            };
            if let Some(prefix) = prefix {
                text.push_str(prefix);
                text.push_str(": ");
            }
            let start = text.len();
            text.push_str(value.value);
            ranges.push(start..text.len());
        }
        Self {
            text,
            values: ranges,
        }
    }

    /// The parts of `bytes` (a range of the packed text) that fall inside
    /// values, as `(value index, range within that value)`. A range across
    /// several values yields a part of each; prefixes and separators yield
    /// nothing.
    fn locate(&self, bytes: Range<usize>) -> impl Iterator<Item = (usize, Range<usize>)> + '_ {
        let first = self.values.partition_point(|v| v.end <= bytes.start);
        self.values[first..]
            .iter()
            .take_while(move |v| v.start < bytes.end)
            .enumerate()
            .filter_map(move |(i, v)| {
                let start = bytes.start.max(v.start);
                let end = bytes.end.min(v.end);
                (start < end).then(|| (first + i, start - v.start..end - v.start))
            })
    }
}

/// `range` of `value` without leading or trailing whitespace. The model's
/// tokens carry the space before a word.
fn trim(value: &str, range: Range<usize>) -> Range<usize> {
    let Some(text) = value.get(range.clone()) else {
        return range;
    };
    let start = range.start + (text.len() - text.trim_start().len());
    let end = range.end - (text.len() - text.trim_end().len());
    start..end.max(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(value: &'a str, key: Option<&'a str>, path: &'a str) -> DocumentValue<'a> {
        DocumentValue {
            value,
            ctx: LeafContext {
                key,
                path,
                credential_context: false,
            },
        }
    }

    #[test]
    fn packs_values_after_their_keys() {
        let values = [
            value("Alice Smith", Some("name"), "customer.name"),
            value("plain", None, ""),
        ];
        let packed = Packed::new(&values, Context::Key);
        assert_eq!(packed.text, "name: Alice Smith\n\nplain");
        assert_eq!(&packed.text[packed.values[0].clone()], "Alice Smith");
        assert_eq!(&packed.text[packed.values[1].clone()], "plain");

        let packed = Packed::new(&values, Context::Path);
        assert_eq!(packed.text, "customer.name: Alice Smith\n\nplain");

        let packed = Packed::new(&values, Context::None);
        assert_eq!(packed.text, "Alice Smith\n\nplain");
    }

    #[test]
    fn locates_spans_within_values_only() {
        let values = [
            value("Alice", Some("name"), "name"),
            value("Smith", Some("surname"), "surname"),
        ];
        let packed = Packed::new(&values, Context::Key);
        // "name: Alice\n\nsurname: Smith"
        let whole = 0..packed.text.len();
        let parts: Vec<_> = packed.locate(whole).collect();
        assert_eq!(parts, [(0, 0..5), (1, 0..5)]);

        // A span over the key alone reports nothing.
        assert_eq!(packed.locate(0..4).count(), 0);

        // Part of the second value.
        let start = packed.values[1].start + 1;
        let parts: Vec<_> = packed.locate(start..start + 3).collect();
        assert_eq!(parts, [(1, 1..4)]);
    }

    #[test]
    fn windows_own_every_token_once() {
        for (len, size, overlap) in [(10, 16, 4), (100, 16, 4), (1000, 64, 16), (65, 64, 16)] {
            let windows = windows(len, size, overlap);
            let mut next = 0;
            for w in &windows {
                assert_eq!(w.owned.start, next, "{windows:?}");
                assert!(w.tokens.start <= w.owned.start && w.owned.end <= w.tokens.end);
                assert!(w.tokens.len() <= size, "{w:?}");
                next = w.owned.end;
            }
            assert_eq!(next, len);
        }
    }

    #[test]
    fn windows_give_owned_tokens_context_on_both_sides() {
        let windows = windows(100, 16, 4);
        for w in &windows[1..windows.len() - 1] {
            assert_eq!(w.owned.start - w.tokens.start, 4);
            assert_eq!(w.tokens.end - w.owned.end, 4);
        }
    }

    #[test]
    fn decodes_bioes_spans() {
        // O, B-person, I-person, E-person, O, S-email.
        let person = 1 + 4 * SPAN_LABELS
            .iter()
            .position(|l| *l == "private_person")
            .unwrap();
        let email = 1 + 4 * SPAN_LABELS
            .iter()
            .position(|l| *l == "private_email")
            .unwrap();
        let labels = [0, person, person + 1, person + 2, 0, email + 3];
        let width = 1 + 4 * SPAN_LABELS.len();
        let mut logits = vec![0.0; labels.len() * width];
        for (t, &l) in labels.iter().enumerate() {
            logits[t * width + l] = 20.0;
        }

        let spans = decode(&labels, &logits);
        assert_eq!(spans.len(), 2, "{spans:?}");
        assert_eq!(SPAN_LABELS[spans[0].category], "private_person");
        assert_eq!(spans[0].tokens, 1..4);
        assert_eq!(SPAN_LABELS[spans[1].category], "private_email");
        assert_eq!(spans[1].tokens, 5..6);
        assert!(spans.iter().all(|s| s.score > 0.99));
    }

    #[test]
    fn trims_the_space_a_token_carries() {
        assert_eq!(trim("hi Alice ", 2..9), 3..8);
        assert_eq!(trim("   ", 0..3), 3..3);
    }

    #[test]
    fn parses_devices() {
        assert_eq!("auto".parse(), Ok(Device::Auto));
        assert_eq!("cpu".parse(), Ok(Device::Cpu));
        assert_eq!("cuda".parse(), Ok(Device::Cuda(0)));
        assert_eq!("cuda:2".parse(), Ok(Device::Cuda(2)));
        assert!("metal".parse::<Device>().is_err());
        assert!("cuda:x".parse::<Device>().is_err());
    }

    #[cfg(not(feature = "privacy-filter-cuda"))]
    #[test]
    fn auto_is_the_cpu_without_cuda() {
        assert_eq!(Device::Auto.resolve(), Device::Cpu);
    }

    /// With CUDA compiled in, a machine without a driver or a GPU must still
    /// resolve `auto`, not panic in the driver probe.
    #[test]
    fn auto_resolves_on_any_machine() {
        assert!(matches!(
            Device::Auto.resolve(),
            Device::Cpu | Device::Cuda(0)
        ));
    }

    #[test]
    fn parses_viterbi_as_a_name_or_biases() {
        let config: PrivacyFilterConfig =
            serde_yaml_ng::from_str("model_dir: m\nviterbi: high_recall\n").unwrap();
        assert!(matches!(config.viterbi, Viterbi::OperatingPoint(ref n) if n == "high_recall"));

        let config: PrivacyFilterConfig = serde_yaml_ng::from_str(
            "model_dir: m
viterbi:
  transition_bias_background_stay: 0.5
  transition_bias_background_to_start: -0.5
  transition_bias_inside_to_continue: 0
  transition_bias_inside_to_end: 0
  transition_bias_end_to_background: 0
  transition_bias_end_to_start: 0
",
        )
        .unwrap();
        let Viterbi::Biases(biases) = config.viterbi else {
            panic!("expected biases");
        };
        assert_eq!(biases.transition_bias_background_stay, 0.5);
        assert_eq!(biases.transition_bias_background_to_start, -0.5);
    }

    #[test]
    fn every_setting_has_a_default() {
        let config: PrivacyFilterConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert_eq!(config.model_dir, None);
        assert_eq!(config.device, Device::Auto);
        assert_eq!(config.context, Context::Key);
        assert_eq!(config.max_tokens, 1024);
        assert_eq!(config.categories, SPAN_LABELS);
        assert!(config.model.is_none());
    }

    /// The layout Hugging Face's tools write: a ref naming a snapshot.
    #[test]
    fn the_default_model_dir_is_the_cached_snapshot() {
        let cache = tempfile::tempdir().unwrap();
        let repo = cache.path().join("models--eugenehp--privacy-filter-rs");
        std::fs::create_dir_all(repo.join("refs")).unwrap();
        std::fs::write(repo.join("refs").join("main"), "abc123\n").unwrap();

        // SAFETY: no other test reads or writes this variable.
        unsafe { std::env::set_var("HF_HUB_CACHE", cache.path()) };
        let found = default_model_dir();
        std::fs::remove_file(repo.join("refs").join("main")).unwrap();
        let missing = default_model_dir();
        unsafe { std::env::remove_var("HF_HUB_CACHE") };

        assert_eq!(found.unwrap(), repo.join("snapshots").join("abc123"));
        let err = missing.unwrap_err();
        assert!(err.contains("privacy_filter download"), "{err}");
    }

    #[test]
    fn a_missing_model_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = PrivacyFilterDetector::new(&PrivacyFilterConfig::new(dir.path())).unwrap_err();
        let err = err.to_string();
        assert!(
            err.contains("privacy_filter") && err.contains("config.json"),
            "{err}"
        );
    }

    #[test]
    fn an_empty_category_list_is_rejected() {
        let mut config = PrivacyFilterConfig::new("m");
        config.categories.clear();
        let err = PrivacyFilterDetector::new(&config).unwrap_err().to_string();
        assert!(err.contains("categories"), "{err}");
    }

    #[test]
    fn an_unknown_category_is_rejected() {
        let mut config = PrivacyFilterConfig::new("m");
        config.categories = vec!["ssn".into()];
        let err = PrivacyFilterDetector::new(&config).unwrap_err().to_string();
        assert!(
            err.contains("ssn") && err.contains("private_email"),
            "{err}"
        );
    }
}
