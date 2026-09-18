//! A secret-scanning rule engine for betterleaks/gitleaks-style TOML rulesets.
//!
//! Each rule has a regex (and optionally keywords that must appear before the
//! regex runs). A match produces a candidate secret, taken from the rule's
//! `secretGroup` or else its first non-empty capture group. Candidates are then
//! checked against the ruleset's global `filter` and the rule's own `filter`,
//! both [expr-lang](https://expr-lang.org) expressions that return `true` to
//! discard a candidate. Rules with `components` only report a secret when the
//! required companion rules also match nearby.
//!
//! Every occurrence of each reported secret in the value is redacted.
//!
//! `path`-only rules, `prefilter`, `validate`, and legacy `allowlists` are not
//! used, since they apply to file scanning and live verification rather than
//! to redacting a single value.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use expr::{Context, Environment, Program, Value};
use include_dir::{Dir, include_dir};
use indexmap::IndexMap;
use memchr::memmem;
use regex::Regex;
use regex::bytes::Regex as BytesRegex;
use serde::Deserialize;

use super::entropy::shannon_entropy;
use super::placeholder::Placeholders;
use super::{Detection, Detector, LeafContext};
use crate::Error;
use crate::glob::{Glob, any_match};

/// The vendored betterleaks release; refresh it with
/// `scripts/update-betterleaks.rs`.
static BETTERLEAKS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/vendor/betterleaks");

fn vendored(name: &str) -> &'static [u8] {
    BETTERLEAKS
        .get_file(name)
        .unwrap_or_else(|| panic!("vendor/betterleaks/{name} is missing"))
        .contents()
}

fn default_toml() -> &'static str {
    std::str::from_utf8(vendored("betterleaks.toml")).expect("bundled ruleset is UTF-8")
}

/// The betterleaks ruleset vendored into this binary, ready to use.
///
/// Add it to a [`Redactor`](crate::Redactor) with
/// [`RedactorBuilder::detector`](crate::RedactorBuilder::detector):
///
/// ```
/// use velociredactor::RedactorBuilder;
/// use velociredactor::detect::BETTERLEAKS_RULESET;
///
/// let redactor = RedactorBuilder::new()
///     .detector(BETTERLEAKS_RULESET.clone())
///     .build();
/// ```
///
/// The rules behind it are shared, so cloning it is cheap and the 486 KB of
/// TOML is parsed once per process.
pub static BETTERLEAKS_RULESET: LazyLock<RulesetDetector> =
    LazyLock::new(|| RulesetDetector::from_toml(default_toml()).expect("bundled ruleset is valid"));

/// The `ruleset` detector's settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetConfig {
    /// Rulesets to load, in order. A later rule replaces an earlier one with
    /// the same id.
    pub rules: Vec<RuleSource>,
    /// Comments marking a line as intentionally containing a secret.
    #[serde(default = "default_allow_signatures")]
    pub allow_signatures: Vec<String>,
    /// Globs matching the ids of rules to switch off.
    #[serde(default)]
    pub exclude_rules: Vec<String>,
}

fn default_allow_signatures() -> Vec<String> {
    RulesetDetector::DEFAULT_ALLOW_SIGNATURES
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// Where a ruleset's rules come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// The betterleaks release vendored into this binary, written
    /// `builtin:betterleaks`.
    Betterleaks,
    /// A betterleaks/gitleaks TOML file.
    Path(PathBuf),
}

impl<'de> Deserialize<'de> for RuleSource {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let source = String::deserialize(deserializer)?;
        match source.strip_prefix("builtin:") {
            Some("betterleaks") => Ok(RuleSource::Betterleaks),
            Some(other) => Err(serde::de::Error::custom(format!(
                "unknown built-in ruleset {other:?} (expected builtin:betterleaks)"
            ))),
            None => Ok(RuleSource::Path(PathBuf::from(source))),
        }
    }
}

/// Detects secrets using a ruleset. Cloning is cheap.
///
/// The rules themselves are shared; the vocabulary that decides which matches
/// to discard (placeholders, allow-comment signatures, excluded rule ids)
/// sits beside them, so changing it does not re-parse the rules.
#[derive(Clone)]
pub struct RulesetDetector {
    inner: Arc<Ruleset>,
    placeholders: Placeholders,
    allow_signatures: Arc<[String]>,
    exclude_rules: Arc<[Glob]>,
}

impl std::fmt::Debug for RulesetDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RulesetDetector")
            .field("rules", &self.inner.rules.len())
            .finish()
    }
}

impl RulesetDetector {
    /// The comment markers gitleaks and betterleaks conventionally use to mark
    /// a line as intentionally containing a secret.
    pub const DEFAULT_ALLOW_SIGNATURES: [&'static str; 2] = ["betterleaks:allow", "gitleaks:allow"];

    /// Load the rulesets `config` names and apply its settings.
    ///
    /// `placeholders` decides which matched values are documentation rather
    /// than secrets. Relative paths are resolved by the caller.
    pub fn new(config: &RulesetConfig, placeholders: &Placeholders) -> Result<Self, Error> {
        // The overwhelmingly common case is the bundled rules alone, where
        // the parsed ruleset is shared instead of parsed again.
        let mut detector = match config.rules.as_slice() {
            [RuleSource::Betterleaks] => BETTERLEAKS_RULESET.clone(),
            sources => {
                let mut combined: Option<RawConfig> = None;
                for source in sources {
                    let raw = match source {
                        RuleSource::Betterleaks => {
                            parse_toml(default_toml(), "builtin:betterleaks")
                        }
                        RuleSource::Path(path) => {
                            let source = std::fs::read_to_string(path).map_err(|err| {
                                Error::Ruleset(format!("{}: {err}", path.display()))
                            })?;
                            parse_toml(&source, &path.display().to_string())
                        }
                    }?;
                    combined = Some(match combined {
                        None => raw,
                        Some(previous) => previous.extended_by(raw),
                    });
                }
                Self::build(combined.unwrap_or_default())?
            }
        };
        detector.placeholders = placeholders.clone();
        detector.allow_signatures = config.allow_signatures.clone().into();
        detector.exclude_rules = config
            .exclude_rules
            .iter()
            .map(|p| Glob::flat(p))
            .collect::<Vec<_>>()
            .into();
        Ok(detector)
    }

    /// A ruleset with no rules.
    pub fn empty() -> Self {
        Self::build(RawConfig::default()).expect("empty ruleset is valid")
    }

    /// Parse a ruleset. If it sets `[extend] useDefault = true`, the bundled
    /// rules are included and rules with the same id are replaced.
    pub fn from_toml(source: &str) -> Result<Self, Error> {
        let mut config = parse_toml(source, "ruleset")?;
        if config.extend.use_default {
            let base = parse_toml(default_toml(), "builtin:betterleaks")?;
            config = base.extended_by(config);
        }
        Self::build(config)
    }

    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let source = std::fs::read_to_string(path)
            .map_err(|err| Error::Ruleset(format!("{}: {err}", path.display())))?;
        Self::from_toml(&source).map_err(|err| Error::Ruleset(format!("{}: {err}", path.display())))
    }

    /// Use these allow-comment markers instead of the default ones.
    pub fn allow_signatures(
        mut self,
        signatures: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allow_signatures = signatures.into_iter().map(Into::into).collect();
        self
    }

    /// Discard matched values that `placeholders` considers documentation.
    pub fn placeholders(mut self, placeholders: &Placeholders) -> Self {
        self.placeholders = placeholders.clone();
        self
    }

    /// Switch off the rules whose id matches one of these globs, such as
    /// `github-pat` or `aws-*`. The patterns have no separator; see
    /// [`Glob::flat`](crate::Glob::flat).
    pub fn exclude_rules(mut self, patterns: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.exclude_rules = patterns
            .into_iter()
            .map(|p| Glob::flat(p.as_ref()))
            .collect::<Vec<_>>()
            .into();
        self
    }

    /// Ids of the loaded rules, in file order.
    pub fn rule_ids(&self) -> impl Iterator<Item = &str> {
        self.inner.rules.iter().map(|r| r.id.as_str())
    }

    fn build(config: RawConfig) -> Result<Self, Error> {
        Ruleset::build(config).map(|inner| Self {
            inner: Arc::new(inner),
            placeholders: Placeholders::default(),
            allow_signatures: default_allow_signatures().into(),
            exclude_rules: Vec::new().into(),
        })
    }
}

fn parse_toml(source: &str, shown: &str) -> Result<RawConfig, Error> {
    toml::from_str(source).map_err(|err| Error::Ruleset(format!("{shown}: {err}")))
}

/// The vocabulary a scan uses to discard matches.
struct ScanCtx<'a> {
    placeholders: &'a Placeholders,
    allow_signatures: &'a [String],
    exclude_rules: &'a [Glob],
}

impl Detector for RulesetDetector {
    fn name(&self) -> &str {
        "ruleset"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let scan = ScanCtx {
            placeholders: &self.placeholders,
            allow_signatures: &self.allow_signatures,
            exclude_rules: &self.exclude_rules,
        };
        self.inner.detect(value, &scan, out);
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    extend: RawExtend,
    #[serde(default)]
    rules: Vec<RawRule>,
}

impl RawConfig {
    fn extended_by(mut self, other: RawConfig) -> RawConfig {
        let overridden: HashSet<&str> = other.rules.iter().map(|r| r.id.as_str()).collect();
        self.rules.retain(|r| !overridden.contains(r.id.as_str()));
        self.rules.extend(other.rules);
        self.filter = match (self.filter, other.filter) {
            (Some(a), Some(b)) => Some(format!("({a}) || ({b})")),
            (a, b) => a.or(b),
        };
        self
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawExtend {
    #[serde(default)]
    use_default: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRule {
    id: String,
    #[serde(default)]
    regex: Option<String>,
    /// Rules restricted to certain file paths never apply to bare values.
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    secret_group: usize,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    token_efficiency: bool,
    #[serde(default)]
    skip_report: bool,
    #[serde(default)]
    components: Vec<RawComponent>,
    /// Older spelling of `components`.
    #[serde(default)]
    required: Vec<RawRequired>,
}

#[derive(Debug, Deserialize)]
struct RawComponent {
    id: String,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    within: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRequired {
    id: String,
    within_lines: Option<usize>,
    within_columns: Option<usize>,
}

struct Rule {
    id: String,
    /// `None` for rules that never apply to bare values (path-only or
    /// path-restricted rules).
    regex: Option<BytesRegex>,
    secret_group: usize,
    skip_report: bool,
    components: Vec<Component>,
    filter: Option<Filter>,
}

struct Component {
    rule: usize,
    optional: bool,
    window: Window,
}

/// How close a component match must be to the primary match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Window {
    Anywhere,
    /// Component starts within this many bytes before or after the match.
    Columns {
        before: usize,
        after: usize,
    },
    /// Component starts within this many lines (and, for single-line
    /// matches, optionally columns) of the match.
    Box {
        lines_before: usize,
        lines_after: usize,
        cols_before: usize,
        cols_after: usize,
    },
}

struct Filter {
    program: Program,
    uses_fragment: bool,
}

struct Ruleset {
    rules: Vec<Rule>,
    keywords: Option<AhoCorasick>,
    keyword_rules: Vec<Vec<usize>>,
    keywordless_rules: Vec<usize>,
    global_filter: Option<Filter>,
    env: Environment<'static>,
}

impl Ruleset {
    fn build(config: RawConfig) -> Result<Self, Error> {
        let index: HashMap<String, usize> = config
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();

        let mut rules = Vec::with_capacity(config.rules.len());
        let mut keyword_ids: HashMap<String, usize> = HashMap::new();
        let mut keyword_list: Vec<String> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut keywordless_rules = Vec::new();

        for (i, raw) in config.rules.into_iter().enumerate() {
            let fail = |msg: String| Error::Ruleset(format!("rule {:?}: {msg}", raw.id));
            let Some(pattern) = raw.regex.as_deref().filter(|_| raw.path.is_none()) else {
                rules.push(Rule {
                    id: raw.id,
                    regex: None,
                    secret_group: 0,
                    skip_report: true,
                    components: Vec::new(),
                    filter: None,
                });
                continue;
            };
            let regex = compile_rule_regex(pattern).map_err(|e| fail(e.to_string()))?;
            if raw.secret_group >= regex.captures_len() {
                return Err(fail(format!(
                    "secretGroup {} exceeds the number of capture groups",
                    raw.secret_group
                )));
            }

            let mut components = Vec::new();
            for c in &raw.components {
                let rule = *index
                    .get(&c.id)
                    .ok_or_else(|| fail(format!("unknown component rule {:?}", c.id)))?;
                let window = parse_window(&c.within).map_err(fail)?;
                components.push(Component {
                    rule,
                    optional: c.optional,
                    window,
                });
            }
            for r in &raw.required {
                let rule = *index
                    .get(&r.id)
                    .ok_or_else(|| fail(format!("unknown required rule {:?}", r.id)))?;
                let mut within = Vec::new();
                if let Some(lines) = r.within_lines {
                    within.push(format!("{lines}L"));
                }
                if let Some(cols) = r.within_columns {
                    within.push(format!("{cols}C"));
                }
                components.push(Component {
                    rule,
                    optional: false,
                    window: parse_window(&within.join(",")).map_err(fail)?,
                });
            }

            let mut filter_parts = Vec::new();
            if let Some(entropy) = raw.entropy.filter(|e| *e != 0.0) {
                filter_parts.push(format!(r#"entropy(finding["secret"]) <= {entropy:?}"#));
            }
            if raw.token_efficiency {
                filter_parts.push(r#"failsTokenEfficiency(finding["secret"])"#.to_owned());
            }
            if let Some(f) = raw.filter.as_deref().filter(|f| !f.trim().is_empty()) {
                filter_parts.push(f.to_owned());
            }
            let filter = compose_filter(&filter_parts)
                .map(|source| compile_filter(&source))
                .transpose()
                .map_err(fail)?;

            if raw.keywords.is_empty() {
                keywordless_rules.push(i);
            }
            for keyword in &raw.keywords {
                let keyword = keyword.to_lowercase();
                let id = *keyword_ids.entry(keyword.clone()).or_insert_with(|| {
                    keyword_list.push(keyword);
                    keyword_rules.push(Vec::new());
                    keyword_list.len() - 1
                });
                keyword_rules[id].push(i);
            }

            rules.push(Rule {
                id: raw.id,
                regex: Some(regex),
                secret_group: raw.secret_group,
                skip_report: raw.skip_report,
                components,
                filter,
            });
        }

        let keywords = if keyword_list.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::Standard)
                    .build(&keyword_list)
                    .map_err(|e| Error::Ruleset(e.to_string()))?,
            )
        };

        let global_filter = config
            .filter
            .as_deref()
            .filter(|f| !f.trim().is_empty())
            .map(compile_filter)
            .transpose()
            .map_err(|e| Error::Ruleset(format!("global filter: {e}")))?;

        Ok(Self {
            rules,
            keywords,
            keyword_rules,
            keywordless_rules,
            global_filter,
            env: filter_environment(),
        })
    }

    fn detect(&self, value: &str, scan: &ScanCtx<'_>, out: &mut Vec<Detection>) {
        if value.is_empty() || self.rules.is_empty() {
            return;
        }
        let bytes = value.as_bytes();
        let mut candidates = vec![false; self.rules.len()];
        if let Some(ac) = &self.keywords {
            for m in ac.find_overlapping_iter(bytes) {
                for &rule in &self.keyword_rules[m.pattern().as_usize()] {
                    candidates[rule] = true;
                }
            }
        }
        for &rule in &self.keywordless_rules {
            candidates[rule] = true;
        }

        let lines = LineIndex::new(bytes);
        let mut secrets: Vec<(Vec<u8>, usize)> = Vec::new();
        let mut seen = HashSet::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if !candidates[i] || rule.skip_report {
                continue;
            }
            // Excluded only as a reporting rule: a rule listed as another
            // rule's component still runs, so excluding it does not silently
            // switch off the rules that depend on it.
            if any_match(scan.exclude_rules, &rule.id) {
                continue;
            }
            for finding in self.find(i, value, &lines, scan) {
                if seen.insert(finding.secret.clone()) {
                    secrets.push((finding.secret, i));
                }
            }
        }

        for (secret, rule) in secrets {
            let Ok(text) = std::str::from_utf8(&secret) else {
                continue;
            };
            if scan.placeholders.is_placeholder(text) {
                continue;
            }
            for start in memmem::find_iter(bytes, &secret) {
                let range = snap_to_chars(value, start..start + secret.len());
                out.push(Detection::new(
                    range,
                    format!("ruleset:{}", self.rules[rule].id),
                ));
            }
        }
    }

    /// Findings for one rule, including its component requirements.
    fn find(
        &self,
        rule_index: usize,
        value: &str,
        lines: &LineIndex,
        scan: &ScanCtx<'_>,
    ) -> Vec<Finding> {
        let rule = &self.rules[rule_index];
        let findings = self.find_primary(rule, value, lines, scan);
        if rule.components.is_empty() || findings.is_empty() {
            return findings;
        }

        let component_findings: Vec<Vec<Finding>> = rule
            .components
            .iter()
            .map(|c| self.find_primary(&self.rules[c.rule], value, lines, scan))
            .collect();

        findings
            .into_iter()
            .filter(|primary| {
                rule.components
                    .iter()
                    .zip(&component_findings)
                    .all(|(component, found)| {
                        component.optional
                            || found
                                .iter()
                                .any(|f| within(component.window, primary, f, value.len()))
                    })
            })
            .collect()
    }

    fn find_primary(
        &self,
        rule: &Rule,
        value: &str,
        lines: &LineIndex,
        scan: &ScanCtx<'_>,
    ) -> Vec<Finding> {
        let Some(regex) = &rule.regex else {
            return Vec::new();
        };
        let bytes = value.as_bytes();
        let mut findings = Vec::new();
        for m in regex.find_iter(bytes) {
            let matched = trim_newlines(m.as_bytes());
            if matched.is_empty() {
                continue;
            }
            let start = m.start();
            let end = start + matched.len();
            let line = &bytes[lines.line_range(start, end)];
            if scan
                .allow_signatures
                .iter()
                .any(|sig| memmem::find(line, sig.as_bytes()).is_some())
            {
                continue;
            }

            let mut secret = matched;
            let mut captures = IndexMap::new();
            if let Some(groups) = regex.captures(matched)
                && groups.len() >= 2
            {
                if rule.secret_group > 0 {
                    secret = groups
                        .get(rule.secret_group)
                        .map_or(&[][..], |g| g.as_bytes());
                } else if let Some(g) = groups.iter().skip(1).flatten().find(|g| !g.is_empty()) {
                    secret = g.as_bytes();
                }
                for (i, name) in regex.capture_names().enumerate() {
                    if let (Some(name), Some(g)) = (name, groups.get(i))
                        && !g.is_empty()
                    {
                        captures.insert(
                            name.to_owned(),
                            Value::String(String::from_utf8_lossy(g.as_bytes()).into_owned()),
                        );
                    }
                }
            }

            let candidate = Candidate {
                value,
                match_range: m.range(),
                matched,
                secret,
                line,
                captures,
            };
            if self.filtered(rule, &candidate) {
                continue;
            }
            let start_line = lines.line_of(start);
            findings.push(Finding {
                secret: secret.to_vec(),
                start,
                end,
                start_line,
                end_line: lines.line_of(end.saturating_sub(1).max(start)),
                start_col: start - lines.line_start(start_line),
            });
        }
        findings
    }

    fn filtered(&self, rule: &Rule, candidate: &Candidate<'_>) -> bool {
        if self.global_filter.is_none() && rule.filter.is_none() {
            return false;
        }
        let include_fragment = self.global_filter.as_ref().is_some_and(|f| f.uses_fragment)
            || rule.filter.as_ref().is_some_and(|f| f.uses_fragment);
        let ctx = candidate.context(&rule.id, include_fragment);
        [&self.global_filter, &rule.filter]
            .into_iter()
            .flatten()
            .any(|filter| {
                // A filter that fails to evaluate keeps the finding: when in
                // doubt, redact.
                matches!(self.env.run(&filter.program, &ctx), Ok(Value::Bool(true)))
            })
    }
}

/// A regex match being considered by filters.
struct Candidate<'a> {
    value: &'a str,
    match_range: Range<usize>,
    matched: &'a [u8],
    secret: &'a [u8],
    line: &'a [u8],
    captures: IndexMap<String, Value>,
}

impl Candidate<'_> {
    /// The variables visible to filter expressions: `finding` (a map
    /// describing the match) and `attributes` (source metadata, which is
    /// always empty here).
    fn context(&self, rule_id: &str, include_fragment: bool) -> Context {
        let lossy = |b: &[u8]| Value::String(String::from_utf8_lossy(b).into_owned());
        let bytes = self.value.as_bytes();
        let (start, end) = (self.match_range.start, self.match_range.end);
        let line_start = bytes[..start]
            .iter()
            .rposition(|&b| b == b'\n' || b == b'\r')
            .map_or(0, |i| i + 1);
        let line_end = bytes[end..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .map_or(bytes.len(), |i| end + i);
        let fragment = if include_fragment { self.value } else { "" };

        let mut map = IndexMap::new();
        map.insert("secret".into(), lossy(self.secret));
        map.insert("match".into(), lossy(self.matched));
        map.insert("line".into(), lossy(self.line));
        map.insert("rule_id".into(), Value::String(rule_id.to_owned()));
        map.insert("description".into(), Value::String(String::new()));
        map.insert("context".into(), Value::String(String::new()));
        map.insert(
            "entropy".into(),
            Value::String(shannon_entropy(self.secret).to_string()),
        );
        map.insert("captures".into(), Value::Map(self.captures.clone()));
        map.insert("fragment_raw".into(), Value::String(fragment.to_owned()));
        map.insert("match_start_idx".into(), Value::Integer(start as i64));
        map.insert("match_end_idx".into(), Value::Integer(end as i64));
        map.insert(
            "match_line_start_idx".into(),
            Value::Integer(line_start as i64),
        );
        map.insert("match_line_end_idx".into(), Value::Integer(line_end as i64));

        let mut ctx = Context::default();
        ctx.insert("finding", Value::Map(map));
        ctx.insert("attributes", Value::Map(IndexMap::new()));
        ctx
    }
}

struct Finding {
    secret: Vec<u8>,
    start: usize,
    end: usize,
    start_line: usize,
    end_line: usize,
    /// Offset of `start` from the beginning of its line.
    start_col: usize,
}

fn within(window: Window, primary: &Finding, component: &Finding, len: usize) -> bool {
    match window {
        Window::Anywhere => true,
        Window::Columns { before, after } => {
            component.start >= primary.start.saturating_sub(before)
                && component.start < (primary.end + after).min(len)
        }
        Window::Box {
            lines_before,
            lines_after,
            cols_before,
            cols_after,
        } => {
            if component.start_line + lines_before < primary.start_line
                || component.start_line > primary.end_line + lines_after
            {
                return false;
            }
            if primary.start_line == primary.end_line && (cols_before > 0 || cols_after > 0) {
                let end_col = primary.start_col + (primary.end - primary.start);
                return component.start_col >= primary.start_col.saturating_sub(cols_before)
                    && component.start_col < end_col + cols_after;
            }
            true
        }
    }
}

/// Line lookups for one value.
struct LineIndex {
    starts: Vec<usize>,
    len: usize,
}

impl LineIndex {
    fn new(bytes: &[u8]) -> Self {
        let mut starts = vec![0];
        starts.extend(memchr::memchr_iter(b'\n', bytes).map(|i| i + 1));
        Self {
            starts,
            len: bytes.len(),
        }
    }

    fn line_of(&self, offset: usize) -> usize {
        self.starts.partition_point(|&s| s <= offset) - 1
    }

    fn line_start(&self, line: usize) -> usize {
        self.starts[line]
    }

    /// The full lines spanned by `start..end`, without the final newline.
    fn line_range(&self, start: usize, end: usize) -> Range<usize> {
        let first = self.line_start(self.line_of(start));
        let last = self.line_of(end.saturating_sub(1).max(start));
        let stop = self.starts.get(last + 1).map_or(self.len, |&next| next - 1);
        first..stop.max(first)
    }
}

fn trim_newlines(mut b: &[u8]) -> &[u8] {
    while let [b'\n', rest @ ..] = b {
        b = rest;
    }
    while let [rest @ .., b'\n'] = b {
        b = rest;
    }
    b
}

/// Widen `range` to the nearest UTF-8 character boundaries.
fn snap_to_chars(s: &str, mut range: Range<usize>) -> Range<usize> {
    while !s.is_char_boundary(range.start) {
        range.start -= 1;
    }
    while !s.is_char_boundary(range.end) {
        range.end += 1;
    }
    range
}

/// Rules are written for Go's RE2, where `\w`, `\d`, `\s`, and `\b` are
/// ASCII-only. Matching bytes with Unicode disabled gives the same behavior.
fn compile_rule_regex(pattern: &str) -> Result<BytesRegex, regex::Error> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .or_else(|_| BytesRegex::new(pattern))
}

/// Parse a proximity spec such as `5L`, `7L,200C`, `-2L,+3L`, or `80C`.
///
/// A bare number means columns. `NL` means within N lines, counting the
/// match's own line as the first.
fn parse_window(spec: &str) -> Result<Window, String> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "0" {
        return Ok(Window::Anywhere);
    }
    #[derive(Default)]
    struct Dir {
        before: usize,
        after: usize,
        both: usize,
    }
    let (mut lines, mut cols) = (Dir::default(), Dir::default());
    let (mut has_lines, mut has_cols) = (false, false);
    for token in spec.split(',') {
        let token = token.trim();
        let (sign, rest) = match token.as_bytes().first() {
            Some(b'+') => (Some('+'), &token[1..]),
            Some(b'-') => (Some('-'), &token[1..]),
            _ => (None, token),
        };
        let (digits, unit) = match rest.as_bytes().last() {
            Some(b'L' | b'l') => (&rest[..rest.len() - 1], 'L'),
            Some(b'C' | b'c') => (&rest[..rest.len() - 1], 'C'),
            _ => (rest, 'C'),
        };
        let mut amount: usize = digits
            .parse()
            .map_err(|_| format!("invalid proximity {spec:?}"))?;
        let target = if unit == 'L' {
            has_lines = true;
            amount = amount.saturating_sub(1);
            &mut lines
        } else {
            has_cols = true;
            &mut cols
        };
        match sign {
            Some('-') => target.before = target.before.max(amount),
            Some('+') => target.after = target.after.max(amount),
            _ => target.both = target.both.max(amount),
        }
    }
    let cols_before = cols.before.max(cols.both);
    let cols_after = cols.after.max(cols.both);
    Ok(if has_lines {
        Window::Box {
            lines_before: lines.before.max(lines.both),
            lines_after: lines.after.max(lines.both),
            cols_before,
            cols_after,
        }
    } else if has_cols {
        Window::Columns {
            before: cols_before,
            after: cols_after,
        }
    } else {
        Window::Anywhere
    })
}

fn compose_filter(parts: &[String]) -> Option<String> {
    match parts {
        [] => None,
        [one] => Some(one.clone()),
        many => Some(
            many.iter()
                .map(|p| format!("({p})"))
                .collect::<Vec<_>>()
                .join(" || "),
        ),
    }
}

fn compile_filter(source: &str) -> Result<Filter, String> {
    let rewritten = flatten_namespaces(source);
    let program = expr::compile(&rewritten).map_err(|e| format!("invalid filter: {e}"))?;
    Ok(Filter {
        program,
        uses_fragment: source.contains("fragment_raw"),
    })
}

/// Rewrite `filter.name(` calls to `filter_name(`, leaving string literals
/// untouched, since functions are registered under flat names.
fn flatten_namespaces(source: &str) -> String {
    const PREFIX: &str = "filter.";
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' && q != b'`' && i + 1 < bytes.len() {
                    out.push_str(&source[i..i + 2]);
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None => {
                if source[i..].starts_with("//") {
                    let end = source[i..].find('\n').map_or(source.len(), |n| i + n);
                    out.push_str(&source[i..end]);
                    i = end;
                    continue;
                }
                if matches!(b, b'"' | b'\'' | b'`') {
                    quote = Some(b);
                } else if source[i..].starts_with(PREFIX)
                    && (i == 0 || !is_ident_byte(bytes[i - 1]))
                {
                    out.push_str("filter_");
                    i += PREFIX.len();
                    continue;
                }
            }
        }
        let ch_len = source[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&source[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn filter_environment() -> Environment<'static> {
    let mut env = Environment::new();

    fn str_arg(args: &[Value], i: usize) -> &str {
        args.get(i).and_then(Value::as_string).unwrap_or("")
    }
    fn list_arg(args: &[Value], i: usize) -> Vec<String> {
        args.get(i)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_string().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    // Byte length for strings, matching the offsets exposed in `finding`.
    env.add_function("len", |c| {
        Ok(match c.args.first() {
            Some(Value::String(s)) => Value::Integer(s.len() as i64),
            Some(Value::Array(a)) => Value::Integer(a.len() as i64),
            Some(Value::Map(m)) => Value::Integer(m.len() as i64),
            Some(Value::Bytes(b)) => Value::Integer(b.len() as i64),
            _ => Value::Integer(0),
        })
    });

    for name in ["entropy", "filter_entropy"] {
        env.add_function(name, |c| {
            Ok(Value::Float(shannon_entropy(
                str_arg(&c.args, 0).as_bytes(),
            )))
        });
    }
    for name in ["matchesAny", "filter_matchesAny"] {
        env.add_function(name, |c| {
            let Some(Value::String(s)) = c.args.first() else {
                return Ok(Value::Bool(false));
            };
            let patterns = list_arg(&c.args, 1);
            Ok(Value::Bool(
                joined_regex(&patterns).is_some_and(|re| re.is_match(s)),
            ))
        });
    }
    for name in ["containsAny", "filter_containsAny"] {
        env.add_function(name, |c| {
            let Some(Value::String(s)) = c.args.first() else {
                return Ok(Value::Bool(false));
            };
            let terms = list_arg(&c.args, 1);
            Ok(Value::Bool(
                term_matcher(&terms).is_some_and(|ac| ac.is_match(&s.to_lowercase())),
            ))
        });
    }
    env.add_function("filter_findMatch", |c| {
        let s = str_arg(&c.args, 0);
        let pattern = str_arg(&c.args, 1).to_owned();
        let found = joined_regex(&[pattern])
            .and_then(|re| re.find(s).map(|m| m.as_str().to_owned()))
            .unwrap_or_default();
        Ok(Value::String(found))
    });
    env.add_function("filter_tokenRatio", |c| {
        Ok(Value::Float(
            tokens::ratio(str_arg(&c.args, 0)).map_or(0.0, |(_, r)| r),
        ))
    });
    for name in ["failsTokenEfficiency", "filter_failsTokenEfficiency"] {
        env.add_function(name, |c| {
            Ok(Value::Bool(tokens::fails_efficiency(str_arg(&c.args, 0))))
        });
    }
    // Confidence levels are not used for redaction.
    env.add_function("filter_setConfidence", |c| {
        Ok(c.args.into_iter().next().unwrap_or(Value::Nil))
    });
    env
}

fn joined_regex(patterns: &[String]) -> Option<Regex> {
    static CACHE: LazyLock<Mutex<HashMap<Vec<String>, Option<Regex>>>> =
        LazyLock::new(Default::default);
    if patterns.is_empty() {
        return None;
    }
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(patterns.to_vec())
        .or_insert_with(|| {
            let joined = patterns
                .iter()
                .map(|p| format!("(?:{p})"))
                .collect::<Vec<_>>()
                .join("|");
            Regex::new(&joined).ok()
        })
        .clone()
}

fn term_matcher(terms: &[String]) -> Option<AhoCorasick> {
    static CACHE: LazyLock<Mutex<HashMap<Vec<String>, Option<AhoCorasick>>>> =
        LazyLock::new(Default::default);
    if terms.is_empty() {
        return None;
    }
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(terms.to_vec())
        .or_insert_with(|| AhoCorasick::new(terms.iter().map(|t| t.to_lowercase())).ok())
        .clone()
}

/// Tokenizer-based heuristics: natural-language text tokenizes into few,
/// long tokens, while random secrets need many short ones.
mod tokens {
    use super::*;
    use tiktoken_rs::CoreBPE;

    static BPE: LazyLock<Option<CoreBPE>> = LazyLock::new(|| tiktoken_rs::cl100k_base().ok());

    static WORDS: LazyLock<HashSet<String>> = LazyLock::new(|| {
        let mut text = String::new();
        flate2::read::GzDecoder::new(vendored("words.txt.gz"))
            .read_to_string(&mut text)
            .expect("bundled word list is valid gzip text");
        text.lines()
            .filter(|w| !w.is_empty())
            .map(str::to_owned)
            .collect()
    });

    /// The analyzed text and its characters-per-token ratio.
    pub(super) fn ratio(secret: &str) -> Option<(String, f64)> {
        let bpe = BPE.as_ref()?;
        let analyzed = if secret.len() < 20 && secret.contains(['\n', '\r']) {
            secret.replace(['\n', '\r'], "")
        } else {
            secret.to_owned()
        };
        let count = bpe.encode_ordinary(&analyzed).len();
        if count == 0 {
            return None;
        }
        let ratio = analyzed.len() as f64 / count as f64;
        Some((analyzed, ratio))
    }

    pub(super) fn fails_efficiency(secret: &str) -> bool {
        let Some((analyzed, ratio)) = ratio(secret) else {
            return false;
        };
        if contains_word(&analyzed, 5) {
            return true;
        }
        let threshold = if analyzed.len() < 12 && contains_word(&analyzed, 4) {
            2.1
        } else {
            2.5
        };
        ratio >= threshold
    }

    /// Whether any substring of at least `min_len` bytes is a dictionary word.
    pub(super) fn contains_word(word: &str, min_len: usize) -> bool {
        let lower = word.to_lowercase();
        let bytes = lower.as_bytes();
        if bytes.len() < min_len {
            return false;
        }
        (0..=bytes.len() - min_len).any(|start| {
            (start + min_len..=bytes.len())
                .any(|end| std::str::from_utf8(&bytes[start..end]).is_ok_and(|w| WORDS.contains(w)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(detector: &RulesetDetector, s: &str) -> Vec<String> {
        let mut out = Vec::new();
        detector.detect(s, &LeafContext::default(), &mut out);
        out.iter().map(|d| s[d.range.clone()].to_owned()).collect()
    }

    #[test]
    fn bundled_word_list_loads() {
        assert!(tokens::contains_word("password", 8));
    }

    #[test]
    fn bundled_rules_load() {
        let rules = &*BETTERLEAKS_RULESET;
        assert!(rules.rule_ids().count() > 400);
        assert!(rules.inner.global_filter.is_some());
    }

    #[test]
    fn finds_known_token_formats() {
        let rules = &*BETTERLEAKS_RULESET;
        let token = "ghp_R4nd0mT0k3nV4lu3AbCdEfGhIjKlMnOpQr12";
        assert_eq!(
            secrets(rules, &format!("export GITHUB_TOKEN={token}")),
            [token]
        );
    }

    #[test]
    fn global_filter_drops_template_values() {
        let rules = &*BETTERLEAKS_RULESET;
        assert!(secrets(rules, "api_key = \"${API_KEY}\"").is_empty());
    }

    #[test]
    fn allow_signature_suppresses_findings() {
        let rules = &*BETTERLEAKS_RULESET;
        let token = "ghp_R4nd0mT0k3nV4lu3AbCdEfGhIjKlMnOpQr12";
        assert!(secrets(rules, &format!("token={token} # gitleaks:allow")).is_empty());
    }

    #[test]
    fn every_occurrence_is_reported() {
        let rules = &*BETTERLEAKS_RULESET;
        let token = "ghp_R4nd0mT0k3nV4lu3AbCdEfGhIjKlMnOpQr12";
        let text = format!("GITHUB_TOKEN={token}\nagain: {token}");
        assert_eq!(secrets(rules, &text).len(), 2);
    }

    #[test]
    fn custom_ruleset_with_secret_group_and_entropy() {
        let rules = RulesetDetector::from_toml(
            r#"
[[rules]]
id = "acme"
regex = '''acme_key\s*=\s*"([a-z0-9]+)"'''
secretGroup = 1
entropy = 3.0
keywords = ["acme_key"]
"#,
        )
        .unwrap();
        assert_eq!(
            secrets(&rules, r#"acme_key = "x9f3k2m8q7w1z5""#),
            ["x9f3k2m8q7w1z5"]
        );
        assert!(secrets(&rules, r#"acme_key = "aaaaaaaaaa""#).is_empty());
        assert!(secrets(&rules, r#"other = "x9f3k2m8q7w1z5""#).is_empty());
    }

    #[test]
    fn required_components_gate_findings() {
        let rules = RulesetDetector::from_toml(
            r#"
[[rules]]
id = "secret"
regex = '''SECRET_[A-Z0-9]{8}'''
components = [{ id = "account", within = "2L" }]

[[rules]]
id = "account"
regex = '''ACCOUNT_[0-9]{4}'''
skipReport = true
"#,
        )
        .unwrap();
        assert_eq!(
            secrets(&rules, "ACCOUNT_1234\nSECRET_ABCD1234"),
            ["SECRET_ABCD1234"]
        );
        assert!(secrets(&rules, "SECRET_ABCD1234").is_empty());
        assert!(secrets(&rules, "ACCOUNT_1234\n\n\n\nSECRET_ABCD1234").is_empty());
    }

    #[test]
    fn filters_can_use_fragment_offsets() {
        let rules = RulesetDetector::from_toml(
            r#"
[[rules]]
id = "tok"
regex = '''tok_[a-z]{6}'''
filter = '''
let before = finding["fragment_raw"][max(finding["match_start_idx"] - 5, 0):finding["match_start_idx"]];
filter.matchesAny(before, [`test `])
'''
"#,
        )
        .unwrap();
        assert!(secrets(&rules, "test tok_abcdef").is_empty());
        assert_eq!(secrets(&rules, "prod tok_abcdef"), ["tok_abcdef"]);
    }

    #[test]
    fn extend_default_keeps_bundled_rules() {
        let rules = RulesetDetector::from_toml(
            "[extend]\nuseDefault = true\n\n[[rules]]\nid = \"mine\"\nregex = '''MINE_[0-9]{6}'''\n",
        )
        .unwrap();
        assert!(rules.rule_ids().any(|id| id == "mine"));
        assert!(rules.rule_ids().count() > 400);
    }

    #[test]
    fn every_bundled_filter_evaluates() {
        let inner = &BETTERLEAKS_RULESET.inner;
        let value = "line one\nconfig.api_key = \"x9f3k2m8q7w1z5v4\" # note\nline three";
        let start = value.find("api_key").unwrap();
        let end = value.find(" # note").unwrap();
        let candidate = Candidate {
            value,
            match_range: start..end,
            matched: &value.as_bytes()[start..end],
            secret: b"x9f3k2m8q7w1z5v4",
            line: b"config.api_key = \"x9f3k2m8q7w1z5v4\" # note",
            captures: IndexMap::new(),
        };
        let mut failures = Vec::new();
        let filters = inner
            .rules
            .iter()
            .filter_map(|r| r.filter.as_ref().map(|f| (r.id.as_str(), f)))
            .chain(inner.global_filter.iter().map(|f| ("<global>", f)));
        for (id, filter) in filters {
            let ctx = candidate.context(id, true);
            match inner.env.run(&filter.program, &ctx) {
                Ok(Value::Bool(_)) => {}
                other => failures.push(format!("{id}: {other:?}")),
            }
        }
        assert!(
            failures.is_empty(),
            "filters failed:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn window_parsing() {
        assert_eq!(parse_window("").unwrap(), Window::Anywhere);
        assert_eq!(
            parse_window("80").unwrap(),
            Window::Columns {
                before: 80,
                after: 80
            }
        );
        assert_eq!(
            parse_window("7L,200C").unwrap(),
            Window::Box {
                lines_before: 6,
                lines_after: 6,
                cols_before: 200,
                cols_after: 200
            }
        );
        assert_eq!(
            parse_window("-2L,+4L").unwrap(),
            Window::Box {
                lines_before: 1,
                lines_after: 3,
                cols_before: 0,
                cols_after: 0
            }
        );
        assert!(parse_window("xL").is_err());
    }

    #[test]
    fn namespace_flattening_skips_strings() {
        assert_eq!(
            flatten_namespaces(r#"filter.entropy(x) || matchesAny(y, [`filter.x`, "filter.y"])"#),
            r#"filter_entropy(x) || matchesAny(y, [`filter.x`, "filter.y"])"#
        );
    }

    #[test]
    fn dictionary_words() {
        assert!(tokens::contains_word("xxpasswordxx", 5));
        assert!(!tokens::contains_word("q7x9z", 5));
        assert!(tokens::fails_efficiency("thisisaplainenglishsentence"));
        assert!(!tokens::fails_efficiency("aB3dE5fG7hJ9kL1mN2pQ4r"));
    }
}
