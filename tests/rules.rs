//! Forcing and sparing redactions by key path, value, pattern, and detector.
#![cfg(feature = "json")]

mod common;

use common::HIGH_ENTROPY_SECRET as S;
use velociredactor::config::Config;
use velociredactor::detect::{
    BETTERLEAKS_RULESET, DetectorConfig, DetectorEntry, EmailConfig, PathDetector, RegexConfig,
    RegexDetector, RulesetDetector, ValueDetector,
};
use velociredactor::{Allow, Finding, FormatHint, Redaction, Redactor, RedactorBuilder};

const DOC: &str = r#"{
  "users": [{"name": "Jane Roe", "ssn": "123-45-6789"}],
  "db": {"host": "h.example", "user": "u", "password": "hunter2"},
  "build": {"note": "n"}
}"#;

fn render(redaction: &Redaction<'_>, allow: &Allow) -> String {
    String::from_utf8(redaction.render(allow).unwrap()).unwrap()
}

fn scan<'a>(builder: RedactorBuilder, input: &'a str) -> Redaction<'a> {
    builder
        .build()
        .redact(input.as_bytes(), FormatHint::Name("json"))
        .expect("valid json")
}

fn redact(builder: RedactorBuilder, input: &str) -> String {
    render(&scan(builder, input), &Allow::none())
}

fn redact_with(redactor: &Redactor, input: &str) -> String {
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Name("json"))
        .expect("valid json");
    render(&redaction, &Allow::none())
}

/// The built-in configuration keeping only `keep` among its detectors, plus
/// the email detector, which it never lists.
fn configured(keep: &[&str]) -> Redactor {
    let mut config = Config::builtin().clone();
    config.detectors.retain(|d| keep.contains(&d.config.id()));
    config
        .detectors
        .push(DetectorConfig::PiiEmail(EmailConfig::default()).into());
    config.redactor().expect("valid configuration").0
}

fn tokens_of<'a>(redaction: &'a Redaction<'_>, detector: &str) -> Vec<&'a Finding> {
    redaction
        .findings()
        .iter()
        .filter(|f| f.detector == detector)
        .collect()
}

#[test]
fn disallowed_paths_redact_whatever_the_value_holds() {
    let redaction = scan(
        Redactor::builder().detector(PathDetector::new(["users.name", "users.ssn"])),
        DOC,
    );
    let out = render(&redaction, &Allow::none());
    assert!(out.contains(r#""name": "[REDACTED-1]""#), "{out}");
    assert!(out.contains(r#""ssn": "[REDACTED-2]""#), "{out}");
    // Array nesting adds nothing to a key path.
    assert_eq!(tokens_of(&redaction, "path").len(), 2);
    assert_eq!(
        redaction.findings()[0].path.as_deref(),
        Some("users.name"),
        "the path is reported"
    );
}

#[test]
fn path_globs_span_keys_and_segments() {
    let out = redact(
        Redactor::builder().detector(PathDetector::new(["**.ssn"])),
        DOC,
    );
    assert!(out.contains(r#""ssn": "[REDACTED-1]""#), "{out}");
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");

    let out = redact(
        Redactor::builder().detector(PathDetector::new(["db.*"])),
        DOC,
    );
    assert!(out.contains(r#""host": "[REDACTED-1]""#), "{out}");
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");

    // A single star stays inside one segment.
    let out = redact(Redactor::builder().detector(PathDetector::new(["*"])), DOC);
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");
}

#[test]
fn allowed_paths_are_never_scanned() {
    let doc = format!(r#"{{"keep": {{"api_key": "{S}"}}, "other": "{S}"}}"#);

    let redaction = scan(Redactor::builder().allow_paths(["keep.**"]), &doc);
    let out = render(&redaction, &Allow::none());
    assert_eq!(
        out,
        format!(r#"{{"keep": {{"api_key": "{S}"}}, "other": "[REDACTED-1]"}}"#),
        "a secret at an allowed path survives even where the same value is redacted elsewhere"
    );
    assert_eq!(
        redaction.findings()[0].occurrences,
        1,
        "the allowed occurrence is not counted"
    );

    // Allowing a whole subtree also spares what a disallowed path would take.
    let out = redact(
        Redactor::builder()
            .allow_paths(["users"])
            .detector(PathDetector::new(["users.**"])),
        DOC,
    );
    assert!(out.contains(r#""ssn": "123-45-6789""#), "{out}");
}

const FONT_URL: &str =
    "https://fonts.gstatic.com/s/bebasneue/v9/JTUSjIg69CK48gW7PXoo9WdhyyTh89ZNpQ.woff2";
const FONT_FILE: &str = "JTUSjIg69CK48gW7PXoo9WdhyyTh89ZNpQ";
const FONTS: &str = r#"https://fonts\.gstatic\.com/[^\s"')]+"#;

#[test]
fn allowed_within_spares_a_secret_by_its_surroundings() {
    let doc =
        format!(r#"{{"css": "src: url({FONT_URL}) format('woff2')", "other": "{FONT_FILE}"}}"#);
    let unallowed = scan(Redactor::builder(), &doc);
    assert!(
        unallowed.findings().iter().any(|f| f.secret == FONT_FILE),
        "the file name alone looks like a secret"
    );

    let redaction = scan(Redactor::builder().allow_within([FONTS]).unwrap(), &doc);
    let out = render(&redaction, &Allow::none());
    assert_eq!(
        out,
        format!(r#"{{"css": "src: url({FONT_URL}) format('woff2')", "other": "[REDACTED-1]"}}"#),
        "only the occurrence inside the URL survives"
    );
    assert_eq!(
        redaction.findings()[0].occurrences,
        1,
        "the allowed occurrence is not counted"
    );
}

#[test]
fn allowed_within_does_not_spare_a_secret_reaching_past_the_match() {
    let doc = r#"{"a": "keep:abc123"}"#;
    let builder = || Redactor::builder().detector(RegexDetector::new("regex", "abc123").unwrap());

    let out = redact(builder().allow_within(["keep:abc"]).unwrap(), doc);
    assert_eq!(out, r#"{"a": "keep:[REDACTED-1]"}"#);

    let out = redact(builder().allow_within(["keep:abc123"]).unwrap(), doc);
    assert_eq!(out, doc);

    // A pattern that is the secret alone behaves like `allow.regexes`.
    let out = redact(builder().allow_within(["abc123"]).unwrap(), doc);
    assert_eq!(out, doc);
}

#[cfg(feature = "yaml")]
#[test]
fn allowed_within_applies_to_comments() {
    let doc = format!("# {FONT_URL}\nfont: x\n");
    let findings = |builder: RedactorBuilder| {
        builder
            .comments(true)
            .build()
            .redact(doc.as_bytes(), FormatHint::Name("yaml"))
            .unwrap()
            .findings()
            .len()
    };
    assert_eq!(findings(Redactor::builder()), 1, "the comment is scanned");
    assert_eq!(
        findings(Redactor::builder().allow_within([FONTS]).unwrap()),
        0
    );
}

#[test]
fn allowed_within_comes_from_the_configuration() {
    let mut config = Config::builtin().clone();
    config.allow.within.push(FONTS.into());
    let redactor = config.redactor().expect("valid configuration").0;
    let doc = format!(r#"{{"css": "url({FONT_URL})"}}"#);
    assert_eq!(redact_with(&redactor, &doc), doc);
}

#[test]
fn an_invalid_allowed_within_pattern_is_not_echoed() {
    let err = Redactor::builder()
        .allow_within(["sk-live-SECRET("])
        .err()
        .expect("the pattern does not compile")
        .to_string();
    assert!(err.contains("allow-within"), "{err}");
    assert!(!err.contains("SECRET"), "{err}");
}

#[test]
fn disallowed_values_and_patterns_are_reported_by_their_own_detectors() {
    let redaction = scan(
        Redactor::builder()
            .detector(ValueDetector::new(["Jane Roe"]).unwrap())
            .detector(RegexDetector::new("regex", r"\d{3}-\d{2}-\d{4}").unwrap()),
        DOC,
    );
    assert_eq!(tokens_of(&redaction, "value").len(), 1);
    assert_eq!(tokens_of(&redaction, "regex").len(), 1);

    let out = render(&redaction, &Allow::none());
    assert!(out.contains(r#""name": "[REDACTED-1]""#), "{out}");
    assert!(out.contains(r#""ssn": "[REDACTED-2]""#), "{out}");
}

#[test]
fn a_disallowed_value_is_redacted_wherever_it_appears() {
    let out = redact(
        Redactor::builder().detector(ValueDetector::new(["acme"]).unwrap()),
        r#"{"a": "acme corp", "b": "at acme", "c": "ok"}"#,
    );
    assert_eq!(
        out,
        r#"{"a": "[REDACTED-1] corp", "b": "at [REDACTED-1]", "c": "ok"}"#
    );
}

#[test]
fn allowing_wins_over_disallowing() {
    let redaction = scan(
        Redactor::builder()
            .detector(PathDetector::new(["users.name"]))
            .detector(ValueDetector::new(["123-45-6789"]).unwrap()),
        DOC,
    );

    let allow = Allow::values(["Jane Roe"])
        .with_regexes([r"\d{3}-\d{2}-\d{4}"])
        .unwrap();
    let out = render(&redaction, &allow);
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");
    assert!(out.contains(r#""ssn": "123-45-6789""#), "{out}");
    let allowed: Vec<&str> = redaction
        .findings()
        .iter()
        .filter(|f| allow.allows(f))
        .map(|f| f.secret.as_str())
        .collect();
    assert_eq!(
        allowed,
        ["Jane Roe", "123-45-6789"],
        "both are still listed, as allowed"
    );
}

/// Detection is exactly the `detectors` list: one that is not listed does not
/// run, and there is no separate switch for turning one off.
#[test]
fn only_the_configured_detectors_run() {
    let doc = format!(r#"{{"api_key": "{S}", "mail": "jane@corp.example"}}"#);

    let both = configured(&["entropy", "ruleset"]);
    assert_eq!(
        redact_with(&both, &doc),
        r#"{"api_key": "[REDACTED-1]", "mail": "[REDACTED-2]"}"#
    );

    // Without entropy the key survives: no bundled rule knows its shape.
    let no_entropy = configured(&["ruleset"]);
    assert_eq!(
        redact_with(&no_entropy, &doc),
        format!(r#"{{"api_key": "{S}", "mail": "[REDACTED-1]"}}"#)
    );

    let mut none = Config::builtin().clone();
    none.detectors.clear();
    let none = none.redactor().expect("valid configuration").0;
    assert_eq!(redact_with(&none, &doc), doc);
}

/// `regex` entries carry their own label, so unrelated groups of patterns
/// stay apart in a listing instead of all reporting as `regex`.
#[test]
fn regex_entries_report_their_configured_label() {
    let mut config = Config::builtin().clone();
    config.detectors.push(DetectorEntry {
        label: Some("acme".to_owned()),
        ..DetectorConfig::Regex(RegexConfig {
            patterns: vec!["ACME-[0-9]{4}".to_owned()],
        })
        .into()
    });
    config.detectors.push(
        DetectorConfig::Regex(RegexConfig {
            patterns: vec!["ticket-[0-9]+".to_owned()],
        })
        .into(),
    );
    let redactor = config.redactor().expect("valid configuration").0;

    let redaction = redactor
        .redact(
            br#"{"a": "ACME-1234", "b": "ticket-99"}"#,
            FormatHint::Name("json"),
        )
        .expect("valid json");
    let labels: Vec<&str> = redaction
        .findings()
        .iter()
        .map(|f| f.detector.as_str())
        .collect();
    assert_eq!(labels, ["acme", "regex"], "the default label is `regex`");
}

/// The built-in configuration labels its own patterns, so a Supabase key is
/// still reported as `provider_token` now that it is a `regex` entry.
#[test]
fn the_builtin_regex_patterns_keep_their_label() {
    let secret = format!("sb_secret_{}", "probe_20260710_7f91c2d8e4a6b3f0");
    let doc = format!(r#"{{"note": "{secret}"}}"#);
    let redaction = Redactor::builder()
        .build()
        .redact(doc.as_bytes(), FormatHint::Name("json"))
        .expect("valid json");
    assert_eq!(redaction.findings()[0].detector, "provider_token");
}

/// One bundled rule can be switched off by id without switching off the
/// ruleset around it.
#[test]
fn ruleset_rules_can_be_excluded_by_id() {
    let key = "ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2";
    let doc = format!(r#"{{"note": "{key}"}}"#);

    let mut config = Config::builtin().clone();
    config.detectors.retain(|d| d.config.id() == "ruleset");
    let ruleset = config.redactor().expect("valid configuration").0;
    assert_eq!(redact_with(&ruleset, &doc), r#"{"note": "[REDACTED-1]"}"#);

    for detector in &mut config.detectors {
        if let DetectorConfig::Ruleset(ruleset) = &mut detector.config {
            ruleset.exclude_rules = vec!["github-*".into()];
        }
    }
    let excluded = config.redactor().expect("valid configuration").0;
    assert_eq!(redact_with(&excluded, &doc), doc);
}

/// A relabelled ruleset reports its own label in place of `ruleset`, and
/// keeps the id of the rule that matched.
#[test]
fn a_relabelled_ruleset_keeps_its_rule_ids() {
    let doc = r#"{"note": "ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2"}"#;
    let mut config = Config::builtin().clone();
    config.detectors.retain(|d| d.config.id() == "ruleset");
    config.detectors[0].label = Some("gitleaks".into());
    let redaction = config
        .redactor()
        .expect("valid configuration")
        .0
        .redact(doc.as_bytes(), FormatHint::Name("json"))
        .expect("valid json");
    assert_eq!(redaction.findings()[0].detector, "gitleaks:github-pat");
}

/// A disabled entry runs only once turned on, by label or by detector id.
#[test]
fn a_disabled_entry_runs_only_when_enabled() {
    let doc = r#"{"a": "ACME-1234"}"#;
    let mut config = Config::builtin().clone();
    config.detectors.push(DetectorEntry {
        enabled: false,
        label: Some("acme".into()),
        config: DetectorConfig::Regex(RegexConfig {
            patterns: vec!["ACME-[0-9]{4}".to_owned()],
        }),
    });
    let off = config.redactor().expect("valid configuration").0;
    assert_eq!(redact_with(&off, doc), doc);

    for name in ["acme", "regex"] {
        let mut config = config.clone();
        assert!(config.enable_detectors(&[name.to_owned()]).is_empty());
        let on = config.redactor().expect("valid configuration").0;
        assert_eq!(redact_with(&on, doc), r#"{"a": "[REDACTED-1]"}"#);
    }

    assert_eq!(config.enable_detectors(&["nope".to_owned()]), ["nope"]);
}

/// The same, through the Rust API, on the bundled ruleset itself.
#[test]
fn the_bundled_ruleset_is_a_detector_like_any_other() {
    let key = "ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2";
    let doc = format!(r#"{{"note": "{key}"}}"#);

    let rules: RulesetDetector = BETTERLEAKS_RULESET.clone();
    assert_eq!(
        redact_with(&Redactor::builder().detector(rules.clone()).build(), &doc),
        r#"{"note": "[REDACTED-1]"}"#
    );

    let excluded = rules.exclude_rules(["github-pat"]);
    let redactor = RedactorBuilder::new()
        .shared_format(std::sync::Arc::new(velociredactor::format::Json))
        .detector(excluded)
        .build();
    assert_eq!(redact_with(&redactor, &doc), doc);
}

#[test]
fn plain_text_values_have_no_path() {
    let redactor = Redactor::builder()
        .detector(PathDetector::new(["**"]))
        .build();
    let redaction = redactor
        .redact(b"just some words", FormatHint::Raw)
        .unwrap();
    assert_eq!(redaction.findings()[0].path, None);
    assert_eq!(
        render(&redaction, &Allow::none()),
        "[REDACTED-1]",
        "`**` matches the empty path of a plain-text document"
    );
}
