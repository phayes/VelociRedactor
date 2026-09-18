//! Forcing and sparing redactions by key path, value, pattern, and detector.

mod common;

use common::HIGH_ENTROPY_SECRET as S;
use stripsecret::detect::{RegexDetector, ValueDetector};
use stripsecret::{Allow, Finding, FormatHint, Redaction, Redactor, RedactorBuilder};

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
        Redactor::builder().disallow_paths(["users.name", "users.ssn"]),
        DOC,
    );
    let out = render(&redaction, &Allow::none());
    assert!(out.contains(r#""name": "REDACTION-1""#), "{out}");
    assert!(out.contains(r#""ssn": "REDACTION-2""#), "{out}");
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
    let out = redact(Redactor::builder().disallow_paths(["**.ssn"]), DOC);
    assert!(out.contains(r#""ssn": "REDACTION-1""#), "{out}");
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");

    let out = redact(Redactor::builder().disallow_paths(["db.*"]), DOC);
    assert!(out.contains(r#""host": "REDACTION-1""#), "{out}");
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");

    // A single star stays inside one segment.
    let out = redact(Redactor::builder().disallow_paths(["*"]), DOC);
    assert!(out.contains(r#""name": "Jane Roe""#), "{out}");
}

#[test]
fn allowed_paths_are_never_scanned() {
    let doc = format!(r#"{{"keep": {{"api_key": "{S}"}}, "other": "{S}"}}"#);

    let redaction = scan(Redactor::builder().allow_paths(["keep.**"]), &doc);
    let out = render(&redaction, &Allow::none());
    assert_eq!(
        out,
        format!(r#"{{"keep": {{"api_key": "{S}"}}, "other": "REDACTION-1"}}"#),
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
            .disallow_paths(["users.**"]),
        DOC,
    );
    assert!(out.contains(r#""ssn": "123-45-6789""#), "{out}");
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
    assert!(out.contains(r#""name": "REDACTION-1""#), "{out}");
    assert!(out.contains(r#""ssn": "REDACTION-2""#), "{out}");
}

#[test]
fn a_disallowed_value_is_redacted_wherever_it_appears() {
    let out = redact(
        Redactor::builder().detector(ValueDetector::new(["acme"]).unwrap()),
        r#"{"a": "acme corp", "b": "at acme", "c": "ok"}"#,
    );
    assert_eq!(
        out,
        r#"{"a": "REDACTION-1 corp", "b": "at REDACTION-1", "c": "ok"}"#
    );
}

#[test]
fn allowing_wins_over_disallowing() {
    let redaction = scan(
        Redactor::builder()
            .disallow_paths(["users.name"])
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

#[test]
fn excluded_detectors_report_nothing() {
    let doc = format!(r#"{{"api_key": "{S}", "mail": "jane@corp.example"}}"#);
    let with_pii = || Redactor::builder().pii([stripsecret::detect::Pii::Email]);

    let out = redact(with_pii(), &doc);
    assert_eq!(out, r#"{"api_key": "REDACTION-1", "mail": "REDACTION-2"}"#);

    let out = redact(with_pii().exclude_detectors(["entropy"]), &doc);
    assert_eq!(
        out,
        format!(r#"{{"api_key": "{S}", "mail": "REDACTION-1"}}"#)
    );

    let out = redact(with_pii().exclude_detectors(["pii:*"]), &doc);
    assert_eq!(
        out,
        r#"{"api_key": "REDACTION-1", "mail": "jane@corp.example"}"#
    );

    let out = redact(with_pii().exclude_detectors(["*"]), &doc);
    assert_eq!(out, doc);
}

#[test]
fn excluding_matches_the_reported_label_not_only_the_detector_name() {
    let key = "ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2";
    let doc = format!(r#"{{"note": "{key}"}}"#);

    let out = redact(Redactor::builder().exclude_detectors(["entropy"]), &doc);
    assert_eq!(
        out, r#"{"note": "REDACTION-1"}"#,
        "the ruleset still finds it"
    );

    let out = redact(
        Redactor::builder().exclude_detectors(["entropy", "ruleset:github-pat"]),
        &doc,
    );
    assert_eq!(out, doc);
}

#[test]
fn plain_text_values_have_no_path() {
    let redactor = Redactor::builder().disallow_paths(["**"]).build();
    let redaction = redactor
        .redact(b"just some words", FormatHint::Raw)
        .unwrap();
    assert_eq!(redaction.findings()[0].path, None);
    assert_eq!(
        render(&redaction, &Allow::none()),
        "REDACTION-1",
        "`**` matches the empty path of a plain-text document"
    );
}
