//! Redaction tokens, allow lists, custom rules, and extension points.

mod common;

use common::*;
#[cfg(feature = "json")]
use velociredactor::config::Config;
#[cfg(feature = "json")]
use velociredactor::detect::DetectorConfig;
use velociredactor::detect::{
    AddressDetector, Detection, Detector, DocumentValue, EmailDetector, LeafContext, PhoneDetector,
    RegexDetector,
};
use velociredactor::format::{Format, FormatError, Leaf, LeafVisitor, Splicer};
#[cfg(feature = "json")]
use velociredactor::policy::ScanAll;
use velociredactor::{Allow, FormatHint, Redactor, RedactorBuilder, ReplacementFormat};

const S: &str = HIGH_ENTROPY_SECRET;

/// Render with real tokens.
fn render(redactor: &Redactor, input: &str, format: &str, allow: &Allow) -> String {
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Name(format))
        .unwrap();
    String::from_utf8(redaction.render(allow).unwrap()).unwrap()
}

#[test]
fn token_format() {
    let redaction = redactor()
        .redact(b"export DB_PASSWORD=hunter2", FormatHint::Name("text"))
        .unwrap();
    let finding = &redaction.findings()[0];
    assert_eq!(finding.id, 1);
    assert_eq!(finding.token(), "[REDACTED-1]");
    assert_eq!(finding.len, 7);
    assert_eq!(finding.detector, "credential_assignment");
    assert_eq!(
        String::from_utf8(redaction.render(&Allow::none()).unwrap()).unwrap(),
        "export DB_PASSWORD=[REDACTED-1]"
    );
}

#[test]
fn a_custom_replacement_format_is_wired_through_the_builder() {
    let format = ReplacementFormat::parse("[REDACTED-{n}:{reason}]").unwrap();
    let redactor = Redactor::builder().replacement(format.clone()).build();
    assert_eq!(redactor.replacement(), &format);

    let redaction = redactor
        .redact(b"export DB_PASSWORD=hunter2", FormatHint::Name("text"))
        .unwrap();
    let finding = &redaction.findings()[0];
    assert_eq!(finding.token(), "[REDACTED-1:credential_assignment]");
    assert_eq!(
        String::from_utf8(redaction.render(&Allow::none()).unwrap()).unwrap(),
        "export DB_PASSWORD=[REDACTED-1:credential_assignment]"
    );
}

#[test]
fn a_reason_format_rejects_detector_labels_it_cannot_recognize() {
    let format = ReplacementFormat::parse("[REDACTED-{n}:{reason}]").unwrap();
    let redactor = RedactorBuilder::new()
        .detector(RegexDetector::new("bad label", "secret").unwrap())
        .replacement(format)
        .build();
    let err = redactor
        .redact(b"secret", FormatHint::Raw)
        .err()
        .expect("the invalid reason must fail")
        .to_string();
    assert!(err.contains("reason"), "{err}");
}

#[test]
fn len_counts_bytes() {
    let redactor = Redactor::builder()
        .detector(RegexDetector::new("word", "café").unwrap())
        .build();
    let redaction = redactor
        .redact("a café".as_bytes(), FormatHint::Name("text"))
        .unwrap();
    assert_eq!(redaction.findings()[0].len, 5);
    assert_eq!(redactor.redact_str("a café"), "a [REDACTED-1]");
}

#[test]
fn equal_values_share_an_id() {
    let input = format!("a DB_PASSWORD=hunter2 b {S} c DB_PASSWORD=hunter2 d {S}");
    let redaction = redactor()
        .redact(input.as_bytes(), FormatHint::Name("text"))
        .unwrap();
    let findings = redaction.findings();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].secret, "hunter2");
    assert_eq!(findings[1].secret, S);
    assert_eq!(findings[0].id, 1);
    assert_eq!(findings[1].id, 2);
    assert_eq!(findings[0].occurrences, 2);
    assert_eq!(findings[0].offsets, [14, 84]);
    assert_eq!(
        rendered(&redaction, &Allow::none()),
        "a DB_PASSWORD=[REDACTED-1] b [REDACTED-2] c DB_PASSWORD=[REDACTED-1] d [REDACTED-2]"
    );
}

#[test]
fn allow_by_value() {
    let input = format!(
        "one DB_PASSWORD=hunter2\ntwo {S}\nthree postgres://app:pwd123@db.example.com/app\n"
    );
    let redaction = redactor()
        .redact(input.as_bytes(), FormatHint::Name("text"))
        .unwrap();
    assert_eq!(
        rendered(&redaction, &Allow::none()),
        "one DB_PASSWORD=[REDACTED-1]\ntwo [REDACTED-2]\nthree [REDACTED-3]\n"
    );

    assert_eq!(
        rendered(&redaction, &Allow::values([S])),
        format!("one DB_PASSWORD=[REDACTED-1]\ntwo {S}\nthree [REDACTED-3]\n")
    );
    assert_eq!(
        rendered(&redaction, &Allow::values(["hunter2"])),
        format!("one DB_PASSWORD=hunter2\ntwo [REDACTED-2]\nthree [REDACTED-3]\n")
    );

    let all = Allow::values(redaction.findings().iter().map(|f| f.secret.clone()));
    assert_eq!(rendered(&redaction, &all), input);
}

#[test]
fn output_redacts_to_itself() {
    let cases = [
        (
            "text",
            format!("x {S} DB_PASSWORD=hunter2 postgres://u:pw@h/db"),
        ),
        #[cfg(feature = "json")]
        (
            "json",
            format!(r#"{{"k":"{S}","db_password":"hunter2","e":"a@b.co"}}"#),
        ),
        #[cfg(feature = "yaml")]
        ("yaml", format!("k: {S}\ndb_password: hunter2\n")),
        #[cfg(feature = "dotenv")]
        ("dotenv", format!("API_KEY={S}\nDB_PASSWORD=hunter2\n")),
    ];
    for (format, input) in cases {
        let redactor = Redactor::builder()
            .detector(EmailDetector::default())
            .detector(PhoneDetector)
            .detector(AddressDetector)
            .build();
        let once = render(&redactor, &input, format, &Allow::none());
        let redaction = redactor
            .redact(once.as_bytes(), FormatHint::Name(format))
            .unwrap();
        assert!(
            redaction.findings().is_empty(),
            "{format}: {once}\n{:?}",
            redaction.findings()
        );
    }
}

#[test]
fn inline_custom_rules() {
    let redactor = Redactor::builder()
        .detector(RegexDetector::new("acme", r"ACME_[A-Z0-9]{8}").unwrap())
        .build();
    assert_eq!(
        redactor.redact_str("token ACME_AB12CD34 here"),
        "token [REDACTED-1] here"
    );
    // Without the rule the low-entropy token is left alone.
    assert_eq!(text("token ACME_AB12CD34 here"), "token ACME_AB12CD34 here");
}

#[test]
fn empty_builder_redacts_nothing() {
    let redactor = RedactorBuilder::new().build();
    let input = format!("{S} DB_PASSWORD=hunter2");
    assert_eq!(redactor.redact_str(&input), input);
}

/// The thresholds live on the detector, so lowering one means building the
/// detector with a lower one and adding it in place of the configured one.
#[cfg(feature = "json")]
#[test]
fn entropy_thresholds_live_on_the_detector() {
    let input = r#"{"api_key":"production"}"#;
    assert_eq!(render(redactor(), input, "json", &Allow::none()), input);

    let mut config = Config::builtin().clone();
    for detector in &mut config.detectors {
        if let DetectorConfig::Entropy(entropy) = &mut detector.config {
            entropy.sensitive_threshold = 3.0;
        }
    }
    let lowered = config.redactor().expect("valid configuration").0;
    assert_eq!(
        render(&lowered, input, "json", &Allow::none()),
        r#"{"api_key":"[REDACTED-1]"}"#
    );
}

#[cfg(feature = "json")]
#[test]
fn scan_all_policy_scans_skipped_keys() {
    let input = format!(r#"{{"session_id":"{S}"}}"#);
    let default = render(redactor(), &input, "json", &Allow::none());
    assert_eq!(default, input);
    let scan_all = Redactor::builder().policy(ScanAll).build();
    assert_eq!(
        render(&scan_all, &input, "json", &Allow::none()),
        r#"{"session_id":"[REDACTED-1]"}"#
    );
}

#[cfg(feature = "json")]
#[test]
fn raw_skips_format_detection() {
    let input = format!(r#"{{"token":"{S}","session_id":"{S}"}}"#);

    let auto = redactor()
        .redact(input.as_bytes(), FormatHint::Auto)
        .unwrap();
    assert_eq!(auto.format(), "json");
    assert_eq!(
        rendered(&auto, &Allow::none()),
        format!(r#"{{"token":"[REDACTED-1]","session_id":"{S}"}}"#)
    );

    let raw = redactor()
        .redact(input.as_bytes(), FormatHint::Raw)
        .unwrap();
    assert_eq!(raw.format(), "text");
    assert!(raw.warnings().is_empty());
    assert_eq!(
        rendered(&raw, &Allow::none()),
        r#"{"token":"[REDACTED-1]","session_id":"[REDACTED-1]"}"#
    );
}

/// A detector that flags the word "banana".
struct Banana;

impl Detector for Banana {
    fn name(&self) -> &str {
        "banana"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for (i, m) in value.match_indices("banana") {
            out.push(Detection::new(i..i + m.len(), self.name()));
        }
    }
}

/// A document-scoped detector: flags every value that comes after one equal
/// to "flag", which no per-value detector could know.
#[cfg(feature = "json")]
struct AfterFlag;

#[cfg(feature = "json")]
impl Detector for AfterFlag {
    fn name(&self) -> &str {
        "after_flag"
    }

    fn detect(&self, _value: &str, _ctx: &LeafContext<'_>, _out: &mut Vec<Detection>) {
        panic!("a document-scoped detector is never called per value");
    }

    fn document_scope(&self) -> bool {
        true
    }

    fn detect_document(
        &self,
        values: &[DocumentValue<'_>],
        out: &mut [Vec<Detection>],
    ) -> Result<(), velociredactor::Error> {
        let mut flagged = false;
        for (value, out) in values.iter().zip(out) {
            if flagged {
                out.push(Detection::new(0..value.value.len(), self.name()));
            }
            flagged |= value.value == "flag";
        }
        Ok(())
    }
}

#[cfg(feature = "json")]
#[test]
fn document_scoped_detectors_see_the_whole_document() {
    let redactor = RedactorBuilder::new()
        .format(velociredactor::format::Json)
        .detector(AfterFlag)
        .detector(Banana)
        .build();
    let out = render(
        &redactor,
        r#"{"a":"one banana","b":"flag","c":"two","d":{"e":"three"}}"#,
        "json",
        &Allow::none(),
    );
    assert_eq!(
        out,
        r#"{"a":"one [REDACTED-1]","b":"flag","c":"[REDACTED-2]","d":{"e":"[REDACTED-3]"}}"#
    );
}

#[cfg(feature = "json")]
#[test]
fn document_scoped_detectors_are_given_only_scanned_values() {
    let redactor = RedactorBuilder::new()
        .format(velociredactor::format::Json)
        .detector(AfterFlag)
        .allow_paths(["skipped"])
        .build();
    // The skipped "flag" is never seen, so nothing after it is flagged.
    let out = render(
        &redactor,
        r#"{"skipped":"flag","c":"two"}"#,
        "json",
        &Allow::none(),
    );
    assert_eq!(out, r#"{"skipped":"flag","c":"two"}"#);
}

/// A document-scoped detector that cannot look.
struct Broken;

impl Detector for Broken {
    fn name(&self) -> &str {
        "broken"
    }

    fn detect(&self, _value: &str, _ctx: &LeafContext<'_>, _out: &mut Vec<Detection>) {}

    fn document_scope(&self) -> bool {
        true
    }

    fn detect_document(
        &self,
        _values: &[DocumentValue<'_>],
        _out: &mut [Vec<Detection>],
    ) -> Result<(), velociredactor::Error> {
        Err(velociredactor::Error::Detector {
            name: self.name().into(),
            message: "no model".into(),
        })
    }
}

#[test]
fn a_failing_document_scoped_detector_fails_the_redaction() {
    let redactor = RedactorBuilder::new().detector(Broken).build();
    let err = redactor
        .redact(b"hello", FormatHint::Raw)
        .err()
        .expect("a detector that could not look is not a clean result");
    assert_eq!(err.to_string(), "broken: no model");
}

/// A `key: value` per line format that only treats text after `: ` as a value.
struct Colon;

impl Format for Colon {
    fn name(&self) -> &str {
        "colon"
    }

    fn extensions(&self) -> &[&str] {
        &["colon"]
    }

    fn rewrite(&self, input: &[u8], visitor: &mut dyn LeafVisitor) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(input).map_err(|e| FormatError::new("colon", e))?;
        let mut splicer = Splicer::new(input);
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            if let Some((key, value)) = line.trim_end().split_once(": ") {
                let start = offset + key.len() + 2;
                let leaf = Leaf::new(value).with_key(Some(key)).with_offset(start);
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

#[test]
fn user_defined_format_and_detector() {
    let redactor = Redactor::builder().format(Colon).detector(Banana).build();
    let input = "banana: banana split\nid: banana\n";
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Path("fruit.colon".as_ref()))
        .unwrap();
    assert_eq!(redaction.format(), "colon");
    assert_eq!(
        rendered(&redaction, &Allow::none()),
        "banana: [REDACTED-1] split\nid: banana\n"
    );
}

#[cfg(feature = "json")]
#[test]
fn locations_point_at_the_secret() {
    let input = format!("{{\n  \"a\": \"x\",\n  \"b\": \"prefix {S}\"\n}}");
    let redaction = redactor()
        .redact(input.as_bytes(), FormatHint::Name("json"))
        .unwrap();
    let finding = &redaction.findings()[0];
    assert_eq!(finding.field.as_deref(), Some("b"));
    assert_eq!(redaction.line_col(finding.offset().unwrap()), (3, 16));
}

#[cfg(all(feature = "parallel", feature = "json"))]
#[test]
fn large_jsonl_is_consistent() {
    let mut input = String::new();
    for i in 0..5000 {
        if i % 7 == 0 {
            input.push_str(&format!("{{\"n\":{i},\"t\":\"key {S}{}\"}}\n", i % 3));
        } else {
            input.push_str(&format!("{{\"n\":{i},\"t\":\"hello {i}\"}}\n"));
        }
    }
    let first = render(redactor(), &input, "jsonl", &Allow::none());
    let second = render(redactor(), &input, "jsonl", &Allow::none());
    assert_eq!(first, second);
    assert!(!first.contains(S));
    assert_eq!(
        redactor()
            .redact(input.as_bytes(), FormatHint::Name("jsonl"))
            .unwrap()
            .findings()
            .len(),
        3
    );
}
