//! Redaction tokens, allow lists, custom rules, and extension points.

mod common;

use std::fs;

use common::*;
use stripsecret::config::Config;
use stripsecret::detect::{
    AddressDetector, Detection, Detector, DetectorConfig, EmailDetector, LeafContext, Pack,
    PhoneDetector, RegexDetector, load_pack_dir,
};
use stripsecret::format::{Format, FormatError, Leaf, LeafVisitor, Splicer};
use stripsecret::policy::ScanAll;
use stripsecret::{Allow, FormatHint, Redactor, RedactorBuilder};

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
    assert_eq!(finding.token(), "REDACTION-1");
    assert_eq!(finding.len, 7);
    assert_eq!(finding.detector, "credential-assignment");
    assert_eq!(
        String::from_utf8(redaction.render(&Allow::none()).unwrap()).unwrap(),
        "export DB_PASSWORD=REDACTION-1"
    );
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
    assert_eq!(redactor.redact_str("a café"), "a REDACTION-1");
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
        "a DB_PASSWORD=REDACTION-1 b REDACTION-2 c DB_PASSWORD=REDACTION-1 d REDACTION-2"
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
        "one DB_PASSWORD=REDACTION-1\ntwo REDACTION-2\nthree REDACTION-3\n"
    );

    assert_eq!(
        rendered(&redaction, &Allow::values([S])),
        format!("one DB_PASSWORD=REDACTION-1\ntwo {S}\nthree REDACTION-3\n")
    );
    assert_eq!(
        rendered(&redaction, &Allow::values(["hunter2"])),
        format!("one DB_PASSWORD=hunter2\ntwo REDACTION-2\nthree REDACTION-3\n")
    );

    let all = Allow::values(redaction.findings().iter().map(|f| f.secret.clone()));
    assert_eq!(rendered(&redaction, &all), input);
}

#[test]
fn output_redacts_to_itself() {
    for (format, input) in [
        (
            "text",
            format!("x {S} DB_PASSWORD=hunter2 postgres://u:pw@h/db"),
        ),
        (
            "json",
            format!(r#"{{"k":"{S}","db_password":"hunter2","e":"a@b.co"}}"#),
        ),
        ("yaml", format!("k: {S}\ndb_password: hunter2\n")),
        ("dotenv", format!("API_KEY={S}\nDB_PASSWORD=hunter2\n")),
    ] {
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
        "token REDACTION-1 here"
    );
    // Without the rule the low-entropy token is left alone.
    assert_eq!(text("token ACME_AB12CD34 here"), "token ACME_AB12CD34 here");
}

#[test]
fn rule_packs_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("acme.yaml"),
        "name: acme\nversion: 1.0.0\nrules:\n  - id: token\n    regex: 'ACME_[A-Z0-9]{8}'\n    samples:\n      - { input: 'ACME_AB12CD34', redacted: true }\n",
    )
    .unwrap();
    let loaded = load_pack_dir(dir.path()).unwrap();
    assert_eq!(loaded.packs.len(), 1);
    let (detectors, warnings) = loaded.packs[0].detectors();
    assert!(warnings.is_empty());

    let mut builder = Redactor::builder();
    for d in detectors {
        builder = builder.detector(d);
    }
    let redaction = builder
        .build()
        .redact(b"token ACME_AB12CD34", FormatHint::Name("text"))
        .unwrap();
    assert_eq!(redaction.findings()[0].detector, "acme.token");

    let pack = Pack::parse(
        "name: p\nversion: '1'\nrules:\n  - id: r\n    regex: 'X+'\n",
        "p.yaml".as_ref(),
    )
    .unwrap();
    assert_eq!(pack.detectors().0.len(), 1);
}

#[test]
fn empty_builder_redacts_nothing() {
    let redactor = RedactorBuilder::new().build();
    let input = format!("{S} DB_PASSWORD=hunter2");
    assert_eq!(redactor.redact_str(&input), input);
}

/// The thresholds live on the detector, so lowering one means building the
/// detector with a lower one and adding it in place of the configured one.
#[test]
fn entropy_thresholds_live_on_the_detector() {
    let input = r#"{"api_key":"production"}"#;
    assert_eq!(render(redactor(), input, "json", &Allow::none()), input);

    let mut config = Config::builtin().clone();
    for detector in &mut config.detectors {
        if let DetectorConfig::Entropy(entropy) = detector {
            entropy.sensitive_threshold = 3.0;
        }
    }
    let lowered = config.redactor().expect("valid configuration").0;
    assert_eq!(
        render(&lowered, input, "json", &Allow::none()),
        r#"{"api_key":"REDACTION-1"}"#
    );
}

#[test]
fn scan_all_policy_scans_skipped_keys() {
    let input = format!(r#"{{"session_id":"{S}"}}"#);
    let default = render(redactor(), &input, "json", &Allow::none());
    assert_eq!(default, input);
    let scan_all = Redactor::builder().policy(ScanAll).build();
    assert_eq!(
        render(&scan_all, &input, "json", &Allow::none()),
        r#"{"session_id":"REDACTION-1"}"#
    );
}

#[test]
fn raw_skips_format_detection() {
    let input = format!(r#"{{"token":"{S}","session_id":"{S}"}}"#);

    let auto = redactor()
        .redact(input.as_bytes(), FormatHint::Auto)
        .unwrap();
    assert_eq!(auto.format(), "json");
    assert_eq!(
        rendered(&auto, &Allow::none()),
        format!(r#"{{"token":"REDACTION-1","session_id":"{S}"}}"#)
    );

    let raw = redactor()
        .redact(input.as_bytes(), FormatHint::Raw)
        .unwrap();
    assert_eq!(raw.format(), "text");
    assert!(raw.warnings().is_empty());
    assert_eq!(
        rendered(&raw, &Allow::none()),
        r#"{"token":"REDACTION-1","session_id":"REDACTION-1"}"#
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
        "banana: REDACTION-1 split\nid: banana\n"
    );
}

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

#[cfg(feature = "parallel")]
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
