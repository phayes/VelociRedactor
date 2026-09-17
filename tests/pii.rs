mod common;

use common::*;
use stripsecret::detect::{
    AddressDetector, Detector, EmailDetector, LeafContext, PhoneDetector, Pii, RegexDetector,
};
use stripsecret::{Allow, FormatHint, Redactor};

fn matches(detector: &dyn Detector, s: &str) -> Vec<String> {
    let mut out = Vec::new();
    detector.detect(s, &LeafContext::default(), &mut out);
    out.iter().map(|d| s[d.range.clone()].to_owned()).collect()
}

fn pii_redactor(categories: &[Pii]) -> Redactor {
    Redactor::builder().pii(categories.iter().copied()).build()
}

#[test]
fn email_pattern() {
    for s in [
        "user@example.com",
        "user+tag@domain.co.uk",
        "first.last@company.org",
        "a@b.com",
    ] {
        assert_eq!(matches(&EmailDetector, s), [s], "{s}");
    }
    for s in [
        "not an email",
        "@missing.local",
        "missing@",
        "no-at-sign-here",
        "",
    ] {
        assert!(matches(&EmailDetector, s).is_empty(), "{s}");
    }
    assert_eq!(matches(&EmailDetector, "a@b.com and c@d.org").len(), 2);
}

#[test]
fn phone_pattern() {
    for s in [
        "555-123-4567",
        "(555) 123-4567",
        "+1-555-123-4567",
        "+1.555.123.4567",
        "1-555-123-4567",
        "555 123 4567",
    ] {
        assert!(!matches(&PhoneDetector, s).is_empty(), "{s}");
    }
    for s in [
        "42",
        "12345",
        "not a phone",
        "1.234.567.8901",
        "192.168.001.0001",
        "555.123.4567",
    ] {
        assert!(matches(&PhoneDetector, s).is_empty(), "{s}");
    }
}

#[test]
fn address_pattern() {
    for s in [
        "123 Main Street",
        "456 Oak Avenue",
        "789 Sunset Blvd",
        "42 Pine Drive",
    ] {
        assert!(!matches(&AddressDetector, s).is_empty(), "{s}");
    }
    for s in [
        "this is normal text",
        "123 lowercase street",
        "no number Street",
    ] {
        assert!(matches(&AddressDetector, s).is_empty(), "{s}");
    }
}

#[test]
fn detectors_report_their_category() {
    let mut out = Vec::new();
    EmailDetector.detect(
        "contact user@example.com for info",
        &LeafContext::default(),
        &mut out,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].label, "pii:email");
    assert_eq!(
        &"contact user@example.com for info"[out[0].range.clone()],
        "user@example.com"
    );
}

#[test]
fn allowlisted_emails_are_not_pii() {
    for email in [
        "noreply@github.com",
        "user@users.noreply.github.com",
        "dependabot@users.noreply.github.com",
        "actions@github.com",
        "someone@noreply.github.com",
        "Noreply@GitHub.com",
    ] {
        assert!(
            matches(&EmailDetector, &format!("from {email} to")).is_empty(),
            "{email}"
        );
    }
    let git_log =
        "Author: Bot <noreply@github.com>\nCo-Authored-By: User <user@users.noreply.github.com>";
    assert!(matches(&EmailDetector, git_log).is_empty());
}

#[test]
fn categories_are_opt_in() {
    let input = "contact user@example.com and call 555-123-4567";
    assert_eq!(text(input), input);

    let email_only = pii_redactor(&[Pii::Email]);
    assert_eq!(
        normalize(&email_only.redact_str(input)),
        "contact REDACTION-1 and call 555-123-4567"
    );

    let all = pii_redactor(&Pii::ALL);
    assert_eq!(
        normalize(&all.redact_str("lives at 123 Main Street, call 555-123-4567")),
        "lives at REDACTION-1, call REDACTION-2"
    );
}

#[test]
fn category_names_parse() {
    assert_eq!("email".parse::<Pii>().unwrap(), Pii::Email);
    assert_eq!(" Phone ".parse::<Pii>().unwrap(), Pii::Phone);
    assert!("ssn".parse::<Pii>().is_err());
}

#[test]
fn custom_pii_patterns() {
    let redactor = Redactor::builder()
        .detector(RegexDetector::new("pii:employee_id", r"EMP-\d{6}").unwrap())
        .build();
    let redaction = redactor
        .redact(b"employee EMP-123456 joined", FormatHint::Name("text"))
        .unwrap();
    assert_eq!(redaction.findings().len(), 1);
    assert_eq!(redaction.findings()[0].detector, "pii:employee_id");
    assert!(RegexDetector::new("bad", "[invalid").is_err());
}

#[test]
fn secrets_and_pii_coexist() {
    let redactor = pii_redactor(&[Pii::Email]);
    let got =
        normalize(&redactor.redact_str(&format!("key={HIGH_ENTROPY_SECRET} user@example.com")));
    assert_eq!(got, "REDACTION-1 REDACTION-2");
}

#[test]
fn file_paths_survive_with_pii_enabled() {
    let redactor = pii_redactor(&[Pii::Email, Pii::Phone]);
    for path in [
        "/tmp/TestE2E_Something3407889464/001/controller.go",
        "/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/TestE2E_Something/controller",
        "/Users/someone/.claude/projects/something.jsonl",
        "/tmp/test/controller.go\n/tmp/test/model.go\n/tmp/test/view.go",
        r"controller.go\nmodel.go\nview.go",
        r"something.go\tanother.go",
        r"C:\\Users\\test\\file.go",
    ] {
        assert_eq!(redactor.redact_str(path), path);
    }
}

#[test]
fn skipped_json_fields_are_not_scanned_for_pii() {
    let redactor = pii_redactor(&[Pii::Email]);
    let input =
        br#"{"file_path":"user@example.com/project/file.go","content":"contact admin@test.org"}"#;
    let redaction = redactor.redact(input, FormatHint::Name("jsonl")).unwrap();
    assert_eq!(
        rendered(&redaction, &Allow::none()),
        r#"{"file_path":"user@example.com/project/file.go","content":"contact REDACTION-1"}"#
    );

    let paths = br#"{"file_path":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test/controller.go","cwd":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test","content":"normal text here"}"#;
    let redaction = redactor.redact(paths, FormatHint::Name("jsonl")).unwrap();
    assert!(redaction.findings().is_empty());
}
