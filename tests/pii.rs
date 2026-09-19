mod common;

use common::*;
use velociredactor::detect::{
    AddressDetector, Detector, EmailConfig, EmailDetector, LeafContext, PhoneDetector,
    RegexDetector,
};
use velociredactor::{Allow, FormatHint, Redactor, RedactorBuilder};

fn matches(detector: &dyn Detector, s: &str) -> Vec<String> {
    let mut out = Vec::new();
    detector.detect(s, &LeafContext::default(), &mut out);
    out.iter().map(|d| s[d.range.clone()].to_owned()).collect()
}

/// The built-in configuration plus the given personal-data detectors, which
/// it leaves switched off.
fn pii_redactor(detectors: impl IntoIterator<Item = Box<dyn Detector>>) -> Redactor {
    detectors
        .into_iter()
        .fold(Redactor::builder(), RedactorBuilder::boxed_detector)
        .build()
}

fn email() -> Box<dyn Detector> {
    Box::new(EmailDetector::default())
}

fn phone() -> Box<dyn Detector> {
    Box::new(PhoneDetector)
}

fn address() -> Box<dyn Detector> {
    Box::new(AddressDetector)
}

/// An email detector carrying the allowlist that the commented-out
/// `pii:email` entry of the built-in configuration documents.
fn allowlisting_email_detector() -> EmailDetector {
    EmailDetector::new(&EmailConfig {
        allowlist: [
            "noreply@",
            "actions@",
            "info@",
            "@users.noreply.github.com",
            "@noreply.github.com",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    })
}

#[test]
fn email_pattern() {
    for s in [
        "user@example.com",
        "user+tag@domain.co.uk",
        "first.last@company.org",
        "a@b.com",
    ] {
        assert_eq!(matches(&EmailDetector::default(), s), [s], "{s}");
    }
    for s in [
        "not an email",
        "@missing.local",
        "missing@",
        "no-at-sign-here",
        "",
    ] {
        assert!(matches(&EmailDetector::default(), s).is_empty(), "{s}");
    }
    assert_eq!(
        matches(&EmailDetector::default(), "a@b.com and c@d.org").len(),
        2
    );
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
    EmailDetector::default().detect(
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
fn a_detector_with_no_allowlist_reports_every_address() {
    assert_eq!(
        matches(&EmailDetector::default(), "from noreply@github.com to"),
        ["noreply@github.com"]
    );
}

#[test]
fn allowlisted_emails_are_not_pii() {
    let detector = allowlisting_email_detector();
    for email in [
        "noreply@github.com",
        "user@users.noreply.github.com",
        "dependabot@users.noreply.github.com",
        "actions@github.com",
        "someone@noreply.github.com",
        "Noreply@GitHub.com",
    ] {
        assert!(
            matches(&detector, &format!("from {email} to")).is_empty(),
            "{email}"
        );
    }
    let git_log =
        "Author: Bot <noreply@github.com>\nCo-Authored-By: User <user@users.noreply.github.com>";
    assert!(matches(&detector, git_log).is_empty());
}

#[test]
fn personal_data_detectors_are_opt_in() {
    let input = "contact user@example.com and call 555-123-4567";
    assert_eq!(text(input), input, "the defaults redact no personal data");

    let email_only = pii_redactor([email()]);
    assert_eq!(
        email_only.redact_str(input),
        "contact [REDACTED-1] and call 555-123-4567"
    );

    let all = pii_redactor([email(), phone(), address()]);
    assert_eq!(
        all.redact_str("lives at 123 Main Street, call 555-123-4567"),
        "lives at [REDACTED-1], call [REDACTED-2]"
    );
}

/// The names a configuration's `pii:` entries are written under.
#[test]
fn detectors_report_the_names_the_configuration_uses() {
    assert_eq!(EmailDetector::default().name(), "pii:email");
    assert_eq!(PhoneDetector.name(), "pii:phone");
    assert_eq!(AddressDetector.name(), "pii:address");
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
    let redactor = pii_redactor([email()]);
    let got = redactor.redact_str(&format!("key={HIGH_ENTROPY_SECRET} user@example.com"));
    assert_eq!(got, "[REDACTED-1] [REDACTED-2]");
}

#[test]
fn file_paths_survive_with_pii_enabled() {
    let redactor = pii_redactor([email(), phone()]);
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
    let redactor = pii_redactor([email()]);
    let input =
        br#"{"file_path":"user@example.com/project/file.go","content":"contact admin@test.org"}"#;
    let redaction = redactor.redact(input, FormatHint::Name("jsonl")).unwrap();
    assert_eq!(
        rendered(&redaction, &Allow::none()),
        r#"{"file_path":"user@example.com/project/file.go","content":"contact [REDACTED-1]"}"#
    );

    let paths = br#"{"file_path":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test/controller.go","cwd":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test","content":"normal text here"}"#;
    let redaction = redactor.redact(paths, FormatHint::Name("jsonl")).unwrap();
    assert!(redaction.findings().is_empty());
}
