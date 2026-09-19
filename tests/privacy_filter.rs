//! The `privacy_filter` detector against the real model.
//!
//! The model is 2.6 GB, so these tests run only when
//! `VELOCIREDACTOR_PF_MODEL` names a directory holding it, as downloaded by
//! `veloci privacy_filter download --dir DIR`. Build with `--release`: the
//! model is unusably slow unoptimized.

#![cfg(feature = "privacy-filter")]

use std::sync::LazyLock;

use velociredactor::detect::{PrivacyFilterConfig, PrivacyFilterDetector};
use velociredactor::format::Json;
use velociredactor::{Allow, FormatHint, Redactor, RedactorBuilder};

static REDACTOR: LazyLock<Option<Redactor>> = LazyLock::new(|| {
    let dir = std::env::var_os("VELOCIREDACTOR_PF_MODEL")?;
    let detector = PrivacyFilterDetector::new(&PrivacyFilterConfig::new(dir))
        .expect("the model in VELOCIREDACTOR_PF_MODEL loads");
    Some(
        RedactorBuilder::new()
            .format(Json)
            .detector(detector)
            .build(),
    )
});

fn redactor() -> Option<&'static Redactor> {
    let redactor = REDACTOR.as_ref();
    if redactor.is_none() {
        eprintln!("skipped: set VELOCIREDACTOR_PF_MODEL to the model's directory");
    }
    redactor
}

#[test]
fn finds_personal_data_in_the_values_it_belongs_to() {
    let Some(redactor) = redactor() else { return };
    let input = r#"{"customer_name":"Alice Smith","note":"mail alice.smith@fastmail.com","status":"shipped"}"#;
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Name("json"))
        .unwrap();

    let found: Vec<_> = redaction
        .findings()
        .iter()
        .map(|f| (f.detector.as_str(), f.secret.as_str(), f.field.as_deref()))
        .collect();
    assert_eq!(
        found,
        [
            (
                "privacy_filter:private_person",
                "Alice Smith",
                Some("customer_name")
            ),
            (
                "privacy_filter:private_email",
                "alice.smith@fastmail.com",
                Some("note")
            ),
        ]
    );
    assert_eq!(
        String::from_utf8(redaction.render(&Allow::none()).unwrap()).unwrap(),
        r#"{"customer_name":"REDACTION-1","note":"mail REDACTION-2","status":"shipped"}"#
    );
}

/// A document longer than one window is read in several, and what each finds
/// lands in the value it came from.
///
/// This checks where findings land, not what the model judges personal:
/// whether it flags any one row is its call.
#[test]
fn reads_long_documents_in_windows() {
    let Some(redactor) = redactor() else { return };
    let first = ["Alice", "Bob", "Carmen", "Deepak", "Elena", "Farid"];
    let last = ["Smith", "Nguyen", "Garcia", "Patel", "Okafor", "Tanaka"];
    let rows: Vec<String> = (0..150)
        .map(|i| {
            let (f, l) = (first[i % 6], last[i / 6 % 6]);
            format!(
                r#"{{"n":{i},"contact":"{}.{}{i}@gmail.com"}}"#,
                f.to_lowercase(),
                l.to_lowercase()
            )
        })
        .collect();
    let input = format!("[{}]", rows.join(","));
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Name("json"))
        .unwrap();

    let emails: Vec<_> = redaction
        .findings()
        .iter()
        .filter(|f| f.detector == "privacy_filter:private_email")
        .collect();
    for email in &emails {
        assert_eq!(email.field.as_deref(), Some("contact"), "{email:?}");
        assert!(email.secret.ends_with("@gmail.com"), "{email:?}");
    }
    // Rows from the first and last windows are both found.
    let row = |f: &&&velociredactor::Finding| {
        let digits: String = f.secret.chars().filter(char::is_ascii_digit).collect();
        digits.parse::<usize>().unwrap()
    };
    assert!(emails.iter().any(|f| row(&f) < 20), "{emails:?}");
    assert!(emails.iter().any(|f| row(&f) >= 130), "{emails:?}");
}
