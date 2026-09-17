#![allow(dead_code)]

use std::sync::LazyLock;

use std::collections::HashMap;

use redactify::{Allow, FormatHint, Redaction, Redactor};

/// A value whose Shannon entropy is above the default threshold.
pub const HIGH_ENTROPY_SECRET: &str = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA";

static REDACTOR: LazyLock<Redactor> = LazyLock::new(|| Redactor::builder().build());

pub fn redactor() -> &'static Redactor {
    &REDACTOR
}

/// Replace each `[REDACTION|…]` token with `REDACTION-<n>`, numbering
/// distinct keys in order of first appearance, so expectations stay readable.
pub fn normalize(output: &str) -> String {
    let mut numbers: HashMap<String, usize> = HashMap::new();
    let mut out = String::with_capacity(output.len());
    let mut prev = 0;
    for range in redactify::find_tokens(output) {
        let key = redactify::token_key(&output[range.clone()])
            .unwrap()
            .to_owned();
        let next = numbers.len() + 1;
        let n = *numbers.entry(key).or_insert(next);
        out.push_str(&output[prev..range.start]);
        out.push_str(&format!("REDACTION-{n}"));
        prev = range.end;
    }
    out.push_str(&output[prev..]);
    out
}

/// Render `redaction` and normalize the tokens.
pub fn rendered(redaction: &Redaction<'_>, allow: &Allow) -> String {
    normalize(&String::from_utf8(redaction.render(allow).unwrap()).unwrap())
}

/// Redact `input` as plain text.
pub fn text(input: &str) -> String {
    normalize(&redactor().redact_str(input))
}

/// Redact `input` as the named format, with nothing allowed.
pub fn as_format(format: &str, input: &str) -> String {
    let redaction = redactor()
        .redact(input.as_bytes(), FormatHint::Name(format))
        .unwrap_or_else(|e| panic!("redact as {format}: {e}"));
    rendered(&redaction, &Allow::none())
}

/// Assert that each `(input, want)` pair redacts as plain text to `want`.
pub fn assert_text_cases(cases: &[(&str, &str)]) {
    let mut failures = Vec::new();
    for (input, want) in cases {
        let got = text(input);
        if got != *want {
            failures.push(format!(
                "  input: {input:?}\n   want: {want:?}\n    got: {got:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Assemble a private-key block from fragments so no complete key marker
/// appears in the source.
pub fn fake_openssh_private_key() -> String {
    let marker = |kind: &str| format!("-----{kind} OPEN{}SSH PRIV{}ATE KEY-----", "", "");
    [
        marker("BEGIN"),
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW".into(),
        "QyNTUxOQAAACB7ZlJ8tkWCKdRJRGF1BngP3bkNbz8bMF6Yl5xLJp9m1QAAAJj2M3UO9jN1".into(),
        "DgAAAAtzc2gtZWQyNTUxOQAAACB7ZlJ8tkWCKdRJRGF1BngP3bkNbz8bMF6Yl5xLJp9m1QA".into(),
        "AAEAGZmFrZS1rZXktZm9yLXJlZGFjdGlvbi10ZXN0LW9ubHkBAgMEBQY=".into(),
        marker("END"),
    ]
    .join("\n")
}

/// Supabase prefixes assembled from pieces so complete tokens never appear
/// in the source.
pub fn supabase_secret_prefix() -> String {
    format!("sb{}", "_secret_")
}

pub fn supabase_personal_prefix() -> String {
    format!("sb{}", "p_")
}

pub fn supabase_publishable_prefix() -> String {
    format!("sb{}", "_publishable_")
}
