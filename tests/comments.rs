//! Scanning comments, which are skipped unless asked for.

mod common;

use common::HIGH_ENTROPY_SECRET as S;
use velociredactor::{Allow, FormatHint, Redactor};

/// Redact `input` as `format`, with comment scanning on or off.
fn redact(format: &str, input: &str, comments: bool) -> String {
    let redactor = Redactor::builder().comments(comments).build();
    let redaction = redactor
        .redact(input.as_bytes(), FormatHint::Name(format))
        .unwrap_or_else(|e| panic!("redact as {format}: {e}"));
    String::from_utf8(redaction.render(&Allow::none()).unwrap()).unwrap()
}

/// Assert that the secret in a comment survives by default and is redacted
/// with comments on, and that redacting again changes nothing.
#[track_caller]
fn assert_comment_scanned(format: &str, input: &str, want: &str) {
    assert_eq!(redact(format, input, false), input, "{format}: default");
    let got = redact(format, input, true);
    assert_eq!(got, want, "{format}: with comments");
    assert_eq!(redact(format, &got, true), got, "{format}: not idempotent");
}

#[test]
fn json_line_and_block_comments() {
    assert_comment_scanned(
        "json",
        &format!("{{\n  // token {S}\n  \"a\": \"ok\" /* and {S} */\n}}"),
        "{\n  // token [REDACTED-1]\n  \"a\": \"ok\" /* and [REDACTED-1] */\n}",
    );
}

#[test]
fn json_strings_that_look_like_comments_are_left_alone() {
    let input = format!(r#"{{"note": "// not a comment {S}"}}"#);
    // The string is a value, so it is redacted either way, and only once.
    let want = r#"{"note": "// not a comment [REDACTED-1]"}"#;
    assert_eq!(redact("json", &input, false), want);
    assert_eq!(redact("json", &input, true), want);
}

#[test]
fn yaml_comments() {
    assert_comment_scanned(
        "yaml",
        &format!("# lead {S}\na: ok # trail {S}\n"),
        "# lead [REDACTED-1]\na: ok # trail [REDACTED-1]\n",
    );
}

#[test]
fn yaml_hashes_inside_scalars_are_not_comments() {
    // The block scalar's body is a value: redacted once, and not spliced
    // twice by also being read as a comment.
    let input = format!("note: |\n  # inside {S}\nurl: \"http://x/#frag\"\n");
    let want = "note: |\n  # inside [REDACTED-1]\nurl: \"http://x/#frag\"\n";
    assert_eq!(redact("yaml", &input, true), want);
    assert_eq!(redact("yaml", &input, false), want);
}

#[test]
fn toml_comments() {
    assert_comment_scanned(
        "toml",
        &format!("# lead {S}\n[s]\na = \"ok\" # trail {S}\n"),
        "# lead [REDACTED-1]\n[s]\na = \"ok\" # trail [REDACTED-1]\n",
    );
}

#[test]
fn toml_hashes_inside_strings_are_not_comments() {
    let input = "a = \"x # y\"\nb = '''\n# z\n'''\n";
    assert_eq!(redact("toml", input, true), input);
}

#[test]
fn hcl_comments() {
    assert_comment_scanned(
        "hcl",
        &format!("# lead {S}\nvariable \"v\" {{\n  default = \"ok\" // trail {S}\n}}\n"),
        "# lead [REDACTED-1]\nvariable \"v\" {\n  default = \"ok\" // trail [REDACTED-1]\n}\n",
    );
}

#[test]
fn hcl_heredoc_bodies_are_values_not_comments() {
    let input = format!("a = <<EOT\n# inside {S}\nEOT\n");
    let want = "a = <<EOT\n# inside [REDACTED-1]\nEOT\n";
    assert_eq!(redact("hcl", &input, true), want);
    assert_eq!(redact("hcl", &input, false), want);
}

#[test]
fn ini_and_dotenv_comments() {
    assert_comment_scanned(
        "ini",
        &format!("; lead {S}\n[s]\nkey = ok\n# other {S}\n"),
        "; lead [REDACTED-1]\n[s]\nkey = ok\n# other [REDACTED-1]\n",
    );
    assert_comment_scanned(
        "dotenv",
        &format!("# lead {S}\nKEY=ok\n"),
        "# lead [REDACTED-1]\nKEY=ok\n",
    );
}

#[test]
fn xml_comments() {
    assert_comment_scanned(
        "xml",
        &format!("<r><!-- token {S} --><a>ok</a></r>"),
        "<r><!-- token [REDACTED-1] --><a>ok</a></r>",
    );
}

#[test]
fn properties_comments() {
    assert_comment_scanned(
        "properties",
        &format!("# lead {S}\nkey=ok\n"),
        "# lead [REDACTED-1]\nkey=ok\n",
    );
}

#[test]
fn a_secret_in_a_comment_shares_the_token_with_the_same_value_elsewhere() {
    let input = format!("# see {S}\na = \"{S}\"\n");
    assert_eq!(
        redact("toml", &input, true),
        "# see [REDACTED-1]\na = \"[REDACTED-1]\"\n"
    );
}

#[test]
fn formats_without_comments_are_unaffected() {
    let input = format!("name,key\nx,{S}\n");
    let with = redact("csv", &input, true);
    assert_eq!(with, redact("csv", &input, false));
    assert_eq!(with, "name,key\nx,[REDACTED-1]\n");
}
