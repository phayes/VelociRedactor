#![cfg(feature = "cli")]

mod common;

use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::normalize;
use stripsecret::{DEFAULT_SALT, redaction_key};

const S: &str = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA";

fn stripsecret(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_stripsecret"))
        .args(args)
        .env_remove("STRIPSECRET_SALT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn redact(args: &[&str], stdin: &str) -> Output {
    stripsecret(&[&["redact"], args].concat(), stdin)
}

fn list(args: &[&str], stdin: &str) -> Output {
    stripsecret(&[&["list"], args].concat(), stdin)
}

fn raw_stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stdout(output: &Output) -> String {
    normalize(&raw_stdout(output))
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn key(value: &str) -> String {
    redaction_key(DEFAULT_SALT.as_bytes(), value)
}

#[test]
fn redacts_stdin_with_full_token() {
    let out = redact(&[], &format!("token {S}\n"));
    assert!(out.status.success());
    assert_eq!(
        raw_stdout(&out),
        format!("token [REDACTION|entropy|45|{}]\n", key(S))
    );
}

#[test]
fn salt_changes_keys() {
    let out = redact(&["--salt", "team"], "DB_PASSWORD=hunter2");
    let team_key = redaction_key(b"team", "hunter2");
    assert_eq!(
        raw_stdout(&out),
        format!("DB_PASSWORD=[REDACTION|credential-assignment|7|{team_key}]")
    );

    let out = Command::new(env!("CARGO_BIN_EXE_stripsecret"))
        .env("STRIPSECRET_SALT", "team")
        .args(["redact", "--allow-key", &team_key])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn detects_format_from_file_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    fs::write(&path, format!("token: {S}\nsession_id: {S}\n")).unwrap();
    let out = redact(&[path.to_str().unwrap()], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!("token: \"REDACTION-1\"\nsession_id: {S}\n")
    );
}

#[test]
fn raw_skips_format_detection() {
    let input = format!("token: {S}\nsession_id: {S}\n");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    fs::write(&path, &input).unwrap();

    let out = redact(&[path.to_str().unwrap(), "--raw"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "token: REDACTION-1\nsession_id: REDACTION-1\n"
    );

    let sniffed = format!(r#"{{"token":"{S}","session_id":"{S}"}}"#);
    let out = redact(&["--raw"], &sniffed);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        r#"{"token":"REDACTION-1","session_id":"REDACTION-1"}"#
    );

    let out = list(&["--json", "--raw"], &sniffed);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["format"], "text");

    let out = redact(&["--raw", "-f", "json"], &sniffed);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("cannot be used with"));
}

#[test]
fn allow_and_check() {
    let input = format!("a {S}\nb DB_PASSWORD=hunter2\n");
    let hunter = key("hunter2");

    let out = redact(&["--check"], &input);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=REDACTION-2\n");

    let out = redact(&["--check", "--allow-key", &hunter], &input);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=hunter2\n");

    let out = redact(&["--allow-value", "hunter2"], &input);
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=hunter2\n");

    let s_key = key(S);
    let out = redact(
        &["--check", "--allow-key", &s_key, "--allow-key", &hunter],
        &input,
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), input);

    // A full token copied from the output works as a key.
    let token = format!("[REDACTION|entropy|45|{}]", key(S));
    let out = redact(&["--allow-key", &token], &input);
    assert_eq!(stdout(&out), format!("a {S}\nb DB_PASSWORD=REDACTION-1\n"));
}

#[test]
fn unmatched_allow_entries_warn() {
    let unknown = key("never-seen");
    let out = redact(
        &["--allow-key", &unknown, "--allow-value", "nope"],
        "DB_PASSWORD=hunter2",
    );
    let err = stderr(&out);
    assert!(
        err.contains(&format!("--allow-key {unknown}: no such redaction")),
        "{err}"
    );
    assert!(
        err.contains("1 --allow-value value(s) matched no redaction"),
        "{err}"
    );
    assert!(!err.contains("nope"), "{err}");

    let out = redact(&["--allow-key", "abc"], "x");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn list_shows_key_start_and_length_but_not_values() {
    let out = list(&[], &format!("x {S}\n"));
    assert!(out.status.success());
    let table = raw_stdout(&out);
    let lines: Vec<&str> = table.lines().collect();
    assert!(lines[0].starts_with("KEY"), "{table}");
    for column in ["DETECTOR", "START", "LEN", "COUNT", "LOCATION"] {
        assert!(lines[0].contains(column), "{table}");
    }
    assert!(!lines[0].contains("VALUE"), "{table}");
    let row: Vec<&str> = lines[1].split_whitespace().collect();
    assert_eq!(
        row[..6],
        [key(S).as_str(), "entropy", "2", "45", "1", "1:3"]
    );
    assert!(!table.contains(S), "{table}");
    assert!(out.stderr.is_empty());

    let out = list(&["--show-value"], &format!("x {S}\n"));
    let table = raw_stdout(&out);
    assert!(table.lines().next().unwrap().contains("VALUE"), "{table}");
    assert!(table.contains(S), "{table}");

    let out = list(&["--allow-key", &key(S)], &format!("x {S}\n"));
    assert!(
        raw_stdout(&out)
            .lines()
            .nth(1)
            .unwrap()
            .ends_with("allowed")
    );

    let out = list(&[], "nothing here\n");
    assert_eq!(raw_stdout(&out), "no redactions\n");
}

#[test]
fn list_check() {
    let out = list(&["--check"], "DB_PASSWORD=hunter2");
    assert_eq!(out.status.code(), Some(1));
    let out = list(
        &["--check", "--allow-value", "hunter2"],
        "DB_PASSWORD=hunter2",
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn json_list() {
    let input = format!("{{\"to\":\"x\",\"token\":\"{S}\",\"again\":\"{S}\"}}");
    let out = list(&["--json", "-f", "json"], &input);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["format"], "json");
    let entry = &doc["redactions"][0];
    assert_eq!(entry["key"], key(S));
    assert_eq!(entry["token"], format!("[REDACTION|entropy|45|{}]", key(S)));
    assert_eq!(entry["detector"], "entropy");
    assert_eq!(entry["start"], 19);
    assert_eq!(entry["length"], 45);
    assert_eq!(entry["line"], 1);
    assert_eq!(entry["column"], 20);
    assert_eq!(entry["field"], "token");
    assert_eq!(entry["occurrences"], 2);
    assert_eq!(entry["offsets"], serde_json::json!([19, 75]));
    assert_eq!(entry["allowed"], false);
    assert!(entry.get("value").is_none());
    assert!(!raw_stdout(&out).contains(S));

    let out = list(&["--json", "--show-value", "--allow-value", S], &input);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["value"], S);
    assert_eq!(doc["redactions"][0]["allowed"], true);
}

#[test]
fn explicit_format_and_pii() {
    let out = redact(
        &["-f", "json", "--pii", "email"],
        r#"{"to":"jane@corp.example","id":"x"}"#,
    );
    assert_eq!(
        raw_stdout(&out),
        format!(
            r#"{{"to":"[REDACTION|pii:email|17|{}]","id":"x"}}"#,
            key("jane@corp.example")
        )
    );

    let out = redact(&["-f", "nope"], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown format"));
}

#[test]
fn custom_rules_and_packs() {
    let out = redact(&["--rule", "acme=ACME_[0-9]{4}"], "id ACME_1234\n");
    assert_eq!(
        raw_stdout(&out),
        format!("id [REDACTION|acme|9|{}]\n", key("ACME_1234"))
    );

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("team.yaml"),
        "name: team\nversion: '1'\nrules:\n  - id: t\n    regex: 'TEAM-[0-9]{3}'\n",
    )
    .unwrap();
    let out = redact(
        &["--rules-pack", dir.path().to_str().unwrap()],
        "ref TEAM-123\n",
    );
    assert_eq!(stdout(&out), "ref REDACTION-1\n");
    assert!(raw_stdout(&out).contains("|team.t|8|"));

    let out = redact(&["--rule", "missing-equals"], "");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn custom_ruleset_replaces_bundled_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.toml");
    fs::write(&path, "[[rules]]\nid = \"zz\"\nregex = '''ZZ[0-9]{4}'''\n").unwrap();
    let out = redact(
        &["--ruleset", path.to_str().unwrap()],
        "ZZ1234 ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2\n",
    );
    assert_eq!(
        stdout(&out),
        "REDACTION-1 ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2\n"
    );
    assert!(raw_stdout(&out).contains("|ruleset:zz|6|"));
}

#[test]
fn output_and_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.env");
    let output = dir.path().join("out.env");
    fs::write(&input, format!("KEY={S}\n")).unwrap();

    let out = redact(
        &[input.to_str().unwrap(), "-o", output.to_str().unwrap()],
        "",
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(
        normalize(&fs::read_to_string(&output).unwrap()),
        "KEY=REDACTION-1\n"
    );

    let out = redact(&[input.to_str().unwrap(), "--in-place"], "");
    assert!(out.status.success());
    let redacted = fs::read_to_string(&input).unwrap();
    assert_eq!(normalize(&redacted), "KEY=REDACTION-1\n");

    // Running again on redacted output changes nothing.
    let out = redact(&[input.to_str().unwrap(), "--check"], "");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(raw_stdout(&out), redacted);

    let out = redact(&["--in-place"], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--in-place needs a file"));
}

#[test]
fn invalid_structured_input_falls_back_to_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.json");
    fs::write(&path, format!("{{ not json {S}")).unwrap();
    let out = redact(&[path.to_str().unwrap()], "");
    assert!(out.status.success());
    assert!(stderr(&out).contains("treating input as plain text"));
    assert_eq!(stdout(&out), "{ not json REDACTION-1");
}

#[test]
fn list_formats() {
    let out = stripsecret(&["formats"], "");
    let listing = raw_stdout(&out);
    for name in [
        "json", "jsonl", "yaml", "toml", "xml", "hcl", "ini", "dotenv", "csv",
    ] {
        assert!(
            listing.lines().any(|l| l.starts_with(name)),
            "{name} missing"
        );
    }
}

#[test]
fn subcommand_is_required() {
    let out = stripsecret(&[], "");
    assert!(!out.status.success());
    let out = stripsecret(&["--allow-by-key", "x"], "");
    assert!(!out.status.success());
}
