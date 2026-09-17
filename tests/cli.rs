#![cfg(feature = "cli")]

use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const S: &str = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA";

fn redactify(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_redactify"))
        .args(args)
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

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn redacts_stdin() {
    let out = redactify(&[], &format!("token {S}\n"));
    assert!(out.status.success());
    assert_eq!(stdout(&out), "token REDACTION-1\n");
}

#[test]
fn detects_format_from_file_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    fs::write(&path, format!("token: {S}\nsession_id: {S}\n")).unwrap();
    let out = redactify(&[path.to_str().unwrap()], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!("token: REDACTION-1\nsession_id: {S}\n")
    );
}

#[test]
fn allow_and_check() {
    let input = format!("a {S}\nb DB_PASSWORD=hunter2\n");

    let out = redactify(&["--check"], &input);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=REDACTION-2\n");

    let out = redactify(&["--check", "--allow", "2"], &input);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=hunter2\n");

    let out = redactify(&["--check", "--allow", "1,2"], &input);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), input);

    let out = redactify(&["-a", "1", "-a", "9"], &input);
    assert!(stderr(&out).contains("--allow 9: no such redaction"));
}

#[test]
fn list_does_not_print_secrets() {
    let out = redactify(&["--list"], &format!("x {S}\n"));
    let err = stderr(&out);
    assert!(err.contains("REDACTION-1"), "{err}");
    assert!(err.contains("entropy"), "{err}");
    assert!(!err.contains(S), "{err}");
}

#[test]
fn explicit_format_and_pii() {
    let out = redactify(
        &["-f", "json", "--pii", "email"],
        r#"{"to":"jane@corp.example","id":"x"}"#,
    );
    assert_eq!(stdout(&out), r#"{"to":"REDACTION-1","id":"x"}"#);

    let out = redactify(&["-f", "nope"], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown format"));
}

#[test]
fn custom_rules_and_packs() {
    let out = redactify(&["--rule", "acme=ACME_[0-9]{4}"], "id ACME_1234\n");
    assert_eq!(stdout(&out), "id REDACTION-1\n");

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("team.yaml"),
        "name: team\nversion: '1'\nrules:\n  - id: t\n    regex: 'TEAM-[0-9]{3}'\n",
    )
    .unwrap();
    let out = redactify(
        &["--rules-pack", dir.path().to_str().unwrap()],
        "ref TEAM-123\n",
    );
    assert_eq!(stdout(&out), "ref REDACTION-1\n");

    let out = redactify(&["--rule", "missing-equals"], "");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn custom_ruleset_replaces_bundled_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.toml");
    fs::write(&path, "[[rules]]\nid = \"zz\"\nregex = '''ZZ[0-9]{4}'''\n").unwrap();
    let out = redactify(
        &["--ruleset", path.to_str().unwrap()],
        "ZZ1234 ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2\n",
    );
    assert_eq!(
        stdout(&out),
        "REDACTION-1 ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2\n"
    );
}

#[test]
fn output_and_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.env");
    let output = dir.path().join("out.env");
    fs::write(&input, format!("KEY={S}\n")).unwrap();

    let out = redactify(
        &[input.to_str().unwrap(), "-o", output.to_str().unwrap()],
        "",
    );
    assert!(out.status.success());
    assert!(stdout(&out).is_empty());
    assert_eq!(fs::read_to_string(&output).unwrap(), "KEY=REDACTION-1\n");

    let out = redactify(&[input.to_str().unwrap(), "--in-place"], "");
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(&input).unwrap(), "KEY=REDACTION-1\n");

    let out = redactify(&["--in-place"], "");
    assert!(!out.status.success());
}

#[test]
fn invalid_structured_input_falls_back_to_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.json");
    fs::write(&path, format!("{{ not json {S}")).unwrap();
    let out = redactify(&[path.to_str().unwrap()], "");
    assert!(out.status.success());
    assert!(stderr(&out).contains("treating input as plain text"));
    assert_eq!(stdout(&out), "{ not json REDACTION-1");
}

#[test]
fn list_formats() {
    let out = redactify(&["--list-formats"], "");
    let listing = stdout(&out);
    for name in [
        "json", "jsonl", "yaml", "toml", "xml", "hcl", "ini", "dotenv", "csv",
    ] {
        assert!(
            listing.lines().any(|l| l.starts_with(name)),
            "{name} missing"
        );
    }
}
