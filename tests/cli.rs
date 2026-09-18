#![cfg(feature = "cli")]

mod common;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const S: &str = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA";

/// The configuration built into the binary, as the crate ships it.
const BUILTIN: &str = include_str!("../default_config.yml");

fn stripsecret(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_stripsecret"))
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

fn redact(args: &[&str], stdin: &str) -> Output {
    stripsecret(&[&["redact"], args].concat(), stdin)
}

fn list(args: &[&str], stdin: &str) -> Output {
    stripsecret(&[&["list"], args].concat(), stdin)
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// Write a configuration file and return its path.
///
/// It is the built-in configuration with `edits` applied as first-occurrence
/// replacements, and with `rules` in place of the trailing (empty) `allow`
/// and `disallow` sections — which is how a user writes one: start from
/// `stripsecret config` and edit.
fn write_config(dir: &Path, edits: &[(&str, &str)], rules: &str) -> String {
    let head = BUILTIN
        .split_once("\nallow:\n")
        .expect("the built-in configuration ends with the rule sections")
        .0;
    let mut source = head.to_owned();
    for (from, to) in edits {
        assert!(source.contains(from), "{from:?} is no longer in the file");
        source = source.replacen(from, to, 1);
    }
    source.push('\n');
    source.push_str(rules);

    let path = dir.join("stripsecret.yml");
    fs::write(&path, source).unwrap();
    path.to_str().unwrap().to_owned()
}

/// A configuration whose only change is the rule sections.
fn rules_config(dir: &Path, rules: &str) -> String {
    write_config(dir, &[], rules)
}

#[test]
fn redacts_stdin() {
    let out = redact(&[], &format!("token {S}\n"));
    assert!(out.status.success());
    assert_eq!(stdout(&out), "token REDACTION-1\n");
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
    let dir = tempfile::tempdir().unwrap();
    let input = format!("a {S}\nb DB_PASSWORD=hunter2\n");

    let out = redact(&["--check"], &input);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=REDACTION-2\n");

    let one = rules_config(dir.path(), "allow:\n  values: [hunter2]\n");
    let out = redact(&["--config", &one], &input);
    assert_eq!(stdout(&out), "a REDACTION-1\nb DB_PASSWORD=hunter2\n");

    let both = write_config(
        dir.path(),
        &[],
        &format!("allow:\n  values: [\"{S}\", hunter2]\n"),
    );
    let out = redact(&["--check", "--config", &both], &input);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), input);
}

#[test]
fn list_shows_token_start_and_length_but_not_values() {
    let dir = tempfile::tempdir().unwrap();
    let out = list(&[], &format!("x {S}\n"));
    assert!(out.status.success());
    let table = stdout(&out);
    let lines: Vec<&str> = table.lines().collect();
    assert!(lines[0].starts_with("TOKEN"), "{table}");
    for column in ["DETECTOR", "START", "LEN", "COUNT", "LOCATION"] {
        assert!(lines[0].contains(column), "{table}");
    }
    assert!(!lines[0].contains("VALUE"), "{table}");
    let row: Vec<&str> = lines[1].split_whitespace().collect();
    assert_eq!(row[..6], ["REDACTION-1", "entropy", "2", "45", "1", "1:3"]);
    assert!(!table.contains(S), "{table}");
    assert!(out.stderr.is_empty());

    let out = list(&["--show-value"], &format!("x {S}\n"));
    let table = stdout(&out);
    assert!(table.lines().next().unwrap().contains("VALUE"), "{table}");
    assert!(table.contains(S), "{table}");

    let allowed = write_config(dir.path(), &[], &format!("allow:\n  values: [\"{S}\"]\n"));
    let out = list(&["--config", &allowed], &format!("x {S}\n"));
    assert!(stdout(&out).lines().nth(1).unwrap().ends_with("allowed"));

    let out = list(&[], "nothing here\n");
    assert_eq!(stdout(&out), "no redactions\n");
}

#[test]
fn list_check() {
    let dir = tempfile::tempdir().unwrap();
    let out = list(&["--check"], "DB_PASSWORD=hunter2");
    assert_eq!(out.status.code(), Some(1));

    let config = rules_config(dir.path(), "allow:\n  values: [hunter2]\n");
    let out = list(&["--check", "--config", &config], "DB_PASSWORD=hunter2");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn json_list() {
    let dir = tempfile::tempdir().unwrap();
    let input = format!("{{\"to\":\"x\",\"token\":\"{S}\",\"again\":\"{S}\"}}");
    let out = list(&["--json", "-f", "json"], &input);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["format"], "json");
    let entry = &doc["redactions"][0];
    assert_eq!(entry["id"], 1);
    assert_eq!(entry["token"], "REDACTION-1");
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
    assert!(!stdout(&out).contains(S));

    let allowed = write_config(dir.path(), &[], &format!("allow:\n  values: [\"{S}\"]\n"));
    let out = list(&["--json", "--show-value", "--config", &allowed], &input);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["value"], S);
    assert_eq!(doc["redactions"][0]["allowed"], true);
}

#[test]
fn explicit_format_and_pii() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &[("categories: []", "categories: [email]")], "");
    let out = redact(
        &["-f", "json", "--config", &config],
        r#"{"to":"jane@corp.example","id":"x"}"#,
    );
    assert_eq!(stdout(&out), r#"{"to":"REDACTION-1","id":"x"}"#);

    let out = redact(&["-f", "nope"], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown format"));
}

#[test]
fn entropy_thresholds_are_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let input = r#"{"api_key":"production"}"#;
    let out = redact(&["-f", "json"], input);
    assert_eq!(stdout(&out), input);

    let sensitive = write_config(
        dir.path(),
        &[("sensitive-threshold: 3.5", "sensitive-threshold: 3.0")],
        "",
    );
    let out = redact(&["-f", "json", "--config", &sensitive], input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), r#"{"api_key":"REDACTION-1"}"#);

    let ordinary = write_config(dir.path(), &[("threshold: 4.5", "threshold: 3.0")], "");
    let out = redact(&["--config", &ordinary], "production ");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "REDACTION-1 ");
}

#[test]
fn custom_rules_and_packs() {
    let dir = tempfile::tempdir().unwrap();
    let config = rules_config(dir.path(), "disallow:\n  regexes: ['ACME_[0-9]{4}']\n");
    let out = redact(&["--config", &config], "id ACME_1234\n");
    assert_eq!(stdout(&out), "id REDACTION-1\n");

    let listed = list(&["--json", "--config", &config], "id ACME_1234\n");
    let doc: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["detector"], "regex");

    let packs = tempfile::tempdir().unwrap();
    fs::write(
        packs.path().join("team.yaml"),
        "name: team\nversion: '1'\nrules:\n  - id: t\n    regex: 'TEAM-[0-9]{3}'\n",
    )
    .unwrap();
    let with_pack = write_config(
        dir.path(),
        &[(
            "rules-packs: []",
            &format!("rules-packs: [\"{}\"]", packs.path().to_str().unwrap()),
        )],
        "",
    );
    let out = redact(&["--config", &with_pack], "ref TEAM-123\n");
    assert_eq!(stdout(&out), "ref REDACTION-1\n");

    let listed = list(&["--json", "--config", &with_pack], "ref TEAM-123\n");
    let doc: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["detector"], "team.t");

    let broken = rules_config(dir.path(), "disallow:\n  regexes: ['unclosed(']\n");
    let out = redact(&["--config", &broken], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("does not compile"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn custom_ruleset_replaces_bundled_rules() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.toml");
    fs::write(&rules, "[[rules]]\nid = \"zz\"\nregex = '''ZZ[0-9]{4}'''\n").unwrap();

    // The path is relative to the configuration file that names it.
    let config = write_config(
        dir.path(),
        &[("  # path: rules.toml", "  path: rules.toml")],
        "",
    );
    let input = "ZZ1234 ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2\n";

    let out = redact(&["--config", &config], input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "REDACTION-1 ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2\n"
    );

    let listed = list(&["--json", "--config", &config], input);
    let doc: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["detector"], "ruleset:zz");
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
    assert_eq!(fs::read_to_string(&output).unwrap(), "KEY=REDACTION-1\n");

    let out = redact(&[input.to_str().unwrap(), "--in-place"], "");
    assert!(out.status.success());
    let redacted = fs::read_to_string(&input).unwrap();
    assert_eq!(redacted, "KEY=REDACTION-1\n");

    // Running again on redacted output changes nothing.
    let out = redact(&[input.to_str().unwrap(), "--check"], "");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), redacted);

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

#[test]
fn subcommand_is_required() {
    let out = stripsecret(&[], "");
    assert!(!out.status.success());
    let out = stripsecret(&["--allow-by-key", "x"], "");
    assert!(!out.status.success());
}

#[test]
fn rule_options_are_not_command_line_flags() {
    // Rules live in the configuration; the command line says how to apply
    // them. Each of these used to be a flag.
    for flag in [
        "--allow-value",
        "--allow-regex",
        "--allow-path",
        "--disallow-value",
        "--disallow-regex",
        "--disallow-path",
        "--exclude-detector",
        "--pii",
        "--comments",
        "--entropy-threshold",
        "--rules-pack",
        "--ruleset",
        "--strict",
    ] {
        let out = redact(&[flag, "x"], "");
        assert_eq!(out.status.code(), Some(2), "{flag} is still accepted");
        assert!(
            stderr(&out).contains("unexpected argument"),
            "{flag}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn comments_are_scanned_only_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let input = format!("# token {S}\nkey = \"ok\"\n");
    let out = redact(&["-f", "toml"], &input);
    assert_eq!(stdout(&out), input);

    let config = write_config(dir.path(), &[("comments: false", "comments: true")], "");
    let out = redact(&["-f", "toml", "--config", &config], &input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "# token REDACTION-1\nkey = \"ok\"\n");
}

#[test]
fn path_rules() {
    let dir = tempfile::tempdir().unwrap();
    let input = r#"{"users":[{"ssn":"123-45-6789"}],"db":{"note":"hi"}}"#;

    let any_ssn = rules_config(dir.path(), "disallow:\n  paths: [\"**.ssn\"]\n");
    let out = redact(&["-f", "json", "--config", &any_ssn], input);
    assert_eq!(
        stdout(&out),
        r#"{"users":[{"ssn":"REDACTION-1"}],"db":{"note":"hi"}}"#
    );

    let listed = list(&["--json", "-f", "json", "--config", &any_ssn], input);
    let doc: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["detector"], "path");
    assert_eq!(doc["redactions"][0]["path"], "users.ssn");

    let guarded = format!(r#"{{"keep":{{"k":"{S}"}},"other":"{S}"}}"#);
    let keep = rules_config(dir.path(), "allow:\n  paths: [\"keep.**\"]\n");
    let out = redact(&["-f", "json", "--config", &keep], &guarded);
    assert_eq!(
        stdout(&out),
        format!(r#"{{"keep":{{"k":"{S}"}},"other":"REDACTION-1"}}"#)
    );
}

#[test]
fn value_and_regex_rules() {
    let dir = tempfile::tempdir().unwrap();

    let value = rules_config(dir.path(), "disallow:\n  values: [Bluebird]\n");
    let out = redact(&["--config", &value], "codename Bluebird\n");
    assert_eq!(stdout(&out), "codename REDACTION-1\n");

    let both = rules_config(
        dir.path(),
        "allow:\n  regexes: ['ACME-1234']\ndisallow:\n  regexes: ['ACME-[0-9]{4}']\n",
    );
    let out = redact(&["--config", &both], "ACME-1234 and ACME-9999\n");
    // An allowed secret still takes an id, so the next one is REDACTION-2.
    assert_eq!(stdout(&out), "ACME-1234 and REDACTION-2\n");

    // An allow pattern must match the whole secret.
    let partial = rules_config(dir.path(), "allow:\n  regexes: ['sk-ant']\n");
    let out = redact(&["--config", &partial], &format!("x {S}\n"));
    assert_eq!(stdout(&out), "x REDACTION-1\n");
}

#[test]
fn rule_lists_take_several_entries() {
    let dir = tempfile::tempdir().unwrap();
    let config = rules_config(
        dir.path(),
        "disallow:\n  values: [alpha, gamma]\n  regexes: ['A-[0-9]+', 'C-[0-9]+']\n",
    );
    let out = redact(&["--config", &config], "alpha beta gamma A-11 B-22 C-33\n");
    assert_eq!(
        stdout(&out),
        "REDACTION-1 beta REDACTION-2 REDACTION-3 B-22 REDACTION-4\n"
    );

    let doc = r#"{"a":"1","b":"2","c":"3"}"#;
    let paths = rules_config(dir.path(), "disallow:\n  paths: [a, c]\n");
    let out = redact(&["-f", "json", "--config", &paths], doc);
    assert_eq!(
        stdout(&out),
        r#"{"a":"REDACTION-1","b":"2","c":"REDACTION-2"}"#
    );

    let spared = rules_config(
        dir.path(),
        "allow:\n  paths: [a, c]\ndisallow:\n  paths: [\"**\"]\n",
    );
    let out = redact(&["-f", "json", "--config", &spared], doc);
    assert_eq!(stdout(&out), r#"{"a":"1","b":"REDACTION-1","c":"3"}"#);
}

#[test]
fn exclude_detector_switches_detectors_off() {
    let dir = tempfile::tempdir().unwrap();
    let input = format!("{S} jane@corp.example\n");

    let no_pii = write_config(
        dir.path(),
        &[
            ("categories: []", "categories: [email]"),
            ("exclude: []", "exclude: [\"pii:*\"]"),
        ],
        "",
    );
    let out = redact(&["--config", &no_pii], &input);
    assert_eq!(stdout(&out), "REDACTION-1 jane@corp.example\n");

    let nothing = write_config(
        dir.path(),
        &[
            ("categories: []", "categories: [email]"),
            ("exclude: []", "exclude: [\"*\"]"),
        ],
        "",
    );
    let out = redact(&["--config", &nothing], &input);
    assert_eq!(stdout(&out), input);
}

#[test]
fn config_replaces_the_builtin_rules() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        dir.path(),
        &[("comments: false", "comments: true")],
        "allow:\n  paths: [\"build.**\"]\ndisallow:\n  paths: [\"**.customer\"]\n  regexes: ['ACME-[0-9]{4}']\n",
    );

    let input = format!(
        "{{\n  // ref ACME-1234\n  \"customer\": \"Big Co\",\n  \"build\": {{\"k\": \"{S}\"}}\n}}"
    );
    let out = redact(&["--config", &config], &input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!(
            "{{\n  // ref REDACTION-1\n  \"customer\": \"REDACTION-2\",\n  \"build\": {{\"k\": \"{S}\"}}\n}}"
        )
    );
}

#[test]
fn an_incomplete_config_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.yml");

    // A configuration replaces the built-in one, so leaving out a detection
    // section is an error rather than a silently empty list.
    fs::write(&path, "allow:\n  values: [hunter2]\n").unwrap();
    let out = redact(&["--config", path.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("policy"), "{}", stderr(&out));

    fs::write(&path, "nonsense: 1\n").unwrap();
    let out = redact(&["--config", path.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown field"), "{}", stderr(&out));
}

#[test]
fn config_resolves_rule_paths_relative_to_itself() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::write(
        dir.path().join("rules/team.yaml"),
        "name: team\nversion: '1'\nrules:\n  - id: t\n    regex: 'TEAM-[0-9]{3}'\n",
    )
    .unwrap();
    let config = write_config(
        dir.path(),
        &[("rules-packs: []", "rules-packs: [rules]")],
        "",
    );

    // Run from a directory where `rules` does not exist.
    let out = Command::new(env!("CARGO_BIN_EXE_stripsecret"))
        .args(["redact", "--config", &config])
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"ref TEAM-123\n")
                .unwrap();
            child.wait_with_output().unwrap()
        })
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "ref REDACTION-1\n");
}

#[test]
fn the_config_subcommand_prints_a_usable_starting_point() {
    let out = stripsecret(&["config"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    assert_eq!(
        printed, BUILTIN,
        "the printed configuration is the real one"
    );

    // Saved and passed straight back, it changes nothing.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("copy.yml");
    fs::write(&path, &printed).unwrap();

    let input = format!(r#"{{"api_key":"{S}","session_id":"abc","note":"hi"}}"#);
    let with_copy = redact(&["-f", "json", "--config", path.to_str().unwrap()], &input);
    let with_builtin = redact(&["-f", "json"], &input);
    assert!(with_copy.status.success(), "{}", stderr(&with_copy));
    assert_eq!(stdout(&with_copy), stdout(&with_builtin));
}

#[test]
fn skipped_keys_are_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let input = r#"{"session_id":"abc123"}"#;

    // By default a key ending in `id` is never scanned, so no rule can reach
    // it: this is what makes `disallow.paths` look like it does nothing.
    let unreachable = rules_config(dir.path(), "disallow:\n  paths: [session_id]\n");
    let out = redact(&["-f", "json", "--config", &unreachable], input);
    assert_eq!(stdout(&out), input);

    // Dropping the suffix from the configuration makes the rule bite.
    let reachable = write_config(
        dir.path(),
        &[(
            r#"skip-key-suffixes: ["signature", "id", "ids"]"#,
            r#"skip-key-suffixes: ["signature"]"#,
        )],
        "disallow:\n  paths: [session_id]\n",
    );
    let out = redact(&["-f", "json", "--config", &reachable], input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), r#"{"session_id":"REDACTION-1"}"#);
}
