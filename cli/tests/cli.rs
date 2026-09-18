use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const S: &str = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA";

/// The configuration built into the binary, as the crate ships it.
const BUILTIN: &str = include_str!("../../default_config.yml");

/// The command-line manual built into the binary.
const CLI_README: &str = include_str!("../README.md");

/// Environment variable the binary reads for a configuration file.
const CONFIG_ENV: &str = "VELOCIREDACTOR_CONFIG";

fn velociredactor(args: &[&str], stdin: &str) -> Output {
    velociredactor_with(args, stdin, None)
}

fn velociredactor_with(args: &[&str], stdin: &str, config_env: Option<&str>) -> Output {
    velociredactor_cmd(args, stdin, config_env, None, None)
}

fn velociredactor_in(dir: &Path, home: &Path, args: &[&str], stdin: &str) -> Output {
    velociredactor_cmd(args, stdin, None, Some(dir), Some(home))
}

fn velociredactor_cmd(
    args: &[&str],
    stdin: &str,
    config_env: Option<&str>,
    current_dir: Option<&Path>,
    home: Option<&Path>,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_velociredactor"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove(CONFIG_ENV);
    if let Some(path) = config_env {
        cmd.env(CONFIG_ENV, path);
    }
    if let Some(dir) = current_dir {
        cmd.current_dir(dir);
    }
    if let Some(home) = home {
        cmd.env("HOME", home);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn redact(args: &[&str], stdin: &str) -> Output {
    velociredactor(&[&["redact"], args].concat(), stdin)
}

fn list(args: &[&str], stdin: &str) -> Output {
    velociredactor(&[&["list"], args].concat(), stdin)
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
/// section — which is how a user writes one: start from
/// `velociredactor config show` and edit.
fn write_config(dir: &Path, edits: &[(impl AsRef<str>, impl AsRef<str>)], rules: &str) -> String {
    write_named_config(dir, "velociredactor.yml", edits, rules)
}

fn write_named_config(
    dir: &Path,
    name: &str,
    edits: &[(impl AsRef<str>, impl AsRef<str>)],
    rules: &str,
) -> String {
    let head = BUILTIN
        .split_once("\nallow:\n")
        .expect("the built-in configuration ends with the rule sections")
        .0;
    let mut source = head.to_owned();
    for (from, to) in edits {
        let (from, to) = (from.as_ref(), to.as_ref());
        assert!(source.contains(from), "{from:?} is no longer in the file");
        source = source.replacen(from, to, 1);
    }
    source.push('\n');
    source.push_str(rules);

    let path = dir.join(name);
    fs::write(&path, source).unwrap();
    path.to_str().unwrap().to_owned()
}

/// A configuration whose only change is the rule sections.
fn rules_config(dir: &Path, rules: &str) -> String {
    write_config(dir, NO_EDITS, rules)
}

const NO_EDITS: &[(&str, &str)] = &[];

/// The built-in configuration with one more entry in its `detectors` list.
fn detector_config(dir: &Path, entry: &str) -> String {
    write_config(dir, &[extra_detector(entry)], "")
}

/// The built-in configuration with the personal-data detectors added.
fn pii_config(dir: &Path) -> String {
    write_config(
        dir,
        &[extra_detector(
            "  - pii:email:\n      allowlist: [\"noreply@\"]\n  - pii:phone\n  - pii:address",
        )],
        "",
    )
}

/// An extra detector entry, appended after the last one the file lists.
fn extra_detector(entry: &str) -> (String, String) {
    (
        "  - credential_key".to_owned(),
        format!("  - credential_key\n\n{entry}"),
    )
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
        NO_EDITS,
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

    let allowed = write_config(
        dir.path(),
        NO_EDITS,
        &format!("allow:\n  values: [\"{S}\"]\n"),
    );
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

    let allowed = write_config(
        dir.path(),
        NO_EDITS,
        &format!("allow:\n  values: [\"{S}\"]\n"),
    );
    let out = list(&["--json", "--show-value", "--config", &allowed], &input);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["value"], S);
    assert_eq!(doc["redactions"][0]["allowed"], true);
}

#[test]
fn explicit_format_and_pii() {
    let dir = tempfile::tempdir().unwrap();
    let config = pii_config(dir.path());
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
        &[("sensitive_threshold: 3.5", "sensitive_threshold: 3.0")],
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
fn custom_regex_rules() {
    let dir = tempfile::tempdir().unwrap();
    let config = detector_config(dir.path(), "  - regex:\n      patterns: ['ACME_[0-9]{4}']");
    let out = redact(&["--config", &config], "id ACME_1234\n");
    assert_eq!(stdout(&out), "id REDACTION-1\n");

    let listed = list(&["--json", "--config", &config], "id ACME_1234\n");
    let doc: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["detector"], "regex");

    // A second entry keeps its own label, which is how unrelated groups of
    // patterns stay apart in a listing.
    let labelled = write_config(
        dir.path(),
        &[extra_detector(
            "  - regex:\n      label: team\n      patterns: ['TEAM-[0-9]{3}']",
        )],
        "",
    );
    let out = redact(&["--config", &labelled], "ref TEAM-123\n");
    assert_eq!(stdout(&out), "ref REDACTION-1\n");

    let listed = list(&["--json", "--config", &labelled], "ref TEAM-123\n");
    let doc: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(doc["redactions"][0]["detector"], "team");

    let broken = detector_config(dir.path(), "  - regex:\n      patterns: ['unclosed(']");
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
        &[("        - builtin:betterleaks", "        - ./rules.toml")],
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
    let out = velociredactor(&["formats"], "");
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
fn man_prints_the_cli_readme() {
    let out = velociredactor(&["man"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let manual = stdout(&out);
    let expected: String = CLI_README
        .split_inclusive('\n')
        .filter(|line| !line.contains("<img"))
        .collect();
    assert_eq!(manual, expected);
    assert!(!manual.contains("<img"));
    assert!(out.stderr.is_empty());

    let help = velociredactor(&["--help"], "");
    assert!(help.status.success(), "{}", stderr(&help));
    assert!(stdout(&help).contains("man"), "{}", stdout(&help));
}

#[test]
fn subcommand_is_required() {
    let out = velociredactor(&[], "");
    assert!(!out.status.success());
    let out = velociredactor(&["--allow-by-key", "x"], "");
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

    let any_ssn = detector_config(dir.path(), "  - path:\n      paths: [\"**.ssn\"]");
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

    let value = detector_config(dir.path(), "  - value:\n      values: [Bluebird]");
    let out = redact(&["--config", &value], "codename Bluebird\n");
    assert_eq!(stdout(&out), "codename REDACTION-1\n");

    let both = write_config(
        dir.path(),
        &[extra_detector(
            "  - regex:\n      patterns: ['ACME-[0-9]{4}']",
        )],
        "allow:\n  regexes: ['ACME-1234']\n",
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
        "  - value:\n      values: [alpha, gamma]\n  - regex:\n      patterns: ['A-[0-9]+', 'C-[0-9]+']",
    );
    let out = redact(&["--config", &config], "alpha beta gamma A-11 B-22 C-33\n");
    assert_eq!(
        stdout(&out),
        "REDACTION-1 beta REDACTION-2 REDACTION-3 B-22 REDACTION-4\n"
    );

    let doc = r#"{"a":"1","b":"2","c":"3"}"#;
    let paths = detector_config(dir.path(), "  - path:\n      paths: [a, c]");
    let out = redact(&["-f", "json", "--config", &paths], doc);
    assert_eq!(
        stdout(&out),
        r#"{"a":"REDACTION-1","b":"2","c":"REDACTION-2"}"#
    );

    let spared = write_config(
        dir.path(),
        &[extra_detector("  - path:\n      paths: [\"**\"]")],
        "allow:\n  paths: [a, c]\n",
    );
    let out = redact(&["-f", "json", "--config", &spared], doc);
    assert_eq!(stdout(&out), r#"{"a":"1","b":"REDACTION-1","c":"3"}"#);
}

/// There is no switch for turning a detector off: the `detectors` list is
/// exactly what runs.
#[test]
fn a_detector_that_is_not_listed_does_not_run() {
    let dir = tempfile::tempdir().unwrap();
    let input = format!("{S} jane@corp.example\n");

    // The shipped file lists no personal-data detector, so the address stays.
    let out = redact(&[], &input);
    assert_eq!(stdout(&out), "REDACTION-1 jane@corp.example\n");

    // Uncommenting the `pii:` block is all it takes to switch it on.
    let with_pii = pii_config(dir.path());
    let out = redact(&["--config", &with_pii], &input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "REDACTION-1 REDACTION-2\n");

    // A detector name the crate does not know is an error, not a no-op.
    let unknown = write_config(
        dir.path(),
        &[("  - credentialed_uri", "  - credentialed_url")],
        "",
    );
    let out = redact(&["--config", &unknown], &input);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("credentialed_url"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn config_replaces_the_builtin_rules() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        dir.path(),
        &[
            ("comments: false".to_owned(), "comments: true".to_owned()),
            extra_detector(
                "  - path:\n      paths: [\"**.customer\"]\n  - regex:\n      patterns: ['ACME-[0-9]{4}']",
            ),
        ],
        "allow:\n  paths: [\"build.**\"]\n",
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
    assert!(stderr(&out).contains("formats"), "{}", stderr(&out));

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
        dir.path().join("rules/team.toml"),
        "[[rules]]\nid = \"t\"\nregex = '''TEAM-[0-9]{3}'''\n",
    )
    .unwrap();
    let config = write_config(
        dir.path(),
        &[("        - builtin:betterleaks", "        - rules/team.toml")],
        "",
    );

    // Run from a directory where `rules` does not exist.
    let out = Command::new(env!("CARGO_BIN_EXE_velociredactor"))
        .args(["redact", "--config", &config])
        .current_dir(std::env::temp_dir())
        .env_remove(CONFIG_ENV)
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
    let out = velociredactor(&["config", "show"], "");
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
fn config_show_prints_a_given_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.yml");
    fs::write(&path, "comments: true\n").unwrap();

    let out = velociredactor(&["config", "show", "--config", path.to_str().unwrap()], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "comments: true\n");

    let out = velociredactor_with(&["config", "show"], "", Some(path.to_str().unwrap()));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "comments: true\n");

    let out = velociredactor(&["config", "show", path.to_str().unwrap()], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("unexpected argument"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn config_location_names_the_file_or_the_builtin() {
    let out = velociredactor(&["config", "location"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "[builtin-default]\n");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.yml");
    let out = velociredactor(
        &["config", "location", "--config", path.to_str().unwrap()],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{}\n", path.display()));

    let out = velociredactor_with(&["config", "location"], "", Some(path.to_str().unwrap()));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{}\n", path.display()));
}

#[test]
fn config_flag_overrides_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let from_env = dir.path().join("from-env.yml");
    let from_flag = dir.path().join("from-flag.yml");
    fs::write(&from_env, "from-env\n").unwrap();
    fs::write(&from_flag, "from-flag\n").unwrap();

    let out = velociredactor_with(
        &["config", "show", "--config", from_flag.to_str().unwrap()],
        "",
        Some(from_env.to_str().unwrap()),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "from-flag\n");

    let out = velociredactor_with(
        &[
            "config",
            "location",
            "--config",
            from_flag.to_str().unwrap(),
        ],
        "",
        Some(from_env.to_str().unwrap()),
    );
    assert_eq!(stdout(&out), format!("{}\n", from_flag.display()));
}

#[test]
fn redact_reads_the_config_environment() {
    let env_dir = tempfile::tempdir().unwrap();
    let flag_dir = tempfile::tempdir().unwrap();
    let env_config = rules_config(env_dir.path(), "allow:\n  values: [hunter2]\n");
    let input = "DB_PASSWORD=hunter2\n";

    let out = velociredactor_with(&["redact"], input, Some(&env_config));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), input);

    let flag = rules_config(flag_dir.path(), "allow:\n  values: []\n");
    let out = velociredactor_with(&["redact", "--config", &flag], input, Some(&env_config));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "DB_PASSWORD=REDACTION-1\n");
}

#[test]
fn discovers_velociredactor_yml_from_the_current_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = rules_config(dir.path(), "allow:\n  values: [hunter2]\n");
    let input = "DB_PASSWORD=hunter2\n";

    let out = velociredactor_in(dir.path(), dir.path(), &["config", "location"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let located = stdout(&out);
    assert_eq!(
        fs::canonicalize(located.trim()).unwrap(),
        fs::canonicalize(&path).unwrap()
    );

    let out = velociredactor_in(dir.path(), dir.path(), &["redact"], input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), input);

    let out = velociredactor_in(dir.path(), dir.path(), &["config", "show"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), fs::read_to_string(&path).unwrap());
}

#[test]
fn discovers_uppercase_name_by_walking_to_a_parent() {
    let dir = tempfile::tempdir().unwrap();
    let child = dir.path().join("src");
    fs::create_dir(&child).unwrap();
    write_named_config(
        dir.path(),
        "VELOCIREDACTOR.yml",
        NO_EDITS,
        "allow:\n  values: [hunter2]\n",
    );

    let out = velociredactor_in(&child, dir.path(), &["config", "location"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let located = stdout(&out);
    assert_ne!(located, "[builtin-default]\n");
    assert!(
        located.contains("velociredactor.yml") || located.contains("VELOCIREDACTOR.yml"),
        "{located}"
    );

    let out = velociredactor_in(&child, dir.path(), &["redact"], "DB_PASSWORD=hunter2\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "DB_PASSWORD=hunter2\n");
}

#[test]
fn command_line_and_environment_override_discovery() {
    let dir = tempfile::tempdir().unwrap();
    rules_config(dir.path(), "allow:\n  values: [hunter2]\n");
    let flag_dir = tempfile::tempdir().unwrap();
    let env_dir = tempfile::tempdir().unwrap();
    let from_flag = flag_dir.path().join("from-flag.yml");
    let from_env = env_dir.path().join("from-env.yml");
    fs::write(&from_flag, "from-flag\n").unwrap();
    fs::write(&from_env, "from-env\n").unwrap();

    // `--config` wins over a file sitting in the current directory.
    let out = velociredactor_cmd(
        &["config", "show", "--config", from_flag.to_str().unwrap()],
        "",
        None,
        Some(dir.path()),
        Some(dir.path()),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "from-flag\n");

    // `$VELOCIREDACTOR_CONFIG` wins over discovery, and loses to `--config`.
    let out = velociredactor_cmd(
        &["config", "show"],
        "",
        Some(from_env.to_str().unwrap()),
        Some(dir.path()),
        Some(dir.path()),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "from-env\n");

    let out = velociredactor_cmd(
        &[
            "config",
            "location",
            "--config",
            from_flag.to_str().unwrap(),
        ],
        "",
        Some(from_env.to_str().unwrap()),
        Some(dir.path()),
        Some(dir.path()),
    );
    assert_eq!(stdout(&out), format!("{}\n", from_flag.display()));
}

#[test]
fn discovery_falls_back_to_the_builtin() {
    let dir = tempfile::tempdir().unwrap();
    let out = velociredactor_in(dir.path(), dir.path(), &["config", "location"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "[builtin-default]\n");
}

#[test]
fn config_validate_accepts_a_usable_file_and_rejects_a_broken_one() {
    let out = velociredactor(&["config", "validate"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());

    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("ok.yml");
    fs::write(&ok, BUILTIN).unwrap();
    let out = velociredactor(
        &["config", "validate", "--config", ok.to_str().unwrap()],
        "",
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let out = velociredactor_with(&["config", "validate"], "", Some(ok.to_str().unwrap()));
    assert!(out.status.success(), "{}", stderr(&out));

    let broken = dir.path().join("broken.yml");
    fs::write(&broken, "allow:\n  values: [hunter2]\n").unwrap();
    let out = velociredactor(
        &["config", "validate", "--config", broken.to_str().unwrap()],
        "",
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("formats"), "{}", stderr(&out));

    let unknown = dir.path().join("unknown.yml");
    fs::write(&unknown, "nonsense: 1\n").unwrap();
    let out = velociredactor_with(&["config", "validate"], "", Some(unknown.to_str().unwrap()));
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown field"), "{}", stderr(&out));

    let invalid = write_config(
        dir.path(),
        &[extra_detector("  - regex:\n      patterns: ['unclosed(']")],
        "allow:\n  regexes: ['also(']\n",
    );
    let out = velociredactor(&["config", "validate", "--config", &invalid], "");
    assert_eq!(out.status.code(), Some(2));
    let err = stderr(&out);
    assert!(err.contains("does not compile"), "{err}");
    assert!(err.contains("allow-regex"), "{err}");
}

#[test]
fn config_requires_a_subcommand() {
    let out = velociredactor(&["config"], "");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("show"), "{}", stderr(&out));
}

#[test]
fn skipped_keys_are_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let input = r#"{"session_id":"abc123"}"#;

    // By default a key ending in `id` is never scanned, so no rule can reach
    // it: this is what makes a `path` detector look like it does nothing.
    let unreachable = detector_config(dir.path(), "  - path:\n      paths: [session_id]");
    let out = redact(&["-f", "json", "--config", &unreachable], input);
    assert_eq!(stdout(&out), input);

    // Dropping the suffix from the configuration makes the rule bite.
    let reachable = write_config(
        dir.path(),
        &[
            (
                r#"skip_key_suffixes: ["signature", "id", "ids"]"#.to_owned(),
                r#"skip_key_suffixes: ["signature"]"#.to_owned(),
            ),
            extra_detector("  - path:\n      paths: [session_id]"),
        ],
        "",
    );
    let out = redact(&["-f", "json", "--config", &reachable], input);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), r#"{"session_id":"REDACTION-1"}"#);
}

/// A scratch git repository holding a `.env` and a source file.
fn agent_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".env"), "DB_PASSWORD=hunter2\n").unwrap();
    fs::write(dir.path().join(".env.example"), "DB_PASSWORD=changeme\n").unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    dir
}

fn agent_init(dir: &Path, args: &[&str]) -> Output {
    velociredactor_in(dir, dir, &[&["agent", "init"], args].concat(), "")
}

/// Claude Code's PreToolUse input for reading `file` from `cwd`.
fn hook_input(cwd: &Path, tool: &str, key: &str, file: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "cwd": cwd,
        "tool_input": { key: file },
    })
    .to_string()
}

#[test]
fn agent_status_reports_an_unconfigured_project() {
    let dir = agent_repo();
    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "status", "--json"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let status: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(status["configured"], false);
    assert_eq!(status["config"], serde_json::Value::Null);

    // A configuration without an agent section is not a choice either.
    rules_config(dir.path(), "");
    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "status"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("not configured"), "{}", stdout(&out));
}

#[test]
fn agent_init_writes_a_complete_configuration() {
    let dir = agent_repo();
    let out = agent_init(
        dir.path(),
        &[
            "--protect",
            ".env*",
            "--protect",
            "*.pem",
            "--exclude",
            ".env.example",
            "--enforce",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let written = fs::read_to_string(dir.path().join("velociredactor.yml")).unwrap();
    assert!(
        written.starts_with(BUILTIN),
        "the built-in rules are kept, comments and all"
    );

    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "status", "--json"], "");
    let status: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(status["configured"], true);
    assert_eq!(status["protected"], serde_json::json!([".env*", "*.pem"]));
    assert_eq!(status["exclude"], serde_json::json!([".env.example"]));
    assert_eq!(status["enforce"], true);

    // Redaction is unchanged by the new section.
    let out = velociredactor_in(dir.path(), dir.path(), &["redact", ".env"], "");
    assert_eq!(stdout(&out), "DB_PASSWORD=REDACTION-1\n");

    let out = velociredactor_in(dir.path(), dir.path(), &["config", "validate"], "");
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn agent_init_from_a_subdirectory_writes_at_the_repository_root() {
    let dir = agent_repo();
    let out = agent_init(&dir.path().join("src"), &["--protect", ".env"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(dir.path().join("velociredactor.yml").is_file());
    assert!(!dir.path().join("src/velociredactor.yml").exists());
}

#[test]
fn agent_init_appends_to_an_existing_configuration() {
    let dir = agent_repo();
    rules_config(dir.path(), "allow:\n  values: [hunter2]\n");
    let out = agent_init(dir.path(), &["--protect", ".env"]);
    assert!(out.status.success(), "{}", stderr(&out));

    let written = fs::read_to_string(dir.path().join("velociredactor.yml")).unwrap();
    assert!(
        written.contains("values: [hunter2]"),
        "existing rules are kept"
    );
    let out = velociredactor_in(dir.path(), dir.path(), &["redact", ".env"], "");
    assert_eq!(stdout(&out), "DB_PASSWORD=hunter2\n");
}

#[test]
fn agent_init_refuses_to_replace_an_agent_section() {
    let dir = agent_repo();
    assert!(
        agent_init(dir.path(), &["--protect", ".env"])
            .status
            .success()
    );
    let before = fs::read_to_string(dir.path().join("velociredactor.yml")).unwrap();

    let out = agent_init(dir.path(), &["--protect", "*.pem"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("already has an agent section"),
        "{}",
        stderr(&out)
    );
    let after = fs::read_to_string(dir.path().join("velociredactor.yml")).unwrap();
    assert_eq!(before, after);

    let out = agent_init(dir.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "--protect is required");
}

#[test]
fn agent_check_exits_1_for_protected_files() {
    let dir = agent_repo();
    assert!(
        agent_init(
            dir.path(),
            &["--protect", ".env*", "--exclude", ".env.example"]
        )
        .status
        .success()
    );

    let out = velociredactor_in(
        dir.path(),
        dir.path(),
        &["agent", "check", ".env", ".env.example", "src/main.rs"],
        "",
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), ".env\n");

    let out = velociredactor_in(
        dir.path(),
        dir.path(),
        &["agent", "check", "src/main.rs"],
        "",
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "");

    // Each file is judged by its own project's configuration, wherever the
    // command runs from.
    let elsewhere = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    let out = velociredactor_in(
        elsewhere.path(),
        elsewhere.path(),
        &["agent", "check", env.to_str().unwrap()],
        "",
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn agent_check_protects_nothing_without_an_agent_section() {
    let dir = agent_repo();
    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "check", ".env"], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn agent_hook_denies_protected_reads_only_when_enforced() {
    let dir = agent_repo();
    assert!(
        agent_init(dir.path(), &["--protect", ".env", "--enforce"])
            .status
            .success()
    );
    let other = tempfile::tempdir().unwrap();

    for (tool, key, instead) in [
        ("Read", "file_path", "velociredactor redact"),
        ("Grep", "path", "velociredactor grep"),
    ] {
        let out = velociredactor_in(
            other.path(),
            other.path(),
            &["agent", "hook"],
            &hook_input(dir.path(), tool, key, ".env"),
        );
        assert!(out.status.success(), "{}", stderr(&out));
        let reason = hook_denial(&out).expect("the read is denied");
        assert!(reason.contains(instead), "{reason}");
    }

    let out = velociredactor_in(
        dir.path(),
        dir.path(),
        &["agent", "hook"],
        &hook_input(dir.path(), "Read", "file_path", "src/main.rs"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "", "unprotected files are allowed silently");

    // Without `enforce` the hook allows everything.
    let unenforced = agent_repo();
    assert!(
        agent_init(unenforced.path(), &["--protect", ".env"])
            .status
            .success()
    );
    let out = velociredactor_in(
        unenforced.path(),
        unenforced.path(),
        &["agent", "hook"],
        &hook_input(unenforced.path(), "Read", "file_path", ".env"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
}

/// The reason a hook's output denies the tool call, if it does.
fn hook_denial(out: &Output) -> Option<String> {
    if stdout(out).is_empty() {
        return None;
    }
    let decision: serde_json::Value = serde_json::from_str(&stdout(out)).unwrap();
    let output = &decision["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse");
    assert_eq!(output["permissionDecision"], "deny");
    Some(
        output["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

/// A search of a directory reaches every file under it, so it is denied
/// when any of them is protected.
#[test]
fn agent_hook_denies_searching_a_directory_holding_protected_files() {
    let dir = agent_repo();
    assert!(
        agent_init(dir.path(), &["--protect", ".env", "--enforce"])
            .status
            .success()
    );
    let grep = |input: serde_json::Value| {
        let input = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "cwd": dir.path(),
            "tool_input": input,
        });
        velociredactor_in(
            dir.path(),
            dir.path(),
            &["agent", "hook"],
            &input.to_string(),
        )
    };

    let out = grep(serde_json::json!({ "pattern": "DB_", "path": "." }));
    assert!(out.status.success(), "{}", stderr(&out));
    let reason = hook_denial(&out).expect("the search is denied");
    assert!(reason.contains("velociredactor grep DB_ "), "{reason}");
    assert!(
        reason.contains(".env"),
        "names the protected file: {reason}"
    );

    // Without a path, Grep searches the current directory.
    let out = grep(serde_json::json!({ "pattern": "DB_" }));
    assert!(hook_denial(&out).is_some(), "{}", stderr(&out));

    let out = grep(serde_json::json!({ "pattern": "main", "path": "src" }));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(hook_denial(&out), None, "src holds nothing protected");

    // A search skips what .gitignore excludes, as ripgrep does, so it
    // cannot reach an ignored protected file.
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    let out = grep(serde_json::json!({ "pattern": "DB_", "path": "." }));
    assert_eq!(hook_denial(&out), None);
}

/// Claude Code blocks the tool call on exit status 2, so a broken input or
/// configuration must fail with any other status.
#[test]
fn agent_hook_failures_do_not_block() {
    let dir = agent_repo();
    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "hook"], "not json");
    assert_eq!(out.status.code(), Some(1));

    fs::write(dir.path().join("velociredactor.yml"), "nonsense: 1\n").unwrap();
    let out = velociredactor_in(
        dir.path(),
        dir.path(),
        &["agent", "hook"],
        &hook_input(dir.path(), "Read", "file_path", ".env"),
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

/// A git repository holding a secret in a structured file and in a hidden
/// one, a plain file, and an ignored file.
fn grep_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join(".git")).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(
        root.join("sub/config.yml"),
        format!("db:\n  host: prod.internal\n  api_key: \"{S}\"\n  user: admin\n"),
    )
    .unwrap();
    fs::write(root.join(".env"), format!("ANTHROPIC_KEY={S}\nOTHER=1\n")).unwrap();
    fs::write(root.join("readme.txt"), "nothing here\n").unwrap();
    fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
    fs::write(root.join("ignored.txt"), "api_key in an ignored file\n").unwrap();
    dir
}

fn grep_in(dir: &Path, args: &[&str]) -> Output {
    velociredactor_in(dir, dir, &[&["grep"], args].concat(), "")
}

#[test]
fn grep_prints_matches_from_redacted_text() {
    let dir = grep_repo();
    let out = grep_in(dir.path(), &["-C1", "api_key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "sub/config.yml-2-  host: prod.internal\n\
         sub/config.yml:3:  api_key: \"REDACTION-1\"\n\
         sub/config.yml-4-  user: admin\n"
    );
}

#[test]
fn grep_for_a_secret_finds_nothing() {
    let dir = grep_repo();
    for args in [
        &["--hidden", S][..],
        &["--hidden", "-F", "-e", "sk-ant-api03"],
        &["-o", "--hidden", "sk-ant-[a-z0-9-]+"],
    ] {
        let out = grep_in(dir.path(), args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), "", "{args:?}");
    }
}

#[test]
fn grep_output_never_holds_a_secret() {
    let dir = grep_repo();
    for args in [
        &["--hidden", "-e", "."][..],
        &["--hidden", "-o", "-e", "=.*"],
        &["--hidden", "--json", "KEY|key"],
        &["--hidden", "-v", "zzz"],
    ] {
        let out = grep_in(dir.path(), args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        let text = stdout(&out);
        assert!(!text.contains(S), "{args:?}: {text}");
        assert!(text.contains("REDACTION-1"), "{args:?}: {text}");
    }
}

#[test]
fn grep_summary_modes() {
    let dir = grep_repo();
    let out = grep_in(dir.path(), &["-l", "--hidden", "-e", "="]);
    assert_eq!(stdout(&out), ".env\n");

    // The file matched on disk, but not once redacted.
    let out = grep_in(dir.path(), &["--files-without-match", "sk-ant"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "readme.txt\nsub/config.yml\n");

    let out = grep_in(dir.path(), &["-c", "host|user", "sub/config.yml"]);
    assert_eq!(stdout(&out), "2\n");

    let out = grep_in(dir.path(), &["-q", "host"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "");
    let out = grep_in(dir.path(), &["-q", "absent"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn grep_honors_ignore_files_and_hidden_files() {
    let dir = grep_repo();
    let out = grep_in(dir.path(), &["-l", "-e", "."]);
    assert_eq!(stdout(&out), "readme.txt\nsub/config.yml\n");

    let out = grep_in(dir.path(), &["-l", "--no-ignore", "ignored"]);
    assert_eq!(stdout(&out), "ignored.txt\n");

    let out = grep_in(dir.path(), &["-l", "-g", "*.yml", "-e", "."]);
    assert_eq!(stdout(&out), "sub/config.yml\n");
}

#[test]
fn grep_reads_standard_input() {
    let out = velociredactor(&["grep", "token", "-"], &format!("token: {S}\nother\n"));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "1:token: REDACTION-1\n");
}

#[test]
fn grep_needs_a_pattern() {
    let dir = grep_repo();
    let out = grep_in(dir.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("no pattern"), "{}", stderr(&out));
}

#[test]
fn grep_reports_unreadable_paths() {
    let dir = grep_repo();
    let out = grep_in(dir.path(), &["host", "missing.txt", "sub"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "sub/config.yml:2:  host: prod.internal\n");
}

#[test]
fn grep_stops_at_a_broken_configuration() {
    let dir = grep_repo();
    fs::write(dir.path().join("sub/velociredactor.yml"), "nonsense: 1\n").unwrap();
    fs::create_dir(dir.path().join("zzz")).unwrap();
    fs::write(dir.path().join("zzz/later.txt"), "host\n").unwrap();
    // `readme.txt` comes first and uses the built-in configuration.
    let out = grep_in(dir.path(), &["-e", "."]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stdout(&out),
        "readme.txt:1:nothing here\n",
        "nothing after the failure"
    );
    let err = stderr(&out);
    assert!(err.contains("velociredactor.yml"), "{err}");
    assert_eq!(err.matches("error:").count(), 1, "{err}");
}

#[test]
fn grep_loads_a_configuration_only_when_a_file_using_it_matches() {
    let dir = grep_repo();
    fs::write(dir.path().join("sub/velociredactor.yml"), "nonsense: 1\n").unwrap();
    let out = grep_in(dir.path(), &["nothing"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "readme.txt:1:nothing here\n");
    assert_eq!(stderr(&out), "");
}

#[test]
fn grep_redacts_each_file_by_its_own_configuration() {
    let dir = grep_repo();
    fs::write(dir.path().join("secret.txt"), format!("api_key: \"{S}\"\n")).unwrap();
    // The subdirectory leaves the secret in place; the root does not.
    write_config(
        &dir.path().join("sub"),
        NO_EDITS,
        &format!("allow:\n  values: [\"{S}\"]\n"),
    );
    let out = grep_in(dir.path(), &["-g", "!velociredactor.yml", "api_key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!("secret.txt:1:api_key: \"REDACTION-1\"\nsub/config.yml:3:  api_key: \"{S}\"\n")
    );
}

#[test]
fn grep_prints_files_in_path_order() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    let mut want = String::new();
    for i in 0..300 {
        let name = format!("f{i:03}.env");
        fs::write(dir.path().join(&name), format!("KEY={S}\nline {i}\n")).unwrap();
        want.push_str(&format!("{name}:1:KEY=REDACTION-1\n{name}-2-line {i}\n"));
        if i < 299 {
            want.push_str("--\n");
        }
    }
    let out = grep_in(dir.path(), &["-A1", "KEY"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), want);
}

#[test]
fn agent_status_suggests_candidates_by_name() {
    let dir = agent_repo();
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
    fs::write(dir.path().join("node_modules/pkg/test.pem"), "").unwrap();

    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "status"], "");
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("not configured"), "{text}");
    // Ignored files are where secrets live, so they are suggested.
    assert!(text.contains("--protect '.env*'"), "{text}");
    assert!(text.contains("--exclude .env.example"), "{text}");
    assert!(
        !text.contains("*.pem"),
        "dependency directories are skipped: {text}"
    );
    assert!(text.contains("velociredactor agent init"), "{text}");
    assert!(text.contains("velociredactor agent skill setup"), "{text}");

    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "status", "--json"], "");
    let status: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let env = status["suggested"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["pattern"] == ".env*")
        .expect(".env* is suggested");
    assert_eq!(env["flag"], "--protect");
    assert!(env["examples"].as_array().unwrap().contains(&".env".into()));

    // Once configured, there is nothing to suggest.
    assert!(
        agent_init(dir.path(), &["--protect", ".env"])
            .status
            .success()
    );
    let out = velociredactor_in(dir.path(), dir.path(), &["agent", "status", "--json"], "");
    let status: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(status["suggested"], serde_json::json!([]));
}

#[test]
fn agent_init_without_patterns_explains_what_to_do() {
    let dir = agent_repo();
    let out = agent_init(dir.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let text = stderr(&out);
    assert!(text.contains("--protect GLOB"), "{text}");
    assert!(
        text.contains("--protect '.env*'"),
        "lists candidates: {text}"
    );
    assert!(text.contains("ask the user"), "{text}");
    assert!(!dir.path().join("velociredactor.yml").exists());

    let out = velociredactor(&["agent", "init", "--help"], "");
    assert!(out.status.success());
    assert!(
        stdout(&out).contains(".gitignore conventions"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn agent_skill_prints_the_skills() {
    let skill = |args: &[&str]| velociredactor(&[&["agent", "skill"], args].concat(), "");
    let main = include_str!("../skills/velociredactor/SKILL.md");

    // Without a name, the skills are listed with where to start.
    let out = skill(&[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let list = stdout(&out);
    for name in [
        "velociredactor-setup",
        "velociredactor-config",
        "velociredactor-share",
    ] {
        assert!(list.contains(name), "{list}");
    }
    assert!(list.contains("velociredactor agent skill NAME"), "{list}");
    assert!(
        list.contains("velociredactor agent skill velociredactor\n"),
        "{list}"
    );

    assert_eq!(stdout(&skill(&["velociredactor"])), main);

    let setup = include_str!("../skills/velociredactor-setup/SKILL.md");
    assert_eq!(stdout(&skill(&["setup"])), setup);
    assert_eq!(stdout(&skill(&["velociredactor-setup"])), setup);

    // A skill's references come after it.
    let config = stdout(&skill(&["config"]));
    assert!(config.starts_with(include_str!("../skills/velociredactor-config/SKILL.md")));
    assert!(
        config.contains("# velociredactor.yml reference"),
        "{config}"
    );

    let out = skill(&["nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("velociredactor-share"),
        "{}",
        stderr(&out)
    );
}

/// `cli/skills` is a copy of `plugin/skills`, so the published crate can
/// embed them. The plugin is absent from the published crate itself.
#[test]
fn embedded_skills_match_the_plugin() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let plugin = root.join("../plugin/skills");
    if !plugin.exists() {
        return;
    }
    fn files(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files(&path, base, out);
            } else {
                let name = path.strip_prefix(base).unwrap().display().to_string();
                out.push((name, fs::read(&path).unwrap()));
            }
        }
    }
    let (mut want, mut have) = (Vec::new(), Vec::new());
    files(&plugin, &plugin, &mut want);
    files(&root.join("skills"), &root.join("skills"), &mut have);
    want.sort();
    have.sort();
    let names = |v: &[(String, Vec<u8>)]| v.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    assert_eq!(
        names(&have),
        names(&want),
        "cp -R plugin/skills/. cli/skills/"
    );
    for ((name, a), (_, b)) in have.iter().zip(&want) {
        assert!(
            a == b,
            "cli/skills/{name} differs from plugin/skills; copy it over"
        );
    }
}
