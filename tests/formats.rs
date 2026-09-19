//! Each format redacts only values, keeps everything else byte-for-byte, and
//! produces output its own parser still accepts.

mod common;

use common::*;
use velociredactor::{Allow, FormatHint};

const S: &str = HIGH_ENTROPY_SECRET;

fn check(format: &str, input: &str, want: &str) {
    let got = as_format(format, input);
    assert_eq!(got, want, "{format} output differs");
}

fn unchanged_without_secrets(format: &str, input: &str) {
    assert_eq!(
        as_format(format, input),
        input,
        "{format} changed clean input"
    );
}

#[test]
fn yaml() {
    let input = format!(
        r#"# deployment settings
service: api   # trailing comment
token: {S}
quoted: "prefix {S} suffix"
single: 'it''s {S}'
list:
  - plain
  - {S}
flow: [a, {S}]
db:
  host: db.example.com
  user: svc
  password: hunter2
session_id: {S}
block: |
  first line
  key {S}
  last line
folded: >-
  some folded
  text {S}
---
second: {S}
"#
    );
    let want = r#"# deployment settings
service: api   # trailing comment
token: "[REDACTED-1]"
quoted: "prefix [REDACTED-1] suffix"
single: 'it''s [REDACTED-1]'
list:
  - plain
  - "[REDACTED-1]"
flow: [a, "[REDACTED-1]"]
db:
  host: db.example.com
  user: svc
  password: "[REDACTED-2]"
session_id: sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA
block: |
  first line
  key [REDACTED-1]
  last line
folded: >-
  some folded
  text [REDACTED-1]
---
second: "[REDACTED-1]"
"#;
    let got = as_format("yaml", &input);
    assert_eq!(got, want);

    // Redacted values stay strings when the real output is parsed.
    let raw = redactor()
        .redact(input.as_bytes(), FormatHint::Name("yaml"))
        .unwrap()
        .render(&Allow::none())
        .unwrap();
    let raw = String::from_utf8(raw).unwrap();
    let docs: Vec<serde_yaml_ng::Value> = serde_yaml_ng::Deserializer::from_str(&raw)
        .map(|doc| serde::Deserialize::deserialize(doc).unwrap())
        .collect();
    let token = docs[0]["token"].as_str().unwrap();
    let replacement = redactor().replacement();
    assert!(
        velociredactor::is_redaction_token(replacement, token),
        "{token}"
    );
    assert!(velociredactor::is_redaction_token(
        replacement,
        docs[0]["flow"][1].as_str().unwrap()
    ));
    assert!(velociredactor::is_redaction_token(
        replacement,
        docs[1]["second"].as_str().unwrap()
    ));
    unchanged_without_secrets("yaml", "a: 1\nb: [x, y]\nc: {d: e}\n");
}

#[test]
fn yaml_escaped_scalar_is_requoted() {
    let input = format!("key: \"\\x41{}\"\n", &S[1..]);
    let got = as_format("yaml", &input);
    assert_eq!(got, "key: \"[REDACTED-1]\"\n");
}

#[test]
fn yaml_multiline_secret_in_block_scalar_is_rewritten_as_block() {
    let key = fake_openssh_private_key();
    let indented = key.replace('\n', "\n  ");
    let input = format!("key: |\n  {indented}\nnext: ok\n");
    let got = as_format("yaml", &input);
    assert_eq!(got, "key: |\n  [REDACTED-1]\nnext: ok\n");
}

#[test]
fn yaml_non_ascii_offsets() {
    let input = format!("naïve: \"café {S}\"\nnext: é\n");
    assert_eq!(
        as_format("yaml", &input),
        "naïve: \"café [REDACTED-1]\"\nnext: é\n"
    );
}

#[test]
fn toml() {
    let input = format!(
        r#"# settings
title = "demo"   # comment
token = "{S}"
literal = '{S}'
multi = """
line {S}
"""
nums = [1, 2]
list = ["ok", "{S}"]
inline = {{ key = "{S}", id = "{S}" }}

[database]
host = "db.example.com"
user = "svc"
password = "hunter2"

[[servers]]
url = "postgres://app:pwd123@db.example.com/app"
"#
    );
    let want = r#"# settings
title = "demo"   # comment
token = "[REDACTED-1]"
literal = '[REDACTED-1]'
multi = """
line [REDACTED-1]
"""
nums = [1, 2]
list = ["ok", "[REDACTED-1]"]
inline = { key = "[REDACTED-1]", id = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA" }

[database]
host = "db.example.com"
user = "svc"
password = "[REDACTED-2]"

[[servers]]
url = "[REDACTED-3]"
"#;
    check("toml", &input, want);
    want.parse::<toml_edit::DocumentMut>().unwrap();
    unchanged_without_secrets("toml", "a = 1\n[b]\nc = \"d\"\n");
}

#[test]
fn toml_escaped_value_is_requoted() {
    let input = format!("key = \"\\u0073{}\"\n", &S[1..]);
    assert_eq!(as_format("toml", &input), "key = \"[REDACTED-1]\"\n");
}

#[test]
fn xml() {
    let input = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- config -->
<configuration>
  <appSettings>
    <add key="ApiKey" value="{S}" />
    <add key="Mode" value='fast' />
  </appSettings>
  <token>{S}</token>
  <note>fish &amp; chips {S}</note>
  <data><![CDATA[secret: {S}]]></data>
  <id>{S}</id>
</configuration>
"#
    );
    let want = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- config -->
<configuration>
  <appSettings>
    <add key="ApiKey" value="[REDACTED-1]" />
    <add key="Mode" value='fast' />
  </appSettings>
  <token>[REDACTED-1]</token>
  <note>fish &amp; chips [REDACTED-1]</note>
  <data><![CDATA[secret: [REDACTED-1]]]></data>
  <id>sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA</id>
</configuration>
"#;
    check("xml", &input, want);
    unchanged_without_secrets("xml", "<a b=\"c\">d &lt; e</a>");
}

#[test]
fn xml_plist_keys() {
    let input = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>host</key>
  <string>db.example.com</string>
  <key>user</key>
  <string>svc</string>
  <key>password</key>
  <string>hunter2</string>
  <key>db_password</key>
  <string>hunter3</string>
</dict>
</plist>
"#;
    // Values are keyed by the preceding <key>, so `db_password` is
    // recognized. Streaming XML gives no view of a dict's other keys up front,
    // so a bare `password` gets no host/user credential context.
    let got = as_format("xml", input);
    assert_eq!(
        got,
        input.replace("<string>hunter3</string>", "<string>[REDACTED-1]</string>")
    );
}

#[test]
fn xml_is_auto_detected_by_declaration() {
    let input = format!("<?xml version=\"1.0\"?><a>{S}</a>");
    let redaction = redactor()
        .redact(input.as_bytes(), FormatHint::Auto)
        .unwrap();
    assert_eq!(redaction.format(), "xml");
}

#[test]
fn hcl() {
    let input = format!(
        r#"# terraform
variable "region" {{
  default = "us-east-1"
}}

resource "aws_db_instance" "db" {{
  username = "svc"
  password = "hunter2"
  api_key  = "{S}"
  tags = {{
    Name  = "db"
    Token = "{S}"
  }}
  list = ["a", "{S}"]
  greeting = "hello ${{var.name}} {S}"
  id = "{S}"
}}

locals {{
  script = <<EOT
token: {S}
EOT
}}
"#
    );
    let got = as_format("hcl", &input);
    let want = input.replace(S, "[REDACTED-1]");
    let want = want.replace("id = \"[REDACTED-1]\"", &format!("id = \"{S}\""));
    assert_eq!(got, want);
    hcl_edit::parser::parse_body(&got).unwrap();
    unchanged_without_secrets("hcl", "a = \"b\"\nblock \"x\" {\n  c = [1, 2]\n}\n");
}

#[test]
fn hcl_credential_context() {
    let input = "db {\n  host = \"h\"\n  user = \"u\"\n  password = \"correct-horse\"\n}\n";
    assert_eq!(
        as_format("hcl", input),
        "db {\n  host = \"h\"\n  user = \"u\"\n  password = \"[REDACTED-1]\"\n}\n"
    );
}

#[test]
fn ini() {
    let input = format!(
        "; comment\nglobal = 1\n\n[client]\nhost = db.example.com\nuser = svc\npassword = \"hunter2\"\n\n[registry]\n//registry.npmjs.org/:_authToken={S}\nsession_id = {S}\nweird line {S}\n"
    );
    let want = "; comment\nglobal = 1\n\n[client]\nhost = db.example.com\nuser = svc\npassword = \"[REDACTED-1]\"\n\n[registry]\n//registry.npmjs.org/:_authToken=[REDACTED-2]\nsession_id = sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA\nweird line [REDACTED-2]\n";
    check("ini", &input, want);
    unchanged_without_secrets("ini", "[a]\nb = c\n");
}

#[test]
fn dotenv() {
    let input = format!(
        "# env\nexport API_KEY={S}\nDB_PASSWORD='hunter2'\nHOME_DIR=${{HOME}}/app\nQUOTED=\"{S}\"\n"
    );
    let want = "# env\nexport API_KEY=[REDACTED-1]\nDB_PASSWORD='[REDACTED-2]'\nHOME_DIR=${HOME}/app\nQUOTED=\"[REDACTED-1]\"\n";
    check("dotenv", &input, want);
}

#[test]
fn dotenv_hex_digest_on_api_key() {
    let hex = "b65cc3551e470d5abe2448d41429daa2";
    check(
        "dotenv",
        &format!("API_KEY={hex}\n"),
        "API_KEY=[REDACTED-1]\n",
    );
    check("dotenv", &format!("NOTE={hex}\n"), &format!("NOTE={hex}\n"));
}

#[test]
fn dotenv_file_names() {
    let formats = redactor().formats();
    for name in [
        ".env",
        ".env.local",
        ".env.production",
        "prod.env",
        ".envrc",
    ] {
        let format = formats.for_path(name.as_ref()).unwrap();
        assert_eq!(format.name(), "dotenv", "{name}");
    }
}

#[test]
fn properties() {
    let input = format!(
        "# app\napp.name = demo\ndb.password = hunter2\napi.key: {S}\nmultiline = first \\\n    {S}\nuser.id={S}\n"
    );
    let want = "# app\napp.name = demo\ndb.password = [REDACTED-1]\napi.key: [REDACTED-2]\nmultiline = first \\\n    [REDACTED-2]\nuser.id=sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA\n";
    check("properties", &input, want);
}

#[test]
fn csv() {
    let input = format!(
        "name,token,user_id\nalice,{S},{S}\nbob,\"plain, text\",x\n\"carol\",\"quoted {S}\",y"
    );
    let want = "name,token,user_id\nalice,[REDACTED-1],sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA\nbob,\"plain, text\",x\ncarol,quoted [REDACTED-1],y";
    check("csv", &input, want);
}

#[test]
fn csv_crlf() {
    let input = format!("a,b\r\n1,{S}\r\n2,x\r\n");
    check("csv", &input, "a,b\r\n1,[REDACTED-1]\r\n2,x\r\n");
}

#[test]
fn tsv() {
    let input = format!("k\tv\ntoken\t{S}\n");
    check("tsv", &input, "k\tv\ntoken\t[REDACTED-1]\n");
}

#[test]
fn binary_plist() {
    let mut dict = plist::Dictionary::new();
    dict.insert("token".into(), plist::Value::String(S.into()));
    dict.insert("session_id".into(), plist::Value::String(S.into()));
    dict.insert("count".into(), plist::Value::Integer(3.into()));
    let mut input = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_binary(&mut input)
        .unwrap();

    let redaction = redactor().redact(&input, FormatHint::Auto).unwrap();
    assert_eq!(redaction.format(), "bplist");
    let out = redaction.render(&Allow::none()).unwrap();
    let value = plist::Value::from_reader(std::io::Cursor::new(out)).unwrap();
    let dict = value.as_dictionary().unwrap();
    let token = redaction.findings()[0].token();
    assert_eq!(dict["token"].as_string(), Some(token));
    assert_eq!(dict["session_id"].as_string(), Some(S));
    assert_eq!(dict["count"].as_signed_integer(), Some(3));

    // Nothing to redact: the original bytes are returned.
    let secret = &redaction.findings()[0].secret;
    assert_eq!(redaction.render(&Allow::values([secret])).unwrap(), input);
}

#[test]
fn format_selection_by_path() {
    let formats = redactor().formats();
    for (path, want) in [
        ("config.json", "json"),
        ("a/b/settings.JSONC", "json"),
        ("events.jsonl", "jsonl"),
        ("docker-compose.yml", "yaml"),
        ("Cargo.lock", "toml"),
        ("pyproject.toml", "toml"),
        ("pom.xml", "xml"),
        ("main.tf", "hcl"),
        ("terraform.tfvars", "hcl"),
        (".npmrc", "ini"),
        ("setup.cfg", "ini"),
        ("app.properties", "properties"),
        ("data.csv", "csv"),
        ("data.tsv", "tsv"),
        ("notes.txt", "text"),
    ] {
        let format = formats
            .for_path(path.as_ref())
            .unwrap_or_else(|| panic!("no format for {path}"));
        assert_eq!(format.name(), want, "{path}");
    }
    assert!(formats.for_path("README".as_ref()).is_none());
}

#[test]
fn traversal_order_is_stable() {
    // Rendering twice with different allow lists must address the same
    // values; if a format visited values in a different order the ids would
    // land on the wrong values.
    let input = format!("a: {S}\nb: other-{S}x\nc: {S}\n");
    let redaction = redactor()
        .redact(input.as_bytes(), FormatHint::Name("yaml"))
        .unwrap();
    assert_eq!(redaction.findings().len(), 2);
    let all = rendered(&redaction, &Allow::none());
    let second = &redaction.findings()[1].secret;
    let keep_two = rendered(&redaction, &Allow::values([second]));
    assert_eq!(
        all,
        "a: \"[REDACTED-1]\"\nb: \"[REDACTED-2]\"\nc: \"[REDACTED-1]\"\n"
    );
    assert_eq!(
        keep_two,
        format!("a: \"[REDACTED-1]\"\nb: other-{S}x\nc: \"[REDACTED-1]\"\n")
    );
}
