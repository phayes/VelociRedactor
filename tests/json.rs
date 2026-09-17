mod common;

use common::*;

fn jsonl(input: &str) -> String {
    as_format("jsonl", input)
}

fn json(input: &str) -> String {
    as_format("json", input)
}

const S: &str = HIGH_ENTROPY_SECRET;

#[test]
fn no_secrets_is_unchanged() {
    let input = r#"{"type":"text","content":"hello"}"#;
    assert_eq!(jsonl(input), input);
    assert_eq!(json(input), input);
}

#[test]
fn value_with_secret_is_redacted() {
    assert_eq!(
        jsonl(&format!(r#"{{"type":"text","content":"key={S}"}}"#)),
        r#"{"type":"text","content":"REDACTION-1"}"#
    );
}

#[test]
fn hex_digest_is_redacted_under_sensitive_keys() {
    let hex = "a40d4b59bf3532493688056bdd1a16a7";
    assert_eq!(
        json(&format!(r#"{{"api_key":"{hex}"}}"#)),
        r#"{"api_key":"REDACTION-1"}"#
    );
    assert_eq!(
        json(&format!(r#"{{"apiKey":"{hex}"}}"#)),
        r#"{"apiKey":"REDACTION-1"}"#
    );
    assert_eq!(
        json(&format!(r#"{{"note":"{hex}"}}"#)),
        format!(r#"{{"note":"{hex}"}}"#)
    );
    assert_eq!(
        json(&format!(r#"{{"foreign_key":"{hex}"}}"#)),
        format!(r#"{{"foreign_key":"{hex}"}}"#)
    );
    assert_eq!(
        json(r#"{"api_key":"production"}"#),
        r#"{"api_key":"production"}"#
    );
    // Keys ending in `id` are skipped by the default policy.
    assert_eq!(
        json(&format!(r#"{{"secret_id":"{hex}"}}"#)),
        format!(r#"{{"secret_id":"{hex}"}}"#)
    );
}

#[test]
fn top_level_arrays() {
    assert_eq!(
        json(&format!(r#"["{S}","normal text"]"#)),
        r#"["REDACTION-1","normal text"]"#
    );
    assert_eq!(json(r#"["hello","world"]"#), r#"["hello","world"]"#);
}

#[test]
fn every_line_is_redacted() {
    let input = format!(
        "{{\"content\":\"safe text\",\"id\":\"abc\"}}\n{{\"content\":\"key={S}\",\"id\":\"def\"}}\n{{\"content\":\"also safe\",\"id\":\"ghi\"}}"
    );
    assert_eq!(
        jsonl(&input),
        "{\"content\":\"safe text\",\"id\":\"abc\"}\n{\"content\":\"REDACTION-1\",\"id\":\"def\"}\n{\"content\":\"also safe\",\"id\":\"ghi\"}"
    );
}

#[test]
fn invalid_lines_are_redacted_as_text() {
    assert_eq!(
        jsonl(&format!(r#"{{"type":"text", "invalid {S} json"#)),
        r#"{"type":"text", "invalid REDACTION-1 json"#
    );
}

#[test]
fn malformed_line_with_escaped_newline_still_redacts_provider_token() {
    let secret = format!(
        "{}probe_20260710_7f91c2d8e4a6b3f0",
        supabase_secret_prefix()
    );
    let line = format!(r#"{{"content":"line1\n{secret}"}} <-- truncated"#);
    let got = jsonl(&line);
    assert!(!got.contains(&secret), "{got}");
    assert!(got.contains("REDACTION-1"));
}

#[test]
fn provider_token_in_nested_content() {
    let secret = format!(
        "{}probe_20260710_7f91c2d8e4a6b3f0",
        supabase_secret_prefix()
    );
    let line = format!(
        r#"{{"type":"user","message":{{"role":"user","content":"the service_role key is {secret} now"}}}}"#
    );
    assert_eq!(
        jsonl(&line),
        r#"{"type":"user","message":{"role":"user","content":"the service_role key is REDACTION-1 now"}}"#
    );
}

#[test]
fn skipped_fields_keep_values_that_are_redacted_elsewhere() {
    let input = format!(r#"{{"session_id":"{S}","content":"{S}"}}"#);
    assert_eq!(
        jsonl(&input),
        format!(r#"{{"session_id":"{S}","content":"REDACTION-1"}}"#)
    );
}

#[test]
fn signatures_are_preserved() {
    let input = format!(r#"{{"type":"thinking","thinking":"plan","thinkingSignature":"{S}"}}"#);
    assert_eq!(jsonl(&input), input);
}

#[test]
fn image_objects_are_skipped() {
    let input =
        format!(r#"{{"a":{{"type":"image","data":"{S}"}},"b":{{"type":"text","content":"{S}"}}}}"#);
    assert_eq!(
        json(&input),
        format!(
            r#"{{"a":{{"type":"image","data":"{S}"}},"b":{{"type":"text","content":"REDACTION-1"}}}}"#
        )
    );
}

#[test]
fn skipped_keys_cover_nested_containers() {
    let input = format!(r#"{{"ids":["{S}"],"content":["{S}"]}}"#);
    assert_eq!(
        json(&input),
        format!(r#"{{"ids":["{S}"],"content":["REDACTION-1"]}}"#)
    );
}

#[test]
fn credentialed_uri_in_content() {
    let input =
        r#"{"type":"text","content":"DATABASE_URL=postgres://app:pwd123@db.example.com:5432/app"}"#;
    assert_eq!(
        jsonl(input),
        r#"{"type":"text","content":"DATABASE_URL=REDACTION-1"}"#
    );
}

#[test]
fn private_key_block_inside_escaped_string() {
    let content =
        serde_json::to_string(&format!("key:\n{}\nend", fake_openssh_private_key())).unwrap();
    let input = format!(r#"{{"type":"text","content":{content}}}"#);
    let got = jsonl(&input);
    assert_eq!(got, r#"{"type":"text","content":"key:\nREDACTION-1\nend"}"#);
}

#[test]
fn database_credentials_in_messages() {
    let input = r#"{"type":"assistant","message":"dsn host=db.example.com user=svc password=hunter2 dbname=app and env DB_PASSWORD=secret123","session_id":"ses_37273a1fdffegpYbwUTqEkPsQ0","file_path":"/tmp/TestE2E_ExistingFiles/controller.go"}"#;
    let got = jsonl(input);
    for leaked in ["password=hunter2", "DB_PASSWORD=secret123"] {
        assert!(!got.contains(leaked), "{leaked} leaked: {got}");
    }
    for kept in [
        "ses_37273a1fdffegpYbwUTqEkPsQ0",
        "/tmp/TestE2E_ExistingFiles/controller.go",
    ] {
        assert!(got.contains(kept), "{kept} missing: {got}");
    }
}

#[test]
fn structured_credential_fields() {
    let input = r#"{"type":"assistant","env":{"DB_PASSWORD":"correct-horse-db","REDIS_PASSWORD":"${REDIS_PASSWORD}","note":"correct-horse-db"},"db":{"password":"correct-horse-db","host":"db.example.com","user":"svc"},"session_id":"ses_37273a1fdffegpYbwUTqEkPsQ0"}"#;
    assert_eq!(
        jsonl(input),
        // Values identical to a redacted value are redacted too.
        r#"{"type":"assistant","env":{"DB_PASSWORD":"REDACTION-1","REDIS_PASSWORD":"${REDIS_PASSWORD}","note":"REDACTION-1"},"db":{"password":"REDACTION-1","host":"db.example.com","user":"svc"},"session_id":"ses_37273a1fdffegpYbwUTqEkPsQ0"}"#
    );
}

#[test]
fn normalized_and_dotted_credential_keys() {
    let got = jsonl(
        r#"{"env":{"DB Password":"correct-horse-db"},"session_id":"ses_37273a1fdffegpYbwUTqEkPsQ0"}"#,
    );
    assert_eq!(
        got,
        r#"{"env":{"DB Password":"REDACTION-1"},"session_id":"ses_37273a1fdffegpYbwUTqEkPsQ0"}"#
    );

    let got = jsonl(
        r#"{"config":{"db.password":"correct-horse-db","mysql.root.password":"correct-horse-mysql"}}"#,
    );
    assert_eq!(
        got,
        r#"{"config":{"db.password":"REDACTION-1","mysql.root.password":"REDACTION-2"}}"#
    );
}

#[test]
fn root_password_keys() {
    let got = jsonl(
        r#"{"env":{"MYSQL_ROOT_PASSWORD":"correct-horse-mysql","MONGO_INITDB_ROOT_PASSWORD":"correct-horse-mongo","MSSQL_SA_PASSWORD":"correct-horse-mssql"}}"#,
    );
    assert_eq!(
        got,
        r#"{"env":{"MYSQL_ROOT_PASSWORD":"REDACTION-1","MONGO_INITDB_ROOT_PASSWORD":"REDACTION-2","MSSQL_SA_PASSWORD":"REDACTION-3"}}"#
    );
}

#[test]
fn bare_password_needs_credential_context() {
    assert_eq!(
        json(r#"{"password":"correct-horse","note":"x"}"#),
        r#"{"password":"correct-horse","note":"x"}"#
    );
    assert_eq!(
        json(r#"{"db":{"host":"h","user":"u","password":"correct-horse"}}"#),
        r#"{"db":{"host":"h","user":"u","password":"REDACTION-1"}}"#
    );
    // Credential context is inherited by nested objects.
    assert_eq!(
        json(r#"{"host":"h","user":"u","auth":{"password":"correct-horse"}}"#),
        r#"{"host":"h","user":"u","auth":{"password":"REDACTION-1"}}"#
    );
}

#[test]
fn shared_value_is_redacted_in_every_context() {
    let input = r#"{"db":{"host":"db.example.com","user":"svc","password":"shared-secret"},"misc":{"password":"shared-secret"}}"#;
    assert_eq!(
        jsonl(input),
        r#"{"db":{"host":"db.example.com","user":"svc","password":"REDACTION-1"},"misc":{"password":"REDACTION-1"}}"#
    );
}

#[test]
fn path_fields_are_preserved() {
    let input = r#"{"session_id":"ses_37273a1fdffegpYbwUTqEkPsQ0","file_path":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test/controller.go","cwd":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test","root":"/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/test","directory":"/tmp/TestE2E_ExistingFiles","content":"normal text here"}"#;
    assert_eq!(jsonl(input), input);
}

const PRETTY_EXPORT: &str = r#"{
  "info": {
    "id": "ses_309461a8bffeQfY7CYDOUHX6VP",
    "slug": "misty-river",
    "directory": "/tmp/test-repo"
  },
  "messages": [
    {
      "info": {
        "id": "msg_cb99a444f001Ftd3kTVmr8XQHZ",
        "sessionID": "ses_309461a8bffeQfY7CYDOUHX6VP",
        "role": "user"
      },
      "parts": [
        {
          "id": "prt_cb99a443b001GE99vjBG60vHbF",
          "type": "text",
          "text": "hello world"
        }
      ]
    },
    {
      "info": {
        "id": "msg_cb99a444f001Ftd3kTVmr8XQHZ",
        "sessionID": "ses_309461a8bffeQfY7CYDOUHX6VP",
        "role": "assistant"
      },
      "parts": [
        {
          "id": "prt_cb99a6f2e0012koCcOJBSwRBwR",
          "type": "text",
          "text": "hello back"
        },
        {
          "id": "prt_cb99a6f2f001e98CKuwDKU3oWr",
          "type": "tool",
          "tool": "write",
          "callID": "call_abc123",
          "state": {
            "status": "completed",
            "input": {"filePath": "/tmp/test/hello.md"},
            "output": "wrote file",
            "metadata": {"files": [{"filePath": "/tmp/test/hello.md", "relativePath": "hello.md"}]}
          }
        }
      ]
    }
  ]
}"#;

#[test]
fn pretty_printed_ids_are_preserved() {
    assert!(stripsecret::detect::shannon_entropy(b"msg_cb99a444f001Ftd3kTVmr8XQHZ") > 4.5);
    assert_eq!(json(PRETTY_EXPORT), PRETTY_EXPORT);
}

#[test]
fn auto_detects_pretty_printed_json() {
    let redaction = redactor()
        .redact(PRETTY_EXPORT.as_bytes(), stripsecret::FormatHint::Auto)
        .unwrap();
    assert_eq!(redaction.format(), "json");
    assert!(redaction.findings().is_empty());
}

#[test]
fn pretty_printed_secrets_are_caught() {
    let input = format!(
        "{{\n  \"info\": {{ \"id\": \"ses_test123\" }},\n  \"parts\": [\n    {{ \"id\": \"prt_test789\", \"type\": \"text\", \"text\": \"your api key is {S}\" }}\n  ]\n}}\n"
    );
    let got = json(&input);
    assert_eq!(got, input.replace(S, "REDACTION-1"));
}

#[test]
fn secrets_in_content_next_to_paths() {
    let input = format!(r#"{{"file_path":"/tmp/test.go","content":"api_key={S}"}}"#);
    assert_eq!(
        jsonl(&input),
        r#"{"file_path":"/tmp/test.go","content":"REDACTION-1"}"#
    );
}

// Values whose raw spelling differs from their decoded form.

#[test]
fn raw_line_separator() {
    let got = jsonl(&format!("{{\"text\":\"before \u{2028} {S}\"}}"));
    assert_eq!(got, "{\"text\":\"before \u{2028} REDACTION-1\"}");
}

#[test]
fn escaped_solidus_is_kept() {
    let got = jsonl(&format!(r#"{{"text":"path\/to {S}"}}"#));
    assert_eq!(got, r#"{"text":"path\/to REDACTION-1"}"#);
}

#[test]
fn escaped_ascii_inside_secret_rewrites_the_value() {
    let line = format!(r#"{{"text":"{}u0073{}"}}"#, '\\', &S[1..]);
    let got = jsonl(&line);
    assert!(!got.contains(&S[1..]), "{got}");
    assert_eq!(got, r#"{"text":"REDACTION-1"}"#);
}

#[test]
fn escaped_non_ascii() {
    let line = format!(r#"{{"text":"caf{}u00e9 {S}"}}"#, '\\');
    let got = jsonl(&line);
    assert_eq!(got, format!(r#"{{"text":"caf{}u00e9 REDACTION-1"}}"#, '\\'));
}

#[test]
fn same_value_with_different_spellings() {
    let got = jsonl(&format!(r#"{{"a":"x/y {S}","b":"x\/y {S}"}}"#));
    assert_eq!(got, r#"{"a":"x/y REDACTION-1","b":"x\/y REDACTION-1"}"#);
}

#[test]
fn keyed_credential_with_escaped_value() {
    let line = format!(
        r#"{{"host":"db.example.com","username":"svc","password":"hunter{}u0032"}}"#,
        '\\'
    );
    assert_eq!(
        jsonl(&line),
        r#"{"host":"db.example.com","username":"svc","password":"REDACTION-1"}"#
    );
}

#[test]
fn duplicate_keys_are_all_scanned() {
    assert_eq!(
        jsonl(&format!(r#"{{"text":"{S}","text":"safe"}}"#)),
        r#"{"text":"REDACTION-1","text":"safe"}"#
    );
    assert_eq!(
        jsonl(&format!(r#"{{"outer":[{{"k":"{S}","k":"safe"}}],"n":1}}"#)),
        r#"{"outer":[{"k":"REDACTION-1","k":"safe"}],"n":1}"#
    );
    let pretty = format!("{{\n  \"text\": \"{S}\",\n  \"text\": \"safe\"\n}}");
    assert_eq!(
        json(&pretty),
        "{\n  \"text\": \"REDACTION-1\",\n  \"text\": \"safe\"\n}"
    );
}

#[test]
fn nul_characters_in_keys_and_values() {
    let line = format!(r#"{{"a":"{0}u0000{S}","a{0}u0000":"{S}"}}"#, '\\');
    let got = jsonl(&line);
    assert!(!got.contains(S), "{got}");
}

#[test]
fn formatting_and_numbers_are_preserved() {
    let line = format!(r#"{{ "text" : "{S}" , "n" : 12345678901234567890 }}"#);
    assert_eq!(
        jsonl(&line),
        r#"{ "text" : "REDACTION-1" , "n" : 12345678901234567890 }"#
    );
}

#[test]
fn neighbouring_lines_are_untouched() {
    let content = format!("{{\"k\":\"v\"}}\n{{\"text\":\"a\\/b {S}\"}}\n{{\"k2\":\"v2\"}}\n");
    assert_eq!(
        jsonl(&content),
        "{\"k\":\"v\"}\n{\"text\":\"a\\/b REDACTION-1\"}\n{\"k2\":\"v2\"}\n"
    );
}

#[test]
fn crlf_lines() {
    let content = format!("{{\"a\":\"{S}\"}}\r\n{{\"b\":\"ok\"}}\r\n");
    assert_eq!(
        jsonl(&content),
        "{\"a\":\"REDACTION-1\"}\r\n{\"b\":\"ok\"}\r\n"
    );
}

#[test]
fn jsonc_comments_and_single_quotes() {
    let input =
        format!("{{\n  // a comment\n  'token': '{S}', /* trailing */\n  unquoted: \"ok\",\n}}\n");
    assert_eq!(json(&input), input.replace(S, "REDACTION-1"));
}

#[test]
fn jsonl_is_auto_detected() {
    let content = format!("{{\"a\":\"{S}\"}}\n{{\"b\":\"ok\"}}\n");
    let redaction = redactor()
        .redact(content.as_bytes(), stripsecret::FormatHint::Auto)
        .unwrap();
    assert_eq!(redaction.format(), "jsonl");
}

#[test]
fn invalid_json_falls_back_to_text_when_auto_detected_by_path() {
    let input = format!("not json at all {S}");
    let redaction = redactor()
        .redact(
            input.as_bytes(),
            stripsecret::FormatHint::Path("x.json".as_ref()),
        )
        .unwrap();
    assert_eq!(redaction.format(), "text");
    assert_eq!(redaction.warnings().len(), 1);
    assert_eq!(
        rendered(&redaction, &stripsecret::Allow::none()),
        "not json at all REDACTION-1"
    );
}

#[test]
fn invalid_json_errors_when_format_is_explicit() {
    assert!(
        redactor()
            .redact(b"{not json", stripsecret::FormatHint::Name("json"))
            .is_err()
    );
}
