mod common;

use common::*;
use redactify::detect::shannon_entropy;

#[test]
fn no_secrets_is_unchanged() {
    let input = "hello world, this is normal text";
    assert_eq!(text(input), input);
}

#[test]
fn high_entropy_secret_is_redacted() {
    assert_eq!(
        text(&format!("my key is {HIGH_ENTROPY_SECRET} ok")),
        "my key is REDACTION-1 ok"
    );
}

#[test]
fn low_entropy_known_formats_are_redacted() {
    assert!(shannon_entropy(b"AKIAYRWQG5EJLPZLBYNP") <= 4.5);
    assert_text_cases(&[
        ("key=AKIAYRWQG5EJLPZLBYNP", "key=REDACTION-1"),
        (
            "key=AKIAYRWQG5EJLPZLBYNP AKIAYRWQG5EJLPZLBYNP",
            "key=REDACTION-1 REDACTION-1",
        ),
        (
            "key=AKIAYRWQG5EJLPZLBYNPAKIAYRWQG5EJLPZLBYNP",
            "key=REDACTION-1",
        ),
    ]);
}

#[test]
fn supabase_provider_tokens() {
    let secret = format!(
        "{}probe_20260710_7f91c2d8e4a6b3f0",
        supabase_secret_prefix()
    );
    let real_secret = format!(
        "{}9uM4GhB0STF5R4K3HxQtlg_bzWW6DRj",
        supabase_secret_prefix()
    );
    let sbp = format!(
        "{}test_probe_20260710_test_probe_2026071",
        supabase_personal_prefix()
    );
    let secret_hyphen = format!(
        "{}probe-20260710-7f91c2d8e4a6b3f0",
        supabase_secret_prefix()
    );
    let sbp_hyphen = format!(
        "{}probe-20260710-7f91c2d8e4a6b3f0",
        supabase_personal_prefix()
    );
    for low in [&secret, &sbp] {
        assert!(
            shannon_entropy(low.as_bytes()) <= 4.5,
            "{low} is not low-entropy"
        );
    }

    let cases = [
        (secret.clone(), "REDACTION-1".to_owned()),
        (
            format!("{secret} is the service_role key"),
            "REDACTION-1 is the service_role key".into(),
        ),
        (
            format!("service_role key: {secret}"),
            "service_role key: REDACTION-1".into(),
        ),
        (
            format!(r#"SUPABASE_SERVICE_ROLE_KEY="{secret}""#),
            r#"SUPABASE_SERVICE_ROLE_KEY="REDACTION-1""#.into(),
        ),
        (format!("key: '{secret}'"), "key: 'REDACTION-1'".into()),
        (
            format!("{secret} then {secret}"),
            "REDACTION-1 then REDACTION-1".into(),
        ),
        (
            format!(r#"SUPABASE_SERVICE_ROLE_KEY="{real_secret}""#),
            r#"SUPABASE_SERVICE_ROLE_KEY="REDACTION-1""#.into(),
        ),
        (
            format!("SUPABASE_ACCESS_TOKEN={sbp}"),
            "SUPABASE_ACCESS_TOKEN=REDACTION-1".into(),
        ),
        (secret_hyphen, "REDACTION-1".into()),
        (sbp_hyphen, "REDACTION-1".into()),
        // Glued to a preceding word character, or to a literal `\n`.
        (format!("x{secret}"), "xREDACTION-1".into()),
        (
            format!(r"first line\n{secret}"),
            r"first line\nREDACTION-1".into(),
        ),
        (
            format!(r"first line\n{sbp}"),
            r"first line\nREDACTION-1".into(),
        ),
    ];
    let cases: Vec<(&str, &str)> = cases
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    assert_text_cases(&cases);
}

#[test]
fn supabase_length_boundaries() {
    let body20 = "boundary_probe_2026x";
    let body19 = "boundary_probe_2026";
    let s20 = format!("{}{body20}", supabase_secret_prefix());
    let s19 = format!("{}{body19}", supabase_secret_prefix());
    let p20 = format!("{}{body20}", supabase_personal_prefix());
    let p19 = format!("{}{body19}", supabase_personal_prefix());
    assert_text_cases(&[
        (&s20, "REDACTION-1"),
        (&s19, &s19),
        (&p20, "REDACTION-1"),
        (&p19, &p19),
    ]);
}

#[test]
fn supabase_over_redaction_guards() {
    let publishable = format!(
        r#"NEXT_PUBLIC_SUPABASE_KEY="{}probe_20260710_7f91c2d8e4a6b3f0""#,
        supabase_publishable_prefix()
    );
    let short_secret = format!("{}short", supabase_secret_prefix());
    let short_token = format!("{}short", supabase_personal_prefix());
    let prose = format!(
        "the {} prefix identifies Supabase secret keys",
        supabase_secret_prefix()
    );
    assert_text_cases(&[
        (&publishable, &publishable),
        (&short_secret, &short_secret),
        (&short_token, &short_token),
        (&prose, &prose),
    ]);
}

/// Long identifiers that merely start with a provider prefix are redacted.
/// Over-redaction is the accepted trade-off for catching low-entropy keys.
#[test]
fn supabase_long_identifiers_are_over_redacted() {
    let a = format!(
        "func {}key_rotation_handler() {{}}",
        supabase_secret_prefix()
    );
    let b = format!(
        "call lib{}something_long_enough_value()",
        supabase_personal_prefix()
    );
    assert_text_cases(&[(&a, "func REDACTION-1() {}"), (&b, "call libREDACTION-1()")]);
}

#[test]
fn credentialed_uris() {
    assert_text_cases(&[
        (
            "DATABASE_URL=postgres://app:pwd123@db.example.com:5432/app",
            "DATABASE_URL=REDACTION-1",
        ),
        (
            r#"dsn="postgresql://svc:moderatepw@localhost/app?sslmode=require""#,
            r#"dsn="REDACTION-1""#,
        ),
        (
            "mongo=mongodb+srv://user:pass123@cluster0.example.mongodb.net/app?retryWrites=true",
            "mongo=REDACTION-1",
        ),
        ("mysql://root:p@localhost:3306/app", "REDACTION-1"),
        (
            "cache redis://:hunter2@localhost:6379/0",
            "cache REDACTION-1",
        ),
        (
            "proxy=https://user:pass@example.com/path",
            "proxy=REDACTION-1",
        ),
        (
            "repo=ssh://git@github.com/example/cli",
            "repo=ssh://git@github.com/example/cli",
        ),
        (
            "url=https://example.com/a:b@c",
            "url=https://example.com/a:b@c",
        ),
    ]);
}

#[test]
fn database_connection_strings() {
    assert_text_cases(&[
        (
            r#"dsn="host=db.example.com port=5432 user=svc password=hunter2 dbname=app sslmode=require""#,
            r#"dsn="REDACTION-1""#,
        ),
        (
            "password=hunter2 sslmode=require user=svc host=db.example.com dbname=app",
            "REDACTION-1",
        ),
        (
            "conn=Server=tcp:db.example.com,1433;Database=app;User Id=svc;Password=hunter2;Encrypt=true",
            "conn=REDACTION-1",
        ),
        (
            "conn=Driver={ODBC Driver 18 for SQL Server};Server=db;UID=svc;PWD=hunter2;Database=app",
            "conn=REDACTION-1",
        ),
        (
            "jdbc:postgresql://db.example.com:5432/app?user=svc&password=hunter2&ssl=true",
            "REDACTION-1",
        ),
        (
            "DATABASE_URL=postgresql://db.example.com:5432/app?user=svc&password=hunter2&sslmode=require",
            "DATABASE_URL=REDACTION-1",
        ),
        (
            "DATABASE_URL=postgresql://db.example.com:5432/app?user=svc&Password=hunter2&sslmode=require",
            "DATABASE_URL=REDACTION-1",
        ),
        (
            "MONGO_URL=mongodb://cluster0.example.mongodb.net/app?authSource=admin&username=svc&password=hunter2",
            "MONGO_URL=REDACTION-1",
        ),
        (
            "MONGO_URL=mongodb+srv://cluster0.example.mongodb.net/app?authSource=admin&username=svc&password=hunter2",
            "MONGO_URL=REDACTION-1",
        ),
        (
            "DATABASE_URL=postgresql://db.example.com/app?user=svc&password=${DB_PASSWORD}",
            "DATABASE_URL=postgresql://db.example.com/app?user=svc&password=${DB_PASSWORD}",
        ),
        (
            "jdbc:sqlserver://db.example.com:1433;databaseName=app;user=svc;password=hunter2;encrypt=true",
            "REDACTION-1",
        ),
        (
            r#"conn=Server=db.example.com;User ID=svc;Password="se;cret;here";Encrypt=true"#,
            "conn=REDACTION-1",
        ),
        (
            "conn=Server=db.example.com;User ID=svc;Password='se;cret;here';Encrypt=true",
            "conn=REDACTION-1",
        ),
    ]);
}

#[test]
fn bounded_credential_values() {
    assert_text_cases(&[
        ("DB_PASSWORD=secret123", "DB_PASSWORD=REDACTION-1"),
        ("PGPASSWORD='secret123'", "PGPASSWORD='REDACTION-1'"),
        (
            r#"REDIS_PASSWORD="secret123""#,
            r#"REDIS_PASSWORD="REDACTION-1""#,
        ),
        (
            "database_password=secret123",
            "database_password=REDACTION-1",
        ),
        ("APP_DB_PASSWORD=secret123", "APP_DB_PASSWORD=REDACTION-1"),
        ("PROD_MYSQL_PWD=secret123", "PROD_MYSQL_PWD=REDACTION-1"),
        (
            "MYSQL_ROOT_PASSWORD=secret123",
            "MYSQL_ROOT_PASSWORD=REDACTION-1",
        ),
        (
            "MARIADB_ROOT_PASSWORD=secret123",
            "MARIADB_ROOT_PASSWORD=REDACTION-1",
        ),
        (
            "MONGO_INITDB_ROOT_PASSWORD=secret123",
            "MONGO_INITDB_ROOT_PASSWORD=REDACTION-1",
        ),
        (
            "MSSQL_SA_PASSWORD=secret123",
            "MSSQL_SA_PASSWORD=REDACTION-1",
        ),
        ("DB__PASSWORD=secret123", "DB__PASSWORD=REDACTION-1"),
    ]);
}

#[test]
fn bounded_credential_value_over_redaction_guards() {
    let already_redacted = format!(
        "DB_PASSWORD={}",
        redactify::token(
            "credential-assignment",
            7,
            &redactify::redaction_key(b"x", "hunter2")
        )
    );
    assert_text_cases(&[
        ("DB_PASSWORD=${DB_PASSWORD}", "DB_PASSWORD=${DB_PASSWORD}"),
        ("DB_PASSWORD=REDACTED", "DB_PASSWORD=REDACTED"),
        (already_redacted.as_str(), "DB_PASSWORD=REDACTION-1"),
        (
            "the password field should be rotated regularly",
            "the password field should be rotated regularly",
        ),
        ("key=not-a-secret-setting", "key=not-a-secret-setting"),
        ("PWD=/workspace/project", "PWD=/workspace/project"),
        ("password=not-a-secret-setting", "password=REDACTION-1"),
        (
            "https://example.com/?password_reset=true",
            "https://example.com/?password_reset=true",
        ),
        (
            "https://example.com/callback?user=svc&password=not-a-db-credential&debug=true",
            "https://example.com/callback?user=svc&password=REDACTION-1",
        ),
        ("DB_PASSWORD_HASH=abcdef", "DB_PASSWORD_HASH=abcdef"),
        ("MYSQL_USER_ID=alice", "MYSQL_USER_ID=alice"),
        ("DB_PASSWORD=<password>", "DB_PASSWORD=<password>"),
        ("DB_PASSWORD=your_password", "DB_PASSWORD=your_password"),
        (
            "DB_PASSWORD=<your-db-password>",
            "DB_PASSWORD=<your-db-password>",
        ),
        ("DB_PASSWORD=*****", "DB_PASSWORD=*****"),
        ("DB_PASSWORD=......", "DB_PASSWORD=......"),
        ("DB_PASSWORD=secret_here", "DB_PASSWORD=secret_here"),
        ("password=changeme", "password=changeme"),
        (
            "Server=db.internal;Database=prod;User Id=app;Password=changeme;TrustCert=true",
            "Server=db.internal;Database=prod;User Id=app;Password=changeme;TrustCert=true",
        ),
        // A greedy finding that starts with a placeholder is redacted whole:
        // the tail can hold a real secret.
        (
            "password=changeme&db_pass=hunter2hunter2",
            "password=REDACTION-1",
        ),
        (
            r#"password="changeme;realSecret42""#,
            r#"password="REDACTION-1""#,
        ),
        ("password=changeme&sslmode=require", "password=REDACTION-1"),
        (
            "password=hunter2secret&sslmode=require",
            "password=REDACTION-1",
        ),
        ("DB_PASSWORD=placeholder", "DB_PASSWORD=placeholder"),
    ]);
}

#[test]
fn short_and_opaque_values_are_not_placeholders() {
    assert_text_cases(&[
        ("DB_PASSWORD=x", "DB_PASSWORD=REDACTION-1"),
        ("DB_PASSWORD=-", "DB_PASSWORD=REDACTION-1"),
        ("DB_PASSWORD=*", "DB_PASSWORD=REDACTION-1"),
        ("DB_PASSWORD=xx", "DB_PASSWORD=REDACTION-1"),
        ("DB_PASSWORD=<hunter2>", "DB_PASSWORD=REDACTION-1"),
        ("DB_PASSWORD=<RealPassword>", "DB_PASSWORD=REDACTION-1"),
    ]);
}

#[test]
fn openssh_private_key_block_is_redacted_whole() {
    let key = fake_openssh_private_key();
    assert_eq!(text(&format!("key:\n{key}\nend")), "key:\nREDACTION-1\nend");
}

#[test]
fn file_paths_are_preserved() {
    for path in [
        "/tmp/TestE2E_Something3407889464/001/controller.go",
        "/private/var/folders/v4/31cd3cg52_sfrpb1mbtr7q7r0000gn/T/TestE2E_Something/controller",
        "Reading file: /tmp/test/model.go",
        "/Users/someone/.claude/projects/something.jsonl",
        "/tmp/test/controller.go\n/tmp/test/model.go\n/tmp/test/view.go",
    ] {
        assert_eq!(text(path), path);
    }
}

#[test]
fn real_secrets_are_caught() {
    for input in [
        format!("api_key={HIGH_ENTROPY_SECRET}"),
        "key=AKIAYRWQG5EJLPZLBYNP".to_owned(),
        "token=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB".to_owned(),
    ] {
        assert!(
            text(&input).contains("REDACTION-"),
            "{input} was not redacted"
        );
    }
}

/// Known gap: shell `--password=` flags have no database prefix, DSN
/// structure, or URI shape, so nothing matches them.
#[test]
fn shell_password_flags_are_not_redacted() {
    assert_text_cases(&[
        (
            "mysql -u svc --password=hunter2 -h db.example.com app",
            "mysql -u svc --password=hunter2 -h db.example.com app",
        ),
        (
            "psql --password=hunter2 -U svc -h db.example.com app",
            "psql --password=hunter2 -U svc -h db.example.com app",
        ),
    ]);
}

#[test]
fn redaction_is_idempotent() {
    for input in [
        "DATABASE_URL=postgres://svc:hunter2@db.example.com/app".to_owned(),
        "DB_PASSWORD=hunter2".to_owned(),
        r#"conn=Server=db.example.com;User ID=svc;Password="se;cret;here";Encrypt=true"#.to_owned(),
        "jdbc:postgresql://db.example.com:5432/app?user=svc&password=hunter2".to_owned(),
        format!("my key is {HIGH_ENTROPY_SECRET} ok"),
    ] {
        let once = text(&input);
        assert_ne!(once, input);
        assert_eq!(text(&once), once, "not idempotent for {input:?}");
    }
}

#[test]
fn github_token_is_redacted_by_ruleset() {
    let input = "auth with token ghp_a1b2c1d2e1f2g1h2a1b2c1d2e1f2g1h2a1b2";
    assert_eq!(text(input), "auth with token REDACTION-1");
}

#[test]
fn invalid_utf8_is_passed_through() {
    let mut input = b"key \xff\xfe ".to_vec();
    input.extend_from_slice(HIGH_ENTROPY_SECRET.as_bytes());
    let redaction = redactor()
        .redact(&input, redactify::FormatHint::Name("text"))
        .unwrap();
    let out = redaction.render(&redactify::Allow::none()).unwrap();
    let token = redaction.findings()[0].token();
    assert_eq!(
        out,
        [b"key \xff\xfe ".as_slice(), token.as_bytes()].concat()
    );
}
