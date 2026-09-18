use std::sync::LazyLock;

use regex::Regex;

use super::placeholder::{Placeholders, unquote_range};
use super::{Detection, Detector, LeafContext};

/// A database-flavoured password key: a vendor prefix, optional `_word` or
/// `-word` segments, then `password`, `passwd`, or `pwd`.
const DB_PASSWORD_KEY: &str = r"(?:db|database|pg|postgres|postgresql|mysql|mariadb|redis|mongo|mongodb|sqlserver|mssql|jdbc)(?:[_-]+[a-z0-9]+)*[_-]*(?:password|passwd|pwd)";

/// `DB_PASSWORD=value`. The key must start at a non-alphanumeric boundary, so
/// `APP_DB_PASSWORD` matches (via the `_`) but `mydbpassword` does not.
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?:^|[^A-Za-z0-9])({DB_PASSWORD_KEY})\s*=\s*("[^"]*"|'[^']*'|[^\s,;&]+)"#
    ))
    .unwrap()
});

static DB_PASSWORD_KEY_EXACT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^{DB_PASSWORD_KEY}$")).unwrap());

static GENERIC_PASSWORD_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:password|passwd|pwd)$").unwrap());

/// Detects `DB_PASSWORD=value` style assignments inside free text and reports
/// the value.
///
/// Values that `placeholders` considers documentation are left alone.
#[derive(Debug, Clone, Default)]
pub struct CredentialAssignmentDetector {
    placeholders: Placeholders,
}

impl CredentialAssignmentDetector {
    pub fn new(placeholders: &Placeholders) -> Self {
        Self {
            placeholders: placeholders.clone(),
        }
    }
}

impl Detector for CredentialAssignmentDetector {
    fn name(&self) -> &str {
        "credential-assignment"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        for caps in ASSIGNMENT.captures_iter(value) {
            let m = caps.get(2).expect("group 2 always participates");
            let range = unquote_range(value, m.range());
            if self.placeholders.has_real_value(&value[range.clone()]) {
                out.push(Detection::new(range, self.name()));
            }
        }
    }
}

/// Redacts the entire value of a password field in structured data.
///
/// Database password keys (`db_password`, `mysql.root.password`,
/// `PG-PASSWORD`) always qualify. A bare `password`, `passwd`, or `pwd` key
/// qualifies only inside an object that also has host and user keys.
///
/// Values that `placeholders` considers documentation are left alone.
#[derive(Debug, Clone, Default)]
pub struct CredentialKeyDetector {
    placeholders: Placeholders,
}

impl CredentialKeyDetector {
    pub fn new(placeholders: &Placeholders) -> Self {
        Self {
            placeholders: placeholders.clone(),
        }
    }
}

impl Detector for CredentialKeyDetector {
    fn name(&self) -> &str {
        "credential-key"
    }

    fn detect(&self, value: &str, ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        let Some(key) = ctx.key else { return };
        if is_credential_key(key, ctx.credential_context) && self.placeholders.has_real_value(value)
        {
            out.push(Detection::new(0..value.len(), self.name()));
        }
    }
}

fn is_credential_key(key: &str, credential_context: bool) -> bool {
    let normalized = normalize_key(key);
    DB_PASSWORD_KEY_EXACT.is_match(&normalized)
        || (credential_context && GENERIC_PASSWORD_KEY.is_match(&normalized))
}

/// Lowercase and map `-`, space, and `.` to `_`, so `DB-Password`,
/// `db password`, and dotted keys from flattened configs such as
/// `mysql.root.password` compare equal to their snake_case forms.
pub(crate) fn normalize_key(key: &str) -> String {
    key.trim()
        .to_lowercase()
        .chars()
        .map(|c| if matches!(c, '-' | ' ' | '.') { '_' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignments(s: &str) -> Vec<&str> {
        let mut out = Vec::new();
        CredentialAssignmentDetector::default().detect(s, &LeafContext::default(), &mut out);
        out.iter().map(|d| &s[d.range.clone()]).collect()
    }

    fn key_hit(key: &str, credential_context: bool, value: &str) -> bool {
        let mut out = Vec::new();
        let ctx = LeafContext {
            key: Some(key),
            credential_context,
            ..LeafContext::default()
        };
        CredentialKeyDetector::default().detect(value, &ctx, &mut out);
        !out.is_empty()
    }

    #[test]
    fn finds_bounded_assignments() {
        assert_eq!(assignments("DB_PASSWORD=hunter2"), ["hunter2"]);
        assert_eq!(
            assignments("export APP_DB_PASSWORD='s3cret value'"),
            ["s3cret value"]
        );
        assert_eq!(assignments(r#"POSTGRES_PASSWORD="abc123""#), ["abc123"]);
        assert_eq!(assignments("x mysql-root-password = qwerty, y"), ["qwerty"]);
        assert_eq!(assignments("REDIS_PWD=pa55;other=1"), ["pa55"]);
    }

    #[test]
    fn ignores_unbounded_or_placeholder_assignments() {
        assert!(assignments("mydbpassword=hunter2").is_empty());
        assert!(assignments("DB_PASSWORD=changeme").is_empty());
        assert!(assignments("DB_PASSWORD=${DB_PASSWORD}").is_empty());
        assert!(assignments("DB_PASSWORD=***").is_empty());
        assert!(assignments("DB_PASSWORD=''").is_empty());
        assert!(assignments("PASSWORD=hunter2").is_empty());
    }

    #[test]
    fn credential_keys() {
        assert!(key_hit("db_password", false, "hunter2"));
        assert!(key_hit("DB-Password", false, "hunter2"));
        assert!(key_hit("mysql.root.password", false, "hunter2"));
        assert!(key_hit("postgres password", false, "hunter2"));
        assert!(!key_hit("password", false, "hunter2"));
        assert!(key_hit("password", true, "hunter2"));
        assert!(key_hit("pwd", true, "hunter2"));
        assert!(!key_hit("db_password", false, "changeme"));
        assert!(!key_hit("db_password", false, ""));
        assert!(!key_hit("password_hint", true, "hunter2"));
    }
}
