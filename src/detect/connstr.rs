use std::sync::LazyLock;

use regex::Regex;
use url::Url;

use super::placeholder::{Placeholders, unquote_range};
use super::{Detection, Detector, LeafContext};

static JDBC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?-u:\b)jdbc:[^\s"'<>`]+"#).unwrap());
static DATABASE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?-u:\b)(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s"'<>`]+"#,
    )
    .unwrap()
});
/// `host=… user=… password=…` style DSNs (libpq and similar).
static KEYWORD_DSN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?-u:\b)[a-z_][a-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s"']+)(?:\s+[a-z_][a-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s"']+)){2,}"#,
    )
    .unwrap()
});
/// `Server=…;User Id=…;Password=…` style connection strings (ADO.NET and similar).
static SEMICOLON_CONN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?-u:\b)[a-z][a-z0-9 _-]*=(?:\{[^}]*\}|"[^"]*"|'[^']*'|[^=;"'\s]+)(?:;[a-z][a-z0-9 _-]*=(?:\{[^}]*\}|"[^"]*"|'[^']*'|[^=;"'\s]+)){2,}"#,
    )
    .unwrap()
});

static KEYWORD_HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:^|\s)host=").unwrap());
static KEYWORD_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:^|\s)user=").unwrap());
static SEMICOLON_SERVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|;)\s*(?:server|data source|datasource|addr|address|network address)\s*=")
        .unwrap()
});
static SEMICOLON_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|;)\s*(?:user id|userid|user|uid)\s*=").unwrap());
static PASSWORD_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:^|[?&;\s])(?:password|pwd)=("[^"]*"|'[^']*'|[^&;\s"']+)"#).unwrap()
});

struct Rule {
    pattern: &'static LazyLock<Regex>,
    has_secret: fn(&str, &Placeholders) -> bool,
}

static RULES: [Rule; 4] = [
    Rule {
        pattern: &JDBC,
        has_secret: jdbc_has_password,
    },
    Rule {
        pattern: &DATABASE_URL,
        has_secret: database_url_has_password,
    },
    Rule {
        pattern: &KEYWORD_DSN,
        has_secret: keyword_dsn_has_password,
    },
    Rule {
        pattern: &SEMICOLON_CONN,
        has_secret: semicolon_conn_has_password,
    },
];

/// Detects database connection strings that carry a password: JDBC URLs,
/// database URLs with a `password` query parameter, keyword DSNs, and
/// semicolon-separated connection strings.
///
/// The whole connection string is reported, since hosts and user names in the
/// same string are often sensitive too. Strings whose password is a
/// placeholder are ignored, as decided by `placeholders`.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStringDetector {
    placeholders: Placeholders,
}

impl ConnectionStringDetector {
    pub fn new(placeholders: &Placeholders) -> Self {
        Self {
            placeholders: placeholders.clone(),
        }
    }
}

impl Detector for ConnectionStringDetector {
    fn name(&self) -> &str {
        "connection-string"
    }

    fn detect(&self, value: &str, _ctx: &LeafContext<'_>, out: &mut Vec<Detection>) {
        if !value.contains('=') {
            return;
        }
        for rule in &RULES {
            for m in rule.pattern.find_iter(value) {
                let start = m.start();
                let end = trim_trailing_punctuation(value, start, m.end());
                if start < end && (rule.has_secret)(&value[start..end], &self.placeholders) {
                    out.push(Detection::new(start..end, self.name()));
                }
            }
        }
    }
}

/// Drop sentence punctuation that the greedy patterns pick up after a
/// connection string embedded in prose.
fn trim_trailing_punctuation(s: &str, start: usize, mut end: usize) -> usize {
    while end > start
        && matches!(
            s.as_bytes()[end - 1],
            b'.' | b',' | b';' | b':' | b'!' | b'?' | b')' | b']'
        )
    {
        end -= 1;
    }
    end
}

fn jdbc_has_password(candidate: &str, placeholders: &Placeholders) -> bool {
    candidate
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("jdbc:"))
        && has_password_assignment(candidate, placeholders)
}

fn database_url_has_password(candidate: &str, placeholders: &Placeholders) -> bool {
    let Ok(url) = Url::parse(candidate) else {
        return false;
    };
    if url.host_str().is_none_or(str::is_empty) {
        return false;
    }
    url.query_pairs().any(|(key, value)| {
        (key.eq_ignore_ascii_case("password") || key.eq_ignore_ascii_case("pwd"))
            && placeholders.has_real_value(&value)
    })
}

fn keyword_dsn_has_password(candidate: &str, placeholders: &Placeholders) -> bool {
    KEYWORD_HOST.is_match(candidate)
        && KEYWORD_USER.is_match(candidate)
        && has_password_assignment(candidate, placeholders)
}

fn semicolon_conn_has_password(candidate: &str, placeholders: &Placeholders) -> bool {
    SEMICOLON_SERVER.is_match(candidate)
        && SEMICOLON_USER.is_match(candidate)
        && has_password_assignment(candidate, placeholders)
}

fn has_password_assignment(candidate: &str, placeholders: &Placeholders) -> bool {
    PASSWORD_ASSIGNMENT.captures_iter(candidate).any(|caps| {
        let m = caps.get(1).expect("group 1 always participates");
        let range = unquote_range(candidate, m.range());
        placeholders.has_real_value(&candidate[range])
    })
}
