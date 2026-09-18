//! A small glob matcher used by path and detector filters.

use regex::Regex;

/// A glob pattern.
///
/// Three flavors are supported:
///
/// - [`Glob::new`] treats `.` as a separator, for matching the dotted key
///   paths of structured documents. `*` matches within one segment, `**`
///   matches across segments, and `?` matches one character other than `.`.
/// - [`Glob::path`] is the same with `/` as the separator, for matching
///   relative file paths.
/// - [`Glob::flat`] has no separator: `*` matches any run of characters and
///   `?` matches any single character. It is used for detector names, which
///   contain `.` and `:` as ordinary characters.
#[derive(Debug, Clone)]
pub struct Glob {
    source: String,
    regex: Regex,
}

impl Glob {
    /// A separator-aware pattern, for dotted key paths.
    ///
    /// `a.*.b` matches `a.x.b` but not `a.x.y.b`; `a.**.b` matches both, and
    /// also `a.b`.
    pub fn new(pattern: &str) -> Self {
        Self::compile(pattern, Some('.'))
    }

    /// A separator-aware pattern, for `/`-separated file paths.
    ///
    /// `src/*.rs` matches `src/main.rs` but not `src/a/b.rs`; `src/**/*.rs`
    /// matches both.
    pub fn path(pattern: &str) -> Self {
        Self::compile(pattern, Some('/'))
    }

    /// A pattern with no separator, where `*` matches anything.
    pub fn flat(pattern: &str) -> Self {
        Self::compile(pattern, None)
    }

    fn compile(pattern: &str, separator: Option<char>) -> Self {
        let regex = Regex::new(&translate(pattern, separator))
            .expect("a translated glob is always a valid regex");
        Self {
            source: pattern.to_owned(),
            regex,
        }
    }

    /// Whether `text` matches this pattern in full.
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }

    /// The pattern this glob was built from.
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

/// Whether any of `globs` matches `text`.
pub(crate) fn any_match(globs: &[Glob], text: &str) -> bool {
    globs.iter().any(|g| g.is_match(text))
}

/// Translate a glob into an anchored regular expression.
fn translate(pattern: &str, separator: Option<char>) -> String {
    // Without a separator every wildcard is unrestricted.
    let (star, question) = match separator {
        Some(sep) => {
            let class = format!("[^{}]", regex::escape(&sep.to_string()));
            (format!("{class}*"), class)
        }
        None => (".*".to_owned(), ".".to_owned()),
    };

    let mut out = String::with_capacity(pattern.len() * 2 + 4);
    out.push_str("(?s)^");
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &pattern[i..];
        match (bytes[i], separator) {
            (b'*', Some(sep)) if rest.starts_with("**") => {
                // `**` followed by a separator spans whole segments,
                // including none at all.
                if rest[2..].starts_with(sep) {
                    let sep = regex::escape(&sep.to_string());
                    out.push_str(&format!("(?:[^{sep}]+{sep})*"));
                    i += 3;
                } else {
                    out.push_str(".*");
                    i += 2;
                }
            }
            (b'*', _) => {
                out.push_str(&star);
                i += 1;
            }
            (b'?', _) => {
                out.push_str(&question);
                i += 1;
            }
            // A trailing separator and `**` also matches the path with
            // nothing after it.
            (b, Some(sep)) if b as char == sep && rest.len() == 3 && rest.ends_with("**") => {
                out.push_str(&format!("(?:{}.*)?", regex::escape(&sep.to_string())));
                i += 3;
            }
            _ => {
                let end = i + utf8_len(bytes[i]);
                out.push_str(&regex::escape(&pattern[i..end]));
                i = end;
            }
        }
    }
    out.push('$');
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_segments() {
        let g = Glob::new("aws.secret_key");
        assert!(g.is_match("aws.secret_key"));
        assert!(!g.is_match("aws.secret_keys"));
        assert!(!g.is_match("x.aws.secret_key"));
    }

    #[test]
    fn single_star_stays_in_one_segment() {
        let g = Glob::new("users.*.ssn");
        assert!(g.is_match("users.jane.ssn"));
        assert!(!g.is_match("users.a.b.ssn"));
        assert!(!g.is_match("users.ssn"));

        assert!(Glob::new("*").is_match("token"));
        assert!(Glob::new("*").is_match(""));
        assert!(!Glob::new("*").is_match("a.b"));
        assert!(Glob::new("*_key").is_match("api_key"));
    }

    #[test]
    fn double_star_spans_segments() {
        let g = Glob::new("users.**.ssn");
        assert!(g.is_match("users.ssn"));
        assert!(g.is_match("users.jane.ssn"));
        assert!(g.is_match("users.a.b.c.ssn"));
        assert!(!g.is_match("users.ssn.x"));

        let tail = Glob::new("secrets.**");
        assert!(tail.is_match("secrets"));
        assert!(tail.is_match("secrets.a"));
        assert!(tail.is_match("secrets.a.b"));
        assert!(!tail.is_match("secretsx"));

        assert!(Glob::new("**").is_match("a.b.c"));
        assert!(Glob::new("**").is_match(""));
        assert!(Glob::new("**.key").is_match("key"));
        assert!(Glob::new("**.key").is_match("a.b.key"));
    }

    #[test]
    fn question_matches_one_character() {
        assert!(Glob::new("k?y").is_match("key"));
        assert!(!Glob::new("k?y").is_match("kay.y"));
        assert!(!Glob::new("k?y").is_match("ky"));
    }

    #[test]
    fn special_characters_are_literal() {
        assert!(Glob::new("a+b").is_match("a+b"));
        assert!(!Glob::new("a+b").is_match("aab"));
        assert!(Glob::new("wée.*").is_match("wée.x"));
    }

    #[test]
    fn flat_globs_ignore_dots() {
        let g = Glob::flat("*");
        assert!(g.is_match("ruleset:aws-key"));
        assert!(g.is_match("team.rule"));
        assert!(Glob::flat("ruleset:*").is_match("ruleset:aws-key"));
        assert!(Glob::flat("pii:*").is_match("pii:email"));
        assert!(!Glob::flat("pii:*").is_match("entropy"));
        assert!(Glob::flat("entropy").is_match("entropy"));
    }

    #[test]
    fn path_globs_use_slashes() {
        let g = Glob::path("src/*.rs");
        assert!(g.is_match("src/main.rs"));
        assert!(!g.is_match("src/a/b.rs"));
        assert!(Glob::path("*.env").is_match("prod.env"));
        assert!(Glob::path("a.b").is_match("a.b"), "dots are literal");

        let g = Glob::path("secrets/**");
        assert!(g.is_match("secrets"));
        assert!(g.is_match("secrets/a/b.txt"));
        assert!(!g.is_match("secretsx"));

        let g = Glob::path("**/*.log");
        assert!(g.is_match("app.log"));
        assert!(g.is_match("logs/2026/app.log"));
        assert!(!g.is_match("app.log/x"));
    }

    #[test]
    fn newlines_are_matched_by_wildcards() {
        assert!(Glob::flat("a*b").is_match("a\nb"));
    }
}
