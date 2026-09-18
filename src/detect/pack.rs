//! Rule packs: versioned files of custom redaction rules.
//!
//! A pack is a YAML (or `.json`) file whose `name` matches its file stem:
//!
//! ```yaml
//! name: acme-internal
//! version: 1.0.0
//! description: Internal ACME tokens
//! rules:
//!   - id: acme-token
//!     regex: 'ACME_TOKEN_[A-Za-z0-9]{20,}'
//!     samples:
//!       - { input: "ACME_TOKEN_abc123def456ghi789jkl", redacted: true }
//!       - { input: "ACME_TOKEN_short", redacted: false }
//! ```

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use super::{Detector, RegexDetector};
use crate::Error;

const MAX_IDENTIFIER_LEN: usize = 64;
/// Files larger than this are skipped when loading a directory.
pub const MAX_PACK_FILE_BYTES: u64 = 1 << 20;
/// At most this many packs are loaded from one directory tree.
pub const MAX_PACK_FILES: usize = 256;

/// Pack names and rule ids are restricted to characters that are safe in
/// file names and log lines.
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._-]+$").unwrap());

/// The `rule-packs` detector's settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RulePacksConfig {
    /// Pack files, or directories to load every pack from.
    pub paths: Vec<PathBuf>,
}

impl RulePacksConfig {
    /// Load every pack named here and compile its rules.
    ///
    /// A rule that fails to compile, or a pack file that cannot be read, is
    /// skipped with a warning rather than failing the whole load.
    pub fn detectors(&self, warnings: &mut Vec<String>) -> Result<Vec<Box<dyn Detector>>, Error> {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        for path in &self.paths {
            for pack in load_packs(path, warnings)? {
                let (pack_detectors, pack_warnings) = pack.detectors();
                warnings.extend(pack_warnings);
                detectors.extend(
                    pack_detectors
                        .into_iter()
                        .map(|d| Box::new(d) as Box<dyn Detector>),
                );
            }
        }
        Ok(detectors)
    }
}

/// Load a pack file, or every pack in a directory.
fn load_packs(path: &Path, warnings: &mut Vec<String>) -> Result<Vec<Pack>, Error> {
    if path.is_dir() {
        let loaded = load_pack_dir(path)?;
        warnings.extend(loaded.warnings);
        return Ok(loaded.packs);
    }
    let source = fs::read_to_string(path)
        .map_err(|err| Error::Pack(format!("reading {}: {err}", path.display())))?;
    Ok(vec![Pack::parse(&source, path)?])
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rules: Vec<PackRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub regex: String,
    #[serde(default)]
    pub samples: Vec<PackSample>,
}

/// A self-test for a rule: whether `input` should be matched.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSample {
    pub input: String,
    pub redacted: bool,
}

impl Pack {
    /// Parse and validate a pack. `path` selects the encoding (JSON for
    /// `.json`, YAML otherwise) and must have a stem equal to the pack name.
    pub fn parse(data: &str, path: &Path) -> Result<Self, Error> {
        let shown = path.display();
        let is_json = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let pack: Pack = if is_json {
            let mut stream = serde_json::Deserializer::from_str(data).into_iter::<Pack>();
            let pack = match stream.next() {
                Some(Ok(pack)) => pack,
                Some(Err(err)) => return Err(Error::Pack(format!("parse {shown}: {err}"))),
                None => return Err(Error::Pack(format!("parse {shown}: empty file"))),
            };
            if stream.next().is_some() {
                return Err(Error::Pack(format!(
                    "parse {shown}: trailing content after pack"
                )));
            }
            pack
        } else {
            let mut docs = serde_yaml_ng::Deserializer::from_str(data);
            let first = docs
                .next()
                .ok_or_else(|| Error::Pack(format!("parse {shown}: empty file")))?;
            let pack = Pack::deserialize(first)
                .map_err(|err| Error::Pack(format!("parse {shown}: {err}")))?;
            if docs.next().is_some() {
                return Err(Error::Pack(format!(
                    "parse {shown}: trailing content after pack"
                )));
            }
            pack
        };
        pack.validate(path)?;
        Ok(pack)
    }

    fn validate(&self, path: &Path) -> Result<(), Error> {
        let shown = path.display();
        let fail = |msg: String| Err(Error::Pack(format!("{shown}: {msg}")));
        if self.name.is_empty() {
            return fail("missing required field 'name'".into());
        }
        validate_identifier("name", &self.name).or_else(fail)?;
        if self.version.is_empty() {
            return fail("missing required field 'version'".into());
        }
        if self.rules.is_empty() {
            return fail("'rules' must contain at least one entry".into());
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if stem != self.name {
            return fail(format!(
                "pack name {:?} does not match filename stem {stem:?}",
                self.name
            ));
        }
        let mut seen = HashSet::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.id.is_empty() {
                return fail(format!("rules[{i}] missing required field 'id'"));
            }
            validate_identifier(&format!("rules[{i}].id"), &rule.id).or_else(fail)?;
            if rule.regex.is_empty() {
                return fail(format!(
                    "rules[{i}] ({}) missing required field 'regex'",
                    rule.id
                ));
            }
            if !seen.insert(&rule.id) {
                return fail(format!("duplicate rule id {:?}", rule.id));
            }
        }
        Ok(())
    }

    /// Compile the pack's rules.
    ///
    /// Rules that fail to compile are dropped with a warning. Samples whose
    /// outcome differs from the expectation produce a warning but keep the
    /// rule. Warnings never include the pattern or sample text.
    pub fn detectors(&self) -> (Vec<RegexDetector>, Vec<String>) {
        let mut detectors = Vec::new();
        let mut warnings = Vec::new();
        for rule in &self.rules {
            let name = format!("{}.{}", self.name, rule.id);
            match RegexDetector::new(&name, &rule.regex) {
                Ok(detector) => {
                    for (i, sample) in rule.samples.iter().enumerate() {
                        let matched = detector.regex().is_match(&sample.input);
                        if matched != sample.redacted {
                            warnings.push(format!(
                                "{name}: sample {i} (length {}) expected redacted={}, got {matched}",
                                sample.input.len(),
                                sample.redacted
                            ));
                        }
                    }
                    detectors.push(detector);
                }
                Err(err) => warnings.push(format!("skipping rule: {err}")),
            }
        }
        (detectors, warnings)
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(format!(
            "{field} {value:?} exceeds {MAX_IDENTIFIER_LEN}-character limit"
        ));
    }
    if !IDENTIFIER.is_match(value) {
        return Err(format!(
            "{field} {value:?} contains characters outside [A-Za-z0-9._-]"
        ));
    }
    Ok(())
}

/// Packs found by [`load_pack_dir`], plus warnings for files that were skipped.
#[derive(Debug, Default)]
pub struct LoadedPacks {
    pub packs: Vec<Pack>,
    pub warnings: Vec<String>,
}

/// Load every `.yaml`, `.yml`, and `.json` pack under `dir`, recursively.
///
/// A missing directory yields no packs. The directory itself must not be a
/// symlink. Symlinked files, unreadable or invalid files, and files over
/// [`MAX_PACK_FILE_BYTES`] are skipped with a warning; loading stops after
/// [`MAX_PACK_FILES`] packs.
pub fn load_pack_dir(dir: &Path) -> Result<LoadedPacks, Error> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(LoadedPacks::default()),
        Err(err) => return Err(Error::Pack(format!("read {}: {err}", dir.display()))),
    };
    if meta.file_type().is_symlink() {
        return Err(Error::Pack(format!("{} is a symlink", dir.display())));
    }
    if !meta.is_dir() {
        return Err(Error::Pack(format!("{} is not a directory", dir.display())));
    }

    let mut files = Vec::new();
    let mut loaded = LoadedPacks::default();
    collect_pack_files(dir, &mut files, &mut loaded.warnings);
    files.sort();

    for path in files {
        if loaded.packs.len() >= MAX_PACK_FILES {
            loaded.warnings.push(format!(
                "{}: skipped, limit of {MAX_PACK_FILES} packs reached",
                path.display()
            ));
            break;
        }
        match load_pack_file(&path) {
            Ok(pack) => loaded.packs.push(pack),
            Err(warning) => loaded.warnings.push(warning),
        }
    }
    Ok(loaded)
}

fn collect_pack_files(dir: &Path, files: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            warnings.push(format!("{}: {err}", dir.display()));
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            warnings.push(format!("{}: skipped symlink", path.display()));
        } else if file_type.is_dir() {
            collect_pack_files(&path, files, warnings);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "yaml" | "yml" | "json"))
        {
            files.push(path);
        }
    }
}

fn load_pack_file(path: &Path) -> Result<Pack, String> {
    let size = fs::metadata(path)
        .map_err(|err| format!("{}: {err}", path.display()))?
        .len();
    if size > MAX_PACK_FILE_BYTES {
        return Err(format!(
            "{}: skipped, {size} bytes exceeds the {MAX_PACK_FILE_BYTES}-byte limit",
            path.display()
        ));
    }
    let data = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    Pack::parse(&data, path).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str, path: &str) -> Result<Pack, Error> {
        Pack::parse(body, Path::new(path))
    }

    #[test]
    fn parses_valid_yaml_and_json() {
        let yaml = r#"
name: acme-internal
version: 1.0.0
description: Internal ACME tokens
rules:
  - id: acme-token
    regex: 'ACME_TOKEN_[A-Za-z0-9]{20,}'
    samples:
      - { input: "ACME_TOKEN_abc123def456ghi789jkl", redacted: true }
      - { input: "ACME_TOKEN_short", redacted: false }
  - id: acme-session
    regex: 'asess_[a-f0-9]{32}'
"#;
        let pack = parse(yaml, "acme-internal.yaml").unwrap();
        assert_eq!(pack.name, "acme-internal");
        assert_eq!(pack.version, "1.0.0");
        assert_eq!(pack.rules.len(), 2);
        assert_eq!(pack.rules[0].id, "acme-token");
        assert_eq!(pack.rules[0].samples.len(), 2);

        let json = r#"{
  "name": "acme-internal",
  "version": "1.0.0",
  "rules": [{"id": "acme-token", "regex": "ACME_TOKEN_[A-Za-z0-9]{20,}"}]
}"#;
        let pack = parse(json, "acme-internal.json").unwrap();
        assert_eq!(pack.rules.len(), 1);
        assert!(pack.rules[0].samples.is_empty());
    }

    #[test]
    fn rejects_invalid_packs() {
        let long_id = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        let long_body =
            format!("name: long-id\nversion: 1.0.0\nrules:\n  - id: {long_id}\n    regex: 'X+'\n");
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "noname.yaml",
                "version: 1.0.0\nrules:\n  - id: x\n    regex: 'X+'\n",
                &["name"],
            ),
            (
                "empty.yaml",
                "name: empty\nversion: 1.0.0\nrules: []\n",
                &["rules"],
            ),
            (
                "dupe.yaml",
                "name: dupe\nversion: 1.0.0\nrules:\n  - id: same\n    regex: 'A+'\n  - id: same\n    regex: 'B+'\n",
                &["duplicate"],
            ),
            (
                "actual-filename.yaml",
                "name: not-the-filename\nversion: 1.0.0\nrules:\n  - id: x\n    regex: 'X+'\n",
                &["name", "filename"],
            ),
            (
                "unknown-yaml.yaml",
                "name: unknown-yaml\nversion: 1.0.0\nrules:\n  - id: x\n    regex: 'X+'\n    samplez: []\n",
                &["samplez"],
            ),
            (
                "unknown-json.json",
                r#"{"name": "unknown-json", "version": "1.0.0", "rules": [{"id": "x", "regex": "X+", "samplez": []}]}"#,
                &["samplez"],
            ),
            (
                "trailing-json.json",
                r#"{"name": "trailing-json", "version": "1.0.0", "rules": [{"id": "x", "regex": "X+"}]}
{"name": "second"}"#,
                &["trailing"],
            ),
            (
                "multiple-yaml.yaml",
                "name: multiple-yaml\nversion: 1.0.0\nrules:\n  - id: x\n    regex: 'X+'\n---\nname: second\n",
                &["trailing"],
            ),
            (
                "bad-id.yaml",
                "name: bad-id\nversion: 1.0.0\nrules:\n  - id: 'has space'\n    regex: 'X+'\n",
                &["rules[0].id", "characters"],
            ),
            ("long-id.yaml", &long_body, &["rules[0].id", "limit"]),
        ];
        for (path, body, wants) in cases {
            let err = parse(body, path).expect_err(path).to_string();
            for want in *wants {
                assert!(
                    err.contains(want),
                    "{path}: {err:?} should mention {want:?}"
                );
            }
        }
    }

    #[test]
    fn samples_warn_but_keep_rule() {
        let pack = parse(
            "name: p\nversion: '1'\nrules:\n  - id: r\n    regex: 'TOK_[0-9]+'\n    samples:\n      - { input: 'TOK_123', redacted: true }\n      - { input: 'TOK_SECRETVALUE', redacted: true }\n",
            "p.yaml",
        )
        .unwrap();
        let (detectors, warnings) = pack.detectors();
        assert_eq!(detectors.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("sample 1"));
        assert!(!warnings[0].contains("SECRETVALUE"));
    }

    #[test]
    fn invalid_regex_is_dropped_without_echoing_pattern() {
        let pack = parse(
            "name: p\nversion: '1'\nrules:\n  - id: bad\n    regex: 'LEAKED_SECRET('\n  - id: good\n    regex: 'G+'\n",
            "p.yaml",
        )
        .unwrap();
        let (detectors, warnings) = pack.detectors();
        assert_eq!(detectors.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(!warnings[0].contains("LEAKED_SECRET"));
    }

    fn write(dir: &Path, name: &str, body: &str) {
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn loads_directory_recursively_and_skips_bad_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write(
            dir,
            "alpha.yaml",
            "name: alpha\nversion: 1.0.0\nrules:\n  - id: a\n    regex: 'A+'\n",
        );
        write(
            dir,
            "beta.json",
            r#"{"name": "beta", "version": "1.0.0", "rules": [{"id": "b", "regex": "B+"}]}"#,
        );
        write(dir, "ignored.txt", "not a pack");
        write(dir, "broken.yaml", "name: [this is malformed");
        fs::create_dir(dir.join("local")).unwrap();
        write(
            &dir.join("local"),
            "personal.yaml",
            "name: personal\nversion: 1.0.0\nrules:\n  - id: p\n    regex: 'P+'\n",
        );

        let loaded = load_pack_dir(dir).unwrap();
        let mut names: Vec<_> = loaded.packs.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["alpha", "beta", "personal"]);
        assert_eq!(loaded.warnings.len(), 1);
    }

    #[test]
    fn missing_directory_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_pack_dir(&tmp.path().join("does-not-exist")).unwrap();
        assert!(loaded.packs.is_empty());
    }

    #[test]
    fn rejects_non_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("redactors");
        fs::write(&path, "not a directory").unwrap();
        let err = load_pack_dir(&path).unwrap_err();
        assert!(err.to_string().contains("not a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinked_files_and_rejects_symlinked_root() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("symlinked.yaml");
        fs::write(
            &target,
            "name: symlinked\nversion: 1.0.0\nrules:\n  - id: x\n    regex: 'X+'\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, tmp.path().join("symlinked.yaml")).unwrap();
        assert!(load_pack_dir(tmp.path()).unwrap().packs.is_empty());

        let link = tmp.path().join("linked-dir");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(
            load_pack_dir(&link)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
    }

    #[test]
    fn skips_oversized_files() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "tiny.yaml",
            "name: tiny\nversion: 1.0.0\nrules:\n  - id: t\n    regex: 'T+'\n",
        );
        let huge = format!(
            "name: huge\nversion: 1.0.0\ndescription: {}\nrules:\n  - id: h\n    regex: 'H+'\n",
            "x".repeat(MAX_PACK_FILE_BYTES as usize + 1)
        );
        write(tmp.path(), "huge.yaml", &huge);
        let loaded = load_pack_dir(tmp.path()).unwrap();
        assert_eq!(loaded.packs.len(), 1);
        assert_eq!(loaded.packs[0].name, "tiny");
    }
}
