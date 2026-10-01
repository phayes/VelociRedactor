//! What a file looks like through the mount: the one place redaction happens.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustix::fs::Stat;
use veloci::FormatHint;

use crate::util::{Rules, RulesCache};

/// How a regular file is served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// `allow.files` names it: served as it is, and writable.
    Excluded,
    /// Nothing in it is redacted: served as it is, and writable.
    Clean,
    /// Something in it is redacted: served redacted, and not writable.
    Redacted,
    /// A binary file, served as it is, as `scan` and `grep` skip them.
    Binary,
    /// It could not be redacted, so it cannot be read or written.
    Failed(String),
}

/// A regular file as the mount shows it.
#[derive(Debug)]
pub struct View {
    pub class: Class,
    /// Its size through the mount.
    pub size: u64,
    /// Its redacted contents, for [`Class::Redacted`].
    pub bytes: Option<Arc<[u8]>>,
    /// How many values each detector redacted, for [`Class::Redacted`].
    pub findings: BTreeMap<String, usize>,
}

impl View {
    pub fn plain(class: Class, size: u64) -> Self {
        View {
            class,
            size,
            bytes: None,
            findings: BTreeMap::new(),
        }
    }

    /// Whether writing to the file must be refused.
    pub fn protects(&self) -> bool {
        matches!(self.class, Class::Redacted | Class::Failed(_))
    }

    /// How many values are redacted.
    pub fn redacted(&self) -> usize {
        self.findings.values().sum()
    }
}

/// The identity and version of a file's contents. A file whose key is
/// unchanged has not been written since it was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, u64),
    ctime: (i64, u64),
}

impl Key {
    #[allow(clippy::unnecessary_cast)]
    pub fn of(stat: &Stat) -> Self {
        Key {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            size: stat.st_size as u64,
            mtime: (stat.st_mtime as i64, stat.st_mtime_nsec as u64),
            ctime: (stat.st_ctime as i64, stat.st_ctime_nsec as u64),
        }
    }
}

/// How the format of each file is chosen.
#[derive(Debug, Clone)]
pub enum Hint {
    Path,
    Name(String),
    Raw,
}

/// Classifies files with one set of configurations. Replaced as a whole when
/// the configuration is reloaded.
pub struct Classifier {
    pub rules: RulesCache,
    hint: Hint,
}

impl Classifier {
    pub fn new(rules: RulesCache, hint: Hint) -> Self {
        Classifier { rules, hint }
    }

    /// Whether `allow.files` leaves the file at `path` unredacted. Checked
    /// before reading it, since then nothing needs to be.
    pub fn excluded(&self, path: &Path) -> bool {
        self.rules
            .for_file(path)
            .is_ok_and(|rules| rules.allowed_files.matches(path))
    }

    /// Classify `data` as the contents of the file at `path`, with the rules
    /// found for that path.
    pub fn classify(&self, path: &Path, data: &[u8]) -> View {
        match self.rules.for_file(path) {
            Ok(rules) => self.classify_with(&rules, path, data),
            Err(err) => View::plain(Class::Failed(format!("{err:#}")), 0),
        }
    }

    /// Classify `data` as the contents of the file at `path`, with `rules`.
    pub fn classify_with(&self, rules: &Rules, path: &Path, data: &[u8]) -> View {
        let size = data.len() as u64;
        if rules.allowed_files.matches(path) {
            return View::plain(Class::Excluded, size);
        }
        // As in grep: a NUL byte near the start means a binary file.
        if data[..data.len().min(8192)].contains(&0) {
            return View::plain(Class::Binary, size);
        }
        let hint = match &self.hint {
            Hint::Path => FormatHint::Path(path),
            Hint::Name(name) => FormatHint::Name(name),
            Hint::Raw => FormatHint::Raw,
        };
        let redaction = match rules.redactor_for(Some(path)).redact(data, hint) {
            Ok(redaction) => redaction,
            Err(err) => return View::plain(Class::Failed(err.to_string()), 0),
        };
        let allow = rules.allow_for(Some(path));
        let mut findings = BTreeMap::new();
        for finding in redaction.findings() {
            if !allow.allows(finding) {
                *findings.entry(finding.detector.clone()).or_default() += finding.occurrences;
            }
        }
        if findings.is_empty() {
            return View::plain(Class::Clean, size);
        }
        match redaction.render(allow) {
            Ok(bytes) => View {
                class: Class::Redacted,
                size: bytes.len() as u64,
                bytes: Some(bytes.into()),
                findings,
            },
            Err(err) => View::plain(Class::Failed(err.to_string()), 0),
        }
    }
}

/// Classified files by path, each valid while its [`Key`] is unchanged.
/// Redacted contents are kept within a memory budget, least recently used
/// first out.
pub struct ViewCache {
    inner: Mutex<CacheInner>,
    budget: u64,
}

struct CacheInner {
    entries: HashMap<PathBuf, Entry>,
    /// Bytes of redacted contents held.
    bytes: u64,
    tick: u64,
}

struct Entry {
    key: Key,
    view: Arc<View>,
    used: u64,
}

/// Entries kept at most, whatever their size.
const MAX_ENTRIES: usize = 100_000;

impl ViewCache {
    pub fn new(budget: u64) -> Self {
        ViewCache {
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                bytes: 0,
                tick: 0,
            }),
            budget,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The view of the file at `path`, if it was classified with this key.
    pub fn get(&self, path: &Path, key: &Key) -> Option<Arc<View>> {
        let mut inner = self.lock();
        inner.tick += 1;
        let tick = inner.tick;
        let entry = inner.entries.get_mut(path)?;
        if entry.key != *key {
            return None;
        }
        entry.used = tick;
        Some(entry.view.clone())
    }

    pub fn insert(&self, path: &Path, key: Key, view: Arc<View>) {
        let mut inner = self.lock();
        inner.tick += 1;
        let used = inner.tick;
        let size = held(&view);
        if size > self.budget {
            // Too big to keep: it is redacted again when next needed.
            if let Some(old) = inner.entries.remove(path) {
                inner.bytes -= held(&old.view);
            }
            return;
        }
        if let Some(old) = inner
            .entries
            .insert(path.to_owned(), Entry { key, view, used })
        {
            inner.bytes -= held(&old.view);
        }
        inner.bytes += size;
        while inner.bytes > self.budget || inner.entries.len() > MAX_ENTRIES {
            let want_bytes = inner.bytes > self.budget;
            let Some(victim) = inner
                .entries
                .iter()
                .filter(|(_, e)| !want_bytes || held(&e.view) > 0)
                .min_by_key(|(_, e)| e.used)
                .map(|(p, _)| p.clone())
            else {
                break;
            };
            if let Some(old) = inner.entries.remove(&victim) {
                inner.bytes -= held(&old.view);
            }
        }
    }

    /// Forget the file at `path` and everything under it.
    pub fn invalidate(&self, path: &Path) {
        let mut inner = self.lock();
        let gone: Vec<PathBuf> = inner
            .entries
            .keys()
            .filter(|p| p.starts_with(path))
            .cloned()
            .collect();
        for p in gone {
            if let Some(old) = inner.entries.remove(&p) {
                inner.bytes -= held(&old.view);
            }
        }
    }

    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.entries.clear();
        inner.bytes = 0;
    }
}

fn held(view: &View) -> u64 {
    view.bytes.as_ref().map_or(0, |b| b.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{ConfigArg, EnableArg};
    use std::fs;

    fn classifier(config: Option<&Path>) -> Classifier {
        let arg = ConfigArg {
            config: config.map(Path::to_path_buf),
            enable: EnableArg::default(),
        };
        Classifier::new(RulesCache::new(arg), Hint::Path)
    }

    const SECRET: &[u8] = b"password = \"hunter2-Zx81-Qq7b-Lm42\"\nhost = \"db.internal\"\n";

    #[test]
    fn classifies_by_contents_and_rules() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("veloci.yml");
        fs::write(&config, veloci::config::Config::builtin_source()).unwrap();
        let c = classifier(Some(&config));

        let clean = c.classify(&dir.path().join("a.txt"), b"hello world\n");
        assert_eq!(clean.class, Class::Clean);
        assert_eq!(clean.size, 12);

        let secret = c.classify(&dir.path().join("app.toml"), SECRET);
        assert_eq!(secret.class, Class::Redacted, "{secret:?}");
        assert!(secret.protects());
        let bytes = secret.bytes.as_ref().unwrap();
        assert_eq!(secret.size, bytes.len() as u64);
        assert!(!String::from_utf8_lossy(bytes).contains("hunter2"));

        let binary = c.classify(&dir.path().join("x.bin"), b"\0\x01secret");
        assert_eq!(binary.class, Class::Binary);
    }

    #[test]
    fn allow_files_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("veloci.yml");
        let source = veloci::config::Config::builtin_source().replacen(
            "  files: []",
            "  files: [\"docs/\"]",
            1,
        );
        fs::write(&config, source).unwrap();
        let c = classifier(Some(&config));
        let path = dir.path().join("docs/app.toml");
        assert!(c.excluded(&path));
        assert_eq!(c.classify(&path, SECRET).class, Class::Excluded);
        assert_eq!(
            c.classify(&dir.path().join("app.toml"), SECRET).class,
            Class::Redacted
        );
    }

    fn stat_of(path: &Path) -> Stat {
        rustix::fs::stat(path).unwrap()
    }

    #[test]
    fn cache_is_keyed_by_contents_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "one").unwrap();
        let key = Key::of(&stat_of(&file));
        let cache = ViewCache::new(10);
        let view = |n: usize| {
            Arc::new(View {
                class: Class::Redacted,
                size: n as u64,
                bytes: Some(vec![b'x'; n].into()),
                findings: BTreeMap::new(),
            })
        };
        cache.insert(Path::new("a"), key, view(6));
        assert!(cache.get(Path::new("a"), &key).is_some());
        fs::write(&file, "three").unwrap();
        let changed = Key::of(&stat_of(&file));
        assert!(cache.get(Path::new("a"), &changed).is_none());

        cache.insert(Path::new("b"), key, view(6));
        // Over budget: the least recently used, `a`, goes.
        assert!(cache.get(Path::new("a"), &key).is_none());
        assert!(cache.get(Path::new("b"), &key).is_some());
        // Bigger than the whole budget: not kept.
        cache.insert(Path::new("c"), key, view(11));
        assert!(cache.get(Path::new("c"), &key).is_none());

        cache.invalidate(Path::new(""));
        assert!(cache.get(Path::new("b"), &key).is_none());
    }
}
