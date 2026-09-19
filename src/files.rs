//! Sets of files named by `.gitignore`-style patterns.
//!
//! The configuration names files in three places: the `agent` section, for
//! files agents must read redacted, `allow.files`, for files never redacted,
//! and `allow.file_paths`, for key paths never scanned in some files. All
//! use [`FileGlobs`].

use std::path::{Component, Path, PathBuf};

use crate::{Error, Glob};

/// Separates the file pattern from the key path in an `allow.file_paths`
/// entry: `config/*.yml#db.password`.
pub const FILE_PATH_SEPARATOR: char = '#';

/// Key paths never scanned in the files matching a pattern, from
/// `allow.file_paths` entries such as `config/*.yml#db.password`.
///
/// The part before the first `#` is a file pattern, as in [`FileGlobs`]; the
/// rest is a key-path glob, as in [`Glob::new`].
#[derive(Debug, Clone, Default)]
pub struct FileKeyPaths {
    entries: Vec<(FileGlobs, String)>,
}

impl FileKeyPaths {
    /// Parse `entries`, with their file patterns relative to `base`, which
    /// should be absolute.
    pub fn new<S: AsRef<str>>(
        entries: impl IntoIterator<Item = S>,
        base: impl Into<PathBuf>,
    ) -> Result<Self, Error> {
        let base = base.into();
        let entries = entries
            .into_iter()
            .map(|entry| {
                let entry = entry.as_ref();
                match entry.split_once(FILE_PATH_SEPARATOR) {
                    Some((file, path)) if !file.trim().is_empty() && !path.trim().is_empty() => {
                        Ok((FileGlobs::new([file], [], base.clone()), path.trim().to_owned()))
                    }
                    _ => Err(Error::Config(format!(
                        "allow.file_paths entry {entry:?} is not FILE{FILE_PATH_SEPARATOR}KEY.PATH, \
                         such as \"config.yml{FILE_PATH_SEPARATOR}db.password\""
                    ))),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    /// The key paths never scanned in the file at `path`.
    pub fn for_file(&self, path: &Path) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(files, _)| files.matches(path))
            .map(|(_, key_path)| key_path.as_str())
            .collect()
    }
}

/// Path patterns anchored at a directory, with exclusions.
///
/// Patterns follow `.gitignore` conventions, with `/` as the separator:
///
/// - a pattern with no `/` matches a file name in any directory (`.env*`,
///   `*.pem`);
/// - a pattern with a `/` matches the path from the base directory, with or
///   without a leading `/` (`config/prod.yml`, `/secrets/**`);
/// - a pattern ending in `/` matches everything under that directory
///   (`secrets/`);
/// - `*` and `?` stay within one path segment, and `**` spans segments.
#[derive(Debug, Clone)]
pub struct FileGlobs {
    base: PathBuf,
    include: Vec<Glob>,
    exclude: Vec<Glob>,
}

impl FileGlobs {
    /// Files matching `include` but not `exclude`, relative to `base`, which
    /// should be absolute.
    pub fn new<S: AsRef<str>>(
        include: impl IntoIterator<Item = S>,
        exclude: impl IntoIterator<Item = S>,
        base: impl Into<PathBuf>,
    ) -> Self {
        let base = base.into();
        Self {
            base: std::fs::canonicalize(&base).unwrap_or(base),
            include: include.into_iter().map(|p| compile(p.as_ref())).collect(),
            exclude: exclude.into_iter().map(|p| compile(p.as_ref())).collect(),
        }
    }

    /// The directory patterns are relative to.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Whether no file can match.
    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
    }

    /// Whether `path` is one of these files.
    ///
    /// A relative `path` is taken from the current directory. The path is
    /// checked both as written and with symbolic links resolved, so a link
    /// to a matching file matches, and so does a matching link. Paths
    /// outside the base directory never match.
    pub fn matches(&self, path: &Path) -> bool {
        if self.is_empty() {
            return false;
        }
        let Ok(absolute) = std::path::absolute(path) else {
            return false;
        };
        let lexical = normalize(&absolute);
        let resolved = std::fs::canonicalize(&absolute).ok();
        std::iter::once(lexical)
            .chain(resolved)
            .any(|candidate| self.matches_absolute(&candidate))
    }

    fn matches_absolute(&self, absolute: &Path) -> bool {
        let Ok(relative) = absolute.strip_prefix(&self.base) else {
            return false;
        };
        let relative: Vec<_> = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect();
        let relative = relative.join("/");
        if relative.is_empty() {
            return false;
        }
        let hit = |globs: &[Glob]| globs.iter().any(|glob| glob.is_match(&relative));
        hit(&self.include) && !hit(&self.exclude)
    }
}

/// Compile one `.gitignore`-style pattern into a path glob.
fn compile(pattern: &str) -> Glob {
    let pattern = pattern.trim();
    // As in `.gitignore`, only a slash before the end anchors a pattern.
    let anchored = pattern.trim_end_matches('/').contains('/');
    let mut pattern = pattern.trim_start_matches('/').to_owned();
    if pattern.ends_with('/') {
        pattern.push_str("**");
    }
    if anchored {
        Glob::path(&pattern)
    } else {
        Glob::path(&format!("**/{pattern}"))
    }
}

/// Remove `.` and resolve `..` without touching the file system.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}
