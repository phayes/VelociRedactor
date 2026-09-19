//! What the commands share: finding and loading configurations, and small
//! helpers.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, mpsc};
use std::thread;

use anyhow::{Context, Result};
use clap::Args;
use ignore::overrides::OverrideBuilder;
use ignore::{DirEntry, WalkBuilder};
use rayon::iter::{ParallelBridge, ParallelIterator};
use velociredactor::agent::AgentPolicy;
use velociredactor::config::Config;
use velociredactor::detect::DetectorConfig;
use velociredactor::files::{FileGlobs, FileKeyPaths};
use velociredactor::{Allow, Redactor};

/// Environment variable naming a configuration file that replaces the
/// built-in one when `--config` is omitted.
pub const CONFIG_ENV: &str = "VELOCIREDACTOR_CONFIG";

/// Names accepted for a discovered configuration file, in preference order.
pub const CONFIG_FILE_NAMES: [&str; 2] = ["veloci.yml", "VELOCI.yml"];

/// Directories of dependencies and build output, never worth looking inside
/// for a project's own secrets.
pub const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
];

/// The configuration file, from `--config`, `$VELOCIREDACTOR_CONFIG`, or
/// a `veloci.yml` found by walking from the current directory.
#[derive(Debug, Clone, Args)]
pub struct ConfigArg {
    /// Configuration file, replacing the built-in one.
    ///
    /// `--config` wins over `$VELOCIREDACTOR_CONFIG`. When both are omitted,
    /// `veloci.yml` or `VELOCI.yml` is looked for in the
    /// current directory and its parents.
    #[arg(short, long, value_name = "FILE", env = CONFIG_ENV)]
    pub config: Option<PathBuf>,
}

impl ConfigArg {
    /// The file `--config` or `$VELOCIREDACTOR_CONFIG` named, if either did.
    pub fn explicit_path(&self) -> Option<&Path> {
        self.config.as_deref().filter(|p| !p.as_os_str().is_empty())
    }

    /// The file that will be used: `--config` or `$VELOCIREDACTOR_CONFIG`
    /// if either named one, otherwise a discovered file, otherwise none
    /// (the built-in configuration).
    pub fn resolved_path(&self) -> Result<Option<PathBuf>> {
        if let Some(path) = self.explicit_path() {
            return Ok(Some(path.to_owned()));
        }
        discover_config()
    }

    /// Like [`ConfigArg::resolved_path`], but discovering from `start`
    /// rather than the current directory.
    pub fn resolved_path_from(&self, start: &Path) -> Option<PathBuf> {
        if let Some(path) = self.explicit_path() {
            return Some(path.to_owned());
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        discover_from(start, home.as_deref())
    }

    /// Like [`ConfigArg::resolved_path_from`], with discoveries shared
    /// between calls.
    pub fn resolved_path_cached(
        &self,
        start: &Path,
        discoveries: &mut Discoveries,
    ) -> Option<PathBuf> {
        match self.explicit_path() {
            Some(path) => Some(path.to_owned()),
            None => discoveries.discover(start),
        }
    }

    /// The rules to apply, in order: `--config`, `$VELOCIREDACTOR_CONFIG`,
    /// a discovered file, or the built-in configuration.
    pub fn load(&self) -> Result<Config> {
        match self.resolved_path()? {
            Some(path) => Ok(Config::from_path(path)?),
            None => Ok(Config::builtin().clone()),
        }
    }
}

/// A `veloci.yml` or `VELOCI.yml` found by walking from the current
/// directory, if one is in reach.
fn discover_config() -> Result<Option<PathBuf>> {
    let cwd = std::env::current_dir().context("determining the current directory")?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    Ok(discover_from(&cwd, home.as_deref()))
}

/// Walk from `start` toward the filesystem root looking for a configuration
/// file.
///
/// Each directory is searched for [`CONFIG_FILE_NAMES`] before deciding
/// whether to go further. The walk stops at the first file found, a git
/// repository root (a `.git` file or directory), the home directory when
/// `start` is inside it, or the filesystem root.
fn discover_from(start: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        match discover_in(dir, home) {
            Discovery::Found(path) => return Some(path),
            Discovery::Stop => return None,
            Discovery::Parent => dir = dir.parent()?,
        }
    }
}

/// What configuration discovery makes of one directory.
enum Discovery {
    /// The directory holds this configuration file.
    Found(PathBuf),
    /// The walk ends here with nothing found.
    Stop,
    /// The walk goes on to the parent directory.
    Parent,
}

fn discover_in(dir: &Path, home: Option<&Path>) -> Discovery {
    for name in CONFIG_FILE_NAMES {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Discovery::Found(candidate);
        }
    }
    // Worktrees and some submodules keep `.git` as a file; a normal clone
    // keeps it as a directory. Either one is the repository root. The walk
    // reaches the home directory only when it started inside it.
    let at_git_root = dir.join(".git").exists();
    let at_home_root = home.is_some_and(|home| dir == home);
    if at_git_root || at_home_root || dir.parent().is_none() {
        Discovery::Stop
    } else {
        Discovery::Parent
    }
}

/// [`discover_from`] for many starting directories, remembering the answer
/// for every directory it passes through.
pub struct Discoveries {
    home: Option<PathBuf>,
    found: HashMap<PathBuf, Option<PathBuf>>,
}

impl Discoveries {
    pub fn new() -> Self {
        Discoveries {
            home: std::env::var_os("HOME").map(PathBuf::from),
            found: HashMap::new(),
        }
    }

    pub fn discover(&mut self, start: &Path) -> Option<PathBuf> {
        let mut passed = Vec::new();
        let mut dir = start;
        let found = loop {
            if let Some(found) = self.found.get(dir) {
                break found.clone();
            }
            passed.push(dir.to_path_buf());
            match discover_in(dir, self.home.as_deref()) {
                Discovery::Found(path) => break Some(path),
                Discovery::Stop => break None,
                Discovery::Parent => match dir.parent() {
                    Some(parent) => dir = parent,
                    None => break None,
                },
            }
        };
        for dir in passed {
            self.found.insert(dir, found.clone());
        }
        found
    }
}

/// The nearest directory at or above `start` holding `.git`.
pub fn git_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// The `agent` section of `config`, loaded from `path`, anchored at the
/// directory holding it.
pub fn anchored_policy(config: &Config, path: &Path) -> Result<Option<AgentPolicy>> {
    let Some(agent) = &config.agent else {
        return Ok(None);
    };
    let base =
        std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    let base = base.parent().unwrap_or(Path::new("/"));
    Ok(Some(AgentPolicy::new(agent, base)))
}

pub fn build_redactor(config: &Config) -> Result<Redactor> {
    let (redactor, warnings) = config.redactor()?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Ok(redactor)
}

/// What one configuration file makes of the files it covers.
pub struct Rules {
    pub redactor: Redactor,
    pub allow: Allow,
    /// Its `allow.files`, anchored at its directory.
    pub allowed_files: FileGlobs,
    /// Its `allow.file_paths`, anchored at its directory.
    pub allowed_file_paths: FileKeyPaths,
    /// Its `agent` section, anchored at its directory.
    pub agent: Option<AgentPolicy>,
}

impl Rules {
    /// The redactor for the file at `path`, or for standard input when
    /// `None`: with the key paths `allow.file_paths` names for the file
    /// left unscanned.
    pub fn redactor_for(&self, path: Option<&Path>) -> Cow<'_, Redactor> {
        let key_paths = path.map_or_else(Vec::new, |path| self.allowed_file_paths.for_file(path));
        if key_paths.is_empty() {
            Cow::Borrowed(&self.redactor)
        } else {
            Cow::Owned(self.redactor.with_allow_paths(key_paths))
        }
    }

    /// The allow list for the file at `path`, or for standard input when
    /// `None`: everything, when `allow.files` names the file.
    pub fn allow_for(&self, path: Option<&Path>) -> &Allow {
        static ALL: LazyLock<Allow> = LazyLock::new(Allow::all);
        match path {
            Some(path) if self.allowed_files.matches(path) => &ALL,
            _ => &self.allow,
        }
    }
}

/// The directory `allow.files` and `allow.file_paths` of the configuration
/// loaded from `path` are relative to; empty for the built-in configuration,
/// which allows no files.
fn config_base(path: Option<&Path>) -> Result<PathBuf> {
    let Some(path) = path else {
        return Ok(PathBuf::new());
    };
    let absolute =
        std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    Ok(absolute.parent().unwrap_or(Path::new("/")).to_owned())
}

/// The `allow.files` of `config`, loaded from `path`, anchored at the
/// directory holding it; the built-in configuration's when `path` is `None`.
pub fn allowed_files(config: &Config, path: Option<&Path>) -> Result<FileGlobs> {
    Ok(config.allowed_files(config_base(path)?))
}

/// The `allow.file_paths` of `config`, loaded from `path`, anchored at the
/// directory holding it; the built-in configuration's when `path` is `None`.
pub fn allowed_file_paths(config: &Config, path: Option<&Path>) -> Result<FileKeyPaths> {
    Ok(config.allowed_file_paths(config_base(path)?)?)
}

/// The rules of the configuration at `path`, or of the built-in
/// configuration, without the `privacy_filter` detector when `skip_model`.
fn load_rules(path: Option<&Path>, skip_model: bool) -> Result<Rules> {
    let load = || -> Result<Rules> {
        let mut config = match path {
            Some(path) => Config::from_path(path)?,
            None => Config::builtin().clone(),
        };
        if skip_model {
            config
                .detectors
                .retain(|detector| !matches!(detector, DetectorConfig::PrivacyFilter(_)));
        }
        let agent = match path {
            // The built-in configuration never chooses agent files.
            Some(path) => anchored_policy(&config, path)?,
            None => None,
        };
        Ok(Rules {
            redactor: build_redactor(&config)?,
            allow: config.allow()?,
            allowed_files: allowed_files(&config, path)?,
            allowed_file_paths: allowed_file_paths(&config, path)?,
            agent,
        })
    };
    match path {
        Some(path) => load().with_context(|| format!("loading {}", path.display())),
        None => load(),
    }
}

/// A configuration's rules, or why they could not be loaded.
type LoadedRules = Arc<OnceLock<Result<Arc<Rules>, String>>>;

/// Rules for files that may each find a different configuration, shared
/// between threads. Each configuration is loaded once, when first needed.
pub struct RulesCache {
    config: ConfigArg,
    /// Whether to leave out the `privacy_filter` detector, which is too slow
    /// for a quick look at a whole project.
    skip_model: bool,
    discoveries: Mutex<Discoveries>,
    /// By configuration file, `None` for the built-in one.
    rules: Mutex<HashMap<Option<PathBuf>, LoadedRules>>,
}

impl RulesCache {
    pub fn new(config: ConfigArg) -> Self {
        RulesCache {
            config,
            skip_model: false,
            discoveries: Mutex::new(Discoveries::new()),
            rules: Mutex::new(HashMap::new()),
        }
    }

    /// Leave out the `privacy_filter` detector when `skip` is true.
    pub fn skip_model(mut self, skip: bool) -> Self {
        self.skip_model = skip;
        self
    }

    /// The rules for a file in `directory`, which should be absolute, or for
    /// standard input when `None`. A configuration that cannot be loaded is
    /// a [`Fatal`] error.
    pub fn for_directory(&self, directory: Option<&Path>) -> Result<Arc<Rules>> {
        let path = match directory {
            None => self.config.resolved_path()?,
            Some(directory) => {
                let mut discoveries = self.discoveries.lock().unwrap_or_else(|e| e.into_inner());
                self.config
                    .resolved_path_cached(directory, &mut discoveries)
            }
        };
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        let loaded = rules.entry(path.clone()).or_default().clone();
        drop(rules);
        // Other threads wanting the same rules wait here while they load.
        let loaded = loaded.get_or_init(|| {
            load_rules(path.as_deref(), self.skip_model)
                .map(Arc::new)
                .map_err(|err| format!("{err:#}"))
        });
        match loaded {
            Ok(rules) => Ok(rules.clone()),
            Err(err) => Err(Fatal(err.clone()).into()),
        }
    }

    /// The rules for the file at `path`.
    pub fn for_file(&self, path: &Path) -> Result<Arc<Rules>> {
        let absolute =
            std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
        self.for_directory(Some(absolute.parent().unwrap_or(Path::new("/"))))
    }
}

/// A configuration that could not be loaded. It stops the whole command,
/// where other errors stop only the file they occur in.
#[derive(Debug)]
pub struct Fatal(pub String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

/// How commands that take directories walk them.
pub struct WalkOptions<'a> {
    /// Globs selecting paths; a leading `!` excludes instead.
    pub globs: &'a [String],
    /// Whether to include hidden files and directories.
    pub hidden: bool,
    /// Whether to include files that `.gitignore`, `.ignore` and similar
    /// files exclude.
    pub ignored: bool,
    pub follow: bool,
    pub max_depth: Option<usize>,
    /// Directory names never descended into, at any depth below the root.
    /// Git's own `.git` is always skipped, even with `hidden`.
    pub skipped_dirs: &'static [&'static str],
}

/// A walk of `root` in path order, which the caller may refine further
/// before building.
pub fn walk_builder(root: &Path, options: &WalkOptions<'_>) -> Result<WalkBuilder> {
    let cwd = std::env::current_dir().context("determining the current directory")?;
    let mut overrides = OverrideBuilder::new(&cwd);
    for glob in options.globs {
        overrides
            .add(glob)
            .with_context(|| format!("parsing the glob {glob:?}"))?;
    }
    let skipped_dirs = options.skipped_dirs;
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(!options.hidden)
        .ignore(!options.ignored)
        .git_ignore(!options.ignored)
        .git_global(!options.ignored)
        .git_exclude(!options.ignored)
        .parents(!options.ignored)
        .follow_links(options.follow)
        .max_depth(options.max_depth)
        .overrides(overrides.build().context("parsing --glob")?)
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(move |entry| {
            let name = entry.file_name().to_string_lossy();
            let skipped = entry.file_name() == ".git"
                || (entry.file_type().is_some_and(|t| t.is_dir())
                    && skipped_dirs.contains(&name.as_ref()));
            entry.depth() == 0 || !skipped
        });
    Ok(builder)
}

/// Whether a walk's entry is a file to read: a regular file, or a root the
/// walk was given that leads to one.
pub fn is_file(entry: &DirEntry) -> bool {
    entry.file_type().is_some_and(|t| t.is_file()) || (entry.depth() == 0 && entry.path().is_file())
}

/// `path` as shown to the user: without the `./` of an implicit current
/// directory.
pub fn display_path(path: &Path, implicit_root: bool) -> &Path {
    match path.strip_prefix("./") {
        Ok(stripped) if implicit_root => stripped,
        _ => path,
    }
}

/// Run `work` on each of `items` in parallel, and hand the results to
/// `report` one at a time, in the order of the items.
///
/// Items are drawn as they are needed, so a slow walk feeds the threads as it
/// goes. Setting `stop`, which `work` may do, ends the run early, and so
/// does `report` returning `false` or an error. Results that arrived but
/// could not be reported in order, because an earlier item was skipped by a
/// stop, are returned.
pub fn for_each_ordered<S, T, W>(
    items: impl Iterator<Item = S> + Send,
    stop: &AtomicBool,
    init: impl Fn() -> W + Send + Sync,
    work: impl Fn(&mut W, S) -> T + Send + Sync,
    mut report: impl FnMut(T) -> Result<bool>,
) -> Result<Vec<T>>
where
    S: Send,
    T: Send,
{
    let (sender, receiver) = mpsc::channel::<(usize, T)>();
    thread::scope(|scope| {
        let (init, work) = (&init, &work);
        scope.spawn(move || {
            items
                .take_while(|_| !stop.load(Ordering::Relaxed))
                .enumerate()
                .par_bridge()
                .for_each_init(
                    || (sender.clone(), init()),
                    |(sender, worker), (index, item)| {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let _ = sender.send((index, work(worker, item)));
                    },
                );
        });

        // Hold back results that arrive ahead of their turn.
        let mut early = BTreeMap::new();
        let mut next = 0;
        for (index, result) in &receiver {
            early.insert(index, result);
            while let Some(result) = early.remove(&next) {
                next += 1;
                match report(result) {
                    Ok(true) => {}
                    Ok(false) => {
                        stop.store(true, Ordering::Relaxed);
                        return Ok(Vec::new());
                    }
                    Err(err) => {
                        stop.store(true, Ordering::Relaxed);
                        return Err(err);
                    }
                }
            }
        }
        Ok(early.into_values().collect())
    })
}

pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// `text` quoted for a POSIX shell when it needs to be.
pub fn shell_quote(text: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+=:@%,".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn write_file(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, "found\n").unwrap();
        path
    }

    #[test]
    fn finds_a_config_in_the_starting_directory() {
        let root = tempfile::tempdir().unwrap();
        let want = write_file(root.path(), "veloci.yml");
        assert_eq!(discover_from(root.path(), Some(root.path())), Some(want));
    }

    #[test]
    fn finds_an_uppercase_config_name() {
        let root = tempfile::tempdir().unwrap();
        write_file(root.path(), "VELOCI.yml");
        let found =
            discover_from(root.path(), Some(root.path())).expect("uppercase name is accepted");
        assert!(
            CONFIG_FILE_NAMES
                .iter()
                .any(|name| found.file_name().is_some_and(|n| n == *name)),
            "{found:?}"
        );
        assert_eq!(fs::read_to_string(&found).unwrap(), "found\n");
    }

    #[test]
    fn prefers_the_lowercase_name_when_both_exist() {
        let root = tempfile::tempdir().unwrap();
        let lower = write_file(root.path(), "veloci.yml");
        let upper = root.path().join("VELOCI.yml");
        if upper != lower {
            fs::write(&upper, "other\n").unwrap();
        }
        assert_eq!(discover_from(root.path(), Some(root.path())), Some(lower));
    }

    #[test]
    fn walks_up_to_a_parent() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        let want = write_file(root.path(), "veloci.yml");
        assert_eq!(discover_from(&child, Some(root.path())), Some(want));
    }

    #[test]
    fn prefers_the_closest_file() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        write_file(root.path(), "veloci.yml");
        let want = write_file(&child, "veloci.yml");
        assert_eq!(discover_from(&child, Some(root.path())), Some(want));
    }

    #[test]
    fn ignores_a_directory_with_the_config_name() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        fs::create_dir(child.join("veloci.yml")).unwrap();
        let want = write_file(root.path(), "veloci.yml");
        assert_eq!(discover_from(&child, Some(root.path())), Some(want));
    }

    #[test]
    fn finds_a_config_in_a_git_root() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let src = repo.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        let want = write_file(&repo, "veloci.yml");
        write_file(root.path(), "veloci.yml");
        assert_eq!(discover_from(&src, Some(root.path())), Some(want));
    }

    #[test]
    fn stops_at_a_git_directory() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let src = repo.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        write_file(root.path(), "veloci.yml");
        assert_eq!(discover_from(&src, Some(root.path())), None);
    }

    #[test]
    fn stops_at_a_git_file() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let src = repo.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(repo.join(".git"), "gitdir: /elsewhere/.git/worktrees/x\n").unwrap();
        write_file(root.path(), "veloci.yml");
        assert_eq!(discover_from(&src, Some(root.path())), None);
    }

    #[test]
    fn finds_a_config_in_home() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("home");
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        let want = write_file(&home, "veloci.yml");
        write_file(outer.path(), "veloci.yml");
        assert_eq!(discover_from(&project, Some(&home)), Some(want));
    }

    #[test]
    fn stops_at_home_when_starting_inside_it() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("home");
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        write_file(outer.path(), "veloci.yml");
        assert_eq!(discover_from(&project, Some(&home)), None);
    }

    #[test]
    fn walks_past_home_when_starting_outside_it() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("home");
        let other = outer.path().join("other");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir(&other).unwrap();
        let want = write_file(outer.path(), "veloci.yml");
        assert_eq!(discover_from(&other, Some(&home)), Some(want));
    }

    #[test]
    fn cached_discovery_agrees_with_discover_from() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let nested = repo.join("a/b/c");
        let configured = repo.join("a/configured/d");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(&configured).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        write_file(&repo.join("a/configured"), "veloci.yml");
        write_file(root.path(), "veloci.yml");

        let mut discoveries = Discoveries {
            home: Some(root.path().to_owned()),
            found: Default::default(),
        };
        // Deepest first, so later lookups hit directories already passed.
        for dir in [
            &nested,
            &configured,
            &repo.join("a/b"),
            &repo,
            &repo.join("a/configured"),
        ] {
            assert_eq!(
                discoveries.discover(dir),
                discover_from(dir, Some(root.path())),
                "{dir:?}"
            );
        }
    }

    #[test]
    fn returns_none_when_nothing_is_in_reach() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        assert_eq!(discover_from(&child, Some(root.path())), None);
    }
}
