//! Files an AI coding agent must read through Veloci Redactor.
//!
//! The `agent` section of a configuration names the files in a project that
//! agents must never read directly: they read the redacted output of
//! `veloci redact` instead. The section only records which files those
//! are; the agent skills and hooks that act on it live outside this crate.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::files::FileGlobs;

/// The `agent` section of a configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Path globs, relative to the directory holding the configuration, of
    /// files agents must read redacted. See [`FileGlobs`] for the syntax.
    pub protected: Vec<String>,
    /// Path globs that are never protected, even when `protected` matches.
    pub exclude: Vec<String>,
    /// Block agents' direct reads of protected files where the agent supports
    /// it, instead of only instructing them.
    pub enforce: bool,
}

/// The compiled `agent` section, anchored at a project directory. Its
/// patterns follow [`FileGlobs`].
#[derive(Debug, Clone)]
pub struct AgentPolicy {
    files: FileGlobs,
    enforce: bool,
}

impl AgentPolicy {
    /// Compile `config` with its paths relative to `base`, which should be
    /// absolute.
    pub fn new(config: &AgentConfig, base: impl Into<PathBuf>) -> Self {
        Self {
            files: FileGlobs::new(&config.protected, &config.exclude, base),
            enforce: config.enforce,
        }
    }

    /// The directory patterns are relative to.
    pub fn base(&self) -> &Path {
        self.files.base()
    }

    /// Whether direct reads of protected files should be blocked.
    pub fn enforce(&self) -> bool {
        self.enforce
    }

    /// Whether an agent must read `path` redacted.
    ///
    /// A relative `path` is taken from the current directory. The path is
    /// checked both as written and with symbolic links resolved, so a link
    /// to a protected file is protected, and so is a protected link. Paths
    /// outside the project directory are never protected.
    pub fn is_protected(&self, path: &Path) -> bool {
        self.files.matches(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(protected: &[&str], exclude: &[&str]) -> AgentPolicy {
        let config = AgentConfig {
            protected: protected.iter().map(|s| s.to_string()).collect(),
            exclude: exclude.iter().map(|s| s.to_string()).collect(),
            enforce: false,
        };
        AgentPolicy::new(&config, "/project")
    }

    fn protected(policy: &AgentPolicy, path: &str) -> bool {
        policy.is_protected(&Path::new("/project").join(path))
    }

    #[test]
    fn a_bare_name_matches_at_any_depth() {
        let p = policy(&[".env*", "*.pem"], &[]);
        assert!(protected(&p, ".env"));
        assert!(protected(&p, ".env.production"));
        assert!(protected(&p, "services/api/.env"));
        assert!(protected(&p, "certs/server.pem"));
        assert!(!protected(&p, "src/env.rs"));
    }

    #[test]
    fn a_pattern_with_a_slash_is_anchored() {
        let p = policy(&["config/prod.yml", "/data/*.csv"], &[]);
        assert!(protected(&p, "config/prod.yml"));
        assert!(!protected(&p, "app/config/prod.yml"));
        assert!(protected(&p, "data/users.csv"));
        assert!(!protected(&p, "data/2026/users.csv"));
    }

    #[test]
    fn a_directory_pattern_covers_its_contents() {
        let p = policy(&["secrets/", "dumps/**"], &[]);
        assert!(protected(&p, "secrets/a.txt"));
        assert!(protected(&p, "nested/secrets/a/b.txt"));
        assert!(protected(&p, "dumps/2026/db.sql"));
        assert!(!protected(&p, "nested/dumps/db.sql"));
    }

    #[test]
    fn exclusions_win() {
        let p = policy(&[".env*"], &[".env.example"]);
        assert!(protected(&p, ".env"));
        assert!(!protected(&p, ".env.example"));
    }

    #[test]
    fn dot_dot_cannot_escape_a_match() {
        let p = policy(&[".env"], &[]);
        assert!(protected(&p, "src/../.env"));
        assert!(protected(&p, "./.env"));
    }

    #[test]
    fn paths_outside_the_project_are_not_protected() {
        let p = policy(&["*"], &[]);
        assert!(!p.is_protected(Path::new("/elsewhere/.env")));
        assert!(!p.is_protected(Path::new("/project")));
    }
}
