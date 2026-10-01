//! Which changes the mount refuses, and why.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

use super::view::{Class, View};
use crate::util::CONFIG_FILE_NAMES;

/// Why a change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The file holds this many redacted values.
    Redacted(usize),
    /// The file could not be redacted.
    Failed,
    /// It would change a configuration file.
    Config,
    /// It would create, move or delete `.git`, where configuration discovery
    /// stops.
    Git,
    /// Moving or linking it would leave its secrets unredacted at the new
    /// path.
    Reveal,
    /// The write holds a redaction token.
    Token,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Redacted(1) => write!(f, "it holds 1 redacted secret"),
            Reason::Redacted(n) => write!(f, "it holds {n} redacted secrets"),
            Reason::Failed => write!(f, "it could not be redacted"),
            Reason::Config => write!(
                f,
                "veloci.yml files are read-only through the mount (see --allow-veloci-yml)"
            ),
            Reason::Git => write!(
                f,
                ".git cannot be created, moved or deleted through the mount"
            ),
            Reason::Reveal => write!(f, "its secrets would not be redacted at the new path"),
            Reason::Token => write!(f, "the data holds a redaction token"),
        }
    }
}

// Names are compared ignoring case: on a case-insensitive filesystem,
// configuration discovery finds `Veloci.yml` as `veloci.yml`. On a
// case-sensitive one this refuses a little more than it must.

/// Whether an entry called `name` decides which configuration applies:
/// a configuration file, or `.git`, where configuration discovery stops.
pub fn is_config_name(name: &OsStr) -> bool {
    is_git(name) || is_config_file_name(name)
}

/// Whether `name` is `.git`, in any case.
pub fn is_git(name: &OsStr) -> bool {
    name.eq_ignore_ascii_case(".git")
}

fn is_config_file_name(name: &OsStr) -> bool {
    CONFIG_FILE_NAMES
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

/// Whether `path`, relative to the source directory, is a configuration
/// file: named like one, or `config`, the one named on the command line.
pub fn is_config_path(path: &Path, config: Option<&Path>) -> bool {
    config.is_some_and(|c| c.as_os_str().eq_ignore_ascii_case(path))
        || path.file_name().is_some_and(is_config_file_name)
}

/// Whether the file whose view is `view` may be overwritten or truncated.
pub fn may_write(view: &View) -> Result<(), Reason> {
    match view.class {
        Class::Redacted => Err(Reason::Redacted(view.redacted())),
        Class::Failed(_) => Err(Reason::Failed),
        Class::Excluded | Class::Clean | Class::Binary => Ok(()),
    }
}

/// Whether a file classified `before` at its old path may become one
/// classified `after` at a new path.
pub fn may_move(before: &Class, after: &Class) -> Result<(), Reason> {
    match (before, after) {
        (Class::Redacted, Class::Redacted) => Ok(()),
        (Class::Redacted, _) => Err(Reason::Reveal),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn view(class: Class, n: usize) -> View {
        let mut findings = BTreeMap::new();
        if n > 0 {
            findings.insert("entropy".to_owned(), n);
        }
        View {
            class,
            size: 0,
            bytes: None,
            findings,
        }
    }

    #[test]
    fn writes() {
        assert_eq!(may_write(&view(Class::Clean, 0)), Ok(()));
        assert_eq!(may_write(&view(Class::Excluded, 0)), Ok(()));
        assert_eq!(may_write(&view(Class::Binary, 0)), Ok(()));
        assert_eq!(
            may_write(&view(Class::Redacted, 2)),
            Err(Reason::Redacted(2))
        );
        assert_eq!(
            may_write(&view(Class::Failed("x".into()), 0)),
            Err(Reason::Failed)
        );
    }

    #[test]
    fn moves() {
        use Class::*;
        let table = [
            (Redacted, Redacted, true),
            (Redacted, Clean, false),
            (Redacted, Excluded, false),
            (Redacted, Binary, false),
            (Redacted, Failed(String::new()), false),
            (Clean, Excluded, true),
            (Excluded, Clean, true),
            (Clean, Redacted, true),
        ];
        for (before, after, allowed) in table {
            assert_eq!(
                may_move(&before, &after).is_ok(),
                allowed,
                "{before:?} -> {after:?}"
            );
        }
    }

    #[test]
    fn config_names() {
        assert!(is_config_name(OsStr::new("veloci.yml")));
        assert!(is_config_name(OsStr::new("VELOCI.yml")));
        assert!(is_config_name(OsStr::new(".git")));
        assert!(!is_config_name(OsStr::new("veloci.yaml.bak")));
        assert!(is_config_name(OsStr::new("Veloci.YML")));
        assert!(is_config_name(OsStr::new(".GIT")));
        assert!(is_config_path(Path::new("a/veloci.yml"), None));
        assert!(is_config_path(
            Path::new("conf/rules.yml"),
            Some(Path::new("conf/rules.yml"))
        ));
        assert!(!is_config_path(
            Path::new("a/b.yml"),
            Some(Path::new("conf/rules.yml"))
        ));
    }

    #[test]
    fn reasons_read_well() {
        assert_eq!(
            Reason::Redacted(1).to_string(),
            "it holds 1 redacted secret"
        );
        assert_eq!(
            Reason::Redacted(3).to_string(),
            "it holds 3 redacted secrets"
        );
    }
}
