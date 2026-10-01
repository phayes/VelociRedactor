//! The mount's inode numbers, each standing for a path relative to the source
//! directory.
//!
//! Numbers are never reused, so the kernel's generation numbers can stay 0.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// The root of the mount: the source directory itself.
pub const ROOT: u64 = 1;
/// The `--status-dir` directory.
pub const STATUS_DIR: u64 = 2;
/// The `denials` file in it.
pub const DENIALS: u64 = 3;
/// The first number handed to a real file.
const FIRST: u64 = 16;

pub struct Inodes {
    inner: RwLock<Inner>,
}

struct Inner {
    by_ino: HashMap<u64, Node>,
    by_path: HashMap<PathBuf, u64>,
    next: u64,
}

struct Node {
    /// `None` once the file is deleted, while the kernel still holds the
    /// number.
    path: Option<PathBuf>,
    /// How many lookups the kernel has not yet forgotten.
    lookups: u64,
}

impl Inodes {
    pub fn new() -> Self {
        let mut by_ino = HashMap::new();
        by_ino.insert(
            ROOT,
            Node {
                path: Some(PathBuf::new()),
                lookups: 1,
            },
        );
        let mut by_path = HashMap::new();
        by_path.insert(PathBuf::new(), ROOT);
        Inodes {
            inner: RwLock::new(Inner {
                by_ino,
                by_path,
                next: FIRST,
            }),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    /// The path `ino` stands for, unless it is unknown or deleted.
    pub fn path(&self, ino: u64) -> Option<PathBuf> {
        self.read().by_ino.get(&ino)?.path.clone()
    }

    /// The number for `path`, counting one more kernel lookup of it.
    pub fn lookup(&self, path: &Path) -> u64 {
        let mut inner = self.write();
        if let Some(&ino) = inner.by_path.get(path) {
            if let Some(node) = inner.by_ino.get_mut(&ino) {
                node.lookups += 1;
            }
            return ino;
        }
        let ino = inner.next;
        inner.next += 1;
        inner.by_ino.insert(
            ino,
            Node {
                path: Some(path.to_owned()),
                lookups: 1,
            },
        );
        inner.by_path.insert(path.to_owned(), ino);
        ino
    }

    /// The number for `path`, if it has one, without counting a lookup.
    pub fn find(&self, path: &Path) -> Option<u64> {
        self.read().by_path.get(path).copied()
    }

    /// The kernel forgets `count` lookups of `ino`.
    pub fn forget(&self, ino: u64, count: u64) {
        if ino < FIRST {
            return;
        }
        let mut inner = self.write();
        let Some(node) = inner.by_ino.get_mut(&ino) else {
            return;
        };
        node.lookups = node.lookups.saturating_sub(count);
        if node.lookups > 0 {
            return;
        }
        if let Some(node) = inner.by_ino.remove(&ino)
            && let Some(path) = node.path
            && inner.by_path.get(&path) == Some(&ino)
        {
            inner.by_path.remove(&path);
        }
    }

    /// The file at `path` is gone.
    pub fn remove(&self, path: &Path) {
        let mut inner = self.write();
        if let Some(ino) = inner.by_path.remove(path)
            && let Some(node) = inner.by_ino.get_mut(&ino)
        {
            node.path = None;
        }
    }

    /// `from`, and everything under it, moved to `to`, replacing whatever
    /// was there.
    pub fn rename(&self, from: &Path, to: &Path) {
        let mut inner = self.write();
        let replaced: Vec<PathBuf> = inner
            .by_path
            .keys()
            .filter(|p| p.starts_with(to))
            .cloned()
            .collect();
        for path in replaced {
            if let Some(ino) = inner.by_path.remove(&path)
                && let Some(node) = inner.by_ino.get_mut(&ino)
            {
                node.path = None;
            }
        }
        let moved: Vec<(PathBuf, u64)> = inner
            .by_path
            .iter()
            .filter(|(p, _)| p.starts_with(from))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        for (path, ino) in moved {
            inner.by_path.remove(&path);
            let rest = path.strip_prefix(from).unwrap_or(Path::new(""));
            let new = if rest.as_os_str().is_empty() {
                to.to_owned()
            } else {
                to.join(rest)
            };
            if let Some(node) = inner.by_ino.get_mut(&ino) {
                node.path = Some(new.clone());
            }
            inner.by_path.insert(new, ino);
        }
    }

    /// `a` and `b`, and everything under them, trade places.
    pub fn exchange(&self, a: &Path, b: &Path) {
        let swap = PathBuf::from("\0veloci-exchange");
        self.rename(a, &swap);
        self.rename(b, a);
        self.rename(&swap, b);
    }

    /// Every number the kernel may hold.
    pub fn all(&self) -> Vec<u64> {
        self.read().by_ino.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups_are_counted_and_forgotten() {
        let inodes = Inodes::new();
        let a = inodes.lookup(Path::new("a"));
        assert_eq!(inodes.lookup(Path::new("a")), a);
        assert_eq!(inodes.path(a).unwrap(), Path::new("a"));
        inodes.forget(a, 1);
        assert_eq!(inodes.path(a).unwrap(), Path::new("a"));
        inodes.forget(a, 1);
        assert!(inodes.path(a).is_none());
        // A new number, never the old one.
        assert_ne!(inodes.lookup(Path::new("a")), a);
        assert_eq!(inodes.path(ROOT).unwrap(), Path::new(""));
        inodes.forget(ROOT, 10);
        assert!(inodes.path(ROOT).is_some());
    }

    #[test]
    fn rename_moves_a_subtree() {
        let inodes = Inodes::new();
        let dir = inodes.lookup(Path::new("d"));
        let file = inodes.lookup(Path::new("d/f"));
        let other = inodes.lookup(Path::new("dx"));
        let target = inodes.lookup(Path::new("e"));
        inodes.rename(Path::new("d"), Path::new("e"));
        assert_eq!(inodes.path(dir).unwrap(), Path::new("e"));
        assert_eq!(inodes.path(file).unwrap(), Path::new("e/f"));
        assert_eq!(inodes.path(other).unwrap(), Path::new("dx"));
        assert!(inodes.path(target).is_none());
        assert_eq!(inodes.find(Path::new("e/f")), Some(file));
        assert_eq!(inodes.find(Path::new("d/f")), None);
    }

    #[test]
    fn exchange_and_remove() {
        let inodes = Inodes::new();
        let a = inodes.lookup(Path::new("a"));
        let b = inodes.lookup(Path::new("b"));
        inodes.exchange(Path::new("a"), Path::new("b"));
        assert_eq!(inodes.path(a).unwrap(), Path::new("b"));
        assert_eq!(inodes.path(b).unwrap(), Path::new("a"));
        inodes.remove(Path::new("a"));
        assert!(inodes.path(b).is_none());
        assert_eq!(inodes.find(Path::new("a")), None);
    }
}
