//! The filesystem: every request is answered from the source directory, with
//! reads redacted by [`view`](super::view) and changes checked by
//! [`policy`](super::policy).
//!
//! Every underlying operation goes through a directory fd for the source
//! directory, opened before mounting, and paths relative to it. A mountpoint
//! inside the source directory is left out of the view, so the filesystem
//! never reaches into itself.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, WriteFlags,
};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags, Stat, Timespec, Timestamps, XattrFlags};
use unicode_normalization::UnicodeNormalization;

use super::inodes::{DENIALS, Inodes, ROOT, STATUS_DIR};
use super::policy::{self, Reason, fold, is_config_name, is_config_path, is_git};
use super::status::{self, DenialLog, STATUS_XATTR};
use super::view::{Class, Classifier, Key, View, ViewCache};
use crate::util::Rules;

/// How long the kernel may trust names and attributes. Short, so changes made
/// outside the mount show up quickly.
const TTL: Duration = Duration::from_secs(1);

/// What the filesystem knows. Shared with the thread that reloads the
/// configuration.
pub struct State {
    /// The source directory.
    pub root: OwnedFd,
    /// Its absolute path.
    pub source: PathBuf,
    /// The mountpoint's absolute path.
    pub mountpoint: PathBuf,
    /// The mountpoint relative to the source directory, when inside it.
    pub hidden: Option<PathBuf>,
    /// The `--status-dir` name.
    pub status_dir: Option<OsString>,
    /// `--config`, relative to the source directory, when inside it.
    pub config: Option<PathBuf>,
    pub classifier: RwLock<Arc<Classifier>>,
    pub views: ViewCache,
    pub inodes: Inodes,
    pub log: DenialLog,
    /// The error refused writes fail with.
    pub deny: Errno,
    pub deny_tokens: bool,
    /// Whether configuration files may be changed through the mount.
    pub allow_config: bool,
    /// Directory listings of case-insensitive directories, for
    /// [`State::on_disk_name`].
    names: Mutex<HashMap<PathBuf, (Key, FoldedNames)>>,
    handles: Mutex<HashMap<u64, Arc<Handle>>>,
    next_handle: AtomicU64,
}

/// A directory's entry names by their lowercase form.
type FoldedNames = HashMap<String, Vec<OsString>>;

/// An open file or directory.
enum Handle {
    File(OpenFile),
    Dir(Vec<(OsString, FileType, u64)>),
    Denials(Vec<u8>),
}

struct OpenFile {
    file: File,
    path: PathBuf,
    /// Whether it was opened for writing, which was checked then.
    writable: bool,
    /// The view last served, and the contents it was made from.
    view: Mutex<Option<(Key, Arc<View>)>>,
}

/// Why a request fails: an error, or a refusal to report.
enum Refusal {
    Errno(Errno),
    Reason(Reason),
}

impl From<Errno> for Refusal {
    fn from(err: Errno) -> Self {
        Refusal::Errno(err)
    }
}

impl From<Reason> for Refusal {
    fn from(reason: Reason) -> Self {
        Refusal::Reason(reason)
    }
}

fn errno(err: rustix::io::Errno) -> Errno {
    Errno::from_i32(err.raw_os_error())
}

fn io_errno(err: io::Error) -> Errno {
    Errno::from(err)
}

/// `path` as an argument relative to the source directory's fd.
fn at(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

impl State {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: OwnedFd,
        source: PathBuf,
        mountpoint: PathBuf,
        hidden: Option<PathBuf>,
        status_dir: Option<OsString>,
        config: Option<PathBuf>,
        classifier: Classifier,
        cache_size: u64,
        log: DenialLog,
        deny: Errno,
        deny_tokens: bool,
        allow_config: bool,
    ) -> Self {
        State {
            root,
            source,
            mountpoint,
            hidden,
            status_dir,
            config,
            classifier: RwLock::new(Arc::new(classifier)),
            views: ViewCache::new(cache_size),
            inodes: Inodes::new(),
            log,
            deny,
            deny_tokens,
            allow_config,
            names: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    pub fn classifier(&self) -> Arc<Classifier> {
        self.classifier
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Use `classifier` from now on, forgetting everything classified before.
    pub fn reload(&self, classifier: Classifier) {
        *self.classifier.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(classifier);
        self.views.clear();
        let handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        for handle in handles.values() {
            if let Handle::File(file) = &**handle {
                *file.view.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
        }
    }

    fn abs(&self, path: &Path) -> PathBuf {
        self.source.join(path)
    }

    fn path(&self, ino: INodeNo) -> Result<PathBuf, Errno> {
        self.inodes.path(ino.0).ok_or(Errno::ENOENT)
    }

    fn child(&self, parent: INodeNo, name: &OsStr) -> Result<PathBuf, Errno> {
        if parent.0 == STATUS_DIR || parent.0 == DENIALS {
            return Err(Errno::EPERM);
        }
        let dir = self.path(parent)?;
        let name = self.on_disk_name(&dir, name);
        Ok(dir.join(name))
    }

    /// The name the entry `name` in the directory `dir` has on disk, when it
    /// exists.
    ///
    /// On a case-insensitive filesystem the kernel may ask for `DOCS/env`
    /// when the directory is `docs`. Everything that judges a path, such as
    /// `allow.files`, must see the name on disk, or a file could be moved
    /// under a spelling that dodges a rule and then read under the real one.
    fn on_disk_name(&self, dir: &Path, name: &OsStr) -> OsString {
        let Some(text) = name.to_str() else {
            return name.to_owned();
        };
        // Fast path: no other spelling of the name exists, so it is exact.
        // The other spellings tried are the other case and the other Unicode
        // normalization forms.
        let upper = text.to_uppercase();
        let flipped = if upper != text {
            upper
        } else {
            text.to_lowercase()
        };
        let others = [flipped, text.nfc().collect(), text.nfd().collect()];
        if !others
            .iter()
            .any(|other| other != text && self.stat(&dir.join(other)).is_ok())
        {
            return name.to_owned();
        }
        let Ok(dir_stat) = self.stat(dir) else {
            return name.to_owned();
        };
        let key = Key::of(&dir_stat);
        let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        if !names.get(dir).is_some_and(|(k, _)| *k == key) {
            let Ok(listing) = self.raw_list(dir) else {
                return name.to_owned();
            };
            let mut folded = FoldedNames::new();
            for entry in listing {
                folded.entry(fold(&entry)).or_default().push(entry);
            }
            if names.len() >= 4096 {
                names.clear();
            }
            names.insert(dir.to_owned(), (key, folded));
        }
        let (_, folded) = &names[dir];
        let candidates = folded.get(&fold(name)).map_or(&[][..], Vec::as_slice);
        if candidates.iter().any(|c| c == name) {
            return name.to_owned();
        }
        match candidates {
            // Filesystems fold case by their own rules, such as `ß` as `ss`:
            // when no name folds the same way, the entry that is the same
            // file.
            [] => {
                let Ok(target) = self.stat(&dir.join(name)) else {
                    return name.to_owned();
                };
                folded
                    .values()
                    .flatten()
                    .find(|c| {
                        self.stat(&dir.join(c))
                            .is_ok_and(|other| same_file(&other, &target))
                    })
                    .cloned()
                    .unwrap_or_else(|| name.to_owned())
            }
            [only] => only.clone(),
            // Several entries differing only in case: the one that is the
            // same file.
            several => {
                let target = self.stat(&dir.join(name)).ok();
                several
                    .iter()
                    .find(|c| {
                        target.as_ref().is_some_and(|t| {
                            self.stat(&dir.join(c))
                                .is_ok_and(|other| same_file(&other, t))
                        })
                    })
                    .unwrap_or(&several[0])
                    .clone()
            }
        }
    }

    /// The names in the directory `dir`, as they are on disk.
    fn raw_list(&self, dir: &Path) -> Result<Vec<OsString>, Errno> {
        let fd = rfs::openat(
            &self.root,
            at(dir),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        let mut names = Vec::new();
        for entry in rfs::Dir::read_from(&fd).map_err(errno)? {
            let name = OsStr::from_bytes(entry.map_err(errno)?.file_name().to_bytes()).to_owned();
            if name != "." && name != ".." {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Whether `path` is the mountpoint or the status directory, which the
    /// view leaves out.
    fn reserved(&self, path: &Path) -> bool {
        self.hidden.as_deref() == Some(path)
            || self
                .status_dir
                .as_deref()
                .is_some_and(|name| path == Path::new(name))
    }

    fn stat(&self, path: &Path) -> Result<Stat, Errno> {
        rfs::statat(&self.root, at(path), AtFlags::SYMLINK_NOFOLLOW).map_err(errno)
    }

    fn open(&self, path: &Path, flags: OFlags, mode: Mode) -> Result<File, Errno> {
        let fd = rfs::openat(
            &self.root,
            at(path),
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
        .map_err(errno)?;
        Ok(File::from(fd))
    }

    fn handle(&self, fh: FileHandle) -> Result<Arc<Handle>, Errno> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&fh.0)
            .cloned()
            .ok_or(Errno::EBADF)
    }

    fn add_handle(&self, handle: Handle) -> FileHandle {
        let fh = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(fh, Arc::new(handle));
        FileHandle(fh)
    }

    /// The view of the regular file at `path`, whose metadata is `stat`;
    /// `None` when it cannot be read.
    fn view(&self, path: &Path, stat: &Stat) -> Option<Arc<View>> {
        let key = Key::of(stat);
        if let Some(view) = self.views.get(path, &key) {
            return Some(view);
        }
        let classifier = self.classifier();
        if classifier.excluded(&self.abs(path)) {
            let view = Arc::new(View::plain(Class::Excluded, key_size(stat)));
            self.views.insert(path, key, view.clone());
            return Some(view);
        }
        let file = self.open(path, OFlags::RDONLY, Mode::empty()).ok()?;
        self.view_of(path, &file).map(|(_, view)| view)
    }

    /// The view of `file`, open on the regular file at `path`, and the
    /// contents it describes.
    fn view_of(&self, path: &Path, file: &File) -> Option<(Key, Arc<View>)> {
        // A file written while it is read is read again.
        for _ in 0..4 {
            let key = Key::of(&rfs::fstat(file).ok()?);
            if let Some(view) = self.views.get(path, &key) {
                return Some((key, view));
            }
            let classifier = self.classifier();
            let abs = self.abs(path);
            let view = if classifier.excluded(&abs) {
                View::plain(
                    Class::Excluded,
                    rfs::fstat(file).ok().map_or(0, |s| key_size(&s)),
                )
            } else {
                let data = read_all(file).ok()?;
                if Key::of(&rfs::fstat(file).ok()?) != key {
                    continue;
                }
                classifier.classify(&abs, &data)
            };
            let view = Arc::new(view);
            self.views.insert(path, key, view.clone());
            return Some((key, view));
        }
        None
    }

    /// Whether `path` is a configuration file the mount keeps read-only.
    fn is_config(&self, path: &Path) -> bool {
        !self.allow_config && is_config_path(path, self.config.as_deref())
    }

    /// Whether changing what is at `path` changes which configuration
    /// applies, or what it says.
    fn changes_config(&self, path: &Path) -> Result<(), Refusal> {
        if path.file_name().is_some_and(is_git) {
            return Err(Reason::Git.into());
        }
        if self.is_config(path) {
            return Err(Reason::Config.into());
        }
        Ok(())
    }

    /// Whether the file at `path`, if any, may be overwritten or truncated.
    fn may_write(&self, path: &Path) -> Result<(), Refusal> {
        if self.is_config(path) {
            return Err(Reason::Config.into());
        }
        let Ok(stat) = self.stat(path) else {
            return Ok(());
        };
        if !is_regular(&stat) {
            return Ok(());
        }
        match self.view(path, &stat) {
            Some(view) => policy::may_write(&view).map_err(Refusal::from),
            None => Ok(()),
        }
    }

    /// Whether an entry may be created at `path`.
    fn may_create(&self, path: &Path) -> Result<(), Refusal> {
        if self.reserved(path) {
            return Err(Errno::EEXIST.into());
        }
        self.changes_config(path)
    }

    /// Whether the entry at `path` may be removed or moved away.
    fn may_remove(&self, path: &Path) -> Result<(), Refusal> {
        if self.reserved(path)
            || self
                .hidden
                .as_deref()
                .is_some_and(|hidden| hidden.starts_with(path))
        {
            return Err(Errno::EBUSY.into());
        }
        self.changes_config(path)
    }

    /// Whether moving or linking what is at `from` to `to` keeps every secret
    /// in it redacted.
    fn may_move(&self, from: &Path, to: &Path) -> Result<(), Refusal> {
        let Ok(stat) = self.stat(from) else {
            return Ok(());
        };
        if is_regular(&stat) {
            return self.may_move_file(from, &stat, to, None);
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Ok(());
        }
        let classifier = self.classifier();
        let parent = |p: &Path| self.abs(p.parent().unwrap_or(Path::new("")));
        let fatal = |err: anyhow::Error| {
            eprintln!("veloci: {err:#}");
            Refusal::Errno(Errno::EIO)
        };
        let before = classifier
            .rules
            .for_directory(Some(&parent(from)))
            .map_err(fatal)?;
        let after = classifier
            .rules
            .for_directory(Some(&parent(to)))
            .map_err(fatal)?;
        // The same rules, none of them about particular files: a move
        // changes nothing. Configurations inside the directory move with it.
        if Arc::ptr_eq(&before, &after)
            && after.allowed_files.is_empty()
            && after.allowed_file_paths.is_empty()
        {
            return Ok(());
        }
        self.may_move_tree(from, to, &after)
    }

    /// [`State::may_move`] for each file under the directory `from`, which
    /// would be found at `to` with the rules `after`.
    fn may_move_tree(&self, from: &Path, to: &Path, after: &Rules) -> Result<(), Refusal> {
        let entries = self.list(from).map_err(Refusal::Errno)?;
        // Files below a configuration, or a `.git`, that moves with them
        // keep the same rules.
        if entries.iter().any(|(name, _, _)| is_config_name(name)) {
            return Ok(());
        }
        for (name, kind, _) in entries {
            let (from, to) = (from.join(&name), to.join(&name));
            match kind {
                FileType::RegularFile => {
                    if let Ok(stat) = self.stat(&from) {
                        self.may_move_file(&from, &stat, &to, Some(after))?;
                    }
                }
                FileType::Directory => self.may_move_tree(&from, &to, after)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn may_move_file(
        &self,
        from: &Path,
        stat: &Stat,
        to: &Path,
        after: Option<&Rules>,
    ) -> Result<(), Refusal> {
        let Some(view) = self.view(from, stat) else {
            return Ok(());
        };
        if view.class != Class::Redacted {
            return Ok(());
        }
        let file = self.open(from, OFlags::RDONLY, Mode::empty())?;
        let data = read_all(&file).map_err(io_errno)?;
        let classifier = self.classifier();
        let to = self.abs(to);
        let moved = match after {
            Some(rules) => classifier.classify_with(rules, &to, &data),
            None => classifier.classify(&to, &data),
        };
        policy::may_move(&view.class, &moved.class).map_err(Refusal::from)
    }

    /// Report `refusal` of `op` on `path` by process `pid`, and
    /// the error to answer with.
    fn refuse(&self, pid: u32, op: &str, path: &Path, refusal: Refusal) -> Errno {
        match refusal {
            Refusal::Errno(err) => err,
            Refusal::Reason(reason) => {
                self.log.deny(pid, op, path, &reason);
                self.deny
            }
        }
    }

    /// The attributes of the entry at `path`, numbered `ino`, as the mount
    /// shows them.
    fn attr(&self, ino: u64, path: Option<&Path>, stat: &Stat) -> FileAttr {
        let mut attr = file_attr(ino, stat);
        if attr.kind == FileType::RegularFile
            && let Some(path) = path
        {
            if let Some(view) = self.view(path, stat) {
                attr.size = view.size;
                attr.blocks = view.size.div_ceil(512);
                if view.protects() {
                    attr.perm &= !0o222;
                }
            }
            if self.is_config(path) {
                attr.perm &= !0o222;
            }
        }
        attr
    }

    /// Look up `path`, counting a kernel lookup.
    fn entry(&self, path: &Path) -> Result<FileAttr, Errno> {
        let stat = self.stat(path)?;
        let ino = self.inodes.lookup(path);
        Ok(self.attr(ino, Some(path), &stat))
    }

    fn virtual_attr(&self, ino: u64) -> FileAttr {
        let now = SystemTime::now();
        let (kind, perm, size) = if ino == DENIALS {
            (FileType::RegularFile, 0o444, self.log.recent().len() as u64)
        } else {
            (FileType::Directory, 0o555, 0)
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// The entries of the directory at `path`, without `.` and `..` and
    /// without what the view leaves out.
    fn list(&self, path: &Path) -> Result<Vec<(OsString, FileType, u64)>, Errno> {
        let fd = rfs::openat(
            &self.root,
            at(path),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        let mut entries = Vec::new();
        for entry in rfs::Dir::read_from(&fd).map_err(errno)? {
            let entry = entry.map_err(errno)?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes()).to_owned();
            if name == "." || name == ".." {
                continue;
            }
            let child = path.join(&name);
            if self.reserved(&child) {
                continue;
            }
            let kind = match file_type(entry.file_type()) {
                Some(kind) => kind,
                None => match self.stat(&child) {
                    Ok(stat) => mode_type(stat.st_mode),
                    Err(_) => continue,
                },
            };
            let ino = self.inodes.find(&child).unwrap_or(entry.ino());
            entries.push((name, kind, ino));
        }
        Ok(entries)
    }

    /// The `/proc` path of the entry at `path`, for the calls that take no
    /// directory fd.
    fn proc_path(&self, path: &Path) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.root.as_raw_fd())).join(at(path))
    }

    fn status_text(&self, ino: u64) -> Result<String, Errno> {
        if ino == STATUS_DIR || ino == DENIALS {
            return Ok("veloci status".to_owned());
        }
        let path = self.path(INodeNo(ino))?;
        let stat = self.stat(&path)?;
        Ok(match mode_type(stat.st_mode) {
            FileType::RegularFile => {
                status::file_status(self.view(&path, &stat).as_deref(), self.is_config(&path))
            }
            FileType::Directory => "directory".to_owned(),
            FileType::Symlink => "symlink".to_owned(),
            _ => "special file".to_owned(),
        })
    }

    /// Forget what is cached about `path`.
    fn changed(&self, path: &Path) {
        self.views.invalidate(path);
    }
}

impl OpenFile {
    /// The view of the open file's current contents.
    fn current(&self, state: &State) -> Result<(Key, Arc<View>), Errno> {
        let key = Key::of(&rfs::fstat(&self.file).map_err(errno)?);
        let mut cached = self.view.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((k, view)) = &*cached
            && *k == key
        {
            return Ok((key, view.clone()));
        }
        let (key, view) = state.view_of(&self.path, &self.file).ok_or(Errno::EIO)?;
        *cached = Some((key, view.clone()));
        Ok((key, view))
    }

    fn forget_view(&self) {
        *self.view.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn read_all(file: &File) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = vec![0; 1 << 16];
    loop {
        let n = file.read_at(&mut buf, data.len() as u64)?;
        if n == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&buf[..n]);
    }
}

fn read_range(file: &File, offset: u64, size: u32) -> io::Result<Vec<u8>> {
    let mut data = vec![0; size as usize];
    let mut filled = 0;
    while filled < data.len() {
        let n = file.read_at(&mut data[filled..], offset + filled as u64)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    data.truncate(filled);
    Ok(data)
}

/// `path` with its last component as asked for and in both Unicode
/// normalization forms: the names a new entry may get on disk, since some
/// filesystems (HFS+, some network servers) normalize the names they store.
fn spellings(path: &Path) -> Vec<PathBuf> {
    let mut spellings = vec![path.to_owned()];
    if let Some(name) = path.file_name().and_then(OsStr::to_str) {
        for other in [name.nfc().collect::<String>(), name.nfd().collect()] {
            let other = path.with_file_name(other);
            if !spellings.contains(&other) {
                spellings.push(other);
            }
        }
    }
    spellings
}

#[allow(clippy::unnecessary_cast)]
fn same_file(a: &Stat, b: &Stat) -> bool {
    a.st_dev as u64 == b.st_dev as u64 && a.st_ino as u64 == b.st_ino as u64
}

fn is_regular(stat: &Stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
}

#[allow(clippy::unnecessary_cast)]
fn key_size(stat: &Stat) -> u64 {
    stat.st_size as u64
}

fn mode_type(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        _ => FileType::RegularFile,
    }
}

fn file_type(kind: rfs::FileType) -> Option<FileType> {
    Some(match kind {
        rfs::FileType::RegularFile => FileType::RegularFile,
        rfs::FileType::Directory => FileType::Directory,
        rfs::FileType::Symlink => FileType::Symlink,
        rfs::FileType::Fifo => FileType::NamedPipe,
        rfs::FileType::Socket => FileType::Socket,
        rfs::FileType::CharacterDevice => FileType::CharDevice,
        rfs::FileType::BlockDevice => FileType::BlockDevice,
        _ => return None,
    })
}

fn time(secs: i64, nsecs: u64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs as u32)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs()) + Duration::from_nanos(nsecs)
    }
}

#[allow(clippy::unnecessary_cast)]
fn file_attr(ino: u64, stat: &Stat) -> FileAttr {
    let ctime = time(stat.st_ctime as i64, stat.st_ctime_nsec as u64);
    FileAttr {
        ino: INodeNo(ino),
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: time(stat.st_atime as i64, stat.st_atime_nsec as u64),
        mtime: time(stat.st_mtime as i64, stat.st_mtime_nsec as u64),
        ctime,
        crtime: ctime,
        kind: mode_type(stat.st_mode),
        perm: (stat.st_mode & 0o7777) as u16,
        nlink: stat.st_nlink as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u32,
        blksize: stat.st_blksize as u32,
        flags: 0,
    }
}

/// The flags of an open request worth passing to the underlying file.
fn open_flags(flags: i32) -> OFlags {
    let kept = libc::O_ACCMODE | libc::O_APPEND | libc::O_TRUNC | libc::O_SYNC | libc::O_DSYNC;
    OFlags::from_bits_retain((flags & kept) as _)
}

fn writes(flags: i32) -> bool {
    flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_TRUNC != 0
}

fn timespec(time: Option<TimeOrNow>) -> Timespec {
    match time {
        None => Timespec {
            tv_sec: 0,
            tv_nsec: rfs::UTIME_OMIT,
        },
        Some(TimeOrNow::Now) => Timespec {
            tv_sec: 0,
            tv_nsec: rfs::UTIME_NOW,
        },
        Some(TimeOrNow::SpecificTime(time)) => match time.duration_since(UNIX_EPOCH) {
            Ok(d) => Timespec {
                tv_sec: d.as_secs() as _,
                tv_nsec: d.subsec_nanos() as _,
            },
            Err(e) => Timespec {
                tv_sec: -(e.duration().as_secs() as i64) as _,
                tv_nsec: 0,
            },
        },
    }
}

/// Answer an xattr request for `data`: its size when `size` is 0.
fn reply_xattr(reply: ReplyXattr, size: u32, data: &[u8]) {
    if size == 0 {
        reply.size(data.len() as u32);
    } else if (size as usize) < data.len() {
        reply.error(Errno::ERANGE);
    } else {
        reply.data(data);
    }
}

/// The FUSE filesystem over [`State`].
pub struct VelociFs {
    pub state: Arc<State>,
    /// Threads for requests that may redact a file.
    pub pool: rayon::ThreadPool,
    /// Called when the session ends, however it ends.
    pub on_destroy: Box<dyn Fn() + Send + Sync>,
}

impl VelociFs {
    /// Answer a request on the pool, so that redacting a large file holds up
    /// only the requests waiting for that file.
    fn spawn(&self, work: impl FnOnce(&State) + Send + 'static) {
        let state = self.state.clone();
        self.pool.spawn(move || work(&state));
    }
}

impl Filesystem for VelociFs {
    fn destroy(&mut self) {
        (self.on_destroy)();
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_owned();
        self.spawn(move |s| {
            let name = name.as_os_str();
            if parent.0 == ROOT && s.status_dir.as_deref() == Some(name) {
                return reply.entry(&TTL, &s.virtual_attr(STATUS_DIR), Generation(0));
            }
            if parent.0 == STATUS_DIR {
                return if name == "denials" {
                    reply.entry(&TTL, &s.virtual_attr(DENIALS), Generation(0))
                } else {
                    reply.error(Errno::ENOENT)
                };
            }
            let path = match s.child(parent, name) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            if s.reserved(&path) {
                return reply.error(Errno::ENOENT);
            }
            match s.entry(&path) {
                Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                Err(err) => reply.error(err),
            }
        });
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.state.inodes.forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        self.spawn(move |s| {
            if ino.0 == STATUS_DIR || ino.0 == DENIALS {
                return reply.attr(&TTL, &s.virtual_attr(ino.0));
            }
            let path = s.inodes.path(ino.0);
            let result = match (&path, fh.map(|fh| s.handle(fh))) {
                (Some(path), _) => s.stat(path).map(|st| s.attr(ino.0, Some(path), &st)),
                // A deleted file, still open.
                (None, Some(Ok(handle))) => match &*handle {
                    Handle::File(open) => rfs::fstat(&open.file).map_err(errno).map(|st| {
                        let mut attr = file_attr(ino.0, &st);
                        if let Ok((_, view)) = open.current(s) {
                            attr.size = view.size;
                            if view.protects() {
                                attr.perm &= !0o222;
                            }
                        }
                        attr
                    }),
                    _ => Err(Errno::ENOENT),
                },
                (None, _) => Err(Errno::ENOENT),
            };
            match result {
                Ok(attr) => reply.attr(&TTL, &attr),
                Err(err) => reply.error(err),
            }
        });
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let pid = req.pid();
        self.spawn(move |s| {
            let path = match s.path(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            let result = (|| -> Result<(), Refusal> {
                if let Some(size) = size {
                    let open = fh.and_then(|fh| s.handle(fh).ok());
                    match open.as_deref() {
                        // Checked when it was opened.
                        Some(Handle::File(open)) if open.writable => {
                            rfs::ftruncate(&open.file, size).map_err(errno)?;
                            open.forget_view();
                        }
                        _ => {
                            s.may_write(&path)?;
                            let file = s.open(&path, OFlags::WRONLY, Mode::empty())?;
                            rfs::ftruncate(&file, size).map_err(errno)?;
                        }
                    }
                    s.changed(&path);
                }
                if let Some(mode) = mode {
                    let stat = s.stat(&path)?;
                    // Linux cannot change a symbolic link's mode.
                    if mode_type(stat.st_mode) != FileType::Symlink {
                        rfs::chmodat(
                            &s.root,
                            at(&path),
                            Mode::from_raw_mode(mode & 0o7777),
                            AtFlags::empty(),
                        )
                        .map_err(errno)?;
                    }
                }
                if uid.is_some() || gid.is_some() {
                    rfs::chownat(
                        &s.root,
                        at(&path),
                        uid.map(rustix::process::Uid::from_raw),
                        gid.map(rustix::process::Gid::from_raw),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .map_err(errno)?;
                }
                if atime.is_some() || mtime.is_some() {
                    let times = Timestamps {
                        last_access: timespec(atime),
                        last_modification: timespec(mtime),
                    };
                    rfs::utimensat(&s.root, at(&path), &times, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(errno)?;
                }
                Ok(())
            })();
            if let Err(refusal) = result {
                return reply.error(s.refuse(pid, "truncating", &path, refusal));
            }
            match s.stat(&path) {
                Ok(stat) => reply.attr(&TTL, &s.attr(ino.0, Some(&path), &stat)),
                Err(err) => reply.error(err),
            }
        });
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        self.spawn(move |s| {
            let path = match s.path(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            let target = match rfs::readlinkat(&s.root, at(&path), Vec::new()) {
                Ok(target) => PathBuf::from(OsString::from_vec(target.into_bytes())),
                Err(err) => return reply.error(errno(err)),
            };
            // An absolute link into the source directory would lead out of the
            // mount to the unredacted file: it leads to the same file in the
            // mount instead.
            let target = match target.strip_prefix(&s.source) {
                Ok(rest)
                    if target.is_absolute()
                        && !s.hidden.as_deref().is_some_and(|h| rest.starts_with(h)) =>
                {
                    s.mountpoint.join(rest)
                }
                _ => target,
            };
            reply.data(target.as_os_str().as_bytes());
        });
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let s = &self.state;
        let path = match s.child(parent, name) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        if let Err(refusal) = s.may_create(&path) {
            return reply.error(s.refuse(req.pid(), "creating", &path, refusal));
        }
        if let Err(err) = rfs::mknodat(
            &s.root,
            at(&path),
            rfs::FileType::from_raw_mode(mode),
            Mode::from_raw_mode(mode & 0o7777),
            rdev.into(),
        ) {
            return reply.error(errno(err));
        }
        match s.entry(&path) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(err),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let s = &self.state;
        let path = match s.child(parent, name) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        if let Err(refusal) = s.may_create(&path) {
            return reply.error(s.refuse(req.pid(), "creating", &path, refusal));
        }
        if let Err(err) = rfs::mkdirat(&s.root, at(&path), Mode::from_raw_mode(mode & 0o7777)) {
            return reply.error(errno(err));
        }
        match s.entry(&path) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(err),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let s = &self.state;
        let path = match s.child(parent, name) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        if s.reserved(&path) {
            return reply.error(Errno::ENOENT);
        }
        if let Err(refusal) = s.may_remove(&path) {
            return reply.error(s.refuse(req.pid(), "deleting", &path, refusal));
        }
        match rfs::unlinkat(&s.root, at(&path), AtFlags::empty()) {
            Ok(()) => {
                s.inodes.remove(&path);
                s.changed(&path);
                reply.ok();
            }
            Err(err) => reply.error(errno(err)),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let s = &self.state;
        let path = match s.child(parent, name) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        if let Err(refusal) = s.may_remove(&path) {
            return reply.error(s.refuse(req.pid(), "deleting", &path, refusal));
        }
        match rfs::unlinkat(&s.root, at(&path), AtFlags::REMOVEDIR) {
            Ok(()) => {
                s.inodes.remove(&path);
                s.changed(&path);
                reply.ok();
            }
            Err(err) => reply.error(errno(err)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let s = &self.state;
        let path = match s.child(parent, link_name) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        if let Err(refusal) = s.may_create(&path) {
            return reply.error(s.refuse(req.pid(), "creating", &path, refusal));
        }
        if let Err(err) = rfs::symlinkat(target, &s.root, at(&path)) {
            return reply.error(errno(err));
        }
        match s.entry(&path) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(err),
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let pid = req.pid();
        let name = name.to_owned();
        let newname = newname.to_owned();
        self.spawn(move |s| {
            let name = name.as_os_str();
            let newname = newname.as_os_str();
            let (from, to) = match (s.child(parent, name), s.child(newparent, newname)) {
                (Ok(from), Ok(to)) => (from, to),
                (Err(err), _) | (_, Err(err)) => return reply.error(err),
            };
            // On a case-insensitive filesystem `to` may be an entry under another
            // spelling, while the name the file ends up with is the one asked for.
            // Both must pass.
            let asked = to.with_file_name(newname);
            let exchange = flags.contains(RenameFlags::RENAME_EXCHANGE);
            let check = || -> Result<(), Refusal> {
                if s.reserved(&from) {
                    return Err(Errno::ENOENT.into());
                }
                s.may_remove(&from)?;
                if exchange {
                    s.may_remove(&to)?;
                    s.may_move(&to, &from)?;
                } else {
                    s.may_create(&to)?;
                    s.may_create(&asked)?;
                    // Replacing another file overwrites it; renaming a file to
                    // another spelling of its own name does not.
                    let itself = match (s.stat(&from), s.stat(&to)) {
                        (Ok(a), Ok(b)) => same_file(&a, &b),
                        _ => false,
                    };
                    if !itself {
                        s.may_write(&to)?;
                    }
                }
                s.may_move(&from, &to)?;
                for asked in spellings(&asked) {
                    if asked != to {
                        s.may_create(&asked)?;
                        s.may_move(&from, &asked)?;
                    }
                }
                Ok(())
            };
            if let Err(refusal) = check() {
                let op = format!("moving {} to", from.display());
                return reply.error(s.refuse(pid, &op, &asked, refusal));
            }
            match rfs::renameat_with(
                &s.root,
                at(&from),
                &s.root,
                at(&asked),
                rfs::RenameFlags::from_bits_retain(flags.bits()),
            ) {
                Ok(()) => {
                    // The name it has now, which the filesystem decides.
                    let moved = s.child(newparent, newname).unwrap_or(asked);
                    if exchange {
                        s.inodes.exchange(&from, &moved);
                    } else {
                        s.inodes.rename(&from, &moved);
                    }
                    s.changed(&from);
                    s.changed(&to);
                    s.changed(&moved);
                    reply.ok();
                }
                Err(err) => reply.error(errno(err)),
            }
        });
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let pid = req.pid();
        let newname = newname.to_owned();
        self.spawn(move |s| {
            let newname = newname.as_os_str();
            let (from, to) = match (s.path(ino), s.child(newparent, newname)) {
                (Ok(from), Ok(to)) => (from, to),
                (Err(err), _) | (_, Err(err)) => return reply.error(err),
            };
            let check = || -> Result<(), Refusal> {
                if s.is_config(&from) {
                    return Err(Reason::Config.into());
                }
                for to in spellings(&to) {
                    s.may_create(&to)?;
                    s.may_move(&from, &to)?;
                }
                Ok(())
            };
            if let Err(refusal) = check() {
                let op = format!("linking {} to", from.display());
                return reply.error(s.refuse(pid, &op, &to, refusal));
            }
            if let Err(err) = rfs::linkat(&s.root, at(&from), &s.root, at(&to), AtFlags::empty()) {
                return reply.error(errno(err));
            }
            match s.entry(&to) {
                Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                Err(err) => reply.error(err),
            }
        });
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let s = &self.state;
        if ino.0 == DENIALS {
            if flags.acc_mode() != OpenAccMode::O_RDONLY {
                return reply.error(Errno::EACCES);
            }
            let fh = s.add_handle(Handle::Denials(s.log.recent()));
            // Its size changes as refusals come in.
            return reply.opened(fh, FopenFlags::FOPEN_DIRECT_IO);
        }
        let path = match s.path(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        let writable = writes(flags.0);
        if writable && let Err(refusal) = s.may_write(&path) {
            return reply.error(s.refuse(req.pid(), "writing to", &path, refusal));
        }
        let file = match s.open(&path, open_flags(flags.0), Mode::empty()) {
            Ok(file) => file,
            Err(err) => return reply.error(err),
        };
        if writable {
            s.changed(&path);
        }
        let fh = s.add_handle(Handle::File(OpenFile {
            file,
            path,
            writable,
            view: Mutex::new(None),
        }));
        reply.opened(fh, FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.spawn(move |s| {
            let handle = match s.handle(fh) {
                Ok(handle) => handle,
                Err(err) => return reply.error(err),
            };
            let slice = |data: &[u8]| -> Vec<u8> {
                let start = (offset as usize).min(data.len());
                let end = start.saturating_add(size as usize).min(data.len());
                data[start..end].to_vec()
            };
            let open = match &*handle {
                Handle::File(open) => open,
                Handle::Denials(text) => return reply.data(&slice(text)),
                Handle::Dir(_) => return reply.error(Errno::EISDIR),
            };
            for _ in 0..4 {
                let (key, view) = match open.current(s) {
                    Ok(current) => current,
                    Err(err) => return reply.error(err),
                };
                match &view.class {
                    Class::Redacted => {
                        let bytes = view.bytes.as_deref().unwrap_or_default();
                        return reply.data(&slice(bytes));
                    }
                    Class::Failed(_) => return reply.error(Errno::EIO),
                    Class::Excluded | Class::Clean | Class::Binary => {
                        let data = match read_range(&open.file, offset, size) {
                            Ok(data) => data,
                            Err(err) => return reply.error(io_errno(err)),
                        };
                        // Served only if the file did not change while read.
                        match rfs::fstat(&open.file) {
                            Ok(stat) if Key::of(&stat) == key => return reply.data(&data),
                            Ok(_) => open.forget_view(),
                            Err(err) => return reply.error(errno(err)),
                        }
                    }
                }
            }
            reply.error(Errno::EIO);
        });
    }

    fn write(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let s = &self.state;
        let handle = match s.handle(fh) {
            Ok(handle) => handle,
            Err(err) => return reply.error(err),
        };
        let Handle::File(open) = &*handle else {
            return reply.error(Errno::EBADF);
        };
        if !open.writable {
            return reply.error(Errno::EBADF);
        }
        if s.deny_tokens {
            let abs = s.abs(&open.path);
            if let Ok(rules) = s.classifier().rules.for_file(&abs) {
                let redactor = rules.redactor_for(Some(&abs));
                let text = String::from_utf8_lossy(data);
                if veloci::find_tokens(redactor.replacement(), &text)
                    .next()
                    .is_some()
                {
                    let err = s.refuse(req.pid(), "writing to", &open.path, Reason::Token.into());
                    return reply.error(err);
                }
            }
        }
        match open.file.write_all_at(data, offset) {
            Ok(()) => {
                open.forget_view();
                s.changed(&open.path);
                reply.written(data.len() as u32);
            }
            Err(err) => reply.error(io_errno(err)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let s = &self.state;
        let handle = s
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fh.0);
        if let Some(handle) = handle
            && let Handle::File(open) = &*handle
            && open.writable
        {
            s.changed(&open.path);
        }
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let s = &self.state;
        let result = s.handle(fh).and_then(|handle| match &*handle {
            Handle::File(open) if datasync => rfs::fdatasync(&open.file).map_err(errno),
            Handle::File(open) => rfs::fsync(&open.file).map_err(errno),
            _ => Ok(()),
        });
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let s = &self.state;
        let mut entries = vec![
            (OsString::from("."), FileType::Directory, ino.0),
            (OsString::from(".."), FileType::Directory, ROOT),
        ];
        if ino.0 == STATUS_DIR {
            entries.push((OsString::from("denials"), FileType::RegularFile, DENIALS));
        } else {
            let path = match s.path(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            match s.list(&path) {
                Ok(list) => entries.extend(list),
                Err(err) => return reply.error(err),
            }
            if ino.0 == ROOT
                && let Some(name) = &s.status_dir
            {
                entries.push((name.clone(), FileType::Directory, STATUS_DIR));
            }
        }
        let fh = s.add_handle(Handle::Dir(entries));
        reply.opened(fh, FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let handle = match self.state.handle(fh) {
            Ok(handle) => handle,
            Err(err) => return reply.error(err),
        };
        let Handle::Dir(entries) = &*handle else {
            return reply.error(Errno::ENOTDIR);
        };
        for (i, (name, kind, ino)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.state
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fh.0);
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match rfs::fstatvfs(&self.state.root) {
            Ok(st) => reply.statfs(
                st.f_blocks,
                st.f_bfree,
                st.f_bavail,
                st.f_files,
                st.f_ffree,
                st.f_bsize as u32,
                st.f_namemax as u32,
                st.f_frsize as u32,
            ),
            Err(err) => reply.error(errno(err)),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let s = &self.state;
        if name.as_bytes().starts_with(b"user.veloci.") {
            return reply.error(Errno::EPERM);
        }
        let path = match s.path(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        match rfs::lsetxattr(
            s.proc_path(&path),
            name,
            value,
            XattrFlags::from_bits_retain(flags as _),
        ) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(err)),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let name = name.to_owned();
        self.spawn(move |s| {
            let name = name.as_os_str();
            if name == STATUS_XATTR {
                return match s.status_text(ino.0) {
                    Ok(text) => reply_xattr(reply, size, text.as_bytes()),
                    Err(err) => reply.error(err),
                };
            }
            if ino.0 == STATUS_DIR || ino.0 == DENIALS {
                return reply.error(Errno::NO_XATTR);
            }
            let path = match s.path(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            let proc = s.proc_path(&path);
            let mut buf = vec![0; size as usize];
            match rfs::lgetxattr(&proc, name, &mut buf[..]) {
                Ok(n) if size == 0 => reply.size(n as u32),
                Ok(n) => reply.data(&buf[..n]),
                Err(err) => reply.error(errno(err)),
            }
        });
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let s = &self.state;
        let mut names = Vec::new();
        if ino.0 != STATUS_DIR && ino.0 != DENIALS {
            let path = match s.path(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            let proc = s.proc_path(&path);
            let needed = match rfs::llistxattr(&proc, &mut [0u8; 0][..]) {
                Ok(n) => n,
                Err(err) => return reply.error(errno(err)),
            };
            names = vec![0; needed];
            match rfs::llistxattr(&proc, &mut names[..]) {
                Ok(n) => names.truncate(n),
                Err(err) => return reply.error(errno(err)),
            }
        }
        names.extend_from_slice(STATUS_XATTR.as_bytes());
        names.push(0);
        reply_xattr(reply, size, &names);
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let s = &self.state;
        if name.as_bytes().starts_with(b"user.veloci.") {
            return reply.error(Errno::EPERM);
        }
        let path = match s.path(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        match rfs::lremovexattr(s.proc_path(&path), name) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(errno(err)),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        self.spawn(move |s| {
            if ino.0 == STATUS_DIR || ino.0 == DENIALS {
                return if mask.contains(AccessFlags::W_OK) {
                    reply.error(Errno::EACCES)
                } else {
                    reply.ok()
                };
            }
            let path = match s.path(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            if mask.contains(AccessFlags::W_OK) && s.may_write(&path).is_err() {
                return reply.error(Errno::EACCES);
            }
            match s.stat(&path) {
                Ok(_) => reply.ok(),
                Err(err) => reply.error(err),
            }
        });
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let pid = req.pid();
        let name = name.to_owned();
        self.spawn(move |s| {
            let name = name.as_os_str();
            let path = match s.child(parent, name) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            let check = || -> Result<(), Refusal> {
                s.may_create(&path)?;
                if flags & libc::O_EXCL == 0 {
                    // Opening a file that is already there.
                    s.may_write(&path)?;
                }
                Ok(())
            };
            if let Err(refusal) = check() {
                return reply.error(s.refuse(pid, "creating", &path, refusal));
            }
            let mut oflags = open_flags(flags) | OFlags::CREATE;
            if flags & libc::O_EXCL != 0 {
                oflags |= OFlags::EXCL;
            }
            let file = match s.open(&path, oflags, Mode::from_raw_mode(mode & 0o7777)) {
                Ok(file) => file,
                Err(err) => return reply.error(err),
            };
            let attr = match s.entry(&path) {
                Ok(attr) => attr,
                Err(err) => return reply.error(err),
            };
            s.changed(&path);
            let fh = s.add_handle(Handle::File(OpenFile {
                file,
                path,
                writable: true,
                view: Mutex::new(None),
            }));
            reply.created(&TTL, &attr, Generation(0), fh, FopenFlags::empty());
        });
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let s = &self.state;
        let handle = match s.handle(fh) {
            Ok(handle) => handle,
            Err(err) => return reply.error(err),
        };
        let Handle::File(open) = &*handle else {
            return reply.error(Errno::EBADF);
        };
        if !open.writable {
            return reply.error(Errno::EBADF);
        }
        match rfs::fallocate(
            &open.file,
            rfs::FallocateFlags::from_bits_retain(mode as _),
            offset,
            length,
        ) {
            Ok(()) => {
                open.forget_view();
                s.changed(&open.path);
                reply.ok();
            }
            Err(err) => reply.error(errno(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_cover_both_normalization_forms() {
        let composed = Path::new("docs/caf\u{00e9}");
        let decomposed = Path::new("docs/cafe\u{0301}");
        assert_eq!(spellings(composed), [composed, decomposed]);
        assert_eq!(spellings(decomposed), [decomposed, composed]);
        assert_eq!(
            spellings(Path::new("docs/plain")),
            [Path::new("docs/plain")]
        );
    }
}
