//! Mounting: checking the arguments, mounting, reloading on SIGHUP, and
//! unmounting on SIGINT or SIGTERM.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result, bail};
use fuser::{Config, Errno, INodeNo, MountOption, SessionACL};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use super::MountArgs;
use super::fs::{State, VelociFs};
use super::status::DenialLog;
use super::view::{Classifier, Hint};
use crate::util::{RulesCache, git_root};

/// What the main thread waits for.
enum Event {
    Reload,
    Stop,
    Ended,
}

pub fn run(args: MountArgs) -> Result<ExitCode> {
    let cwd = std::env::current_dir().context("determining the current directory")?;
    let source = match &args.source {
        Some(dir) => dir.clone(),
        None => git_root(&cwd).unwrap_or(cwd),
    };
    let source = fs::canonicalize(&source)
        .with_context(|| format!("resolving the source directory {}", source.display()))?;
    if !source.is_dir() {
        bail!("the source {} is not a directory", source.display());
    }
    let mountpoint = fs::canonicalize(&args.mountpoint)
        .with_context(|| format!("resolving the mountpoint {}", args.mountpoint.display()))?;
    if !mountpoint.is_dir() {
        bail!("the mountpoint {} is not a directory", mountpoint.display());
    }
    if fs::read_dir(&mountpoint)?.next().is_some() {
        bail!("the mountpoint {} is not empty", mountpoint.display());
    }
    if source.starts_with(&mountpoint) {
        bail!(
            "the mountpoint {} would hide the source directory {}",
            mountpoint.display(),
            source.display()
        );
    }
    let hidden = mountpoint.strip_prefix(&source).ok().map(Path::to_path_buf);
    if let Some(name) = &args.status_dir {
        let mut components = Path::new(name).components();
        if !matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(_)), None)
        ) {
            bail!("--status-dir {name:?}: expected a plain name such as .veloci");
        }
    }
    let config = match args.config.explicit_path() {
        Some(path) => fs::canonicalize(path)
            .ok()
            .and_then(|p| p.strip_prefix(&source).ok().map(Path::to_path_buf)),
        None => None,
    };
    let hint = match (&args.format, args.raw) {
        (Some(name), _) => Hint::Name(name.clone()),
        (None, true) => Hint::Raw,
        (None, false) => Hint::Path,
    };
    let classifier = load(&args, &source, &hint)?;

    let root: std::os::fd::OwnedFd = fs::File::open(&source)
        .with_context(|| format!("opening {}", source.display()))?
        .into();
    let sink: Box<dyn Write + Send> = match &args.log {
        Some(path) => Box::new(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?,
        ),
        None => Box::new(io::stderr()),
    };
    let state = Arc::new(State::new(
        root,
        source.clone(),
        mountpoint.clone(),
        hidden.clone(),
        args.status_dir.clone(),
        config,
        classifier,
        args.cache_size,
        DenialLog::new(sink),
        deny_errno(&args.deny_errno),
        args.deny_tokens,
        args.allow_veloci_yml,
    ));

    let (events, waiting) = mpsc::channel();
    let ended = events.clone();
    let threads = thread::available_parallelism().map_or(4, |n| n.get().max(4));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("veloci-mount-{i}"))
        .build()
        .context("starting worker threads")?;
    let filesystem = VelociFs {
        state: state.clone(),
        pool,
        on_destroy: Box::new(move || {
            let _ = ended.send(Event::Ended);
        }),
    };

    let mut options = vec![
        MountOption::FSName(format!("veloci:{}", source.display())),
        MountOption::Subtype("veloci".to_owned()),
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    if args.read_only {
        options.push(MountOption::RO);
    }
    let mut config = Config::default();
    if args.allow_other {
        // Other users get their own permissions checked by the kernel.
        options.push(MountOption::DefaultPermissions);
        options.push(MountOption::AutoUnmount);
        config.acl = SessionACL::All;
    }
    config.mount_options = options;
    // Slow requests go to the pool; these threads only read requests and
    // answer the quick ones.
    config.n_threads = Some(2);
    config.clone_fd = true;

    let exclude = if args.no_git_exclude {
        None
    } else {
        hidden.as_ref().and_then(|_| GitExclude::add(&mountpoint))
    };

    let session = match fuser::spawn_mount(filesystem, &mountpoint, &config) {
        Ok(session) => session,
        Err(err) => {
            if let Some(exclude) = exclude {
                exclude.remove();
            }
            return Err(err).with_context(|| {
                format!(
                    "mounting on {} (FUSE needs /dev/fuse and fusermount3, from the fuse3 package)",
                    mountpoint.display()
                )
            });
        }
    };
    eprintln!(
        "veloci: mounted a redacted view of {} on {}",
        source.display(),
        mountpoint.display()
    );
    eprintln!(
        "veloci: unmount with Ctrl-C or `fusermount3 -u {}`; reload the configuration with `kill -HUP {}`",
        mountpoint.display(),
        std::process::id()
    );

    let mut signals = Signals::new([SIGHUP, SIGINT, SIGTERM]).context("handling signals")?;
    let handle = signals.handle();
    thread::spawn(move || {
        for signal in signals.forever() {
            let event = if signal == SIGHUP {
                Event::Reload
            } else {
                Event::Stop
            };
            if events.send(event).is_err() {
                break;
            }
        }
    });

    let notifier = session.notifier();
    let mut stopped = false;
    for event in waiting.iter() {
        match event {
            Event::Reload => match load(&args, &source, &hint) {
                Ok(classifier) => {
                    state.reload(classifier);
                    for ino in state.inodes.all() {
                        // The kernel may not know every number any more.
                        let _ = notifier.inval_inode(INodeNo(ino), 0, 0);
                    }
                    eprintln!("veloci: reloaded the configuration");
                }
                Err(err) => {
                    eprintln!("veloci: keeping the old configuration: {err:#}");
                }
            },
            Event::Stop => {
                stopped = true;
                break;
            }
            Event::Ended => break,
        }
    }
    handle.close();
    let result = if stopped {
        session.umount_and_join()
    } else {
        session.join()
    };
    if let Some(exclude) = exclude {
        exclude.remove();
    }
    result.context("unmounting")?;
    eprintln!("veloci: unmounted {}", mountpoint.display());
    Ok(ExitCode::SUCCESS)
}

/// The configurations, checked by loading the one for the source directory.
fn load(args: &MountArgs, source: &Path, hint: &Hint) -> Result<Classifier> {
    let rules = RulesCache::new(args.config.clone());
    let root_rules = rules.for_directory(Some(source))?;
    if let Hint::Name(name) = hint
        && root_rules.redactor.formats().get(name).is_none()
    {
        bail!("--format {name}: no such format; `veloci formats` lists them");
    }
    Ok(Classifier::new(rules, hint.clone()))
}

fn deny_errno(name: &str) -> Errno {
    Errno::from_i32(match name {
        "EPERM" => libc::EPERM,
        "EKEYREJECTED" => libc::EKEYREJECTED,
        "ENOKEY" => libc::ENOKEY,
        _ => libc::EACCES,
    })
}

/// A line in `.git/info/exclude` that keeps a mountpoint inside the
/// repository out of `git status` while mounted.
struct GitExclude {
    file: PathBuf,
    lines: String,
    /// Whether the file was created for it.
    created: bool,
}

const EXCLUDE_COMMENT: &str = "# veloci mount: a redacted view, while it is mounted";

impl GitExclude {
    fn add(mountpoint: &Path) -> Option<Self> {
        let root = git_root(mountpoint.parent()?)?;
        let git = root.join(".git");
        if !git.is_dir() {
            return None;
        }
        let relative = mountpoint.strip_prefix(&root).ok()?;
        let pattern = format!("/{}/", relative.display());
        let file = git.join("info").join("exclude");
        let created = !file.exists();
        let existing = fs::read_to_string(&file).unwrap_or_default();
        if existing.lines().any(|line| line.trim() == pattern) {
            return None;
        }
        let lines = format!("{EXCLUDE_COMMENT}\n{pattern}\n");
        let mut text = existing;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&lines);
        fs::create_dir_all(file.parent()?).ok()?;
        fs::write(&file, text).ok()?;
        Some(GitExclude {
            file,
            lines,
            created,
        })
    }

    fn remove(self) {
        if let Ok(text) = fs::read_to_string(&self.file)
            && text.contains(&self.lines)
        {
            let text = text.replacen(&self.lines, "", 1);
            let _ = if text.is_empty() && self.created {
                fs::remove_file(&self.file)
            } else {
                fs::write(&self.file, text)
            };
        }
    }
}

/// Mountpoints of `veloci mount` filesystems, which directory walks skip:
/// they hold redacted copies of files that are already being walked.
pub fn veloci_mounts() -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let (fields, rest) = line.split_once(" - ")?;
            // fusermount records the subtype; a mount made directly by root
            // keeps only the source name.
            let mut rest = rest.split(' ');
            let (fstype, name) = (rest.next()?, rest.next()?);
            if fstype != "fuse.veloci" && !(fstype == "fuse" && name.starts_with("veloci:")) {
                return None;
            }
            let mountpoint = fields.split(' ').nth(4)?;
            Some(PathBuf::from(OsStr::from_bytes(&unescape(mountpoint))))
        })
        .collect()
}

/// Undo mountinfo's octal escapes, such as `\040` for a space.
fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && let Some(code) = bytes
                .get(i + 1..i + 4)
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| u8::from_str_radix(digits, 8).ok())
        {
            out.push(code);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_mountinfo() {
        assert_eq!(unescape(r"/tmp/a\040b"), b"/tmp/a b");
        assert_eq!(unescape(r"/tmp/plain"), b"/tmp/plain");
        assert_eq!(unescape(r"/tmp/x\"), b"/tmp/x\\");
    }

    #[test]
    fn git_exclude_comes_and_goes() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/info")).unwrap();
        fs::write(dir.path().join(".git/info/exclude"), "*.log").unwrap();
        let mountpoint = dir.path().join(".redacted");
        fs::create_dir(&mountpoint).unwrap();
        let exclude = GitExclude::add(&mountpoint).unwrap();
        let text = fs::read_to_string(dir.path().join(".git/info/exclude")).unwrap();
        assert!(text.contains("\n/.redacted/\n"), "{text}");
        // Already there: not added twice.
        assert!(GitExclude::add(&mountpoint).is_none());
        exclude.remove();
        let text = fs::read_to_string(dir.path().join(".git/info/exclude")).unwrap();
        assert_eq!(text, "*.log\n");

        fs::remove_file(dir.path().join(".git/info/exclude")).unwrap();
        GitExclude::add(&mountpoint).unwrap().remove();
        assert!(!dir.path().join(".git/info/exclude").exists());
    }
}
