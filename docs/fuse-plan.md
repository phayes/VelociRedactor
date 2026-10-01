# Plan: `veloci fuse`

Mount a directory through a FUSE filesystem, built on the
[`fuser`](https://crates.io/crates/fuser) crate (0.18). Every read is redacted,
and a write is refused when it would overwrite content that has a secret in it.
An agent, sandbox or tool that works only inside the mountpoint can then never
read a secret, even with its own `cat`, `grep` or editor, and needs no
skill or hook to keep it in line.

```console
veloci fuse MOUNTPOINT [--source DIR] [--config FILE] [--detector NAME] [--comments] ...
```

### The source directory

SOURCE is the real directory the mount mirrors. Every path under MOUNTPOINT
maps to the same relative path under SOURCE. For example, `MOUNTPOINT/config/app.yml` maps to
`SOURCE/config/app.yml`, and each operation on it is carried out on that real file:
reads are redacted, writes are checked, and everything else is passed through. Files are
never copied. SOURCE is also where the rules come from. Each file's configuration
is found from its real directory under SOURCE, the same way as `veloci redact SOURCE/...`
would find it, so a `veloci.yml` at the repository root covers the whole mount.

`--source DIR` chooses it. When it is left out, SOURCE is the Git repository root
holding the current directory, or the current directory outside a repository. This is
the same rule `veloci init` uses (`git_root(cwd).unwrap_or(cwd)`, as in
`project_root`). Running `veloci fuse /tmp/proj-redacted` from anywhere in a
repository therefore mounts the whole repository.

## 1. Semantics

### Classification

Every regular file gets one of these classes. They are worked out from the file's
current content and the rules that apply to it:

| Class       | When                                                                 | Read            | Write / truncate      |
|-------------|----------------------------------------------------------------------|-----------------|-----------------------|
| `excluded`  | `allow.files` matches the path (`Rules::allow_for` → `Allow::all`)  | raw passthrough | allowed               |
| `clean`     | redacting finds nothing that the allow list does not permit         | raw (identical) | allowed               |
| `redacted`  | at least one finding the allow list does not permit                 | redacted view   | **denied**            |
| `binary`    | NUL byte near the start (same test as `scan`)                       | raw passthrough | allowed               |

- The rules are worked out for each file, as `scan` and `grep` do: `RulesCache::for_file`, then
  `Rules::redactor_for(path)` (applies `allow.file_paths`) and
  `Rules::allow_for(path)` (applies `allow.files`). `--config`, `--detector`
  and `--comments` affect the result just as they do for `redact`.
- `--format NAME` / `--raw` work as they do in `redact`, but apply to the whole mount. The
  default is `FormatHint::Path`.
- Every file is redacted as configured, whatever its size. There is no size limit.
  The `agent` section does not narrow what the mount redacts.
- Binary files are passed through. This matches `scan`, `grep` and `githook`. A
  `--redact-binary` flag could raw-redact them later.

### Reads

- `open` + `read` on a `redacted` file serves the bytes from
  `Redaction::render(allow)`. The result is cached (see §3).
- `getattr` has to report the size of the **redacted** content. Otherwise `cat`, `cp`
  and editors would truncate or pad the file. So `getattr` on a regular file classifies
  it, and the result is cached.
- For `redacted` files, `open` replies with `keep_cache = false`, and attr/entry TTLs are
  short (1 s by default) so that changes made outside the mount show up.
- `mmap` works through the page cache, because we do not set `FOPEN_DIRECT_IO`.

### Writes

The rule: **a write is allowed when the file is `excluded`, or when it is `clean`
at the moment it is opened for writing.** Concretely:

- `open` with `O_WRONLY`/`O_RDWR`, `create` on an existing path, `O_TRUNC`,
  `setattr(size)`, and `fallocate` on a `redacted` file return the deny errno
  (§2).
- Each write handle records its decision at `open`. Writes through it go
  straight to the underlying fd. They are not re-checked per write, because that
  would mean re-redacting the whole file on each chunk, which is O(n²).
- After a write handle is released, the cache entry is dropped, so a secret written
  through the mount is redacted on the next read. Reads through an `O_RDWR` handle
  on a file that has since become `redacted` serve the redacted view.
- New files (`create`, `mknod`), `mkdir`, `symlink`: allowed.
- `unlink` and `rmdir` are always allowed, including on `redacted` files.
  Deleting a secret does not reveal it. (Configuration files are the exception;
  see below.)
- **Namespace operations that could leak a secret or destroy one:**
  - `rename`/`link` **onto** a `redacted` file: denied. This would destroy the secret.
    It is the same thing as overwriting it.
  - `rename`/`link` of a `redacted` file **to a path that would make it `excluded`**
    (`allow.files`): denied. Otherwise `mv .env docs/allowed.txt` would reveal the secret.
- **Configuration files are read-only through the mount**, unless it is mounted with
  `--allow-veloci-yml`. Without this, an agent could write `allow: {files: ["*"]}`
  into `veloci.yml` and then read everything.
  - Writes, truncation, rename onto, rename away, and unlink of any
    `veloci.yml`/`VELOCI.yml` (`CONFIG_FILE_NAMES`), and of the resolved `--config`
    file when it lives under SOURCE, are denied.
  - Creating a new `veloci.yml`/`VELOCI.yml` anywhere in the tree is denied, because
    config discovery would pick it up for that subtree.
  - `.git` can never be created, moved or deleted through the mount, even with
    `--allow-veloci-yml`. Config discovery stops at a `.git`, so a new one would
    cut a subtree off from its configuration.
- Optional hardening: deny a write whose buffer contains a redaction token
  (`veloci::find_tokens`). This catches an agent writing `[REDACTED-3]` back
  into a file. The file was `clean` and so no secret is lost, but the token is
  almost always a mistake. This would be off by default, behind `--deny-tokens`.

### Symbolic links

- `readlink` is passed through. A relative link resolves inside the mount and is
  redacted as normal.
- An **absolute** link into SOURCE, such as `/home/u/proj/.env`, would let a reader
  step out of the mount and read the raw file. `readlink` rewrites a target under
  SOURCE so that it points into MOUNTPOINT. Targets outside SOURCE are left as
  they are, because they are outside our scope, the same as reading any file outside
  the mount.
- `symlink` creation is allowed. The rules above still decide reads through the
  mount.

### Other operations

`readdir(plus)`, `statfs`, `chmod`, `chown`, `utimens`, `fsync`, `flush`, and
`setxattr`/`removexattr` (outside the `user.veloci.*` namespace) are passed
through to SOURCE.

## 2. Signalling "denied for redaction" vs. ordinary permission denied

POSIX has no custom errnos. FUSE forwards any errno below 512 unchanged, so the
plan uses several signals together:

1. **Mode bits.** For a `redacted` file, `getattr` reports the mode with every
   write bit cleared, and `access(W_OK)` fails. `ls -l` shows `-r--r--r--`. Editors
   such as vim, VS Code and nano notice before writing and open the file read-only
   or warn. Tools that check `access()` never even try the write. We do not mount
   with `default_permissions`, so the filesystem makes this decision itself (§1).
2. **A configurable errno**, `--deny-errno NAME`. The default is `EACCES`, because
   tools handle it gracefully, and it is what `access(W_OK)` returns for the masked
   mode bits, so the check and the write agree. A user who wants the reason to be clear can choose one
   that ordinary filesystems never return for permissions:
   - `EPERM` ("Operation not permitted"): distinct from `EACCES` but still generic.
   - `EKEYREJECTED` ("Key was rejected by service") or `ENOKEY`
     ("Required key not available"). These are Linux-only, unusual and easy to
     search for. macOS falls back to `EPERM`.

   This would be validated against an allow-list of names, mapped through
   `libc`, and the help text would document what each one prints.
3. **Extended attribute `user.veloci.status`** on every file, read-only:
   `getfattr -n user.veloci.status .env` →
   `redacted: 2 findings (entropy, credentialed_uri); writes denied`, or
   `clean`, `excluded (allow.files)`, `binary`,
   `config file; writes denied`. It also appears in `listxattr`. This gives agents
   and scripts a way to ask *why*. Values are never shown, the same rule as
   `scan` without `--show-value`.
4. **A log.** Each denial is written to stderr, or to `--log FILE`, as
   `veloci: denied write to .env (pid 1234, comm "vim"): holds 2 redacted
   secrets`. FUSE's `Request::pid()` tells us the process, which we can name from
   `/proc/PID/comm`.
5. **A virtual status directory** (optional, `--status-dir NAME`, off by
   default so the tree is not changed): `MOUNT/.veloci/denials` is a ring
   buffer of recent denials, using the same lines as the log. It is read-only and
   is never passed through to SOURCE.

The skill (`plugin/skills/veloci/SKILL.md`) gains a short section explaining how
to read these signals. A write that fails on a mounted tree means the file holds a
secret, and the agent should follow "Editing protected files" (ask the user).

## 3. Architecture

New module `cli/src/fuse/`, compiled only on Unix (`#[cfg(unix)]`) behind a
default-on `fuse` feature of `veloci-cli`:

```
cli/src/fuse/
  mod.rs       FuseArgs (clap), run(): validation, mount, signal handling
  fs.rs        impl fuser::Filesystem for VelociFs — thin, delegates below
  inodes.rs    inode table: ino <-> relative path, lookup counts, rename/unlink upkeep
  view.rs      classify() + content cache; the only place redaction happens
  policy.rs    write/rename/link/create decisions (pure, unit-tested)
  status.rs    xattr text, denial log, optional status directory
```

- **`view.rs`.** `classify(path) -> Arc<View>`, where `View` is
  `{ class, size, bytes: Option<Arc<[u8]>>, findings: Vec<(detector, count)> }`.
  It is keyed by `(dev, ino, size, mtime_ns, ctime_ns)` of the underlying file,
  so changes made outside the mount invalidate it. Rendered bytes are kept in an
  LRU cache bounded by `--cache-size` (default 256M), and only for
  `redacted` files. For other classes we keep only the class. It reuses
  `util::RulesCache` as it is. Configuration is loaded once and reloaded **only on
  SIGHUP**. Edits to `veloci.yml` made outside the mount take effect after
  `kill -HUP`, never by surprise halfway through a session. A reload swaps in a fresh
  `RulesCache`, clears the view cache, and asks the kernel to drop cached attrs and
  pages (`notify_inval_inode`). A configuration that fails to load on SIGHUP is
  logged, and the old one stays in force.
- **`inodes.rs`.** Starts path-based, with an `RwLock<HashMap<u64, PathBuf>>` plus a
  reverse map. The FUSE ino is our own counter, with ino 1 = SOURCE, and `st_ino` from
  disk is passed through in attrs. `rename` re-keys the subtree. Paths are
  stored relative to SOURCE. Every underlying operation goes through a directory
  fd for SOURCE that is opened **before** mounting (`openat`, `fstatat`, `renameat`,
  `unlinkat` and so on, via `rustix`), and never through an absolute path. This is
  what makes it safe to mount inside SOURCE, or over it (§3.1). It also means the mount
  keeps following the same directory if SOURCE is renamed while mounted.
- **Concurrency.** fuser 0.18's `Filesystem` takes `&self`, and on Linux
  `Config { n_threads, clone_fd }` gives it several worker threads. We use
  `n_threads = available_parallelism()`, and the redaction work runs on that
  thread. The `Redactor` is already `Sync`. `getattr` on a large directory
  (`ls -l`) classifies many files, so `readdirplus` may prefetch on rayon.
- **Mounting.** `fuser::spawn_mount` with `MountOption::FSName("veloci")`,
  `Subtype("veloci")`, `DefaultPermissions` *off*, `AutoUnmount`, and
  `--allow-other`/`--allow-root` passed through. The command runs in the
  foreground. It unmounts cleanly on SIGINT/SIGTERM by dropping the
  `BackgroundSession`, and stays up until then or until `fusermount -u`.
  `--read-only` adds `MountOption::RO`.
- **No libfuse.** fuser's default build is pure Rust and mounts through
  `fusermount3`, so we need no C build dependency. At runtime we need the `fuse3`
  package on Linux. When `/dev/fuse` or `fusermount3` is missing, `run()` prints a
  clear error.
- **Later optimization.** For `excluded`/`binary` files, fuser's
  `ReplyOpen::open_backing` / `opened_passthrough` (kernel 6.9+) can hand the
  kernel the real fd, giving native-speed reads. This is **never** used for `clean`
  files, because a secret written later would then bypass us.

### 3.1 Mounting inside SOURCE

`veloci fuse .redacted`, run in a repository, mounts the redacted view at
`REPO/.redacted`. That directory is inside SOURCE, so the mount would contain itself.
Without care, there are two problems:

- **Self-recursion and deadlock.** If our filesystem touched `SOURCE/.redacted`,
  the kernel would send the request back to us, because the path is now our own
  mount. A worker thread would then wait on itself.
- **Infinite trees.** `find` or `rg` inside the mount would see `.redacted/.redacted/...`.

The fix is to **hide the mountpoint from the view.** At startup we record its path
relative to SOURCE, plus its `(dev, ino)` from before mounting:

- `lookup` of that name in its parent returns `ENOENT`, and `readdir(plus)` skips it.
  We therefore never `openat` into it, and recursion cannot happen. Because
  MOUNTPOINT must be empty, hiding it loses nothing.
- `create`, `mkdir`, `symlink`, `link` and `rename` *to* that name return `EEXIST`.
  `rename` of an ancestor directory of it is refused with `EBUSY`. This is what
  the kernel already does for a mountpoint, so it is no surprise.
- The `.veloci` status directory (`--status-dir`) is hidden and reserved in the
  same way.

Tools that walk the **real** tree descend into the mount and see redacted
duplicates. That is safe, but slow and noisy:

- **Git.** `veloci fuse` adds the mountpoint to `.git/info/exclude`, and removes
  it again on unmount, so `git status` stays clean. `--no-git-exclude` turns this off.
- **veloci `scan`/`grep`/`agent status`.** These skip directories whose filesystem
  type is `fuse.veloci` (we set the subtype). We check this once per directory with
  `statfs` and add it to the existing `SKIPPED_DIRS` check. Without this, scanning
  the repository would also scan the redacted copy.
- **Other tools** (IDE indexers, ripgrep): the README tells users to pick a
  name that the project's ignore files already cover, or to add it to them.

**Mounting over SOURCE (`--over`, follow-up).** Because all underlying access goes
through the directory fd opened before mounting, MOUNTPOINT can be SOURCE itself.
We add `MountOption::CUSTOM("nonempty")` when needed. After that, every process
that resolves the repository path, `cd`s into it, or starts there sees only
the redacted view, while veloci still reaches the real files through its fd. Two
caveats go in the help text. A process whose current directory was already inside
SOURCE keeps seeing the real files until it changes directory. And the user has to
unmount to edit secrets.

### Validation in `run()`

- SOURCE (from `--source`, else the Git root, else the current directory) must be a
  directory. MOUNTPOINT must be an empty directory.
- MOUNTPOINT may be inside SOURCE (see §3.1), or SOURCE itself (`--over`).
  Any other case where SOURCE is inside MOUNTPOINT is refused.
- The configuration is loaded once up front, so that a bad config fails before mounting
  (as `config validate` does).

## 4. CLI surface

```text
veloci fuse [OPTIONS] MOUNTPOINT
        --source DIR       Directory to mirror (default: Git root, else current dir)
        --no-git-exclude   Don't add a mountpoint inside the repo to .git/info/exclude
    -c, --config FILE      Configuration file (default: found per file)
        --detector NAME    Also run this disabled detector (repeatable)
        --comments         Also scan comments
    -f, --format NAME      Treat every file as this format
        --raw              Treat every file as plain text
        --deny-errno NAME  Error for denied writes: EACCES (default), EPERM, EKEYREJECTED
        --deny-tokens      Refuse writes containing a redaction token
        --allow-veloci-yml Allow changing configuration files through the mount
        --read-only        Refuse all writes
        --allow-other      Let other users access the mount
        --status-dir NAME  Serve recent denials in this virtual directory
        --log FILE         Write denials here instead of standard error
```

`ConfigArg` and `EnableArg` from `util.rs` are flattened in, as `scan` and `grep`
do. On non-Unix platforms the subcommand still parses, but exits 2 with
"`veloci fuse` needs FUSE, which is not available on Windows". This keeps the
help and manual the same on every platform.

## 5. Threat model (for the README)

The mount is only a boundary when the reader cannot reach SOURCE directly. A
mount inside SOURCE (§3.1) is convenient, but `cat ../.env` from inside it reaches
the raw file. It is a guard-rail, unless the sandbox exposes only the mountpoint. Put
the agent in a container, user namespace, bubblewrap sandbox or separate user
that sees only MOUNTPOINT. Use `--allow-other` when the reader is another
user. Without that, the mount is a guard-rail of the same strength as the
`enforce` hook: it stops accidental reads, but cannot stop a determined process
that knows the real path.

## 6. Implementation steps

1. **Dependencies.** `fuser = "0.18"` (default features) and `libc` in
   `cli/Cargo.toml` under `[target.'cfg(unix)'.dependencies]`, behind a
   default-on `fuse` feature. Check that `cargo build` still works on the Windows and
   macOS targets in `dist-workspace.toml`.
2. **`view.rs` + `policy.rs` with unit tests, before any FUSE code.**
   Classification over a temp dir, using real configs: `allow.files`, `file_paths`,
   binary, and config-file detection. Write, rename
   and link decisions get a table-driven test.
3. **`inodes.rs`** with tests for lookup/forget counts and rename re-keying.
4. **`fs.rs`.** Read-only operations first (`lookup`, `getattr`, `readdir(plus)`,
   `open`, `read`, `release`, `readlink`, `statfs`, `getxattr`, `listxattr`,
   `access`). Ship `--read-only` at this point as a usable milestone.
5. **The write path.** `create`, `write`, `setattr`, `fallocate`, `mkdir`,
   `mknod`, `unlink`, `rmdir`, `symlink`, `rename`, `link`, `flush`, `fsync`,
   `setxattr`, `removexattr`, with the decisions from `policy.rs`.
6. **Signals.** Mode-bit masking, `--deny-errno`, xattr, log, optional status dir.
7. **Integration tests** (`cli/tests/fuse.rs`, `#[cfg(target_os = "linux")]`).
   Each test skips with a message when `/dev/fuse` or `fusermount3` is missing.
   They mount a temp dir with `veloci fuse` in the background and cover:
   - `cat` shows tokens, `stat` size equals the redacted length, `grep secret` finds nothing.
   - Appending to a clean file works, and the next read redacts a secret written that way.
   - `open(O_WRONLY)`, `O_TRUNC` and `truncate` on a secret file fail with the
     configured errno, and the mode shows no write bits.
   - Editor-style write-temp-then-rename onto a clean file works, but onto a secret file fails.
   - `mv .env allowed/` (an `allow.files` path) fails, while `mv .env other-name` works.
   - Writing or creating `veloci.yml` fails.
   - `getfattr -n user.veloci.status` gives the expected text.
   - An absolute symlink into SOURCE resolves inside the mount.
   - Mount at `SOURCE/.redacted`: the mount does not list itself, `find` inside it
     terminates, `git status` in SOURCE is clean, and `veloci scan SOURCE` skips it.
   - `--over`: after mounting, `cat SOURCE/.env` shows tokens.
   - An external edit to SOURCE shows up within the TTL.
   - Deleting a file with secrets works.
   - An external edit to `veloci.yml` changes nothing until SIGHUP, and takes effect after it.
8. **CI.** Add `sudo apt-get install -y fuse3` to the Linux job in
   `.github/workflows/rust.yml`. GitHub's Ubuntu runners expose `/dev/fuse`.
9. **Docs.** A README section ("Mount a redacted view") plus a command-reference
   entry. `veloci man` embeds the README. Also: an `after_long_help` with examples,
   a note in `plugin/skills/veloci/SKILL.md` (and its `cli/skills` copy), and the
   threat model from §5.
10. **macOS (follow-up).** Test against macFUSE 4 and FUSE-T. fuser's
    pure-Rust mount on macOS may need the `libfuse` feature or
    `macfuse-4-compat`. Gate it behind a feature until it is verified, and keep
    Linux as the supported platform for the first release.

## 7. Risks

- **Cost of `getattr`.** `ls -l` and IDE indexers stat everything, and each stat
  of an uncached file redacts it. This is mitigated by the cache keyed on file
  identity, and parallel `readdirplus` prefetch. Very large files are redacted in
  full the first time they are touched, and the rendered copy counts against
  `--cache-size`.
- **Size changes under a reader.** When a secret is written through the mount, or
  outside it, the redacted size changes. Short TTLs and dropping the cache on
  release keep this bounded. Tools that held an old size may see a short read
  once.
- **Write-check race.** The check happens at open. A process with a write handle
  opened while the file was clean can keep writing after the file gains a secret,
  and can overwrite the secret it just added. This is accepted: the secret came in
  through that same handle, so no pre-existing secret is lost.
- **Format detection by path.** A rename can change the format, for example
  `x.txt` → `x.json`, and so change the findings. This is fine, because the cache key
  includes the inode, and the path is re-read on lookup.

## 8. Decisions

1. `unlink`/`rmdir` are always allowed, even on files with secrets, because deleting
   a secret does not reveal it. There is no `--deny-unlink`. Configuration files are
   still protected (§1).
2. There is no size limit. Every file is redacted, whatever its size.
3. There is no `--protected-only`. The mount redacts as configured.
4. Configuration is reloaded only on SIGHUP.
5. The default `--deny-errno` is `EACCES`, which agrees with `access(W_OK)`.
6. Configuration files can be changed through the mount only with
   `--allow-veloci-yml`. `.git` stays protected even then.

## 9. Not yet implemented

- `--over` (mounting over SOURCE itself).
- `readdirplus` prefetch, and kernel passthrough for excluded and binary files.
- macOS.
