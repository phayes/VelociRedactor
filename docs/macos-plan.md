# Plan: `veloci mount` on macOS (macFUSE, kernel-extension backend)

`veloci mount` currently builds only on Linux. This plan adds macOS support on
top of [macFUSE](https://macfuse.github.io), using its kernel-extension
backend. It is meant to be carried out on a Mac. Nothing here has been run on
macOS yet, so every step ends with something to verify.

Read `docs/mount-plan.md` first for what the command does. Only the FUSE
adapter is platform-specific. `cli/src/mount/view.rs`, `policy.rs`,
`status.rs` and `inodes.rs` hold the rules, and should not need changes
beyond small `cfg`s.

## Goals

- `veloci mount` works on macOS when macFUSE is installed and its system
  extension is allowed.
- **The released binary launches without macFUSE.** We never link libfuse.
  It is loaded at runtime only when `veloci mount` runs, and a missing library
  is a clear error, not a crash at launch.
- Every rule from Linux holds: reads redacted, protected files unwritable,
  reveal checks on moves, configuration and `.git` protected, SIGHUP reload.

Out of scope: macFUSE's FSKit backend, FUSE-T, and `--over`. See "Later" at
the end.

## 1. Dependencies and `cfg`s

In `cli/Cargo.toml`, the `mount` dependencies are under
`[target.'cfg(target_os = "linux")'.dependencies]`. Add a macOS section:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
# macos-no-mount: fuser links no libfuse; we mount ourselves (section 2).
fuser = { version = "0.18", optional = true, features = ["macos-no-mount"] }
libc = { version = "0.2", optional = true }
libloading = { version = "0.8", optional = true }
rustix = { version = "1", features = ["fs", "process"], optional = true }
signal-hook = { version = "0.3", optional = true }
unicode-normalization = { version = "0.1", optional = true }
```

Add `"dep:libloading"` to the `mount` feature. Cargo allows a feature to name an
optional dependency that only exists on some targets.

Without `macos-no-mount`, fuser's build script runs `pkg-config` for macFUSE,
and fails on any Mac without it, CI runners included. With it, fuser builds
anywhere and expects `Session::from_fd`.

In `cli/src/mount/mod.rs`, change every
`#[cfg(all(target_os = "linux", feature = "mount"))]` to
`#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "mount"))]`,
and its negations to match. Do the same in `cli/tests/mount.rs`.

**Verify:** `cargo build` and `cargo clippy --all-targets` on macOS, with
and without macFUSE installed.

## 2. Mounting without linking libfuse

On macOS, fuser uses exactly one libfuse function to mount:
`fuse_mount_compat25(mountpoint, args) -> fd`. Unmounting is
`unmount(2)` (see fuser's `src/mnt/fuse2.rs` and `src/mnt/mod.rs`). We do the
same through `libloading`. Put this in a new `cli/src/mount/macos.rs`, compiled
only on macOS:

1. **Load the library.** Try `$VELOCI_LIBFUSE` if set, then
   `/usr/local/lib/libfuse.2.dylib` and `/usr/local/lib/libfuse.dylib`. That
   is where the macFUSE installer puts them, on Intel and Apple Silicon
   alike. Check that this is still true for the installed macFUSE version. If
   none loads, fail with:
   `veloci mount needs macFUSE: brew install --cask macfuse (https://macfuse.github.io)`,
   exit status 2.
2. **Build the arguments** exactly as fuser's `with_fuse_args` in
   `src/mnt/mod.rs` does: `argv = ["veloci", "-o", OPT, "-o", OPT, ...]` and a
   `#[repr(C)] struct fuse_args { argc: c_int, argv: *const *const c_char, allocated: c_int }`
   with `allocated: 0`. Use the options from `session.rs`, plus these macOS ones:
   - `fsname=veloci:<source>`. This keeps `veloci_mounts()` working (section 4).
   - `volname=veloci <source dir name>`, the name Finder shows.
   - `noappledouble`, so Finder doesn't write `.DS_Store` and `._*` files into
     the source through the mount.
   - `nobrowse`, which keeps the mount out of the Finder sidebar and Spotlight.
   - `allow_other` and `default_permissions` with `--allow-other`, as on Linux.
   - Drop `nodev`/`nosuid` if macFUSE rejects them.
3. **Mount:** `fd = fuse_mount_compat25(mountpoint, &args)`. If `fd < 0`, the
   usual cause is that the system extension is not allowed. Fail with a message
   pointing to
   https://github.com/macfuse/macfuse/wiki/Getting-Started (Apple Silicon:
   allow third-party kernel extensions in Recovery, then approve macFUSE in
   System Settings > Privacy & Security).
4. **Run:** `fuser::Session::from_fd(filesystem, OwnedFd::from_raw_fd(fd), acl, config)`,
   then `.spawn()`. The resulting `BackgroundSession` does not unmount on its
   own, so the stop path in `session.rs` must call `libc::unmount(mountpoint, 0)`
   and then `join()`. Fall back to `MNT_FORCE` if the first attempt reports busy.
5. **Threads:** fuser refuses `n_threads != 1` on macOS. Set
   `config.n_threads = None` and `clone_fd = false` there. The worker pool
   already answers slow requests (`VelociFs::spawn`), so one fuser thread is
   enough.

Keep Linux on `fuser::spawn_mount`. Give `session.rs` a small
`fn mount(filesystem, mountpoint, options) -> Result<Mounted>` with a Linux and
a macOS implementation, where `Mounted` knows how to unmount and join.

**Verify:** the mount appears in `mount` output, `ls` and `cat` work through it,
Ctrl-C unmounts, `umount MOUNTPOINT` from another shell ends the command
cleanly (the `on_destroy` path), and `git status` is clean again afterwards.

## 3. Replacing the Linux-only calls in `fs.rs`

| Linux code today | macOS replacement |
|---|---|
| `State::proc_path` (`/proc/self/fd/N/rel`) for `l*xattr` | `source.join(rel)` with `XATTR_NOFOLLOW`. An absolute path is safe here: a mount inside the source covers only the hidden mountpoint, which never appears in `rel`. Use `libc::getxattr(path, name, buf, size, 0, XATTR_NOFOLLOW)` and its `set`/`list`/`remove` siblings, unless rustix's Apple versions already pass `XATTR_NOFOLLOW` for the `l*` functions (check). |
| `STATUS_XATTR = "user.veloci.status"` and the protected `user.veloci.` prefix | `veloci.status` and `veloci.`, since macOS has no `user.` namespace. Make both `cfg`'d constants in `status.rs`, and use the constant in the `fs.rs` prefix checks instead of the literal. |
| `setxattr`/`getxattr` `position` argument | Pass it through on macOS (resource forks). It is always 0 on Linux. |
| `/proc/PID/comm` in `DenialLog::deny` | `libc::proc_name(pid, buf, len)` |
| `libc::EKEYREJECTED`, `libc::ENOKEY` in `deny_errno` | They don't exist on macOS. Map both to `EPERM`, and note it in the `--deny-errno` help. |
| `rfs::renameat_with(..., flags)` | fuser's `RenameFlags` has no flags on macOS. Use `renameat` when the flags are empty, and `ENOTSUP` otherwise. Leave fuser's macOS-only `exchange` (`exchangedata`) at its default `ENOSYS`. If it is ever implemented, it needs the same checks as `RENAME_EXCHANGE` (`may_remove` and `may_move` both ways). |
| `rfs::fallocate` | Answer `ENOTSUP` on macOS. |
| `rfs::fdatasync` | `fsync` if rustix has no Apple `fdatasync`. |
| `rfs::mknodat` | Check it exists for Apple in rustix. If not, `ENOTSUP`. |
| `libc::O_DSYNC` etc. in `open_flags` | Check each constant exists on macOS. Drop any that don't. |
| `Stat` field types | `Key::of`, `file_attr` and `same_file` already cast every field. Confirm they compile. |

Also in `fs.rs`: `virtual_attr` uses `rustix::process::geteuid`, which is fine.
`statfs` uses `fstatvfs`, also fine.

**Verify:** `cargo clippy --all-targets` is clean on macOS, and
`xattr -p veloci.status MOUNT/.env` prints `redacted: 1 finding ...`.

## 4. Replacing the Linux-only calls in `session.rs`

- **`veloci_mounts()`** reads `/proc/self/mountinfo`. On macOS, use
  `libc::getmntinfo(&mut ptr, MNT_NOWAIT)` and pick entries whose
  `f_mntfromname` starts with `veloci:` (and whose `f_fstypename` is `macfuse`,
  `osxfuse` or `fusefs`; check what macFUSE reports). Return `f_mntonname`.
  `scan`, `grep` and `agent status` then skip a mount inside the repository.
- **Messages and help** mention `fusermount3`. On macOS, say `umount MOUNTPOINT`
  (or `diskutil unmount MOUNTPOINT`). Make the unmount hint in `session.rs` and
  `MOUNT_HELP` in `main.rs` platform-specific, and change the `Mount` command's
  "(Linux)" to "(Linux, and macOS with macFUSE)".

## 5. Things to check on a real Mac

1. **Case sensitivity.** fuser always asks the kernel for
   `FUSE_CASE_INSENSITIVE` on macOS (`INIT_FLAGS` in fuser's `src/lib.rs`), and
   offers no way to turn it off. On the usual case-insensitive APFS volume that
   matches the source. Check:
   - `mv .env DOCS/env` is refused when `docs/` is in `allow.files`.
     `State::on_disk_name` should make this work. The ciopfs test covers it
     on Linux.
   - `Veloci.yml` and `.GIT` are refused.
   - Composed and decomposed `é` resolve to the same entry. APFS is
     normalization-insensitive, and `fold` uses NFC.
   - On a **case-sensitive** APFS volume, two files differing only in case
     both appear and read correctly. If the case-insensitive flag breaks this,
     document that case-sensitive sources are unsupported.
2. **Sizes and modes.** `ls -l MOUNT/.env` shows the redacted size and
   `-r--r--r--`. `cat` shows tokens, never the secret. Open the file in vim and
   TextEdit and check how each reports it as read-only.
3. **Errors.** A refused write fails with `EACCES` by default and `EPERM` with
   `--deny-errno eperm`. Each refusal is logged with the process name from
   `proc_name`.
4. **Kernel notifications.** After `kill -HUP`, `inval_inode` either works
   or fails harmlessly (errors are ignored). Either way, a changed `allow`
   rule shows within about a second (`TTL`).
5. **Finder and system clutter.** Copying a file with Finder through the mount
   leaves no `._*` or `.DS_Store` in the source. Spotlight doesn't index the
   mount (`mdutil -s MOUNT`).
6. **Privacy prompts.** Note any "access files on a removable/network volume"
   prompt in the docs.
7. **Request pid.** The kernel-extension backend should provide the requesting
   pid. Confirm log lines show a real pid and command name.

## 6. Tests

`cli/tests/mount.rs` needs:

- **`cfg`:** `any(target_os = "linux", target_os = "macos")`.
- **`fuse_available()`:** on macOS, the libfuse dylib exists. If a mount still
  fails (extension not allowed), skip with a message rather than fail: start
  the mount, and if the child exits non-zero before mounting, print its log
  and skip.
- **`Mount::mounted()`:** reads `/proc/self/mountinfo`. Replace it on both
  platforms with a portable check: the mountpoint's `st_dev` differs from its
  parent's.
- **`truncate`:** `files_with_secrets_cannot_be_written` runs the `truncate`
  command, which macOS lacks. Keep that line Linux-only. The `set_len` case
  covers it.
- **xattr name:** `status()` reads `user.veloci.status`. Use the `cfg`'d name.
- **Case-insensitive test:** it uses `ciopfs`. On macOS, run it against a
  plain temporary directory when the volume is case-insensitive (create `a`,
  check whether `A` exists), and skip otherwise.
- **macFUSE's own `fusermount3`:** doesn't exist. Make the cleanup in
  `Mount::stop` use `umount` on macOS.

**CI:** GitHub's macOS runners can't load kernel extensions. Add a
`macos-latest` job to `.github/workflows/rust.yml` that runs `cargo build`,
`cargo clippy --all-targets` and `cargo test`. The mount tests skip there,
and the unit tests for the rules still run. The real mount tests are run by
hand on a Mac, as in section 5.

## 7. Docs

- **README.md and cli/README.md** (both): in "Mount a redacted view", add
  macOS. Install with `brew install --cask macfuse`, and allow the system
  extension (link the macFUSE getting-started page). Use
  `xattr -p veloci.status FILE` instead of `getfattr`, and unmount with
  `umount`. In the command reference, mention that `--deny-errno` names
  `EKEYREJECTED`/`ENOKEY` are Linux-only.
- **`plugin/skills/veloci/SKILL.md` and its `cli/skills` copy:** mention
  `xattr -p veloci.status` alongside `getfattr`.
- **`docs/mount-plan.md`:** move macOS out of "Not yet implemented".

## 8. Release

The dist targets already include `aarch64-apple-darwin` and
`x86_64-apple-darwin`, and `mount` is a default feature, so the macOS release
binaries pick this up with no change. Nothing is linked, so Homebrew needs no
dependency on macFUSE. Mention it in the formula's caveats if the tap allows.

**Verify:** a release build runs `veloci --help` and `veloci redact` on a Mac
**without** macFUSE installed, and `veloci mount` there prints the
install message.

## Later

- **FSKit backend** (`-o backend=fskit`, macOS 15.4+, no kernel extension), as
  opt-in `--backend fskit`. Known limits to handle:
  - **`/Volumes` only:** mount at `/Volumes/veloci-<name>`, and offer a
    `.redacted` symlink in the repository.
  - **Files always opened read/write:** decide on the first `write` to each
    handle instead of at `open`.
  - **Attributes reportedly reduced to uid/gid:** add a self-test that mounts,
    checks a known redacted file's size and mode through the mount, and refuses
    to continue on a mismatch.
  - **No notifications, and no request pid.**
- **FUSE-T**, or a local NFS server, if macFUSE proves too much friction.
