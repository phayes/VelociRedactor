//! `veloci mount`, mounted for real. Each test is skipped, with a message,
//! where FUSE is not available.

#![cfg(all(target_os = "linux", feature = "mount"))]

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const SECRET: &str = "hunter2-Zx81-Qq7b-Lm42";
const ENV: &str = "DB_PASSWORD=hunter2-Zx81-Qq7b-Lm42\nDEBUG=true\n";
const ENV_REDACTED: &str = "DB_PASSWORD=[REDACTED-1]\nDEBUG=true\n";

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const EEXIST: i32 = 17;

/// The built-in configuration, with `docs/` in `allow.files`.
fn config() -> String {
    include_str!("../../default_config.yml").replacen("  files: []", "  files: [\"docs/\"]", 1)
}

fn fuse_available() -> bool {
    let available = Path::new("/dev/fuse").exists() && on_path("fusermount3");
    if !available {
        eprintln!("skipped: FUSE is not available (needs /dev/fuse and fusermount3)");
    }
    available
}

/// A source directory holding a repository, and a mount of it.
struct Mount {
    dir: tempfile::TempDir,
    mountpoint: PathBuf,
    child: Option<Child>,
    log: PathBuf,
    /// A case-insensitive `ciopfs` mount the source directory is on.
    ciopfs: Option<PathBuf>,
}

impl Mount {
    /// Mount `src` on `mnt`, both in a new directory, with `args`.
    fn new(args: &[&str]) -> Option<Mount> {
        Self::at("mnt", args)
    }

    /// Mount with the mountpoint at `mountpoint`, relative to the new
    /// directory.
    fn at(mountpoint: &str, args: &[&str]) -> Option<Mount> {
        Self::with_source(mountpoint, args, false)
    }

    /// Mount, with the source directory on a case-insensitive filesystem
    /// when `case_insensitive`.
    fn with_source(mountpoint: &str, args: &[&str], case_insensitive: bool) -> Option<Mount> {
        if !fuse_available() {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let ciopfs = if case_insensitive {
            if !on_path("ciopfs") {
                eprintln!("skipped: needs ciopfs for a case-insensitive filesystem");
                return None;
            }
            let back = dir.path().join("back");
            fs::create_dir_all(&back).unwrap();
            fs::create_dir_all(&src).unwrap();
            let status = Command::new("ciopfs")
                .arg(&back)
                .arg(&src)
                .status()
                .unwrap();
            assert!(status.success());
            Some(src.clone())
        } else {
            None
        };
        fs::create_dir_all(src.join(".git/info")).unwrap();
        fs::create_dir_all(src.join("docs")).unwrap();
        fs::write(src.join("veloci.yml"), config()).unwrap();
        fs::write(src.join(".env"), ENV).unwrap();
        fs::write(src.join("readme.txt"), "hello world\n").unwrap();
        let mountpoint = dir.path().join(mountpoint);
        fs::create_dir_all(&mountpoint).unwrap();
        let log = dir.path().join("log");
        let mut mount = Mount {
            child: None,
            mountpoint,
            log,
            dir,
            ciopfs,
        };
        mount.start(args);
        Some(mount)
    }

    fn start(&mut self, args: &[&str]) {
        let child = Command::new(env!("CARGO_BIN_EXE_veloci"))
            .arg("mount")
            .arg(&self.mountpoint)
            .args(args)
            .current_dir(self.src())
            .env_remove("VELOCI_CONFIG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&self.log).unwrap())
            .spawn()
            .unwrap();
        self.child = Some(child);
        let start = Instant::now();
        while !self.mounted() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "not mounted: {}",
                fs::read_to_string(&self.log).unwrap_or_default()
            );
            sleep(Duration::from_millis(50));
        }
    }

    fn mounted(&self) -> bool {
        let mountpoint = fs::canonicalize(&self.mountpoint).unwrap();
        fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.split(' ').nth(4) == Some(mountpoint.to_str().unwrap()))
    }

    fn src(&self) -> PathBuf {
        self.dir.path().join("src")
    }

    fn mnt(&self, path: &str) -> PathBuf {
        self.mountpoint.join(path)
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn signal(&self, signal: &str) {
        let pid = self.child.as_ref().unwrap().id().to_string();
        assert!(
            Command::new("kill")
                .args([signal, &pid])
                .status()
                .unwrap()
                .success()
        );
    }

    /// Unmount, as Ctrl-C does, and wait for the command to finish.
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            self.signal_pid(child.id(), "-INT");
            let start = Instant::now();
            while child.try_wait().unwrap().is_none() {
                if start.elapsed() > Duration::from_secs(20) {
                    let _ = Command::new("fusermount3")
                        .arg("-u")
                        .arg(&self.mountpoint)
                        .status();
                    let _ = child.kill();
                }
                sleep(Duration::from_millis(50));
            }
        }
    }

    fn signal_pid(&self, pid: u32, signal: &str) {
        let _ = Command::new("kill")
            .args([signal, &pid.to_string()])
            .status();
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        self.stop();
        if let Some(path) = &self.ciopfs {
            let _ = Command::new("fusermount3").arg("-u").arg(path).status();
        }
    }
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

fn os_error(result: std::io::Result<impl Sized>) -> i32 {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err.raw_os_error().unwrap(),
    }
}

fn status(path: &Path) -> String {
    let mut buf = vec![0; 512];
    let n = rustix::fs::getxattr(path, "user.veloci.status", &mut buf[..]).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

#[test]
fn reads_are_redacted() {
    let Some(m) = Mount::new(&[]) else { return };
    let env = fs::read_to_string(m.mnt(".env")).unwrap();
    assert_eq!(env, ENV_REDACTED);
    // The size is the redacted one, so tools read exactly that.
    assert_eq!(
        fs::metadata(m.mnt(".env")).unwrap().len(),
        ENV_REDACTED.len() as u64
    );
    assert_eq!(
        fs::read_to_string(m.mnt("readme.txt")).unwrap(),
        "hello world\n"
    );
    let listing: Vec<_> = fs::read_dir(&m.mountpoint)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(listing.contains(&".env".to_owned()), "{listing:?}");
    // The source is untouched.
    assert_eq!(fs::read_to_string(m.src().join(".env")).unwrap(), ENV);
}

#[test]
fn files_with_secrets_cannot_be_written() {
    let Some(m) = Mount::new(&[]) else { return };
    let env = m.mnt(".env");
    let mode = fs::metadata(&env).unwrap().permissions().mode();
    assert_eq!(mode & 0o222, 0, "{mode:o}");
    assert_eq!(
        os_error(fs::OpenOptions::new().append(true).open(&env)),
        EACCES
    );
    assert_eq!(os_error(fs::write(&env, "x")), EACCES);
    assert_eq!(
        os_error(
            fs::OpenOptions::new()
                .write(true)
                .open(&env)
                .and_then(|f| f.set_len(0))
        ),
        EACCES
    );
    assert!(
        !Command::new("truncate")
            .args(["-s", "0"])
            .arg(&env)
            .status()
            .unwrap()
            .success()
    );
    assert!(rustix::fs::access(&env, rustix::fs::Access::WRITE_OK).is_err());
    assert_eq!(fs::read_to_string(m.src().join(".env")).unwrap(), ENV);
    assert!(m.log().contains("denied writing to .env"), "{}", m.log());
    assert_eq!(
        status(&env),
        "redacted: 1 finding (credential_key); writes denied"
    );
}

#[test]
fn deny_errno_chooses_the_error() {
    let Some(m) = Mount::new(&["--deny-errno", "eperm"]) else {
        return;
    };
    assert_eq!(os_error(fs::write(m.mnt(".env"), "x")), EPERM);
}

#[test]
fn clean_files_can_be_written_and_secrets_written_are_redacted() {
    let Some(m) = Mount::new(&[]) else { return };
    let readme = m.mnt("readme.txt");
    assert_eq!(status(&readme), "clean");
    let mut file = fs::OpenOptions::new().append(true).open(&readme).unwrap();
    writeln!(file, "PASSWORD={SECRET}").unwrap();
    drop(file);
    assert!(
        fs::read_to_string(m.src().join("readme.txt"))
            .unwrap()
            .contains(SECRET)
    );
    let shown = fs::read_to_string(&readme).unwrap();
    assert!(!shown.contains(SECRET), "{shown}");
    assert!(shown.contains("[REDACTED-1]"), "{shown}");
    // Now it holds a secret, it is protected like any other.
    assert_eq!(os_error(fs::write(&readme, "x")), EACCES);

    fs::write(m.mnt("new.txt"), "fresh\n").unwrap();
    assert_eq!(
        fs::read_to_string(m.src().join("new.txt")).unwrap(),
        "fresh\n"
    );
}

#[test]
fn replacing_files() {
    let Some(m) = Mount::new(&[]) else { return };
    // As editors save: write a temporary file, then rename it over.
    fs::write(m.mnt("tmp1"), "saved\n").unwrap();
    fs::rename(m.mnt("tmp1"), m.mnt("readme.txt")).unwrap();
    assert_eq!(
        fs::read_to_string(m.src().join("readme.txt")).unwrap(),
        "saved\n"
    );
    fs::write(m.mnt("tmp2"), "saved\n").unwrap();
    assert_eq!(os_error(fs::rename(m.mnt("tmp2"), m.mnt(".env"))), EACCES);
    assert_eq!(fs::read_to_string(m.src().join(".env")).unwrap(), ENV);
}

#[test]
fn moves_that_would_reveal_secrets_are_refused() {
    let Some(m) = Mount::new(&[]) else { return };
    // `docs/` is in `allow.files`.
    assert_eq!(
        os_error(fs::rename(m.mnt(".env"), m.mnt("docs/env"))),
        EACCES
    );
    assert_eq!(
        os_error(fs::hard_link(m.mnt(".env"), m.mnt("docs/env"))),
        EACCES
    );
    fs::create_dir(m.mnt("dir")).unwrap();
    fs::rename(m.mnt(".env"), m.mnt("dir/.env")).unwrap();
    assert_eq!(
        os_error(fs::rename(m.mnt("dir"), m.mnt("docs/dir"))),
        EACCES
    );
    assert_eq!(fs::read_to_string(m.mnt("dir/.env")).unwrap(), ENV_REDACTED);
    // Files without secrets move anywhere.
    fs::rename(m.mnt("readme.txt"), m.mnt("docs/readme.txt")).unwrap();
}

#[test]
fn other_spellings_cannot_dodge_rules_on_case_insensitive_filesystems() {
    let Some(m) = Mount::with_source("mnt", &[], true) else {
        return;
    };
    // `DOCS` is `docs`, which `allow.files` names.
    assert_eq!(
        os_error(fs::rename(m.mnt(".env"), m.mnt("DOCS/env"))),
        EACCES
    );
    assert_eq!(
        os_error(fs::hard_link(m.mnt(".env"), m.mnt("Docs/env"))),
        EACCES
    );
    fs::create_dir(m.mnt("dir")).unwrap();
    fs::rename(m.mnt(".env"), m.mnt("dir/.env")).unwrap();
    assert_eq!(
        os_error(fs::rename(m.mnt("DIR"), m.mnt("DOCS/dir"))),
        EACCES
    );
    // Configuration discovery would find these as `veloci.yml` and `.git`.
    assert_eq!(os_error(fs::write(m.mnt("dir/Veloci.YML"), "x")), EACCES);
    assert_eq!(os_error(fs::create_dir(m.mnt("dir/.GIT"))), EACCES);
    assert!(
        m.log().contains("denied moving .env to docs/env"),
        "{}",
        m.log()
    );
}

#[test]
fn files_with_secrets_can_be_deleted() {
    let Some(m) = Mount::new(&[]) else { return };
    fs::remove_file(m.mnt(".env")).unwrap();
    assert!(!m.src().join(".env").exists());
}

#[test]
fn configuration_cannot_be_changed() {
    let Some(m) = Mount::new(&[]) else { return };
    assert_eq!(os_error(fs::write(m.mnt("veloci.yml"), "x")), EACCES);
    assert_eq!(os_error(fs::remove_file(m.mnt("veloci.yml"))), EACCES);
    assert_eq!(
        os_error(fs::rename(m.mnt("veloci.yml"), m.mnt("old.yml"))),
        EACCES
    );
    fs::create_dir(m.mnt("sub")).unwrap();
    assert_eq!(os_error(fs::write(m.mnt("sub/veloci.yml"), "x")), EACCES);
    assert_eq!(os_error(fs::create_dir(m.mnt("sub/.git"))), EACCES);
    assert_eq!(
        os_error(fs::rename(m.mnt("readme.txt"), m.mnt("sub/VELOCI.yml"))),
        EACCES
    );
    assert_eq!(os_error(fs::remove_dir_all(m.mnt(".git"))), EACCES);
    assert!(status(&m.mnt("veloci.yml")).ends_with("configuration file, writes denied"));
}

#[test]
fn allow_veloci_yml_lets_configuration_change() {
    let Some(m) = Mount::new(&["--allow-veloci-yml"]) else {
        return;
    };
    fs::write(m.mnt("veloci.yml"), config()).unwrap();
    fs::create_dir(m.mnt("sub")).unwrap();
    fs::write(m.mnt("sub/veloci.yml"), config()).unwrap();
    fs::remove_file(m.mnt("sub/veloci.yml")).unwrap();
    assert_eq!(status(&m.mnt("veloci.yml")), "clean");
    // `.git` still decides where configuration discovery stops.
    assert_eq!(os_error(fs::create_dir(m.mnt("sub/.git"))), EACCES);
    // Secrets stay protected.
    assert_eq!(os_error(fs::write(m.mnt(".env"), "x")), EACCES);
}

#[test]
fn absolute_symlinks_stay_in_the_mount() {
    let Some(m) = Mount::new(&[]) else { return };
    symlink(m.src().join(".env"), m.src().join("link")).unwrap();
    let target = fs::read_link(m.mnt("link")).unwrap();
    assert_eq!(
        target,
        fs::canonicalize(&m.mountpoint).unwrap().join(".env")
    );
    assert_eq!(fs::read_to_string(m.mnt("link")).unwrap(), ENV_REDACTED);
}

#[test]
fn changes_outside_the_mount_show_up() {
    let Some(m) = Mount::new(&[]) else { return };
    assert_eq!(
        fs::read_to_string(m.mnt("readme.txt")).unwrap(),
        "hello world\n"
    );
    fs::write(m.src().join("readme.txt"), format!("PASSWORD={SECRET}\n")).unwrap();
    let start = Instant::now();
    loop {
        let shown = fs::read_to_string(m.mnt("readme.txt")).unwrap();
        assert!(!shown.contains(SECRET), "{shown}");
        if shown.contains("[REDACTED-1]") {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{shown}");
        sleep(Duration::from_millis(200));
    }
}

#[test]
fn configuration_reloads_on_sighup_only() {
    let Some(m) = Mount::new(&[]) else { return };
    let allowed = config().replacen("  values: []", &format!("  values: [\"{SECRET}\"]"), 1);
    assert_ne!(allowed, config());
    fs::write(m.src().join("veloci.yml"), allowed).unwrap();
    sleep(Duration::from_millis(1500));
    assert_eq!(fs::read_to_string(m.mnt(".env")).unwrap(), ENV_REDACTED);
    m.signal("-HUP");
    let start = Instant::now();
    while fs::read_to_string(m.mnt(".env")).unwrap() != ENV {
        assert!(start.elapsed() < Duration::from_secs(5), "{}", m.log());
        sleep(Duration::from_millis(200));
    }
    assert!(m.log().contains("reloaded the configuration"));
}

#[test]
fn deny_tokens_refuses_tokens() {
    let Some(m) = Mount::new(&["--deny-tokens"]) else {
        return;
    };
    assert_eq!(
        os_error(fs::write(m.mnt("readme.txt"), "A=[REDACTED-1]\n")),
        EACCES
    );
    fs::write(m.mnt("readme.txt"), "A=b\n").unwrap();
}

#[test]
fn status_dir_lists_refusals() {
    let Some(m) = Mount::new(&["--status-dir", ".veloci"]) else {
        return;
    };
    let _ = fs::write(m.mnt(".env"), "x");
    let denials = fs::read_to_string(m.mnt(".veloci/denials")).unwrap();
    assert!(denials.contains("denied writing to .env"), "{denials}");
    assert_eq!(
        fs::write(m.mnt(".veloci/denials"), "x").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
}

#[test]
fn read_only_refuses_everything() {
    let Some(m) = Mount::new(&["--read-only"]) else {
        return;
    };
    assert!(fs::write(m.mnt("readme.txt"), "x").is_err());
    assert!(fs::write(m.mnt("new"), "x").is_err());
    assert_eq!(fs::read_to_string(m.mnt(".env")).unwrap(), ENV_REDACTED);
}

#[test]
fn mounting_inside_the_source() {
    let Some(mut m) = Mount::at("src/.redacted", &[]) else {
        return;
    };
    // The mount leaves itself out, so walking it ends.
    let listing: Vec<_> = fs::read_dir(&m.mountpoint)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!listing.contains(&".redacted".to_owned()), "{listing:?}");
    assert_eq!(fs::read_to_string(m.mnt(".env")).unwrap(), ENV_REDACTED);
    assert_eq!(os_error(fs::create_dir(m.mnt(".redacted"))), EEXIST);
    let exclude = fs::read_to_string(m.src().join(".git/info/exclude")).unwrap();
    assert!(exclude.contains("/.redacted/"), "{exclude}");

    // `scan` skips the mount, which holds only redacted copies.
    let scan = Command::new(env!("CARGO_BIN_EXE_veloci"))
        .args(["scan", "-l"])
        .current_dir(m.src())
        .env_remove("VELOCI_CONFIG")
        .output()
        .unwrap();
    let listed = String::from_utf8(scan.stdout).unwrap();
    assert!(listed.contains(".env"), "{listed}");
    assert!(!listed.contains(".redacted"), "{listed}");

    m.stop();
    assert!(!m.src().join(".git/info/exclude").exists());
}

#[test]
fn the_mountpoint_must_be_empty() {
    if !fuse_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("mnt")).unwrap();
    fs::write(dir.path().join("mnt/x"), "").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_veloci"))
        .args(["mount", "--source"])
        .arg(dir.path())
        .arg(dir.path().join("mnt"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not empty"));
}
