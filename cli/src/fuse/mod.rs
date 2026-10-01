//! `veloci fuse`: mount a redacted view of a directory.
//!
//! The arguments parse on every platform, so the help and the manual are the
//! same everywhere; the filesystem itself is Linux only.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use crate::util::ConfigArg;

#[cfg(all(target_os = "linux", feature = "fuse"))]
mod fs;
#[cfg(all(target_os = "linux", feature = "fuse"))]
mod inodes;
#[cfg(all(target_os = "linux", feature = "fuse"))]
mod mount;
#[cfg(all(target_os = "linux", feature = "fuse"))]
mod policy;
#[cfg(all(target_os = "linux", feature = "fuse"))]
mod status;
#[cfg(all(target_os = "linux", feature = "fuse"))]
mod view;

#[cfg(all(target_os = "linux", feature = "fuse"))]
pub use mount::veloci_mounts;

/// The errors `--deny-errno` accepts.
pub const DENY_ERRNOS: &[&str] = &["EACCES", "EPERM", "EKEYREJECTED", "ENOKEY"];

#[derive(Debug, Args)]
pub struct FuseArgs {
    /// Empty directory to mount the redacted view on. It may be inside the
    /// source directory; the view then leaves it out.
    pub mountpoint: PathBuf,

    /// Directory to mirror. Defaults to the Git repository root holding the
    /// current directory, or the current directory outside a repository.
    #[arg(long, value_name = "DIR")]
    pub source: Option<PathBuf>,

    #[command(flatten)]
    pub config: ConfigArg,

    /// Treat every file as this format, instead of detecting each file's.
    #[arg(short, long, value_name = "NAME")]
    pub format: Option<String>,

    /// Treat every file as plain text, skipping format detection.
    #[arg(long, conflicts_with = "format")]
    pub raw: bool,

    /// The error a refused write fails with: EACCES ("Permission denied"),
    /// EPERM ("Operation not permitted"), or the Linux-only EKEYREJECTED
    /// ("Key was rejected by service") or ENOKEY ("Required key not
    /// available"), which no ordinary permission problem gives.
    #[arg(long, value_name = "NAME", default_value = "EACCES", value_parser = parse_errno)]
    pub deny_errno: String,

    /// Also refuse writes that contain a redaction token such as
    /// `[REDACTED-1]`, which is almost always a redacted value being
    /// written back by mistake.
    #[arg(long)]
    pub deny_tokens: bool,

    /// Allow creating, changing, moving and deleting configuration files
    /// (`veloci.yml`, `VELOCI.yml`, `--config`) through the mount. Without it
    /// they are read-only, since a changed configuration could reveal what it
    /// redacts. Changes still take effect only on SIGHUP.
    #[arg(long)]
    pub allow_veloci_yml: bool,

    /// Refuse every write.
    #[arg(long)]
    pub read_only: bool,

    /// Let other users use the mount. Needs `user_allow_other` in
    /// /etc/fuse.conf unless run as root. Their own file permissions apply.
    #[arg(long)]
    pub allow_other: bool,

    /// Serve the most recent refusals in a read-only file `NAME/denials` at
    /// the root of the mount.
    #[arg(long, value_name = "NAME")]
    pub status_dir: Option<OsString>,

    /// Append refusals to this file instead of printing them to standard
    /// error.
    #[arg(long, value_name = "FILE")]
    pub log: Option<PathBuf>,

    /// Don't add a mountpoint inside the repository to `.git/info/exclude`
    /// while mounted.
    #[arg(long)]
    pub no_git_exclude: bool,

    /// Memory for redacted file contents kept between reads, such as `64M`.
    #[arg(long, value_name = "SIZE", default_value = "256M", value_parser = crate::scan::parse_size)]
    pub cache_size: u64,
}

fn parse_errno(text: &str) -> Result<String, String> {
    let name = text.to_ascii_uppercase();
    if DENY_ERRNOS.contains(&name.as_str()) {
        Ok(name)
    } else {
        Err(format!("expected one of {}", DENY_ERRNOS.join(", ")))
    }
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
pub fn run(args: FuseArgs) -> Result<ExitCode> {
    mount::run(args)
}

#[cfg(not(all(target_os = "linux", feature = "fuse")))]
pub fn run(_args: FuseArgs) -> Result<ExitCode> {
    eprintln!("veloci: `veloci fuse` needs FUSE, which this build does not support (Linux only)");
    Ok(ExitCode::from(2))
}

/// Mountpoints of `veloci fuse` filesystems, which directory walks skip:
/// they hold redacted copies of files that are already being walked.
#[cfg(not(all(target_os = "linux", feature = "fuse")))]
pub fn veloci_mounts() -> Vec<PathBuf> {
    Vec::new()
}
