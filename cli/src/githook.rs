//! `veloci githook`: refuse a commit that adds secrets.
//!
//! The staged diff says which lines a commit adds. Each staged file is then
//! redacted whole, as it is in the index, so formats and allow lists see the
//! full file, and only the secrets on added lines are reported.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use clap::Args;
use veloci::FormatHint;

use crate::util::{ConfigArg, RulesCache};

/// Staged files larger than this are not scanned.
const MAX_FILESIZE: usize = 10 << 20;

#[derive(Debug, Args)]
pub struct GithookArgs {
    #[command(flatten)]
    config: ConfigArg,
}

/// A secret on a line the commit adds.
struct Hit {
    /// The file, relative to the repository root.
    path: PathBuf,
    /// The first added line it is on.
    line: usize,
    detector: String,
}

/// The lines a diff adds to one file.
#[derive(Debug, Default, PartialEq)]
struct Added {
    /// 1-based line numbers in the new file.
    lines: BTreeSet<usize>,
    /// The added lines' text, each followed by a newline.
    text: Vec<u8>,
}

pub fn run(args: GithookArgs) -> Result<ExitCode> {
    let cwd = std::env::current_dir().context("determining the current directory")?;
    let root = git(&cwd, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(String::from_utf8(root)?.trim_end_matches(['\n', '\r']));

    let rules = RulesCache::new(args.config);
    let mut hits = Vec::new();
    for (blob, path) in staged_blobs(&root)? {
        hits.extend(check_file(&root, &rules, &blob, &path)?);
    }
    if hits.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }

    eprintln!("veloci: refusing to commit secrets");
    let shown: Vec<String> = hits
        .iter()
        .map(|hit| format!("{}:{}", hit.path.display(), hit.line))
        .collect();
    let width = shown.iter().map(|s| s.chars().count()).max().unwrap_or(0);
    for (location, hit) in shown.iter().zip(&hits) {
        eprintln!("  {location:<width$}  {}", hit.detector);
    }
    eprintln!(
        "Review with `veloci list FILE`; allow false positives in veloci.yml,\n\
         or bypass once with `git commit --no-verify`."
    );
    Ok(ExitCode::from(1))
}

/// The staged files the commit adds or changes, as `(blob id, path)` with
/// paths relative to `root`. Submodules and symbolic links are left out.
fn staged_blobs(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    // Renames are left undetected, so a renamed file counts as added whole.
    let raw = git(
        root,
        &[
            "diff",
            "--cached",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-renames",
            "--diff-filter=d",
        ],
    )?;
    // Each entry is `:OLDMODE NEWMODE OLDID NEWID STATUS` NUL `PATH` NUL.
    let mut fields = raw.split(|&b| b == 0).filter(|f| !f.is_empty());
    let mut blobs = Vec::new();
    while let (Some(meta), Some(path)) = (fields.next(), fields.next()) {
        let meta = String::from_utf8_lossy(meta);
        let parts: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
        let [_, mode, _, id, _] = parts[..] else {
            bail!("unexpected `git diff --raw` output: {meta:?}");
        };
        if mode.starts_with("100") {
            blobs.push((id.to_owned(), PathBuf::from(bytes_to_os(path))));
        }
    }
    Ok(blobs)
}

/// The secrets on lines the commit adds to the staged file at `path`.
fn check_file(root: &Path, rules: &RulesCache, blob: &str, path: &Path) -> Result<Vec<Hit>> {
    let data = git(root, &["cat-file", "blob", blob])?;
    // As in `scan`: too large, or a NUL byte near the start means binary.
    if data.len() > MAX_FILESIZE || data[..data.len().min(8192)].contains(&0) {
        return Ok(Vec::new());
    }
    let absolute = root.join(path);
    let rules = rules.for_file(&absolute)?;
    if rules.allowed_files.matches(&absolute) {
        return Ok(Vec::new());
    }

    let mut diff = Command::new("git");
    diff.current_dir(root)
        .env("GIT_LITERAL_PATHSPECS", "1")
        .args(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff"])
        .args(["--no-textconv", "--no-renames", "--"])
        .arg(path);
    let added = added_lines(&output(&mut diff)?);
    if added.lines.is_empty() {
        return Ok(Vec::new());
    }

    let redaction = rules
        .redactor_for(Some(&absolute))
        .redact(&data, FormatHint::Path(path))
        .with_context(|| format!("redacting {}", path.display()))?;
    let mut hits = Vec::new();
    for finding in redaction.findings() {
        if rules.allow.allows(finding) {
            continue;
        }
        let line = if finding.offsets.is_empty() {
            // No positions: judge by whether the added text holds the value.
            let secret = finding.secret.as_bytes();
            let found = !secret.is_empty() && added.text.windows(secret.len()).any(|w| w == secret);
            found.then(|| *added.lines.first().expect("lines is not empty"))
        } else {
            finding.offsets.iter().find_map(|&offset| {
                let first = redaction.line_col(offset).0;
                let last = redaction.line_col(offset + finding.len.saturating_sub(1)).0;
                added.lines.range(first..=last).next().copied()
            })
        };
        if let Some(line) = line {
            hits.push(Hit {
                path: path.to_owned(),
                line,
                detector: finding.detector.clone(),
            });
        }
    }
    Ok(hits)
}

/// The lines a `git diff -U0` of one file adds.
fn added_lines(diff: &[u8]) -> Added {
    let mut added = Added::default();
    // The next new-file line number, once inside a hunk.
    let mut next: Option<usize> = None;
    for line in diff.split(|&b| b == b'\n') {
        if line.starts_with(b"@@") {
            next = hunk_start(line);
        } else if let (Some(n), Some(text)) = (next.as_mut(), line.strip_prefix(b"+")) {
            added.lines.insert(*n);
            added.text.extend_from_slice(text);
            added.text.push(b'\n');
            *n += 1;
        }
    }
    added
}

/// The first new-file line of a hunk header `@@ -a,b +c,d @@`.
fn hunk_start(header: &[u8]) -> Option<usize> {
    let header = std::str::from_utf8(header).ok()?;
    let new = header.split(' ').find_map(|part| part.strip_prefix('+'))?;
    new.split(',').next()?.parse().ok()
}

/// Run git in `dir` and return its standard output.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    output(Command::new("git").current_dir(dir).args(args))
}

fn output(command: &mut Command) -> Result<Vec<u8>> {
    let shown = format!("{command:?}");
    let out = command
        .output()
        .with_context(|| format!("running {shown}"))?;
    if !out.status.success() {
        bail!(
            "{shown} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

#[cfg(unix)]
fn bytes_to_os(bytes: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(bytes).to_owned()
}

#[cfg(not(unix))]
fn bytes_to_os(bytes: &[u8]) -> std::ffi::OsString {
    String::from_utf8_lossy(bytes).into_owned().into()
}

#[cfg(test)]
mod tests {
    use super::added_lines;

    #[test]
    fn reads_added_lines_from_hunks() {
        let diff = b"diff --git a/f b/f\n\
            --- a/f\n\
            +++ b/f\n\
            @@ -1 +1 @@\n\
            -old\n\
            +new\n\
            @@ -5,0 +6,2 @@ fn context\n\
            ++++ looks like a header\n\
            +two\n\
            @@ -9,3 +10,0 @@\n\
            -gone\n\
            -gone\n\
            -gone\n\
            \\ No newline at end of file\n";
        let added = added_lines(diff);
        assert_eq!(added.lines.into_iter().collect::<Vec<_>>(), [1, 6, 7]);
        assert_eq!(added.text, b"new\n+++ looks like a header\ntwo\n");
    }

    #[test]
    fn nothing_added_without_hunks() {
        let added = added_lines(b"diff --git a/f b/f\nold mode 100644\nnew mode 100755\n");
        assert!(added.lines.is_empty());
    }
}
