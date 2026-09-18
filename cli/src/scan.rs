//! `velociredactor scan`: find the files that hold secrets.
//!
//! Every file under the given paths is redacted in memory, with the
//! configuration found from its own directory. Files left with anything to
//! redact after allow lists are reported, with how many values would be
//! redacted and which detectors found them. The values themselves are never
//! printed.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::json;
use velociredactor::FormatHint;

use crate::util::{
    CONFIG_ENV, ConfigArg, Fatal, RulesCache, SKIPPED_DIRS, WalkOptions, for_each_ordered,
    is_broken_pipe, is_file, walk_builder,
};

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or directories to scan. Directories are scanned recursively;
    /// the default is the current directory.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Report only files the configuration's `agent` section does not
    /// protect: secrets agents could still read directly. Protected files
    /// are not read.
    #[arg(long)]
    unprotected: bool,

    /// Print only the paths of files with secrets.
    #[arg(short = 'l', long)]
    files_with_matches: bool,

    /// Print the results as JSON.
    #[arg(long, conflicts_with = "files_with_matches")]
    json: bool,

    /// Scan only paths matching this glob; a leading `!` excludes instead.
    /// Repeat for more.
    #[arg(short = 'g', long, value_name = "GLOB")]
    glob: Vec<String>,

    /// Skip hidden files and directories, which are scanned by default.
    #[arg(long)]
    skip_hidden: bool,

    /// Skip files that `.gitignore`, `.ignore` and similar files exclude,
    /// which are scanned by default: that is where secrets usually are.
    #[arg(long)]
    skip_ignored: bool,

    /// Also scan dependency and build directories: node_modules, target,
    /// vendor, .venv, venv, __pycache__, dist and build.
    #[arg(long)]
    all_dirs: bool,

    /// Follow symbolic links.
    #[arg(short = 'L', long)]
    follow: bool,

    /// Descend at most this many directories.
    #[arg(short = 'd', long, value_name = "NUM")]
    max_depth: Option<usize>,

    /// Skip files larger than this, such as `500K` or `1G`.
    #[arg(long, value_name = "SIZE", default_value = "10M", value_parser = parse_size)]
    max_filesize: u64,

    /// Configuration file, replacing the built-in one. When omitted, each
    /// file uses the configuration found from its own directory.
    #[arg(long, value_name = "FILE", env = CONFIG_ENV)]
    config: Option<PathBuf>,
}

/// What to scan, beyond the paths.
pub struct Scan<'a> {
    pub walk: WalkOptions<'a>,
    /// Files larger than this are skipped.
    pub max_filesize: u64,
    /// Stop after this many files.
    pub max_files: Option<usize>,
    /// Report only files no `agent` section protects, which are not read.
    pub unprotected: bool,
    /// Leave out the `privacy_filter` detector.
    pub skip_model: bool,
    /// Paths are shown relative to this directory when under it.
    pub relative_to: Option<&'a Path>,
}

impl Scan<'_> {
    /// Scanning a whole project the way `agent status` does: the files no
    /// `agent` section protects, but not dependencies, within limits that
    /// keep it quick.
    pub fn project(root: &Path, skip_model: bool) -> Scan<'_> {
        Scan {
            walk: WalkOptions {
                globs: &[],
                hidden: true,
                ignored: true,
                follow: false,
                max_depth: Some(8),
                skipped_dirs: SKIPPED_DIRS,
            },
            max_filesize: 1 << 20,
            max_files: Some(50_000),
            unprotected: true,
            skip_model,
            relative_to: Some(root),
        }
    }
}

/// A file with secrets.
pub struct Hit {
    /// The path as shown.
    pub path: PathBuf,
    /// Each value that would be redacted, as its detector and, when known,
    /// its line.
    pub findings: Vec<(String, Option<usize>)>,
    /// Whether an `agent` section protects the file.
    pub protected: bool,
}

impl Hit {
    /// The detectors that found something, each once, in order of first
    /// finding.
    pub fn detectors(&self) -> Vec<&str> {
        let mut detectors: Vec<&str> = Vec::new();
        for (detector, _) in &self.findings {
            if !detectors.contains(&detector.as_str()) {
                detectors.push(detector);
            }
        }
        detectors
    }
}

/// What a scan found.
#[derive(Default)]
pub struct Report {
    pub hits: Vec<Hit>,
    /// Files redacted.
    pub scanned: usize,
    /// Files passed over as binary or too large.
    pub skipped: usize,
    /// Protected files left unread under `unprotected`.
    pub protected: usize,
    /// Files that could not be scanned, and why.
    pub errors: Vec<String>,
}

/// What scanning one file produced.
enum Outcome {
    Clean,
    Skipped,
    /// Protected, and left unread.
    Protected,
    Hit(Hit),
    Failed(String),
    /// A configuration could not be loaded, which stops the scan.
    Fatal(String),
}

/// Scan `roots` with `config`. Fails only when a configuration cannot be
/// loaded or a walk cannot be set up; files that cannot be read are listed
/// in the report.
pub fn scan(roots: &[PathBuf], options: &Scan<'_>, config: ConfigArg) -> Result<Report> {
    let rules = RulesCache::new(config).skip_model(options.skip_model);

    // Build every walker first, so a bad `--glob` fails before anything is
    // scanned.
    let mut walks = Vec::new();
    for root in roots {
        walks.push(walk_builder(root, &options.walk)?.build());
    }
    let entries = walks
        .into_iter()
        .flatten()
        .filter(|entry| entry.as_ref().map_or(true, is_file))
        .take(options.max_files.unwrap_or(usize::MAX));

    let mut report = Report::default();
    let mut fatal = None;
    let stop = AtomicBool::new(false);
    let unreported = for_each_ordered(
        entries,
        &stop,
        || (),
        |(), entry| {
            let outcome = match entry {
                Ok(entry) => scan_file(&rules, options, entry.path()),
                Err(err) => Outcome::Failed(err.to_string()),
            };
            if matches!(outcome, Outcome::Fatal(_)) {
                stop.store(true, Ordering::Relaxed);
            }
            outcome
        },
        |outcome| {
            match outcome {
                Outcome::Clean => report.scanned += 1,
                Outcome::Skipped => report.skipped += 1,
                Outcome::Protected => report.protected += 1,
                Outcome::Hit(hit) => {
                    report.scanned += 1;
                    report.hits.push(hit);
                }
                Outcome::Failed(err) => report.errors.push(err),
                Outcome::Fatal(err) => {
                    fatal = Some(err);
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )?;
    // The scan stopped before the files ahead of a failed configuration
    // were reported.
    let fatal = fatal.or_else(|| {
        unreported.into_iter().find_map(|outcome| match outcome {
            Outcome::Fatal(err) => Some(err),
            _ => None,
        })
    });
    if let Some(err) = fatal {
        return Err(Fatal(err).into());
    }
    for hit in &mut report.hits {
        if let Some(shown) = options
            .relative_to
            .and_then(|base| hit.path.strip_prefix(base).ok())
        {
            hit.path = shown.to_owned();
        }
    }
    Ok(report)
}

fn scan_file(rules: &RulesCache, options: &Scan<'_>, path: &Path) -> Outcome {
    let result = (|| -> Result<Outcome> {
        let rules = match rules.for_file(path) {
            Ok(rules) => rules,
            Err(err) if err.is::<Fatal>() => return Ok(Outcome::Fatal(format!("{err:#}"))),
            Err(err) => return Err(err),
        };
        let protected = rules
            .agent
            .as_ref()
            .is_some_and(|agent| agent.is_protected(path));
        if protected && options.unprotected {
            return Ok(Outcome::Protected);
        }

        let mut file =
            fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
        let size = file
            .metadata()
            .with_context(|| format!("reading {}", path.display()))?
            .len();
        if size > options.max_filesize {
            return Ok(Outcome::Skipped);
        }
        let mut data = Vec::with_capacity(size as usize);
        file.read_to_end(&mut data)
            .with_context(|| format!("reading {}", path.display()))?;
        // As in grep: a NUL byte near the start means a binary file.
        if data[..data.len().min(8192)].contains(&0) {
            return Ok(Outcome::Skipped);
        }

        let redaction = rules
            .redactor
            .redact(&data, FormatHint::Path(path))
            .with_context(|| format!("redacting {}", path.display()))?;
        let findings: Vec<_> = redaction
            .findings()
            .iter()
            .filter(|finding| !rules.allow.allows(finding))
            .map(|finding| {
                let line = finding.offset().map(|o| redaction.line_col(o).0);
                (finding.detector.clone(), line)
            })
            .collect();
        if findings.is_empty() {
            return Ok(Outcome::Clean);
        }
        Ok(Outcome::Hit(Hit {
            path: path.to_owned(),
            findings,
            protected,
        }))
    })();
    result.unwrap_or_else(|err| Outcome::Failed(format!("{err:#}")))
}

pub fn run(args: ScanArgs) -> Result<ExitCode> {
    let implicit_root = args.paths.is_empty();
    let paths = if implicit_root {
        vec![PathBuf::from(".")]
    } else {
        args.paths.clone()
    };
    let options = Scan {
        walk: WalkOptions {
            globs: &args.glob,
            hidden: !args.skip_hidden,
            ignored: !args.skip_ignored,
            follow: args.follow,
            max_depth: args.max_depth,
            skipped_dirs: if args.all_dirs { &[] } else { SKIPPED_DIRS },
        },
        max_filesize: args.max_filesize,
        max_files: None,
        unprotected: args.unprotected,
        skip_model: false,
        relative_to: implicit_root.then_some(Path::new(".")),
    };
    let report = scan(
        &paths,
        &options,
        ConfigArg {
            config: args.config.clone(),
        },
    )?;

    for error in &report.errors {
        eprintln!("error: {error}");
    }
    match print(&args, &report) {
        Err(err) if is_broken_pipe(&err) => {}
        result => result?,
    }
    Ok(if !report.hits.is_empty() {
        ExitCode::from(1)
    } else if !report.errors.is_empty() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn print(args: &ScanArgs, report: &Report) -> Result<()> {
    let mut out = io::stdout().lock();
    if args.json {
        let files: Vec<_> = report
            .hits
            .iter()
            .map(|hit| {
                let findings: Vec<_> = hit
                    .findings
                    .iter()
                    .map(|(detector, line)| json!({ "detector": detector, "line": line }))
                    .collect();
                json!({
                    "path": hit.path.display().to_string(),
                    "count": hit.findings.len(),
                    "detectors": hit.detectors(),
                    "protected": hit.protected,
                    "findings": findings,
                })
            })
            .collect();
        let document = json!({
            "files": files,
            "scanned": report.scanned,
            "skipped": report.skipped,
            "protected_unread": report.protected,
            "errors": report.errors,
        });
        serde_json::to_writer_pretty(&mut out, &document)?;
        writeln!(out)?;
        return Ok(());
    }
    if args.files_with_matches {
        for hit in &report.hits {
            writeln!(out, "{}", hit.path.display())?;
        }
        return Ok(());
    }

    if !report.hits.is_empty() {
        let rows: Vec<[String; 4]> = report
            .hits
            .iter()
            .map(|hit| {
                [
                    hit.path.display().to_string(),
                    hit.findings.len().to_string(),
                    hit.detectors().join(","),
                    if hit.protected { "protected" } else { "" }.into(),
                ]
            })
            .collect();
        let header = ["FILE", "FINDINGS", "DETECTORS", ""].map(String::from);
        write_table(&mut out, &header, &rows)?;
    }
    out.flush()?;
    let with = if args.unprotected {
        "unprotected with secrets"
    } else {
        "with secrets"
    };
    let unread = if args.unprotected {
        format!(", {} protected and not read", report.protected)
    } else {
        String::new()
    };
    eprintln!(
        "scanned {} files: {} {with}, {} skipped as binary or over --max-filesize{unread}",
        report.scanned,
        report.hits.len(),
        report.skipped,
    );
    Ok(())
}

/// Write rows as columns aligned under `header`.
fn write_table(out: &mut impl Write, header: &[String; 4], rows: &[[String; 4]]) -> Result<()> {
    let mut widths = [0; 4];
    for row in std::iter::once(header).chain(rows) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for row in std::iter::once(header).chain(rows) {
        let line: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        writeln!(out, "{}", line.join("  ").trim_end())?;
    }
    Ok(())
}

/// A size in bytes, with an optional `K`, `M` or `G` suffix (powers of 1024).
fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (number, shift) = match text.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&text[..text.len() - 1], 10),
        Some('M') => (&text[..text.len() - 1], 20),
        Some('G') => (&text[..text.len() - 1], 30),
        _ => (text, 0),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
        .ok_or_else(|| format!("{text:?} is not a size such as 4096, 500K, 10M or 1G"))
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("500K"), Ok(500 << 10));
        assert_eq!(parse_size("10m"), Ok(10 << 20));
        assert_eq!(parse_size("1G"), Ok(1 << 30));
        assert!(parse_size("ten").is_err());
        assert!(parse_size("").is_err());
    }
}
