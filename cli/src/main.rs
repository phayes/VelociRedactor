use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use velociredactor::config::Config;
use velociredactor::detect::privacy_filter;
use velociredactor::{Allow, Finding, FormatHint, Redaction, Redactor};

/// Redact secrets and personal data from files.
///
/// Each redacted value becomes a token `REDACTION-N`, where `N` numbers
/// distinct secrets in order of first appearance. Equal values share a
/// number.
///
/// What counts as a secret is configuration, not command line: the options
/// here say how to apply the rules, and `velociredactor config show` prints the
/// rules that are built in. Write your own by editing a copy of them:
///
///     velociredactor config show > velociredactor.yml
///     velociredactor redact secrets.json
///
/// Configuration is chosen in this order: `--config`, then
/// `$VELOCIREDACTOR_CONFIG`, then a `velociredactor.yml` or
/// `VELOCIREDACTOR.yml` found in the current directory or a parent (stopping
/// at a git repository root — a `.git` file or directory — the home
/// directory when running inside it, or the filesystem root), then the
/// built-in configuration.
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write the input with secrets replaced by redaction tokens.
    Redact(RedactArgs),
    /// List the secrets that would be redacted.
    List(ListArgs),
    /// List the supported input formats.
    Formats,
    /// Inspect or check a configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Manage the OpenAI model behind the `privacy_filter` detector.
    #[command(subcommand, name = "privacy_filter")]
    PrivacyFilter(PrivacyFilterCommand),
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the configuration that would be used.
    Show(ConfigArg),
    /// Print where the configuration was loaded from.
    Location(ConfigArg),
    /// Check that the configuration can be loaded.
    Validate(ConfigArg),
}

/// Environment variable naming a configuration file that replaces the
/// built-in one when `--config` is omitted.
const CONFIG_ENV: &str = "VELOCIREDACTOR_CONFIG";

/// Names accepted for a discovered configuration file, in preference order.
const CONFIG_FILE_NAMES: [&str; 2] = ["velociredactor.yml", "VELOCIREDACTOR.yml"];

/// The configuration file, from `--config`, `$VELOCIREDACTOR_CONFIG`, or
/// a `velociredactor.yml` found by walking from the current directory.
#[derive(Debug, Args)]
struct ConfigArg {
    /// Configuration file, replacing the built-in one.
    ///
    /// `--config` wins over `$VELOCIREDACTOR_CONFIG`. When both are omitted,
    /// `velociredactor.yml` or `VELOCIREDACTOR.yml` is looked for in the
    /// current directory and its parents.
    #[arg(short, long, value_name = "FILE", env = CONFIG_ENV)]
    config: Option<PathBuf>,
}

impl ConfigArg {
    /// The file `--config` or `$VELOCIREDACTOR_CONFIG` named, if either did.
    fn explicit_path(&self) -> Option<&Path> {
        self.config.as_deref().filter(|p| !p.as_os_str().is_empty())
    }

    /// The file that will be used: `--config` or `$VELOCIREDACTOR_CONFIG`
    /// if either named one, otherwise a discovered file, otherwise none
    /// (the built-in configuration).
    fn resolved_path(&self) -> Result<Option<PathBuf>> {
        if let Some(path) = self.explicit_path() {
            return Ok(Some(path.to_owned()));
        }
        discover_config()
    }

    /// The rules to apply, in order: `--config`, `$VELOCIREDACTOR_CONFIG`,
    /// a discovered file, or the built-in configuration.
    fn load(&self) -> Result<Config> {
        match self.resolved_path()? {
            Some(path) => Ok(Config::from_path(path)?),
            None => Ok(Config::builtin().clone()),
        }
    }
}

#[derive(Debug, Subcommand)]
enum PrivacyFilterCommand {
    /// Download the model (about 2.6 GB) from Hugging Face, and print the
    /// configuration entry that uses it.
    Download(DownloadArgs),
}

#[derive(Debug, Args)]
struct DownloadArgs {
    /// Put the model in this directory. By default it goes in the Hugging
    /// Face cache ($HF_HOME/hub), where the detector finds it without a
    /// `model_dir` and other tools can share it.
    #[arg(short, long, value_name = "DIR")]
    dir: Option<PathBuf>,

    /// The Hugging Face repository to download from.
    #[arg(long, value_name = "OWNER/NAME", default_value = privacy_filter::MODEL_REPO)]
    repo: String,

    /// The revision (branch, tag, or commit) to download.
    #[arg(long, value_name = "REV")]
    revision: Option<String>,
}

#[derive(Debug, Args)]
struct RedactArgs {
    #[command(flatten)]
    input: InputArgs,

    /// Write the result to this file instead of standard output.
    #[arg(short, long, value_name = "FILE", conflicts_with = "in_place")]
    output: Option<PathBuf>,

    /// Overwrite the input file with the result.
    #[arg(short, long)]
    in_place: bool,

    /// Exit with status 1 if anything was redacted (after allow lists).
    #[arg(long)]
    check: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    #[command(flatten)]
    input: InputArgs,

    /// Print the list as JSON.
    #[arg(long)]
    json: bool,

    /// Include redacted values in the list.
    #[arg(long)]
    show_value: bool,

    /// Exit with status 1 if anything would be redacted (after allow lists).
    #[arg(long)]
    check: bool,
}

/// Options shared by `redact` and `list`.
#[derive(Debug, Args)]
struct InputArgs {
    /// File to read. Reads standard input when omitted or `-`.
    file: Option<PathBuf>,

    #[command(flatten)]
    config: ConfigArg,

    /// Input format. Detected from the file name or content when omitted.
    #[arg(short, long, value_name = "NAME")]
    format: Option<String>,

    /// Treat the input as plain text, skipping format detection.
    #[arg(long, conflicts_with = "format")]
    raw: bool,
}

impl InputArgs {
    fn path(&self) -> Option<&Path> {
        self.file.as_deref().filter(|p| *p != Path::new("-"))
    }

    /// The rules to apply, in order: `--config`, `$VELOCIREDACTOR_CONFIG`,
    /// a discovered `velociredactor.yml`, or the built-in configuration.
    fn config(&self) -> Result<Config> {
        self.config.load()
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Redact(args) => redact(args),
        Command::List(args) => list(args),
        Command::Formats => formats(),
        Command::Config(ConfigCommand::Show(args)) => show_config(&args),
        Command::Config(ConfigCommand::Location(args)) => locate_config(&args),
        Command::Config(ConfigCommand::Validate(args)) => validate_config(&args),
        Command::PrivacyFilter(PrivacyFilterCommand::Download(args)) => download_model(args),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn redact(args: RedactArgs) -> Result<ExitCode> {
    let path = args.input.path();
    if args.in_place && path.is_none() {
        bail!("--in-place needs a file");
    }
    let config = args.input.config()?;
    let redactor = build_redactor(&config)?;
    let input = read_input(path)?;
    let (redaction, allow) = scan(&redactor, &config, &args.input, &input)?;

    let output = redaction.render(&allow)?;
    match (&args.output, path) {
        (Some(out), _) => {
            fs::write(out, &output).with_context(|| format!("writing {}", out.display()))?
        }
        (None, Some(path)) if args.in_place => {
            fs::write(path, &output).with_context(|| format!("writing {}", path.display()))?
        }
        _ => io::stdout()
            .write_all(&output)
            .context("writing standard output")?,
    }
    Ok(exit_code(args.check, &redaction, &allow))
}

fn list(args: ListArgs) -> Result<ExitCode> {
    let config = args.input.config()?;
    let redactor = build_redactor(&config)?;
    let input = read_input(args.input.path())?;
    let (redaction, allow) = scan(&redactor, &config, &args.input, &input)?;

    let mut stdout = io::stdout().lock();
    if args.json {
        print_json(&mut stdout, &redaction, &allow, args.show_value)?;
    } else {
        print_table(&mut stdout, &redaction, &allow, args.show_value)?;
    }
    Ok(exit_code(args.check, &redaction, &allow))
}

/// Print the configuration that would be used, comments and all.
fn show_config(args: &ConfigArg) -> Result<ExitCode> {
    match args.resolved_path()? {
        Some(path) => {
            let source = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            io::stdout()
                .write_all(&source)
                .context("writing standard output")?;
        }
        None => {
            io::stdout()
                .write_all(Config::builtin_source().as_bytes())
                .context("writing standard output")?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Print the path of the configuration that would be used.
fn locate_config(args: &ConfigArg) -> Result<ExitCode> {
    match args.resolved_path()? {
        Some(path) => println!("{}", path.display()),
        None => println!("[builtin-default]"),
    }
    Ok(ExitCode::SUCCESS)
}

/// A `velociredactor.yml` or `VELOCIREDACTOR.yml` found by walking from the
/// current directory, if one is in reach.
fn discover_config() -> Result<Option<PathBuf>> {
    let cwd = std::env::current_dir().context("determining the current directory")?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    Ok(discover_from(&cwd, home.as_deref()))
}

/// Walk from `start` toward the filesystem root looking for a configuration
/// file.
///
/// Each directory is searched for [`CONFIG_FILE_NAMES`] before deciding
/// whether to go further. The walk stops at the first file found, a git
/// repository root (a `.git` file or directory), the home directory when
/// `start` is inside it, or the filesystem root.
fn discover_from(start: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let inside_home = home.is_some_and(|home| start.starts_with(home));
    let mut dir = start.to_path_buf();
    loop {
        for name in CONFIG_FILE_NAMES {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // Worktrees and some submodules keep `.git` as a file; a normal
        // clone keeps it as a directory. Either one is the repository root.
        let at_git_root = dir.join(".git").exists();
        let at_home_root = inside_home && home.is_some_and(|home| dir == home);
        if at_git_root || at_home_root || dir.parent().is_none() {
            return None;
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Check that the configuration can be turned into a redactor.
fn validate_config(args: &ConfigArg) -> Result<ExitCode> {
    let config = args.load()?;
    let (errors, warnings) = config.validate();
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    if errors.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    for error in errors {
        eprintln!("error: {error}");
    }
    Ok(ExitCode::from(2))
}

fn download_model(args: DownloadArgs) -> Result<ExitCode> {
    let Some((owner, name)) = args.repo.split_once('/') else {
        bail!("--repo must be OWNER/NAME, not {:?}", args.repo);
    };
    let client = hf_hub::HFClientSync::new().context("starting the Hugging Face client")?;
    let dir = client
        .model(owner, name)
        .snapshot_download()
        .maybe_revision(args.revision)
        .allow_patterns(
            privacy_filter::MODEL_FILES
                .iter()
                .map(|f| f.to_string())
                .collect(),
        )
        .maybe_local_dir(args.dir.clone())
        .progress(DownloadProgress::default())
        .send()
        .with_context(|| format!("downloading {}", args.repo))?;
    eprintln!();

    // Relative paths in a configuration are read against its own directory,
    // so give an absolute one.
    let dir = fs::canonicalize(&dir).unwrap_or(dir);
    eprintln!("downloaded the model to {}", dir.display());
    eprintln!("to use it, add this under `detectors` in your configuration:");
    println!("  - privacy_filter:");
    // Without --dir the model is where the detector looks when given no
    // directory, so the entry needs none.
    if args.dir.is_some() {
        println!("      model_dir: {:?}", dir.display().to_string());
    }
    // Listed out, so taking one away is an edit rather than a lookup.
    println!("      categories:");
    for category in privacy_filter::categories() {
        println!("        - {category}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Reports a download's overall progress on standard error.
#[derive(Default)]
struct DownloadProgress {
    state: Mutex<ProgressState>,
}

#[derive(Default)]
struct ProgressState {
    /// The total the download announced when it started, which is zero when
    /// it could not tell.
    announced: u64,
    /// Bytes received and expected so far, by file.
    files: std::collections::HashMap<String, (u64, u64)>,
    /// Bytes received and expected by the batched (xet) transfer, which
    /// reports no per-file breakdown.
    batch: (u64, u64),
    /// Whether the download has finished.
    complete: bool,
    /// The last whole percentage printed.
    shown: Option<u64>,
}

impl hf_hub::progress::ProgressHandler for DownloadProgress {
    fn on_progress(&self, event: &hf_hub::progress::ProgressEvent) {
        use hf_hub::progress::{DownloadEvent, ProgressEvent};

        let ProgressEvent::Download(event) = event else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match event {
            DownloadEvent::Start { total_bytes, .. } => state.announced = *total_bytes,
            DownloadEvent::Progress { files } => {
                for file in files {
                    state.files.insert(
                        file.filename.clone(),
                        (file.bytes_completed, file.total_bytes),
                    );
                }
            }
            DownloadEvent::AggregateProgress {
                bytes_completed,
                total_bytes,
                ..
            } => state.batch = (*bytes_completed, *total_bytes),
            DownloadEvent::Complete => state.complete = true,
        }
        // Each source undercounts in its own way, so take the largest.
        let (files_done, files_total) = state
            .files
            .values()
            .fold((0, 0), |(d, t), (fd, ft)| (d + fd, t + ft));
        let total = state.announced.max(files_total).max(state.batch.1);
        // Files already on disk arrive with no byte counts at all.
        let done = if state.complete {
            total
        } else {
            files_done.max(state.batch.0)
        };
        if total == 0 {
            return;
        }
        let percent = done.min(total) * 100 / total;
        if state.shown != Some(percent) {
            state.shown = Some(percent);
            eprint!(
                "\rdownloading: {percent:>3}% of {:.1} GB",
                total as f64 / 1e9
            );
        }
    }
}

fn formats() -> Result<ExitCode> {
    let redactor = Redactor::builder().build();
    for format in redactor.formats().iter() {
        println!("{:<12} {}", format.name(), format.extensions().join(", "));
    }
    Ok(ExitCode::SUCCESS)
}

/// Exit 1 under `--check` when anything is still redacted.
fn exit_code(check: bool, redaction: &Redaction<'_>, allow: &Allow) -> ExitCode {
    let remaining = redaction.findings().iter().any(|f| !allow.allows(f));
    if check && remaining {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn read_input(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(path) => fs::read(path).with_context(|| format!("reading {}", path.display())),
        None => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .context("reading standard input")?;
            Ok(buf)
        }
    }
}

/// Redact `input` and build the allow list, printing warnings to stderr.
fn scan<'a>(
    redactor: &Redactor,
    config: &Config,
    args: &InputArgs,
    input: &'a [u8],
) -> Result<(Redaction<'a>, Allow)> {
    let hint = match (&args.format, args.raw, args.path()) {
        (_, true, _) => FormatHint::Raw,
        (Some(name), _, _) => {
            if redactor.formats().get(name).is_none() {
                let names: Vec<_> = redactor.formats().names().collect();
                bail!("unknown format {name:?} (available: {})", names.join(", "));
            }
            FormatHint::Name(name)
        }
        (None, false, Some(path)) => FormatHint::Path(path),
        (None, false, None) => FormatHint::Auto,
    };

    let redaction = redactor.redact(input, hint)?;
    let allow = config.allow()?;

    for warning in redaction.warnings() {
        eprintln!("warning: {warning}");
    }
    Ok((redaction, allow))
}

fn build_redactor(config: &Config) -> Result<Redactor> {
    let (redactor, warnings) = config.redactor()?;
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    Ok(redactor)
}

fn print_table(
    out: &mut impl Write,
    redaction: &Redaction<'_>,
    allow: &Allow,
    show_value: bool,
) -> Result<()> {
    if redaction.findings().is_empty() {
        writeln!(out, "no redactions")?;
        return Ok(());
    }

    let mut header = vec!["TOKEN", "DETECTOR", "START", "LEN", "COUNT", "LOCATION"];
    if show_value {
        header.push("VALUE");
    }
    header.push("");
    let header: Vec<String> = header.into_iter().map(String::from).collect();

    let rows: Vec<Vec<String>> = redaction
        .findings()
        .iter()
        .map(|f| {
            let mut row = vec![
                f.token(),
                f.detector.clone(),
                f.offset().map_or_else(|| "-".into(), |o| o.to_string()),
                f.len.to_string(),
                f.occurrences.to_string(),
                location(redaction, f),
            ];
            if show_value {
                row.push(format!("{:?}", f.secret));
            }
            row.push(if allow.allows(f) { "allowed" } else { "" }.into());
            row
        })
        .collect();

    let mut widths = vec![0; header.len()];
    for row in std::iter::once(&header).chain(&rows) {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    for row in std::iter::once(&header).chain(&rows) {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        writeln!(out, "{}", line.join("  ").trim_end())?;
    }
    Ok(())
}

fn print_json(
    out: &mut impl Write,
    redaction: &Redaction<'_>,
    allow: &Allow,
    show_value: bool,
) -> Result<()> {
    let redactions: Vec<_> = redaction
        .findings()
        .iter()
        .map(|f| {
            let (line, column) = f
                .offset()
                .map(|o| redaction.line_col(o))
                .map_or((None, None), |(l, c)| (Some(l), Some(c)));
            let mut entry = json!({
                "id": f.id,
                "token": f.token(),
                "detector": f.detector,
                "start": f.offset(),
                "length": f.len,
                "line": line,
                "column": column,
                "field": f.field,
                "path": f.path,
                "occurrences": f.occurrences,
                "offsets": f.offsets,
                "allowed": allow.allows(f),
            });
            if show_value {
                entry["value"] = json!(f.secret);
            }
            entry
        })
        .collect();
    let document = json!({
        "format": redaction.format(),
        "redactions": redactions,
        "warnings": redaction.warnings(),
    });
    serde_json::to_writer_pretty(&mut *out, &document)?;
    writeln!(out)?;
    Ok(())
}

fn location(redaction: &Redaction<'_>, finding: &Finding) -> String {
    let mut parts = Vec::new();
    if let Some(offset) = finding.offset() {
        let (line, col) = redaction.line_col(offset);
        parts.push(format!("{line}:{col}"));
    }
    if let Some(name) = finding.path.as_ref().or(finding.field.as_ref()) {
        parts.push(format!("[{name}]"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn write_file(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, "found\n").unwrap();
        path
    }

    #[test]
    fn finds_a_config_in_the_starting_directory() {
        let root = tempfile::tempdir().unwrap();
        let want = write_file(root.path(), "velociredactor.yml");
        assert_eq!(discover_from(root.path(), Some(root.path())), Some(want));
    }

    #[test]
    fn finds_an_uppercase_config_name() {
        let root = tempfile::tempdir().unwrap();
        write_file(root.path(), "VELOCIREDACTOR.yml");
        let found =
            discover_from(root.path(), Some(root.path())).expect("uppercase name is accepted");
        assert!(
            CONFIG_FILE_NAMES
                .iter()
                .any(|name| found.file_name().is_some_and(|n| n == *name)),
            "{found:?}"
        );
        assert_eq!(fs::read_to_string(&found).unwrap(), "found\n");
    }

    #[test]
    fn prefers_the_lowercase_name_when_both_exist() {
        let root = tempfile::tempdir().unwrap();
        let lower = write_file(root.path(), "velociredactor.yml");
        let upper = root.path().join("VELOCIREDACTOR.yml");
        if upper != lower {
            fs::write(&upper, "other\n").unwrap();
        }
        assert_eq!(discover_from(root.path(), Some(root.path())), Some(lower));
    }

    #[test]
    fn walks_up_to_a_parent() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        let want = write_file(root.path(), "velociredactor.yml");
        assert_eq!(discover_from(&child, Some(root.path())), Some(want));
    }

    #[test]
    fn prefers_the_closest_file() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        write_file(root.path(), "velociredactor.yml");
        let want = write_file(&child, "velociredactor.yml");
        assert_eq!(discover_from(&child, Some(root.path())), Some(want));
    }

    #[test]
    fn ignores_a_directory_with_the_config_name() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        fs::create_dir(child.join("velociredactor.yml")).unwrap();
        let want = write_file(root.path(), "velociredactor.yml");
        assert_eq!(discover_from(&child, Some(root.path())), Some(want));
    }

    #[test]
    fn finds_a_config_in_a_git_root() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let src = repo.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        let want = write_file(&repo, "velociredactor.yml");
        write_file(root.path(), "velociredactor.yml");
        assert_eq!(discover_from(&src, Some(root.path())), Some(want));
    }

    #[test]
    fn stops_at_a_git_directory() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let src = repo.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        write_file(root.path(), "velociredactor.yml");
        assert_eq!(discover_from(&src, Some(root.path())), None);
    }

    #[test]
    fn stops_at_a_git_file() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let src = repo.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(repo.join(".git"), "gitdir: /elsewhere/.git/worktrees/x\n").unwrap();
        write_file(root.path(), "velociredactor.yml");
        assert_eq!(discover_from(&src, Some(root.path())), None);
    }

    #[test]
    fn finds_a_config_in_home() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("home");
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        let want = write_file(&home, "velociredactor.yml");
        write_file(outer.path(), "velociredactor.yml");
        assert_eq!(discover_from(&project, Some(&home)), Some(want));
    }

    #[test]
    fn stops_at_home_when_starting_inside_it() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("home");
        let project = home.join("project");
        fs::create_dir_all(&project).unwrap();
        write_file(outer.path(), "velociredactor.yml");
        assert_eq!(discover_from(&project, Some(&home)), None);
    }

    #[test]
    fn walks_past_home_when_starting_outside_it() {
        let outer = tempfile::tempdir().unwrap();
        let home = outer.path().join("home");
        let other = outer.path().join("other");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir(&other).unwrap();
        let want = write_file(outer.path(), "velociredactor.yml");
        assert_eq!(discover_from(&other, Some(&home)), Some(want));
    }

    #[test]
    fn returns_none_when_nothing_is_in_reach() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("src");
        fs::create_dir(&child).unwrap();
        assert_eq!(discover_from(&child, Some(root.path())), None);
    }
}
