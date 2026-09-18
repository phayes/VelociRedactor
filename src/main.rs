use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use velociredactor::config::Config;
use velociredactor::{Allow, Finding, FormatHint, Redaction, Redactor};

/// Redact secrets and personal data from files.
///
/// Each redacted value becomes a token `REDACTION-N`, where `N` numbers
/// distinct secrets in order of first appearance. Equal values share a
/// number.
///
/// What counts as a secret is configuration, not command line: the options
/// here say how to apply the rules, and `velociredactor config` prints the rules
/// that are built in. Write your own by editing a copy of them:
///
///     velociredactor config > my-config.yml
///     velociredactor redact --config my-config.yml secrets.json
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
    /// Print the built-in configuration, as a starting point for your own.
    Config,
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

    /// Rules to apply, replacing the built-in ones. See `velociredactor config`.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

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

    /// The rules to apply: the file given with `--config`, which replaces the
    /// built-in configuration, or the built-in configuration itself.
    fn config(&self) -> Result<Config> {
        match &self.config {
            Some(path) => Ok(Config::from_path(path)?),
            None => Ok(Config::builtin().clone()),
        }
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Redact(args) => redact(args),
        Command::List(args) => list(args),
        Command::Formats => formats(),
        Command::Config => print_builtin_config(),
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

/// Print the built-in configuration verbatim, comments and all.
fn print_builtin_config() -> Result<ExitCode> {
    io::stdout()
        .write_all(Config::builtin_source().as_bytes())
        .context("writing standard output")?;
    Ok(ExitCode::SUCCESS)
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
