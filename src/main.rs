use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use stripsecret::detect::{
    EntropyDetector, Pack, Pii, RegexDetector, RulesetDetector, load_pack_dir,
};
use stripsecret::{Allow, Finding, FormatHint, Redaction, Redactor};

/// Redact secrets and personal data from files.
///
/// Each redacted value becomes a token `REDACTION-N`, where `N` numbers
/// distinct secrets in order of first appearance. Equal values share a
/// number. False positives can be let through with `--allow-value`.
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

    /// Input format. Detected from the file name or content when omitted.
    #[arg(short, long, value_name = "NAME")]
    format: Option<String>,

    /// Treat the input as plain text, skipping format detection.
    #[arg(long, conflicts_with = "format")]
    raw: bool,

    /// Entropy threshold in bits per byte. Tokens above this are redacted.
    #[arg(long, value_name = "BITS", default_value_t = EntropyDetector::DEFAULT_THRESHOLD)]
    entropy_threshold: f64,

    /// Entropy threshold for values under a sensitive key (api_key, token, …).
    #[arg(long, value_name = "BITS", default_value_t = EntropyDetector::SENSITIVE_THRESHOLD)]
    sensitive_threshold: f64,

    /// Leave this exact value unredacted (repeatable).
    #[arg(long, value_name = "VALUE")]
    allow_value: Vec<String>,

    /// Also redact personal data (comma-separated: email, phone, address).
    #[arg(long, value_name = "KINDS", value_delimiter = ',')]
    pii: Vec<Pii>,

    /// Extra personal-data pattern (repeatable).
    #[arg(long, value_name = "LABEL=REGEX")]
    pii_pattern: Vec<String>,

    /// Extra secret pattern (repeatable).
    #[arg(long, value_name = "LABEL=REGEX")]
    rule: Vec<String>,

    /// Rule pack file, or directory of packs (repeatable).
    #[arg(long, value_name = "PATH")]
    rules_pack: Vec<PathBuf>,

    /// Use this betterleaks/gitleaks ruleset instead of the bundled one.
    #[arg(long, value_name = "FILE")]
    ruleset: Option<PathBuf>,
}

impl InputArgs {
    fn path(&self) -> Option<&Path> {
        self.file.as_deref().filter(|p| *p != Path::new("-"))
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Redact(args) => redact(args),
        Command::List(args) => list(args),
        Command::Formats => formats(),
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
    let redactor = build_redactor(&args.input)?;
    let input = read_input(path)?;
    let (redaction, allow) = scan(&redactor, &args.input, &input)?;

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
    let redactor = build_redactor(&args.input)?;
    let input = read_input(args.input.path())?;
    let (redaction, allow) = scan(&redactor, &args.input, &input)?;

    let mut stdout = io::stdout().lock();
    if args.json {
        print_json(&mut stdout, &redaction, &allow, args.show_value)?;
    } else {
        print_table(&mut stdout, &redaction, &allow, args.show_value)?;
    }
    Ok(exit_code(args.check, &redaction, &allow))
}

fn formats() -> Result<ExitCode> {
    let redactor = Redactor::builder().build();
    for format in redactor.formats().iter() {
        println!("{:<12} {}", format.name(), format.extensions().join(", "));
    }
    Ok(ExitCode::SUCCESS)
}

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
    args: &InputArgs,
    input: &'a [u8],
) -> Result<(Redaction<'a>, Allow)> {
    let hint = match (&args.format, args.raw, args.path()) {
        (Some(name), _, _) => {
            if redactor.formats().get(name).is_none() {
                let names: Vec<_> = redactor.formats().names().collect();
                bail!("unknown format {name:?} (available: {})", names.join(", "));
            }
            FormatHint::Name(name)
        }
        (None, true, _) => FormatHint::Raw,
        (None, false, Some(path)) => FormatHint::Path(path),
        (None, false, None) => FormatHint::Auto,
    };

    let redaction = redactor.redact(input, hint)?;
    let allow = Allow::values(args.allow_value.iter().cloned());

    for warning in redaction.warnings() {
        eprintln!("warning: {warning}");
    }
    let unmatched_values = allow.unmatched_value_count(redaction.findings());
    if unmatched_values > 0 {
        eprintln!("warning: {unmatched_values} --allow-value value(s) matched no redaction");
    }
    Ok((redaction, allow))
}

fn build_redactor(args: &InputArgs) -> Result<Redactor> {
    let mut builder = Redactor::builder()
        .entropy_threshold(args.entropy_threshold)
        .sensitive_threshold(args.sensitive_threshold)
        .pii(args.pii.iter().copied());

    if let Some(path) = &args.ruleset {
        builder = builder.ruleset(RulesetDetector::from_path(path)?);
    }
    for spec in &args.rule {
        let (label, pattern) = split_spec(spec, "--rule")?;
        builder = builder.detector(RegexDetector::new(label, pattern)?);
    }
    for spec in &args.pii_pattern {
        let (label, pattern) = split_spec(spec, "--pii-pattern")?;
        builder = builder.detector(RegexDetector::new(format!("pii:{label}"), pattern)?);
    }
    for path in &args.rules_pack {
        let packs = if path.is_dir() {
            let loaded = load_pack_dir(path)?;
            for warning in &loaded.warnings {
                eprintln!("warning: {warning}");
            }
            loaded.packs
        } else {
            let source =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            vec![Pack::parse(&source, path)?]
        };
        for pack in packs {
            let (detectors, warnings) = pack.detectors();
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            for detector in detectors {
                builder = builder.detector(detector);
            }
        }
    }
    Ok(builder.build())
}

fn split_spec<'a>(spec: &'a str, flag: &str) -> Result<(&'a str, &'a str)> {
    match spec.split_once('=') {
        Some((label, pattern)) if !label.is_empty() && !pattern.is_empty() => Ok((label, pattern)),
        _ => bail!("{flag} expects LABEL=REGEX"),
    }
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
    if let Some(field) = &finding.field {
        parts.push(format!("[{field}]"));
    }
    parts.join(" ")
}
