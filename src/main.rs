use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;
use redactify::detect::{Pack, Pii, RegexDetector, RulesetDetector, load_pack_dir};
use redactify::{Allow, Finding, FormatHint, Redaction, Redactor};

/// Redact secrets and personal data from a file.
///
/// Each distinct redacted value becomes a numbered token such as
/// `REDACTION-3`. Numbers are stable for a given input and configuration, so
/// false positives can be let through by re-running with `--allow 3`.
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    /// File to redact. Reads standard input when omitted or `-`.
    file: Option<PathBuf>,

    /// Input format. Detected from the file name or content when omitted.
    #[arg(short, long, value_name = "NAME")]
    format: Option<String>,

    /// Redaction numbers to leave unredacted (comma-separated, repeatable).
    #[arg(short, long, value_name = "IDS", value_delimiter = ',')]
    allow: Vec<u32>,

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

    /// Write the result to this file instead of standard output.
    #[arg(short, long, value_name = "FILE", conflicts_with = "in_place")]
    output: Option<PathBuf>,

    /// Overwrite the input file with the result.
    #[arg(short, long, requires = "file")]
    in_place: bool,

    /// Print a table of redactions to standard error.
    #[arg(short, long)]
    list: bool,

    /// Exit with status 1 if anything was redacted (after `--allow`).
    #[arg(long)]
    check: bool,

    /// Print the available formats and exit.
    #[arg(long)]
    list_formats: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let redactor = build_redactor(&cli)?;

    if cli.list_formats {
        for format in redactor.formats().iter() {
            println!("{:<12} {}", format.name(), format.extensions().join(", "));
        }
        return Ok(ExitCode::SUCCESS);
    }

    let path = cli.file.as_deref().filter(|p| *p != Path::new("-"));
    let input = match path {
        Some(path) => fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        None => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .context("reading standard input")?;
            buf
        }
    };

    let hint = match (&cli.format, path) {
        (Some(name), _) => {
            if redactor.formats().get(name).is_none() {
                let names: Vec<_> = redactor.formats().names().collect();
                bail!("unknown format {name:?} (available: {})", names.join(", "));
            }
            FormatHint::Name(name)
        }
        (None, Some(path)) => FormatHint::Path(path),
        (None, None) => FormatHint::Auto,
    };

    let redaction = redactor.redact(&input, hint)?;
    for warning in redaction.warnings() {
        eprintln!("warning: {warning}");
    }

    let allow = Allow::ids(cli.allow.iter().copied());
    let known: BTreeSet<u32> = redaction.findings().iter().map(|f| f.id).collect();
    for id in cli.allow.iter().filter(|id| !known.contains(id)) {
        eprintln!("warning: --allow {id}: no such redaction");
    }

    let output = redaction.render(&allow)?;
    if cli.list {
        print_table(&redaction, &allow);
    }

    match (&cli.output, cli.in_place, path) {
        (Some(out), _, _) => {
            fs::write(out, &output).with_context(|| format!("writing {}", out.display()))?
        }
        (None, true, Some(path)) => {
            fs::write(path, &output).with_context(|| format!("writing {}", path.display()))?
        }
        _ => io::stdout()
            .write_all(&output)
            .context("writing standard output")?,
    }

    let remaining = redaction.findings().iter().any(|f| !allow.contains(f.id));
    Ok(if cli.check && remaining {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn build_redactor(cli: &Cli) -> Result<Redactor> {
    let mut builder = Redactor::builder().pii(cli.pii.iter().copied());

    if let Some(path) = &cli.ruleset {
        builder = builder.ruleset(RulesetDetector::from_path(path)?);
    }
    for spec in &cli.rule {
        let (label, pattern) = split_spec(spec, "--rule")?;
        builder = builder.detector(RegexDetector::new(label, pattern)?);
    }
    for spec in &cli.pii_pattern {
        let (label, pattern) = split_spec(spec, "--pii-pattern")?;
        builder = builder.detector(RegexDetector::new(format!("pii:{label}"), pattern)?);
    }
    for path in &cli.rules_pack {
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

fn print_table(redaction: &Redaction<'_>, allow: &Allow) {
    let mut stderr = io::stderr().lock();
    if redaction.findings().is_empty() {
        let _ = writeln!(stderr, "no redactions");
        return;
    }
    let rows: Vec<[String; 5]> = redaction
        .findings()
        .iter()
        .map(|f| {
            let status = if allow.contains(f.id) { "allowed" } else { "" };
            [
                redactify::token(f.id),
                f.detector.clone(),
                location(redaction, f),
                preview(f),
                status.to_owned(),
            ]
        })
        .collect();
    let header = ["TOKEN", "DETECTOR", "LOCATION", "VALUE", ""].map(String::from);
    let mut widths = [0; 5];
    for row in std::iter::once(&header).chain(&rows) {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    for row in std::iter::once(&header).chain(&rows) {
        let line: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        let _ = writeln!(stderr, "{}", line.join("  ").trim_end());
    }
}

fn location(redaction: &Redaction<'_>, finding: &Finding) -> String {
    let mut parts = Vec::new();
    if let Some(offset) = finding.offset {
        let (line, col) = redaction.line_col(offset);
        parts.push(format!("{line}:{col}"));
    }
    if let Some(key) = &finding.key {
        parts.push(format!("[{key}]"));
    }
    if finding.occurrences > 1 {
        parts.push(format!("(x{})", finding.occurrences));
    }
    parts.join(" ")
}

/// A short hint of the redacted value that does not reveal it.
fn preview(finding: &Finding) -> String {
    let chars: Vec<char> = finding.secret.chars().collect();
    let shown = (chars.len() / 5).min(4);
    let head: String = chars[..shown]
        .iter()
        .map(|c| if c.is_control() { ' ' } else { *c })
        .collect();
    format!("{head}… ({} chars)", chars.len())
}
