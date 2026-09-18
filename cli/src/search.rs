//! `velociredactor grep`: search files, showing matches from their redacted
//! text.
//!
//! Each file is searched twice. The first pass searches the file as it is
//! on disk and only asks whether anything matches. A file that matches is
//! redacted, and the second pass searches the redacted text and prints what
//! it finds. Output therefore never holds a secret, and a search for a
//! secret's own text finds nothing.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::mem;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args};
use grep::printer::{
    JSON, JSONBuilder, Standard, StandardBuilder, Summary, SummaryBuilder, SummaryKind,
};
use grep::regex::{RegexMatcher, RegexMatcherBuilder};
use grep::searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkMatch};
use ignore::types::TypesBuilder;
use termcolor::NoColor;
use velociredactor::FormatHint;

use crate::util::{
    CONFIG_ENV, ConfigArg, Fatal, RulesCache, WalkOptions, display_path, for_each_ordered,
    is_broken_pipe, is_file, walk_builder,
};

/// Flags follow ripgrep's. Output is never colored and never grouped under
/// headings.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("mode").multiple(false)))]
pub struct GrepArgs {
    /// A regular expression, followed by the files or directories to search.
    /// With `-e`, every argument is a path. Directories are searched
    /// recursively; the default is the current directory, and `-` is
    /// standard input.
    #[arg(value_name = "PATTERN|PATH")]
    positional: Vec<String>,

    /// A pattern to search for. Repeat to search for any of several.
    #[arg(
        short = 'e',
        long = "regexp",
        value_name = "PATTERN",
        allow_hyphen_values = true
    )]
    regexp: Vec<String>,

    /// Treat patterns as literal text, not regular expressions.
    #[arg(short = 'F', long)]
    fixed_strings: bool,

    /// Match case-insensitively.
    #[arg(short = 'i', long)]
    ignore_case: bool,

    /// Match case-insensitively unless a pattern has an uppercase letter.
    #[arg(short = 'S', long)]
    smart_case: bool,

    /// Match only whole words.
    #[arg(short = 'w', long)]
    word_regexp: bool,

    /// Match only whole lines.
    #[arg(short = 'x', long)]
    line_regexp: bool,

    /// Select lines that do not match.
    #[arg(short = 'v', long)]
    invert_match: bool,

    /// Let matches span lines.
    #[arg(short = 'U', long)]
    multiline: bool,

    /// With `--multiline`, let `.` match newlines.
    #[arg(long, requires = "multiline")]
    multiline_dotall: bool,

    /// Search only paths matching this glob; a leading `!` excludes instead.
    /// Repeat for more.
    #[arg(short = 'g', long, value_name = "GLOB")]
    glob: Vec<String>,

    /// Search only files of this type, such as `rust` or `yaml`. Repeat for
    /// more.
    #[arg(short = 't', long = "type", value_name = "TYPE")]
    file_type: Vec<String>,

    /// Skip files of this type. Repeat for more.
    #[arg(short = 'T', long = "type-not", value_name = "TYPE")]
    type_not: Vec<String>,

    /// Search hidden files and directories.
    #[arg(long)]
    hidden: bool,

    /// Search files that `.gitignore`, `.ignore` and similar files exclude.
    #[arg(long)]
    no_ignore: bool,

    /// Follow symbolic links.
    #[arg(short = 'L', long)]
    follow: bool,

    /// Descend at most this many directories.
    #[arg(short = 'd', long, value_name = "NUM")]
    max_depth: Option<usize>,

    /// Accepted for grep habits; directories are always searched
    /// recursively.
    #[arg(short = 'r', long, short_alias = 'R', hide = true)]
    recursive: bool,

    /// Show line numbers (the default).
    #[arg(short = 'n', long, overrides_with = "no_line_number")]
    line_number: bool,

    /// Hide line numbers.
    #[arg(short = 'N', long)]
    no_line_number: bool,

    /// Show the file name on each match, even for a single file.
    #[arg(short = 'H', long, overrides_with = "no_filename")]
    with_filename: bool,

    /// Never show file names.
    #[arg(short = 'I', long)]
    no_filename: bool,

    /// Print only the paths of files with a match.
    #[arg(short = 'l', long, group = "mode")]
    files_with_matches: bool,

    /// Print only the paths of files without a match.
    #[arg(long, group = "mode")]
    files_without_match: bool,

    /// Print only the number of matching lines in each file.
    #[arg(short = 'c', long, group = "mode")]
    count: bool,

    /// Print nothing; exit 0 on the first match.
    #[arg(short = 'q', long, group = "mode")]
    quiet: bool,

    /// Print results as ripgrep's JSON Lines messages.
    #[arg(long, group = "mode")]
    json: bool,

    /// Print only the matched part of each line.
    #[arg(short = 'o', long)]
    only_matching: bool,

    /// Show this many lines after each match.
    #[arg(short = 'A', long, value_name = "NUM")]
    after_context: Option<usize>,

    /// Show this many lines before each match.
    #[arg(short = 'B', long, value_name = "NUM")]
    before_context: Option<usize>,

    /// Show this many lines before and after each match.
    #[arg(short = 'C', long, value_name = "NUM")]
    context: Option<usize>,

    /// Stop after this many matching lines in each file.
    #[arg(short = 'm', long, value_name = "NUM")]
    max_count: Option<u64>,

    /// Configuration file, replacing the built-in one. When omitted, each
    /// file uses the configuration found from its own directory.
    #[arg(long, value_name = "FILE", env = CONFIG_ENV)]
    config: Option<PathBuf>,
}

/// How results are printed. Each file prints into a buffer of its own, so
/// files can be searched in parallel and their results written in order.
enum Printer {
    Standard(Standard<NoColor<Vec<u8>>>),
    Summary(Summary<NoColor<Vec<u8>>>),
    Json(JSON<Vec<u8>>),
}

impl Printer {
    /// Search `data` for `path` and print the results. True when something
    /// matched.
    fn search(
        &mut self,
        searcher: &mut Searcher,
        matcher: &RegexMatcher,
        path: &Path,
        data: &[u8],
    ) -> io::Result<bool> {
        fn run<S: Sink<Error = io::Error>>(
            searcher: &mut Searcher,
            matcher: &RegexMatcher,
            data: &[u8],
            mut sink: S,
            has_match: impl Fn(&S) -> bool,
        ) -> io::Result<bool> {
            searcher.search_slice(matcher, data, &mut sink)?;
            Ok(has_match(&sink))
        }
        match self {
            Printer::Standard(p) => run(
                searcher,
                matcher,
                data,
                p.sink_with_path(matcher, path),
                |s| s.has_match(),
            ),
            Printer::Summary(p) => run(
                searcher,
                matcher,
                data,
                p.sink_with_path(matcher, path),
                |s| s.has_match(),
            ),
            Printer::Json(p) => run(
                searcher,
                matcher,
                data,
                p.sink_with_path(matcher, path),
                |s| s.has_match(),
            ),
        }
    }

    /// What was printed since the last call.
    fn take(&mut self) -> Vec<u8> {
        match self {
            Printer::Standard(p) => mem::take(p.get_mut().get_mut()),
            Printer::Summary(p) => mem::take(p.get_mut().get_mut()),
            Printer::Json(p) => mem::take(p.get_mut()),
        }
    }
}

/// Records whether a search found a match, and stops it at the first.
struct Probe(bool);

impl Sink for Probe {
    type Error = io::Error;

    fn matched(&mut self, _: &Searcher, _: &SinkMatch<'_>) -> io::Result<bool> {
        self.0 = true;
        Ok(false)
    }
}

/// Something the walk produced, to search or report.
enum Source {
    Stdin,
    Entry(Result<ignore::DirEntry, ignore::Error>),
}

/// What searching one file produced, to be reported in walk order.
#[derive(Default)]
struct Outcome {
    output: Vec<u8>,
    /// Lines for standard error.
    messages: Vec<String>,
    /// Whether the file counts toward exit status 0. Under
    /// `--files-without-match` the printer reports a file without a match
    /// as a hit.
    hit: bool,
    /// Whether the file could not be searched.
    failed: bool,
    /// Whether the search must stop: a configuration could not be loaded.
    fatal: bool,
}

/// What every thread of a search shares.
struct Shared<'a> {
    args: &'a GrepArgs,
    matcher: RegexMatcher,
    rules: RulesCache,
    show_path: bool,
    /// Whether paths defaulted to the current directory, whose `./` is left
    /// off the paths shown.
    implicit_root: bool,
}

/// The searchers and printer of one thread.
struct Worker<'a> {
    shared: &'a Shared<'a>,
    /// Pass 1: whether a file matches at all.
    probe: Searcher,
    /// Pass 2: the matches in a file's redacted text.
    searcher: Searcher,
    printer: Printer,
}

impl<'a> Worker<'a> {
    fn new(shared: &'a Shared<'a>) -> Self {
        let args = shared.args;
        Worker {
            shared,
            // Pass 1 stops at the first match and ignores the output options.
            probe: SearcherBuilder::new()
                .binary_detection(BinaryDetection::quit(b'\x00'))
                .invert_match(args.invert_match)
                .multi_line(args.multiline)
                .line_number(false)
                .build(),
            searcher: searcher(args),
            printer: printer(args, shared.show_path),
        }
    }

    fn search(&mut self, source: Source) -> Outcome {
        let mut outcome = Outcome::default();
        let result = match source {
            Source::Stdin => {
                let mut data = Vec::new();
                io::stdin()
                    .read_to_end(&mut data)
                    .context("reading standard input")
                    .and_then(|_| {
                        self.search_data(Path::new("-"), Path::new("<stdin>"), &data, &mut outcome)
                    })
            }
            Source::Entry(Err(err)) => Err(err.into()),
            Source::Entry(Ok(entry)) if is_file(&entry) => {
                self.search_file(entry.path(), &mut outcome)
            }
            Source::Entry(Ok(_)) => Ok(()),
        };
        if let Err(err) = result {
            outcome.messages.push(format!("error: {err:#}"));
            outcome.failed = true;
            outcome.fatal = err.is::<Fatal>();
        }
        outcome.output = self.printer.take();
        outcome
    }

    fn search_file(&mut self, path: &Path, outcome: &mut Outcome) -> Result<()> {
        let display = display_path(path, self.shared.implicit_root);
        let data = fs::read(path).with_context(|| format!("reading {}", display.display()))?;
        self.search_data(path, display, &data, outcome)
    }

    /// Search `data`, read from `path` (`-` for standard input) and shown as
    /// `display`.
    fn search_data(
        &mut self,
        path: &Path,
        display: &Path,
        data: &[u8],
        outcome: &mut Outcome,
    ) -> Result<()> {
        let matcher = &self.shared.matcher;
        let mut probe = Probe(false);
        self.probe
            .search_slice(matcher, data, &mut probe)
            .with_context(|| format!("searching {}", display.display()))?;
        if !probe.0 {
            // Nothing to redact. This prints only under
            // `--files-without-match`, and then only the path.
            outcome.hit = self
                .printer
                .search(&mut self.searcher, matcher, display, b"")?;
            return Ok(());
        }

        let stdin = path == Path::new("-");
        let (rules, hint) = if stdin {
            (self.shared.rules.for_directory(None)?, FormatHint::Auto)
        } else {
            (self.shared.rules.for_file(path)?, FormatHint::Path(path))
        };
        let redaction = rules
            .redactor
            .redact(data, hint)
            .with_context(|| format!("redacting {}", display.display()))?;
        for warning in redaction.warnings() {
            outcome
                .messages
                .push(format!("warning: {}: {warning}", display.display()));
        }
        let redacted = redaction
            .render(&rules.allow)
            .with_context(|| format!("redacting {}", display.display()))?;
        outcome.hit = self
            .printer
            .search(&mut self.searcher, matcher, display, &redacted)?;
        Ok(())
    }
}

pub fn grep(args: GrepArgs) -> Result<ExitCode> {
    match run(&args) {
        Err(err) if is_broken_pipe(&err) => Ok(ExitCode::SUCCESS),
        result => result,
    }
}

fn run(args: &GrepArgs) -> Result<ExitCode> {
    let (patterns, paths, implicit_root) = split_positional(args)?;
    let shared = Shared {
        args,
        matcher: matcher(args, &patterns)?,
        rules: RulesCache::new(ConfigArg {
            config: args.config.clone(),
        }),
        show_path: !args.no_filename
            && (args.with_filename || paths.len() > 1 || paths.iter().any(|p| p.is_dir())),
        implicit_root,
    };

    // Build every walker first, so a bad `--glob` or `--type` fails before
    // anything is searched.
    let mut sources: Vec<Box<dyn Iterator<Item = Source> + Send>> = Vec::new();
    for path in &paths {
        if path == Path::new("-") {
            sources.push(Box::new(std::iter::once(Source::Stdin)));
        } else {
            sources.push(Box::new(walker(args, path)?.map(Source::Entry)));
        }
    }

    let context = args.context.or(args.before_context).or(args.after_context);
    let separate_files = matches!(printer(args, false), Printer::Standard(_))
        && context.is_some_and(|lines| lines > 0);

    let mut failed = false;
    let mut found = false;
    let mut printed = false;
    let mut stdout = BufWriter::new(io::stdout().lock());
    let stop = AtomicBool::new(false);
    let unreported = for_each_ordered(
        sources.into_iter().flatten(),
        &stop,
        || Worker::new(&shared),
        |worker, source| {
            let outcome = worker.search(source);
            if outcome.fatal {
                stop.store(true, Ordering::Relaxed);
            }
            outcome
        },
        |mut outcome| {
            if !outcome.messages.is_empty() {
                stdout.flush().context("writing standard output")?;
                for message in &outcome.messages {
                    eprintln!("{message}");
                }
            }
            failed |= outcome.failed;
            found |= outcome.hit;
            if outcome.fatal || (args.quiet && found) {
                return Ok(false);
            }
            if outcome.output.is_empty() {
                return Ok(true);
            }
            // One printer would separate context groups across files; each
            // file has its own, so separate them here.
            if separate_files && printed {
                outcome.output.splice(0..0, *b"--\n");
            }
            printed = true;
            stdout
                .write_all(&outcome.output)
                .context("writing standard output")?;
            Ok(true)
        },
    )?;
    // A configuration failed, and the search stopped before the files ahead
    // of it were reported.
    if let Some(outcome) = unreported.iter().find(|outcome| outcome.fatal) {
        stdout.flush().context("writing standard output")?;
        for message in &outcome.messages {
            eprintln!("{message}");
        }
        failed = true;
    }

    stdout.flush().context("writing standard output")?;
    Ok(if args.quiet && found {
        ExitCode::SUCCESS
    } else if failed {
        ExitCode::from(2)
    } else if found {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// The patterns, the paths to search, and whether the paths defaulted to
/// the current directory.
fn split_positional(args: &GrepArgs) -> Result<(Vec<String>, Vec<PathBuf>, bool)> {
    // Without `-e`, the first argument is the pattern.
    let mut positional = args.positional.iter();
    let mut patterns = Vec::new();
    if args.regexp.is_empty() {
        let Some(pattern) = positional.next() else {
            bail!("no pattern given");
        };
        patterns.push(pattern.clone());
    }
    patterns.extend(args.regexp.iter().cloned());
    let paths: Vec<PathBuf> = positional.map(PathBuf::from).collect();
    if paths.is_empty() {
        return Ok((patterns, vec![PathBuf::from(".")], true));
    }
    Ok((patterns, paths, false))
}

fn matcher(args: &GrepArgs, patterns: &[String]) -> Result<RegexMatcher> {
    let mut builder = RegexMatcherBuilder::new();
    builder
        .case_insensitive(args.ignore_case)
        .case_smart(args.smart_case && !args.ignore_case)
        .word(args.word_regexp)
        .whole_line(args.line_regexp)
        .fixed_strings(args.fixed_strings)
        // `^` and `$` match at line boundaries, as in grep.
        .multi_line(true)
        .dot_matches_new_line(args.multiline_dotall);
    if !args.multiline {
        // Keeps matches within a line, which lets the searcher go line by
        // line.
        builder.line_terminator(Some(b'\n'));
    }
    builder.build_many(patterns).context("parsing the pattern")
}

/// The searcher for pass 2, which prints.
fn searcher(args: &GrepArgs) -> Searcher {
    let before = args.before_context.or(args.context).unwrap_or(0);
    let after = args.after_context.or(args.context).unwrap_or(0);
    SearcherBuilder::new()
        // The redacted text of a file pass 1 found to be text.
        .binary_detection(BinaryDetection::quit(b'\x00'))
        .invert_match(args.invert_match)
        .multi_line(args.multiline)
        .line_number(!args.no_line_number)
        .before_context(before)
        .after_context(after)
        .max_matches(args.max_count)
        .build()
}

fn printer(args: &GrepArgs, show_path: bool) -> Printer {
    let out = Vec::new();
    let summary = if args.files_with_matches {
        Some(SummaryKind::PathWithMatch)
    } else if args.files_without_match {
        Some(SummaryKind::PathWithoutMatch)
    } else if args.count {
        Some(SummaryKind::Count)
    } else if args.quiet {
        Some(SummaryKind::QuietWithMatch)
    } else {
        None
    };
    if let Some(kind) = summary {
        Printer::Summary(
            SummaryBuilder::new()
                .kind(kind)
                .path(show_path)
                .build_no_color(out),
        )
    } else if args.json {
        Printer::Json(JSONBuilder::new().build(out))
    } else {
        Printer::Standard(
            StandardBuilder::new()
                .path(show_path)
                .only_matching(args.only_matching)
                .build_no_color(out),
        )
    }
}

/// Walk `root` in path order, honoring ignore files, globs and types.
fn walker(args: &GrepArgs, root: &Path) -> Result<ignore::Walk> {
    let mut builder = walk_builder(
        root,
        &WalkOptions {
            globs: &args.glob,
            hidden: args.hidden,
            ignored: args.no_ignore,
            follow: args.follow,
            max_depth: args.max_depth,
            skipped_dirs: &[],
        },
    )?;
    let mut types = TypesBuilder::new();
    types.add_defaults();
    for name in &args.file_type {
        types.select(name);
    }
    for name in &args.type_not {
        types.negate(name);
    }
    builder.types(types.build().context("parsing --type")?);
    Ok(builder.build())
}
