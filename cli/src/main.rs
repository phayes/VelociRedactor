mod scan;
mod search;
mod util;

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use velociredactor::agent::AgentPolicy;
use velociredactor::config::Config;
use velociredactor::detect::privacy_filter;
use velociredactor::{Allow, Finding, FormatHint, Redaction, Redactor};

use crate::util::{
    CONFIG_FILE_NAMES, ConfigArg, SKIPPED_DIRS, WalkOptions, allowed_file_paths, allowed_files,
    anchored_policy, build_redactor, git_root, is_file, shell_quote, walk_builder,
};

/// Redact secrets and personal data from files.
///
/// Each redacted value becomes a token `[REDACTED-N]`, where `N` numbers distinct secrets in order of first appearance.
/// Equal values share a number.
///
/// Configuration defines what counts as a secret.
/// `veloci config show` prints the built-in rules as a starting point:
///
///     veloci config show > veloci.yml
///     veloci redact secrets.json
///
/// Configuration is chosen in this order: `--config`, `$VELOCIREDACTOR_CONFIG`, a discovered `veloci.yml` or `VELOCI.yml`, and the built-in configuration.
/// Discovery stops at a Git repository root, the home directory when running inside it, or the filesystem root.
#[derive(Debug, Parser)]
#[command(name = "veloci", version, about, long_about)]
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
    /// Search files like ripgrep, printing matches from their redacted text.
    ///
    /// Files are searched as they are on disk first. Each file with a match
    /// is redacted and searched again, and only that second search prints.
    /// Output never holds a secret, and searching for a secret finds nothing.
    /// Line numbers count lines of the redacted text, which can be fewer
    /// than the file's when a multi-line secret becomes one token.
    Grep(search::GrepArgs),
    /// List the files that hold secrets.
    ///
    /// Every file is redacted in memory with the configuration found from
    /// its own directory, and each file with anything to redact is listed
    /// with how many values and which detectors found them. Values are
    /// hidden unless `--show-value` is given. Directories are scanned
    /// recursively, including hidden and ignored files, where secrets
    /// usually are, but not Git's files or dependency and build directories.
    /// Binary files are skipped.
    ///
    /// Exits 1 when any file holds secrets, 0 when none does, and 2 on an
    /// error with nothing found.
    Scan(scan::ScanArgs),
    /// List the supported input formats.
    Formats,
    /// Print the complete command-line manual.
    Man,
    /// Inspect or check a configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Manage the OpenAI model behind the `privacy_filter` detector.
    #[command(subcommand, name = "privacy_filter")]
    PrivacyFilter(PrivacyFilterCommand),
    /// Choose and check the files AI coding agents must read redacted.
    ///
    /// Coding agents send everything they read to their model. A project lists
    /// its sensitive files in the `agent` section of `veloci.yml`, and
    /// agents read those files with `veloci redact FILE` and search
    /// them with `veloci grep`, never directly.
    ///
    /// AI agents: run `veloci agent skill velociredactor` for complete
    /// instructions, then `veloci agent status` to see whether this project has
    /// chosen its files. If it has not, ask the user which files to protect
    /// before running `veloci agent init`. If it has, `veloci
    /// scan --unprotected` lists files holding secrets that it leaves out.
    #[command(subcommand)]
    Agent(AgentCommand),
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

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Print the configuration's `agent` section, or that it has none.
    ///
    /// Also lists the files whose contents hold secrets that no `agent`
    /// section protects, as `veloci scan --unprotected` finds them,
    /// but without the slow `privacy_filter` detector. Values are never
    /// shown, and protected files are not read. When the project has not
    /// chosen its protected files yet, also suggests file name patterns, and
    /// how to record a choice with `veloci agent init`.
    Status(AgentStatusArgs),
    /// Print which of the given files agents must read redacted, and exit 1
    /// if any.
    Check(AgentCheckArgs),
    /// Record which files agents must read redacted.
    ///
    /// Adds an `agent` section to the configuration in use, or creates
    /// `veloci.yml` at the repository root from the built-in
    /// configuration when there is none. It refuses to replace an existing
    /// `agent` section; edit that in the file instead.
    ///
    /// AI agents: the user decides what is protected. Run
    /// `veloci agent status` to see candidates, ask the user which to
    /// protect, what to exclude, and whether to enforce, and only then run
    /// this. `veloci agent skill setup` has the full procedure.
    #[command(after_long_help = INIT_HELP)]
    Init(AgentInitArgs),
    /// Print the instructions (Agent Skills) for AI agents using
    /// Veloci Redactor.
    ///
    /// With no name, lists the skills; start with `velociredactor`, which
    /// covers reading, searching and editing protected files. The same skills install as a Claude Code plugin or
    /// into any agent's skills directory; see
    /// https://github.com/phayes/velociredactor/tree/master/plugin.
    Skill(AgentSkillArgs),
    /// Answer a Claude Code PreToolUse hook: read its JSON on standard input
    /// and deny reading a protected file when `enforce` is set.
    Hook(ConfigArg),
}

#[derive(Debug, Args)]
struct AgentStatusArgs {
    #[command(flatten)]
    config: ConfigArg,

    /// Print the status as JSON.
    #[arg(long)]
    json: bool,

    /// Don't read file contents: suggest candidates by file name only.
    #[arg(long)]
    no_scan: bool,

    /// Scan with the `privacy_filter` detector too, when the configuration
    /// enables it. It is left out by default because it is slow.
    #[arg(long, conflicts_with = "no_scan")]
    privacy_filter: bool,
}

#[derive(Debug, Args)]
struct AgentCheckArgs {
    /// Files to check. Each is judged by the configuration found from its own
    /// directory.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    #[command(flatten)]
    config: ConfigArg,
}

#[derive(Debug, Args)]
struct AgentInitArgs {
    /// A path pattern of files to protect, such as `.env*` or `secrets/`.
    /// Repeat for more. Quote it so the shell does not expand it.
    #[arg(long, value_name = "GLOB")]
    protect: Vec<String>,

    /// A path pattern never to protect, even when a `--protect` pattern
    /// matches, such as `.env.example`. Repeat for more.
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

    /// Block agents' own read and search tools on protected files, where the
    /// agent supports hooks (Claude Code with the Veloci Redactor plugin),
    /// instead of only instructing them.
    #[arg(long)]
    enforce: bool,

    #[command(flatten)]
    config: ConfigArg,
}

#[derive(Debug, Args)]
struct AgentSkillArgs {
    /// The skill to print: `velociredactor` (reading, searching and editing
    /// protected files), `setup` (choosing them), `config` (customizing
    /// redaction), or `share` (redacting before sharing). Lists the skills
    /// when omitted.
    #[arg(value_name = "NAME")]
    name: Option<String>,
}

/// Examples and pattern syntax for `agent init --help`.
const INIT_HELP: &str = "\
Patterns follow .gitignore conventions, relative to veloci.yml:
  .env*            no `/`: a file name at any depth
  config/prod.yml  a `/`: anchored at the project root
  secrets/         a trailing `/`: everything in the directory
  exports/**/*.csv `*` stays in one path segment, `**` spans segments

Examples:
  veloci agent init --protect '.env*' --exclude .env.example
  veloci agent init --protect '.env*' --protect '*.pem' \\
      --protect secrets/ --protect '*.log' --enforce

Change the choice later by editing the `agent` section of veloci.yml.";

/// An agent skill embedded in the binary.
struct Skill {
    name: &'static str,
    /// What it covers, in a line.
    summary: &'static str,
    /// Its `SKILL.md`.
    text: &'static str,
    /// Files beside it that it links to, as `(relative path, text)`.
    references: &'static [(&'static str, &'static str)],
}

/// The agent skills, from `plugin/skills`. `cli/skills` is a copy, so the
/// crate carries them when published.
const SKILLS: &[Skill] = &[
    Skill {
        name: "velociredactor",
        summary: "How to read, search and edit protected files. Start here.",
        text: include_str!("../skills/velociredactor/SKILL.md"),
        references: &[],
    },
    Skill {
        name: "velociredactor-setup",
        summary: "Choosing which files to protect, on first use in a project.",
        text: include_str!("../skills/velociredactor-setup/SKILL.md"),
        references: &[],
    },
    Skill {
        name: "velociredactor-config",
        summary: "Customizing what is redacted in veloci.yml.",
        text: include_str!("../skills/velociredactor-config/SKILL.md"),
        references: &[(
            "references/config-reference.md",
            include_str!("../skills/velociredactor-config/references/config-reference.md"),
        )],
    },
    Skill {
        name: "velociredactor-share",
        summary: "Redacting text before it leaves the machine.",
        text: include_str!("../skills/velociredactor-share/SKILL.md"),
        references: &[],
    },
];

/// The complete command-line manual embedded in the binary.
const CLI_README: &str = include_str!("../README.md");

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
    /// a discovered `veloci.yml`, or the built-in configuration.
    fn config(&self) -> Result<Config> {
        self.config.load()
    }

    /// The redactor for the input: with the key paths `allow.file_paths`
    /// names for the input file left unscanned.
    fn redactor(&self, config: &Config) -> Result<Redactor> {
        let redactor = build_redactor(config)?;
        // Parsed even for standard input, so a bad entry is always an error.
        let config_path = self.config.resolved_path()?;
        let file_paths = allowed_file_paths(config, config_path.as_deref())?;
        let Some(path) = self.path() else {
            return Ok(redactor);
        };
        let key_paths = file_paths.for_file(path);
        if key_paths.is_empty() {
            return Ok(redactor);
        }
        Ok(redactor.with_allow_paths(key_paths))
    }

    /// The allow list for the input: everything, when `allow.files` in the
    /// configuration names the input file.
    fn allow(&self, config: &Config) -> Result<Allow> {
        if let Some(path) = self.path() {
            let config_path = self.config.resolved_path()?;
            if allowed_files(config, config_path.as_deref())?.matches(path) {
                return Ok(Allow::all());
            }
        }
        Ok(config.allow()?)
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Redact(args) => redact(args),
        Command::List(args) => list(args),
        Command::Grep(args) => search::grep(args),
        Command::Scan(args) => scan::run(args),
        Command::Formats => formats(),
        Command::Man => man(),
        Command::Config(ConfigCommand::Show(args)) => show_config(&args),
        Command::Config(ConfigCommand::Location(args)) => locate_config(&args),
        Command::Config(ConfigCommand::Validate(args)) => validate_config(&args),
        Command::PrivacyFilter(PrivacyFilterCommand::Download(args)) => download_model(args),
        Command::Agent(AgentCommand::Status(args)) => agent_status(&args),
        Command::Agent(AgentCommand::Check(args)) => agent_check(&args),
        Command::Agent(AgentCommand::Init(args)) => agent_init(&args),
        Command::Agent(AgentCommand::Skill(args)) => agent_skill(&args),
        Command::Agent(AgentCommand::Hook(args)) => agent_hook(&args),
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
    let redactor = args.input.redactor(&config)?;
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
    let redactor = args.input.redactor(&config)?;
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

/// The `agent` section of the configuration found from `start`, anchored at
/// that configuration's directory, if there is one.
fn agent_policy(args: &ConfigArg, start: &Path) -> Result<Option<AgentPolicy>> {
    // The built-in configuration never chooses agent files.
    let Some(path) = args.resolved_path_from(start) else {
        return Ok(None);
    };
    anchored_policy(&Config::from_path(&path)?, &path)
}

/// The directory to discover the configuration of `path` from.
fn directory_of(path: &Path) -> Result<PathBuf> {
    let path =
        std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    if path.is_dir() {
        return Ok(path);
    }
    Ok(path.parent().map_or(path.clone(), Path::to_path_buf))
}

/// Print the configuration's `agent` section.
fn agent_status(args: &AgentStatusArgs) -> Result<ExitCode> {
    let path = args.config.resolved_path()?;
    let config = args.config.load()?;
    let configured = path.is_some() && config.agent.is_some();
    let agent = config.agent.unwrap_or_default();

    let root = project_root(path.as_deref())?;
    let candidates = if configured {
        Vec::new()
    } else {
        find_candidates(&root)
    };
    let secrets = if args.no_scan {
        Vec::new()
    } else {
        find_secrets(&root, &args.config, !args.privacy_filter)?
    };

    if args.json {
        let suggested: Vec<_> = candidates
            .iter()
            .map(|c| json!({ "flag": c.flag, "pattern": c.pattern, "what": c.what, "examples": c.examples }))
            .collect();
        let secrets: Vec<_> = secrets
            .iter()
            .map(|hit| {
                json!({
                    "path": hit.path.display().to_string(),
                    "count": hit.findings.len(),
                    "detectors": hit.detectors(),
                })
            })
            .collect();
        let status = json!({
            "config": path.as_ref().map(|p| p.display().to_string()),
            "configured": configured,
            "protected": agent.protected,
            "exclude": agent.exclude,
            "enforce": agent.enforce,
            "suggested": suggested,
            "scanned": !args.no_scan,
            "secrets": secrets,
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(ExitCode::SUCCESS);
    }

    match &path {
        Some(path) => println!("config:    {}", path.display()),
        None => println!("config:    [builtin-default]"),
    }
    if !configured {
        println!("agent:     not configured\n");
        print!("{}", not_configured_help(&candidates, &secrets));
        return Ok(ExitCode::SUCCESS);
    }
    println!("protected: {}", agent.protected.join(" "));
    println!("exclude:   {}", agent.exclude.join(" "));
    println!("enforce:   {}", agent.enforce);
    if !secrets.is_empty() {
        println!("\nUnprotected files whose contents hold likely secrets (values not shown):");
        print!("{}", secrets_list(&secrets));
        println!(
            "\nAI agents: read and search these only through `veloci redact`\n\
             and `veloci grep`, and ask the user whether to add them to the\n\
             agent section of the configuration."
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Print each file agents must read redacted; exit 1 if there are any.
fn agent_check(args: &AgentCheckArgs) -> Result<ExitCode> {
    let mut any = false;
    for file in &args.files {
        let policy = agent_policy(&args.config, &directory_of(file)?)?;
        if policy.is_some_and(|policy| policy.is_protected(file)) {
            println!("{}", file.display());
            any = true;
        }
    }
    Ok(if any {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Add an `agent` section to the configuration, creating one if needed.
fn agent_init(args: &AgentInitArgs) -> Result<ExitCode> {
    if args.protect.is_empty() {
        let root = project_root(args.config.resolved_path()?.as_deref())?;
        let (candidates, secrets) = (
            find_candidates(&root),
            find_secrets(&root, &args.config, true)?,
        );
        eprintln!("error: name the files to protect with --protect GLOB\n");
        eprint!("{}", not_configured_help(&candidates, &secrets));
        return Ok(ExitCode::from(2));
    }
    let path = match args.config.resolved_path()? {
        Some(path) => path,
        None => {
            let cwd = std::env::current_dir().context("determining the current directory")?;
            git_root(&cwd).unwrap_or(cwd).join(CONFIG_FILE_NAMES[0])
        }
    };

    let mut source = if path.exists() {
        let config = Config::from_path(&path)?;
        if config.agent.is_some() {
            bail!(
                "{} already has an agent section; edit it there",
                path.display()
            );
        }
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
    } else {
        // A configuration replaces the built-in one entirely, so start from
        // all of it rather than from the agent section alone.
        Config::builtin_source().to_owned()
    };

    if !source.ends_with('\n') {
        source.push('\n');
    }
    source.push_str(&agent_section(args));
    fs::write(&path, &source).with_context(|| format!("writing {}", path.display()))?;
    eprintln!("wrote the agent section to {}", path.display());

    let (errors, warnings) = Config::from_path(&path)?.validate();
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

/// The YAML `agent` section `agent init` appends.
fn agent_section(args: &AgentInitArgs) -> String {
    // JSON strings are YAML strings, and quoting keeps a leading `*` from
    // being read as an alias.
    let list = |globs: &[String]| -> String {
        globs
            .iter()
            .map(|glob| format!("    - {}\n", json!(glob)))
            .collect()
    };
    let mut section = String::from(
        "\n# Files AI coding agents must read redacted; see `veloci agent`.\nagent:\n  protected:\n",
    );
    section.push_str(&list(&args.protect));
    if args.exclude.is_empty() {
        section.push_str("  exclude: []\n");
    } else {
        section.push_str("  exclude:\n");
        section.push_str(&list(&args.exclude));
    }
    section.push_str(&format!("  enforce: {}\n", args.enforce));
    section
}

/// Answer a Claude Code PreToolUse hook.
///
/// Claude Code treats exit status 2 as a verdict to block the tool call, so
/// every failure here exits 1 instead: a broken configuration must not stop
/// the agent reading anything at all.
fn agent_hook(args: &ConfigArg) -> Result<ExitCode> {
    match hook_denial(args) {
        Ok(Some(reason)) => {
            let output = json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            });
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Ok(None) => Ok(ExitCode::SUCCESS),
        Err(err) => {
            eprintln!("veloci agent hook: {err:#}");
            Ok(ExitCode::from(1))
        }
    }
}

/// Why the tool call on standard input must be denied, if it must.
fn hook_denial(args: &ConfigArg) -> Result<Option<String>> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("reading the hook input")?;
    let input: serde_json::Value =
        serde_json::from_str(&input).context("parsing the hook input")?;

    // `Read` names a `file_path`. `Grep` names a `path`, a file or a
    // directory, and searches the current directory without one.
    let tool_input = &input["tool_input"];
    let grep = input["tool_name"] == "Grep";
    let Some(target) = tool_input["file_path"]
        .as_str()
        .or_else(|| tool_input["path"].as_str())
        .or(grep.then_some("."))
    else {
        return Ok(None);
    };
    let target = match input["cwd"].as_str() {
        Some(cwd) => Path::new(cwd).join(target),
        None => PathBuf::from(target),
    };

    let Some(policy) = agent_policy(args, &directory_of(&target)?)? else {
        return Ok(None);
    };
    if !policy.enforce() {
        return Ok(None);
    }
    let Some(protected) = first_protected(&policy, &target) else {
        return Ok(None);
    };

    let shown = target.display().to_string();
    if !grep {
        return Ok(Some(format!(
            "{shown} is protected by Veloci Redactor. Read it with \
             `veloci redact {}` instead; redacted values appear as \
             [REDACTED-N] tokens.",
            shell_quote(&shown),
        )));
    }
    let pattern = tool_input["pattern"].as_str().unwrap_or("PATTERN");
    let within = if protected == target {
        format!("{shown} is protected by Veloci Redactor")
    } else {
        format!(
            "{shown} holds files protected by Veloci Redactor, such as {}",
            protected.display()
        )
    };
    Ok(Some(format!(
        "{within}. Search with `veloci grep {} {}` instead: it takes \
         ripgrep's options and prints matches from redacted text.",
        shell_quote(pattern),
        shell_quote(&shown),
    )))
}

/// `target` if it is a protected file, or else the first protected file a
/// search of it would reach, walking as ripgrep does by default but
/// including hidden files.
fn first_protected(policy: &AgentPolicy, target: &Path) -> Option<PathBuf> {
    if !target.is_dir() {
        return policy.is_protected(target).then(|| target.to_owned());
    }
    ignore::WalkBuilder::new(target)
        .hidden(false)
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .map(ignore::DirEntry::into_path)
        .find(|path| policy.is_protected(path))
}

/// Print an agent skill, or list them.
fn agent_skill(args: &AgentSkillArgs) -> Result<ExitCode> {
    let Some(name) = &args.name else {
        print!("{}", skill_list());
        return Ok(ExitCode::SUCCESS);
    };
    let wanted = name.trim_start_matches("velociredactor-");
    let Some(skill) = SKILLS.iter().find(|skill| {
        skill.name == name || skill.name.strip_prefix("velociredactor-") == Some(wanted)
    }) else {
        bail!("no skill {name:?}\n\n{}", skill_list());
    };

    let mut out = io::stdout().lock();
    out.write_all(skill.text.as_bytes())?;
    // References are separate files beside the skill; print them after it,
    // so the relative links in it still lead somewhere.
    for (path, reference) in skill.references {
        write!(out, "\n\n---\n\n<!-- {path} -->\n\n{reference}")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// The skills, and how to print them.
fn skill_list() -> String {
    let mut list = String::from(
        "Instructions for AI coding agents using Veloci Redactor, as Agent Skills\n\
         (https://agentskills.io):\n\n",
    );
    for skill in SKILLS {
        list.push_str(&format!("  {:<24} {}\n", skill.name, skill.summary));
    }
    list.push_str(
        "\nPrint one with `veloci agent skill NAME`; the `velociredactor-`\n\
         prefix is optional. Start with:\n\n\
         \x20   veloci agent skill velociredactor\n\n\
         To install them for an agent instead, copy them into its skills directory\n\
         or add the Claude Code plugin: https://github.com/phayes/velociredactor/tree/master/plugin\n",
    );
    list
}

/// A pattern `agent init` might be given, with files in the project it
/// would cover.
struct Candidate {
    /// `--protect` or `--exclude`.
    flag: &'static str,
    pattern: &'static str,
    what: &'static str,
    examples: Vec<String>,
}

/// Commonly sensitive files, as `(flag, pattern, what they are)`. Exclusions
/// follow the patterns they carve exceptions from.
const CANDIDATES: &[(&str, &str, &str)] = &[
    ("--protect", ".env*", "environment files"),
    ("--exclude", ".env.example", "sample environment file"),
    ("--exclude", ".env.sample", "sample environment file"),
    ("--exclude", ".env.template", "sample environment file"),
    ("--protect", "*.pem", "keys and certificates"),
    ("--protect", "*.key", "private keys"),
    ("--protect", "*.p12", "key stores"),
    ("--protect", "*.pfx", "key stores"),
    ("--protect", "*.jks", "key stores"),
    ("--protect", "id_rsa*", "SSH keys"),
    ("--protect", "id_ed25519*", "SSH keys"),
    ("--protect", "credentials*", "credentials"),
    ("--protect", "secrets/", "secrets directory"),
    ("--protect", "*.secrets.*", "secrets files"),
    ("--protect", ".npmrc", "package registry tokens"),
    ("--protect", ".pypirc", "package registry tokens"),
    ("--protect", ".netrc", "login credentials"),
    ("--protect", "*.kubeconfig", "cluster credentials"),
    ("--protect", "*.tfstate*", "Terraform state"),
    ("--protect", "*.tfvars", "Terraform variables"),
    ("--protect", "*.log", "logs"),
    ("--protect", "*.har", "HTTP captures"),
    ("--protect", "*.sql", "database dumps"),
    ("--protect", "*.dump", "database dumps"),
    ("--protect", "*.sqlite", "databases"),
    ("--protect", "*.db", "databases"),
];

/// The directory the protected files are chosen for: the configuration's,
/// or the repository root, or the current directory.
fn project_root(config: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = config.and_then(Path::parent) {
        let dir = std::path::absolute(dir).context("resolving the configuration directory")?;
        return Ok(dir);
    }
    let cwd = std::env::current_dir().context("determining the current directory")?;
    Ok(git_root(&cwd).unwrap_or(cwd))
}

/// The [`CANDIDATES`] with files under `root`, found by name alone.
/// Ignored and hidden files are included, since that is where secrets
/// usually are.
fn find_candidates(root: &Path) -> Vec<Candidate> {
    use velociredactor::agent::AgentConfig;

    const MAX_FILES: usize = 50_000;
    const MAX_EXAMPLES: usize = 3;

    let policies: Vec<_> = CANDIDATES
        .iter()
        .map(|(_, pattern, _)| {
            let config = AgentConfig {
                protected: vec![pattern.to_string()],
                ..AgentConfig::default()
            };
            AgentPolicy::new(&config, root)
        })
        .collect();
    let mut examples = vec![Vec::new(); CANDIDATES.len()];

    let walk = walk_builder(
        root,
        &WalkOptions {
            globs: &[],
            hidden: true,
            ignored: true,
            follow: false,
            max_depth: Some(8),
            skipped_dirs: SKIPPED_DIRS,
        },
    );
    let Ok(walk) = walk else {
        return Vec::new();
    };
    let files = walk
        .build()
        .filter_map(Result::ok)
        .filter(is_file)
        .take(MAX_FILES);
    for entry in files {
        let path = entry.path();
        for (policy, found) in policies.iter().zip(&mut examples) {
            if found.len() < MAX_EXAMPLES && policy.is_protected(path) {
                let shown = path.strip_prefix(root).unwrap_or(path);
                found.push(shown.display().to_string());
            }
        }
    }

    CANDIDATES
        .iter()
        .zip(examples)
        .filter(|(_, examples)| !examples.is_empty())
        .map(|(&(flag, pattern, what), examples)| Candidate {
            flag,
            pattern,
            what,
            examples,
        })
        .collect()
}

/// The unprotected files under `root` whose contents hold secrets, as
/// `veloci scan --unprotected` finds them, with paths relative to
/// `root`. `skip_model` leaves out the slow `privacy_filter` detector.
fn find_secrets(root: &Path, config: &ConfigArg, skip_model: bool) -> Result<Vec<scan::Hit>> {
    let report = scan::scan(
        &[root.to_owned()],
        &scan::Scan::project(root, skip_model),
        config.clone(),
    )?;
    Ok(report.hits)
}

/// Files with secrets, one per line, up to a limit.
fn secrets_list(secrets: &[scan::Hit]) -> String {
    const MAX_SECRETS: usize = 20;

    let mut list = String::new();
    for hit in secrets.iter().take(MAX_SECRETS) {
        let path = hit.path.display().to_string();
        list.push_str(&format!(
            "  {path:<28} {} ({})\n",
            hit.findings.len(),
            hit.detectors().join(", ")
        ));
    }
    if secrets.len() > MAX_SECRETS {
        list.push_str(&format!(
            "  ... and {} more; `veloci scan --unprotected` lists them all\n",
            secrets.len() - MAX_SECRETS
        ));
    }
    list
}

/// What to do about a project with no `agent` section.
fn not_configured_help(candidates: &[Candidate], secrets: &[scan::Hit]) -> String {
    let mut help = String::from(
        "No files are protected yet. The project chooses which files AI agents\n\
         must read redacted (with `veloci redact` and `veloci grep`)\n\
         instead of directly.\n\n",
    );
    if candidates.is_empty() {
        help.push_str(
            "No commonly sensitive file names were found here. Typical choices\n\
             are .env*, *.pem, secrets/, *.log and database dumps.\n\n",
        );
    } else {
        help.push_str("Likely candidates here, by file name:\n");
        for c in candidates {
            let flag = format!("{} {}", c.flag, shell_quote(c.pattern));
            help.push_str(&format!(
                "  {flag:<28} {}: {}\n",
                c.what,
                c.examples.join(", ")
            ));
        }
        help.push('\n');
    }
    if !secrets.is_empty() {
        help.push_str("Files whose contents hold likely secrets (values not shown):\n");
        help.push_str(&secrets_list(secrets));
        help.push_str(
            "A file no pattern above covers can be protected by its path, such as\n\
             --protect config/settings.yml.\n\n",
        );
    }
    help.push_str(
        "AI agents: ask the user which of these to protect, what else to add,\n\
         what to exclude, and whether to --enforce (block direct reads where the\n\
         agent supports it). Then record the answer, for example:\n\n\
         \x20   veloci agent init --protect '.env*' --exclude .env.example --enforce\n\n\
         Pattern syntax: veloci agent init --help\n\
         Full procedure: veloci agent skill setup\n",
    );
    help
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

/// Print the complete command-line manual.
fn man() -> Result<ExitCode> {
    let manual: String = CLI_README
        .split_inclusive('\n')
        .filter(|line| !line.contains("<img"))
        .collect();
    io::stdout()
        .write_all(manual.as_bytes())
        .context("writing standard output")?;
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
    let allow = args.allow(config)?;

    for warning in redaction.warnings() {
        eprintln!("warning: {warning}");
    }
    Ok((redaction, allow))
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
                f.token().to_owned(),
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
