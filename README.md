<p align="center"><img src="https://raw.githubusercontent.com/phayes/velociredactor/master/logo.png" alt="Veloci Redactor logo" width="300"></p>

# Veloci Redactor

Veloci Redactor (`veloci`) redacts secrets and personal data from text and structured files while preserving their shape and formatting. Each distinct secret is replaced by a stable numbered token such as `[REDACTED-1]`.

Veloci Redactor aims:
 - ***Fast***, with parallel scanning and a very fast regex engine.
 - ***Exaustive***, with built-in support for all [Betterleaks](https://betterleaks.com) secret patterns, and optional support for [OpenAI's Privacy Filter](https://openai.com/index/introducing-openai-privacy-filter/).
 - ***Configurable*** with extensive configuration options.
 - ***Extensible*** with a matching [rust crate](https://crates.io/crates/velociredactor) and traits. 
 - ***AI Native*** with built-in LLM skills so AI models can automatically start using `veloci` to avoid reading sensitive data into context.

This README is the command-line manual. For the Rust library, see the [`velociredactor` crate](https://crates.io/crates/velociredactor), its [API documentation](https://docs.rs/velociredactor), and the [crate guide](README.crate.md).

## Install

The latest release for this platform:

```console
curl -fsSL https://raw.githubusercontent.com/phayes/velociredactor/master/scripts/install.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/phayes/velociredactor/master/scripts/install.ps1 | iex
```

The Unix script installs to `/usr/local/bin` when that directory is writable, otherwise `~/.local/bin`. The Windows script installs to `%LOCALAPPDATA%\Programs\veloci` and can append that directory with `-AddToPath`. Override either with `--prefix` / `-Prefix` or `$PREFIX`. From cargo:

```console
cargo install velociredactor-cli
```

With Nix:

```console
nix run github:phayes/velociredactor
nix profile install github:phayes/velociredactor
```

The binary includes the default rules and all supported structured formats. It also includes the optional OpenAI Privacy Filter detector; that model is downloaded separately and is disabled in the default configuration.

## Redact input

Pass a file:

```console
veloci redact secrets.json
```

Read standard input by omitting the file or writing `-`:

```console
printf 'DB_PASSWORD=hunter2\n' | veloci redact
```

Write to a different file with `--output`, or replace the input file with `--in-place`:

```console
veloci redact secrets.json --output safe.json
veloci redact secrets.json --in-place
```

The format is selected from the file name and then the content. Use `--format NAME` to select one explicitly, or `--raw` to treat the entire input as plain text:

```console
veloci redact document --format json
veloci redact document.txt --raw
veloci formats
```

Structured formats are parsed so that values can be changed while preserving keys and formatting. Configuration can enable comment scanning.

## Inspect findings

`list` reports what would be redacted without writing a redacted document:

```console
veloci list secrets.json
veloci list secrets.json --json
veloci list secrets.json --show-value
```

Values are hidden by default. `--show-value` deliberately prints sensitive data and should be used with care.

Both `redact` and `list` accept `--check`. They exit with status 1 when any non-allowed finding remains, making them suitable for checks in scripts and CI:

```console
veloci redact --check secrets.json >/dev/null
```

## Search files

`grep` searches like ripgrep, but prints matches from each file's redacted text:

```console
veloci grep password
veloci grep -C2 -t yaml api_key config/
veloci grep -l --hidden AWS_
```

Each file is searched as it is on disk first. A file with a match is redacted and searched again, and only that second search prints, so output never holds a secret and searching for a secret's own text finds nothing. Line numbers count lines of the redacted text, which can be fewer than the file's when a multi-line secret, such as a private key, becomes one token.

Directories are searched recursively, skipping hidden files and files that `.gitignore` excludes. Each file is redacted with the configuration found from its own directory unless `--config` is given. The exit status is 0 when something matched, 1 when nothing did, and 2 on an error.

## Find files with secrets

`scan` lists the files that hold secrets, with how many values each would have redacted and which detectors found them. Values are hidden by default:

```console
$ veloci scan
FILE                 FINDINGS  DETECTORS
.env                 1         entropy                   protected
config/settings.yml  2         entropy,credentialed_uri
scanned 5 files: 2 with secrets, 0 skipped as binary or over --max-filesize
```

```console
veloci scan -l config/          # paths only
veloci scan --json              # with the line of each finding
veloci scan --show-value        # include the secrets
veloci scan --unprotected       # only files the agent section leaves readable
```

`--show-value` deliberately prints sensitive data and should be used with care. It adds a `VALUE` column to the table, showing up to three values per file cut to 60 characters each, and a `value` field with the full value to each `--json` finding.

Each file is redacted in memory with the configuration found from its own directory, and allow lists apply. Unlike `grep`, hidden and `.gitignore`d files are scanned by default, since that is where secrets usually live; `--skip-hidden` and `--skip-ignored` leave them out. Git's own files and dependency and build directories (`node_modules`, `target`, `vendor`, `.venv`, `venv`, `__pycache__`, `dist`, `build`) are skipped unless `--all-dirs` is given, and so are binary files and files over `--max-filesize` (10M by default). Files that an `agent` section protects are marked `protected`. The exit status is 1 when any file holds secrets, 0 when none does, and 2 on an error with nothing found.

## Configuration

Configuration defines what counts as sensitive. Print the complete built-in configuration to make an editable copy:

```console
veloci config show > veloci.yml
veloci config validate
```

A configuration file replaces the built-in configuration completely. `veloci` chooses the configuration in this order:

1. `--config FILE`
2. `$VELOCIREDACTOR_CONFIG` environment variable
3. `veloci.yml` or `VELOCI.yml` in the current directory or an eligible parent directory.
4. the built-in configuration

This means you may place `veloci.yml` in the root of your Git repository, and veloci will find it.

```console
veloci config location
veloci config show
veloci config validate
```

`config validate` reports every independently detectable configuration error and any warnings raised while constructing the redactor.

The configuration controls:

- the formats that can be recognized;
- which keys, objects, and comments are scanned;
- documentation placeholders excluded from credential detection;
- the detectors and their settings;
- exact values, regular expressions, surrounding patterns, and key paths that are allowed.

See [default_config.yml](https://github.com/phayes/velociredactor/blob/master/default_config.yml) for a documented example of a config file.

## Privacy Filter model

The optional `privacy_filter` detector uses the [OpenAI Privacy Filter transformer model](https://openai.com/index/introducing-openai-privacy-filter/). It is slower and substantially heavier than the built-in pattern detectors, so it is disabled by default.

Download the model to the Hugging Face cache and print the configuration entry that enables it:

```console
veloci privacy_filter download
```

Use `--dir DIR` for another location, `--repo OWNER/NAME` for another model repository, or `--revision REV` for a particular revision. The CLI crate's `cuda` feature enables NVIDIA GPU execution, and `openblas` enables system OpenBLAS acceleration on Linux. (TODO: TURN ALL THIS THIS ON BY DEFAULT FOR COMPATIBLE PLATFORMS)

## AI agents

Coding agents send whatever they read to their model. Veloci Redactor ships [agent skills](plugin/skills) and a Claude Code plugin that make agents read and search sensitive files through `redact` and `grep`, so secrets never reach the model.

Install the plugin in Claude Code:

```console
/plugin marketplace add phayes/velociredactor
/plugin install velociredactor@velociredactor
```

The skills follow the [Agent Skills](https://agentskills.io) standard, so other agents can load them too. Copy the directories under `plugin/skills/` into the agent's skills directory, such as `.agents/skills/` for Codex. An agent with no skills installed can list and print them from the binary with `veloci agent skill`. See [plugin/README.md](plugin/README.md) for details.

The first time the skills are used in a project, the agent asks which files to protect. It records the answer in an `agent` section of `veloci.yml`, which you can also write yourself:

```console
veloci agent init --protect '.env*' --protect '*.pem' --exclude .env.example --enforce
veloci agent status
veloci agent check .env
```

Patterns follow `.gitignore` conventions, relative to the configuration file. `agent check` exits 1 when any file it is given is protected. `agent status` also lists the files whose contents hold secrets that no `agent` section protects, as `scan --unprotected` finds them. Protected files are not read. Until the project has chosen, it suggests file name patterns as well. It leaves out the slow `privacy_filter` detector unless given `--privacy-filter`, and `--no-scan` makes it read no contents at all, suggesting by file name only.

With `enforce`, the plugin's hook blocks the agent's own Read and Grep tools on protected files, and on searches of directories holding them. The agent is pointed at `veloci redact` or `veloci grep` instead. Without `enforce`, the skills only instruct the agent.

## Command reference

```text
veloci redact [OPTIONS] [FILE]
    -c, --config FILE   Configuration file
    -f, --format NAME  Select the input format
        --raw          Treat input as plain text
    -o, --output FILE  Write to a file
    -i, --in-place     Replace the input file
        --check        Exit 1 when anything is redacted

veloci list [OPTIONS] [FILE]
    -c, --config FILE   Configuration file
    -f, --format NAME  Select the input format
        --raw          Treat input as plain text
        --json         Emit JSON
        --show-value   Include sensitive values
        --check        Exit 1 when anything would be redacted

veloci grep [OPTIONS] PATTERN [PATH...]
        --config FILE    Configuration file (default: found per file)
    -e, --regexp PAT     Pattern; repeat for several (paths follow)
    -F, --fixed-strings  Literal patterns
    -i, --ignore-case    Case-insensitive
    -S, --smart-case     Case-insensitive unless uppercase is used
    -w, --word-regexp    Whole words only
    -x, --line-regexp    Whole lines only
    -v, --invert-match   Select non-matching lines
    -U, --multiline      Let matches span lines
        --multiline-dotall  With -U, `.` matches newlines
    -g, --glob GLOB      Include (or with `!`, exclude) paths
    -t, --type TYPE      Only files of a type; -T, --type-not TYPE skips
        --hidden         Search hidden files
        --no-ignore      Search files ignore files exclude
    -L, --follow         Follow symbolic links
    -d, --max-depth NUM  Limit directory depth
    -n / -N              Show / hide line numbers (shown by default)
    -H / -I              Always / never show file names
    -l, --files-with-matches, --files-without-match
    -c, --count          Count matching lines
    -q, --quiet          No output; exit 0 on a match
        --json           ripgrep's JSON Lines output
    -o, --only-matching  Print only matched text
    -A/-B/-C NUM         Lines of context after / before / around
    -m, --max-count NUM  Matching lines per file

veloci scan [OPTIONS] [PATH...]
        --config FILE      Configuration file (default: found per file)
        --unprotected      Only files no agent section protects (not read)
    -l, --files-with-matches  Print only paths
        --json             Emit JSON
        --show-value       Include sensitive values
    -g, --glob GLOB        Include (or with `!`, exclude) paths
        --skip-hidden      Skip hidden files (scanned by default)
        --skip-ignored     Skip files ignore files exclude (scanned by default)
        --all-dirs         Also scan dependency and build directories
    -L, --follow           Follow symbolic links
    -d, --max-depth NUM    Limit directory depth
        --max-filesize SIZE  Skip larger files (default 10M)

veloci formats
veloci config show [--config FILE]
veloci config location [--config FILE]
veloci config validate [--config FILE]
veloci privacy_filter download [--dir DIR] [--repo OWNER/NAME]
                                         [--revision REV]
veloci agent status [--json] [--no-scan] [--privacy-filter] [--config FILE]
veloci agent check FILE... [--config FILE]
veloci agent init --protect GLOB... [--exclude GLOB...] [--enforce]
veloci agent skill [NAME]      Print an agent skill, or list them
veloci agent hook              Claude Code PreToolUse hook (JSON on stdin)
veloci man
```

Use `veloci --help` or `veloci COMMAND --help` for concise generated help. `veloci man` prints this complete manual.

## License

Veloci Redactor is available under the [MIT License](LICENSE).
