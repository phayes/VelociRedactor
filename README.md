<p align="center"><img src="https://raw.githubusercontent.com/phayes/velociredactor/master/logo.png" alt="velociredactor logo" width="300"></p>

# velociredactor

`velociredactor` redacts secrets and personal data from text and structured files while preserving their shape and formatting. Each distinct secret is replaced by a stable numbered token such as `REDACTION-1`.

Velociredactor aims:
 - *Fast*, with parallel scanning and a very fast regex engine.
 - *Exaustive*, with built-in support for all [Betterleaks](https://betterleaks.com) secret patterns, and optional support for [OpenAI's Privacy Filter](https://openai.com/index/introducing-openai-privacy-filter/).
 - *Configurable* with extensive configuration options.
 - *Extensible* with a matching [rust crate](https://crates.io/crates/velociredactor) and traits. 
 - *AI Native* with built-in LLM skills so AI models can automatically start using `velociredactor` to avoid reading sensitive data into context.

This README is the command-line manual. For the Rust library, see the [`velociredactor` crate](https://crates.io/crates/velociredactor), its [API documentation](https://docs.rs/velociredactor), and the [crate guide](README.crate.md).

## Install

From a checkout:

```console
cargo install --path cli
```

The binary includes the default rules and all supported structured formats. It also includes the optional OpenAI Privacy Filter detector; that model is downloaded separately and is disabled in the default configuration.

## Redact input

Pass a file:

```console
velociredactor redact secrets.json
```

Read standard input by omitting the file or writing `-`:

```console
printf 'DB_PASSWORD=hunter2\n' | velociredactor redact
```

Write to a different file with `--output`, or replace the input file with `--in-place`:

```console
velociredactor redact secrets.json --output safe.json
velociredactor redact secrets.json --in-place
```

The format is selected from the file name and then the content. Use `--format NAME` to select one explicitly, or `--raw` to treat the entire input as plain text:

```console
velociredactor redact document --format json
velociredactor redact document.txt --raw
velociredactor formats
```

Structured formats are parsed so that values can be changed while preserving keys and formatting. Configuration can enable comment scanning.

## Inspect findings

`list` reports what would be redacted without writing a redacted document:

```console
velociredactor list secrets.json
velociredactor list secrets.json --json
velociredactor list secrets.json --show-value
```

Values are hidden by default. `--show-value` deliberately prints sensitive data and should be used with care.

Both `redact` and `list` accept `--check`. They exit with status 1 when any non-allowed finding remains, making them suitable for checks in scripts and CI:

```console
velociredactor redact --check secrets.json >/dev/null
```

## Search files

`grep` searches like ripgrep, but prints matches from each file's redacted text:

```console
velociredactor grep password
velociredactor grep -C2 -t yaml api_key config/
velociredactor grep -l --hidden AWS_
```

Each file is searched as it is on disk first. A file with a match is redacted and searched again, and only that second search prints, so output never holds a secret and searching for a secret's own text finds nothing. Line numbers count lines of the redacted text, which can be fewer than the file's when a multi-line secret, such as a private key, becomes one token.

Directories are searched recursively, skipping hidden files and files that `.gitignore` excludes. Each file is redacted with the configuration found from its own directory unless `--config` is given. The exit status is 0 when something matched, 1 when nothing did, and 2 on an error.

## Configuration

Configuration defines what counts as sensitive. Print the complete built-in configuration to make an editable copy:

```console
velociredactor config show > velociredactor.yml
velociredactor config validate
```

A configuration file replaces the built-in configuration completely. `velociredactor` chooses the configuration in this order:

1. `--config FILE`
2. `$VELOCIREDACTOR_CONFIG` environment variable
3. `velociredactor.yml` or `VELOCIREDACTOR.yml` in the current directory or an eligible parent directory.
4. the built-in configuration

This means you may place `velociredactor.yml` in the root of your Git repository, and velociredactor will find it.

```console
velociredactor config location
velociredactor config show
velociredactor config validate
```

`config validate` reports every independently detectable configuration error and any warnings raised while constructing the redactor.

The configuration controls:

- the formats that can be recognized;
- which keys, objects, and comments are scanned;
- documentation placeholders excluded from credential detection;
- the detectors and their settings;
- exact values, regular expressions, and key paths that are allowed.

See [default_config.yml](https://github.com/phayes/velociredactor/blob/master/default_config.yml) for a documented example of a config file.

## Privacy Filter model

The optional `privacy_filter` detector uses the [OpenAI Privacy Filter transformer model](https://openai.com/index/introducing-openai-privacy-filter/). It is slower and substantially heavier than the built-in pattern detectors, so it is disabled by default.

Download the model to the Hugging Face cache and print the configuration entry that enables it:

```console
velociredactor privacy_filter download
```

Use `--dir DIR` for another location, `--repo OWNER/NAME` for another model repository, or `--revision REV` for a particular revision. The CLI crate's `cuda` feature enables NVIDIA GPU execution, and `openblas` enables system OpenBLAS acceleration on Linux. (TODO: TURN ALL THIS THIS ON BY DEFAULT FOR COMPATIBLE PLATFORMS)

## AI agents

Coding agents send whatever they read to their model. velociredactor ships [agent skills](plugin/skills) and a Claude Code plugin that make agents read and search sensitive files through `redact` and `grep`, so secrets never reach the model.

Install the plugin in Claude Code:

```console
/plugin marketplace add phayes/velociredactor
/plugin install velociredactor@velociredactor
```

The skills follow the [Agent Skills](https://agentskills.io) standard, so other agents can load them too. Copy the directories under `plugin/skills/` into the agent's skills directory, such as `.agents/skills/` for Codex. See [plugin/README.md](plugin/README.md) for details.

The first time the skills are used in a project, the agent asks which files to protect. It records the answer in an `agent` section of `velociredactor.yml`, which you can also write yourself:

```console
velociredactor agent init --protect '.env*' --protect '*.pem' --exclude .env.example --enforce
velociredactor agent status
velociredactor agent check .env
```

Patterns follow `.gitignore` conventions, relative to the configuration file. `agent check` exits 1 when any file it is given is protected.

With `enforce`, the plugin's hook blocks the agent's own Read and Grep tools on protected files, and on searches of directories holding them. The agent is pointed at `velociredactor redact` or `velociredactor grep` instead. Without `enforce`, the skills only instruct the agent.

## Command reference

```text
velociredactor redact [OPTIONS] [FILE]
    -c, --config FILE   Configuration file
    -f, --format NAME  Select the input format
        --raw          Treat input as plain text
    -o, --output FILE  Write to a file
    -i, --in-place     Replace the input file
        --check        Exit 1 when anything is redacted

velociredactor list [OPTIONS] [FILE]
    -c, --config FILE   Configuration file
    -f, --format NAME  Select the input format
        --raw          Treat input as plain text
        --json         Emit JSON
        --show-value   Include sensitive values
        --check        Exit 1 when anything would be redacted

velociredactor grep [OPTIONS] PATTERN [PATH...]
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

velociredactor formats
velociredactor config show [--config FILE]
velociredactor config location [--config FILE]
velociredactor config validate [--config FILE]
velociredactor privacy_filter download [--dir DIR] [--repo OWNER/NAME]
                                         [--revision REV]
velociredactor agent status [--json] [--config FILE]
velociredactor agent check FILE... [--config FILE]
velociredactor agent init --protect GLOB... [--exclude GLOB...] [--enforce]
velociredactor agent hook              Claude Code PreToolUse hook (JSON on stdin)
velociredactor man
```

Use `velociredactor --help` or `velociredactor COMMAND --help` for concise generated help. `velociredactor man` prints this complete manual.

## License

velociredactor is available under the [MIT License](LICENSE).
