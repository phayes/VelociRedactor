<p align="center"><img src="https://raw.githubusercontent.com/phayes/veloci/master/logo.png" alt="Veloci Redactor logo" width="300"></p>

# Veloci Redactor

Veloci Redactor (`veloci`) finds and redacts secrets and personal data from text and structured files. Each distinct secret is identified and replaced by a token such as `[REDACTED-1]`.

Veloci Redactor aims:
 - ***Fast***, with parallel scanning and a very fast regex engine.
 - ***Exaustive***, with built-in support for all [Betterleaks](https://betterleaks.com) secret patterns, and optional support for [OpenAI's Privacy Filter](https://openai.com/index/introducing-openai-privacy-filter/).
 - ***Configurable*** with extensive configuration options.
 - ***Extensible*** with a matching [rust crate](https://crates.io/crates/veloci) and traits. 
 - ***AI Native*** with built-in LLM skills so AI models can automatically start using `veloci` to avoid reading sensitive data into context.

This README is the command-line manual. For the Rust library, see the [`veloci` crate](https://crates.io/crates/veloci), its [API documentation](https://docs.rs/veloci), and the [crate guide](README.crate.md).

## Install

```console
# Any platform:
curl -fsSL https://raw.githubusercontent.com/phayes/veloci/master/scripts/install.sh | bash

# Homebrew (macOS and Linux)
brew install phayes/tap/veloci-cli

# Debian and Ubuntu (.deb, amd64 or arm64)
VERSION=0.3.1 ARCH=$(dpkg --print-architecture)
curl -fsSLO "https://github.com/phayes/veloci/releases/download/v$VERSION/veloci_${VERSION}_$ARCH.deb"
sudo apt install "./veloci_${VERSION}_$ARCH.deb"

# Cargo (rust)
cargo install veloci-cli

# Nix
nix run github:phayes/veloci && nix profile install github:phayes/veloci
```

```powershell
# Windows: Powershell
irm https://raw.githubusercontent.com/phayes/veloci/master/scripts/install.ps1 | iex

# Windows: Scoop
scoop bucket add phayes https://github.com/phayes/scoop-bucket
scoop install veloci
```

## Claude Code

```
claude
/plugin marketplace add phayes/veloci
/plugin install veloci@veloci

Hi Caude, set up veloci for this project
```

## Configuring Veloci Redactor
```
veloci init
cat veloci.yml # View the config and edit as needed
```

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
veloci scan --show-value        # display the secrets, use with care
veloci scan --unprotected       # only files the agent section leaves readable
```

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

Veloci Redactor is content (`json`, `yaml` etc) aware and by default will scan only values (not comments).

```console
veloci redact document --format json # Force json formatter
veloci redact document.txt --raw     # Treat it as raw text, not a structured file
veloci redact foo.yml --comments     # Also scan comments            
```

## Inspect findings

`list` reports what would be redacted without writing a redacted document:

```console
veloci list secrets.json
veloci list secrets.json --json
veloci list secrets.json --show-value
veloci list secrets.json --comments --show-value
```

Values are hidden by default. `--show-value` deliberately prints sensitive data and should be used with care.

Both `redact` and `list` accept `--check`. They exit with status 1 when any non-allowed finding remains, making them suitable for checks in scripts and CI:

```console
veloci redact --check secrets.json >/dev/null
```

## Search files

`grep` searches like ripgrep, but redacts before any results are printed:

```console
veloci grep password
veloci grep -C2 -t yaml api_key config/
veloci grep -l --hidden AWS_
```

Directories are searched recursively, skipping hidden files and files that `.gitignore` excludes. Each file is redacted with the configuration found from its own directory unless `--config` is given. The exit status is 0 when something matched, 1 when nothing did, and 2 on an error.

## Block commits that add secrets

`veloci githook` is a Git pre-commit hook to block secrets from accidentally being committed. 

```console
$ git commit -m "Add client"
veloci: refusing to commit secrets
  src/client.py:3  entropy
Review with `veloci list FILE`; allow false positives in veloci.yml,
or bypass once with `git commit --no-verify`.
```

Install it in a repository:

```sh
printf '#!/bin/sh\nexec veloci githook\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Or with the [pre-commit](https://pre-commit.com) framework, in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: veloci
        name: veloci
        entry: veloci githook
        language: system
        pass_filenames: false
```

Binary files, files over 10M, submodules and symbolic links are skipped. The exit status is 1 when the commit adds secrets, 0 when it does not, and 2 on an error.

## Configuration

Configuration defines what counts as sensitive. Create an editable copy of the complete built-in configuration as `veloci.yml` at the root of your Git repository (it asks first; `--yes` skips the question):

```console
veloci init
veloci config validate
```

A configuration file replaces the built-in configuration completely. `veloci` chooses the configuration in this order:

1. `--config FILE`
2. `$VELOCI_CONFIG` environment variable
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

See [default_config.yml](https://github.com/phayes/veloci/blob/master/default_config.yml) for a documented example of a config file.

## Privacy Filter model

The optional `privacy_filter` detector uses the [OpenAI Privacy Filter transformer model](https://openai.com/index/introducing-openai-privacy-filter/). It is slower and substantially heavier than the built-in pattern detectors, so it is not in the default configuration.

Download the model to the Hugging Face cache and print a configuration entry for it:

```console
veloci privacy_filter download
```

The printed entry has `enabled: false`, so it runs only when asked for, with `--detector privacy_filter` on any command. Any detector entry can be disabled this way, and named by its `label` or detector name.

Use `--dir DIR` for another location, `--repo OWNER/NAME` for another model repository, or `--revision REV` for a particular revision. The CLI crate's `cuda` feature enables NVIDIA GPU execution, and `openblas` enables system OpenBLAS acceleration on Linux. (TODO: TURN ALL THIS THIS ON BY DEFAULT FOR COMPATIBLE PLATFORMS)

## AI agents

Coding agents send whatever they read to their model. Veloci Redactor ships [agent skills](plugin/skills) and a Claude Code plugin that make agents read and search sensitive files through `redact` and `grep`, so secrets never reach the model.

Install the plugin in Claude Code:

```console
/plugin marketplace add phayes/veloci
/plugin install veloci@veloci
```

The skills follow the [Agent Skills](https://agentskills.io) standard, so other agents can load them too. Copy the directories under `plugin/skills/` into the agent's skills directory, such as `.agents/skills/` for Codex. An agent with no skills installed can list and print them from the binary with `veloci agent skill`. See [plugin/README.md](plugin/README.md) for details.

The first time the skills are used in a project, the agent asks which files to protect. It records the answer in an `agent` section of `veloci.yml`, which you can also write yourself:

```console
veloci agent init --protect '.env*' --protect '*.pem' --exclude .env.example --enforce
veloci agent status
veloci agent check .env
```

Patterns follow `.gitignore` conventions, relative to the configuration file. `agent check` exits 1 when any file it is given is protected. `agent status` also lists the files whose contents hold secrets that no `agent` section protects, as `scan --unprotected` finds them. Protected files are not read. Until the project has chosen, it suggests file name patterns as well. Detectors the configuration disables, such as a slow `privacy_filter`, run only when named with `--detector`, and `--no-scan` makes it read no contents at all, suggesting by file name only.

With `enforce`, the plugin's hook blocks the agent's own Read and Grep tools on protected files, and on searches of directories holding them. The agent is pointed at `veloci redact` or `veloci grep` instead. Without `enforce`, the skills only instruct the agent.

## Command reference

```text
veloci redact [OPTIONS] [FILE]
    -c, --config FILE   Configuration file
        --detector NAME  Also run this disabled detector (repeatable)
    -f, --format NAME  Select the input format
        --raw          Treat input as plain text
    -o, --output FILE  Write to a file
    -i, --in-place     Replace the input file
        --check        Exit 1 when anything is redacted

veloci list [OPTIONS] [FILE]
    -c, --config FILE   Configuration file
        --detector NAME  Also run this disabled detector (repeatable)
    -f, --format NAME  Select the input format
        --raw          Treat input as plain text
        --json         Emit JSON
        --show-value   Include sensitive values
        --check        Exit 1 when anything would be redacted

veloci grep [OPTIONS] PATTERN [PATH...]
        --config FILE    Configuration file (default: found per file)
        --detector NAME  Also run this disabled detector (repeatable)
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
        --detector NAME    Also run this disabled detector (repeatable)
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

veloci init [--yes]            Create veloci.yml at the project root
veloci githook [--config FILE] [--detector NAME]
veloci formats
veloci config show [--config FILE]
veloci config location [--config FILE]
veloci config validate [--config FILE]
veloci privacy_filter download [--dir DIR] [--repo OWNER/NAME]
                                         [--revision REV]
veloci agent status [--json] [--no-scan] [--detector NAME] [--config FILE]
veloci agent check FILE... [--config FILE]
veloci agent init --protect GLOB... [--exclude GLOB...] [--enforce]
veloci agent skill [NAME]      Print an agent skill, or list them
veloci agent hook              Claude Code PreToolUse hook (JSON on stdin)
veloci man
```

Use `veloci --help` or `veloci COMMAND --help` for concise generated help. `veloci man` prints this complete manual.

## License

Veloci Redactor is available under the [MIT License](LICENSE).
