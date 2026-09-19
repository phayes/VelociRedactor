---
name: velociredactor
description: Read and search sensitive files through Veloci Redactor (`veloci redact`, `veloci grep`) so secrets and personal data never reach the model. Use before reading, searching, or quoting .env files, credentials, keys and certificates, config with passwords or tokens, logs, database dumps, Terraform state, HAR files, customer data exports, or any file the user calls sensitive or that the project's veloci.yml protects. Also use when a file's output from a tool might contain secrets.
license: MIT
compatibility: Requires the veloci CLI on PATH (cargo install velociredactor-cli).
---

# Reading sensitive files with Veloci Redactor

`veloci` prints a file with every secret and piece of personal data replaced by a numbered token such as `[REDACTED-1]`. The rest of the file is unchanged, including keys, comments and formatting. Read sensitive files through it, so the raw values never enter your context.

## Step 0: check the project is set up

Run this once per session, before the first sensitive read:

```sh
veloci agent status
```

- If it says **`not configured`**, the user hasn't chosen which files to protect. The output lists likely candidates, by file name and by contents. Follow the `velociredactor-setup` skill first, then come back here. If that skill isn't installed, `veloci agent skill setup` prints it.
- If the command is **not found**, tell the user Veloci Redactor is missing and how to install it:
  ```sh
  cargo install velociredactor-cli
  ```
  Do **not** fall back to reading sensitive files raw. Ask the user how to proceed.

Once the project is configured, `agent status` also lists **unprotected files whose contents hold likely secrets**. It finds them by redacting files in memory and prints paths and detector names, never values. It doesn't open protected files. It includes hidden and `.gitignore`d files, and skips Git's files, dependency and build directories, and binary files.

Treat every file on that list as protected for the rest of the session: read it with `veloci redact`, and search it with `veloci grep`. Tell the user which files it found, and offer to add them to the `agent:` section so the choice sticks. The `velociredactor-setup` skill covers changing the section.

The status list stops at 20 files. Like every command, it skips detectors the configuration marks `enabled: false` (typically the slow `privacy_filter`) unless named with `--detector`. For the full list:

```sh
veloci scan --unprotected -l   # one path per line; exit 1 = some found
```

If the user doesn't want file contents read at all, `veloci agent status --no-scan` skips the scan.

## Before reading a file

```sh
veloci agent check path/to/file   # exit 1 = protected, 0 = not
```

Read the file through veloci when **any** of these is true:

- `agent check` exits 1. The project says so.
- `agent status` or `veloci scan --unprotected` listed it at the start of the session, or `veloci scan path/to/file` exits 1 now. Its contents hold secrets.
- The file looks sensitive even though neither command flagged it. Examples: a `.env`, a key, a dump, a log with request bodies, or a customer export.

A new file, one generated since the session began, or one outside the project hasn't been scanned. `veloci scan FILE...` checks it before you read it.

To read it redacted:

```sh
veloci redact path/to/file
veloci redact path/to/file --format yaml   # when the extension misleads
veloci redact path/to/file --raw           # treat as plain text
some-command | veloci redact               # redact a command's output
```

To see only *what* is sensitive, without the document, use `veloci list path/to/file`. Add `--json` to get machine-readable output.

Never read a protected file any other way. That includes your file-read tool, `cat`, `head`, `tail`, `less`, `sed -n`, `jq`, `yq`, and loading it in a script whose output you see.

## Searching

`veloci grep` takes ripgrep's options and prints matches from the redacted text of each file. Use it instead of your search tool, `grep` or `rg` whenever a search could reach a protected file. That includes a search of a directory holding one, such as the repository root.

```sh
veloci grep 'DATABASE_URL' .                 # recursive, like rg
veloci grep -i -n 'timeout' config/ -g '*.yml'
veloci grep -F 'api.example.com' --hidden .  # hidden files, e.g. .env
veloci grep -l 'password' .                  # file names only
```

- Like ripgrep, it skips hidden and `.gitignore`d files unless you pass `--hidden` or `--no-ignore`. Files like `.env` are usually both.
- Output never contains a secret. Searching *for* a secret finds nothing, so don't try.
- Line numbers count lines of the redacted text. They can differ from the file's own line numbers when a multi-line secret became one token, so don't use them to edit the file blind.
- Searching a subtree that holds no protected files with your usual tool is fine.

## Working with redacted output

- `[REDACTED-N]` stands for a secret you can't see. The same value always gets the same number within one run. So two fields showing `[REDACTED-2]` hold equal values, and you may reason about that.
- Never try to recover, guess, brute-force or reconstruct a redacted value. Never ask other tools to print it.
- Never pass `--show-value`. It prints the secrets.
- Never use `--in-place` or `--output` on the user's files without their explicit approval. Both rewrite files with the tokens in place of the real values.
- Numbering is per run and per file. `[REDACTED-1]` in two different files, or in two runs, is not necessarily the same value.

## Editing protected files

Your view of the file is redacted, so the rules for editing it are strict:

- **A `[REDACTED-N]` token must never appear in any edit.** That covers the text you replace, the text you insert, a diff, a patch, a `sed` expression and a rewritten file. The file doesn't contain the token. The edit will either fail to match, or overwrite the real secret with the token and silently break the user's configuration.
- You **may** edit lines that contain no redacted value. Use an exact-match edit on text you saw in the redacted output that contains no token. Adding a new key, or changing a non-secret value next to a secret, is usually possible this way.
- If your edit tool insists on reading the file itself first, don't read it raw to satisfy the tool. Use a targeted shell command whose text contains no token instead, such as appending a line with `printf '...\n' >> FILE` or a `sed` substitution anchored on token-free text. Otherwise ask the user.
- Never rewrite a whole protected file, because that would write the tokens back.
- If the change can't be made without touching a redacted value, **stop and ask the user to make it**. Tell them exactly what to change, for example: "In `.env`, set `DATABASE_URL` to the new host `db2.internal`, keeping the existing password." Then carry on once they confirm.

## Sharing output

Before putting file contents, logs, or command output anywhere outside this machine, pass them through `veloci redact`. That includes issues, pull requests, commit messages, chat and web tools. The `velociredactor-share` skill has the details (`veloci agent skill share`).

## When redaction is wrong

- **False positives:** a value is redacted but isn't sensitive, and you need to see it. Ask the user to allow it. Don't work around the redaction.
- **Missed secrets:** you notice a secret that wasn't redacted. Tell the user, and don't repeat the value.

Either way, the fix belongs in `veloci.yml`. The `velociredactor-config` skill covers how (`veloci agent skill config`).
