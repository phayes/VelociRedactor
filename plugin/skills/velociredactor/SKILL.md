---
name: velociredactor
description: Read and search sensitive files through velociredactor (`velociredactor redact`, `velociredactor grep`) so secrets and personal data never reach the model. Use before reading, searching, or quoting .env files, credentials, keys and certificates, config with passwords or tokens, logs, database dumps, Terraform state, HAR files, customer data exports, or any file the user calls sensitive or that the project's velociredactor.yml protects. Also use when a file's output from a tool might contain secrets.
license: MIT
compatibility: Requires the velociredactor CLI on PATH (cargo install --git https://github.com/phayes/velociredactor velociredactor-cli).
---

# Reading sensitive files with velociredactor

`velociredactor` prints a file with every secret and piece of personal data replaced by a numbered token such as `REDACTION-1`. The rest of the file is unchanged, including keys, comments and formatting. Read sensitive files through it, so the raw values never enter your context.

## Step 0: check the project is set up

Run this once per session, before the first sensitive read:

```sh
velociredactor agent status
```

- If it says **`not configured`**, the user hasn't chosen which files to protect. Follow the `velociredactor-setup` skill first, then come back here.
- If the command is **not found**, tell the user velociredactor is missing and how to install it:
  ```sh
  cargo install --git https://github.com/phayes/velociredactor velociredactor-cli
  ```
  Do **not** fall back to reading sensitive files raw. Ask the user how to proceed.

## Before reading a file

```sh
velociredactor agent check path/to/file   # exit 1 = protected, 0 = not
```

Read the file through velociredactor when **either** is true:

- `agent check` exits 1. The project says so.
- The file looks sensitive even though it isn't listed. Examples: a `.env`, a key, a dump, a log with request bodies, or a customer export.

To read it redacted:

```sh
velociredactor redact path/to/file
velociredactor redact path/to/file --format yaml   # when the extension misleads
velociredactor redact path/to/file --raw           # treat as plain text
some-command | velociredactor redact               # redact a command's output
```

To see only *what* is sensitive, without the document, use `velociredactor list path/to/file`. Add `--json` to get machine-readable output.

Never read a protected file any other way. That includes your file-read tool, `cat`, `head`, `tail`, `less`, `sed -n`, `jq`, `yq`, and loading it in a script whose output you see.

## Searching

`velociredactor grep` takes ripgrep's options and prints matches from the redacted text of each file. Use it instead of your search tool, `grep` or `rg` whenever a search could reach a protected file. That includes a search of a directory holding one, such as the repository root.

```sh
velociredactor grep 'DATABASE_URL' .                 # recursive, like rg
velociredactor grep -i -n 'timeout' config/ -g '*.yml'
velociredactor grep -F 'api.example.com' --hidden .  # hidden files, e.g. .env
velociredactor grep -l 'password' .                  # file names only
```

- Like ripgrep, it skips hidden and `.gitignore`d files unless you pass `--hidden` or `--no-ignore`. Files like `.env` are usually both.
- Output never contains a secret. Searching *for* a secret finds nothing, so don't try.
- Line numbers count lines of the redacted text. They can differ from the file's own line numbers when a multi-line secret became one token, so don't use them to edit the file blind.
- Searching a subtree that holds no protected files with your usual tool is fine.

## Working with redacted output

- `REDACTION-N` stands for a secret you can't see. The same value always gets the same number within one run. So two fields showing `REDACTION-2` hold equal values, and you may reason about that.
- Never try to recover, guess, brute-force or reconstruct a redacted value. Never ask other tools to print it.
- Never pass `--show-value`. It prints the secrets.
- Never use `--in-place` or `--output` on the user's files without their explicit approval. Both rewrite files with the tokens in place of the real values.
- Numbering is per run and per file. `REDACTION-1` in two different files, or in two runs, is not necessarily the same value.

## Editing protected files

Your view of the file is redacted, so the rules for editing it are strict:

- **A `REDACTION-N` token must never appear in any edit.** That covers the text you replace, the text you insert, a diff, a patch, a `sed` expression and a rewritten file. The file doesn't contain the token. The edit will either fail to match, or overwrite the real secret with the token and silently break the user's configuration.
- You **may** edit lines that contain no redacted value. Use an exact-match edit on text you saw in the redacted output that contains no token. Adding a new key, or changing a non-secret value next to a secret, is usually possible this way.
- If your edit tool insists on reading the file itself first, don't read it raw to satisfy the tool. Use a targeted shell command whose text contains no token instead, such as appending a line with `printf '...\n' >> FILE` or a `sed` substitution anchored on token-free text. Otherwise ask the user.
- Never rewrite a whole protected file, because that would write the tokens back.
- If the change can't be made without touching a redacted value, **stop and ask the user to make it**. Tell them exactly what to change, for example: "In `.env`, set `DATABASE_URL` to the new host `db2.internal`, keeping the existing password." Then carry on once they confirm.

## Sharing output

Before putting file contents, logs, or command output anywhere outside this machine, pass them through `velociredactor redact`. That includes issues, pull requests, commit messages, chat and web tools. The `velociredactor-share` skill has the details.

## When redaction is wrong

- **False positives:** a value is redacted but isn't sensitive, and you need to see it. Ask the user to allow it. Don't work around the redaction.
- **Missed secrets:** you notice a secret that wasn't redacted. Tell the user, and don't repeat the value.

Either way, the fix belongs in `velociredactor.yml`. The `velociredactor-config` skill covers how.
