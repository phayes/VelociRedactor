---
name: velociredactor-setup
description: First-run setup of velociredactor in a project. Asks the user which files AI agents must read redacted and records the answer in velociredactor.yml. Use when `velociredactor agent status` reports "not configured", when the user asks to set up, enable or install velociredactor or redaction for a repo, or when they want to change which files are protected.
license: MIT
compatibility: Requires the velociredactor CLI on PATH.
---

# Setting up velociredactor for a project

The goal is an `agent:` section in the project's `velociredactor.yml` that lists the files agents must read through `velociredactor redact`. **The user decides what goes in it.** Your job is to find likely candidates, ask, and record the answer.

## 1. Check the current state

```sh
velociredactor agent status
```

- **Already configured, and the user wants changes:** edit the `agent:` section of the file it names (see step 5). Don't run `agent init` again, because it refuses to replace an existing section.
- **`config: [builtin-default]`:** there's no config file yet. `agent init` will create one at the repository root.
- **A config file with no `agent` section:** `agent init` will append the section to that file.

## 2. Find candidate files

`velociredactor agent status` already lists two kinds of candidates. Add `--json` for machine-readable output (`suggested` and `secrets`).

- **By file name:** patterns such as `.env*` or `*.pem`, with example paths.
- **By contents:** files that `velociredactor scan` found secrets in, with how many values each holds and which detectors found them. It never shows the values. It includes hidden and ignored files, which are often where the secrets are.

`agent status` shows the first 20 files with secrets. It leaves out the slow `privacy_filter` detector, even when the project enables it; `--privacy-filter` puts it back. If the user doesn't want file contents read at all, use `agent status --no-scan`, which suggests file names only. For every file with secrets, with the line of each finding and every detector the project enables:

```sh
velociredactor scan              # table: file, findings, detectors
velociredactor scan --json       # machine-readable
```

Treat both lists as a starting point. Also look at the names of tracked and ignored files yourself, for data that detectors don't recognize, such as customer exports. **Don't read file contents to judge them.** `scan` and `velociredactor list FILE` tell you what's inside without showing it.

```sh
git ls-files --cached --others --exclude-standard
git ls-files --others --ignored --exclude-standard --directory
```

Group the matches into categories like these, and skip any category that has no matches:

| Category | Typical patterns |
|---|---|
| Environment files | `.env*` (usually excluding `.env.example`, `.env.sample`, `.env.template`) |
| Keys and certificates | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `id_rsa*`, `id_ed25519*` |
| Credentials and tokens | `credentials*`, `secrets/`, `.npmrc`, `.pypirc`, `.netrc`, `*.kubeconfig`, `service-account*.json` |
| Infrastructure state | `*.tfstate`, `*.tfstate.backup`, `*.tfvars` |
| Logs and captures | `*.log`, `logs/`, `*.har` |
| Databases and dumps | `*.sql`, `*.dump`, `*.sqlite`, `*.db`, `*.bak` |
| Data exports | `*.csv`, `*.jsonl`, `*.parquet` under `data/`, `exports/`, `fixtures/` and similar |
| Production config | `config/*prod*`, `*.secrets.yml`, `appsettings.*.json` |

A file that `scan` lists but that no category covers, such as `config/settings.yml`, can be protected by its own path. So can a directory, if several of its files hold secrets: `config/`. Some hits are false positives, such as test fixtures with sample keys or docs with example passwords. Present them anyway and let the user decide. To see where in a file the findings are, still without values:

```sh
velociredactor list path/to/candidate
```

## 3. Ask the user

Present the categories that have matches, with a few example paths each, and the files `scan` found secrets in, and ask which to protect. Use your structured question tool if you have one (a multi-select works well); otherwise ask in plain text. Also ask:

1. **Anything else?** Paths only they know about, such as customer data or internal docs.
2. **Exceptions?** Files matching a pattern that are safe, such as `.env.example`.
3. **Enforcement?** In agents that support hooks, including Claude Code with the velociredactor plugin, `enforce: true` *blocks* direct reads of protected files, and searches that would reach them, instead of relying on instructions alone. The agent is pointed at `velociredactor redact` or `velociredactor grep` instead. Recommend it for repositories with real secrets.

Don't add patterns the user didn't agree to.

## 4. Record the answer

```sh
velociredactor agent init \
  --protect '.env*' --protect '*.pem' --protect 'secrets/' \
  --exclude '.env.example' \
  --enforce            # only if the user asked for enforcement
```

Pattern syntax follows `.gitignore`, relative to the directory holding `velociredactor.yml`:

- No `/` in the pattern matches a file name at any depth: `.env*`, `*.pem`.
- A `/` anchors the pattern at the project root: `config/prod.yml`, `/data/*.csv`.
- A trailing `/` covers a whole directory: `secrets/`.
- `*` stays within one segment, and `**` spans segments: `exports/**/*.csv`.

Always quote patterns so the shell doesn't expand them.

## 5. Confirm and hand off

```sh
velociredactor agent status
velociredactor agent check <one file per category>   # each should print and exit 1
velociredactor config validate
```

`agent status` now lists the unprotected files whose contents hold secrets, without opening the protected ones. If it lists any, the user chose not to protect them, or a pattern missed them. Mention them once.

Then tell the user:

- which patterns are now protected, and whether enforcement is on;
- that `velociredactor.yml` should be committed, so the whole team and every agent share the choice;
- that they can change the choice any time by editing the `agent:` section (`protected`, `exclude`, `enforce`), or by asking you.

To change an existing section later, edit the YAML directly and run `velociredactor config validate`. The file also holds the redaction rules, so keep the rest of it intact. The `velociredactor-config` skill covers those rules.
