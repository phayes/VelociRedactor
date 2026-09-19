---
name: velociredactor-config
description: Customize what Veloci Redactor redacts by editing veloci.yml. Covers fixing false positives with allow lists, catching missed secrets with custom regexes, rulesets, exact values or key paths, turning on personal-data (PII) detection or the OpenAI Privacy Filter model, tuning entropy, and changing which files agents must read redacted. Use when redaction hides too much or too little, or the user asks to configure, tune, or extend Veloci Redactor.
license: MIT
compatibility: Requires the veloci CLI on PATH.
---

# Customizing Veloci Redactor

All behavior comes from one YAML file. You change it in three steps: **find the file, edit it, then verify.**

## Find the file

```sh
veloci config location   # path, or [builtin-default]
```

The config file is chosen in this order: `--config FILE`, then `$VELOCIREDACTOR_CONFIG`, then `veloci.yml` or `VELOCI.yml` in the current directory or a parent (stopping at the git root). If none of those exists, the built-in config is used.

**A config file replaces the built-in configuration completely.** Nothing is merged. So never create a config from scratch with only the section you need. Start from the full built-in one:

```sh
veloci config show > veloci.yml
```

`veloci agent init` also writes a complete file.

## Make the change

| Goal | Where | Example |
|---|---|---|
| A value is wrongly redacted | `allow.values` | `values: ["not-a-secret-build-id"]` |
| A family of values is wrongly redacted | `allow.regexes` (must match the whole value) | `regexes: ['^build-[0-9a-f]{12}$']` |
| A value is harmless only where it appears, like a file name in a font URL | `allow.within` (the secret must lie inside a match in its value) | `within: ['https://fonts\.gstatic\.com/[^\s"'')]+']` |
| A key's values must never be scanned | `allow.paths` (dotted key-path glob) | `paths: ["build.**", "**.commit_sha"]` |
| A key's values must never be scanned in some files only | `allow.file_paths` (`FILE#KEY.PATH`) | `file_paths: ["example.yaml#user.name"]` |
| A whole file holds only samples or fixtures | `allow.files` (`.gitignore`-style, relative to the config) | `files: ["tests/fixtures/", "*.example"]` |
| A sample credential keeps being flagged | `placeholder.values` (lowercase) | add `"dummy_token"` |
| An in-house token format is missed | a new `regex` detector | see below |
| A known secret string must always go | a `value` detector | `- value: { values: [hunter2] }` |
| Everything under a key must go | a `path` detector | `- path: { paths: ["users.**.ssn"] }` |
| Too many or too few random-looking strings | `entropy.threshold` (default 4.5, lower redacts more) | `threshold: 4.8` |
| A noisy vendor rule | `ruleset.exclude_rules` | `exclude_rules: ["generic-api-key"]` |
| Extra gitleaks/betterleaks rules | `ruleset.rules` | add `./my-rules.toml` (relative to the config) |
| Emails, phone numbers, addresses | uncomment `pii:email`, `pii:phone`, `pii:address` | |
| Names and other contextual PII | the `privacy_filter` detector | see below |
| Secrets in comments | `comments: true` | |
| The token written in place of a secret | `replacement` | `"[REDACTED-{n}]"` or `"[REDACTED-{n}:{reason}]"` |
| Which files agents read redacted | `agent.protected`, `agent.exclude`, `agent.enforce` | `protected: [".env*", "secrets/"]` |

Custom regex detector. Add it under `detectors:`. The `label` appears in `veloci list` output:

```yaml
  - regex:
      label: acme_token
      patterns:
        - 'acme_(live|test)_[A-Za-z0-9]{32}'
```

Patterns use Rust `regex` syntax and are not anchored. List a `regex` detector as many times as you need.

`detectors` is an ordered list, and a detector that isn't listed doesn't run. Deleting an entry turns it off.

Privacy Filter model: it's slow, uses up to 16 GB of memory, and is a 2.6 GB download. Confirm with the user before turning it on.

```sh
veloci privacy_filter download   # prints the entry to paste under detectors
```

Full reference: [references/config-reference.md](references/config-reference.md). The file printed by `veloci config show` is itself documented, so read the comments near what you're changing.

## Verify

```sh
veloci config validate                  # exit 0 = usable; warnings/errors on stderr
veloci list path/to/sample              # which detector fired, where; values hidden
veloci list path/to/sample --json       # same, machine-readable
veloci redact --check path/to/sample    # exit 1 if anything is still redacted
veloci scan                             # every file with findings, before and after a change
```

After a change that should cut false positives or catch new secrets, compare `veloci scan` over the project from before and after the change. That shows which files it affected.

To check a single value without writing it to disk, pipe it in: `printf 'KEY=value\n' | veloci list`. Don't use `--show-value` to check your work. The `DETECTOR` column and the positions are enough to confirm a fix. Only the user may decide to look at values.

When you're done, tell the user what you changed and why. Remind them to commit `veloci.yml` so the whole team shares the rules.
