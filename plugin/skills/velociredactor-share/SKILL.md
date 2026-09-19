---
name: velociredactor-share
description: Redact secrets and personal data with Veloci Redactor before text leaves the machine. Use before pasting logs, stack traces, config, command output, or file excerpts into a GitHub issue or pull request, a commit message, a gist, a chat message, a bug report, a web search, or any other external service or tool, and when the user asks to scrub, sanitize, or anonymize text for sharing.
license: MIT
compatibility: Requires the veloci CLI on PATH.
---

# Redacting before sharing

Anything sent to an external service can be cached, indexed or read by others, even if it's deleted later. Before text leaves the machine, pass it through veloci.

## Redact the text

From a file or a command's output:

```sh
veloci redact path/to/app.log > /tmp/app.redacted.log
failing-command 2>&1 | veloci redact --raw
```

For text you composed yourself, such as an issue body, pipe it in on stdin:

```sh
veloci redact --raw <<'EOF'
...text...
EOF
```

Use `--raw` for free-form text, so it isn't parsed as JSON or YAML. For a structured file, let veloci detect the format, or pass `--format NAME`. Detecting the format keeps keys readable while still redacting their values.

Always send the redacted version, not the original. If you write it to a temporary file, send that file and then delete it.

## Gate on it

To check that text is clean before sending it, without printing it:

```sh
veloci redact --check --raw < draft.md > /dev/null && echo clean
```

Exit 1 means something would be redacted. In that case, send the redacted output instead, or ask the user.

To check files before attaching or uploading them, such as a directory of logs for a bug report:

```sh
veloci scan path/to/logs/ other-file.txt   # exit 1 = some hold secrets; lists which
```

Send the redacted version of each file it lists.

## Things to watch for

- Redaction covers secrets and, when turned on, personal data. It doesn't remove internal hostnames, project names, or proprietary code. If content may be confidential beyond secrets, ask the user before sharing it at all.
- Personal-data detection (`pii:*`, `privacy_filter`) is off unless the project turned it on. For customer data, check `veloci config show`. If needed, suggest the `velociredactor-config` skill to turn it on.
- `[REDACTED-N]` tokens are safe to share. Say so if a reader might think they're a bug. For example: "values replaced by [REDACTED-N] tokens".
- Never use `--show-value` output, or the unredacted original, in anything you share.
