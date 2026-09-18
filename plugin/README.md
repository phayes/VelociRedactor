# velociredactor agent skills

These skills make AI coding agents read and search sensitive files through `velociredactor`. Secrets and personal data are replaced by `REDACTION-N` tokens before they reach the model.

| Skill | What it does |
|---|---|
| [`velociredactor`](skills/velociredactor/SKILL.md) | Reads protected or sensitive files with `velociredactor redact`, searches them with `velociredactor grep`, and edits them without ever writing a `REDACTION-N` token back. |
| [`velociredactor-setup`](skills/velociredactor-setup/SKILL.md) | On first use in a project, asks which files to protect and records the answer in `velociredactor.yml`. |
| [`velociredactor-config`](skills/velociredactor-config/SKILL.md) | Customizes detection: allow lists, custom patterns, PII, the Privacy Filter model, and the protected files. |
| [`velociredactor-share`](skills/velociredactor-share/SKILL.md) | Redacts logs and other output before they go into issues, pull requests, chat or web tools. |

Every skill needs the `velociredactor` binary on `PATH`:

```console
cargo install velociredactor-cli
```

## Installing

### Claude Code

```console
/plugin marketplace add phayes/velociredactor
/plugin install velociredactor@velociredactor
```

The plugin installs the four skills and a `PreToolUse` hook. The hook does nothing unless a project turns on `enforce` (see below).

### Other agents

The skills follow the [Agent Skills](https://agentskills.io) standard. Copy the directories under `skills/` into the agent's skills directory:

| Agent | Project | Personal |
|---|---|---|
| Codex, Gemini CLI, GitHub Copilot, Cursor, and most others | `.agents/skills/` | `~/.agents/skills/` |
| Claude Code, without the plugin | `.claude/skills/` | `~/.claude/skills/` |
| Codex | | `~/.codex/skills/` |
| Gemini CLI | `.gemini/skills/` | `~/.gemini/skills/` |
| GitHub Copilot | `.github/skills/` | `~/.copilot/skills/` |

For example, for a single project:

```console
git clone --depth 1 https://github.com/phayes/velociredactor /tmp/velociredactor
mkdir -p .agents/skills
cp -R /tmp/velociredactor/plugin/skills/* .agents/skills/
```

Only Claude Code gets the enforcing hook. In other agents the skills work by instruction alone.

## Choosing the protected files

The first time the skills are used in a project, the agent runs `velociredactor agent status`. If the project hasn't chosen its protected files yet, the agent:

1. finds likely candidates by file name only, without reading contents;
2. asks you which to protect, what to exclude, and whether to enforce;
3. writes your answer with `velociredactor agent init`.

The answer lives in the `agent` section of `velociredactor.yml`. Commit that file, so every teammate and agent shares it:

```yaml
agent:
  protected:
    - ".env*"
    - "*.pem"
    - "secrets/"
  exclude:
    - ".env.example"
  enforce: true
```

Patterns follow `.gitignore` conventions, relative to `velociredactor.yml`.

## Enforcement

With `enforce: true`, the Claude Code plugin's hook runs `velociredactor agent hook` before every Read and Grep tool call:

- **Read of a protected file:** denied. The agent is told to run `velociredactor redact FILE`.
- **Grep of a protected file, or of a directory holding one:** denied. The agent is told the exact `velociredactor grep` command to run instead. The directory walk follows ripgrep's rules, so files that `.gitignore` excludes don't count, because the Grep tool wouldn't search them either.

Limits:

- Shell commands such as `cat .env` are not intercepted. The skills tell the agent not to run them, but that is an instruction, not a guarantee.
- If `velociredactor` isn't installed, or the configuration is broken, the hook fails without blocking. It never stops the agent from reading anything at all.

## Developing

```console
claude plugin validate .            # the marketplace, from the repository root
claude plugin validate ./plugin     # the plugin
```
