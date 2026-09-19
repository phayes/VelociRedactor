# velociredactor.yml reference

This is a condensed guide to every section. The authoritative, fully commented version is the output of `velociredactor config show`, which prints the built-in configuration when no file is in use. A config file replaces the built-in configuration in full, so every required section must be present.

## Top-level sections

| Key | Required | Purpose |
|---|---|---|
| `comments` | no (default `false`) | Also scan comments, in formats that have them. |
| `formats` | yes | Formats to recognize, in the order they're tried when guessing from content. |
| `policy` | yes | Which values get scanned at all. |
| `placeholder` | yes | Values that look like credentials but are samples or masks. |
| `detectors` | yes | What finds secrets, run in the order listed. |
| `allow` | no | Values, key paths (everywhere or in some files) and files never redacted. This overrides every detector. |
| `agent` | no | Files AI agents must read redacted. |

## formats

The names are `json`, `jsonl`, `yaml`, `toml`, `xml`, `hcl`, `ini`, `dotenv`, `properties`, `csv`, `tsv`, `psv`, `bplist` and `text`. Run `velociredactor formats` to see which file extensions map to each. On the command line, `--format NAME` forces one format, and `--raw` treats the input as plain text.

## policy

- `skip_key_suffixes`: key endings that are never scanned, compared case-insensitively. The defaults are `signature`, `id` and `ids`.
- `skip_keys`: exact lowercase key names that are never scanned, such as `path` and `cwd`.
- `skip_object`: skips objects whose `key` field starts with one of the listed `prefixes` or equals one of the listed `values`. This is used for inline images and base64 blobs.
- `credential_context`: `host_keys` and `user_keys`. When an object has both a host key and a user key, a bare `password` key inside that object is treated as sensitive.

A key that `policy` skips is never scanned. That means a `path` detector can't redact it either, so remove the key from `policy` first.

## placeholder

- `values`: lowercase strings that are never treated as secrets, such as `changeme` and `example`.
- `mask_characters`, `mask_min_length`: a value made entirely of one of these characters is a mask, such as `****` or `xxxx`.
- `bracket_min_length`: the minimum length for a `<lowercase-name>` placeholder to count.

Placeholders are consulted by `ruleset`, `credentialed_uri`, `connection_string`, `credential_assignment` and `credential_key`. They are not consulted by `entropy`, `regex`, `value` or `path`.

## detectors

Detectors run in the order listed, and a detector that isn't listed doesn't run. `velociredactor list` reports each finding under its detector's name.

| Detector | Settings | Finds |
|---|---|---|
| `entropy` | `threshold` (4.5), `sensitive_threshold` (3.5), `min_token_length` (10), `sensitive_segments`, `structural_keys`, `hex_digest_lengths` | Random-looking tokens. A lower threshold redacts more. |
| `ruleset` | `rules` (`builtin:betterleaks` and/or TOML paths), `allow_signatures`, `exclude_rules` (globs) | Several hundred vendor-specific secret formats, reported as `ruleset:<id>`. |
| `regex` | `label`, `patterns` | Your own patterns. Can be listed any number of times. |
| `credentialed_uri` | none | URLs with a password, such as `postgres://u:p@h/db`. |
| `connection_string` | none | JDBC URLs, libpq DSNs and ADO.NET connection strings. |
| `credential_assignment` | none | `DB_PASSWORD=value` inside free text. |
| `credential_key` | none | The whole value of a password field. |
| `pii:email` | `allowlist` (`noreply@`, `@example.org`, exact addresses) | Email addresses. Off by default. |
| `pii:phone` | none | Phone numbers. Off by default. |
| `pii:address` | none | Postal addresses. Off by default. |
| `privacy_filter` | `model_dir`, `device`, `context`, `min_score`, `categories`, `max_tokens`, `viterbi` | Names, addresses, dates, account numbers and other personal data, found by an ML model. Heavy; install it with `velociredactor privacy_filter download`. |
| `value` | `values` | Exact strings, wherever they appear. |
| `path` | `paths` (dotted key-path globs) | Everything stored at the given key paths. |

Key-path globs, used by `path` and `allow.paths`: keys are joined with `.`, and arrays add no segment. `*` matches within one key, `**` matches across any number of keys, and `?` matches one character. For example, `users.**.ssn` or `secrets.**`.

## allow

- `values`: exact strings left in place.
- `regexes`: patterns that must match the **whole** value.
- `within`: patterns matched against the whole value around a secret. A secret lying entirely inside a match is left in place and never becomes a finding, so `list` does not show it. Use them when the secret alone looks random but its surroundings show it is harmless: `'https://fonts\.gstatic\.com/[^\s"'')]+'` spares the file name in a font URL, while the same text elsewhere is still redacted. Not anchored, and `.` does not cross a newline. Keep them tight: `https://fonts\.gstatic\.com/.*` would also spare a real secret later on the same line.
- `paths`: key-path globs that are never scanned.
- `files`: file globs never redacted at all, relative to the config file, with the same `.gitignore` conventions as `agent` (`tests/fixtures/`, `*.example`). `scan` does not report them.
- `file_paths`: key paths never scanned in some files only, written `FILE#KEY.PATH`: a file glob as in `files`, `#`, then a key-path glob as in `paths` (`example.yaml#user.name`, `"config/*.yml#db.*.password"`).

## agent

```yaml
agent:
  protected: [".env*", "*.pem", "secrets/"]   # files agents read only via `velociredactor redact`
  exclude: [".env.example"]                   # never protected
  enforce: true                               # block direct reads where the agent supports hooks
```

The patterns follow `.gitignore` conventions, relative to this file:

- With no `/`, a pattern matches a file name at any depth.
- With a `/`, it is anchored at the project root.
- A trailing `/` covers a whole directory.

Useful commands:

- `velociredactor agent status` prints the agent section.
- `velociredactor agent check FILE…` exits 1 if any of the files is protected.

## Commands for checking your work

```sh
velociredactor config validate          # errors → exit 2
velociredactor list FILE [--json]       # findings, values hidden
velociredactor redact --check FILE      # exit 1 if anything remains redacted
```
