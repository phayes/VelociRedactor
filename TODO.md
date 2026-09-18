# TODO

- Add `--comments` to scan comments in formats that have them (JSONC, YAML, TOML, HCL, INI, …). Comments are skipped today.
- Add a persistent config directory support (defaults, allow lists, rules packs).
  - Start with a config file yml as a first pass
- Add a disallow-path (with glob) that ALWAYS strips regardless of content.  (DETECTOR becomeds path)
- Add allow-path that never redacts a path (with glom)
- add support for --exclude-detector (repeatable, glom)
- add --disallow-value (Danger! Since these will be in plaintext - but still useful in some situataions)
- collapse --pii-pattern and --rule into --disallow-regex REGEX (DETECTOR just becomes regex)
- add --allow-regex REGEX 