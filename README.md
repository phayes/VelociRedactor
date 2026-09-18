<p align="center"><img src="https://raw.githubusercontent.com/phayes/velociredactor/master/logo.png" alt="velociredactor logo" width="300"></p>

# velociredactor

`velociredactor` redacts secrets and personal data from text and structured files while preserving their shape and formatting. Each distinct secret is replaced by a stable numbered token such as `REDACTION-1`.

Velociredactor aims to be *fast*, with parallel scanning and a very fast regex engine. It aims to be *exaustive*, with built-in support for all [Betterleaks](https://betterleaks.com) secret patterns, and optional support for [OpenAI's Privacy Filter](https://openai.com/index/introducing-openai-privacy-filter/). Finally, it aims to be *configurable* with extensive configuration options, and *extensible* with a matching [rust crate](https://crates.io/crates/velociredactor) and traits. 

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

velociredactor formats
velociredactor config show [--config FILE]
velociredactor config location [--config FILE]
velociredactor config validate [--config FILE]
velociredactor privacy_filter download [--dir DIR] [--repo OWNER/NAME]
                                         [--revision REV]
velociredactor man
```

Use `velociredactor --help` or `velociredactor COMMAND --help` for concise generated help. `velociredactor man` prints this complete manual.

## License

velociredactor is available under the [MIT License](LICENSE).
