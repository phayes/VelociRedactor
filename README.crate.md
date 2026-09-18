# velociredactor

<p align="center"><img src="https://raw.githubusercontent.com/phayes/velociredactor/master/logo.png" alt="velociredactor logo" width="420"></p>

`velociredactor` is a Rust library for redacting secrets and personal data from text and structured files.

Each redacted value becomes a token named `REDACTION-N`. `N` numbers distinct secrets in order of first appearance, and equal values share a number. Exact values and regular expressions can allow confirmed false positives.

Structured format support preserves keys and formatting while replacing values. Comment scanning is configurable. Raw mode treats the complete input as plain text.

The [CLI README](README.md) covers the command-line program, installation, and command reference.

## Quick start

Add the crate to a project:

```toml
[dependencies]
velociredactor = "0.1"
```

The default builder includes the built-in configuration:

```rust
use velociredactor::{Allow, FormatHint, Redactor};

let redactor = Redactor::builder().build();
let input = br#"{"db_password": "hunter2", "note": "hello"}"#;

let redaction = redactor.redact(input, FormatHint::Name("json")).unwrap();
assert_eq!(redaction.findings()[0].id, 1);
assert_eq!(redaction.findings()[0].token(), "REDACTION-1");

let output = redaction.render(&Allow::none()).unwrap();
assert_eq!(
    output,
    br#"{"db_password": "REDACTION-1", "note": "hello"}"#
);

// Render the same findings again while allowing that value through.
assert_eq!(redaction.render(&Allow::values(["hunter2"])).unwrap(), input);
```

[`Redactor::redact`] separates detection from rendering. A [`Redaction`] can render the same findings repeatedly with different [`Allow`] lists. [`Redactor::redact_str`] provides a compact plain-text API that replaces every finding.

## Configuration

Configuration defines the values to scan, documentation placeholders, active detectors, recognized formats, and allowed findings.

[`config::Config`] represents the complete configuration. [`Config::builtin`](config::Config::builtin) returns the copy compiled into the crate. [`Config::builtin_source`](config::Config::builtin_source) returns its commented YAML source. [`Config::apply`](config::Config::apply) applies a configuration to a [`RedactorBuilder`].

A configuration loaded from a file replaces the built-in configuration completely. Start a custom configuration from [`Config::builtin_source`](config::Config::builtin_source).

[`RedactorBuilder::new`] creates an empty builder. [`Redactor::builder`] creates a builder with the built-in detectors, formats, and policy.

## Formats

Default features provide structured handling for:

- JSON and JSON Lines
- YAML
- TOML
- XML
- HCL
- INI and dotenv files
- Java properties
- CSV, TSV, and pipe-separated values
- binary property lists
- plain text

[`FormatHint`] chooses a format by name, path, content, or raw text. An inferred structured format that fails to parse falls back to plain text and records a warning. An explicitly named format returns its parse error.

## Cargo features

The default feature set enables parallel detection and every bundled structured format.

- `parallel` uses Rayon for detector execution.
- `json`, `yaml`, `toml`, `xml`, `hcl`, `ini`, `dotenv`, `properties`, `csv`, and `plist` enable their corresponding formats.
- `privacy-filter` enables the OpenAI Privacy Filter model detector.
- `privacy-filter-cuda` enables NVIDIA CUDA execution.
- `privacy-filter-accelerate` enables Apple Accelerate.
- `privacy-filter-openblas` enables a system OpenBLAS installation.

Choose one BLAS backend feature for a build. The privacy-filter model is downloaded separately.

## Extending

Implement [`detect::Detector`] to add detection logic and register it with [`RedactorBuilder::detector`]. Bundled detectors such as [`detect::BETTERLEAKS_RULESET`] and [`detect::EmailDetector`] use the same interface. A detector that needs every document value together uses [`detect::Detector::document_scope`].

Implement [`format::Format`] to add a file format and register it with [`RedactorBuilder::format`]. The [`format::LeafVisitor`] interface communicates values and replacements while the format owns parsing and serialization.

Implement [`policy::LeafPolicy`] to control which structured values are scanned and which objects provide credential context.

The repository includes a complete custom detector and format in `examples/custom.rs`.

## License

velociredactor is available under the [MIT License](https://github.com/phayes/velociredactor/blob/master/LICENSE).
