//! Fetches the betterleaks ruleset and word list used by the default
//! `RulesetDetector`, verifies them against pinned checksums, and places them in
//! `OUT_DIR` for `include_bytes!`.
//!
//! Environment:
//! - `REDACTIFY_BETTERLEAKS_DIR`: read `betterleaks.toml` and `words.txt.gz`
//!   from this directory instead of downloading (for offline builds).
//! - `DOCS_RS`: write empty placeholders; docs.rs builds have no network.

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const BETTERLEAKS_TAG: &str = "v1.8.1";

struct Asset {
    file_name: &'static str,
    repo_path: &'static str,
    sha256: &'static str,
}

const ASSETS: &[Asset] = &[
    Asset {
        file_name: "betterleaks.toml",
        repo_path: "config/betterleaks.toml",
        sha256: "27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42",
    },
    Asset {
        file_name: "words.txt.gz",
        repo_path: "internal/words/words.txt.gz",
        sha256: "d4dd5530d98f4ff343864ed71cfc0064abeae34e4f078edc0b46590c2da8fb47",
    },
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=REDACTIFY_BETTERLEAKS_DIR");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));

    if env::var_os("DOCS_RS").is_some() {
        for asset in ASSETS {
            fs::write(out_dir.join(asset.file_name), b"").expect("write placeholder asset");
        }
        return;
    }

    let local_dir = env::var_os("REDACTIFY_BETTERLEAKS_DIR").map(PathBuf::from);
    for asset in ASSETS {
        let dest = out_dir.join(asset.file_name);
        if dest.exists() && sha256_hex(&fs::read(&dest).unwrap_or_default()) == asset.sha256 {
            continue;
        }
        let bytes = match &local_dir {
            Some(dir) => read_local(dir, asset),
            None => download(asset),
        };
        let actual = sha256_hex(&bytes);
        if actual != asset.sha256 {
            panic!(
                "checksum mismatch for {} ({}): expected {}, got {}",
                asset.file_name, BETTERLEAKS_TAG, asset.sha256, actual
            );
        }
        fs::write(&dest, bytes).expect("write asset to OUT_DIR");
    }
}

fn read_local(dir: &Path, asset: &Asset) -> Vec<u8> {
    let path = dir.join(asset.file_name);
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "REDACTIFY_BETTERLEAKS_DIR: cannot read {}: {err}",
            path.display()
        )
    })
}

fn download(asset: &Asset) -> Vec<u8> {
    let url = format!(
        "https://raw.githubusercontent.com/betterleaks/betterleaks/{BETTERLEAKS_TAG}/{}",
        asset.repo_path
    );
    let response = ureq::get(&url).call().unwrap_or_else(|err| {
        panic!(
            "failed to download {url}: {err}\n\
             For offline builds, set REDACTIFY_BETTERLEAKS_DIR to a directory \
             containing betterleaks.toml and words.txt.gz from betterleaks {BETTERLEAKS_TAG}."
        )
    });
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .unwrap_or_else(|err| panic!("failed to read {url}: {err}"));
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
