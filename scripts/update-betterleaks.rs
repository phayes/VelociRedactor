#!/usr/bin/env -S cargo +nightly -Zscript
---
[package]
edition = "2024"

[dependencies]
sha2 = "0.11"
ureq = "3"
---

/// The betterleaks release to vendor: a tag such as "v1.8.1", or "latest"
/// for the newest published release. Edit this to update.
const TAG: &str = "latest";

// Downloads the betterleaks ruleset, word list, and license for `TAG` into
// `vendor/betterleaks/`, which the crate embeds at compile time. Run it from
// anywhere inside the repository:
//
//     scripts/update-betterleaks.rs
//
// `vendor/betterleaks/VERSION` records the vendored tag (the resolved one when
// `TAG` is "latest") and
// `vendor/betterleaks/SHA256SUMS` the checksum of each file, so updates show
// up clearly in review.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use ureq::ResponseExt;

const REPO: &str = "betterleaks/betterleaks";

/// (file name in the vendor directory, path in the betterleaks repository)
const FILES: &[(&str, &str)] = &[
    ("betterleaks.toml", "config/betterleaks.toml"),
    ("words.txt.gz", "internal/words/words.txt.gz"),
    ("LICENSE", "LICENSE"),
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let dir = vendor_dir()?;
    let tag = if TAG == "latest" {
        let tag = latest_tag()?;
        eprintln!("latest release is {tag}");
        tag
    } else {
        TAG.to_owned()
    };

    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut sums = String::new();
    for (name, repo_path) in FILES {
        let url = format!("https://raw.githubusercontent.com/{REPO}/{tag}/{repo_path}");
        eprintln!("fetching {url}");
        let bytes = download(&url)?;
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sums.push_str(&format!("{digest}  {name}\n"));
        let path = dir.join(name);
        fs::write(&path, &bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    write(&dir.join("SHA256SUMS"), &sums)?;
    write(&dir.join("VERSION"), &format!("{tag}\n"))?;
    eprintln!("vendored betterleaks {tag} into {}", dir.display());
    Ok(())
}

/// `vendor/betterleaks` under the repository root, found from the current
/// directory upwards.
fn vendor_dir() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        if is_repo_root(&dir) {
            return Ok(dir.join("vendor").join("betterleaks"));
        }
        if !dir.pop() {
            return Err("run this from inside the velociredactor repository".into());
        }
    }
}

fn is_repo_root(dir: &Path) -> bool {
    fs::read_to_string(dir.join("Cargo.toml"))
        .is_ok_and(|manifest| manifest.contains("name = \"velociredactor\""))
}

/// The newest published release tag. GitHub redirects `/releases/latest` to
/// `/releases/tag/<tag>`, so the tag is the last segment of the final URL.
/// Downloads then use this fixed tag, so every file comes from one release.
fn latest_tag() -> Result<String, String> {
    let url = format!("https://github.com/{REPO}/releases/latest");
    let response = ureq::get(&url)
        .call()
        .map_err(|e| format!("resolve {url}: {e}"))?;
    let final_url = response.get_uri().to_string();
    final_url
        .split_once("/releases/tag/")
        .map(|(_, tag)| tag.trim_end_matches('/').to_owned())
        .filter(|tag| !tag.is_empty() && !tag.contains('/'))
        .ok_or_else(|| format!("unexpected redirect from {url} to {final_url}"))
}

fn download(url: &str) -> Result<Vec<u8>, String> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| format!("download {url}: {e}"))?;
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {url}: {e}"))?;
    Ok(bytes)
}

fn write(path: &Path, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}
