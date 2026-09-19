#!/usr/bin/env bash
# Install the latest veloci binary from GitHub releases for this platform.
#
#   curl -fsSL https://raw.githubusercontent.com/phayes/velociredactor/master/scripts/install.sh | bash
#
# Environment:
#   PREFIX    install directory (default: /usr/local/bin if writable, else ~/.local/bin)
#   VERSION   release tag such as v0.1.1 (default: latest)
set -euo pipefail

REPO="phayes/velociredactor"
RELEASES="https://github.com/${REPO}/releases"

usage() {
  cat <<'EOF'
Install the veloci binary from GitHub releases.

Usage: install.sh [--prefix DIR] [--version TAG]

  --prefix DIR   directory to place veloci
                 (default: $PREFIX, or /usr/local/bin if writable, else ~/.local/bin)
  --version TAG  release tag to install, such as v0.1.1 (default: latest)
  -h, --help     show this help

Requires curl, plus sha256sum or shasum. Releases are glibc builds; Alpine
and other musl systems should use: cargo install velociredactor-cli
EOF
}

prefix="${PREFIX:-}"
version="${VERSION:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || { echo "install.sh: --prefix needs a directory" >&2; exit 2; }
      prefix="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || { echo "install.sh: --version needs a tag" >&2; exit 2; }
      version="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need() {
  command -v "$1" >/dev/null || {
    echo "install.sh: need $1 on PATH" >&2
    exit 1
  }
}

need curl

os="$(uname -s)"
arch="$(uname -m)"

case "$os/$arch" in
  Darwin/arm64)
    target="aarch64-apple-darwin"
    archive_ext="tar.gz"
    exe="veloci"
    ;;
  Darwin/x86_64)
    target="x86_64-apple-darwin"
    archive_ext="tar.gz"
    exe="veloci"
    ;;
  Linux/aarch64 | Linux/arm64)
    target="aarch64-unknown-linux-gnu"
    archive_ext="tar.gz"
    exe="veloci"
    ;;
  Linux/x86_64)
    target="x86_64-unknown-linux-gnu"
    archive_ext="tar.gz"
    exe="veloci"
    ;;
  MINGW*/ARM64 | MINGW*/aarch64 | MSYS*/ARM64 | MSYS*/aarch64 | CYGWIN*/ARM64 | CYGWIN*/aarch64)
    target="aarch64-pc-windows-msvc"
    archive_ext="zip"
    exe="veloci.exe"
    ;;
  MINGW*/x86_64 | MSYS*/x86_64 | CYGWIN*/x86_64)
    target="x86_64-pc-windows-msvc"
    archive_ext="zip"
    exe="veloci.exe"
    ;;
  *)
    echo "install.sh: no release for $os/$arch" >&2
    echo "Install from source: cargo install velociredactor-cli" >&2
    exit 1
    ;;
esac

if [[ "$os" == Linux ]]; then
  if [[ -f /etc/alpine-release ]] || { command -v ldd >/dev/null && ldd --version 2>&1 | grep -qi musl; }; then
    echo "install.sh: published Linux binaries are glibc; this system looks like musl." >&2
    echo "Install from source: cargo install velociredactor-cli" >&2
    exit 1
  fi
fi

if [[ -z "$prefix" ]]; then
  if [[ -d /usr/local/bin && -w /usr/local/bin ]]; then
    prefix=/usr/local/bin
  else
    prefix="${HOME:?HOME is not set}/.local/bin"
  fi
fi

if [[ -z "$version" ]]; then
  # /releases/latest redirects to /releases/tag/<tag>; that avoids the API
  # rate limit and does not need jq.
  latest_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "${RELEASES}/latest")"
  version="${latest_url##*/}"
fi

if [[ -z "$version" || "$version" == latest ]]; then
  echo "install.sh: could not resolve the latest release tag" >&2
  exit 1
fi

asset="velociredactor-${version}-${target}.${archive_ext}"
base="${RELEASES}/download/${version}"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/veloci-install.XXXXXX")"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

echo "Downloading ${asset}"
curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}"
curl -fsSL -o "${tmp}/${asset}.sha256" "${base}/${asset}.sha256"

if command -v sha256sum >/dev/null; then
  (cd "$tmp" && sha256sum -c --status "${asset}.sha256")
elif command -v shasum >/dev/null; then
  (cd "$tmp" && shasum -a 256 -c "${asset}.sha256" >/dev/null)
else
  echo "install.sh: need sha256sum or shasum to verify the download" >&2
  exit 1
fi

mkdir -p "${tmp}/extract"
case "$archive_ext" in
  tar.gz)
    tar -xzf "${tmp}/${asset}" -C "${tmp}/extract"
    ;;
  zip)
    need unzip
    unzip -q "${tmp}/${asset}" -d "${tmp}/extract"
    ;;
esac

# CI packs README, LICENSE, and the binary in velociredactor-<tag>-<target>/.
# Older releases named the binary velociredactor; install either as veloci.
staged="${tmp}/extract/velociredactor-${version}-${target}"
if [[ -f "${staged}/${exe}" ]]; then
  bin="${staged}/${exe}"
elif [[ -f "${staged}/velociredactor${exe#veloci}" ]]; then
  bin="${staged}/velociredactor${exe#veloci}"
else
  echo "install.sh: archive did not contain ${exe} at the expected path" >&2
  exit 1
fi

mkdir -p "$prefix"
if [[ ! -w "$prefix" ]]; then
  echo "install.sh: cannot write to ${prefix}" >&2
  echo "Re-run with --prefix DIR or as a user who can write there." >&2
  exit 1
fi

dest="${prefix}/${exe}"
install -m 755 "$bin" "$dest"
echo "Installed ${dest} (${version}, ${target})"
"$dest" --version
