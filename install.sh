#!/usr/bin/env bash
set -Eeuo pipefail
REPO="mahanneo/Dragon-VPS-Manager-NG"
REF="${DRAGON_REF:-main}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

command -v curl >/dev/null 2>&1 || { apt-get update && apt-get install -y curl ca-certificates; }
curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz" -o "$TMP/source.tar.gz"
tar -xzf "$TMP/source.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'Dragon-VPS-Manager-NG-*' | head -n1)"
[[ -n "$SRC" ]] || { echo "Unable to locate extracted source."; exit 1; }
bash "$SRC/scripts/install.sh"
