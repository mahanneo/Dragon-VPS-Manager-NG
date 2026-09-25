#!/usr/bin/env bash
set -Eeuo pipefail

REPO="mahanneo/Makia-VPS-Manager"
REF="${MAKIA_REF:-main}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash upgrade.sh"
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "Fetching the latest Makia updater from ${REPO}@${REF}..."
curl -fL --retry 3 "https://raw.githubusercontent.com/${REPO}/${REF}/scripts/update.sh" -o "$TMP"
chmod 0700 "$TMP"
bash "$TMP"
