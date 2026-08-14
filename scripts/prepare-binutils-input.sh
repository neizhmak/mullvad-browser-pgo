#!/usr/bin/env bash

# Fail-closed workaround for the pinned Binutils ftpmirror.gnu.org input only.
set -euo pipefail

: "${UPSTREAM:?UPSTREAM must name the pinned upstream checkout}"
readonly config="$UPSTREAM/projects/binutils/config"

mapfile -t input < <(python3 - "$config" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
try:
    text = path.read_text(encoding="utf-8")
except OSError as exc:
    raise SystemExit(f"error: cannot inspect pinned Binutils config: {exc}")

version_match = re.search(r"(?m)^version:\s*['\"]?([0-9][0-9A-Za-z.+~-]*)['\"]?\s*$", text)
if not version_match:
    raise SystemExit("error: pinned Binutils config has no supported version")
version = version_match.group(1)
expected_url = "https://ftpmirror.gnu.org/gnu/binutils/binutils-[% c(\"version\") %].tar.xz"

entries = re.findall(r"(?ms)^  - URL:\s*([^\n]+)\n(.*?)(?=^  - |\Z)", text)
matches = [(url.strip().strip("'\""), body) for url, body in entries
           if url.strip().strip("'\"") == expected_url]
if len(matches) != 1:
    raise SystemExit("error: pinned Binutils config does not require the supported GNU mirror input")
body = matches[0][1]

def field(name, required=False):
    match = re.search(rf"(?m)^\s{{4}}{name}:\s*['\"]?([^'\"\s#]+)['\"]?\s*(?:#.*)?$", body)
    if required and not match:
        raise SystemExit(f"error: supported Binutils input has no {name}")
    return match.group(1) if match else ""

if field("sig_ext", True) != "sig":
    raise SystemExit("error: supported Binutils input does not use a .sig signature")
keyring = field("gpg_keyring", True)
if "/" in keyring or keyring in (".", ".."):
    raise SystemExit("error: invalid Binutils keyring name")

checksums = [(name, field(name)) for name in ("sha512sum", "sha256sum")]
checksums = [(name, value) for name, value in checksums if value]
for name, value in checksums:
    size = 128 if name == "sha512sum" else 64
    if not re.fullmatch(rf"[0-9A-Fa-f]{{{size}}}", value):
        raise SystemExit(f"error: unsupported pinned Binutils {name}")

print(version)
print(keyring)
values = dict(checksums)
print(values.get("sha512sum", ""))
print(values.get("sha256sum", ""))
PY
)
[[ ${#input[@]} -eq 4 ]] || { echo "error: failed to inspect pinned Binutils input" >&2; exit 1; }

readonly version=${input[0]}
readonly keyring="$UPSTREAM/keyring/${input[1]}"
readonly expected_sha512=${input[2]}
readonly expected_sha256=${input[3]}
readonly filename="binutils-$version.tar.xz"
readonly signature="$filename.sig"
readonly output_dir="$UPSTREAM/out/binutils"
readonly configured_base="https://ftpmirror.gnu.org/gnu/binutils"
readonly fallback_base="https://ftp.gnu.org/gnu/binutils"

[[ -f "$keyring" ]] || { echo "error: pinned Binutils keyring is missing: $keyring" >&2; exit 1; }
mkdir -p "$output_dir"

verify() {
  local tarball=$1 signature_file=$2 actual
  gpg --batch --no-default-keyring --no-auto-check-trustdb --keyring "$keyring" --trust-model always \
    --verify "$signature_file" "$tarball" >/dev/null 2>&1 || return 1
  if [[ -n "$expected_sha512" ]]; then
    actual="$(sha512sum "$tarball" | awk '{print $1}')"
    [[ "${actual,,}" == "${expected_sha512,,}" ]] || return 1
  fi
  if [[ -n "$expected_sha256" ]]; then
    actual="$(sha256sum "$tarball" | awk '{print $1}')"
    [[ "${actual,,}" == "${expected_sha256,,}" ]] || return 1
  fi
}

if [[ -f "$output_dir/$filename" && -f "$output_dir/$signature" ]] \
    && verify "$output_dir/$filename" "$output_dir/$signature"; then
  echo "Pinned Binutils input is already present and verified in $output_dir."
  exit 0
fi
# Never leave a previously invalid tarball at the canonical path for RBM to use.
rm -f -- "$output_dir/$filename" "$output_dir/$signature"

download_and_verify() {
  local base=$1 label=$2 stage
  stage="$(mktemp -d "$output_dir/.binutils-input.XXXXXXXX")"
  trap 'rm -rf -- "$stage"' RETURN
  echo "Checking $label Binutils source: $base/$filename"
  if ! curl --fail --location --silent --show-error --connect-timeout 15 --max-time 120 \
      --output "$stage/$filename" "$base/$filename" \
      || ! curl --fail --location --silent --show-error --connect-timeout 15 --max-time 120 \
      --output "$stage/$signature" "$base/$signature"; then
    echo "$label Binutils source was unavailable." >&2
    return 1
  fi
  if ! verify "$stage/$filename" "$stage/$signature"; then
    echo "$label Binutils input failed pinned signature/checksum verification." >&2
    return 1
  fi

  # Publish the signature first; the verified tarball is the final atomic rename.
  mv -f -- "$stage/$signature" "$output_dir/$signature"
  mv -f -- "$stage/$filename" "$output_dir/$filename"
  trap - RETURN
  rm -rf -- "$stage"
  echo "Using verified Binutils input from $label."
}

if download_and_verify "$configured_base" "RBM-configured GNU mirror"; then
  exit 0
fi
if download_and_verify "$fallback_base" "GNU primary fallback"; then
  exit 0
fi

echo "error: neither configured nor fallback GNU source provided a verified Binutils input" >&2
exit 1
