#!/usr/bin/env bash

# Fail-closed workaround for the pinned wasi-config git.savannah.gnu.org input only.
set -euo pipefail

: "${UPSTREAM:?UPSTREAM must name the pinned upstream checkout}"
readonly config="$UPSTREAM/projects/wasi-config/config"

mapfile -t input < <(python3 - "$config" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
try:
    text = path.read_text(encoding="utf-8")
except OSError as exc:
    raise SystemExit(f"error: cannot inspect pinned wasi-config config: {exc}")

url_match = re.search(r"(?m)^git_url:\s*([^\s#]+)", text)
if not url_match or url_match.group(1) != "https://git.savannah.gnu.org/git/config.git":
    raise SystemExit("error: pinned wasi-config config does not require the supported Savannah git_url")

hash_match = re.search(r"(?m)^git_hash:\s*([0-9a-f]{40})\s*$", text)
if not hash_match:
    raise SystemExit("error: pinned wasi-config config has no supported git_hash")

print(url_match.group(1))
print(hash_match.group(1))
PY
)
[[ ${#input[@]} -eq 2 ]] || { echo "error: failed to inspect pinned wasi-config input" >&2; exit 1; }

readonly expected_url=${input[0]}
readonly expected_hash=${input[1]}
readonly clones_dir="$UPSTREAM/git_clones"
readonly target_dir="$clones_dir/wasi-config"
readonly primary_url="https://git.savannah.gnu.org/git/config.git"
readonly mirror_url="https://gitlab.com/freedesktop-sdk/mirrors/savannah/config.git"
readonly backup_mirror_url="https://github.com/cgitmirror/config.git"

verify() {
  local dir=$1 commit
  [[ -d "$dir/.git" ]] || return 1
  commit="$(git -C "$dir" rev-parse --verify "$expected_hash^{commit}" 2>/dev/null)" || return 1
  [[ "$commit" == "$expected_hash" ]] || return 1
}

if [[ -d "$target_dir" ]] && verify "$target_dir"; then
  echo "Pinned wasi-config clone is already present and verified in $target_dir."
  exit 0
fi

mkdir -p "$clones_dir"
rm -rf -- "$target_dir"

clone_and_verify() {
  local url=$1 label=$2 stage
  stage="$(mktemp -d "$clones_dir/.wasi-config.XXXXXXXX")"
  trap 'rm -rf -- "$stage"' RETURN
  echo "Checking $label wasi-config source: $url"
  if ! git clone --quiet "$url" "$stage" 2>/dev/null; then
    echo "$label wasi-config source was unavailable." >&2
    return 1
  fi
  if ! verify "$stage"; then
    echo "$label wasi-config clone failed pinned commit verification." >&2
    return 1
  fi

  git -C "$stage" remote set-url origin "$expected_url"
  git -C "$stage" checkout --quiet --detach "$expected_hash"
  mv -f -- "$stage" "$target_dir"
  trap - RETURN
  echo "Using verified wasi-config clone from $label."
}

if clone_and_verify "$primary_url" "official Savannah Git"; then
  exit 0
fi
if clone_and_verify "$mirror_url" "official freedesktop GitLab mirror"; then
  exit 0
fi
if clone_and_verify "$backup_mirror_url" "GitHub cgit mirror"; then
  exit 0
fi

echo "error: no available source provided a verified wasi-config clone" >&2
exit 1
