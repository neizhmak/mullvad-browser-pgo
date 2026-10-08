#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?UPSTREAM must name pinned checkout}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
patch_file="$root/patches/firefox-pgo-generate.patch"
# Force HTTP/1.1 and large buffer to prevent GitLab HTTP/2 stream errors (curl 92)
git config --global http.version HTTP/1.1 || true
git config --global http.postBuffer 524288000 || true

# The patch's exact preimage makes upstream recipe drift a hard failure.
git -C "$UPSTREAM" diff --quiet
git -C "$UPSTREAM" apply --check "$patch_file"
git -C "$UPSTREAM" apply "$patch_file"
git -C "$UPSTREAM" diff --check
sha256sum "$patch_file" | tee "${RUNNER_TEMP:-/tmp}/pgo-overlay.sha256"
"$root/scripts/prepare-wasi-config-input.sh"
