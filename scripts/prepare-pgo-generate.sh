#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?UPSTREAM must name pinned checkout}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
patch_file="$root/patches/firefox-pgo-generate.patch"
# Force HTTP/1.1 and large buffer to prevent GitLab HTTP/2 stream errors (curl 92)
git config --global http.version HTTP/1.1 || true
git config --global http.postBuffer 524288000 || true

# Clean up pre-installed runner software to free ~40-50 GB on root filesystem (/)
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo rm -rf \
    /usr/local/lib/android \
    /usr/share/dotnet \
    /opt/ghc \
    /usr/local/.ghcup \
    /usr/local/share/powershell \
    /usr/local/share/chromium \
    /opt/hostedtoolcache/CodeQL \
    /usr/lib/jvm \
    2>/dev/null || true
fi

# Set up scratch directory on /mnt if available
if [[ -d "/mnt" ]]; then
  mnt_tmp="/mnt/rbm-tmp"
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo mkdir -p "$mnt_tmp"
    sudo chown -R "$(id -u):$(id -g)" "$mnt_tmp" 2>/dev/null || true
  else
    mkdir -p "$mnt_tmp" 2>/dev/null || true
  fi
  if [[ -d "$mnt_tmp" && -w "$mnt_tmp" ]]; then
    chmod 777 "$mnt_tmp" 2>/dev/null || true
    if [[ -d "$UPSTREAM" ]]; then
      if [[ -d "$UPSTREAM/tmp" && ! -L "$UPSTREAM/tmp" ]]; then
        cp -a "$UPSTREAM/tmp/." "$mnt_tmp/" 2>/dev/null || true
        rm -rf "$UPSTREAM/tmp"
      fi
      ln -sfn "$mnt_tmp" "$UPSTREAM/tmp"
    fi
  fi
fi

# The patch's exact preimage makes upstream recipe drift a hard failure.
git -C "$UPSTREAM" diff --quiet
git -C "$UPSTREAM" apply --check "$patch_file"
git -C "$UPSTREAM" apply "$patch_file"
git -C "$UPSTREAM" diff --check
sha256sum "$patch_file" | tee "${RUNNER_TEMP:-/tmp}/pgo-overlay.sha256"
"$root/scripts/prepare-wasi-config-input.sh"
