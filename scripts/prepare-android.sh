#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?UPSTREAM must name pinned checkout}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
patch_file="$root/patches/android-mullvad.patch"

# Force HTTP/1.1 and large buffer to prevent GitLab HTTP/2 stream errors (curl 92)
git config --global http.version HTTP/1.1 || true
git config --global http.postBuffer 524288000 || true
git config --global http.lowSpeedLimit 1000 || true
git config --global http.lowSpeedTime 60 || true

# Pre-clone git dependencies with retries to protect against transient GitLab connection timeouts
preclone_repo() {
  local project="$1" url="$2" extra_opts="${3:-}"
  local target_dir="$UPSTREAM/git_clones/$project"
  if [[ ! -d "$target_dir/.git" ]]; then
    mkdir -p "$UPSTREAM/git_clones"
    for attempt in {1..6}; do
      echo "Pre-cloning $project from $url (attempt $attempt/6)..."
      if git clone $extra_opts "$url" "$target_dir"; then
        echo "Successfully pre-cloned $project."
        return 0
      fi
      echo "Clone of $project failed; retrying in 15s..."
      rm -rf "$target_dir"
      sleep 15
    done
    echo "Warning: pre-clone of $project failed after 6 attempts; RBM will retry during build." >&2
  fi
}

preclone_repo "application-services" "https://gitlab.torproject.org/tpo/applications/application-services.git" "--recurse-submodules"
preclone_repo "translation" "https://gitlab.torproject.org/tpo/translation.git"


# Clean up pre-installed runner software to free ~35-40 GB on root filesystem (/)
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo rm -rf \
    /usr/share/dotnet \
    /opt/ghc \
    /usr/local/.ghcup \
    /usr/local/share/powershell \
    /usr/local/share/chromium \
    /opt/hostedtoolcache/CodeQL \
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

# Safe reruns accept an exact already-applied patch, not arbitrary recipe drift.
if git -C "$UPSTREAM" apply --reverse --check "$patch_file" >/dev/null 2>&1; then
  echo 'Exact Android overlay is already applied.'
else
  git -C "$UPSTREAM" apply --check "$patch_file"
  git -C "$UPSTREAM" apply "$patch_file"
fi
git -C "$UPSTREAM" diff --check
sha256sum "$patch_file" | tee "${RUNNER_TEMP:-/tmp}/android-overlay.sha256"
"$root/scripts/prepare-wasi-config-input.sh"
