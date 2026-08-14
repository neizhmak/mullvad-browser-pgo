#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"
log="$RUNNER_TEMP/pgo-generate-build.log"
cd "$UPSTREAM"
# Build only the pinned Firefox RBM project, not browser/release.
./rbm/rbm build firefox --target alpha --target mullvadbrowser-windows-x86_64 \
  --target pgo-generate 2>&1 | tee "$log"
grep -F -- '--enable-profile-generate=cross' "$log" >/dev/null || {
  echo 'instrumented configure evidence is missing' >&2; exit 1; }
if grep -F -- '--enable-profile-use' "$log"; then
  echo 'profile-use was accidentally enabled' >&2; exit 1
fi
mkdir -p "$RUNNER_TEMP/instrumented"
mapfile -t packages < <(find out/firefox -type f \( -name '*.tar.xz' -o -name '*.tar.zst' \) | sort)
((${#packages[@]} == 1)) || { printf 'Expected one Firefox package, found %s\n' "${#packages[@]}" >&2; printf '%s\n' "${packages[@]}" >&2; exit 1; }
cp "${packages[0]}" "$RUNNER_TEMP/instrumented/"
sha256sum "$RUNNER_TEMP/instrumented/$(basename "${packages[0]}")" | tee "$RUNNER_TEMP/instrumented/package.sha256"
