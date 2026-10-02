#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"
log="$RUNNER_TEMP/pgo-generate-build.log"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$UPSTREAM"
common=(--target alpha --target mullvadbrowser-windows-x86_64 --target pgo-generate)
# Build only the pinned Firefox RBM project, not browser/release.
# Stream project/resource evidence before termination; later always() steps can
# be skipped when the hosted runner shuts down.
python3 "$root/scripts/observe-rbm-build.py" --upstream "$UPSTREAM" \
  --log "$log" --resource-log "$RUNNER_TEMP/pgo-generate-resources.jsonl" \
  -- ./rbm/rbm build firefox "${common[@]}"
# RBM writes configure output in its project log, not necessarily to stdout.
project_log="$UPSTREAM/logs/firefox-windows-x86_64.log"
[[ -s "$project_log" ]] || { echo 'Firefox project build log is missing' >&2; exit 1; }
grep -F -- '--enable-profile-generate=cross' "$project_log" >/dev/null || {
  echo 'instrumented configure evidence is missing' >&2; exit 1; }
# mach build --verbose records compiler commands. Configure arguments alone
# must not stand in for C++ AND Rust instrumentation evidence.
grep -E -- '(^|[[:space:]])-fprofile-generate(=|[[:space:]]|$)' "$project_log" >/dev/null || {
  echo 'C++ profile-generation compiler evidence is missing' >&2; exit 1; }
grep -E -- '-C[[:space:]]*profile-generate(=|[[:space:]]|$)' "$project_log" >/dev/null || {
  echo 'Rust profile-generation compiler evidence is missing' >&2; exit 1; }
if grep -F -- '--enable-profile-use' "$project_log"; then
  echo 'profile-use was accidentally enabled' >&2; exit 1
fi
filename="$(./rbm/rbm showconf firefox filename "${common[@]}")"
[[ -n "$filename" && "$filename" != */* ]] || { echo 'invalid Firefox RBM output filename' >&2; exit 1; }
output="$UPSTREAM/out/firefox/$filename"
# Official Firefox output is a directory containing multiple archives, including
# NSIS plugins. Only browser.tar is an instrumented browser runtime.
packages=()
for extension in zst xz; do
  [[ ! -f "$output/browser.tar.$extension" ]] || packages+=("$output/browser.tar.$extension")
done
((${#packages[@]} == 1)) || { printf 'Expected one browser runtime archive, found %s\n' "${#packages[@]}" >&2; exit 1; }
[[ -s "${packages[0]}" && ! -L "${packages[0]}" ]] || { echo 'browser runtime archive is empty or a symlink' >&2; exit 1; }
mkdir -p "$RUNNER_TEMP/instrumented"
cp "${packages[0]}" "$RUNNER_TEMP/instrumented/"
sha256sum "$RUNNER_TEMP/instrumented/$(basename "${packages[0]}")" | tee "$RUNNER_TEMP/instrumented/package.sha256"
