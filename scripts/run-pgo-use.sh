#!/usr/bin/env bash
# Separate Firefox compilation from lightweight browser packaging for hosted runners.
set -euo pipefail
stage=''
while (($#)); do
  case "$1" in
    --stage) (($# >= 2)) || { echo '--stage needs a value' >&2; exit 2; }; stage="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$stage" == firefox || "$stage" == browser ]] || { echo 'use --stage firefox|browser' >&2; exit 2; }
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"; : "${PGO_PROFILE_IDENTITY:?}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="$RUNNER_TEMP/pgo-use"
profile="$work/profile"
[[ -s "$profile/merged.profdata" && -s "$profile/jarlog" ]] || { echo 'prepare-pgo-use.sh must run first' >&2; exit 1; }
python3 "$root/scripts/profile-artifacts.py" validate --directory "$profile"
export PGO_PROFILE_SHA256="$(sha256sum "$profile/merged.profdata" | cut -d' ' -f1)"
export PGO_JARLOG_SHA256="$(sha256sum "$profile/jarlog" | cut -d' ' -f1)"
args=(--target alpha --target mullvadbrowser-windows-x86_64 --target pgo-use)
get() { (cd "$UPSTREAM" && ./rbm/rbm showconf "$1" "$2" "${args[@]}"); }
selected_directory() {
  local project="$1" filename="$2"
  [[ "$filename" =~ ^[a-zA-Z0-9._-]+$ ]] || { echo 'unsafe RBM output filename' >&2; exit 1; }
  printf '%s/out/%s/%s\n' "$UPSTREAM" "$project" "$filename"
}
if [[ "$stage" == firefox ]]; then
  filename="$(get firefox filename)"
  selected="$(selected_directory firefox "$filename")"
  existed=false; [[ ! -d "$selected" ]] || existed=true
  build_log="$(get firefox build_log)"
  [[ "$build_log" == /* ]] || build_log="$UPSTREAM/$build_log"
  if [[ "$existed" == false ]]; then rm -f "$build_log"; fi
  (cd "$UPSTREAM" && ./rbm/rbm build firefox "${args[@]}") 2>&1 | tee "$work/firefox-rbm.log"
  if [[ "$existed" == false ]]; then
    [[ -s "$build_log" ]] || { echo 'Firefox project log is missing' >&2; exit 1; }
    cp "$build_log" "$work/firefox-project.log"
    grep -F -- '--enable-profile-use=cross' "$build_log" >/dev/null || { echo 'profile-use configure evidence is missing' >&2; exit 1; }
    grep -F -- '-fprofile-use=/var/tmp/dist/pgo/merged.profdata' "$build_log" >/dev/null || { echo 'C++ profile-use compiler evidence is missing' >&2; exit 1; }
    grep -E -- '-C[[:space:]]*profile-use=/var/tmp/dist/pgo/merged.profdata' "$build_log" >/dev/null || { echo 'Rust profile-use compiler evidence is missing' >&2; exit 1; }
    if grep -F -- '--enable-profile-generate' "$build_log"; then echo 'profile-use build enabled generation' >&2; exit 1; fi
  fi
  python3 "$root/scripts/collect-pgo-packages.py" snapshot-firefox \
    --directory "$selected" --rbm-filename "$filename" --profile-directory "$profile" \
    --profile-identity "$PGO_PROFILE_IDENTITY" --output-directory "$work"
  if [[ -n "${GITHUB_ENV:-}" ]]; then printf 'PGO_FIREFOX_ARTIFACT_DIR=%s\n' "$work" >> "$GITHUB_ENV"; fi
  exit 0
fi
artifact="${PGO_FIREFOX_ARTIFACT_DIR:-$work}"
export PGO_FIREFOX_SHA256="$(python3 "$root/scripts/collect-pgo-packages.py" verify-firefox \
  --artifact-directory "$artifact" --profile-directory "$profile" --profile-identity "$PGO_PROFILE_IDENTITY")"
input="$UPSTREAM/projects/browser/pgo-firefox-$PGO_FIREFOX_SHA256.tar"
if [[ -e "$input" && "$(sha256sum "$input" | cut -d' ' -f1)" != "$PGO_FIREFOX_SHA256" ]]; then
  echo 'conflicting prebuilt Firefox input' >&2; exit 1
fi
cp "$artifact/firefox-output.tar" "$input"
firefox_input="$(get browser input_files_by_name/firefox)"
[[ "$firefox_input" == "$(basename "$input")" ]] || { echo 'browser packaging selected a Firefox project instead of the verified local artifact' >&2; exit 1; }
get browser input_files > "$work/browser-inputs.log"
get browser build > "$work/browser-pgo-use.rendered"
filename="$(get browser filename)"
selected="$(selected_directory browser "$filename")"
(cd "$UPSTREAM" && ./rbm/rbm build browser "${args[@]}") 2>&1 | tee "$work/browser-rbm.log"
build_log="$(get browser build_log)"
[[ "$build_log" == /* ]] || build_log="$UPSTREAM/$build_log"
[[ ! -f "$build_log" ]] || cp "$build_log" "$work/browser-project.log"
version="$(get browser version)"
application_directory="$(get browser var/Project_Name)"
python3 "$root/scripts/collect-pgo-packages.py" collect --directory "$selected" \
  --destination "$RUNNER_TEMP/final-packages" --version "$version" \
  --application-directory "$application_directory" --firefox-manifest "$artifact/firefox-output.json" \
  --profile-identity "$PGO_PROFILE_IDENTITY"
if [[ -n "${GITHUB_ENV:-}" ]]; then printf 'PGO_FINAL_PACKAGES_DIR=%s\n' "$RUNNER_TEMP/final-packages" >> "$GITHUB_ENV"; fi
