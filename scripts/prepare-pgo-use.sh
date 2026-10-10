#!/usr/bin/env bash
# Apply the profile-use overlay only after the generation/toolchain overlay.
set -euo pipefail
: "${UPSTREAM:?UPSTREAM must name the pinned, generation-patched checkout}"
: "${RUNNER_TEMP:?}"
: "${PGO_PROFILE_DIR:?PGO_PROFILE_DIR must contain a verified schema-2 profile}"
: "${PGO_EXPECTED_PROVENANCE:?use independently resolved expected source/toolchain provenance}"
: "${PGO_PROFILE_IDENTITY:?use the full profile identity from the generation job}"
[[ "$PGO_PROFILE_IDENTITY" =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid profile identity' >&2; exit 1; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="$RUNNER_TEMP/pgo-use"
mkdir -p "$work"
python3 "$root/scripts/profile-artifacts.py" restore \
  --source-directory "$PGO_PROFILE_DIR" --directory "$work/profile" \
  --expected-provenance "$PGO_EXPECTED_PROVENANCE" --expected-identity "$PGO_PROFILE_IDENTITY"
export PGO_PROFILE_SHA256="$(sha256sum "$work/profile/merged.profdata" | cut -d' ' -f1)"
export PGO_JARLOG_SHA256="$(sha256sum "$work/profile/jarlog" | cut -d' ' -f1)"
python3 - "$UPSTREAM" "$root/upstream.lock.json" <<'PY_PIN'
import json, pathlib, subprocess, sys
upstream, lockfile = sys.argv[1:]
lock = json.loads(pathlib.Path(lockfile).read_text())
actual = subprocess.check_output(['git', '-C', upstream, 'rev-parse', 'HEAD'], text=True).strip()
if actual != lock['commit']:
    raise SystemExit('PGO use requires the exact locked upstream commit')
PY_PIN
patch_file="$root/patches/firefox-pgo-use.patch"
# Safe reruns accept an exact already-applied patch, not arbitrary recipe drift.
if git -C "$UPSTREAM" apply --reverse --check "$patch_file" >/dev/null 2>&1; then
  echo 'Exact PGO use overlay is already applied.'
else
  git -C "$UPSTREAM" apply --check "$patch_file"
  git -C "$UPSTREAM" apply "$patch_file"
fi
git -C "$UPSTREAM" diff --check
python3 - "$UPSTREAM/projects/firefox/config" <<'PY_FIX'
import pathlib, sys
config_path = pathlib.Path(sys.argv[1])
if config_path.is_file():
    text = config_path.read_text(encoding="utf-8")
    fixed = text.replace("    name: pgo-profdata\n    sha256sum: '[% c(\"var/pgo_profile_sha256\") %]'\n    refresh_input: 1\n",
                         "    name: pgo-profdata\n    sha256sum: '[% c(\"var/pgo_profile_sha256\") %]'\n")
    fixed = fixed.replace("    name: pgo-jarlog\n    sha256sum: '[% c(\"var/pgo_jarlog_sha256\") %]'\n    refresh_input: 1\n",
                          "    name: pgo-jarlog\n    sha256sum: '[% c(\"var/pgo_jarlog_sha256\") %]'\n")
    if fixed != text:
        config_path.write_text(fixed, encoding="utf-8")
PY_FIX
python3 - "$work/profile" "$UPSTREAM/projects/firefox" <<'PY_INPUTS'
import hashlib, pathlib, shutil, sys
profile, destination = map(pathlib.Path, sys.argv[1:])
for source_name, suffix in [('merged.profdata', 'profdata'), ('jarlog', 'jarlog')]:
    source = profile / source_name
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    target = destination / ('pgo-' + digest + '.' + suffix)
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise SystemExit('conflicting profile input: ' + str(target))
    shutil.copyfile(source, target)
PY_INPUTS
common=(--target alpha --target mullvadbrowser-windows-x86_64)
use=("${common[@]}" --target pgo-use)
get() { (cd "$UPSTREAM" && python3 "$root/scripts/rbm_network.py" --upstream "$PWD" --project "$1" --key "$2" "${@:3}"); }
rust_generate="$(get rust filename "${common[@]}" --target pgo-generate)"
rust_use="$(get rust filename "${use[@]}")"
firefox_rust="$(get firefox input_files_by_name/rust "${use[@]}")"
[[ "$rust_use" == "$rust_generate" && "$rust_use" == *-profiler* && "$firefox_rust" == "$rust_use" ]] || {
  echo 'final Firefox does not resolve the same profiler Rust input as generation' >&2; exit 1; }
get firefox build "${common[@]}" > "$work/firefox-baseline.rendered"
get firefox build "${use[@]}" > "$work/firefox-pgo-use.rendered"
get firefox input_files "${use[@]}" > "$work/firefox-inputs.log"
python3 - "$work/firefox-baseline.rendered" "$work/firefox-pgo-use.rendered" <<'PY_RENDER'
import pathlib, sys
baseline, use = [pathlib.Path(p).read_text() for p in sys.argv[1:]]
if '--enable-profile-use' in baseline or '--enable-profile-generate' in baseline:
    raise SystemExit('normal Firefox rendering was not preserved')
if '--enable-profile-generate' in use:
    raise SystemExit('generation and use flags are not mutually exclusive')
lines = use.splitlines()
commands = []
for i, line in enumerate(lines):
    if line.strip().startswith('./mach configure'):
        command = [line.strip()]
        while command[-1].endswith('\\') and i + 1 < len(lines):
            i += 1
            command.append(lines[i].strip())
        commands.append('\n'.join(command))
if len(commands) != 1:
    raise SystemExit('expected exactly one rendered configure command')
for flag in ['--enable-profile-use=cross', '--with-pgo-profile-path=/var/tmp/dist/pgo/merged.profdata', '--with-pgo-jarlog=/var/tmp/dist/pgo/jarlog']:
    if commands[0].count(flag) != 1:
        raise SystemExit('profile-use argument missing from configure: ' + flag)
print('Verified effective profile-use configure flags and unchanged baseline.')
PY_RENDER
{
  printf 'PGO_PROFILE_SHA256=%s\n' "$PGO_PROFILE_SHA256"
  printf 'PGO_JARLOG_SHA256=%s\n' "$PGO_JARLOG_SHA256"
} > "$work/profile-inputs.env"
if [[ -n "${GITHUB_ENV:-}" ]]; then cat "$work/profile-inputs.env" >> "$GITHUB_ENV"; fi
printf 'Shared profiler Rust input: %s\n' "$rust_use" | tee "$work/rust-input.log"
sha256sum "$patch_file" | tee "$work/pgo-use-overlay.sha256"
