#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
args=(--target alpha --target mullvadbrowser-windows-x86_64 --target pgo-generate)
get() { "$UPSTREAM/rbm/rbm" showconf firefox "$1" "${args[@]}" | tail -n1; }
firefox_repo="$(get git_url)"; firefox_ref="$(get git_hash)"; firefox_revision="$(get var/git_commit)"
[[ "$firefox_revision" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid Firefox revision: $firefox_revision" >&2; exit 1; }
mkdir -p "$RUNNER_TEMP/provenance"
git clone --no-checkout --filter=blob:none "$firefox_repo" "$RUNNER_TEMP/firefox-source"
git -C "$RUNNER_TEMP/firefox-source" fetch --depth=1 origin "$firefox_revision"
git -C "$RUNNER_TEMP/firefox-source" checkout --detach "$firefox_revision"
actual="$(git -C "$RUNNER_TEMP/firefox-source" rev-parse HEAD)"; [[ "$actual" == "$firefox_revision" ]]
profileserver="$RUNNER_TEMP/firefox-source/build/pgo/profileserver.py"
[[ -s "$profileserver" ]] || { echo 'pinned profileserver.py missing' >&2; exit 1; }
python3 - "$root/upstream.lock.json" "$RUNNER_TEMP/provenance/build.json" <<PY
import hashlib,json,subprocess,sys
lock=json.load(open(sys.argv[1]))
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
data={"schema":1,"upstream_lock":lock,"firefox":{"repository":"$firefox_repo","ref":"$firefox_ref","revision":"$firefox_revision"},"pgo_overlay_sha256":sha("$root/patches/firefox-pgo-generate.patch"),"profileserver":{"path":"build/pgo/profileserver.py","revision":"$firefox_revision","sha256":sha("$profileserver")}}
json.dump(data,open(sys.argv[2],'w'),sort_keys=True,indent=2); open(sys.argv[2],'a').write('\\n')
PY
cp "$profileserver" "$RUNNER_TEMP/provenance/profileserver.py"
printf 'FIREFOX_REPOSITORY=%s\nFIREFOX_REVISION=%s\n' "$firefox_repo" "$firefox_revision" >> "$GITHUB_ENV"
