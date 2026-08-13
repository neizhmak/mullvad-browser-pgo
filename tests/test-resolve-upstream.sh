#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

setup_case() {
  local case_dir=$1 refs=$2
  mkdir -p "$case_dir/scripts" "$case_dir/bin"
  cp "$ROOT_DIR/scripts/resolve-upstream.sh" "$case_dir/scripts/"
  cp "$ROOT_DIR/upstream.lock.json" "$case_dir/upstream.lock.json"
  cp "$refs" "$case_dir/refs"
  cat >"$case_dir/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1-} == ls-remote ]] || { echo 'unexpected git command' >&2; exit 2; }
cat "$TEST_REFS_FILE"
EOF
  chmod +x "$case_dir/bin/git"
}

run_resolver() {
  local case_dir=$1
  shift
  PATH="$case_dir/bin:$PATH" TEST_REFS_FILE="$case_dir/refs" \
    "$case_dir/scripts/resolve-upstream.sh" "$@"
}

cat >"$work_dir/newer.refs" <<'EOF'
729e1f7ccd88bbc75f33d29cbf39da26ca2e2721	refs/tags/mb-16.0a9-build1
7dd751cf1837d667908b339aebf82567ece55e20	refs/tags/mb-16.0a9-build1^{}
1111111111111111111111111111111111111111	refs/tags/mb-16.0a10-build1
2222222222222222222222222222222222222222	refs/tags/mb-16.0a10-build1^{}
EOF
setup_case "$work_dir/newer" "$work_dir/newer.refs"
run_resolver "$work_dir/newer" | grep -F 'Lock status: stale or mismatched'
if run_resolver "$work_dir/newer" --check; then
  echo 'error: --check accepted a stale lock' >&2
  exit 1
fi
run_resolver "$work_dir/newer" --update-lock
python3 - "$work_dir/newer/upstream.lock.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)
assert lock["tag"] == "mb-16.0a10-build1"
assert lock["tag_object"] == "1111111111111111111111111111111111111111"
assert lock["commit"] == "2222222222222222222222222222222222222222"
PY

for changed_field in tag_object commit; do
  cp "$work_dir/newer.refs" "$work_dir/mutated-$changed_field.refs"
  if [[ $changed_field == tag_object ]]; then
    sed -i '1s/729e1f7ccd88bbc75f33d29cbf39da26ca2e2721/3333333333333333333333333333333333333333/' \
      "$work_dir/mutated-$changed_field.refs"
  else
    sed -i '2s/7dd751cf1837d667908b339aebf82567ece55e20/4444444444444444444444444444444444444444/' \
      "$work_dir/mutated-$changed_field.refs"
  fi
  setup_case "$work_dir/mutated-$changed_field" "$work_dir/mutated-$changed_field.refs"
  before="$(sha256sum "$work_dir/mutated-$changed_field/upstream.lock.json")"
  for mode in report check update; do
    args=()
    [[ $mode == check ]] && args=(--check)
    [[ $mode == update ]] && args=(--update-lock)
    output="$work_dir/$changed_field-$mode.output"
    if run_resolver "$work_dir/mutated-$changed_field" "${args[@]}" >"$output" 2>&1; then
      echo "error: $mode accepted changed $changed_field" >&2
      exit 1
    fi
    grep -F 'integrity anomaly' "$output"
    grep -F "expected" "$output"
    grep -F "observed" "$output"
    [[ "$(sha256sum "$work_dir/mutated-$changed_field/upstream.lock.json")" == "$before" ]] || {
      echo "error: $mode modified lock after integrity anomaly" >&2
      exit 1
    }
  done
done

echo 'resolve-upstream integrity tests passed'
