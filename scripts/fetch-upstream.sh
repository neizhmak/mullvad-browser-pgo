#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LOCK_FILE="$ROOT_DIR/upstream.lock.json"

usage() {
  cat <<'EOF'
Usage: fetch-upstream.sh [--destination DIRECTORY]

Fetch and check out the exact tree identified by upstream.lock.json. An existing
destination must be a Git worktree and will be reset and cleaned.
EOF
}

destination=
case "${1-}" in
  '') ;;
  --destination)
    [[ $# -eq 2 && -n "${2-}" ]] || { usage >&2; exit 2; }
    destination=$2
    ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

command -v git >/dev/null || { echo 'error: git is required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'error: python3 is required' >&2; exit 1; }

mapfile -t lock < <(python3 - "$LOCK_FILE" <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        lock = json.load(stream)
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"error: cannot read lock: {exc}")
required = {"repository", "tag", "tag_object", "commit"}
if set(lock) != required or any(not isinstance(lock[k], str) for k in required):
    raise SystemExit("error: invalid lock schema")
if lock["repository"] != "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git":
    raise SystemExit("error: lock does not name the canonical repository")
if not re.fullmatch(r"mb-\d+\.\d+a\d+-build\d+", lock["tag"]):
    raise SystemExit("error: invalid locked Alpha tag")
if any(not re.fullmatch(r"[0-9a-f]{40}", lock[k]) for k in ("tag_object", "commit")):
    raise SystemExit("error: invalid locked object ID")
print(lock["repository"]); print(lock["tag"]); print(lock["tag_object"]); print(lock["commit"])
PY
)
[[ ${#lock[@]} -eq 4 ]] || { echo 'error: failed to parse lock' >&2; exit 1; }
repository=${lock[0]}; tag=${lock[1]}; tag_object=${lock[2]}; commit=${lock[3]}

if [[ -z "$destination" ]]; then
  destination="$(mktemp -d "${TMPDIR:-/tmp}/tor-browser-build.XXXXXXXX")"
  echo "Created disposable destination: $destination"
elif [[ -e "$destination" && ! -d "$destination/.git" ]]; then
  echo "error: existing destination is not a Git worktree: $destination" >&2
  exit 1
else
  mkdir -p "$destination"
fi

if [[ ! -d "$destination/.git" ]]; then
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "$repository"
else
  git -C "$destination" remote set-url origin "$repository"
fi

# Force the locked tag ref so a reusable checkout cannot retain a different object.
git -C "$destination" fetch --depth=1 --force --no-tags origin \
  "+refs/tags/$tag:refs/tags/$tag"

actual_tag_object="$(git -C "$destination" rev-parse "refs/tags/$tag")"
actual_commit="$(git -C "$destination" rev-parse "refs/tags/$tag^{}")"
[[ "$(git -C "$destination" cat-file -t "$actual_tag_object")" == tag ]] || {
  echo "error: locked ref is not an annotated tag object" >&2; exit 1;
}
[[ "$actual_tag_object" == "$tag_object" ]] || {
  echo "error: tag object mismatch: expected $tag_object, got $actual_tag_object" >&2; exit 1;
}
[[ "$actual_commit" == "$commit" ]] || {
  echo "error: peeled commit mismatch: expected $commit, got $actual_commit" >&2; exit 1;
}

git -C "$destination" checkout --quiet --detach "$commit"
git -C "$destination" reset --quiet --hard "$commit"
git -C "$destination" clean -q -dffx
head_commit="$(git -C "$destination" rev-parse HEAD)"
[[ "$head_commit" == "$commit" ]] || {
  echo "error: HEAD mismatch: expected $commit, got $head_commit" >&2; exit 1;
}

echo "Checked out $tag"
echo "Tag object: $actual_tag_object"
echo "HEAD: $head_commit"
echo "Destination: $destination"
