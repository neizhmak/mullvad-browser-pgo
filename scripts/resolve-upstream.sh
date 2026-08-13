#!/usr/bin/env bash
set -euo pipefail

readonly REPOSITORY='https://gitlab.torproject.org/tpo/applications/tor-browser-build.git'
readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LOCK_FILE="$ROOT_DIR/upstream.lock.json"

usage() {
  cat <<'EOF'
Usage: resolve-upstream.sh [--check | --update-lock]

Without an option, reports whether upstream.lock.json pins the newest Alpha.
--check exits nonzero when the lock is stale; --update-lock explicitly updates it.
EOF
}

mode=report
case "${1-}" in
  '') ;;
  --check) mode=check ;;
  --update-lock) mode=update ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
(( $# <= 1 )) || { usage >&2; exit 2; }

command -v git >/dev/null || { echo 'error: git is required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'error: python3 is required' >&2; exit 1; }

refs_file="$(mktemp)"
trap 'rm -f "$refs_file"' EXIT
git ls-remote --tags "$REPOSITORY" 'refs/tags/mb-*' >"$refs_file"
[[ -s "$refs_file" ]] || { echo 'error: upstream returned no mb-* tags' >&2; exit 1; }

python3 - "$mode" "$LOCK_FILE" "$refs_file" "$REPOSITORY" <<'PY'
import json
import os
import re
import sys
import tempfile

mode, lock_path, refs_path, repository = sys.argv[1:]
pattern = re.compile(r"mb-(\d+)\.(\d+)a(\d+)-build(\d+)")
oid_pattern = re.compile(r"[0-9a-f]{40}")
refs = {}

with open(refs_path, encoding="utf-8") as stream:
    for raw in stream:
        try:
            oid, ref = raw.rstrip("\n").split("\t")
        except ValueError:
            raise SystemExit(f"error: malformed ls-remote output: {raw.rstrip()!r}")
        if not oid_pattern.fullmatch(oid):
            raise SystemExit(f"error: malformed object ID for {ref}: {oid!r}")
        peeled = ref.endswith("^{}")
        tag = ref.removeprefix("refs/tags/").removesuffix("^{}")
        # Reject names which look intended as Alpha build tags but are malformed.
        if tag.startswith("mb-") and "a" in tag and "build" in tag and not pattern.fullmatch(tag):
            raise SystemExit(f"error: malformed Alpha-like upstream tag: {tag}")
        match = pattern.fullmatch(tag)
        if not match:
            continue
        kind = "commit" if peeled else "tag_object"
        entry = refs.setdefault(tag, {"version": tuple(map(int, match.groups()))})
        if kind in entry and entry[kind] != oid:
            raise SystemExit(f"error: ambiguous duplicate {kind} ref for {tag}")
        entry[kind] = oid

if not refs:
    raise SystemExit("error: upstream returned no valid Mullvad Browser Alpha build tags")
for tag, entry in refs.items():
    if "tag_object" not in entry or "commit" not in entry:
        raise SystemExit(f"error: {tag} is not an unambiguous annotated tag with a peeled commit")

tag, selected = max(refs.items(), key=lambda item: item[1]["version"])
new_lock = {
    "repository": repository,
    "tag": tag,
    "tag_object": selected["tag_object"],
    "commit": selected["commit"],
}

try:
    with open(lock_path, encoding="utf-8") as stream:
        current = json.load(stream)
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"error: cannot read valid lock file {lock_path}: {exc}")

required = set(new_lock)
if set(current) != required or any(not isinstance(current.get(k), str) for k in required):
    raise SystemExit(f"error: lock must contain exactly these string fields: {', '.join(new_lock)}")
if current["repository"] != repository:
    raise SystemExit(f"error: lock repository is not canonical: {current['repository']!r}")
if not pattern.fullmatch(current["tag"]):
    raise SystemExit(f"error: malformed locked Alpha tag: {current['tag']!r}")
for key in ("tag_object", "commit"):
    if not oid_pattern.fullmatch(current[key]):
        raise SystemExit(f"error: malformed locked {key}: {current[key]!r}")

locked_upstream = refs.get(current["tag"])
if locked_upstream is not None:
    identity_changes = []
    for key in ("tag_object", "commit"):
        if current[key] != locked_upstream[key]:
            identity_changes.append(
                f"  {key}: expected {current[key]}, observed {locked_upstream[key]}"
            )
    if identity_changes:
        raise SystemExit(
            f"error: integrity anomaly: locked tag {current['tag']} changed identity\n"
            + "\n".join(identity_changes)
        )

print(f"Locked Alpha tag: {current['tag']}")
print(f"Newest Alpha tag: {tag}")
same = current == new_lock
print("Lock status: current" if same else "Lock status: stale or mismatched")

if mode == "update" and not same:
    locked_match = pattern.fullmatch(current["tag"])
    locked_version = tuple(map(int, locked_match.groups()))
    if selected["version"] <= locked_version:
        raise SystemExit(
            "error: refusing to update: selected Alpha tag is not newer than the lock"
        )
    directory = os.path.dirname(lock_path)
    fd, temporary = tempfile.mkstemp(prefix=".upstream.lock.", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(new_lock, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, lock_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Updated {lock_path}")
elif mode == "check" and not same:
    raise SystemExit("error: upstream.lock.json does not match the newest Alpha tag")
PY
