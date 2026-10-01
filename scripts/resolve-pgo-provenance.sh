#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/scripts/resolve-pgo-provenance.py"
