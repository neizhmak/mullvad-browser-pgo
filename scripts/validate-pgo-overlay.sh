#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?UPSTREAM must name the patched pinned checkout}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
baseline="$RUNNER_TEMP/firefox-build-baseline.rendered"
pgo="$RUNNER_TEMP/firefox-build-pgo.rendered"
common=(--target alpha --target mullvadbrowser-windows-x86_64)
(cd "$UPSTREAM" && python3 "$root/scripts/rbm_network.py" --upstream "$PWD" --project firefox --key build "${common[@]}") > "$baseline"
(cd "$UPSTREAM" && python3 "$root/scripts/rbm_network.py" --upstream "$PWD" --project firefox --key build "${common[@]}" --target pgo-generate) > "$pgo"
python3 "$root/scripts/validate-pgo-rendering.py" --baseline "$baseline" --pgo "$pgo"
