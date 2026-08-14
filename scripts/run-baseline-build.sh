#!/usr/bin/env bash

# Retry the official baseline build once without disturbing RBM's completed outputs.
set -o pipefail

: "${UPSTREAM:?UPSTREAM must name the pinned upstream checkout}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"

readonly max_attempts=2
readonly retry_delay_seconds="${BASELINE_RETRY_DELAY_SECONDS:-15}"
readonly build_log="$RUNNER_TEMP/baseline-build.log"
readonly start_seconds=$SECONDS

cd "$UPSTREAM" || exit 1

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  echo "Baseline build attempt $attempt/$max_attempts starting (elapsed: $((SECONDS - start_seconds))s)" \
    | tee -a "$build_log"

  make mullvadbrowser-alpha-windows-x86_64 2>&1 | tee -a "$build_log"
  status=$?

  echo "Baseline build attempt $attempt/$max_attempts finished with status $status (elapsed: $((SECONDS - start_seconds))s)" \
    | tee -a "$build_log"
  if ((status == 0)); then
    exit 0
  fi
  if ((attempt == max_attempts)); then
    echo "Baseline build failed after $max_attempts attempts; preserving upstream outputs in $UPSTREAM/out." \
      | tee -a "$build_log" >&2
    exit "$status"
  fi

  echo "Baseline build attempt $attempt failed; preserving $UPSTREAM/out and retrying in ${retry_delay_seconds}s." \
    | tee -a "$build_log" >&2
  sleep "$retry_delay_seconds"
done
