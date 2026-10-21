#!/usr/bin/env bash
# Run every fuzz target in client-go for a bounded time each.
#
#   deploy/fuzz.sh [seconds per target]     (default 20)
#
# `go test` already runs each target's seed inputs as ordinary tests. This goes
# further: it lets the fuzzer generate new inputs against each target in turn.
# Go fuzzes one target per run, so the targets are run one after another. The
# list comes from `go test -list`, so a target added later is picked up without
# editing this file, and a platform's own targets are the ones it builds.
#
# An input that breaks a target is written under client-go/testdata/fuzz/<target>/
# and the run stops there. Commit that file with the fix: from then on it is one
# of the seeds every `go test` runs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SECS="${1:-20}"
cd "$HERE/client-go"
targets="$(go test -list '^Fuzz' . | grep '^Fuzz' || true)"
[ -n "$targets" ] || { echo "no fuzz targets found" >&2; exit 1; }
for t in $targets; do
  echo "== $t (${SECS}s)"
  go test -run '^$' -fuzz "^${t}\$" -fuzztime "${SECS}s" .
done
echo "every target ran ${SECS}s with no failing input"
