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
#
# The one failure this script does not stop on is Go's own timer, and only on
# the Go releases that have the race behind it (go_has_fuzztime_race below).
# When -fuzztime runs out there is a moment in which the fuzzer's parent
# context has the deadline error and its child context does not yet. The check
# in Go's fuzz coordinator that drops a cancellation error compares the error
# only with the child's (internal/fuzz/fuzz.go, `err == fuzzCtx.Err()`), so the
# deadline is reported as a failure instead of a clean stop. Go's fix is in
# 1.27 and is due in 1.26.11. The run then ends with exactly
#
#   --- FAIL: <target> (N.NNs)
#       context deadline exceeded
#
# and nothing else, whatever the target does. A run is counted as a pass only
# when ALL of these hold; any other failure is a failure:
#   - the go in PATH is a release with the race. On any other, including one
#     whose version cannot be read, the timer report is a failure like any
#     other, and deploy/test_fuzz.sh fails until this workaround is removed;
#   - the output carries none of the lines Go prints for a failing input
#     ("Failing input written to", "To re-run:", "fuzz: minimizing",
#     "failure while testing seed corpus entry"), wherever they appear;
#   - the output, less the fuzzer's progress lines and go test's closing
#     FAIL lines, is those two lines and no more (a crash, a panic, a t.Fatal
#     message, a seed that fails: each adds a line, so none of them can look
#     like the timer);
#   - no file under any testdata/fuzz directory of the module was added or
#     changed during the run. A crash still being minimized when the race hits
#     is written there by Go with only the deadline error as its message, so
#     the directories are checked, not just the text. Go writes a failing
#     input nowhere else: its build-cache corpus only ever receives inputs
#     that widened coverage, which most passing runs add, so it is not a sign
#     of a failure.
# deploy/test_fuzz.sh checks each of these, with planted failing inputs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SECS="${1:-20}"
cd "$HERE/client-go"

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# go_has_fuzztime_race: the go in PATH is a release that reports its own
# -fuzztime deadline as a failure. The module needs Go 1.26 or later
# (client-go/go.mod), and the fix is due in 1.26.11, so only 1.26.0 to 1.26.10
# qualify. When the image moves past them, remove go_has_fuzztime_race, its
# use below and the stand-in cases in deploy/test_fuzz.sh, which fails on such
# a Go to say so. If a later Go still shows the race, add it here instead.
go_has_fuzztime_race() {
  case "$(go env GOVERSION 2>/dev/null || true)" in
    go1.26.[0-9] | go1.26.10) return 0 ;;
  esac
  return 1
}

# Every file under any testdata/fuzz directory of the module, with its
# checksum, in a fixed order.
corpus_state() {
  find . -path '*/testdata/fuzz/*' -type f -exec cksum {} + | LC_ALL=C sort -k3
}

# crash_reported: $log carries a line Go prints only for a failing input.
crash_reported() {
  grep -q -i -E -e 'failing input written to' -e 'to re-run:' \
    -e 'fuzz: minimizing' -e 'failure while testing seed corpus entry' "$log"
}

# deadline_only <target>: the output in $log is Go's timer report and nothing
# else. The fuzzer's progress lines and go test's closing "FAIL", "exit status"
# and "FAIL <package> <time>" lines are dropped; two lines must remain.
deadline_only() {
  local rest
  rest="$(grep -v -E -e '^fuzz: elapsed: ' -e '^FAIL$' -e '^exit status [0-9]+$' \
    -e '^FAIL[[:space:]]+[^[:space:]]+[[:space:]]+[0-9.]+s$' "$log" || true)"
  [ "$(printf '%s\n' "$rest" | wc -l)" -eq 2 ] || return 1
  printf '%s\n' "$rest" | sed -n 1p | grep -qE "^--- FAIL: $1 \([0-9.]+s\)\$" || return 1
  [ "$(printf '%s\n' "$rest" | sed -n 2p)" = "    context deadline exceeded" ]
}

targets="$(go test -list '^Fuzz' . | grep '^Fuzz' || true)"
[ -n "$targets" ] || { echo "no fuzz targets found" >&2; exit 1; }
for t in $targets; do
  echo "== $t (${SECS}s)"
  before="$(corpus_state)"
  rc=0
  go test -run '^$' -fuzz "^${t}\$" -fuzztime "${SECS}s" . 2>&1 | tee "$log" || rc=$?
  [ "$rc" -ne 0 ] || continue
  if [ "$(corpus_state)" = "$before" ] && ! crash_reported && deadline_only "$t"; then
    if go_has_fuzztime_race; then
      echo "== $t: Go reported its own -fuzztime deadline as a failure (a race in" \
        "Go's fuzzer before 1.26.11); no input was written and nothing else" \
        "failed, so this counts as a pass"
      continue
    fi
    echo "== $t: Go $(go env GOVERSION 2>/dev/null || echo '(unknown)') is not a" \
      "release with the fuzzer's deadline race, so this report is a failure" >&2
  fi
  exit "$rc"
done
echo "every target ran ${SECS}s with no failing input"
