#!/usr/bin/env bash
# Checks deploy/fuzz.sh: that it does not fail on Go's own -fuzztime report
# on a Go release with the fuzzer's deadline race, and that it never lets a
# real failure through as that report.
#
#   bash deploy/test_fuzz.sh
#
# Part one runs the script against a stand-in `go` that prints what Go prints,
# so the timer report can be produced on demand and every way a real failure
# could be dressed up as it can be tried. Part two runs it against the real go
# on throwaway modules whose targets fail in the ways a real bug would: a
# planted failing seed, a panic and a test failure that both say "context
# deadline exceeded", found by the fuzzer itself. Part three fails when the go
# this runs with no longer has the race, so the workaround is removed rather
# than kept past its need. Every part runs in a temporary directory; nothing in
# the tree is touched.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bad=0

# expect <name> <want: pass|fail> <must contain> <dir> <env...>: run the copy of
# fuzz.sh in <dir> and compare its exit status and output with what is wanted.
expect() {
  local name="$1" want="$2" must="$3" dir="$4" rc=0 out
  shift 4
  out="$(cd "$dir" && env "$@" bash deploy/fuzz.sh 1 2>&1)" || rc=$?
  if { [ "$want" = pass ] && [ "$rc" -ne 0 ]; } || { [ "$want" = fail ] && [ "$rc" -eq 0 ]; }; then
    echo "NOT OK  $name: wanted $want, exit status was $rc"
    printf '%s\n' "$out" | sed 's/^/        /'
    bad=1
  elif [ -n "$must" ] && ! grep -qF -- "$must" <<<"$out"; then
    echo "NOT OK  $name: the output does not say: $must"
    printf '%s\n' "$out" | sed 's/^/        /'
    bad=1
  else
    echo "ok      $name"
  fi
}

# --- part one: a stand-in go ------------------------------------------------
stub="$tmp/stub"
mkdir -p "$stub/deploy" "$stub/client-go" "$tmp/bin"
cp "$HERE/deploy/fuzz.sh" "$stub/deploy/fuzz.sh"
cat >"$tmp/bin/go" <<'EOF'
#!/usr/bin/env bash
# Prints what `go test` printed in the failing CI run, by FAKE_MODE, or by
# FAKE_MODE_<target> for one target of several (FAKE_TARGETS). `go env
# GOVERSION` prints FAKE_GOVERSION, a release with the race unless set; set to
# "fail", the command fails.
if [ "$1 $2" = "env GOVERSION" ]; then
  [ "${FAKE_GOVERSION-}" != fail ] || exit 1
  printf '%s\n' "${FAKE_GOVERSION-go1.26.10}"; exit 0
fi
if [ "$1 $2" = "test -list" ]; then
  printf '%s\n' ${FAKE_TARGETS:-FuzzOne}; printf 'ok  \texample/pkg\t0.008s\n'; exit 0
fi
t= prev=
for a in "$@"; do
  if [ "$prev" = -fuzz ]; then t="${a#^}"; t="${t%\$}"; fi
  prev="$a"
done
m="FAKE_MODE_$t"
mode="${!m:-$FAKE_MODE}"
[ "$t" = FuzzOne ] && other=FuzzTwo || other=FuzzOne
echo "fuzz: elapsed: 0s, gathering baseline coverage: 11/11 completed, now fuzzing with 6 workers"
echo "fuzz: elapsed: 6s, execs: 4368 (1448/sec), new interesting: 1 (total: 12)"
timer() { printf -- '--- FAIL: %s (6.02s)\n    context deadline exceeded\nFAIL\nexit status 1\nFAIL\texample/pkg\t6.025s\n' "$1"; }
crasher() { mkdir -p "${2:-testdata/fuzz}/$t"; printf 'go test fuzz v1\n[]byte("x")\n' >"${2:-testdata/fuzz}/$t/$1"; }
case "$mode" in
  pass)            printf 'PASS\nok  \texample/pkg\t6.019s\n' ;;
  timer)           timer $t; exit 1 ;;
  timer-new-file)  crasher 1a2b3c4d; timer $t; exit 1 ;;
  timer-sub-file)  crasher 1a2b3c4d sub/testdata/fuzz; timer $t; exit 1 ;;
  timer-changed)   printf 'changed\n' >testdata/fuzz/$t/seed; timer $t; exit 1 ;;
  timer-other)     timer $other; exit 1 ;;
  timer-message)   crasher 1a2b3c4d
                   printf -- '--- FAIL: %s (6.02s)\n    context deadline exceeded\n    Failing input written to testdata/fuzz/%s/1a2b3c4d\nFAIL\nexit status 1\n' $t $t; exit 1 ;;
  timer-minimize)  echo "fuzz: minimizing 12-byte failing input file"; timer $t; exit 1 ;;
  timer-glued)     printf 'fuzz: elapsed: 6s, execs: 4370 (1448/sec)%s\n' "$FAKE_GLUE"; timer $t; exit 1 ;;
  timer-own-line)  printf -- '--- FAIL: %s (0.01s)\n    fuzz_test.go:9: context deadline exceeded\nFAIL\nexit status 1\n' $t; exit 1 ;;
  timer-panic-line) printf -- '--- FAIL: %s (6.02s)\n    panic: context deadline exceeded\nFAIL\nexit status 1\n' $t; exit 1 ;;
  fatal-then-timer) printf -- '--- FAIL: %s (6.02s)\n    the verifier accepted bytes that were not signed\n    context deadline exceeded\nFAIL\n' $t; exit 1 ;;
  panic)           crasher 1a2b3c4d
                   printf -- '--- FAIL: %s (0.40s)\n    panic: planted [recovered]\n    Failing input written to testdata/fuzz/%s/1a2b3c4d\nFAIL\nexit status 1\n' $t $t; exit 1 ;;
  other)           printf -- '--- FAIL: %s (0.40s)\n    fuzzing process hung or terminated unexpectedly: exit status 2\nFAIL\n' $t; exit 1 ;;
esac
EOF
chmod +x "$tmp/bin/go"
stubrun() { # <name> <want> <must contain> <FAKE_MODE> [VAR=value ...]
  rm -rf "$stub/client-go" && mkdir -p "$stub/client-go/testdata/fuzz/FuzzOne"
  printf 'go test fuzz v1\n[]byte("seed")\n' >"$stub/client-go/testdata/fuzz/FuzzOne/seed"
  expect "$1" "$2" "$3" "$stub" PATH="$tmp/bin:$PATH" FAKE_MODE="$4" "${@:5}"
}
stubrun "a run that passes" pass "every target ran" pass
stubrun "the timer report alone is a pass (the failing CI run's output)" pass "counts as a pass" timer
stubrun "the timer report on go1.26.0 is a pass" pass "counts as a pass" timer FAKE_GOVERSION=go1.26.0
stubrun "the timer report with a crasher file written is a failure" fail "" timer-new-file
stubrun "the timer report with a crasher in another package's corpus is a failure" fail "" timer-sub-file
stubrun "the timer report with a corpus file changed is a failure" fail "" timer-changed
stubrun "the timer report for another target is a failure" fail "" timer-other
stubrun "the timer report with Go's 'Failing input written' line is a failure" fail "" timer-message
stubrun "the timer report after 'minimizing' is a failure" fail "" timer-minimize
for glue in "Failing input written to| testdata/fuzz/FuzzOne/1a2b3c4d" "To re-run:|" \
  "fuzz: minimizing| 12-byte failing input file" "failure while testing seed corpus entry|: FuzzOne/seed"; do
  stubrun "the timer report with '${glue%%|*}' glued to a progress line is a failure" fail "" \
    timer-glued FAKE_GLUE="${glue%%|*}${glue#*|}"
done
stubrun "a test's own 'file:line: context deadline exceeded' is a failure" fail "" timer-own-line
stubrun "a panic saying 'context deadline exceeded' is a failure" fail "" timer-panic-line
stubrun "a test's own message before the timer line is a failure" fail "" fatal-then-timer
stubrun "a panic with a crasher written is a failure" fail "" panic
stubrun "a worker that died is a failure" fail "" other
for v in go1.26.11 go1.27.0 "devel go1.28-0123abcd" "" fail; do
  stubrun "the timer report on a Go without the race (${v:-empty version}) is a failure" fail "is not a release" timer FAKE_GOVERSION="$v"
done
stubrun "two targets, both with the timer report alone, pass" pass "every target ran" timer FAKE_TARGETS="FuzzOne FuzzTwo"
stubrun "two targets, the second with a real crash, is a failure" fail "panic: planted" timer \
  FAKE_TARGETS="FuzzOne FuzzTwo" FAKE_MODE_FuzzTwo=panic
stubrun "two targets, the second printing the first's timer report, is a failure" fail "" pass \
  FAKE_TARGETS="FuzzOne FuzzTwo" FAKE_MODE_FuzzTwo=timer-other

# --- part two: the real go, planted failing inputs ----------------------------
mkreal() { # <dir> <test file after its package clause>: a throwaway module
  mkdir -p "$1/deploy" "$1/client-go"
  cp "$HERE/deploy/fuzz.sh" "$1/deploy/fuzz.sh"
  (cd "$1/client-go" && go mod init plantedfuzz >/dev/null 2>&1 &&
    printf 'package plantedfuzz\n\n%s\n' "$2" >fuzz_test.go)
}
mkreal "$tmp/clean" 'import "testing"

func FuzzClean(f *testing.F) {
	f.Add([]byte("ok"))
	f.Fuzz(func(t *testing.T, b []byte) {})
}'
expect "the real go on a target that cannot fail passes" pass "every target ran" "$tmp/clean"

mkreal "$tmp/planted" 'import "testing"

func FuzzPlanted(f *testing.F) {
	f.Add([]byte("ok"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if string(b) == "BOOM" {
			t.Fatalf("planted failure")
		}
	})
}'
mkdir -p "$tmp/planted/client-go/testdata/fuzz/FuzzPlanted"
printf 'go test fuzz v1\n[]byte("BOOM")\n' >"$tmp/planted/client-go/testdata/fuzz/FuzzPlanted/planted"
expect "the real go on a planted failing input fails" fail "planted failure" "$tmp/planted"

# Inputs the fuzzer finds itself: any input but the seed fails, so the first
# mutation is a crash, and its message is the deadline error's own text.
mkreal "$tmp/panics" 'import (
	"context"
	"testing"
)

func FuzzPanicsWithDeadline(f *testing.F) {
	f.Add([]byte("ok"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if string(b) != "ok" {
			panic(context.DeadlineExceeded)
		}
	})
}'
expect "the real go on a panic saying 'context deadline exceeded' fails" fail \
  "--- FAIL: FuzzPanicsWithDeadline" "$tmp/panics"

mkreal "$tmp/deadlinebug" 'import (
	"context"
	"testing"
)

func FuzzReturnsADeadlineError(f *testing.F) {
	f.Add([]byte("ok"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if string(b) != "ok" {
			ctx, cancel := context.WithTimeout(context.Background(), 0)
			defer cancel()
			<-ctx.Done()
			t.Fatal(ctx.Err())
		}
	})
}'
expect "the real go on a target failing with its own deadline error fails" fail \
  "--- FAIL: FuzzReturnsADeadlineError" "$tmp/deadlinebug"

# The closest a target's own failure comes to the timer report: two lines,
# the second the deadline error, told apart only by its file:line prefix.
mkreal "$tmp/setup" 'import (
	"context"
	"testing"
)

func FuzzSetupTimesOut(f *testing.F) {
	f.Fatal(context.DeadlineExceeded)
	f.Fuzz(func(t *testing.T, b []byte) {})
}'
expect "the real go on a target whose setup fails with the deadline error fails" fail \
  "fuzz_test.go:" "$tmp/setup"

# --- part three: the go this runs with still needs the workaround -------------
# fuzz.sh's own version check, given this go's version: when it no longer
# grants the timer report a pass, the race is fixed here and the workaround is
# due to be removed.
v="$(go env GOVERSION 2>/dev/null || echo fail)"
was="$bad"
bad=0
stubrun "this go ($v) is a release with the race fuzz.sh works around" pass "counts as a pass" \
  timer FAKE_GOVERSION="$v"
if [ "$bad" -ne 0 ]; then
  echo "        $v does not have the fuzzer's deadline race: remove go_has_fuzztime_race and"
  echo "        its use from deploy/fuzz.sh and the timer cases from this file."
fi
bad=$((was | bad))

[ "$bad" -eq 0 ] || { echo "deploy/fuzz.sh: a check failed" >&2; exit 1; }
echo "deploy/fuzz.sh: every check passed"
