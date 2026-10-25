#!/bin/sh
# staticcheck on both Go modules, for every OS the release is built for.
#
#   deploy/staticcheck.sh
#
# Each module is checked once per GOOS and the runs are merged, which is how
# staticcheck reports code unused on every OS rather than unused on one: a
# function only the Windows build calls is used. Any finding fails. The
# checker is the pinned release below, built with this toolchain; set
# STATICCHECK to use one already installed.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=v0.8.2 # staticcheck 2026.2.2
SC="${STATICCHECK:-}"
if [ -z "$SC" ]; then
  BIN="$(mktemp -d)"
  GOBIN="$BIN" GOFLAGS= go install "honnef.co/go/tools/cmd/staticcheck@$VERSION"
  SC="$BIN/staticcheck"
fi
OUT="$(mktemp -d)"
bad=0
for mod in client-go deploy/release-sign; do
  for os in linux darwin windows; do
    (cd "$HERE/$mod" && GOOS=$os "$SC" -f binary ./... > "$OUT/$os.bin")
  done
  found="$(cd "$HERE/$mod" && "$SC" -merge "$OUT/linux.bin" "$OUT/darwin.bin" "$OUT/windows.bin" || true)"
  if [ -n "$found" ]; then
    printf '%s\n' "$found" | sed "s#^#$mod/#"
    bad=1
  else
    echo "ok      $mod: no findings on linux, darwin and windows"
  fi
done
rm -rf "$OUT"
exit "$bad"
