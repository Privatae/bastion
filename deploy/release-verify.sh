#!/usr/bin/env bash
# Check a release manifest's signature the way a bastion does.
#
#   deploy/release-verify.sh <bastion|bastion-agent> <manifest> <sig-file> [<rev>...]
#
# The signature must verify against the keys this tree pins
# (productionReleaseKeys in client-go/release_sign.go), and this tree must pin
# at least two (the primary and the offline spare). Each <rev> names another
# commit of this repository whose pinned keys it must ALSO verify against:
# publish.sh passes the commit the fleet runs today, because those are the
# bastions that will read this manifest, and they check it with their own
# keys, not with the ones this release introduces.
#
# The keys are read by parsing the Go source (release-sign pinned), so the
# script sees what the compiler sees. The check runs in the same pinned Go
# image deploy/build.sh uses. Prints the key that verified against this tree.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
KIND="${1:?kind}"; MAN="${2:?manifest}"; SIG="${3:?signature file}"; shift 3
GO_IMAGE="$(sed -n 's/^GO_IMAGE="\(.*\)"$/\1/p' "$HERE/deploy/build.sh")"
MODCACHE="${GOMODCACHE_DIR:-$HOME/go/pkg/mod}"
mkdir -p "$MODCACHE"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp "$MAN" "$WORK/manifest"; cp "$SIG" "$WORK/sig"
cp "$HERE/client-go/release_sign.go" "$WORK/keys-0.go"
n=0
for rev in "$@"; do
  n=$((n + 1))
  # A commit from before signing pins nothing and its bastions check nothing,
  # so there is no key set to hold this signature to.
  git -C "$HERE" show "$rev:client-go/release_sign.go" > "$WORK/keys-$n.go" 2>/dev/null \
    || rm -f "$WORK/keys-$n.go"
done

docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache \
  -v "$HERE/deploy/release-sign":/src:ro -v "$WORK":/in:ro -v "$MODCACHE":/go/pkg/mod \
  -w /src -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -buildvcs=false" -e CGO_ENABLED=0 \
  -e KIND="$KIND" "$GO_IMAGE" sh -ec '
  go build -o /tmp/release-sign .
  set -- $(/tmp/release-sign pinned /in/keys-0.go)
  [ "$#" -ge 2 ] || { echo "this tree pins $# release key(s); a release needs the primary and the spare" >&2; exit 1; }
  signed_by=$(/tmp/release-sign verify "$KIND" /in/manifest /in/sig "$@")
  for f in /in/keys-*.go; do
    [ "$f" = /in/keys-0.go ] && continue
    set -- $(/tmp/release-sign pinned "$f")
    [ "$#" -gt 0 ] || continue
    /tmp/release-sign verify "$KIND" /in/manifest /in/sig "$@" >/dev/null \
      || { echo "the signature does not verify against the keys pinned by the release the fleet runs today" >&2; exit 1; }
  done
  echo "$signed_by"'
