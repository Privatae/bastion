#!/usr/bin/env bash
# Build every release binary into client-go/dist, the same way every time.
#
#   deploy/build.sh <version>
#
# publish.sh calls this to make a release, and verify-release.sh calls it to
# rebuild one and compare. They share this file so the two can never build
# differently.
#
# What makes two builds of the same commit byte-identical:
#   - the toolchain image is pinned by digest, not by tag. A tag moves when a
#     new Go patch release is pushed, and a different compiler writes different
#     bytes.
#   - GOTOOLCHAIN=local, so go.mod cannot make the build fetch another compiler.
#   - -trimpath, so no path from the machine that built it lands in the binary.
#   - -buildvcs=false, so no VCS state is stamped in (only client-go is mounted,
#     but this says so instead of relying on it).
#   - -mod=readonly with go.sum, so every module is the one go.sum names.
#   - CGO_ENABLED=0, so no system C library is linked.
# The version is the only thing passed in, and it is the same for everyone who
# builds that release.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VER="${1:?usage: deploy/build.sh <version>}"

# golang:1.25-alpine as of the digest below (go1.25.14). Move it deliberately,
# in its own commit, and a release built after that commit is rebuilt with the
# new one.
GO_IMAGE="golang@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59"

# The module cache is only a download cache: go.sum checks everything read from
# it. It is kept between runs so a rebuild does not fetch every module again.
MODCACHE="${GOMODCACHE_DIR:-$HOME/go/pkg/mod}"
mkdir -p "$MODCACHE"

# --user: the files in dist/ belong to whoever ran this, not to root, so a
# non-root checkout can clean up after itself.
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache \
  -v "$HERE/client-go":/src -v "$MODCACHE":/go/pkg/mod -w /src \
  -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -trimpath -buildvcs=false" \
  -e VER="$VER" "$GO_IMAGE" sh -c '
  rm -rf /src/dist && mkdir -p /src/dist
  for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
    os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=".exe"
    GOOS=$os GOARCH=$arch go build -ldflags "-X main.clientVersion=$VER" \
      -o /src/dist/privatae-bastion-$os-$arch$ext .
  done'
