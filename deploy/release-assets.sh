#!/usr/bin/env bash
# Rebuild a published release from its tag and collect the files its GitHub
# release carries, refusing unless they are exactly what was signed.
#
#   deploy/release-assets.sh v<version> <out dir>
#
# Needs git, docker, curl and python3, and a clone of this repository that has
# the tag. It needs no key or account of ours. .github/workflows/release.yml
# runs it for every release tag; anyone can run it to check a release.
#
# The tag must be annotated, with the line `built from <commit>` that names
# the commit the release was built from in the development repository. The
# tag's own deploy/build.sh rebuilds the binaries (a pinned toolchain image,
# so the bytes are reproducible), deploy/manifest.py writes the release
# manifest from them, and the signature published beside the manifest, which
# is named by the manifest's digest and never removed, must verify against
# the release keys pinned in this checkout and at the tag. A rebuild that
# differs by one byte gives another digest, no signature by that name, and
# nothing in <out dir>. When the tag is the release the public manifest names
# now, the rebuilt manifest must also equal that one byte for byte.
#
# <out dir> gets the six binaries, version.json (the signed manifest),
# version.json.<first 16 hex of its sha256>.sig (its signature, the file every
# bastion's self-update checks) and SHA256SUMS (the binaries and the manifest,
# in the format `sha256sum -c` reads; it is not signed itself).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:?usage: deploy/release-assets.sh v<version> <out dir>}"
OUT="${2:?usage: deploy/release-assets.sh v<version> <out dir>}"
BASE="${MANIFEST_BASE:-https://privatae.ai/bastion}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release tag: $TAG" >&2; exit 2; }
VER="${TAG#v}"
[ ! -e "$OUT" ] || [ -z "$(ls -A "$OUT")" ] || { echo "$OUT is not empty" >&2; exit 2; }

git -C "$HERE" rev-parse -q --verify "refs/tags/$TAG" >/dev/null || { echo "no tag $TAG in this clone" >&2; exit 1; }
[ "$(git -C "$HERE" cat-file -t "refs/tags/$TAG")" = tag ] || { echo "$TAG is not an annotated tag" >&2; exit 1; }
FROM="$(git -C "$HERE" tag -l --format='%(contents)' "$TAG" | sed -n 's/^built from \([0-9a-f]\{7,40\}\)$/\1/p')"
[ "$(printf '%s\n' "$FROM" | grep -c .)" = 1 ] || { echo "$TAG does not carry exactly one 'built from <commit>' line" >&2; exit 1; }
SRC="$(git -C "$HERE" rev-parse "refs/tags/$TAG^{commit}")"
[ "$(git -C "$HERE" show "$SRC:deploy/VERSION" | tr -d '[:space:]')" = "$VER" ] \
  || { echo "deploy/VERSION at $TAG is not $VER" >&2; exit 1; }
echo "release: $TAG at $SRC, built from $FROM"

WORK="$(mktemp -d)"
trap 'git -C "$HERE" worktree remove --force "$WORK/src" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
git -C "$HERE" worktree add -q --detach "$WORK/src" "$SRC"
"$WORK/src/deploy/build.sh" "$VER"
DIST="$WORK/src/client-go/dist"
python3 "$HERE/deploy/manifest.py" "$VER" "$FROM" "$DIST" > "$WORK/version.json"
H="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$WORK/version.json")"
SIG="version.json.$H.sig"
curl -fsS --max-time 30 "$BASE/$SIG" -o "$WORK/$SIG" \
  || { echo "no signature is published for the rebuilt manifest ($SIG): the rebuild is not the signed release" >&2; exit 1; }
SIGNED_BY="$("$HERE/deploy/release-verify.sh" bastion "$WORK/version.json" "$WORK/$SIG" "$SRC")" \
  || { echo "the signature $SIG does not verify against the rebuilt manifest" >&2; exit 1; }
echo "signature: ok ($SIGNED_BY)"

if curl -fsS --max-time 30 "$BASE/version.json" -o "$WORK/live.json"; then
  LIVE="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$WORK/live.json")"
  if [ "$LIVE" = "$VER" ]; then
    cmp -s "$WORK/live.json" "$WORK/version.json" \
      || { echo "the public manifest names $VER but differs from the rebuilt one" >&2; exit 1; }
    echo "the public manifest names $VER and is byte for byte the rebuilt one"
  else
    echo "the public manifest names $LIVE; $VER is checked by its signature alone"
  fi
fi

mkdir -p "$OUT"
cp "$DIST"/privatae-bastion-* "$WORK/version.json" "$WORK/$SIG" "$OUT/"
(cd "$OUT" && python3 - <<'PY'
import hashlib, os
names = sorted(f for f in os.listdir(".") if f.startswith("privatae-bastion-")) + ["version.json"]
with open("SHA256SUMS", "w") as fh:
    for n in names:
        fh.write("%s  %s\n" % (hashlib.sha256(open(n, "rb").read()).hexdigest(), n))
PY
)
n="$(ls "$OUT" | grep -c '^privatae-bastion-')"
[ "$n" = 6 ] || { echo "expected 6 binaries, built $n" >&2; exit 1; }
echo "assets for $TAG in $OUT:"
ls -l "$OUT"
