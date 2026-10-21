#!/usr/bin/env bash
# Rebuild the published bastion from source and check it is what was published.
#
#   deploy/verify-release.sh
#
# Needs git, docker, curl and python3. Run it from a clone of this
# repository. It does not need any key or account of ours.
#
# It fetches the public manifest, checks its signature against the release keys
# pinned in client-go/release_sign.go, checks out the release's source in a
# separate worktree, rebuilds with deploy/build.sh exactly as publish.sh does,
# and compares every binary's sha256 with the manifest. If they all match, the
# binaries we serve are the ones this source produces, and the signature says
# we are the ones who published them.
#
# Which source: the manifest's built_from names the commit in the repository
# the release was built in. The public repository carries each release as a
# single commit of the same tree, tagged v<version>, so built_from is not a
# commit there. The script uses built_from when this checkout has it, and
# otherwise the tag v<version>, which must be an annotated tag whose message
# has the line "built from <built_from>" exactly as the manifest writes it.
# Either way, the digests show this source builds the published binaries.
# Files the build does not read could differ without changing the bytes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${MANIFEST_BASE:-https://privatae.ai/bastion}"
WORK="$(mktemp -d)"
trap 'git -C "$HERE" worktree remove --force "$WORK/src" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

curl -fsS --max-time 30 "$BASE/version.json" -o "$WORK/version.json"
H="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$WORK/version.json")"
curl -fsS --max-time 30 "$BASE/version.json.$H.sig" -o "$WORK/version.json.sig"
read -r VER FROM < <(python3 -c 'import json,sys;m=json.load(open(sys.argv[1]));print(m["version"],m["built_from"])' "$WORK/version.json")
echo "published: v$VER built from $FROM"

# The signature, against the keys YOUR checkout pins (the starting point you
# chose to trust) and against the keys the published commit pins.
FETCH_FAILED=0
git -C "$HERE" fetch -q --tags origin 2>"$WORK/fetch.err" || FETCH_FAILED=1
if [ "$FETCH_FAILED" -eq 1 ]; then
  echo "fetch: could not fetch tags from origin (git exited non-zero)" >&2
  sed 's/^/  /' "$WORK/fetch.err" >&2
fi
TAG="v$VER"
if git -C "$HERE" cat-file -e "$FROM^{commit}" 2>/dev/null; then
  SRC="$(git -C "$HERE" rev-parse "$FROM^{commit}")"
  echo "source: commit $FROM (built_from, present in this checkout)"
elif git -C "$HERE" rev-parse -q --verify "refs/tags/$TAG^{commit}" >/dev/null; then
  # A release tag is annotated and records the built_from it was published
  # from, in the same form the manifest uses. Without that record there is
  # nothing tying the tag to this release.
  if [ "$(git -C "$HERE" cat-file -t "refs/tags/$TAG")" != tag ] \
     || ! git -C "$HERE" tag -l --format='%(contents)' "$TAG" | grep -qxF "built from $FROM"; then
    echo "source: tag $TAG does not carry the release record (an annotated tag with the line 'built from $FROM'); nothing was built" >&2
    exit 1
  fi
  SRC="$(git -C "$HERE" rev-parse "refs/tags/$TAG^{commit}")"
  echo "source: tag $TAG at commit $SRC (built_from $FROM is not in this checkout)"
elif [ "$FETCH_FAILED" -eq 1 ]; then
  echo "source: neither built_from $FROM nor tag $TAG is in this checkout, and tags could not be fetched; nothing was built" >&2
  exit 1
else
  echo "source: neither built_from $FROM nor tag $TAG is in this checkout or on origin" >&2
  echo "  the release may not be tagged yet; nothing was built" >&2
  exit 1
fi
git -C "$HERE" worktree add -q --detach "$WORK/src" "$SRC"
SIGNED_BY="$("$HERE/deploy/release-verify.sh" bastion "$WORK/version.json" "$WORK/version.json.sig" "$SRC")" \
  || { echo "signature: FAILED against the keys pinned in this checkout or at $SRC" >&2; exit 1; }
echo "signature: ok ($SIGNED_BY)"

# The rebuild, with the build script from that commit.
"$WORK/src/deploy/build.sh" "$VER"
python3 - "$WORK/version.json" "$WORK/src/client-go/dist" <<'PY'
import hashlib, json, os, sys
m = json.load(open(sys.argv[1]))
dist = sys.argv[2]
bad = 0
for k, v in sorted(m["binaries"].items()):
    p = os.path.join(dist, "privatae-bastion-" + k)
    got = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else "missing"
    same = got == v["sha256"]
    bad += not same
    print("  %-20s %s" % (k, "ok" if same else "DIFFERS (rebuilt %s, published %s)" % (got[:16], v["sha256"][:16])))
print("rebuild: every binary matches the published digest" if not bad else "rebuild: %d binaries differ" % bad)
sys.exit(1 if bad else 0)
PY
