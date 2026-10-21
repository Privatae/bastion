#!/usr/bin/env bash
# Cross-build the bastion for all platforms (VERSION-stamped) + publish to the edge
#
# RENAMED: the published artifact is privatae-bastion-<os>-<arch>. The files
# under the previous binary name are deliberately NOT pruned from the webroot's dl/
# — an installer or a doc still pointing at the old filename keeps resolving, and
# self-update swaps a bastion's own executable in place (update.go) so a field
# machine on the old name upgrades onto the new binary without renaming itself.
# (privatae.ai/bastion/) with a version manifest. Run after committing client-go changes.
# Bump deploy/VERSION first. Replaces the old hand-copy.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# WHERE THIS PUBLISHES IS NOT BAKED IN. Everyone who runs a bastion can read
# this repository, so it names none of our hosts and no key path of ours: EDGES
# and KEY are required, and an unset one stops the script with a message instead
# of publishing somewhere wrong. Whoever cuts a release supplies them.
#
# EDGES: publish to EVERY front door. Each edge serves /bastion from its OWN
# local disk -- that locality is the whole point, it is what keeps the installer
# serving during a platform outage -- so a one-edge publish leaves the fleet
# serving two different binaries behind a single manifest. The installer
# verifies the digest, so that fails CLOSED (the stale edge refuses to
# install rather than installing the wrong bytes), but it is still an outage for
# whoever DNS happens to point at. Publish to all, verify each. Override with
# EDGE=<one-target> for a deliberate single-box publish.
# EDGE (one box) satisfies the requirement on its own — it is the documented
# single-box override above, and requiring EDGES first would have killed it with
# an error naming a variable the operator was never told to set.
if [ -n "${EDGE:-}" ]; then EDGES="$EDGE"; fi
: "${EDGES:?set EDGES to the space-separated edge hosts to publish to (or EDGE=<one> for a single box)}"
: "${KEY:?set KEY to the ssh key that reaches the edges}"
# The webroot and the backup directory are supplied for the same reason EDGES and
# KEY are: everyone who runs a bastion reads this file, so it names no path of
# ours.
: "${WEBROOT:?set WEBROOT to the directory on each edge that serves /bastion}"
: "${BACKUP_DIR:?set BACKUP_DIR to a directory OUTSIDE the webroot for rotated installers}"
# OUTSIDE is load-bearing, not advice. Backups used to land beside the live files
# and every superseded installer was served at a stable public URL -- the earlier
# install.sh, the one with no checksum verification, at HTTP 200 (measured).
# While the backup directory was hardcoded outside the webroot that could not
# recur by construction; as an operator-supplied value it can, so the guarantee
# is re-asserted here.
case "$BACKUP_DIR" in
  "$WEBROOT"|"$WEBROOT"/*)
    echo "BACKUP_DIR ($BACKUP_DIR) is inside WEBROOT ($WEBROOT) -- rotated installers would be served publicly" >&2
    exit 1;;
esac
# A release is published in two runs, because the release key never comes to
# this machine: it stays on the key holder's own computer.
#
#   1. deploy/publish.sh                   builds, writes the manifest, and prints
#                                          the one release-sign command to run
#   2. SIGNATURE=<line> deploy/publish.sh  builds again, checks SIGNATURE against
#                                          the keys this tree pins, and publishes
#
# The build is reproducible, so the second run's manifest is byte-for-byte the
# one that was signed; if it is not (a commit landed in between), the signature
# does not verify and nothing is published.
VER="$(tr -d '[:space:]' < "$HERE/deploy/VERSION")"
GITSHA="$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
# The license we are about to publish, digested HERE from the repo, so both
# verifications below compare the edges and the public URL against this tree
# rather than against each other. Digested with python3 for the same reason the
# manifest is built with it: python3 is already required by this script, while
# sha256sum/shasum differ across the machines a release might be cut from.
LIC_SHA="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$HERE/LICENSE")"
echo "building bastion v$VER ($GITSHA)"

# RATCHET: refuse to publish a build that is not a descendant of the
# currently-published built_from. A rebuild from a DIVERGENT branch was once
# republished with a HIGHER version but a SMALLER feature set (lost the worker lanes),
# regressing every field bastion. A proper forward move (including a merge) passes;
# a divergent tip fails. Override an intentional non-linear publish with ALLOW_NONLINEAR=1.
CUR_FROM="$(curl -fsS --max-time 15 https://privatae.ai/bastion/version.json | python3 -c 'import sys,json;print(json.load(sys.stdin).get("built_from",""))' 2>/dev/null || true)"
if [ -n "$CUR_FROM" ]; then
  if git -C "$HERE" merge-base --is-ancestor "$CUR_FROM" HEAD 2>/dev/null; then
    echo "ratchet ok: published $CUR_FROM is an ancestor of $GITSHA (forward move)"
  else
    echo "RATCHET REFUSED: $GITSHA is not a descendant of published built_from $CUR_FROM (would regress the field). Merge/rebase forward, or ALLOW_NONLINEAR=1 to override." >&2
    [ "${ALLOW_NONLINEAR:-}" = "1" ] || exit 1
  fi
fi

# Reproducible: deploy/verify-release.sh rebuilds a published release with the
# same script and compares every digest.
"$HERE/deploy/build.sh" "$VER"

# version manifest: {version, built_from, binaries:{os-arch:{url,sha256}}} — built with python
# (clean JSON; the host + the bastion self-update read this to decide "out of date").
python3 - "$VER" "$GITSHA" "$HERE/client-go/dist" > "$HERE/client-go/dist/version.json" <<'PY'
import sys, os, hashlib, json
ver, sha, dist = sys.argv[1], sys.argv[2], sys.argv[3]
binaries = {}
for f in sorted(os.listdir(dist)):
    if not f.startswith("privatae-bastion-"):
        continue
    h = hashlib.sha256(open(os.path.join(dist, f), "rb").read()).hexdigest()
    # ?v=<version> IS LOAD-BEARING, not decoration. dl.privatae.ai sits behind
    # Cloudflare, which caches these objects and keys on the full URL including
    # the query string. Without it a publish replaces the bytes on both edges,
    # both edges verify, the manifest is fresh — and Cloudflare keeps serving the
    # PREVIOUS binary to anyone whose request lands on a warm edge. The client
    # downloads the old bytes, compares them against the new digest, and aborts
    # with "sha256 mismatch" — which reads like a corrupt build and is actually a
    # stale cache. Measured publishing 0.23.0: windows-amd64.exe came
    # back cf-cache-status HIT, age 3917, carrying 0.22.0's bytes. It was the
    # ONLY stale one, because it was the only object anything had requested since
    # the previous publish — so this breaks one platform at a time, at random,
    # for whoever happens to have downloaded last. The worst possible shape.
    #
    # A new version string is a new cache key is a guaranteed miss. Needs no
    # Cloudflare credential and cannot be forgotten at publish time. update.go
    # downloads binaries[key].url verbatim, so bastions already in the field pick
    # this up from the manifest with no client change.
    binaries[f[len("privatae-bastion-"):]] = {
        "url": f"https://dl.privatae.ai/dl/{f}?v={ver}", "sha256": h}
json.dump({"version": ver, "built_from": sha, "binaries": binaries}, sys.stdout, indent=2)
PY

MAN="$HERE/client-go/dist/version.json"
MAN_SHA="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$MAN")"
if [ -z "${SIGNATURE:-}" ]; then
  cat <<ASK

Built bastion v$VER. Nothing has been published.

On the computer that holds the release key, run:

    release-sign sign bastion $VER $MAN_SHA

then run this again with the line it prints:

    SIGNATURE='<that line>' deploy/publish.sh

ASK
  exit 3
fi
# The signature file is named by the manifest's digest (release_sign.go
# releaseSigURL), and old ones are never removed, so a machine that read the
# previous manifest a moment ago still finds the signature that belongs to it.
SIG_NAME="version.json.${MAN_SHA:0:16}.sig"
printf '%s\n' "$SIGNATURE" > "$HERE/client-go/dist/$SIG_NAME"
# Checked against this tree's keys AND the keys of the release the fleet runs
# now (CUR_FROM, read by the ratchet above): those bastions read this manifest
# with their own keys, so a signature only the new keys accept would strand
# them.
SIGNED_BY="$("$HERE/deploy/release-verify.sh" bastion "$MAN" "$HERE/client-go/dist/$SIG_NAME" ${CUR_FROM:+"$CUR_FROM"})" \
  || { echo "SIGNATURE does not verify for bastion v$VER (manifest $MAN_SHA); nothing was published" >&2; exit 1; }
echo "manifest signature ok (key $SIGNED_BY)"

# A bastion from this tree refuses an agent manifest that is not signed, so the
# agent must already be published signed at the address it reads, or every
# new folder grant on an updated machine fails to install the agent. Checked
# here, before this release can reach any machine. (The legacy /freeagent
# address is read only by bastions older than 0.42.0; this release never asks
# it.)
AGENTCHECK="$(mktemp -d)"
for B in https://privatae.ai/bastion-agent; do
  curl -fsS --max-time 30 "$B/version.json" -o "$AGENTCHECK/m" \
    || { echo "agent manifest $B/version.json is unreachable; publish the signed agent first" >&2; rm -rf "$AGENTCHECK"; exit 1; }
  AH="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$AGENTCHECK/m")"
  if ! curl -fsS --max-time 30 "$B/version.json.$AH.sig" -o "$AGENTCHECK/s" \
     || ! "$HERE/deploy/release-verify.sh" bastion-agent "$AGENTCHECK/m" "$AGENTCHECK/s" ${CUR_FROM:+"$CUR_FROM"} >/dev/null; then
    echo "the agent manifest at $B is not signed with a key this release pins; publish the signed agent first" >&2
    rm -rf "$AGENTCHECK"; exit 1
  fi
done
rm -rf "$AGENTCHECK"
echo "agent manifests are signed at both addresses"

for E in $EDGES; do
  echo "--- publishing to $E ---"
  ssh -i "$KEY" "$E" 'rm -rf /tmp/bn && mkdir -p /tmp/bn'
  # install.ps1 ships from the repo too: it once existed only as bytes in the
  # webroot, so the Windows installer customers piped to `iex` had
  # no review history and no deploy path.
  # LICENSE ships with the binaries: GPL-3 sections 4 and 5 require the license to
  # travel with the program, and a downloaded binary carries no text of its own.
  # It lands at /bastion/LICENSE.txt, next to version.json — the URL both
  # installers print after a successful install. The .txt is what makes a browser
  # render it inline instead of offering a download.
  scp -i "$KEY" "$HERE"/client-go/dist/privatae-bastion-* "$HERE"/client-go/dist/version.json \
    "$HERE/client-go/dist/$SIG_NAME" \
    "$HERE"/deploy/install.sh "$HERE"/deploy/install.ps1 "$HERE"/LICENSE "$E":/tmp/bn/
  # WEBROOT/BACKUP_DIR are passed as remote ENVIRONMENT and expand REMOTELY, like
  # every other variable in this body. That is deliberate: the heredoc delimiter is
  # quoted so nothing here expands locally, which is what keeps $ts/$f/$b working.
  # Do not "fix" this by interpolating the paths locally or unquoting the delimiter
  # -- unquoting it would expand $ts/$f/$b on THIS box, where they are empty.
  ssh -i "$KEY" "$E" "WEBROOT='$WEBROOT' BACKUP_DIR='$BACKUP_DIR' sh -s" <<'REMOTE'
    set -e
    # A second edge starts with no webroot at all, so create it rather than
    # assuming it. The .bak of install.sh is best-effort for the same reason.
    install -d -m755 "$WEBROOT/dl"
    ts=$(date +%s)
    # Backups go OUTSIDE the webroot. They used to land next to the live files,
    # which served every superseded installer and binary at a stable public URL:
    # /bastion/install.sh.bak-<ts> was the earlier script -- the one with no
    # checksum verification -- reachable at HTTP 200 (measured).
    # Hardening install.sh is worth nothing while the vulnerable one sits next to
    # it. Caddy now 404s \.bak and dotfiles too; this is the other half, so the
    # exposure cannot come back if that rule is ever lost.
    install -d -m700 "$BACKUP_DIR"
    cp -a "$WEBROOT/install.sh"  "$BACKUP_DIR/install.sh.bak-$ts" 2>/dev/null || true
    cp -a "$WEBROOT/install.ps1" "$BACKUP_DIR/install.ps1.bak-$ts" 2>/dev/null || true
    for f in /tmp/bn/privatae-bastion-*; do b=$(basename "$f"); mv "$f" "$WEBROOT/dl/$b"; chmod 755 "$WEBROOT/dl/$b"; done
    # The signature lands before the manifest it signs. A bastion that reads
    # the new manifest in between asks for its signature by the manifest's
    # digest and finds it already there.
    for f in /tmp/bn/version.json.*.sig; do b=$(basename "$f"); mv "$f" "$WEBROOT/$b"; chmod 644 "$WEBROOT/$b"; done
    mv /tmp/bn/version.json "$WEBROOT/version.json"; chmod 644 "$WEBROOT/version.json"
    mv /tmp/bn/install.sh "$WEBROOT/install.sh"; chmod 644 "$WEBROOT/install.sh"
    mv /tmp/bn/install.ps1 "$WEBROOT/install.ps1"; chmod 644 "$WEBROOT/install.ps1"
    mv /tmp/bn/LICENSE "$WEBROOT/LICENSE.txt"; chmod 644 "$WEBROOT/LICENSE.txt"
    rm -rf /tmp/bn
REMOTE
done

# Verify each edge independently: the bytes on ITS disk must match the digests in
# the manifest IT serves. This is the one failure the manifest cannot catch on its
# own -- a publish that reported success while leaving an edge half-written looks
# identical to a good one until a customer's install refuses.
for E in $EDGES; do
  printf '  %s: ' "$E"
  ssh -i "$KEY" "$E" 'cd '"$WEBROOT"' && python3 - <<VERIFY
import hashlib, json, os, sys
m = json.load(open("version.json"))
bad = []
for k, v in m["binaries"].items():
    p = os.path.join("dl", "privatae-bastion-" + k)
    if not os.path.exists(p):
        bad.append(k + " MISSING"); continue
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != v["sha256"]:
        bad.append(k + " DIGEST-MISMATCH")
# The signature of this manifest, under its digest name.
sig = "version.json.%s.sig" % hashlib.sha256(open("version.json", "rb").read()).hexdigest()[:16]
if not os.path.exists(sig):
    bad.append(sig + " MISSING")
# LICENSE.txt is not in the manifest, so its expected digest is the one this
# publish computed from the repo and passed in. Same failure shape as a binary:
# an edge serving the wrong license text fails the publish.
if not os.path.exists("LICENSE.txt"):
    bad.append("LICENSE.txt MISSING")
elif hashlib.sha256(open("LICENSE.txt", "rb").read()).hexdigest() != "'"$LIC_SHA"'":
    bad.append("LICENSE.txt DIGEST-MISMATCH")
print(("VERIFY FAILED: " + "; ".join(bad)) if bad else
      "ok - %d binaries + LICENSE.txt match the manifest (v%s)" % (len(m["binaries"]), m["version"]))
sys.exit(1 if bad else 0)
VERIFY'
done

# OUTSIDE-IN VERIFY — the check the per-edge loop above cannot make.
#
# That loop reads each edge's own disk over ssh, so it proves the bytes LANDED.
# It once proved exactly that and reported success while Cloudflare
# served the previous windows-amd64.exe to the actual internet. A privileged
# vantage cannot see a cache that sits in front of it; only a plain public fetch
# can. So fetch the manifest and every binary the way a customer's machine does
# and compare against the digests — no ssh, no mesh, no key.
echo "--- verifying from the public internet (through the cache) ---"
python3 - "$VER" "$LIC_SHA" <<'OUTSIDE'
import hashlib, json, sys, urllib.request
ver, lic_sha = sys.argv[1], sys.argv[2]
def get(u):
    req = urllib.request.Request(u, headers={"User-Agent": "publish-verify"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read(), r.headers
m, _ = get("https://privatae.ai/bastion/version.json")
m = json.loads(m)
if m["version"] != ver:
    print("  VERIFY FAILED: the public manifest says %s, we published %s" % (m["version"], ver))
    sys.exit(1)
bad = []
for k, v in sorted(m["binaries"].items()):
    body, hdrs = get(v["url"])
    got = hashlib.sha256(body).hexdigest()
    cache = hdrs.get("cf-cache-status", "-")
    if got == v["sha256"]:
        print("  %-20s ok   (cache %s)" % (k, cache))
    else:
        bad.append(k)
        print("  %-20s STALE — served %s, manifest %s (cache %s, age %s)"
              % (k, got[:16], v["sha256"][:16], cache, hdrs.get("age", "-")))
# LICENSE.txt gets the same treatment, at BOTH URLs. ?v= defeats a warm cache the
# way it does for the binaries — but the installers print the BARE url, and that is
# the one a person actually opens, so checking only the cache-busted key would pass
# while a warm edge served an old license to every user. The binaries have no such
# gap: update.go downloads the ?v= url straight out of the manifest, so there the
# key that is verified IS the key that is fetched. LICENSE.txt is not in the
# manifest, so both URLs are compared against the digest of the LICENSE in the tree
# being published, and a non-200 raises out of get() into the same failure.
for label, lic_url in (("LICENSE.txt?v", f"https://privatae.ai/bastion/LICENSE.txt?v={ver}"),
                       ("LICENSE.txt bare", "https://privatae.ai/bastion/LICENSE.txt")):
    try:
        body, hdrs = get(lic_url)
    except Exception as e:
        bad.append(label)
        print("  %-20s UNREACHABLE — %s" % (label, e))
        continue
    got = hashlib.sha256(body).hexdigest()
    cache = hdrs.get("cf-cache-status", "-")
    if got == lic_sha:
        print("  %-20s ok   (cache %s)" % (label, cache))
        continue
    bad.append(label)
    if label == "LICENSE.txt bare":
        # Name the remedy: this one is a cache in front of a correct origin, and the
        # ?v= line above will usually have passed, so the fix is a purge and re-run
        # rather than a rebuild.
        print("  LICENSE.txt STALE at the bare URL (edge cache) — purge https://privatae.ai/bastion/LICENSE.txt and re-run")
    print("  %-20s STALE — served %s, repo %s (cache %s, age %s)"
          % (label, got[:16], lic_sha[:16], cache, hdrs.get("age", "-")))
if bad:
    print("\n  VERIFY FAILED: %d object/objects are stale or missing at the public URL: %s" % (len(bad), ", ".join(bad)))
    print("  The edges hold the right bytes; something in front of them does not.")
    sys.exit(1)
print("  all %d binaries + LICENSE.txt (both URLs) match as the internet sees them" % len(m["binaries"]))
OUTSIDE

# The signature, fetched the way a bastion fetches it (release_sign.go
# releaseSigURL: version.json.<first 8 bytes of the manifest's sha256>.sig),
# and checked against the manifest the internet is served.
SIGCHECK="$(mktemp -d)"; trap 'rm -rf "$SIGCHECK"' EXIT
curl -fsS --max-time 30 "https://privatae.ai/bastion/version.json" -o "$SIGCHECK/m"
H="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$SIGCHECK/m")"
curl -fsS --max-time 30 "https://privatae.ai/bastion/version.json.$H.sig" -o "$SIGCHECK/s" \
  || { echo "  VERIFY FAILED: version.json.$H.sig is not served publicly" >&2; exit 1; }
if "$HERE/deploy/release-verify.sh" bastion "$SIGCHECK/m" "$SIGCHECK/s" ${CUR_FROM:+"$CUR_FROM"} >/dev/null; then
  echo "  version.json.$H.sig ok   (verifies against the public manifest)"
else
  echo "  VERIFY FAILED: the public version.json.$H.sig does not verify against the public manifest" >&2
  exit 1
fi

echo "published bastion v$VER to:"
for E in $EDGES; do echo "    $E"; done
echo "  https://privatae.ai/bastion/  (manifest: /bastion/version.json)"
