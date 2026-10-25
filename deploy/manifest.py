#!/usr/bin/env python3
"""Write a bastion release manifest (version.json) to standard output.

    python3 deploy/manifest.py <version> <built_from> <dist dir>

publish.sh writes every release manifest with this, and release-assets.sh
writes it again from a rebuild of the release's tag. The manifest is a function
of the version, the commit it was built from and the bytes of the binaries in
<dist dir>, so a rebuild of the same release writes the same bytes, and the
signature published for the release (named by the manifest's digest) still
verifies against it.

The format: {version, built_from, binaries: {<os>-<arch>[.exe]: {url, sha256}}},
keys in that order, the binaries sorted by file name, indented by two spaces,
no newline at the end.
"""

import hashlib
import json
import os
import sys


def manifest(ver, built_from, dist):
    binaries = {}
    for f in sorted(os.listdir(dist)):
        if not f.startswith("privatae-bastion-"):
            continue
        with open(os.path.join(dist, f), "rb") as fh:
            h = hashlib.sha256(fh.read()).hexdigest()
        # ?v=<version> IS LOAD-BEARING, not decoration. dl.privatae.ai sits
        # behind a cache that keys on the full URL including the query string.
        # Without it a publish replaces the bytes on every edge, every edge
        # verifies, the manifest is fresh, and the cache keeps serving the
        # PREVIOUS binary to anyone whose request lands on a warm edge: the
        # client downloads the old bytes, compares them with the new digest,
        # and aborts with "sha256 mismatch", which reads like a corrupt build
        # and is a stale cache. It breaks one platform at a time, for whoever
        # downloaded last. A new version string is a new cache key and so a
        # guaranteed miss; update.go downloads binaries[key].url verbatim, so
        # bastions already in the field pick this up with no client change.
        binaries[f[len("privatae-bastion-"):]] = {
            "url": f"https://dl.privatae.ai/dl/{f}?v={ver}", "sha256": h}
    return json.dumps({"version": ver, "built_from": built_from, "binaries": binaries}, indent=2)


def main(argv):
    if len(argv) != 4:
        print("usage: deploy/manifest.py <version> <built_from> <dist dir>", file=sys.stderr)
        return 2
    sys.stdout.write(manifest(argv[1], argv[2], argv[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
