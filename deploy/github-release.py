#!/usr/bin/env python3
"""Attach a release's checked files to its GitHub release.

    GH_TOKEN=<token> python3 deploy/github-release.py <owner/repo> v<version> <assets dir> <CHANGELOG.md>

.github/workflows/release.yml runs this after deploy/release-assets.sh has
filled <assets dir> with files it checked against the signed manifest. The
release for the tag is made if it does not exist yet, named
`bastion <version>`, with that version's section of <CHANGELOG.md> as its
notes; an existing release keeps its name and notes. Each file in
<assets dir> is uploaded, replacing an asset of the same name, so a re-run
leaves the same set. Standard library only; the token is read from the
environment and sent only to the GitHub API.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
UPLOADS = os.environ.get("GITHUB_UPLOADS_URL", "https://uploads.github.com")


def call(method, url, token, body=None, ctype="application/json"):
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "Content-Type": ctype,
        "User-Agent": "bastion-release-assets"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"message": raw.decode(errors="replace")[:300]}


def notes(changelog, ver):
    """The CHANGELOG section `## <ver>`, up to the next `## ` heading."""
    text = open(changelog, encoding="utf-8").read()
    m = re.search(r"^## " + re.escape(ver) + r"[ \t]*$", text, re.M)
    if m is None:
        raise SystemExit("CHANGELOG has no section for %s" % ver)
    nxt = re.search(r"^## ", text[m.end():], re.M)
    body = text[m.end():m.end() + nxt.start() if nxt else len(text)].strip()
    return (body + "\n\n---\nThe binaries attached here were rebuilt from this tag by this repository's "
            "release workflow, and their digests are the ones in the signed manifest `version.json` "
            "attached beside them. To check them yourself, see "
            "[Verify a release](https://github.com/Privatae/bastion#verify-a-release).")


def main(argv):
    if len(argv) != 5:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    repo, tag, assets, changelog = argv[1:]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise SystemExit("not a release tag: " + tag)
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise SystemExit("GH_TOKEN is not set")
    ver = tag[1:]
    files = sorted(os.listdir(assets))
    if not files:
        raise SystemExit("no assets in " + assets)

    st, rel = call("GET", "%s/repos/%s/releases/tags/%s" % (API, repo, tag), token)
    if st == 404:
        st, rel = call("POST", "%s/repos/%s/releases" % (API, repo), token, {
            "tag_name": tag, "name": "bastion " + ver, "body": notes(changelog, ver),
            "draft": False, "prerelease": False})
        if st != 201:
            raise SystemExit("could not make the release for %s: HTTP %d %s" % (tag, st, rel))
        print("made the release for %s" % tag)
    elif st != 200:
        raise SystemExit("could not read the release for %s: HTTP %d %s" % (tag, st, rel))

    have = {a["name"]: a["id"] for a in rel.get("assets", [])}
    for name in files:
        if name in have:
            st, _ = call("DELETE", "%s/repos/%s/releases/assets/%d" % (API, repo, have[name]), token)
            if st != 204:
                raise SystemExit("could not replace %s: HTTP %d" % (name, st))
        with open(os.path.join(assets, name), "rb") as fh:
            data = fh.read()
        url = "%s/repos/%s/releases/%d/assets?name=%s" % (UPLOADS, repo, rel["id"], urllib.parse.quote(name))
        st, up = call("POST", url, token, data, "application/octet-stream")
        if st != 201 or up.get("size") != len(data):
            raise SystemExit("upload of %s failed: HTTP %d %s" % (name, st, up))
        print("attached %s (%d bytes)" % (name, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
