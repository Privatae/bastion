#!/usr/bin/env bash
# Check that every test the security claims table cites exists.
#
#   deploy/check-claims.sh [repo root]      (default: the repository this sits in)
#
# The "How each claim is tested" table in docs/claims.md names, for each
# security claim, a test in client-go as `file_test.go`: `TestOrFuzzName`. A row is only worth
# something while that function exists: a renamed or deleted test would leave
# the claim looking covered when nothing checks it. This finds every such
# citation in the table and confirms `func <name>(` is defined in the cited
# file. It prints ok or MISSING for each row and exits non-zero if any is
# missing.
#
# A table it can only partly read must not pass as a clean one, so the rows
# are read one by one: every body row's test cell must be either exactly one
# citation in that form or "not covered by a test". A row that is neither is
# named and fails the check, and so does a table with no citations at all.
#
# It checks that the test exists, not what it asserts; that part is reviewed
# by reading the test when a row is added or changed.
#
#   deploy/check-claims.sh --skipped <go test -json output> [repo root]
#
# reads a `go test -json` run instead and names every cited test that
# skipped in it, with the reason it gave. It exits non-zero if any did: a CI job
# that runs a claim's test where it cannot run proves nothing about the claim.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${1:-}" = "--skipped" ]; then
  RUN="$(cd "$(dirname "${2:?usage: deploy/check-claims.sh --skipped <go test -json output> [repo root]}")" && pwd)/$(basename "$2")"
  ROOT="${3:-$HERE}"
  cd "$ROOT"
  [ -f docs/claims.md ] || { echo "no docs/claims.md in $ROOT" >&2; exit 2; }
  python3 - "$RUN" <<'PY'
import json, re, sys

cited = set(re.findall(r"`[\w./-]+_test\.go`: `(\w+)`", open("docs/claims.md", encoding="utf-8").read()))
skipped, why, ran = {}, {}, set()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    t = e.get("Test")
    if not t:
        continue
    top = t.split("/")[0]
    if top not in cited:
        continue
    ran.add(top)
    if e.get("Action") == "output" and "_test.go:" in e.get("Output", ""):
        why.setdefault(t, e["Output"].strip())
    if e.get("Action") == "skip":
        skipped[t] = True
for t in sorted(skipped):
    print("SKIPPED " + t + ": " + why.get(t, "(no reason printed)"))
print("%d cited tests ran here, %d of them skipped" % (len(ran), len(skipped)))
sys.exit(1 if skipped else 0)
PY
  exit $?
fi
ROOT="${1:-$HERE}"
cd "$ROOT"
[ -f docs/claims.md ] && [ -d client-go ] || { echo "not a repository root (no docs/claims.md or client-go): $ROOT" >&2; exit 2; }
python3 - <<'PY'
import re, sys

text = open("docs/claims.md", encoding="utf-8").read()
head = re.search(r"^#{1,6} How each claim is tested[ \t]*$", text, re.M)
if head is None:
    print("docs/claims.md has no 'How each claim is tested' heading", file=sys.stderr)
    sys.exit(1)
# The table runs from that heading to the next heading, or to the end of the file.
nxt = re.search(r"^#{1,6} ", text[head.end():], re.M)
table = text[head.end():head.end() + nxt.start() if nxt else len(text)]

cite = re.compile(r"`([\w./-]+_test\.go)`: `(\w+)`")
rows, unreadable = [], []
body = [l for l in table.splitlines() if l.startswith("|")][2:]  # past header and rule
for line in body:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    test = cells[1] if len(cells) == 3 else ""
    if test == "not covered by a test":
        continue
    m = cite.fullmatch(test)
    if m:
        rows.append(m.groups())
    else:
        unreadable.append(line)
for line in unreadable:
    print("UNREADABLE " + line)
if not rows:
    print("no test citations found in the table", file=sys.stderr)
    sys.exit(1)

missing = 0
for path, name in rows:
    try:
        src = open("client-go/" + path, encoding="utf-8").read()
    except OSError:
        src = ""
    ok = re.search(r"^func " + re.escape(name) + r"\(", src, re.M) is not None
    missing += not ok
    print(("ok      " if ok else "MISSING ") + "client-go/" + path + ": " + name)

print(f"{len(rows) - missing} of {len(rows)} cited tests found")
if unreadable:
    print(f"{len(unreadable)} table row(s) cite no test in the expected form", file=sys.stderr)
sys.exit(1 if missing or unreadable else 0)
PY
