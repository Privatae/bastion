#!/usr/bin/env bash
# Check that every test the README's security table cites exists.
#
#   deploy/check-claims.sh [repo root]      (default: the repository this sits in)
#
# The README's "How each claim is tested" table names, for each security claim,
# a test in client-go as `file_test.go`: `TestOrFuzzName`. A row is only worth
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
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="${1:-$HERE}"
cd "$ROOT"
[ -f README.md ] && [ -d client-go ] || { echo "not a repository root: $ROOT" >&2; exit 2; }
python3 - <<'PY'
import re, sys

text = open("README.md", encoding="utf-8").read()
start = text.find("### How each claim is tested")
if start < 0:
    print("the README has no 'How each claim is tested' section", file=sys.stderr)
    sys.exit(1)
end = text.find("\n## ", start)
table = text[start:end if end >= 0 else len(text)]

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
