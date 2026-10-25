#!/usr/bin/env python3
"""deploy/github-release.py against a fake GitHub API on loopback.

    python3 -I deploy/test_github_release.py

A release that does not exist is made with the version's CHANGELOG section
and every file attached; a re-run replaces each asset of the same name and
leaves an existing release's name and notes alone; the token goes only in
the Authorization header.
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True  # leave no __pycache__ beside the script under test
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ghrel", os.path.join(HERE, "github-release.py"))


class Fake:
    def __init__(self):
        self.release = None
        self.calls = []
        self.next_id = 100


def handler(fake):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, obj=None):
            raw = json.dumps(obj).encode() if obj is not None else b""
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def body(self):
            return self.rfile.read(int(self.headers.get("Content-Length", 0)))

        def do_GET(self):
            fake.calls.append(("GET", self.path, self.headers.get("Authorization")))
            if self.path == "/repos/o/r/releases/tags/v1.2.3":
                return self.reply(200, fake.release) if fake.release else self.reply(404, {"message": "Not Found"})
            self.reply(404, {})

        def do_POST(self):
            data = self.body()
            fake.calls.append(("POST", self.path, self.headers.get("Authorization")))
            if self.path == "/repos/o/r/releases":
                req = json.loads(data)
                fake.release = {"id": 7, "tag_name": req["tag_name"], "name": req["name"], "body": req["body"], "assets": []}
                return self.reply(201, fake.release)
            if self.path.startswith("/repos/o/r/releases/7/assets?name="):
                name = self.path.split("name=", 1)[1]
                fake.next_id += 1
                fake.release["assets"].append({"id": fake.next_id, "name": name, "size": len(data)})
                return self.reply(201, {"id": fake.next_id, "name": name, "size": len(data)})
            self.reply(404, {})

        def do_DELETE(self):
            fake.calls.append(("DELETE", self.path, self.headers.get("Authorization")))
            aid = int(self.path.rsplit("/", 1)[1])
            fake.release["assets"] = [a for a in fake.release["assets"] if a["id"] != aid]
            self.reply(204)
    return H


def main():
    fake = Fake()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(fake))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    os.environ.update({"GITHUB_API_URL": base, "GITHUB_UPLOADS_URL": base, "GH_TOKEN": "t0ken"})
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with tempfile.TemporaryDirectory() as d:
        assets = os.path.join(d, "assets")
        os.mkdir(assets)
        for name, data in (("privatae-bastion-linux-amd64", b"bin"), ("version.json", b"{}")):
            open(os.path.join(assets, name), "wb").write(data)
        cl = os.path.join(d, "CHANGELOG.md")
        open(cl, "w").write("# Changelog\n\n## 1.2.4\n\n- later\n\n## 1.2.3\n\n- **One change.**\n\n## 1.2.2\n\n- earlier\n")

        assert mod.main(["x", "o/r", "v1.2.3", assets, cl]) == 0
        rel = fake.release
        assert rel["name"] == "bastion 1.2.3", rel
        assert rel["body"].startswith("- **One change.**") and "later" not in rel["body"] and "earlier" not in rel["body"], rel["body"]
        assert sorted(a["name"] for a in rel["assets"]) == ["privatae-bastion-linux-amd64", "version.json"]

        rel["name"], rel["body"] = "kept", "kept notes"
        open(os.path.join(assets, "version.json"), "wb").write(b'{"v":1}')
        assert mod.main(["x", "o/r", "v1.2.3", assets, cl]) == 0
        assert (rel["name"], rel["body"]) == ("kept", "kept notes")
        sizes = {a["name"]: a["size"] for a in rel["assets"]}
        assert sizes == {"privatae-bastion-linux-amd64": 3, "version.json": 7}, sizes
        assert sum(1 for c in fake.calls if c[0] == "DELETE") == 2
        assert all(c[2] == "Bearer t0ken" for c in fake.calls)
        assert not any("t0ken" in c[1] for c in fake.calls)

        try:
            mod.main(["x", "o/r", "v9.9.9", assets, cl])
        except SystemExit as e:
            assert "no section for 9.9.9" in str(e), e
        else:
            raise AssertionError("a version with no CHANGELOG section must not get a release")
    srv.shutdown()
    print("ok - github-release.py makes, fills and refills a release")


if __name__ == "__main__":
    main()
