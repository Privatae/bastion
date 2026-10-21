//go:build linux

package main

// An OPT-IN end-to-end run of a mirror sync against the real world: a real slot
// (docker, --network none) running Gitea on its socket, a real reach grant with
// two small public GitHub repos, a real `git fetch` over this machine's own
// connection, and a real push through the bridge into the server. Skipped
// unless BASTION_MIRROR_E2E=1 — it needs docker, git, the internet and root.
//
//	go test -c -o /tmp/b.test . && BASTION_MIRROR_E2E=1 /tmp/b.test -test.run TestMirrorEndToEnd -test.v

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMirrorEndToEnd(t *testing.T) {
	if os.Getenv("BASTION_MIRROR_E2E") != "1" {
		t.Skip("set BASTION_MIRROR_E2E=1 (needs docker, git, the internet)")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	name := "e2emirror"
	spec := harnessSpec{Mode: "service", ServiceOp: "up", ServiceName: name, owner: "h.example",
		Image: "gitea/gitea:1.26.2-rootless", Socket: "gitea.sock", DataPath: "/var/lib/gitea", DataUID: 1000,
		Envs: map[string]string{
			"GITEA__security__INSTALL_LOCK":                  "true",
			"GITEA__server__PROTOCOL":                        "http+unix",
			"GITEA__server__HTTP_ADDR":                       "/var/lib/gitea/gitea.sock",
			"GITEA__server__UNIX_SOCKET_PERMISSION":          "660",
			"GITEA__server__ROOT_URL":                        "http://forge.local/",
			"GITEA__server__DISABLE_SSH":                     "true",
			"GITEA__repository__ENABLE_PUSH_CREATE_USER":     "true",
			"GITEA__repository__DEFAULT_PUSH_CREATE_PRIVATE": "true",
		}}
	if b, code := runService(spec); code != 0 {
		t.Fatalf("up: %s", b)
	}
	defer runService(harnessSpec{Mode: "service", ServiceOp: "down", ServiceName: name, Purge: true, owner: "h.example"})

	sock, ok := "", false
	for i := 0; i < 60 && !ok; i++ {
		time.Sleep(time.Second)
		sock, ok = serviceUpstream(name)
	}
	if !ok {
		t.Fatal("the server's socket never answered")
	}
	cname := serviceContainerPrefix + name
	rt := serviceRuntime()
	if out, err := runCmd(time.Minute, rt, "exec", cname, "gitea", "admin", "user", "create", "--username", "rig",
		"--password", "E2e-pass-12345!", "--email", "rig@example.invalid", "--admin", "--must-change-password=false"); err != nil {
		t.Fatalf("create user: %s", out)
	}
	tok, err := runCmd(time.Minute, rt, "exec", cname, "gitea", "admin", "user", "generate-access-token",
		"--username", "rig", "--token-name", "e2e", "--scopes", "all", "--raw")
	if err != nil {
		t.Fatalf("token: %s", tok)
	}
	tok = strings.TrimSpace(tok)

	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	terms := reachTermsFor("h.example", name, 30)
	terms["mirrors"] = []map[string]any{
		{"url": "https://github.com/kelseyhightower/nocode.git", "repo": "rig/nocode"},
		{"url": "https://github.com/golang/example.git", "repo": "rig/example"},
	}
	tc, sig := signedTerms(t, priv, terms)
	if err := dcnSaveFile(dir, &dcnGrantFile{VerifyPubkey: pub, Stores: map[string]dcnGrantRec{},
		Reach: map[string]dcnGrantRec{"1": {TermsCanonical: tc, Signature: sig}}}); err != nil {
		t.Fatal(err)
	}

	b, code := runService(harnessSpec{Mode: "service", ServiceOp: "mirror", ServiceName: name,
		PushToken: tok, owner: "h.example", dcnDir: dir})
	t.Logf("mirror result: %s", b)
	if code != 0 {
		t.Fatalf("the sync must succeed: %s", b)
	}

	// Read the server's own view over its socket: both repos exist, with commits.
	hc := &http.Client{Transport: &http.Transport{Dial: func(_, _ string) (net.Conn, error) { return net.Dial("unix", sock) }}}
	// Gitea indexes a pushed repo in a background queue, so poll for a moment.
	for _, repo := range []string{"rig/nocode", "rig/example"} {
		var last string
		arrived := false
		for i := 0; i < 30 && !arrived; i++ {
			req, _ := http.NewRequest("GET", "http://forge.local/api/v1/repos/"+repo+"/commits?limit=1", nil)
			req.Header.Set("Authorization", "token "+tok)
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", repo, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var commits []map[string]any
			_ = json.Unmarshal(body, &commits)
			if resp.StatusCode == 200 && len(commits) > 0 {
				arrived = true
				t.Logf("%s arrived after %ds: latest commit %v", repo, i, commits[0]["sha"])
			} else {
				last = string(body)
				time.Sleep(time.Second)
			}
		}
		if !arrived {
			t.Fatalf("%s did not arrive in the server: %s", repo, last)
		}
	}
}
