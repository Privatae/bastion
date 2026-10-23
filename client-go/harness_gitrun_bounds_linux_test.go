package main

// A git run's copy is bounded by how many entries a tree holds as well as by
// its bytes; it never hands git the run's token in an argument or a config
// file; and it uses nothing of the agent's tree while the agent's container
// may still be running.

import (
	"encoding/base64"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Many empty files cost nothing in bytes; each still counts against the
// copy, so a tree of them is refused and nothing is pushed.
func TestAGitRunRefusesATreeOfTooManyEntries(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, `cd "$1"
i=0; while [ $i -lt 40 ]; do mkdir d$i; j=0; while [ $j -lt 100 ]; do : > d$i/f$j; j=$((j+1)); done; i=$((i+1)); done
`)
	saved := maxCopiedTreeBytes
	maxCopiedTreeBytes = 1 << 20 // 4000 entries at 512 bytes each are 2 MB
	t.Cleanup(func() { maxCopiedTreeBytes = saved })
	res, code := f.run(t)
	if code == 0 || res["ok"] != false {
		t.Fatalf("a tree of 4000 empty files was copied under a 1 MiB limit: %v", res)
	}
	if e, _ := res["error"].(string); !strings.Contains(e, "too large") {
		t.Errorf("the error does not say the tree is too large: %q", e)
	}
	if branchPushed(f) {
		t.Error("the branch was pushed")
	}
}

// A container the runtime does not confirm removed fails the run before any
// of its tree is copied.
func TestAGitRunFailsWhenTheAgentsContainerIsNotRemoved(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, "cd \"$1\" && echo new > edit.txt\n")
	docker := filepath.Join(filepath.Dir(f.agentFile), "docker")
	b, err := os.ReadFile(docker)
	if err != nil {
		t.Fatal(err)
	}
	failing := strings.Replace(string(b), "ps|pull|rm) exit 0;;", "ps|pull) exit 0;;\nrm) echo 'Error: removal stuck' >&2; exit 1;;", 1)
	if failing == string(b) {
		t.Fatal("the stand-in runtime changed shape")
	}
	if err := os.WriteFile(docker, []byte(failing), 0o755); err != nil {
		t.Fatal(err)
	}
	res, code := f.run(t)
	if code == 0 || res["ok"] != false {
		t.Fatalf("a run whose container was not removed reads ok: %v", res)
	}
	if e, _ := res["error"].(string); !strings.Contains(e, "could not be removed") || !strings.Contains(e, "removal stuck") {
		t.Errorf("the error does not say the container was not removed: %q", e)
	}
	if branchPushed(f) {
		t.Error("the branch was pushed")
	}
}

// Against a server that needs the token, the run clones and pushes with the
// token in no git argument and in no clone's config.
func TestAGitRunKeepsTheTokenOutOfEveryArgumentAndConfig(t *testing.T) {
	f := newGitRunFixture(t)
	f.setAgent(t, "cd \"$1\" && echo new > edit.txt\n")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("harness:"+gitRunToken))
	backend := &cgi.Handler{Path: realGit, Args: []string{"http-backend"}, Root: "/git",
		Env: []string{"GIT_PROJECT_ROOT=" + filepath.Dir(f.origin), "GIT_HTTP_EXPORT_ALL=1",
			"REMOTE_USER=harness", "GIT_CONFIG_NOSYSTEM=1", "HOME=" + t.TempDir()}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	logs := t.TempDir()
	argvLog, cfgLog := filepath.Join(logs, "argv"), filepath.Join(logs, "config")
	bin := t.TempDir()
	wrapper := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + argvLog + "\n" +
		"prev=; for a; do if [ \"$prev\" = -C ] && [ -f \"$a/.git/config\" ]; then cat \"$a/.git/config\" >> " + cfgLog + "; fi; prev=$a; done\n" +
		"exec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	repoURL := strings.Replace(srv.URL, "http://", "http://harness:"+gitRunToken+"@", 1) + "/git/" + filepath.Base(f.origin)
	b, code := runGit(harnessSpec{Mode: "git", HarnessID: "h1", Image: "harness:test",
		RepoURL: repoURL, Branch: "agent-work", MaxMinutes: 1})
	if code != 0 {
		t.Fatalf("the run failed: %s", b)
	}
	if !branchPushed(f) {
		t.Fatal("the branch is not in the origin")
	}
	argv, _ := os.ReadFile(argvLog)
	if !strings.Contains(string(argv), "push origin agent-work") {
		t.Fatalf("the stand-in git did not see the push:\n%s", argv)
	}
	cfg, _ := os.ReadFile(cfgLog)
	if len(cfg) == 0 {
		t.Fatal("no clone's config was read")
	}
	for name, body := range map[string][]byte{"an argument": argv, "a clone's config": cfg} {
		for _, secret := range []string{gitRunToken, strings.TrimPrefix(want, "Basic ")} {
			if strings.Contains(string(body), secret) {
				t.Errorf("the token is in %s:\n%s", name, body)
			}
		}
	}
}

// Every git call carries the harness identity: nothing of this machine's user
// or host name reaches the clone the agent is handed, and the commit is the
// harness's.
func TestAGitRunsGitCarriesTheHarnessIdentity(t *testing.T) {
	f := newGitRunFixture(t)
	reflog := filepath.Join(t.TempDir(), "reflog")
	f.setAgent(t, "cp \"$1/.git/logs/HEAD\" "+reflog+" && cd \"$1\" && echo new > edit.txt\n")
	res, code := f.run(t)
	if code != 0 {
		t.Fatalf("the run failed: %v", res)
	}
	b, err := os.ReadFile(reflog)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if !strings.Contains(string(b), " harness <harness@privatae.ai> ") || (host != "" && strings.Contains(string(b), host)) {
		t.Errorf("the agent's clone records another identity:\n%s", b)
	}
	who := strings.TrimSpace(testGit(t, f.origin, "log", "-1", "--format=%an <%ae> / %cn <%ce>", "agent-work"))
	if who != "harness <harness@privatae.ai> / harness <harness@privatae.ai>" {
		t.Errorf("the commit is by %q", who)
	}
}
