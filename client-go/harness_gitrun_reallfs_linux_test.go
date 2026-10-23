package main

// A git run against a repository that keeps a file in Git LFS, with the real
// git-lfs. It runs only where git-lfs is installed; every server it talks to
// is in this test, on loopback.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func lfsPointer(body string) (oid, pointer string) {
	sum := sha256.Sum256([]byte(body))
	oid = hex.EncodeToString(sum[:])
	return oid, fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oid, len(body))
}

func TestAGitRunWithTheRealGitLFS(t *testing.T) {
	if out, err := exec.Command("git-lfs", "version").Output(); err != nil || !strings.HasPrefix(string(out), "git-lfs/") {
		t.Skip("git-lfs is not installed")
	}
	f := newGitRunFixture(t)
	realGit, _ := exec.LookPath("git")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("harness:"+gitRunToken))

	var mu sync.Mutex
	store := map[string][]byte{}
	v1oid, v1ptr := lfsPointer("v1\n")
	store[v1oid] = []byte("v1\n")
	var srvURL string
	backend := &cgi.Handler{Path: realGit, Args: []string{"http-backend"}, Root: "/git",
		Env: []string{"GIT_PROJECT_ROOT=" + filepath.Dir(f.origin), "GIT_HTTP_EXPORT_ALL=1",
			"REMOTE_USER=harness", "GIT_CONFIG_NOSYSTEM=1", "HOME=" + t.TempDir()}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/store/") { // the object hrefs the batch answer gives
			oid := strings.TrimPrefix(r.URL.Path, "/store/")
			mu.Lock()
			defer mu.Unlock()
			if r.Method == http.MethodPut {
				b, _ := io.ReadAll(r.Body)
				store[oid] = b
				return
			}
			_, _ = w.Write(store[oid])
			return
		}
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.Path, "/info/lfs/") {
			backend.ServeHTTP(w, r)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/objects/batch") {
			http.NotFound(w, r) // locks: not supported here
			return
		}
		var req struct {
			Operation string `json:"operation"`
			Objects   []struct {
				Oid  string `json:"oid"`
				Size int64  `json:"size"`
			} `json:"objects"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var objs []map[string]any
		mu.Lock()
		for _, o := range req.Objects {
			obj := map[string]any{"oid": o.Oid, "size": o.Size, "authenticated": true}
			_, have := store[o.Oid]
			if req.Operation == "download" || !have {
				obj["actions"] = map[string]any{req.Operation: map[string]any{"href": srvURL + "/store/" + o.Oid}}
			}
			objs = append(objs, obj)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"transfer": "basic", "objects": objs})
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	var foreignHits atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		http.Error(w, "no", http.StatusForbidden)
	}))
	t.Cleanup(foreign.Close)

	seed := filepath.Join(t.TempDir(), "s")
	testGit(t, "", "clone", "-q", f.origin, seed)
	for name, body := range map[string]string{".gitattributes": "*.bin filter=lfs diff=lfs merge=lfs -text\n", "big.bin": v1ptr} {
		if err := os.WriteFile(filepath.Join(seed, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	testGit(t, seed, "add", "-A")
	testGit(t, seed, "commit", "-q", "-m", "an lfs file")
	testGit(t, seed, "push", "-q", "origin", "main")

	// The agent changes the large file and names a foreign LFS server.
	f.setAgent(t, `set -e
cd "$1"
grep -qx v1 big.bin
echo v2 > big.bin
printf '[lfs]\n\turl = `+foreign.URL+`/x.git/info/lfs\n\tpushurl = `+foreign.URL+`/x.git/info/lfs\n[remote "origin"]\n\tlfsurl = `+foreign.URL+`/y\n' > .lfsconfig
`)
	repoURL := strings.Replace(srv.URL, "http://", "http://harness:"+gitRunToken+"@", 1) + "/git/" + filepath.Base(f.origin)
	b, code := runGit(harnessSpec{Mode: "git", HarnessID: "h1", Image: "harness:test",
		RepoURL: repoURL, Branch: "agent-work", MaxMinutes: 1})
	t.Logf("result: %s", b)
	if code != 0 {
		t.Fatalf("the run failed")
	}
	v2oid, v2ptr := lfsPointer("v2\n")
	if got := testGit(t, f.origin, "show", "agent-work:big.bin"); got != v2ptr {
		t.Errorf("big.bin on the branch = %q, want the pointer to v2", got)
	}
	mu.Lock()
	got := string(store[v2oid])
	mu.Unlock()
	if got != "v2\n" {
		t.Errorf("the LFS object for v2 was not sent to the repository's own LFS server (%q)", got)
	}
	if n := foreignHits.Load(); n != 0 {
		t.Errorf("the foreign LFS server named in .lfsconfig got %d requests", n)
	}
}
