//go:build !windows

// The git half runs a stand-in helper as a shell script, so it is unix-only.

package main

// No secrets cached for git. The credential helper asks the running daemon
// for a token on every auth and keeps nothing; store and erase are no-ops;
// and the lines git-setup prints reset git's helper chain for the forge so a
// helper configured before them never sees the token. The daemon here is a
// loopback test server, and git runs against a throwaway HOME.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// withStdio runs fn with stdin fed from in and returns what it wrote to stdout.
func withStdio(t *testing.T, in string, fn func()) string {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	ir, iw, _ := os.Pipe()
	or, ow, _ := os.Pipe()
	os.Stdin, os.Stdout = ir, ow
	go func() { _, _ = io.WriteString(iw, in); _ = iw.Close() }()
	done := make(chan string)
	go func() { b, _ := io.ReadAll(or); done <- string(b) }()
	fn()
	_ = ow.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	_ = ir.Close()
	return <-done
}

// gitPairing writes one pairing whose control port is addr.
func gitPairing(t *testing.T, host, addr, secret string) {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(Config{HostName: host, WGPrivateKey: "k", BastionTunnelIP: "2001:db8::a:1",
		ListenAddr: addr, OperatorSecret: secret, GitProxyAddr: "127.0.0.1:7978"})
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// configTree lists every file under the config dir with its contents.
func configTree(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			raw, _ := os.ReadFile(p)
			fmt.Fprintf(&b, "%s\n%s\n", p, raw)
		}
		return nil
	})
	return b.String()
}

func TestTheGitHelperFetchesATokenPerAuthAndStoresNothing(t *testing.T) {
	cfgDir := uiTestConfigDir(t)
	var asked atomic.Int64
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/git-credential" || r.Header.Get("Authorization") != "Bearer local-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		n := asked.Add(1)
		fmt.Fprintf(w, "username=forge\npassword=token-%d\n", n)
	}))
	defer daemon.Close()
	gitPairing(t, "h.host.privatae.ai", strings.TrimPrefix(daemon.URL, "http://"), "local-secret")
	before := configTree(t, cfgDir)

	ask := "protocol=https\nhost=" + gitForgeHost + "\n\n"
	for i := 1; i <= 3; i++ {
		out := withStdio(t, ask, func() {
			if err := cmdGitCredential("", "get"); err != nil {
				t.Fatal(err)
			}
		})
		if want := fmt.Sprintf("password=token-%d\n", i); !strings.Contains(out, want) {
			t.Fatalf("auth %d: the helper must relay a fresh token from the daemon (%q), got %q", i, want, out)
		}
	}
	if asked.Load() != 3 {
		t.Fatalf("three auths must be three requests to the daemon, got %d", asked.Load())
	}

	// git hands the helper the token to store, and later to erase: both are
	// no-ops, and neither reaches the daemon or the disk.
	for _, action := range []string{"store", "erase"} {
		out := withStdio(t, ask+"username=forge\npassword=token-1\n\n", func() {
			if err := cmdGitCredential("", action); err != nil {
				t.Fatal(err)
			}
		})
		if out != "" {
			t.Fatalf("%s must print nothing, printed %q", action, out)
		}
	}
	// Another forge: not ours, so nothing is asked and nothing is answered.
	out := withStdio(t, "protocol=https\nhost=github.com\n\n", func() {
		if err := cmdGitCredential("", "get"); err != nil {
			t.Fatal(err)
		}
	})
	if out != "" || asked.Load() != 3 {
		t.Fatalf("a request for another host must go nowhere: printed %q, %d requests", out, asked.Load())
	}
	if after := configTree(t, cfgDir); after != before {
		t.Fatalf("the helper wrote to the bastion's config:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// splitShellish splits one printed `git config` line into argv, honouring
// the double quotes git-setup prints around the helper value.
func splitShellish(line string) []string {
	var out []string
	var cur strings.Builder
	inQ, any := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQ, any = !inQ, true
		case r == ' ' && !inQ:
			if any || cur.Len() > 0 {
				out = append(out, cur.String())
			}
			cur.Reset()
			any = false
		default:
			cur.WriteRune(r)
		}
	}
	if any || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func TestGitSetupResetsTheHelperChainBeforeItsOwnHelper(t *testing.T) {
	uiTestConfigDir(t)
	gitPairing(t, "h.host.privatae.ai", "127.0.0.1:7878", "s")
	out := withStdio(t, "", func() {
		if err := cmdGitSetup(); err != nil {
			t.Fatal(err)
		}
	})
	var helperLines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.Contains(l, ".helper") {
			helperLines = append(helperLines, l)
		}
	}
	// This comparison is the one place the tests pin the real forge name:
	// git-setup prints the host as a literal, and the expected lines here come
	// from gitForgeHost, so a change to either one fails. If git-setup is ever
	// switched to print gitForgeHost, the name needs an explicit pin elsewhere.
	want := []string{
		`git config --global --replace-all credential.https://` + gitForgeHost + `.helper ""`,
		`git config --global --add credential.https://` + gitForgeHost + `.helper "!privatae-bastion git-credential"`,
	}
	if strings.Join(helperLines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("git-setup must reset the forge's helper chain, then add its own helper:\n got %q\nwant %q", helperLines, want)
	}

	// Several hosts: every host's pair of lines still starts with the reset.
	gitPairing(t, "g.host.privatae.ai", "127.0.0.1:7879", "s")
	out = withStdio(t, "", func() { _ = cmdGitSetup() })
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "--add credential.https://"+gitForgeHost+".helper") {
			if i == 0 || !strings.Contains(lines[i-1], `--replace-all credential.https://`+gitForgeHost+`.helper ""`) {
				t.Fatalf("a helper line without the reset right before it:\n%s", out)
			}
		}
	}
}

// gitForge stands in for the forge at gitForgeHost: a TLS server that demands Basic
// auth with the host's token and serves a real repository through
// git-http-backend, reached through a CONNECT proxy the way the bastion's
// git proxy is. It counts the requests that carried the right token.
type gitForge struct {
	proxy  string
	authed atomic.Int64
}

func newGitForge(t *testing.T, git, token string) *gitForge {
	t.Helper()
	root := t.TempDir()
	if out, err := exec.Command(git, "init", "-q", "--bare", filepath.Join(root, "r.git")).CombinedOutput(); err != nil {
		t.Fatalf("init: %v %s", err, out)
	}
	f := &gitForge{}
	backend := &cgi.Handler{Path: git, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("forge:"+token))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="forge"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		f.authed.Add(1)
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "https://")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect || req.Host != gitForgeHost+":443" {
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}(c)
		}
	}()
	f.proxy = "http://" + ln.Addr().String()
	return f
}

// No secrets cached for git, end to end. A real git reads the forge
// through the proxy, with git-setup's lines applied and a caching helper
// (`store`) configured in each place a machine might already have one:
// before those lines, after them, and in the repository's own config. Each
// ls-remote authenticates with the host's token from the bastion's helper, and
// the token is never written to disk.
func TestNoHelperOnTheMachineStoresTheForgeToken(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed here")
	}
	// Before 2.46 git does not announce the authtype capability, so the
	// helper answers with a username and password and a helper configured
	// after git-setup's lines stores them: the residual the README states and
	// TestWithoutTheAuthtypeCapabilityOnlyTheResetProtects pins.
	if v, ok := gitVersion(git); !ok || v[0] < 2 || (v[0] == 2 && v[1] < 46) {
		t.Skipf("git %v is older than 2.46; this test measures the authtype form", v)
	}
	const token = "token-from-host"
	cfgDir := uiTestConfigDir(t)
	var asked atomic.Int64
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		fmt.Fprintf(w, "username=forge\npassword=%s\n", token)
	}))
	defer daemon.Close()
	gitPairing(t, "h.host.privatae.ai", strings.TrimPrefix(daemon.URL, "http://"), "s")
	setup := withStdio(t, "", func() { _ = cmdGitSetup() })

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, place := range []string{"before", "after", "repository"} {
		t.Run("store configured "+place, func(t *testing.T) {
			forge := newGitForge(t, git, token)
			home := t.TempDir()
			bin := t.TempDir()
			// `privatae-bastion` on git's PATH is this test binary, which
			// answers as the real helper (gitHelperChildMain).
			stub := "#!/bin/sh\nexec '" + self + "' \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "privatae-bastion"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			env := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+cfgDir, "GIT_CONFIG_NOSYSTEM=1",
				"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"), "GIT_TERMINAL_PROMPT=0",
				"GIT_ASKPASS=", "SSH_ASKPASS=", "PRIVATAE_TEST_GIT_HELPER_CONFIG="+cfgDir,
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			repo := filepath.Join(home, "work")
			run := func(dir string, args ...string) {
				t.Helper()
				cmd := exec.Command(git, args...)
				cmd.Env, cmd.Dir = env, dir
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			run(home, "init", "-q", repo)
			if place == "before" {
				run(home, "config", "--global", "credential.helper", "store")
			}
			for _, l := range strings.Split(setup, "\n") {
				if l = strings.TrimSpace(l); strings.HasPrefix(l, "git config --global --") && strings.Contains(l, ".helper") {
					run(home, splitShellish(l)[1:]...)
				}
			}
			switch place {
			case "after":
				run(home, "config", "--global", "credential.helper", "store")
			case "repository":
				run(repo, "config", "credential.helper", "store")
			}
			// The proxy line git-setup prints names the bastion's own port;
			// here it is the test's proxy. Certificate checks are off only in
			// this throwaway HOME, for the test server's certificate.
			run(home, "config", "--global", "http.https://"+gitForgeHost+".proxy", forge.proxy)
			run(home, "config", "--global", "http.https://"+gitForgeHost+".sslVerify", "false")

			before := asked.Load()
			for i := 0; i < 2; i++ {
				run(repo, "ls-remote", "-q", "https://"+gitForgeHost+"/r.git")
			}
			if forge.authed.Load() == 0 {
				t.Fatal("the forge never saw the host's token")
			}
			if asked.Load()-before < 2 {
				t.Fatalf("each run must ask the host for the token, asked %d times for two", asked.Load()-before)
			}
			// git's store helper writes ~/.git-credentials, or
			// $XDG_CONFIG_HOME/git/credentials when that exists.
			for _, p := range []string{filepath.Join(home, ".git-credentials"), filepath.Join(cfgDir, "git", "credentials")} {
				if raw, err := os.ReadFile(p); err == nil && strings.Contains(string(raw), token) {
					t.Fatalf("a caching helper configured %s git-setup's lines stored the token in %s", place, p)
				}
			}
		})
	}
}

// What the bastion cannot close alone: a git that does not announce the
// authtype capability (older than 2.46) is given the username and password,
// and hands them to every helper in its list on approve. For it, git-setup's
// reset keeps out a helper configured before it and nothing else. This pins
// the fallback form so the residual stays what the README says it is.
func TestWithoutTheAuthtypeCapabilityOnlyTheResetProtects(t *testing.T) {
	host := []byte("username=forge\npassword=t0k\n")
	if got := string(gitCredentialReply(host, false)); got != "username=forge\npassword=t0k\nquit=1\n" {
		t.Fatalf("fallback form: %q", got)
	}
	got := string(gitCredentialReply(host, true))
	want := "capability[]=authtype\nauthtype=Basic\ncredential=" +
		base64.StdEncoding.EncodeToString([]byte("forge:t0k")) + "\nephemeral=1\nquit=1\n"
	if got != want {
		t.Fatalf("authtype form:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "password=") {
		t.Fatal("the authtype form must not carry the password field any helper would store")
	}
	if got := string(gitCredentialReply([]byte("error\n"), true)); got != "error\n" {
		t.Fatalf("an answer without a credential is passed on unchanged: %q", got)
	}

	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed here")
	}
	for _, after := range []bool{false, true} {
		home := t.TempDir()
		env := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"))
		run := func(stdin string, args ...string) {
			t.Helper()
			cmd := exec.Command(git, args...)
			cmd.Env, cmd.Stdin = env, strings.NewReader(stdin)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		if !after {
			run("", "config", "--global", "credential.helper", "store")
		}
		run("", "config", "--global", "--replace-all", "credential.https://"+gitForgeHost+".helper", "")
		run("", "config", "--global", "--add", "credential.https://"+gitForgeHost+".helper", "!true")
		if after {
			run("", "config", "--global", "credential.helper", "store")
		}
		run("protocol=https\nhost="+gitForgeHost+"\n"+string(gitCredentialReply(host, false))+"\n", "credential", "approve")
		_, err := os.Stat(filepath.Join(home, ".git-credentials"))
		if stored := err == nil; stored != after {
			t.Fatalf("store configured after=%v: stored=%v; the fallback's residual is exactly the helper configured after the reset", after, stored)
		}
	}
}

// gitVersion reads "git version X.Y.Z…" into [X, Y].
func gitVersion(git string) ([2]int, bool) {
	out, err := exec.Command(git, "version").Output()
	if err != nil {
		return [2]int{}, false
	}
	f := strings.Fields(string(out))
	if len(f) < 3 {
		return [2]int{}, false
	}
	var v [2]int
	if n, _ := fmt.Sscanf(f[2], "%d.%d", &v[0], &v[1]); n != 2 {
		return [2]int{}, false
	}
	return v, true
}
