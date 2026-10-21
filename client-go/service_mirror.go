package main

// service_mirror.go — MIRRORING into a slot server, done by THIS machine.
//
// A slot server has no network (service.go), so it cannot pull the repos the
// person asked it to mirror ("I want my code local, mirroring x, y and z").
// This machine does it for it, as an ordinary `git fetch` over the person's
// OWN connection — the code goes from the upstream straight to their machine
// and never touches the platform — and then pushes the result into the server
// through its pinned socket.
//
// WHAT IT MAY FETCH is the reach grant's `mirrors` list (service_reach.go):
// signed by the host, approved by the person, one entry per upstream (an https
// URL and the server repo it lands in). Nothing else is fetched. Running a sync
// needs no further approval — it is standing work under the list the person
// approved — but it still runs only for the host the grant names.
//
// THE FETCH IS HELD TO THE PUBLIC INTERNET, on every machine (the egress lane
// only does this on an anchored box): every address the source's host resolves
// to is vetted (internalIP: loopback, LAN, private, carrier-NAT, link-local),
// and git is then PINNED to the vetted address (http.curloptResolve) so a
// second lookup cannot answer 127.0.0.1. https only, no redirects, no
// credential helpers, no user or system git config.
//
// THE PUSH goes through a loopback bridge that exists for that one push only: a
// reverse proxy answering nothing but a random per-push path, dialling the
// server's pinned socket with the peer-uid check (mirrorPushBridge). The host's
// credential for its own server rides in git's ENVIRONMENT, never on the
// command line. A git older than 2.37 is refused: it would silently ignore the
// pin (gitUsableForMirror).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var mirrorRepoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// mirrorURLRe is the WHOLE shape a mirror source may take — an allowlist, the
// same pattern on the host (service_reach.py _MIRROR_URL) so both sides accept
// exactly the same strings. The host is a DNS name whose last label STARTS
// with a letter: curl reads a host as an IPv4 address when every part starts
// with a digit ("2130706433", "127.1", "0x7f000001", "10.0xa"), BEFORE it
// consults the pin, which would skip the vetting. The port is digits; the path is
// unreserved characters, "/" and %-escapes of two hex digits.
var mirrorURLRe = regexp.MustCompile(`^https://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*` +
	`[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?::[0-9]{1,5})?/(?:[A-Za-z0-9._~+-]|%[0-9A-Fa-f]{2}|/)+$`)

// The git and resolver seams, so the tests run with no network and no git.
var (
	mirrorGit       = runGitEnv
	mirrorResolve   = func(ctx context.Context, host string) ([]net.IP, error) { return lookupIPs(ctx, host) }
	mirrorGitUsable = gitUsableForMirror
)

// gitUsableForMirror: "" when this machine's git can run a PINNED fetch, else
// why not. http.curloptResolve arrived in git 2.37; an older git ignores the
// setting WITHOUT an error, which would silently drop the pin to the vetted
// address — so an older git is refused, never used.
func gitUsableForMirror() string {
	if _, err := exec.LookPath("git"); err != nil {
		return "git is not installed on this machine — install git 2.37 or newer and the sync can run"
	}
	out, err := runGitEnv(15*time.Second, nil, "version")
	if err != nil {
		return "git on this machine did not report its version"
	}
	return gitVersionRefusal(out)
}

// gitVersionRefusal: "" for `git version` output at 2.37 or newer, else why not.
func gitVersionRefusal(out string) string {
	var maj, min int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "git version %d.%d", &maj, &min); err != nil {
		return "git on this machine reported a version this bastion cannot read: " + truncate(out, 60)
	}
	if maj < 2 || (maj == 2 && min < 37) {
		return fmt.Sprintf("git %d.%d is too old: a mirror fetch is pinned to its vetted address with "+
			"http.curloptResolve, which git before 2.37 silently ignores — install git 2.37 or newer", maj, min)
	}
	return ""
}

// mirrorPushBridge opens the local bridge for ONE push and returns its base URL
// and a closer. INTENTIONALLY LOOPBACK, and more than that: it is a reverse
// proxy that forwards only requests under a random, unguessable path prefix
// (the URL is given only to the git child), to the server's pinned
// socket with the peer-uid check. A local process that finds the port but not
// the path gets a 404. The path does sit in the git child's command line for
// the length of the push, so a local user who reads it there reaches only the
// server's anonymous surface: the token is in git's environment, not the URL.
func mirrorPushBridge(slot string, dataUID int) (string, func(), error) {
	var rb [24]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", nil, err
	}
	prefix := "/" + hex.EncodeToString(rb[:])
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			up, ok := serviceUpstream(slot)
			if !ok {
				return nil, fmt.Errorf("the server's socket is not answering")
			}
			c, err := serviceDialSocket(up, 5*time.Second)
			if err != nil {
				return nil, err
			}
			if uid, err := servicePeerUID(c); err != nil || dataUID < 1 || int(uid) != dataUID {
				_ = c.Close()
				return nil, fmt.Errorf("the socket is not answered by the server's own uid")
			}
			return c, nil
		},
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "server.local"
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, prefix)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = "server.local"
		},
		Transport: tr,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix+"/") {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	// Loopback on purpose (see above): the only client is this process's git child.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return "http://" + ln.Addr().String() + prefix + "/", func() { _ = srv.Close() }, nil
}

func lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// printableASCII: every byte is a visible ASCII character — no spaces, no
// control characters, no Unicode (a right-to-left override in a URL would make
// the list the person approves read in an order it does not have).
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// mirrorSourceRefusal: "" when m is a source this box will fetch, else why not.
// Checked when a grant is verified AND again before a fetch.
func mirrorSourceRefusal(m mirrorSource) string {
	if !printableASCII(m.URL) || !printableASCII(m.Repo) {
		return "a mirror entry must be printable ASCII"
	}
	if strings.ContainsAny(m.URL, "|,>") || strings.ContainsAny(m.Repo, "|,>") {
		return "a mirror entry contains a reserved character"
	}
	if len(m.URL) > 2000 || !mirrorURLRe.MatchString(m.URL) {
		return "a mirror source must be a plain https URL of a repository on a named host " +
			"(no credentials, query, fragment or IP address)"
	}
	u, err := url.Parse(m.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") == "" {
		return "a mirror source must be a plain https URL of a repository (no credentials, query or fragment)"
	}
	if !mirrorRepoRe.MatchString(m.Repo) || strings.Contains(m.Repo, "..") {
		return "a mirror destination must be owner/name"
	}
	return ""
}

// mirrorListRefusal checks a whole list: every entry, and no two sources into
// the same repo — a sync prunes and force-pushes, so two sources sharing a
// destination would each delete the other's branches on every run.
func mirrorListRefusal(ms []mirrorSource) string {
	seen := map[string]bool{}
	for _, m := range ms {
		if why := mirrorSourceRefusal(m); why != "" {
			return why
		}
		k := strings.ToLower(m.Repo)
		if seen[k] {
			return "two mirror sources land in the same repo (" + m.Repo + ")"
		}
		seen[k] = true
	}
	return ""
}

// mirrorVetHost resolves host and returns ONE vetted public address to pin git
// to, or the refusal. Every address must be public: a name with any internal
// answer is refused outright, never filtered down to its public ones.
func mirrorVetHost(ctx context.Context, host string) (string, error) {
	var ips []net.IP
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		ips = []net.IP{ip}
	} else {
		if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
			return "", fmt.Errorf("%s is this machine", host)
		}
		r, err := mirrorResolve(ctx, host)
		if err != nil || len(r) == 0 {
			return "", fmt.Errorf("could not resolve %s on this machine", host)
		}
		ips = r
	}
	for _, ip := range ips {
		if internalIP(ip) {
			return "", fmt.Errorf("%s resolves to %s — a mirror is fetched from the public internet only, "+
				"never this machine, its network or the mesh", host, ip)
		}
	}
	return ips[0].String(), nil
}

// runGitEnv runs git with a clean, locked-down config and extra env.
func runGitEnv(timeout time.Duration, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	hideConsole(cmd)
	home, _ := os.MkdirTemp("", "privatae-mirror-home-")
	defer os.RemoveAll(home)
	cmd.Env = append([]string{
		"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "PATH=" + os.Getenv("PATH"),
	}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mirrorGitSafe is the config every mirror git call carries.
var mirrorGitSafe = []string{
	"-c", "credential.helper=", "-c", "core.askPass=", "-c", "http.followRedirects=false",
	"-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
}

var (
	mirrorLocksMu sync.Mutex
	mirrorLocks   = map[string]*sync.Mutex{}
)

func mirrorLockFor(slot string) *sync.Mutex {
	mirrorLocksMu.Lock()
	defer mirrorLocksMu.Unlock()
	if mirrorLocks[slot] == nil {
		mirrorLocks[slot] = &sync.Mutex{}
	}
	return mirrorLocks[slot]
}

// reachGrantFor returns the verified reach grant for (slot, self) on this box.
func reachGrantFor(dir, self, slot string) (*reachTerms, string) {
	if dir == "" || self == "" {
		return nil, "no pairing identity for this job"
	}
	grantsMu.Lock()
	f, err := dcnLoadFile(dir)
	grantsMu.Unlock()
	if err != nil || f.VerifyPubkey == "" {
		return nil, "no verified grants on this box for this host"
	}
	hn, _ := os.Hostname()
	for _, rec := range f.Reach {
		t, err := reachVerifyRec(f.VerifyPubkey, rec)
		if err == nil && t.Slot == slot && t.Subject == self && t.Server == hn {
			return t, ""
		}
	}
	return nil, "no reach grant for server '" + slot + "' held by " + self + " (default-deny)"
}

// serviceMirror runs one sync of every approved source into the server.
func serviceMirror(spec harnessSpec, res map[string]interface{}) ([]byte, int) {
	res["service_name"] = spec.ServiceName
	if !serviceNameRe.MatchString(spec.ServiceName) {
		return serviceFail(res, "service_name is not a valid slot name")
	}
	grant, why := reachGrantFor(spec.dcnDir, spec.owner, spec.ServiceName)
	if grant == nil {
		return serviceFail(res, why)
	}
	if len(grant.Mirrors) == 0 {
		return serviceFail(res, "the reach grant for this server names no mirror sources — nothing is approved to fetch")
	}
	if strings.TrimSpace(spec.PushToken) == "" || strings.ContainsAny(spec.PushToken, "\r\n") {
		return serviceFail(res, "push_token (the host's credential for its own server) is required")
	}
	if why := mirrorGitUsable(); why != "" {
		return serviceFail(res, why)
	}
	rec, err := loadServiceRecord(spec.ServiceName)
	if err != nil {
		return serviceFail(res, "no server named '"+spec.ServiceName+"' on this machine")
	}
	if _, ok := serviceUpstream(spec.ServiceName); !ok {
		return serviceFail(res, "the server is not running with no network and its socket answering; nothing to push into")
	}
	lk := mirrorLockFor(spec.ServiceName)
	lk.Lock()
	defer lk.Unlock()

	base, err := servicesDir()
	if err != nil {
		return serviceFail(res, "no services directory: "+err.Error())
	}
	// The cache is the BASTION's, outside the directory the container owns.
	cache := filepath.Join(base, spec.ServiceName, "mirror-cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return serviceFail(res, "cannot create the mirror cache: "+err.Error())
	}

	authEnv := []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: token " + spec.PushToken}

	results := []map[string]any{}
	failed := 0
	for _, m := range grant.Mirrors {
		r := map[string]any{"url": m.URL, "repo": m.Repo}
		results = append(results, r)
		if why := mirrorSourceRefusal(m); why != "" {
			r["error"], failed = why, failed+1
			continue
		}
		u, _ := url.Parse(m.URL)
		port := u.Port()
		if port == "" {
			port = "443"
		}
		// Bounded: the resolver's own retries could otherwise hold the sync past
		// the host's wait for it.
		vctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		ip, err := mirrorVetHost(vctx, u.Hostname())
		cancel()
		if err != nil {
			r["error"], failed = err.Error(), failed+1
			continue
		}
		pin := u.Hostname() + ":" + port + ":" + ip
		if strings.Contains(ip, ":") {
			pin = u.Hostname() + ":" + port + ":[" + ip + "]"
		}
		sum := sha256.Sum256([]byte(m.URL))
		repoDir := filepath.Join(cache, hex.EncodeToString(sum[:8])+".git")
		if _, err := os.Stat(repoDir); err != nil {
			if out, err := mirrorGit(time.Minute, nil, "init", "--bare", "--quiet", repoDir); err != nil {
				r["error"], failed = "cache init failed: "+truncate(out, 200), failed+1
				continue
			}
		}
		fetch := append(append([]string{}, mirrorGitSafe...), "-c", "http.curloptResolve="+pin,
			"-C", repoDir, "fetch", "--prune", "--no-tags", m.URL,
			"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
		if out, err := mirrorGit(10*time.Minute, nil, fetch...); err != nil {
			r["error"], failed = "fetch failed: "+truncate(out, 300), failed+1
			continue
		}
		// The push goes ONLY to the bridge, opened for this push and closed
		// after it: http is allowed for it and nothing else.
		pushBase, closeBridge, err := mirrorPushBridge(spec.ServiceName, rec.DataUID)
		if err != nil {
			r["error"], failed = "cannot open the local bridge to the server: "+err.Error(), failed+1
			continue
		}
		push := []string{"-c", "credential.helper=", "-c", "core.askPass=", "-c", "http.followRedirects=false",
			"-c", "protocol.allow=never", "-c", "protocol.http.allow=always",
			"-C", repoDir, "push", "--prune", pushBase + m.Repo + ".git",
			"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}
		out, err := mirrorGit(10*time.Minute, authEnv, push...)
		closeBridge()
		if err != nil {
			r["error"], failed = "push into the server failed: "+truncate(strings.ReplaceAll(out, spec.PushToken, "***"), 300), failed+1
			continue
		}
		r["ok"] = true
	}
	res["mirrors"] = results
	res["ok"] = failed == 0
	b, _ := json.Marshal(res)
	if failed > 0 {
		return b, 1
	}
	return b, 0
}
