//go:build !windows

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMirrorSourceRefusal(t *testing.T) {
	ok := mirrorSource{URL: "https://github.com/pallets/flask.git", Repo: "mirrors/flask"}
	if why := mirrorSourceRefusal(ok); why != "" {
		t.Fatalf("a plain https repo is fine: %s", why)
	}
	for label, m := range map[string]mirrorSource{
		"http":        {URL: "http://github.com/a/b", Repo: "m/b"},
		"file":        {URL: "file:///srv/repo", Repo: "m/b"},
		"ssh":         {URL: "ssh://git@github.com/a/b", Repo: "m/b"},
		"userinfo":    {URL: "https://user:pw@github.com/a/b", Repo: "m/b"},
		"query":       {URL: "https://github.com/a/b?x=1", Repo: "m/b"},
		"no path":     {URL: "https://github.com/", Repo: "m/b"},
		"comma":       {URL: "https://github.com/a/b,c", Repo: "m/b"},
		"repo no /":   {URL: "https://github.com/a/b", Repo: "flask"},
		"repo dotdot": {URL: "https://github.com/a/b", Repo: "m/..x"},
		"repo pipe":   {URL: "https://github.com/a/b", Repo: "m/b|c"},
	} {
		if mirrorSourceRefusal(m) == "" {
			t.Errorf("%s must be refused", label)
		}
	}
}

// Every address must be public; git is pinned to a vetted one.
func TestMirrorVetHost(t *testing.T) {
	old := mirrorResolve
	defer func() { mirrorResolve = old }()
	answers := map[string][]net.IP{
		"github.com": {net.ParseIP("140.82.112.3")},
		"evil.test":  {net.ParseIP("8.8.8.8"), net.ParseIP("192.168.1.10")},
		"loop.test":  {net.ParseIP("127.0.0.1")},
		"cgnat.test": {net.ParseIP("100.64.0.9")},
		"nat64.test": {net.ParseIP("64:ff9b::a00:1")},
		"v6ula.test": {net.ParseIP("fd12:3456::1")},
	}
	mirrorResolve = func(ctx context.Context, h string) ([]net.IP, error) { return answers[h], nil }
	if ip, err := mirrorVetHost(context.Background(), "github.com"); err != nil || ip != "140.82.112.3" {
		t.Fatalf("a public host is pinned to its address: %q %v", ip, err)
	}
	for _, h := range []string{"evil.test", "loop.test", "cgnat.test", "nat64.test", "v6ula.test", "localhost", "10.0.0.1", "nowhere.test"} {
		if _, err := mirrorVetHost(context.Background(), h); err == nil {
			t.Errorf("%s must be refused", h)
		}
	}
}

// The purpose is the 0.36.0 string when there are no mirrors, and binds the
// mirror list (sorted) when there are — the host pins the same strings.
func TestReachPurposeWithMirrors(t *testing.T) {
	base := &reachTerms{Server: "box1", Slot: "forge", Subject: "h.example", TTLDays: 30}
	if p, _ := purposeForReach(base); p != "service_reach_grant|box1|forge|h.example|ttl:30" {
		t.Fatalf("no mirrors: unchanged, got %q", p)
	}
	base.Mirrors = []mirrorSource{
		{URL: "https://github.com/psf/requests.git", Repo: "mirrors/requests"},
		{URL: "https://github.com/pallets/flask.git", Repo: "mirrors/flask"},
	}
	want := "service_reach_grant|box1|forge|h.example|ttl:30|mirrors:" +
		"https://github.com/pallets/flask.git>mirrors/flask,https://github.com/psf/requests.git>mirrors/requests"
	if p, err := purposeForReach(base); err != nil || p != want {
		t.Fatalf("mirrors bound, sorted:\n got  %q\n want %q (%v)", p, want, err)
	}
	if p, _ := purposeFromDetails(map[string]any{"kind": reachKind, "server": "box1", "slot": "forge",
		"subject": "h.example", "ttl_days": float64(30), "mirrors": []any{
			map[string]any{"url": "https://github.com/pallets/flask.git", "repo": "mirrors/flask"},
			map[string]any{"url": "https://github.com/psf/requests.git", "repo": "mirrors/requests"}}}); p != want {
		t.Fatalf("the words the person reads build the same purpose: %q", p)
	}
}

type gitCall struct {
	env  []string
	args []string
}

// A sync, end to end with git and DNS stubbed and a real socket standing in for
// the server: the fetch is pinned to the vetted address, the push goes only to
// the loopback bridge, the token never appears in argv, an internal upstream is
// refused while the others sync, and only the granted host may run it.
func TestServiceMirrorSync(t *testing.T) {
	setupBox(t)
	stubServiceRuntime(t, "docker")
	oldGit, oldRes, oldFound := mirrorGit, mirrorResolve, mirrorGitUsable
	defer func() { mirrorGit, mirrorResolve, mirrorGitUsable = oldGit, oldRes, oldFound }()
	mirrorGitUsable = func() string { return "" }
	mirrorResolve = func(ctx context.Context, h string) ([]net.IP, error) {
		if h == "inside.test" {
			return []net.IP{net.ParseIP("192.168.1.5")}, nil
		}
		return []net.IP{net.ParseIP("140.82.112.3")}, nil
	}
	var mu sync.Mutex
	var calls []gitCall
	mirrorGit = func(d time.Duration, env []string, args ...string) (string, error) {
		mu.Lock()
		calls = append(calls, gitCall{env: env, args: args})
		mu.Unlock()
		return "", nil
	}

	spec := forgeSpec("forge")
	spec.owner = tAnchor
	if b, code := runService(spec); code != 0 {
		t.Fatalf("up: %s", b)
	}
	data, _ := serviceDataDir("forge")
	ln, err := net.Listen("unix", filepath.Join(data, "gitea.sock"))
	if err != nil {
		t.Skip("no unix sockets here")
	}
	defer ln.Close()

	cfgs, _ := loadPairings()
	var dir string
	for _, c := range cfgs {
		if c.HostName == tAnchor {
			dir = c.dcnDir()
		}
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	put := func(terms map[string]any) {
		tc, sig := signedTerms(t, priv, terms)
		if err := dcnSaveFile(dir, &dcnGrantFile{VerifyPubkey: pub, Stores: map[string]dcnGrantRec{},
			Reach: map[string]dcnGrantRec{"1": {TermsCanonical: tc, Signature: sig}}}); err != nil {
			t.Fatal(err)
		}
	}
	job := harnessSpec{Mode: "service", ServiceOp: "mirror", ServiceName: "forge", PushToken: "SECRET-TOKEN",
		owner: tAnchor, dcnDir: dir}

	// No grant: refused.
	put(reachTermsFor(tMember, "forge", 30))
	if b, code := runService(job); code == 0 || !strings.Contains(string(b), "no reach grant") {
		t.Fatalf("another host's grant does not let this one sync: %s", b)
	}
	// A grant with no mirrors: refused.
	put(reachTermsFor(tAnchor, "forge", 30))
	if b, code := runService(job); code == 0 || !strings.Contains(string(b), "no mirror sources") {
		t.Fatalf("nothing approved to fetch: %s", b)
	}

	// Two public sources and one that resolves inside the network.
	terms := reachTermsFor(tAnchor, "forge", 30)
	terms["mirrors"] = []map[string]any{
		{"url": "https://github.com/pallets/flask.git", "repo": "mirrors/flask"},
		{"url": "https://inside.test/secret/repo.git", "repo": "mirrors/secret"},
		{"url": "https://github.com/psf/requests.git", "repo": "mirrors/requests"},
	}
	put(terms)
	calls = nil
	b, code := runService(job)
	if code == 0 || !strings.Contains(string(b), "public internet only") {
		t.Fatalf("the internal upstream must fail the sync with its reason: %s", b)
	}
	res := decodeRes(t, b)
	oks := 0
	for _, r := range res["mirrors"].([]any) {
		if m := r.(map[string]any); m["ok"] == true {
			oks++
		}
	}
	if oks != 2 {
		t.Fatalf("the two public sources still sync: %s", b)
	}
	var fetches, pushes int
	for _, c := range calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "SECRET-TOKEN") {
			t.Fatalf("the token must never be on the command line: %s", joined)
		}
		if strings.Contains(joined, "inside.test") && strings.Contains(joined, " fetch ") {
			t.Fatalf("the internal upstream must never be fetched: %s", joined)
		}
		switch {
		case strings.Contains(joined, " fetch "):
			fetches++
			if !strings.Contains(joined, "http.curloptResolve=github.com:443:140.82.112.3") ||
				!strings.Contains(joined, "protocol.allow=never") || !strings.Contains(joined, "protocol.https.allow=always") ||
				!strings.Contains(joined, "http.followRedirects=false") {
				t.Fatalf("a fetch must be pinned and locked down: %s", joined)
			}
		case strings.Contains(joined, " push "):
			pushes++
			if !strings.Contains(joined, "http://127.0.0.1:") || strings.Contains(joined, "protocol.https.allow") {
				t.Fatalf("a push goes only to the loopback bridge: %s", joined)
			}
			if !strings.Contains(strings.Join(c.env, "\n"), "Authorization: token SECRET-TOKEN") {
				t.Fatal("the push carries the token in its environment")
			}
		}
	}
	if fetches != 2 || pushes != 2 {
		t.Fatalf("two fetches and two pushes, got %d / %d", fetches, pushes)
	}
	// The cache is the bastion's, not inside the server's data dir.
	if _, err := os.Stat(filepath.Join(data, "mirror-cache")); err == nil {
		t.Fatal("the mirror cache must not be inside the server's data dir")
	}
}

func TestGitVersionRefusal(t *testing.T) {
	for out, ok := range map[string]bool{
		"git version 2.37.0\n":               true,
		"git version 2.43.0":                 true,
		"git version 2.39.5 (Apple Git-154)": true,
		"git version 3.0.1":                  true,
		"git version 2.36.6":                 false,
		"git version 1.9.9":                  false,
		"not git at all":                     false,
	} {
		if got := gitVersionRefusal(out) == ""; got != ok {
			t.Errorf("%q: usable=%v, want %v", out, got, ok)
		}
	}
}

// Entries are visible ASCII only, and no two sources may land in one repo.
func TestMirrorListRefusal(t *testing.T) {
	good := []mirrorSource{
		{URL: "https://github.com/pallets/flask.git", Repo: "mirrors/flask"},
		{URL: "https://github.com/psf/requests.git", Repo: "mirrors/requests"},
	}
	if why := mirrorListRefusal(good); why != "" {
		t.Fatalf("a clean list is fine: %s", why)
	}
	for label, ms := range map[string][]mirrorSource{
		"space":        {{URL: "https://github.com/a/b c", Repo: "m/b"}},
		"tab":          {{URL: "https://github.com/a/b", Repo: "m/\tb"}},
		"unicode":      {{URL: "https://gíthub.com/a/b", Repo: "m/b"}},
		"rtl override": {{URL: "https://github.com/a/\u202eb", Repo: "m/b"}},
		"duplicate":    {good[0], {URL: "https://github.com/x/flask.git", Repo: "mirrors/flask"}},
		"dup any case": {good[0], {URL: "https://github.com/x/flask.git", Repo: "Mirrors/Flask"}},
	} {
		if mirrorListRefusal(ms) == "" {
			t.Errorf("%s must be refused", label)
		}
	}
	// A grant carrying a bad list does not verify, and no purpose is built for it.
	if _, err := purposeForReach(&reachTerms{Server: "b", Slot: "s", Subject: "h", TTLDays: 1,
		Mirrors: []mirrorSource{good[0], good[0]}}); err == nil {
		t.Fatal("a duplicate destination must not produce a purpose")
	}
}

func TestInternalIPRanges(t *testing.T) {
	for _, s := range []string{"0.1.2.3", "198.18.0.1", "198.19.255.1", "240.0.0.1", "255.255.255.254",
		"64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::a00:1", "64:ff9b:1::8c52:7003", "2002:a00:1::1", "2002:c0a8:101::1", "100.64.0.1", "::ffff:10.0.0.1"} {
		if !internalIP(net.ParseIP(s)) {
			t.Errorf("%s must be internal", s)
		}
	}
	// NAT64 and 6to4 are judged by the IPv4 inside them: a public one is public.
	for _, s := range []string{"140.82.112.3", "198.20.0.1", "8.8.8.8", "2606:4700::1111",
		"64:ff9b::8c52:7003", "2002:8c52:7003::1"} {
		if internalIP(net.ParseIP(s)) {
			t.Errorf("%s is public", s)
		}
	}
}

// The push bridge answers only its random path, strips it before the server
// sees the request, and refuses a socket answered by any uid but the server's.
func TestMirrorPushBridge(t *testing.T) {
	setupBox(t)
	stubServiceRuntime(t, "docker")
	if b, code := runService(forgeSpec("forge")); code != 0 {
		t.Fatalf("up: %s", b)
	}
	data, _ := serviceDataDir("forge")
	ln, err := net.Listen("unix", filepath.Join(data, "gitea.sock"))
	if err != nil {
		t.Skip("no unix sockets here")
	}
	defer ln.Close()
	var mu sync.Mutex
	var seen []string
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		_, _ = w.Write([]byte("server"))
	}))
	get := func(u string) int {
		resp, err := http.Get(u)
		if err != nil {
			return -1
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The server runs as uid 1000 by its record; this test's socket is answered
	// by our own uid, so the bridge must refuse to carry anything to it.
	base, closeBridge, err := mirrorPushBridge("forge", 1000)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	root := "http://" + u.Host
	if code := get(root + "/mirrors/flask.git/info/refs"); code != http.StatusNotFound {
		t.Fatalf("a path outside the random prefix gets 404, got %d", code)
	}
	if code := get(root + u.Path[:len(u.Path)-2] + "/x"); code != http.StatusNotFound {
		t.Fatalf("a near-miss prefix gets 404, got %d", code)
	}
	if code := get(base + "mirrors/flask.git/info/refs"); code != http.StatusBadGateway {
		t.Fatalf("a socket answered by the wrong uid is refused, got %d", code)
	}
	closeBridge()
	if code := get(base + "x"); code != -1 {
		t.Fatalf("the bridge is gone after its push, got %d", code)
	}
	mu.Lock()
	if len(seen) != 0 {
		t.Fatalf("nothing may have reached the server: %v", seen)
	}
	mu.Unlock()

	// With the uid that really answers, the request arrives with the prefix gone.
	if os.Getuid() < 1 {
		t.Log("running as uid 0: the forwarding half is covered by the opt-in e2e run")
		return
	}
	base, closeBridge, err = mirrorPushBridge("forge", os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridge()
	if code := get(base + "mirrors/flask.git/info/refs"); code != 200 {
		t.Fatalf("the granted path is forwarded, got %d", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "/mirrors/flask.git/info/refs" {
		t.Fatalf("the server sees the path without the prefix: %v", seen)
	}
}

// The host (service_reach.py) runs the SAME vectors, from a copy of this file:
// both sides must accept exactly the same mirror URLs.
func TestMirrorURLVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/mirror_url_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		URL string `json:"url"`
		OK  bool   `json:"ok"`
	}
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		got := mirrorSourceRefusal(mirrorSource{URL: v.URL, Repo: "m/b"}) == ""
		if got != v.OK {
			t.Errorf("%q: accepted=%v, want %v", v.URL, got, v.OK)
		}
	}
}
