package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A save-by-DIGEST tarball has RepoTags null, so `docker load` produces an
// UNTAGGED image and the `image inspect image:tag` idempotence check misses
// forever — which meant re-downloading ~600MB every poll on someone's home
// line. Recovery depends on reading the ID out of load's output, so that parse
// is pinned here. (Measured: save-by-digest -> RepoTags [None].)
func TestParseLoadedImageID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Loaded image ID: sha256:6454e81731e1\n", "sha256:6454e81731e1"},
		{"noise\nLoaded image ID: sha256:abc123\nmore\n", "sha256:abc123"},
		{"  Loaded image ID: sha256:deadbeef  ", "sha256:deadbeef"},
		// Tagged load: nothing to recover, the inspect above it already passed.
		{"Loaded image: forge.example.com/acme/db:v0.1.1\n", ""},
		{"", ""},
		{"Error processing tar file", ""},
	}
	for _, c := range cases {
		if got := parseLoadedImageID(c.in); got != c.want {
			t.Errorf("parseLoadedImageID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The forwarder reaches the user's memory: anything that can connect to it can
// run BASE_BACKUP. The mirror gets its own network so only its own containers
// can route there, and this is the second wall behind that.
func TestMirrorPeerAllowed(t *testing.T) {
	_, subnet, err := net.ParseCIDR("172.31.7.0/24")
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		addr  string
		allow *net.IPNet
		want  bool
	}
	for _, c := range []tc{
		{"172.31.7.5:40000", subnet, true},    // the replica, on the private net
		{"127.0.0.1:40000", subnet, true},     // the host itself, diagnostics
		{"[::1]:40000", subnet, true},         // ditto, v6 loopback
		{"172.17.0.9:40000", subnet, false},   // a container on the DEFAULT bridge
		{"192.168.1.50:40000", subnet, false}, // something on the user's LAN
		{"172.31.7.5:40000", nil, false},      // unknown subnet -> refuse, never widen
		{"garbage", subnet, false},
	} {
		got := mirrorPeerAllowed(fakeAddr(c.addr), c.allow)
		if got != c.want {
			t.Errorf("mirrorPeerAllowed(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }

// A failure the next identical attempt cannot fix must back OFF. Without this
// the manager retried a multi-hundred-megabyte download every 60s forever.
func TestNextBackoffGrowsAndCaps(t *testing.T) {
	d := nextBackoff(0)
	if d != mirrorPollInterval {
		t.Fatalf("first backoff = %v, want %v", d, mirrorPollInterval)
	}
	prev := d
	for i := 0; i < 20; i++ {
		d = nextBackoff(d)
		if d < prev {
			t.Fatalf("backoff shrank: %v -> %v", prev, d)
		}
		prev = d
	}
	if d != mirrorBackoffMax {
		t.Fatalf("backoff settled at %v, want cap %v", d, mirrorBackoffMax)
	}
	if mirrorBackoffMax < 10*time.Minute {
		t.Fatalf("cap %v is too small to stop a download loop", mirrorBackoffMax)
	}
}

// One daemon serves several hosts. Reports must not leak across pairings, or a
// heartbeat reports another host's replica — and "absent" must mean "send no
// field", not "send an empty one".
func TestMirrorReportsArePerHost(t *testing.T) {
	mirrorMu.Lock()
	mirrorReports = map[string]mirrorReport{}
	mirrorMu.Unlock()

	if r := currentMirrorReport("a.example"); r != nil {
		t.Fatalf("unknown host should report nil, got %+v", r)
	}
	setMirrorReport("a.example", mirrorReport{State: "running", ImageTag: "v1"})
	setMirrorReport("b.example", mirrorReport{State: "failed", ImageTag: "v2"})

	a, b := currentMirrorReport("a.example"), currentMirrorReport("b.example")
	if a == nil || a.ImageTag != "v1" || a.State != "running" {
		t.Fatalf("host a report wrong: %+v", a)
	}
	if b == nil || b.ImageTag != "v2" || b.State != "failed" {
		t.Fatalf("host b report wrong: %+v", b)
	}
	setMirrorReport("a.example", mirrorReport{State: "absent"})
	if r := currentMirrorReport("a.example"); r != nil {
		t.Fatalf("absent must yield nil (no heartbeat field), got %+v", r)
	}
	if r := currentMirrorReport("b.example"); r == nil || r.ImageTag != "v2" {
		t.Fatalf("clearing host a disturbed host b: %+v", r)
	}
	// The returned value is a copy — a caller must not be able to mutate the
	// stored report through it.
	c := currentMirrorReport("b.example")
	c.ImageTag = "tampered"
	if again := currentMirrorReport("b.example"); again.ImageTag != "v2" {
		t.Fatalf("report is not copied on read: %+v", again)
	}
}

// docker and podman disagree on the shape of `network inspect`, and a template
// written for one returns EMPTY on the other — worse than an error, because by
// then the capability is advertised and the failure reads as an unexplained
// refusal. Both shapes are pinned.
func TestParseNetworkInspectBothRuntimes(t *testing.T) {
	docker := `[{"Name":"privatae-mirror-net-x","IPAM":{"Driver":"default",
	  "Config":[{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"}]}}]`
	podman := `[{"name":"privatae-mirror-net-x","driver":"bridge",
	  "subnets":[{"subnet":"10.89.1.0/24","gateway":"10.89.1.1"}]}]`
	for _, c := range []struct{ label, in, gw, sub string }{
		{"docker", docker, "172.19.0.1", "172.19.0.0/16"},
		{"podman", podman, "10.89.1.1", "10.89.1.0/24"},
	} {
		gw, sub, err := parseNetworkInspect(c.in)
		if err != nil || gw != c.gw || sub != c.sub {
			t.Errorf("%s: got (%q,%q,%v), want (%q,%q,nil)", c.label, gw, sub, err, c.gw, c.sub)
		}
	}
	// An IPv6-only or empty network must ERROR, not return "" — an empty subnet
	// would leave mirrorPeerAllowed with nothing to check and it refuses then,
	// but surfacing the cause here is what makes that debuggable.
	for _, bad := range []string{`[]`, `[{"IPAM":{"Config":[]}}]`, `not json`,
		`[{"subnets":[{"subnet":"fd00::/64","gateway":"fd00::1"}]}]`} {
		if _, _, err := parseNetworkInspect(bad); err == nil {
			t.Errorf("parseNetworkInspect(%q) should have errored", bad)
		}
	}
}

// A reseed must never leave the user with NO copy. The base backup that
// replaces it runs over a home connection and can fail; deleting first would
// mean a window with nothing, which is the one thing this feature promises
// against.
func TestRetireAndPromoteNeverLoseTheOnlyCopy(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "pgdata")
	if err := os.MkdirAll(cur, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(cur, "PG_VERSION")
	if err := os.WriteFile(marker, []byte("17"), 0o600); err != nil {
		t.Fatal(err)
	}

	// retireCopy moves aside; it must NOT delete.
	retireCopy("", "host.example", dir)
	if _, err := os.Stat(cur); !os.IsNotExist(err) {
		t.Fatalf("pgdata should have been moved aside, still present")
	}
	prev := filepath.Join(dir, "pgdata.previous", "PG_VERSION")
	if b, err := os.ReadFile(prev); err != nil || string(b) != "17" {
		t.Fatalf("the old copy must survive retirement, got %v/%q", err, b)
	}

	// A seed that never completes leaves the retired copy intact.
	staging := filepath.Join(dir, "pgdata.new")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("retired copy vanished while a seed was in flight: %v", err)
	}

	// promoteSeed swaps the finished seed in and only then drops the old one.
	if err := os.WriteFile(filepath.Join(staging, "PG_VERSION"), []byte("17"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := promoteSeed(dir); err != nil {
		t.Fatalf("promoteSeed: %v", err)
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "17" {
		t.Fatalf("promoted copy not in place: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pgdata.previous")); !os.IsNotExist(err) {
		t.Fatalf("previous copy should be dropped only AFTER a successful promote")
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging dir should be gone after promote")
	}
}

// Container and network names go into runtime CLI arguments; a host handle is
// attacker-influenceable only by the platform, but the sanitiser is what keeps
// them valid identifiers rather than shell-adjacent surprises.
func TestNamesAreSanitised(t *testing.T) {
	for _, in := range []string{"a b", "a/b", "a;rm -rf /", "a$(x)", "üñî"} {
		cn, nn := mirrorContainerName(in), mirrorNetName(in)
		for _, s := range []string{cn, nn} {
			for _, r := range s {
				ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
					(r >= '0' && r <= '9') || r == '-' || r == '_'
				if !ok {
					t.Fatalf("name %q from %q contains %q", s, in, r)
				}
			}
		}
		if cn == mirrorContainerPrefix || nn == mirrorNetPrefix {
			t.Fatalf("name for %q collapsed to the bare prefix", in)
		}
	}
}
