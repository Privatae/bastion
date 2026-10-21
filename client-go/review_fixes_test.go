//go:build !windows

// Tagged !windows. These tests were ALREADY unix-only — they use
// helpers that live behind `//go:build !windows` (sessionShellsPath,
// withConfigDir, withMarkerAt, setupBox) — so this file has never compiled for
// Windows and `GOOS=windows go vet ./...` has been red on it since it was
// written. The tag removes no coverage; it states a dependency that was already
// there so vet can run clean on that target, which is what makes a REAL Windows
// regression visible instead of being lost in a failure everyone scrolls past.
// Windows-safe coverage of the machine-authority gate lives in privilege_test.go.

package main

// One test per blocking finding from the anchoring review, plus the notes.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func grantMember(t *testing.T, caps []string) {
	t.Helper()
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, caps, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("grant: %d %s", code, errOut)
	}
}

// The harness LANE is gated by caps, not only the mgmt op table. A member
// without "harness" gets a refused J frame + exit 126 before any job runs; the
// anchor and a member holding the cap reach the job (echo mode proves it ran).
func TestHarnessLaneGatedByCaps(t *testing.T) {
	grantMember(t, []string{"observe"})
	drive := func(self string) (string, int) {
		up := websocket.Upgrader{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer ws.Close()
			handleHarnessConn(ws, self, "")
		}))
		defer srv.Close()
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// On an anchored box the run spends the person's approval (writes.go);
		// testApproval signs one from a test device, "" on a local box.
		hs := harnessSpec{HarnessID: "h1", Mode: "echo", Prompt: "ping"}
		hs.Approval = testApproval(t, "harness:run", harnessArgs(hs))
		spec, _ := json.Marshal(hs)
		_ = c.WriteMessage(websocket.BinaryMessage, append([]byte("H"), spec...))
		var out string
		for {
			_, data, err := c.ReadMessage()
			if err != nil {
				t.Fatal(err)
			}
			switch data[0] {
			case 'J':
				out = string(data[1:])
			case 'X':
				var code int
				fmt.Sscanf(string(data[1:]), "%d", &code)
				return out, code
			}
		}
	}
	if out, code := drive(tMember); code != 126 || !contains(out, "caps") {
		t.Fatalf("a member without the harness cap must be refused on the lane: %d %s", code, out)
	}
	if out, code := drive(tAnchor); code != 0 || !contains(out, `"echo":"ping"`) {
		t.Fatalf("the anchor's harness lane must run the job: %d %s", code, out)
	}
	// a member WITH the cap runs the job
	writePairingState(t, tMember, pairingPending)
	priv := setupBoxKeep(t)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"harness"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("re-grant: %d %s", code, errOut)
	}
	if out, code := drive(tMember); code != 0 || !contains(out, `"echo":"ping"`) {
		t.Fatalf("a member with the harness cap must run the job: %d %s", code, out)
	}
}

// setupBoxKeep re-pins a fresh anchor signing key on an already-set-up box
// (the previous key is not kept by setupBox), by rewriting the pin directly.
func setupBoxKeep(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	f, err := loadAnchorFile()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.VerifyPubkey = base64.StdEncoding.EncodeToString(pub)
	if err := saveAnchorFile(f); err != nil {
		t.Fatal(err)
	}
	return priv
}

// The egress LANE is gated too: a member without "egress" gets a 403
// before any dial; the anchor's request is dialled.
func TestEgressLaneGatedByCaps(t *testing.T) {
	grantMember(t, []string{"observe"})
	dialed := false
	dialOut := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		return nil, fmt.Errorf("stop here")
	}
	drive := func(self string) string {
		srvSide, cliSide := net.Pipe()
		go handleEgressConn(srvSide, dialOut, self)
		_ = cliSide.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(cliSide, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		line, _ := bufio.NewReader(cliSide).ReadString('\n')
		cliSide.Close()
		return line
	}
	if line := drive(tMember); !contains(line, "403") || dialed {
		t.Fatalf("a member without the egress cap must get 403 and no dial: %q dialed=%v", line, dialed)
	}
	if line := drive(tAnchor); !dialed || contains(line, "403") {
		t.Fatalf("the anchor's egress must be dialled: %q dialed=%v", line, dialed)
	}
}

// A runtime save (endpoint rotation directive) after a drop must leave
// State=revoked on disk. The heartbeat goroutine's Config was loaded while the
// pairing was active; the rotate path may only touch the endpoint fields.
func TestRotateDirectiveAfterDropKeepsRevoked(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingActive)
	cfgs, _ := loadPairings()
	running := pairingFor(cfgs, tMember) // the daemon's stale copy: State active
	running.Endpoint, running.EndpointPubKey = "relay-a:51820", "pk"

	// another writer revokes it on disk
	disk := pairingFor(cfgs, tMember)
	*disk = *running
	disk.State = pairingRevoked
	if err := disk.save(); err != nil {
		t.Fatal(err)
	}
	// the host's rotate directive names the entry we are already on, with a
	// new candidate list: the "keep the list current" save path
	resp := []byte(`{"rotate_endpoint":{"endpoint":"relay-a:51820","endpoints":["relay-a:51820","relay-b:51820"],"endpoint_pubkey":"pk"}}`)
	maybeRotateEndpoint(resp, running, nil)

	if loadState(t, tMember) != pairingRevoked {
		t.Fatal("a rotate save clobbered State back to active")
	}
	after, _ := loadPairings()
	if got := pairingFor(after, tMember); len(got.Endpoints) != 2 {
		t.Fatalf("the endpoint list must still have been saved: %v", got.Endpoints)
	}
	if running.State != pairingRevoked {
		t.Fatal("updateOnDisk must refresh the in-memory State from disk")
	}
}

// The daemon follows the files: a running pairing whose file flips to
// revoked (or disappears) is stopped on the next supervise pass.
func TestSuperviseFollowsDiskState(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingActive)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { <-ctx.Done(); close(done) }()
	supervisor.Lock()
	supervisor.runs = map[string]*pairingRun{tMember: {cancel: cancel, done: done}}
	supervisor.Unlock()
	t.Cleanup(func() {
		supervisor.Lock()
		supervisor.runs = nil
		supervisor.Unlock()
	})
	superviseOnce()
	if ctx.Err() != nil {
		t.Fatal("an active pairing must not be stopped")
	}
	writePairingState(t, tMember, pairingPending)
	superviseOnce()
	if ctx.Err() == nil {
		t.Fatal("a pairing flipped to pending on disk must be stopped")
	}
}

// A revoked host presenting a fresh token becomes PENDING (a new request
// for the anchor), and unpair removes the files.
func TestReplaceRevokedBecomesPendingAndUnpair(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingRevoked)
	cfgs, _ := loadPairings()
	_, st, err := pairPrecheck(cfgs, "member", true, false)
	if err != nil || st != pairingPending {
		t.Fatalf("--replace on a revoked pairing must write pending: %q %v", st, err)
	}

	// unpair: networked mode needs root — asserted through the seam so it holds
	// whatever euid the suite runs under
	if err := savePairingGrant(tMember, &pairingGrantFile{TermsCanonical: "x", Signature: "y"}); err != nil {
		t.Fatal(err)
	}
	prevSeam := unpairNeedsRoot
	t.Cleanup(func() { unpairNeedsRoot = prevSeam })
	unpairNeedsRoot = func() bool { return true }
	if _, err := unpairHost(tMember); err == nil || !contains(err.Error(), "root") {
		t.Fatalf("unpair on a networked box must need root: %v", err)
	}
	// the real predicate: networked + non-root is exactly the refusing case
	if got := prevSeam(); got != (os.Geteuid() != 0) {
		t.Fatalf("unpairNeedsRoot on a networked box must be (euid != 0), got %v", got)
	}
	unpairNeedsRoot = func() bool { return false }
	// the anchor is refused with the anchor present
	if _, err := unpairHost(tAnchor); err == nil || !contains(err.Error(), "anchor") {
		t.Fatalf("the anchor must not be unpairable: %v", err)
	}
	if currentAnchor() == nil {
		t.Fatal("a refused unpair must not have touched the anchor")
	}
	host, err := unpairHost("member")
	if err != nil || host != tMember {
		t.Fatalf("unpair: %v", err)
	}
	pd, _ := pairingsDir()
	for _, f := range []string{tMember + ".json", tMember + pairingGrantSuffix} {
		if _, err := os.Stat(filepath.Join(pd, f)); err == nil {
			t.Fatalf("unpair must delete %s", f)
		}
	}
	if _, err := unpairHost("member"); err == nil {
		t.Fatal("unpairing an unknown host must fail")
	}
}

// A runtime save must never recreate an unpaired host's file. Delete the
// file under a running pairing's copy; saveEndpoints must fail and leave the
// file absent (a rotate/failover save inside the 15 s supervise window used to
// bring the host back with State active).
func TestRuntimeSaveNeverRecreatesAPairingFile(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingActive)
	cfgs, _ := loadPairings()
	running := pairingFor(cfgs, tMember)
	pd, _ := pairingsDir()
	p := filepath.Join(pd, tMember+".json")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	running.Endpoints = []string{"relay-a:51820"}
	if err := running.saveEndpoints(); err != errPairingGone {
		t.Fatalf("saveEndpoints on a gone file must return errPairingGone, got %v", err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("a runtime save recreated an unpaired host's file")
	}
	// the same through the handler path
	if _, err := updatePairingOnDisk(tMember, func(d *Config) { d.State = pairingActive }); err != errPairingGone {
		t.Fatalf("updatePairingOnDisk on a gone file must refuse: %v", err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("updatePairingOnDisk recreated the file")
	}
}

// A pairing write goes through atomicWrite: no temp file is left behind
// and the file is whole; the lock file exists after any locked write.
func TestPairingSaveIsAtomicAndLocked(t *testing.T) {
	setupBox(t)
	c := &Config{HostName: tMember, State: pairingPending}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	pd, _ := pairingsDir()
	ents, _ := os.ReadDir(pd)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	cd, _ := configDir()
	if _, err := os.Stat(filepath.Join(cd, "pairings.lock")); err != nil {
		t.Fatal("a locked write must have created pairings.lock")
	}
	if loadState(t, tMember) != pairingPending {
		t.Fatal("the written file must read back whole")
	}
}

// On an anchored box an empty lane identity is default-deny; on an
// unanchored box nothing is gated.
func TestCapsAllowEmptySelfIsDefaultDenyWhenAnchored(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if why := capsAllow("", "egress"); why != "" {
		t.Fatalf("an unanchored box gates nothing: %s", why)
	}
	setupBox(t)
	if why := capsAllow("", "egress"); why == "" {
		t.Fatal("an empty self on an anchored box must be refused")
	}
}

// Notes — the two claims share a key and must not share a byte space; names
// with a newline are refused everywhere a claim is written.
func TestSigningInputsAreDomainSeparatedAndNewlinesRefused(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if string(ownerSigningInput("x\nhost", "t")) == string(anchorSigningInput("x", "host", "t")) {
		t.Fatal("owner and anchor signing inputs collide")
	}
	if !strings.HasPrefix(string(ownerSigningInput("a", "t")), "owner\n") ||
		!strings.HasPrefix(string(anchorSigningInput("a", "h", "t")), "anchor\n") {
		t.Fatal("signing inputs must carry a kind tag")
	}
	for _, bad := range []string{"", "a\nb", "a\rb", strings.Repeat("x", 121)} {
		if _, err := writeOwnerClaim(bad); err == nil {
			t.Errorf("owner name %q must be refused", bad)
		}
		if err := writeAnchor(bad, tAnchor); err == nil {
			t.Errorf("anchor owner %q must be refused", bad)
		}
	}
	if err := writeAnchor("ok", "not/a/host"); err == nil {
		t.Error("an invalid anchor host must be refused")
	}
}

// Notes — peers carry their state so a pending host never shows as an
// established peer; since is first_seen and survives --replace.
func TestPeersCarryStateAndFirstSeen(t *testing.T) {
	setupBox(t)
	writePairingState(t, tMember, pairingPending)
	peers := peersFor(tAnchor)
	if len(peers) != 1 || peers[0].State != pairingPending {
		t.Fatalf("a pending peer must announce its state: %+v", peers)
	}
	raw, _ := json.Marshal(peers)
	if !contains(string(raw), `"state":"pending"`) {
		t.Fatalf("state must be on the wire: %s", raw)
	}
	// first_seen wins over mtime and is kept by --replace
	cfgs, _ := loadPairings()
	m := pairingFor(cfgs, tMember)
	m.FirstSeen = "2026-01-01T00:00:00Z"
	_ = m.save()
	if got := sinceOf(m); got != "2026-01-01T00:00:00Z" {
		t.Fatalf("since must be first_seen: %s", got)
	}
	if e := pairingsReport(); e[1].Since != "2026-01-01T00:00:00Z" {
		t.Fatalf("pairings report must use first_seen: %+v", e)
	}
	cfgs, _ = loadPairings()
	existing, _, _ := pairPrecheck(cfgs, "member", true, false)
	if existing.FirstSeen != "2026-01-01T00:00:00Z" {
		t.Fatal("the existing pairing handed to --replace must carry first_seen for pairWithToken to keep")
	}
}
