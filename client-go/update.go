package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Self-update. The host directs an update via the heartbeat RESPONSE
// ({"update":{"version":X}}); the bastion fetches the published manifest, downloads its own
// platform's binary, verifies the sha256, atomically swaps its own executable, and exits —
// systemd's Restart=always brings it back on the new binary.
//
// Trust: the directive rides the authenticated mTLS heartbeat from the bastion's OWN host, so the
// platform can't push code unilaterally — only the user's host can direct it — the manifest must
// carry a valid release signature (release_sign.go), and the binary is checked against the
// digest in that signed manifest. FAIL-CLOSED: any error (bad manifest, download failure, sha256 mismatch) aborts
// WITHOUT swapping, so the bastion stays on the working binary. A .bak rollback copy is kept.

// manifestURL is a var so a test can prove a refused directive never fetches.
var manifestURL = "https://privatae.ai/bastion/version.json"

type updateManifest struct {
	Version  string `json:"version"`
	Binaries map[string]struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"binaries"`
}

// parseUpdateTarget extracts the host's requested target version from a heartbeat response, or "".
func parseUpdateTarget(body []byte) string {
	var hb struct {
		Update *struct {
			Version string `json:"version"`
		} `json:"update"`
	}
	if json.Unmarshal(body, &hb) != nil || hb.Update == nil {
		return ""
	}
	return hb.Update.Version
}

// selfUpdateMu makes the update a process singleton: with multi-homing (0.10.0)
// EVERY paired host's heartbeat can direct an update concurrently, and two
// goroutines racing replaceSelf would clobber the binary mid-swap. One attempt at
// a time — a successful swap exits the process, a failed one may retry on a later
// beat (same semantics as before, just serialized).
var selfUpdateMu sync.Mutex

// self is the pairing whose heartbeat carried the directive. The binary is
// shared by every pairing on the box, so on an anchored machine only the
// anchor host may direct a swap (anchor.go anchorOnly); a member host's
// directive is logged and ignored. An unanchored LOCAL box keeps the old
// behaviour; an unanchored NETWORKED one refuses the swap outright (0.24.0),
// before any fetch or disk write.
func maybeSelfUpdate(self, dcnDir string, heartbeatResponse []byte) {
	target := parseUpdateTarget(heartbeatResponse)
	if target == "" || target == clientVersion {
		return
	}
	// directiveGate (writes.go): anchor-only, then the person's local switch,
	// then — on an anchored box — an approval bound to THIS target version.
	// A binary swap is the one write that can change every rule after it, so
	// it is the last thing that should run on a host's word alone.
	//
	// A move to a NEWER version skips only the approval (0.44.0). What approves
	// it is the release signature, made on the key holder's own computer:
	// fetchManifest below refuses a manifest that does not verify, and the swap
	// happens only when the manifest names exactly this target, so the one
	// thing that gets past without an approval is a newer signed release. That
	// is the rule the agent has always updated under. A move to an older
	// version, or to one that cannot be compared with this one ("dev", a
	// suffix), still needs the approval: a signature shows that a release was
	// published once, not that it is the latest.
	var why string
	if versionNewer(target, clientVersion) {
		why = directiveWalls(self, directiveSelfUpdate)
	} else {
		why = directiveGate(self, dcnDir, directiveSelfUpdate, []string{target},
			directiveApproval(heartbeatResponse, directiveSelfUpdate))
	}
	if why != "" {
		fmt.Printf("self-update: %s\n", why)
		// Tell the HOST, not just this box's log: it asked for a version and is
		// otherwise left watching a number that never changes.
		recordDirectiveRefusal("self-update", why)
		return
	}
	clearDirectiveRefusal("self-update")
	selfUpdateMu.Lock()
	defer selfUpdateMu.Unlock()
	m, err := fetchManifest()
	if err != nil {
		fmt.Printf("self-update: manifest fetch failed (%v), staying on %s\n", err, clientVersion)
		return
	}
	// The six-hourly check is not the only place this is learned. A directed
	// update reads the same manifest, and its answer is fresher than anything
	// the poll holds. It matters most on the mismatch path immediately below,
	// where this process does NOT exit: the host asked for a version the
	// manifest does not carry, and the page is then the only thing that can say
	// what is actually published.
	recordLatestPublished(m.Version)
	if m.Version != target {
		fmt.Printf("self-update: manifest is %s but host asked for %s, skipping\n", m.Version, target)
		return
	}
	key := runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		key += ".exe"
	}
	b, ok := m.Binaries[key]
	if !ok {
		fmt.Printf("self-update: manifest has no binary for %s, skipping\n", key)
		return
	}
	data, err := download(b.URL)
	if err != nil {
		fmt.Printf("self-update: download failed (%v), staying on %s\n", err, clientVersion)
		return
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != b.SHA256 {
		fmt.Printf("self-update: sha256 mismatch for %s, aborting (staying on %s)\n", key, clientVersion)
		return
	}
	if err := replaceSelf(data); err != nil {
		fmt.Printf("self-update: swap failed (%v), staying on %s\n", err, clientVersion)
		return
	}
	fmt.Printf("self-update: %s -> %s applied, restarting\n", clientVersion, target)
	// On Linux this is the whole restart: systemd Restart=always re-execs the
	// path, now the new binary, and launchd's KeepAlive does the same for the
	// macOS daemon. An ordinary Windows install has no supervisor, so
	// relaunchAfterUpdate starts the replacement itself — without it the update
	// was a clean shutdown and the machine went dark (relaunch_windows.go carries
	// the measurement). As a Windows service it starts nothing, and the service
	// manager restarts it (sysservice_windows.go).
	relaunchAfterUpdate()
	os.Exit(0)
}

// resolvedSelf is the on-disk path of THIS running binary, symlinks resolved.
func resolvedSelf() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, e := filepath.EvalSymlinks(self); e == nil {
		self = resolved
	}
	return self, nil
}

// replaceSelf swaps the running executable for `data`, cross-platform.
//
// The old code wrote a temp file and os.Rename'd it OVER the running binary. That
// works on Linux/macOS but FAILS on Windows: a running .exe image is locked, so you
// can neither overwrite nor delete it — the rename returns Access Denied and the
// update silently no-ops (every Windows bastion stayed on its old version forever).
// Windows CAN, however, RENAME a running image. So move the current binary aside to
// <self>.old, then write the new one at the original path. Same path works on Linux/
// macOS. The .old copy is the rollback; cleanupStaleBinaries removes it on next start
// (a running binary can't delete itself, so cleanup waits for the restart).
func replaceSelf(data []byte) error {
	self, err := resolvedSelf()
	if err != nil {
		return err
	}
	return swapBinaryAt(self, data)
}

// swapBinaryAt is the testable core of replaceSelf: move `path` aside to path.old,
// then write `data` at `path`. Roll back on write failure.
func swapBinaryAt(path string, data []byte) error {
	old := path + ".old"
	_ = os.Remove(old)
	if err := os.Rename(path, old); err != nil {
		return fmt.Errorf("move running binary aside: %w", err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		_ = os.Rename(old, path) // roll back so the service still has a binary to re-exec
		return fmt.Errorf("write new binary: %w", err)
	}
	return nil
}

// cleanupStaleBinaries removes leftovers from a prior self-update swap (a running
// binary can't delete its predecessor, so it's cleared on the next start). Called
// once at daemon startup. Best-effort.
func cleanupStaleBinaries() {
	self, err := resolvedSelf()
	if err != nil {
		return
	}
	for _, suffix := range []string{".old", ".new", ".bak"} {
		_ = os.Remove(self + suffix)
	}
}

// fetchManifest returns the release manifest only when its signature verifies
// (release_sign.go). Both readers go through here: the directed update, which
// trusts the manifest's digests, and the availability poll, which shows its
// version on the local page.
func fetchManifest() (*updateManifest, error) {
	body, err := fetchSignedManifest(manifestURL, releaseKindBastion)
	if err != nil {
		return nil, err
	}
	var m updateManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ── is a newer version published? ───────────────────────────────────────────
//
// fetchManifest existed before this and was called from exactly one place:
// maybeSelfUpdate, which runs only when the HOST directs an update. So the box
// never asked whether it was current, and the local UI could not say "0.24.4 is
// available" — the person at the machine had to open the host to find out
// whether the thing in front of them was the thing that shipped.
//
// This ONLY RECORDS. It never downloads, never verifies, never swaps: the
// directed path above is the only thing that touches the binary, and the local
// UI must never grow a button that starts one (ui.go's header — the UI is a
// view of this machine and never originates a request to the host).

const (
	// updateCheckEvery — WHY SIX HOURS, measured against the cadences already in
	// this binary.
	//
	// Everything else that repeats here is either a local read or a beat to the
	// user's OWN host down their own tunnel: supervise 15 s (run.go:239),
	// heartbeat 60 s (run.go:596), host posture and the second-bastion scan
	// 5 min (observe_ops.go:797, otherbastions.go:317), local agent reconcile
	// 10 min (freeagent_managed.go:114). This one is different in kind. It is
	// the only repeating request in the binary that leaves for privatae.ai, the
	// platform's public edge, and it carries this machine's address to the
	// company whose whole claim is that it cannot see this machine. So it is
	// priced at the rate the ANSWER changes, not at the rate the page redraws.
	//
	// Measured: 32 bumps of deploy/VERSION in one 30-day span, with publishes
	// on 18 distinct days out of 60 — about one publish a day, sometimes
	// several. Six hours is four requests a day and is never more than six hours
	// behind a publish, which is well inside the window that matters, because
	// this banner does not act on anything. The HOST applies updates (the
	// Network app's per-machine Update button, which posts to the host's
	// per-bastion update endpoint), and the host reads the same manifest on
	// its own account.
	//
	// Rejected — matching the 5-minute refreshes: 288 requests a day per machine
	// to learn a fact that changes about once a day, and it would hand the
	// platform a five-minute-resolution presence trace of a box that is supposed
	// to be invisible to it. The cost here is privacy before bandwidth.
	// Rejected — riding the 60 s heartbeat: the same objection 1440 times a day,
	// and that beat goes to the user's host, not to us.
	// Rejected — jitter: start times already stagger these, because the first
	// check is updateCheckFirst after a daemon comes up and daemons do not come
	// up together. A simultaneous fleet restart would correlate them, on a
	// static JSON behind the edge cache, which is the one job an edge has.
	// Jitter would buy a seam and a weak test for nothing measurable.
	updateCheckEvery = 6 * time.Hour

	// updateCheckFirst keeps the first check clear of daemon startup, the
	// busiest moment this process has: every pairing is bringing up a tunnel and
	// beating immediately (run.go:595). It still lands long before someone who
	// has just started the bastion has finished opening the page, and the
	// fragment re-polls every 3 s (uiassets/page.html), so the banner appears on
	// its own when the answer arrives.
	updateCheckFirst = 30 * time.Second
)

var (
	latestMu        sync.Mutex
	latestPublished string
)

// runUpdateAvailabilityPoll asks, slowly, until ctx is done.
func runUpdateAvailabilityPoll(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(updateCheckFirst):
	}
	for {
		checkLatestPublished()
		select {
		case <-ctx.Done():
			return
		case <-time.After(updateCheckEvery):
		}
	}
}

// checkLatestPublished fetches the manifest and records what it said.
//
// Failure is SILENT and leaves the last known answer in place. Running with no
// route to privatae.ai is a supported way to use this product — an egress-
// filtered or genuinely isolated machine still serves its host over its own
// tunnel — and telling that user something is wrong because a version file is
// unreachable would be raising an alarm about the thing they chose.
func checkLatestPublished() {
	if m, err := fetchManifest(); err == nil {
		recordLatestPublished(m.Version)
	}
}

func recordLatestPublished(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	latestMu.Lock()
	latestPublished = v
	latestMu.Unlock()
}

// updateAvailable is the page's question: is a published version NEWER than the
// one running here. "" means no — and "" is also the answer to a question that
// cannot be answered, because an unparseable clientVersion (a `dev` build,
// run.go:32) or an unparseable manifest cannot support the claim. The page says
// nothing rather than something it cannot stand behind.
func updateAvailable() string {
	latestMu.Lock()
	v := latestPublished
	latestMu.Unlock()
	if !versionNewer(v, clientVersion) {
		return ""
	}
	return v
}

// versionNewer reports whether a is a strictly later release than b, in the
// dotted-decimal shape deploy/VERSION has always had ("0.24.3").
//
// NOT a string comparison, which is the bug this exists to prevent: "0.9.0"
// sorts ABOVE "0.24.3" lexically, so every machine on a 0.9 line would have
// been told it was ahead of the world, and every 0.24 machine would have been
// told to update to a release from months earlier. Compared component by
// component; a missing component is 0, so 0.24 and 0.24.0 are one release; and
// anything that is not a plain number makes the comparison unanswerable rather
// than guessed at.
func versionNewer(a, b string) bool {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return false
	}
	for i := 0; i < len(av) || i < len(bv); i++ {
		x, y := 0, 0
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// ownVersionComparable reports whether this build can compare its own version
// with another, which a move forward with no approval needs (maybeSelfUpdate).
func ownVersionComparable() bool {
	_, ok := parseVersion(clientVersion)
	return ok
}

func parseVersion(s string) ([]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// Atoi accepts a sign, so "0.-1" would parse and then compare as a
		// release older than everything. A version component is a count.
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strings.HasPrefix(p, "+") {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func download(url string) ([]byte, error) {
	c := &http.Client{Timeout: 120 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download %s: %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
