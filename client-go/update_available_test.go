package main

// "Is there a newer version?" — the question the box never asked.
// fetchManifest had exactly one caller, maybeSelfUpdate, which runs only when
// the HOST directs an update (update.go), so a machine could sit months behind
// and say nothing about it to the person sitting at it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// freshVersionState isolates the package-level answer and the build stamp.
func freshVersionState(t *testing.T) {
	t.Helper()
	latestMu.Lock()
	old := latestPublished
	latestPublished = ""
	latestMu.Unlock()
	oldClient, oldURL := clientVersion, manifestURL
	t.Cleanup(func() {
		latestMu.Lock()
		latestPublished = old
		latestMu.Unlock()
		clientVersion, manifestURL = oldClient, oldURL
	})
}

// The trap this function exists to avoid is a string compare. "0.9.0" sorts
// ABOVE "0.24.3" lexically, so a plain > would have told every 0.24 machine to
// go back to a release from months earlier — and every 0.9 machine that it was
// ahead of the world.
func TestVersionNewerIsNotAStringCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.24.4", "0.24.3", true},
		{"0.24.3", "0.24.4", false},
		{"0.24.3", "0.24.3", false},
		{"0.9.0", "0.24.3", false}, // the lexical trap, in the direction that matters
		{"0.24.3", "0.9.0", true},  // ...and in the other
		{"1.0.0", "0.99.99", true},
		{"0.24", "0.24.0", false}, // a missing component is zero, not "older"
		{"0.24.0", "0.24", false},
		{"0.24.1", "0.24", true},
		{"v0.25.0", "0.24.3", true}, // a stray v is not a different release
		// Unanswerable, in both directions: a `dev` build (run.go:32) and a
		// manifest this code cannot parse must produce NO claim rather than a
		// guessed ordering.
		{"0.24.4", "dev", false},
		{"dev", "0.24.3", false},
		{"0.24.4", "", false},
		{"", "0.24.3", false},
		{"0.24.4", "0.24.3-rc1", false},
		{"0.24.-1", "0.24.3", false},
		{"0.24.+4", "0.24.3", false},
	}
	for _, c := range cases {
		if got := versionNewer(c.a, c.b); got != c.want {
			t.Errorf("versionNewer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestUpdateAvailableOnlyClaimsWhatItCanStandBehind(t *testing.T) {
	freshVersionState(t)
	clientVersion = "0.24.3"

	if got := updateAvailable(); got != "" {
		t.Errorf("nothing has been checked yet, so there is nothing to say: %q", got)
	}
	recordLatestPublished("0.24.4")
	if got := updateAvailable(); got != "0.24.4" {
		t.Errorf("a newer published version must reach the page: %q", got)
	}
	recordLatestPublished("0.24.3")
	if got := updateAvailable(); got != "" {
		t.Errorf("the version we are already on is not an update: %q", got)
	}
	recordLatestPublished("0.9.9")
	if got := updateAvailable(); got != "" {
		t.Errorf("an OLDER published version must never read as available: %q", got)
	}
	// A local build cannot be compared, so it claims nothing — rather than
	// telling every developer their machine is out of date.
	recordLatestPublished("0.24.4")
	clientVersion = "dev"
	if got := updateAvailable(); got != "" {
		t.Errorf("an unparseable running version must produce no claim: %q", got)
	}
	// An empty or blank manifest version never overwrites a real answer.
	clientVersion = "0.24.3"
	recordLatestPublished("   ")
	if got := updateAvailable(); got != "0.24.4" {
		t.Errorf("a blank manifest version must not erase what is known: %q", got)
	}
}

// manifestServer serves a version.json and counts every hit, including the hit
// on the BINARY the manifest points at — which the availability check must
// never make.
func manifestServer(t *testing.T, version string) (url string, manifestHits, binaryHits *atomic.Int64) {
	t.Helper()
	manifestHits, binaryHits = &atomic.Int64{}, &atomic.Int64{}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) {
		manifestHits.Add(1)
		bin := map[string]any{"url": srv.URL + "/dl", "sha256": "00"}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": version,
			"binaries": map[string]any{
				"linux-amd64": bin, "linux-arm64": bin,
				"darwin-amd64": bin, "darwin-arm64": bin,
				"windows-amd64.exe": bin, "windows-arm64.exe": bin,
			},
		})
	})
	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
		binaryHits.Add(1)
		_, _ = w.Write([]byte("this must never be fetched by a status page"))
	})
	srv = httptest.NewServer(signedStub(releaseKindBastion, mux))
	t.Cleanup(srv.Close)
	return srv.URL + "/version.json", manifestHits, binaryHits
}

// The check READS. It never downloads, never verifies, never swaps — the
// directed path is the only thing allowed to touch the binary, and a local UI
// that could start one would be across the line in ui.go's header.
func TestTheAvailabilityCheckOnlyReadsTheManifest(t *testing.T) {
	freshVersionState(t)
	clientVersion = "0.24.3"
	url, manifestHits, binaryHits := manifestServer(t, "0.24.4")
	manifestURL = url

	checkLatestPublished()

	if got := updateAvailable(); got != "0.24.4" {
		t.Fatalf("the check did not record what was published: %q", got)
	}
	if n := manifestHits.Load(); n != 1 {
		t.Errorf("one check is one manifest fetch, got %d", n)
	}
	if n := binaryHits.Load(); n != 0 {
		t.Fatalf("the availability check downloaded the binary %d time(s) — it is a "+
			"status page, not an updater", n)
	}

	// An unreachable manifest leaves the last known answer alone and says
	// nothing: running with no route to privatae.ai is a supported way to use
	// this, and it must not be reported as a fault.
	manifestURL = "http://127.0.0.1:1/version.json"
	checkLatestPublished()
	if got := updateAvailable(); got != "0.24.4" {
		t.Errorf("a failed check must not erase the answer: %q", got)
	}
}

// A host-directed update reads the same manifest, and on the mismatch path it
// does NOT exit — so what it learned is the freshest thing the page can have.
func TestADirectedUpdateAlsoRecordsWhatIsPublished(t *testing.T) {
	uiTestConfigDir(t)
	freshVersionState(t)
	t.Cleanup(func() { clearDirectiveRefusal("self-update") })
	clientVersion = "0.24.3"
	url, _, binaryHits := manifestServer(t, "0.24.4")
	manifestURL = url

	// The host asks for a version the manifest does not carry: maybeSelfUpdate
	// fetches, finds the mismatch, and returns without swapping anything.
	maybeSelfUpdate("member.host.privatae.ai", "", []byte(`{"update":{"version":"9.9.9"}}`))

	if n := binaryHits.Load(); n != 0 {
		t.Fatalf("a target the manifest does not carry must download nothing (%d hits)", n)
	}
	if got := updateAvailable(); got != "0.24.4" {
		t.Fatalf("the directed path must record what the manifest actually said: %q", got)
	}
}

// The cadence, as a constraint rather than a restatement of the number: this is
// the only repeating request in the binary that leaves for privatae.ai, so it
// must stay far slower than everything that talks to the user's own host or
// reads local disk. The slowest of those is faReconcileEvery (10 min,
// freeagent_managed.go:114). Breaking this is what "the banner feels slow"
// turns into if nobody writes down why it is slow on purpose.
func TestTheAvailabilityCheckStaysSlow(t *testing.T) {
	if updateCheckEvery < 20*faReconcileEvery {
		t.Errorf("updateCheckEvery = %v — a public poll must stay an order of magnitude "+
			"slower than the slowest local refresh (%v); update.go carries the measurement",
			updateCheckEvery, faReconcileEvery)
	}
	if updateCheckFirst < 10*time.Second || updateCheckFirst > updateCheckEvery {
		t.Errorf("updateCheckFirst = %v — it must clear daemon startup and still be the "+
			"first of the series", updateCheckFirst)
	}
}
