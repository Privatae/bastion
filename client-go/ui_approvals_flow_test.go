package main

// Three review findings on the given page, each pinned by the test that would
// have caught it.
//
// The first one is the interesting one. That change's headline was a defect where
// rendering a page CREATED state for a pairing the anchor had never approved,
// and the given page reintroduced it three files later. The original test could
// not see it because its fixture pre-creates the DCN directory (uigiven_test.go
// givenPairing), so "was it created?" was already answered yes before the page
// ran. A test whose fixture supplies the thing under test can only ever pass.
//
// So these assert on a path that NOTHING has created: the pairing names a DCN
// dir inside a temp root, the directory is deliberately absent, and the page is
// rendered. If the page asked, the directory exists afterwards.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pairingWithAbsentDCN writes a pairing whose DCNDir does NOT exist. Nothing
// here creates it — that is the whole point.
func pairingWithAbsentDCN(t *testing.T, host, state string) string {
	t.Helper()
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	dcn := filepath.Join(t.TempDir(), "never-created")
	b, _ := json.Marshal(&Config{
		HostName: host, ListenAddr: "127.0.0.1:59999",
		DCNDir: dcn, State: state, FirstSeen: "2026-09-01T00:00:00Z",
	})
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dcn); !os.IsNotExist(err) {
		t.Fatalf("fixture is broken: %s exists before the page ran", dcn)
	}
	return dcn
}

func TestNoPageCreatesStateForAPairingTheAnchorHasNotApproved(t *testing.T) {
	for _, state := range []string{pairingPending, pairingRevoked} {
		t.Run(state, func(t *testing.T) {
			uiTestConfigDir(t)
			dcn := pairingWithAbsentDCN(t, "waiting.host.privatae.ai", state)
			u := uiTestServer(t)
			h := u.handler()
			tok, _ := u.sessions.mint()
			cookie := uiCookieName + "=" + tok

			// Every page that walks the pairing list. The status page was fixed
			// first; /given reintroduced it; both are asserted here so the
			// next page to walk that list has a test waiting for it.
			for _, path := range []string{"/", "/fragments/status", "/given",
				"/fragments/given", "/setup"} {
				r := uiReq(http.MethodGet, path)
				r.Header.Set("Cookie", cookie)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("%s = %d", path, w.Code)
				}
				if _, err := os.Stat(dcn); !os.IsNotExist(err) {
					t.Fatalf("rendering %s created %s for a %s pairing — dcnDir() is "+
						"MkdirAll-on-read (config.go:115) and run.go:311-318 keeps every "+
						"such call behind active() so a host the anchor has not approved "+
						"gets no directories", path, dcn, state)
				}
			}
		})
	}
}

// Answering a request for a pairing the anchor has not approved is wrong on its
// own terms — that host holds no lanes to act on the answer — and it also
// reached cfg.dcnDir() on the way.
func TestApprovingForAnInactivePairingIsRefused(t *testing.T) {
	uiTestConfigDir(t)
	dcn := pairingWithAbsentDCN(t, "waiting.host.privatae.ai", pairingPending)
	u := uiTestServer(t)
	cookie := uiCookieName + "="
	tok, _ := u.sessions.mint()
	cookie += tok

	for _, route := range []string{"/approve", "/deny"} {
		w := uiPost(t, u.handler(), route, url.Values{
			"host": {"waiting.host.privatae.ai"}, "id": {"abc"}, "code": {"000000"},
		}, cookie)
		if !strings.Contains(w.Body.String(), "does not serve") {
			t.Errorf("%s on a pending pairing was not refused: %q", route, w.Body.String())
		}
		if _, err := os.Stat(dcn); !os.IsNotExist(err) {
			t.Fatalf("%s created %s for a pending pairing", route, dcn)
		}
	}
}

// A read that FAILED is not a machine with nothing on it. Folding the error
// into the empty state printed the single most reassuring sentence on the box
// about a machine whose records could not be read.
func TestAnUnreadablePairingStoreNeverReadsAsNothingIsShared(t *testing.T) {
	uiTestConfigDir(t)
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	// A pairing file that is not JSON. loadPairings must surface an error; if
	// this ever stops erroring the test says so rather than passing quietly.
	if err := os.WriteFile(filepath.Join(pd, "broken.host.privatae.ai.json"),
		[]byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPairings(); err == nil {
		t.Skip("loadPairings tolerates an unparseable record; this case needs a new fixture")
	}

	u := uiTestServer(t)
	h := u.handler()
	tok, _ := u.sessions.mint()
	cookie := uiCookieName + "=" + tok

	for _, path := range []string{"/given", "/setup"} {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		body := w.Body.String()
		if strings.Contains(body, "No host is paired with this machine") {
			t.Errorf("%s printed the reassuring sentence for a store it could not read", path)
		}
		if !strings.Contains(body, "cannot be read") {
			t.Errorf("%s did not say the records are unreadable: %q", path,
				strings.TrimSpace(body)[:min(240, len(strings.TrimSpace(body)))])
		}
	}
}

// `sudo` is not a command on Windows, so a hardcoded unix line in the anchor
// panel was untypeable there. And -H is load-bearing on unix: set-mode writes
// through configDir() ($HOME-derived), so a bare sudo can land the mode file in
// the invoking user's directory while the root daemon reads its own.
func TestSetModeHintMatchesThePlatform(t *testing.T) {
	win := setModeCommandHintFor("windows")
	if strings.Contains(win, "sudo") {
		t.Errorf("the Windows hint tells the user to run sudo: %q", win)
	}
	if !strings.Contains(win, "Administrator") {
		t.Errorf("the Windows hint does not say where to run it: %q", win)
	}
	for _, goos := range []string{"linux", "darwin"} {
		got := setModeCommandHintFor(goos)
		if !strings.HasPrefix(got, "sudo -H ") {
			t.Errorf("%s hint is not the -H form: %q", goos, got)
		}
	}
}

// main.go's usage IS the command — it is what gets typed. It disagreed with
// adminHowTo for two different verbs; claim-owner was fixed first and
// set-mode was not.
func TestUsageNeverTeachesABareSudoForAHomeDerivedWrite(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"claim-owner", "set-mode", "claim-anchor"} {
		if strings.Contains(string(b), "sudo privatae-bastion "+verb) {
			t.Errorf("main.go prints `sudo privatae-bastion %s` without -H. That verb writes "+
				"through configDir(), which is $HOME-derived, so the write can land in the "+
				"invoking user's directory while the root daemon reads its own and sees "+
				"nothing.", verb)
		}
	}
}
