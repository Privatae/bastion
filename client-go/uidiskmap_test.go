package main

// The disk map page: the layout, the drawing, and the four properties the page
// is not allowed to lose — no inline style, no unescaped filename, no poll that
// walks a disk, and nothing rendered for a path this machine never scanned.

import (
	"context"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// dmTestInstall swaps the machine-wide map for one the test controls, so no
// test ever walks the disk of whoever is running it.
func dmTestInstall(t *testing.T, res *dmResult) *dmState {
	t.Helper()
	old := diskMap
	s := &dmState{
		res:   res,
		scan:  dmScan,
		roots: func(dmScope) ([]string, []string) { return nil, nil },
	}
	diskMap = s
	t.Cleanup(func() { diskMap = old })
	return s
}

// dmBigTree writes a tree with enough in it to draw a real picture: a few
// heavy files, a long tail of small ones, and several types.
func dmBigTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel string, n int) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Videos/holiday.mp4", 900000)
	write("Videos/wedding.mov", 400000)
	write("Models/qwen.gguf", 600000)
	write("Photos/a.jpg", 30000)
	write("Photos/b.jpg", 25000)
	write("Photos/c.png", 18000)
	write("Docs/report.pdf", 40000)
	write("Docs/notes.md", 900)
	write("code/main.go", 1200)
	write("code/vendor/dep.go", 700)
	for i := 0; i < 200; i++ {
		write(fmt.Sprintf("cache/tiny/%d.tmp", i), 40)
	}
	return root
}

func dmRender(t *testing.T, u *uiServer, cookie, path string) string {
	t.Helper()
	target := "/diskmap"
	if path != "" {
		target += "?p=" + url.QueryEscape(path)
	}
	r := uiReq(http.MethodGet, target)
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", target, w.Code, w.Body.String())
	}
	return w.Body.String()
}

// ── the CSP property the whole design turns on ──────────────────────────────

// TestTheMapNeverEmitsInlineStyle is the assertion behind uidiskmap.go's
// header. The page's CSP is `default-src 'self'` with no 'unsafe-inline'
// (ui.go renderWith), so an inline style silently does nothing — app.css:169
// records the last time that happened here. A treemap is the single most
// natural thing in this codebase to write as inline styles, so the ban has to
// be mechanical.
func TestTheMapNeverEmitsInlineStyle(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, dmScanTree(t, dmBigTree(t)))
	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), "")

	if !strings.Contains(body, "<rect") {
		t.Fatal("the page carries no rectangles, so this test is checking an empty map")
	}
	for _, bad := range []string{`style="`, `style='`, "<style"} {
		if strings.Contains(body, bad) {
			t.Errorf("the page contains %q. The CSP is `default-src 'self'` with no "+
				"'unsafe-inline', so this does NOTHING in a browser and the layout it "+
				"was meant to produce is silently lost.", bad)
		}
	}
	// And the header it depends on is actually being sent.
	r := uiReq(http.MethodGet, "/diskmap")
	r.Header.Set("Cookie", uiSignedIn(t, u))
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q — the rule this whole design is shaped around is not being sent", csp)
	}
}

// The SVG is built in Go and handed to the template as template.HTML, which
// turns escaping from the template's job into this unit's. So a filename is
// the injection vector, and a filename is chosen by whoever writes to the
// disk — including, on a machine with a folder shared to a host, the host.
//
// THE FIRST VERSION OF THIS TEST NEVER RAN. Its hostile filename contained
// `</title>`, and a `/` cannot be in a filename on any filesystem, so
// os.WriteFile failed and the test t.Skip'd — silently, and it would have
// skipped just as silently with dmEsc replaced by the identity function. The
// names below use only characters a real file can actually carry, and the
// fixture failing is now a FATAL rather than a skip anywhere but Windows.
func TestAFilenameCannotInjectMarkupIntoTheMap(t *testing.T) {
	root := t.TempDir()
	names := []string{
		`<script>alert(1).mp4`,
		`a&b" c'd.jpg`,
	}
	for i, n := range names {
		err := os.WriteFile(filepath.Join(root, n), make([]byte, 5000*(i+1)), 0o644)
		if err == nil {
			continue
		}
		if runtime.GOOS == "windows" {
			t.Skipf("Windows will not hold %q: %v", n, err)
		}
		t.Fatalf("the fixture could not be written, so this test would have proved "+
			"nothing: %q: %v", n, err)
	}
	uiTestConfigDir(t)
	dmTestInstall(t, dmScanTree(t, root))
	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), "")

	if !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Errorf("the dangerous name is not in the page escaped: %q", dmSnip(body, "alert"))
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("a FILENAME opened a script element inside the map. The SVG is " +
			"template.HTML, so dmEsc is the only thing between a filename and the " +
			"document.")
	}
	if !strings.Contains(body, "a&amp;b") {
		t.Errorf("an ampersand in a filename reached the page raw: %q", dmSnip(body, "a&"))
	}
	// The strongest form of the same claim: an unescaped < or " anywhere in the
	// map stops it being XML, and nothing else in this file would notice.
	svg := dmSVGOf(t, body) + "</svg>"
	dec := xml.NewDecoder(strings.NewReader(svg))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("with those filenames in it the map is no longer well formed: %v", err)
		}
	}
}

func dmSnip(body, around string) string {
	i := strings.Index(body, around)
	if i < 0 {
		return "(not present)"
	}
	a, b := i-60, i+60
	if a < 0 {
		a = 0
	}
	if b > len(body) {
		b = len(body)
	}
	return body[a:b]
}

// ── the headers, compared rather than copied ────────────────────────────────

// renderDiskMap sets the same four headers renderWith does, by duplication.
// Duplication is safe only if something compares them.
func TestTheDiskMapCarriesTheSameHeadersAsTheStatusPage(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, nil)
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	get := func(path string) http.Header {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
		}
		return w.Header()
	}
	status, disk := get("/"), get("/diskmap")
	for _, k := range []string{"Content-Type", "Cache-Control",
		"Content-Security-Policy", "X-Content-Type-Options"} {
		if status.Get(k) != disk.Get(k) {
			t.Errorf("%s: status page %q, disk map %q", k, status.Get(k), disk.Get(k))
		}
	}
	if disk.Get("Content-Security-Policy") == "" {
		t.Fatal("the disk map is served with no CSP at all, and so is the status " +
			"page this compared it against — the comparison proved nothing")
	}
}

// serveAsset refuses a rebound host BEFORE it looks at the name (ui.go), so
// the rebinding walk in ui_test.go answers 403 for /assets/diskmap.css whether
// or not the file is on the allow-list — it passed with diskmap.css removed.
// This is the assertion that name is actually served.
func TestTheDiskMapStylesheetIsServedFromTheBinary(t *testing.T) {
	uiTestConfigDir(t)
	h := uiTestServer(t).handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, uiReq(http.MethodGet, "/assets/diskmap.css"))
	if w.Code != http.StatusOK {
		t.Fatalf("/assets/diskmap.css = %d — the map page would render unstyled", w.Code)
	}
	if !strings.Contains(w.Body.String(), ".dm-svg") {
		t.Error("the stylesheet does not look like itself; the embed may be stale")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("served without nosniff")
	}
}

// ── the poll, which must never walk a disk ──────────────────────────────────

// The status page re-fetches itself every three seconds. If the disk map
// hitched a ride on that, a page left open would walk the machine's storage
// every three seconds forever.
func TestTheStatusPollNeverStartsADiskScan(t *testing.T) {
	uiTestConfigDir(t)
	started := 0
	s := dmTestInstall(t, nil)
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		started++
		return &dmResult{}
	}
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	for i := 0; i < 20; i++ {
		for _, path := range []string{"/", "/fragments/status", "/diskmap", "/fragments/diskmap"} {
			r := uiReq(http.MethodGet, path)
			r.Header.Set("Cookie", cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("%s = %d", path, w.Code)
			}
		}
	}
	if started != 0 {
		t.Fatalf("%d scans were started by rendering pages. A walk of this machine's "+
			"storage must only ever begin because somebody pressed a button.", started)
	}
}

// And the fragment stops polling on its own when the scan ends, because a
// fragment that keeps polling is a fragment that keeps a page busy for nothing.
func TestTheFragmentOnlyPollsWhileAScanIsRunning(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	release := make(chan struct{})
	s.scan = func(ctx context.Context, _ []string, _ int, _ func(dmProgress)) *dmResult {
		<-release
		return &dmResult{TakenAt: uiNow()}
	}
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	idle := dmFragment(t, h, cookie)
	if strings.Contains(idle, "every 2s") {
		t.Error("an idle map polls. Nothing on this page changes unless a scan is running.")
	}

	w := uiPost(t, h, "/diskmap/scan", url.Values{}, cookie)
	if !strings.Contains(w.Body.String(), "every 2s") {
		t.Error("a running scan does not poll, so its progress would never move")
	}
	if !strings.Contains(dmFragment(t, h, cookie), "every 2s") {
		t.Error("the polled fragment does not carry the next poll")
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		body := dmFragment(t, h, cookie)
		if !strings.Contains(body, "every 2s") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fragment was still polling 5s after the scan finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dmFragment(t *testing.T, h http.Handler, cookie string) string {
	t.Helper()
	r := uiReq(http.MethodGet, "/fragments/diskmap")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/fragments/diskmap = %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// Two full-disk walks do not go twice as fast; on anything but an NVMe they
// fight for the same head and both finish later than either would alone.
func TestOnlyOneScanRunsAtATime(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		started <- struct{}{}
		<-release
		return &dmResult{TakenAt: uiNow()}
	}
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	w := uiPost(t, h, "/diskmap/scan", url.Values{}, cookie)
	<-started
	// A form with no scope is the default one, and the default is your files.
	if !strings.Contains(w.Body.String(), "Mapping your files") {
		t.Errorf("the first scan did not say it had started: %q", dmSnip(w.Body.String(), "state"))
	}
	w = uiPost(t, h, "/diskmap/scan", url.Values{}, cookie)
	if !strings.Contains(w.Body.String(), "already running") {
		t.Errorf("a second scan press did not say one was already running: %q",
			dmSnip(w.Body.String(), "flash"))
	}
	close(release)
	select {
	case <-started:
		t.Fatal("a second walk was started while the first was still going")
	case <-time.After(200 * time.Millisecond):
	}
}

// The scan is the one thing on this page that makes the machine do work. It is
// a POST so the Origin check applies — a <img src="/diskmap/scan"> that could
// start a full-disk walk is a denial of service written by accident.
func TestStartingAScanIsPostOnlyAndTakesTheOriginCheck(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	started := 0
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		started++
		return &dmResult{}
	}
	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	for _, route := range []string{"/diskmap/scan", "/diskmap/stop"} {
		r := uiReq(http.MethodGet, route)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", route, w.Code)
		}

		r = httptest.NewRequest(http.MethodPost, route, nil)
		r.Host = "127.0.0.1:" + uiTestPort
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Cookie", cookie)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403", route, w.Code)
		}
	}
	if started != 0 {
		t.Fatalf("%d scans were started by a refused request", started)
	}
}

// ── the memory comes back ───────────────────────────────────────────────────

func TestAMapNobodyIsLookingAtIsReleased(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	s.staleAfter = 40 * time.Millisecond
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		return &dmResult{Nodes: []dmNode{{Name: "/", Dir: true, Root: true,
			Parent: -1, FirstChild: -1, NextSibling: -1}}, Roots: []int32{0}, TakenAt: uiNow()}
	}
	if !s.dmStart(dmScopeHome) {
		t.Fatal("the scan did not start")
	}
	// It exists once the walk lands.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if s.dmView().Res != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan never produced a map")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// dmView above counts as looking, so wait out two full windows with
	// nobody looking.
	time.Sleep(160 * time.Millisecond) // four stale windows with nobody looking
	s.mu.Lock()
	held := s.res
	s.mu.Unlock()
	if held != nil {
		t.Error("a map nobody has looked at in four stale-windows is still held. " +
			"Measured worst case is ~92 MB, and a background daemon on someone's " +
			"laptop does not get to keep that for a page nobody has open.")
	}
}

func TestLookingAtAMapKeepsItAlive(t *testing.T) {
	uiTestConfigDir(t)
	s := dmTestInstall(t, nil)
	s.staleAfter = 60 * time.Millisecond
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		return &dmResult{Nodes: []dmNode{{Name: "/", Dir: true, Root: true,
			Parent: -1, FirstChild: -1, NextSibling: -1}}, Roots: []int32{0}, TakenAt: uiNow()}
	}
	s.dmStart(dmScopeHome)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if s.dmView().Res != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the scan never produced a map")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Keep looking, the way a page left open does.
	for i := 0; i < 12; i++ {
		time.Sleep(20 * time.Millisecond)
		if s.dmView().Res == nil {
			t.Fatal("the map was released out from under somebody who was reading it")
		}
	}
}

// ── drilling ────────────────────────────────────────────────────────────────

func TestDrillingIntoAFolderAndBackOut(t *testing.T) {
	uiTestConfigDir(t)
	root := dmBigTree(t)
	dmTestInstall(t, dmScanTree(t, root))
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)

	top := dmRender(t, u, cookie, "")
	if !strings.Contains(top, "holiday.mp4") {
		t.Error("the biggest file on the disk is not named anywhere on the top page")
	}
	// Every folder IN THE PICTURE is a link, which is what makes drilling
	// possible with no script at all. Scoped to the <svg> on purpose: the
	// breadcrumb, the "covers" list and the biggest-things table all emit the
	// same href, so a whole-page search passed with the map's links deleted.
	if !strings.Contains(dmSVGOf(t, top), `<a href="/diskmap?p=`) {
		t.Error("nothing in the PICTURE is a link, so the only way into a folder " +
			"is the table underneath it")
	}

	photos := filepath.Join(root, "Photos")
	in := dmRender(t, u, cookie, photos)
	if !strings.Contains(in, "a.jpg") || !strings.Contains(in, "c.png") {
		t.Error("drilling into Photos does not show what is in Photos")
	}
	if strings.Contains(in, "holiday.mp4") {
		t.Error("drilling into Photos still shows a file from a different folder")
	}
	// The way back out is the breadcrumb, and what matters is that FOLLOWING
	// it lands on the parent — not that its href is spelled a particular way.
	// html/template percent-encodes with lowercase hex and url.QueryEscape
	// with uppercase, so a string comparison here would be testing which
	// escaper ran rather than whether the link works.
	back := dmFirstCrumbHref(t, in)
	out := dmRender(t, u, cookie, back)
	if !strings.Contains(out, "holiday.mp4") {
		t.Errorf("following the breadcrumb from Photos (p=%q) did not land back at "+
			"the top of the map", back)
	}
}

// dmSVGOf returns just the <svg> element, so an assertion about the map is an
// assertion about the map.
func dmSVGOf(t *testing.T, body string) string {
	t.Helper()
	a := strings.Index(body, "<svg class=\"dm-svg\"")
	if a < 0 {
		t.Fatal("the page carries no map at all")
	}
	b := strings.Index(body[a:], "</svg>")
	if b < 0 {
		t.Fatal("the map element is never closed")
	}
	return body[a : a+b]
}

// dmFirstCrumbHref pulls the first breadcrumb link out of the page and decodes
// its p= argument, which is what a browser would send back.
func dmFirstCrumbHref(t *testing.T, body string) string {
	t.Helper()
	at := strings.Index(body, "dm-crumbs")
	if at < 0 {
		t.Fatal("the page has no breadcrumb at all, so there is no way back out")
	}
	m := regexp.MustCompile(`href="(/diskmap\?p=[^"]*)"`).FindStringSubmatch(body[at:])
	if m == nil {
		t.Fatalf("the breadcrumb carries no link: %s", dmSnip(body[at:], "nav"))
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatalf("the breadcrumb href does not parse: %q: %v", m[1], err)
	}
	return u.Query().Get("p")
}

// A path this scan never saw is refused in words. The alternative — quietly
// showing the root instead — teaches the user that they typed it right.
func TestAPathThisMapDoesNotHoldIsSaidRatherThanSwallowed(t *testing.T) {
	uiTestConfigDir(t)
	dmTestInstall(t, dmScanTree(t, dmBigTree(t)))
	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), "/etc/shadow")
	if !strings.Contains(body, "not in this map") {
		t.Errorf("a path outside the map was silently replaced by the root: %q",
			dmSnip(body, "flash"))
	}
	if strings.Contains(body, "shadow") {
		t.Error("the page echoed the path it refused, which is a way of confirming " +
			"what does and does not exist on this machine")
	}
}

func TestAFileHasNoInsideSoItsParentIsShown(t *testing.T) {
	uiTestConfigDir(t)
	root := dmBigTree(t)
	dmTestInstall(t, dmScanTree(t, root))
	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), filepath.Join(root, "Videos", "holiday.mp4"))
	if !strings.Contains(body, "wedding.mov") {
		t.Error("asking for a FILE did not fall back to the folder it is in")
	}
}

// ── the legend tells the truth about what it could not draw ─────────────────

// A legend built from the drawn rectangles would say "video 2 GB" about a
// folder holding 40 GB of video in files too small to draw. The user is here
// to find out where the space went, and the space is in the part the picture
// could not show.
func TestTheLegendCountsTheWholeSubtreeNotOnlyWhatWasDrawn(t *testing.T) {
	root := t.TempDir()
	// One enormous file and a thousand small ones AS ITS SIBLINGS. Siblings
	// rather than a subfolder on purpose: a folder too small to open is drawn
	// as one block and its children are never considered, so the "too small to
	// draw" count is about items with no block of their own, which is what
	// this is exercising.
	if err := os.WriteFile(filepath.Join(root, "one.mp4"), make([]byte, 500<<20), 0o644); err != nil {
		t.Skipf("no room for the fixture: %v", err)
	}
	// Half of them beside it and half a level down, so this also fails if the
	// legend stops DESCENDING: a legend that only reads the folder it is
	// looking at would report 500 and the map would disagree with itself.
	deeper := filepath.Join(root, "more")
	if err := os.MkdirAll(deeper, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		dir := root
		if i%2 == 0 {
			dir = deeper
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.jpg", i)),
			make([]byte, 100), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := dmScanTree(t, root)
	_, cells, tiny, _, _ := dmSVG(res, res.Roots[0])
	if tiny == 0 {
		t.Fatalf("nothing was too small to draw (%d cells), so this test is not "+
			"exercising the case it exists for", cells)
	}
	legend := dmLegend(res, res.Roots[0])
	var images string
	for _, l := range legend {
		if l.Label == "Images" {
			images = l.Size
			if l.Items != 1000 {
				t.Errorf("the legend counts %d images, want 1000 — it is counting "+
					"what was drawn rather than what is there", l.Items)
			}
		}
	}
	if images == "" {
		t.Fatal("the legend has no Images row at all, though 1000 .jpg files are here")
	}
}

// ── what the map is NOT ─────────────────────────────────────────────────────

func TestTheMapSaysEverythingItCouldNotSee(t *testing.T) {
	uiTestConfigDir(t)
	root := dmBigTree(t)
	res := dmScanTree(t, root)
	// Stand in for the three ways a real machine's map comes back incomplete.
	res.Denied, res.DeniedPaths = 3, []string{"/var/private-thing"}
	res.Crossings = []string{"/mnt/second-disk"}
	res.Skipped = []string{"/proc"}
	res.Capped, res.CappedAt = true, "/somewhere/it/stopped"
	res.Cancelled = true
	dmTestInstall(t, res)

	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), "")
	for _, want := range []string{
		"could not be read", "/var/private-thing",
		"were not entered", "/mnt/second-disk",
		"/proc",
		"stopped after counting", "/somewhere/it/stopped",
		"stopped before it finished",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not say %q. A map that quietly omits is worse "+
				"than no map.", want)
		}
	}
}

func TestAStaleMapSaysSoRatherThanBeingPresentedAsCurrent(t *testing.T) {
	uiTestConfigDir(t)
	res := dmScanTree(t, dmBigTree(t))
	res.TakenAt = time.Now().Add(-2 * dmStaleAfter)
	dmTestInstall(t, res)
	u := uiTestServer(t)
	body := dmRender(t, u, uiSignedIn(t, u), "")
	if !strings.Contains(body, "Map again for a current picture") {
		t.Errorf("a map older than the stale window is shown as current: %q",
			dmSnip(body, "checked"))
	}
}

// ── the squarified layout ───────────────────────────────────────────────────

func TestSquarifyFillsTheRectangleWithoutOverlapping(t *testing.T) {
	r := dmRect{X: 0, Y: 0, W: 600, H: 400}
	vals := []float64{6, 6, 4, 3, 2, 2, 1}
	rects := dmSquarify(vals, r)
	if len(rects) != len(vals) {
		t.Fatalf("got %d rects for %d values", len(rects), len(vals))
	}
	var area float64
	for i, c := range rects {
		area += c.area()
		if c.X < -1e-6 || c.Y < -1e-6 || c.X+c.W > r.W+1e-6 || c.Y+c.H > r.H+1e-6 {
			t.Errorf("rect %d %v escapes the container %v", i, c, r)
		}
		if math.IsNaN(c.W) || math.IsNaN(c.H) || c.W < 0 || c.H < 0 {
			t.Errorf("rect %d is not a rectangle: %v", i, c)
		}
	}
	if math.Abs(area-r.area()) > 1e-6 {
		t.Errorf("the rects cover %.4f of %.4f — a treemap whose areas do not add "+
			"up is drawing sizes that are not the sizes", area, r.area())
	}
	// Areas must be PROPORTIONAL, which is the only claim the picture makes.
	total := 0.0
	for _, v := range vals {
		total += v
	}
	for i, v := range vals {
		want := v / total * r.area()
		if math.Abs(rects[i].area()-want) > 1e-6 {
			t.Errorf("rect %d has area %.4f, want %.4f (value %v of %v)",
				i, rects[i].area(), want, v, total)
		}
	}
	// No two rects may overlap.
	for i := range rects {
		for j := i + 1; j < len(rects); j++ {
			if dmOverlap(rects[i], rects[j]) {
				t.Errorf("rects %d %v and %d %v overlap", i, rects[i], j, rects[j])
			}
		}
	}
}

func dmOverlap(a, b dmRect) bool {
	const e = 1e-9
	return a.X+a.W > b.X+e && b.X+b.W > a.X+e &&
		a.Y+a.H > b.Y+e && b.Y+b.H > a.Y+e
}

// The reason squarified was worth writing rather than slice-and-dice, measured
// on the shape of data this actually gets: a few big things and a long tail.
// Slice-and-dice gives every cell the full height of its parent, so a folder
// with a hundred children is a hundred hairlines — nothing hoverable, nothing
// clickable, no shape.
func TestSquarifyKeepsBlocksFarSquarerThanSliceAndDice(t *testing.T) {
	r := dmRect{X: 0, Y: 0, W: dmCanvasW, H: dmCanvasH}
	var vals []float64
	for i := 100; i > 0; i-- {
		vals = append(vals, float64(i*i))
	}
	sq := dmMeanRatio(dmSquarify(vals, r))
	sd := dmMeanRatio(dmSliceAndDice(vals, r))
	if sq >= sd {
		t.Errorf("squarified mean aspect ratio %.2f is no better than slice-and-dice "+
			"%.2f — the algorithm is not doing the one thing it is for", sq, sd)
	}
	if sq > 4 {
		t.Errorf("squarified mean aspect ratio is %.2f; blocks that long are not "+
			"blocks", sq)
	}
	t.Logf("mean aspect ratio over 100 cells: squarified %.2f, slice-and-dice %.2f", sq, sd)
}

func dmSliceAndDice(vals []float64, r dmRect) []dmRect {
	total := 0.0
	for _, v := range vals {
		total += v
	}
	out := make([]dmRect, len(vals))
	x := r.X
	for i, v := range vals {
		w := r.W * v / total
		out[i] = dmRect{X: x, Y: r.Y, W: w, H: r.H}
		x += w
	}
	return out
}

func dmMeanRatio(rects []dmRect) float64 {
	sum, n := 0.0, 0
	for _, c := range rects {
		if c.W <= 0 || c.H <= 0 {
			continue
		}
		sum += math.Max(c.W/c.H, c.H/c.W)
		n++
	}
	if n == 0 {
		return math.Inf(1)
	}
	return sum / float64(n)
}

func TestSquarifySurvivesTheDegenerateInputsARealDiskProduces(t *testing.T) {
	r := dmRect{X: 0, Y: 0, W: 100, H: 50}
	for name, vals := range map[string][]float64{
		"nothing":            {},
		"all zero":           {0, 0, 0},
		"zeroes in the tail": {10, 5, 0, 0, 0},
		"one item":           {7},
		"negative":           {5, -3, 1},
	} {
		rects := dmSquarify(vals, r)
		if len(rects) != len(vals) {
			t.Errorf("%s: got %d rects for %d values", name, len(rects), len(vals))
		}
		for i, c := range rects {
			if math.IsNaN(c.X) || math.IsNaN(c.Y) || math.IsNaN(c.W) || math.IsNaN(c.H) {
				t.Errorf("%s: rect %d is NaN: %v — a zero-size file is an ordinary "+
					"thing to find on a disk", name, i, c)
			}
		}
	}
	// And an empty container, which is what a deeply nested recursion hits.
	for _, bad := range []dmRect{{}, {W: 10}, {H: 10}, {W: -5, H: 5}} {
		if got := dmSquarify([]float64{1, 2}, bad); len(got) != 2 {
			t.Errorf("container %v produced %d rects", bad, len(got))
		}
	}
}

// The SVG is assembled by string concatenation, which is the cheapest way to
// emit 4,000 rectangles and the easiest way to emit 4,000 rectangles and one
// unbalanced tag. A browser's HTML parser would paper over that and render
// something subtly wrong; an XML parser will not.
func TestTheMapIsWellFormedMarkup(t *testing.T) {
	res := dmScanTree(t, dmBigTree(t))
	svg, cells, _, _, _ := dmSVG(res, res.Roots[0])
	if cells == 0 {
		t.Fatal("nothing was drawn, so this parsed an empty document")
	}
	dec := xml.NewDecoder(strings.NewReader(svg))
	depth, elems := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the emitted SVG is not well formed: %v", err)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			elems++
		case xml.EndElement:
			depth--
		}
	}
	if depth != 0 {
		t.Errorf("the SVG ends at nesting depth %d — a tag is unbalanced", depth)
	}
	if elems < cells {
		t.Errorf("%d elements for %d cells; cells are being dropped", elems, cells)
	}
}

// ── types and sizes ─────────────────────────────────────────────────────────

func TestTheTypeIsReadOffTheNameAndNothingElse(t *testing.T) {
	for name, want := range map[string]string{
		"holiday.mp4":       "video",
		"HOLIDAY.MP4":       "video",
		"qwen3-8b.gguf":     "model",
		"archive.tar.gz":    "archive",
		"notes.md":          "document",
		"main.go":           "code",
		".bashrc":           "other", // a leading dot is not an extension
		"Makefile":          "other",
		"trailing.":         "other",
		"thing.unheard-of":  "other",
		"a.b.c.jpg":         "image",
		"libfoo.so":         "binary",
		"places.sqlite":     "db",
		"syslog.log":        "logtmp",
		"disk.qcow2":        "vmdisk",
		"track.flac":        "audio",
		"photo.PNG":         "image",
		"no-extension-here": "other",
	} {
		if got := dmKindOf(name); got != want {
			t.Errorf("dmKindOf(%q) = %q, want %q", name, got, want)
		}
	}
	// Every kind must have a colour, or a legend row would be invisible.
	for _, k := range dmKinds {
		if dmFillOf(k.Key) != k.Fill {
			t.Errorf("kind %q does not resolve to its own colour", k.Key)
		}
	}
	// No extension may be claimed by two kinds — the second would silently win
	// and the legend would disagree with itself.
	seen := map[string]string{}
	for _, k := range dmKinds {
		for _, e := range k.Exts {
			if prev, dup := seen[e]; dup {
				t.Errorf("extension %q is claimed by both %q and %q", e, prev, k.Key)
			}
			seen[e] = k.Key
		}
	}
}

// The page must spell a byte count the way the rest of the machine already
// does, or a user reads one number on the map and a different spelling of the
// same number when they approve a model download.
func TestSizesAreSpelledTheWayThisMachineAlreadySpellsThem(t *testing.T) {
	for _, n := range []int64{1 << 20, 5 << 20, 1 << 30, 3<<30 + 7} {
		if dmBytes(n) != modelBytesWords(n) {
			t.Errorf("dmBytes(%d) = %q but the machine says %q elsewhere "+
				"(modelswap.go)", n, dmBytes(n), modelBytesWords(n))
		}
	}
	// And the one tier it adds, which that one does not have.
	if got := dmBytes(2048); got != "2 KB" {
		t.Errorf("dmBytes(2048) = %q, want \"2 KB\"", got)
	}
	if got := dmBytes(700); got != "700 bytes" {
		t.Errorf("dmBytes(700) = %q", got)
	}
}

// ── the measurement that set dmMaxCells ─────────────────────────────────────

// TestMeasureARealMap renders a real directory and prints what it costs, so
// the constants in uidiskmap.go can be re-derived instead of remembered. Off
// unless DISKMAP_MEASURE names a directory, the same way ui_preview_test.go is
// off unless UI_PREVIEW_DIR does.
//
//	DISKMAP_MEASURE=$HOME go test -run TestMeasureARealMap -v ./client-go
func TestMeasureARealMap(t *testing.T) {
	root := os.Getenv("DISKMAP_MEASURE")
	if root == "" {
		t.Skip("DISKMAP_MEASURE unset")
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	res := dmScan(context.Background(), []string{root}, dmMaxEntries, nil)
	walk := time.Since(start)
	runtime.ReadMemStats(&m1)
	peak := int64(m1.HeapAlloc - m0.HeapAlloc)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	held := int64(m1.HeapAlloc - m0.HeapAlloc)
	t.Logf("walk  %s: %d entries (%d dirs, %d files), %s, %d denied, %d crossings, in %v",
		root, len(res.Nodes), res.Dirs, res.Files, dmBytes(res.Bytes),
		res.Denied, len(res.Crossings), walk)
	// The number dmMaxEntries is derived from. Peak is before a collection and
	// held is after one, so the gap is the walk's own garbage rather than the
	// map — and the map is what the cap has to bound.
	if n := int64(len(res.Nodes)); n > 0 {
		t.Logf("mem   peak %s (%d B/entry), held %s (%d B/entry) — dmMaxEntries×held = %s",
			dmBytes(peak), peak/n, dmBytes(held), held/n, dmBytes(dmMaxEntries*held/n))
	}
	runtime.KeepAlive(res)

	start = time.Now()
	svg, cells, tiny, tinyBytes, overflow := dmSVG(res, res.Roots[0])
	draw := time.Since(start)
	per := 0
	if cells > 0 {
		per = len(svg) / cells
	}
	t.Logf("draw  %d cells, %d too small (%s), overflow=%v, %d bytes of SVG (%d/cell), in %v",
		cells, tiny, dmBytes(tinyBytes), overflow, len(svg), per, draw)

	start = time.Now()
	legend := dmLegend(res, res.Roots[0])
	t.Logf("legend %d rows in %v", len(legend), time.Since(start))
	for _, l := range legend {
		t.Logf("   %-20s %10s  %d files", l.Label, l.Size, l.Items)
	}
	if out := os.Getenv("DISKMAP_MEASURE_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(
			`<!doctype html><meta charset=utf-8><link rel=stylesheet href=app.css>`+
				`<link rel=stylesheet href=diskmap.css><body class=dm-page><main>`+svg+
				`</main>`), 0o644)
		t.Logf("wrote %s", out)
	}
}
