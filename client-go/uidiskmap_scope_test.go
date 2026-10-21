package main

// Two non-blocking review notes on the disk map, taken rather than
// carried. Neither is a hole — the Origin check already refuses a cross-site
// POST, and losing your place is not a security bug — but a finding nobody
// clears is a finding somebody re-finds.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Three of the five read pages enforced GET and two did not. The inconsistency
// is the finding: a reader deciding whether this codebase checks methods on
// reads got a different answer depending on which file they opened.
func TestEveryReadPageIsGETOnly(t *testing.T) {
	uiTestConfigDir(t)
	u := uiTestServer(t)
	h := u.handler()
	tok, _ := u.sessions.mint()
	cookie := uiCookieName + "=" + tok

	for _, path := range []string{
		"/given", "/fragments/given",
		"/diskmap", "/fragments/diskmap",
		"/setup", "/agents", "/fragments/agents", "/policy", "/fragments/policy",
	} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		r.Host = "127.0.0.1:" + uiTestPort
		r.Header.Set("Origin", "http://127.0.0.1:"+uiTestPort)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405 — it is a read, and the pages disagreeing "+
				"about whether reads check the method is how the next one gets written "+
				"without a check", path, w.Code)
		}
	}
}

// Re-scanning from inside a folder dropped the user at the root of the disk,
// because the start branch rendered with an empty path. On a machine with a
// million files, being returned to the top is the difference between a tool and
// a demo.
func TestRescanningKeepsWhereYouWereStanding(t *testing.T) {
	uiTestConfigDir(t)
	// A REAL WALK IS NOT A FIXTURE. Without this the POST below drives the
	// machine-wide diskMap, whose roots are the actual volumes (diskmap.go:620
	// — `var diskMap = &dmState{scan: dmScan, roots: dmDefaultRoots}`), so the
	// first version of this test walked the disk of whoever ran it. Measured
	// before fixing: running=true, 140,000 entries, 5.6GB, roots=[/], 300ms in.
	// diskmap.go:611-612 says a test never does that, and every sibling here
	// installs the seam; this one had shipped without it.
	s := dmTestInstall(t, nil)
	release := make(chan struct{})
	// LIFO: this runs BEFORE dmTestInstall's restore, so the walker goroutine
	// is unblocked and gone before the package-wide map is put back.
	t.Cleanup(func() { close(release) })
	s.scan = func(context.Context, []string, int, func(dmProgress)) *dmResult {
		<-release
		return &dmResult{TakenAt: uiNow()}
	}
	u := uiTestServer(t)
	cookie := uiSignedIn(t, u)

	// THE MECHANISM IS THE POLL, not the body text. A fresh scan renders the
	// progress view, which shows no path at all — so asserting on rendered words
	// proved nothing (the first version of this test passed with the fix removed).
	// What decides where the person lands is the ?p= on the fragment poll the
	// scanning view emits: when the walk finishes, that poll is what draws the
	// finished map.
	const deep = "/home/user/Documents"
	w := uiPost(t, u.handler(), "/diskmap/scan", url.Values{"p": {deep}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("scan = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/diskmap?p=`) {
		t.Fatalf("the scanning view polls with no ?p=, so the finished map will draw "+
			"the root and move the person without telling them. Body:\n%s", body)
	}
	if !strings.Contains(body, url.QueryEscape(deep)) {
		t.Errorf("the poll does not carry %q", deep)
	}
}

// The form has to CARRY the path, or the handler's fix is unreachable from the
// page: a fix the UI never exercises is a fix in name only.
func TestTheRescanFormCarriesTheCurrentPath(t *testing.T) {
	src := readSourceFile(t, "uiassets/diskmap.html")
	i := strings.Index(src, `hx-post="/diskmap/scan"`)
	if i < 0 {
		t.Fatal("the scan form is gone — this check would pass for ever")
	}
	// Look at every scan form, not just the first: the page has two.
	forms := strings.Count(src, `hx-post="/diskmap/scan"`)
	carried := strings.Count(src, `name="p" value="{{.Path}}"`)
	if forms < 2 {
		t.Fatalf("expected both scan forms, found %d", forms)
	}
	if carried < 1 {
		t.Error("no scan form carries the current path, so re-scanning from inside a " +
			"folder returns the user to the root of the disk without saying so")
	}
}

// ── and the rule that was only ever written down ────────────────────────────

// diskmap.go:611-612 says the roots are "swapped in tests so a test never walks
// a developer's real disk", and every test in uidiskmap_test.go obeys it — but
// obedience was a convention, so the first version of the re-scan test above
// broke it silently. Nothing failed: a test that walks the machine still
// passes, it just takes the disk with it (measured: 140,000 entries and 5.6GB
// in the 300ms before the assertions finished, on a box whose full-suite run
// already has a load-sensitive async lane in it).
//
// This is the convention made mechanical. Parse the package's own test sources
// and require the seam wherever a test can actually start a walk.
const dmGuardSelf = "TestNoTestCanStartARealDiskWalk"

func TestNoTestCanStartARealDiskWalk(t *testing.T) {
	fset := token.NewFileSet()
	names, err := packageTestFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 20 {
		t.Fatalf("only %d _test.go files found — the scan has stopped finding them, "+
			"which makes this check a green light that proves nothing", len(names))
	}

	checked := 0
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == dmGuardSelf {
				continue
			}
			var startsAWalk, posts, installs bool
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					// Comments are not in the AST, so a route named in prose
					// cannot trip this.
					if x.Kind == token.STRING && strings.Contains(x.Value, "/diskmap/scan") {
						startsAWalk = true
					}
				case *ast.Ident:
					switch x.Name {
					case "uiPost", "MethodPost":
						posts = true
					case "dmTestInstall":
						installs = true
					}
				case *ast.SelectorExpr:
					// diskMap.dmStart() reaches the machine-wide map directly.
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "diskMap" &&
						strings.HasPrefix(x.Sel.Name, "dmStart") {
						startsAWalk, posts = true, true
					}
				}
				return true
			})
			// A GET at the route is refused by guarded() before the handler
			// runs, which is exactly what the rebinding and signed-out tests
			// assert — they name the route and must not be dragged in here.
			if !startsAWalk || !posts {
				continue
			}
			checked++
			if !installs {
				t.Errorf("%s (%s) can start a disk walk and does not call dmTestInstall. "+
					"Without it the POST drives the package-wide diskMap, whose roots are "+
					"this machine's actual volumes (diskmap.go:620), so the test walks the "+
					"disk of whoever runs it — and still passes. The seam is five lines: "+
					"`s := dmTestInstall(t, nil)` then a `s.scan` that blocks on a channel "+
					"closed in t.Cleanup.", fn.Name.Name, name)
			}
		}
	}
	if checked < 3 {
		t.Fatalf("only %d walk-starting tests found; this check has stopped seeing them", checked)
	}
}

func packageTestFiles() ([]string, error) {
	ents, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), "_test.go") {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
