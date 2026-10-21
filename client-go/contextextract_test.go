//go:build !windows

package main

// Gates for ctx_extract (contextextract.go) — the op that turns a user's
// document into text ON THEIR MACHINE.
//
// These drive the REAL mgmt frame path with driveOp, so what is measured is what
// a host would actually get back: the caps gate, the argv, the refusals, and the
// text itself. The PDF below is a real one-page document built by hand (620
// bytes) rather than a fixture nobody can regenerate.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A valid one-page PDF whose visible text is exactly probePDFText. 11pt on a
// 612x792 MediaBox — at 24pt the string ran off the page and pdftotext returned
// it TRUNCATED, which would have made a full-string assertion fail for a reason
// that has nothing to do with this code.
const probePDFText = "PRIVATAE EXTRACTION PROBE alpha bravo charlie"

const probePDFB64 = "JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5" +
	"cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVu" +
	"dCAyIDAgUiAvTWVkaWFCb3ggWzAgMCA2MTIgNzkyXSAvUmVzb3VyY2VzIDw8IC9Gb250IDw8IC9GMSA1IDAgUiA+PiA+PiAv" +
	"Q29udGVudHMgNCAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCA3NiA+PgpzdHJlYW0KQlQgL0YxIDExIFRmIDcy" +
	"IDcwMCBUZCAoUFJJVkFUQUUgRVhUUkFDVElPTiBQUk9CRSBhbHBoYSBicmF2byBjaGFybGllKSBUaiBFVAplbmRzdHJlYW0K" +
	"ZW5kb2JqCjUgMCBvYmoKPDwgL1R5cGUgL0ZvbnQgL1N1YnR5cGUgL1R5cGUxIC9CYXNlRm9udCAvSGVsdmV0aWNhID4+CmVu" +
	"ZG9iagp4cmVmCjAgNgowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMDkgMDAwMDAgbiAKMDAwMDAwMDA1OCAwMDAwMCBu" +
	"IAowMDAwMDAwMTE1IDAwMDAwIG4gCjAwMDAwMDAyNDEgMDAwMDAgbiAKMDAwMDAwMDM2NyAwMDAwMCBuIAp0cmFpbGVyCjw8" +
	"IC9TaXplIDYgL1Jvb3QgMSAwIFIgPj4Kc3RhcnR4cmVmCjQzNwolJUVPRgo="

// driveExtract runs one ctx_extract job through the REAL mgmt frame path with a
// CONFIGURED context root.
//
// driveOp (anchor_test.go) passes empty roots, which is right for the ops it was
// written for but makes every rootCtx op answer "context store not configured" —
// and a test that asserts "was refused" would then pass on that refusal while
// proving nothing about this code. Measured: three of these tests went green
// that way before this helper existed.
func driveExtract(t *testing.T, self string, args []string) (string, string, int) {
	t.Helper()
	out, errOut, code, _ := driveExtractIn(t, self, args)
	return out, errOut, code
}

// driveExtractIn additionally hands back the context root it used, so a test can
// look at what the call left on disk.
func driveExtractIn(t *testing.T, self string, args []string) (string, string, int, string) {
	t.Helper()
	ctxRoot := t.TempDir()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handleMgmtConnFor(ws, self, ctxRoot, "", "")
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	job, _ := json.Marshal(mgmtJob{Op: "ctx_extract", Args: args, Approval: testApproval(t, "ctx_extract", args)})
	if err := c.WriteMessage(websocket.BinaryMessage, append([]byte("C"), job...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errOut string
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch data[0] {
		case 'O':
			out += string(data[1:])
		case 'R':
			errOut += string(data[1:])
		case 'X':
			var code int
			fmt.Sscanf(string(data[1:]), "%d", &code)
			return out, errOut, code, ctxRoot
		}
	}
}

// THE DOCUMENT MUST NOT SURVIVE THE CALL. It is the user's file, handed over for
// one job; a scratch copy left behind in the pairing's root would be this lane
// quietly accumulating their documents on their own disk, which is the opposite
// of the reason extraction runs here at all. Checked on BOTH paths — a tool that
// fails must clean up exactly as well as one that succeeds.
func TestCtxExtractLeavesNothingOnDisk(t *testing.T) {
	setupBox(t)
	if ok, _ := probePrepTool(prepTool{Name: "pdf-text", Bin: "pdftotext", Args: []string{"-v"}}); !ok {
		t.Skip("pdftotext not installed")
	}
	for _, tc := range []struct {
		name, b64 string
		wantCode  int
	}{
		{"a document it can read", probePDFB64, 0},
		{"a document it cannot", base64.StdEncoding.EncodeToString([]byte("not a pdf")), 1},
	} {
		_, _, code, root := driveExtractIn(t, tAnchor, []string{extractReq(t, "pdf-text", tc.b64)})
		if code != tc.wantCode {
			t.Fatalf("%s: code=%d want %d", tc.name, code, tc.wantCode)
		}
		left, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			names := []string{}
			for _, e := range left {
				names = append(names, e.Name())
			}
			t.Fatalf("%s: the user's document was left in the context root: %v", tc.name, names)
		}
	}
}

// A configured root must NOT be what makes this safe: the same job on a pairing
// without the dcn family is refused before the handler ever sees the root.

func extractReq(t *testing.T, tool, b64 string) string {
	t.Helper()
	b, err := json.Marshal(ctxExtractReq{Tool: tool, Mime: "application/pdf", B64: b64})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// THE WHOLE FEATURE IN ONE ASSERTION: a real PDF in, its real text out, over the
// real management frame.
func TestCtxExtractReturnsThePDFsText(t *testing.T) {
	setupBox(t)
	if ok, _ := probePrepTool(prepTool{Name: "pdf-text", Bin: "pdftotext", Args: []string{"-v"}}); !ok {
		t.Skip("pdftotext not installed on this box — a skip proves nothing, install poppler-utils")
	}
	out, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-text", probePDFB64)})
	if code != 0 {
		t.Fatalf("ctx_extract failed: code=%d err=%s", code, errOut)
	}
	var resp ctxExtractResp
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("reply is not JSON: %v (%q)", err, out)
	}
	if !strings.Contains(resp.Text, probePDFText) {
		t.Fatalf("extracted text does not contain the document's words.\n  want substring: %q\n  got: %q",
			probePDFText, resp.Text)
	}
	if resp.Tool != "pdf-text" || resp.Chars != len(resp.Text) || resp.Truncated {
		t.Fatalf("reply metadata disagrees with its own text: %+v", resp)
	}
}

// The caps gate, driven through the real frame. A pairing granted another family
// must not be able to make this machine run a program — this is the assertion
// that would fail if ctx_extract were ever renamed out of the ctx_ prefix, since
// opFamily returns "" for an unknown op and capsAllow then ALLOWS it.
func TestCtxExtractRefusedWithoutTheDCNFamily(t *testing.T) {
	priv := setupBox(t)
	writePairingState(t, tMember, pairingPending)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	terms, sig := signTerms(t, priv, grantTerms(tMember, []string{"observe"}, future))
	if _, errOut, code := driveOp(t, tAnchor, "pairing_grant_sync", []string{terms, sig}); code != 0 {
		t.Fatalf("could not install the observe-only grant: %d %s", code, errOut)
	}
	_, errOut, code := driveExtract(t, tMember, []string{extractReq(t, "pdf-text", probePDFB64)})
	if code == 0 {
		t.Fatal("a pairing granted only 'observe' ran an extractor on this machine")
	}
	if !contains(errOut, "dcn") && !contains(errOut, "caps") {
		t.Fatalf("refused, but not for the caps reason: %q", errOut)
	}
}

// Only a tool this build NAMES may run. Advertising a capability must never by
// itself be enough to execute something.
func TestCtxExtractRefusesAnUnknownTool(t *testing.T) {
	setupBox(t)
	// "transcribe" was the not-yet-a-job example here and is a real job now
	// (contextstt.go), so it is replaced rather than left to pass for the wrong
	// reason: it was still refused, but as "this is not audio" instead of "this
	// build has no such tool", which is not what this test asserts. "translate"
	// takes its place and is deliberately a job this lane might plausibly gain —
	// a name nobody would ever add is a weak stand-in.
	for _, tool := range []string{"", "rm", "pdf-text; rm -rf /", "translate"} {
		_, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, tool, probePDFB64)})
		if code == 0 {
			t.Fatalf("tool %q was accepted — only names in extractArgv may run", tool)
		}
		if !contains(errOut, "unknown tool") && !contains(errOut, "tool table") {
			t.Fatalf("tool %q refused for the wrong reason: %q", tool, errOut)
		}
	}
}

// Over the cap is REFUSED WITH ITS SIZE — never silently truncated, never partly
// extracted. The number has to be in the message or a caller cannot tell whether
// to split the document or wait for the pull lane.
func TestCtxExtractRefusesAnOversizeDocumentWithItsSize(t *testing.T) {
	setupBox(t)
	big := base64.StdEncoding.EncodeToString(make([]byte, ctxExtractMaxBytes+1))
	_, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-text", big)})
	if code == 0 {
		t.Fatal("a document over the cap was accepted")
	}
	if !contains(errOut, "8388609") || !contains(errOut, "8388608") {
		t.Fatalf("the refusal must state the document's size AND the cap, got: %q", errOut)
	}
	if contains(errOut, "truncat") && !contains(errOut, "not truncated") {
		t.Fatalf("refusal must not imply truncation: %q", errOut)
	}
}

// A document the tool cannot read fails with the TOOL's own words, not a generic
// error — a password-protected PDF should say so.
func TestCtxExtractSurfacesTheToolsOwnFailure(t *testing.T) {
	setupBox(t)
	if ok, _ := probePrepTool(prepTool{Name: "pdf-text", Bin: "pdftotext", Args: []string{"-v"}}); !ok {
		t.Skip("pdftotext not installed")
	}
	junk := base64.StdEncoding.EncodeToString([]byte("this is definitely not a PDF"))
	_, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-text", junk)})
	if code == 0 {
		t.Fatal("a non-PDF was accepted as extractable")
	}
	if !contains(errOut, "could not read this document") {
		t.Fatalf("unhelpful failure: %q", errOut)
	}
}

// Garbage in the envelope is refused before anything is written to disk or run.
func TestCtxExtractRefusesBadInput(t *testing.T) {
	setupBox(t)
	cases := map[string]string{
		"not json":       "{not json",
		"not base64":     extractReq(t, "pdf-text", "!!!! not base64 !!!!"),
		"empty document": extractReq(t, "pdf-text", ""),
	}
	for name, arg := range cases {
		if _, _, code := driveExtract(t, tAnchor, []string{arg}); code == 0 {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, _, code := driveExtract(t, tAnchor, nil); code == 0 {
		t.Fatal("a job with no argument at all was accepted")
	}
}

// ── the findings, as gates ──────────────────────────────────────────────────

// OUTPUT IS BOUNDED AS IT ARRIVES, not after the process exits. Extracted text
// is not proportional to the input: a 3.2 MB PDF whose 20,000 pages share one
// compressed stream made pdftotext emit ~83 MB and peaked the bastion at 211 MiB
// heap / 306 MiB allocated (measured). Capping the REPLY is too late —
// by then the bytes are already in memory, on the user's machine, times the
// worker count.
func TestRunExtractBoundsOutputAsItArrives(t *testing.T) {
	// 64 MiB of 'x' down stdout from a process that exits 0.
	out, timedOut, err := runExtract(20*time.Second, "sh", "-c",
		"head -c 67108864 /dev/zero | tr '\\0' 'x'")
	if err != nil || timedOut {
		t.Fatalf("the producer should have succeeded: err=%v timedOut=%v", err, timedOut)
	}
	if len(out) > ctxExtractMaxText+1 {
		t.Fatalf("captured %d bytes; the cap is %d — output is not bounded as it "+
			"arrives, so a runaway document costs whatever it feels like",
			len(out), ctxExtractMaxText+1)
	}
}

// A DEADLINE IS NOT A BAD DOCUMENT. Before this split, a timeout was reported as
// "could not read this document: <the first 400 chars OF THE USER'S OWN FILE>",
// presented to the model as the tool's explanation.
func TestRunExtractSeparatesATimeoutFromAFailure(t *testing.T) {
	_, timedOut, _ := runExtract(300*time.Millisecond, "sh", "-c", "sleep 5")
	if !timedOut {
		t.Fatal("a command that outlived its deadline must report timedOut")
	}
	_, timedOut2, err := runExtract(5*time.Second, "sh", "-c", "echo nope >&2; exit 3")
	if timedOut2 {
		t.Fatal("a command that FAILED must not be reported as a timeout")
	}
	if err == nil {
		t.Fatal("a non-zero exit must surface as an error")
	}
}

// Scratch left by a process that died mid-job is swept at start — nothing else
// would ever notice one of the user's documents sitting there.
func TestSweepStaleScratch(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"extract-111", "extract-222"} {
		if err := os.WriteFile(filepath.Join(root, n), []byte("a user's document"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(root, "ctx-blob-keep")
	if err := os.WriteFile(keep, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := sweepStaleScratch(root); n != 2 {
		t.Fatalf("swept %d, want 2", n)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("the sweep removed a file that was not extraction scratch")
	}
	if n := sweepStaleScratch(""); n != 0 {
		t.Fatal("an unconfigured root must sweep nothing")
	}
}

// An oversize document is refused WITHOUT being decoded. The frame already
// exists three times by the time the handler sees it (the websocket message,
// job.Args[0], req.B64); decoding first added a fourth copy of a body about to
// be refused. The estimate is the cheap gate; the exact check still runs after.
func TestCtxExtractRefusesOversizeBeforeDecoding(t *testing.T) {
	setupBox(t)
	// Deliberately NOT valid base64. If the handler decodes before checking the
	// size, it fails with "body is not base64" — which is how this test knows
	// the order regressed, rather than merely that something was refused.
	big := strings.Repeat("!", (ctxExtractMaxBytes/3)*4+64)
	_, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-text", big)})
	if code == 0 {
		t.Fatal("an oversize body was accepted")
	}
	if contains(errOut, "not base64") {
		t.Fatalf("the body was DECODED before its size was checked — the size "+
			"gate must come first: %q", errOut)
	}
	if !contains(errOut, "over the") {
		t.Fatalf("refused, but not for size: %q", errOut)
	}
}
