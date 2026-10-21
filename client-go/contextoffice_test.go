//go:build !windows

package main

// Gates for office-text (contextoffice.go).
//
// These drive REAL docx/xlsx/pptx files — written by LibreOffice, embedded in
// contextoffice_fixtures_test.go — through the REAL ctx_extract management
// frame, because an argv builder test would have proved nothing about the thing
// that actually decides whether this works.
//
// THE CONCURRENCY TEST IS THE POINT OF THIS FILE. LibreOffice, the obvious tool
// for this job, loses one of two simultaneous conversions in 5 of 5 trials with
// no message on either stream. This box runs mgmtWorkerCount management workers,
// so two extractions overlapping is ordinary operation, and a lane that fails
// that way fails invisibly. TestOfficeTextIsSafeUnderConcurrency is the standing
// proof that this implementation does not.

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func officeReq(t *testing.T, b64 string) string {
	t.Helper()
	b, err := json.Marshal(ctxExtractReq{
		Tool: "office-text",
		Mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		B64:  b64,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// driveOffice runs one office-text job through the real frame and returns the
// decoded reply.
func driveOffice(t *testing.T, b64 string) (ctxExtractResp, string, int) {
	t.Helper()
	out, errOut, code := driveExtract(t, tAnchor, []string{officeReq(t, b64)})
	var resp ctxExtractResp
	if code == 0 {
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("reply is not JSON: %v (%q)", err, out)
		}
	}
	return resp, errOut, code
}

// ── the whole feature, one format at a time ─────────────────────────────────

// A REAL WORD DOCUMENT IN, ITS REAL WORDS OUT, over the real management frame.
func TestOfficeTextReadsARealDOCX(t *testing.T) {
	setupBox(t)
	resp, errOut, code := driveOffice(t, fxDOCX)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	for _, want := range []string{"PRIVATAE EXTRACTION PROBE alpha bravo charlie",
		"A second paragraph with delta echo."} {
		if !strings.Contains(resp.Text, want) {
			t.Fatalf("the document's words are missing.\n  want: %q\n  got: %q", want, resp.Text)
		}
	}
	if resp.Chars != len(resp.Text) || resp.Truncated {
		t.Fatalf("reply metadata disagrees with its own text: %+v", resp)
	}
	// The language belongs to the OCR engine. A docx has none, and reporting
	// whichever tesseract pack this machine happens to hold as "the language
	// this document was read in" would be a guess wearing a fact's clothes.
	if resp.Lang != "" {
		t.Fatalf("a docx came back with a language on it: %q", resp.Lang)
	}
}

// A DECK: every slide in NUMERIC order, the speaker notes with them and
// labelled, and a slide with nothing on it still accounted for.
func TestOfficeTextReadsARealPPTXWithItsNotes(t *testing.T) {
	setupBox(t)
	resp, errOut, code := driveOffice(t, fxPPTX)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	one := strings.Index(resp.Text, "PRIVATAE SLIDE ONE echo foxtrot")
	three := strings.Index(resp.Text, "PRIVATAE SLIDE THREE golf hotel")
	if one < 0 || three < 0 {
		t.Fatalf("slide text missing: %q", resp.Text)
	}
	if one > three {
		t.Fatalf("slides came back out of order — slide 1 after slide 3:\n%s", resp.Text)
	}
	// THE NOTES ARE THE PROSE IN A DECK. A slide is noun phrases; the notes are
	// the sentences someone meant to say, and they are what a search for "the
	// deck where we explained the pricing change" has to hit.
	if !strings.Contains(resp.Text, "Remember to explain the pricing change here") {
		t.Fatalf("the speaker notes were dropped:\n%s", resp.Text)
	}
	if !strings.Contains(resp.Text, "Notes:") {
		t.Fatalf("the notes are merged into the slide instead of being labelled as notes:\n%s",
			resp.Text)
	}
	// A SLIDE WITH NO TEXT MUST STILL BE VISIBLE. Silence about it is the blind
	// answer: a user whose deck is photographs needs to see that there were
	// slides and they had no words, not an empty result.
	if !strings.Contains(resp.Text, "--- Slide 2 ---") {
		t.Fatalf("a slide with no text on it vanished from the extraction:\n%s", resp.Text)
	}
}

// ── spreadsheets are not prose ──────────────────────────────────────────────

// WHAT A SPREADSHEET EMITS, and every assertion here is a decision that would
// otherwise be invisible.
func TestOfficeTextEmitsASpreadsheetAsLabelledRecords(t *testing.T) {
	setupBox(t)
	resp, errOut, code := driveOffice(t, fxXLSX)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	text := resp.Text

	// THE SHEET NAME IS A HEADING. It is the user's own title for that data and
	// is often the only prose in a workbook — "Q3 Forecast" is what makes the
	// file findable, not the numbers under it.
	for _, want := range []string{"=== Sheet: Q3 Forecast ===", "=== Sheet: Headcount ==="} {
		if !strings.Contains(text, want) {
			t.Fatalf("the sheet's own name is not in the extraction: %q\n%s", want, text)
		}
	}
	// ONE ROW IS ONE LINE, with its labels in the same chunk, so a retrieval hit
	// hands back a whole record rather than a stray number.
	if !strings.Contains(text, "Region | Revenue | Signed") {
		t.Fatalf("the header row is not emitted as a line:\n%s", text)
	}
	if !strings.Contains(text, "Northwind | 1250 | 2023-09-15") {
		t.Fatalf("a data row is not emitted as one labelled record:\n%s", text)
	}
	// A FORMULA EMITS ITS RESULT. "=SUM(B2:B3)" is not what the user reads and
	// not what they would search for; 4150 is.
	if !strings.Contains(text, "Total | 4150") {
		t.Fatalf("the formula's cached result is missing:\n%s", text)
	}
	if strings.Contains(text, "SUM(") {
		t.Fatalf("the formula's SOURCE was emitted instead of its result:\n%s", text)
	}
	// DATES EMIT AS DATES. This is the one place the stored value is actively
	// WRONG rather than merely terse: the cell holds a day count and would come
	// back as "45184", a number nobody will ever search for. The leap day is
	// here on purpose — 1900 is not a leap year and Excel thinks it is, so an
	// off-by-one in the epoch shows up as 2024-02-28 or 2024-03-01.
	if !strings.Contains(text, "2024-02-29") {
		t.Fatalf("a date came back as something other than its date:\n%s", text)
	}
	if strings.Contains(text, "45184") || strings.Contains(text, "45349") {
		t.Fatalf("a date was emitted as its raw serial number:\n%s", text)
	}
	// A BLANK ROW IS DROPPED. A sheet is a sparse grid whose used range is far
	// larger than its content; emitting the padding buries the content.
	if strings.Contains(text, "\n\n\n") || strings.Contains(text, " | \n") {
		t.Fatalf("empty cells or rows were emitted as padding:\n%q", text)
	}
}

// ── the concurrency case, which is why LibreOffice is not used ──────────────

// TWO EXTRACTIONS AT ONCE, BOTH CORRECT.
//
// MEASURED on soffice 26.2.5.2 the same day this was written: two concurrent
// `--headless --convert-to` against one user profile, five trials, and in 5 of 5
// exactly one of the pair exited 1 having written no output file and NOTHING to
// stdout or stderr. Not an error — an empty failure, on a machine that runs
// several management workers, which would have surfaced as an intermittent and
// entirely unexplained "could not read this document" on documents that were
// fine.
//
// This implementation has no profile, no lock and no shared state: it is a
// function over a file. The test drives the three formats at once through
// separate frames and asserts every one of them came back whole, which is the
// assertion that would have failed on the other design.
func TestOfficeTextIsSafeUnderConcurrency(t *testing.T) {
	setupBox(t)
	// The approval device's key is created on first use. Six first uses at once
	// would each create their own key, and one extraction could sign with a key
	// another has written but not yet pinned. Create and pin it once, here, so
	// the goroutines below race only on the extraction this test is about.
	if currentAnchor() != nil {
		pub, err := deviceInit()
		if err != nil {
			t.Fatalf("device-init: %v", err)
		}
		if err := pinDeviceKey(pub); err != nil {
			t.Fatalf("pin-device: %v", err)
		}
	}
	cases := []struct {
		name, b64, want string
	}{
		{"docx", fxDOCX, "PRIVATAE EXTRACTION PROBE"},
		{"xlsx", fxXLSX, "=== Sheet: Q3 Forecast ==="},
		{"pptx", fxPPTX, "PRIVATAE SLIDE ONE echo foxtrot"},
		{"docx again", fxDOCX, "A second paragraph with delta echo."},
		{"xlsx again", fxXLSX, "Total | 4150"},
		{"pptx again", fxPPTX, "Remember to explain the pricing change here"},
	}
	// Several rounds: a lock-shaped failure is a race and one round of six can
	// win it by luck.
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		type result struct {
			name string
			resp ctxExtractResp
			err  string
			code int
		}
		results := make([]result, len(cases))
		for i, tc := range cases {
			wg.Add(1)
			go func(i int, tc struct{ name, b64, want string }) {
				defer wg.Done()
				resp, errOut, code := driveOffice(t, tc.b64)
				results[i] = result{tc.name, resp, errOut, code}
			}(i, tc)
		}
		wg.Wait()
		for i, r := range results {
			if r.code != 0 {
				t.Fatalf("round %d: %s failed while %d others ran alongside it: %s",
					round, r.name, len(cases)-1, r.err)
			}
			if !strings.Contains(r.resp.Text, cases[i].want) {
				t.Fatalf("round %d: %s came back WITHOUT its own content while others ran "+
					"alongside it — this is the shape of a shared-state failure.\n  want: %q\n  got: %q",
					round, r.name, cases[i].want, r.resp.Text)
			}
		}
	}
}

// ── cannot-do vs nothing-in-it ──────────────────────────────────────────────

// "THIS BOX CANNOT READ THAT" MUST NOT READ LIKE "THAT DOCUMENT HAD NO TEXT".
//
// The first is a non-zero exit with a sentence naming what the file actually is.
// The second is a SUCCESS with the structure of the document in it and no words
// — a deck of photographs comes back as its slide headings, never as silence.
func TestOfficeTextSaysCannotRatherThanEmpty(t *testing.T) {
	setupBox(t)

	notAZip := base64.StdEncoding.EncodeToString([]byte("this is definitely not an office document"))
	_, errOut, code := driveOffice(t, notAZip)
	if code == 0 {
		t.Fatal("a file that is not an Office package was accepted as extractable")
	}
	if !strings.Contains(errOut, "not an Office package") {
		t.Fatalf("refused, but without saying what the file is not: %q", errOut)
	}

	// A ZIP that is not an Office package at all — the message has to separate
	// "this is not one of these" from "this one is empty".
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("hello.txt")
	io.WriteString(w, "just a zip")
	zw.Close()
	_, errOut, code = driveOffice(t, base64.StdEncoding.EncodeToString(buf.Bytes()))
	if code == 0 {
		t.Fatal("an ordinary ZIP was accepted as an Office document")
	}
	if !strings.Contains(errOut, "ZIP but not an Office document") {
		t.Fatalf("refused, but not for the reason it was refused for: %q", errOut)
	}

	// AN ODF FILE IS NAMED AS ONE. It is the single most likely wrong file to
	// arrive here, and "cannot read this" would send the user looking for a
	// broken document instead of a Save As.
	odf := officeZip(t, map[string]string{
		"mimetype":              "application/vnd.oasis.opendocument.text",
		"content.xml":           `<x/>`,
		"META-INF/manifest.xml": `<x/>`,
	})
	_, errOut, code = driveOffice(t, base64.StdEncoding.EncodeToString(odf))
	if code == 0 {
		t.Fatal("an OpenDocument file was accepted as a docx")
	}
	if !strings.Contains(errOut, "OpenDocument") {
		t.Fatalf("an ODF file was refused without being identified: %q", errOut)
	}
}

// A DOCUMENT WITH NOTHING IN IT SUCCEEDS AND SAYS SO. It is not a failure —
// an empty document is a fact about the document, and reporting it as an error
// would make a user go looking for a fault in their machine.
func TestOfficeTextAnEmptyDocumentIsNotAFailure(t *testing.T) {
	setupBox(t)
	empty := officeZip(t, map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`,
		"word/document.xml": `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
			`<w:body><w:p/></w:body></w:document>`,
	})
	resp, errOut, code := driveOffice(t, base64.StdEncoding.EncodeToString(empty))
	if code != 0 {
		t.Fatalf("a document with no words in it was reported as a failure: %s", errOut)
	}
	if strings.TrimSpace(resp.Text) != "" {
		t.Fatalf("an empty document produced text: %q", resp.Text)
	}
}

// ── corrupt input ───────────────────────────────────────────────────────────

// A TRUNCATED PACKAGE FAILS FAST AND SAYS WHAT IT IS. Corrupt files exist in
// every real corpus and a hang is worse than an error.
func TestOfficeTextOnCorruptInput(t *testing.T) {
	setupBox(t)
	real, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fxDOCX, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"truncated", real[:len(real)/2]},
		{"header only", real[:200]},
		{"one byte", real[:1]},
	} {
		start := time.Now()
		_, errOut, code := driveOffice(t, base64.StdEncoding.EncodeToString(tc.body))
		if code == 0 {
			t.Fatalf("%s: a corrupt package was accepted", tc.name)
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("%s: took %v — a corrupt file must fail fast, not hang",
				tc.name, time.Since(start))
		}
		if !strings.Contains(errOut, "not an Office package") {
			t.Fatalf("%s: refused without naming the problem: %q", tc.name, errOut)
		}
	}
}

// A PART THAT IS MALFORMED PART-WAY KEEPS WHAT CAME OUT BEFORE IT. Throwing
// away nine readable slides because the tenth has broken XML helps nobody.
func TestOfficeTextKeepsWhatItReadBeforeBadXML(t *testing.T) {
	body := `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>the readable half</w:t></w:r></w:p><w:p><w:r><w:t>and then`
	text, partial := runsToText(body, "t", "p", "tab", "br", time.Time{})
	if !strings.Contains(text, "the readable half") {
		t.Fatalf("the text read before the break was thrown away: %q", text)
	}
	if !partial {
		t.Fatal("a part that failed to parse was reported as complete")
	}
}

// ── the zip bomb ────────────────────────────────────────────────────────────

// A PACKAGE THAT EXPANDS PAST THE SOURCE CEILING IS STOPPED, AND SAYS SO.
//
// MEASURED: 0.38 MB of ZIP declaring 69.2 MB of sheet XML — a 182x ratio — is
// stopped by the unpack budget in 82 ms. A size check on the FILE proves nothing
// here, which is the whole reason the budget counts decompressed bytes.
//
// And it is stopped LOUDLY. The first version of this guard skipped the sheet
// and returned zero characters with exit 0, which is a silently empty
// extraction of a document the user can see has data in it.
func TestOfficeTextStopsAZipBombAndSaysSo(t *testing.T) {
	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	row := `<row r="1">` + strings.Repeat(`<c r="A1"><v>7</v></c>`, 20) + `</row>`
	for sheet.Len() < officeMaxUnpacked+(8<<20) {
		sheet.WriteString(row)
	}
	sheet.WriteString(`</sheetData></worksheet>`)
	pkg := officeZip(t, map[string]string{
		"xl/workbook.xml": `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
			`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
			`<sheets><sheet name="Big" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/></Relationships>`,
		"xl/worksheets/sheet1.xml": sheet.String(),
	})
	if len(pkg) > 8<<20 {
		t.Fatalf("the bomb did not compress: %d bytes packed", len(pkg))
	}
	f := filepath.Join(t.TempDir(), "bomb.xlsx")
	if err := os.WriteFile(f, pkg, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	text, res, err := extractOffice(f, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("the package should be read up to the budget, not refused whole: %v", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatalf("the bomb was not bounded: %v", time.Since(start))
	}
	if !res.Partial {
		t.Fatal("a package stopped by the unpack budget was reported as complete")
	}
	if !strings.Contains(text, "could not be read") {
		t.Fatalf("the sheet was skipped SILENTLY — the user gets an empty result "+
			"from a workbook they can see has data in it:\n%q", text)
	}
}

// ── the builtin's own honesty ───────────────────────────────────────────────

// THE PROBE PROVES THE CAPABILITY, NOT A PROXY FOR IT. There is no binary to
// exit 0, so the probe runs the whole reader over a package built in memory and
// checks the words come back — the same reason ocrProve exists.
func TestOfficeProveRunsTheRealReader(t *testing.T) {
	ok, why := officeProve()
	if !ok {
		t.Fatalf("the built-in reader cannot read its own test document: %s", why)
	}
	// And the probe path the rest of the lane uses agrees, without looking for a
	// program that does not exist.
	var tool prepTool
	for _, tl := range prepToolTable {
		if tl.Name == "office-text" {
			tool = tl
		}
	}
	if tool.Name == "" {
		t.Fatal("office-text is not in prepToolTable")
	}
	if !tool.Builtin || tool.Bin != "" {
		t.Fatalf("office-text is advertised as needing a program: %+v", tool.Bin)
	}
	ok, ver, why := probePrepToolDetail(tool)
	if !ok {
		t.Fatalf("probePrepToolDetail refused a builtin: %s", why)
	}
	if ver == "" {
		t.Fatal("a builtin must still say what it is in the advertisement")
	}
}

// A BUILTIN IS ADVERTISED ON EVERY BOX. Nothing to install means nothing that
// can be missing, which is the one claim in this whole table that needs no
// machine-specific probe to be true.
func TestOfficeTextIsAlwaysAdvertised(t *testing.T) {
	setupBox(t)
	resetPrepCache()
	defer resetPrepCache()
	tools, scan, ok := prepCapable(tAnchor)
	if !ok {
		t.Fatal("a box with a builtin extractor reported no extraction capability at all")
	}
	found := false
	for _, tl := range tools {
		if tl.Name == "office-text" {
			found = true
			if !tl.Builtin {
				t.Fatal("office-text is advertised without saying it needs no install")
			}
			if tl.CeilingS != ctxExtractTimeoutFor("office-text").Seconds() {
				t.Fatalf("office-text advertises %.0fs but runs under %.0fs",
					tl.CeilingS, ctxExtractTimeoutFor("office-text").Seconds())
			}
		}
	}
	if !found {
		t.Fatalf("office-text needs no install and was still not advertised: %+v (scan %+v)",
			tools, scan)
	}
}

// THE USER'S DOCUMENT DOES NOT SURVIVE THE CALL, on this job as on the others.
func TestOfficeTextLeavesNothingOnDisk(t *testing.T) {
	setupBox(t)
	for _, tc := range []struct {
		name, b64 string
		wantCode  int
	}{
		{"a document it can read", fxXLSX, 0},
		{"a document it cannot", base64.StdEncoding.EncodeToString([]byte("not an office file")), 1},
	} {
		_, _, code, root := driveExtractIn(t, tAnchor, []string{officeReq(t, tc.b64)})
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

// ── helpers ─────────────────────────────────────────────────────────────────

func officeZip(t *testing.T, parts map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range parts {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ── the other transport ─────────────────────────────────────────────────────

// BOTH TRANSPORTS, PROVEN, NOT ASSUMED.
//
// The two paths converge on one scratch file, so "it must work for pull as well"
// is a reasonable expectation and it is exactly the kind of expectation that is
// wrong for an uninteresting reason. A spreadsheet is the case to drive it with:
// a workbook that has run to any size is the likeliest office document to pass
// the 8 MiB inline cap, and pull is the only way it arrives at all.
func TestOfficeTextWorksOnThePullTransport(t *testing.T) {
	setupBox(t)
	h, _ := startFakeHost(t, "bearer-abc")
	doc, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fxXLSX, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	tk := h.issue(doc)
	out, errOut, code, root := driveExtractIn(t, tAnchor,
		[]string{pullReq(t, "office-text", tk, int64(len(doc)), ctxPullMaxBytes)})
	if code != 0 {
		t.Fatalf("pulled office extraction failed: code=%d err=%s", code, errOut)
	}
	var resp ctxExtractResp
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("reply is not JSON: %v (%q)", err, out)
	}
	if !strings.Contains(resp.Text, "=== Sheet: Q3 Forecast ===") ||
		!strings.Contains(resp.Text, "Total | 4150") {
		t.Fatalf("the pulled workbook's content is missing:\n%s", resp.Text)
	}
	if resp.Source != "pull" {
		t.Fatalf("the reply must say which transport carried the document, got %q", resp.Source)
	}
	left, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("the pulled document was left in the context root: %v", left)
	}
}

// ── the three parsing defects, each against a file a real writer produced ────
//
// Each test below asserts TWICE: first that the fixture still has the structure
// the defect needs (read out of the package's own XML), then that the reader
// handles it. The first assertion is not ceremony — all three of these defects
// sat under a green suite because the fixtures in contextoffice_fixtures_test.go
// happen not to contain the structures involved, and a fixture that quietly
// stops exhibiting a bug turns its test into a rubber stamp.

// officePart returns one part of a base64 package, as text, for asserting on the
// FIXTURE rather than on the reader.
func officePart(t *testing.T, b64, part string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b64, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name != part {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	t.Fatalf("the fixture has no part %q", part)
	return ""
}

// officeSection returns the extracted text between one "--- Slide N ---" heading
// and the next, which is the unit a note is or is not attached to.
func officeSection(t *testing.T, text string, n int) string {
	t.Helper()
	head := fmt.Sprintf("--- Slide %d ---", n)
	i := strings.Index(text, head)
	if i < 0 {
		t.Fatalf("slide %d is not in the extraction at all:\n%s", n, text)
	}
	rest := text[i+len(head):]
	if j := strings.Index(rest, "--- Slide "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// A TEXT BOX'S WORDS GO IN ONCE, NOT TWICE.
//
// Word and LibreOffice both write a text box as <mc:AlternateContent>: an
// <mc:Choice> holding the DrawingML shape and an <mc:Fallback> holding the VML
// one, each carrying a complete copy of the same w:txbxContent. Those are
// ALTERNATIVES — ECMA-376 Part 3 has a consumer select exactly one branch — and
// a walker that takes every w:t in the part takes both, so every callout, pull
// quote and diagram label in the user's corpus is stored twice. Duplicated text
// is not cosmetic here: it is doubled embedding cost, two retrieval hits for one
// passage, and a document that looks like it says a thing twice.
func TestOfficeTextEmitsATextBoxOnce(t *testing.T) {
	setupBox(t)

	// THE FIXTURE STILL HAS THE STRUCTURE. If LibreOffice ever stops writing
	// both branches this test would pass for the wrong reason.
	doc := officePart(t, fxDOCXTextBox, "word/document.xml")
	if !strings.Contains(doc, "<mc:Choice") || !strings.Contains(doc, "<mc:Fallback") {
		t.Fatalf("the fixture no longer carries an mc:Choice/mc:Fallback pair — it cannot " +
			"exercise the defect it exists for")
	}
	if n := strings.Count(doc, "BOXPROBE UNIQUE CALLOUT WORDS"); n != 2 {
		t.Fatalf("the fixture's text box appears %d times in word/document.xml, want 2 "+
			"(once per alternate-content branch)", n)
	}

	resp, errOut, code := driveOffice(t, fxDOCXTextBox)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	if n := strings.Count(resp.Text, "BOXPROBE UNIQUE CALLOUT WORDS"); n != 1 {
		t.Fatalf("the text box was extracted %d times, want exactly 1 — both "+
			"alternate-content branches were walked:\n%s", n, resp.Text)
	}
	// And it is still there at all: dropping the box would be the other failure.
	for _, want := range []string{
		"BOXPROBE body paragraph before the callout",
		"BOXPROBE UNIQUE CALLOUT WORDS",
		"BOXPROBE body paragraph after the callout",
	} {
		if !strings.Contains(resp.Text, want) {
			t.Fatalf("the document lost %q:\n%s", want, resp.Text)
		}
	}
}

// SPEAKER NOTES BELONG TO THE SLIDE THE PACKAGE SAYS THEY DO.
//
// notesSlideN.xml is NOT slideN.xml's notes. The parts are numbered in the order
// they are created, so a deck where someone wrote notes on slide 3 before slide
// 2 has notesSlide1.xml attached to slide 3. The normative link is the
// relationship in ppt/slides/_rels/slideN.xml.rels, and it is the only thing
// that knows. Getting this wrong quotes one slide's words under another slide's
// heading, so a user who searches a phrase from their notes is sent to the wrong
// slide — a wrong answer delivered with a citation, which is worse than no hit.
func TestOfficeTextPairsNotesByRelationshipNotByFilename(t *testing.T) {
	setupBox(t)

	// THE FIXTURE'S OWN RELATIONSHIPS, so the expectation below is read out of
	// the file rather than assumed.
	if r := officePart(t, fxPPTXNotesMisnumbered, "ppt/slides/_rels/slide1.xml.rels"); strings.Contains(r, "notesSlide") {
		t.Fatalf("the fixture's slide 1 now HAS notes — it cannot exercise the defect:\n%s", r)
	}
	if r := officePart(t, fxPPTXNotesMisnumbered, "ppt/slides/_rels/slide3.xml.rels"); !strings.Contains(r, "notesSlides/notesSlide1.xml") {
		t.Fatalf("the fixture's slide 3 no longer points at notesSlide1.xml — the "+
			"mis-numbering it exists to catch is gone:\n%s", r)
	}

	resp, errOut, code := driveOffice(t, fxPPTXNotesMisnumbered)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	// SLIDE 1 HAS NO NOTES. Filename pairing hands it notesSlide1.xml, which is
	// slide THREE's.
	if s := officeSection(t, resp.Text, 1); strings.Contains(s, "NOTEBODY") {
		t.Fatalf("slide 1 has no notes in this deck, and notes were printed under it "+
			"anyway — this is another slide's words attributed to slide 1:\n%s", s)
	}
	if s := officeSection(t, resp.Text, 2); !strings.Contains(s, "NOTEBODY belongs to slide two echo") {
		t.Fatalf("slide 2's own notes are not under slide 2:\n%s", s)
	}
	if s := officeSection(t, resp.Text, 3); !strings.Contains(s, "NOTEBODY belongs to slide three delta") {
		t.Fatalf("slide 3's notes were lost — they live in notesSlide1.xml and the "+
			"reader looked for notesSlide3.xml:\n%s", s)
	}
}

// AN OMITTED CELL IS AN EMPTY COLUMN, NOT A MISSING ONE.
//
// A spreadsheet writer emits a <c> only for cells that exist; an untouched
// interior cell is absent from the XML entirely. Its column therefore lives in
// its r="D3" reference and NOWHERE ELSE, so appending cells in document order
// slides every value after a gap to the left. That is silent record corruption:
// the extracted line still reads as a clean labelled record, and it asserts that
// a number belongs to a column it does not belong to. Nothing downstream can
// detect it, which is why this is the worst of the three.
func TestOfficeTextKeepsAValueUnderItsOwnColumn(t *testing.T) {
	setupBox(t)

	// THE FIXTURE STILL OMITS THE GAP. If a future regeneration materialises
	// B3/C3 the file stops testing anything.
	sheet := officePart(t, fxXLSXSparseRow, "xl/worksheets/sheet1.xml")
	for _, absent := range []string{`<c r="B3"`, `<c r="C3"`, `<c r="B4"`} {
		if strings.Contains(sheet, absent) {
			t.Fatalf("the fixture no longer omits %s — it cannot exercise the defect", absent)
		}
	}
	for _, present := range []string{`<c r="A3"`, `<c r="D3"`} {
		if !strings.Contains(sheet, present) {
			t.Fatalf("the fixture lost %s", present)
		}
	}

	resp, errOut, code := driveOffice(t, fxXLSXSparseRow)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	header := officeLineWith(t, resp.Text, "Account")
	hdr := strings.Split(header, officeRowSep)
	balance := -1
	for i, h := range hdr {
		if strings.TrimSpace(h) == "Balance" {
			balance = i
		}
	}
	if balance < 0 {
		t.Fatalf("the header row did not come out as a record: %q", header)
	}
	// THE ASSERTION. 999 is in column D, under "Balance", in a row whose B and C
	// are not in the file at all.
	row := strings.Split(officeLineWith(t, resp.Text, "SPARSEACCOUNT"), officeRowSep)
	if len(row) <= balance || strings.TrimSpace(row[balance]) != "999" {
		t.Fatalf("the value in column D came back under column %q instead of %q — the "+
			"omitted interior cells collapsed and shifted the row left.\n  header: %q\n  row:    %q",
			strings.TrimSpace(hdr[min(len(hdr)-1, len(row)-1)]), "Balance", header,
			strings.Join(row, officeRowSep))
	}
	// The second gap shape — one missing cell, not two — for the same reason.
	row4 := strings.Split(officeLineWith(t, resp.Text, "Eastwind"), officeRowSep)
	if len(row4) <= balance || strings.TrimSpace(row4[balance]) != "42" {
		t.Fatalf("a single omitted cell shifted the rest of the row:\n  %q", strings.Join(row4, officeRowSep))
	}
	region := -1
	for i, h := range hdr {
		if strings.TrimSpace(h) == "Region" {
			region = i
		}
	}
	if strings.TrimSpace(row4[region]) != "East" {
		t.Fatalf("%q is not under %q:\n  %q", "East", "Region", strings.Join(row4, officeRowSep))
	}
}

func officeLineWith(t *testing.T, text, want string) string {
	t.Helper()
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	t.Fatalf("no line containing %q:\n%s", want, text)
	return ""
}

// THE BRANCH-SELECTION RULE ITSELF, on the shapes a real package produces around
// the one the fixture pins. The docx fixture proves the common case end to end;
// these are the neighbours of it that a hand-check would otherwise have to be
// trusted for — and each one is a way a naive "skip every mc:Fallback" would be
// wrong.
func TestOfficeTextTakesOneAlternateContentBranch(t *testing.T) {
	doc := func(inner string) string {
		return `<?xml version="1.0"?><w:document ` +
			`xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ` +
			`xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">` +
			`<w:body>` + inner + `</w:body></w:document>`
	}
	run := func(inner string) string {
		s, _ := runsToText(doc(inner), "t", "p", "tab", "br", time.Time{})
		return strings.TrimSpace(s)
	}
	for _, tc := range []struct{ name, in, want string }{
		{
			// A package with NO Choice at all still has its words read. Skipping
			// every Fallback outright would silently drop this one.
			"fallback is used when there is no choice",
			`<w:p><mc:AlternateContent><mc:Fallback><w:r><w:t>ONLYFALLBACK</w:t></w:r>` +
				`</mc:Fallback></mc:AlternateContent></w:p>`,
			"ONLYFALLBACK",
		},
		{
			// Several Choices are several alternatives, not several parts.
			"the first choice wins and the rest are alternatives",
			`<w:p><mc:AlternateContent>` +
				`<mc:Choice Requires="a"><w:r><w:t>FIRST</w:t></w:r></mc:Choice>` +
				`<mc:Choice Requires="b"><w:r><w:t>SECOND</w:t></w:r></mc:Choice>` +
				`<mc:Fallback><w:r><w:t>FB</w:t></w:r></mc:Fallback>` +
				`</mc:AlternateContent></w:p>`,
			"FIRST",
		},
		{
			// A text box inside a text box: the inner element's selection must not
			// leak into the outer one's, in either direction.
			"they nest",
			`<w:p><mc:AlternateContent><mc:Choice Requires="a"><w:r><w:t>OUTER </w:t></w:r>` +
				`<mc:AlternateContent><mc:Choice Requires="c"><w:r><w:t>INNER</w:t></w:r></mc:Choice>` +
				`<mc:Fallback><w:r><w:t>INNERFB</w:t></w:r></mc:Fallback></mc:AlternateContent>` +
				`</mc:Choice><mc:Fallback><w:r><w:t>OUTERFB</w:t></w:r></mc:Fallback>` +
				`</mc:AlternateContent></w:p>`,
			"OUTER INNER",
		},
		{
			// Two in a row: the second must not inherit "a branch was already
			// taken" from the first, which is what a bare flag would have done.
			"two in sequence each get their own branch",
			`<w:p><mc:AlternateContent><mc:Choice Requires="a"><w:r><w:t>C1</w:t></w:r></mc:Choice>` +
				`<mc:Fallback><w:r><w:t>F1</w:t></w:r></mc:Fallback></mc:AlternateContent></w:p>` +
				`<w:p><mc:AlternateContent><mc:Choice Requires="a"><w:r><w:t>C2</w:t></w:r></mc:Choice>` +
				`<mc:Fallback><w:r><w:t>F2</w:t></w:r></mc:Fallback></mc:AlternateContent></w:p>`,
			"C1\nC2",
		},
		{
			// TRACKED CHANGES come out in final-view form, which readDOCX's note
			// records as a consequence of the element names rather than a choice —
			// so it is pinned here rather than believed.
			"an insertion is text and a deletion is not",
			`<w:p><w:ins><w:r><w:t>INSERTED</w:t></w:r></w:ins>` +
				`<w:del><w:r><w:delText>DELETED</w:delText></w:r></w:del>` +
				`<w:r><w:t> kept</w:t></w:r></w:p>`,
			"INSERTED kept",
		},
	} {
		if got := run(tc.in); got != tc.want {
			t.Errorf("%s:\n  want %q\n  got  %q", tc.name, tc.want, got)
		}
	}
}

// A CELL REFERENCE IS BIJECTIVE BASE-26, which is the one place this arithmetic
// is easy to get wrong by a whole column at every carry.
func TestXLSXColumnFromReference(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		want int
	}{
		{"A1", 0}, {"B2", 1}, {"D3", 3}, {"Z1", 25},
		{"AA1", 26}, {"AB1", 27}, {"AZ1", 51}, {"BA1", 52},
		{"XFD1048576", 16383}, // the last column the format has
		{"a1", 0},             // lowercase is not emitted, and is not worth refusing
		{"", -1}, {"1", -1}, {"XFE1", -1}, {"ZZZZ1", -1},
	} {
		if got := colFromRef(tc.ref); got != tc.want {
			t.Errorf("colFromRef(%q) = %d, want %d", tc.ref, got, tc.want)
		}
	}
}
