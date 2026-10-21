//go:build !windows

package main

// Gates for two findings about WHICH pages of a PDF reach the OCR engine:
// the layer-first order, and the stamp band.
//
// LAYER FIRST — pdf-ocr rasterized every page before it looked at the text layer, and the
// reason written in the source was that the extra rendered page doubled as the
// page-count probe, so the job needed two binaries rather than three. MEASURED
// on this box (poppler 26.01.0), against the same two-page document:
//
//	pdftotext -layout -q -f 1 -l 31 -- doc.pdf -    6.2 ms   exit 0, exactly 2 form feeds
//	pdftoppm  -png -gray -r 300 -f 1 -l 3 doc.pdf   978.5 ms  2 PNGs
//
// So the layer pass carries the page count for free with the same cap+1 trick,
// on a binary pdf-ocr already runs, and the justification did not survive the
// measurement. These gates pin the restructured order.
//
// THE STAMP BAND — a stamp, a fax header or a scanner footer over a scanned page puts a
// handful of REAL characters in the text layer of a page that is otherwise a
// picture. Under a 16-character band that page never reached the engine, and the
// user got the stamp instead of their document.
//
// Every test here drives the real poppler and the real tesseract.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ── fixtures, built here rather than pasted as base64 ──────────────────────

// densePDF is a text PDF of n pages, each carrying well over ocrPageHasText
// characters — an ordinary born-digital document, the case the layer-first order is about.
//
// Built rather than embedded so the per-page character count is a number this
// file states and can assert, instead of a property of an opaque blob.
func densePDF(t *testing.T, n int) ([]byte, int) {
	t.Helper()
	const line = "the quick brown fox jumps over the lazy dog 0123456789"
	const lines = 24
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"", // filled below: the page tree
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	kids := []string{}
	perPage := 0
	for p := 1; p <= n; p++ {
		var c bytes.Buffer
		for i := 0; i < lines; i++ {
			fmt.Fprintf(&c, "BT /F1 11 Tf 72 %d Td (p%d %s) Tj ET\n", 720-i*24, p, line)
		}
		objs = append(objs,
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", c.Len(), c.String()))
		contents := len(objs)
		objs = append(objs, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "+
			"/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", contents))
		kids = append(kids, fmt.Sprintf("%d 0 R", len(objs)))
		perPage = lines * (len(line) + 4)
	}
	objs[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), n)
	return assemblePDF(objs), perPage
}

// stampedScanPDF is ONE page that is a picture of words, with a short REAL text
// layer written over it — a copier footer, a fax TTI header, a Bates number.
//
// The picture is the image XObject out of scannedPDFB64, this package's existing
// image-only fixture, so the page really is a scan and not a drawing of one. The
// stamp is ordinary visible Helvetica, which is what a scanner app, a fax MFP or
// an e-signature service actually writes.
func stampedScanPDF(t *testing.T, stamp string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scannedPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	img, w, h := grabImageXObject(t, raw)
	content := fmt.Sprintf("q 612 0 0 792 0 0 cm /Im1 Do Q\nBT /F1 9 Tf 36 768 Td (%s) Tj ET\n",
		strings.NewReplacer("\\", `\\`, "(", `\(`, ")", `\)`).Replace(stamp))
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources " +
			"<< /XObject << /Im1 5 0 R >> /Font << /F1 6 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace "+
			"/DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream",
			w, h, len(img), img),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	return assemblePDF(objs)
}

// grabImageXObject lifts the deflated image stream, and its pixel dimensions,
// out of a PDF that holds exactly one image.
func grabImageXObject(t *testing.T, pdf []byte) (string, int, int) {
	t.Helper()
	re := regexp.MustCompile(`(?s)/Length (\d+) 0 R\s*/Subtype /Image\s*/Width (\d+)\s*/Height (\d+).*?stream\r?\n`)
	m := re.FindSubmatchIndex(pdf)
	if m == nil {
		t.Fatal("the scanned fixture no longer holds an image XObject in the expected shape")
	}
	var w, h int
	fmt.Sscan(string(pdf[m[4]:m[5]]), &w)
	fmt.Sscan(string(pdf[m[6]:m[7]]), &h)
	start := m[1]
	end := bytes.Index(pdf[start:], []byte("\nendstream"))
	if end < 0 {
		t.Fatal("the scanned fixture's image stream has no endstream")
	}
	data := pdf[start : start+end]
	// Prove it really is the deflated raster and not something that merely parses.
	if _, err := zlib.NewReader(bytes.NewReader(data)); err != nil {
		t.Fatalf("the scanned fixture's image stream is not deflate: %v", err)
	}
	return string(data), w, h
}

// assemblePDF writes objects 1..n with a correct xref, the same way
// mixedLayerPDF does.
func assemblePDF(objs []string) []byte {
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offs := make([]int, 0, len(objs))
	for i, o := range objs {
		offs = append(offs, pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objs)+1, xref)
	return pdf.Bytes()
}

// ── observing which binaries a job actually ran ────────────────────────────

// spyBinary puts a shim for `name` at the FRONT of PATH that records every
// invocation and then execs the real binary.
//
// The property under test — "a text PDF renders no pages" — is invisible in
// pdf-ocr's return value and the scratch directory is removed before the job
// returns, so the only honest place to observe it is at the process boundary.
// This observes exactly that, against the real tool, with no seam added to
// production code for a test's benefit.
func spyBinary(t *testing.T, name string) (log func() []string) {
	t.Helper()
	real, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed on this machine", name)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, name+".log")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexec %q \"$@\"\n", logPath, real)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, err := os.ReadFile(logPath)
		if err != nil {
			return nil
		}
		return strings.FieldsFunc(strings.TrimSpace(string(b)), func(r rune) bool { return r == '\n' })
	}
}

// hideBinary removes `name` from this test's PATH while leaving every other tool
// reachable, so a job that depends on it takes the path it takes when poppler
// will not answer.
func hideBinary(t *testing.T, keep []string, hide string) {
	t.Helper()
	dir := t.TempDir()
	for _, k := range keep {
		p, err := exec.LookPath(k)
		if err != nil {
			t.Skipf("%s is not installed on this machine", k)
		}
		if err := os.Symlink(p, filepath.Join(dir, k)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.LookPath(hide); err != nil {
		t.Skipf("%s is not installed on this machine, so there is nothing to hide", hide)
	}
	t.Setenv("PATH", dir)
	if _, err := exec.LookPath(hide); err == nil {
		t.Fatalf("%s is still reachable after narrowing PATH — the test is not testing anything", hide)
	}
}

// ── layer first ─────────────────────────────────────────────────────────────

// A TEXT PDF RENDERS NOTHING.
//
// pdf-ocr's contract is "this PDF's text, reading the pages that have none". For
// a born-digital document that is every page from the text layer and no engine
// work at all — and, with the layer read first, no RASTER work either. Rasterizing first taxed
// every text document about 160x on this box (6.2 ms of layer pass against
// 978.5 ms of render for two pages) for a page count the layer pass already
// carries.
func TestATextPDFRendersNoPages(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	raw, perPage := densePDF(t, 2)
	if perPage <= ocrPageHasText {
		t.Fatalf("the fixture carries ~%d chars per page, which is not above the "+
			"%d-character band — it cannot test the text-document path",
			perPage, ocrPageHasText)
	}
	src := filepath.Join(dir, "text.pdf")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	seen := spyBinary(t, "pdftoppm")
	text, pages, total, deadline, err := runPDFOCRCapped(dir, src,
		time.Now().Add(ocrExtractTimeout), 30)
	if err != nil {
		t.Fatalf("pdf-ocr failed on a text PDF: %v", err)
	}
	if deadline {
		t.Fatal("a two-page text PDF ran out of time")
	}
	if ran := seen(); len(ran) != 0 {
		t.Fatalf("a text PDF rasterized pages it never needed — pdftoppm ran %d time(s):\n  %s\n"+
			"every page of this document has a text layer, so the render is pure cost on "+
			"the user's machine", len(ran), strings.Join(ran, "\n  "))
	}
	if len(pages) != 2 || total != 2 {
		t.Fatalf("read %d pages, total=%d, want 2 and 2 — the page count has to survive "+
			"the move to a layer-first order", len(pages), total)
	}
	for _, p := range pages {
		if p.How != "text" {
			t.Fatalf("page %d of a text document was recorded as how=%q", p.Page, p.How)
		}
	}
	if !strings.Contains(text, "p1 the quick brown fox") || !strings.Contains(text, "p2 the quick brown fox") {
		t.Fatalf("both pages' text did not come back:\n%s", text)
	}
}

// THE PAGE COUNT STILL COMES FROM THE cap+1 TRICK, only now on the layer pass.
// A document with a page past the cap has to say so, and it must say so without
// rendering that page — which is the whole saving.
func TestMorePagesIsAnsweredByTheLayerPass(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	raw, _ := densePDF(t, 3)
	src := filepath.Join(dir, "text.pdf")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	seen := spyBinary(t, "pdftoppm")
	_, pages, total, _, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Fatalf("read %d pages with the cap at 2", len(pages))
	}
	if total >= 0 {
		t.Fatal("a 3-page document under a cap of 2 was reported complete — the user " +
			"would have no way to know the rest of their document exists")
	}
	if ran := seen(); len(ran) != 0 {
		t.Fatalf("answering \"is there a page past the cap\" rendered %d page(s); the "+
			"layer pass carries the count for free:\n  %s", len(ran), strings.Join(ran, "\n  "))
	}
}

// POPPLER REFUSING THE LAYER IS NOT A REFUSAL OF THE DOCUMENT.
//
// The layer pass carries both the text and the page count, so when it returns
// neither there is no count to work from and the job falls back to the render
// probe that used to be unconditional. Losing that fallback would turn "I could
// not read the text layer" into "I could not read your document", which is the
// sentence this whole lane exists to avoid.
//
// Driven by taking pdftotext off this test's PATH: that produces exactly the
// condition — a layer pass that answers with nothing and no page count — against
// the real rasterizer and the real engine, without needing a PDF that poppler's
// two halves happen to disagree about.
func TestAScanIsStillReadWhenTheLayerPassAnswersNothing(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "scan.pdf")
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scannedPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	hideBinary(t, []string{"pdftoppm", "tesseract"}, "pdftotext")

	text, pages, total, deadline, err := runPDFOCRCapped(dir, src,
		time.Now().Add(ocrExtractTimeout), 30)
	if err != nil {
		t.Fatalf("a document whose text layer could not be read was refused outright: %v", err)
	}
	if deadline {
		t.Fatal("a two-page scan ran out of time")
	}
	if len(pages) != 2 || total != 2 {
		t.Fatalf("read %d pages, total=%d, want 2 and 2 — with no layer pass the page "+
			"count has to come from the render probe", len(pages), total)
	}
	for _, p := range pages {
		if p.How != "ocr" {
			t.Fatalf("page %d was recorded as how=%q with no text layer available at all",
				p.Page, p.How)
		}
	}
	if !strings.Contains(text, ocrFixtureLine1) {
		t.Fatalf("the document came back without its words:\n%s", text)
	}
}

// ── the stamp band ──────────────────────────────────────────────────────────

// ocrStampFixture is the exact case that was reported: twenty-one characters
// of scanner footer over a page that is otherwise a picture of words.
const ocrStampFixture = "Scanned by CamScanner"

// A STAMP OVER A SCAN MUST NOT STAND IN FOR THE PAGE.
//
// The band was 16 characters, so this page's 21-character footer read as "this
// page has a text layer" and the body of the document never reached the engine.
// The user got the name of the app that scanned it and nothing they wrote.
//
// MEASURED on this box, this fixture: layer 21 chars, OCR of the same page 88
// chars — a ratio of 4.2, against the 2.0 the comparison requires. On a
// full-page scan the ratio is far wider still (26x to 142x across five real
// stamp formats over a 2,530-character page).
func TestAStampedScanReturnsThePageNotTheStamp(t *testing.T) {
	needPDFOCR(t)
	if len(ocrStampFixture) != 21 {
		t.Fatalf("the stamp is %d chars; the reported case is 21", len(ocrStampFixture))
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "stamped.pdf")
	if err := os.WriteFile(src, stampedScanPDF(t, ocrStampFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	// The layer measured through the real binary first, at arm's length from
	// this package's own helpers, so a failure below says which half moved
	// rather than blaming the code.
	out, lerr := runCmd(30*time.Second, "pdftotext", "-layout", "-q", "-f", "1", "-l", "1", "--", src, "-")
	if got := strings.TrimSpace(strings.ReplaceAll(out, "\f", "")); lerr != nil || got != ocrStampFixture {
		t.Skipf("this poppler does not read the fixture's stamp as %q (got %q, err=%v) — "+
			"the fixture, not the code, is what changed", ocrStampFixture, got, lerr)
	}

	text, pages, _, deadline, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 1)
	if err != nil {
		t.Fatalf("pdf-ocr failed on the stamped scan: %v", err)
	}
	if deadline {
		t.Fatal("one page ran out of time")
	}
	if len(pages) != 1 {
		t.Fatalf("read %d pages, want 1", len(pages))
	}
	if !strings.Contains(text, ocrFixtureLine1) {
		t.Fatalf("a scanned page carrying a %d-character stamp came back as the stamp "+
			"and nothing else.\n  the page says %q\n  what was indexed: %q\n"+
			"the user believes this document is in their corpus; its body is not",
			len(ocrStampFixture), ocrFixtureLine1, strings.TrimSpace(text))
	}
	if pages[0].How != "ocr" {
		t.Fatalf("the page was recorded as how=%q after the engine's reading was kept",
			pages[0].How)
	}
}

// THE OTHER SIDE OF THE SAME WIDENING, and the one that makes it safe to widen.
//
// Widening the band admits genuinely sparse TEXT pages — a title page, a section
// divider — to the comparison, and on those two pages the layer and its OCR come
// out close in length, so "keep whichever is longer" is a coin flip. MEASURED on
// six real sparse pages from real documents (48 to 364 characters of layer), the
// OCR/layer length ratio ran 0.10 to 1.08; on the same measurement over five
// real stamp formats on a full-page scan it ran 26.7 to 141.7. Nothing sits
// between, so the engine's reading is kept only when it is a MULTIPLE longer.
//
// Without the multiple, one of those six real pages flipped: a 110-character
// layer lost to a 119-character OCR that kept 11 of the layer's 16 words and
// invented 8 the page does not contain.
func TestASparseTextPageKeepsItsOwnWordsAgainstACloseOCR(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	if len(sparseLayerText) >= ocrPageHasText {
		t.Fatalf("the fixture's layer is %d chars, which is not inside the %d-character "+
			"band — it cannot test what the band admits", len(sparseLayerText), ocrPageHasText)
	}
	src := filepath.Join(dir, "sparse.pdf")
	if err := os.WriteFile(src, stampedScanPDF(t, sparseLayerText), 0o600); err != nil {
		t.Fatal(err)
	}

	// THE FIXTURE HAS TO SIT IN THE WINDOW THE MARGIN GOVERNS, and whether it
	// does is a property of this machine's poppler and tesseract rather than of
	// this file. Both sides are measured here, through the real binaries, so a
	// fixture that drifted out of the window skips loudly instead of passing for
	// the wrong reason — which is what the first version of this test did.
	out, lerr := runCmd(30*time.Second, "pdftotext", "-layout", "-q", "-f", "1", "-l", "1", "--", src, "-")
	layer := strings.TrimSpace(strings.ReplaceAll(out, "\f", ""))
	if lerr != nil || layer != sparseLayerText {
		t.Skipf("this poppler reads the fixture's layer as %q, not %q (err=%v)", layer, sparseLayerText, lerr)
	}
	page, rerr := renderOnePage(dir, src, 1, 60*time.Second)
	if rerr != nil {
		t.Skipf("this machine could not render the fixture: %v", rerr)
	}
	eng, _, oerr := runExtract(60*time.Second, "tesseract", ocrArgv(page)...)
	ocr := strings.TrimSpace(eng)
	if oerr != nil {
		t.Skipf("this machine's engine could not read the fixture: %v", oerr)
	}
	if !(len(ocr) > len(layer) && len(ocr) < ocrBeatsLayer*len(layer)) {
		t.Skipf("the fixture is outside the window this test is about: layer %d chars, "+
			"OCR %d chars, and the margin only decides between %d and %d",
			len(layer), len(ocr), len(layer)+1, ocrBeatsLayer*len(layer)-1)
	}

	text, pages, _, _, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 1)
	if err != nil {
		t.Fatal(err)
	}
	if pages[0].How != "text" {
		t.Fatalf("an OCR reading of %d characters replaced a REAL %d-character text layer "+
			"on a length lead of %d.\n  the document states %q\n  what was kept: %q\n"+
			"the engine's reading is kept only when it is %dx longer; below that the "+
			"two readings are close enough that length says nothing",
			len(ocr), len(layer), len(ocr)-len(layer), sparseLayerText,
			strings.TrimSpace(text), ocrBeatsLayer)
	}
	if !strings.Contains(text, sparseLayerText) {
		t.Fatalf("the page was recorded as how=text and its text layer is not in the "+
			"result:\n%s", text)
	}
}

// Inside the band, and short enough that the engine's reading of this fixture's
// picture is LONGER than it but not a multiple longer — the window where the
// length proxy stops being informative and the margin is what decides.
const sparseLayerText = "Chapter 3 Methods and materials, with a note on the sampling frame and the cohorts"
