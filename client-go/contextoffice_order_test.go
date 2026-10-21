//go:build !windows

package main

// Gates for four office items: slide ORDER, docx COMMENTS, HIDDEN
// sheets and slides, and the workbook that stops before its last sheet.
//
// Each test asserts TWICE, the way contextoffice_test.go's defect gates do:
// first that the fixture still carries the structure the behaviour needs, read
// out of the package's own XML, then that the reader does the right thing with
// it. The first half is not ceremony — three earlier defects all sat under a green suite
// because the fixtures did not contain the shapes involved, and the reordering
// case below cannot be built with LibreOffice at all (it renumbers the parts).

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// ── 1. slide order ──────────────────────────────────────────────────────────

// A DECK COMES OUT IN THE ORDER IT IS PRESENTED IN.
//
// ppt/slides/slideN.xml is numbered in CREATION order. The order a person sees —
// the order the deck plays in, and the numbers PowerPoint puts under the slides —
// is p:sldIdLst in ppt/presentation.xml, resolved through that part's
// relationships. Drag a slide to a new position and the list is rewritten while
// the parts keep their old numbers, so the two disagree on any deck anyone has
// edited.
//
// Reading the file numbers instead returns the deck in the wrong sequence AND
// labels every slide with a number the user cannot find in their own deck. A
// citation to "slide 1" that lands on the deck's third slide is a wrong answer
// delivered as a fact.
func TestOfficeTextEmitsSlidesInPresentationOrder(t *testing.T) {
	setupBox(t)

	// THE FIXTURE STILL DIVERGES. If a regeneration ever renumbers the parts to
	// match the list — which is exactly what LibreOffice does on write — this
	// file stops testing anything and the test must say so rather than pass.
	pres := officePart(t, fxPPTXReordered, "ppt/presentation.xml")
	lst := pres[strings.Index(pres, "<p:sldIdLst"):]
	if i := strings.Index(lst, "</p:sldIdLst>"); i >= 0 {
		lst = lst[:i]
	}
	rels := officePart(t, fxPPTXReordered, "ppt/_rels/presentation.xml.rels")
	// The first entry of the list must NOT be the first slide part.
	firstID := relIDAt(t, lst, 0)
	if got := relTarget(t, rels, firstID); got != "slides/slide3.xml" {
		t.Fatalf("the fixture's first presented slide is now %q, not slides/slide3.xml — "+
			"its file numbering and its p:sldIdLst no longer disagree, so it cannot "+
			"exercise the defect:\n  sldIdLst: %s", got, lst)
	}
	if !strings.Contains(officePart(t, fxPPTXReordered, "ppt/slides/slide1.xml"), "FIRST slide alpha") {
		t.Fatalf("the fixture's slide1.xml is no longer the deck's created-first slide")
	}

	resp, errOut, code := driveOffice(t, fxPPTXReordered)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	// THE SEQUENCE. The deck reads THIRD, FIRST, SECOND.
	third := strings.Index(resp.Text, "THIRD slide charlie")
	first := strings.Index(resp.Text, "FIRST slide alpha")
	second := strings.Index(resp.Text, "SECOND slide bravo")
	if third < 0 || first < 0 || second < 0 {
		t.Fatalf("slide text missing:\n%s", resp.Text)
	}
	if !(third < first && first < second) {
		t.Fatalf("the deck came back in the order its slides were CREATED, not the order "+
			"it is presented in — this deck plays THIRD, FIRST, SECOND:\n%s", resp.Text)
	}
	// THE LABELS. "--- Slide 1 ---" must name the slide the user sees first.
	if s := officeSection(t, resp.Text, 1); !strings.Contains(s, "THIRD slide charlie") {
		t.Fatalf("slide 3's text came back labelled slide 1 is the OLD bug; this is its "+
			"mirror — the deck's first slide is not under \"--- Slide 1 ---\":\n%s", s)
	}
	if s := officeSection(t, resp.Text, 3); !strings.Contains(s, "SECOND slide bravo") {
		t.Fatalf("the deck's third slide is not under \"--- Slide 3 ---\":\n%s", s)
	}
}

// relIDAt returns the r:id of the nth <p:sldId> in a sldIdLst fragment.
func relIDAt(t *testing.T, lst string, n int) string {
	t.Helper()
	rest, seen := lst, 0
	for {
		i := strings.Index(rest, "<p:sldId ")
		if i < 0 {
			break
		}
		rest = rest[i+len("<p:sldId "):]
		j := strings.Index(rest, ">")
		if j < 0 {
			break
		}
		if seen == n {
			return attrValue(t, rest[:j], "r:id")
		}
		seen++
	}
	t.Fatalf("the fixture's sldIdLst has no entry %d: %s", n, lst)
	return ""
}

// relTarget returns the Target of the Relationship with this Id.
func relTarget(t *testing.T, rels, id string) string {
	t.Helper()
	for _, chunk := range strings.Split(rels, "<Relationship ") {
		if attrValue(t, chunk, "Id") == id {
			return attrValue(t, chunk, "Target")
		}
	}
	t.Fatalf("no relationship %q in:\n%s", id, rels)
	return ""
}

func attrValue(t *testing.T, s, name string) string {
	t.Helper()
	i := strings.Index(s, name+`="`)
	if i < 0 {
		return ""
	}
	rest := s[i+len(name)+2:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// ── 2. docx comments ────────────────────────────────────────────────────────

// A REVIEWER'S COMMENTS ARE THE USER'S OWN WORDS AND THEY ARE KEPT, LABELLED.
//
// The call, and the reasoning behind it, is written out on readDOCXComments. In
// one line: a comment is substantive prose about the document, which is what
// makes a deck's speaker notes worth extracting, and the same answer applies —
// take them, keep them out of the body text, and label them so a hit on one is
// visibly a comment and not something the document says.
func TestOfficeTextKeepsTheReviewersComments(t *testing.T) {
	setupBox(t)

	// THE FIXTURE STILL PUTS THE WORDS WHERE ONLY A COMMENTS READER FINDS THEM.
	body := officePart(t, fxDOCXComments, "word/document.xml")
	if strings.Contains(body, "COMMENTBODY") {
		t.Fatalf("the fixture's comment text is now inside word/document.xml — the body " +
			"walker would find it and this test would pass without reading comments at all")
	}
	rels := officePart(t, fxDOCXComments, "word/_rels/document.xml.rels")
	if !strings.Contains(rels, "/relationships/comments") {
		t.Fatalf("the fixture no longer declares a comments relationship:\n%s", rels)
	}
	comments := officePart(t, fxDOCXComments, "word/comments.xml")
	for _, want := range []string{`w:author="Dana Reviewer"`, `w:author="Sam Second"`} {
		if !strings.Contains(comments, want) {
			t.Fatalf("the fixture lost %s from word/comments.xml", want)
		}
	}

	resp, errOut, code := driveOffice(t, fxDOCXComments)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	for _, want := range []string{
		"COMMENTBODY this number is stale, check it against the finance sheet",
		"COMMENTBODY second remark about the pricing change",
	} {
		if !strings.Contains(resp.Text, want) {
			t.Fatalf("the reviewer's comment was dropped — someone searching their own "+
				"words about this document finds nothing.\n  missing: %q\n%s", want, resp.Text)
		}
	}
	// LABELLED, NOT MERGED. A comment must not read as something the document says.
	if !strings.Contains(resp.Text, "--- Comments ---") {
		t.Fatalf("the comments are folded into the document's own text with nothing "+
			"marking them as comments:\n%s", resp.Text)
	}
	if !strings.Contains(resp.Text, "Dana Reviewer") {
		t.Fatalf("the comment is not attributed to whoever wrote it:\n%s", resp.Text)
	}
	// The body is still the body, and it comes first.
	bodyAt := strings.Index(resp.Text, "COMMENTPROBE the body paragraph")
	head := strings.Index(resp.Text, "--- Comments ---")
	if bodyAt < 0 || bodyAt > head {
		t.Fatalf("the document's own paragraphs are missing or come after its comments:\n%s",
			resp.Text)
	}
}

// ── 3. hidden sheets and hidden slides ──────────────────────────────────────

// A HIDDEN SHEET IS READ AND SAID TO BE HIDDEN.
//
// The call is written out on the sheetRef.heading comment. In one line: dropping
// a hidden sheet loses content silently and a silent loss is the one outcome this
// lane never chooses, so it is read — and marked, because a search hit a user
// cannot find anywhere in the file they have open is the thing that makes them
// distrust the whole corpus.
func TestOfficeTextMarksAHiddenSheet(t *testing.T) {
	setupBox(t)

	// THE FIXTURE STILL HIDES THEM, and the state lives in the workbook part
	// rather than in the worksheet — which is why reading the sheets alone can
	// never tell.
	wb := officePart(t, fxXLSXHiddenSheet, "xl/workbook.xml")
	for _, want := range []string{`state="hidden"`, `state="veryHidden"`} {
		if !strings.Contains(wb, want) {
			t.Fatalf("the fixture's workbook no longer declares %s — it cannot exercise "+
				"the case:\n%s", want, wb)
		}
	}
	if s := officePart(t, fxXLSXHiddenSheet, "xl/worksheets/sheet2.xml"); strings.Contains(s, `state="`) {
		t.Fatalf("the fixture's hidden worksheet part now carries a state of its own; the " +
			"point of this case is that only the workbook knows")
	}

	resp, errOut, code := driveOffice(t, fxXLSXHiddenSheet)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	// READ: the hidden sheets' contents are there.
	for _, want := range []string{
		"HIDDENPROBE this sheet is hidden scratch delta",
		"HIDDENPROBE this sheet is veryHidden echo",
	} {
		if !strings.Contains(resp.Text, want) {
			t.Fatalf("a hidden sheet's contents were dropped: %q\n%s", want, resp.Text)
		}
	}
	// MARKED: and the user can tell which ones they were.
	if !strings.Contains(resp.Text, "=== Sheet: Scratch working (hidden) ===") {
		t.Fatalf("a hidden sheet's contents went into the corpus with nothing saying it is "+
			"hidden — a hit on it sends the user looking for a sheet they cannot see:\n%s",
			resp.Text)
	}
	if !strings.Contains(resp.Text, "=== Sheet: Locked assumptions (very hidden) ===") {
		t.Fatalf("the veryHidden sheet — the one Excel's own interface cannot unhide — is "+
			"not marked:\n%s", resp.Text)
	}
	// AND AN ORDINARY SHEET IS NOT MARKED. Marking everything says nothing.
	if !strings.Contains(resp.Text, "=== Sheet: Summary ===") {
		t.Fatalf("a visible sheet's heading changed:\n%s", resp.Text)
	}
}

// A HIDDEN SLIDE IS READ AND SAID TO BE HIDDEN, for the same reason and with the
// same shape. show="0" on the p:sld root is what "Hide Slide" writes: the slide
// stays in the deck and in the file, and is skipped when the deck is played.
func TestOfficeTextMarksAHiddenSlide(t *testing.T) {
	setupBox(t)

	sld := officePart(t, fxPPTXHiddenSlide, "ppt/slides/slide2.xml")
	if !strings.Contains(sld, `show="0"`) {
		t.Fatalf("the fixture's slide 2 is no longer hidden — it cannot exercise the case")
	}
	if s := officePart(t, fxPPTXHiddenSlide, "ppt/slides/slide1.xml"); strings.Contains(s, `show="0"`) {
		t.Fatalf("the fixture's slide 1 is hidden too, so the test cannot tell a marked " +
			"heading from a blanket one")
	}

	resp, errOut, code := driveOffice(t, fxPPTXHiddenSlide)
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}
	if !strings.Contains(resp.Text, "HIDSLIDEPROBE second slide is HIDDEN bravo") {
		t.Fatalf("the hidden slide's text was dropped:\n%s", resp.Text)
	}
	if !strings.Contains(resp.Text, "--- Slide 2 (hidden) ---") {
		t.Fatalf("the hidden slide went into the corpus looking exactly like a slide the "+
			"deck actually shows:\n%s", resp.Text)
	}
	if !strings.Contains(resp.Text, "--- Slide 1 ---\n") {
		t.Fatalf("a visible slide's heading changed:\n%s", resp.Text)
	}
}

// ── 4. the workbook that stopped ────────────────────────────────────────────

// bigWorkbook builds a workbook whose text runs past ctxExtractMaxText part-way
// through its FIRST sheet, with named sheets behind it.
//
// IT IS GENERATED RATHER THAN EMBEDDED because the shape under test is SIZE —
// 4 MiB of emitted text — and a base64 constant of a real writer's 15 MB of sheet
// XML would be a multi-hundred-kilobyte source file to assert a property that
// has nothing to do with the writer. The row shape it emits is not invented: it
// is openpyxl 3.1.5's, copied from a workbook written with it and read back,
// which is `<row r="1"><c r="A1" t="inlineStr"><is><t>…</t></is>
// </c></row>` exactly as below.
func bigWorkbook(t *testing.T, rows int, sheets ...string) []byte {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for i := 1; i <= rows; i++ {
		fmt.Fprintf(&sb, `<row r="%d"><c r="A%d" t="inlineStr"><is><t>BIGROW short cell value abc</t></is></c></row>`, i, i)
	}
	sb.WriteString(`</sheetData></worksheet>`)

	var decl, rels strings.Builder
	parts := map[string]string{"xl/worksheets/sheet1.xml": sb.String()}
	for i, name := range sheets {
		fmt.Fprintf(&decl, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, name, i+1, i+1)
		fmt.Fprintf(&rels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i+1, i+1)
		if i > 0 {
			parts[fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1)] =
				`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
					`<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>TAILSHEET ` + name +
					`</t></is></c></row></sheetData></worksheet>`
		}
	}
	parts["xl/workbook.xml"] = `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>` + decl.String() + `</sheets></workbook>`
	parts["xl/_rels/workbook.xml.rels"] = `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rels.String() + `</Relationships>`
	return officeZip(t, parts)
}

// A WORKBOOK THAT STOPPED SAYS WHAT IT NEVER GOT TO.
//
// Emission stops at ctxExtractMaxText, and the sheet it stopped inside says so.
// The sheets BEHIND it said nothing at all: a user whose workbook holds
// "Assumptions" and "Notes" after a huge data sheet got a reply that read as a
// complete extraction of a workbook with one sheet in it. That is the blind
// answer readPPTX already refuses to give for a slide with no words on it, and it
// is the same answer here.
//
// This is also where the `_ = stopped` dead variable went: see readXLSX.
func TestOfficeTextNamesTheSheetsItNeverReached(t *testing.T) {
	setupBox(t)

	pkg := bigWorkbook(t, 200000, "Big data", "Assumptions", "Notes")
	resp, errOut, code := driveOffice(t, base64.StdEncoding.EncodeToString(pkg))
	if code != 0 {
		t.Fatalf("ctx_extract failed: %s", errOut)
	}

	// THE INPUT REALLY IS OVER THE WALL. Without this the rest passes vacuously
	// the day ctxExtractMaxText moves or the row shape shrinks. Either signal
	// proves it: the sheet said it stopped, or the reply itself was cut.
	if !strings.Contains(resp.Text, "this workbook is larger") && !resp.Truncated {
		t.Fatalf("the generated workbook no longer overruns one extraction, so it cannot "+
			"exercise the case — %d chars, cap %d", len(resp.Text), ctxExtractMaxText)
	}
	if strings.Contains(resp.Text, "TAILSHEET Assumptions") {
		t.Fatalf("the generated workbook is small enough to reach its later sheets")
	}

	// THE ASSERTION: the reply names the sheets it never opened.
	for _, want := range []string{"Assumptions", "Notes"} {
		if !strings.Contains(resp.Text, want) {
			t.Fatalf("the extraction stopped inside the first sheet and never said that "+
				"%q exists — the reply reads as a complete extraction of a one-sheet "+
				"workbook.\n  tail: %q", want, tailOf(resp.Text, 400))
		}
	}
	if !strings.Contains(resp.Text, "2 more sheets in this workbook were not read") {
		t.Fatalf("the reply does not say how many sheets went unread:\n  tail: %q",
			tailOf(resp.Text, 400))
	}
	// AND IT SURVIVES THE REPLY'S OWN TRUNCATION. resp.Text is what the host
	// receives, after contextextract.go cuts anything past ctxExtractMaxText —
	// so a marker written past the cap would be the one sentence thrown away.
	if resp.Truncated {
		t.Fatalf("the workbook's closing markers were written past the reply's own cap and "+
			"cut back off: chars=%d of %d", resp.Chars, resp.CharsAll)
	}
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
