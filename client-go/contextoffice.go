package main

// office-text — docx, xlsx and pptx, read by this binary, ON THE USER'S MACHINE.
//
// ── WHY THIS IS NOT LIBREOFFICE ─────────────────────────────────────────────
//
// soffice's interface was unverified. It was installed and run
// (LibreOffice 26.2.5.2) before a line of this was written, and what
// it actually does rules it out for this lane on four separate counts. Every
// number below is from a run, not from documentation:
//
//  1. IT HAS NO ONE INTERFACE FOR THE THREE FORMATS. `--convert-to txt` works
//     for Writer only. On a .xlsx and a .pptx it fails with "Error: no export
//     filter ... found, aborting" and exit 1 — Calc and Impress have no text
//     export filter at all. A spreadsheet needs `--convert-to csv` (which
//     writes ONE sheet, the first) and a deck needs `--convert-to html`, whose
//     output for a two-slide deck with eleven words on it is 5,837 bytes of
//     XHTML that then has to be stripped back down. Three filters, one of them
//     lossy by default and one of them not text.
//
//  2. TWO AT ONCE SILENTLY LOSES ONE. MEASURED, five trials of two concurrent
//     `--headless --convert-to` against the same user profile: in 5 of 5, one
//     of the pair exited 1 having written NO output file and NOTHING to stdout
//     OR stderr. Not an error message — an empty failure. This box runs
//     mgmtWorkerCount management workers, so two extractions overlapping is
//     normal operation, and the result would have been an intermittent, wholly
//     unexplained "could not read this document" on documents that are fine.
//     It IS fixable — a private profile per invocation
//     (-env:UserInstallation=file:///…) gave 10 of 10 clean runs at 296 KB and
//     ~0.3 s each — but the fix is a mkdtemp dance around a program that
//     defaults to corrupting concurrent work without saying so.
//
//  3. IT COSTS THE USER 332 MB. Measured with dpkg-query over the 70 packages
//     `libreoffice-writer libreoffice-calc libreoffice-impress` pulls in. This
//     lane runs on the user's own machine and what they must install is a
//     first-class cost, not a footnote.
//
//  4. ITS FAILURES ARE NOT DISTINGUISHABLE. A corrupted .xlsx reports "no
//     export filter" — the SAME message as asking for a format it cannot write.
//     A file of plain garbage named .docx exits 0, because LibreOffice sniffs
//     content, decides it is a text file, and hands back the garbage as the
//     document's text.
//
// What it does do well, and the reason it is worth recording rather than just
// rejecting: a password-protected document does NOT hang. Headless suppresses
// the password dialog and it exits 1 in 0.4 s with "Error: source file could not
// be loaded" — the right behaviour, with a message that does not say the file
// was encrypted.
//
// ── WHAT THIS DOES INSTEAD ──────────────────────────────────────────────────
//
// docx, xlsx and pptx are all OPC packages: a ZIP of XML parts (ECMA-376). Go's
// standard library reads both halves, so this job needs NO binary on the user's
// machine and NO new module in go.mod — archive/zip and encoding/xml, nothing
// else. THE USER INSTALLS NOTHING.
//
// That is also the smaller attack surface by a wide margin. These are untrusted
// documents from a user's own corpus; the alternative was handing each one to a
// 332 MB office suite with a long history of parser CVEs, running as the user.
//
// The cost of the choice, stated plainly: the legacy BINARY formats (.doc, .xls,
// .ppt — OLE2 compound files, not ZIPs) are NOT read by this and are not mapped
// on the host. They are a different container and a different job, and a box
// with LibreOffice on it could carry them later as a separate tool name. This
// job claims the three OPC formats and nothing more.
//
// ── WHY ONE JOB NAME AND NOT THREE ──────────────────────────────────────────
//
// pdf-text and ocr are separate names because a machine can genuinely have one
// and not the other. Built into the binary, all three formats are present or
// absent together — there is no partial install to describe — so three names
// would be three ways of saying the same true thing.
//
// The format is decided by WHAT IS IN THE PACKAGE, not by the mime the host
// sent or the extension: measured above, the extension lies often enough that
// LibreOffice itself ignores it.

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// officeExtractTimeout bounds one office-text job. Declared in
// ctxExtractTimeoutFor, which is the only place a ceiling exists.
//
// DERIVED FROM MEASUREMENT, not chosen. This is in-process XML parsing of a ZIP
// the pull path already caps at ctxPullMaxBytes, so the worst case is bounded by
// construction and was measured at it:
//
//	50,000 x 12 text workbook   6.2 MB packed, 35.1 MB of sheet XML   0.45 s
//	numeric workbook at the
//	  unpack ceiling            0.36 MB packed, 65.0 MB of sheet XML  0.55-0.61 s
//
// Both stopped at ctxExtractMaxText rather than at a clock, which is the general
// case: the text ceiling is reached long before a time limit is.
//
// 20 s is therefore >30x the worst case measurable at the source ceiling, which
// leaves room for a slow disk and a loaded machine without letting a
// pathological package hold a management worker. It is deliberately the same
// number as the plain text-layer read: both are "parse a file this box already
// has", and giving them different ceilings would imply a difference in the work
// that is not there.
const officeExtractTimeout = ctxExtractTimeout

// officeMaxUnpacked is the wall on DECOMPRESSED bytes across all parts of one
// package, and it is what a zip bomb hits.
//
// A 64 MiB upload can declare petabytes of uncompressed content; archive/zip
// will happily stream it, so a size check on the file proves nothing about the
// cost of reading it. The number is NOT a new one: it is ctxPullMaxBytes, this
// box's existing ceiling on one source document. Reusing it states the rule
// rather than inventing a second threshold — a package may not expand to more
// than the largest document this lane would have accepted whole.
const officeMaxUnpacked = ctxPullMaxBytes

// officeRowSep separates a spreadsheet row's cells. Pipe rather than comma or
// tab because it survives being read back as prose, needs no quoting rules, and
// keeps one record on one line — see the emission note on readXLSX.
const officeRowSep = " | "

// officeKind is which of the three a package turned out to be.
type officeKind string

const (
	kindDOCX officeKind = "docx"
	kindXLSX officeKind = "xlsx"
	kindPPTX officeKind = "pptx"
)

// officeResult is what one extraction produced, beyond the text.
type officeResult struct {
	Kind officeKind
	// Parts is sheets for a workbook, slides for a deck, and 1 for a document.
	// Reported so "no text" from a 40-slide deck of photographs reads
	// differently from "no text" out of an empty package.
	Parts int
	// Partial is set when a part failed to parse and the text is what came out
	// of the parts that did. The alternative — throwing away nine readable
	// slides because the tenth has malformed XML — helps nobody.
	Partial bool
	// Deadline is set when the clock ran out mid-package.
	Deadline bool
}

// runOfficeText is the office-text job, in extractMulti's shape.
//
// It is in extractMulti rather than extractArgv because it is not an argv: it is
// zero commands, which is as far from "one command writing to stdout" as the
// three commands pdf-ocr runs. Putting it there means the drift gates already
// cover it and no third table had to be invented.
//
// root is unused: this job needs no scratch of its own, which is one more thing
// that cannot leak a user's document.
func runOfficeText(root, in string, deadline time.Time) (string, []ocrPageResult, int, bool, error) {
	text, res, err := extractOffice(in, deadline)
	if err != nil {
		return "", nil, 0, false, err
	}
	return text, nil, res.Parts, res.Deadline, nil
}

// extractOffice reads one OPC package off disk.
func extractOffice(in string, deadline time.Time) (string, officeResult, error) {
	zr, err := zip.OpenReader(in)
	if err != nil {
		// THE "CANNOT" ANSWER, and it has to be distinguishable from an empty
		// document. A file that is not a ZIP was never one of these three
		// formats, whatever it was called.
		return "", officeResult{}, fmt.Errorf(
			"this is not a docx, xlsx or pptx — it is not an Office package at all "+
				"(%v). A .doc/.xls/.ppt saved in the older binary format is a different "+
				"container and this job does not read it", err)
	}
	defer zr.Close()
	return extractOfficeZip(&zr.Reader, deadline)
}

// extractOfficeZip is the reader itself, taking an already-opened package. Split
// out so the capability PROBE can run the whole path over a package built in
// memory — proving the reader works, not that a file exists.
func extractOfficeZip(zr *zip.Reader, deadline time.Time) (string, officeResult, error) {
	budget := &unpackBudget{left: officeMaxUnpacked}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[path.Clean(f.Name)] = f
	}

	switch {
	case files["word/document.xml"] != nil:
		return readDOCX(files, budget, deadline)
	case files["xl/workbook.xml"] != nil:
		return readXLSX(files, budget, deadline)
	case files["ppt/presentation.xml"] != nil:
		return readPPTX(files, budget, deadline)
	}
	// A ZIP with none of the three main parts. An ENCRYPTED OOXML file never
	// reaches here (it is an OLE2 container, so zip.OpenReader already refused
	// it), but an ODF document does, and saying which is more use than "cannot
	// read".
	if f := files["mimetype"]; f != nil {
		if mt, err := readPart(f, budget, 200); err == nil && strings.HasPrefix(mt, "application/vnd.oasis") {
			return "", officeResult{}, fmt.Errorf(
				"this is an OpenDocument file (%s), not a docx/xlsx/pptx — this job "+
					"reads the Office formats only", strings.TrimSpace(mt))
		}
	}
	return "", officeResult{}, fmt.Errorf(
		"this is a ZIP but not an Office document: it has no word/document.xml, " +
			"xl/workbook.xml or ppt/presentation.xml")
}

// ── relationships ───────────────────────────────────────────────────────────
//
// An OPC package NEVER links its parts by filename. Every reference from part X
// to part Y goes through X's own relationship part — the sibling
// <dir>/_rels/<name>.rels — which maps a relationship id and a type url to a
// target path. Filenames look like they encode the link (slide1 ↔ notesSlide1,
// sheet1 ↔ the first sheet) and they do not; the numbering is creation order and
// nothing more. Reading the rels is the only way to be right, and the defects
// that come of guessing are silent misattribution rather than a visible failure.

// officeRel is one <Relationship> entry, with its target already resolved to a
// package path this reader can look up.
type officeRel struct {
	id      string
	relType string
	target  string
}

// officeRelsMax bounds one relationship part. Rels parts are a handful of lines
// even in a large package; this is generous by orders of magnitude and exists
// only so a malicious package cannot spend the whole unpack budget here.
const officeRelsMax = 4 << 20

// partRels reads the relationship part belonging to `part` and resolves every
// target against `part`'s own directory, which is what the spec says a relative
// target is relative to. An EXTERNAL target (a hyperlink, a linked image on
// someone's disk) is dropped: it names something outside the package, and this
// reader must never be the thing that goes and looks.
func partRels(files map[string]*zip.File, part string, b *unpackBudget) []officeRel {
	dir := path.Dir(part)
	rf := files[path.Join(dir, "_rels", path.Base(part)+".rels")]
	if rf == nil {
		return nil
	}
	body, err := readPart(rf, b, officeRelsMax)
	if err != nil {
		return nil
	}
	var out []officeRel
	d := xml.NewDecoder(strings.NewReader(body))
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Relationship" {
			continue
		}
		var r officeRel
		external := false
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "Id":
				r.id = a.Value
			case "Type":
				r.relType = a.Value
			case "Target":
				r.target = a.Value
			case "TargetMode":
				external = strings.EqualFold(a.Value, "External")
			}
		}
		if external || r.id == "" || r.target == "" {
			continue
		}
		if strings.HasPrefix(r.target, "/") {
			// Package-absolute: "/ppt/slides/slide1.xml".
			r.target = path.Clean(strings.TrimPrefix(r.target, "/"))
		} else {
			r.target = path.Clean(path.Join(dir, r.target))
		}
		out = append(out, r)
	}
	return out
}

// ── the budget ──────────────────────────────────────────────────────────────

type unpackBudget struct{ left int64 }

// readPart decompresses one part, bounded twice: by what is left of the
// package's whole allowance and by what this part could sanely be.
func readPart(f *zip.File, b *unpackBudget, max int64) (string, error) {
	if b.left <= 0 {
		return "", fmt.Errorf("this package expands to more than %d bytes, which is "+
			"more than the largest document this lane reads", officeMaxUnpacked)
	}
	if max > b.left {
		max = b.left
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	// max+1 so hitting the wall is detectable rather than silently truncating.
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	b.left -= int64(len(data))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > max {
		return "", fmt.Errorf("%s is larger than this lane unpacks", f.Name)
	}
	return string(data), nil
}

// officePartMax is the wall on ONE content part, and it is the SAME number as
// the package budget on purpose.
//
// It was briefly 32 MiB, a smaller "surely no single part is bigger than this"
// number, and that was wrong twice over. MEASURED: a plain 50,000-row x
// 12-column worksheet — 6.2 MB packed — is 35.1 MB of sheet XML, so the cap
// refused an ordinary large spreadsheet. And it refused it QUIETLY: the sheet
// was skipped, the reply came back with zero characters and exit 0, and the
// only trace was an internal flag that never reached the user. A second
// threshold bought nothing the package budget was not already enforcing, and
// cost a silently empty extraction of a perfectly good workbook.
const officePartMax = officeMaxUnpacked

// ── docx ────────────────────────────────────────────────────────────────────

// readDOCX walks word/document.xml. The text of a Word document lives in <w:t>
// runs inside <w:p> paragraphs; a text box's words are in the same part (inside
// w:txbxContent) so they come out with it — ONCE, see the alternate-content note
// on runsToText, which is what stops the same text box being read out of both
// halves of an <mc:AlternateContent>.
//
// Headers, footers and footnotes are separate parts and are NOT read. They are
// page furniture — a filename, a page number, a confidentiality stamp repeated
// on every page — and folding them in would put the same line into the document
// forty times, which costs an embedding lane more than it gives it.
//
// COMMENTS ARE READ, AND LABELLED — see readDOCXComments for why, and for the
// alternative that was rejected.
//
// TRACKED CHANGES come out in their FINAL-VIEW form: an insertion is inside an
// ordinary w:r and is emitted, a deletion is in w:delText which is not a w:t and
// is therefore not. That is the same text the document shows with markup turned
// off, which is the right answer for a corpus, but it is a consequence of the
// element names rather than something this chose, so it is written down.
func readDOCX(files map[string]*zip.File, b *unpackBudget, deadline time.Time) (string, officeResult, error) {
	body, err := readPart(files["word/document.xml"], b, officePartMax)
	if err != nil {
		return "", officeResult{Kind: kindDOCX}, fmt.Errorf("word/document.xml could not be read: %w", err)
	}
	text, partial := runsToText(body, "t", "p", "tab", "br", deadline)
	comments, cpartial := readDOCXComments(files, b, deadline)
	partial = partial || cpartial
	text += commentsBlock(comments, len(text))
	return text, officeResult{Kind: kindDOCX, Parts: 1, Partial: partial,
		Deadline: pastDeadline(deadline)}, nil
}

// ── docx comments ───────────────────────────────────────────────────────────
//
// THE CALL: a document's comments ARE extracted, into their own labelled block
// after the document's text, attributed to whoever wrote each one.
//
// The reasoning is the reasoning readPPTX already gives for speaker notes, and
// the two cases are the same case. A comment is the most prose-like text in a
// Word document — someone's actual sentences about the thing, where the body is
// often headings and figures — and "the document where Dana said the number was
// stale" is exactly the search a person runs. Dropping them loses that, and
// loses it silently: the words are in the file the user handed over and nothing
// in the reply says they were left behind.
//
// The objection is real and it is answered by LABELLING rather than by dropping:
// a comment is not something the document SAYS, and merging the two would put a
// reviewer's "this is wrong" into the corpus as the document's own assertion.
// So comments go under their own heading, one per line, each named with its
// author — which makes a retrieval hit on one visibly a comment, the same way
// "Notes:" makes a hit on a speaker note visibly a note.
//
// THE ALTERNATIVE, rejected: keep dropping them, on the grounds that a corpus
// should hold what a document says and nothing else. That is a coherent line and
// it is the wrong one here, because this lane's job is to make the user's own
// files findable by their own words, and a comment is their own words. It also
// fails the test the rest of this file applies to itself — a user searching a
// phrase they typed into their own document would get nothing back, with no way
// to tell that the phrase was ever read.
//
// AUTHOR NAMES: included, because "what did Sam say about this" is usually the
// question, and a comment with the name stripped off answers half of it. The
// name goes exactly where the rest of the document's words go and no further —
// back to the user's own host, as this document's text.

// docxComment is one <w:comment>: its author when the writer recorded one, and
// its text.
type docxComment struct {
	author string
	text   string
}

// officeCommentsHeading labels the comment block. It is the same "--- … ---"
// shape as a slide heading so one reader of this output learns one convention.
const officeCommentsHeading = "--- Comments ---"

// readDOCXComments reads the comments part, found THROUGH THE RELATIONSHIP
// rather than at word/comments.xml, for the reason stated on partRels: the
// filename is not the link. The suffix match is exact — "/commentsExtended",
// "/commentsIds" and "/commentsExtensible" are threading and identity metadata,
// not text, and do not end in "/comments".
//
// A document with no comments part has no comments; there is no fallback to a
// guessed path.
func readDOCXComments(files map[string]*zip.File, b *unpackBudget, deadline time.Time) ([]docxComment, bool) {
	target := ""
	for _, r := range partRels(files, "word/document.xml", b) {
		if strings.HasSuffix(r.relType, "/comments") {
			target = r.target
			break
		}
	}
	f := files[target]
	if target == "" || f == nil {
		return nil, false
	}
	body, err := readPart(f, b, officePartMax)
	if err != nil {
		// A comments part that will not unpack is a partial read of the document,
		// not a failure of it: the body text is still the user's.
		return nil, true
	}
	return commentsFromXML(body, deadline)
}

// commentsFromXML walks a WordprocessingML comments part.
//
// It is its own walker rather than a runsToText call because the BOUNDARIES
// matter here — one comment must not run into the next, and each one carries an
// author — and runsToText has no notion of a group. What it does NOT duplicate is
// the alternate-content rule: mcSelect is the same object runsToText uses, so a
// text box inside a comment is read once here for the same reason it is read
// once in the body.
//
// Returns the comments and whether the part failed to parse part-way through.
func commentsFromXML(body string, deadline time.Time) ([]docxComment, bool) {
	d := xml.NewDecoder(strings.NewReader(body))
	mc := newMCSelect()
	var out []docxComment
	var cur docxComment
	var line, text strings.Builder
	depth, commentAt := 0, -1
	inT, checked, taken := false, 0, 0
	flushLine := func() {
		s := strings.TrimSpace(line.String())
		line.Reset()
		if s == "" {
			return
		}
		if text.Len() > 0 {
			text.WriteString("\n")
		}
		text.WriteString(s)
	}
	for {
		checked++
		if checked%512 == 0 && pastDeadline(deadline) {
			return out, false
		}
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, true
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			skip := mc.start(t)
			if !skip && commentAt < 0 && t.Name.Local == "comment" {
				commentAt = depth
				cur = docxComment{}
				text.Reset()
				line.Reset()
				for _, a := range t.Attr {
					if a.Name.Local == "author" {
						cur.author = strings.TrimSpace(a.Value)
					}
				}
				continue
			}
			if skip || commentAt < 0 {
				continue
			}
			switch t.Name.Local {
			case "t":
				inT = true
			case "tab":
				line.WriteString("\t")
			case "br":
				flushLine()
			}
		case xml.CharData:
			if inT && commentAt >= 0 && !mc.skipping() {
				line.Write(t)
			}
		case xml.EndElement:
			skip := mc.end(t)
			closing := commentAt >= 0 && depth == commentAt && t.Name.Local == "comment"
			depth--
			if closing {
				flushLine()
				cur.text = strings.TrimSpace(text.String())
				commentAt = -1
				inT = false
				if cur.text == "" {
					continue
				}
				out = append(out, cur)
				taken += len(cur.text)
				// The whole comment block still has to fit inside one reply. This
				// is the same ceiling the body text has, reached the same way.
				if taken >= ctxExtractMaxText {
					return out, false
				}
				continue
			}
			if skip || commentAt < 0 {
				continue
			}
			switch t.Name.Local {
			case "t":
				inT = false
			case "p":
				flushLine()
			}
		}
	}
	return out, false
}

// commentsBlock renders the comments that FIT after `used` characters of document
// text, and says plainly when some did not.
//
// Comments are cut at a whole comment, never mid-sentence, and the count of what
// was left out is stated — a half-quoted remark attributed to a named person is
// the one way this could be worse than dropping them.
func commentsBlock(comments []docxComment, used int) string {
	if len(comments) == 0 {
		return ""
	}
	var b strings.Builder
	head := "\n" + officeCommentsHeading + "\n"
	if used+len(head)+officeTailReserve > ctxExtractMaxText {
		return ""
	}
	b.WriteString(head)
	left := 0
	for i, c := range comments {
		line := "Comment: " + c.text + "\n"
		if c.author != "" {
			line = "Comment (" + c.author + "): " + c.text + "\n"
		}
		if used+b.Len()+len(line)+officeTailReserve > ctxExtractMaxText {
			left = len(comments) - i
			break
		}
		b.WriteString(line)
	}
	if left > 0 {
		word := "comments"
		if left == 1 {
			word = "comment"
		}
		fmt.Fprintf(&b, "--- %d more %s on this document were not included: it is larger "+
			"than one extraction returns ---\n", left, word)
	}
	return b.String()
}

// ── pptx ────────────────────────────────────────────────────────────────────

// readPPTX walks the slides and takes the SPEAKER NOTES with them.
//
// The notes are the reason this is worth doing well. A slide is a handful of
// noun phrases; the notes are the sentences the person actually meant to say,
// and they are the most prose-like text in the whole file — the best thing in a
// deck for someone searching "the deck where we explained the pricing change".
// They are labelled, not merged, so a hit on a note is visibly a note.
//
// ── NOTES ARE PAIRED BY RELATIONSHIP, NEVER BY FILENAME ─────────────────────
//
// ppt/notesSlides/notesSlideN.xml is NOT slideN.xml's notes, and nothing in the
// format says it is. The parts are numbered in the order they are CREATED, so a
// deck where someone wrote notes on slide 3 before slide 2 has notesSlide1.xml
// attached to slide 3 — VERIFIED on a real package: slide1 has no notes
// relationship at all, slide2 points at notesSlide2.xml and slide3 points at
// notesSlide1.xml. The only thing that knows is the relationship in
// ppt/slides/_rels/slideN.xml.rels, so that is what is read.
//
// Pairing by filename, which this used to do, quotes one slide's words
// under another slide's heading. That is worse than losing them: a user who
// searches a phrase from their own notes is sent, with a citation, to a slide
// that does not contain it.
//
// A slide with no notesSlide relationship has no notes. There is deliberately no
// filename fallback — a fallback here is the defect, reinstated for the cases
// nobody checked.
//
// ── SLIDE ORDER IS p:sldIdLst, NEVER THE FILE NUMBERING ─────────────────────
//
// ppt/slides/slideN.xml is numbered in CREATION order, the same way notesSlideN
// is. The order the deck is PRESENTED in — the order it plays, and the numbers
// under the thumbnails in PowerPoint — is <p:sldIdLst> in ppt/presentation.xml,
// whose entries carry r:id values resolved through
// ppt/_rels/presentation.xml.rels. Dragging a slide to a new position rewrites
// that list and does not touch the parts, so the two disagree on any deck anyone
// has edited.
//
// MEASURED on a deck built with three slides and then reordered by
// moving the third to the front: sldIdLst reads rId9, rId7, rId8 while the
// targets are slide1, slide2, slide3, and LibreOffice 26.2.5.2 handed that exact
// file writes it back out with the THIRD slide as slide1.xml. An office suite
// agrees with the list.
//
// Reading file numbers instead — which this used to do — returned the
// deck in the wrong sequence AND labelled every slide with a number the user
// cannot find in their own deck, so a citation to "slide 1" landed on a different
// slide. The label here is now the slide's POSITION in the presentation, which is
// the number the user sees.
//
// A slide part that the list does not name is not in the deck and is not read:
// it is a leftover, and emitting it would put text in the corpus that the
// document does not show. If the list cannot be read at all — no
// presentation.xml, no relationships, a malformed part — the file numbering is
// the fallback, because some order is better than refusing a readable deck.
func readPPTX(files map[string]*zip.File, b *unpackBudget, deadline time.Time) (string, officeResult, error) {
	slides := presentationSlides(files, b)
	if len(slides) == 0 {
		for _, p := range numberedParts(files, "ppt/slides/slide", ".xml") {
			slides = append(slides, p.name)
		}
	}
	if len(slides) == 0 {
		return "", officeResult{Kind: kindPPTX}, fmt.Errorf(
			"this presentation has no slides in it")
	}
	var out strings.Builder
	partial := false
	for i, name := range slides {
		n := i + 1
		if pastDeadline(deadline) {
			return out.String(), officeResult{Kind: kindPPTX, Parts: len(slides),
				Partial: partial, Deadline: true}, nil
		}
		f := files[name]
		if f == nil {
			// The list names a part the package does not contain. Say so rather
			// than skip: a slide missing from the file is a fact about the file.
			partial = true
			fmt.Fprintf(&out, "--- Slide %d ---\n(this slide is in the presentation but its "+
				"part is not in the file)\n\n", n)
			continue
		}
		body, err := readPart(f, b, officePartMax)
		if err != nil {
			partial = true
			fmt.Fprintf(&out, "--- Slide %d ---\n(this slide could not be read: %v)\n\n", n, err)
			continue
		}
		// DrawingML: text runs are <a:t> inside <a:p> paragraphs.
		txt, p := runsToText(body, "t", "p", "", "br", deadline)
		partial = partial || p
		if slideIsHidden(body) {
			fmt.Fprintf(&out, "--- Slide %d (hidden) ---\n", n)
		} else {
			fmt.Fprintf(&out, "--- Slide %d ---\n", n)
		}
		if strings.TrimSpace(txt) != "" {
			out.WriteString(txt)
			if !strings.HasSuffix(txt, "\n") {
				out.WriteString("\n")
			}
		}
		notesName := ""
		for _, r := range partRels(files, name, b) {
			if strings.HasSuffix(r.relType, "/notesSlide") {
				notesName = r.target
				break
			}
		}
		if nf := files[notesName]; notesName != "" && nf != nil {
			if nb, err := readPart(nf, b, officePartMax); err == nil {
				if ntxt, np := runsToText(nb, "t", "p", "", "br", deadline); strings.TrimSpace(ntxt) != "" {
					partial = partial || np
					out.WriteString("Notes: ")
					out.WriteString(strings.TrimSpace(ntxt))
					out.WriteString("\n")
				}
			}
		}
		out.WriteString("\n")
	}
	return out.String(), officeResult{Kind: kindPPTX, Parts: len(slides),
		Partial: partial, Deadline: pastDeadline(deadline)}, nil
}

// officeRelNS is the officeDocument relationships namespace, and it is needed
// here for ONE reason: <p:sldId id="258" r:id="rId9"/> carries two attributes
// whose local name is "id". Matching on the local name alone picks whichever
// comes first and would read the slide's internal identifier as a relationship
// id, which resolves to nothing.
const officeRelNS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

// presentationSlides returns the deck's slide parts in PRESENTATION order, or
// nil when the package does not say what that order is.
func presentationSlides(files map[string]*zip.File, b *unpackBudget) []string {
	pf := files["ppt/presentation.xml"]
	if pf == nil {
		return nil
	}
	body, err := readPart(pf, b, officePartMax)
	if err != nil {
		return nil
	}
	rels := map[string]string{}
	for _, r := range partRels(files, "ppt/presentation.xml", b) {
		if strings.HasSuffix(r.relType, "/slide") {
			rels[r.id] = r.target
		}
	}
	var out []string
	d := xml.NewDecoder(strings.NewReader(body))
	inList := false
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "sldIdLst":
				inList = true
			case "sldId":
				if !inList {
					continue
				}
				for _, a := range t.Attr {
					if a.Name.Space != officeRelNS || a.Name.Local != "id" {
						continue
					}
					if target := rels[a.Value]; target != "" {
						out = append(out, target)
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local == "sldIdLst" {
				inList = false
			}
		}
	}
	return out
}

// slideIsHidden reads show="0" off the slide part's ROOT <p:sld> element, which
// is what PowerPoint's "Hide Slide" writes: the slide stays in the deck and in
// the file and is skipped when the deck is played.
//
// Only the root element is looked at, and the walk stops at the first start tag
// either way. "show" is an ordinary word and appears on other elements inside a
// slide; the hidden flag is the root's attribute and nothing else's.
func slideIsHidden(body string) bool {
	d := xml.NewDecoder(strings.NewReader(body))
	for {
		tok, err := d.Token()
		if err != nil {
			return false
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "sld" {
			return false
		}
		for _, a := range se.Attr {
			if a.Name.Local == "show" {
				return a.Value == "0" || strings.EqualFold(a.Value, "false")
			}
		}
		return false
	}
}

// ── xlsx ────────────────────────────────────────────────────────────────────
//
// A SPREADSHEET IS NOT PROSE, and flattening one naively produces a wall of
// digits that embeds badly and retrieves worse: "300" carries no meaning and
// every workbook in a corpus contains it.
//
// What makes a spreadsheet findable is its LABELS — the names the user gave the
// sheets, the header row they typed, and the text cells. So the emission keeps
// every label next to the values it labels:
//
//	=== Sheet: Q3 Forecast ===
//	Region | Q1 | Q2
//	North | 100 | 200
//
//   - THE SHEET NAME IS A HEADING. It is the user's own title for that data and
//     it is often the only prose in the file. A workbook's sheet names alone
//     ("Headcount", "Q3 Forecast", "Churn by cohort") make it findable.
//   - ONE ROW IS ONE LINE, so a retrieval hit hands back a whole record rather
//     than an isolated number, and the header line sits in the same chunk as
//     the rows under it.
//   - EMPTY ROWS AND TRAILING EMPTY CELLS ARE DROPPED. A sheet is a sparse grid
//     with a used range far larger than its content; emitting the padding would
//     bury the content in separators.
//   - AN INTERIOR EMPTY CELL IS KEPT, AS AN EMPTY FIELD. It is the opposite case
//     and it is not symmetric with the one above: closing a middle gap moves
//     every value after it under the wrong header, which is a false record
//     rather than a noisy one. The column comes from the cell's own r="D3"
//     reference — see sheetRows.
//   - A HIDDEN SHEET IS READ, AND ITS HEADING SAYS IT IS HIDDEN. See
//     sheetRef.heading. The same call is made for a hidden SLIDE in readPPTX.
//   - FORMULAS EMIT THEIR RESULT, not their source. `=SUM(B2:B9)` is not what
//     the user reads and not what they would search for; 4,150 is. OOXML stores
//     both, and this takes the cached value.
//   - DATES EMIT AS DATES. This is the one place the raw value is actively
//     WRONG rather than merely terse: a date is stored as a day count and would
//     come out as "45200" — a number no one will ever search for, in place of
//     "2023-09-15". The number format decides, read from styles.xml.
//
// The row cap is not a new number. Emission stops when the accumulated text
// reaches ctxExtractMaxText, the ceiling this lane already has for a reply, and
// says which sheet and row it stopped at. For scale: Elasticsearch's
// ingest-attachment defaults to 100,000 indexed characters and Tika's
// parseToString to the same; ctxExtractMaxText is 4 MiB, roughly 40x that, so a
// workbook that hits this wall is far past what a text index would have kept.

type sheetRef struct {
	name  string // the part path
	title string
	// state is the workbook's <sheet state="…">: "", "hidden" or "veryHidden".
	// It lives on the workbook entry and nowhere else — a hidden sheet's own
	// worksheet part is an ordinary one, full of the user's cells.
	state string
}

// heading is the sheet's line in the output, and it is where a HIDDEN sheet is
// declared to be hidden.
//
// THE CALL: a hidden sheet is READ, and MARKED. Not skipped.
//
// The case for skipping is that hiding a sheet is how people put working aside —
// scratch columns, an old version, the lookup table behind a dropdown — and a
// corpus that quotes it back is quoting something the user does not think of as
// part of their document.
//
// It loses to two things. First, hiding is also how people keep a sheet they
// still rely on out of the way, and a reader that silently drops it produces the
// worst answer this lane has: a search that finds nothing, from a document that
// contains the words, with nothing anywhere saying why. Every other decision in
// this file goes the other way on exactly that trade — an unreadable sheet says
// so in the text, a slide with no words on it is still printed, a workbook that
// stopped says where. Second, the confusing part of a hidden-sheet hit is not
// that it exists, it is that the user cannot find it in the file they have open;
// and that is fixed by saying "(hidden)", not by deleting the content.
//
// So the user can always tell, and the marking is on the heading a hit is
// retrieved with rather than in a flag they never see.
//
// "veryHidden" is named separately because it is a different act: Excel's own
// interface cannot unhide it — it takes the VBA editor — so a user seeing that
// sheet quoted back is even further from being able to find it.
func (s sheetRef) heading() string {
	switch {
	case strings.EqualFold(s.state, "veryHidden"):
		return fmt.Sprintf("=== Sheet: %s (very hidden) ===", s.title)
	case strings.EqualFold(s.state, "hidden"):
		return fmt.Sprintf("=== Sheet: %s (hidden) ===", s.title)
	}
	return fmt.Sprintf("=== Sheet: %s ===", s.title)
}

// officeTailReserve is room held back at the end of a workbook's text for the
// sentences that say the extraction stopped early.
//
// It exists because those sentences were being written PAST the reply's own
// ceiling and cut back off by the truncation at contextextract.go. MEASURED
// on a 200,000-row single-column sheet: the reply came back at exactly
// ctxExtractMaxText characters ending in "--- stopped after 1", with the rest of
// the sentence, and everything that would have followed it, gone. Whether it
// survived depended on how wide the last row happened to be — a sheet of wide
// rows left enough slack and a sheet of narrow ones did not.
//
// 1 KiB against a 4 MiB reply is 0.02% of the text, and it holds the stop marker
// (about 90 characters) plus the unread-sheet list bounded below.
const officeTailReserve = 1024

// officeUnreadNamesMax bounds how many sheet names the unread list prints, so a
// workbook with 300 sheets cannot spend the reserve on its own table of contents.
const officeUnreadNamesMax = 12

// officeUnreadNameMax bounds one printed sheet name, for the same reason: a title
// is untrusted text and can be as long as the writer allowed.
const officeUnreadNameMax = 60

func readXLSX(files map[string]*zip.File, b *unpackBudget, deadline time.Time) (string, officeResult, error) {
	shared := readSharedStrings(files, b)
	dateStyles := readDateStyles(files, b)
	sheets := workbookSheets(files, b)
	if len(sheets) == 0 {
		return "", officeResult{Kind: kindXLSX}, fmt.Errorf("this workbook has no sheets in it")
	}
	var out strings.Builder
	partial, stopped := false, false
	var unread []sheetRef
	for i, sh := range sheets {
		if pastDeadline(deadline) {
			return out.String(), officeResult{Kind: kindXLSX, Parts: len(sheets),
				Partial: partial, Deadline: true}, nil
		}
		f := files[sh.name]
		if f == nil {
			partial = true
			fmt.Fprintf(&out, "%s\n(this sheet is named in the workbook but "+
				"its data is not in the file)\n\n", sh.heading())
			continue
		}
		body, err := readPart(f, b, officePartMax)
		if err != nil {
			// SAY IT IN THE TEXT, not only in a flag. A sheet that could not be
			// read and a sheet with nothing in it are different facts, and the
			// user is the one who needs to tell them apart.
			partial = true
			fmt.Fprintf(&out, "%s\n(this sheet could not be read: %v)\n\n", sh.heading(), err)
			continue
		}
		fmt.Fprintf(&out, "%s\n", sh.heading())
		rows, p, hitWall := sheetRows(body, shared, dateStyles, &out, deadline)
		partial = partial || p
		if rows == 0 {
			out.WriteString("(no cells with anything in them)\n")
		}
		out.WriteString("\n")
		if hitWall {
			fmt.Fprintf(&out, "--- stopped after %d rows of %q: this workbook is larger "+
				"than one extraction returns ---\n", rows, sh.title)
			stopped, unread = true, sheets[i+1:]
			break
		}
	}
	// WHAT THE EXTRACTION NEVER GOT TO, NAMED.
	//
	// This is where `_ = stopped` went. The flag was computed and thrown away,
	// which left the reply saying where it stopped INSIDE a sheet and saying
	// nothing at all about the sheets behind it — so a workbook whose data sheet
	// runs long came back reading like a complete extraction of a workbook with
	// one sheet in it. The sheet names are the most findable thing a workbook has
	// (see the emission note above), and losing them without a word is the blind
	// answer readPPTX refuses to give for a slide with no text on it.
	if stopped && len(unread) > 0 {
		out.WriteString(unreadSheetsLine(unread))
	}
	return out.String(), officeResult{Kind: kindXLSX, Parts: len(sheets),
		Partial: partial, Deadline: pastDeadline(deadline)}, nil
}

// unreadSheetsLine names the sheets an extraction stopped before reaching,
// bounded so the line always fits inside officeTailReserve.
func unreadSheetsLine(unread []sheetRef) string {
	names := make([]string, 0, officeUnreadNamesMax)
	for _, sh := range unread {
		if len(names) == officeUnreadNamesMax {
			names = append(names, "…")
			break
		}
		title := sh.title
		if len(title) > officeUnreadNameMax {
			title = title[:officeUnreadNameMax] + "…"
		}
		names = append(names, strconv.Quote(title))
	}
	word, verb := "sheets", "were"
	if len(unread) == 1 {
		word, verb = "sheet", "was"
	}
	return fmt.Sprintf("--- %d more %s in this workbook %s not read: %s ---\n",
		len(unread), word, verb, strings.Join(names, ", "))
}

// sheetRows streams one worksheet, writing rows as it goes.
//
// A CELL'S COLUMN IS ITS r="…" REFERENCE, NOT ITS POSITION AMONG ITS SIBLINGS.
// A writer emits a <c> only for cells that exist, and an untouched interior cell
// is absent from the XML entirely — MEASURED on files written by openpyxl 3.1.5
// AND by LibreOffice 26.2.5.2, both of which emit `<row r="3"><c r="A3"/><c
// r="D3"/></row>` for a row whose B and C were never typed in. So appending
// cells in document order slides every value after a gap to the left, and the
// emitted line then asserts that a number belongs to a column it does not belong
// to — a clean-looking labelled record that is simply false, which nothing
// downstream can detect. That is what this used to do.
//
// The gap is emitted as an EMPTY FIELD rather than closed up, so a value stays
// under the header it sits under. Trailing empties are still dropped, since a
// sheet's used range runs far past its content and the padding would bury it.
//
// Returns rows written, whether the XML failed part-way, and whether emission
// stopped at the wall — which is ctxExtractMaxText less officeTailReserve, so
// that the sentences readXLSX writes afterwards to say it stopped are inside the
// reply rather than past its end.
func sheetRows(body string, shared []string, dateStyles map[int]bool,
	out *strings.Builder, deadline time.Time) (int, bool, bool) {
	d := xml.NewDecoder(strings.NewReader(body))
	rows, checked := 0, 0
	var cells []string
	inCell, cellType, cellStyle, cellRef := false, "", 0, ""
	var val, inline strings.Builder
	inV, inT := false, false
	for {
		// The deadline is checked every 512 tokens rather than every one: a
		// time.Now() per token on a 60 MB part is measurable, and 512 tokens is
		// microseconds of overshoot.
		checked++
		if checked%512 == 0 && pastDeadline(deadline) {
			return rows, false, false
		}
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Malformed part-way. Keep the rows already emitted and say so —
			// see officeResult.Partial.
			return rows, true, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "row":
				cells = cells[:0]
			case "c":
				inCell, cellType, cellStyle, cellRef = true, "", 0, ""
				val.Reset()
				inline.Reset()
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "t":
						cellType = a.Value
					case "s":
						cellStyle, _ = strconv.Atoi(a.Value)
					case "r":
						cellRef = a.Value
					}
				}
			case "v":
				inV = inCell
			case "t":
				inT = inCell
			}
		case xml.CharData:
			if inV {
				val.Write(t)
			} else if inT {
				inline.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "v":
				inV = false
			case "t":
				inT = false
			case "c":
				txt := cellText(cellType, cellStyle, val.String(), inline.String(), shared, dateStyles)
				// A cell with no usable reference — which no writer emits, but a
				// corrupt or hand-made part can — falls back to its position, the
				// only other thing available.
				if col := colFromRef(cellRef); col >= 0 {
					for len(cells) <= col {
						cells = append(cells, "")
					}
					cells[col] = txt
				} else {
					cells = append(cells, txt)
				}
				inCell = false
			case "row":
				line := trimTrailing(cells)
				if len(line) == 0 {
					continue
				}
				joined := strings.Join(line, officeRowSep)
				if out.Len()+len(joined)+1 > ctxExtractMaxText-officeTailReserve {
					return rows, false, true
				}
				out.WriteString(joined)
				out.WriteString("\n")
				rows++
			}
		}
	}
	return rows, false, false
}

// xlsxMaxColumns is the format's own ceiling — column XFD, 16,384 — and it is
// here as a bound on ALLOCATION, not as a policy. A reference is three letters
// of untrusted input; without this, r="ZZZ1" asks for 18,278 empty strings and a
// longer one asks for more. Anything past the ceiling is not a column this
// format can have, so it is treated as no reference at all.
const xlsxMaxColumns = 16384

// colFromRef turns a cell reference's letters into a zero-based column index —
// "A" is 0, "D" is 3, "AA" is 26. Returns -1 when there is nothing usable to
// read, which the caller handles by falling back to sibling position.
//
// The letters are bijective base-26: there is no zero digit, so "AA" is
// 1*26 + 1 = 27, i.e. index 26, and the plain positional reading is off by one
// at every carry.
func colFromRef(ref string) int {
	n, letters := 0, 0
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c < 'A' || c > 'Z' {
			break
		}
		letters++
		if letters > 3 {
			return -1
		}
		n = n*26 + int(c-'A') + 1
	}
	if letters == 0 || n > xlsxMaxColumns {
		return -1
	}
	return n - 1
}

// cellText resolves one cell to what a person reading the sheet would see.
func cellText(cellType string, style int, v, inlineStr string, shared []string, dateStyles map[int]bool) string {
	switch cellType {
	case "s": // shared string: v is an index into the table
		if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && i >= 0 && i < len(shared) {
			return shared[i]
		}
		return ""
	case "inlineStr":
		return strings.TrimSpace(inlineStr)
	case "str": // a formula that returned text — v IS the result
		return strings.TrimSpace(v)
	case "b":
		if strings.TrimSpace(v) == "1" {
			return "TRUE"
		}
		return "FALSE"
	case "e": // an error value: #DIV/0! and friends, as the user sees them
		return strings.TrimSpace(v)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if dateStyles[style] {
		if s := serialToDate(v); s != "" {
			return s
		}
	}
	return v
}

// serialToDate turns Excel's day count into an ISO date, which is the form
// anyone would actually search for.
//
// The 1900 epoch with its leap-year bug: Excel treats 1900 as a leap year, so
// serial 60 is a day that never existed and every serial above it is one greater
// than the true day count. Day 1 is 1900-01-01, so subtracting 2 from serials
// past 60 lands on the right date — the arithmetic every reader of this format
// does. The 1904 (Mac) epoch is not handled; it is rare and getting it wrong by
// four years is visible, not silent.
func serialToDate(v string) string {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 1 || f > 2958466 { // 2958465 = 9999-12-31
		return ""
	}
	days := math.Floor(f)
	frac := f - days
	off := 2.0
	if days < 60 {
		off = 1.0
	}
	t := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(days-off))
	if frac > 0 {
		t = t.Add(time.Duration(frac * 24 * float64(time.Hour)))
		return t.Format("2006-01-02 15:04")
	}
	return t.Format("2006-01-02")
}

// readDateStyles maps a cell's style index to "this is a date".
//
// xl/styles.xml holds <cellXfs>, one <xf numFmtId=…> per style index. The
// built-in ids 14-22 and 45-47 are the date and time formats every writer uses;
// a custom format is a date when its code contains a day, month-as-date or year
// token. Anything unreadable here simply yields no date styles, and the cell
// falls back to its raw value — worse output, never a failed extraction.
func readDateStyles(files map[string]*zip.File, b *unpackBudget) map[int]bool {
	out := map[int]bool{}
	f := files["xl/styles.xml"]
	if f == nil {
		return out
	}
	body, err := readPart(f, b, 8<<20)
	if err != nil {
		return out
	}
	customDate := map[int]bool{}
	d := xml.NewDecoder(strings.NewReader(body))
	inCellXfs, idx := false, 0
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "numFmt":
				id, code := -1, ""
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "numFmtId":
						id, _ = strconv.Atoi(a.Value)
					case "formatCode":
						code = a.Value
					}
				}
				if id >= 0 && isDateFormatCode(code) {
					customDate[id] = true
				}
			case "cellXfs":
				inCellXfs = true
			case "xf":
				if !inCellXfs {
					continue
				}
				id := 0
				for _, a := range t.Attr {
					if a.Name.Local == "numFmtId" {
						id, _ = strconv.Atoi(a.Value)
					}
				}
				if builtinDateFmt(id) || customDate[id] {
					out[idx] = true
				}
				idx++
			}
		case xml.EndElement:
			if t.Name.Local == "cellXfs" {
				inCellXfs = false
			}
		}
	}
	return out
}

func builtinDateFmt(id int) bool {
	return (id >= 14 && id <= 22) || (id >= 45 && id <= 47)
}

// isDateFormatCode reads a custom number format's code. Quoted literals and the
// colour/condition brackets are skipped so a currency format like
// [$-409]#,##0.00 or "dollars"0.00 cannot be mistaken for a date by the 'd' in
// its literal text.
func isDateFormatCode(code string) bool {
	inQuote, inBracket := false, false
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == '[':
			inBracket = true
		case c == ']':
			inBracket = false
		case inQuote || inBracket:
		case c == '\\':
			i++
		case c == 'y' || c == 'Y' || c == 'd' || c == 'D':
			return true
		case c == 'm' || c == 'M':
			// 'm' is minutes next to h/s and months otherwise. Either way the
			// cell is a date or a time and the serial needs converting.
			return true
		}
	}
	return false
}

// readSharedStrings loads xl/sharedStrings.xml, the table every text cell in a
// workbook points into.
func readSharedStrings(files map[string]*zip.File, b *unpackBudget) []string {
	f := files["xl/sharedStrings.xml"]
	if f == nil {
		return nil
	}
	body, err := readPart(f, b, officePartMax)
	if err != nil {
		return nil
	}
	var out []string
	d := xml.NewDecoder(strings.NewReader(body))
	var cur strings.Builder
	depth, inT := 0, false
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "si":
				depth++
				cur.Reset()
			case "t":
				inT = depth > 0
			}
		case xml.CharData:
			if inT {
				cur.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inT = false
			case "si":
				depth--
				// A string split across formatting runs arrives as several <t>
				// in one <si> and is concatenated, which is what the cell shows.
				out = append(out, strings.TrimSpace(cur.String()))
			}
		}
	}
	return out
}

// workbookSheets pairs each sheet's USER-GIVEN NAME with the part that holds it.
//
// The name is the point: it is the label the sheet is findable by. It lives in
// xl/workbook.xml against a relationship id, and the part path lives in
// xl/_rels/workbook.xml.rels against the same id, so both are read. If the rels
// part is missing or does not resolve, the sheets fall back to file order —
// the titles are still right, only the pairing could drift, and a wrong pairing
// is better than no titles at all.
func workbookSheets(files map[string]*zip.File, b *unpackBudget) []sheetRef {
	rels := map[string]string{}
	for _, r := range partRels(files, "xl/workbook.xml", b) {
		rels[r.id] = r.target
	}
	fallback := numberedParts(files, "xl/worksheets/sheet", ".xml")
	var out []sheetRef
	if wf := files["xl/workbook.xml"]; wf != nil {
		if body, err := readPart(wf, b, 8<<20); err == nil {
			d := xml.NewDecoder(strings.NewReader(body))
			for {
				tok, err := d.Token()
				if err != nil {
					break
				}
				se, ok := tok.(xml.StartElement)
				if !ok || se.Name.Local != "sheet" {
					continue
				}
				var title, rid, state string
				for _, a := range se.Attr {
					switch a.Name.Local {
					case "name":
						title = a.Value
					case "id": // r:id
						rid = a.Value
					case "state":
						// "visible", "hidden" or "veryHidden"; absent means
						// visible. Carried so the heading can say so.
						state = a.Value
					}
				}
				part := rels[rid]
				if part == "" && len(out) < len(fallback) {
					part = fallback[len(out)].name
				}
				if title == "" {
					title = fmt.Sprintf("Sheet%d", len(out)+1)
				}
				if strings.EqualFold(state, "visible") {
					state = ""
				}
				out = append(out, sheetRef{name: part, title: title, state: state})
			}
		}
	}
	if len(out) == 0 {
		for i, p := range fallback {
			out = append(out, sheetRef{name: p.name, title: fmt.Sprintf("Sheet%d", i+1)})
		}
	}
	return out
}

// ── shared XML walking ──────────────────────────────────────────────────────

// officeMCNS is the Markup Compatibility namespace (ECMA-376 Part 3). Unlike the
// content dialects it is ONE url in every part of every format, which is why the
// alternate-content handling below matches on it rather than on a local name:
// "Choice" and "Fallback" are ordinary words and could appear elsewhere.
const officeMCNS = "http://schemas.openxmlformats.org/markup-compatibility/2006"

// mcSelect implements ECMA-376 Part 3's selection rule over a token stream, and
// it exists as a type rather than as four local variables because TWO walkers
// need it: runsToText, and the comment walker in readDOCXComments. A text box
// inside a comment is the same alternate-content pair as a text box in the body,
// and a second hand-written copy of this logic is how the two would drift.
//
// The rule it enforces is stated in full on runsToText.
//
// Usage: call start on every StartElement and end on every EndElement, in order,
// BEFORE acting on the element. Both return "this element is inside a branch
// being skipped"; skipping() answers the same question for CharData.
type mcSelect struct {
	depth int
	// skipFrom is the depth of the alternate-content branch currently being
	// ignored, or -1 when none is.
	skipFrom int
	// taken has one entry per open <mc:AlternateContent> — they nest, a text box
	// inside a text box — recording whether a branch of it has already been
	// taken.
	taken []bool
}

func newMCSelect() *mcSelect { return &mcSelect{skipFrom: -1} }

func (m *mcSelect) start(t xml.StartElement) bool {
	m.depth++
	if t.Name.Space == officeMCNS {
		switch t.Name.Local {
		case "AlternateContent":
			// Pushed even inside a skipped branch so the pop in end always has
			// something to take off; the guard on Choice/Fallback is what keeps a
			// skipped branch from claiming anything.
			m.taken = append(m.taken, false)
		case "Choice", "Fallback":
			if m.skipFrom < 0 && len(m.taken) > 0 {
				if m.taken[len(m.taken)-1] {
					m.skipFrom = m.depth
				} else {
					m.taken[len(m.taken)-1] = true
				}
			}
		}
	}
	return m.skipFrom >= 0
}

func (m *mcSelect) end(t xml.EndElement) bool {
	m.depth--
	if m.skipFrom >= 0 && m.depth < m.skipFrom {
		m.skipFrom = -1
	}
	if t.Name.Space == officeMCNS && t.Name.Local == "AlternateContent" && len(m.taken) > 0 {
		m.taken = m.taken[:len(m.taken)-1]
	}
	return m.skipFrom >= 0
}

func (m *mcSelect) skipping() bool { return m.skipFrom >= 0 }

// runsToText pulls text runs out of a WordprocessingML or DrawingML part.
//
// tEl is the run element ("t" in both dialects), pEl the paragraph, tabEl an
// element that means a tab, brEl one that means a line break. Namespace
// PREFIXES are deliberately not matched for those: Go's decoder resolves them to
// URLs, the two dialects use different URLs for the same local names, and
// matching on local name is what makes one walker serve both.
//
// ── ALTERNATE CONTENT: ONE BRANCH, NEVER BOTH ───────────────────────────────
//
// <mc:AlternateContent> is how both Word and PowerPoint write anything with more
// than one representation, and a TEXT BOX is the common case: an
// <mc:Choice Requires="wps"> holding the DrawingML shape and an <mc:Fallback>
// holding the VML one. BOTH CARRY A FULL COPY OF THE SAME w:txbxContent —
// verified on a LibreOffice-written docx, where the callout's words appear twice
// in word/document.xml — because they are alternatives, not parts. Part 3 has a
// consumer select exactly one: the first Choice whose Requires it understands,
// and the Fallback only if none matched.
//
// So this takes the FIRST branch of each AlternateContent and skips the rest.
// Requires is not evaluated, and that is the right reading for a TEXT extractor
// rather than a laziness: the namespaces it names describe how to DRAW the
// thing, and this job wants only the words inside, which every branch spells the
// same way. Taking the first Choice — the richest representation, and the one a
// current Word opens — and falling through to Fallback only when a package has
// no Choice at all is the behaviour that reads every text box exactly once.
//
// Walking both, which this used to do, put every callout, pull quote
// and diagram label into the corpus TWICE: doubled embedding cost, two retrieval
// hits for one passage, and a document that appears to say a thing twice.
//
// Returns the text and whether the part failed to parse part-way through.
func runsToText(body, tEl, pEl, tabEl, brEl string, deadline time.Time) (string, bool) {
	d := xml.NewDecoder(strings.NewReader(body))
	var out strings.Builder
	var line strings.Builder
	inT, checked := false, 0
	mc := newMCSelect()
	flush := func() {
		s := strings.TrimRight(line.String(), " \t")
		line.Reset()
		if strings.TrimSpace(s) == "" {
			return
		}
		out.WriteString(s)
		out.WriteString("\n")
	}
	for {
		checked++
		if checked%512 == 0 && pastDeadline(deadline) {
			flush()
			return out.String(), false
		}
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			flush()
			return out.String(), true
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if mc.start(t) {
				break
			}
			switch t.Name.Local {
			case tEl:
				inT = true
			case tabEl:
				if tabEl != "" {
					line.WriteString("\t")
				}
			case brEl:
				flush()
			}
		case xml.CharData:
			if inT && !mc.skipping() {
				line.Write(t)
				if out.Len()+line.Len() > ctxExtractMaxText {
					flush()
					return out.String(), false
				}
			}
		case xml.EndElement:
			if mc.end(t) {
				break
			}
			switch t.Name.Local {
			case tEl:
				inT = false
			case pEl:
				flush()
			}
		}
	}
	flush()
	return out.String(), false
}

// numberedParts finds slideN.xml / sheetN.xml and returns them in NUMERIC order.
// Sorting the names as strings puts slide10 before slide2.
type numberedPart struct {
	name string
	n    int
}

func numberedParts(files map[string]*zip.File, prefix, suffix string) []numberedPart {
	var out []numberedPart
	for name := range files {
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		mid := name[len(prefix) : len(name)-len(suffix)]
		n, err := strconv.Atoi(mid)
		if err != nil {
			continue
		}
		out = append(out, numberedPart{name: name, n: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].n < out[j].n })
	return out
}

func trimTrailing(cells []string) []string {
	end := len(cells)
	for end > 0 && strings.TrimSpace(cells[end-1]) == "" {
		end--
	}
	return cells[:end]
}

func pastDeadline(deadline time.Time) bool {
	return !deadline.IsZero() && time.Now().After(deadline)
}

// ── the probe ───────────────────────────────────────────────────────────────

// officeProbeText is the text the probe package contains and the probe expects
// back out of it.
const officeProbeText = "PRIVATAE OFFICE PROBE"

// officeProbePackage builds a minimal, valid docx in memory: a content-types
// part and a document with one paragraph.
func officeProbePackage() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`},
		{"word/document.xml", `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>` + officeProbeText + `</w:t></w:r></w:p></w:body></w:document>`},
	}
	for _, p := range parts {
		w, err := zw.Create(p[0])
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(w, p[1]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// officeProve is the capability probe, and it PROVES THE CAPABILITY rather than
// a proxy for it.
//
// The rest of this table probes a binary and takes its exit code, because that
// is the only handle an external program offers. This job has no binary, so the
// honest probe is the whole reader run end to end over a package built in
// memory: if the ZIP layer, the XML walker and the text assembly all work, the
// probe returns the document's own words back.
//
// The failure it is guarding against is not a missing install — there is none —
// but a build where this path is broken. A box in that state must not advertise
// office-text, for exactly the reason `tesseract --version` exiting 0 on a
// machine with no language data must not: an advertisement that a job will
// produce text, from a box that would return none.
func officeProve() (bool, string) {
	pkg, err := officeProbePackage()
	if err != nil {
		return false, "this build cannot assemble an Office package to test itself with: " + err.Error()
	}
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return false, "this build's ZIP reader rejected its own test package: " + err.Error()
	}
	text, _, err := extractOfficeZip(zr, time.Time{})
	if err != nil {
		return false, "this build's Office reader failed on its own test document: " + err.Error()
	}
	if !strings.Contains(text, officeProbeText) {
		return false, "this build's Office reader returned no text from its own test document"
	}
	return true, ""
}
