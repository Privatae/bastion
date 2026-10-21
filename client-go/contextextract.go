package main

// ctx_extract — turn a user's bytes into their content, ON THEIR MACHINE.
//
// contextprep.go says WHAT this box can do. This runs it.
//
// The host hands over one document and gets back TEXT. That text then feeds the
// embedding lane that already works, so a PDF becomes searchable with no new
// columns, no wire probing and no two-tower gate — which is why extraction is
// cheaper to land than the picture lane was, not more expensive.
//
// ── TWO TRANSPORTS, and which one a job uses ────────────────────────────────
//
// INLINE: the document rides the management frame as base64. Simple, and hard
// ceilinged — measured, not guessed. A management job is ONE WebSocket frame
// carrying its payload as base64 in args, and base64 inflates by 4/3, so
// the host's 16 MiB WebSocket frame ceiling is reached at just under 12 MiB of original bytes
// (ctxcap_measure_test.go; the same wall backupfetch.go documents).
// ctxExtractMaxBytes sits at 8 MiB to leave room for the JSON around the payload.
// A document over it is REFUSED WITH ITS SIZE, never silently truncated and never
// half-extracted.
//
// PULL (contextpull.go): the host sends a single-use TICKET and this box fetches
// the source over the tunnel it already holds, streaming to disk at constant
// memory. Ceiling 64 MiB. This is what OCR needs — scanned PDFs routinely exceed
// 8 MiB — and it is the reason the inline cap never had to grow.
//
// The blocker that kept this file inline-only until now was auth, and the note
// that recorded it was accurate: the host route serving a context row's bytes
// requires an application token this box does not hold, and the host's one
// internal-auth bypass is allow-listed to a single unrelated route. The fix was not to
// soften that gate — it is a general read over every row — but a route with a
// narrower authority: GET /api/network/bastions/context-source, this box's own
// bearer plus a ticket that names one document and expires. See contextpull.go.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// The largest ORIGINAL document accepted in one inline job. See the note above:
// 8 MiB of source is ~10.7 MiB of base64, about two thirds of the 16 MiB frame
// ceiling, which leaves the JSON envelope room it will never need to fight for.
const ctxExtractMaxBytes = 8 << 20

// How much extracted TEXT travels back. A document can legitimately produce more
// text than anyone wants in one frame; past this the reply is marked truncated
// and says how much there was. Flagged-partial beats both silent truncation and
// a refusal that hands the user nothing after the work was already done.
const ctxExtractMaxText = 4 << 20

// Extraction is bounded so one pathological file cannot hold a mgmt worker.
// Comfortably inside the host's 30 s dispatch timeout, so the host
// sees a real answer rather than a timeout it cannot attribute.
const ctxExtractTimeout = 20 * time.Second

// ctxExtractTimeoutFor is how long THIS job may take, and it is THE ONLY PLACE
// that number exists. Reading a PDF's text layer and OCRing thirty scanned pages
// are not the same amount of work and one number cannot bound both honestly:
// 20 s refuses every scanned document, and 150 s for everything lets a broken
// pdftotext hold a worker for two and a half minutes.
//
// THE HOST DOES NOT MIRROR THIS. It reads each value out of the prep
// advertisement (prepToolReport.CeilingS, filled from this function), waits that
// plus a round trip, and hands the same number back as extract_budget. So a job
// this file gains tomorrow is bounded correctly on a host that has never heard
// of it, which a mirrored table cannot do: the host's fallback for an unknown
// job can only be the largest value the HOST knows, and the bastion publishes on
// its own schedule. The concrete case is a transcription job bounded in minutes
// meeting a host whose largest known ceiling is 150 s.
func ctxExtractTimeoutFor(tool string) time.Duration {
	switch tool {
	case "ocr":
		return ocrImageTimeout
	case "pdf-ocr":
		return ocrExtractTimeout
	case "office-text":
		return officeExtractTimeout
	case ctxFramesTool:
		return ctxFramesTimeout
	case sttTool, sttAVTool:
		// THE ONLY CEILING IN THIS SWITCH THAT IS NOT A CONSTANT, and the reason
		// is the reason this mechanism was built. Transcription's cost is set by
		// the model the user installed and by how fast their machine is: an hour
		// of audio is about 75 seconds of work at base.en on eight cores and
		// about fifteen minutes at large-v3-turbo. No literal can be honest about
		// both, so the number comes from a measurement the probe took on THIS
		// machine (contextstt.go, sttCeiling). It is large, which is exactly the
		// case prepToolReport.CeilingS exists for.
		return sttCeiling()
	}
	return ctxExtractTimeout
}

// ctxExtractBudget is what this job actually gets: the SMALLER of what this box
// allows for the tool and what the host granted. Down, never up.
//
// Identical in shape and reason to ctxPullBudget one file over. The host's wait
// is the grant plus a round trip, so clamping down keeps the box under the host
// by construction; clamping UP would let a host park this machine's worker for
// as long as it liked.
//
// A grant of 0 is a host that predates the field. It gets this box's own number
// rather than zero — refusing the job would break every bastion whose host has
// not been updated, and the only job such a host can ask for is the text-layer
// read anyway.
func ctxExtractBudget(tool string, grantedS float64) time.Duration {
	own := ctxExtractTimeoutFor(tool)
	if grantedS <= 0 {
		return own
	}
	granted := time.Duration(grantedS * float64(time.Second))
	if granted < own {
		return granted
	}
	return own
}

type ctxExtractReq struct {
	// Tool is a NAME FROM contextprep.go's table ("pdf-text"), not a binary and
	// not an argv. The host asks for a job; which program does it is this box's
	// business, so swapping poppler later is not a host-visible change.
	Tool string `json:"tool"`
	Mime string `json:"mime"`
	// B64 is the INLINE path: the document rides the management frame. Capped at
	// ctxExtractMaxBytes by the frame, which is why the pull path exists.
	B64 string `json:"b64"`
	// Ticket is the PULL path (contextpull.go): a single-use, machine-bound token
	// that authorizes ONE fetch of ONE document from this host. Not an id and not
	// a URL — see contextpull.go's header for why it is neither.
	Ticket string `json:"ticket"`
	// Size is what the host says the document weighs, verified after the
	// transfer. 0 = not declared (a row that predates the field), in which case
	// only the ceiling applies.
	Size int64 `json:"size"`
	// Doc is the host's stable name for the document ("ctx:<id>"). The
	// person's approval binds it with the tool and the mime, and — inline —
	// the sha256 of B64 too; never the ticket (writes.go approvalArgs). Not
	// used by the extraction itself.
	Doc string `json:"doc"`
	// MaxBytes is the host's proposed ceiling. The smaller of it and
	// ctxPullMaxBytes wins — a host asking for more gets this box's number.
	MaxBytes int64 `json:"max_bytes"`
	// PullBudget is the SECONDS the host grants for the fetch, and it is what
	// keeps this box giving up before the host does: the host's own wait is this
	// number plus a fixed allowance. Clamped down by ctxPullBudget, never up. 0
	// is a host predating the field and gets the floor.
	PullBudget float64 `json:"pull_budget"`
	// ExtractBudget is the SECONDS the host grants for the WORK, the way
	// PullBudget grants the seconds for the transfer. Clamped down by this box's
	// own ceiling for the job and never up — a host asking for more gets the
	// box's number, exactly as with the pull budget.
	//
	// The host does not invent it: it is the ceiling THIS BOX declared for THIS
	// job in its own prep advertisement (prepToolReport.CeilingS), handed back.
	// That is what removes the mirrored table the ordering used to rest on, and
	// with it the case where a bastion ships a longer job than the host has
	// heard of and the host gives up while the machine is still working.
	//
	// 0 is a host predating the field, which can only be asking for the
	// text-layer read — every job added since declares a ceiling, enforced by
	// TestEveryAdvertisedToolDeclaresItsCeiling — and gets this box's own number.
	ExtractBudget float64 `json:"extract_budget"`
	// Model NAMES which of this box's models the job should use, from the list
	// the box advertised (prepToolReport.Models). Empty means "the best one you
	// have", which is the normal case.
	//
	// It is a NAME, never a path: the host chooses among what the machine said it
	// has, and where those files live is the box's business. A name this machine
	// does not hold is REFUSED with the list rather than quietly served a
	// different model — the accuracy of a transcript is set by which model read
	// it, so a silent substitution would put a number on the record that the run
	// never earned.
	Model string `json:"model"`
	// Lang NAMES the spoken language for a transcription job, the same way Model
	// names the model: the host chooses, the box does it or refuses. Empty means
	// the engine's own default, which its help states is `en` — and that is what
	// every job has always run as, which is exactly the problem this field
	// closes. "auto" is a language a host may name.
	//
	// It is REFUSED rather than quietly ignored on a model that cannot honour it:
	// an English-only model handed -l de transcribes English and exits 0
	// (measured), so passing the flag blindly would put a German label on an
	// English transcript. See sttLang.
	//
	// The OCR lanes do not read this — their language is whichever pack the
	// machine has, which is the box's business and is reported back, not chosen.
	Lang string `json:"lang,omitempty"`
}

type ctxExtractResp struct {
	Tool string `json:"tool"`
	// Source is which transport actually carried the document, "inline" or
	// "pull". Reported rather than inferred: the host decides, but a job that
	// fell back would otherwise be invisible in the record.
	Source    string `json:"source,omitempty"`
	Chars     int    `json:"chars"`
	Truncated bool   `json:"truncated,omitempty"`
	CharsAll  int    `json:"chars_total,omitempty"`
	Text      string `json:"text"`
	// ── the scanned-PDF record ──────────────────────────────────────────────
	//
	// Pages is how many pages this job read. PagesOCR is how many of them had no
	// usable text layer and went to the engine. Both are reported rather than
	// inferred, because they are the difference between the three answers a user
	// can get from a document that produced no text: this machine has no engine,
	// this machine has an engine with no language data, and the engine read every
	// page and they are blank. Only the box knows the third one.
	Pages    int `json:"pages,omitempty"`
	PagesOCR int `json:"pages_ocr,omitempty"`
	// PagesUnread is pages the engine could not finish inside one page's
	// allowance. Counted separately from a blank page and from a page past the
	// cap, because they are three different things to tell a user and only one
	// of them means the document is complete.
	PagesUnread int `json:"pages_unread,omitempty"`
	// PagesMore is set when the document has more pages than one job reads. The
	// count is deliberately NOT reported — this build knows "there is a page
	// past the cap" and nothing more, and a number it did not measure would be
	// a guess in a field that looks like a fact.
	PagesMore bool `json:"pages_more,omitempty"`
	// Lang is the language the engine actually read in. Reported so a wrong
	// transcription has a visible first thing to check.
	Lang string `json:"lang,omitempty"`
	// Deadline is set when the clock ran out mid-document and the text is what
	// was read before it did. Partial and SAID to be partial: the pages already
	// read are the user's, and throwing them away to return a clean error helps
	// nobody.
	Deadline bool `json:"deadline,omitempty"`
	// ── the transcript record (contextstt.go) ───────────────────────────────
	//
	// Model is the speech model that ACTUALLY RAN. Not the one asked for and not
	// the box's preference: the one that produced these words. It is the most
	// important field this reply gained, because base.en and large-v3-turbo
	// differ by 3x in error rate on hard audio, so the same transcript means two
	// different things depending on which read it. The host writes it onto every
	// row it files.
	Model string `json:"model,omitempty"`
	// Segments is the transcript with its timestamps: {t0, t1, text} in
	// milliseconds from the start of the recording. The host chunks ON these
	// boundaries and files each chunk's first t0 as media_offset_ms, which
	// is what lets a search result be jumped to in the audio.
	//
	// Text carries the same words joined, so a host that has never heard of this
	// field still files a searchable transcript — it just cannot offer the jump.
	Segments []sttSegment `json:"segments,omitempty"`
	// AudioMS is how long the recording is; 0 means the box could not find out
	// and is never reported as a duration. DoneMS is how far the transcript
	// reaches. Together they are what tells a user how much of their meeting is
	// in the corpus and how much is not.
	AudioMS int64 `json:"audio_ms,omitempty"`
	DoneMS  int64 `json:"transcribed_ms,omitempty"`
	// Capped is the recording running past what one job covers, so this is the
	// first hour of it and the rest is NOT in the corpus.
	Capped bool `json:"audio_capped,omitempty"`
	// Blank is the engine having read the whole recording and found no speech in
	// it. A FINISHED job with an empty answer — which is a different sentence
	// from "this box has no engine" and from "it has one and no model", and the
	// only one of the three that the box alone can tell anyone.
	Blank bool `json:"blank,omitempty"`
	// NonSpeech is the engine having heard a sound and NAMED it instead of
	// transcribing it — "[Music]", "(applause)", "[♪♪♪]". A fourth answer beside
	// the three above, and it is separate from Blank on purpose: a song is not
	// silence, and a reply that said it was would be a false statement about the
	// user's own file. The annotation itself never reaches the corpus.
	NonSpeech bool `json:"non_speech,omitempty"`
	// Demuxed is ffmpeg having unpacked an audio track before the engine saw it.
	// Reported rather than inferred from the tool name, so "this needed ffmpeg"
	// is visible in the record of the job that needed it.
	Demuxed bool `json:"demuxed,omitempty"`
}

func ctxExtractFail(ws *websocket.Conn, msg string) {
	sendMgmt(ws, 'R', []byte(msg+"\n"))
	sendMgmtExit(ws, 1)
}

// extractArgv is how each tool is asked to write plain text to stdout.
//
// Verified against the real binaries, not copied from documentation:
//
//	pdftotext -layout -q -- <in> -   preserves column layout and writes to stdout.
//	                                 "-" as the output file IS the stdout spelling;
//	                                 poppler has no --stdout flag.
//
//	tesseract <in> - -l <lang>       "-" as the output BASE is tesseract's
//	                                 spelling of stdout; there is no --stdout.
//	                                 The language comes from what the box has
//	                                 installed (ocrLang), because hardcoding
//	                                 "eng" would refuse a machine whose only
//	                                 pack is another language.
//
// A tool absent from this map is refused even if contextprep.go can probe it,
// so advertising a capability can never by itself make this run something.
var extractArgv = map[string]func(in string) []string{
	"pdf-text": func(in string) []string { return []string{"-layout", "-q", "--", in, "-"} },
	"ocr":      ocrArgv,
}

// extractMulti is the jobs that are NOT one command.
//
// pdf-ocr reads the text layer, renders only the pages whose layer is too thin
// to be the page, and runs the engine on those — three programs and a per-page
// decision, which is not an argv.
// It lives in its own table rather than being forced into the shape of one, and
// the drift gates (TestAdvertisedToolsCanActuallyRun and its twin) read the
// UNION of the two so a job in either is advertisable and a job in neither is
// not.
var extractMulti = map[string]func(root, in string, deadline time.Time) (string, []ocrPageResult, int, bool, error){
	"pdf-ocr": runPDFOCR,
	// office-text runs ZERO commands: docx/xlsx/pptx are ZIPs of XML and this
	// binary reads them itself (contextoffice.go). That is even further from
	// "one argv writing to stdout" than pdf-ocr's three programs are, so it
	// belongs here rather than in a third table.
	"office-text": runOfficeText,
}

// transcribeTools is the jobs whose answer is text WITH TIMESTAMPS, plus the
// name of the model that produced it.
//
// A THIRD TABLE RATHER THAN A WIDER SECOND ONE, and the reason is the same one
// that kept video out of extractMulti. extractMulti's signature returns
// (text, []ocrPageResult, pageTotal, deadline, error) — a shape built around
// PAGES. A transcript has no pages; it has segments, a duration, a model, and
// the difference between "silence" and "could not decode". Widening extractMulti
// to carry those would put a speech concern inside the OCR job's return type and
// leave every caller reading five values where three are always zero.
//
// It also answers the widening extractArgv seemed to need. That table
// is `func(in string) []string` and a transcription argv needs a MODEL PATH as
// well as an input — but the widening is not needed once the job lives here,
// because the model is resolved inside the runner where it belongs. pdf-text and
// ocr do not grow a parameter they would ignore, and the choice of model stays
// next to the code that has to explain it.
//
// The drift gates read the UNION of every runner table, so a job in any one of
// them is advertisable and a job in none of them is not.
var transcribeTools = map[string]func(root, in, tool, model, lang string, deadline time.Time) (sttResult, error){
	sttTool:   runTranscribe,
	sttAVTool: runTranscribe,
}

// handleCtxExtract runs ONE document through ONE tool and returns its text.
//
// root is the pairing's sandboxed context root — the scratch file never leaves
// it, and it is removed before the reply is sent whatever happened.
func handleCtxExtract(ws *websocket.Conn, root string, args []string) {
	if len(args) < 1 {
		ctxExtractFail(ws, "ctx_extract: need a JSON argument")
		return
	}
	var req ctxExtractReq
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		ctxExtractFail(ws, "ctx_extract: argument is not JSON: "+err.Error())
		return
	}

	// The tool must be one this box ADVERTISED, and it must still answer. Probing
	// again here rather than trusting the last heartbeat is the difference between
	// "we told you ten minutes ago" and "it works now" — a user can uninstall
	// poppler between a beat and a job.
	mk, single := extractArgv[req.Tool]
	multi, multiOK := extractMulti[req.Tool]
	// FOUR RUNNERS, and a tool is in exactly one. extractArgv is one command
	// producing text; extractMulti is several commands producing text;
	// frameTools (contextframes.go) is the one whose answer is not text at all;
	// transcribeTools (contextstt.go) is the one whose answer is text with a
	// time on every piece of it and the name of the model that heard it.
	// Neither of the last two is extractMulti with a different body: that
	// runner's signature returns a string and a list of OCR PAGE results, and
	// widening it to carry jpegs — or segments, a duration and a model — would
	// put another job's concerns inside the OCR job's type. The drift gates read
	// the union of all four and fail on any overlap.
	frames := frameTools[req.Tool]
	stt, sttOK := transcribeTools[req.Tool]
	if !single && !multiOK && !frames && !sttOK {
		ctxExtractFail(ws, "ctx_extract: unknown tool "+strconv.Quote(req.Tool)+
			" — this box runs only the jobs it advertises")
		return
	}
	var tool prepTool
	for _, t := range prepToolTable {
		if t.Name == req.Tool {
			tool = t
		}
	}
	// "Is this name in the table at all" — tested on the NAME, not on Bin. It was
	// Bin, which worked only for as long as every job had a program: office-text
	// is built into this binary and has none, and a Bin test would have refused
	// the one job that can never be missing.
	if tool.Name != req.Tool {
		ctxExtractFail(ws, "ctx_extract: "+req.Tool+" is not in this build's tool table")
		return
	}
	// RE-PROBE, and for OCR that means a real OCR of the test image, not a
	// --version. A user can remove a language pack between a heartbeat and a
	// job, and the failure that would cause here is the one this lane is most
	// obliged not to produce: a scanned document coming back empty. The reason
	// is carried through verbatim so the refusal says what to install.
	if ok, _, why := probePrepToolDetail(tool); !ok {
		if why != "" {
			ctxExtractFail(ws, "ctx_extract: "+why+" — nothing was extracted")
			return
		}
		ctxExtractFail(ws, "ctx_extract: "+toolLabel(tool)+" is not installed on this machine "+
			"(or stopped working) — nothing was extracted")
		return
	}

	// ONE TRANSPORT PER JOB, decided by which field the host filled in. Both at
	// once is refused rather than silently preferring one: a host that sent both
	// does not know which document it is asking about, and guessing for it is
	// how the wrong bytes get extracted.
	inline := strings.TrimSpace(req.B64) != ""
	pull := strings.TrimSpace(req.Ticket) != ""
	switch {
	case inline && pull:
		ctxExtractFail(ws, "ctx_extract: a job carries a document OR a fetch ticket, never both")
		return
	case !inline && !pull:
		ctxExtractFail(ws, "ctx_extract: empty document")
		return
	}

	var raw []byte
	if inline {
		// SIZE BEFORE DECODE. base64 is 4/3, so the encoded length tells us the
		// document's size without materialising it — and by this point the frame
		// already exists three times over (the raw websocket message, job.Args[0],
		// and req.B64). Decoding first added a fourth copy of a body we were about
		// to refuse anyway. The exact check still runs after the decode, because
		// this one is an estimate from the padding and must not be the wall.
		if est := (len(strings.TrimSpace(req.B64)) / 4) * 3; est > ctxExtractMaxBytes {
			ctxExtractFail(ws, fmt.Sprintf(
				"ctx_extract: document is about %d bytes, over the %d this lane "+
					"carries in one job — not truncated, not partly extracted",
				est, ctxExtractMaxBytes))
			return
		}

		var err error
		raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(req.B64))
		if err != nil {
			ctxExtractFail(ws, "ctx_extract: body is not base64: "+err.Error())
			return
		}
		if len(raw) == 0 {
			ctxExtractFail(ws, "ctx_extract: empty document")
			return
		}
		// Refused WITH ITS SIZE. A caller that gets "too big" and no number cannot
		// tell whether to split, downscale, or wait for the pull lane.
		if len(raw) > ctxExtractMaxBytes {
			ctxExtractFail(ws, fmt.Sprintf(
				"ctx_extract: document is %d bytes, over the %d this lane carries in one "+
					"job (a management frame holds its payload as base64 and the host's "+
					"socket stops at 16 MiB) — not truncated, not partly extracted",
				len(raw), ctxExtractMaxBytes))
			return
		}
	}

	// Scratch inside the pairing's own sandboxed root, removed whatever happens.
	// The document is the user's and never persists past the call.
	f, err := os.CreateTemp(root, "extract-*")
	if err != nil {
		ctxExtractFail(ws, "ctx_extract: cannot open scratch space: "+err.Error())
		return
	}
	scratch := f.Name()
	defer os.Remove(scratch)
	if pull {
		// STRAIGHT TO DISK, at constant memory. Not through a []byte first: the
		// point of this path is that a 64 MiB source never exists whole in the
		// bastion's heap, times mgmtWorkerCount, on the user's own machine.
		//
		// A partial download is still scratch and still removed — by the defer
		// above on every early return here, and explicitly before the reply on
		// the paths that reach it.
		n, perr := pullSourceInto(f, strings.TrimSpace(req.Ticket), req.MaxBytes,
			ctxPullBudget(req.PullBudget))
		if perr != nil {
			f.Close()
			_ = os.Remove(scratch)
			ctxExtractFail(ws, "ctx_extract: "+perr.Error())
			return
		}
		// VERIFY BEFORE USE, the discipline backup_fetch established. The host
		// declares the length it expects to serve; a short or long body means
		// the transfer or the row changed under the job, and either way the
		// extracted text would be of something other than what was asked for.
		if req.Size > 0 && n != req.Size {
			f.Close()
			_ = os.Remove(scratch)
			ctxExtractFail(ws, fmt.Sprintf(
				"ctx_extract: fetched %d bytes but this host said the document is %d "+
					"— nothing was extracted", n, req.Size))
			return
		}
		if n == 0 {
			f.Close()
			_ = os.Remove(scratch)
			ctxExtractFail(ws, "ctx_extract: empty document")
			return
		}
	} else if _, err := f.Write(raw); err != nil {
		f.Close()
		ctxExtractFail(ws, "ctx_extract: cannot write scratch file: "+err.Error())
		return
	}
	if err := f.Close(); err != nil {
		ctxExtractFail(ws, "ctx_extract: cannot close scratch file: "+err.Error())
		return
	}

	limit := ctxExtractBudget(req.Tool, req.ExtractBudget)

	source := "inline"
	if pull {
		source = "pull"
	}

	// THE TWO BRANCHES THAT ARE NOT A DOCUMENT. Everything above this line is
	// the same for every shape of job — the tool is advertised and still
	// answers, the transport was chosen, the user's bytes are in one scratch
	// file inside the pairing's own root, and the budget is settled. Below it,
	// every line assumes the answer is a flat string with pages behind it. A
	// clip's answer is pictures; a recording's is words with times on them and
	// the name of the model that heard them. Both fork here rather than
	// pretending. Each handler owns the scratch file from that point, including
	// removing it before it replies.
	if frames {
		handleCtxFrames(ws, root, scratch, tool, source, limit)
		return
	}
	if sttOK {
		handleCtxTranscribe(ws, root, scratch, req, stt, source, limit)
		return
	}

	var out string
	var timedOut bool
	var pages []ocrPageResult
	var pageTotal int
	var deadlineHit bool
	if multiOK {
		// A multi-step job owns its own clock because it spends it in pieces —
		// read the layer, then a render and an engine run per page that needs
		// one — and each
		// piece has to know how much is left. It reports a DEADLINE separately
		// from a timeout: out of time with pages already read is a partial
		// answer, not a failed job.
		out, pages, pageTotal, deadlineHit, err = multi(root, scratch, time.Now().Add(limit))
	} else {
		out, timedOut, err = runExtract(limit, tool.Bin, mk(scratch)...)
	}

	// REMOVE IT HERE, before any reply — not on the deferred path.
	//
	// The guarantee this lane makes is that the user's document is gone by the
	// time the host is told the job finished, and `defer` does not provide it:
	// the terminal frame is written inside the reply helpers below, so the host
	// reads "done" while the file is still on disk and the deferred Remove has
	// not run. Caught by TestCtxExtractLeavesNothingOnDisk, which failed ONLY
	// under the full suite — the window is microseconds and load is what widens
	// it, which is exactly why it looked flaky and was not.
	// The defer above stays as the backstop for the early returns that never
	// reach this line.
	_ = os.Remove(scratch)

	if timedOut {
		// A DEADLINE IS NOT A BAD DOCUMENT, and saying so was actively
		// misleading: runCmd returns the text extracted so far on any failure,
		// so a timeout used to be reported as "could not read this document:
		// <the first 400 characters OF THE USER'S OWN DOCUMENT>", presented as
		// the tool's explanation. The host stores that string as the error and
		// the model reads it.
		ctxExtractFail(ws, fmt.Sprintf(
			"ctx_extract: %s was still working after %s and was stopped — the "+
				"document was not rejected, it did not finish in the time this "+
				"lane allows", toolLabel(tool), limit))
		return
	}
	if err != nil {
		// The tool's own words: a password-protected or corrupt PDF lands here
		// and poppler explains it better than this code could.
		//
		// WHICH VARIABLE HOLDS THEM DEPENDS ON THE PATH, and that was a bug. An
		// argv job's explanation arrives in `out`, because runExtract returns
		// stdout+stderr on a non-zero exit. A MULTI-STEP job's arrives in `err`
		// and `out` is empty — so every failure of pdf-ocr, the only multi job
		// there was, came back as the bare sentence "could not read this
		// document" with "pdftoppm could not rasterize this PDF: …" thrown away.
		// The host stores that string and the model reads it, so the difference
		// is the difference between a user knowing what to fix and not.
		msg := strings.TrimSpace(out)
		if msg == "" && err != nil {
			msg = strings.TrimSpace(err.Error())
		}
		if len(msg) > 400 {
			msg = msg[:400]
		}
		ctxExtractFail(ws, "ctx_extract: "+toolLabel(tool)+" could not read this document"+
			ifNonEmpty(msg, ": "+msg))
		return
	}

	resp := ctxExtractResp{Tool: req.Tool, Source: source, Chars: len(out), Text: out}
	// THE LANGUAGE BELONGS TO THE ENGINE, NOT TO EVERY MULTI-STEP JOB. This was
	// `multiOK || req.Tool == "ocr"`, which was true of every job in extractMulti
	// — correct while pdf-ocr was the only one in it, and wrong the moment a
	// second arrived: office-text reads a ZIP and has no language, so it would
	// have reported whichever tesseract pack the machine happens to have as the
	// language its docx was read in. A field that looks like a fact.
	if req.Tool == "ocr" || req.Tool == "pdf-ocr" {
		resp.Lang = ocrLang()
	}
	if len(pages) > 0 {
		resp.Pages = len(pages)
		for _, p := range pages {
			switch p.How {
			case "ocr":
				resp.PagesOCR++
			case "unread":
				resp.PagesUnread++
			}
		}
		// pageTotal of -1 is runPDFOCR's way of saying "there is at least one
		// page past the cap and this build did not count how many".
		resp.PagesMore = pageTotal < 0
	}
	resp.Deadline = deadlineHit
	if len(out) > ctxExtractMaxText {
		resp.Text = out[:ctxExtractMaxText]
		resp.Chars = ctxExtractMaxText
		resp.CharsAll = len(out)
		resp.Truncated = true
	}
	b, err := json.Marshal(resp)
	if err != nil {
		ctxExtractFail(ws, "ctx_extract: cannot encode the result: "+err.Error())
		return
	}
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// sweepStaleScratch removes extraction scratch left by a PREVIOUS process.
//
// Every in-handler path removes its own file, and a panic would unwind through
// the defer. What neither covers is the process dying mid-job — kill -9, a power
// cut, an OOM — which leaves one of the user's documents on their disk with
// nothing that would ever notice. Called once at worker start; best-effort by
// design, since a scratch file that cannot be removed must not stop the lane
// from coming up.
func sweepStaleScratch(root string) int {
	if root == "" || root == "-" {
		return 0
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		// "extract-" is the one source document; "frames-" is the video job's
		// DIRECTORY of decoded jpegs (contextframes.go), which is more of the
		// user's picture data than any text job leaves behind — and it is a
		// directory, so the IsDir skip that was right for the first would have
		// stranded the second for ever.
		switch {
		case !e.IsDir() && strings.HasPrefix(e.Name(), "extract-"):
			if err := os.Remove(filepath.Join(root, e.Name())); err == nil {
				n++
			}
		case e.IsDir() && strings.HasPrefix(e.Name(), "frames-"):
			if err := os.RemoveAll(filepath.Join(root, e.Name())); err == nil {
				n++
			}
		}
	}
	return n
}

// capWriter stops accepting bytes once it holds `max`, and remembers that it
// did. The process keeps running and keeps writing into /dev/null as far as it
// can tell, so nothing changes about its exit code.
type capWriter struct {
	buf bytes.Buffer
	max int
	hit bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.max - w.buf.Len()
	if room <= 0 {
		w.hit = true
		return len(p), nil // absorbed and dropped: never fail the process
	}
	if len(p) > room {
		w.buf.Write(p[:room])
		w.hit = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// runExtract runs one extractor with the output BOUNDED as it arrives.
//
// runCmd (harness.go) captures stdout into an unbounded bytes.Buffer, which is
// right for the fixed-output commands it was written for and wrong here: the
// caller controls the input, and extracted text is not proportional to it.
// MEASURED: a 3.2 MB PDF whose 20,000 pages share one compressed
// stream made pdftotext emit ~83 MB, peaking the bastion at 211 MiB heap and
// 306 MiB allocated — on the USER'S machine, times mgmtWorkerCount. Capping
// after the process exits, which is what the reply cap did, is too late.
//
// Bounding at the reply cap +1 keeps exactly enough to know truncation
// happened, and means a runaway document costs a few megabytes instead of
// however much text it felt like producing.
//
// Returns (output, timedOut, err). timedOut is separated because a deadline and
// an unreadable document are different facts and were being reported as one.
func runExtract(timeout time.Duration, name string, args ...string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd) // extraction runs while the user works — console_windows.go
	out := &capWriter{max: ctxExtractMaxText + 1}
	errb := &capWriter{max: 8 << 10} // a tool's complaint, not its output
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	timedOut := ctx.Err() == context.DeadlineExceeded
	if err != nil && !timedOut {
		return strings.TrimSpace(out.buf.String() + " " + errb.buf.String()), false, err
	}
	return out.buf.String(), timedOut, err
}

// ifNonEmpty keeps the error line readable when a tool said nothing at all.
func ifNonEmpty(s, withPrefix string) string {
	if s == "" {
		return ""
	}
	return withPrefix
}

// toolLabel is what a refusal calls the thing that refused.
//
// A job with a program is named by it — "pdftotext could not read this
// document" tells a user precisely what to go and check. A BUILTIN has no
// program, and the empty string this used to produce read as a sentence with a
// hole in it (" could not read this document"), so it is named for what it is.
func toolLabel(t prepTool) string {
	if t.Bin != "" {
		return t.Bin
	}
	return "this box's built-in " + t.Name + " reader"
}
