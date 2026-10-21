package main

// contextprep.go — what this machine can turn into TEXT.
//
// OCR and the other common data-preparation tools belong here because
// preparing context is the bastion's whole job. A video decoder, likewise, is
// a user thing — never a platform service — so it has to be something the user
// runs.
//
// The principle that makes those one family: ANYTHING THAT TURNS A USER'S
// BYTES INTO THEIR CONTENT RUNS ON THEIR HARDWARE. Same reason embeddings went
// to the bastion, and stronger — an embedding is a vector, but OCR output is
// the literal text of their document and a transcript is the literal words
// they said.
//
// This file is the ADVERTISEMENT half only: which of those tools this box
// actually has. It never runs one on a document; that is the ctx_extract op.
//
// ── why one capability with a list, and not one token per tool ──────────────
//
// The host's question is always "can this box turn THIS mime into text", which
// is a lookup, not six separate checks. The heartbeat already carries lists
// beside capabilities for exactly this (models, llm_models, schedulers —
// agents.go:448-479), so the shape exists; six tokens would be six flag days
// for no gain.
//
// ── why the probe RUNS the tool ─────────────────────────────────────────────
//
// detectRuntime (harness.go:580) runs `docker ps -q` and takes the exit code
// rather than looking for a file, because a binary on PATH that cannot execute
// is not a capability. Same rule here.
//
// MEASURED, and it is why the version is read from BOTH streams:
// `pdftotext -v` writes its banner to STDERR and exits 0, while `tesseract
// --version` and `ffmpeg -version` write to STDOUT. runCmd returns clean
// stdout on success, so a version read through it reports poppler as blank
// while poppler works perfectly. The CAPABILITY decision is the exit code
// alone; the version string is for the operator's eyes and must not be allowed
// to influence it.
//
// ── quiet vs blind ─────────────────────────────────────────────────────────
//
// A box that has no tools and a box that could not look must not read the same
// to the host. That distinction is already made three times in this heartbeat
// (agent-observe, computer-observe, scheduler-observe — agents.go:423-444), so
// the scan report travels the way schedScanReport does.

import (
	"os/exec"
	"strings"
	"sync"
	"time"
)

// prepCapability is the single token. Additive: agents.go:359-360 records that
// hosts predating a capability ignore one they do not know, so this needs no
// host-side flag day and an older host simply never offers the feature.
const prepCapability = "context-prep"

// prepGateOp is the op name this capability is gated by, and the name is
// LOAD-BEARING. capsAllow maps an op to a family through opFamily
// (anchor.go:411-427), and opFamily returns "" for a name it does not
// recognise — whereupon capsAllow ALLOWS it (anchor.go:476-479). So an op
// called "prep_extract" would be UNGATED on an anchored box, silently. The
// "ctx_" prefix puts it in the dcn family, beside ctx_* and backup_fetch,
// which is where it belongs on the merits too: like backup_fetch it pulls the
// host's bytes onto the user's machine. Nothing in anchor.go needs to change
// and no seventh caps family has to be invented.
//
// prepGateOpFamily is asserted against opFamily in the test, so renaming the
// op without thinking about the family fails a gate instead of quietly opening
// this lane to every member pairing.
const prepGateOp = "ctx_extract"
const prepGateOpFamily = "dcn"

// prepCacheFor matches scanSchedulers' cadence (schedulers.go:435) for the
// same reason given there: the heartbeat is every 60 s, this is a handful of
// shell-outs, and installing a tool should show up within minutes without
// anyone restarting the daemon.
const prepCacheFor = 10 * time.Minute

// prepTool is one thing this box might be able to do, the binary that would do
// it, and an argv that proves the binary RUNS.
//
// EVERY probe argv below was executed against the real tool and
// its exit code recorded — none is copied from documentation. A tool whose
// interface has not been verified does not belong in this table: advertising
// it would be the exact dishonesty the quiet-vs-blind rule exists to prevent.
type prepTool struct {
	// Name is what the HOST asks for. It names the job, not the program, so
	// swapping poppler for something else later is not a host-visible change.
	Name string
	Bin  string
	Args []string
	// Builtin marks a job THIS BINARY does, with no program on the machine to
	// probe: office-text reads docx/xlsx/pptx out of Go's own archive/zip and
	// encoding/xml, so there is nothing to install and nothing to exec.
	//
	// It does not weaken the honesty rule, it moves where the rule bites. A
	// builtin still has to PROVE itself below, and office-text's Prove runs the
	// whole reader over a package assembled in memory. What a builtin removes is
	// the "is it installed" question, which for a builtin has exactly one answer.
	Builtin bool
	// Needs are the OTHER binaries this job cannot run without, each with an
	// argv that proves IT runs. pdf-ocr rasterizes with poppler before it hands
	// a page to the engine, and a box holding one of the two must not advertise
	// the job. Probed exactly like Bin, after it.
	Needs []prepTool
	// Prove, when set, is the LAST word on availability and overrides nothing
	// before it — every binary must still answer first. It exists because an
	// exit code is sometimes a PROXY for the capability rather than the
	// capability: `tesseract --version` and `tesseract --list-langs` both exit 0
	// on a machine with no language data installed, which cannot read a word
	// (measured, contextocr.go's header). Returning a REASON is the point: "the
	// engine is here and has no language data" and "there is no engine" are
	// different answers that the user fixes with different commands.
	Prove func() (bool, string)
	// Langs, when set, is what this job can read. It travels beside the tool so
	// a user can see which language pack their machine is using without asking
	// it anything.
	Langs func() []string
	// Models, when set, is the MODEL FILES this job can load, best-first.
	//
	// Unlike Langs this is not merely informational, and transcription is why it
	// exists. "I have poppler" is the whole answer for a PDF; "I have a speech
	// engine" is not the answer for a recording, because base.en and
	// large-v3-turbo are three times apart in error rate on hard audio and eleven
	// times apart in CPU (measured, contextstt.go). A host choosing a machine for
	// a recording is choosing a model whether it knows it or not, so the list
	// travels and the host may name one.
	Models func() []string
}

// prepToolTable is every job this build knows how to probe for.
//
// DELIBERATELY ABSENT, and each for a stated reason rather than an oversight:
//   - transcribe: the implementation is not chosen. whisper.cpp (a binary),
//     openai-whisper (python) and faster-whisper (a library) differ in what the
//     user must install, not merely in speed, so the pick is partly a product
//     call. The rule is to benchmark rather than pick from reputation; until that
//     runs there is no argv to verify and nothing honest to advertise.
//
// Adding it means verifying its argv the same way, not appending a row.
var prepToolTable = []prepTool{
	// Text PDFs — the largest gap by volume, and no OCR needed for them.
	// -v exits 0 and prints to stderr (measured).
	{Name: "pdf-text", Bin: "pdftotext", Args: []string{"-v"}},
	// OCR of a picture: the literal words on it, read by the engine.
	//
	// Args is the cheap "does the binary run" gate; Prove is what actually
	// decides, because --version exits 0 on a machine with no language data.
	// contextocr.go's header has the measurement.
	{Name: "ocr", Bin: "tesseract", Args: []string{"--version"},
		Prove: ocrProve, Langs: ocrLangs},
	// A scanned PDF: its own text layer where it has one, the engine where it
	// does not. Needs BOTH poppler tools as well as the engine — the layer pass
	// reads the text and carries the page count, the rasterizer draws the pages
	// that need the engine — which is why this is a separate job from "ocr" and
	// not the same one pointed at a PDF.
	//
	// Bin is the engine rather than poppler on purpose: a box with no tesseract
	// reports this job as simply absent (it also has no "ocr"), while a box WITH
	// the engine and no pdftoppm reports it as blocked and names the missing
	// piece. The first binary probed is the one whose absence is uninteresting.
	{Name: "pdf-ocr", Bin: "tesseract", Args: []string{"--version"},
		Needs: []prepTool{
			{Name: "rasterize", Bin: "pdftoppm", Args: []string{"-v"}},
			{Name: "pdf-layer", Bin: "pdftotext", Args: []string{"-v"}},
		},
		Prove: ocrProve, Langs: ocrLangs},
	// Office documents: docx, xlsx and pptx, read by THIS BINARY.
	//
	// soffice was unverified, so it was installed and run
	// before this row was written. It is not used, and contextoffice.go's header
	// carries the four measurements that decided it — the one that matters most
	// here is that two concurrent headless conversions against one user profile
	// lose one of the pair in 5 of 5 trials, silently, with nothing on either
	// stream. This box runs mgmtWorkerCount management workers.
	//
	// No Bin and no Args because there is no program: these three formats are
	// ZIPs of XML and Go's standard library reads both halves. THE USER INSTALLS
	// NOTHING, which on a lane that runs on their own machine is the criterion
	// that decides between two tools that would both work.
	{Name: "office-text", Builtin: true, Prove: officeProve},
	// A clip's FRAMES (contextframes.go). Two binaries, because the job is two
	// steps: ffprobe reads the container's keyframe index without decoding
	// anything, and ffmpeg then decodes only the frames the plan asks for. A box
	// with one and not the other cannot finish the job, so Needs carries the
	// second — the same structure pdf-ocr uses for its rasterizer.
	//
	// Both argvs were run against the real binaries (ffmpeg 8.0.1):
	// each exits 0 and banners to stdout.
	//
	// This job's answer is PICTURES, not text, so its runner is frameTools
	// rather than extractArgv or extractMulti — see contextframes.go for why the
	// reply has a second shape instead of a text field holding base64.
	{Name: ctxFramesTool, Bin: "ffmpeg", Args: []string{"-version"},
		Needs: []prepTool{
			{Name: "probe", Bin: "ffprobe", Args: []string{"-version"}},
		}},
	// SPEECH TO TEXT — the words the user actually said (contextstt.go).
	//
	// Two rows for one engine, and the split is the same one pdf-text/pdf-ocr
	// makes: whisper-cli reads wav, mp3, flac and ogg BY ITSELF and FAILS on mp4
	// and m4a (measured against the real binary; its own help prints the list).
	// So a box with the engine alone can transcribe every voice memo the user
	// owns, and a box with ffmpeg as well can also transcribe a clip's audio
	// track. One row would either refuse the first box or lie to the second.
	//
	// `--version` exits 0 in 0.01s and banners to stdout (measured). It is the
	// cheap gate only: Prove is what decides, because an installed engine WITH NO
	// MODEL also exits 0 — and that is the normal state after installing it, the
	// Ubuntu 26.04 package shipping no model file at all. Prove loads a model and
	// transcribes a known input, and it TIMES that run, which is where this job's
	// declared ceiling comes from.
	{Name: sttTool, Bin: sttBin, Args: []string{"--version"},
		Prove: sttProve, Models: sttModelsReport},
	// Bin is the ENGINE rather than ffmpeg on purpose, the same way pdf-ocr's is
	// tesseract rather than poppler: a box with no whisper-cli reports this job
	// as simply absent (it has no "transcribe" either), while a box WITH the
	// engine and no ffmpeg reports it as blocked and names the missing piece —
	// which is the sentence that tells an mp4 user what to install.
	{Name: sttAVTool, Bin: sttBin, Args: []string{"--version"},
		Needs: []prepTool{
			{Name: "demux", Bin: "ffmpeg", Args: []string{"-version"}},
		},
		Prove: sttProve, Models: sttModelsReport},
}

// prepToolReport is one AVAILABLE tool as the host sees it.
type prepToolReport struct {
	Name string `json:"name"`
	Bin  string `json:"bin"`
	// Version is the tool's own first line, best-effort and for the operator's
	// eyes only. Empty is NOT a failure signal — see the stream note above.
	Version string `json:"version,omitempty"`
	// Langs is what this job can read, when reading is language-shaped. Only OCR
	// fills it in. It is informational: the box picks the language it uses and
	// reports it in the job's result; this is so a user can see which packs are
	// installed without running anything.
	Langs []string `json:"langs,omitempty"`
	// Models is what this job can load, best-first, when the job is one whose
	// answer depends on a model. Only transcription fills it in.
	//
	// The FIRST entry is what runs when the host names none. The host may name
	// one from this list in the job (ctxExtractReq.Model) and the reply says
	// which one ACTUALLY ran (ctxExtractResp.Model), so a transcript's accuracy
	// is a recorded fact rather than something inferred from whatever the machine
	// happened to hold at the time.
	Models []string `json:"models,omitempty"`
	// Builtin says this job needs nothing installed — the binary does it. The
	// host shows it so a user comparing two machines can see that one of these
	// jobs is available on every box running this version and the others depend
	// on what they have put on the machine.
	Builtin bool `json:"builtin,omitempty"`
	// CeilingS is the SECONDS this box will spend on this job before it stops,
	// and unlike Langs it is NOT informational — the host's dispatch wait is
	// built from it.
	//
	// THE NUMBER ORIGINATES HERE AND TRAVELS; there is no copy of it on the
	// host. It was briefly a table on the box and a mirrored table on the host
	// with a comment on each side asserting their relationship, which is the
	// shape that had ALREADY failed once in this lane — the pull path's two
	// deadline constants were in the wrong order across the whole domain while
	// both comments claimed otherwise.
	//
	// The exposure a mirror leaves points the way its mitigation does not. A
	// host's fallback for a job it has never heard of can only be the largest
	// ceiling THE HOST knows. The bastion publishes separately and users update
	// on their own schedule, so a box shipping a transcription job bounded at
	// ten minutes — an hour of audio on a CPU is not a 150-second job — against
	// a host that has not been updated gives: host waits 170 s, box works 600 s,
	// and the user is told their machine did not answer by the side that quit
	// first, with the transcript discarded when it arrives. That is exactly the
	// failure the pull path was rebuilt to eliminate.
	//
	// So: the box declares what each job costs, the host waits that plus a round
	// trip, and the host GRANTS the same number back in the job as
	// extract_budget, which the box clamps DOWN to and never up — the shape
	// pull_budget already proved one change earlier. A job that does not exist
	// yet is covered by construction rather than by anyone remembering.
	CeilingS float64 `json:"ceiling_s"`
}

// prepToolBlocked is a job whose PROGRAM is on this machine but which still
// cannot run, with the reason in plain language.
//
// This is the whole quiet-vs-blind distinction for tools. Without it a box with
// no OCR engine and a box with the engine and no language data are the same
// silence — the same empty tool list, the same "none of your machines can do
// this" — and the two are fixed by different commands. Reported for a tool
// whose FIRST binary answered, so a machine with none of the software installed
// stays quiet rather than listing everything it has never had.
type prepToolBlocked struct {
	Name   string `json:"name"`
	Bin    string `json:"bin"`
	Reason string `json:"reason"`
}

// prepScanReport is how much was looked at, so "no tools" from a box that
// probed three binaries is visibly different from a box that probed none.
type prepScanReport struct {
	// Supported is whether this build can probe at all. Always true here (the
	// probe is exec, which every platform has); it exists so a future build
	// that cannot probe on some platform has an honest way to say so, the way
	// schedScanReport.Supported does.
	Supported bool `json:"supported"`
	// Probed is how many tools were tried, Found how many answered.
	Probed int `json:"probed"`
	Found  int `json:"found"`
	// Blocked is every job that is ALMOST here — its program is installed and
	// something else is missing. See prepToolBlocked. An older host ignores the
	// field; a newer one turns it into the sentence that tells the user what to
	// install.
	Blocked []prepToolBlocked `json:"blocked,omitempty"`
	// Pull is whether this box can FETCH a source instead of being handed it in
	// the management frame (contextpull.go). It rides the scan report, not
	// prep_tools, because the transport is a property of the BOX's extraction
	// lane and not of any one tool — every tool on a box that can pull can be
	// fed by a pull.
	//
	// It is what keeps the host honest across versions: a bastion that predates
	// this reports no field, the host reads that as false, and it keeps sending
	// documents inline instead of handing out a ticket that box could not
	// redeem. Advertising it means "this box COULD fetch", never "will" — the
	// host still decides, per job, which transport to use.
	Pull bool `json:"pull"`
}

var prepCache = struct {
	sync.Mutex
	at    time.Time
	tools []prepToolReport
	scan  prepScanReport
}{}

// probePrepTool runs one tool's proving argv. Returns whether it ran, and its
// first output line if there was one.
//
// Both streams are read because the banner's stream varies by tool (measured
// above). The exit code is the ONLY input to the availability decision — a
// tool that runs but prints nothing is available.
func probePrepTool(t prepTool) (bool, string) {
	ok, ver, _ := probePrepToolDetail(t)
	return ok, ver
}

// probePrepToolDetail is the full answer: available, its version, and — when it
// is NOT available but its program is installed — why not.
//
// The order is deliberate and each step is a strictly better authority than the
// one before it: the program runs, then everything it depends on runs, then the
// job is actually PERFORMED on a known input. A tool with no Prove stops after
// the first two, which is right for pdftotext (there is no second thing it could
// be missing) and wrong for tesseract (there is, and it exits 0 anyway).
func probePrepToolDetail(t prepTool) (bool, string, string) {
	if t.Builtin {
		// No program, so the first two steps have nothing to ask. The THIRD one
		// still runs and is the whole probe: Prove performs the job on a known
		// input and compares the answer. A builtin is never "not installed", but
		// it can still be broken, and a broken one must not be advertised.
		if t.Prove != nil {
			if ok, why := t.Prove(); !ok {
				return false, "", why
			}
		}
		return true, "built in — nothing to install", ""
	}
	out, err := runCmd(5*time.Second, t.Bin, t.Args...)
	if err != nil {
		// A non-zero exit and a missing binary both land here, and they are NOT
		// the same thing to the user. An absent program is quiet — there is
		// nothing to say about software nobody installed. A present one that
		// will not run is named.
		if _, lerr := exec.LookPath(t.Bin); lerr == nil {
			return false, "", t.Bin + " is installed on this machine but did not run"
		}
		return false, "", ""
	}
	for _, n := range t.Needs {
		if _, nerr := runCmd(5*time.Second, n.Bin, n.Args...); nerr != nil {
			return false, "", t.Bin + " works but " + n.Bin + " is missing or will not run, " +
				"and this job needs both"
		}
	}
	if t.Prove != nil {
		if ok, why := t.Prove(); !ok {
			return false, "", why
		}
	}
	// Success: runCmd gave clean stdout, which is EMPTY for tools that banner
	// to stderr. Absent output is not absent capability, so report available
	// with no version rather than probing again for a cosmetic string.
	return true, firstLine(out), ""
}

// firstLine is the tool's own first line of output, trimmed and length-capped
// so a chatty or hostile binary cannot inflate the heartbeat body.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return strings.TrimSpace(s)
}

// scanPrepTools is the heartbeat's entry point: probe every known tool, cached.
func scanPrepTools() ([]prepToolReport, prepScanReport) {
	prepCache.Lock()
	defer prepCache.Unlock()
	if !prepCache.at.IsZero() && time.Since(prepCache.at) < prepCacheFor {
		// Tools are cached; the transport is not. It flips exactly once, when
		// the daemon wires its tunnel client, and a box that probed before that
		// would otherwise keep reporting pull=false for up to prepCacheFor —
		// telling the host to send documents inline on a machine that can fetch.
		scan := prepCache.scan
		scan.Pull = ctxPullConfigured()
		return prepCache.tools, scan
	}
	tools := []prepToolReport{}
	blocked := []prepToolBlocked{}
	for _, t := range prepToolTable {
		ok, ver, why := probePrepToolDetail(t)
		if !ok {
			if why != "" {
				blocked = append(blocked, prepToolBlocked{Name: t.Name, Bin: t.Bin, Reason: why})
			}
			continue
		}
		// The ceiling is read from the SAME function the job is actually run
		// under (ctxExtractTimeoutFor), never from a second literal beside it —
		// the declaration and the enforcement have to be one value or the
		// declaration is just another mirror, one file further away.
		r := prepToolReport{Name: t.Name, Bin: t.Bin, Version: ver,
			Builtin:  t.Builtin,
			CeilingS: ctxExtractTimeoutFor(t.Name).Seconds()}
		if t.Langs != nil {
			r.Langs = t.Langs()
		}
		if t.Models != nil {
			r.Models = t.Models()
		}
		tools = append(tools, r)
	}
	// Pull is read LIVE, not cached with the tool probes: it flips once when the
	// daemon's tunnel client is wired (run.go), and a box that reported false in
	// the first beat must not keep saying so for prepCacheFor afterwards.
	scan := prepScanReport{Supported: true, Probed: len(prepToolTable), Found: len(tools),
		Blocked: blocked, Pull: ctxPullConfigured()}
	prepCache.at, prepCache.tools, prepCache.scan = time.Now(), tools, scan
	return tools, scan
}

// prepCapable says whether the capability travels for THIS pairing.
//
// Two conditions, both required, and the caps one is not optional politeness:
// on an anchored box a member pairing without the dcn family will be refused
// at the op, so advertising to it would be a control that fails after the user
// has already chosen it — the reason mirror.go:63-67 gives for gating its own
// advertisement. Withheld means the probe is skipped entirely, matching how
// the inference lanes behave at agents.go:351-358.
func prepCapable(self string) ([]prepToolReport, prepScanReport, bool) {
	if capsAllow(self, prepGateOp) != "" {
		return nil, prepScanReport{}, false
	}
	tools, scan := scanPrepTools()
	return tools, scan, len(tools) > 0
}
