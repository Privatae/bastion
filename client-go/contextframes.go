package main

// contextframes.go — a clip becomes FRAMES, on the user's own machine.
//
// This finishes the video half the picture lane left open. Everything else in the
// extraction lane turns bytes into TEXT; this one does not, and that difference
// is the whole design problem. contextextract.go's reply carries a `text`
// field, the host chunks it and files it as ordinary context rows, and the text
// embedding lane picks them up. None of that works for a picture.
//
// So the reply grew a SECOND shape — `frames`, each one a downscaled jpeg and
// the millisecond offset it was taken at — and the host files those into the
// MEDIA lane (its media_parent_id / media_offset_ms columns), never the
// text one. Extracted text counts as text, frames count as media, and neither
// borrows the other's denominator.
//
// ── WHY KEYFRAMES, AND NOT SCENE DETECTION ──────────────────────────────────
//
// MEASURED on a 10-minute 1080p30 clip (18,000 frames), ffmpeg 9.0:
// scene detection cost 96.6 CPU-s and found 49 frames; taking the keyframes
// cost 2.1 CPU-s and found 120. On one core that is 115.5 s against 2.2 s.
// Scene detection costs 45x the CPU AND finds FEWER frames, because x264
// already ran scene detection when the video was encoded and marked each cut as
// a keyframe — re-deriving them decodes all 18,000 frames to recompute what the
// container already records. That supersedes the picture lane's original "sample
// at scene cuts" recommendation, which was written before anything was measured.
//
// RE-CONFIRMED HERE on ffmpeg 8.0.1 / libx264 (the version this was built
// against, not the 9.0 of the original measurement) with a four-scene clip cut
// at 0/6/12/18 s: the encoder's keyframes landed at exactly 0.000000, 6.000000,
// 12.000000 and 18.000000. The premise holds on this build.
//
// One caveat that is NOT a contradiction and is worth writing down, because it
// shapes the acceptance test: x264's scenecut is a RATE decision, not a pixel
// diff. A cut between two flat colour fields is cheap to inter-predict, so the
// encoder does not spend an IDR on it and the cut gets no keyframe. Textured
// content cuts do. A test built on solid colours would "prove" keyframes miss
// scene changes and would be measuring the test's own synthetic input.
//
// ── WHAT STOPS A TWO-HOUR FILM FROM ARRIVING WHOLE ──────────────────────────
//
// A clip's keyframe count is the encoder's choice and scales with length: the
// measured 10-minute clip had 120, a feature film has thousands. Two separate
// walls bound it, and which one binds is content-dependent:
//
//   COUNT  — ctxFramesMaxCount, a policy number with production precedent.
//   BYTES  — ctxFramesMaxBytes, the transport, and the same 8 MiB wall the
//            request side already lives behind.
//
// When a clip exceeds either, the frames that survive are spread ACROSS THE
// TIMELINE rather than taken from the front. First-N would index the opening
// titles of every film and nothing else.
//
// ── THE DECODE IS THE USER'S, THE VECTOR IS THE HOST'S ──────────────────────
//
// This hands back frames, never vectors. Vectors would need the bastion to
// hold the media model too, which forks the code the moment someone's decoder
// is at home and their model is at a provider. So the box decodes and the
// host embeds, through the media lane it already has.
//
// Nothing here keeps a frame either. The host stores the VECTOR and the
// TIMESTAMP and drops the bytes — measured at 416 kB against
// 4.97 MB per clip, 12x — because the clip itself is already stored and any
// frame reproduces by seeking to its offset in about 150 ms.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// ctxFramesTool is the job name the host asks for. A job, not a program — the
// same rule the rest of the table follows, so swapping ffmpeg later is not a
// host-visible change.
const ctxFramesTool = "video-frames"

// ctxFramesWidth is the long edge frames are scaled to before they cross the
// wire. 384 px because that is what CLIP-family image encoders consume anyway,
// so a larger frame is bytes the model throws away. Measured: the
// difference is 2.61 MB for 4 full-resolution frames against 265 kB downscaled,
// about 10x.
const ctxFramesWidth = 384

// ctxFramesJpegQ is ffmpeg's -q:v for mjpeg, where 2 is best and 31 worst.
// 3 measured at 6.5 kB per 384 px frame on synthetic test content here and is
// consistent with the 28 kB per frame measured on real footage. The budget below
// is enforced on the ACTUAL bytes, so this number sets typical size and never
// decides whether the reply fits.
const ctxFramesJpegQ = "3"

// ctxFramesMaxCount is the most frames ONE job returns, and it is the number
// this file exists to justify.
//
// PRECEDENT, read from the vendors' own interface documents rather than from
// reputation. Production video indexing does not keep every frame; it keeps one
// embedding per interval, and the interval is a small band:
//
//   - TwelveLabs Marengo Embed 2.7 (AWS Bedrock, "TwelveLabs Marengo Embed 2.7
//     request parameters"): useFixedLengthSec takes 2-10 seconds per clip, and
//     minClipSec defaults to 4 with a range of 1-5. Left alone it segments by
//     shot boundary — the same thing the encoder's keyframes already record.
//   - Google Vertex AI multimodal embeddings: the default videoSegmentConfig is
//     {startOffsetSec: 0, endOffsetSec: 120, intervalSec: 16}, one embedding
//     per 16 seconds, and one request covers at most 120 seconds of video.
//
// So the production band is one frame per 4-16 seconds. 240 frames is 64
// minutes at Vertex's 16 s default and 16 minutes at Marengo's 4 s floor — it
// covers an ordinary upload whole, and a feature film gets the sparse end of
// the same band rather than a refusal.
//
// It is a ceiling on ONE JOB, never on the user: a clip past it is indexed
// across its whole length at lower density, and re-running against a future
// build with a bigger number costs one decode of a file that is still stored.
const ctxFramesMaxCount = 240

// ctxFramesMaxBytes is the transport wall, and it is deliberately the SAME
// number the inline request path uses. A management job is one WebSocket frame
// and uvicorn's 16 MiB ws_max_size is reached at just under 12 MiB of
// plaintext, so 8 MiB of jpeg is ~10.7 MiB of base64 and leaves the JSON
// envelope the room ctxExtractMaxBytes was chosen to leave it.
//
// At the measured 28 kB per 384 px frame, 240 frames is 6.7 MB and the
// COUNT binds first. On unusually detailed footage the bytes bind first. Which
// one bound is reported, so a short reply is never a mystery.
const ctxFramesMaxBytes = ctxExtractMaxBytes

// ctxFramesTargetGapS is how thin is TOO THIN.
//
// Keyframe cadence is the encoder's choice: the measured clip ran one per 5 s,
// but a long static screen recording can go a minute between them and would be
// indexed at one frame a minute. Past this gap the extractor seeks at fixed
// offsets to fill it in — measured at 60 ms per seek on this box and ~150 ms on
// real footage, bounded, nothing like a full decode.
//
// 16 seconds is Vertex AI's default intervalSec, quoted above. Taking a
// production system's DEFAULT rather than its floor is deliberate: every
// topped-up frame costs a seek, and the floor (Marengo's 4 s) would quadruple
// that cost on exactly the content that needs it least.
const ctxFramesTargetGapS = 16.0

// ctxFramesTopUpBudget bounds the seeking, in TIME rather than in a count,
// because the cost of a seek varies with the file and the disk. Whatever fits
// in this is added; the reply says how many were added and whether the budget
// stopped it early.
const ctxFramesTopUpBudget = 30 * time.Second

// ctxFramesTimeout is this job's own ceiling, and it is not ctxExtractTimeout.
// A text extractor reads one document; this decodes a file that can be hours
// long and then seeks through the thin parts of it. 20 s is right for poppler
// and would kill a film before its keyframe pass finished.
//
// IT IS NOT MIRRORED ON THE HOST, and it is reached through exactly one
// mapping: ctxExtractTimeoutFor. That function fills prepToolReport.CeilingS,
// the host reads the number off the advertisement, waits it plus a round trip,
// and grants the same number back as extract_budget — which ctxExtractBudget
// then clamps DOWN to here. A copy of this constant in the host's source would
// be right until the first build that changed it, and then the host would give
// up first and call a working machine unresponsive.
const ctxFramesTimeout = 120 * time.Second

// ctxFramesProbeTimeout bounds the container read that lists the keyframes. It
// decodes nothing, so it is fast even on a long file; this exists so a
// pathological or truncated container cannot hold a worker.
const ctxFramesProbeTimeout = 30 * time.Second

// ctxFrame is one frame as the host receives it: where it came from in the
// clip, and the picture.
type ctxFrame struct {
	// OffsetMs is the frame's position in the clip. It lands in
	// the host's media_offset_ms column, which exists for exactly
	// this, and it is what lets a search hit say "4:32 into the clip" and
	// reproduce the frame by seeking rather than by storing it.
	OffsetMs int64 `json:"offset_ms"`
	// B64 is the jpeg. The host embeds it and drops it.
	B64 string `json:"b64"`
	// Bytes is the jpeg's true length, so the host does not have to decode the
	// base64 to know what it is holding.
	Bytes int `json:"bytes"`
	// Source is "keyframe" or "topup" — whether the encoder marked this moment
	// or the extractor filled a thin stretch. Carried because they are
	// different facts about the clip, and a clip that is mostly top-up is a
	// clip whose encoder barely marked anything.
	Source string `json:"source"`
}

// ctxFramesReport is the honesty half: what the clip HAD against what came
// back, and which wall cut it. Without this a 240-frame reply from a two-hour
// film is indistinguishable from a complete one.
type ctxFramesReport struct {
	DurationMs int64 `json:"duration_ms"`
	// Keyframes is how many the container records — the number before any
	// decimation, top-up or budget.
	Keyframes int `json:"keyframes"`
	// Stride is 1 when every keyframe survived, n when every nth did.
	Stride int `json:"stride"`
	// ToppedUp is how many fixed-offset seeks filled thin stretches.
	ToppedUp int `json:"topped_up"`
	// TopUpCutShort is true when ctxFramesTopUpBudget ran out with gaps left.
	TopUpCutShort bool `json:"topup_cut_short,omitempty"`
	// Returned is how many frames are in the reply.
	Returned int `json:"returned"`
	// Bytes is their combined jpeg size.
	Bytes int `json:"bytes"`
	// LimitedBy is "", "count" or "bytes" — which wall decided Returned. Said
	// out loud so nobody has to infer it from the numbers.
	LimitedBy string `json:"limited_by,omitempty"`
	Width     int    `json:"width"`
}

// ctxFramesResp is the reply. Deliberately NOT ctxExtractResp with a frames
// field bolted on: a reader of either struct should be able to tell what kind
// of answer it is holding without checking whether a string is empty.
type ctxFramesResp struct {
	Tool   string          `json:"tool"`
	Source string          `json:"source,omitempty"`
	Mime   string          `json:"mime"`
	Frames []ctxFrame      `json:"frames"`
	Report ctxFramesReport `json:"report"`
}

// frameTools are the jobs whose answer is FRAMES rather than text. A tool is in
// exactly one runner: extractArgv (text) or here. The drift gate in
// contextprep_test.go checks both directions, so advertising a job with no
// runner — the bug that comment in prepToolTable records — still fails the
// build, and so does a runner nothing advertises.
var frameTools = map[string]bool{ctxFramesTool: true}

// ── the plan ────────────────────────────────────────────────────────────────

// framePlan is what will be extracted, decided BEFORE anything is decoded.
// Deciding first is what bounds the work: the alternative — write every
// keyframe and then throw most away — is unbounded disk on the user's machine
// for a long recording (a six-hour capture at one keyframe a second is 21,600
// files) and the reason the keyframe list is read from the container first.
type framePlan struct {
	Stride    int
	KeyIdx    []int     // indices into the keyframe list that will be written
	TopUps    []float64 // seconds, the thin stretches to seek
	LimitedBy string
}

// planFrames decides which moments of the clip come back.
//
// keys is every keyframe time the container records, in seconds, ascending.
// durS is the clip's duration, used only to know whether the tail after the
// last keyframe is a thin stretch worth filling.
func planFrames(keys []float64, durS float64) framePlan {
	p := framePlan{Stride: 1}
	if len(keys) == 0 {
		return p
	}
	// DECIMATE FIRST, EVENLY. stride = ceil(n / max) keeps every nth keyframe,
	// which spreads the survivors over the whole clip. It is even in KEYFRAME
	// INDEX rather than in wall-clock time — the two are the same to the extent
	// the encoder's cadence is regular, and where it is not, the top-up pass
	// below is what covers the thin stretches. What matters is that it is never
	// first-N: the opening titles are not the film.
	if len(keys) > ctxFramesMaxCount {
		p.Stride = (len(keys) + ctxFramesMaxCount - 1) / ctxFramesMaxCount
		p.LimitedBy = "count"
	}
	for i := 0; i < len(keys); i += p.Stride {
		p.KeyIdx = append(p.KeyIdx, i)
	}
	// TOP UP THE THIN STRETCHES. Only if there is room left under the ceiling —
	// a clip that already filled it is dense by definition and has no thin
	// stretch worth a seek.
	room := ctxFramesMaxCount - len(p.KeyIdx)
	if room <= 0 {
		return p
	}
	// Gaps between consecutive SELECTED frames, plus the head (a clip whose
	// first keyframe is not at zero) and the tail (after the last one).
	bounds := make([]float64, 0, len(p.KeyIdx)+2)
	if keys[p.KeyIdx[0]] > ctxFramesTargetGapS {
		bounds = append(bounds, 0)
	}
	for _, i := range p.KeyIdx {
		bounds = append(bounds, keys[i])
	}
	if durS > bounds[len(bounds)-1] {
		bounds = append(bounds, durS)
	}
	for i := 0; i+1 < len(bounds) && room > 0; i++ {
		gap := bounds[i+1] - bounds[i]
		if gap <= ctxFramesTargetGapS {
			continue
		}
		// n evenly spaced points strictly inside the gap, at about the target
		// spacing. ceil(gap/target)-1 of them, so 40 s at a 16 s target gets
		// two and lands three frames 13.3 s apart.
		n := int(math.Ceil(gap/ctxFramesTargetGapS)) - 1
		if n > room {
			n = room
		}
		step := gap / float64(n+1)
		for j := 1; j <= n; j++ {
			p.TopUps = append(p.TopUps, bounds[i]+step*float64(j))
			room--
		}
	}
	return p
}

// ── reading the container ───────────────────────────────────────────────────

// ffprobeKeyframes lists every keyframe time and the clip's duration, WITHOUT
// decoding a single frame.
//
// It reads packet flags, which the container records, so the cost is a file
// scan and not a decode — the same distinction that makes keyframes 45x cheaper
// than scene detection. -select_streams v:0 keeps it to the video track.
//
// Output is capped: a long file has one line per packet (a two-hour clip is
// ~216,000 of them, a few MB) and this runs on the user's machine.
func ffprobeKeyframes(bin, path string) (keys []float64, durS float64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), ctxFramesProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-v", "error",
		"-select_streams", "v:0",
		"-show_entries", "packet=pts_time,flags",
		"-show_entries", "format=duration",
		"-of", "csv=p=0",
		path)
	hideConsole(cmd) // console_windows.go
	out := &capWriter{max: 32 << 20}
	errb := &capWriter{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, 0, fmt.Errorf("reading this clip's structure took longer than %s "+
			"and was stopped — the file was not rejected, it did not finish in the "+
			"time this lane allows", ctxFramesProbeTimeout)
	}
	if runErr != nil {
		msg := strings.TrimSpace(errb.buf.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return nil, 0, fmt.Errorf("%s could not read this clip%s", bin, ifNonEmpty(msg, ": "+msg))
	}
	if out.hit {
		return nil, 0, fmt.Errorf("this clip's packet index is larger than this lane " +
			"reads in one job — nothing was extracted")
	}
	for _, line := range strings.Split(out.buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, ",")
		// A format=duration row is a single bare number; a packet row is
		// "<pts_time>,<flags>". Telling them apart by field count rather than
		// by position, because ffprobe emits the format section after the
		// packets and an empty pts_time is legal.
		if len(f) == 1 {
			if d, e := strconv.ParseFloat(f[0], 64); e == nil && d > durS {
				durS = d
			}
			continue
		}
		if len(f) < 2 || !strings.Contains(f[1], "K") {
			continue
		}
		t, e := strconv.ParseFloat(f[0], 64)
		if e != nil || t < 0 {
			// A packet with no pts is not a moment anyone can seek back to, so
			// it cannot become a frame offset. Skipped, not guessed at.
			continue
		}
		keys = append(keys, t)
	}
	sort.Float64s(keys)
	if durS <= 0 && len(keys) > 0 {
		durS = keys[len(keys)-1]
	}
	return keys, durS, nil
}

// ── extracting ──────────────────────────────────────────────────────────────

// extractKeyframes writes the planned keyframes as downscaled jpegs into dir
// and returns their paths in clip order.
//
// ONE PASS, with -skip_frame nokey, so ffmpeg decodes only keyframes — this is
// the 2.1 CPU-s path from the measurement. select='not(mod(n,stride))' then
// keeps every nth of THOSE, so the n the filter counts is the keyframe index
// and output i is keys[i*stride].
//
// VERIFIED rather than assumed, on a clip cut at 0/6/12/18 s: the pass wrote
// frames at PTS 0/180/360/540 (frame numbers at 30 fps = 0/6/12/18 s), and with
// stride 2 it wrote 0 and 360 — keys[0] and keys[2]. The acceptance test
// re-checks the mapping against known cut times rather than trusting it here.
func extractKeyframes(bin, in, dir string, stride int, deadline time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	vf := fmt.Sprintf("scale=%d:-2", ctxFramesWidth)
	if stride > 1 {
		vf = fmt.Sprintf("select='not(mod(n\\,%d))',%s", stride, vf)
	}
	cmd := exec.CommandContext(ctx, bin,
		"-v", "error",
		"-skip_frame", "nokey",
		"-i", in,
		"-an", "-sn", "-dn",
		"-fps_mode", "passthrough",
		"-vf", vf,
		"-q:v", ctxFramesJpegQ,
		"-f", "image2",
		filepath.Join(dir, "k_%06d.jpg"))
	hideConsole(cmd) // console_windows.go
	errb := &capWriter{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = &capWriter{max: 8 << 10}, errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("this clip was still decoding after %s and was stopped "+
			"— it was not rejected, it did not finish in the time this lane allows",
			deadline)
	}
	if err != nil {
		msg := strings.TrimSpace(errb.buf.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return nil, fmt.Errorf("%s could not decode this clip%s", bin, ifNonEmpty(msg, ": "+msg))
	}
	// Sorted by name, which the %06d pattern makes clip order.
	paths, err := filepath.Glob(filepath.Join(dir, "k_*.jpg"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// seekFrame writes ONE frame from the middle of a thin stretch.
//
// -ss BEFORE -i is the fast seek: ffmpeg jumps to the preceding keyframe and
// decodes forward, rather than decoding from zero. Measured at ~60 ms here and
// ~150 ms on real footage, which is what makes topping up affordable at all.
func seekFrame(bin, in, out string, atS float64, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-v", "error",
		"-ss", strconv.FormatFloat(atS, 'f', 3, 64),
		"-i", in,
		"-an", "-sn", "-dn",
		"-frames:v", "1",
		"-vf", fmt.Sprintf("scale=%d:-2", ctxFramesWidth),
		"-q:v", ctxFramesJpegQ,
		"-y", out)
	hideConsole(cmd) // console_windows.go
	cmd.Stdout, cmd.Stderr = &capWriter{max: 4 << 10}, &capWriter{max: 8 << 10}
	return cmd.Run()
}

// ── the job ─────────────────────────────────────────────────────────────────

// handleCtxFrames runs the whole video job against a scratch file that is
// already on disk, and REPLIES. It owns `dir` and removes it before the reply
// goes out, for the reason contextextract.go gives: the guarantee this lane
// makes is that the user's bytes are gone by the time the host is told the job
// finished, and a deferred remove does not provide it.
func handleCtxFrames(ws *websocket.Conn, root, scratch string, tool prepTool,
	source string, limit time.Duration) {
	dir, err := os.MkdirTemp(root, "frames-*")
	if err != nil {
		ctxExtractFail(ws, "ctx_extract: cannot open scratch space: "+err.Error())
		return
	}
	frames, report, ferr := runFrameJob(tool, scratch, dir, limit)
	_ = os.RemoveAll(dir)
	_ = os.Remove(scratch)
	if ferr != nil {
		ctxExtractFail(ws, "ctx_extract: "+ferr.Error())
		return
	}
	resp := ctxFramesResp{Tool: ctxFramesTool, Source: source, Mime: "image/jpeg",
		Frames: frames, Report: report}
	b, err := json.Marshal(resp)
	if err != nil {
		ctxExtractFail(ws, "ctx_extract: cannot encode the result: "+err.Error())
		return
	}
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// runFrameJob is handleCtxFrames without the websocket, so the acceptance test
// can drive the real ffmpeg against a real clip and check the timestamps rather
// than checking an argv string.
func runFrameJob(tool prepTool, in, dir string, limit time.Duration) ([]ctxFrame, ctxFramesReport, error) {
	started := time.Now()
	probeBin := ctxFramesProbeBin(tool)
	keys, durS, err := ffprobeKeyframes(probeBin, in)
	if err != nil {
		return nil, ctxFramesReport{}, err
	}
	rep := ctxFramesReport{
		DurationMs: int64(durS * 1000),
		Keyframes:  len(keys),
		Stride:     1,
		Width:      ctxFramesWidth,
	}
	if len(keys) == 0 {
		// An honest empty answer, not an error: a file with no video keyframes
		// is a file this job has nothing to say about, and calling it a failure
		// would send the user to look at their decoder.
		return []ctxFrame{}, rep, nil
	}
	plan := planFrames(keys, durS)
	rep.Stride = plan.Stride
	rep.LimitedBy = plan.LimitedBy

	// THE BUDGET IS THE CALLER'S, not a constant read here. handleCtxExtract
	// resolves it with ctxExtractBudget: this box's own ceiling for the job
	// (ctxExtractTimeoutFor, which is where the number lives) clamped DOWN by
	// whatever the host granted. Reading a constant here instead would be a
	// second enforcement point that could disagree with the advertised one.
	ceiling := limit
	if ceiling <= 0 {
		ceiling = ctxExtractTimeoutFor(ctxFramesTool)
	}
	left := ceiling - time.Since(started)
	if left <= 0 {
		return nil, rep, fmt.Errorf("this clip's structure alone took the whole %s this "+
			"lane allows — nothing was decoded", ceiling)
	}
	paths, err := extractKeyframes(tool.Bin, in, dir, plan.Stride, left)
	if err != nil {
		return nil, rep, err
	}
	// THE MAPPING IS CHECKED, NOT ASSUMED. Output i is keys[i*stride] only if
	// the pass wrote what the plan expected; a mismatch means the filter
	// selected differently than planned and every offset after it would be a
	// confident lie about where in the clip the picture came from.
	if len(paths) != len(plan.KeyIdx) {
		return nil, rep, fmt.Errorf(
			"this clip's keyframe pass wrote %d frames where its packet index said %d "+
				"— the offsets could not be trusted, so nothing was returned",
			len(paths), len(plan.KeyIdx))
	}
	frames := make([]ctxFrame, 0, len(paths)+len(plan.TopUps))
	for i, p := range paths {
		b, rerr := os.ReadFile(p)
		if rerr != nil || len(b) == 0 {
			continue
		}
		frames = append(frames, ctxFrame{
			OffsetMs: int64(keys[plan.KeyIdx[i]] * 1000),
			B64:      base64.StdEncoding.EncodeToString(b),
			Bytes:    len(b),
			Source:   "keyframe",
		})
	}
	// TOP UP, bounded by the clock rather than by a count.
	topDeadline := started.Add(ctxFramesTopUpBudget)
	for _, at := range plan.TopUps {
		if time.Now().After(topDeadline) || time.Since(started) > ceiling {
			rep.TopUpCutShort = true
			break
		}
		out := filepath.Join(dir, fmt.Sprintf("t_%d.jpg", int64(at*1000)))
		if err := seekFrame(tool.Bin, in, out, at, ctxFramesTopUpBudget); err != nil {
			// A seek that fails is a thin stretch that stays thin. It is not a
			// failed job: the keyframes are real and already extracted.
			continue
		}
		b, rerr := os.ReadFile(out)
		if rerr != nil || len(b) == 0 {
			continue
		}
		frames = append(frames, ctxFrame{
			OffsetMs: int64(at * 1000),
			B64:      base64.StdEncoding.EncodeToString(b),
			Bytes:    len(b),
			Source:   "topup",
		})
		rep.ToppedUp++
	}
	sort.Slice(frames, func(a, b int) bool { return frames[a].OffsetMs < frames[b].OffsetMs })

	// THE BYTE WALL, applied last because it is the only one that needs the
	// real sizes. Dropping evenly keeps the timeline covered; dropping the tail
	// would silently turn a film into its first half.
	frames, dropped := fitFrameBudget(frames)
	if dropped {
		rep.LimitedBy = "bytes"
	}
	rep.Returned = len(frames)
	for _, f := range frames {
		rep.Bytes += f.Bytes
	}
	return frames, rep, nil
}

// fitFrameBudget thins an over-budget set EVENLY until it fits.
//
// Keeps every mth frame, raising m until the total is under the wall. Even
// thinning is the same rule the count ceiling follows and for the same reason:
// the first frames of a clip are not a summary of it.
func fitFrameBudget(in []ctxFrame) ([]ctxFrame, bool) {
	total := 0
	for _, f := range in {
		total += f.Bytes
	}
	if total <= ctxFramesMaxBytes || len(in) == 0 {
		return in, false
	}
	for m := 2; m <= len(in); m++ {
		out := make([]ctxFrame, 0, len(in)/m+1)
		sum := 0
		for i := 0; i < len(in); i += m {
			out = append(out, in[i])
			sum += in[i].Bytes
		}
		if sum <= ctxFramesMaxBytes {
			return out, true
		}
	}
	// Every subset of two or more was still too big, which means one frame is
	// past the wall on its own. Return the single middle frame rather than
	// nothing: one picture from the middle of the clip is worth more than a
	// refusal, and the report says the bytes were what cut it.
	return in[len(in)/2 : len(in)/2+1], true
}

// ctxFramesProbeBin is the container reader that goes with this tool's decoder.
// It comes from the tool's own Needs list rather than from a constant here, so
// the binary that is PROBED at heartbeat time is the binary that is RUN — the
// drift the prepToolTable comment records, pointed at the second binary.
func ctxFramesProbeBin(t prepTool) string {
	for _, a := range t.Needs {
		if a.Bin != "" {
			return a.Bin
		}
	}
	return "ffprobe"
}
