//go:build !windows

// Tagged to match anchor_test.go and contextprep_test.go, which is where
// setupBox and driveExtractIn live. Without this the WINDOWS test build fails
// on `undefined: setupBox` — verified with GOOS=windows go vet. The lane itself
// (contextframes.go) is platform-neutral and builds everywhere; only these
// gates borrow the anchored-box fixture.

package main

// Acceptance for the video lane.
//
// THE BAR, and it is deliberately not an argv check: a real clip is built here
// with real ffmpeg, with scene cuts at times this file chooses, and the job has
// to hand back frames AT THOSE TIMES that are visibly different pictures from
// each other. An argv assertion would have passed every version of this file
// that got the timestamp mapping wrong.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// ffmpegOrSkip keeps this suite honest on a box with no decoder: the lane's
// whole premise is that the tool is the USER'S, so a build machine without one
// is normal and must not fail the build. It must also not silently pass — the
// skip says which binary was missing.
func ffmpegOrSkip(t *testing.T) prepTool {
	t.Helper()
	tool := prepTool{}
	for _, x := range prepToolTable {
		if x.Name == ctxFramesTool {
			tool = x
		}
	}
	if tool.Bin == "" {
		t.Fatal("prepToolTable no longer advertises " + ctxFramesTool)
	}
	if ok, _ := probePrepTool(tool); !ok {
		t.Skip("ffmpeg/ffprobe not installed here — the decoder is the user's, " +
			"so this is a normal build machine; run this suite where ffmpeg is")
	}
	return tool
}

// buildSceneClip writes a clip of `n` scenes, `secs` each, with TEXTURED
// sources so x264's scenecut actually fires.
//
// WHY TEXTURED AND NOT COLOURS, measured while writing this: x264's scenecut is
// a rate decision, not a pixel diff. A cut between two flat colour fields is
// cheap to inter-predict, so the encoder spends no IDR on it and the cut gets
// no keyframe — a clip of solid colours "proves" keyframes miss scene changes
// and is measuring its own synthetic input. With smptebars/testsrc2/mandelbrot/
// rgbtestsrc the keyframes land on the cuts to the millisecond.
func buildSceneClip(t *testing.T, dir string, n, secs int) string {
	t.Helper()
	sources := []string{"smptebars", "testsrc2", "mandelbrot", "rgbtestsrc",
		"testsrc", "smptehdbars"}
	if n > len(sources) {
		n = len(sources)
	}
	args := []string{"-v", "error", "-y"}
	fc := ""
	for i := 0; i < n; i++ {
		args = append(args, "-f", "lavfi", "-t", fmt.Sprint(secs),
			"-i", fmt.Sprintf("%s=s=640x360:r=30", sources[i]))
		fc += fmt.Sprintf("[%d:v]format=yuv420p[s%d];", i, i)
	}
	for i := 0; i < n; i++ {
		fc += fmt.Sprintf("[s%d]", i)
	}
	fc += fmt.Sprintf("concat=n=%d:v=1:a=0[v]", n)
	out := filepath.Join(dir, "scenes.mp4")
	args = append(args, "-filter_complex", fc, "-map", "[v]",
		"-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p", out)
	cmd := exec.Command("ffmpeg", args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not build the test clip: %v\n%s", err, b)
	}
	return out
}

// meanRGB is a frame's average colour, which is enough to tell "this is a
// different scene" from "this is the same scene twice" without pulling in an
// image-comparison dependency.
func meanRGB(t *testing.T, b64 string) [3]float64 {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("frame is not base64: %v", err)
	}
	if len(raw) < 4 || raw[0] != 0xFF || raw[1] != 0xD8 {
		t.Fatalf("frame does not start with a JPEG SOI marker (% x)", raw[:4])
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("frame does not decode as an image: %v", err)
	}
	bnds := img.Bounds()
	if bnds.Dx() != ctxFramesWidth {
		t.Fatalf("frame is %d px wide, expected the %d the lane downscales to",
			bnds.Dx(), ctxFramesWidth)
	}
	var s [3]float64
	var n float64
	for y := bnds.Min.Y; y < bnds.Max.Y; y += 4 {
		for x := bnds.Min.X; x < bnds.Max.X; x += 4 {
			r, g, b, _ := img.At(x, y).RGBA()
			s[0] += float64(r >> 8)
			s[1] += float64(g >> 8)
			s[2] += float64(b >> 8)
			n++
		}
	}
	for i := range s {
		s[i] /= n
	}
	return s
}

// TestFramesLandOnTheCutsWePutIn is the acceptance test.
func TestFramesLandOnTheCutsWePutIn(t *testing.T) {
	tool := ffmpegOrSkip(t)
	dir := t.TempDir()
	clip := buildSceneClip(t, dir, 4, 6) // cuts at 0, 6, 12, 18 s

	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	frames, rep, err := runFrameJob(tool, clip, work, ctxExtractTimeoutFor(ctxFramesTool))
	if err != nil {
		t.Fatalf("frame job failed: %v", err)
	}

	// 1. THE ENCODER MARKED THE CUTS. This is the premise the whole design
	// rests on — keyframes instead of scene detection — checked on this build
	// rather than taken on trust.
	if rep.Keyframes != 4 {
		t.Fatalf("the container records %d keyframes for a 4-cut clip; the premise "+
			"that the encoder marks each cut does not hold on this build", rep.Keyframes)
	}
	if rep.Stride != 1 || rep.LimitedBy != "" {
		t.Fatalf("a 4-frame clip should hit no wall, got stride=%d limited_by=%q",
			rep.Stride, rep.LimitedBy)
	}
	if rep.Returned != 4 || len(frames) != 4 {
		t.Fatalf("expected 4 frames, got %d (report says %d)", len(frames), rep.Returned)
	}

	// 2. AT THE TIMES THE CUTS WERE PUT AT. One frame time per second of
	// tolerance would pass a build that returned the wrong frames, so this is
	// tight: 100 ms is three frames at 30 fps.
	want := []int64{0, 6000, 12000, 18000}
	for i, f := range frames {
		if d := f.OffsetMs - want[i]; d > 100 || d < -100 {
			t.Fatalf("frame %d came back at %d ms, the cut was put at %d ms",
				i, f.OffsetMs, want[i])
		}
		if f.Source != "keyframe" {
			t.Fatalf("frame %d is %q; a clip this dense needs no top-up", i, f.Source)
		}
		if f.Bytes <= 0 {
			t.Fatalf("frame %d reports %d bytes", i, f.Bytes)
		}
	}

	// 3. AND THEY ARE ACTUALLY DIFFERENT PICTURES. Four frames at four
	// timestamps proves nothing if they are the same image — which is exactly
	// what a wrong seek, or a mis-mapped index, would produce.
	means := make([][3]float64, len(frames))
	for i, f := range frames {
		means[i] = meanRGB(t, f.B64)
	}
	for i := 0; i < len(means); i++ {
		for j := i + 1; j < len(means); j++ {
			d := math.Abs(means[i][0]-means[j][0]) +
				math.Abs(means[i][1]-means[j][1]) +
				math.Abs(means[i][2]-means[j][2])
			if d < 10 {
				t.Fatalf("frames %d and %d are the same picture (mean colour "+
					"distance %.2f) — the offsets may be right and the frames wrong",
					i, j, d)
			}
		}
	}

	// 4. THE CLIP'S LENGTH IS REPORTED, because media_offset_ms is meaningless
	// to a reader who does not know how long the clip is.
	if rep.DurationMs < 23000 || rep.DurationMs > 25000 {
		t.Fatalf("a 24 s clip reported %d ms", rep.DurationMs)
	}
	if rep.Bytes <= 0 || rep.Bytes > ctxFramesMaxBytes {
		t.Fatalf("reported %d bytes", rep.Bytes)
	}

	// 5. NOTHING OF THE USER'S IS LEFT BEHIND once the job has answered. The
	// job owns this directory; the handler removes it before the reply, and the
	// files inside it are pictures out of someone's video.
	ents, _ := os.ReadDir(work)
	if len(ents) == 0 {
		t.Fatal("the work directory is empty before the handler cleans it — " +
			"this test is no longer exercising the extraction it thinks it is")
	}
}

// TestDecimationSpreadsAcrossTheWholeClip drives a clip with far more keyframes
// than the ceiling and checks that what comes back covers the END of the clip,
// not just the beginning. First-N is the failure this rule exists to prevent.
func TestDecimationSpreadsAcrossTheWholeClip(t *testing.T) {
	tool := ffmpegOrSkip(t)
	dir := t.TempDir()
	clip := filepath.Join(dir, "dense.mp4")
	// 300 s at a forced keyframe every second = 300 keyframes, past the 240
	// ceiling. Small and cheap: 320x180, and testsrc so it encodes fast.
	cmd := exec.Command("ffmpeg", "-v", "error", "-y",
		"-f", "lavfi", "-t", "300", "-i", "testsrc2=s=320x180:r=15",
		"-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
		"-force_key_frames", "expr:gte(t,n_forced*1)", clip)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not build the dense clip: %v\n%s", err, b)
	}
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	frames, rep, err := runFrameJob(tool, clip, work, ctxExtractTimeoutFor(ctxFramesTool))
	if err != nil {
		t.Fatalf("frame job failed: %v", err)
	}
	t.Logf("dense clip: %d keyframes -> %d frames, stride %d, %d bytes, %s",
		rep.Keyframes, rep.Returned, rep.Stride, rep.Bytes, time.Since(start))
	if rep.Keyframes < 250 {
		t.Fatalf("wanted a clip past the ceiling, got %d keyframes", rep.Keyframes)
	}
	if rep.Returned > ctxFramesMaxCount {
		t.Fatalf("%d frames came back, past the %d ceiling", rep.Returned, ctxFramesMaxCount)
	}
	if rep.LimitedBy == "" {
		t.Fatal("a clip past the ceiling must say which wall cut it")
	}
	if rep.Stride < 2 {
		t.Fatalf("stride %d on a clip with %d keyframes and a %d ceiling",
			rep.Stride, rep.Keyframes, ctxFramesMaxCount)
	}
	// The last frame must be near the end of the clip. This is the first-N
	// check, and it is the whole point of decimating rather than truncating.
	last := frames[len(frames)-1].OffsetMs
	if last < rep.DurationMs-int64(2*ctxFramesTargetGapS*1000) {
		t.Fatalf("the last frame is at %d ms of a %d ms clip — the tail of the "+
			"timeline was dropped, which is first-N wearing a stride", last, rep.DurationMs)
	}
	if rep.Bytes > ctxFramesMaxBytes {
		t.Fatalf("%d bytes came back, past the %d wall", rep.Bytes, ctxFramesMaxBytes)
	}
}

// TestThinKeyframesAreToppedUp drives a clip whose encoder marked almost
// nothing — a long static screen recording is the real case — and checks the
// lane fills the gaps by seeking rather than indexing one frame a minute.
func TestThinKeyframesAreToppedUp(t *testing.T) {
	tool := ffmpegOrSkip(t)
	dir := t.TempDir()
	clip := filepath.Join(dir, "sparse.mp4")
	// 120 s with one keyframe per 60 s: two keyframes, a 60 s gap, and a target
	// gap of 16 s — so three top-ups belong in the middle stretch.
	cmd := exec.Command("ffmpeg", "-v", "error", "-y",
		"-f", "lavfi", "-t", "120", "-i", "testsrc2=s=320x180:r=15",
		"-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
		"-g", "900", "-x264-params", "scenecut=0:keyint=900:min-keyint=900", clip)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not build the sparse clip: %v\n%s", err, b)
	}
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	frames, rep, err := runFrameJob(tool, clip, work, ctxExtractTimeoutFor(ctxFramesTool))
	if err != nil {
		t.Fatalf("frame job failed: %v", err)
	}
	t.Logf("sparse clip: %d keyframes, %d topped up, %d returned over %d ms",
		rep.Keyframes, rep.ToppedUp, rep.Returned, rep.DurationMs)
	if rep.Keyframes > 4 {
		t.Fatalf("wanted a sparse clip, the encoder marked %d keyframes", rep.Keyframes)
	}
	if rep.ToppedUp == 0 {
		t.Fatal("a clip with a 60 s keyframe gap was not topped up — a static " +
			"screen recording would be indexed at one frame a minute")
	}
	// Every gap in the ANSWER must now be inside the target, which is the thing
	// topping up is for. One target's slack, because the last stretch before
	// the clip ends can be shorter than a full step.
	for i := 1; i < len(frames); i++ {
		if gap := frames[i].OffsetMs - frames[i-1].OffsetMs; gap > int64(2*ctxFramesTargetGapS*1000) {
			t.Fatalf("frames %d and %d are %d ms apart, past twice the %g s target",
				i-1, i, gap, ctxFramesTargetGapS)
		}
	}
	seen := false
	for _, f := range frames {
		if f.Source == "topup" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("the report counted top-ups but no frame is labelled one")
	}
}

// ── the plan, without a decoder ─────────────────────────────────────────────

func TestPlanFramesNeverTakesTheFirstN(t *testing.T) {
	keys := make([]float64, 1000)
	for i := range keys {
		keys[i] = float64(i) * 2 // one keyframe every 2 s, 2000 s of clip
	}
	p := planFrames(keys, 2000)
	if p.Stride != 5 {
		t.Fatalf("stride %d for 1000 keys into %d slots", p.Stride, ctxFramesMaxCount)
	}
	if len(p.KeyIdx) > ctxFramesMaxCount {
		t.Fatalf("%d frames planned, past the %d ceiling", len(p.KeyIdx), ctxFramesMaxCount)
	}
	if p.LimitedBy != "count" {
		t.Fatalf("limited_by %q", p.LimitedBy)
	}
	// THE POINT: the plan reaches the end of the clip.
	if last := keys[p.KeyIdx[len(p.KeyIdx)-1]]; last < 1900 {
		t.Fatalf("the last planned frame is at %.0f s of a 2000 s clip", last)
	}
	if len(p.TopUps) != 0 {
		t.Fatalf("a clip that already filled the ceiling was topped up %d times",
			len(p.TopUps))
	}
}

func TestPlanFramesTopsUpAThinStretch(t *testing.T) {
	// Two keyframes 60 s apart in a 60 s clip.
	p := planFrames([]float64{0, 60}, 60)
	if p.Stride != 1 || len(p.KeyIdx) != 2 {
		t.Fatalf("stride %d keys %v", p.Stride, p.KeyIdx)
	}
	// ceil(60/16)-1 = 3 points inside the gap, evenly: 15, 30, 45.
	if len(p.TopUps) != 3 {
		t.Fatalf("expected 3 top-ups in a 60 s gap at a 16 s target, got %v", p.TopUps)
	}
	for i, want := range []float64{15, 30, 45} {
		if math.Abs(p.TopUps[i]-want) > 0.001 {
			t.Fatalf("top-up %d at %.3f s, expected %.0f s", i, p.TopUps[i], want)
		}
	}
}

func TestPlanFramesLeavesADenseClipAlone(t *testing.T) {
	// One keyframe every 5 s for 10 minutes — the shape measured on real footage.
	keys := make([]float64, 120)
	for i := range keys {
		keys[i] = float64(i) * 5
	}
	p := planFrames(keys, 600)
	if p.Stride != 1 || len(p.KeyIdx) != 120 || len(p.TopUps) != 0 || p.LimitedBy != "" {
		t.Fatalf("the measured clip should pass through untouched: stride=%d kept=%d "+
			"topups=%d limited=%q", p.Stride, len(p.KeyIdx), len(p.TopUps), p.LimitedBy)
	}
}

func TestFitFrameBudgetThinsEvenlyAndKeepsTheTail(t *testing.T) {
	// 240 frames of 100 kB each is 24 MB, three times the wall.
	in := make([]ctxFrame, 240)
	for i := range in {
		in[i] = ctxFrame{OffsetMs: int64(i) * 1000, Bytes: 100 << 10}
	}
	out, dropped := fitFrameBudget(in)
	if !dropped {
		t.Fatal("24 MB of frames fitted an 8 MiB wall")
	}
	sum := 0
	for _, f := range out {
		sum += f.Bytes
	}
	if sum > ctxFramesMaxBytes {
		t.Fatalf("%d bytes survived an %d wall", sum, ctxFramesMaxBytes)
	}
	if out[0].OffsetMs != 0 {
		t.Fatalf("thinning moved the first frame to %d ms", out[0].OffsetMs)
	}
	if last := out[len(out)-1].OffsetMs; last < 200000 {
		t.Fatalf("the surviving frames stop at %d ms of a 239000 ms clip — thinning "+
			"turned the clip into its first half", last)
	}
}

func TestFitFrameBudgetLeavesASmallSetAlone(t *testing.T) {
	in := []ctxFrame{{OffsetMs: 0, Bytes: 1000}, {OffsetMs: 5000, Bytes: 1000}}
	out, dropped := fitFrameBudget(in)
	if dropped || len(out) != 2 {
		t.Fatalf("2 kB of frames was thinned against an %d wall", ctxFramesMaxBytes)
	}
}

func TestFitFrameBudgetOnOneEnormousFrame(t *testing.T) {
	in := make([]ctxFrame, 5)
	for i := range in {
		in[i] = ctxFrame{OffsetMs: int64(i) * 1000, Bytes: ctxFramesMaxBytes * 2}
	}
	out, dropped := fitFrameBudget(in)
	if !dropped || len(out) != 1 {
		t.Fatalf("expected one frame back, got %d (dropped=%v)", len(out), dropped)
	}
	// The MIDDLE of the clip, not its first frame: if only one picture survives
	// it should not be the title card.
	if out[0].OffsetMs != 2000 {
		t.Fatalf("the surviving frame is at %d ms, expected the middle", out[0].OffsetMs)
	}
}

// THE WHOLE FEATURE IN ONE ASSERTION, over the REAL management frame: a real
// clip goes in as a ctx_extract job, real frames come back at the times the
// cuts were put at, and nothing of the user's is left on disk afterwards.
//
// The tests above drive runFrameJob directly, which is where the timestamp
// logic lives. This one drives the op — the caps gate, the transport choice,
// the JSON shape on the wire, the scratch-file lifecycle — because every one of
// those is a way the feature can be broken without the frame logic changing.
func TestCtxExtractReturnsAClipsFramesOverTheRealFrame(t *testing.T) {
	ffmpegOrSkip(t)
	setupBox(t)

	// Small on purpose: the INLINE transport carries the clip base64 in one
	// management frame, capped at ctxExtractMaxBytes. 320x180 keeps a 4-scene
	// clip comfortably inside it, and the scene cuts are what is being tested,
	// not the resolution.
	dir := t.TempDir()
	src := filepath.Join(dir, "clip.mp4")
	cmd := exec.Command("ffmpeg", "-v", "error", "-y",
		"-f", "lavfi", "-t", "4", "-i", "smptebars=s=320x180:r=30",
		"-f", "lavfi", "-t", "4", "-i", "testsrc2=s=320x180:r=30",
		"-f", "lavfi", "-t", "4", "-i", "mandelbrot=s=320x180:r=30",
		"-filter_complex",
		"[0:v]format=yuv420p[a];[1:v]format=yuv420p[b];[2:v]format=yuv420p[c];"+
			"[a][b][c]concat=n=3:v=1:a=0[v]",
		"-map", "[v]", "-c:v", "libx264", "-preset", "veryfast",
		"-pix_fmt", "yuv420p", src)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not build the clip: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > ctxExtractMaxBytes {
		t.Fatalf("the test clip is %d bytes, past the inline cap — this test would "+
			"be measuring the cap rather than the frames", len(raw))
	}
	job, err := json.Marshal(ctxExtractReq{
		Tool: ctxFramesTool, Mime: "video/mp4",
		B64: base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatal(err)
	}

	out, errOut, code, ctxRoot := driveExtractIn(t, tAnchor, []string{string(job)})
	if code != 0 {
		t.Fatalf("ctx_extract failed: code=%d err=%s", code, errOut)
	}
	var resp ctxFramesResp
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("reply is not JSON: %v (%q)", err, out)
	}
	if resp.Tool != ctxFramesTool || resp.Mime != "image/jpeg" || resp.Source != "inline" {
		t.Fatalf("reply metadata is wrong: %+v", resp.Report)
	}
	// THE REPLY CARRIES NO TEXT FIELD AT ALL. A frame reply that decoded as a
	// text reply with an empty body is how the host ends up filing a clip as
	// zero chunks of nothing and calling it a success.
	var asText ctxExtractResp
	_ = json.Unmarshal([]byte(out), &asText)
	if asText.Text != "" {
		t.Fatalf("a clip's reply carries a text field (%q) — the host's text reader "+
			"would accept it", asText.Text)
	}
	if len(resp.Frames) != 3 {
		t.Fatalf("expected 3 frames for a 3-cut clip, got %d (report %+v)",
			len(resp.Frames), resp.Report)
	}
	for i, want := range []int64{0, 4000, 8000} {
		if d := resp.Frames[i].OffsetMs - want; d > 100 || d < -100 {
			t.Fatalf("frame %d came back at %d ms, the cut was put at %d ms",
				i, resp.Frames[i].OffsetMs, want)
		}
	}
	// Different pictures, checked the same way as above.
	a, b, c := meanRGB(t, resp.Frames[0].B64), meanRGB(t, resp.Frames[1].B64),
		meanRGB(t, resp.Frames[2].B64)
	for _, pair := range [][2][3]float64{{a, b}, {b, c}, {a, c}} {
		d := math.Abs(pair[0][0]-pair[1][0]) + math.Abs(pair[0][1]-pair[1][1]) +
			math.Abs(pair[0][2]-pair[1][2])
		if d < 10 {
			t.Fatalf("two of the three frames are the same picture (distance %.2f)", d)
		}
	}

	// NOTHING OF THE USER'S SURVIVES THE CALL. The clip's scratch file AND the
	// directory of decoded frames — which is more of their picture data than any
	// text job leaves behind — must both be gone by the time the host is told
	// the job finished.
	ents, err := os.ReadDir(ctxRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("the context root still holds %v after the reply — the user's clip "+
			"and its decoded frames outlived the job", names)
	}
}

// A CLIP'S CEILING IS NOT A DOCUMENT'S, and it is reached through the one
// mapping every other job uses.
//
// The landed gate (contextocr_test.go) already pins that every advertised job
// declares a ceiling and that the declared number equals the enforced one. This
// pins the thing specific to video: a keyframe pass over an hours-long file is
// not a 20-second job, and the reason the per-tool mechanism exists at all is
// that these two numbers genuinely differ. If they ever collapse, the mechanism
// is carrying no weight here and should be questioned rather than kept.
func TestTheClipCeilingIsNotTheDocumentCeiling(t *testing.T) {
	video := ctxExtractTimeoutFor(ctxFramesTool)
	if video <= ctxExtractTimeout {
		t.Fatalf("video-frames gets %s against the %s text default — a clip's "+
			"keyframe pass needs longer than a text-layer read", video, ctxExtractTimeout)
	}
	// AND THE HOST'S GRANT STILL CLAMPS IT DOWN, never up. A host that has
	// never heard of this job grants nothing and the box uses its own number; a
	// host granting less wins; a host granting more does not.
	if got := ctxExtractBudget(ctxFramesTool, 0); got != video {
		t.Fatalf("a host that granted nothing left the clip with %s, not %s", got, video)
	}
	if got := ctxExtractBudget(ctxFramesTool, 5); got != 5*time.Second {
		t.Fatalf("a host granting 5s left the clip with %s", got)
	}
	if got := ctxExtractBudget(ctxFramesTool, video.Seconds()*10); got != video {
		t.Fatalf("a host granting ten times the ceiling got %s — the clamp only "+
			"goes down", got)
	}
}

// The stale-scratch sweep has to reach the video job's DIRECTORY, not just the
// text job's file. A process killed mid-decode leaves a folder of pictures out
// of someone's video on their own disk, with nothing that would ever notice.
func TestSweepStaleScratchTakesTheFrameDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "extract-1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fdir := filepath.Join(root, "frames-abc")
	if err := os.MkdirAll(fdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fdir, "k_000001.jpg"), []byte("jpeg"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Something that is neither, which must survive.
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := sweepStaleScratch(root); n != 2 {
		t.Fatalf("sweep removed %d entries, expected the document AND the frame "+
			"directory", n)
	}
	if _, err := os.Stat(fdir); !os.IsNotExist(err) {
		t.Fatal("a directory of decoded frames survived the sweep")
	}
	if _, err := os.Stat(filepath.Join(root, "keep.txt")); err != nil {
		t.Fatal("the sweep removed something that was not its scratch")
	}
}
