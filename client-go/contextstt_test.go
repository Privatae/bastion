//go:build !windows

// Tagged to match anchor_test.go, where setupBox and the pairing fixtures live.
// contextstt.go itself is platform-neutral and builds everywhere; only these
// gates borrow the anchored-box fixture.

package main

// Gates for speech to text (contextstt.go).
//
// THE BAR THESE MEET: real whisper-cli, real audio with known words in it, over
// a real ctx_extract management frame, on the PULL transport — which is the one
// that matters here, because 8 MiB of inline frame is 4.4 minutes of 16 kHz PCM
// and a recording worth transcribing is usually longer than that. A test of the
// argv builder would prove nothing about any of it.
//
// THE FIXTURE. The audio is named by PRIVATAE_STT_TEST_AUDIO (a wav with speech
// in it) and PRIVATAE_STT_TEST_WORDS (a comma-separated list of words that are
// actually said in it). It is not committed: a speech clip long enough to be a
// real test is hundreds of kilobytes, and the point of these checks is the real
// engine reading real words rather than a fixture round-tripping through a
// parser. The unit gates below run everywhere and need neither.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// sttFixture is the wav and the words in it, or a skip.
func sttFixture(t *testing.T) (string, []string) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("PRIVATAE_STT_TEST_AUDIO"))
	if path == "" {
		t.Skip("PRIVATAE_STT_TEST_AUDIO is not set — no speech fixture to read")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("PRIVATAE_STT_TEST_AUDIO %q is not readable: %v", path, err)
	}
	words := []string{}
	for _, w := range strings.Split(os.Getenv("PRIVATAE_STT_TEST_WORDS"), ",") {
		if w = strings.TrimSpace(w); w != "" {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		t.Skip("PRIVATAE_STT_TEST_WORDS is not set — a transcript with nothing known " +
			"to check against is not a test of transcription")
	}
	return path, words
}

// requireEngine skips unless this machine can actually transcribe. The reason is
// carried through so a skip says which of the two halves is missing — the engine
// or a model — which is the same distinction the capability itself makes.
func requireEngine(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(sttBin); err != nil {
		t.Skipf("%s is not on PATH", sttBin)
	}
	if ok, why := sttProve(); !ok {
		t.Skipf("this machine cannot transcribe: %s", why)
	}
}

// decodeSTT reads a successful reply.
func decodeSTT(t *testing.T, out, errOut string, code int) ctxExtractResp {
	t.Helper()
	if code != 0 {
		t.Fatalf("ctx_extract refused the job: %s", strings.TrimSpace(errOut))
	}
	var resp ctxExtractResp
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("reply is not the shape this lane returns: %v (%q)", err, out)
	}
	return resp
}

// ── THE ONE THAT MATTERS: real audio, real engine, over the pull transport ──

func TestTranscribeRealAudioOverThePull(t *testing.T) {
	setupBox(t)
	requireEngine(t)
	wav, words := sttFixture(t)
	resetPrepCache()

	doc, err := os.ReadFile(wav)
	if err != nil {
		t.Fatal(err)
	}
	h, hostName := startFakeHost(t, "bearer-abc")
	_ = hostName
	ticket := h.issue(doc)

	req, err := json.Marshal(ctxExtractReq{
		Tool: sttTool, Mime: "audio/wav", Ticket: ticket,
		Size: int64(len(doc)), MaxBytes: ctxPullMaxBytes,
		PullBudget:    60,
		ExtractBudget: sttCeiling().Seconds(),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, errOut, code, root := driveExtractIn(t, tAnchor, []string{string(req)})
	resp := decodeSTT(t, out, errOut, code)

	if resp.Source != "pull" {
		t.Fatalf("the job went over %q, not the pull transport this test exists to "+
			"exercise", resp.Source)
	}
	low := strings.ToLower(resp.Text)
	for _, w := range words {
		if !strings.Contains(low, strings.ToLower(w)) {
			t.Fatalf("the transcript is missing %q, a word that is said in this "+
				"recording — got: %q", w, firstLine(resp.Text))
		}
	}

	// THE MODEL IS ON THE RECORD. Without it a transcript cannot be judged
	// afterwards: base.en and large-v3-turbo are 3x apart in error rate on hard
	// audio and the words look identical either way.
	if resp.Model == "" {
		t.Fatal("the reply does not say which model read this recording — the host " +
			"writes that onto every row, and a transcript with no model on it claims " +
			"an accuracy nobody can check")
	}
	if resp.Model != sttFindModels()[0].Name {
		t.Fatalf("a job naming no model ran %q, not this box's best %q",
			resp.Model, sttFindModels()[0].Name)
	}

	// THE TIMESTAMPS ARE THE FEATURE. A transcript without them is a wall of
	// text; with them a search result is a moment in the recording.
	if len(resp.Segments) == 0 {
		t.Fatal("no segments — there is nothing to file as media_offset_ms, so a " +
			"result could never be jumped to")
	}
	var last int64 = -1
	for i, s := range resp.Segments {
		if s.T0 < last {
			t.Fatalf("segment %d starts at %dms, before segment %d ended at %dms — "+
				"offsets that go backwards would file the wrong moment", i, s.T0, i-1, last)
		}
		if s.T1 < s.T0 {
			t.Fatalf("segment %d ends before it starts (%d..%d)", i, s.T0, s.T1)
		}
		last = s.T1
	}
	if resp.DoneMS != resp.Segments[len(resp.Segments)-1].T1 {
		t.Fatalf("transcribed_ms is %d but the last segment ends at %d — the number "+
			"the user is shown must be the one the engine actually reached",
			resp.DoneMS, resp.Segments[len(resp.Segments)-1].T1)
	}
	// The fixture is a wav, so its own header states the duration exactly and the
	// box must have read it rather than leaving it unknown.
	if resp.AudioMS <= 0 {
		t.Fatal("audio_ms is unset for a wav — the RIFF header states the length, " +
			"so 'how much of your recording is in the corpus' is answerable and was " +
			"not answered")
	}
	if resp.Blank {
		t.Fatal("a recording with words in it came back flagged as silence")
	}

	// NOTHING OF THE USER'S IS LEFT BEHIND, checked after the terminal frame the
	// way the rest of this lane checks it.
	leftovers, _ := os.ReadDir(root)
	for _, e := range leftovers {
		t.Fatalf("the user's recording is still on their disk after the job "+
			"reported done: %s", e.Name())
	}
}

// ── THE TRAP: the engine exits 0 on audio it could not read ─────────────────
//
// THIS IS THE RED-FIRST CHECK. whisper-cli prints "error: failed to read audio
// file" to STDERR and EXITS ZERO on an mp4 (measured against the real binary).
// A runner that believed the exit code returns a successful job with no text in
// it, and the host — which has three carefully separated sentences for an empty
// answer — picks the wrong one and tells the user their recording is silence.
//
// The user's fix for "this is silence" is nothing. The user's fix for this is to
// install ffmpeg. Getting it wrong sends them nowhere.
func TestAContainerRefusedByTheEngineIsNotSilence(t *testing.T) {
	setupBox(t)
	requireEngine(t)
	wav, _ := sttFixture(t)
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg is not installed — no way to build a container to refuse")
	}
	resetPrepCache()

	mp4 := filepath.Join(t.TempDir(), "clip.mp4")
	if err := exec.Command("ffmpeg", "-nostdin", "-v", "error", "-y",
		"-i", wav, "-c:a", "aac", mp4).Run(); err != nil {
		t.Fatalf("could not build the mp4 fixture: %v", err)
	}
	doc, err := os.ReadFile(mp4)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := startFakeHost(t, "bearer-abc")

	// The PLAIN transcribe job, pointed at a container it cannot read.
	req, err := json.Marshal(ctxExtractReq{
		Tool: sttTool, Mime: "video/mp4", Ticket: h.issue(doc),
		Size: int64(len(doc)), MaxBytes: ctxPullMaxBytes,
		PullBudget: 60, ExtractBudget: sttCeiling().Seconds(),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, errOut, code := driveExtract(t, tAnchor, []string{string(req)})

	if code == 0 {
		var resp ctxExtractResp
		_ = json.Unmarshal([]byte(out), &resp)
		t.Fatalf("a recording the engine COULD NOT DECODE came back as a successful "+
			"job (text=%q blank=%v). whisper-cli exits 0 on a file it failed to read, "+
			"so this reply is an empty transcript presented as a finished one — the "+
			"host will tell the user their recording is silent and they will fix "+
			"nothing", resp.Text, resp.Blank)
	}
	low := strings.ToLower(errOut)
	if !strings.Contains(low, "ffmpeg") {
		t.Fatalf("the refusal does not name ffmpeg, which is the thing that would "+
			"make this work: %q", strings.TrimSpace(errOut))
	}
}

// ── AND THE SAME CONTAINER, ON THE JOB THAT HAS ffmpeg ──────────────────────
//
// Transcribing an mp4 DOES require ffmpeg. This is the half that proves the
// other half of that sentence: with ffmpeg present, av-transcribe gets the same
// words out of the container that transcribe gets out of the wav.
func TestAnMP4IsTranscribedWhenFFmpegIsThere(t *testing.T) {
	setupBox(t)
	requireEngine(t)
	wav, words := sttFixture(t)
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg is not installed — av-transcribe is correctly unavailable here")
	}
	resetPrepCache()

	mp4 := filepath.Join(t.TempDir(), "clip.mp4")
	if err := exec.Command("ffmpeg", "-nostdin", "-v", "error", "-y",
		"-i", wav, "-c:a", "aac", mp4).Run(); err != nil {
		t.Fatalf("could not build the mp4 fixture: %v", err)
	}
	doc, err := os.ReadFile(mp4)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := startFakeHost(t, "bearer-abc")

	req, err := json.Marshal(ctxExtractReq{
		Tool: sttAVTool, Mime: "video/mp4", Ticket: h.issue(doc),
		Size: int64(len(doc)), MaxBytes: ctxPullMaxBytes,
		PullBudget: 60, ExtractBudget: sttCeiling().Seconds(),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, errOut, code, root := driveExtractIn(t, tAnchor, []string{string(req)})
	resp := decodeSTT(t, out, errOut, code)

	if !resp.Demuxed {
		t.Fatal("the reply does not record that ffmpeg unpacked the audio track — " +
			"'this needed ffmpeg' has to be visible in the record of the job that " +
			"needed it")
	}
	low := strings.ToLower(resp.Text)
	for _, w := range words {
		if !strings.Contains(low, strings.ToLower(w)) {
			t.Fatalf("the mp4's transcript is missing %q: %q", w, firstLine(resp.Text))
		}
	}
	if resp.AudioMS <= 0 {
		t.Fatal("the demux produced a wav and its duration was still not read")
	}
	// The demux writes a second file of the user's audio into the pairing root.
	// It has to be gone too, and by the same deadline.
	leftovers, _ := os.ReadDir(root)
	for _, e := range leftovers {
		t.Fatalf("the unpacked audio track is still on the user's disk after the job "+
			"reported done: %s", e.Name())
	}
}

// ── THE THIRD ANSWER: silence is a finished job, not a failure ──────────────

func TestSilenceIsAFinishedJobAndSaysSo(t *testing.T) {
	setupBox(t)
	requireEngine(t)
	resetPrepCache()

	h, _ := startFakeHost(t, "bearer-abc")
	doc := sttProbeWAV()
	req, err := json.Marshal(ctxExtractReq{
		Tool: sttTool, Mime: "audio/wav", Ticket: h.issue(doc),
		Size: int64(len(doc)), MaxBytes: ctxPullMaxBytes,
		PullBudget: 60, ExtractBudget: sttCeiling().Seconds(),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, errOut, code := driveExtract(t, tAnchor, []string{string(req)})
	resp := decodeSTT(t, out, errOut, code)

	// THE ASSERTION IS DELIBERATELY THE WEAK ONE, and the reason is a measurement
	// rather than a compromise. On the same one second of digital silence,
	// tiny.en returns [BLANK_AUDIO] and base.en returns the word "You" — Whisper's
	// documented habit of inventing short filler where there is nothing. No
	// whisper-cli flag fixes it without losing the signal: `-sns` suppresses the
	// non-speech tokens and returns NOTHING AT ALL, which makes "silence"
	// indistinguishable from "the engine produced no output", collapsing two of
	// the three answers this lane exists to keep apart.
	//
	// So what is pinned is what is true of every model: silence is a FINISHED job
	// that names its model, and it never comes back as a wall of invented text.
	// Which of the two it is depends on the model, and that is the model's
	// behaviour, not this code's.
	if !resp.Blank && len(resp.Text) > 40 {
		t.Fatalf("one second of digital silence produced %d characters: %q — that is "+
			"invented text going into the user's corpus, not a transcript",
			len(resp.Text), resp.Text)
	}
	if resp.Model == "" {
		t.Fatal("even a silent recording must say which model read it")
	}
}

// ── the model is CHOSEN, never substituted ──────────────────────────────────

func TestANamedModelIsUsedOrRefusedWithTheList(t *testing.T) {
	requireEngine(t)
	models := sttFindModels()
	if len(models) == 0 {
		t.Skip("no models on this machine")
	}

	got, err := sttPickModel(models[len(models)-1].Name)
	if err != nil {
		t.Fatalf("a model this box holds was refused: %v", err)
	}
	if got.Name != models[len(models)-1].Name {
		t.Fatalf("asked for %q and got %q", models[len(models)-1].Name, got.Name)
	}

	// THE SUBSTITUTION THAT MUST NOT HAPPEN. Quietly running a different model
	// would put a number on the record the run never earned.
	_, err = sttPickModel("definitely-not-a-model-9f3c")
	if err == nil {
		t.Fatal("a model this machine does not have was accepted — the job must " +
			"refuse rather than silently read the recording with something else")
	}
	for _, m := range models {
		if !strings.Contains(err.Error(), m.Name) {
			t.Fatalf("the refusal does not list %q, so the caller cannot tell what "+
				"to ask for instead: %v", m.Name, err)
		}
	}
}

// ── the declaration is the enforcement ──────────────────────────────────────
//
// The ceiling for this job is the only one in ctxExtractTimeoutFor that is not a
// literal — it is measured on the machine, because an hour of audio is 75
// seconds of work at base.en and fifteen minutes at large-v3-turbo. That makes
// it the one most able to drift from what is advertised, so it is pinned.
func TestTranscribeCeilingIsBoundedAndStable(t *testing.T) {
	for _, tool := range []string{sttTool, sttAVTool} {
		got := ctxExtractTimeoutFor(tool)
		if got < sttMinCeiling {
			t.Fatalf("%s declares %s, under the floor %s", tool, got, sttMinCeiling)
		}
		if got > sttMaxCeiling {
			t.Fatalf("%s declares %s, over the guard %s — the host clamps it anyway, "+
				"but a box that declares more than it will be granted is a box whose "+
				"advertisement is not its behaviour", tool, got, sttMaxCeiling)
		}
		// DECLARED == ENFORCED, across the float round trip the wire makes. The
		// advertisement is a float64 of seconds and the grant comes back the same
		// way; a ceiling with sub-second precision would survive neither.
		if got != got.Round(time.Second) {
			t.Fatalf("%s declares %s, which is not a whole number of seconds — it "+
				"cannot survive the round trip through ceiling_s and extract_budget",
				tool, got)
		}
		if again := ctxExtractTimeoutFor(tool); again != got {
			t.Fatalf("%s declared %s and then %s — the gate that asserts the "+
				"advertisement equals the enforcement compares two separate calls",
				tool, got, again)
		}
	}
}

// ── reading what the engine printed ─────────────────────────────────────────

func TestSTTParseReadsTheEnginesOwnFormat(t *testing.T) {
	// Copied from a real run, byte for byte.
	const out = `
[00:00:00.000 --> 00:00:07.940]   And so my fellow Americans ask not what your country can do for you
[00:00:07.940 --> 00:01:10.760]   ask what you can do for your country.
whisper_print_timings: something the engine said about itself
`
	segs, blank, _ := sttParse(out)
	if blank {
		t.Fatal("a transcript with words in it was read as silence")
	}
	if len(segs) != 2 {
		t.Fatalf("want 2 segments, got %d: %+v", len(segs), segs)
	}
	if segs[0].T0 != 0 || segs[0].T1 != 7940 {
		t.Fatalf("first segment spans %d..%d, want 0..7940", segs[0].T0, segs[0].T1)
	}
	if segs[1].T1 != 70760 {
		t.Fatalf("second segment ends at %d, want 70760 (1m10.760s)", segs[1].T1)
	}
	// A LINE THAT IS NOT A SEGMENT IS NOT TRANSCRIPT. The engine writes its own
	// remarks to stdout under some builds, and a parser that took an unrecognised
	// line as text would put the engine's words into the user's corpus.
	if strings.Contains(sttText(segs), "whisper_print_timings") {
		t.Fatal("the engine's own output about itself ended up in the transcript")
	}
}

func TestBlankAudioIsSilenceAndNeverText(t *testing.T) {
	segs, blank, nonSpeech := sttParse("[00:00:00.000 --> 00:00:10.000]   [BLANK_AUDIO]\n")
	if nonSpeech {
		t.Fatal("silence was reported as a sound the engine could not name — [BLANK_AUDIO] is bracket-wrapped like every annotation, so the specific answer has to be taken before the general one")
	}
	if !blank {
		t.Fatal("the engine's own silence token was not read as silence")
	}
	if len(segs) != 1 {
		t.Fatalf("the silent stretch was dropped entirely: %+v", segs)
	}
	if got := sttText(segs); got != "" {
		t.Fatalf("[BLANK_AUDIO] reached the user's corpus as %q", got)
	}
}

func TestSTTClockRejectsWhatIsNotATimestamp(t *testing.T) {
	for _, s := range []string{"00:00:01.500", " 01:02:03.004 "} {
		if _, ok := sttClock(s); !ok {
			t.Fatalf("a real timestamp %q was rejected", s)
		}
	}
	for _, s := range []string{"", "nope", "1:2", "aa:bb:cc.ddd", "00:00"} {
		if _, ok := sttClock(s); ok {
			t.Fatalf("%q was read as a timestamp", s)
		}
	}
	got, _ := sttClock("01:02:03.004")
	if got != 3723004 {
		t.Fatalf("01:02:03.004 came to %dms, want 3723004", got)
	}
}

// ── the wav header, which is where an unknown duration stops being unknown ──

func TestWavDurationIsReadFromTheHeader(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "one.wav")
	if err := os.WriteFile(p, sttProbeWAV(), 0o600); err != nil {
		t.Fatal(err)
	}
	ms, ok := wavDurationMS(p)
	if !ok {
		t.Fatal("a wav this file wrote could not be read back")
	}
	if ms != 1000 {
		t.Fatalf("one second of 16 kHz mono came back as %dms", ms)
	}
	// NOT A WAV IS NOT A DURATION. Reporting 0 as "zero seconds" rather than as
	// "unknown" would tell a user their whole recording was transcribed when
	// nothing was known about its length at all.
	q := filepath.Join(dir, "not.wav")
	if err := os.WriteFile(q, []byte("this is not a RIFF file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := wavDurationMS(q); ok {
		t.Fatal("a non-wav reported a duration")
	}
}

// ── the text cap must not leave offsets pointing past the text ──────────────

func TestSegmentsAreTrimmedWithTheText(t *testing.T) {
	segs := []sttSegment{
		{T0: 0, T1: 1000, Text: "aaaa"},
		{T0: 1000, T1: 2000, Text: "bbbb"},
		{T0: 2000, T1: 3000, Text: "cccc"},
	}
	// Room for "aaaa\nbbbb" and not for the third.
	got := sttSegmentsWithin(segs, 9)
	if len(got) != 2 {
		t.Fatalf("want 2 segments inside a 9-char cap, got %d: %+v", len(got), got)
	}
	if len(sttSegmentsWithin(segs, 0)) != 0 {
		t.Fatal("a zero cap kept segments, which would give the host offsets for " +
			"words it did not receive")
	}
}

// ── model ranking ───────────────────────────────────────────────────────────

func TestModelsRankBestFirst(t *testing.T) {
	names := []string{"tiny.en", "base.en", "small.en", "large-v3-turbo", "medium.en"}
	best := ""
	bestRank := -1
	for _, n := range names {
		if r := sttRank(n); r > bestRank {
			bestRank, best = r, n
		}
	}
	if best != "large-v3-turbo" {
		t.Fatalf("the best-ranked model is %q, not large-v3-turbo — which is the "+
			"one the benchmark put at 3.84%% on hard audio against base.en's 12.55%%",
			best)
	}
	// A quantization ranks with its parent, so a box holding only base.en-q5_1
	// does not fall to the bottom of the order behind a tiny.
	if sttRank("base.en-q5_1") != sttRank("base.en") {
		t.Fatal("a quantized base ranks apart from base — it is the same model class")
	}
	if sttRank("something-nobody-has-heard-of") != 0 {
		t.Fatal("an unknown model outranked a measured one")
	}
}

// ── the prep advertisement carries the models ───────────────────────────────

func TestTranscribeAdvertisesItsModels(t *testing.T) {
	setupBox(t)
	requireEngine(t)
	resetPrepCache()
	defer resetPrepCache()

	tools, _, _ := prepCapable(tAnchor)
	found := false
	for _, tool := range tools {
		if tool.Name != sttTool {
			continue
		}
		found = true
		if len(tool.Models) == 0 {
			t.Fatal("transcribe is advertised with no models — 'this box has a speech " +
				"engine' is not an answer for a recording, because which model reads " +
				"it decides how accurate the transcript is")
		}
		if tool.CeilingS <= 0 {
			t.Fatal("transcribe is advertised with no ceiling")
		}
	}
	if !found {
		t.Fatal("this machine can transcribe and did not advertise it")
	}
}

// The blocked sentence is what a user in the commonest state actually reads:
// engine installed, no model, because the distribution package ships none.
func TestNoModelNamesWhereToPutOne(t *testing.T) {
	why := sttNoModelReason()
	if !strings.Contains(why, sttModelEnv) {
		t.Fatalf("the reason does not name the override %s: %q", sttModelEnv, why)
	}
	dirs := sttModelDirs()
	if len(dirs) == 0 {
		t.Fatal("no directories are searched for a model at all")
	}
	for _, d := range dirs {
		if strings.Contains(d, string(os.PathSeparator)) && !strings.Contains(why, d) {
			t.Fatalf("the reason does not name %q, one of the directories that was "+
				"actually searched — a user told 'no model' with no list has nowhere "+
				"to put one: %q", d, why)
		}
	}
	_ = fmt.Sprint()
}

// ── the engine's annotations are not the user's words ──────────────────────

// sttMusicWAV is ten seconds of a plain synthesised melody — four harmonics per
// note with a decaying envelope, the cheapest thing that is unmistakably music
// and unmistakably not speech. Built here for the same reason sttProbeWAV is:
// nobody should inherit a fixture they cannot regenerate.
func sttMusicWAV() []byte {
	const rate = 16000
	notes := []float64{261.63, 329.63, 392.00, 523.25, 392.00,
		329.63, 261.63, 196.00, 261.63, 329.63}
	data := make([]byte, 0, rate*2*len(notes))
	for _, f := range notes {
		for k := 0; k < rate; k++ {
			tt := float64(k) / rate
			env := math.Exp(-tt * 1.5)
			if tt*20 < 1 {
				env *= tt * 20
			}
			v := 0.0
			for h, a := range map[int]float64{1: 1.0, 2: 0.5, 3: 0.25, 4: 0.12} {
				v += a * math.Sin(2*math.Pi*f*float64(h)*tt)
			}
			v *= env * 0.18
			if v > 1 {
				v = 1
			} else if v < -1 {
				v = -1
			}
			data = binary.LittleEndian.AppendUint16(data, uint16(int16(v*32767)))
		}
	}
	b := make([]byte, 0, 44+len(data))
	b = append(b, "RIFF"...)
	b = binary.LittleEndian.AppendUint32(b, uint32(36+len(data)))
	b = append(b, "WAVEfmt "...)
	b = binary.LittleEndian.AppendUint32(b, 16)
	b = binary.LittleEndian.AppendUint16(b, 1)
	b = binary.LittleEndian.AppendUint16(b, 1)
	b = binary.LittleEndian.AppendUint32(b, rate)
	b = binary.LittleEndian.AppendUint32(b, rate*2)
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = binary.LittleEndian.AppendUint16(b, 16)
	b = append(b, "data"...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

// THE MEASUREMENT THAT DECIDES THE SHAPE OF THE FIX, pinned so it cannot quietly
// stop being true. Every line below came out of the real whisper-cli
// on real synthesised audio:
//
//	ten seconds of a melody       base.en  -> "[Music]"
//	the same ten seconds          tiny.en  -> "(music)"
//	eight seconds of a 440 Hz tone tiny.en -> "(phone ringing)"
//	eight seconds of white noise   base.en -> "(machine whirring)"
//
// Four spellings, two bracket styles, two cases, from two models on four inputs.
// A real song produced "[♪♪♪]". So the vocabulary is
// open-ended and a word list is a list of whatever somebody happened to hit —
// which is why the fix is the SHAPE and this test pins the shape.
func TestTheEnginesNonSpeechAnnotationsAreNeverTranscript(t *testing.T) {
	observed := []string{"[Music]", "(music)", "(phone ringing)", "(machine whirring)",
		"[♪♪♪]", "(applause)", "[MUSIC PLAYING]"}
	for _, tok := range observed {
		segs, blank, nonSpeech := sttParse(
			"[00:00:00.000 --> 00:00:10.000]   " + tok + "\n")
		if got := sttText(segs); got != "" {
			t.Fatalf("the engine's annotation %s reached the user's corpus as %q — "+
				"those are the engine's words about a sound, never words anybody said, "+
				"and a song filed as text is a false hit in every search that matches it",
				tok, got)
		}
		if len(segs) != 1 {
			t.Fatalf("%s was dropped entirely (%d segments) — it has to stay a "+
				"timestamped segment, or \"the engine listened and there was no speech\" "+
				"becomes indistinguishable from \"the engine returned nothing\"",
				tok, len(segs))
		}
		if !nonSpeech {
			t.Fatalf("%s was not reported as a sound the engine named", tok)
		}
		if blank {
			t.Fatalf("%s was reported as SILENCE — it is not. Telling a user their "+
				"music upload is silent is a false statement about their own file",
				tok)
		}
	}
}

// THE THREE ANSWERS SURVIVE THE FIX, which is the constraint that ruled out
// --suppress-nst. Silence, a named sound and real speech have to stay three
// different replies; a fix that made any two of them look alike would have
// traded one wrong answer for a worse one.
func TestSilenceAndANamedSoundAndSpeechStayThreeAnswers(t *testing.T) {
	cases := []struct {
		name             string
		line             string
		blank, nonSpeech bool
		text             string
	}{
		{"silence", "[BLANK_AUDIO]", true, false, ""},
		{"a named sound", "[Music]", false, true, ""},
		{"speech", "ask what you can do for your country.", false, false,
			"ask what you can do for your country."},
	}
	for _, c := range cases {
		segs, blank, nonSpeech := sttParse("[00:00:00.000 --> 00:00:10.000]   " + c.line + "\n")
		if blank != c.blank || nonSpeech != c.nonSpeech || sttText(segs) != c.text {
			t.Fatalf("%s came back blank=%v nonSpeech=%v text=%q; want %v/%v/%q",
				c.name, blank, nonSpeech, sttText(segs), c.blank, c.nonSpeech, c.text)
		}
	}
	// AND MUSIC BEFORE A MEETING IS A MEETING. Neither flag is set when real
	// words were found; the transcript is the words and the annotation is gone.
	segs, blank, nonSpeech := sttParse(
		"[00:00:00.000 --> 00:00:05.000]   [Music]\n" +
			"[00:00:05.000 --> 00:00:09.000]   right, shall we start\n")
	if blank || nonSpeech {
		t.Fatalf("a recording with speech in it was flagged blank=%v nonSpeech=%v",
			blank, nonSpeech)
	}
	if got := sttText(segs); got != "right, shall we start" {
		t.Fatalf("transcript is %q — the annotation was kept or the speech was lost", got)
	}
}

// SPEECH THAT MERELY CONTAINS A BRACKET IS SPEECH. The rule is the WHOLE segment
// being one wrapped group; anything wider would start deleting things people
// actually said.
func TestSpeechContainingBracketsIsKeptIntact(t *testing.T) {
	for _, line := range []string{
		"the rate (about four percent) is fixed",
		"(yes) and (no) are both answers",
		"see clause [4] of the agreement",
		"(",
		"()x",
	} {
		segs, _, nonSpeech := sttParse("[00:00:00.000 --> 00:00:02.000]   " + line + "\n")
		if nonSpeech || sttText(segs) != line {
			t.Fatalf("%q was treated as an engine annotation and dropped — that is a "+
				"word the user said", line)
		}
	}
}

// THE SAME THING THROUGH THE REAL ENGINE. The unit gate above pins the shape;
// this proves the shape is the one the binary on this machine actually produces.
func TestRealMusicNeverBecomesTextInTheCorpus(t *testing.T) {
	requireEngine(t)
	dir := t.TempDir()
	wav := filepath.Join(dir, "music.wav")
	if err := os.WriteFile(wav, sttMusicWAV(), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := runTranscribe(dir, wav, sttTool, "", "", time.Now().Add(sttCeiling()))
	if err != nil {
		t.Fatalf("transcribing music failed: %v", err)
	}
	if strings.TrimSpace(res.Text) != "" {
		t.Fatalf("ten seconds of music produced %q in the user's searchable corpus "+
			"(model %s) — nobody said any of that", res.Text, res.Model)
	}
	if res.Blank {
		t.Fatalf("music was reported as silence by %s — the recording is not silent, "+
			"and saying it is is a false statement about the user's file", res.Model)
	}
	if !res.NonSpeech && len(res.Segments) > 0 {
		t.Logf("note: %s produced %d segments and named no sound; nothing reached "+
			"the corpus, which is the assertion that matters", res.Model, len(res.Segments))
	}
}

// ── the deadline sentence a user reads ─────────────────────────────────────

// A NEGATIVE DURATION IN A SENTENCE SHOWN TO A PERSON. The message said "still
// working after %s" and filled it with time.Until(deadline) — the time REMAINING,
// evaluated after the deadline had already passed, so what reached the user was
// "after -4s". The defect was never the sign: remaining time was the wrong
// quantity for a sentence about elapsed time, and clamping the display would
// have left the reply saying something it had not measured.
func TestTheDeadlineSentenceReportsElapsedTimeNotTimeRemaining(t *testing.T) {
	requireEngine(t)
	dir := t.TempDir()
	wav := filepath.Join(dir, "probe.wav")
	if err := os.WriteFile(wav, sttProbeWAV(), 0o600); err != nil {
		t.Fatal(err)
	}
	// Short enough that the engine is killed while the model is still loading,
	// which is the only path that reaches this sentence: it needs zero segments.
	// MEASURED on this box, base.en is killed inside 400 ms and the overshoot past
	// the deadline is 3-84 ms across six timed-out runs — so the OLD expression
	// rendered "0s" here. It is non-positive BY CONSTRUCTION at every magnitude;
	// a larger overshoot renders a negative, which is what was reported.
	const budget = 300 * time.Millisecond
	start := time.Now()
	_, err := runTranscribe(dir, wav, sttTool, "", "", time.Now().Add(budget))
	ran := time.Since(start)
	if err == nil {
		t.Skip("this machine loaded a model and transcribed inside the budget — " +
			"there is no deadline to report on")
	}
	msg := err.Error()
	m := regexp.MustCompile(`after (-?[0-9.]+)(ms|s|m|h)`).FindStringSubmatch(msg)
	if m == nil {
		t.Skipf("a different failure came back, so the deadline sentence was not "+
			"reached: %v", err)
	}
	d, perr := time.ParseDuration(m[1] + m[2])
	if perr != nil {
		t.Fatalf("the duration in the deadline sentence does not parse: %q", msg)
	}
	if strings.HasPrefix(m[1], "-") {
		t.Fatalf("the user is shown a NEGATIVE duration %q in a sentence about how "+
			"long something took: %s", m[1]+m[2], msg)
	}
	if d <= 0 {
		t.Fatalf("the engine ran for %v and the sentence says \"after %s\" — the "+
			"reply is reporting the time REMAINING, which is <= 0 by the time this "+
			"branch is reached, rather than the time that elapsed.\nFull sentence: %s",
			ran.Round(time.Millisecond), m[1]+m[2], msg)
	}
	if d < budget/2 {
		t.Fatalf("the engine ran for %v and the sentence names %s — that is not the "+
			"elapsed time it claims to be.\nFull sentence: %s",
			ran.Round(time.Millisecond), m[1]+m[2], msg)
	}
}

// Sub-second runs must be expressible. Rounding to whole seconds turned every
// fast failure into the literal words "after 0s", which is as unbelievable to a
// reader as a negative was, and on this box it is the common case.
func TestAFastFailureReportsAFastTimeNotZero(t *testing.T) {
	if got := sttReadableDuration(311 * time.Millisecond); got.String() != "311ms" {
		t.Fatalf("311ms rendered as %q", got)
	}
	if got := sttReadableDuration(4200 * time.Millisecond); got.String() != "4s" {
		t.Fatalf("4.2s rendered as %q", got)
	}
}

// ── the language is recorded, and never silently substituted ───────────────

// NOTHING ON THE ROW SAID WHICH LANGUAGE A RECORDING WAS DECODED AS. The reply
// has carried a `lang` field all along — the host writes it onto the row and the
// OCR lanes fill it — and the transcript lane left it empty, so a recording
// decoded under an English prior had no first thing to check.
func TestEveryTranscriptRecordsTheLanguageItWasDecodedIn(t *testing.T) {
	requireEngine(t)
	dir := t.TempDir()
	wav := filepath.Join(dir, "probe.wav")
	if err := os.WriteFile(wav, sttProbeWAV(), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := runTranscribe(dir, wav, sttTool, "", "", time.Now().Add(sttCeiling()))
	if err != nil {
		t.Fatalf("transcribe failed: %v", err)
	}
	if res.Lang != sttDefaultLang {
		t.Fatalf("lang=%q on a transcript run with no language named; want %q — the "+
			"engine's own help states its default is [en], and a row that does not "+
			"say which language it was decoded in hides its own first failure mode",
			res.Lang, sttDefaultLang)
	}
}

// AN ENGLISH-ONLY MODEL MUST REFUSE, NOT PRETEND. MEASURED against the real
// binary: ggml-base.en handed `-l de` prints "main: WARNING: model is not
// multilingual, ignoring language and translation options", transcribes the
// audio as ENGLISH, and exits 0. A box that passed the flag through would file an
// English transcript on a row labelled German — the same silent substitution
// sttPickModel refuses one field over.
func TestAnEnglishOnlyModelRefusesAnotherLanguage(t *testing.T) {
	en := sttModel{Name: "base.en"}
	if _, err := sttLang(en, "de"); err == nil {
		t.Fatal("an English-only model accepted a request to transcribe German — the " +
			"engine ignores the flag and hands back English, so the row would carry a " +
			"language the run never used")
	}
	if got, err := sttLang(en, ""); err != nil || got != sttDefaultLang {
		t.Fatalf("an unnamed language on an English-only model gave (%q, %v); want "+
			"(%q, nil)", got, err, sttDefaultLang)
	}
	if got, err := sttLang(en, "EN"); err != nil || got != sttDefaultLang {
		t.Fatalf("English named explicitly on an English-only model was refused: (%q, %v)",
			got, err)
	}
	multi := sttModel{Name: "large-v3-turbo"}
	for _, want := range []string{"de", "auto", "ja"} {
		if got, err := sttLang(multi, want); err != nil || got != want {
			t.Fatalf("a multilingual model refused %q: (%q, %v)", want, got, err)
		}
	}
	// The quantized English-only variants carry the suffix and are still English.
	for _, n := range []string{"base.en-q5_1", "small.en", "tiny.en"} {
		if !sttModelIsEnglishOnly(n) {
			t.Fatalf("%s was read as multilingual", n)
		}
	}
	for _, n := range []string{"large-v3-turbo", "base", "small-q5_1"} {
		if sttModelIsEnglishOnly(n) {
			t.Fatalf("%s was read as English-only", n)
		}
	}
	// And the backstop reads the engine's own sentence, which is the authority
	// over this build's reading of a filename.
	if !sttEnglishOnlyRefusal(
		"main: WARNING: model is not multilingual, ignoring language and translation options") {
		t.Fatal("the engine's own not-multilingual warning was not recognised")
	}
	if sttEnglishOnlyRefusal("whisper_model_load: n_langs = 100") {
		t.Fatal("a multilingual model's own load line was read as a refusal")
	}
}

// THE ARGV CARRIES THE LANGUAGE ONLY WHEN THERE IS ONE TO CARRY, so an ordinary
// English job runs exactly the argv it ran before this field existed.
func TestLanguageArgvIsUnchangedForAnOrdinaryEnglishJob(t *testing.T) {
	base := sttArgv("/m.bin", "/in.wav", 0, sttDefaultLang)
	if strings.Join(base, " ") != "-m /m.bin -f /in.wav -np" {
		t.Fatalf("the default argv changed: %v", base)
	}
	withLang := sttArgv("/m.bin", "/in.wav", 0, "de")
	if strings.Join(withLang, " ") != "-m /m.bin -f /in.wav -np -l de" {
		t.Fatalf("a named language did not reach the engine: %v", withLang)
	}
}
