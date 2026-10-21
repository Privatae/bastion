package main

// contextstt.go — SPEECH TO TEXT, on the user's own machine.
//
// A clip's audio is more searchable than its frames. Someone hunting "the demo
// where we talked about pricing" wants the transcript, not a keyframe — which is
// why this is the highest-value job in the lane. What comes back is
// TEXT, so it feeds the embedding lane that already works, with timestamps so a
// result can be jumped to.
//
// ── THE ENGINE, and why it is whisper.cpp's whisper-cli ─────────────────────
//
// Chosen by a full CPU-only benchmark of whisper.cpp, faster-whisper,
// openai-whisper and parakeet.cpp against LibriSpeech test-clean and test-other,
// scored with Whisper's own EnglishTextNormalizer plus jiwer (81 runs).
//
// The sentence that decided it is an ARCHITECTURE fit rather than an accuracy
// score: whisper-cli is the only candidate this box's existing detection can
// find at all. prepTool{Bin, Args} is executed through exec.CommandContext,
// which resolves a bare name on PATH (harness.go:590-600). faster-whisper
// installs ZERO console scripts and PEP 668 refuses `pip3 install
// faster-whisper` into the system Python on Ubuntu 26.04, so its only home is a
// venv at a path no PATH probe can discover. `whisper-cli` is the binary name on
// all three channels a user would install from — the Ubuntu 26.04 whisper.cpp
// package, Homebrew's whisper.cpp, and the whisper-bin-x64.zip release asset on
// Windows.
//
// ── MEASURED, AND IT SHAPED EVERY NUMBER BELOW ──────────────────────────────
//
// On this box (AMD EPYC 4345P, 8 physical cores, no GPU), whisper.cpp, 5 minutes
// of real audio, greedy decoding (-bs 1 -bo 1, the setting the rig used so every
// engine was compared at the same beam):
//
//	model                WER clean   WER hard   realtime x8   peak RSS
//	tiny.en                  5.32%     14.85%         38-91x     264 MB
//	base.en                  2.41%     12.55%         48-50x     354 MB
//	small.en                 1.90%     15.11%         15x        750 MB
//	large-v3-turbo           1.90%      3.84%          3.9-4.6x  1857 MB
//
// RSS is effectively FLAT as a recording gets longer — 281 MB at one minute to
// 492 MB at thirty — which is the property that lets this survive a one-hour
// meeting on a laptop.
//
// ── THE KNOWN WEAKNESS, designed around rather than hidden ──────────────────
//
// On hard audio at the small model sizes whisper.cpp's errors are DELETIONS. At
// small.en it returned 740 words against a 781-word reference where
// faster-whisper returned 787. For a search feature a deleted word is not a
// wrong result, it is absent content the user will never find. The models
// converge at large-v3-turbo (3.84% against faster-whisper's 3.71%, one deletion
// each).
//
// So WHICH MODEL RAN MATTERS MORE HERE THAN FOR ANY OTHER JOB IN THIS LANE, and
// two things follow from that, both of them in this file:
//
//  1. The model is part of the ADVERTISEMENT (prepToolReport.Models) and part of
//     the ANSWER (ctxExtractResp.Model). The host writes it onto every row, so
//     the record never claims an accuracy the run did not have.
//  2. Decoding runs at whisper-cli's OWN DEFAULT beam, not the rig's -bs 1. The
//     rig forced greedy so four engines could be compared at one setting,
//     and that setting is where the deletions are
//     worst. MEASURED both ways on the same audio: at the default beam base.en
//     scores 9.60% on test-other against 12.55% greedy, and returns 789 words
//     rather than 784; small.en scores 10.12% against 15.11% and returns 752
//     rather than 740. It costs 2.7x the CPU on base.en (25.4 against 9.4
//     CPU-seconds per audio-minute) and is still 16x realtime on eight cores.
//     The exception is large-v3-turbo, which is BETTER greedy on hard audio
//     (3.84% against 4.87%) — but a box holding large-v3-turbo is not the box
//     whose deletions lose a user's words, so one setting is kept and it is the
//     one that protects the small models.
//
// ── TWO JOBS, BECAUSE ffmpeg IS NOT ALWAYS THERE ────────────────────────────
//
// MEASURED against the real binary: whisper-cli's own help prints "supported
// audio formats: flac, mp3, ogg, wav", and it FAILS on mp4 and m4a. An mp4's
// audio track therefore needs an ffmpeg demux and a wav's does not.
//
// One job with ffmpeg in Needs would refuse a box that has whisper-cli and no
// ffmpeg — a box that can transcribe every voice memo the user owns. One job
// without it would advertise mp4 support on a box that would then fail. So
// there are two, exactly as pdf-text and pdf-ocr are two:
//
//	transcribe      whisper-cli alone. wav, mp3, flac, ogg.
//	av-transcribe   whisper-cli + ffmpeg. Anything in a container: mp4, m4a,
//	                mov, mkv, webm — a video's audio track included.
//
// ffprobe is deliberately NOT required. The only thing this job wants from it is
// the recording's duration, and the demux produces a wav whose own header states
// that exactly — so asking for a second binary would block boxes that have
// everything this job actually uses.
//
// A box with the engine and no ffmpeg reports av-transcribe as BLOCKED, naming
// ffmpeg, through the machinery contextprep.go already has for exactly this.
// So: transcribing an mp4 DOES require the user to have ffmpeg, it is said out
// loud, and it is never assumed.
//
// ── THE ENGINE EXITS 0 ON A FILE IT COULD NOT READ ──────────────────────────
//
// MEASURED, and it is the trap in this whole job: `whisper-cli -f clip.mp4`
// prints "error: failed to read audio file" TO STDERR AND EXITS 0. A runner that
// took the exit code as truth would hand back empty text from a successful job,
// and the host would tell the user their recording is silence. That is precisely
// the quiet-vs-blind failure this lane exists to avoid, so the decode failure is
// detected on the stderr text and reported as what it is. (A missing model file
// does exit non-zero — rc=3 — so only the decode needs this.)
//
// ── AND THE THIRD ANSWER ────────────────────────────────────────────────────
//
// "this box has no engine", "it has one and no model", and "that recording is
// silence" are three different things to tell a user, fixed by three different
// actions. The first is contextprep.go's quiet case. The second is a Prove
// refusal naming the directories that were searched — and it is the NORMAL state
// after installing the engine, because the Ubuntu whisper.cpp package ships no
// model at all (verified by unpacking the .deb: usr/bin/whisper-* and two sample
// wavs, no ggml-*.bin anywhere). The third is this file's Blank flag, which
// comes from the engine's own [BLANK_AUDIO] token.
//
// THE THIRD ONE IS ONLY AS GOOD AS THE MODEL, and that is stated rather than
// glossed. MEASURED on the same one second of digital silence: tiny.en returns
// [BLANK_AUDIO]; base.en returns the word "You". Whisper invents short filler on
// silence, it is a known property of the model rather than of this binary, and
// no whisper-cli flag removes it without costing more than it saves —
// `--suppress-nst` was tried and returns NOTHING AT ALL for silence, which makes
// "that recording is silence" indistinguishable from "the engine produced no
// output" and collapses two of the three answers into one.
//
// The real fix is voice activity detection: whisper.cpp ships a --vad path and a
// Silero VAD model, which would cut the silent stretches before the decoder ever
// sees them. It is a SECOND model download and therefore a second setup step, so
// it is named here as the follow-on rather than half-built. What this build does
// instead is never ASK the engine for audio that is not there — see sttArgv's
// note on -d, which is where the damaging version of this appeared.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ── the job names ───────────────────────────────────────────────────────────

// sttTool transcribes what the engine reads by itself.
const sttTool = "transcribe"

// sttAVTool transcribes an audio track that is inside a container, which means
// ffmpeg first. Named for what it does rather than for the file types it covers,
// because the list of containers ffmpeg opens is ffmpeg's business and not this
// table's.
const sttAVTool = "av-transcribe"

const sttBin = "whisper-cli"

// ── how much of one recording a single job covers ───────────────────────────
//
// ONE HOUR, and the number is a policy choice with precedent behind it rather
// than a limit anyone hit.
//
// The precedent, read off what the transcription services publish as the line
// between "one request, answer now" and "queued job", which is the same line
// this lane draws: OpenAI's audio transcription endpoint caps an upload at 25 MB
// and documents splitting longer recordings; Google Cloud Speech-to-Text caps
// its synchronous recognize at 1 minute and its long-running batch at 480;
// AWS Transcribe's streaming session is 4 hours. Everyone puts the synchronous
// door well below the batch one.
//
// What it costs here, from the measurement: an hour of audio at base.en is about
// 9 CPU-minutes, which is 75 seconds of wall clock on eight cores and about 4
// minutes on one. At large-v3-turbo the same hour is 15 minutes of wall clock on
// eight cores and slower than realtime on one — which is why the job does not
// bound itself by this constant alone. It bounds itself by the clock the host
// actually granted, measures how far it got, and SAYS how much of the recording
// is in the corpus and how much is not. A partial transcript that says it is
// partial beats both a refusal and a silent half-answer; it is the same rule
// pdf-ocr's pages_more follows.
//
// It is a ceiling on what the PLATFORM will ask this machine for in one job,
// never a throttle on the user: nothing the user does on their own machine goes
// through it, and a longer recording is transcribed by running the job again on
// the rest.
const sttAudioCapSeconds = 3600

// sttCapMS is that cap as whisper-cli's own -d flag wants it (milliseconds,
// verified against the real binary's help: "-d N, --duration N duration of audio
// to process in milliseconds").
const sttCapMS = sttAudioCapSeconds * 1000

// ── the ceiling this box DECLARES for the job ───────────────────────────────
//
// It is MEASURED ON THIS MACHINE, not extrapolated from the rig. The benchmark
// was run on an 8-core EPYC with no GPU; a user's laptop is a different machine
// and a published realtime factor from one is not a fact about the other. So the
// probe does the job on a known input, times it, and the ceiling is derived from
// what THIS box actually did.
//
// whisper processes audio in 30-second windows, so the cost of a recording is
// roughly one model load plus one window's work per 30 seconds. The probe's
// input is a one-second wav, which costs exactly load + one window — so
// `sttAudioCapSeconds/30` probe-times is a conservative estimate of the cap's
// worth of audio (it pays the load again for every window). Checked against the
// rig: base.en's 5-minute run took 5.93 s of wall clock on 8 cores, 0.59 s per
// window, so a probe of about 1 s predicts 120 s for an hour where the true cost
// is ~75 s. Over by 1.6x, which is the safe direction for a deadline.
//
// The host clamps whatever is declared to its own ceiling on declared
// ceilings (1800 s) and grants the clamped number back
// as extract_budget, which ctxExtractBudget clamps this box down to. So a slow
// machine holding large-v3-turbo declares more than the host will wait for,
// takes the host's number, and reports an honest partial — rather than working
// past the moment the host gave up.
const sttMinCeiling = 60 * time.Second

// sttMaxCeiling is what this box will declare at most. It matches the host's own
// guard so the two never disagree about a number the box could have chosen not
// to send; a machine slower than this still works, it just returns the first
// part of the recording and says so.
const sttMaxCeiling = 30 * time.Minute

// sttUnprobedCeiling is what ctxExtractTimeoutFor answers before any probe has
// run. It can only be read in that window by a job arriving before the first
// heartbeat, which cannot happen through the advertised path, and the value is
// deliberately the floor rather than the ceiling: under-declaring costs a
// partial transcript, over-declaring parks a worker.
const sttUnprobedCeiling = sttMinCeiling

// sttProbeBudget bounds the probe itself. large-v3-turbo is 1.6 GB and loading
// it off a cold cache is not instant; a box slower than this is a box that
// cannot usefully transcribe anything and is better off reported as blocked.
const sttProbeBudget = 120 * time.Second

// sttDemuxShare is how much of the job's clock the ffmpeg demux may take before
// the transcription has had a chance to start. A demux is IO and a stream copy,
// orders of magnitude cheaper than the decode that follows, so a demux eating
// most of the budget means something is wrong with the file rather than that it
// needs more time.
const sttDemuxShare = 4

// sttMaxSegments bounds the reply's segment list independently of the text cap.
// An hour of speech is roughly 600 segments at whisper's own segmentation; this
// is 20x that, so it binds only on a pathological stream and never on a meeting.
const sttMaxSegments = 12000

// ── finding a model ─────────────────────────────────────────────────────────

// sttModelEnv names extra directories to look in, ahead of everything else.
// It exists because THERE IS NO CANONICAL LOCATION and this file must not
// pretend there is: whisper.cpp's own download-ggml-model.sh writes to the
// directory the script sits in, or to $PWD when that directory is a /bin
// (models/download-ggml-model.sh:27-33), and the Ubuntu package ships no model
// at all. So the box searches the places a person plausibly put one, says which
// places it searched when it finds none, and lets the user name their own.
const sttModelEnv = "PRIVATAE_WHISPER_MODELS"

// sttModelDirs is where a ggml model is looked for, in order.
//
// The first entry is this bastion's own directory, which is the answer for a
// user who has no opinion: it is per-user and already created 0700. It is NOT
// where the model-swap lane puts things — modelswap.go manages OLLAMA models
// through ollama's own API and never touches a file path, so the two do not
// share a directory and nothing here reads its ledger. The rest are the
// conventional shares.
func sttModelDirs() []string {
	dirs := []string{}
	for _, d := range filepath.SplitList(os.Getenv(sttModelEnv)) {
		if strings.TrimSpace(d) != "" {
			dirs = append(dirs, d)
		}
	}
	if cfg, err := configDirPath(); err == nil {
		dirs = append(dirs, filepath.Join(cfg, "whisper-models"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".local", "share", "whisper.cpp", "models"),
			filepath.Join(home, ".cache", "whisper.cpp"),
			filepath.Join(home, "whisper.cpp", "models"))
	}
	if runtime.GOOS != "windows" {
		dirs = append(dirs,
			"/usr/local/share/whisper.cpp/models",
			"/usr/share/whisper.cpp/models",
			"/opt/homebrew/share/whisper.cpp/models")
	}
	return dirs
}

// sttModel is one model file this box can load.
type sttModel struct {
	// Name is the model as everyone writes it — "base.en", "large-v3-turbo" —
	// which is the ggml filename with its prefix and suffix removed. It is what
	// the host advertises, what a host may ASK for by name, and what the reply
	// records as having run.
	Name  string
	Path  string
	Bytes int64
}

// sttRank orders models best-first when the host names none.
//
// BY SIZE CLASS, read off the name, and the ordering source is stated because it
// is not what this rig measured. On test-other whisper.cpp put base.en AHEAD of
// small.en at both beams (9.60% against 10.12% at the default beam, 12.55%
// against 15.11% greedy), which inverts the conventional order. That result is
// one five-minute sample and it is not enough to build an unusual default on, so
// the conventional order stands, the measurement is written down here, and the
// host can name a model when it wants a different one.
//
// A quantized variant ranks with its parent: "base.en-q5_1" is a base.en.
func sttRank(name string) int {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "large"):
		return 5
	case strings.HasPrefix(n, "medium"):
		return 4
	case strings.HasPrefix(n, "small"):
		return 3
	case strings.HasPrefix(n, "base"):
		return 2
	case strings.HasPrefix(n, "tiny"):
		return 1
	}
	// Something this build has not heard of. It is not ranked above a model that
	// was measured; it is ranked at the bottom and is still usable by name.
	return 0
}

// sttFindModels lists every ggml model on this machine, best-first.
//
// Only files named ggml-*.bin are considered, which is whisper.cpp's own naming
// and what its downloader writes. A non-whisper .bin in the same directory —
// a parakeet or a llama — would not load, and the probe would then advertise a
// model that fails on the first real job.
func sttFindModels() []sttModel {
	seen := map[string]bool{}
	out := []sttModel{}
	for _, dir := range sttModelDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasPrefix(name, "ggml-") || !strings.HasSuffix(name, ".bin") {
				continue
			}
			model := strings.TrimSuffix(strings.TrimPrefix(name, "ggml-"), ".bin")
			// A model this build cannot name is a model the host cannot ask for.
			if model == "" || seen[model] {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			// whisper.cpp's own test fixtures live beside real models in a source
			// checkout and are not models. They are excluded by name rather than
			// by size, because a legitimate tiny quantization is also small.
			if strings.HasPrefix(model, "for-tests-") {
				continue
			}
			seen[model] = true
			out = append(out, sttModel{Name: model, Path: filepath.Join(dir, name),
				Bytes: info.Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := sttRank(out[i].Name), sttRank(out[j].Name)
		if ri != rj {
			return ri > rj
		}
		// Within a class the larger file is the less quantized one.
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// sttPickModel resolves what the host asked for, or the best this box has.
//
// A host naming a model this machine does not hold is REFUSED with the list,
// never quietly served a different one: the whole point of carrying the model
// through the advertisement and the reply is that nobody has to guess which one
// read their recording.
func sttPickModel(want string) (sttModel, error) {
	models := sttFindModels()
	if len(models) == 0 {
		return sttModel{}, fmt.Errorf("%s", sttNoModelReason())
	}
	want = strings.TrimSpace(want)
	if want == "" {
		return models[0], nil
	}
	for _, m := range models {
		if strings.EqualFold(m.Name, want) {
			return m, nil
		}
	}
	names := make([]string, 0, len(models))
	for _, m := range models {
		names = append(names, m.Name)
	}
	return sttModel{}, fmt.Errorf(
		"this machine has no speech model called %q — it has %s. The model that reads "+
			"a recording decides how accurate the transcript is, so this job does not "+
			"quietly substitute a different one", want, strings.Join(names, ", "))
}

// sttNoModelReason is the ENGINE-IS-HERE-AND-HAS-NO-MODEL sentence, and it names
// the directories that were actually searched.
//
// This is the normal state after installing the engine, not an edge case:
// verified by unpacking the Ubuntu 26.04 whisper.cpp package, which ships
// usr/bin/whisper-cli and two sample wavs and no model file of any kind. A user
// in this state who was told "no machine of yours can transcribe" would go and
// install software that is already on their disk.
func sttNoModelReason() string {
	dirs := sttModelDirs()
	return sttBin + " is installed on this machine and there is no speech model for it " +
		"to load — the engine and the model are separate downloads and the package " +
		"ships no model. Put a ggml model (e.g. ggml-base.en.bin, 148 MB, from " +
		"whisper.cpp's models/download-ggml-model.sh) in one of: " +
		strings.Join(dirs, ", ") + " — or set " + sttModelEnv + " to the directory " +
		"holding the ones you already have"
}

// ── the probe: it LOADS a model and transcribes, it does not ask a version ──

// sttProbe is what the last successful probe learned, kept for the process
// lifetime and keyed by the model file's identity.
//
// It is NOT cleared with prepCache. prepCache expires every 10 minutes so that
// installing a tool shows up without a restart, and re-loading a 1.6 GB model
// six times an hour to re-learn a number that cannot have changed is a cost paid
// on the USER'S machine for nothing. Keyed by path+size+modtime, so replacing a
// model file does force a fresh measurement.
type sttProbeResult struct {
	key    string
	window time.Duration
}

var (
	sttProbeMu   sync.Mutex
	sttProbeSeen sttProbeResult
)

func sttModelKey(m sttModel) string {
	st, err := os.Stat(m.Path)
	if err != nil {
		return m.Path
	}
	return fmt.Sprintf("%s|%d|%d", m.Path, st.Size(), st.ModTime().UnixNano())
}

// sttProve is the LAST word on whether this box can transcribe, and it proves it
// by transcribing.
//
// What it proves: the engine runs, a model file on this machine actually LOADS
// (a truncated 1.6 GB download is a real failure mode and exits non-zero), the
// audio path decodes, and the output is in the timestamped form this file parses
// — proved by round-tripping the engine's own [BLANK_AUDIO] token through the
// parser. What it does NOT prove is that the model transcribes WORDS correctly;
// there is no way to synthesise speech here to check that, and claiming
// otherwise in a probe would be the kind of proxy this lane keeps getting
// burned by. It is stated rather than glossed.
//
// It also TIMES the run, which is where the declared ceiling comes from.
func sttProve() (bool, string) {
	model, err := sttPickModel("")
	if err != nil {
		return false, err.Error()
	}
	key := sttModelKey(model)
	sttProbeMu.Lock()
	cached := sttProbeSeen.key == key && sttProbeSeen.window > 0
	sttProbeMu.Unlock()
	if cached {
		return true, ""
	}

	dir, err := os.MkdirTemp("", "sttprobe-")
	if err != nil {
		return false, sttBin + " is installed but there was no scratch space to prove it " +
			"works: " + err.Error()
	}
	defer os.RemoveAll(dir)
	wav := filepath.Join(dir, "probe.wav")
	if err := os.WriteFile(wav, sttProbeWAV(), 0o600); err != nil {
		return false, sttBin + " is installed but the probe audio could not be written: " +
			err.Error()
	}

	start := time.Now()
	out, errOut, rc, err := sttRun(sttProbeBudget, sttArgv(model.Path, wav, 0, sttDefaultLang)...)
	took := time.Since(start)
	if err != nil || rc != 0 {
		return false, fmt.Sprintf("%s is installed and could not load the model %s — "+
			"%s. A model file that will not load is usually an interrupted download; "+
			"fetch it again", sttBin, model.Name, sttFirstProblem(errOut, out, err))
	}
	// THE EXIT CODE IS NOT THE ANSWER HERE. whisper-cli exits 0 on audio it could
	// not read (measured, see this file's header), so the probe has to look.
	if why := sttDecodeFailure(errOut); why != "" {
		return false, fmt.Sprintf("%s loaded %s and could not read a one-second test "+
			"recording — %s", sttBin, model.Name, why)
	}
	segs, _, _ := sttParse(out)
	if len(segs) == 0 {
		return false, fmt.Sprintf("%s loaded %s and returned nothing in the timestamped "+
			"form this lane reads — the engine on this machine is not producing "+
			"transcripts this build can parse", sttBin, model.Name)
	}

	sttProbeMu.Lock()
	sttProbeSeen = sttProbeResult{key: key, window: took}
	sttProbeMu.Unlock()
	return true, ""
}

// sttModelsReport is what the heartbeat carries: every model this box holds,
// best-first, so the host can name one and a user can see which ones are there.
func sttModelsReport() []string {
	models := sttFindModels()
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.Name)
	}
	return out
}

// sttCeiling is the seconds this box declares for a transcription job, derived
// from what the probe measured on THIS machine. See sttMinCeiling's note for the
// derivation and the check against the rig.
func sttCeiling() time.Duration {
	sttProbeMu.Lock()
	window := sttProbeSeen.window
	sttProbeMu.Unlock()
	if window <= 0 {
		return sttUnprobedCeiling
	}
	d := time.Duration(sttAudioCapSeconds/30) * window
	if d < sttMinCeiling {
		return sttMinCeiling
	}
	if d > sttMaxCeiling {
		return sttMaxCeiling
	}
	// Rounded to whole seconds so the number this box DECLARES and the number the
	// host GRANTS back survive the float round trip exactly — the gate that
	// asserts declared == enforced compares them for equality.
	return d.Round(time.Second)
}

// ── running it ──────────────────────────────────────────────────────────────

// sttArgv is how whisper-cli is asked for a timestamped transcript on stdout.
//
// Every flag verified against the real binary's own help and a real run, not
// copied from documentation:
//
//	-m <model>   the model file. Not optional: the built-in default is a
//	             relative path (models/ggml-base.en.bin) that resolves against
//	             the working directory and would silently pick up a stranger's
//	             file in a source checkout.
//	-f <in>      the input. whisper-cli also takes bare positional files; -f is
//	             used so an input whose name begins with a dash is an input.
//	-np          suppress the engine's own progress chatter. It does NOT
//	             suppress the read_audio_data lines, which go to stderr and are
//	             where the decode failure is found.
//	-d <ms>      how much of the recording to process. PASSED ONLY WHEN THE
//	             RECORDING IS KNOWN TO BE LONGER THAN THE CAP, and this is not a
//	             tidiness point — MEASURED, `-d` is a duration whisper-cli
//	             processes whether or not the file HAS it. jfk.wav is eleven
//	             seconds and takes 0.36 s to transcribe; the same file with
//	             `-d 3600000` was still running at 30 s, inventing "You" and
//	             "(silence)" over the padding it had made up. So a cap applied
//	             blind turns every short recording into an hour of work on the
//	             user's own machine and fills their corpus with words nobody
//	             said. A recording whose length this box could not read is
//	             bounded by the CLOCK instead, which cannot overrun, and reports
//	             an honest partial.
//
// There is deliberately NO -bs/-bo: whisper-cli's own defaults are kept, for the
// reason measured in this file's header. And no -t: the thread count is the
// engine's default of 4 rather than this machine's core count, because this runs
// on the user's own laptop while they are using it and taking every core for a
// background job is not this lane's call to make.
//
// Timestamps are the DEFAULT output and -nt would remove them. They are the
// point: media_offset_ms is what turns a transcript into a moment a user can
// jump to.
//
//	-l <lang>    the spoken language. Passed only when the host named one and
//	             the model can honour it — see sttLang, which is where the whole
//	             language decision lives.
func sttArgv(model, in string, capMS int, lang string) []string {
	args := []string{"-m", model, "-f", in, "-np"}
	if capMS > 0 {
		args = append(args, "-d", strconv.Itoa(capMS))
	}
	if lang != "" && lang != sttDefaultLang {
		args = append(args, "-l", lang)
	}
	return args
}

// ── THE LANGUAGE, and why the box records one at all ────────────────────────
//
// Until this, nothing recorded it. A recording was transcribed under an English
// prior and the row said nothing about that, so a German voice memo that came
// back as English-shaped nonsense had no first thing to check. The reply already
// carries a `lang` field — the host writes it onto the row as ocr_lang and the
// OCR lane fills it (contextextract.go) — and the transcript lane simply left it
// empty. Filling it is the whole of the minimum fix and it costs nothing.
//
// WHAT THE DEFAULT IS, from the binary's own help rather than from a guess:
// `-l LANG, --language LANG [en] spoken language ('auto' for auto-detect)`. So
// when no -l is passed the engine decodes as English. That is what this build
// has always done and it is what it keeps doing — because the only thing that
// could justify changing it is a measurement, and the benchmark behind this file
// covered the English-only models plus large-v3-turbo ON ENGLISH AUDIO. Nobody
// has measured the multilingual models on non-English speech, and switching
// every multilingual box to `auto` on that basis would be choosing new behaviour
// from an unmeasured proxy.
//
// SO THE HOST NAMES IT, exactly the way the host names a model. Same shape, same
// file, same promise: the box does what it was asked or refuses and says why, and
// it never quietly does something else. `auto` is a language a host may name.
const sttDefaultLang = "en"

// sttModelIsEnglishOnly reports whether a model can only ever decode English.
//
// whisper.cpp's own naming: ggml-base.en.bin is the English-only base, ggml-base
// .bin is the multilingual one, and a quantization keeps the suffix in place
// ("base.en-q5_1"). This is a NAME and a name is a proxy, so it is used only to
// refuse EARLY and cheaply — the authority is the engine's own sentence, which
// sttEnglishOnlyRefusal checks on stderr after the fact. Both, because the cheap
// one saves a wasted job and the real one cannot be fooled.
func sttModelIsEnglishOnly(name string) bool {
	n := strings.ToLower(name)
	return n == "en" || strings.HasSuffix(n, ".en") ||
		strings.Contains(n, ".en-") || strings.Contains(n, ".en.")
}

// sttLang resolves the language this job will run in, or refuses.
//
// THE REFUSAL IS THE LOAD-BEARING HALF. MEASURED against the real binary: an
// English-only model handed `-l de` prints "main: WARNING: model is not
// multilingual, ignoring language and translation options" to stderr, transcribes
// the audio as English, and EXITS 0. A box that passed the flag and reported
// success would put an English transcript on a row stamped German — the same
// silent-substitution failure sttPickModel exists to prevent, one field over. So
// a language request an English-only model cannot honour is refused before
// anything runs.
func sttLang(model sttModel, want string) (string, error) {
	want = strings.TrimSpace(strings.ToLower(want))
	if want == "" {
		return sttDefaultLang, nil
	}
	if sttModelIsEnglishOnly(model.Name) && want != sttDefaultLang {
		return "", fmt.Errorf(
			"this machine's speech model %s reads English only, so it cannot "+
				"transcribe %s — the engine would ignore the request and hand back an "+
				"English transcript with a %s label on it. A multilingual model (one "+
				"whose name has no .en in it, e.g. large-v3-turbo) is what reads "+
				"another language", model.Name, want, want)
	}
	return want, nil
}

// sttEnglishOnlyRefusal is the BACKSTOP for the above: the engine's own sentence,
// taken as the authority over this build's reading of a filename. It fires only
// when a language was actually asked for, so a normal English job never sees it.
func sttEnglishOnlyRefusal(stderr string) bool {
	return strings.Contains(strings.ToLower(stderr), "model is not multilingual")
}

// sttRun executes the engine with BOTH streams kept and bounded.
//
// runExtract merges the streams on failure and drops stderr on success, which is
// right for a tool whose complaint only matters when it exits non-zero. This
// engine's most important complaint arrives on stderr WITH a zero exit, so the
// streams stay separate here.
//
// Returns (stdout, stderr, exit code, error). A non-zero exit is reported in the
// code rather than only in err, so a caller can tell "the model would not load"
// (rc 3) from "the process was killed".
func sttRun(timeout time.Duration, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sttBin, args...)
	hideConsole(cmd) // console_windows.go
	out := &capWriter{max: ctxExtractMaxText + 1}
	errb := &capWriter{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	if ctx.Err() != nil {
		// A DEADLINE IS NOT A FAILURE HERE. The engine prints each segment as it
		// finishes it, so the text captured before the kill is real transcript of
		// the user's real recording, and throwing it away to return a clean error
		// helps nobody. The caller reads the partial and flags it.
		return out.buf.String(), errb.buf.String(), code, errDeadline
	}
	return out.buf.String(), errb.buf.String(), code, err
}

// errDeadline marks the clock running out, distinct from every other failure.
var errDeadline = fmt.Errorf("the clock ran out")

// sttReadableDuration renders an elapsed time at a precision that can express
// it. Round(time.Second) was the old spelling and it turns every sub-second run
// into the literal string "0s"; a sentence claiming the engine was "still
// working after 0s" is no more believable than one claiming a negative. On a
// fast machine with a small model it is the COMMON case rather than an edge —
// MEASURED, this box's base.en is killed during model load inside 400 ms. Whole
// seconds above a second, milliseconds below it.
func sttReadableDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(time.Millisecond)
	}
	return d.Round(time.Second)
}

// sttDecodeFailure reads the engine's stderr for the case it does not put in its
// exit code. Returns "" when the audio was read.
//
// Matched on the engine's own sentences, verified by running it against an mp4
// and an m4a: "read_audio_data: failed to read audio data" followed by
// "error: failed to read audio file '<path>'". The path is NOT carried into the
// reason — it is a scratch name inside the pairing's root and means nothing to
// the user.
func sttDecodeFailure(stderr string) string {
	low := strings.ToLower(stderr)
	if strings.Contains(low, "failed to read audio") {
		return "the engine could not decode this recording. whisper.cpp reads wav, " +
			"mp3, flac and ogg by itself; anything in a container (mp4, m4a, mov, " +
			"mkv, webm) has to have its audio track unpacked with ffmpeg first, " +
			"which is the av-transcribe job"
	}
	return ""
}

// sttFirstProblem picks the most useful line out of a failed run.
func sttFirstProblem(stderr, stdout string, err error) string {
	for _, s := range []string{stderr, stdout} {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "error") {
				return firstLine(line)
			}
		}
	}
	if s := strings.TrimSpace(stderr); s != "" {
		return firstLine(s)
	}
	if err != nil {
		return err.Error()
	}
	return "it gave no reason"
}

// ── reading what it printed ─────────────────────────────────────────────────

// sttBlankToken is what the engine prints for a stretch with no speech in it.
// MEASURED: five seconds of digital silence comes back as one segment reading
// "[BLANK_AUDIO]" with rc=0. It is the difference between "that recording is
// silence" and "this box could not read it", which are two of the three answers
// this lane owes a user.
const sttBlankToken = "[BLANK_AUDIO]"

// sttBlankMarks is every way the engine says "nothing was said here". Both were
// OBSERVED coming out of the real binary on real digital silence — [BLANK_AUDIO]
// on a clean run and "(silence)" on the over-run that the -d bug produced — and
// both are the engine describing the audio rather than transcribing it. They are
// dropped from the text for the same reason: a corpus that contains the word
// "silence" because a microphone was off is a corpus with a false hit in it.
//
// This list cannot be complete, and saying so matters more than pretending
// otherwise: Whisper is known to invent short filler on silence ("You", "Thank
// you") that is indistinguishable from speech at this layer. What protects the
// user from that is not a longer list, it is not asking the engine for audio
// that is not there — see sttArgv's note on -d.
var sttBlankMarks = []string{sttBlankToken, "(silence)", "[silence]"}

// sttIsBlankMark reports whether a segment is the engine describing silence
// rather than transcribing speech.
func sttIsBlankMark(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	for _, m := range sttBlankMarks {
		if t == strings.ToLower(m) {
			return true
		}
	}
	return false
}

// sttIsNonSpeechMark reports whether a segment is the engine ANNOTATING a sound
// rather than transcribing speech: "[Music]", "(music)", "(applause)", "[♪♪♪]".
//
// ── WHY THIS IS STRUCTURAL AND NOT A WORD LIST ──────────────────────────────
//
// A list cannot work here, and that is measured rather than assumed. The same
// ten seconds of a synthesised melody through the real binary
// returns "[Music]" from base.en and "(music)" from tiny.en —
// two spellings, two brackets, two cases, one input. Eight seconds of a 440 Hz
// tone returns "(phone ringing)"; eight seconds of white noise returns "(machine
// whirring)". A real song produced "[♪♪♪]". The
// vocabulary is whatever the model decided the sound was, which is open-ended by
// construction, so any list is a list of the examples somebody happened to hit.
//
// WHAT IS INVARIANT is the SHAPE. Whisper wraps an annotation in brackets or
// parentheses and transcribes speech bare. Checked against 997 real speech
// segments — LibriSpeech test-clean and test-other, a voice clip, jfk.wav and a
// thirty-minute recording, all through base.en — of which ZERO were wholly
// wrapped and zero contained a bracket or a parenthesis anywhere at all. So a
// segment whose ENTIRE text is one bracketed group is the engine describing the
// audio, and dropping it cannot cost a user a word they said.
//
// It is deliberately narrow: the whole segment, one group, nothing outside it. A
// segment that merely CONTAINS a parenthesis is speech and is kept intact.
func sttIsNonSpeechMark(text string) bool {
	t := strings.TrimSpace(text)
	if len(t) < 2 {
		return false
	}
	var closer byte
	switch t[0] {
	case '[':
		closer = ']'
	case '(':
		closer = ')'
	default:
		return false
	}
	if t[len(t)-1] != closer {
		return false
	}
	// ONE group, not two. "(yes) and (no)" ends in a bracket and is speech; the
	// opening bracket must be closed only at the very end.
	inner := t[1 : len(t)-1]
	if strings.IndexByte(inner, closer) >= 0 {
		return false
	}
	return true
}

type sttSegment struct {
	// T0 and T1 are milliseconds from the start of the recording. T0 is what
	// becomes media_offset_ms on the row, which is what lets a search result be
	// jumped to in the audio the user already has.
	T0   int64  `json:"t0"`
	T1   int64  `json:"t1"`
	Text string `json:"text"`
}

// sttParse turns the engine's stdout into segments.
//
// The line it produces, verified against the real binary:
//
//	[00:00:00.000 --> 00:00:05.560]   "He hoped there would be stew for dinner...
//
// Parsed on the bracketed prefix only. A line that is not in that shape is
// SKIPPED rather than guessed at — the engine also writes banner and warning
// lines to stdout under some builds, and a parser that treated an unrecognised
// line as transcript would put the engine's own words into the user's corpus.
//
// ── WHAT THIS RETURNS, AND WHY IT IS THREE THINGS AND NOT TWO ───────────────
//
// (segments, blank, nonSpeech). The extra answer exists because "nobody spoke"
// and "nothing was said because it is a song" are different sentences, and
// folding the second into the first would tell a user their music upload is
// SILENT — which is a false statement about their file, made by us.
//
// The states this lane owes a user stay separate all the way down:
//
//	no engine     contextprep.go's quiet case. Never reaches this function.
//	unreadable    sttDecodeFailure, checked on stderr BEFORE this is called.
//	silence       blank — the engine's own [BLANK_AUDIO] and friends.
//	sound, no     nonSpeech — the engine annotated what it heard.
//	speech
//
// This is also the reason `--suppress-nst` was refused rather than used. It
// returns NOTHING AT ALL for a non-speech stretch, which erases the difference
// between "the engine listened and there was no speech" and "the engine produced
// no output", collapsing two of these into one. Dropping the token at the PARSER
// keeps the segment — with its timestamps and an empty text — so the distinction
// survives while the token never reaches the corpus.
//
// Neither flag is set when any real speech was found: a recording with music at
// the top and a meeting after it is a meeting, and its transcript is the words.
func sttParse(out string) ([]sttSegment, bool, bool) {
	segs := []sttSegment{}
	sawText := false
	sawBlank := false
	sawNonSpeech := false
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") {
			continue
		}
		close := strings.Index(trimmed, "]")
		if close < 0 {
			continue
		}
		span := trimmed[1:close]
		arrow := strings.Index(span, "-->")
		if arrow < 0 {
			continue
		}
		t0, ok0 := sttClock(span[:arrow])
		t1, ok1 := sttClock(span[arrow+3:])
		if !ok0 || !ok1 {
			continue
		}
		text := strings.TrimSpace(trimmed[close+1:])
		if text == "" {
			continue
		}
		// SILENCE FIRST. [BLANK_AUDIO] is also bracket-wrapped, so the specific
		// answer has to be taken before the general one or every silence would
		// be reported as a sound the engine could not name.
		if sttIsBlankMark(text) {
			// Kept as a segment so "the engine read this and there is nothing in
			// it" stays distinguishable from "the engine returned nothing", and
			// dropped from the text so the token never reaches the user's corpus.
			sawBlank = true
			segs = append(segs, sttSegment{T0: t0, T1: t1})
			continue
		}
		if sttIsNonSpeechMark(text) {
			// The engine heard something and told us what it was. That is a
			// description of the audio, not a word anybody said, and filing it as
			// text puts "[Music]" in the user's searchable corpus as a false hit.
			// Kept as a timestamped segment for the same reason silence is.
			sawNonSpeech = true
			segs = append(segs, sttSegment{T0: t0, T1: t1})
			continue
		}
		sawText = true
		segs = append(segs, sttSegment{T0: t0, T1: t1, Text: text})
		if len(segs) >= sttMaxSegments {
			break
		}
	}
	return segs, sawBlank && !sawText && !sawNonSpeech, sawNonSpeech && !sawText
}

// sttClock reads "00:01:02.345" into milliseconds. Returns false for anything
// else, which is how a non-transcript line is told apart from a transcript one.
func sttClock(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || m < 0 {
		return 0, false
	}
	sec := parts[2]
	ms := 0
	if dot := strings.Index(sec, "."); dot >= 0 {
		frac := sec[dot+1:]
		for len(frac) < 3 {
			frac += "0"
		}
		v, err := strconv.Atoi(frac[:3])
		if err != nil {
			return 0, false
		}
		ms = v
		sec = sec[:dot]
	}
	s2, err := strconv.Atoi(sec)
	if err != nil || s2 < 0 {
		return 0, false
	}
	return int64(h)*3600000 + int64(m)*60000 + int64(s2)*1000 + int64(ms), true
}

// sttText joins the segments into the plain transcript the embedding lane reads.
func sttText(segs []sttSegment) string {
	var b strings.Builder
	for _, s := range segs {
		if s.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s.Text)
	}
	return b.String()
}

// ── the result ──────────────────────────────────────────────────────────────

type sttResult struct {
	Segments []sttSegment
	Text     string
	// Model is the model that ACTUALLY RAN, not the one that was asked for and
	// not the one the box happens to prefer. It is the field this whole job is
	// arranged around: base.en and large-v3-turbo are three times apart in error
	// rate on hard audio, so a transcript with no model on it is a transcript
	// whose accuracy nobody can judge afterwards.
	Model string
	// Lang is the language the engine ACTUALLY DECODED IN, which is the engine's
	// own default of "en" unless the host named one. Recorded for the same reason
	// Model is: a transcript whose language nobody can see is a transcript whose
	// first failure mode is invisible.
	Lang string
	// AudioMS is how long the recording is, when the box could find out — ffprobe
	// on the av path, the RIFF header on a wav, and 0 when neither applies.
	// 0 means UNKNOWN and is never reported as a duration.
	AudioMS int64
	// DoneMS is how far into the recording the transcript reaches: the end of the
	// last segment the engine produced. Together with AudioMS it is what tells a
	// user how much of their meeting is in the corpus.
	DoneMS int64
	// Blank is the engine reading the whole thing and finding no speech. A
	// finished job with an empty answer, which is a different sentence from every
	// other empty answer in this lane.
	Blank bool
	// NonSpeech is the engine having heard SOMETHING and annotated it rather than
	// transcribed it — music, applause, a ringing phone. Not Blank, because the
	// recording is not silent and telling a user their song is silence is a false
	// statement about their file. Not text either: the annotation is the engine's
	// word, never the user's, and it is dropped before it can reach the corpus.
	NonSpeech bool
	// Demuxed is ffmpeg having unpacked an audio track before the engine saw it.
	Demuxed bool
	// Deadline is the clock running out mid-recording, with the text being what
	// was transcribed before it did. Partial and SAID to be partial.
	Deadline bool
	// Capped is the recording running past sttAudioCapSeconds, so the engine was
	// only asked for the first hour of it.
	Capped bool
}

// runTranscribe is the whole job: unpack an audio track if this is the av
// variant, transcribe, and report what was and was not covered.
func runTranscribe(root, in, tool, model, wantLang string, deadline time.Time) (sttResult, error) {
	var res sttResult
	chosen, err := sttPickModel(model)
	if err != nil {
		return res, err
	}
	res.Model = chosen.Name
	lang, err := sttLang(chosen, wantLang)
	if err != nil {
		return res, err
	}
	res.Lang = lang

	audio := in
	if tool == sttAVTool {
		// THE DEMUX, and it is why this job is separate from the other one. An
		// mp4's audio track is not something whisper.cpp reads; ffmpeg unpacks it
		// to the 16 kHz mono wav the engine wants anyway.
		budget := time.Until(deadline) / sttDemuxShare
		if budget <= 0 {
			return res, fmt.Errorf("there was no time left to unpack this recording's " +
				"audio track")
		}
		wav, ms, derr := sttDemux(root, in, budget)
		if wav != "" {
			defer os.Remove(wav)
		}
		if derr != nil {
			return res, derr
		}
		audio, res.AudioMS, res.Demuxed = wav, ms, true
	} else if ms, ok := wavDurationMS(in); ok {
		// A wav says how long it is in its own header, which costs one read and
		// is exact. Every other container on this path (mp3, ogg, flac) does not,
		// and this job has no ffprobe to ask — so the duration stays UNKNOWN
		// rather than being estimated, and the reply says nothing about it.
		res.AudioMS = ms
	}

	left := time.Until(deadline)
	if left <= 0 {
		return res, fmt.Errorf("there was no time left to transcribe this recording")
	}
	// THE CAP IS ONLY APPLIED WHEN IT BINDS. See sttArgv: -d is a duration the
	// engine will process whether the file has it or not, so passing it for a
	// recording that is shorter — or one whose length is unknown — is how an
	// eleven-second clip becomes an hour of invented text.
	capMS := 0
	if res.AudioMS > sttCapMS {
		capMS = sttCapMS
		res.Capped = true
	}
	// HOW LONG THE ENGINE ACTUALLY RAN, measured rather than derived.
	//
	// The deadline error below used to report time.Until(deadline) — the time
	// REMAINING — in a branch that is only reachable once rerr == errDeadline,
	// which means the deadline has already passed. So the value was NON-POSITIVE
	// BY CONSTRUCTION, at every magnitude, on every machine. That is the whole
	// defect and it needs no example: remaining time was never what "after %s"
	// meant.
	//
	// What a user saw depended on how far past the deadline the kill landed.
	// MEASURED on this box across the six runs that actually hit the deadline
	// (base.en at 50/150/300 ms, large-v3-turbo at 200/1000/3000 ms): the
	// overshoot is 3-84 ms, which Round(time.Second) renders as the literal
	// string "after 0s" — a sentence claiming the engine was still working after
	// no time at all. "after -4s" was also reported, which is the same defect
	// with an overshoot past half a second; that figure was not reproduced here,
	// so it is not written down as if it were.
	//
	// Both clocks here are time.Now() on this box, so the subtraction is
	// monotonic and cannot go backwards. sttRun returns errDeadline only when its
	// own context expired, which means this elapsed IS the budget the engine was
	// given — the two agree by construction rather than by a second guess.
	runStart := time.Now()
	out, errOut, rc, rerr := sttRun(left, sttArgv(chosen.Path, audio, capMS, lang)...)
	ran := time.Since(runStart)
	if rerr != nil && rerr != errDeadline {
		return res, fmt.Errorf("%s could not transcribe this recording: %s",
			sttBin, sttFirstProblem(errOut, out, rerr))
	}
	if rc != 0 && rerr != errDeadline {
		return res, fmt.Errorf("%s exited %d on this recording: %s",
			sttBin, rc, sttFirstProblem(errOut, out, rerr))
	}
	// THE ZERO-EXIT FAILURE. Checked before the output is read, because the
	// output of a failed decode is empty and empty would be reported as silence.
	if why := sttDecodeFailure(errOut); why != "" {
		return res, fmt.Errorf("%s", why)
	}
	// THE BACKSTOP FOR THE LANGUAGE, and it is the engine's own sentence rather
	// than this build's reading of a filename. If the name check let a request
	// through to a model that turns out to be English-only, the engine says so on
	// stderr and transcribes English anyway — so the job is refused HERE rather
	// than returning an English transcript labelled something else. Costs one run
	// in the one case where the naming convention lied.
	if wantLang != "" && lang != sttDefaultLang && sttEnglishOnlyRefusal(errOut) {
		return res, fmt.Errorf(
			"%s reported that the model %s is not multilingual and ignored the request "+
				"to transcribe %s — what it produced is an English transcript, so this "+
				"job is not filing it under %s", sttBin, chosen.Name, lang, lang)
	}
	res.Deadline = rerr == errDeadline

	segs, blank, nonSpeech := sttParse(out)
	res.Segments = segs
	res.Blank = blank
	res.NonSpeech = nonSpeech
	res.Text = sttText(segs)
	if len(segs) > 0 {
		res.DoneMS = segs[len(segs)-1].T1
	}
	if res.Deadline && len(segs) == 0 {
		return res, fmt.Errorf(
			"%s was still loading or still working after %s and produced nothing "+
				"before it was stopped — the recording was not rejected, it did not "+
				"start returning text in the time this lane allows", sttBin,
			sttReadableDuration(ran))
	}
	return res, nil
}

// handleCtxTranscribe owns the scratch file from the moment ctx_extract forks to
// it, including REMOVING IT BEFORE IT REPLIES.
//
// Before, not deferred, and for the reason contextextract.go records against its
// own removal: the terminal frame is written inside the reply helpers, so a
// deferred remove leaves the user's recording on their disk at the moment the
// host is told the job finished. The guarantee this lane makes is that it is
// gone by then.
func handleCtxTranscribe(ws *websocket.Conn, root, scratch string, req ctxExtractReq,
	run func(root, in, tool, model, lang string, deadline time.Time) (sttResult, error),
	source string, limit time.Duration) {

	res, err := run(root, scratch, req.Tool, req.Model, req.Lang, time.Now().Add(limit))
	_ = os.Remove(scratch)
	if err != nil {
		ctxExtractFail(ws, "ctx_extract: "+err.Error())
		return
	}

	resp := ctxExtractResp{
		Tool: req.Tool, Source: source,
		Chars: len(res.Text), Text: res.Text,
		Model: res.Model, Lang: res.Lang, Segments: res.Segments,
		AudioMS: res.AudioMS, DoneMS: res.DoneMS,
		Capped: res.Capped, Blank: res.Blank, NonSpeech: res.NonSpeech,
		Demuxed: res.Demuxed, Deadline: res.Deadline,
	}
	// The text cap applies here too, and the SEGMENTS are trimmed with it rather
	// than left to point past the end of the text they describe. A segment list
	// longer than its transcript would give the host offsets for words it does
	// not have.
	if len(res.Text) > ctxExtractMaxText {
		resp.Text = res.Text[:ctxExtractMaxText]
		resp.Chars = ctxExtractMaxText
		resp.CharsAll = len(res.Text)
		resp.Truncated = true
		resp.Segments = sttSegmentsWithin(res.Segments, ctxExtractMaxText)
		if n := len(resp.Segments); n > 0 {
			resp.DoneMS = resp.Segments[n-1].T1
		}
	}
	b, err := json.Marshal(resp)
	if err != nil {
		ctxExtractFail(ws, "ctx_extract: cannot encode the result: "+err.Error())
		return
	}
	sendMgmt(ws, 'O', b)
	sendMgmtExit(ws, 0)
}

// sttSegmentsWithin keeps the segments whose words survived the text cap, so the
// offsets the host files always describe text the host actually received.
func sttSegmentsWithin(segs []sttSegment, max int) []sttSegment {
	out := []sttSegment{}
	used := 0
	for _, s := range segs {
		if s.Text == "" {
			continue
		}
		next := used + len(s.Text)
		if used > 0 {
			next++ // the newline sttText joins with
		}
		if next > max {
			break
		}
		used = next
		out = append(out, s)
	}
	return out
}

// ── the demux ───────────────────────────────────────────────────────────────

// sttDemux writes the recording's audio track out as the 16 kHz mono wav the
// engine wants, and returns the track's duration.
//
// Flags, each one load-bearing:
//
//	-nostdin      ffmpeg reads stdin by default and would consume the daemon's.
//	-v error      quiet unless something is wrong, so the message this returns
//	              is ffmpeg's actual complaint and not its banner.
//	-vn           drop the video. On a clip this is most of the bytes.
//	-ac 1 -ar 16000 -c:a pcm_s16le
//	              exactly what whisper wants. Doing it here rather than letting
//	              the engine resample means the conversion is ffmpeg's, which is
//	              the better resampler, and the intermediate file is as small as
//	              it can be.
//	-f wav        the format is stated rather than inferred from the name.
//
// NOTHING OF THE USER'S IS LEFT BEHIND: the wav is created inside the pairing's
// own sandboxed root with the same "extract-" prefix the source file uses, so
// the stale-scratch sweep that runs at worker start already removes it if this
// process dies mid-job.
func sttDemux(root, in string, budget time.Duration) (string, int64, error) {
	f, err := os.CreateTemp(root, "extract-audio-*.wav")
	if err != nil {
		return "", 0, fmt.Errorf("no scratch space to unpack this recording's audio: %w", err)
	}
	out := f.Name()
	f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ffmpeg", "-nostdin", "-v", "error", "-y",
		"-i", in, "-vn", "-ac", "1", "-ar", "16000", "-c:a", "pcm_s16le",
		"-f", "wav", out)
	hideConsole(cmd) // console_windows.go
	errb := &capWriter{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = &capWriter{max: 8 << 10}, errb
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return out, 0, fmt.Errorf(
			"unpacking this recording's audio track was still running after %s and was "+
				"stopped — nothing was transcribed", budget.Round(time.Second))
	}
	if runErr != nil {
		msg := strings.TrimSpace(errb.buf.String())
		// NO AUDIO TRACK IS ITS OWN ANSWER. A silent screen recording is a
		// complete, well-formed file that this job has nothing to say about, and
		// calling it a broken file would send the user to look at their camera.
		low := strings.ToLower(msg)
		if strings.Contains(low, "does not contain any stream") ||
			strings.Contains(low, "no audio") {
			return out, 0, fmt.Errorf("this recording has no audio track in it — there " +
				"is nothing to transcribe. That is a complete answer about the file, " +
				"not a failure of this machine")
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out, 0, fmt.Errorf("ffmpeg could not unpack this recording's audio track"+
			"%s", ifNonEmpty(msg, ": "+msg))
	}
	ms, _ := wavDurationMS(out)
	return out, ms, nil
}

// ── the wav header ──────────────────────────────────────────────────────────

// wavDurationMS reads how long a wav is out of its own header.
//
// Exact and free: a RIFF/WAVE file states its byte rate and its data chunk's
// length, so the duration is a division rather than a decode. Returns false for
// anything that is not a wav, which is the honest answer — an UNKNOWN duration
// is reported as unknown and never estimated, because the number is shown to the
// user as "how much of your recording is in the corpus".
func wavDurationMS(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	head := make([]byte, 12)
	if _, err := f.Read(head); err != nil {
		return 0, false
	}
	if string(head[0:4]) != "RIFF" || string(head[8:12]) != "WAVE" {
		return 0, false
	}
	var byteRate uint32
	var dataLen uint32
	// Walk the chunks. fmt carries the byte rate, data carries the length; a wav
	// may hold other chunks (LIST, fact) between them, so this does not assume
	// the canonical 44-byte layout.
	for i := 0; i < 64; i++ {
		hdr := make([]byte, 8)
		if _, err := f.Read(hdr); err != nil {
			break
		}
		id := string(hdr[0:4])
		size := binary.LittleEndian.Uint32(hdr[4:8])
		switch id {
		case "fmt ":
			body := make([]byte, size)
			if _, err := f.Read(body); err != nil || len(body) < 16 {
				return 0, false
			}
			byteRate = binary.LittleEndian.Uint32(body[8:12])
		case "data":
			dataLen = size
			if byteRate > 0 {
				return int64(dataLen) * 1000 / int64(byteRate), true
			}
			return 0, false
		default:
			// Chunks are word-aligned: an odd length is followed by a pad byte.
			skip := int64(size) + int64(size%2)
			if _, err := f.Seek(skip, 1); err != nil {
				return 0, false
			}
		}
	}
	return 0, false
}

// sttProbeWAV is one second of 16 kHz mono silence as a wav, built here rather
// than embedded so there is no asset to keep in step with the parser.
//
// Silence is the right probe input precisely because its answer is a KNOWN
// token: the engine returns [BLANK_AUDIO], which exercises the model load, the
// decoder, the timestamp format and this file's parser in one run, and gives an
// answer that can be asserted rather than merely looked at.
func sttProbeWAV() []byte {
	const rate = 16000
	const samples = rate // one second
	data := make([]byte, samples*2)
	b := make([]byte, 0, 44+len(data))
	b = append(b, "RIFF"...)
	b = binary.LittleEndian.AppendUint32(b, uint32(36+len(data)))
	b = append(b, "WAVEfmt "...)
	b = binary.LittleEndian.AppendUint32(b, 16)   // PCM fmt chunk size
	b = binary.LittleEndian.AppendUint16(b, 1)    // PCM
	b = binary.LittleEndian.AppendUint16(b, 1)    // mono
	b = binary.LittleEndian.AppendUint32(b, rate) // sample rate
	b = binary.LittleEndian.AppendUint32(b, rate*2)
	b = binary.LittleEndian.AppendUint16(b, 2)  // block align
	b = binary.LittleEndian.AppendUint16(b, 16) // bits per sample
	b = append(b, "data"...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	b = append(b, data...)
	return b
}
