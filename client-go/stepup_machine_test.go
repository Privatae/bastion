package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	machineTestSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	hostTestSecret    = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"
)

func codeFor(t *testing.T, secretB32 string) string {
	t.Helper()
	raw, err := b32decode(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(raw, time.Now().Unix()/stepupPeriod)
}

func enrolFactorAt(t *testing.T, dir, secretB32 string) {
	t.Helper()
	f := &stepupFile{SecretB32: secretB32, EnrolledAt: time.Now().UTC().Format(time.RFC3339), LastCounter: -1}
	if err := stepupSave(dir, f); err != nil {
		t.Fatal(err)
	}
}

// With no Host paired, the owner's factor is the only one there is, so a
// command that names none reaches it. It used to refuse ("not paired yet"),
// which left a bastion on its own with no way to prove a person approved
// anything.
func TestWithNoHostTheSecondFactorIsTheMachineOwners(t *testing.T) {
	uiTestConfigDir(t)
	tg, err := resolveStepupTarget("", false)
	if err != nil {
		t.Fatalf("no Host paired and no factor reachable: %v", err)
	}
	if !tg.machine() {
		t.Fatalf("with no Host the factor named %q, not the machine's", tg.host)
	}
	d, _ := configDir()
	if tg.dir != filepath.Join(d, "machine-factor") {
		t.Errorf("the owner's factor lives at %s", tg.dir)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(tg.dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Errorf("the owner's factor directory is %v, not private", st.Mode().Perm())
		}
	}
}

// With a Host paired, a bare command keeps meaning that Host's factor, as it
// always did; --machine reaches the owner's; both at once is refused rather
// than guessed.
func TestMachineAndHostFactorsAreNamedApart(t *testing.T) {
	uiTestConfigDir(t)
	const host = "h1.host.privatae.ai"
	givenPairing(t, host, pairingActive)
	tg, err := resolveStepupTarget("", false)
	if err != nil {
		t.Fatal(err)
	}
	if tg.machine() || tg.host != host {
		t.Errorf("with one Host paired a bare command reached %+v, not that Host's factor", tg)
	}
	mt, err := resolveStepupTarget("", true)
	if err != nil {
		t.Fatal(err)
	}
	if !mt.machine() || mt.dir == tg.dir {
		t.Errorf("--machine reached %+v, the same place as the Host's factor", mt)
	}
	if _, err := resolveStepupTarget(host, true); err == nil {
		t.Error("--machine with --host was accepted; one of them was silently ignored")
	}
}

// The owner's factor and a Host's are two secrets: a code from the Host's
// authenticator approves nothing asked of the machine, and the other way round.
func TestAHostsCodeDoesNotApproveWhatIsAskedOfTheMachine(t *testing.T) {
	uiTestConfigDir(t)
	const host = "h1.host.privatae.ai"
	givenPairing(t, host, pairingActive)
	ht, err := resolveStepupTarget(host, false)
	if err != nil {
		t.Fatal(err)
	}
	mt, err := resolveStepupTarget("", true)
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, ht.dir, hostTestSecret)
	enrolFactorAt(t, mt.dir, machineTestSecret)
	// Refused for the right reason: both are enrolled, so "not enrolled"
	// would mean this test proves nothing.
	if _, err := stepupIssueApproval(mt.dir, codeFor(t, hostTestSecret), "test|machine"); err == nil ||
		!strings.Contains(err.Error(), "code refused") {
		t.Errorf("the Host's code against the machine's factor: %v, want code refused", err)
	}
	if _, err := stepupIssueApproval(ht.dir, codeFor(t, machineTestSecret), "test|host"); err == nil ||
		!strings.Contains(err.Error(), "code refused") {
		t.Errorf("the owner's code against the Host's factor: %v, want code refused", err)
	}
	if _, err := stepupIssueApproval(mt.dir, codeFor(t, machineTestSecret), "test|machine"); err != nil {
		t.Errorf("the owner's own code did not approve: %v", err)
	}
}

// The console's code boxes are reached by anything driving the person's
// browser, which on a whole-machine install cannot read the owner's secret:
// guessing is its only way in, so wrong codes there are throttled, as on the
// tray (approvalpipe.go). Before this, every console act took unlimited
// guesses at a six-digit code.
func TestWrongCodesAtTheConsoleAreThrottled(t *testing.T) {
	uiTestConfigDir(t)
	d, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, d, machineTestSecret)
	for i := 0; i < pipeFreeFailures; i++ {
		if why := markCodeRefusal("fp1", "000000"); !strings.Contains(why, "code refused") {
			t.Fatalf("wrong code %d: %q", i+1, why)
		}
	}
	right := codeFor(t, machineTestSecret)
	if why := markCodeRefusal("fp1", right); !strings.Contains(why, "wrong codes in a row") {
		t.Errorf("after %d wrong codes a mark still took a code: %q", pipeFreeFailures, why)
	}
	if why := ownerCodeRefusal(right, "local_owner|x"); !strings.Contains(why, "wrong codes in a row") {
		t.Errorf("after %d wrong codes an owner act still took a code: %q", pipeFreeFailures, why)
	}
	if msg, _ := recordBaselineFromConsole(right); !strings.Contains(msg, "wrong codes in a row") {
		t.Errorf("after %d wrong codes a baseline still took a code: %q", pipeFreeFailures, msg)
	}
	// The wait passes: the right code is taken and the count starts again.
	if _, err := machineCodeSpend(d, time.Now().Add(pipeSlowEvery+time.Second), func() (string, error) {
		return stepupIssueApproval(d, right, "local_mark|fp1")
	}); err != nil {
		t.Fatalf("after the wait the right code was refused: %v", err)
	}
	if f := pipeThrottleLoad(d); f.Failures != 0 {
		t.Errorf("an accepted code left %d failures counted", f.Failures)
	}
	// Locked after pipeLockAfter: no wait opens it.
	_ = atomicWrite(pipeThrottlePath(d), []byte(`{"failures": 100, "last": "2000-01-01T00:00:00Z"}`))
	if why := markCodeRefusal("fp1", codeFor(t, machineTestSecret)); !strings.Contains(why, "takes no more codes") {
		t.Errorf("a locked console took a code: %q", why)
	}
}
