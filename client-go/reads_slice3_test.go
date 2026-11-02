package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The switch list as JSON has every row the words have, each family of each
// paired host, and an unreadable list reads as every family off.
func TestTheSwitchListReadHasEveryRowTheWordsHave(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	if err := localDenySet(host, "ops", true); err != nil {
		t.Fatal(err)
	}
	v, err := readSwitches(readOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Switches) != len(localSwitchFamilies()) {
		t.Fatalf("want one row per family (%d), got %+v", len(localSwitchFamilies()), v.Switches)
	}
	var buf bytes.Buffer
	printSwitches(&buf, v)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(v.Switches) {
		t.Fatalf("%d rows, %d lines:\n%s", len(v.Switches), len(lines), buf.String())
	}
	for i, r := range v.Switches {
		f := strings.Fields(lines[i])
		if f[0] != r.Host || f[1] != r.Family || (f[2] == "off") != r.Off {
			t.Errorf("row %+v printed as %q", r, lines[i])
		}
		if r.Family == "ops" && (!r.Off || r.Since == "") {
			t.Errorf("ops was switched off: %+v", r)
		}
	}

	// MUTATION: build rows from f.Off only, ignoring readErr. RESULT: red,
	// the families read on while the gate refuses them all.
	path, err := localDenyPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err = readSwitches(readOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Unreadable == "" {
		t.Error("an unreadable list is not said")
	}
	for _, r := range v.Switches {
		if !r.Off {
			t.Errorf("with the list unreadable, %s %s reads on", r.Host, r.Family)
		}
	}
}

// Read as JSON, the device's asks are a program's, not a person's: nothing is
// recorded as shown, so `device-approve all` signs nothing an agent read.
func TestDeviceApprovalsAsJSONRecordsNothingShown(t *testing.T) {
	uiTestConfigDir(t)
	p, err := deviceShownPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdDeviceApprovals([]string{"--json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("device-approvals --json recorded what it printed as shown")
	}
	if err := cmdDeviceApprovals(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("the words listing recorded nothing as shown: %v", err)
	}
	if err := cmdDeviceApprovals([]string{"--jsno"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("a stray flag: %v", err)
	}
}

// A restore request read leaves the sealed key the host sent, and the one
// resealed for it, out of the answer; their digest and the words stay.
func TestTheBackupRequestsReadLeavesTheSealedKeysOut(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	cfg, err := stepupPairing(host)
	if err != nil {
		t.Fatal(err)
	}
	const sealed, resealed = "-----BEGIN AGE ENCRYPTED FILE-----SIDECAR", "-----BEGIN AGE ENCRYPTED FILE-----RESEALED"
	at := time.Now().UTC().Format(time.RFC3339)
	// r1 waits, so it still carries the sidecar it came with; r2 was
	// answered and carries the resealed key.
	if err := resealSave(cfg.dcnDir(), map[string]*resealRequest{
		"r1": {ID: "r1", Stamp: "20261101T000000Z", Pairing: host, HostNumber: 7, HostLabel: "home", To: "age1xyz",
			ToFP: "fp", Sidecar: sealed, SidecarSH: "abc123", At: at, State: "pending"},
		"r2": {ID: "r2", Stamp: "20261101T000000Z", Pairing: host, HostNumber: 7, HostLabel: "home", To: "age1xyz",
			ToFP: "fp", SidecarSH: "def456", At: at, State: "done", Resealed: resealed},
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := resealRead(cfg.dcnDir())
	if err != nil || stored["r1"] == nil || stored["r1"].Sidecar != sealed || stored["r2"] == nil || stored["r2"].Resealed != resealed {
		t.Fatalf("the fixture does not hold both sealed keys: %+v %v", stored, err)
	}
	// MUTATION: build the view from *resealRequest itself. RESULT: red, both
	// sealed keys are in the answer.
	v, err := readBackupRequests(readOpts{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "SIDECAR") || strings.Contains(string(b), "RESEALED") {
		t.Errorf("the read carries a sealed key: %s", b)
	}
	if len(v.Requests) != 2 || v.Requests[0].SidecarSHA == "" || !strings.Contains(v.Requests[0].Words, "home") {
		t.Errorf("the requests as read: %+v", v.Requests)
	}
}

// The backup key read carries the public halves only.
func TestTheBackupKeysReadHasNoSecretHalf(t *testing.T) {
	b, err := json.Marshal(backupKeysRead{Keys: []*backupKeyFile{{Identity: "AGE-SECRET-KEY-1SECRET", Recipient: "age1pub",
		Fingerprint: "fp"}}, Current: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "AGE-SECRET-KEY") {
		t.Errorf("the backup keys read carries the secret: %s", b)
	}
}

// agents show takes a pid, or a session name that matches exactly one, the
// rule stop keeps.
func TestAgentsShowPicksExactlyOneAgent(t *testing.T) {
	views := []agentView{
		{agentObs: agentObs{PID: 101, Signature: "claude-code"}, Self: &agentSelf{Name: "shop"}},
		{agentObs: agentObs{PID: 102, Signature: "claude-code"}, Self: &agentSelf{Name: "twin"}},
		{agentObs: agentObs{PID: 103, Signature: "aider"}, Self: &agentSelf{Name: "twin"}},
	}
	if v, err := pickAgentView(views, "101"); err != nil || v.PID != 101 {
		t.Errorf("by pid: %+v %v", v, err)
	}
	if v, err := pickAgentView(views, "shop"); err != nil || v.PID != 101 {
		t.Errorf("by name: %+v %v", v, err)
	}
	if _, err := pickAgentView(views, "twin"); err == nil || !strings.Contains(err.Error(), "give the pid") {
		t.Errorf("two sessions with one name: %v", err)
	}
	if _, err := pickAgentView(views, "999"); err == nil {
		t.Error("a pid no agent has was shown")
	}
	if _, err := pickAgentView(views, "nobody"); err == nil {
		t.Error("a name no session has was shown")
	}
	if err := cmdAgents([]string{"show"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("show with no agent: %v", err)
	}
	if err := cmdAgents([]string{"show", "--json"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("show --json with no agent: %v", err)
	}
}

// The detail view names the file the kernel says the agent runs, and keeps
// its command line (which can carry a key) out of the words.
func TestAgentsShowKeepsTheCommandLineOutOfTheWords(t *testing.T) {
	v := agentView{agentObs: anObservedAgent("aider", "/usr/local/bin/aider --api-key sk-THEKEY", 4242)}
	var b bytes.Buffer
	printAgentDetail(&b, v, time.Now())
	out := b.String()
	if strings.Contains(out, "sk-THEKEY") {
		t.Errorf("the words carry the command line:\n%s", out)
	}
	if !strings.Contains(out, "/usr/local/bin/aider") || !strings.Contains(out, "4242") {
		t.Errorf("the words do not name the program and pid:\n%s", out)
	}
}

// The file an agent runs is a path whoever placed it chose, so a path built
// of terminal control sequences is shown as such, never sent to the terminal.
//
// MUTATION: row("program", v.Exe). RESULT: red, the escape reaches the words.
func TestAgentsShowNeverPrintsControlCharactersFromTheProgramPath(t *testing.T) {
	v := agentView{agentObs: anObservedAgent("claude-code", "claude", 4242)}
	v.Exe = "/tmp/\x1b]52;c;cHduZWQ=\x07/\x1b[2Jclaude"
	var b bytes.Buffer
	printAgentDetail(&b, v, time.Now())
	out := b.String()
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("the words carry the program path's control characters: %q", out)
	}
	if !strings.Contains(out, `\x1b]52`) {
		t.Errorf("the program path is not shown as what it is: %q", out)
	}
	v.Exe = "/usr/local/bin/claude"
	b.Reset()
	printAgentDetail(&b, v, time.Now())
	if !strings.Contains(b.String(), "program:        /usr/local/bin/claude\n") {
		t.Errorf("a plain path is not shown as is: %q", b.String())
	}
}

// A read is built in the root daemon now, from code that ran only in a
// command's own process before (readOps slices names it finds on disk). One
// that panics is that read's failure, and the daemon serving every pairing
// stays up.
//
// MUTATION: drop the recover in runMachineRead. RESULT: red, the suite
// itself panics.
func TestAReadThatPanicsFailsAndLeavesTheDaemonUp(t *testing.T) {
	uiTestConfigDir(t)
	laneOwner(t, 1000)
	for _, heavy := range []bool{false, true} {
		machineReads["test-panics"] = machineRead{heavy: heavy, build: func(readOpts) (any, error) {
			var s []string
			return s[3], nil
		}}
		r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "test-panics"})
		if r.OK || !r.Failed || !strings.Contains(r.Why, "test-panics") {
			t.Errorf("a read that panics (heavy %v): %+v", heavy, r)
		}
	}
	delete(machineReads, "test-panics")
	if r := serveRead(1000, "sam", agentAskRequest{Op: "read", Read: "status"}); !r.OK {
		t.Errorf("after a read panicked, status: %+v", r)
	}
}

// doctor from an ordinary account beside a system service would, run
// directly, check that account's own empty bastion and report it as the
// machine's (not running, no owner, no factor). So it is a lane read, as
// status is: through ask.sock on Linux and macOS, the ask pipe on Windows.
//
// MUTATION: drop "doctor" from serviceLaneReads. RESULT: red on every system.
func TestDoctorBesideAWindowsServiceIsRefusedAsStatusIs(t *testing.T) {
	if !serviceGuardedCommands["doctor"] || !serviceLaneReads["doctor"] {
		t.Error("doctor is not both guarded and a lane read, so it would check an ordinary account's own bastion")
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if err := serviceGuard(goos, "doctor", true, false); err != nil {
			t.Errorf("%s: doctor beside the service is a lane read: %v", goos, err)
		}
	}
	if err := serviceGuard("windows", "doctor", true, true); err != nil {
		t.Errorf("the administrator's doctor beside a Windows service: %v", err)
	}
}

// doctorWorld is a machine doctor reads from fixtures only.
func doctorWorld(t *testing.T, system bool, latest string) {
	t.Helper()
	uiTestConfigDir(t)
	prevSys, prevLatest, prevSandbox := systemInstalled, doctorLatest, doctorSandbox
	t.Cleanup(func() { systemInstalled, doctorLatest, doctorSandbox = prevSys, prevLatest, prevSandbox })
	systemInstalled = func() bool { return system }
	doctorLatest = func() string { return latest }
	doctorSandbox = func() (bool, string) { return true, "" }
}

func doctorCheckNamed(d doctorRead, name string) (doctorCheck, bool) {
	for _, c := range d.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return doctorCheck{}, false
}

// With no second factor, doctor says what cannot be approved and the command
// that sets one up; with one, it is not a problem.
func TestDoctorFindsAMissingSecondFactorAndNamesTheFix(t *testing.T) {
	doctorWorld(t, false, "")
	d, err := readDoctor(readOpts{})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := doctorCheckNamed(d, "second factor")
	if !ok || c.OK || !strings.Contains(c.Fix, "stepup-enroll --machine") || strings.Contains(c.Fix, "sudo") {
		t.Errorf("no factor, a per-account install: %+v", c)
	}
	systemInstalled = func() bool { return true }
	d, _ = readDoctor(readOpts{})
	if c, _ := doctorCheckNamed(d, "second factor"); !strings.HasPrefix(c.Fix, "sudo -H privatae-bastion stepup-enroll") &&
		!strings.Contains(c.Fix, "Administrator") {
		t.Errorf("no factor, installed for the machine: %+v", c)
	}
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, dir, machineTestSecret)
	d, _ = readDoctor(readOpts{})
	if c, _ := doctorCheckNamed(d, "second factor"); !c.OK {
		t.Errorf("with a factor enrolled: %+v", c)
	}
}

// A newer published version is a problem with the installer as its fix; a
// latest version nobody could read is not one.
func TestDoctorSaysANewerVersionAndNeverAlarmsOffline(t *testing.T) {
	doctorWorld(t, false, "999.0.0")
	prev := clientVersion
	t.Cleanup(func() { clientVersion = prev })
	clientVersion = "1.0.0"
	d, _ := readDoctor(readOpts{})
	c, _ := doctorCheckNamed(d, "version")
	if c.OK || !strings.Contains(c.Problem, "999.0.0") || !strings.Contains(c.Fix, "privatae.ai/bastion/install") {
		t.Errorf("a newer version: %+v", c)
	}
	doctorLatest = func() string { return "" }
	d, _ = readDoctor(readOpts{})
	if c, _ := doctorCheckNamed(d, "version"); !c.OK {
		t.Errorf("no answer from privatae.ai reads as a problem: %+v", c)
	}
	doctorLatest = func() string { return "1.0.0" }
	d, _ = readDoctor(readOpts{})
	if c, _ := doctorCheckNamed(d, "version"); !c.OK {
		t.Errorf("the latest version reads as a problem: %+v", c)
	}
}

// Installed for the whole machine with no owner recorded, doctor says what
// that stops and how to record one; recorded, it names the account.
func TestDoctorFindsNoOwnerAccountOnAMachineInstall(t *testing.T) {
	doctorWorld(t, true, "")
	d, _ := readDoctor(readOpts{})
	c, ok := doctorCheckNamed(d, "owner")
	if !ok || c.OK || !strings.Contains(c.Fix, "approvals-owner") {
		t.Errorf("no owner: %+v", c)
	}
	laneOwner(t, 1000)
	d, _ = readDoctor(readOpts{})
	if c, _ := doctorCheckNamed(d, "owner"); !c.OK || !strings.Contains(c.Detail, "sam") {
		t.Errorf("an owner recorded: %+v", c)
	}
	systemInstalled = func() bool { return false }
	d, _ = readDoctor(readOpts{})
	if _, ok := doctorCheckNamed(d, "owner"); ok {
		t.Error("a per-account install was checked for a machine owner")
	}
}

// An account whose agents' asks are held is named, with the command that
// lifts the hold.
func TestDoctorNamesAHeldAsker(t *testing.T) {
	doctorWorld(t, false, "")
	dir, err := machineFactorDir()
	if err != nil {
		t.Fatal(err)
	}
	enrolFactorAt(t, dir, machineTestSecret)
	now := time.Now()
	for i := 0; i < quarantineStrikes; i++ {
		askStrike(dir, "lee", now)
	}
	d, _ := readDoctor(readOpts{})
	c, ok := doctorCheckNamed(d, "held asker")
	if !ok || c.OK || !strings.Contains(c.Problem, "lee") || !strings.Contains(c.Fix, "quarantine clear --asker lee") {
		t.Errorf("a held asker: %+v (checks %+v)", c, d.Checks)
	}
}

// doctor exits 1 when it finds a problem, so a script can branch, and the
// lane not answering becomes the check rather than an error.
func TestDoctorExitsOneOnAProblemAndSaysTheLane(t *testing.T) {
	doctorWorld(t, false, "")
	err := cmdDoctor(nil)
	var q quietExit
	if !errors.As(err, &q) || q.code != 1 {
		t.Errorf("no factor: want exit 1, got %v", err)
	}
	if err := cmdDoctor([]string{"--jsno"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("a stray flag: %v", err)
	}
	if c := laneCheck(&laneError{down: true, why: "nothing answers"}); c.OK || c.Name != "running" || c.Fix == "" {
		t.Errorf("the lane down: %+v", c)
	}
	if c := laneCheck(&laneError{why: "this machine's bastion answers reads only for its owner's account (sam), not lee"}); c.OK ||
		c.Name != "reads" || !strings.Contains(c.Fix, "doctor") {
		t.Errorf("the lane refusing: %+v", c)
	}
}

func TestTheSliceThreeReadCommandsRefuseStrayFlags(t *testing.T) {
	for name, cmd := range map[string]func([]string) error{
		"switch --list": func(a []string) error { return cmdSwitch(append([]string{"--list"}, a...)) },
		"backup key show": func(a []string) error {
			return cmdBackup(append([]string{"key", "show"}, a...))
		},
		"backup requests": func(a []string) error { return cmdBackup(append([]string{"requests"}, a...)) },
		"backup shares": func(a []string) error {
			return cmdBackup(append([]string{"shares", "--with", "h"}, a...))
		},
	} {
		if err := cmd([]string{"--jsno"}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%s --jsno: %v", name, err)
		}
	}
}

// Not paired, the command that pairs is said the way it is typed here:
// with sudo -H where the bastion is installed for the whole machine.
func TestNotPairedSaysThePairCommandForThisInstall(t *testing.T) {
	doctorWorld(t, true, "")
	_, err := stepupPairing("")
	if err == nil || !strings.Contains(err.Error(), asAdmin("pair <token>")) {
		t.Errorf("not paired, a machine install: %v", err)
	}
	if runtimeIsUnix() && !strings.Contains(err.Error(), "sudo -H privatae-bastion pair") {
		t.Errorf("not paired, a machine install, says no sudo: %v", err)
	}
	systemInstalled = func() bool { return false }
	if _, err := stepupPairing(""); err == nil || strings.Contains(err.Error(), "sudo") {
		t.Errorf("not paired, a per-account install: %v", err)
	}
}

func runtimeIsUnix() bool { return os.PathSeparator == '/' }

// doctor asks privatae.ai at update.go's rate: once, then not again within
// updateCheckEvery, whether that ask was answered or not; the last answer
// stands meanwhile. MUTATION: drop the doctorAskedLoad shortcut. RESULT: red,
// every run fetches.
func TestDoctorAsksPrivataeAtTheUpdateCheckRate(t *testing.T) {
	uiTestConfigDir(t)
	prevFetch, prevNow := doctorFetch, doctorNow
	t.Cleanup(func() { doctorFetch, doctorNow = prevFetch, prevNow })
	forget := func() { latestMu.Lock(); latestPublished = ""; latestMu.Unlock() }
	t.Cleanup(forget)
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	doctorNow = func() time.Time { return now }
	fetches, answer := 0, "0.61.0"
	doctorFetch = func() (string, error) {
		fetches++
		if answer == "" {
			return "", errors.New("no route")
		}
		return answer, nil
	}
	forget()
	if v := doctorLatest(); v != "0.61.0" || fetches != 1 {
		t.Fatalf("first run: %q after %d fetches", v, fetches)
	}
	forget() // a new process: nothing in memory
	now = now.Add(updateCheckEvery - time.Minute)
	if v := doctorLatest(); v != "0.61.0" || fetches != 1 {
		t.Errorf("inside the window: %q after %d fetches", v, fetches)
	}
	forget()
	now = now.Add(2 * time.Minute)
	answer = ""
	if v := doctorLatest(); v != "0.61.0" || fetches != 2 {
		t.Errorf("past the window, no answer: %q after %d fetches (the last answer should stand)", v, fetches)
	}
	forget()
	now = now.Add(time.Hour)
	if v := doctorLatest(); v != "0.61.0" || fetches != 2 {
		t.Errorf("a failed ask is not repeated inside the window: %q after %d fetches", v, fetches)
	}
}

// A folder the agent chose, holding an escape sequence, is printed quoted in
// agents and agents show, never sent to the terminal raw.
func TestAnAgentsFolderNeverReachesTheTerminalRaw(t *testing.T) {
	v := agentView{agentObs: anObservedAgent("aider", "/usr/local/bin/aider", 4242),
		Folder: "/home/u/\x1b]52;c;cGF3bmVk\x07work", GitBranch: "main"}
	var b bytes.Buffer
	printAgents(&b, []agentView{v}, time.Now())
	printAgentDetail(&b, v, time.Now())
	if strings.ContainsAny(b.String(), "\x1b\x07") {
		t.Errorf("a control character reached the output: %q", b.String())
	}
	if !strings.Contains(b.String(), `\x1b]52`) {
		t.Errorf("the folder is not shown at all: %q", b.String())
	}
}

// The slice-3 reads from an ordinary account beside the service ask the
// machine's bastion over its lane on every system (the ask pipe on Windows),
// so the guard lets them by. The rest of backup is not guarded.
func TestTheSliceThreeReadsAreGuardedBesideAWindowsService(t *testing.T) {
	for _, line := range [][]string{
		{"privatae-bastion", "ops", "--json"},
		{"privatae-bastion", "device-approvals"},
		{"privatae-bastion", "backup", "requests"},
		{"privatae-bastion", "backup", "shares", "--with", "h"},
		{"privatae-bastion", "backup", "key", "show"},
	} {
		key := serviceGuardKey(line[1], line)
		if !serviceGuardedCommands[key] || !serviceLaneReads[key] {
			t.Errorf("%v is not both guarded and a lane read", line[1:])
		}
		for _, goos := range []string{"linux", "darwin", "windows"} {
			if err := serviceGuard(goos, key, true, false); err != nil {
				t.Errorf("%s: %v was refused before it could ask the machine's bastion: %v", goos, line[1:], err)
			}
		}
	}
	for _, line := range [][]string{
		{"privatae-bastion", "backup", "reseal", "--sidecar", "f", "--to", "k"},
		{"privatae-bastion", "backup", "restore-plan", "--dir", "d"},
	} {
		if err := serviceGuard("windows", serviceGuardKey(line[1], line), true, false); err != nil {
			t.Errorf("windows: %v works offline and was refused: %v", line[1:], err)
		}
	}
}
