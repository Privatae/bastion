package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testOwnerSID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	testOtherSID = "S-1-5-21-1111111111-2222222222-3333333333-1002"
)

// writeSIDOwner records sid as the machine's owner, as `approvals-owner --sid`
// writes it on Windows.
func writeSIDOwner(t *testing.T, dir, sid string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(approvalsOwnerRecord{SID: sid, SetAt: time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(dir, approvalsOwnerFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The Windows ask pipe answers the owner's reads, acts and console for the
// account whose SID the installer recorded, and refuses every other one, in
// Windows' own commands: no sudo anywhere.
//
// MUTATION: compare p.UID in laneOwnerMatch for a Windows peer. RESULT: red
// (the owner's SID is refused).
func TestTheAskPipeServesTheOwnersSIDOnly(t *testing.T) {
	dir := isolateConfigDir(t)
	owner := askPeer{SID: testOwnerSID, Name: `DESKTOP\owner (` + testOwnerSID + `)`}
	other := askPeer{SID: testOtherSID, Name: `DESKTOP\other (` + testOtherSID + `)`}

	why := readLaneRefusalFor(owner)
	if !strings.Contains(why, "approvals-owner --sid "+testOwnerSID) || !strings.Contains(why, "Administrator terminal") {
		t.Errorf("with no owner recorded, the refusal does not give Windows' command: %q", why)
	}
	writeSIDOwner(t, dir, testOwnerSID)
	if why := readLaneRefusalFor(owner); why != "" {
		t.Errorf("the owner's SID was refused a read: %s", why)
	}
	if why := consoleLaneRefusalFor(owner); why != "" {
		t.Errorf("the owner's SID was refused the console: %s", why)
	}
	// Case differs between a SID read from a token and one typed.
	if why := readLaneRefusalFor(askPeer{SID: strings.ToLower(testOwnerSID), Name: "owner"}); why != "" {
		t.Errorf("the owner's SID in other case was refused: %s", why)
	}
	for _, why := range []string{readLaneRefusalFor(other), consoleLaneRefusalFor(other)} {
		if why == "" || !strings.Contains(why, testOwnerSID) || !strings.Contains(why, other.Name) {
			t.Errorf("another account was not refused, naming both: %q", why)
		}
		if strings.Contains(why, "sudo") {
			t.Errorf("a Windows refusal names sudo: %q", why)
		}
	}
	if r := serveActFor(other, agentAskRequest{Act: "deny", ID: "abcd1234"}); r.OK || r.User != other.Name {
		t.Errorf("another account's act: %+v", r)
	}
	// A record of the other platform's kind is no owner here.
	uid := uint32(1000)
	raw, _ := json.Marshal(approvalsOwnerRecord{UID: &uid, Account: "someone"})
	if err := os.WriteFile(filepath.Join(dir, approvalsOwnerFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if why := readLaneRefusalFor(owner); why == "" {
		t.Error("a uid record let a Windows SID through")
	}
}

// One dispatcher answers both lanes, so the pipe answers what the socket does.
func TestAskAnswerIsTheSocketsAnswer(t *testing.T) {
	isolateConfigDir(t)
	peer := askPeer{SID: testOwnerSID, Name: "owner"}
	var extended []time.Duration
	extend := func(d time.Duration) { extended = append(extended, d) }
	if r, ok := askAnswer(peer, agentAskRequest{Op: "read", Read: "approvals"}, extend, func() int { return 0 }).(agentReadReply); !ok || r.OK {
		t.Errorf("a read with no owner recorded: %+v", r)
	}
	if r, ok := askAnswer(peer, agentAskRequest{Op: "console"}, extend, func() int { return 0 }).(agentAskReply); !ok || r.OK || r.Why == "" {
		t.Errorf("the console with no owner recorded: %+v", r)
	}
	pid := 0
	if r, ok := askAnswer(peer, agentAskRequest{Op: "stop", PID: 4242}, extend, func() int { pid = 7; return 7 }).(agentAskReply); !ok || r.OK {
		t.Errorf("a stop with no code set up: %+v", r)
	}
	if pid != 7 {
		t.Error("a stop was filed without asking which process asked")
	}
	if len(extended) != 1 || extended[0] != readDeadline {
		t.Errorf("deadlines given: %v", extended)
	}
}

func TestAdminCommandsAreEachPlatformsOwn(t *testing.T) {
	if got := adminCommandFor(true, "ui"); strings.Contains(got, "sudo") || !strings.Contains(got, "Administrator terminal") {
		t.Errorf("windows: %q", got)
	}
	if got := adminCommandFor(false, "ui"); got != "sudo -H privatae-bastion ui" {
		t.Errorf("unix: %q", got)
	}
	if !strings.Contains(askPipeSDDL, "0x12019b;;;AU") || strings.Contains(askPipeSDDL, "GW;;;AU") || strings.Contains(askPipeSDDL, "GA;;;AU") {
		t.Errorf("the ask pipe's ACL gives every account more than read and write: %s", askPipeSDDL)
	}
}

// A page with no session names the command that opens it on this machine.
// The machine's console is not opened by "privatae-bastion ui" from just any
// account, and telling a person only that sent them back to a 401.
func TestNotSignedInNamesTheCommandThatOpensThisConsole(t *testing.T) {
	if got := notSignedIn("ui", "windows", true); !strings.Contains(got, "Administrator terminal") ||
		!strings.Contains(got, "owns this machine") || strings.Contains(got, "sudo") {
		t.Errorf("the Windows service's console: %q", got)
	}
	if got := notSignedIn("ui", "linux", true); !strings.Contains(got, "sudo -H privatae-bastion ui") ||
		!strings.Contains(got, "owns this machine") {
		t.Errorf("the root bastion's console: %q", got)
	}
	if got := notSignedIn("ui", "windows", false); !strings.Contains(got, "`privatae-bastion ui`") || strings.Contains(got, "Administrator") {
		t.Errorf("an account's own bastion: %q", got)
	}
	err := uiKeyRefused("127.0.0.1:7880", "401 Unauthorized", "windows", true, false)
	if s := err.Error(); !strings.Contains(s, winServiceName) || strings.Contains(s, "sudo") || strings.Contains(s, "restart it") {
		t.Errorf("a 401 beside the Windows service: %q", s)
	}
}

// A second start says what is running and how to reach it, and never that it
// should be ended: ending it was what the old words sent a person to do.
//
// MUTATION: drop the PID from secondRunWords. RESULT: red.
func TestASecondStartNamesTheRunningBastion(t *testing.T) {
	task := runHolder{PID: 4242, Program: `C:\Users\someone\AppData\Local\Programs\privatae-bastion\privatae-bastion.exe`,
		Started: "2026-11-02T18:02:00Z"}
	console, dialog := secondRunWords(task, true)
	for _, want := range []string{"4242", task.Program, "privatae-bastion ui", "Stop-Process -Id 4242"} {
		if !strings.Contains(console, want) || !strings.Contains(dialog.Body, want) {
			t.Errorf("the refusal does not say %q:\n%s\n%s", want, console, dialog.Body)
		}
	}
	svc, _ := secondRunWords(runHolder{PID: 9, Service: true}, true)
	if !strings.Contains(svc, "as the "+winServiceName+" service") || !strings.Contains(svc, "Restart-Service "+winServiceName) {
		t.Errorf("the service: %s", svc)
	}
	old, _ := secondRunWords(runHolder{}, false)
	if !strings.Contains(old, "Get-Process privatae-bastion") {
		t.Errorf("an older bastion holding the lock: %s", old)
	}
	for _, s := range []string{console, svc, old, dialog.Body} {
		if strings.Contains(s, "Task Manager") || strings.Contains(s, "believe the running one is dead") {
			t.Errorf("the refusal sends the person to end the running bastion: %s", s)
		}
	}
	dir := t.TempDir()
	writeRunHolder(dir, true)
	if h, ok := readRunHolder(dir); !ok || h.PID != os.Getpid() || !h.Console {
		t.Errorf("the holder record: %+v, %v", h, ok)
	}
}

// A bastion relaunched by its predecessor's update waits for it to exit and
// then takes the lock, where it used to refuse as a second copy and leave the
// machine with none.
func TestARelaunchedBastionWaitsForThePredecessorsLock(t *testing.T) {
	clock := time.Unix(0, 0)
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { clock = clock.Add(d) }
	held := 3
	try := func() error {
		if held > 0 {
			held--
			return os.ErrExist
		}
		return nil
	}
	waited := 0
	waitExit := func(pid int, d time.Duration) { waited = pid }
	if err := takeRunLock(try, 4242, waitExit, 30*time.Second, now, sleep); err != nil {
		t.Fatalf("the lock was not taken once the predecessor let go: %v", err)
	}
	if waited != 4242 {
		t.Errorf("waited on process %d", waited)
	}
	held = 1 << 30
	if err := takeRunLock(try, 4242, waitExit, 30*time.Second, now, sleep); err == nil {
		t.Fatal("a lock held for ever was taken")
	}
	held, waited = 1, 0
	if err := takeRunLock(try, 0, waitExit, 30*time.Second, now, sleep); err == nil || waited != 0 {
		t.Errorf("a start that replaces nothing waited, or retried: %v, %d", err, waited)
	}
	t.Setenv(relaunchOfEnv, "4242")
	if got := relaunchOf(); got != 4242 {
		t.Errorf("relaunchOf = %d", got)
	}
	if _, set := os.LookupEnv(relaunchOfEnv); set {
		t.Error("the predecessor's pid would pass on to what this bastion starts")
	}
}

// The Windows files wire it together: they are not built on Linux, so this
// reads them, as TestServiceModeOpensNothingOnTheDesktop does.
func TestTheWindowsFilesWireTheLaneTheCarryAndTheRelaunchWait(t *testing.T) {
	for file, wants := range map[string][]string{
		"relaunch_windows.go":   {`relaunchOfEnv+"="+strconv.Itoa(os.Getpid())`},
		"runguard_windows.go":   {"takeRunLock(", "relaunchOf()", "writeRunHolder(d,", "secondRunWords("},
		"sysservice_windows.go": {"carryStateInto(from, to)", "serviceCarrySource(serviceCarryFromSID)"},
		"asklane_windows.go":    {"askAnswer(peer, req", "pipeServerIsService(c.h)", "askPipeSDDL"},
		"agentask.go":           {"startAskPipe(done)"},
		"../deploy/install.ps1": {"service install --from-account $owner"},
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range wants {
			if !strings.Contains(string(src), w) {
				t.Errorf("%s no longer has %s", file, w)
			}
		}
	}
	// The carry runs before the service's first start, not after it.
	src, _ := os.ReadFile("sysservice_windows.go")
	s := string(src)
	if c, st := strings.Index(s, "carryStateInto(from, to)"), strings.Index(s, "s.Start()"); c < 0 || st < 0 || c > st {
		t.Error("the carry is not before the service starts, so the service would start with no pairing")
	}
}

// A process that started after the connection was made is not the one that
// made it: its id was freed and reused, and answering it would answer a
// stranger as whoever holds that id now.
func TestAPipeClientStartedAfterItsConnectionIsNotTheCaller(t *testing.T) {
	connected := time.Unix(1000, 0)
	if !pipeClientNewer(connected.Add(time.Millisecond), connected) {
		t.Error("a process created after the connection was taken for the caller")
	}
	if pipeClientNewer(connected.Add(-time.Hour), connected) {
		t.Error("the process that connected was refused")
	}
}
