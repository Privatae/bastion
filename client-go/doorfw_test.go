package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fwStandin plays this machine's firewall commands: netsh, ufw, firewall-cmd,
// socketfilterfw, nft and iptables, each with the state it would keep. Every
// command run is recorded, so a test can say what was never run.
type fwStandin struct {
	mu   sync.Mutex
	ran  []string
	fail map[string]bool // a verb that fails ("add")

	// Windows: rule name -> its add arguments.
	win map[string]string
	// ufw: on or off, and its rules as `ufw status` lists them.
	ufwOn    bool
	ufwRules []string
	// firewalld: running, ports now and permanently.
	fwdOn            bool
	fwdNow, fwdPerm  map[string]bool
	macOn, macAllIn  bool
	macApps          map[string]bool
	nftRuleset, ipts string
}

func newFWStandin() *fwStandin {
	return &fwStandin{fail: map[string]bool{}, win: map[string]string{}, fwdNow: map[string]bool{},
		fwdPerm: map[string]bool{}, macApps: map[string]bool{}}
}

var errExit1 = errors.New("exit status 1")

func (f *fwStandin) exec(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := path.Base(strings.ReplaceAll(name, `\`, "/")) + " " + strings.Join(args, " ")
	f.ran = append(f.ran, line)
	a := strings.Join(args, " ")
	switch path.Base(strings.ReplaceAll(name, `\`, "/")) {
	case "netsh.exe":
		if !strings.HasPrefix(a, "advfirewall firewall ") || len(args) < 5 {
			return "", fmt.Errorf("netsh: %s", a)
		}
		rule := strings.TrimPrefix(args[4], "name=")
		switch args[2] {
		case "show":
			if _, ok := f.win[rule]; ok {
				return "Rule Name: " + rule + "\n", nil
			}
			return "No rules match the specified criteria.\n", errExit1
		case "add":
			if f.fail["add"] {
				return "The requested operation requires elevation (Run as administrator).", errExit1
			}
			f.win[rule] = strings.Join(args[5:], " ")
			return "Ok.\n", nil
		case "delete":
			if _, ok := f.win[rule]; !ok {
				return "No rules match the specified criteria.\n", errExit1
			}
			delete(f.win, rule)
			return "\nDeleted 1 rule(s).\nOk.\n", nil
		}
	case "ufw":
		switch {
		case a == "status":
			if !f.ufwOn {
				return "Status: inactive\n", nil
			}
			return "Status: active\n\nTo                         Action      From\n--                         ------      ----\n" +
				strings.Join(f.ufwRules, "\n") + "\n", nil
		case strings.HasPrefix(a, "allow "):
			port := args[1]
			c := ""
			if len(args) == 4 && args[2] == "comment" {
				c = "                   # " + args[3]
			}
			f.ufwRules = append(f.ufwRules, port+"                   ALLOW       Anywhere"+c,
				port+" (v6)              ALLOW       Anywhere (v6)"+c)
			return "Rule added\nRule added (v6)\n", nil
		case strings.HasPrefix(a, "delete allow "):
			port := args[2]
			var keep []string
			for _, r := range f.ufwRules {
				if strings.Fields(r)[0] != port {
					keep = append(keep, r)
				}
			}
			if len(keep) == len(f.ufwRules) {
				return "Could not delete non-existent rule\n", errExit1
			}
			f.ufwRules = keep
			return "Rule deleted\nRule deleted (v6)\n", nil
		}
	case "firewall-cmd":
		perm := len(args) > 0 && args[0] == "--permanent"
		set := f.fwdNow
		if perm {
			set, args = f.fwdPerm, args[1:]
		}
		if len(args) == 0 {
			break
		}
		switch {
		case args[0] == "--state":
			if f.fwdOn {
				return "running\n", nil
			}
			return "not running\n", errors.New("exit status 252")
		case strings.HasPrefix(args[0], "--query-port="):
			if set[strings.TrimPrefix(args[0], "--query-port=")] {
				return "yes\n", nil
			}
			return "no\n", errExit1
		case strings.HasPrefix(args[0], "--add-port="):
			if perm && f.fail["permanent"] {
				return "Error: COMMAND_FAILED\n", errExit1
			}
			set[strings.TrimPrefix(args[0], "--add-port=")] = true
			return "success\n", nil
		case strings.HasPrefix(args[0], "--remove-port="):
			p := strings.TrimPrefix(args[0], "--remove-port=")
			if !set[p] {
				return "Warning: NOT_ENABLED: " + p + "\nsuccess\n", nil
			}
			delete(set, p)
			return "success\n", nil
		}
	case "socketfilterfw":
		switch args[0] {
		case "--getglobalstate":
			if f.macOn {
				return "Firewall is enabled. (State = 1)\n", nil
			}
			return "Firewall is disabled. (State = 0)\n", nil
		case "--getblockall":
			if f.macAllIn {
				return "Firewall is set to block all non-essential incoming connections\nBlock all ENABLED!\n", nil
			}
			return "Block all DISABLED!\n", nil
		case "--listapps":
			// As macOS before 15 prints it (developer.apple.com/forums/thread/757909).
			var b strings.Builder
			fmt.Fprintf(&b, "ALF: total number of apps = %d \n\n", len(f.macApps))
			var ps []string
			for p := range f.macApps {
				ps = append(ps, p)
			}
			sort.Strings(ps)
			for i, p := range ps {
				st := "Block"
				if f.macApps[p] {
					st = "Allow"
				}
				fmt.Fprintf(&b, "%d : %s ( %s incoming connections )\n", i+1, p, st)
			}
			return b.String(), nil
		case "--add":
			f.macApps[args[1]] = false
			return "The file " + args[1] + " added to firewall\n", nil
		case "--unblockapp":
			if f.fail["unblock"] {
				return "Error\n", errExit1
			}
			f.macApps[args[1]] = true
			return "Incoming connection to the application is permitted\n", nil
		case "--remove":
			delete(f.macApps, args[1])
			return "The file " + args[1] + " removed from firewall\n", nil
		}
	case "nft":
		return f.nftRuleset, nil
	case "iptables":
		return f.ipts, nil
	}
	return "", fmt.Errorf("the stand-in does not know %s", line)
}

func (f *fwStandin) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ran...)
}

// fwWorld stands the firewall in for goos, with the door wanted while *want.
func fwWorld(t *testing.T, goos string, root bool) (*fwStandin, *bool) {
	t.Helper()
	uiTestConfigDir(t)
	f := newFWStandin()
	want := true
	prevExec, prevFor, prevBy, prevHave, prevRoot, prevProg, prevWant, prevRead :=
		doorFWExec, doorFirewallFor, doorFirewallByID, doorFWHave, doorFWRoot, doorFWProgram, doorPortWanted, doorFWReadFile
	t.Cleanup(func() {
		doorFWExec, doorFirewallFor, doorFirewallByID, doorFWHave, doorFWRoot, doorFWProgram, doorPortWanted, doorFWReadFile =
			prevExec, prevFor, prevBy, prevHave, prevRoot, prevProg, prevWant, prevRead
	})
	doorFWExec = f.exec
	doorFirewallFor = func(port string) (doorFirewall, string) { return detectDoorFirewall(goos, port) }
	doorFirewallByID = func(id string) doorFirewall { return doorFirewallOf(goos, id) }
	doorFWHave = func(paths ...string) string { return paths[0] }
	doorFWRoot = func() bool { return root }
	doorFWProgram = func() (string, error) { return `C:\Program Files\Privatae\privatae-bastion.exe`, nil }
	doorPortWanted = func(string) bool { return want }
	doorFWReadFile = func(string) ([]byte, error) { return nil, errors.New("no such file") }
	return f, &want
}

func fwAudit(t *testing.T) string {
	t.Helper()
	d, _ := configDir()
	b, _ := os.ReadFile(filepath.Join(d, "pairing_audit.jsonl"))
	return string(b)
}

func countOp(t *testing.T, op string) int {
	return strings.Count(fwAudit(t), `"op":"`+op+`"`)
}

// Windows: the rule is the bastion's own by name, inbound, TCP on the door's
// port only, every profile, for this program only, made by netsh from
// System32. It is made once, kept while the door is in use, and removed when
// the last pairing and window are gone, each step in the audit and in status.
func TestTheWindowsRuleIsTheBastionsOwnAndGoesWithTheDoor(t *testing.T) {
	f, want := fwWorld(t, "windows", false)
	said := doorFirewallEnsure(":8812")
	rule := doorFWRuleName("8812")
	got, ok := f.win[rule]
	if !ok {
		t.Fatalf("no rule %q: %v", rule, f.commands())
	}
	for _, part := range []string{"dir=in", "action=allow", "protocol=TCP", "localport=8812",
		`program=C:\Program Files\Privatae\privatae-bastion.exe`, "profile=any", "enable=yes"} {
		if !strings.Contains(got, part) {
			t.Fatalf("the rule lacks %s: %s", part, got)
		}
	}
	for _, c := range f.commands() {
		if !strings.HasPrefix(c, "netsh.exe advfirewall firewall ") {
			t.Fatalf("ran %q", c)
		}
	}
	if !strings.HasPrefix(netshPath(), `C:\Windows\System32`) {
		t.Fatalf("netsh is not run by its absolute path: %s", netshPath())
	}
	if !strings.Contains(said, "added its own rule in Windows Firewall") {
		t.Fatalf("said %q", said)
	}
	// Again (the daemon's door after the window's): kept, not doubled.
	doorFirewallEnsure(":8812")
	if n := strings.Count(strings.Join(f.commands(), "\n"), " add rule "); n != 1 {
		t.Fatalf("%d adds", n)
	}
	s := readDoorFirewallStatus()
	if s == nil || len(s.Rules) != 1 || !strings.Contains(s.Rules[0], "Windows Firewall allows TCP 8812") {
		t.Fatalf("status: %+v", s)
	}
	// Still in use: the rule stays.
	doorFirewallRelease(":8812")
	if _, ok := f.win[rule]; !ok {
		t.Fatal("removed while the door is still in use")
	}
	// The last pairing and window gone: removed.
	*want = false
	doorFirewallRelease(":8812")
	if _, ok := f.win[rule]; ok {
		t.Fatal("the rule outlived the door")
	}
	if s := readDoorFirewallStatus(); s != nil {
		t.Fatalf("status after: %+v", s)
	}
	if countOp(t, "door_firewall_opened") != 1 || countOp(t, "door_firewall_closed") != 1 {
		t.Fatalf("the audit:\n%s", fwAudit(t))
	}
	// MUTATION: release removes nothing. RESULT: red, "the rule outlived the door".
	// MUTATION: the add drops program=. RESULT: red, "the rule lacks program=".
	// MUTATION: ensure adds without asking has(). RESULT: red, "2 adds".
}

// Windows: the bastion moved (another path): its rule is replaced by one for
// the new path; and an add refused (no administrator) is said once, with the
// command that does it by hand, in status and doctor.
func TestTheWindowsRuleFollowsTheProgramAndAFailureIsSaidOnce(t *testing.T) {
	f, _ := fwWorld(t, "windows", false)
	doorFirewallEnsure(":8812")
	doorFWProgram = func() (string, error) { return `D:\Privatae\privatae-bastion.exe`, nil }
	doorFirewallEnsure(":8812")
	if got := f.win[doorFWRuleName("8812")]; !strings.Contains(got, `program=D:\Privatae\privatae-bastion.exe`) {
		t.Fatalf("the rule names %s", got)
	}
	if st := loadDoorFW(); len(st.Rules) != 1 || st.Rules[0].Program != `D:\Privatae\privatae-bastion.exe` {
		t.Fatalf("the record: %+v", st.Rules)
	}

	g, _ := fwWorld(t, "windows", false)
	g.fail["add"] = true
	doorFirewallEnsure(":8812")
	doorFirewallEnsure(":8812")
	if n := countOp(t, "door_firewall_failed"); n != 1 {
		t.Fatalf("the failure audited %d times", n)
	}
	s := readDoorFirewallStatus()
	if s == nil || len(s.Needs) != 1 || !strings.Contains(s.Needs[0], "New-NetFirewallRule") {
		t.Fatalf("status: %+v", s)
	}
	cs := doorFirewallChecks(s)
	if len(cs) != 1 || cs[0].OK || !strings.Contains(cs[0].Problem, "TCP 8812") {
		t.Fatalf("doctor: %+v", cs)
	}
	// MUTATION: the program is not compared. RESULT: red, the rule names the old path.
	// MUTATION: the note is audited on every ensure. RESULT: red, audited 2 times.
}

// Linux ufw: a rule only while ufw is on, with the bastion's comment; ufw is
// never turned on, off or reset; a rule of the machine's own for the port is
// neither doubled nor removed.
func TestTheUfwRuleIsAddedOnlyWhenUfwIsOnAndNeverTheMachinesOwn(t *testing.T) {
	f, want := fwWorld(t, "linux", true)
	// Off: nothing at all.
	if said := doorFirewallEnsure(":8812"); said != "" || len(loadDoorFW().Rules) != 0 {
		t.Fatalf("ufw off: %q %v", said, f.commands())
	}
	f.ufwOn = true
	doorFirewallEnsure(":8812")
	st := strings.Join(f.ufwRules, "\n")
	if !strings.Contains(st, "8812/tcp") || !strings.Contains(st, "# "+doorFWComment) {
		t.Fatalf("ufw rules: %s", st)
	}
	if s := readDoorFirewallStatus(); s == nil || len(s.Rules) != 1 || !strings.Contains(s.Rules[0], "ufw allows TCP 8812") {
		t.Fatalf("status: %+v", s)
	}
	*want = false
	doorFirewallRelease(":8812")
	if len(f.ufwRules) != 0 {
		t.Fatalf("left: %v", f.ufwRules)
	}
	for _, c := range f.commands() {
		for _, never := range []string{"ufw enable", "ufw disable", "ufw reset", "ufw default", "ufw reload"} {
			if strings.HasPrefix(c, never) {
				t.Fatalf("ran %q", c)
			}
		}
	}

	// The machine's own rule for the port.
	g, want2 := fwWorld(t, "linux", true)
	g.ufwOn = true
	g.ufwRules = []string{"8812/tcp                   ALLOW       Anywhere", "8812/tcp (v6)              ALLOW       Anywhere (v6)"}
	said := doorFirewallEnsure(":8812")
	if !strings.Contains(said, "already allowed") || len(g.ufwRules) != 2 {
		t.Fatalf("said %q, rules %v", said, g.ufwRules)
	}
	*want2 = false
	doorFirewallRelease(":8812")
	if len(g.ufwRules) != 2 {
		t.Fatalf("the machine's own rule was removed: %v", g.commands())
	}
	// MUTATION: ufwRuleFor counts any ALLOW as ours. RESULT: red, the machine's own rule was removed.
	// MUTATION: detection ignores "Status: inactive". RESULT: red, ufw off.
}

// Linux firewalld: the port added now and permanently, and removed the same
// way; a port already open in it is the machine's own.
func TestTheFirewalldPortIsAddedAndRemovedNowAndPermanently(t *testing.T) {
	f, want := fwWorld(t, "linux", true)
	f.fwdOn = true
	doorFirewallEnsure(":8812")
	if !f.fwdNow["8812/tcp"] || !f.fwdPerm["8812/tcp"] {
		t.Fatalf("firewalld: %v %v", f.fwdNow, f.fwdPerm)
	}
	doorFirewallEnsure(":8812")
	if n := strings.Count(strings.Join(f.commands(), "\n"), "--add-port"); n != 2 {
		t.Fatalf("%d adds: %v", n, f.commands())
	}
	*want = false
	doorFirewallRelease(":8812")
	if f.fwdNow["8812/tcp"] || f.fwdPerm["8812/tcp"] {
		t.Fatalf("left: %v %v", f.fwdNow, f.fwdPerm)
	}

	g, want2 := fwWorld(t, "linux", true)
	g.fwdOn = true
	g.fwdNow["8812/tcp"], g.fwdPerm["8812/tcp"] = true, true
	doorFirewallEnsure(":8812")
	*want2 = false
	doorFirewallRelease(":8812")
	if !g.fwdNow["8812/tcp"] || !g.fwdPerm["8812/tcp"] {
		t.Fatal("the machine's own open port was closed")
	}
	// MUTATION: remove only the runtime port. RESULT: red, left permanently.
	// MUTATION: has() reports a port it did not add as ours. RESULT: red, the machine's own port closed.
}

// Linux: a firewall the bastion does not manage (nftables, iptables), or ufw
// it may not change, is said once, with what to allow, in status and doctor,
// and nothing in it is changed.
func TestAFirewallTheBastionDoesNotManageIsSaidOnceAndLeftAlone(t *testing.T) {
	f, want := fwWorld(t, "linux", true)
	f.nftRuleset = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	said := doorFirewallEnsure(":8812")
	doorFirewallEnsure(":8812")
	if !strings.Contains(said, "nftables") || !strings.Contains(said, "tcp dport 8812 accept") {
		t.Fatalf("said %q", said)
	}
	if n := countOp(t, "door_firewall_unmanaged"); n != 1 {
		t.Fatalf("said %d times", n)
	}
	for _, c := range f.commands() {
		if strings.HasPrefix(c, "nft ") && c != "nft list ruleset" {
			t.Fatalf("ran %q", c)
		}
	}
	s := readDoorFirewallStatus()
	if s == nil || len(s.Needs) != 1 || !strings.Contains(s.Needs[0], "nftables") {
		t.Fatalf("status: %+v", s)
	}
	if cs := doorFirewallChecks(s); len(cs) != 1 || cs[0].OK {
		t.Fatalf("doctor: %+v", cs)
	}
	*want = false
	doorFirewallRelease(":8812")
	if s := readDoorFirewallStatus(); s != nil {
		t.Fatalf("still said with no door: %+v", s)
	}

	// iptables, and an account that may not change ufw.
	g, _ := fwWorld(t, "linux", true)
	g.ipts = "-P INPUT DROP\n"
	if said := doorFirewallEnsure(":8812"); !strings.Contains(said, "iptables -I INPUT -p tcp --dport 8812 -j ACCEPT") {
		t.Fatalf("iptables: %q", said)
	}
	h, _ := fwWorld(t, "linux", false)
	doorFWReadFile = func(string) ([]byte, error) { return []byte("ENABLED=yes\n"), nil }
	if said := doorFirewallEnsure(":8812"); !strings.Contains(said, "sudo ufw allow 8812/tcp") {
		t.Fatalf("not root: %q", said)
	}
	for _, c := range h.commands() {
		if strings.HasPrefix(c, "ufw ") {
			t.Fatalf("an account that may not change ufw ran %q", c)
		}
	}
	// MUTATION: nftFiltersInput always false. RESULT: red, said "".
	// MUTATION: the note is not cleared at release. RESULT: red, still said with no door.
}

// macOS: with the application firewall on, this program is allowed; with it
// off nothing is done; "block all incoming" is only said.
func TestTheMacFirewallAllowsTheProgramOnlyWhenItIsOn(t *testing.T) {
	f, want := fwWorld(t, "darwin", true)
	doorFirewallEnsure(":8812")
	if len(f.macApps) != 0 {
		t.Fatal("added with the firewall off")
	}
	f.macOn = true
	doorFirewallEnsure(":8812")
	prog, _ := doorFWProgram()
	if allowed, ok := f.macApps[prog]; !ok || !allowed {
		t.Fatalf("apps: %v", f.macApps)
	}
	*want = false
	doorFirewallRelease(":8812")
	if len(f.macApps) != 0 {
		t.Fatalf("left: %v", f.macApps)
	}
	g, _ := fwWorld(t, "darwin", true)
	g.macOn, g.macAllIn = true, true
	if said := doorFirewallEnsure(":8812"); !strings.Contains(said, "blocks all incoming") || len(g.macApps) != 0 {
		t.Fatalf("block all: %q %v", said, g.macApps)
	}
	// MUTATION: --unblockapp not run. RESULT: red, apps not allowed.
}

// uninstall removes every rule the bastion added, whatever uses the door.
func TestUninstallRemovesTheDoorsOwnRules(t *testing.T) {
	f, _ := fwWorld(t, "windows", false)
	doorFirewallEnsure(":8812")
	doorFirewallEnsure(":9443")
	said, err := doorFirewallRemoveAll()
	if err != nil || len(said) != 2 || len(f.win) != 0 {
		t.Fatalf("uninstall: %v %v, left %v", said, err, f.win)
	}
	if len(loadDoorFW().Rules) != 0 {
		t.Fatal("the record outlived the rules")
	}
	// MUTATION: RemoveAll skips the removal. RESULT: red, rules left.
}

// A rule left behind (a `pair --open` killed before its release, a pairing
// that went while nothing ran) is removed by the daemon's sweep once nothing
// uses its port, and kept while something does.
func TestTheDaemonsSweepRemovesARuleNothingUses(t *testing.T) {
	f, want := fwWorld(t, "windows", false)
	doorFirewallEnsure(":8812")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { doorFirewallSweep(ctx); close(done) }()
	cancel()
	<-done
	if _, ok := f.win[doorFWRuleName("8812")]; !ok {
		t.Fatal("the sweep removed a rule in use")
	}
	*want = false
	doorFirewallReleaseUnused()
	if _, ok := f.win[doorFWRuleName("8812")]; ok {
		t.Fatal("the sweep left a rule nothing uses")
	}
	// MUTATION: doorFirewallReleaseUnused skips recorded rules. RESULT: red, the sweep left a rule.
}

// ufw deletes by rule, whatever its comment: a rule the bastion recorded and
// the person later replaced with their own, or a record that names a port the
// bastion never opened, is the machine's, and is never removed.
func TestUfwNeverRemovesARuleThatIsNotItsOwnWhateverTheRecordSays(t *testing.T) {
	f, want := fwWorld(t, "linux", true)
	f.ufwOn = true
	doorFirewallEnsure(":8812")
	// The person deletes the bastion's rule and puts their own in its place.
	f.ufwRules = []string{"8812/tcp                   ALLOW       Anywhere", "8812/tcp (v6)              ALLOW       Anywhere (v6)"}
	doorFirewallEnsure(":8812")
	*want = false
	doorFirewallRelease(":8812")
	if len(f.ufwRules) != 2 {
		t.Fatalf("the person's own rule was removed: %v", f.commands())
	}

	// A record naming a port the bastion never opened (written by hand, or
	// left from another time): the sweep leaves the machine's rule there.
	g, want2 := fwWorld(t, "linux", true)
	g.ufwOn = true
	g.ufwRules = []string{"22/tcp                     ALLOW       Anywhere"}
	if err := saveDoorFW(doorFWState{Rules: []doorFWRule{{Firewall: "ufw", Port: "22", Added: "2026-01-01T00:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	*want2 = false
	doorFirewallReleaseUnused()
	for _, c := range g.commands() {
		if strings.HasPrefix(c, "ufw delete") {
			t.Fatalf("ran %q on a rule that is not the bastion's", c)
		}
	}
	if len(g.ufwRules) != 1 || len(loadDoorFW().Rules) != 0 {
		t.Fatalf("rules %v, record %+v", g.ufwRules, loadDoorFW().Rules)
	}
	// MUTATION: ufw remove deletes without reading the comment. RESULT: red, the person's own rule was removed.
}

// Only a rule that lets a Host in from anywhere counts as the machine's own
// allow: an outbound rule, or one for one source or interface, does not, so
// the bastion adds its own rather than saying the port is already allowed.
func TestUfwAnOutboundOrOneSourceRuleIsNotTheWayIn(t *testing.T) {
	for _, r := range []string{
		"8812/tcp                   ALLOW OUT   Anywhere",
		"8812/tcp                   ALLOW       10.0.0.0/8",
		"8812/tcp on eth1           ALLOW       Anywhere",
		"8812/tcp                   DENY        Anywhere",
	} {
		f, _ := fwWorld(t, "linux", true)
		f.ufwOn = true
		f.ufwRules = []string{r}
		said := doorFirewallEnsure(":8812")
		if !strings.Contains(said, "added its own rule in ufw") {
			t.Fatalf("with %q: said %q", r, said)
		}
	}
	for _, r := range []string{
		"8812/tcp                   ALLOW       Anywhere",
		"8812/tcp                   ALLOW IN    Anywhere",
		"8812 (v6)                  ALLOW       Anywhere (v6)",
	} {
		if _, other := ufwRuleFor(r, "8812"); !other {
			t.Fatalf("%q lets a Host in from anywhere", r)
		}
	}
	// MUTATION: any line with ALLOW counts. RESULT: red, said "already allowed".
}

// firewalld: a permanent add that fails takes the runtime port back out, so
// no open port is left that no record says is the bastion's.
func TestFirewalldAFailedPermanentAddLeavesNoPortOpen(t *testing.T) {
	f, _ := fwWorld(t, "linux", true)
	f.fwdOn = true
	f.fail["permanent"] = true
	said := doorFirewallEnsure(":8812")
	if !strings.Contains(said, "could not add") {
		t.Fatalf("said %q", said)
	}
	if f.fwdNow["8812/tcp"] {
		t.Fatalf("the runtime port was left open with no record: %v", f.commands())
	}
	// Next time it is tried again, not taken for the machine's own.
	f.fail["permanent"] = false
	if said := doorFirewallEnsure(":8812"); !strings.Contains(said, "added its own rule") {
		t.Fatalf("said %q", said)
	}
	// MUTATION: no undo of the runtime add. RESULT: red, the runtime port was left open.
}

// macOS: an --unblockapp that fails takes the --add back out, so no entry is
// left that would read as the machine's own and never go.
func TestTheMacAFailedUnblockLeavesNoEntry(t *testing.T) {
	f, _ := fwWorld(t, "darwin", true)
	f.macOn = true
	f.fail["unblock"] = true
	if said := doorFirewallEnsure(":8812"); !strings.Contains(said, "could not add") {
		t.Fatalf("said %q", said)
	}
	if len(f.macApps) != 0 {
		t.Fatalf("left an entry with no record: %v", f.macApps)
	}
	// MUTATION: no --remove after a failed --unblockapp. RESULT: red, left an entry.
}

// realDoorPortWanted is the door-in-use check fwWorld stands in.
var realDoorPortWanted = doorPortWanted

// sweepOnce runs the daemon's sweep's first pass.
func sweepOnce() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	doorFirewallSweep(ctx)
}

// A door claims the window (its file is moved aside) before the pairing is
// saved: between the two, neither is there to read. The window is still in
// use then, so a sweep in that gap keeps the rule, and puts it back if it had
// gone; once the window has its result and no pairing uses the port, the
// rule goes.
func TestAWindowClaimedForAPairingStillBeingSavedKeepsTheRule(t *testing.T) {
	f, _ := fwWorld(t, "windows", false)
	doorPortWanted = realDoorPortWanted
	code, err := newWindowCode()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	w := &pairWindow{ID: "w-claimed", Code: code, Door: ":8812", Opened: now.Format(time.RFC3339),
		Expires: now.Add(windowLifetime).Format(time.RFC3339)}
	if err := saveWindowFile(w); err != nil {
		t.Fatal(err)
	}
	doorFirewallEnsure(":8812")
	rule := doorFWRuleName("8812")
	if _, ok := f.win[rule]; !ok {
		t.Fatalf("no rule for the open window: %v", f.commands())
	}
	if !claimWindow(w.ID) {
		t.Fatal("the window could not be claimed")
	}
	sweepOnce()
	if _, ok := f.win[rule]; !ok {
		t.Fatal("the sweep removed the rule while a pairing on the window was being saved")
	}
	// The rule gone in that gap (by hand, or a release that ran then): back.
	delete(f.win, rule)
	sweepOnce()
	if _, ok := f.win[rule]; !ok {
		t.Fatal("the sweep did not put back the rule of a window still in use")
	}
	endWindow(w.ID, windowResult{Error: "the Host refused"})
	sweepOnce()
	if _, ok := f.win[rule]; ok {
		t.Fatal("the rule outlived the window")
	}
	// MUTATION: doorPortsInUse ignores a claimed window. RESULT: red, the sweep removed the rule while a pairing ... was being saved.
	// MUTATION: claimedWindowUnderWay counts a window with its result. RESULT: red, the rule outlived the window.
}

// A rule that goes while its door is in use (removed by hand, the firewall
// reset) is put back by the daemon's sweep; a port a rule of the machine's
// own allows is still never given a second one; nothing in use, nothing added.
func TestTheSweepPutsBackARuleThatWentWhileTheDoorIsInUse(t *testing.T) {
	f, want := fwWorld(t, "windows", false)
	doorFirewallEnsure(":8812")
	rule := doorFWRuleName("8812")
	delete(f.win, rule) // removed by hand
	sweepOnce()
	if got, ok := f.win[rule]; !ok || !strings.Contains(got, "localport=8812") {
		t.Fatalf("not put back: %v", f.commands())
	}
	if n := countOp(t, "door_firewall_opened"); n != 2 {
		t.Fatalf("opened %d times:\n%s", n, fwAudit(t))
	}
	*want = false
	sweepOnce()
	if _, ok := f.win[rule]; ok {
		t.Fatal("a rule nothing uses was kept")
	}
	sweepOnce()
	if _, ok := f.win[rule]; ok {
		t.Fatal("the sweep added a rule nothing uses")
	}

	// ufw: the bastion's rule deleted while the door is in use, back with its comment.
	g, _ := fwWorld(t, "linux", true)
	g.ufwOn = true
	doorFirewallEnsure(":8812")
	g.ufwRules = nil
	sweepOnce()
	if st := strings.Join(g.ufwRules, "\n"); !strings.Contains(st, "8812/tcp") || !strings.Contains(st, "# "+doorFWComment) {
		t.Fatalf("ufw not put back: %v", g.commands())
	}

	// ufw: the machine's own rule allows the port: never a second one.
	h, _ := fwWorld(t, "linux", true)
	h.ufwOn = true
	h.ufwRules = []string{"8812/tcp                   ALLOW       Anywhere"}
	doorFirewallEnsure(":8812")
	sweepOnce()
	sweepOnce()
	for _, c := range h.commands() {
		if strings.HasPrefix(c, "ufw allow") {
			t.Fatalf("ran %q with the machine's own rule there", c)
		}
	}
	// MUTATION: the sweep only releases. RESULT: red, not put back (and in
	// TestAWindowClaimedForAPairingStillBeingSavedKeepsTheRule).
}

// macOS: an entry is for one program path; the bastion that moved removes the
// entry by the path it recorded, both when its door is released and when it
// makes the entry for its new path.
func TestTheMacEntryIsRemovedByThePathItWasAddedFor(t *testing.T) {
	const a, b = "/usr/local/bin/privatae-bastion", "/opt/example/privatae-bastion"
	f, want := fwWorld(t, "darwin", true)
	f.macOn = true
	doorFWProgram = func() (string, error) { return a, nil }
	doorFirewallEnsure(":8812")
	if !f.macApps[a] {
		t.Fatalf("apps: %v", f.macApps)
	}
	doorFWProgram = func() (string, error) { return b, nil }
	*want = false
	doorFirewallRelease(":8812")
	if len(f.macApps) != 0 {
		t.Fatalf("the moved bastion left its old path allowed: %v", f.macApps)
	}

	// Moved while the door is in use: the old path's entry goes, the new one's is made.
	g, _ := fwWorld(t, "darwin", true)
	g.macOn = true
	doorFWProgram = func() (string, error) { return a, nil }
	doorFirewallEnsure(":8812")
	doorFWProgram = func() (string, error) { return b, nil }
	doorFirewallEnsure(":8812")
	if _, ok := g.macApps[a]; ok || !g.macApps[b] {
		t.Fatalf("apps: %v", g.macApps)
	}
	if st := loadDoorFW(); len(st.Rules) != 1 || st.Rules[0].Program != b {
		t.Fatalf("the record: %+v", st.Rules)
	}
	// MUTATION: remove uses this program's path, not the record's. RESULT: red, the moved bastion left its old path allowed.
	// MUTATION: the moved case removes this program's path. RESULT: red, apps: both paths.
}

// macOS: --listapps is read entry by entry, by the exact path, and only an
// "allow incoming" entry counts: a blocked entry is the person's setting and
// is said, not changed; a longer path (…/privatae-bastion.old) is not this
// program's.
func TestTheMacReadsEachEntryAndCountsOnlyAnAllow(t *testing.T) {
	const prog = "/usr/local/bin/privatae-bastion"
	f, _ := fwWorld(t, "darwin", true)
	f.macOn = true
	doorFWProgram = func() (string, error) { return prog, nil }
	f.macApps[prog] = false // the person blocked it
	said := doorFirewallEnsure(":8812")
	if !strings.Contains(said, "block incoming connections for this program") {
		t.Fatalf("said %q", said)
	}
	for _, c := range f.commands() {
		if strings.Contains(c, "--unblockapp") || strings.Contains(c, "--add") || strings.Contains(c, "--remove") {
			t.Fatalf("changed the person's setting: %q", c)
		}
	}
	if s := readDoorFirewallStatus(); s == nil || len(s.Needs) != 1 {
		t.Fatalf("status: %+v", s)
	}

	g, _ := fwWorld(t, "darwin", true)
	g.macOn = true
	doorFWProgram = func() (string, error) { return prog, nil }
	g.macApps[prog+".old"] = true
	if said := doorFirewallEnsure(":8812"); !strings.Contains(said, "added its own rule") || !g.macApps[prog] {
		t.Fatalf("a longer path counted as this program: said %q, apps %v", said, g.macApps)
	}

	// Its own entry, later set to block by the person: left as it is at release.
	h, want := fwWorld(t, "darwin", true)
	h.macOn = true
	doorFWProgram = func() (string, error) { return prog, nil }
	doorFirewallEnsure(":8812")
	h.macApps[prog] = false
	*want = false
	doorFirewallRelease(":8812")
	if allowed, ok := h.macApps[prog]; !ok || allowed {
		t.Fatalf("the person's block was removed: %v", h.macApps)
	}
	// MUTATION: has() counts a listed program whatever its state. RESULT: red, said "already allowed".
	// MUTATION: the path is matched as a prefix. RESULT: red, a longer path counted as this program.
	// MUTATION: remove runs --remove on a blocked entry. RESULT: red, the person's block was removed.
}
