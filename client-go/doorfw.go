package main

// doorfw.go: the door's own inbound rule in this machine's firewall.
//
// A Host connects to the door (hostdoor.go) on TCP 8812, and a firewall on
// this machine that drops inbound connections drops it: Windows Firewall does
// by default on the Public profile. The person never has to touch a firewall,
// so while the door is in use (a pairing whose Host connects here is active,
// or a pairing window is open) the bastion keeps a rule of its own that allows
// the door's port, and when the last such pairing and window are gone it
// removes that rule again. `uninstall` removes it too.
//
//   - Windows: an inbound allow rule for TCP <port>, all profiles, for this
//     program's own path only, named "Privatae bastion: your Host connects
//     (TCP <port>)", made with netsh from System32 by its absolute path.
//   - Linux: only a firewall the bastion recognises and that is on: ufw (a
//     rule allowing <port>/tcp, with the comment "privatae-bastion: your Host
//     connects") or firewalld (the port added to the default zone, now and
//     permanently). It never turns a firewall on, off or changes anything else
//     in it. Rules of another kind (nftables, iptables) are the machine's own:
//     the bastion says once, in status and doctor, what to allow.
//   - macOS: the application firewall, when it is on, is told to allow this
//     program (socketfilterfw --add, --unblockapp); "block all incoming" is
//     the person's choice and is only reported.
//
// A port another rule of the machine already allows is left alone: the
// bastion neither adds a second rule nor removes that one. It removes only the
// rules it recorded adding (door-firewall.json in its state). Every add and
// remove, and a firewall it can't manage, is written to the pairing audit.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// doorFWComment marks the bastion's own ufw rule.
	doorFWComment = "privatae-bastion: your Host connects"
	// doorFWAnyPort is the port of a rule that allows the program on every
	// port (macOS's application firewall is per program, not per port).
	doorFWAnyPort = "*"
	// doorFWExecWait bounds one firewall command: the daemon calls them.
	doorFWExecWait = 30 * time.Second
)

// doorFWRuleName is the Windows Firewall rule for port: recognisably the
// bastion's, and one per port.
func doorFWRuleName(port string) string {
	return "Privatae bastion: your Host connects (TCP " + port + ")"
}

// doorFWExec runs one firewall command by its absolute path and returns its
// output. A variable: the suite never runs the machine's own firewall
// (main_test.go), and the tests stand the firewalls in.
var doorFWExec = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), doorFWExecWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// doorFWHave is the first of these paths that exists, or "".
var doorFWHave = func(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// doorFWReadFile reads a firewall's own configuration file.
var doorFWReadFile = os.ReadFile

// doorFWProgram is this program's own path, which a Windows or macOS rule
// names.
var doorFWProgram = resolvedSelf

// doorFWRoot: this process may change the machine's firewall on Linux.
var doorFWRoot = processIsRoot

// doorFirewall is one firewall the bastion can keep its rule in.
type doorFirewall interface {
	// id is the firewall in the state file: "windows", "ufw", "firewalld",
	// "macos". name is the firewall in the person's words.
	id() string
	name() string
	// has: ours, the bastion's own rule for port is there; other, port is
	// already allowed by a rule of the machine's own.
	has(port string) (ours, other bool, err error)
	add(port string) error
	// remove takes out the bastion's own rule for port; prog is the program
	// its record names (a Windows or macOS rule is for one program path, and
	// the bastion may have moved since it added it).
	remove(port, prog string) error
	// manual is what the person runs to allow port by hand.
	manual(port string) string
}

// doorFirewallFor is this machine's firewall the bastion manages, or nil and
// what the person needs to know ("" when there is nothing to say: no
// firewall that filters inbound connections here was found).
var doorFirewallFor = func(port string) (doorFirewall, string) { return detectDoorFirewall(runtime.GOOS, port) }

// doorFirewallByID is the firewall a recorded rule was added to, to remove it.
var doorFirewallByID = func(id string) doorFirewall { return doorFirewallOf(runtime.GOOS, id) }

func doorFirewallOf(goos, id string) doorFirewall {
	switch id {
	case "windows":
		return winFirewall{netsh: netshPath()}
	case "ufw":
		if p := doorFWHave("/usr/sbin/ufw", "/sbin/ufw"); p != "" {
			return ufwFirewall{bin: p}
		}
	case "firewalld":
		if p := doorFWHave("/usr/bin/firewall-cmd", "/bin/firewall-cmd", "/usr/sbin/firewall-cmd"); p != "" {
			return firewalldFirewall{bin: p}
		}
	case "macos":
		return macFirewall{bin: macSocketFilter}
	}
	return nil
}

// netshPath is netsh.exe in System32, by its absolute path.
func netshPath() string {
	return filepath.Join(systemDir(), "netsh.exe")
}

const macSocketFilter = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// detectDoorFirewall finds the firewall of goos that filters inbound
// connections here.
func detectDoorFirewall(goos, port string) (doorFirewall, string) {
	switch goos {
	case "windows":
		return winFirewall{netsh: netshPath()}, ""
	case "darwin":
		return detectMacFirewall()
	case "linux":
		return detectLinuxFirewall(port)
	}
	return nil, ""
}

func detectLinuxFirewall(port string) (doorFirewall, string) {
	ufw := doorFWHave("/usr/sbin/ufw", "/sbin/ufw")
	fwd := doorFWHave("/usr/bin/firewall-cmd", "/bin/firewall-cmd", "/usr/sbin/firewall-cmd")
	if !doorFWRoot() {
		// ufw and firewalld take root; an account's own bastion can only say so.
		if ufw != "" {
			if raw, err := doorFWReadFile("/etc/ufw/ufw.conf"); err == nil && ufwConfEnabled(string(raw)) {
				return nil, "ufw is on here, and this bastion runs as an account that cannot change it. Allow TCP " + port + " inbound: " + ufwFirewall{}.manual(port)
			}
		}
		if fwd != "" {
			if out, err := doorFWExec(fwd, "--state"); err == nil && strings.TrimSpace(out) == "running" {
				return nil, "firewalld is on here, and this bastion runs as an account that cannot change it. Allow TCP " + port + " inbound: " + firewalldFirewall{}.manual(port)
			}
		}
		return nil, ""
	}
	if ufw != "" {
		if out, err := doorFWExec(ufw, "status"); err == nil && ufwActive(out) {
			return ufwFirewall{bin: ufw}, ""
		}
	}
	if fwd != "" {
		if out, err := doorFWExec(fwd, "--state"); err == nil && strings.TrimSpace(out) == "running" {
			return firewalldFirewall{bin: fwd}, ""
		}
	}
	if nft := doorFWHave("/usr/sbin/nft", "/sbin/nft"); nft != "" {
		if out, err := doorFWExec(nft, "list", "ruleset"); err == nil && nftFiltersInput(out) {
			return nil, "this server filters inbound connections with nftables rules of its own, which the bastion does not change. " +
				"Allow TCP " + port + " inbound in the chain on the input hook, for example: nft add rule inet filter input tcp dport " + port + " accept"
		}
	}
	if ipt := doorFWHave("/usr/sbin/iptables", "/sbin/iptables"); ipt != "" {
		if out, err := doorFWExec(ipt, "-S", "INPUT"); err == nil && iptablesFiltersInput(out) {
			return nil, "this server filters inbound connections with iptables rules of its own, which the bastion does not change. " +
				"Allow TCP " + port + " inbound, for example: iptables -I INPUT -p tcp --dport " + port + " -j ACCEPT, kept the way this server keeps its rules"
		}
	}
	return nil, ""
}

func detectMacFirewall() (doorFirewall, string) {
	out, err := doorFWExec(macSocketFilter, "--getglobalstate")
	if err != nil || !strings.Contains(strings.ToLower(out), "enabled") {
		return nil, ""
	}
	if all, err := doorFWExec(macSocketFilter, "--getblockall"); err == nil && macBlockAll(all) {
		return nil, "this Mac's firewall blocks all incoming connections, a setting the bastion does not change. Your Host can connect once " +
			"System Settings > Network > Firewall > Options no longer blocks all incoming connections"
	}
	return macFirewall{bin: macSocketFilter}, ""
}

// ufwConfEnabled reads ENABLED=yes from /etc/ufw/ufw.conf.
func ufwConfEnabled(conf string) bool {
	for _, l := range strings.Split(conf, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "ENABLED=") {
			v := strings.Trim(strings.TrimPrefix(l, "ENABLED="), `"' `)
			return strings.EqualFold(v, "yes")
		}
	}
	return false
}

// ufwActive reads `ufw status`'s first line.
func ufwActive(status string) bool {
	return parseUfwStatus(status) == "active"
}

// nftFiltersInput: a chain on the input hook that can drop or reject.
func nftFiltersInput(ruleset string) bool {
	if !strings.Contains(ruleset, "hook input") {
		return false
	}
	return strings.Contains(ruleset, "policy drop") || strings.Contains(ruleset, " drop") || strings.Contains(ruleset, " reject")
}

// iptablesFiltersInput: INPUT drops by policy or by a rule.
func iptablesFiltersInput(rules string) bool {
	return strings.Contains(rules, "-P INPUT DROP") || strings.Contains(rules, "-j DROP") || strings.Contains(rules, "-j REJECT")
}

func macBlockAll(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "block all enabled") || strings.Contains(o, "(state = 1)")
}

// ── the firewalls ────────────────────────────────────────────────────────────

type winFirewall struct{ netsh string }

func (winFirewall) id() string   { return "windows" }
func (winFirewall) name() string { return "Windows Firewall" }

func (f winFirewall) has(port string) (bool, bool, error) {
	// netsh exits 0 when a rule of that name exists, 1 with "No rules match".
	_, err := doorFWExec(f.netsh, "advfirewall", "firewall", "show", "rule", "name="+doorFWRuleName(port))
	return err == nil, false, nil
}

func (f winFirewall) add(port string) error {
	prog, err := doorFWProgram()
	if err != nil {
		return fmt.Errorf("this program's path: %w", err)
	}
	out, err := doorFWExec(f.netsh, "advfirewall", "firewall", "add", "rule",
		"name="+doorFWRuleName(port), "dir=in", "action=allow", "protocol=TCP", "localport="+port,
		"program="+prog, "profile=any", "enable=yes", "edge=no")
	return fwErr(err, out)
}

func (f winFirewall) remove(port, _ string) error {
	out, err := doorFWExec(f.netsh, "advfirewall", "firewall", "delete", "rule", "name="+doorFWRuleName(port))
	if err != nil && strings.Contains(out, "No rules match") {
		return nil
	}
	return fwErr(err, out)
}

func (winFirewall) manual(port string) string {
	return `New-NetFirewallRule -DisplayName "` + doorFWRuleName(port) + `" -Direction Inbound -Protocol TCP -LocalPort ` + port +
		` -Program "<path to privatae-bastion.exe>" -Action Allow   (from an Administrator PowerShell)`
}

type ufwFirewall struct{ bin string }

func (ufwFirewall) id() string   { return "ufw" }
func (ufwFirewall) name() string { return "ufw" }

func (f ufwFirewall) has(port string) (bool, bool, error) {
	out, err := doorFWExec(f.bin, "status")
	if err != nil {
		return false, false, fwErr(err, out)
	}
	ours, other := ufwRuleFor(out, port)
	return ours, other, nil
}

// ufwRuleFor reads `ufw status` for an inbound ALLOW of port/tcp from
// anywhere: ours carries the bastion's comment; other is any other rule that
// lets a Host from anywhere in. An outbound rule ("ALLOW OUT"), a rule for one
// source or one interface lets no Host from anywhere in, so it is neither.
func ufwRuleFor(status, port string) (ours, other bool) {
	for _, l := range strings.Split(status, "\n") {
		m := ufwRuleLine.FindStringSubmatch(l)
		if m == nil || (m[1] != port+"/tcp" && m[1] != port) {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(l), "# "+doorFWComment) {
			ours = true
		} else {
			other = true
		}
	}
	return ours, other
}

// ufwRuleLine is one `ufw status` rule allowing To in from anywhere: "To",
// an optional " (v6)", "ALLOW" or "ALLOW IN", then "Anywhere".
var ufwRuleLine = regexp.MustCompile(`^(\S+)(?: \(v6\))?\s+ALLOW(?: IN)?\s+Anywhere(?: \(v6\))?(?:\s|$)`)

func (f ufwFirewall) add(port string) error {
	out, err := doorFWExec(f.bin, "allow", port+"/tcp", "comment", doorFWComment)
	return fwErr(err, out)
}

func (f ufwFirewall) remove(port, _ string) error {
	// `ufw delete allow <port>/tcp` deletes the rule whatever its comment, so
	// it runs only while the rule there is the bastion's own: one the person
	// put in its place (or a record that names another port) is theirs.
	if ours, _, err := f.has(port); err != nil {
		return err
	} else if !ours {
		return nil
	}
	out, err := doorFWExec(f.bin, "delete", "allow", port+"/tcp")
	if err != nil && strings.Contains(out, "Could not delete non-existent rule") {
		return nil
	}
	return fwErr(err, out)
}

func (ufwFirewall) manual(port string) string { return "sudo ufw allow " + port + "/tcp" }

type firewalldFirewall struct{ bin string }

func (firewalldFirewall) id() string   { return "firewalld" }
func (firewalldFirewall) name() string { return "firewalld" }

// has: firewalld keeps no comment, so a port it allows is the bastion's only
// when the bastion recorded adding it (doorFirewallEnsure reads the record).
func (f firewalldFirewall) has(port string) (bool, bool, error) {
	out, err := doorFWExec(f.bin, "--query-port="+port+"/tcp")
	if strings.TrimSpace(out) == "yes" {
		return false, true, nil
	}
	if err != nil && strings.TrimSpace(out) != "no" {
		return false, false, fwErr(err, out)
	}
	return false, false, nil
}

func (f firewalldFirewall) add(port string) error {
	if out, err := doorFWExec(f.bin, "--add-port="+port+"/tcp"); err != nil {
		return fwErr(err, out)
	}
	out, err := doorFWExec(f.bin, "--permanent", "--add-port="+port+"/tcp")
	if err != nil {
		// Never a port left open that no record says is the bastion's: it
		// would read as the machine's own next time and never be removed.
		_, _ = doorFWExec(f.bin, "--remove-port="+port+"/tcp")
	}
	return fwErr(err, out)
}

func (f firewalldFirewall) remove(port, _ string) error {
	out1, err1 := doorFWExec(f.bin, "--remove-port="+port+"/tcp")
	out2, err2 := doorFWExec(f.bin, "--permanent", "--remove-port="+port+"/tcp")
	// NOT_ENABLED: the port was already gone from that configuration.
	if err1 != nil && !strings.Contains(out1, "NOT_ENABLED") {
		return fwErr(err1, out1)
	}
	if err2 != nil && !strings.Contains(out2, "NOT_ENABLED") {
		return fwErr(err2, out2)
	}
	return nil
}

func (firewalldFirewall) manual(port string) string {
	return "sudo firewall-cmd --add-port=" + port + "/tcp && sudo firewall-cmd --permanent --add-port=" + port + "/tcp"
}

type macFirewall struct{ bin string }

func (macFirewall) id() string   { return "macos" }
func (macFirewall) name() string { return "the macOS application firewall" }

// errDoorFWBlocked: the firewall lists this program and blocks its incoming
// connections, a setting of the person's that the bastion does not change.
var errDoorFWBlocked = errors.New("this program's incoming connections are blocked")

// has: other is this program listed as allowed incoming connections (the
// bastion's own only when it recorded adding it: the application firewall
// keeps no comment). A listed program that is blocked is errDoorFWBlocked.
func (f macFirewall) has(string) (bool, bool, error) {
	prog, err := doorFWProgram()
	if err != nil {
		return false, false, err
	}
	listed, allowed, err := f.state(prog)
	if err != nil {
		return false, false, err
	}
	if listed && !allowed {
		return false, false, errDoorFWBlocked
	}
	return false, allowed, nil
}

// state is prog's entry in --listapps: listed, and allowed incoming
// connections.
func (f macFirewall) state(prog string) (listed, allowed bool, err error) {
	out, err := doorFWExec(f.bin, "--listapps")
	if err != nil {
		return false, false, fwErr(err, out)
	}
	listed, allowed = macAppState(parseMacListApps(out), prog)
	return listed, allowed, nil
}

// macApp is one entry of `socketfilterfw --listapps`.
type macApp struct {
	path  string // the program's path, or its name alone (macOS 15)
	named bool   // path is the name alone
	allow bool   // "Allow incoming connections" (state 1); anything else is not
}

var (
	// Before macOS 15: "1 : /usr/sbin/cupsd ( Allow incoming connections )",
	// the state on the same line or the next.
	macAppLine   = regexp.MustCompile(`(?i)^\s*\d+\s*:\s*(.+?)\s*(?:\(\s*(allow|block) incoming connections\s*\))?\s*$`)
	macStateLine = regexp.MustCompile(`(?i)^\s*\(\s*(allow|block) incoming connections\s*\)\s*$`)
	// macOS 15 lists names, not paths: "cupsd (state: 1)", 1 allowed, 4 blocked.
	macNameLine = regexp.MustCompile(`^\s*(.+?)\s*\(state:\s*(\d+)\s*\)\s*$`)
)

// parseMacListApps reads --listapps entry by entry.
func parseMacListApps(out string) []macApp {
	var apps []macApp
	waiting := -1 // an entry whose state is on the next line
	for _, l := range strings.Split(out, "\n") {
		if m := macStateLine.FindStringSubmatch(l); m != nil {
			if waiting >= 0 {
				apps[waiting].allow = strings.EqualFold(m[1], "allow")
				waiting = -1
			}
			continue
		}
		waiting = -1
		if m := macAppLine.FindStringSubmatch(l); m != nil {
			apps = append(apps, macApp{path: m[1], allow: strings.EqualFold(m[2], "allow")})
			if m[2] == "" {
				waiting = len(apps) - 1
			}
			continue
		}
		if m := macNameLine.FindStringSubmatch(l); m != nil {
			apps = append(apps, macApp{path: m[1], named: true, allow: m[2] == "1"})
		}
	}
	return apps
}

// macAppState: prog is listed, and an entry for it allows incoming
// connections. An entry is prog's when its path is exactly prog's, or, in a
// list of names alone (macOS 15), when its name is exactly prog's.
func macAppState(apps []macApp, prog string) (listed, allowed bool) {
	for _, a := range apps {
		if a.path == prog || (a.named && a.path == path.Base(prog)) {
			listed = true
			allowed = allowed || a.allow
		}
	}
	return listed, allowed
}

func (f macFirewall) add(string) error {
	prog, err := doorFWProgram()
	if err != nil {
		return err
	}
	if out, err := doorFWExec(f.bin, "--add", prog); err != nil {
		return fwErr(err, out)
	}
	out, err := doorFWExec(f.bin, "--unblockapp", prog)
	if err != nil {
		// As firewalld's: no entry left that no record says is the bastion's.
		_, _ = doorFWExec(f.bin, "--remove", prog)
	}
	return fwErr(err, out)
}

// remove takes out the entry for the program the record names, which is not
// this one when the bastion moved; a record with no program is this one's.
// An entry no longer listed is gone already, and one the person set to block
// is theirs now and stays.
func (f macFirewall) remove(_, prog string) error {
	if prog == "" {
		p, err := doorFWProgram()
		if err != nil {
			return err
		}
		prog = p
	}
	listed, allowed, err := f.state(prog)
	if err != nil {
		return err
	}
	if !listed || !allowed {
		return nil
	}
	out, err := doorFWExec(f.bin, "--remove", prog)
	return fwErr(err, out)
}

func (macFirewall) manual(string) string {
	return "System Settings > Network > Firewall > Options: allow incoming connections for privatae-bastion"
}

func fwErr(err error, out string) error {
	if err == nil {
		return nil
	}
	if o := strings.TrimSpace(out); o != "" {
		if len(o) > 300 {
			o = o[:300]
		}
		return fmt.Errorf("%v: %s", err, o)
	}
	return err
}

// ── what the bastion added: door-firewall.json ───────────────────────────────

type doorFWRule struct {
	Firewall string `json:"firewall"`
	Port     string `json:"port"`
	Program  string `json:"program,omitempty"`
	Added    string `json:"added"`
}

type doorFWState struct {
	Rules []doorFWRule `json:"rules,omitempty"`
	// Allowed: ports another rule of the machine already allows, and in what.
	Allowed map[string]string `json:"allowed,omitempty"`
	// Notes: per port, what the bastion could not do and the person needs.
	Notes map[string]string `json:"notes,omitempty"`
}

var doorFWMu sync.Mutex

func doorFWPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "door-firewall.json"), nil
}

func loadDoorFW() doorFWState {
	var st doorFWState
	p, err := doorFWPath()
	if err != nil {
		return st
	}
	if raw, err := os.ReadFile(p); err == nil && len(raw) < 64<<10 {
		_ = json.Unmarshal(raw, &st)
	}
	return st
}

func saveDoorFW(st doorFWState) error {
	p, err := doorFWPath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, raw)
}

// withDoorFW runs fn holding the firewall lock: in this process, and across
// the daemon and a `pair --open` or `unpair` at the terminal.
func withDoorFW(fn func(st *doorFWState) bool) {
	doorFWMu.Lock()
	defer doorFWMu.Unlock()
	if p, err := doorFWPath(); err == nil {
		if lf, err := os.OpenFile(p+".lock", os.O_CREATE|os.O_RDWR, 0o600); err == nil {
			defer lf.Close()
			_ = flockFile(lf)
		}
	}
	st := loadDoorFW()
	if fn(&st) {
		_ = saveDoorFW(st)
	}
}

func (st *doorFWState) rule(id, port string) *doorFWRule {
	for i := range st.Rules {
		if st.Rules[i].Firewall == id && st.Rules[i].Port == port {
			return &st.Rules[i]
		}
	}
	return nil
}

func (st *doorFWState) drop(id, port string) {
	out := st.Rules[:0]
	for _, r := range st.Rules {
		if r.Firewall != id || r.Port != port {
			out = append(out, r)
		}
	}
	st.Rules = out
}

func (st *doorFWState) note(port, note string) bool {
	if st.Notes == nil {
		st.Notes = map[string]string{}
	}
	if st.Notes[port] == note {
		return false
	}
	if note == "" {
		delete(st.Notes, port)
	} else {
		st.Notes[port] = note
	}
	return true
}

func (st *doorFWState) allowed(port, by string) {
	if st.Allowed == nil {
		st.Allowed = map[string]string{}
	}
	if by == "" {
		delete(st.Allowed, port)
	} else {
		st.Allowed[port] = by
	}
}

// ruleKey is the port a firewall's rule is kept for: macOS's is per program.
func ruleKey(f doorFirewall, port string) string {
	if f.id() == "macos" {
		return doorFWAnyPort
	}
	return port
}

// doorFirewallEnsure makes sure the door's port is allowed inbound: the door
// on addr is in use. It says, in one line, what holds now.
func doorFirewallEnsure(addr string) string { return doorFirewallEnsureWhile(addr, nil) }

// doorFirewallEnsureWhile is doorFirewallEnsure for a door that may close
// while it runs: inUse, asked holding the firewall lock, false means the door
// closed and its release has run or is waiting for the lock, so nothing is
// added that no release would remove.
func doorFirewallEnsureWhile(addr string, inUse func() bool) string {
	port := doorPort(addr)
	var said string
	withDoorFW(func(st *doorFWState) bool {
		if inUse != nil && !inUse() {
			return false
		}
		f, why := doorFirewallFor(port)
		if f == nil {
			changed := st.note(port, why)
			if _, ok := st.Allowed[port]; ok {
				st.allowed(port, "")
				changed = true
			}
			if why != "" {
				if changed {
					pairingAudit("door_firewall_unmanaged", port, "not done: "+why)
				}
				said = "firewall: " + why
			}
			return changed
		}
		key := ruleKey(f, port)
		prog, _ := doorFWProgram()
		rec := st.rule(f.id(), key)
		if rec != nil && prog != "" && rec.Program != prog && (f.id() == "windows" || f.id() == "macos") {
			// A Windows or macOS rule is for one program path, and the record
			// names another: the bastion moved. That rule is removed by the
			// path it names, then this program's own is read and made.
			if err := f.remove(port, rec.Program); err != nil {
				pairingAudit("door_firewall_failed", port, "not done: removing its rule for "+rec.Program+" from "+f.name()+": "+err.Error())
			}
			st.drop(f.id(), key)
			rec = nil
		}
		ours, other, err := f.has(port)
		if errors.Is(err, errDoorFWBlocked) {
			why := f.name() + " is set to block incoming connections for this program, a setting the bastion does not change. " +
				"Your Host can connect once it allows them: " + f.manual(port)
			if st.note(port, why) {
				pairingAudit("door_firewall_unmanaged", port, "not done: "+why)
			}
			said = "firewall: " + why
			return true
		}
		if err != nil {
			why := "the bastion could not read " + f.name() + " (" + err.Error() + "). Allow TCP " + port + " inbound by hand: " + f.manual(port)
			if st.note(port, why) {
				pairingAudit("door_firewall_failed", port, "not done: "+why)
			}
			said = "firewall: " + why
			return true
		}
		if rec != nil && !ours && other && f.id() == "ufw" {
			// ufw tells its rules apart by comment: the one there now is
			// not the bastion's (the person put their own in its place), so
			// it is the machine's own, and never removed.
			st.drop(f.id(), key)
			rec = nil
		}
		present := ours || other
		now := time.Now().UTC().Format(time.RFC3339)
		switch {
		case rec != nil && present:
			st.note(port, "")
			said = doorFWWords(f.name(), port, true)
			return true
		case rec == nil && ours:
			// Its own rule (by its name or comment), with no record: kept.
			st.Rules = append(st.Rules, doorFWRule{Firewall: f.id(), Port: key, Program: prog, Added: now})
			st.note(port, "")
			pairingAudit("door_firewall_kept", port, "ok: found its own rule in "+f.name()+" allowing TCP "+port+" inbound, and keeps it")
			said = doorFWWords(f.name(), port, true)
			return true
		case rec == nil && other:
			// The machine's own rule: neither doubled nor ever removed.
			st.allowed(port, f.name())
			st.note(port, "")
			said = "firewall: TCP " + port + " is already allowed inbound by a rule of this machine's own in " + f.name() +
				"; the bastion leaves it as it is."
			return true
		case rec != nil:
			// Recorded, but no longer there (removed by hand): added again.
			st.drop(f.id(), key)
		}
		if err := f.add(port); err != nil {
			why := "the bastion could not add its rule to " + f.name() + " (" + err.Error() + "). Allow TCP " + port + " inbound by hand: " + f.manual(port)
			if st.note(port, why) {
				pairingAudit("door_firewall_failed", port, "not done: "+why)
			}
			said = "firewall: " + why
			return true
		}
		st.Rules = append(st.Rules, doorFWRule{Firewall: f.id(), Port: key, Program: prog, Added: now})
		st.allowed(port, "")
		st.note(port, "")
		pairingAudit("door_firewall_opened", port, "ok: added its own rule to "+f.name()+" allowing TCP "+port+
			" inbound, while your Host connects to this server")
		said = doorFWWords(f.name(), port, false)
		return true
	})
	return said
}

func doorFWWords(fw, port string, kept bool) string {
	verb := "added"
	if kept {
		verb = "keeps"
	}
	return "firewall: the bastion " + verb + " its own rule in " + fw + " allowing TCP " + port +
		" inbound; it is removed when no Host connects here any more. A cloud provider's firewall still needs TCP " + port + " allowed."
}

// doorPortsInUse is every port whose door is in use: an active pairing whose
// Host connects here, an open pairing window, or a window a door claimed for
// a pairing it is still saving (claimedWindowUnderWay: between the claim and
// the save, neither the window nor the pairing is there to read).
func doorPortsInUse() []string {
	set := map[string]bool{}
	if cfgs, err := loadPairings(); err == nil {
		for _, c := range cfgs {
			if c.hostDials() && c.active() {
				set[doorPort(c.doorAddr())] = true
			}
		}
	}
	if w := loadOpenWindow(); w != nil {
		set[doorPort(w.Door)] = true
	}
	if w := claimedWindowUnderWay(time.Now()); w != nil {
		set[doorPort(w.Door)] = true
	}
	return sortedSet(set)
}

func sortedSet(set map[string]bool) []string {
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// doorPortWanted: the door on port is in use (doorPortsInUse); doorFWAnyPort,
// any door is.
var doorPortWanted = func(port string) bool {
	for _, p := range doorPortsInUse() {
		if port == doorFWAnyPort || p == port {
			return true
		}
	}
	return false
}

// doorFirewallRelease removes the bastion's own rule for addr's port when the
// door there is no longer in use: no active pairing whose Host connects on
// it and no open window. Called when a door closes, a window ends and a
// pairing goes.
func doorFirewallRelease(addr string) {
	port := doorPort(addr)
	withDoorFW(func(st *doorFWState) bool {
		if doorPortWanted(port) {
			return false
		}
		changed := st.note(port, "")
		if _, ok := st.Allowed[port]; ok {
			st.allowed(port, "")
			changed = true
		}
		for _, r := range append([]doorFWRule(nil), st.Rules...) {
			if r.Port != port && !(r.Port == doorFWAnyPort && !doorPortWanted(doorFWAnyPort)) {
				continue
			}
			if doorFWRemoveRule(st, r, "no Host connects to this server on it any more") {
				changed = true
			}
		}
		return changed
	})
}

// doorFWRemoveRule removes one recorded rule, auditing it. True when the
// record changed.
func doorFWRemoveRule(st *doorFWState, r doorFWRule, why string) bool {
	f := doorFirewallByID(r.Firewall)
	if f == nil {
		pairingAudit("door_firewall_failed", r.Port, "not done: its rule in "+r.Firewall+" could not be removed: that firewall is no longer on this machine")
		st.drop(r.Firewall, r.Port)
		return true
	}
	port := r.Port
	if port == doorFWAnyPort {
		port = ""
	}
	if err := f.remove(port, r.Program); err != nil {
		why := "the bastion could not remove its rule from " + f.name() + " (" + err.Error() + ")"
		if st.note(r.Port, why) {
			pairingAudit("door_firewall_failed", r.Port, "not done: "+why)
			return true
		}
		return false
	}
	st.drop(r.Firewall, r.Port)
	what := "TCP " + r.Port
	if r.Port == doorFWAnyPort {
		what = "this program"
	}
	pairingAudit("door_firewall_closed", r.Port, "ok: removed its own rule from "+f.name()+" allowing "+what+" inbound: "+why)
	return true
}

// doorFirewallRemoveAll removes every rule the bastion added (uninstall).
// Each one removed is said in words.
func doorFirewallRemoveAll() (said []string, err error) {
	var errs []string
	withDoorFW(func(st *doorFWState) bool {
		changed := false
		for _, r := range append([]doorFWRule(nil), st.Rules...) {
			if doorFWRemoveRule(st, r, "the bastion is uninstalled") {
				changed = true
			}
			if st.rule(r.Firewall, r.Port) != nil {
				errs = append(errs, "its rule in "+r.Firewall+" for "+r.Port+": "+st.Notes[r.Port])
				continue
			}
			said = append(said, "removed its own firewall rule ("+r.Firewall+", "+r.Port+")")
		}
		if len(st.Notes) > 0 || len(st.Allowed) > 0 {
			st.Notes, st.Allowed, changed = nil, nil, true
		}
		return changed
	})
	if len(errs) > 0 {
		return said, errors.New(strings.Join(errs, "; "))
	}
	return said, nil
}

// ── status and doctor ────────────────────────────────────────────────────────

// statusFirewall is the door's firewall in status: the bastion's own rules,
// ports the machine already allows, and what the person needs to do.
type statusFirewall struct {
	Rules   []string `json:"rules,omitempty"`
	Allowed []string `json:"allowed,omitempty"`
	Needs   []string `json:"needs,omitempty"`
}

func readDoorFirewallStatus() *statusFirewall {
	st := loadDoorFW()
	if len(st.Rules) == 0 && len(st.Notes) == 0 && len(st.Allowed) == 0 {
		return nil
	}
	s := &statusFirewall{}
	for _, r := range st.Rules {
		what := "TCP " + r.Port
		if r.Port == doorFWAnyPort {
			what = "this program"
		}
		name := r.Firewall
		if f := doorFirewallOf(runtime.GOOS, r.Firewall); f != nil {
			name = f.name()
		}
		s.Rules = append(s.Rules, "the bastion's own rule in "+name+" allows "+what+" inbound (since "+r.Added+")")
	}
	for _, p := range sortedKeys(st.Allowed) {
		s.Allowed = append(s.Allowed, "TCP "+p+" is allowed by a rule of this machine's own in "+st.Allowed[p])
	}
	for _, p := range sortedKeys(st.Notes) {
		s.Needs = append(s.Needs, "TCP "+p+": "+st.Notes[p])
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func printDoorFirewallStatus(w io.Writer, f *statusFirewall) {
	if f == nil {
		return
	}
	for _, l := range f.Rules {
		fmt.Fprintf(w, "firewall: %s\n", l)
	}
	for _, l := range f.Allowed {
		fmt.Fprintf(w, "firewall: %s\n", l)
	}
	for _, l := range f.Needs {
		fmt.Fprintf(w, "firewall: NEEDS YOU: %s\n", l)
	}
}

// doorFirewallChecks are doctor's firewall checks.
func doorFirewallChecks(f *statusFirewall) []doctorCheck {
	if f == nil {
		return nil
	}
	var cs []doctorCheck
	for _, l := range f.Rules {
		cs = append(cs, doctorCheck{Name: "firewall", OK: true, Detail: sentenceCase(l) + "."})
	}
	for _, l := range f.Allowed {
		cs = append(cs, doctorCheck{Name: "firewall", OK: true, Detail: l + "."})
	}
	for _, l := range f.Needs {
		cs = append(cs, doctorCheck{Name: "firewall", Problem: "Your Host connects to this server, and the bastion could not open the way in: " + l + ".",
			Fix: "Allow that port inbound as said; the bastion looks again each time its door opens."})
	}
	return cs
}

// doorFirewallReleaseUnused releases every port the bastion holds a rule or a
// note for (a pairing went while the daemon was not running).
func doorFirewallReleaseUnused() {
	st := loadDoorFW()
	ports := map[string]bool{}
	for _, r := range st.Rules {
		if r.Port != doorFWAnyPort {
			ports[r.Port] = true
		} else {
			ports[doorPort(doorDefaultAddr)] = true
		}
	}
	for p := range st.Notes {
		ports[p] = true
	}
	for p := range st.Allowed {
		ports[p] = true
	}
	for p := range ports {
		doorFirewallRelease(":" + p)
	}
}

// doorFirewallReconcile brings the firewall to what the doors need: every
// port the bastion holds a rule or note for that nothing uses is released, and
// every port in use has its rule ensured again. So a rule that went while its
// door was in use (removed by hand, a firewall reset, or a release that ran
// while a pairing was being saved) is put back, and a port a rule of the
// machine's own allows is still left alone (doorFirewallEnsureWhile).
func doorFirewallReconcile() {
	doorFirewallReleaseUnused()
	ports := map[string]bool{}
	for _, p := range doorPortsInUse() {
		ports[p] = true
	}
	// Recorded rules too: their port is in use when doorPortWanted says so.
	for _, r := range loadDoorFW().Rules {
		if r.Port != doorFWAnyPort {
			ports[r.Port] = true
		}
	}
	for _, p := range sortedSet(ports) {
		port := p
		doorFirewallEnsureWhile(":"+port, func() bool { return doorPortWanted(port) })
	}
}

// doorFWSweepEvery is how often the daemon reconciles the door's rules.
const doorFWSweepEvery = 5 * time.Minute

// doorFirewallSweep reconciles, at start and then every doorFWSweepEvery:
// it removes the rules whose port nothing uses (a `pair --open` that was
// killed before it could, a window that expired with no process left to see
// it) and puts back a rule that went while its port is in use. A state with
// no rule and no note, and no door in use, costs a few file reads.
func doorFirewallSweep(ctx context.Context) {
	t := time.NewTicker(doorFWSweepEvery)
	defer t.Stop()
	for {
		doorFirewallReconcile()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
