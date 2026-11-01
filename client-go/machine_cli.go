package main

// machine_cli.go — the console's This machine page on the command line:
// `schedules`, `tool-servers`, `posture` and `baseline show|diff|record`.
// Each read is one value (reads.go), printed in the console's words or, with
// --json, as itself.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"
)

// ── scheduled jobs that start an agent ──────────────────────────────────────

const schedulesUsage = "usage: privatae-bastion schedules [--json]"

type schedulesRead struct {
	Schedules []uiSchedule `json:"schedules"`
	Read      bool         `json:"schedulers_read"` // false: this platform's schedulers are not read by this build
}

func readSchedules(readOpts) (schedulesRead, error) {
	s, ok := collectSchedules()
	return schedulesRead{Schedules: s, Read: ok}, nil
}

func cmdSchedules(args []string) error {
	asJSON, err := jsonOnly(schedulesUsage, args)
	if err != nil {
		return err
	}
	v, err := readOwnOrMachine("schedules", readOpts{}, readSchedules)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(os.Stdout, v)
	}
	printSchedules(os.Stdout, v)
	return nil
}

func printSchedules(w io.Writer, v schedulesRead) {
	switch {
	case len(v.Schedules) == 0 && v.Read:
		fmt.Fprintln(w, "No scheduled job on this machine starts an AI agent.")
		return
	case len(v.Schedules) == 0:
		fmt.Fprintln(w, "This platform's schedulers cannot be read by this build, so an empty list here means nothing looked.")
		return
	}
	for _, s := range v.Schedules {
		line := s.Agent + "  "
		if s.Schedule != "" {
			line += "runs " + s.Schedule + " · "
		}
		line += s.Where
		if s.User != "" {
			line += " · as " + s.User
		}
		fmt.Fprintln(w, line)
		if s.Command != "" {
			fmt.Fprintln(w, "    "+s.Command)
		}
	}
}

// ── MCP tool servers and their problems ─────────────────────────────────────

const toolServersUsage = "usage: privatae-bastion tool-servers [--json]"

type toolServersRead struct {
	Clients []uiToolGroup `json:"clients"`
}

func readToolServers(readOpts) (toolServersRead, error) {
	return toolServersRead{Clients: collectToolGroups()}, nil
}

func cmdToolServers(args []string) error {
	asJSON, err := jsonOnly(toolServersUsage, args)
	if err != nil {
		return err
	}
	v, err := readOwnOrMachine("tool-servers", readOpts{}, readToolServers)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(os.Stdout, v)
	}
	printToolServers(os.Stdout, v)
	return nil
}

func printToolServers(w io.Writer, v toolServersRead) {
	if len(v.Clients) == 0 {
		fmt.Fprintln(w, "No MCP tool server is configured in any settings file this bastion can read.")
		return
	}
	for _, g := range v.Clients {
		head := g.Client + ": " + plural(len(g.Servers), "tool server", "tool servers")
		if g.Bad > 0 {
			head += fmt.Sprintf(", %d with a problem", g.Bad)
		}
		fmt.Fprintln(w, head)
		for _, s := range g.Servers {
			fmt.Fprintf(w, "  %s  (%s)\n", s.Name, s.Where)
			for _, p := range s.Problems {
				fmt.Fprintln(w, "      "+p)
			}
		}
	}
}

// ── posture: the checks a Host runs on its own servers ──────────────────────

const postureUsage = "usage: privatae-bastion posture [--json]"

// postureNeedsAdmin is a firewall field read without the administrator:
// ufw, nft and iptables refuse an ordinary account, and their refusals read
// as "absent" or a stray word, so the field is not reported at all.
const postureNeedsAdmin = "needs_administrator"

type postureRead struct {
	Supported bool         `json:"supported"`
	OS        string       `json:"os"`
	AsAdmin   bool         `json:"read_as_administrator"`
	Checks    *hostPosture `json:"checks,omitempty"`
}

func readPosture(readOpts) (postureRead, error) {
	r := postureRead{Supported: observeHostSupported, OS: runtime.GOOS, AsAdmin: machineAuthorityHeld()}
	if !r.Supported {
		return r, nil
	}
	p := readHostPosture()
	if !r.AsAdmin {
		p.Ufw, p.Pubwall, p.Input, p.Ssh22 = postureNeedsAdmin, postureNeedsAdmin, postureNeedsAdmin, postureNeedsAdmin
	}
	r.Checks = &p
	return r, nil
}

func cmdPosture(args []string) error {
	asJSON, err := jsonOnly(postureUsage, args)
	if err != nil {
		return err
	}
	v, err := readOwnOrMachine("posture", readOpts{}, readPosture)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(os.Stdout, v)
	}
	printPosture(os.Stdout, v)
	return nil
}

func printPosture(w io.Writer, v postureRead) {
	if !v.Supported || v.Checks == nil {
		fmt.Fprintf(w, "These checks read Linux's firewall, package manager and system log; this machine runs %s, "+
			"so nothing was read.\n", v.OS)
		return
	}
	for _, l := range postureLines(*v.Checks, v.AsAdmin) {
		fmt.Fprintln(w, l)
	}
	fmt.Fprintln(w, "These are the checks a Host runs on its own servers. A firewall other than ufw, "+
		"the pubwall nftables table or iptables' INPUT policy is not read.")
}

// postureLines says each check in words, the firewall first.
func postureLines(p hostPosture, asAdmin bool) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	unread := func(what, v string) { add(what + ": could not be read (" + v + ")") }
	if !asAdmin {
		add("Firewall: not read; it takes the administrator: sudo -H privatae-bastion posture")
	} else {
		switch p.Ufw {
		case "active":
			add("ufw firewall: on")
		case "inactive":
			add("ufw firewall: installed, off")
		case "absent":
			add("ufw firewall: not installed")
		default:
			unread("ufw firewall", p.Ufw)
		}
		switch p.Pubwall {
		case "absent": // Privatae's own table: most machines have none, and that says nothing
		case "drop+tdrop":
			add("pubwall (nftables): refuses by default, and its last rule refuses too")
		case "drop":
			add("pubwall (nftables): refuses by default")
		case "accept+tdrop":
			add("pubwall (nftables): admits by default; only its last rule refuses, so losing that rule opens it")
		case "accept":
			add("pubwall (nftables): admits by default, with no rule that refuses at the end")
		default:
			unread("pubwall (nftables)", p.Pubwall)
		}
		switch p.Input {
		case "DROP", "REJECT":
			add("iptables INPUT: refuses by default (" + p.Input + ")")
		case "ACCEPT":
			add("iptables INPUT: admits by default")
		case "absent":
			add("iptables: not installed")
		default:
			unread("iptables INPUT", p.Input)
		}
		switch p.Ssh22 {
		case "scoped":
			add("SSH (port 22): admitted only from listed addresses")
		case "unscoped":
			add("SSH (port 22): admitted from any address")
		case "unknown":
			add("SSH (port 22): no firewall rule for it was found")
		default:
			unread("SSH (port 22)", p.Ssh22)
		}
	}
	switch p.F2b {
	case "active":
		add("fail2ban: running")
	case "inactive", "failed":
		add("fail2ban: not running (" + p.F2b + ")")
	case "absent":
		add("fail2ban: not checked (no systemctl)")
	default:
		add("fail2ban: " + p.F2b)
	}
	switch {
	case p.Sec < 0:
		add("Security updates: could not be counted (the check reads apt-get)")
	case p.Sec == 0:
		add("Security updates: none waiting")
	default:
		add(fmt.Sprintf("Security updates: %d waiting", p.Sec))
	}
	if p.Reboot == "yes" {
		add("A restart is needed to finish installing updates")
	}
	if p.DiskPct >= 0 {
		add(fmt.Sprintf("Disk (/): %d%% used", p.DiskPct))
	}
	if p.Load >= 0 && p.Cpus > 0 {
		add(fmt.Sprintf("Load: %.2f over the last minute, %d cores", p.Load, p.Cpus))
	}
	if p.Jrn >= 0 {
		add("System log: last line " + (time.Duration(p.Jrn) * time.Second).String() + " ago")
	} else {
		add("System log: could not be read")
	}
	if p.Puv != "" && p.Puv != "absent" {
		add("Check after the last upgrade: " + p.Puv)
	}
	if len(p.Timeouts) > 0 {
		add("Did not finish in time: " + strings.Join(p.Timeouts, ", "))
	}
	return out
}

// ── the baseline: record it, show it, compare against it ────────────────────

const baselineUsage = "usage: privatae-bastion baseline [show] [--json] | baseline diff [--json] | " +
	"sudo -H privatae-bastion baseline record [--force]"

type baselineRead struct {
	Has         bool          `json:"has"`
	Baseline    *baselineFile `json:"baseline,omitempty"`
	Integrity   string        `json:"integrity_note,omitempty"`
	Attestation string        `json:"attestation_note,omitempty"`
}

func readBaseline(readOpts) (baselineRead, error) {
	f, ok, err := baselineLoad()
	if errors.Is(err, os.ErrNotExist) {
		return baselineRead{}, nil
	}
	if err != nil {
		return baselineRead{}, err
	}
	r := baselineRead{Has: true, Baseline: f, Integrity: baselineIntegrityNote(f, ok)}
	if f.Attestation != nil {
		r.Attestation = baselineAttestationNote(f)
	}
	return r, nil
}

// readBaselineDiff compares what runs now against the baseline. The
// administrator's: a pass that cannot read what the baseline read reports
// the difference between two accounts, not a change to the machine.
func readBaselineDiff(readOpts) (deltaReport, error) {
	if err := requireMachineAuthority("baseline diff"); err != nil {
		return deltaReport{}, err
	}
	return deltaPass(&digestCache{}, time.Now(), deltaRoleOperator), nil
}

func cmdBaseline(args []string) error {
	verb := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb, args = args[0], args[1:]
	}
	switch verb {
	case "record":
		force := false
		for _, a := range args {
			if a != "--force" {
				return errors.New(baselineUsage)
			}
			force = true
		}
		return cmdObserveBaseline(force)
	case "show":
		asJSON, err := jsonOnly(baselineUsage, args)
		if err != nil {
			return err
		}
		v, err := readMachine("baseline", readOpts{}, readBaseline)
		if err != nil {
			return laneRefusalError("baseline show", err)
		}
		if asJSON {
			return printJSON(os.Stdout, v)
		}
		return printBaseline(os.Stdout, v)
	case "diff":
		asJSON, err := jsonOnly(baselineUsage, args)
		if err != nil {
			return err
		}
		v, err := readMachine("baseline-diff", readOpts{}, readBaselineDiff)
		if err != nil {
			return laneRefusalError("baseline diff", err)
		}
		if asJSON {
			return printJSON(os.Stdout, v)
		}
		return printDelta(os.Stdout, v)
	}
	return errors.New(baselineUsage)
}
