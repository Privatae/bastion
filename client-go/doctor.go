package main

// doctor.go — what is wrong with this install, and the fix for each one
// (plan Addendum 6, slice 3).
//
//	privatae-bastion doctor [--json]
//
// Each check is a fact the bastion already holds, said as a problem and the
// command that fixes it. The machine's checks are built where its state is:
// in the daemon for the owner's account, through the lane (reads.go), or
// directly for the administrator and a per-account install. The one thing
// only the asking side can find out is whether the lane answers it at all,
// and that becomes the check when it does not. Exit status 1 when any check
// finds a problem, so a script can branch on it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const doctorUsage = "usage: privatae-bastion doctor [--json]"

type doctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"` // what was found, when all is well
	Problem string `json:"problem,omitempty"`
	Fix     string `json:"fix,omitempty"` // the command, or what to do
}

type doctorRead struct {
	Version string        `json:"version"`
	Checks  []doctorCheck `json:"checks"`
}

func (d doctorRead) problems() int {
	n := 0
	for _, c := range d.Checks {
		if !c.OK {
			n++
		}
	}
	return n
}

// systemInstalled: the bastion is installed for the whole machine.
var systemInstalled = func() bool {
	if runtime.GOOS == "linux" {
		return linuxSystemUnitPresent()
	}
	return systemService.installed
}

// doctorSandbox is opSandboxAvailable, replaceable in a test: its probe
// re-executes this binary.
var doctorSandbox = opSandboxAvailable

// asAdmin is a bastion command said the way it has to be typed here: the
// machine's bastion keeps its state as the administrator when it is
// installed for the whole machine.
func asAdmin(cmd string) string {
	switch {
	case !systemInstalled():
		return "privatae-bastion " + cmd
	case runtime.GOOS == "windows":
		return "privatae-bastion " + cmd + "   (from an Administrator terminal)"
	}
	return "sudo -H privatae-bastion " + cmd
}

// installerCommand is how this platform installs the bastion, and so how a
// machine no Host updates moves to a newer version.
func installerCommand() string {
	if runtime.GOOS == "windows" {
		return "irm https://privatae.ai/bastion/install.ps1 | iex"
	}
	return "curl -fsSL https://privatae.ai/bastion/install.sh | sh"
}

// doctorLatest is the newest published version, or "" when it cannot be
// known: the daemon's last answer, else the last time doctor asked
// privatae.ai, if that was within updateCheckEvery, else one fetch that
// waits at most doctorLatestWait. A request to privatae.ai carries this
// machine's address to the platform, so doctor keeps update.go's rate
// (four a day): a run in its own process, or an agent polling it, asks again
// only once that time has passed, whether the last ask was answered or not.
// Running with no route to privatae.ai is supported (update.go), so "" is
// not a problem.
var (
	doctorLatestWait = 10 * time.Second
	doctorLatest     = func() string {
		latestMu.Lock()
		v := latestPublished
		latestMu.Unlock()
		if v != "" {
			return v
		}
		if r, ok := doctorAskedLoad(); ok && doctorNow().Sub(r.AskedAt) < updateCheckEvery {
			return r.Version
		}
		got := make(chan string, 1)
		go func() {
			v, err := doctorFetch()
			if err != nil {
				v = ""
			}
			got <- strings.TrimSpace(v)
		}()
		select {
		case v = <-got:
		case <-time.After(doctorLatestWait):
		}
		if v != "" {
			recordLatestPublished(v)
		} else if r, ok := doctorAskedLoad(); ok {
			v = r.Version // no answer this time: the last one stands, as in update.go
		}
		doctorAskedSave(doctorAsked{Version: v, AskedAt: doctorNow()})
		return v
	}
	doctorNow   = time.Now
	doctorFetch = func() (string, error) {
		m, err := fetchManifest()
		if err != nil {
			return "", err
		}
		return m.Version, nil
	}
)

// doctorAsked is when doctor last asked privatae.ai, and what it knew after.
type doctorAsked struct {
	Version string    `json:"version"`
	AskedAt time.Time `json:"asked_at"`
}

func doctorAskedPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "doctor_latest.json"), nil
}

func doctorAskedLoad() (doctorAsked, bool) {
	var r doctorAsked
	p, err := doctorAskedPath()
	if err != nil {
		return r, false
	}
	raw, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(raw, &r) != nil || r.AskedAt.IsZero() {
		return doctorAsked{}, false
	}
	return r, true
}

func doctorAskedSave(r doctorAsked) {
	p, err := doctorAskedPath()
	if err != nil {
		return
	}
	if raw, err := json.Marshal(r); err == nil {
		_ = atomicWrite(p, raw)
	}
}

// logHint is where the bastion's own log is read on this platform.
func logHint() string {
	switch runtime.GOOS {
	case "linux":
		if systemInstalled() {
			return "journalctl -u privatae-bastion"
		}
		return "journalctl --user -u privatae-bastion"
	case "windows":
		return "the bastion's window, or Event Viewer when it runs as a service"
	}
	return "Console.app, process privatae-bastion"
}

func readDoctor(readOpts) (doctorRead, error) {
	d := doctorRead{Version: clientVersion, Checks: []doctorCheck{}}
	add := func(c doctorCheck) { d.Checks = append(d.Checks, c) }

	s, err := readStatus(readOpts{})
	if err != nil {
		add(doctorCheck{Name: "pairings", Problem: sentenceCase(err.Error()) + ".",
			Fix: "The bastion's log says why: " + logHint()})
		return d, nil
	}
	paired := len(s.Pairings) > 0
	start := runCommandHint()
	if runtime.GOOS == "linux" && systemInstalled() {
		start = "sudo " + start
	}
	switch {
	case s.Running == "no":
		add(doctorCheck{Name: "running", Problem: "The bastion is not running, so nothing on this machine is watched.",
			Fix: start})
	case !paired:
		add(doctorCheck{Name: "running", OK: true, Detail: "Running on its own; no Host is connected."})
	default:
		add(doctorCheck{Name: "running", OK: true, Detail: fmt.Sprintf("Running, paired with %d Host(s).", len(s.Pairings))})
	}

	switch latest := doctorLatest(); {
	case latest == "":
		add(doctorCheck{Name: "version", OK: true, Detail: "This is " + clientVersion +
			"; the latest published version could not be read from privatae.ai."})
	case versionNewer(latest, clientVersion):
		fix := "Run the installer again: " + installerCommand()
		if paired {
			fix = "Your Host can update it (Network app, Update), or run the installer again: " + installerCommand()
		}
		add(doctorCheck{Name: "version", Problem: "Version " + latest + " is published; this machine runs " +
			clientVersion + ".", Fix: fix})
	default:
		add(doctorCheck{Name: "version", OK: true, Detail: clientVersion + " is the latest published version."})
	}

	if systemInstalled() {
		_, name, present, err := ownerAccountLoad()
		fix := "sudo -H privatae-bastion approvals-owner --account <your account>"
		if runtime.GOOS == "windows" {
			fix = "privatae-bastion approvals-owner --sid <your account's SID>   (from an Administrator terminal)"
		}
		switch {
		case err != nil:
			add(doctorCheck{Name: "owner", Problem: "This machine's owner account cannot be read (" + err.Error() + ").",
				Fix: strings.Replace(fix, "approvals-owner ", "approvals-owner --replace ", 1)})
		case !present:
			add(doctorCheck{Name: "owner", Problem: "No account is recorded as this machine's owner, so the console " +
				"opens only for the administrator, and agents in your account can neither read the machine nor ask it " +
				"to stop an agent.", Fix: fix})
		default:
			add(doctorCheck{Name: "owner", OK: true, Detail: "The machine's owner account is " + name + "."})
		}
	}

	factor := existingMachineFactorDir()
	if stepupEnrolled(factor) {
		add(doctorCheck{Name: "second factor", OK: true, Detail: "The machine's owner has a second factor here."})
	} else {
		add(doctorCheck{Name: "second factor", Problem: "This machine has no second factor of its own, so a stop, " +
			"and every ask an agent files, cannot be approved.", Fix: asAdmin("stepup-enroll --machine")})
	}

	now := time.Now()
	var held []string
	for account, e := range askQuarantineLoad(factor) {
		if quarantinedAt(e, now) {
			held = append(held, account)
		}
	}
	sort.Strings(held)
	for _, account := range held {
		add(doctorCheck{Name: "held asker", Problem: sentenceCase(askHoldRefusal(account, askHeldUntil(factor, account, now))) + ".",
			Fix: asAdmin("quarantine clear --asker " + account)})
	}

	for _, c := range doorFirewallChecks(s.Firewall) {
		add(c)
	}
	if s.LLM != nil {
		add(doctorCheck{Name: "model server", OK: true, Detail: sentenceCase(s.LLM.words()) + "."})
	}
	for _, p := range s.Pairings {
		switch {
		case p.Problem != "":
			add(doctorCheck{Name: "host " + p.Host, Problem: "The pairing with " + p.Host + " is not usable: " +
				p.Problem + ".", Fix: "The bastion's log says more: " + logHint()})
		case p.WaitingFor != "":
			add(doctorCheck{Name: "host " + p.Host, OK: true, Detail: p.Host + " waits for " + p.WaitingFor +
				" to admit it; " + p.WaitingFor + " asks you to approve it."})
		case !p.Answering && s.Running != "no":
			add(doctorCheck{Name: "host " + p.Host, Problem: "The bastion is not serving " + p.Host +
				" (nothing answers on " + p.Local + ").", Fix: "The bastion's log says why: " + logHint()})
		}
	}
	if paired {
		localDenyMu.Lock()
		_, derr := localDenyLoad()
		localDenyMu.Unlock()
		if derr != nil {
			add(doctorCheck{Name: "switches", Problem: localDenyUnreadableText(derr), Fix: asAdmin("switch --reset")})
		}
		if ok, why := doctorSandbox(); !ok {
			c := doctorCheck{Name: "sandbox", Problem: "Ops a Host sends cannot run sandboxed here: " + why + "."}
			if !processIsRoot() {
				c.Fix = "Install the bastion for the whole machine: run the installer again without --just-me: " +
					installerCommand()
			}
			add(c)
		}
	}
	return d, nil
}

func cmdDoctor(args []string) error {
	asJSON, err := jsonOnly(doctorUsage, args)
	if err != nil {
		return err
	}
	d, err := readMachine("doctor", readOpts{}, readDoctor)
	var le *laneError
	if errors.As(err, &le) {
		// The one check the machine cannot make for this account.
		d = doctorRead{Version: clientVersion, Checks: []doctorCheck{laneCheck(le)}}
		err = nil
	}
	if err != nil {
		return err
	}
	if asJSON {
		if err := printJSON(os.Stdout, d); err != nil {
			return err
		}
	} else {
		printDoctor(os.Stdout, d)
	}
	if d.problems() > 0 {
		return quietExit{code: 1}
	}
	return nil
}

// laneCheck is the lane not answering this account, as a check.
func laneCheck(le *laneError) doctorCheck {
	if le.down {
		fix := "Start it: sudo " + runCommandHintFor(runtime.GOOS) + "   (see whether it runs: systemctl status privatae-bastion)"
		if runtime.GOOS != "linux" {
			fix = "Start it: " + runCommandHint()
		}
		return doctorCheck{Name: "running", Problem: "The machine's bastion does not answer this account: " + le.why + ".",
			Fix: fix}
	}
	return doctorCheck{Name: "reads", Problem: sentenceCase(le.why) + ".",
		Fix: "As the administrator: sudo -H privatae-bastion doctor"}
}

func printDoctor(w io.Writer, d doctorRead) {
	switch n := d.problems(); n {
	case 0:
		fmt.Fprintf(w, "privatae-bastion %s: nothing wrong found.\n", d.Version)
	case 1:
		fmt.Fprintf(w, "privatae-bastion %s: 1 problem.\n", d.Version)
	default:
		fmt.Fprintf(w, "privatae-bastion %s: %d problems.\n", d.Version, n)
	}
	for _, c := range d.Checks {
		if c.OK {
			fmt.Fprintln(w, "  ok       "+c.Detail)
			continue
		}
		fmt.Fprintln(w, "  PROBLEM  "+c.Problem)
		if c.Fix != "" {
			fmt.Fprintln(w, "           Fix: "+c.Fix)
		}
	}
}
