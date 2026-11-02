package main

// console_hostops.go — the person at the machine always wins: the console
// commands that take reach BACK. Every one
// of them only removes something — an approval, a grant, a hold — so none
// needs machine authority; the local switch (localdeny.go) draws the same line.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cmdStepupDrop revokes one unused approval this box issued for a pairing.
func cmdStepupDrop(host string, machine bool, prefix string) error {
	t, err := resolveStepupTarget(host, machine)
	if err != nil {
		return err
	}
	dir := t.dir
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return errors.New("which approval? (the id `approve` printed)")
	}
	stepupMu.Lock()
	defer stepupMu.Unlock()
	m := approvalsLoad(dir)
	var hits []string
	for id, a := range m {
		if !a.Used && strings.HasPrefix(id, prefix) {
			hits = append(hits, id)
		}
	}
	switch len(hits) {
	case 0:
		return fmt.Errorf("no unused approval starts with %q %s", prefix, t.forWhom())
	case 1:
	default:
		return fmt.Errorf("%d approvals start with %q — give more of the id", len(hits), prefix)
	}
	a := m[hits[0]]
	a.Used = true // burned without ever having run: the same end state a use reaches
	m[hits[0]] = a
	if err := approvalsSave(dir, m); err != nil {
		return err
	}
	fmt.Printf("dropped approval %s (%s) — nothing can run on it now\n", hits[0][:8], a.Purpose)
	return nil
}

// cmdGrantsDrop removes a held store grant from this box.
func cmdGrantsDrop(host, store string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(store), 10, 64)
	if err != nil {
		return errors.New("store id must be a number (the id on the host's store card)")
	}
	dir := cfg.dcnDir()
	present, err := dcnDropStore(dir, id, "dropped at this machine's console")
	if err != nil {
		return err
	}
	if !present {
		fmt.Printf("store %d was not held here for %s\n", id, cfg.HostName)
		return nil
	}
	fmt.Printf("store %d dropped for %s — the host's reads of it stop now and it learns on the next check-in\n", id, cfg.HostName)
	return nil
}

// cmdQuarantineClear lifts this box's hold on a pairing's write lanes.
func cmdQuarantineClear(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("which host?")
	}
	if until := quarantinedUntil(host, time.Now()); until.IsZero() {
		fmt.Printf("%s is not quarantined here\n", host)
		return nil
	}
	quarantineClear(host)
	fmt.Printf("%s may ask this machine for writes again (with your approval, as before)\n", host)
	return nil
}

// cmdOpsList prints the ops and op grants a pairing holds here (ops.go).
// opRow is one op a Host holds here, verified against its signature or not.
type opRow struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	Privilege   string `json:"privilege,omitempty"`
	Summary     string `json:"summary,omitempty"`
	NotVerified string `json:"not_verified,omitempty"`
}

// opGrantRow is one op grant this machine holds and has not dropped.
type opGrantRow struct {
	ID          string `json:"id"`
	Op          string `json:"op,omitempty"`
	Version     string `json:"version,omitempty"`
	RunsLeft    int    `json:"runs_left"`
	Until       string `json:"until,omitempty"`
	Within      string `json:"within,omitempty"`
	NotVerified string `json:"not_verified,omitempty"`
}

// opsRead is what ops and op grants one pairing holds on this machine.
type opsRead struct {
	Host               string       `json:"host"`
	Sandbox            bool         `json:"sandbox"`
	SandboxUnavailable string       `json:"sandbox_unavailable,omitempty"`
	Ops                []opRow      `json:"ops"`
	Grants             []opGrantRow `json:"grants"`
}

func readOps(o readOpts) (opsRead, error) {
	cfg, err := stepupPairing(o.Host)
	if err != nil {
		return opsRead{}, err
	}
	dir := cfg.dcnDir()
	v := opsRead{Host: cfg.HostName, Ops: []opRow{}, Grants: []opGrantRow{}}
	v.Sandbox, v.SandboxUnavailable = opSandboxAvailable()
	if entries, err := os.ReadDir(opsDir(dir)); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == opsRunsDirName || strings.HasSuffix(e.Name(), ".tmp") {
				continue
			}
			r := opRow{ID: e.Name()[:12]}
			if m, err := opLoad(dir, e.Name()); err == nil {
				r.Name, r.Version, r.Privilege, r.Summary = m.Name, m.Version, m.Privilege, m.Summary
			} else {
				r.NotVerified = err.Error()
			}
			v.Ops = append(v.Ops, r)
		}
	}
	f := opsLoad(dir)
	nonces := make([]string, 0, len(f.Grants))
	for nonce, rec := range f.Grants {
		if rec.Dropped == "" {
			nonces = append(nonces, nonce)
		}
	}
	sort.Strings(nonces)
	for _, nonce := range nonces {
		rec := f.Grants[nonce]
		r := opGrantRow{ID: nonce[:8], RunsLeft: rec.UsesLeft}
		if t, err := verifyOpTerms(dir, rec.TermsCanonical, rec.Signature, opKindGrant); err != nil {
			r.NotVerified = err.Error()
		} else {
			r.Op, r.Version, r.Until, r.Within = t.Op, t.Version, t.Expires, t.Bounds
		}
		v.Grants = append(v.Grants, r)
	}
	return v, nil
}

func cmdOpsList(host string, asJSON bool) error {
	v, err := readMachine("ops", readOpts{Host: host}, readOps)
	if err != nil {
		return laneRefusalError("ops", err)
	}
	if asJSON {
		return printJSON(os.Stdout, v)
	}
	printOps(os.Stdout, v)
	return nil
}

func printOps(w io.Writer, v opsRead) {
	if v.Sandbox {
		fmt.Fprintln(w, "sandbox: available")
	} else {
		fmt.Fprintln(w, "sandbox: NOT available —", v.SandboxUnavailable)
	}
	for _, r := range v.Ops {
		if r.NotVerified != "" {
			fmt.Fprintf(w, "op  [%s]  NOT VERIFIED: %s\n", r.ID, r.NotVerified)
			continue
		}
		fmt.Fprintf(w, "op  %s %s  as %s  [%s]\n    %s\n", r.Name, r.Version, r.Privilege, r.ID, r.Summary)
	}
	for _, r := range v.Grants {
		if r.NotVerified != "" {
			fmt.Fprintf(w, "grant [%s]  NOT VERIFIED: %s\n", r.ID, r.NotVerified)
			continue
		}
		fmt.Fprintf(w, "grant [%s]  %s %s  %d run(s) left, until %s\n    within: %s\n", r.ID, r.Op, r.Version, r.RunsLeft, r.Until, r.Within)
	}
	if len(v.Ops) == 0 && len(v.Grants) == 0 {
		fmt.Fprintln(w, "no ops held for", v.Host)
	}
}

// cmdOpsDrop takes a held op grant back at the console.
func cmdOpsDrop(host, prefix string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	prefix = strings.TrimSpace(prefix)
	if prefix == "--all" {
		dropped, err := opsDropWhere(dir, "dropped at this machine's console", func(string, *opGrantRec) bool { return true })
		if err != nil {
			return err
		}
		fmt.Printf("%d op grant(s) dropped — the host cannot run under any of them again\n", len(dropped))
		return nil
	}
	var hits []string
	for nonce, rec := range opsLoad(dir).Grants {
		if rec.Dropped == "" && strings.HasPrefix(nonce, prefix) {
			hits = append(hits, nonce)
		}
	}
	switch len(hits) {
	case 0:
		return fmt.Errorf("no held op grant starts with %q", prefix)
	case 1:
	default:
		return fmt.Errorf("%d grants start with %q — give more of the id", len(hits), prefix)
	}
	if _, err := opsDropGrant(dir, hits[0], "dropped at this machine's console"); err != nil {
		return err
	}
	fmt.Printf("op grant %s dropped — the host cannot run under it again\n", hits[0][:8])
	return nil
}
