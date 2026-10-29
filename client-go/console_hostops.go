package main

// console_hostops.go — the person at the machine always wins: the console
// commands that take reach BACK. Every one
// of them only removes something — an approval, a grant, a hold — so none
// needs machine authority; the local switch (localdeny.go) draws the same line.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// cmdStepupDrop revokes one unused approval this box issued for a pairing.
func cmdStepupDrop(host, prefix string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
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
		return fmt.Errorf("no unused approval starts with %q for %s", prefix, cfg.HostName)
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
func cmdOpsList(host string) error {
	cfg, err := stepupPairing(host)
	if err != nil {
		return err
	}
	dir := cfg.dcnDir()
	ok, why := opSandboxAvailable()
	if ok {
		fmt.Println("sandbox: available")
	} else {
		fmt.Println("sandbox: NOT available —", why)
	}
	n := 0
	if entries, err := os.ReadDir(opsDir(dir)); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == opsRunsDirName || strings.HasSuffix(e.Name(), ".tmp") {
				continue
			}
			n++
			if m, err := opLoad(dir, e.Name()); err == nil {
				fmt.Printf("op  %s %s  as %s  [%s]\n    %s\n", m.Name, m.Version, m.Privilege, e.Name()[:12], m.Summary)
			} else {
				fmt.Printf("op  [%s]  NOT VERIFIED: %v\n", e.Name()[:12], err)
			}
		}
	}
	f := opsLoad(dir)
	for nonce, rec := range f.Grants {
		if rec.Dropped != "" {
			continue
		}
		t, err := verifyOpTerms(dir, rec.TermsCanonical, rec.Signature, opKindGrant)
		if err != nil {
			fmt.Printf("grant [%s]  NOT VERIFIED: %v\n", nonce[:8], err)
			continue
		}
		fmt.Printf("grant [%s]  %s %s  %d run(s) left, until %s\n    within: %s\n", nonce[:8], t.Op, t.Version, rec.UsesLeft, t.Expires, t.Bounds)
	}
	if n == 0 && len(f.Grants) == 0 {
		fmt.Println("no ops held for", cfg.HostName)
	}
	return nil
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
