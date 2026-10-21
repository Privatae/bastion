//go:build linux

package main

// Every process, not only the ones a signature table already recognises.
//
// THE DEFECT THIS FIXES DEFEATED THE FEATURE. The baseline is meant to walk
// the box and account for every pid. It was built from
// scanAgents(), which is signature-FILTERED — it returns a known agent binary,
// an interpreter-wrapped agent, or a process caught talking to a model
// (agents.go:248-252). So the accounting of "what is normal here" contained
// only things already recognised as agents.
//
// Follow that through and the whole detection story collapses: a brand-new
// unknown binary — precisely the rogue process the product exists to catch — is
// not in the baseline, and the delta built on that baseline would never compare
// against it either. The baseline has to hold EVERYTHING so that "not baseline"
// can mean something; what a process IS stays a property recorded on the entry,
// never a condition for being recorded at all.
//
// Found while answering a narrower review question (schedulers missing
// from a baseline whose own Kind field documented them).

import (
	"os"
	"strconv"
	"strings"
)

// baselineAllProcesses returns one observation per live process, unfiltered.
// The fields are the ones the fingerprint needs and nothing more.
func baselineAllProcesses() ([]agentObs, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	facts := procFactsReader()
	self := os.Getpid()
	out := make([]agentObs, 0, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			// A kernel thread has an empty cmdline. It is not a program anybody
			// installed and it cannot be a rogue agent; excluding it keeps the
			// baseline about userland without needing a name list.
			continue
		}
		argv := splitNul(raw)
		full := strings.Join(argv, " ")
		a := agentObs{
			PID: pid, User: procUser(pid), Cmdline: truncate(full, 200),
			Exe: procExe(pid), raw: full,
		}
		if f, ok := facts(pid); ok {
			a.Unit = f.Unit
			a.PPID = f.PPID
		}
		// The signature when there IS one, as a PROPERTY of the entry. An
		// unrecognised process is still recorded; it simply has no signature,
		// which is itself the interesting fact about it.
		if sig, auto, ok := matchSignature(argv); ok {
			a.Signature, a.automation = sig, auto
		}
		out = append(out, a)
	}
	return out, true
}
