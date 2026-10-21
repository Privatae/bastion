package main

// deltastate.go — the little bit of memory a delta needs to be about TIME
// rather than about one scan.
//
// Three questions cannot be answered by comparing two lists, and each of them
// is the difference between a useful finding and a noisy one:
//
//	how long has this been missing   an absence is only a finding once it has
//	                                 outlasted a restart (deltaGoneGrace)
//	when did we first see this       "new since" on the beat, and the age of a
//	                                 finding a person is looking at
//	did that one survive             the short-lived rule counts what came and
//	                                 went instead of reporting it
//
// IT IS NOT ONLY BOOKKEEPING ANY MORE, and that changed underneath this
// paragraph. Since the bastion's own (digest, version) pair moved in here, this
// file is what PINS a `binary_digest_changed` critical: a same-version swap
// repeats every pass because the pair is not advanced past it, and deleting
// this file unpins it. Measured: with the state
// removed, the next pass reports the same swap as `high` — an update, because
// the accounting's version is older — and the pass after that reports nothing.
// The next legitimate fleet update clears it the same way.
//
// So its real lifetime is "until a retake, the next version change, OR the loss
// of this file", not the "until somebody retakes the accounting" this and
// deltarun.go used to say. Inside the accepted threat model — a root intruder
// can also stop the daemon — and written down because a load-bearing file
// described as disposable is how the next person deletes it to fix something
// else.
//
// It is still deliberately NOT digest-protected: it lives in the bastion's own
// 0700 state directory, and a digest here would imply a guarantee about
// timestamps that a file in a directory its owner can write cannot make.
//
// IT IS THROWN AWAY WHEN THE BASELINE CHANGES. A retake redefines what normal
// is; grace timers and first-seen stamps measured against the old accounting
// would then be timing things that are no longer being compared.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const deltaStateVersion = "privatae-delta-state-v1"

type deltaState struct {
	Version string `json:"version"`
	// Baseline is the digest of the accounting this state was kept against.
	Baseline string `json:"baseline"`
	// MissingSince: entry fingerprint -> when it was first not seen.
	MissingSince map[string]string `json:"missing_since,omitempty"`
	// FirstSeen / LastSeen: finding fingerprint -> when this box first and last
	// saw it. LastSeen is what lets the file be pruned without losing the age
	// of anything still current.
	FirstSeen map[string]string `json:"first_seen,omitempty"`
	LastSeen  map[string]string `json:"last_seen,omitempty"`
	// SeenKind: finding fingerprint -> the entry kind it belongs to, so a
	// prune on a pass that could not see that class does not forget it. A
	// fingerprint with no kind predates the listener and identity classes, so
	// it is a process or a scheduler, which are never left out one class at a
	// time (a failed walk skips the prune altogether).
	SeenKind map[string]string `json:"seen_kind,omitempty"`
	// Held: fingerprint -> when the short-lived rule first held it back.
	Held map[string]string `json:"held,omitempty"`
	// ShortLived is the running count of held entries that were gone by the
	// next pass — the storm counter, never reset by a report, so a box
	// spawning thousands of brief processes says so even though none of them
	// is a finding.
	ShortLived int `json:"short_lived"`
	// BastionDigest / BastionVersion: the bastion binary as the LAST PASS saw
	// it. Seeded from the accounting and moved forward on every pass that has
	// nothing to report or reports an update — never past a same-version swap,
	// which is what pins that critical. The accounting's own copy is frozen at
	// the moment it was taken and the fleet updates itself; see deltaBinaryEvent
	// for what comparing against a frozen version does to the rung.
	BastionDigest  string `json:"bastion_digest,omitempty"`
	BastionVersion string `json:"bastion_version,omitempty"`

	dirty bool
	// settledThisPass is how many were counted by THIS pass. Not persisted:
	// it is a property of one run, and the running total above is the part
	// that outlives it.
	settledThisPass int
	// blindKinds and blindFPs are the classes THIS pass did not compare, and
	// the accounting's fingerprints in them. Not persisted: set by deltaPass
	// before the clocks run, a property of one pass. Every clock below reads
	// "absent from this pass" as "came back", "settled" or "stale", which is
	// only true of a class the pass actually looked at.
	blindKinds map[string]bool
	blindFPs   map[string]bool
}

// deltaStateForget is how long a fingerprint nobody has seen is kept. A week is
// long enough that a laptop shut for the weekend does not come back with every
// finding reading as brand new, and short enough that the file cannot grow
// without bound on a box that churns.
const deltaStateForget = 7 * 24 * time.Hour

func deltaStatePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "delta-state.json"), nil
}

// deltaStateLoad reads the state, or returns an empty one. An unreadable or
// corrupt file is NOT an error: refusing to run the detection plane because a
// bookkeeping file was truncated would trade the whole feature for the thing it
// is least sure about.
//
// What it costs is one pass with no memory — a gone-grace restarted, a
// first-seen re-stamped — AND, since the bastion's own digest moved in here, an
// unpinned binary critical: the next pass re-reads that swap against the
// accounting's older version, calls it an update, and goes quiet. That is the
// price of failing open here, and it is written down rather than implied.
func deltaStateLoad(baselineDigest string) *deltaState {
	fresh := &deltaState{Version: deltaStateVersion, Baseline: baselineDigest, dirty: true}
	p, err := deltaStatePath()
	if err != nil {
		return fresh
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return fresh
	}
	var st deltaState
	if json.Unmarshal(b, &st) != nil {
		return fresh
	}
	if st.Version != deltaStateVersion || st.Baseline != baselineDigest {
		return fresh
	}
	return &st
}

func (s *deltaState) save() error {
	if !s.dirty {
		return nil
	}
	p, err := deltaStatePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	// Re-chmod for the reason baselineSave does (baseline.go:359-362): WriteFile
	// applies its mode only on create, so a file first written under a loose
	// umask keeps those permissions for ever.
	_ = os.Chmod(p, 0o600)
	s.dirty = false
	return nil
}

func parseStamp(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (s *deltaState) missingSince(fp string) (time.Time, bool) {
	t, ok := parseStamp(s.MissingSince[fp])
	return t, ok
}

func (s *deltaState) setMissingSince(fp string, at time.Time) {
	if s.MissingSince == nil {
		s.MissingSince = map[string]string{}
	}
	s.MissingSince[fp] = stamp(at)
	s.dirty = true
}

// keepMissing drops every absence not in the set — the entries that came back.
func (s *deltaState) keepMissing(still map[string]bool) {
	for fp := range s.MissingSince {
		if !still[fp] && !s.blindFPs[fp] {
			delete(s.MissingSince, fp)
			s.dirty = true
		}
	}
}

// seen records a sighting and returns when this box FIRST saw this fingerprint.
func (s *deltaState) seen(fp string, at time.Time) time.Time {
	if s.FirstSeen == nil {
		s.FirstSeen = map[string]string{}
	}
	if s.LastSeen == nil {
		s.LastSeen = map[string]string{}
	}
	first, ok := parseStamp(s.FirstSeen[fp])
	if !ok {
		first = at
		s.FirstSeen[fp] = stamp(at)
	}
	s.LastSeen[fp] = stamp(at)
	s.dirty = true
	return first
}

// noteKind records which class a finding fingerprint belongs to (see SeenKind).
func (s *deltaState) noteKind(fp, kind string) {
	if kind == "" || s.SeenKind[fp] == kind {
		return
	}
	if s.SeenKind == nil {
		s.SeenKind = map[string]string{}
	}
	s.SeenKind[fp] = kind
	s.dirty = true
}

// setBlind tells this pass's clocks which classes it did not compare, and
// which of the accounting's fingerprints belong to them.
func (s *deltaState) setBlind(kinds []string, accounting []baselineEntry) {
	s.blindKinds, s.blindFPs = map[string]bool{}, map[string]bool{}
	for _, k := range kinds {
		s.blindKinds[k] = true
	}
	for _, e := range accounting {
		if s.blindKinds[e.Kind] {
			s.blindFPs[e.FP] = true
		}
	}
}

func (s *deltaState) heldSince(fp string) (time.Time, bool) {
	t, ok := parseStamp(s.Held[fp])
	return t, ok
}

func (s *deltaState) hold(fp string, at time.Time) {
	if s.Held == nil {
		s.Held = map[string]string{}
	}
	if _, already := s.Held[fp]; !already {
		s.Held[fp] = stamp(at)
		s.dirty = true
	}
}

// settleHeld closes out the hold list for one pass: everything still held that
// was NOT seen this time around lived and died between two scans, which is the
// short-lived count. Returns how many were counted this pass.
func (s *deltaState) settleHeld(seenThisPass map[string]bool) int {
	n := 0
	for fp := range s.Held {
		if seenThisPass[fp] {
			continue
		}
		// A listener hold on a pass that could not read the socket table was
		// not seen because nothing looked, not because it went away.
		if s.blindKinds["listener"] && strings.HasPrefix(fp, deltaListenerHoldPrefix) {
			continue
		}
		delete(s.Held, fp)
		s.ShortLived++
		n++
		s.dirty = true
	}
	s.settledThisPass = n
	return n
}

func (s *deltaState) setBastion(digest, version string) {
	if s.BastionDigest == digest && s.BastionVersion == version {
		return
	}
	s.BastionDigest, s.BastionVersion = digest, version
	s.dirty = true
}

// release stops holding a fingerprint — it survived, so it is a finding now.
func (s *deltaState) release(fp string) {
	if _, held := s.Held[fp]; held {
		delete(s.Held, fp)
		s.dirty = true
	}
}

// prune forgets fingerprints nobody has seen for deltaStateForget.
func (s *deltaState) prune(now time.Time) {
	for fp, last := range s.LastSeen {
		t, ok := parseStamp(last)
		if ok && now.Sub(t) < deltaStateForget {
			continue
		}
		if s.blindKinds[s.SeenKind[fp]] {
			continue // not refreshed because its class was not looked at
		}
		delete(s.LastSeen, fp)
		delete(s.FirstSeen, fp)
		delete(s.SeenKind, fp)
		delete(s.Held, fp)
		s.dirty = true
	}
}
