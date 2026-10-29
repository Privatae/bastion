package main

// quarantine.go — the box notices abuse of its management lane and closes the
// lane itself.
//
// Two records, both on the enforcing report every beat:
//
//   - a RING of the last refusals on the management lane (not only the last
//     directive refusal directive_refusal.go keeps): who asked, for what, why
//     it was refused, when. The host turns each into an oversight finding.
//   - a QUARANTINE per pairing: five refused WRITE requests from one pairing
//     inside ten minutes close that pairing's write lanes on this box for ten
//     minutes, doubling on every repeat. fail2ban's defaults (5 tries / 10 min
//     / 10 min ban), not numbers invented here. Reads stay open, so the host
//     can still see the finding that explains the refusals; the person at the
//     machine can clear it early at the console.
//
// The probe pattern of 2026-09-24 — refused a read, try a machine, try another
// lane — becomes something the machine itself notices and stops, rather than
// only something the host is told not to do.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	quarantineStrikes  = 5
	quarantineWindow   = 10 * time.Minute
	quarantineBase     = 10 * time.Minute
	quarantineMaxHold  = 24 * time.Hour // the doubling stops here
	quarantineForgive  = 24 * time.Hour // a clean day resets the doubling
	refusalRingMax     = 50
	quarantineFileName = "quarantine.json"
)

var quarantineMu sync.Mutex

type refusalRecord struct {
	TS      string `json:"ts"`
	Pairing string `json:"pairing"`
	Op      string `json:"op"`
	Why     string `json:"why"`
	Write   bool   `json:"write"`
}

type quarantineEntry struct {
	Until    string   `json:"until"`              // RFC3339; "" = not quarantined
	Strikes  int      `json:"strikes"`            // how many holds so far (doubling)
	Refusals []string `json:"refusals,omitempty"` // RFC3339 of recent write refusals
	// LastHold is when the last hold ENDED. A pairing that has behaved for
	// quarantineForgive since then starts again at the base hold — strikes
	// that never decayed would make a hold months later a day long.
	LastHold string `json:"last_hold,omitempty"`
}

type quarantineFile struct {
	Ring    []refusalRecord             `json:"ring"`
	Pairing map[string]*quarantineEntry `json:"pairing"`
}

func quarantinePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, quarantineFileName), nil
}

func quarantineLoad() *quarantineFile {
	f := &quarantineFile{Pairing: map[string]*quarantineEntry{}}
	p, err := quarantinePath()
	if err != nil {
		return f
	}
	raw, err := os.ReadFile(p)
	if err == nil {
		_ = json.Unmarshal(raw, f)
	}
	if f.Pairing == nil {
		f.Pairing = map[string]*quarantineEntry{}
	}
	return f
}

func quarantineSave(f *quarantineFile) error {
	p, err := quarantinePath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, raw)
}

// refusalCounts: does this refusal count as a strike? A refused WRITE that
// the host could have known better than to ask for — an approval that did
// not check out, a family it does not hold, a switched-off lane. NOT a read;
// NOT an op this build does not know (version skew between host and box is
// not the host probing); NOT "this box holds no way to take an approval",
// which is the box's own state and would otherwise let a fresh fleet box
// quarantine its anchor on the first five writes after the roll.
func refusalCounts(op, why string) bool {
	if !opWrites(op) {
		return false
	}
	if strings.Contains(why, noWayToApprove) || strings.HasSuffix(why, "not permitted on this host") ||
		strings.Contains(why, noSandboxHere) || strings.Contains(why, noVerbToolHere) {
		return false
	}
	return true
}

// noteRefusal records one refusal on the lane. A counting refusal (see
// refusalCounts) from a named pairing goes toward that pairing's quarantine;
// everything else is recorded and never counted.
func noteRefusal(pairing, op, why string, write bool, now time.Time) {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	f := quarantineLoad()
	f.Ring = append(f.Ring, refusalRecord{TS: now.UTC().Format(time.RFC3339),
		Pairing: pairing, Op: truncate(op, mgmtAuditOpMax), Why: truncate(why, mgmtAuditWhyMax), Write: write})
	if len(f.Ring) > refusalRingMax {
		f.Ring = f.Ring[len(f.Ring)-refusalRingMax:]
	}
	if write && pairing != "" {
		e := f.Pairing[pairing]
		if e == nil {
			e = &quarantineEntry{}
			f.Pairing[pairing] = e
		}
		// A refusal DURING a hold is the hold working, not a new strike: the
		// quarantine refusal itself comes through here, and counting it would
		// re-arm the hold the moment it lapsed.
		if quarantinedAt(e, now) {
			_ = quarantineSave(f)
			return
		}
		// Recent write refusals only — the window slides.
		kept := e.Refusals[:0]
		for _, ts := range e.Refusals {
			if t, err := time.Parse(time.RFC3339, ts); err == nil && now.Sub(t) < quarantineWindow {
				kept = append(kept, ts)
			}
		}
		e.Refusals = append(kept, now.UTC().Format(time.RFC3339))
		if len(e.Refusals) >= quarantineStrikes && !quarantinedAt(e, now) {
			if t, err := time.Parse(time.RFC3339, e.LastHold); err == nil && now.Sub(t) > quarantineForgive {
				e.Strikes = 0
			}
			hold := quarantineBase
			for i := 0; i < e.Strikes && hold < quarantineMaxHold; i++ {
				hold *= 2
			}
			if hold > quarantineMaxHold {
				hold = quarantineMaxHold
			}
			e.Strikes++
			e.Until = now.Add(hold).UTC().Format(time.RFC3339)
			e.LastHold = e.Until
			e.Refusals = nil
		}
	}
	_ = quarantineSave(f)
}

func quarantinedAt(e *quarantineEntry, now time.Time) bool {
	if e == nil || e.Until == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, e.Until)
	return err == nil && t.After(now)
}

// quarantinedUntil: when this pairing's write lanes reopen, or the zero time.
func quarantinedUntil(pairing string, now time.Time) time.Time {
	if pairing == "" {
		return time.Time{}
	}
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	e := quarantineLoad().Pairing[pairing]
	if !quarantinedAt(e, now) {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, e.Until)
	return t
}

// quarantineClear — the person at the machine lifts the hold (and the strike
// count with it: a cleared hold is forgiven, not merely paused).
func quarantineClear(pairing string) {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	f := quarantineLoad()
	delete(f.Pairing, pairing)
	_ = quarantineSave(f)
}

// quarantineReport is the enforcing-report fragment: the ring and the live
// holds. nil when there is nothing to say, so a quiet box says nothing.
func quarantineReport(now time.Time) map[string]any {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	f := quarantineLoad()
	holds := map[string]any{}
	for p, e := range f.Pairing {
		if quarantinedAt(e, now) {
			holds[p] = map[string]any{"until": e.Until, "strikes": e.Strikes}
		}
	}
	if len(f.Ring) == 0 && len(holds) == 0 {
		return nil
	}
	ring := f.Ring
	if len(ring) > 20 { // the beat carries the newest twenty; audit_fetch has the rest
		ring = ring[len(ring)-20:]
	}
	out := map[string]any{"refusals": ring}
	if len(holds) > 0 {
		names := make([]string, 0, len(holds))
		for p := range holds {
			names = append(names, p)
		}
		sort.Strings(names)
		out["quarantine"] = holds
		out["quarantined"] = names
	}
	return out
}

func quarantineRefusal(until time.Time) string {
	return fmt.Sprintf("refused: this host's write lanes are quarantined on this machine until %s — "+
		"%d refused writes inside %s. Reads still answer; the person at the machine can lift it "+
		"(privatae-bastion quarantine clear <host>).", until.UTC().Format(time.RFC3339),
		quarantineStrikes, quarantineWindow)
}
