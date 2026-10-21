package main

import (
	"sync"
	"time"
)

// The last host-directed action this box REFUSED, carried to the host on the
// enforcing report.
//
// Refusal visibility was uneven on the heartbeat-directive path. A refused
// mirror placement is reported host-side through the mirror
// report, but a refused self-update or contain only fmt.Printf'd on the box. So
// the host asks a machine to update, nothing happens, and the only record is a
// line in a log on the far side of the tunnel.
//
// That is the same failure shape this whole change exists to avoid, turned
// inward. The gate refuses LOUDLY rather than withholding a lane, precisely so
// an operator is never left staring at an absence — and then the two most
// consequential directives refused quietly. This needs no new heartbeat field
// and no host-side handling. The
// enforcing report is already the box's own attestation of what it is applying,
// already rides every beat, and is REPLACED each beat rather than COALESCEd
// (the host replaces the row), so a field here is live by construction and needs no
// column and no migration.
//
// Last-one-wins with a timestamp, and cleared when the same directive later
// succeeds — so "the anchor was fixed and the update went through" stops
// reporting, instead of leaving a stale refusal on screen for ever.
var (
	directiveMu         sync.Mutex
	lastRefusalWhat     string
	lastRefusalWhy      string
	lastRefusalAt       time.Time
	directiveRefusalNow = time.Now // seam: the test pins the timestamp
)

// recordDirectiveRefusal notes that `what` was refused, and why. `what` is the
// directive KIND (self-update, contain, mirror placement), not the instance, so
// a later success of the same kind can clear it.
func recordDirectiveRefusal(what, why string) {
	directiveMu.Lock()
	defer directiveMu.Unlock()
	lastRefusalWhat, lastRefusalWhy, lastRefusalAt = what, why, directiveRefusalNow().UTC()
}

// clearDirectiveRefusal is called when a directive of that kind SUCCEEDS. A
// refusal that has since been resolved must stop being reported: the host would
// otherwise show a machine as refusing something it now does.
func clearDirectiveRefusal(what string) {
	directiveMu.Lock()
	defer directiveMu.Unlock()
	if lastRefusalWhat == what {
		lastRefusalWhat, lastRefusalWhy, lastRefusalAt = "", "", time.Time{}
	}
}

// directiveRefusalReport is the enforcing-report fragment, or nil when this box
// has refused nothing since it started (or since the refusal was resolved).
func directiveRefusalReport() map[string]any {
	directiveMu.Lock()
	defer directiveMu.Unlock()
	if lastRefusalWhat == "" {
		return nil
	}
	return map[string]any{
		"what": lastRefusalWhat,
		"why":  lastRefusalWhy,
		"at":   lastRefusalAt.Format(time.RFC3339),
	}
}
