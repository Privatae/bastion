package main

import (
	"encoding/json"
	"os"
)

// cmdObserve prints the observe plane's snapshot for THIS box exactly as the
// heartbeat would carry it: every observed process with its kind, origin
// and evidence, the scheduled entries that would run an agent or automation,
// and the scan reports that say what could be read. It is the detection
// plane's first gate — a cron job running an agent shows as agent · origin
// scheduler · no tty — made runnable on any machine
// the bastion is installed on, and it is what an operator runs when a card
// on the host does not match what they see on the box.
func cmdObserve() error {
	entries, scan := scanSchedulers()
	out := map[string]any{
		"agent_scan":     agentScanKind,
		"schedulers":     entries,
		"scheduler_scan": scan,
	}
	// Exactly as the heartbeat carries it: a failed walk is no `agents` key
	// plus the reason, never an empty list.
	if agents, err := scanAgents(); err == nil {
		out["agents"] = agents
	} else {
		out["agent_scan_error"] = err.Error()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
