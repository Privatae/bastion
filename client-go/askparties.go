package main

// askparties.go — who asked to stop what, in the form the audit keeps: the
// asking account (the kernel's answer), the asking process and the agent it
// descends from, and the target, each with how it was started (origin.go:
// interactive, scheduler, service, ...). They are kept on the request itself
// (Details "asker" and "target"), so every later row about that request —
// approved, denied, carried out — names both, not only the row that filed it.

// askingAgentObs is the observed agent pid descends from, and its pid.
func askingAgentObs(pid int, observed map[int]agentObs) (agentObs, int, bool) {
	parents := processTree()
	p := pid
	for i := 0; p > 1 && i < 64; i++ {
		if a, ok := observed[p]; ok && a.Kind != kindApp {
			return a, p, true
		}
		p = parents[p]
	}
	return agentObs{}, 0, false
}

// askParties describes the asker and the target of one stop ask. askerPID is
// the kernel's pid for the asking process, 0 where the platform does not say.
func askParties(account string, askerPID, targetPID int, observed map[int]agentObs) (asker, target map[string]any) {
	asker = map[string]any{"account": account}
	if askerPID > 1 {
		asker["pid"] = askerPID
		if a, p, ok := askingAgentObs(askerPID, observed); ok {
			asker["agent"] = agentParty(a, p)
		}
	}
	target = agentParty(observed[targetPID], targetPID)
	return asker, target
}

func agentParty(a agentObs, pid int) map[string]any {
	out := map[string]any{"pid": pid, "signature": a.Signature, "name": familyLabel(a.Signature)}
	if a.Origin != "" {
		out["origin"] = a.Origin
	}
	return out
}

// askPartiesOf is what a request carries about its asker and target, for an
// audit row; nil for a request no local agent asked (a Host's).
func askPartiesOf(d map[string]any) map[string]any {
	if kind, _ := d["kind"].(string); kind != localStopKind {
		return nil // "target" is a critical_action's own word, not a party
	}
	out := map[string]any{}
	for _, k := range []string{"asker", "target"} {
		if v, ok := d[k]; ok && v != nil {
			out[k] = v
		}
	}
	if by, _ := d["asked_by"].(string); by != "" {
		out["who"] = by
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// hostAskDetails drops from a Host's request the fields only this machine
// writes about a local agent's ask. A Host's details are its own words, so
// without this it could name an account on this computer as the asker in the
// owner's audit, and have the owner's deny count against that account.
func hostAskDetails(d map[string]any) {
	delete(d, "asked_by_account")
	delete(d, "asker")
	if kind, _ := d["kind"].(string); kind == localStopKind {
		delete(d, "asked_by")
		delete(d, "target")
	}
}
