package main

// Peer announcement — how a machine introduces the hosts it serves.
//
// One daemon serves many hosts (config.go: one file per pairing under
// pairings/<host_name>.json). This box is therefore the ONLY party that knows
// the set: the platform cannot derive it, deliberately. Every pairing mints a
// fresh WireGuard keypair, and the "hardware fingerprint" is fresh random bytes
// per pairing (pair.go), so two pairings of one machine are unlinkable from the
// outside. That is the privacy property, and it is why discovery has to be the
// machine ANNOUNCING rather than the platform correlating.
//
// The rule: announcement is automatic and symmetric — pairing IS the
// consent, no approval step. Pair a bastion to a second host and both hosts
// learn of each other on the next heartbeat, which is what makes an IT team's
// hosts assemble themselves with zero steps. It is also how you find out that
// someone paired a host to a machine you own, so it only works if it is loud.
//
// WHAT TRAVELS: host name, handle, and when this box started serving it.
// NOTHING ELSE. Not keys, not grants, not context, not fingerprints. That line
// is load-bearing: multi-homing gives each pairing its own DCN dir precisely so
// that one entity's pinned key can never verify another entity's grants
// (config.go). Sharing a NAME is clear of that; carrying anything a peer could
// verify a grant with would be exactly the cross-host bleed that isolation
// exists to prevent.

// peerAnnounce is one OTHER host this machine serves, as told to a host on its
// own heartbeat. The receiving host treats it as a CLAIM by this bastion, not
// as proof, and it grants nothing.
type peerAnnounce struct {
	HostName string `json:"host_name"`
	Handle   string `json:"handle"`
	// State (anchor.go): active | pending | revoked. Without it a
	// host that shares the box would show a PENDING host — one the anchor has
	// not approved — as an established peer. Absent from bastions before it;
	// the host reads absence as active, which is all those could have been.
	State string `json:"state,omitempty"`
	Since string `json:"since,omitempty"`
}

// peersFor returns every pairing on this box EXCEPT the one identified by
// selfHostName, newest-serving first by name order (loadPairings sorts).
//
// Read fresh on each beat rather than cached at start: `privatae-bastion pair`
// writes a new file into the same directory, and a peer the user just added
// must show up on the next heartbeat without restarting the daemon. That IS
// the popup — a cached list would make the feature arrive whenever the box
// next rebooted.
//
// Best-effort by design: any failure to read the directory returns nil, and the
// heartbeat simply carries no peers. A machine that cannot enumerate its own
// pairings must not fail its liveness beat over it.
func peersFor(selfHostName string) []peerAnnounce {
	cfgs, err := loadPairings()
	if err != nil {
		return nil
	}
	out := make([]peerAnnounce, 0, len(cfgs))
	for _, c := range cfgs {
		if c.HostName == "" || c.HostName == selfHostName {
			continue
		}
		// "Since" is first_seen when the pairing carries it (0.16.0+), else the
		// file's mtime — the honest answer already on disk for older pairings,
		// never faked with time.Now(). Omitted when neither can be read.
		out = append(out, peerAnnounce{HostName: c.HostName, Handle: handleOf(c.HostName),
			State: c.stateName(), Since: sinceOf(c)})
	}
	// EMPTY IS A REAL ANSWER, and it is NOT the same as nil.
	//
	// nil is returned above only when the pairing directory cannot be read: we
	// do not know what this box serves, so we say nothing and the host keeps
	// whatever it already has. An empty (non-nil) slice is this box saying "I
	// enumerated my pairings and I serve only this host" — a genuine state
	// change, and the one that happens when the user unpairs the last other
	// host.
	//
	// Collapsing that into nil would make the change unsendable. The host keeps
	// stored peers on an ABSENT key (its heartbeat upsert falls back to what it
	// already holds when the key is missing) so that a bastion too old to
	// report peers cannot retract them — so "none" arriving as "absent" would
	// leave the Network app listing peers the machine no longer serves, with
	// nothing that could ever clear them.
	return out
}
