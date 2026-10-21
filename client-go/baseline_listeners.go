package main

// LISTENERS ENTER THE ACCOUNTING.
//
// A listening port is the thing an intruder needs and the thing a person can
// actually reason about: "this machine started answering on 4444" is a sentence
// with a decision behind it, in a way that "a new process appeared" often is
// not. It is also the class this plane was missing from its first version —
// baselineEntry.Kind has documented `listener` from the start and nothing ever
// wrote one, which is what the fixed note in delta.go existed to admit.
//
// THE SLOT IS THE BIND POINT, THE FINGERPRINT ADDS WHO HOLDS IT. That split is
// not decoration, it is what makes the three events mean different things:
//
//	a port nothing was on before        -> listener_new       (the alarming one)
//	the same port, a different program  -> listener_changed   (more alarming)
//	a port that stopped answering       -> listener_gone
//
// Keyed the same way processes are, for the same reason: the SLOT is position
// (proto + address + port) and the FINGERPRINT is position plus identity (the
// program holding it). Had the program been part of the slot, a service
// replaced at the same port would have come out as an unrelated gone/new pair
// and the sentence a person needs — "something else is answering on 443 now" —
// could not be formed.
//
// DELIBERATELY ABSENT: the pid. It changes on every restart of the same
// service, and baseline.go:36-38 gives the rule. It is carried on the live
// entry (deltaLiveEntry.PIDs) where the noise filter and the kill path need it,
// exactly as processes do.
//
// THE ADDRESS IS PART OF THE SLOT, and this is the one judgement here worth
// arguing with. 127.0.0.1:9000 and 0.0.0.0:9000 are different facts about a
// machine — one is reachable from the network and one is not — so a service
// that starts binding the wildcard instead of loopback SHOULD be a new listener
// rather than a silent change of a known one. The cost is that a box whose
// address changes (DHCP, a new interface) reports its listeners as new once;
// the alternative costs the detection of a service quietly opening itself to
// the network, which is the whole point of the class.

import (
	"sort"
	"strconv"
	"strings"
)

// baselineFromListeners turns a socket table into accounting entries. Pure, and
// shared by BOTH sides — collectBaseline and deltaCollectLive — because the one
// defect this plane has already shipped twice is the two sides folding the same
// observations differently (deltaCollectLiveFrom says so at length).
//
// Returns the entries and the pids that produced each, in step: the caller
// building live entries needs the pids, the caller building the accounting
// throws them away.
func baselineFromListeners(socks []listenSocket) ([]baselineEntry, [][]int) {
	// FOLDED BY FINGERPRINT, because one service legitimately holds several
	// sockets that are the same fact. sshd on :22 over IPv4 and IPv6 is one
	// listener to a person; nginx with four workers accept()ing the same bound
	// port is one listener too. Unfolded, a restart that redistributed workers
	// would churn the accounting with no change to the machine.
	byFP := map[string]int{}
	var out []baselineEntry
	var pids [][]int
	for _, s := range socks {
		e := baselineEntryOfListener(s)
		if i, seen := byFP[e.FP]; seen {
			if s.PID > 0 {
				pids[i] = appendPID(pids[i], s.PID)
			}
			continue
		}
		byFP[e.FP] = len(out)
		out = append(out, e)
		if s.PID > 0 {
			pids = append(pids, []int{s.PID})
		} else {
			pids = append(pids, nil)
		}
	}
	return out, pids
}

// baselineEntryOfListener is the single constructor. Both sides call it; a
// second spelling of this is how the two halves drift.
func baselineEntryOfListener(s listenSocket) baselineEntry {
	proc := strings.TrimSpace(s.Process)
	if proc == "" {
		// A SOCKET WHOSE OWNER THIS BOX COULD NOT READ IS NOT AN OWNERLESS
		// SOCKET. `ss` omits the process column for sockets belonging to
		// another user when it is not run as root, and for kernel-side
		// listeners that have no userspace process at all. Recording "" as
		// though it were the program's name would make every such socket one
		// fingerprint, so two unrelated unreadable listeners would collide and
		// the second would never be reported. The marker keeps them distinct by
		// their bind point, which is the part this box DID observe.
		proc = listenerOwnerUnknown
	}
	e := baselineEntry{
		Kind: "listener",
		// Unit carries the bind point, so baselineSlot's generic path produces
		// the slot for free and there is one slot rule rather than two.
		Unit: listenerBindPoint(s),
		// ArgvShape carries the holder. Reusing the fingerprinted fields rather
		// than adding listener-only ones keeps this class inside the digest
		// rules baseline.go already documents, instead of beside them.
		ArgvShape: proc,
		Origin:    "socket-table",
	}
	e.FP = baselineFP(e.Kind, e.ExeDigest, e.User, e.Unit, e.ArgvShape)
	return e
}

// listenerOwnerUnknown is what stands in for a process this box could not read.
// Spelled out rather than left empty for the reason baseline.go gives about
// DigestNote: an absent field reads as "nothing there", and "I could not look"
// is a different fact that the person is entitled to.
const listenerOwnerUnknown = "(owner unreadable)"

// listenerBindPoint is proto/address:port, normalised so the same bind reads
// the same way across passes.
func listenerBindPoint(s listenSocket) string {
	addr := strings.TrimSpace(s.Local)
	if addr == "" {
		addr = "*"
	}
	// ss prints the v6 wildcard as [::] and the v4 one as 0.0.0.0 or *. They are
	// different binds and stay different; only the empty case is normalised.
	return strings.ToLower(s.Proto) + "/" + addr + ":" + strconv.Itoa(s.Port)
}

func appendPID(xs []int, p int) []int {
	for _, x := range xs {
		if x == p {
			return xs
		}
	}
	xs = append(xs, p)
	sort.Ints(xs)
	return xs
}
