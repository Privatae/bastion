package main

import (
	"sync"
	"time"
)

// ACCOUNT NAMES FOR WINDOWS SIDS, ASKED ONCE PER SCAN AND NEVER FOR LONG.
//
// The Windows process scan names each agent's account (winTokenUser) and
// classifies it (ownerFactsReader), and both turn a SID into an account and a
// domain with LookupAccountSid. On a domain-joined machine that call can go
// to a domain controller, and when the controller cannot be reached it waits
// for the network to give up. Asked per process, with no cache, a scan of a
// few dozen processes could then hold the heartbeat for minutes.
//
// So a scan holds one sidNames: each SID is asked at most once, both callers
// share the answer, and the scan waits on lookups for at most a fixed budget
// in total. Once a lookup has used up the budget, every SID not already
// answered is unresolved for the rest of the scan: the account shows as its
// SID string and the owner's class as unknown, which is what the classifier
// already says when the domain could not be read.
//
// LookupAccountSid cannot be cancelled. A lookup the scan stopped waiting
// for finishes in its own goroutine and is then dropped. At most one lookup
// runs at a time across the process (the slots channel), so a controller
// that stays unreachable for many scans holds one blocked thread, not one per
// scan.
//
// The type has no build tag so the Linux test run checks it with a fake
// lookup; agents_windows.go supplies the real one.

// sidLookupBudget is the most one scan waits on account lookups in total. It
// is a bound on the harm, not a measured lookup time: a scan asks once per
// distinct account, and a domain controller that does not answer costs a
// scan this much of its 60-second beat and no more.
var sidLookupBudget = 2 * time.Second

// sidLookupSlots: one lookup in flight at a time, process-wide.
var sidLookupSlots = make(chan struct{}, 1)

// sidName is one SID's answer. OK is false when the lookup failed, timed
// out, or was never started because the budget was gone.
type sidName struct {
	Account, Domain string
	OK              bool
}

type sidNames struct {
	mu     sync.Mutex
	lookup func(sid string) (account, domain string, err error)
	slots  chan struct{}
	left   time.Duration
	names  map[string]sidName
}

func newSIDNames(lookup func(string) (string, string, error), budget time.Duration, slots chan struct{}) *sidNames {
	return &sidNames{lookup: lookup, slots: slots, left: budget, names: map[string]sidName{}}
}

// resolve answers one SID, from the scan's cache when it has been asked.
func (c *sidNames) resolve(sid string) sidName {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.names[sid]; ok {
		return n
	}
	n := c.ask(sid)
	c.names[sid] = n
	return n
}

// ask runs one lookup within what is left of the budget. Called with mu held.
func (c *sidNames) ask(sid string) sidName {
	if c.left <= 0 {
		return sidName{}
	}
	start := time.Now()
	var n sidName
	finished := boundedSIDCall(c.slots, c.left, func() {
		a, d, err := c.lookup(sid)
		n = sidName{Account: a, Domain: d, OK: err == nil}
	})
	if !finished {
		c.left = 0
		return sidName{}
	}
	c.left -= time.Since(start)
	return n
}

// boundedSIDCall runs call on its own goroutine while holding one of slots,
// and waits for it at most budget in all, the wait for a free slot included.
// It reports whether call finished in time; only then may the caller read
// what call wrote. A call it stopped waiting for keeps its slot until it
// returns, so a lane whose lookup never returns has one blocked goroutine,
// and every later caller on that lane waits its budget and is told no.
func boundedSIDCall(slots chan struct{}, budget time.Duration, call func()) bool {
	if budget <= 0 {
		return false
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
	case <-timer.C:
		return false // an earlier lookup on this lane still holds the slot
	}
	done := make(chan struct{})
	go func() {
		defer func() { <-slots }()
		call()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// ACCOUNT LOOKUPS OUTSIDE A SCAN: the approvals pipe and the folder agent's drop.
//
// Both resolve one SID when something happens (a tray connects, a store's
// agent is started), not once per scan, so they cannot share a scan's budget.
// They share one process-wide cache instead (sidDirectory): an answer is kept
// for sidDirectoryTTL, so the tray's polling asks the directory once per
// account per ten minutes, and a lookup that answers after its caller stopped
// waiting still fills the cache for the next caller. Only an answer is
// cached; a failure or a timeout is asked again next time.
//
// Each caller has its own lane (slot and budget), so a lookup hung on one
// lane never blocks the other or the scan's: at most one goroutine per lane is
// ever held by a directory that does not answer.
//
// What a timeout means is the caller's decision, and both fail closed: the
// pipe refuses an approve (pipeApprove), the drop refuses to start the agent
// (faWinDropOwnerAccount).

// sidAccount is one SID's answer: the account, its domain and its SID type
// (SID_NAME_USE).
type sidAccount struct {
	Account, Domain string
	Type            uint32
}

// sidOutcome is how a lookup outside a scan ended.
type sidOutcome int

const (
	sidResolved sidOutcome = iota // the directory answered with an account
	sidUnmapped                   // the directory answered: no such account
	sidTimedOut                   // the directory did not answer within the lane's budget
)

// sidLane is one caller's single-flight slot and per-lookup budget.
type sidLane struct {
	slots  chan struct{}
	budget time.Duration
}

const (
	sidDirectoryTTL = 10 * time.Minute
	sidDirectoryMax = 256 // accounts kept; a machine has far fewer people
)

type sidCached struct {
	acct sidAccount
	at   time.Time
}

type sidDirectory struct {
	mu     sync.Mutex
	lookup func(sid string) (sidAccount, error)
	now    func() time.Time
	names  map[string]sidCached
}

func newSIDDirectory(lookup func(string) (sidAccount, error)) *sidDirectory {
	return &sidDirectory{lookup: lookup, now: time.Now, names: map[string]sidCached{}}
}

// resolve answers sid from the cache, or asks the directory on lane.
func (d *sidDirectory) resolve(sid string, lane sidLane) (sidAccount, sidOutcome) {
	if a, ok := d.cached(sid); ok {
		return a, sidResolved
	}
	var (
		acct sidAccount
		err  error
	)
	finished := boundedSIDCall(lane.slots, lane.budget, func() {
		// Asked again with the slot held: the lookup this caller queued
		// behind may have just answered for the same SID.
		if a, ok := d.cached(sid); ok {
			acct = a
			return
		}
		acct, err = d.lookup(sid)
		if err == nil {
			d.store(sid, acct) // also when the caller has stopped waiting
		}
	})
	switch {
	case !finished:
		return sidAccount{}, sidTimedOut
	case err != nil:
		return sidAccount{}, sidUnmapped
	}
	return acct, sidResolved
}

func (d *sidDirectory) cached(sid string) (sidAccount, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.names[sid]; ok && d.now().Sub(c.at) < sidDirectoryTTL {
		return c.acct, true
	}
	return sidAccount{}, false
}

func (d *sidDirectory) store(sid string, acct sidAccount) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.names) >= sidDirectoryMax {
		for k, c := range d.names {
			if d.now().Sub(c.at) >= sidDirectoryTTL {
				delete(d.names, k)
			}
		}
		if len(d.names) >= sidDirectoryMax {
			d.names = map[string]sidCached{}
		}
	}
	d.names[sid] = sidCached{acct: acct, at: d.now()}
}

// sidAccountLabel is DOMAIN\account, or the bare account with no domain.
func sidAccountLabel(a sidAccount) string {
	if a.Domain != "" {
		return a.Domain + `\` + a.Account
	}
	return a.Account
}

// winAccountLabel is how the scan names a token's account: DOMAIN\account,
// or the SID itself when it could not be resolved.
func winAccountLabel(sid string, names *sidNames) string {
	n := names.resolve(sid)
	switch {
	case !n.OK:
		return sid
	case n.Domain != "":
		return n.Domain + `\` + n.Account
	}
	return n.Account
}

// winAccountDomain is the account's domain for the owner classifier, "" when
// the SID could not be resolved (classifyWinOwner then says unknown).
func winAccountDomain(sid string, names *sidNames) string {
	if n := names.resolve(sid); n.OK {
		return n.Domain
	}
	return ""
}
