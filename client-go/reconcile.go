package main

// Grant reconcile — the first piece of the bastion acting as the host's NAC
// agent: the box holds what the host granted, and nothing else, and it proves
// that every heartbeat.
//
// The heartbeat reply may carry the set of signed store grants this box SHOULD
// hold, computed by the host from its approved + non-revoked + non-expired
// rows for this hostname:
//
//	{"dcn_grants": {"stores": [{"store_id": 12, "signature": "<b64>"}, ...]}}
//
// Three outcomes per store, and only the first one acts:
//   - on disk, not listed on TWO consecutive replies → a revoke this box missed
//     (it was offline when the host pushed dcn_grant_drop) → DROPPED here,
//     local agent stopped. Two beats, not one: a grant synced while a reply was
//     in flight is unlisted once by timing alone and must survive.
//   - listed, signature differs from the copy on disk → the grant was re-approved
//     with new terms; the box keeps enforcing the OLD signed terms until the
//     host re-syncs (the box can never fabricate a grant) → reported as stale.
//   - listed, not on disk → the host thinks it synced and the box never got it
//     → reported as missing; the host re-syncs.
//
// The field ABSENT means "no instruction" — an older host, or a host that could
// not compute the set (no verify key, DB error). That must never read as
// "drop everything", which is why the host omits the field rather than sending
// an empty list when it is unsure, and why this reads presence, not length.
//
// grants.json is read-modify-written by three goroutines (heartbeat + the mgmt
// workers); grantsMu serializes every load→modify→save so a drop and a sync
// can never interleave and resurrect or lose a grant.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
)

// grantsMu guards every read-modify-write of <dcnDir>/grants.json.
var grantsMu sync.Mutex

type dcnReconcileResult struct {
	Dropped []int64 `json:"dropped,omitempty"`
	Stale   []int64 `json:"stale,omitempty"`
	Missing []int64 `json:"missing,omitempty"`
}

// lastReconcile is what the most recent heartbeat reconcile found, per pairing
// dir — carried on the NEXT heartbeat so the host sees drift it must act on
// (re-sync a stale/missing grant). unlisted counts consecutive replies a held
// store was absent from; a drop needs two. Written by maybeReconcileGrants only.
var (
	lastReconcileMu sync.Mutex
	lastReconcile   = map[string]dcnReconcileResult{}
	unlisted        = map[string]map[string]int{} // dir → store key → consecutive unlisted replies
)

const dropAfterUnlisted = 2

func recordReconcile(dir string, r dcnReconcileResult) {
	lastReconcileMu.Lock()
	defer lastReconcileMu.Unlock()
	if len(r.Dropped)+len(r.Stale)+len(r.Missing) == 0 {
		delete(lastReconcile, dir)
		return
	}
	lastReconcile[dir] = r
}

// reconcileReport returns the pending drift for one pairing (nil when clean).
func reconcileReport(dir string) *dcnReconcileResult {
	lastReconcileMu.Lock()
	defer lastReconcileMu.Unlock()
	r, ok := lastReconcile[dir]
	if !ok {
		return nil
	}
	return &r
}

// bumpUnlisted counts one more reply without `key`, returning the new count.
func bumpUnlisted(dir, key string) int {
	lastReconcileMu.Lock()
	defer lastReconcileMu.Unlock()
	m := unlisted[dir]
	if m == nil {
		m = map[string]int{}
		unlisted[dir] = m
	}
	m[key]++
	return m[key]
}

func clearUnlisted(dir, key string) {
	lastReconcileMu.Lock()
	defer lastReconcileMu.Unlock()
	if m := unlisted[dir]; m != nil {
		delete(m, key)
	}
}

func maybeReconcileGrants(heartbeatResponse []byte, dir string) dcnReconcileResult {
	var out dcnReconcileResult
	if dir == "" {
		return out
	}
	var hb struct {
		DcnGrants *struct {
			Stores []struct {
				StoreID   int64  `json:"store_id"`
				Signature string `json:"signature"`
			} `json:"stores"`
		} `json:"dcn_grants"`
	}
	if json.Unmarshal(heartbeatResponse, &hb) != nil || hb.DcnGrants == nil {
		return out // no instruction
	}
	expected := map[string]string{}
	for _, s := range hb.DcnGrants.Stores {
		if s.StoreID > 0 {
			expected[strconv.FormatInt(s.StoreID, 10)] = s.Signature
		}
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	f, err := dcnLoadFile(dir)
	if err != nil {
		return out
	}
	for key, rec := range f.Stores {
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			continue
		}
		sig, listed := expected[key]
		switch {
		case !listed:
			if bumpUnlisted(dir, key) < dropAfterUnlisted {
				continue // once could be timing; twice is a revoke
			}
			if dropped, err := dcnDropStoreLocked(dir, id, "reconcile: not granted by host"); err == nil && dropped {
				out.Dropped = append(out.Dropped, id)
			}
			clearUnlisted(dir, key)
		case sig != "" && sig != rec.Signature:
			clearUnlisted(dir, key)
			out.Stale = append(out.Stale, id)
		default:
			clearUnlisted(dir, key)
		}
	}
	for key := range expected {
		if _, ok := f.Stores[key]; !ok {
			if id, err := strconv.ParseInt(key, 10, 64); err == nil {
				out.Missing = append(out.Missing, id)
			}
		}
	}
	for _, l := range [][]int64{out.Dropped, out.Stale, out.Missing} {
		sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	}
	if len(out.Dropped) > 0 {
		fmt.Printf("reconcile: dropped %d store grant(s) the host no longer lists: %v\n", len(out.Dropped), out.Dropped)
	}
	recordReconcile(dir, out)
	return out
}
