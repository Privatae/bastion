package main

// The enforcing report — the bastion acting as the host's NAC agent. Every
// heartbeat the box states what it is ENFORCING
// right now, and the host compares that to what it GRANTED:
//
//	"enforcing": {
//	  "grants":  [{"store_id": 12, "signature": "<b64>", "freeagent": "running", "serving": true}, ...],
//	  "tunnel_allowed_ips": ["fd00:9::e:3/128"],   // the ONLY address the tunnel can reach
//	  "mgmt_ops": ["backup_fetch", "ctx_del", ..., "uptime"],  // the whole op vocabulary; nothing else runs
//	  "binary_sha256": "<hex>",
//	  "reconcile": {"stale": [..], "missing": [..]},  // drift the last reconcile found (omitted when clean)
//	  "audit": {"lines": 41, "refused_last_hour": 1,  // the command-lane record (mgmt_audit.go)
//	            "last_refusal": {"ts": "..", "op": "dcn_list", "why": ".."}}
//	}
//
// Before this, device_health was the literal string "healthy" and the host's
// posture engine had nothing real to decide on. Now a grant the host never
// signed, a grant the box no longer holds, or a stale copy is a posture drop
// (degraded) on the host side, and the existing NAC quarantines on it.
//
// Signatures, never terms: the report carries the signature of each grant the
// box holds (a public, non-secret value the host already has), so the host can
// tell "same grant" from "stale copy" without the box shipping paths.

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	binaryDigestOnce sync.Once
	binaryDigest     string
)

// selfDigest is the sha256 of the running binary, computed once. Empty when
// the executable cannot be read (the report still goes; the host treats an
// absent digest as "unknown", not as drift).
func selfDigest() string {
	binaryDigestOnce.Do(func() {
		p, err := os.Executable()
		if err != nil {
			return
		}
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		binaryDigest = hex.EncodeToString(h.Sum(nil))
	})
	return binaryDigest
}

// mgmtOpVocabulary is every op id this box will answer on the management lane —
// the shell allowlist plus the dedicated no-exec handlers, read from the SAME
// table the dispatcher uses (mgmt.go handlerOps), so the report cannot drift
// from the wall. The host compares it to the set it knows.
func mgmtOpVocabulary() []string {
	ops := make([]string, 0, len(handlerOps)+len(p8AllowedOps)+len(sessionOps))
	for k := range handlerOps {
		ops = append(ops, k)
	}
	ops = append(ops, sessionOps...) // the terminal lane (session.go): granted by the same ops list
	for k := range p8AllowedOps {
		ops = append(ops, k)
	}
	sort.Strings(ops)
	return ops
}

// wgAllowedIPs reads the AllowedIPs the WireGuard DEVICE currently holds — what
// is enforced, not what was configured — from the UAPI dump. Nil when unreadable.
func wgAllowedIPs(dev interface{ IpcGet() (string, error) }) []string {
	if dev == nil {
		return nil
	}
	dump, err := dev.IpcGet()
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "allowed_ip="); ok && v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// buildEnforcingReport reads the grants on disk for one pairing and the
// managed-local agent state, and returns the report for the heartbeat. dir=="" (no
// DCN state for this pairing) still reports the tunnel/ops/digest — those are
// enforced regardless. allowed is what the tunnel device holds right now.
func buildEnforcingReport(dir string, allowed []string) map[string]any {
	grants := []map[string]any{}
	if dir != "" {
		if f, err := dcnLoadFile(dir); err == nil {
			ids := make([]string, 0, len(f.Stores))
			for k := range f.Stores {
				ids = append(ids, k)
			}
			sort.Slice(ids, func(i, j int) bool {
				a, _ := strconv.ParseInt(ids[i], 10, 64)
				b, _ := strconv.ParseInt(ids[j], 10, 64)
				return a < b
			})
			status := faManagedStatus()
			for _, k := range ids {
				id, err := strconv.ParseInt(k, 10, 64)
				if err != nil {
					continue
				}
				g := map[string]any{"store_id": id, "signature": f.Stores[k].Signature,
					"freeagent": "absent", "serving": false}
				if st, ok := status[k].(map[string]any); ok {
					if s, ok := st["state"].(string); ok && s != "" {
						g["freeagent"] = s
					}
					if b, ok := st["serving"].(bool); ok {
						g["serving"] = b
					}
				}
				grants = append(grants, g)
			}
		}
	}
	if allowed == nil {
		allowed = []string{}
	}
	rep := map[string]any{
		"grants": grants,
		// Reach grants held for the service slot (service_reach.go): the host
		// re-syncs any it expects that is missing or stale.
		"service_grants": heldReachGrants(dir),
		// Reach grants dropped because their server was stopped: the host
		// revokes these rows rather than re-pushing them.
		"service_grants_dropped": droppedReachGrants(dir),
		"tunnel_allowed_ips":     allowed,
		"mgmt_ops":               mgmtOpVocabulary(),
		"binary_sha256":          selfDigest(),
		// A second factor enrolled HERE (stepup.go): the host routes its code
		// checks for this box's grants and plans to this box.
		"stepup": stepupEnrolled(dir),
		// The write gate (writes.go / device.go): on an anchored box every write
		// needs an approval this box verified. `device` — an approval device is
		// pinned here; `second_factor` — SOME way to approve exists (a device or
		// the factor above). write_gate true with second_factor false is a box
		// whose writes are all refused, and the host says so on its card.
		"write_gate":    currentAnchor() != nil,
		"device":        devicePinned(),
		"second_factor": secondFactorAvailable(dir),
		// A self-update to a newer version needs no approval here (0.44.0,
		// update.go maybeSelfUpdate), so the host delivers one without asking
		// anyone. Said by the box rather than inferred from its version number,
		// so the host never withholds an ask from a box that still gates it —
		// and false on a build that cannot read its own version ("dev", a
		// suffix), which can compare nothing and so gates every update.
		"update_forward_needs_no_approval": ownVersionComparable(),
	}
	// Standing coder grants held (coder_grant.go): the host re-syncs any it
	// expects that is missing or stale.
	rep["coder_grants"] = heldCoderGrants(dir)
	// The op executor (ops_exec_linux.go): whether this machine can run an
	// op the host wrote in a sandbox, and why not when it cannot.
	{
		ok, why := opSandboxAvailable()
		rep["sandbox"] = ok
		if !ok {
			rep["sandbox_reason"] = why
		}
		// An op here sees only the system base and the paths it declares
		// (ops_view.go), and an op reaching a credential store is refused. An
		// older box shows an op the whole machine, so the host keeps to what
		// the box says rather than guessing from its version.
		rep["op_view_closed"] = ok
		// Action ops (ops_action.go): a program in a unit held to its
		// destinations, and the verbs. Said by the box, like the sandbox.
		aok, awhy := opActionAvailable()
		rep["action_ops"] = aok
		if !aok {
			rep["action_ops_reason"] = awhy
		}
	}
	// This machine's encryption key, signed by its own key: what the host
	// seals an action op's credentials to (ops_seal.go).
	if k := opEncKeyClaim(); k != nil {
		rep["encryption_key"] = k
	}
	// The device keys this box accepts (public keys — the host matches them to
	// the bastion that advertises approval_device_key below, so it knows WHICH
	// of the person's machines to file an ask on), and whether THIS box is an
	// approval device. A device's own key is public too.
	if keys := deviceKeys(); len(keys) > 0 {
		rep["device_keys"] = keys
	}
	if f, err := deviceKeyLoad(); err == nil && f.Pub != "" {
		rep["approval_device"] = true
		rep["approval_device_key"] = f.Pub
	}
	// The lane watched (quarantine.go): the last refusals, and any pairing
	// whose write lanes are closed here. Absent on a quiet box.
	for k, v := range quarantineReport(time.Now()) {
		rep[k] = v
	}
	if dir != "" {
		if r := reconcileReport(dir); r != nil {
			rep["reconcile"] = *r
		}
	}
	// The last host-directed action this box REFUSED. Absent when there is
	// nothing to say, so it never reads as "refused: none".
	if r := directiveRefusalReport(); r != nil {
		rep["last_directive_refusal"] = r
	}
	// Accounting on the command lane (mgmt_audit.go): how much has
	// been asked of this box and how much of it was REFUSED in the last hour.
	// The counts, not the lines — a host that sees refused_last_hour > 0 pulls
	// the file with audit_fetch, and until it does the beat stays the size it
	// has always been. Absent on a box that has answered nothing, for the same
	// reason as the field above: a missing record and a quiet machine must not
	// report the same zero.
	if a := mgmtAuditReport(); a != nil {
		rep["audit"] = a
	}
	return rep
}
