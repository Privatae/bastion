package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// The enforcing report: the heartbeat states what the box enforces — the grant
// signatures it holds, the tunnel's only reachable address, the op vocabulary,
// the binary digest, and any drift the last reconcile found.
func TestEnforcingReport(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	rec := signedRec(t, priv, map[string]any{"kind": "dcn_store_grant", "class": "machine",
		"server": "box1", "root": "/data", "mask": []string{"read"},
		"expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	f := &dcnGrantFile{VerifyPubkey: base64.StdEncoding.EncodeToString(pub),
		Stores: map[string]dcnGrantRec{"7": rec, "3": rec}}
	if err := dcnSaveFile(dir, f); err != nil {
		t.Fatal(err)
	}
	// a prior reconcile left drift to report
	maybeReconcileGrants([]byte(`{"dcn_grants":{"stores":[{"store_id":3,"signature":"`+rec.Signature+
		`"},{"store_id":7,"signature":"other"},{"store_id":9,"signature":"x"}]}}`), dir)

	raw := buildHeartbeatBody("", "box1", "linux", "test", "pk", "fp", "100.64.0.9", "ep", false, nil,
		buildEnforcingReport(dir, []string{"fd00:9::e:3/128"}), nil)
	var body struct {
		DeviceHealth string `json:"device_health"`
		Enforcing    struct {
			Grants []struct {
				StoreID   int64  `json:"store_id"`
				Signature string `json:"signature"`
				FreeAgent string `json:"freeagent"`
			} `json:"grants"`
			Tunnel    []string `json:"tunnel_allowed_ips"`
			MgmtOps   []string `json:"mgmt_ops"`
			Digest    string   `json:"binary_sha256"`
			Reconcile *struct {
				Stale   []int64 `json:"stale"`
				Missing []int64 `json:"missing"`
			} `json:"reconcile"`
		} `json:"enforcing"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("heartbeat body: %v", err)
	}
	e := body.Enforcing
	if len(e.Grants) != 2 || e.Grants[0].StoreID != 3 || e.Grants[1].StoreID != 7 {
		t.Fatalf("grants must list every store on disk, ordered by id: %+v", e.Grants)
	}
	if e.Grants[0].Signature != rec.Signature || e.Grants[0].FreeAgent != "absent" {
		t.Fatalf("grant entry must carry the held signature + freeagent state: %+v", e.Grants[0])
	}
	if len(e.Tunnel) != 1 || e.Tunnel[0] != "fd00:9::e:3/128" {
		t.Fatalf("tunnel_allowed_ips must be the host alias only: %v", e.Tunnel)
	}
	hasUptime, hasDrop := false, false
	for _, op := range e.MgmtOps {
		hasUptime = hasUptime || op == "uptime"
		hasDrop = hasDrop || op == "dcn_grant_drop"
	}
	if !hasUptime || !hasDrop {
		t.Fatalf("mgmt_ops must be the full vocabulary (allowlist + handlers): %v", e.MgmtOps)
	}
	if len(e.Digest) != 64 {
		t.Fatalf("binary_sha256 must be a hex sha256 of the running binary: %q", e.Digest)
	}
	if e.Reconcile == nil || len(e.Reconcile.Stale) != 1 || e.Reconcile.Stale[0] != 7 ||
		len(e.Reconcile.Missing) != 1 || e.Reconcile.Missing[0] != 9 {
		t.Fatalf("drift from the last reconcile must ride the heartbeat: %+v", e.Reconcile)
	}
	// legacy field still present for hosts that predate the report
	if body.DeviceHealth != "healthy" {
		t.Fatalf("device_health must still be sent: %q", body.DeviceHealth)
	}

	// no DCN state at all → the report still carries tunnel / ops / digest
	rep := buildEnforcingReport("", nil)
	if len(rep["grants"].([]map[string]any)) != 0 || rep["binary_sha256"] == "" {
		t.Fatalf("a pairing with no DCN dir must still report what it enforces: %+v", rep)
	}
	if _, ok := rep["reconcile"]; ok {
		t.Fatal("no reconcile field without a DCN dir")
	}
}
