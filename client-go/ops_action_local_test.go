//go:build !windows

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// An action op on a person's own machine (local, unanchored) reaches the
// public internet and nothing around the machine; an anchored fleet keeps its
// private destinations, because its ship steps reach private control planes.
// The addresses are documentation and private examples, invented here.

// localOpBox: a local machine, anchored by nobody, with one pairing whose
// pairing dir pins a signing key we hold.
func localOpBox(t *testing.T) (dcn string, priv ed25519.PrivateKey) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := modePath()
	if err := os.WriteFile(p, []byte(`{"mode":"local"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writePairing(t, tAnchor)
	if currentAnchor() != nil {
		t.Fatal("the local box must not be anchored")
	}
	dcn = t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := dcnSaveFile(dcn, &dcnGrantFile{Stores: map[string]dcnGrantRec{},
		VerifyPubkey: base64.StdEncoding.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	return dcn, priv
}

// actionBundle: an unprivileged action op declaring one destination.
func actionBundle(dest string) []opFile {
	man := `name: optest-reach
version: 1.0.0
summary: An action op that reaches one destination.
kind: action
target: machine
privilege: user
interpreter: /bin/sh
time_limit: 30
destinations: ["` + dest + `"]
modes: [dry_run, apply, verify]
undo: none
`
	return []opFile{
		{Path: "op.yaml", Mode: 0o644, B64: base64.StdEncoding.EncodeToString([]byte(man))},
		{Path: "run", Mode: 0o755, B64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\ntrue\n"))},
	}
}

// syncAction drives op_sync for an action op declaring dest, under op_run
// terms signed by priv; it returns the op's output, its error text and code.
func syncAction(t *testing.T, dcn string, priv ed25519.PrivateKey, dest string) (string, string, int) {
	t.Helper()
	files := actionBundle(dest)
	sha, err := opDirDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	terms := opTerm(opKindRun, sha, `{}`, "", 1, time.Hour, "user")
	terms["op"] = "optest-reach"
	pair := signTermsPair(t, priv, terms)
	return driveJob(t, tAnchor, mgmtJob{Op: "op_sync", Args: append(pair, bundleB64(files))}, "", dcn)
}

// RESULT: red before opLocalNetworkDest — a local box held an op declaring
// 10.0.0.2:80 (a home network's address), and its apply would have reached it.
func TestALocalBoxRefusesAnActionOpThatDeclaresAPrivateNetwork(t *testing.T) {
	dcn, priv := localOpBox(t)
	for _, dest := range []string{
		"10.0.0.2:80",         // RFC 1918
		"192.168.1.2:443",     // a home router's range
		"172.16.0.2:8080",     // RFC 1918
		"100.64.0.2:22",       // carrier NAT, and VPN meshes that use it
		"[fd00::2]:80",        // ULA
		"[64:ff9b::a00:2]:80", // 10.0.0.2 through NAT64
		"[2002:a00:2::1]:80",  // 10.0.0.2 through 6to4
		"198.18.0.2:80",       // benchmarking, never a public host
	} {
		out, errOut, code := syncAction(t, dcn, priv, dest)
		if code == 0 || strings.Contains(out, `"held"`) {
			t.Errorf("%s: a local box held an op declaring it: %d %s %s", dest, code, out, errOut)
			continue
		}
		if !strings.Contains(errOut, "private network") || !strings.Contains(errOut, "install a bastion on that computer") {
			t.Errorf("%s: the refusal must say why and what to do instead: %q", dest, errOut)
		}
	}
	// The public internet is still a destination.
	if out, errOut, code := syncAction(t, dcn, priv, "203.0.113.10:443"); code != 0 || !strings.Contains(out, `"held"`) {
		t.Fatalf("a public destination is held on a local box: %d %s %s", code, out, errOut)
	}
	// A name is judged at apply, by every address it resolves to
	// (opResolveDests); at sync it is only a name.
	if out, errOut, code := syncAction(t, dcn, priv, "forge.example.com:443"); code != 0 || !strings.Contains(out, `"held"`) {
		t.Fatalf("a destination by name is held on a local box: %d %s %s", code, out, errOut)
	}
}

func TestAnAnchoredFleetKeepsItsPrivateDestinations(t *testing.T) {
	dcn, priv := opTestBox(t)
	enrollFactor(t, dcn)
	for _, dest := range []string{"10.0.0.2:80", "100.64.0.2:6443", "[fd00::2]:80"} {
		if out, errOut, code := syncAction(t, dcn, priv, dest); code != 0 || !strings.Contains(out, `"held"`) {
			t.Errorf("%s: an anchored box holds a ship step to a private control plane: %d %s %s", dest, code, out, errOut)
		}
	}
	// What every box refuses stays refused.
	if _, errOut, code := syncAction(t, dcn, priv, "127.0.0.1:80"); code == 0 || !strings.Contains(errOut, "loopback") {
		t.Fatalf("loopback stays refused on an anchored box: %d %q", code, errOut)
	}
}
