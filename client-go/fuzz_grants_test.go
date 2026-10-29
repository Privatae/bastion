//go:build !windows

package main

// Fuzz targets for grants and signed records on an anchored box: which
// capability family lets a pairing run an op, which family a step-up request
// is gated on, and what a signed record can be read as.
//
// The box here is the worst case for kind confusion: ONE key signs every kind
// of record (the anchor's pairing records and the entity's grants, plans and
// op terms), so the only thing keeping a record of one kind from being
// accepted as another is each verifier's own check of what it is reading.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// memberFor is the member pairing that holds a grant of exactly one family.
func memberFor(fam string) string { return "m-" + fam + ".host.privatae.ai" }

const memberNoGrant = "m-nogrant.host.privatae.ai"

// A pairing's grant names families, and an op runs only if the grant names its
// family. Whatever the op is called: the anchor pairing may ask for it, a member
// with no grant may not, and a member granted exactly one family may ask only
// for an op of that family (or of "-", the lanes that authorize nothing on this
// box). No op is in a family a grant cannot name except the three floors.
func FuzzEachOpIsAllowedOnlyByItsOwnFamily(f *testing.F) {
	for _, s := range []string{
		"uptime", "observe:ps", "computer:apps", "session:open", "session:root", "dcn_read", "ctx_put", "backup_fetch",
		"harness:run", "mode:x", "model:pull", "mode", "model", "egress", "inference", "device_request", "service:up",
		"services", "service_grant_sync", "op_run", "op_", "stepup_request", "pairing_grant_sync", "audit_fetch",
		"sessionx", "observe", "Observe:ps", "", "dcn", "op", " uptime", "uptime\x00",
	} {
		f.Add(s)
	}
	priv := setupBox(f)
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, fam := range allCaps {
		host := memberFor(fam)
		writePairingState(f, host, pairingActive)
		canonical, _ := json.Marshal(grantTerms(host, []string{fam}, future))
		g, _ := json.Marshal(pairingGrantFile{TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))})
		p, err := pairingGrantPath(host)
		if err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(p, g, 0o600); err != nil {
			f.Fatal(err)
		}
		if caps, ok := pairingCaps(host); !ok || len(caps) != 1 || caps[0] != fam {
			f.Fatalf("the fixture grant for %s does not verify: %v %v", host, caps, ok)
		}
	}
	writePairingState(f, memberNoGrant, pairingActive)
	floors := map[string]bool{"": true, capsFamilyStepup: true, capsFamilyAnchor: true, capsFamilyNone: true}
	grantable := map[string]bool{}
	for _, c := range allCaps {
		grantable[c] = true
	}
	f.Fuzz(func(t *testing.T, op string) {
		fam := opFamily(op)
		if !grantable[fam] && !floors[fam] {
			t.Fatalf("op %q is in family %q, which no grant can name and is not a floor", op, fam)
		}
		if why := capsAllow(tAnchor, op); why != "" {
			t.Fatalf("the anchor pairing was refused %q: %s", op, why)
		}
		if capsAllow(memberNoGrant, op) == "" {
			t.Fatalf("a member with no grant was allowed %q (family %q)", op, fam)
		}
		if capsAllow("", op) == "" {
			t.Fatalf("an empty pairing identity was allowed %q", op)
		}
		for _, g := range allCaps {
			allowed := capsAllow(memberFor(g), op) == ""
			if want := fam == g || fam == capsFamilyNone; allowed != want {
				t.Fatalf("a member granted only %q: allowed=%v for %q (family %q)", g, allowed, op, fam)
			}
		}
	})
}

// stepupArity is how many "|" separate the fields of each kind's purpose, so a
// field that smuggles in a "|" shows up as a purpose with too many fields.
var stepupArity = map[string][]int{
	"dcn_store_grant": {7}, "dcn_move_plan": {5}, "session_root": {2}, reachKind: {4, 5},
	"critical_action": {5}, "model_pull": {4}, opKindRun: {6}, opKindGrant: {6}, "mgmt_op": {3},
}

// A step-up request asks the person to approve something, and raising it is
// gated on the family of what it approves. For any details a pod sends: if the
// box would build a purpose from them, the purpose starts with the request's
// own kind and has that kind's number of fields (so an approval for one kind
// can never be read as one for another, or shift a value into another field),
// and the request is gated on a family a grant can name — never on "-", which
// any granted pairing passes — except critical_action, which authorizes nothing
// on this box, and a directive, which only the anchor may ask for.
func FuzzAStepupIsGatedOnWhatItApproves(f *testing.F) {
	hn, _ := os.Hostname()
	for _, d := range []map[string]any{
		{"kind": "dcn_store_grant", "server": hn, "root": "/srv/x", "mask": []string{"read"}, "excludes": []string{".ssh"}, "ttl_days": 30},
		{"kind": "dcn_move_plan", "store_id": 1, "plan_id": 2, "root": "/srv/x", "archive": "old", "moves": []map[string]string{{"from": "a", "to": "b"}}},
		{"kind": "session_root", "server": hn, "session_id": "s1"},
		{"kind": reachKind, "server": hn, "slot": "gitea", "subject": "h.example", "ttl_days": 7},
		{"kind": reachKind, "server": hn, "slot": "gitea", "subject": "h.example", "mirrors": []map[string]string{{"url": "https://github.com/a/b", "repo": "a/b"}}},
		{"kind": "critical_action", "action": "frontend_deploy", "entity_id": 9001, "action_id": "a1", "target": "t", "summary": "s|x"},
		{"kind": "model_pull", "model": "qwen3:4b", "role": "embed", "max_bytes": 1000},
		{"kind": opKindRun, "server": hn, "op": "write-hello", "sha256": strings.Repeat("a", 64), "params": "{}", "expires": "2030-01-01T00:00:00Z", "changes_sha256": strings.Repeat("b", 64)},
		{"kind": opKindGrant, "server": hn, "op": "write-hello", "sha256": strings.Repeat("a", 64), "bounds": "{}", "expires": "2030-01-01T00:00:00Z", "uses": 3},
		{"kind": "mgmt_op", "op": "service:up", "server": hn, "args": []string{"a|b"}},
		{"kind": "mgmt_op", "op": "self-update", "server": hn},
		{"kind": "mgmt_op", "op": "stepup_request", "server": hn},
		{"kind": "model_pull", "model": "a|b", "role": "embed", "max_bytes": 1},
		{"kind": "session_root", "server": "h|x", "session_id": "s"},
	} {
		raw, _ := json.Marshal(d)
		f.Add(string(raw))
	}
	grantable := map[string]bool{}
	for _, c := range allCaps {
		grantable[c] = true
	}
	f.Fuzz(func(t *testing.T, details string) {
		var d map[string]any
		if json.Unmarshal([]byte(details), &d) != nil || d == nil {
			return
		}
		fam := stepupDetailsFamily(d)
		p, err := purposeFromDetails(d)
		if err != nil {
			return
		}
		kind, _ := d["kind"].(string)
		if !strings.HasPrefix(p, kind+"|") {
			t.Fatalf("details of kind %q built the purpose %q", kind, p)
		}
		arity, n := stepupArity[kind], strings.Count(p, "|")
		fits := false
		for _, a := range arity {
			fits = fits || a == n
		}
		if !fits {
			t.Fatalf("a %s purpose has %d separators, want %v: %q", kind, n, arity, p)
		}
		switch {
		case kind == "critical_action":
			if fam != capsFamilyNone {
				t.Fatalf("critical_action is gated on %q", fam)
			}
		case kind == "mgmt_op" && isDirectiveOp(d["op"].(string)):
			if fam != capsFamilyAnchor {
				t.Fatalf("a directive's approval is gated on %q, not the anchor's", fam)
			}
		case kind == "mgmt_op":
			if fam != opFamily(d["op"].(string)) {
				t.Fatalf("an approval for op %q is gated on %q, not the op's own family %q", d["op"], fam, opFamily(d["op"].(string)))
			}
		default:
			if !grantable[fam] {
				t.Fatalf("a request of kind %q, which the box would build a purpose for, is gated on %q", kind, fam)
			}
		}
	})
}

// signedKinds is every verifier on this box that reads a record signed by a
// pinned key, and a well-formed record of each kind. Each verifier is called
// the way its lane calls it.
type signedKind struct {
	name   string
	record []byte
	verify func(canonical, sig []byte) bool
}

func signedKindsBox(f *testing.F) (ed25519.PrivateKey, []signedKind) {
	priv := setupBox(f)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	dcn := f.TempDir()
	if err := dcnSaveFile(dcn, &dcnGrantFile{Stores: map[string]dcnGrantRec{}, VerifyPubkey: pub}); err != nil {
		f.Fatal(err)
	}
	hn, _ := os.Hostname()
	soon := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	enc := base64.StdEncoding.EncodeToString
	rec := func(c, s []byte) dcnGrantRec { return dcnGrantRec{TermsCanonical: enc(c), Signature: enc(s)} }
	js := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
	anchorRec := func(kind string) map[string]any {
		return map[string]any{"kind": kind, "server": hn, "anchor": tAnchor, "subject": tMember,
			"caps": []string{"observe"}, "issued_at": soon, "expires": soon}
	}
	opRec := func(kind string) map[string]any {
		m := opTerm(kind, strings.Repeat("a", 64), "{}", "{}", 1, time.Hour, "user")
		if kind == opKindGrant {
			m["uses"] = 3
		}
		return m
	}
	kinds := []signedKind{
		{"pairing_grant", js(anchorRec("pairing_grant")), func(c, s []byte) bool {
			_, err := verifyAnchorRecord(enc(c), enc(s), "pairing_grant")
			return err == nil
		}},
		{"pairing_revoke", js(anchorRec("pairing_revoke")), func(c, s []byte) bool {
			_, err := verifyAnchorRecord(enc(c), enc(s), "pairing_revoke")
			return err == nil
		}},
		{"anchor_consent", js(anchorRec("anchor_consent")), func(c, s []byte) bool {
			_, err := verifyAnchorRecord(enc(c), enc(s), "anchor_consent")
			return err == nil
		}},
		{"management grant", js(map[string]any{"entity": 9001, "server": "*", "ops": []string{"uptime"}, "expires": soon}),
			func(c, s []byte) bool {
				_, err := sessionVerifyGrant(dcn, tAnchor, hn, "uptime", enc(c), enc(s), "")
				return err == nil
			}},
		{"dcn_store_grant", js(map[string]any{"kind": "dcn_store_grant", "class": "machine", "server": hn,
			"root": "/srv/x", "mask": []string{"read"}, "expires": soon}), func(c, s []byte) bool {
			_, err := dcnVerifyRec(pub, rec(c, s))
			return err == nil
		}},
		{"dcn_move_plan", js(map[string]any{"kind": "dcn_move_plan", "store_id": 1, "plan_id": 2, "server": hn,
			"root": "/srv/x", "archive": "old", "moves": []map[string]string{{"from": "a", "to": "b"}}, "expires": soon}),
			func(c, s []byte) bool {
				_, err := dcnVerifyPlan(pub, enc(c), enc(s))
				return err == nil
			}},
		{reachKind, js(map[string]any{"kind": reachKind, "server": hn, "slot": "gitea", "subject": tMember,
			"expires": soon}), func(c, s []byte) bool {
			_, err := reachVerifyRec(pub, rec(c, s))
			return err == nil
		}},
		{opKindRun, js(opRec(opKindRun)), func(c, s []byte) bool {
			_, err := verifyOpTerms(dcn, enc(c), enc(s), opKindRun)
			return err == nil
		}},
		{opKindGrant, js(opRec(opKindGrant)), func(c, s []byte) bool {
			_, err := verifyOpTerms(dcn, enc(c), enc(s), opKindGrant)
			return err == nil
		}},
	}
	return priv, kinds
}

// Whatever bytes the one key has signed, at most one verifier on this box
// accepts them: a record is read as one kind or refused, never as two. Each
// well-formed seed is accepted as its own kind and nothing else, so the
// property is not passing because every verifier refuses everything.
func FuzzASignedRecordIsReadAsAtMostOneKind(f *testing.F) {
	priv, kinds := signedKindsBox(f)
	for _, k := range kinds {
		f.Add(k.record)
	}
	f.Add([]byte(`{"kind":"dcn_store_grant","KIND":"service_reach_grant"}`))
	f.Add([]byte(`{"kind":null,"server":"*","ops":["uptime"],"expires":"2099-01-01T00:00:00Z"}`))
	f.Fuzz(func(t *testing.T, canonical []byte) {
		sig := ed25519.Sign(priv, canonical)
		var readAs []string
		for _, k := range kinds {
			if k.verify(canonical, sig) {
				readAs = append(readAs, k.name)
			}
		}
		if len(readAs) > 1 {
			t.Fatalf("one signed record is read as %v:\n%s", readAs, canonical)
		}
		for _, k := range kinds {
			if bytes.Equal(canonical, k.record) && (len(readAs) != 1 || readAs[0] != k.name) {
				t.Fatalf("the well-formed %s record is read as %v", k.name, readAs)
			}
		}
	})
}

// Every verifier checks the signature over the exact bytes it then reads. For
// each kind, a record and a signature that verify: change any byte of either
// and the verifier refuses.
func FuzzAChangedSignedByteNeverVerifies(f *testing.F) {
	priv, kinds := signedKindsBox(f)
	sigs := make([][]byte, len(kinds))
	for i, k := range kinds {
		sigs[i] = ed25519.Sign(priv, k.record)
		f.Add(uint8(i), k.record, sigs[i])
		f.Add(uint8(i), append(append([]byte(nil), k.record...), ' '), sigs[i])
		mut := append([]byte(nil), sigs[i]...)
		mut[0] ^= 1
		f.Add(uint8(i), k.record, mut)
	}
	f.Fuzz(func(t *testing.T, which uint8, canonical, sig []byte) {
		i := int(which) % len(kinds)
		k := kinds[i]
		ok := k.verify(canonical, sig)
		same := bytes.Equal(canonical, k.record) && bytes.Equal(sig, sigs[i])
		if ok && !same {
			t.Fatalf("the %s verifier accepted bytes that were not signed:\n%q\n%x", k.name, canonical, sig)
		}
		if same && !ok {
			t.Fatalf("the %s verifier refused the record and signature it was given", k.name)
		}
	})
}

// A device approval is signed over its fields joined by newlines. Whatever a
// pod does to an approval the device signed, the box accepts it only as the
// approval the device signed: never for another purpose, never with another
// nonce (a fresh nonce would make a spent approval new again).
func FuzzADeviceApprovalIsReadOneWayOnly(f *testing.F) {
	const n = "0123456789abcdef0123456789abcdef"
	f.Add("mgmt_op|uptime|h|d", n, "mgmt_op|uptime|h|d", n)
	f.Add("mgmt_op|uptime|h|d\nx", n, "mgmt_op|uptime|h|d", "x\n"+n)
	f.Add("a", n+"\nb", "a\n"+n, "b")
	f.Add("a", n, "a", n+"0")
	setupBox(f)
	pub, priv, _ := ed25519.GenerateKey(nil)
	key := base64.StdEncoding.EncodeToString(pub)
	if err := pinDeviceKey(key); err != nil {
		f.Fatal(err)
	}
	expires := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	f.Fuzz(func(t *testing.T, signedPurpose, signedNonce, purpose, nonce string) {
		a := deviceApproval{V: deviceApprovalVersion, Purpose: signedPurpose, Nonce: signedNonce,
			Expires: expires, Uses: 1, Key: key}
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, a.canonical()))
		b := a
		b.Purpose, b.Nonce, b.Sig = purpose, nonce, sig
		raw, _ := json.Marshal(&b)
		_, err := verifyDeviceApproval(string(raw), purpose, time.Now())
		plain := !strings.ContainsAny(signedPurpose+signedNonce, "\r\n") && len(signedNonce) >= 16 && signedPurpose != ""
		if err != nil {
			if plain && purpose == signedPurpose && nonce == signedNonce {
				t.Fatalf("the approval the device signed for (%q, %q) was refused: %v", purpose, nonce, err)
			}
			return
		}
		if purpose != signedPurpose || nonce != signedNonce {
			t.Fatalf("an approval signed for (%q, %q) was accepted as (%q, %q)", signedPurpose, signedNonce, purpose, nonce)
		}
	})
}

// FuzzAGrantsRunBoundsHoldWhateverTheHostSends: whatever bounds text a host
// sends, a run bound the machine accepts is one it can hold — a window has a
// length, a zone and a day, a rate names a limit inside the ceilings — and
// judging a run against it at any moment answers, never panics, and never
// lets a run inside an interval or past a day's count.
func FuzzAGrantsRunBoundsHoldWhateverTheHostSends(f *testing.F) {
	m := &opManifest{Params: map[string]opParam{"count": {Type: "integer", Min: ptr64(1), Max: ptr64(5)}}}
	for _, s := range []string{
		`{"_window":{"days":["mon"],"from":"22:00","to":"06:00","tz":"Europe/Berlin"}}`,
		`{"_rate":{"per_day":2,"min_interval_s":600},"count":{"max":2}}`,
		`{"_window":null,"_rate":null}`, `{"_x":1}`, `{"_window":{"from":"02:00","to":"02:00"}}`,
	} {
		f.Add(s, int64(1761739200), int64(300))
	}
	f.Fuzz(func(t *testing.T, raw string, at, gap int64) {
		b, err := parseGrantBounds(m, raw)
		if err != nil {
			return
		}
		if w := b.Window; w != nil {
			if w.from == w.to || w.loc == nil || w.day == [7]bool{} {
				t.Fatalf("accepted a window that is no window: %s", raw)
			}
		}
		if r := b.Rate; r != nil {
			if (r.PerDay == nil && r.MinInterval == nil) || (r.PerDay != nil && (*r.PerDay < 1 || *r.PerDay > opGrantUsesMax)) ||
				(r.MinInterval != nil && (*r.MinInterval < 1 || *r.MinInterval > opRateMinInterval)) {
				t.Fatalf("accepted a rate outside the ceilings: %s", raw)
			}
		}
		now := time.Unix(at%(1<<40), 0)
		last := now.Add(-time.Duration(gap%(1<<30)) * time.Second)
		if last.After(now) {
			last = now
		}
		why, _, _ := opNotNowWhy(b, []time.Time{last}, now)
		if b.Window == nil && b.Rate != nil && b.Rate.MinInterval != nil &&
			now.Sub(last) < time.Duration(*b.Rate.MinInterval)*time.Second && why == "" {
			t.Fatalf("a run inside the interval was let through: %s", raw)
		}
		if b.Window == nil && b.Rate != nil && b.Rate.PerDay != nil && *b.Rate.PerDay == 1 && now.Sub(last) < 24*time.Hour && why == "" {
			t.Fatalf("a second run in a day was let through: %s", raw)
		}
	})
}

func ptr64(v int64) *int64 { return &v }
