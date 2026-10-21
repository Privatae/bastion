package main

// What this machine has given away, driven through the real handler.
//
// NOT tagged !windows, for the same reason ui_test.go and uiauth_test.go are
// not: this whole UI exists because of a Windows desktop, and a page about what
// a host may do to your machine has to be proven on the machine it was built
// for. That constraint is why nothing here borrows setupBox / signTerms /
// grantTerms / tAnchor / tMember from anchor_test.go — those live behind
// //go:build !windows and would take this file with them (buildtags_test.go
// checks exactly that and prints the fix). The fixtures below are local and
// platform-neutral: writeAnchor, pinAnchorVerifyKey, savePairingGrant and
// dcnSaveFile are all ordinary package functions with no build tag.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	gAnchorHost = "anchor.host.privatae.ai"
	gMemberHost = "member.host.privatae.ai"
)

// givenPairing writes one pairing file the way `pair` does, with its DCN dir
// pinned to a temp path so a test can put a real grants.json where the page
// will look for it.
func givenPairing(t *testing.T, host, state string) string {
	t.Helper()
	d, err := pairingsDir()
	if err != nil {
		t.Fatalf("pairingsDir: %v", err)
	}
	dcn := filepath.Join(t.TempDir(), "dcn")
	if err := os.MkdirAll(dcn, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(&Config{
		HostName: host,
		// Loopback and nothing listening, exactly as ui_test.go writes it: a
		// pairing's control port IS loopback-only by design (config.go:39) and
		// this one is deliberately dead, so liveness reads "not answering".
		ListenAddr:      "127.0.0.1:59999",
		BastionTunnelIP: "fd00:9::a:1",
		DCNDir:          dcn,
		State:           state,
		FirstSeen:       "2026-09-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, host+".json"), b, 0o600); err != nil {
		t.Fatalf("write pairing: %v", err)
	}
	return dcn
}

// givenAnchoredBox is a NETWORKED, ANCHORED machine with the anchor host's
// signing key pinned — the shape in which a caps grant means anything at all.
// Returns the key the "anchor host" signs its grants with.
func givenAnchoredBox(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	uiTestConfigDir(t)
	p, err := modePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	givenPairing(t, gAnchorHost, pairingActive)
	if err := writeAnchor("Acme IT", gAnchorHost); err != nil {
		t.Fatalf("writeAnchor: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pinAnchorVerifyKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatalf("pinAnchorVerifyKey: %v", err)
	}
	return priv
}

// givenSignedGrant installs the anchor's signed pairing grant for host. The
// canonical bytes are a marshalled map, which is what the host side sends and
// what verifyAnchorRecord parses (anchor.go:280).
func givenSignedGrant(t *testing.T, priv ed25519.PrivateKey, host string, caps []string) {
	t.Helper()
	hn, _ := os.Hostname()
	canonical, err := json.Marshal(map[string]any{
		"kind": "pairing_grant", "server": hn, "anchor": gAnchorHost,
		"subject": host, "subject_handle": handleOf(host), "caps": caps,
		"issued_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := savePairingGrant(host, &pairingGrantFile{
		TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
		Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
		SyncedAt:       time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("savePairingGrant: %v", err)
	}
}

// givenStoreGrants writes a grants.json holding one signed store grant per
// terms map, keyed by store id, under a freshly generated pinned key.
func givenStoreGrants(t *testing.T, dir string, stores map[string]map[string]any) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &dcnGrantFile{
		VerifyPubkey: base64.StdEncoding.EncodeToString(pub),
		Stores:       map[string]dcnGrantRec{},
	}
	for id, terms := range stores {
		canonical, err := json.Marshal(terms)
		if err != nil {
			t.Fatal(err)
		}
		f.Stores[id] = dcnGrantRec{
			TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
			Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
		}
	}
	if err := dcnSaveFile(dir, f); err != nil {
		t.Fatalf("dcnSaveFile: %v", err)
	}
	return priv
}

// givenMachineStore is the shape of a real machine-store grant, so a test only
// has to say the part it is about.
func givenMachineStore(root string, mask, excludes []string, expires string) map[string]any {
	hn, _ := os.Hostname()
	m := map[string]any{
		"kind": "dcn_store_grant", "class": "machine", "server": hn,
		"root": root, "mask": mask, "expires": expires,
	}
	if excludes != nil {
		m["excludes"] = excludes
	}
	return m
}

// givenPage drives a signed-in GET through the whole mux — the Host check, the
// Origin check, the session check and the template — and returns the body.
func givenPage(t *testing.T, path string) string {
	t.Helper()
	u := uiTestServer(t)
	tok, err := u.sessions.mint()
	if err != nil {
		t.Fatal(err)
	}
	r := uiReq(http.MethodGet, path)
	r.Header.Set("Cookie", uiCookieName+"="+tok)
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

// givenCapsFor slices out ONE host's capability section. The page lists every
// pairing, so an assertion on the whole body would pass on the wrong host's
// row — which is the only mistake this page could make that would be worse
// than not existing.
func givenCapsFor(t *testing.T, body, host string) string {
	t.Helper()
	open := "What " + host + " may do to this machine"
	shut := "Folders of yours that " + host + " can reach"
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("the page has no capability section for %s", host)
	}
	j := strings.Index(body[i:], shut)
	if j < 0 {
		t.Fatalf("the capability section for %s is not closed by its folder section", host)
	}
	return body[i : i+j]
}

// givenFoldersFor slices out ONE host's folder list: from its own heading to
// the next host's capability heading, or to the end of the page.
func givenFoldersFor(t *testing.T, body, host string) string {
	t.Helper()
	open := "Folders of yours that " + host + " can reach"
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("the page has no folder section for %s", host)
	}
	rest := body[i+len(open):]
	if j := strings.Index(rest, "may do to this machine"); j >= 0 {
		// Back up past the next host's <h3>, which carries that host's name.
		if k := strings.LastIndex(rest[:j], "<h3>"); k >= 0 {
			return rest[:k]
		}
		return rest[:j]
	}
	return rest
}

func givenHolds(t *testing.T, section, host string, families ...string) {
	t.Helper()
	for _, f := range families {
		row := givenRow(t, section, f)
		if !strings.Contains(row, "granted") || strings.Contains(row, "refused here") {
			t.Errorf("%s: %q must read as GRANTED and does not:\n%s", host, f, row)
		}
	}
}

func givenRefuses(t *testing.T, section, host string, families ...string) {
	t.Helper()
	for _, f := range families {
		row := givenRow(t, section, f)
		if !strings.Contains(row, "refused here") || strings.Contains(row, ">granted<") {
			t.Errorf("%s: %q must read as REFUSED and does not:\n%s", host, f, row)
		}
	}
}

// givenRow is one family's card. The family id is the last thing in the card
// (the ops line), so a card runs from the previous card boundary to it.
func givenRow(t *testing.T, section, family string) string {
	t.Helper()
	marker := `<p class="cap-ops">` + family + "\n"
	i := strings.Index(section, marker)
	if i < 0 {
		t.Fatalf("no card for the %q family on this page", family)
	}
	start := strings.LastIndex(section[:i], `<div class="cap `)
	if start < 0 {
		t.Fatalf("the %q card has no opening div", family)
	}
	return section[start : i+len(marker)]
}

// ── the ceiling the page claims to show IS the ceiling ──────────────────────

// The page must describe every family the gate can hold, and probe each one
// with an op that really belongs to it. Both halves have failed elsewhere in
// this codebase: opFamily has been renamed under callers before (anchor.go's
// comment on model: vs mode: is the scar), and a family added to allCaps with
// no entry here would be a capability the machine gives away and never
// mentions — which is worse than having no page, because the page would then
// be the reason nobody looked.
func TestEveryCapsFamilyIsDescribedAndProbedByAnOpOfItsOwn(t *testing.T) {
	described := map[string]bool{}
	for _, f := range uiGivenFamilies {
		if described[f.Name] {
			t.Errorf("family %q is described twice", f.Name)
		}
		described[f.Name] = true
		if got := opFamily(f.Probe); got != f.Name {
			t.Errorf("the %q card probes the gate with %q, which opFamily calls %q — "+
				"this card is asking about the wrong capability", f.Name, f.Probe, got)
		}
		if f.Line == "" || f.Detail == "" {
			t.Errorf("family %q has no plain-words description", f.Name)
		}
	}
	for _, c := range allCaps {
		if !described[c] {
			t.Errorf("allCaps holds %q and this page never mentions it. A capability the "+
				"machine gives away and does not name is the failure this page exists to "+
				"end — add a uiGivenFamilies entry saying what it lets a host do here.", c)
		}
	}
	if len(uiGivenFamilies) != len(allCaps) {
		t.Errorf("%d families described, %d in allCaps", len(uiGivenFamilies), len(allCaps))
	}
}

// The ops under each heading are the ops this binary will actually answer.
// mgmtOpVocabulary is handlerOps + sessionOps + p8AllowedOps; the three lane
// gates are not in it and have to be added by hand, so this pins that they are.
func TestTheOpsUnderEachFamilyAreTheOnesTheBoxAnswers(t *testing.T) {
	byFamily := uiFamilyOps()
	for _, op := range mgmtOpVocabulary() {
		fam := opFamily(op)
		if fam == "" {
			continue // stepup_* / pairing_*, excepted from the ceiling
		}
		found := false
		for _, got := range byFamily[fam] {
			found = found || got == op
		}
		if !found {
			t.Errorf("%q is in the op vocabulary and in family %q, and the page does not "+
				"list it", op, fam)
		}
	}
	// The lane gates: capsAllow'd at their own lane, never as a mgmt job, so a
	// list built from the vocabulary alone shows three empty families.
	for op, fam := range map[string]string{
		"harness:run": "harness", "egress": "egress", "inference": "inference",
	} {
		found := false
		for _, got := range byFamily[fam] {
			found = found || got == op
		}
		if !found {
			t.Errorf("family %q lists no ops, so its card reads as granting nothing — "+
				"%q is gated at its lane and is missing from uiFamilyOps", fam, op)
		}
	}
}

// ── what a local machine gives away ─────────────────────────────────────────

// THE UNCOMFORTABLE ONE, and the ordinary case. A local bastion cannot be
// anchored (claim-anchor refuses outside networked mode), capsAllow's
// unanchored branch gates nothing there, and so the pairing IS the
// authorization: the host holds every family including the root shell,
// the files and the screen. The machine has never said so anywhere.
func TestAnUnanchoredLocalMachineSaysItGaveEverythingAway(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "member.host.privatae.ai", pairingActive)

	body := givenPage(t, "/given")
	section := givenCapsFor(t, body, "member.host.privatae.ai")
	givenHolds(t, section, "member.host.privatae.ai", allCaps...)

	// Counted from what the page lists, not a literal: every caps family plus
	// the box-wide directives card (uigiven.go), so a family added to the
	// ceiling does not break this for being added.
	n := len(uiGivenFamilies) + 1
	if !strings.Contains(section, fmt.Sprintf("%d of %d are granted", n, n)) {
		t.Error("the page must count what it gave away, not leave it to be tallied by eye")
	}
	// The three the design singles out, in words a person can act on.
	for _, want := range []string{
		"Open a shell on this machine.",
		"Read your files.",
		"Read this machine, and what is on its screen.",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the page never says %q", want)
		}
	}
	if !strings.Contains(body, "not anchored, so the pairing itself is the authorization") {
		t.Error("the page shows every capability granted and never says WHY — a user " +
			"who cannot tell whether this was a decision or a bug learns nothing")
	}
}

// THE PAGE IS A CONTROL NOW, and the control can only ever remove reach.
//
// The console can switch a granted capability off — that is local control the
// person at the machine needs. This test replaces the one that forbade every
// <form> and <button> here while that was open — the decision is made, so the
// invariant changes from "no controls" to "no control that widens".
func TestTheGivenPageSwitchesOffAndCanNeverWiden(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	givenPairing(t, host, pairingActive)
	body := givenPage(t, "/given")

	if !strings.Contains(body, `hx-post="/given/switch"`) {
		t.Fatal("the page carries no switch at all — local control on your own machine " +
			"is the decision this page exists to honour")
	}
	// EVERY form on this page posts to the switch and nowhere else. A second
	// mutating route added here later is the way a widening control arrives.
	for _, posts := range regexp.MustCompile(`hx-post="([^"]+)"`).FindAllStringSubmatch(body, -1) {
		if posts[1] != "/given/switch" {
			t.Errorf("this page posts to %q as well as the switch. The only mutation "+
				"allowed here is one that removes reach.", posts[1])
		}
	}
	// And the copy says the thing that makes it safe.
	for _, want := range []string{
		"switched off here",
		"never changes the grant",
		"privatae-bastion unpair",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page never says %q — the reason this control is safe is that "+
				"it cannot grant, and a person cannot check that by looking at a button", want)
		}
	}
}

// Switching one off is visible on the page as HAVING BEEN SWITCHED, distinct
// from never having been granted. Those are different facts and only one of
// them has a way back.
func TestASwitchedOffCapabilityReadsDifferentlyFromAnUngrantedOne(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	priv := givenAnchoredBox(t)
	givenPairing(t, host, pairingActive)
	givenSignedGrant(t, priv, host, []string{"dcn", "observe"})

	if err := localDenySet(host, "dcn", true); err != nil {
		t.Fatal(err)
	}
	body := givenPage(t, "/given")
	if !strings.Contains(body, "switched off by you") {
		t.Error("a capability the person switched off does not say so — it reads as " +
			"though the host was never granted it, which is a different fact with a " +
			"different remedy")
	}
	if !strings.Contains(body, "Turn back on") {
		t.Error("there is no way back from a switch on the page that made it")
	}
}

// ── what an anchored machine gives away ─────────────────────────────────────

// The whole point of the caps ceiling, rendered: two hosts on one machine, one
// holding everything because it is the anchor, one holding exactly the two
// families the anchor signed for it. Sliced per host, because a page that
// showed one host's grants under another host's name would be worse than no
// page at all.
func TestAGrantedFamilyIsSeparatedFromAWithheldOne(t *testing.T) {
	priv := givenAnchoredBox(t)
	givenPairing(t, gMemberHost, pairingActive)
	givenSignedGrant(t, priv, gMemberHost, []string{"observe", "dcn"})

	body := givenPage(t, "/given")

	member := givenCapsFor(t, body, gMemberHost)
	givenHolds(t, member, gMemberHost, "observe", "dcn")
	givenRefuses(t, member, gMemberHost, "session", "models", "harness", "egress", "inference")
	if !strings.Contains(member, fmt.Sprintf("2 of %d are granted", len(uiGivenFamilies)+1)) {
		t.Error("the member's count is wrong")
	}

	anchor := givenCapsFor(t, body, gAnchorHost)
	givenHolds(t, anchor, gAnchorHost, allCaps...)
	if !strings.Contains(body, "the anchor is unconstrained") {
		t.Error("the page must say that the anchor holds everything, and why")
	}
}

// Default-deny, said out loud. A member pairing with no grant holds nothing,
// and the reasons it can hold nothing (revoked, expired, another subject, a
// file edited on disk) all land in the same place, so the page names them
// rather than leaving the user to wonder which one happened.
func TestAPairingWithNoVerifiedGrantIsRefusedEverything(t *testing.T) {
	givenAnchoredBox(t)
	givenPairing(t, gMemberHost, pairingActive)

	body := givenPage(t, "/given")
	section := givenCapsFor(t, body, gMemberHost)
	givenRefuses(t, section, gMemberHost, allCaps...)
	if !strings.Contains(section, "None of them are granted") {
		t.Error("the page must say plainly that nothing is granted")
	}
	if !strings.Contains(body, "holds no verified grant from the anchor") {
		t.Error("the page must say why nothing is granted")
	}
}

// A networked machine with no anchor serves nothing on any lane. The page has
// to agree with that, or it would list seven refusals and leave the user
// believing a grant is what is missing.
func TestANetworkedMachineWithNoAnchorSaysItServesNothing(t *testing.T) {
	uiTestConfigDir(t)
	p, err := modePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mode":"networked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	givenPairing(t, gMemberHost, pairingActive)

	body := givenPage(t, "/given")
	givenRefuses(t, givenCapsFor(t, body, gMemberHost), gMemberHost, allCaps...)
	if !strings.Contains(body, "networked but not anchored, so it serves nothing at all") {
		t.Error("the page must name the real reason: the machine is unanchored, not ungranted")
	}
}

// A pending or revoked pairing gets no tunnel, no lanes and no dirs (run.go:194).
// The caps gate knows nothing about pairing state, so the page has to say it
// separately or it would read as a live grant.
func TestAPairingThatIsNotServedSaysSo(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, gMemberHost, pairingRevoked)
	body := givenPage(t, "/given")
	if !strings.Contains(body, "nothing is being served to it right") {
		t.Error("a revoked pairing renders as though it were live")
	}
}

// ── what folders are shared from here ───────────────────────────────────────

// The second view, and the one with no local verb at all before this: dcn_list
// answers the HOST, so the person whose disk it is could not ask what was on
// it. Everything rendered comes off the signed bytes in grants.json.
func TestSharedFoldersAreRenderedFromTheSignedGrant(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	future := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"7": givenMachineStore("/home/user/Documents",
			[]string{"read", "search"}, []string{".ssh", "*.key"}, future),
	})

	body := givenPage(t, "/given")
	for _, want := range []string{
		"/home/user/Documents",
		"read — list the files in it, and read what is in them",
		"search — answer searches over it",
		"<code>.ssh</code>",
		"<code>*.key</code>",
		future,
		">shared<",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the shared folder does not render %q", want)
		}
	}
}

// THE CEILING BEATS THE GRANT, and the page has to agree. capsAllow runs at
// mgmt.go:238, before the store grant is ever loaded, so a host without the
// `dcn` family cannot read a folder however perfect the grant for it is.
//
// This was wrong in the first cut and rendering the page is what caught it: a
// member pairing granted only `observe` showed a folder tagged "shared", which
// is a page frightening its user about something that cannot happen. Getting
// that wrong costs the page its credibility exactly as fast as missing a real
// grant does, and a user who catches it once will not read it again.
func TestAFolderIsNotSharedWhenTheCeilingRefusesEveryFileOperation(t *testing.T) {
	priv := givenAnchoredBox(t)
	dcn := givenPairing(t, gMemberHost, pairingActive)
	givenSignedGrant(t, priv, gMemberHost, []string{"observe"}) // no dcn
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"1": givenMachineStore("/home/user/Documents", []string{"read"}, nil, ""),
	})

	body := givenPage(t, "/given")
	if !strings.Contains(body, "/home/user/Documents") {
		t.Error("the folder must still be listed — the record is on disk and a grant " +
			"that stops being reachable does not stop existing")
	}
	if strings.Contains(body, ">shared<") {
		t.Error("a folder is shown as shared to a host that is refused every file " +
			"operation on this machine")
	}
	if !strings.Contains(body, "refused every file operation on this machine") {
		t.Error("the page must say that the ceiling, not the grant, is what stops this")
	}
}

// A mask value this build has never heard of travels through VERBATIM. A host
// newer than its machine is the ordinary state of a fleet mid-upgrade, and a
// page that silently dropped the permission it could not name would be telling
// the user they granted less than they did.
func TestAnUnknownMaskIsShownRatherThanDropped(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"1": givenMachineStore("/srv/data", []string{"read", "transcribe"}, nil, ""),
	})
	body := givenPage(t, "/given")
	if !strings.Contains(body, "transcribe") {
		t.Error("a mask value this build cannot describe was dropped from the page")
	}
	if !strings.Contains(body, "does not know what this allows") {
		t.Error("an undescribable mask must say that it is undescribable, not sit there " +
			"looking like a word the page understood")
	}
}

// Absent fields are STATED, never defaulted. A grant with no excludes and no
// expiry is a real and common grant, and printing a plausible default for
// either would be inventing a term nobody signed.
func TestAGrantWithNoExclusionsOrExpirySaysSoRatherThanInventingOne(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"2": givenMachineStore("/srv/photos", []string{"read"}, nil, ""),
	})
	body := givenPage(t, "/given")
	if !strings.Contains(body, "the grant names no exclusions at all") {
		t.Error("a grant with no excludes must say so")
	}
	if !strings.Contains(body, "carries no expiry, so it stands until it is removed") {
		t.Error("a grant with no expiry must say that it never expires — the convention " +
			"is expires==\"\" means NEVER (dcn.go:150), and guessing here would be the " +
			"one lie that matters on this page")
	}
}

// A record that does not verify grants NOTHING, and is still LISTED. Hiding it
// would tell the user "nothing is shared" while a record sat on their disk,
// which is the misleading direction; the honest one is to show the bytes and
// the verdict together.
func TestARecordThatDoesNotVerifyIsListedAndNotShownAsShared(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"3": givenMachineStore("/srv/expired", []string{"read"}, nil, past),
		"4": givenMachineStore("/srv/tampered", []string{"read"}, nil, ""),
	})
	// Rewrite store 4's terms, leaving the old signature over the old bytes.
	f, err := dcnLoadFile(dcn)
	if err != nil {
		t.Fatal(err)
	}
	widened, err := json.Marshal(givenMachineStore("/", []string{"read"}, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	rec := f.Stores["4"]
	rec.TermsCanonical = base64.StdEncoding.EncodeToString(widened)
	f.Stores["4"] = rec
	if err := dcnSaveFile(dcn, f); err != nil {
		t.Fatal(err)
	}

	body := givenPage(t, "/given")
	if !strings.Contains(body, "/srv/expired") || !strings.Contains(body, "grant expired") {
		t.Error("an expired grant must be listed, with the reason it grants nothing")
	}
	if !strings.Contains(body, "signature does not verify") {
		t.Error("a record edited on disk must be listed as not verifying")
	}
	if strings.Count(body, ">shared<") != 0 {
		t.Errorf("a record that grants nothing is rendered as shared:\n%s", body)
	}
	if strings.Count(body, ">not in force<") != 2 {
		t.Errorf("both records must read as not in force, got %d",
			strings.Count(body, ">not in force<"))
	}
}

// A SIGNATURE THAT VERIFIES IS NOT THE WHOLE VERDICT, and a page that stopped
// there would show two live shares that this machine refuses. dcnLoadGrantMask
// applies two more walls immediately after the signature checks out (dcn.go:264,
// 270): the grant has to be a machine-class store with a root, and its mask has
// to name at least one operation. Both of these records are perfectly signed.
//
// Caught by mutation: deleting the class/root branch left every test green.
func TestAVerifiedGrantThatTheBoxStillRefusesIsNotShownAsShared(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	// Signed WITH an expiry: an open-ended grant is refused at the signature
	// wall now (dcnVerifyRec), and this test is about the two walls after it.
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	notMachine := givenMachineStore("/srv/elsewhere", []string{"read"}, nil, future)
	notMachine["class"] = "entity"
	noMask := givenMachineStore("/srv/masked", []string{}, nil, future)
	givenStoreGrants(t, dcn, map[string]map[string]any{
		"5": notMachine,
		"6": noMask,
	})

	body := givenPage(t, "/given")
	if strings.Contains(body, ">shared<") {
		t.Error("a grant this machine refuses is rendered as shared")
	}
	if !strings.Contains(body, "not for a folder on this machine") {
		t.Error("a grant that is not a machine store must say so — its signature is " +
			"perfectly good and the reason it grants nothing is somewhere else")
	}
	if !strings.Contains(body, "allows no operation at all") {
		t.Error("a grant whose mask names nothing must say so: dcnHasMask refuses every " +
			"op against it, so it is a folder in the list that cannot be read")
	}
	// And the paths are still there — the records exist and hiding them would
	// tell the user a folder was never granted when it was.
	for _, want := range []string{"/srv/elsewhere", "/srv/masked"} {
		if !strings.Contains(body, want) {
			t.Errorf("the record for %s was hidden rather than listed", want)
		}
	}
}

// THE REST OF WHAT A RECORD REALLY HOLDS. A grant is not just a path and a
// mask: the signed terms also carry a sweep cadence, a TTL that was shown to
// the user at approval and a sensitive flag, and the RECORD carries a seal
// recipient that travels OUTSIDE the signed bytes (dcn.go:59-62). Showing the
// seal without saying it was not part of what was signed would quietly promote
// an unsigned field to an approved one, on the page whose whole job is to say
// what was approved.
func TestTheRestOfWhatAGrantHoldsIsRenderedIncludingTheUnsignedSeal(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	terms := givenMachineStore("/srv/notes", []string{"read"}, nil, "")
	terms["sweep"] = "nightly"
	terms["ttl_days"] = 30
	terms["sensitive"] = true
	canonical, err := json.Marshal(terms)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dcnSaveFile(dcn, &dcnGrantFile{
		VerifyPubkey: base64.StdEncoding.EncodeToString(pub),
		Stores: map[string]dcnGrantRec{"9": {
			TermsCanonical: base64.StdEncoding.EncodeToString(canonical),
			Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
			SealRecipient:  "age1qqqqqqexamplerecipient",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	body := givenPage(t, "/given")
	for _, want := range []string{"nightly", "30 days", "sensitive", "sealed to your registered backup"} {
		if !strings.Contains(body, want) {
			t.Errorf("the grant holds %q and the page does not show it", want)
		}
	}
	if !strings.Contains(body, "outside the signed part of the record") {
		t.Error("the seal recipient is shown as though it were part of what was approved; " +
			"it rides outside the signed bytes and the page has to say so")
	}
}

// Folders belong to the host they were granted to. A page that listed one
// host's folders under another host's name would be the same class of mistake
// as showing its capabilities there, and it is the mistake that would do the
// most damage on a machine serving several hosts.
func TestEachHostsFoldersAreListedUnderThatHost(t *testing.T) {
	priv := givenAnchoredBox(t)
	anchorDCN := ""
	if cfgs, err := loadPairings(); err == nil {
		for _, c := range cfgs {
			if c.HostName == gAnchorHost {
				anchorDCN = c.dcnDir()
			}
		}
	}
	if anchorDCN == "" {
		t.Fatal("the anchor pairing has no DCN dir")
	}
	memberDCN := givenPairing(t, gMemberHost, pairingActive)
	givenSignedGrant(t, priv, gMemberHost, []string{"dcn"})
	givenStoreGrants(t, anchorDCN, map[string]map[string]any{
		"1": givenMachineStore("/srv/only-the-anchor", []string{"read"}, nil, ""),
	})
	givenStoreGrants(t, memberDCN, map[string]map[string]any{
		"2": givenMachineStore("/srv/only-the-member", []string{"read"}, nil, ""),
	})

	body := givenPage(t, "/given")
	anchorFolders := givenFoldersFor(t, body, gAnchorHost)
	if !strings.Contains(anchorFolders, "/srv/only-the-anchor") {
		t.Error("the anchor's folder is not under the anchor")
	}
	if strings.Contains(anchorFolders, "/srv/only-the-member") {
		t.Error("the member's folder is listed under the anchor — on a machine serving " +
			"several hosts this is the worst thing this page could get wrong")
	}
	memberFolders := givenFoldersFor(t, body, gMemberHost)
	if !strings.Contains(memberFolders, "/srv/only-the-member") {
		t.Error("the member's folder is not under the member")
	}
	if strings.Contains(memberFolders, "/srv/only-the-anchor") {
		t.Error("the anchor's folder is listed under the member")
	}
}

// No pinned key means dcnLoadGrantMask refuses before it even looks at a store
// (dcn.go:250). The page says that once, above the list, rather than repeating
// it as a per-row reason.
func TestNoPinnedKeyIsStatedOnceAboveTheList(t *testing.T) {
	uiTestConfigDir(t)
	dcn := givenPairing(t, "member.host.privatae.ai", pairingActive)
	canonical, err := json.Marshal(givenMachineStore("/srv/data", []string{"read"}, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := dcnSaveFile(dcn, &dcnGrantFile{Stores: map[string]dcnGrantRec{
		"1": {TermsCanonical: base64.StdEncoding.EncodeToString(canonical), Signature: "x"},
	}}); err != nil {
		t.Fatal(err)
	}
	body := givenPage(t, "/given")
	if !strings.Contains(body, "No key from this host has been pinned") {
		t.Error("a box with no pinned key must say so — every read is refused there and " +
			"the per-store reasons would all be the same one")
	}
	if strings.Contains(body, ">shared<") {
		t.Error("nothing can be shared when no key is pinned")
	}
}

func TestAMachineSharingNothingSaysNothingRatherThanShowingAnEmptyList(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "member.host.privatae.ai", pairingActive)
	body := givenPage(t, "/given")
	if !strings.Contains(body, "No folder of yours is shared with this host") {
		t.Error("an empty folder list must be said in words; an empty region reads as " +
			"a page that failed to load")
	}
}

func TestAMachineWithNoPairingsSaysNothingWasGivenAway(t *testing.T) {
	uiTestConfigDir(t)
	body := givenPage(t, "/given")
	if !strings.Contains(body, "No host is paired with this machine") {
		t.Error("the one reassuring state on this page must be stated")
	}
}

// ── the fragment and the headers ────────────────────────────────────────────

// The htmx target renders the same view and only the view. A whole document
// swapped into <main> nests a second <html> inside the body.
func TestTheGivenFragmentIsAFragment(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "member.host.privatae.ai", pairingActive)
	frag := givenPage(t, "/fragments/given")
	if !strings.Contains(frag, "member.host.privatae.ai") {
		t.Error("the fragment does not carry the pairing")
	}
	if strings.Contains(frag, "<!doctype html") || strings.Contains(frag, "<script") {
		t.Error("the fragment is a whole page")
	}
}

// renderGiven sets its headers itself rather than going through renderWith,
// which is typed to uiStatus. That duplication is only safe if it cannot drift,
// so this compares the two responses header for header: a CSP added, tightened
// or renamed on the status page and missed here is a red test instead of a
// security page quietly served without one.
func TestTheGivenPageCarriesTheSameHeadersAsTheStatusPage(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "member.host.privatae.ai", pairingActive)
	u := uiTestServer(t)
	h := u.handler()
	tok, err := u.sessions.mint()
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) http.Header {
		r := uiReq(http.MethodGet, path)
		r.Header.Set("Cookie", uiCookieName+"="+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, w.Code)
		}
		return w.Header()
	}
	status, given := get("/fragments/status"), get("/fragments/given")
	for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options",
		"Cache-Control", "Content-Type"} {
		if status.Get(k) == "" {
			t.Fatalf("the status page sets no %s — this comparison would be vacuous", k)
		}
		if given.Get(k) != status.Get(k) {
			t.Errorf("%s: the given page sends %q, the status page sends %q",
				k, given.Get(k), status.Get(k))
		}
	}
}

// The page's own stylesheet has to come out of the binary like every other
// asset — a CSP of default-src 'self' means a missing one is an unstyled page,
// not a broken one, so nothing else would ever report it.
func TestTheGivenStylesheetIsServedFromTheBinary(t *testing.T) {
	uiTestConfigDir(t)
	w := httptest.NewRecorder()
	uiTestServer(t).handler().ServeHTTP(w, uiReq(http.MethodGet, "/assets/given.css"))
	if w.Code != http.StatusOK {
		t.Fatalf("/assets/given.css = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), ".cap") {
		t.Error("given.css does not look like itself — the embed may be empty")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("given.css is served as %q", ct)
	}
}

// The page is reachable. A view of what your machine gave away that nothing
// links to is a view nobody opens.
func TestTheStatusPageLinksToWhatThisMachineGaveAway(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "member.host.privatae.ai", pairingActive)
	u := uiTestServer(t)
	tok, err := u.sessions.mint()
	if err != nil {
		t.Fatal(err)
	}
	r := uiReq(http.MethodGet, "/")
	r.Header.Set("Cookie", uiCookieName+"="+tok)
	w := httptest.NewRecorder()
	u.handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/ = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `href="/given"`) {
		t.Error("nothing on the status page links to /given")
	}
}

// ── the route, driven ───────────────────────────────────────────────────────

// NOTHING DROVE /given/switch AT ALL. The only mentions were a template scan,
// so the route, its method guard, its form parsing and its flash were entirely
// unexercised. The drift failure mode there is not a dead
// button but an INVERTED one: rename the handler's FormValue("off") and "Switch
// off here" would clear the denial instead of setting it.
//
// One POST through the real handler holds the template, the route and the words
// together — and it is what surfaced the flash never being rendered, because
// the tag flips from state and looked correct without it.
func TestSwitchingThroughTheRouteFlipsTheStateAndSaysSo(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	priv := givenAnchoredBox(t)
	givenPairing(t, host, pairingActive)
	givenSignedGrant(t, priv, host, []string{"dcn", "observe"})

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	// GET is refused: this changes something.
	r := uiReq(http.MethodGet, "/given/switch")
	r.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /given/switch = %d, want 405", w.Code)
	}

	// OFF.
	w = uiPost(t, h, "/given/switch", url.Values{
		"host": {host}, "family": {"dcn"}, "off": {"1"},
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("switch off = %d: %s", w.Code, w.Body.String())
	}
	if !localDenied(host, "dcn") {
		t.Error("posting off=1 did not switch anything off — the handler's form " +
			"parsing and the page's button are not talking about the same field")
	}
	body := w.Body.String()
	if !strings.Contains(body, "can no longer") {
		t.Errorf("the page never says what the machine will now DO. The tag flips from "+
			"state, so the switch LOOKS like it worked while the sentence explaining it "+
			"is composed and thrown away: %q", dmSnip(body, "flash"))
	}
	if !strings.Contains(body, "grant is untouched") {
		t.Error("the confirmation does not say the grant is untouched, which is the " +
			"one thing that makes this safe to press")
	}

	// AND BACK ON — the inverted-drift case: if these two ever do the same
	// thing, one of them is silently wrong.
	w = uiPost(t, h, "/given/switch", url.Values{
		"host": {host}, "family": {"dcn"}, "off": {"0"},
	}, cookie)
	if localDenied(host, "dcn") {
		t.Error("posting off=0 did not clear the denial")
	}
	if !strings.Contains(w.Body.String(), "grants nothing") {
		t.Errorf("turning it back on does not say it grants nothing: %q",
			dmSnip(w.Body.String(), "flash"))
	}
}

// AN UNREADABLE LIST IS SAID OUT LOUD. The gate must fail OPEN on a corrupt
// file — one bad file must not stop the machine serving its host — so the page
// carries the opposite obligation: say it, or the person is shown their
// switches as not existing rather than as not working.
func TestAnUnreadableDenyListIsReportedOnThePage(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	priv := givenAnchoredBox(t)
	givenPairing(t, host, pairingActive)
	givenSignedGrant(t, priv, host, []string{"dcn"})
	if err := localDenySet(host, "dcn", true); err != nil {
		t.Fatal(err)
	}
	p, err := localDenyPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	body := givenPage(t, "/given")
	if !strings.Contains(body, "cannot be read") {
		t.Errorf("the page renders every capability as granted while the switches are "+
			"silently not in effect, and never says so: %q", dmSnip(body, "granted"))
	}
	if !strings.Contains(body, "not in effect") {
		t.Error("the note does not say what it MEANS for the person — that what they " +
			"switched off is not being blocked")
	}
}

// THE ONE MUTATING ROUTE ON THIS PAGE IS GUARDED, and until now nothing held
// that. Stripping `u.guarded` from /given/switch survived the entire suite:
// the route test only ever posts with a valid cookie
// and a same-origin header, so it cannot tell a guarded route from an open one.
//
// Deny-only bounds what an unauthorised POST could do — it can never widen —
// but `off=0` CLEARS a denial the person set, so an open route lets a page in
// another tab switch their own protection back on. The approval routes have had
// this check since they were built (ui_approvals_test.go); the newer mutating
// route did not inherit it.
func TestTheSwitchRouteNeedsASessionAndAnOrigin(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	givenPairing(t, host, pairingActive)
	if err := localDenySet(host, "dcn", true); err != nil {
		t.Fatal(err)
	}
	u := uiTestServer(t)
	h := u.handler()
	form := url.Values{"host": {host}, "family": {"dcn"}, "off": {"0"}}

	// No session.
	w := uiPost(t, h, "/given/switch", form, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("switch with no session = %d, want 401", w.Code)
	}

	// A session, but posted from another site: SameSite would normally stop the
	// cookie ever arriving, and this is the check for when it does not.
	cookie := uiSignedIn(t, u)
	r := httptest.NewRequest(http.MethodPost, "/given/switch", strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:" + uiTestPort
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site switch = %d, want 403", w.Code)
	}

	if !localDenied(host, "dcn") {
		t.Fatal("an unauthorised request turned the person's own switch back on")
	}
}

// THE CONFIRMATION NAMES THE HOST AND THE THING IT CAN NO LONGER DO. The route
// test asserted the shape of the sentence — "can no longer", "grant is
// untouched" — and neither of the two facts the sentence exists to carry, so a
// flash naming the wrong host or the wrong capability passed it. On a page
// with seven families and several hosts, those are
// the only two words that tell the person which button they just pressed.
func TestTheConfirmationNamesTheRightHostAndTheRightCapability(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"
	const other = "second.host.privatae.ai"
	givenPairing(t, host, pairingActive)
	givenPairing(t, other, pairingActive)

	u := uiTestServer(t)
	h := u.handler()
	cookie := uiSignedIn(t, u)

	w := uiPost(t, h, "/given/switch", url.Values{
		"host": {other}, "family": {"session"}, "off": {"1"},
	}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("switch off = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	flash := dmSnip(body, "flash")
	if !strings.Contains(body, other+" can no longer") {
		t.Errorf("the confirmation does not name the host that was switched off — with "+
			"two hosts on the page that is the whole sentence: %q", flash)
	}
	if strings.Contains(body, host+" can no longer") {
		t.Errorf("the confirmation names the OTHER host: %q", flash)
	}
	if !strings.Contains(body, uiFamilyVerb("session")) {
		t.Errorf("the confirmation does not say what %s can no longer do; it reads %q",
			other, flash)
	}
	if strings.Contains(flash, uiFamilyVerb("dcn")) {
		t.Errorf("the confirmation names a capability that was not switched: %q", flash)
	}
}

// THE FALLBACK WHEN THE PAIRING STORE ITSELF CANNOT BE READ. localDenySet
// refuses a host this machine never paired with — that is what stops the
// confirmation lying by typo — but it accepts one when the pairing records are
// unreadable, because refusing would let a corrupt file stop a person
// TIGHTENING their own machine. Nothing held either half: making it refuse
// broke no test.
func TestACorruptPairingStoreDoesNotBlockTighteningTheMachine(t *testing.T) {
	uiTestConfigDir(t)
	const host = "member.host.privatae.ai"

	// A host that WAS paired is switchable, and one that never was is refused.
	givenPairing(t, host, pairingActive)
	pdir, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := localDenySet(host, "dcn", true); err != nil {
		t.Fatalf("a paired host was refused: %v", err)
	}
	if err := localDenySet("typo.host.privatae.ai", "dcn", true); err == nil {
		t.Error("a host this machine never paired with was accepted — the page would " +
			"then answer 'X can no longer read your files' about a host it has never heard of")
	}

	// Now make the pairing store unreadable. Tightening must still work.
	if err := os.WriteFile(filepath.Join(pdir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPairings(); err == nil {
		t.Fatal("the fixture did not actually break the pairing store")
	}
	if err := localDenySet(host, "session", true); err != nil {
		t.Fatalf("a corrupt pairing file stopped the person switching something OFF: %v. "+
			"A broken record must never block a tighten.", err)
	}
	if !localDenied(host, "session") {
		t.Error("the switch reported success and wrote nothing")
	}
}
