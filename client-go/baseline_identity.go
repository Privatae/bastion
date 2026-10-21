package main

// IDENTITIES ENTER THE ACCOUNTING.
//
// Persistence on a machine is usually an ACCOUNT, not a process: a user with a
// shell, a sudo rule, a key appended to authorized_keys. All three survive a
// reboot and none of them is a running program, so the process half of this
// plane cannot see any of them however well it works.
//
// WHAT IS RECORDED, AND WHAT DELIBERATELY IS NOT. This runs on the person's own
// computer, so the rule is that the accounting holds the SHAPE of an identity
// and never its content:
//
//	recorded      account name, its shell, uid, whether it holds sudo rights,
//	              how many authorized keys it has, and a digest over the key
//	              set
//	NOT recorded   any key material, any password hash, the text of a sudo rule,
//	              any home directory content
//
// The digest is what makes `authkeys_changed` mean something a count cannot: a
// key swapped for another key is the same count and a different machine. It is
// a one-way hash over the key bodies, salted by baselineVersion like every
// other fingerprint here, so the accounting cannot be read back into keys.
//
// AND NONE OF IT LEAVES THE BOX. What rides the heartbeat is deltaSummary
// (deltarun.go:75-88) — four counts, the baseline state, timestamps and a note
// string. No entry, no name, no digest. The findings themselves stay on the
// machine and are read there with `observe:delta`. That was already true for
// processes; it is what makes this class safe to add, and it is why nothing in
// here may ever be put into a Note.
//
// THE SLOT IS THE ACCOUNT. Its shell, sudo and keys are in the fingerprint, so
// changing any of them is a change to a known account rather than a new one
// appearing — see baselineSlot. `identity_new` is then exactly what it says: an
// account that was not there before.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// identityObs is one account as the box observed it. Platform-neutral so the
// constructors below are testable without a filesystem.
type identityObs struct {
	Name  string
	UID   int
	Shell string
	// Sudo is whether this account is named by a sudo rule or sits in a group
	// that is. The RULE ITSELF IS NOT KEPT — only that one exists.
	Sudo bool
	// SudoUnknown is set when the sudo rules could not be read at all. THIS IS
	// NOT `Sudo == false`: reporting every account as unprivileged because this
	// process could not open /etc/sudoers would make the next readable pass
	// fire `sudoers_changed` at CRITICAL for every one of them. It is the same distinction DigestNote draws for a process whose
	// executable could not be read, and it belongs in the FINGERPRINT rather
	// than beside it, because only what is fingerprinted is compared.
	SudoUnknown bool
	// AuthKeys is how many authorized keys the account has, and KeyDigest is a
	// one-way digest over their bodies. Both, because a count alone cannot see
	// a swap and a digest alone cannot be read by a person.
	AuthKeys   int
	KeyDigest  string
	KeysUnread string // why the key file could not be read, when it could not
}

// identityScanReport is what a platform's reader returns, including its own
// blindness. A reader that cannot look must say so: "no accounts with a shell"
// and "I could not read the account database" are different machines and this
// plane's whole discipline is not conflating them.
type identityScanReport struct {
	Supported bool
	Reason    string
	Accounts  []identityObs
	// Partial names a half that was readable in principle and failed in fact —
	// sudo rules unreadable, a home directory that could not be entered. The
	// accounting keeps what it got and says which half is short.
	Partial string
}

// baselineFromIdentities is the single constructor, shared by BOTH sides for
// the reason deltaCollectLiveFrom gives: two spellings of this is how the
// accounting and the live scan drift apart.
func baselineFromIdentities(ids []identityObs) []baselineEntry {
	out := make([]baselineEntry, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		e := baselineEntryOfIdentity(id)
		if seen[e.FP] {
			continue
		}
		seen[e.FP] = true
		out = append(out, e)
	}
	return out
}

// identityUnknown is what an unreadable property records as. A marker rather
// than an absent field, for the reason DigestNote gives: an absent value reads
// as "nothing there", and "I could not look" is a different fact.
const identityUnknown = "?"

func baselineEntryOfIdentity(id identityObs) baselineEntry {
	// The fingerprinted state of the account, in one field. Ordered and
	// explicit so a reader can see exactly what a change in this entry means.
	// UNKNOWN IS A THIRD VALUE AND IT IS IN THE FINGERPRINT. "this box could
	// not look" compared as "there are none" is the defect this plane's file
	// headers say it has shipped before, and on this class it is expensive: an
	// unreadable key file read as keys=0 produced `authkeys_changed` at HIGH
	// carrying "authorized keys 1 → 0", i.e. the sentence "keys were removed"
	// about a box that never looked.
	sudo := strconv.FormatBool(id.Sudo)
	if id.SudoUnknown {
		sudo = identityUnknown
	}
	keys, digest := strconv.Itoa(id.AuthKeys), id.KeyDigest
	if id.KeysUnread != "" {
		keys, digest = identityUnknown, identityUnknown
	}
	state := "shell=" + id.Shell +
		";uid=" + strconv.Itoa(id.UID) +
		";sudo=" + sudo +
		";keys=" + keys +
		";keydigest=" + digest
	e := baselineEntry{
		Kind:      "identity",
		Unit:      id.Name, // the slot: the account
		User:      id.Name,
		ArgvShape: state,
		Origin:    "account-database",
	}
	if id.KeysUnread != "" {
		// Same rule as DigestNote on a process: an absent number reads as zero,
		// and "this box could not look" is a different fact.
		e.DigestNote = "authorized keys not readable: " + id.KeysUnread
	}
	e.FP = baselineFP(e.Kind, e.ExeDigest, e.User, e.Unit, e.ArgvShape)
	return e
}

// identityKeyDigest is a one-way digest over a key set, order-independent.
//
// SORTED BEFORE HASHING, because the order of lines in an authorized_keys file
// is not a fact about the machine — an editor, a config-management run or a
// re-write can reorder it without granting or revoking anything. Unsorted, the
// first such rewrite would report `authkeys_changed` on every box that had one,
// which is the kind of false finding that teaches people to ignore this plane.
//
// Salted with baselineVersion like every other fingerprint here. STATED
// EXACTLY, because the first version of this line claimed more than it
// delivers: the salt is a public constant in an open
// repo, so it defeats a GENERIC rainbow table and not one built for this
// program, and for an account with a single key the digest is a checkable
// guess against a candidate public key. That is acceptable here and it is not
// nothing: the file is 0600 and local, and anyone who can read it can read
// authorized_keys itself. It is not a reason to put a key body in the file.
func identityKeyDigest(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	norm := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		// The comment field is the part a person edits freely ("erin@laptop"),
		// and it grants nothing. Keeping it would report a renamed key as a new
		// one. Type and body are what authorise.
		f := strings.Fields(k)
		if len(f) >= 2 {
			k = f[0] + " " + f[1]
		}
		norm = append(norm, k)
	}
	if len(norm) == 0 {
		return ""
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(baselineVersion + "\x00authkeys\x00" + strings.Join(norm, "\n")))
	return hex.EncodeToString(sum[:16])
}

// identityCountKeys is the number of real keys in an authorized_keys body —
// blanks and comments are not grants.
func identityCountKeys(keys []string) int {
	n := 0
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		n++
	}
	return n
}

// identityIsLoginShell answers whether a shell can be logged in with. The list
// is the conventional set of "no" shells; anything else counts as yes.
//
// DEFAULTING TO YES IS THE SAFE DIRECTION and is chosen deliberately. An
// unfamiliar shell on an account is more interesting, not less, so an unknown
// value must not silently drop the account out of the accounting — which is
// what a default-no would do, and it would do it for exactly the account
// somebody had reason to make unusual.
func identityIsLoginShell(shell string) bool {
	s := strings.TrimSpace(shell)
	if s == "" {
		return false
	}
	switch s {
	case "/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin",
		"/bin/false", "/usr/bin/false", "/dev/null", "/bin/sync", "/usr/bin/sync":
		return false
	}
	return true
}

// ── reading an identity entry back ──────────────────────────────────────────
//
// The fingerprinted state is one string (baselineEntryOfIdentity), so these are
// the accessors that turn it back into the facts a level rule and a sentence
// need. Parsing what this file wrote is deliberate: the alternative is extra
// fields on baselineEntry that only one class uses, and every one of those is
// another field the digest rules in baseline.go would have to speak about.

func identityField(e baselineEntry, key string) string {
	for _, part := range strings.Split(e.ArgvShape, ";") {
		if v, ok := strings.CutPrefix(part, key+"="); ok {
			return v
		}
	}
	return ""
}

// identitySudo returns whether a sudo rule names this account and whether that
// is KNOWN. Every caller must handle the second value.
//
// IT DID NOT HAVE ONE, AND identityKeys' comment explains exactly why that was
// wrong: "a level rule that reads an unknown count as zero is exactly the bug
// this marker exists to stop". The sudo half had no flag and mapped `?` to
// false, and the level table read it directly — so an account arriving with
// sudo, on a box whose sudoers could not be read, graded high, or WARN if it
// took a service uid, which an attacker picks freely.
func (e baselineEntry) identitySudo() (bool, bool) {
	raw := identityField(e, "sudo")
	if raw == identityUnknown || raw == "" {
		return false, false
	}
	return raw == "true", true
}

// identitySudoOrFalse is for the two places that are comparing two entries and
// have already established both sides are known (sudoKnownBothSides). Nothing
// else may use it.
func (e baselineEntry) identitySudoOrFalse() bool {
	v, _ := e.identitySudo()
	return v
}

func sudoKnownBothSides(was, now baselineEntry) bool {
	_, wok := was.identitySudo()
	_, nok := now.identitySudo()
	return wok && nok
}

func keysKnownBothSides(was, now baselineEntry) bool {
	_, wok := was.identityKeys()
	_, nok := now.identityKeys()
	return wok && nok
}

// identityKeys returns the count and whether it is KNOWN. Every caller must
// handle the second value: a level rule that reads an unknown count as zero is
// exactly the bug this marker exists to stop.
func (e baselineEntry) identityKeys() (int, bool) {
	raw := identityField(e, "keys")
	if raw == identityUnknown {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}

// identityUnreadable is true when any fingerprinted property of this account
// could not be read on the pass that produced the entry.
func (e baselineEntry) identityUnreadable() bool {
	return identityField(e, "sudo") == identityUnknown ||
		identityField(e, "keys") == identityUnknown
}

func (e baselineEntry) identityShell() string { return identityField(e, "shell") }

func (e baselineEntry) identityKeyDigest() string { return identityField(e, "keydigest") }

// identityChangeReason names WHICH property of an account moved, most
// consequential first. An account can change in more than one way at once —
// granting sudo and adding a key is one administrative act — and the reason
// reports the one that matters most while identityChangeWords says all of them.
func identityChangeReason(was, now baselineEntry) string {
	// WHAT WAS READABLE CLASSIFIES FIRST, AND THE ORDER IS THE WHOLE POINT.
	//
	// The first version of this put the unreadable case at the top, citing the
	// process half's deltaReasonUnreadable branch — and copied the wrong half of
	// it. delta.go:693-700 checks HIGH before it checks unreadable, precisely so
	// that "this was replaced AND it now talks to a model" cannot be demoted to
	// a visibility notice by the unreadable shortcut. Putting unreadable first
	// here did exactly that, one rung worse: measured against the real code, a
	// sudo grant on an account whose keys could not be read came out
	// `notice [digest_unreadable]` while the sentence beside it said "a sudo
	// rule now names this account". The box knew, said so, and graded it as
	// nothing. `usermod -u 0` with unreadable keys did the same.
	//
	// It was also sticky and machine-wide: the `?` lives in the ACCOUNTING, so
	// one baseline taken with /home unmounted graded every later change to
	// every one of those accounts a notice until somebody retook it.
	//
	// So: a property that MOVED and was readable on both sides is the reason.
	// Unreadable is what is left when nothing readable moved — which is the
	// only case where the comparison really is about visibility.
	switch {
	case sudoKnownBothSides(was, now) && was.identitySudoOrFalse() != now.identitySudoOrFalse():
		return deltaReasonSudoers
	case keysKnownBothSides(was, now) &&
		(identityField(was, "keys") != identityField(now, "keys") ||
			was.identityKeyDigest() != now.identityKeyDigest()):
		return deltaReasonAuthKeys
	case was.identityShell() != now.identityShell():
		return deltaReasonShell
	case identityField(was, "uid") != identityField(now, "uid"):
		return deltaReasonUID
	case was.identityUnreadable() || now.identityUnreadable():
		// NOTHING READABLE MOVED and one side did not look — so the difference
		// between these two entries IS the visibility, and nothing about the
		// account may be asserted from it.
		return deltaReasonUnreadable
	}
	return deltaReasonCommand
}

// identityChangeWords is the sentence a person reads. It names every property
// that moved, never the key material — see this file's header for the rule.
func identityChangeWords(was, now baselineEntry) string {
	var parts []string
	ws, wsok := was.identitySudo()
	ns, nsok := now.identitySudo()
	switch {
	case !wsok || !nsok:
		// THE CAVEAT THE KEYS HALF ALREADY HAD AND THIS ONE DID NOT. With the
		// baseline at `?` and the pass reading true, the sentence was "a sudo
		// rule now names this account" — asserting a GRANT whose previous state
		// the box never saw.
		parts = append(parts, "this machine could not read the sudo rules on one "+
			"of the two passes, so this account's sudo rights were not compared")
	case ws != ns && ns:
		parts = append(parts, "a sudo rule now names this account")
	case ws != ns:
		parts = append(parts, "no sudo rule names this account any more")
	}
	wk, wok := was.identityKeys()
	nk, nok := now.identityKeys()
	switch {
	case !wok || !nok:
		// ONE SIDE DID NOT LOOK, so nothing may be said about the keys. The
		// sentence that used to come out here was "authorized keys 1 → 0",
		// i.e. keys were removed, about a box that never read the file.
		parts = append(parts, "this machine could not read this account's "+
			"authorized keys on one of the two passes, so they were not compared")
	case wk != nk:
		parts = append(parts, "authorized keys "+strconv.Itoa(wk)+" → "+strconv.Itoa(nk))
	case was.identityKeyDigest() != now.identityKeyDigest():
		// THE CASE A COUNT CANNOT SEE, and the reason the digest is kept at
		// all: one key swapped for another is the same number and a different
		// machine.
		parts = append(parts, "the same number of authorized keys, but not the same keys")
	}
	if was.identityShell() != now.identityShell() {
		parts = append(parts, "shell "+was.identityShell()+" → "+now.identityShell())
	}
	if u1, u2 := identityField(was, "uid"), identityField(now, "uid"); u1 != u2 {
		parts = append(parts, "uid "+u1+" → "+u2)
	}
	if len(parts) == 0 {
		return "this account's recorded state changed"
	}
	return strings.Join(parts, "; ")
}

// listenerIsExposed answers whether a listener faces anything but this machine.
// It decides high-versus-warn on listener_new, and nothing else.
//
// LOOPBACK IS THE ONLY THING TREATED AS UNEXPOSED, and unknown counts as
// exposed. A bind address this does not recognise is more interesting, not
// less — the safe direction is the one that reports.
func listenerIsExposed(e baselineEntry) bool {
	addr := listenerAddr(e)
	switch addr {
	case "127.0.0.1", "::1", "localhost":
		return false
	}
	// The whole 127/8 range, which a service is entitled to bind anywhere in.
	return !strings.HasPrefix(addr, "127.")
}
