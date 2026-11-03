package main

// anchor_local.go — who is in charge of this machine: one authoritative Host,
// the anchor (anchor.go), and which Host that is.
//
// A machine needs one authoritative Host, and the code already has that: the
// anchor. The anchor is still the one mechanism, with its signature and
// verification model unchanged (writeAnchor signs it
// under the box key; grants verify under the anchor Host's pinned key). What
// this file decides is WHICH Host holds it, by three rules, strongest first:
//
//  1. An ORGANISATION'S POLICY, explicitly deployed to the machine, names the
//     Host in charge (anchorPolicy below). It is the only thing that overrides
//     the rule after it, and it is meant for a machine owned by someone other
//     than its local admin. Windows: the AnchorHost value under
//     HKLM\SOFTWARE\Policies\Privatae\Bastion (Group Policy, Intune). macOS:
//     the AnchorHost key of the managed preference domain ai.privatae.bastion
//     (a configuration profile). Linux: anchor_host in the root-owned
//     /etc/privatae-bastion/policy.json. Joining a domain is not a policy:
//     nothing is read from the domain itself. With a policy, claim-anchor for
//     any other Host is refused in words that say an organisation manages the
//     machine, a new pairing of another Host waits for the named one, and the
//     named one takes the anchor when it is paired with machine authority.
//  2. A HOST ON THIS MACHINE is always the one in charge, never "whichever
//     paired first". Paired with machine authority it takes the anchor, from a
//     remote anchor too; the replaced anchor becomes an ordinary pairing that
//     waits for it to admit it (as claim-anchor --rotate leaves the old one),
//     the change is recorded in the pairing audit, and the replaced anchor is
//     told on one last heartbeat (anchorReplacedNote, run.go superviseOnce).
//     A Host on this machine that already holds the anchor keeps it: a second
//     one waits, as any other pairing does, and moving the anchor between two
//     of them is claim-anchor --rotate as before.
//  3. Otherwise the first Host paired with a networked machine (cmdPair, as
//     before this file).
//
// WHAT "ON THIS MACHINE" IS (sameMachineHost). A pairing whose lanes run over
// a unix socket (transport unix): the socket is a file on this machine's own
// disk. Or a pairing whose lane port is a loopback address (transport tcp,
// lane_addr 127.0.0.0/8, ::1 or localhost): loopback never leaves this
// machine's network stack, and it is how a C-Series Host in a VM on this
// computer is reached (npx cseries forwards the VM's lane ports to loopback,
// packages/cseries/src/vm/common.js). Something else forwarded onto loopback
// is something the machine's administrator set up, and taking the anchor needs
// that administrator's authority anyway. Any other address, a LAN one
// included, is another machine. The name the Host gives itself
// (home.cseries.localhost) is not used: it is the Host's word, not the
// machine's.
//
// It adds no power. With machine authority an administrator could already
// claim the anchor on an unanchored box, delete anchor.json, or release an
// anchor (anchor_release.go). What it changes is that the right Host is put in
// charge without anyone having to know the order things were paired in.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// anchorPolicy is an organisation's deployed policy naming the Host in charge.
type anchorPolicy struct {
	Host   string // a host_name, or its handle
	Source string // where it was read, as a person would look for it
}

// readAnchorPolicy reads the policy from this platform's managed store
// (anchorpolicy_*.go). A seam: the suite sets a policy without one.
var readAnchorPolicy = readAnchorPolicyOS

// currentAnchorPolicy is the deployed policy, or nil when there is none or it
// names nothing a host name can be.
func currentAnchorPolicy() *anchorPolicy {
	p := readAnchorPolicy()
	if p == nil {
		return nil
	}
	p.Host = strings.TrimSpace(p.Host)
	if !validHostName(p.Host) {
		return nil
	}
	return p
}

// policyNames says whether the policy names host (its full name or handle).
func policyNames(p *anchorPolicy, host string) bool {
	if p == nil || host == "" {
		return false
	}
	return strings.EqualFold(p.Host, host) || strings.EqualFold(p.Host, handleOf(host)) ||
		strings.EqualFold(handleOf(p.Host), host)
}

// orgManagedRefusal is the words for a Host the policy does not name.
func orgManagedRefusal(p *anchorPolicy, who string) error {
	return fmt.Errorf("an organisation manages this machine: its policy (%s) names %s as the Host in charge of it, "+
		"so %s cannot take charge here. Whoever manages this machine for the organisation changes that policy", p.Source, p.Host, who)
}

// sameMachineHost: the pairing's Host runs on this machine (see the header).
func sameMachineHost(c *Config) bool {
	if c == nil {
		return false
	}
	if c.unixTransport() {
		return true
	}
	if !c.tcpTransport() {
		return false
	}
	return loopbackAddr(c.LaneAddr)
}

// loopbackAddr: host:port whose host is a loopback IP literal or localhost.
func loopbackAddr(hostPort string) bool {
	h, _, err := net.SplitHostPort(strings.TrimSpace(hostPort))
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// admitter is the Host a pending pairing waits for: the anchor, or on a
// machine an organisation's policy governs and nobody holds yet, the Host the
// policy names. "" when nothing on this machine admits anyone.
func admitter() string {
	if a := currentAnchor(); a != nil {
		return a.AnchorHost
	}
	if boxMode() == modeNetworked {
		if p := currentAnchorPolicy(); p != nil {
			return p.Host
		}
	}
	return ""
}

// pendingUnderPolicy: on a networked machine with no anchor yet, a policy
// that names another Host makes a new pairing wait for that one.
func pendingUnderPolicy(handle string) bool {
	if boxMode() != modeNetworked || currentAnchor() != nil {
		return false
	}
	p := currentAnchorPolicy()
	return p != nil && !policyNames(p, handle)
}

// anchorTake is what taking the anchor did, for `pair` and claim-anchor to say.
type anchorTake struct {
	Taken    bool
	Why      string   // the rule, in words
	Replaced string   // the previous anchor, if there was one
	Waiting  []string // pairings that now wait for the new anchor to admit them
}

// The rules by name, in the audit and on the replaced anchor's beat.
const (
	anchorWhyPolicy = "policy"
	anchorWhyLocal  = "same_machine"
	anchorWhyFirst  = "first_pairing"
)

func anchorWhyWords(why string, c *Config, p *anchorPolicy) string {
	switch why {
	case anchorWhyPolicy:
		return "an organisation's policy (" + p.Source + ") names it as the Host in charge of this machine"
	case anchorWhyLocal:
		return "it runs on this machine (" + c.laneWhere() + "), and a Host on the machine is always the one in charge of it"
	case anchorWhyWindow:
		return "you opened the pairing window for it here (`pair --open`), and no Host was in charge of this machine"
	}
	return "it is the first Host paired with this networked machine"
}

// anchorAfterPair puts the right Host in charge after `pair` wrote cfg (see the
// header). Only on a networked machine and with machine authority, which
// claim-anchor needs anyway. Reports what it did.
func anchorAfterPair(cfg *Config, all []*Config) (anchorTake, error) {
	if cfg == nil || boxMode() != modeNetworked || !machineAuthorityHeld() {
		return anchorTake{}, nil
	}
	prev := currentAnchor()
	if prev != nil && prev.AnchorHost == cfg.HostName {
		return anchorTake{}, nil
	}
	pol := currentAnchorPolicy()
	why := ""
	switch {
	case pol != nil:
		if !policyNames(pol, cfg.HostName) {
			return anchorTake{}, nil
		}
		why = anchorWhyPolicy
	case sameMachineHost(cfg):
		if prev != nil {
			if pc := pairingFor(all, prev.AnchorHost); pc != nil && sameMachineHost(pc) && pc.active() {
				// A Host on this machine already holds it: this one waits.
				return anchorTake{}, nil
			}
		}
		why = anchorWhyLocal
	case prev == nil && len(all) == 1:
		why = anchorWhyFirst
	default:
		return anchorTake{}, nil
	}
	t, err := takeAnchor(cfg, prev, why, pol, "")
	if err != nil {
		return anchorTake{}, fmt.Errorf("paired with %s, but putting it in charge of this machine failed: %w\n  anchor it with: %s",
			cfg.HostName, err, anchorCommandHint())
	}
	return t, nil
}

// anchorWhyWindow: the person opened a pairing window for this Host at this
// machine (`pair --open`), with machine authority, and nobody was in charge.
const anchorWhyWindow = "pair_open"

// anchorAfterWindow is anchorAfterPair for a Host paired through a window
// opened at this machine (pair_window.go). The window is the person's say-so,
// typed at this machine, for this one Host, so on a machine nobody is in
// charge of yet that Host takes the anchor, as the first Host of a networked
// machine does, whatever else is paired and in either mode. The rules above it
// still come first: an organisation's policy that names another Host leaves
// it waiting, and a Host on this machine wins (a paired one that is not
// revoked keeps the machine for itself, even before it holds the anchor).
//
// A LOCAL machine has no anchor (claim-anchor and set-mode refuse one there),
// so it is made networked first, which set-mode does with the same authority.
// On a local machine already serving another Host the person said yes to, the
// window's Host does not take it: that would leave the other one waiting.
//
// openerAuthority is whether the person who opened the window held machine
// authority; the process committing the pairing (pair --open's own door, or
// the running bastion's) must hold it too.
func anchorAfterWindow(cfg *Config, all []*Config, openerAuthority bool) (anchorTake, error) {
	took, err := anchorAfterPair(cfg, all)
	if err != nil || took.Taken {
		return took, err
	}
	if cfg == nil || !openerAuthority || !machineAuthorityHeld() || currentAnchor() != nil ||
		cfg.invalid != "" || cfg.State == pairingRevoked {
		return anchorTake{}, nil
	}
	pol := currentAnchorPolicy()
	why := anchorWhyWindow
	if pol != nil {
		if !policyNames(pol, cfg.HostName) {
			return anchorTake{}, nil
		}
		why = anchorWhyPolicy
	}
	// On a networked machine nobody is in charge of, every pairing is refused
	// every op (unanchoredNetworkedRefusal), so the others that takeAnchor
	// leaves waiting lose nothing they had; they now have a Host to admit them.
	// On a local machine the other Hosts are served, so they are not demoted.
	local := boxMode() != modeNetworked
	for _, o := range all {
		if o.HostName == cfg.HostName {
			continue
		}
		if why != anchorWhyPolicy && sameMachineHost(o) && o.invalid == "" && o.State != pairingRevoked {
			return anchorTake{}, nil
		}
		if local && o.active() {
			return anchorTake{}, nil
		}
	}
	if local {
		if err := setBoxMode(modeNetworked); err != nil {
			return anchorTake{}, fmt.Errorf("paired with %s, but making this machine one a Host is in charge of failed: %w", cfg.HostName, err)
		}
		pairingAudit("set_mode", cfg.HostName, "ok: networked, so the Host paired through the window opened here can be put in charge")
	}
	t, err := takeAnchor(cfg, nil, why, pol, "")
	if err != nil {
		return anchorTake{}, fmt.Errorf("paired with %s, but putting it in charge of this machine failed: %w\n  anchor it with: %s",
			cfg.HostName, err, anchorCommandHint())
	}
	return t, nil
}

// anchorReplaced is <configDir>/anchor.replaced.json: the last time a Host
// took the anchor from another. The replaced anchor's run reads it on its
// last beat (anchorReplacedNote); the audit keeps the history.
type anchorReplaced struct {
	Host string `json:"host"` // the anchor that was replaced
	By   string `json:"by"`
	At   string `json:"at"`
	Why  string `json:"why"`
}

func anchorReplacedPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "anchor.replaced.json"), nil
}

// anchorReplacedNote is what the replaced anchor's heartbeat carries, or nil
// when self was not replaced as this machine's anchor.
func anchorReplacedNote(self string) map[string]any {
	p, err := anchorReplacedPath()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var r anchorReplaced
	if json.Unmarshal(raw, &r) != nil || r.Host == "" || r.Host != self {
		return nil
	}
	a := currentAnchor()
	if a == nil || a.AnchorHost != r.By {
		return nil
	}
	return map[string]any{"by": r.By, "at": r.At, "why": r.Why, "waiting_for": r.By}
}

// clearAnchorReplacedFor removes the replaced-anchor record once that Host is
// admitted again.
func clearAnchorReplacedFor(host string) {
	p, err := anchorReplacedPath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var r anchorReplaced
	if json.Unmarshal(raw, &r) == nil && r.Host == host {
		_ = os.Remove(p)
	}
}

// takeAnchor makes cfg this machine's anchor, under the box key as
// claim-anchor does (writeAnchor), and every other pairing that was served an
// ordinary one waiting for it. A previous anchor is recorded as replaced.
// owner "" keeps the machine's owner name.
func takeAnchor(cfg *Config, prev *anchorClaim, why string, pol *anchorPolicy, owner string) (anchorTake, error) {
	if cfg.invalid != "" {
		return anchorTake{}, fmt.Errorf("%s cannot hold the anchor: %s", cfg.HostName, cfg.invalid)
	}
	if cfg.State == pairingRevoked {
		return anchorTake{}, fmt.Errorf("%s is REVOKED on this box — it will not be put in charge; pair that Host again first (`privatae-bastion pair --replace <token>`)", cfg.HostName)
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		if oc := currentOwnerClaim(); oc != nil && oc.Owner != "" {
			owner = oc.Owner
		} else if prev != nil {
			owner = prev.Owner
		} else {
			owner = handleOf(cfg.HostName)
		}
	}
	if err := claimNameOK(owner); err != nil {
		return anchorTake{}, fmt.Errorf("owner: %w", err)
	}
	// The anchor never waits on itself.
	if !cfg.active() {
		if err := cfg.updateOnDisk(func(d *Config) { d.State = pairingActive }); err != nil {
			return anchorTake{}, err
		}
	}
	if err := writeAnchor(owner, cfg.HostName); err != nil {
		return anchorTake{}, err
	}
	if _, err := writeOwnerClaim(owner); err != nil {
		return anchorTake{}, err
	}
	// A consent the old anchor left for a rotation is not this.
	if p, err := anchorConsentPath(); err == nil {
		_ = os.Remove(p)
	}
	t := anchorTake{Taken: true, Why: anchorWhyWords(why, cfg, pol)}
	if prev != nil && prev.AnchorHost != cfg.HostName {
		t.Replaced = prev.AnchorHost
	}
	// Every other pairing that was served now waits for the new anchor: a
	// grant from the old one does not verify under the new one's key, so
	// "active" would be lanes that refuse every op.
	cfgs, err := loadPairings()
	if err != nil {
		return t, err
	}
	for _, c := range cfgs {
		if c.HostName == cfg.HostName || !c.active() {
			continue
		}
		if err := c.updateOnDisk(func(d *Config) { d.State = pairingPending }); err != nil {
			return t, err
		}
		t.Waiting = append(t.Waiting, c.HostName)
	}
	at := time.Now().UTC().Format(time.RFC3339)
	if t.Replaced != "" {
		if p, err := anchorReplacedPath(); err == nil {
			if b, err := json.MarshalIndent(anchorReplaced{Host: t.Replaced, By: cfg.HostName, At: at, Why: why}, "", "  "); err == nil {
				_ = atomicWrite(p, b)
			}
		}
	}
	decision := "ok: in charge of this machine because " + t.Why
	if t.Replaced != "" {
		decision += "; it replaced " + t.Replaced
	}
	pairingAudit("anchor_take", cfg.HostName, decision)
	for _, h := range t.Waiting {
		pairingAudit("anchor_take", h, "waits for "+cfg.HostName+" to admit it")
	}
	_ = maybeWriteMarker()
	kickBeats()
	return t, nil
}

// claimAnchorByRule is claim-anchor's part of the rules in the header, before
// its own paths run. handled: the command's answer is err. Not handled: the
// rest of claim-anchor decides, as before.
func claimAnchorByRule(cfgs []*Config, prev *anchorClaim, token string, rotate bool, owner, host string) (bool, error) {
	named := strings.TrimSpace(host)
	if token != "" {
		h, _, err := decodeToken(token)
		if err != nil {
			return true, err
		}
		named = h
	}
	if pol := currentAnchorPolicy(); pol != nil {
		want := pairingFor(cfgs, pol.Host)
		if want == nil {
			for _, c := range cfgs {
				if policyNames(pol, c.HostName) {
					want = c
					break
				}
			}
		}
		if named != "" && !policyNames(pol, named) {
			if c, err := pickPairing(cfgs, named); err != nil || want == nil || c.HostName != want.HostName {
				return true, orgManagedRefusal(pol, named)
			}
		}
		if token != "" {
			return false, nil // the token names the Host the policy names
		}
		if want == nil {
			return true, fmt.Errorf("an organisation manages this machine: its policy (%s) names %s as the Host in charge "+
				"of it, and %s is not paired with this machine yet. Pair it (`privatae-bastion pair <its code>`) and it takes charge",
				pol.Source, pol.Host, pol.Host)
		}
		if prev != nil && prev.AnchorHost == want.HostName && want.active() {
			fmt.Printf("already anchored to %s (owner %q)\n", prev.AnchorHost, prev.Owner)
			return true, nil
		}
		t, err := takeAnchor(want, prev, anchorWhyPolicy, pol, owner)
		if err != nil {
			return true, err
		}
		printAnchorTake(want.HostName, t)
		return true, nil
	}
	if rotate {
		return false, nil
	}
	var locals []*Config
	for _, c := range cfgs {
		if sameMachineHost(c) && c.invalid == "" && c.State != pairingRevoked {
			locals = append(locals, c)
		}
	}
	if len(locals) == 0 {
		return false, nil
	}
	var want *Config
	switch {
	case token != "":
		if pairingFor(locals, named) == nil {
			return true, fmt.Errorf("%s runs on this machine and is the Host in charge of it, so %s does not take the "+
				"anchor here; %s admits it instead (it asks you to approve it)", locals[0].HostName, named, locals[0].HostName)
		}
		return false, nil
	case named != "":
		c, err := pickPairing(cfgs, named)
		if err != nil {
			return true, err
		}
		if !sameMachineHost(c) {
			return true, fmt.Errorf("%s runs on this machine and is the Host in charge of it, so %s does not take the "+
				"anchor here; %s admits it instead (it asks you to approve it)", locals[0].HostName, c.HostName, locals[0].HostName)
		}
		want = c
	case len(locals) == 1:
		want = locals[0]
	default:
		return false, nil // several Hosts on this machine: --host says which
	}
	if prev != nil && prev.AnchorHost == want.HostName && want.active() {
		fmt.Printf("already anchored to %s (owner %q)\n", prev.AnchorHost, prev.Owner)
		return true, nil
	}
	if prev != nil {
		if pc := pairingFor(cfgs, prev.AnchorHost); pc != nil && sameMachineHost(pc) && pc.active() {
			return false, nil // moving it between two Hosts on this machine is --rotate, as before
		}
	}
	t, err := takeAnchor(want, prev, anchorWhyLocal, nil, owner)
	if err != nil {
		return true, err
	}
	printAnchorTake(want.HostName, t)
	return true, nil
}

// printAnchorTake is claim-anchor's report of takeAnchor.
func printAnchorTake(host string, t anchorTake) {
	fmt.Printf("anchored to %s: %s.\n", host, t.Why)
	if t.Replaced != "" {
		fmt.Printf("  %s was in charge before; it is told so, and now waits for %s to admit it.\n", t.Replaced, host)
	}
	if len(t.Waiting) > 0 {
		fmt.Printf("  Waiting for %s to admit them: %s. %s asks you to approve each.\n", host, strings.Join(t.Waiting, ", "), host)
	}
	fmt.Println("  Every Host paired from now on waits until " + host + " admits it.")
	fmt.Println("  " + anchorFollowNote())
}
