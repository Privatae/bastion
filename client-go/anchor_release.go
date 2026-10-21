package main

// anchor_release.go — `privatae-bastion release-anchor --host <name>`: let go
// of an anchor whose Host is gone.
//
// THE CASE. A Host that runs on this machine is deleted with its data and set
// up again (`npx cseries uninstall --delete-data`, then `npx cseries`). The new
// Host has a new CA and a new signing key. The bastion, anchored to the old
// one, cannot take it:
//
//   - `pair --replace` under another CA is refused (pair_tcp.go), rightly: a
//     Host keeps its CA for life;
//   - the anchor cannot be unpaired (config.go unpairHost);
//   - a new pairing waits, pending, for the old anchor to approve it (pair.go);
//   - rotating the anchor needs the old anchor's consent or 14 days of its
//     silence (anchor.go rotationPermitted), and the old one is gone.
//
// So the machine's administrator says so. This command, with machine
// authority:
//
//  0. checks that the Host is gone: --host-ca names the CA the new Host
//     brought, and it is refused when that is the CA this box pinned for the
//     host (releaseCARefusal). The same CA is the same Host, alive. Only
//     --force, taken at a terminal and never from an installer, skips this;
//  1. drops the anchor, if it is the named host (anchor.json and any rotation
//     consent left for it). A box anchored to another host is refused: naming
//     the host is the check that this is the anchor the administrator means;
//  2. unpairs that host;
//  3. sets its DCN state aside (dcn/<host> → dcn/<host>.released-<when>): the
//     signing key pinned for the old Host, the second factor enrolled for it
//     and the grants it signed. A new pairing under the same name would
//     otherwise inherit that pin, and every grant the new Host signs would be
//     refused as a key mismatch. Nothing is deleted.
//
// After it the box is unanchored, and a networked box with no anchor serves
// nothing (anchor.go), so the next steps belong in the same breath: `pair` the
// new Host, then `claim-anchor`.
//
// It adds no power. An administrator could already delete anchor.json by hand
// (anchor.go header); this does it with the checks above, and says what it did.
// Approval device keys pinned on the old anchor go with anchor.json and are
// pinned again with pin-device. Running it again finds nothing left and
// succeeds, so an installer can retry a step that stopped half-way.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// releaseConsole is a seam so the suite drives --force on any machine; nothing
// outside tests assigns it.
var releaseConsole = stdioIsConsole

// releaseCARefusal says why the Host being released is not shown to be gone,
// or "" when it is: the CA its replacement brought (newCA, from --host-ca)
// must differ from the one this box pinned for it. The same CA is the same
// Host, alive, and releasing it would drop a live anchor and set aside its key
// pin and factor for nothing. A pin this box does not hold cannot be compared,
// so that too is refused; --force, at a terminal, is the administrator saying
// they know.
func releaseCARefusal(name, pinned, newCA string) string {
	switch {
	case newCA == "":
		return "name the new Host's CA with --host-ca <pem file>: release-anchor lets go only of a Host whose CA has changed (its data was deleted)"
	case strings.TrimSpace(pinned) == "":
		return "this box pinned no Host CA for " + name + ", so a changed CA cannot be shown"
	case sameCAs(pinned, newCA):
		return "the CA given with --host-ca is the one " + name + " is paired with, so that Host is not gone"
	}
	return ""
}

func cmdReleaseAnchor(host, hostCAFile string, force bool) error {
	if err := requireMachineAuthority("release-anchor"); err != nil {
		return err
	}
	if !validHostName(host) {
		return fmt.Errorf("%q is not a host name", host)
	}
	// --force skips the CA check, so it is taken only from a person at a
	// terminal. An installer runs its commands with their output captured and
	// never passes it.
	if force && !releaseConsole() {
		return errors.New("release-anchor --force is taken only in an Administrator terminal; this one's input or output " +
			"goes to a file or a pipe — nothing was released")
	}
	newCA := ""
	if hostCAFile != "" {
		ca, err := loadHostCA(hostCAFile)
		if err != nil {
			return err
		}
		newCA = ca
	}
	if err := singletonGuardForPair(); err != nil {
		return err
	}
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	// The exact name (or its handle), never a prefix: this removes a pairing.
	cfg := pairingFor(cfgs, host)
	name := host
	if cfg != nil {
		name = cfg.HostName
	}

	// Is there anything to release, and is the Host it belongs to gone? Both
	// before anything changes.
	a := currentAnchor()
	if a != nil && a.AnchorHost != name {
		return fmt.Errorf("this box is anchored to %s, not %s — release-anchor names the anchor it releases", a.AnchorHost, name)
	}
	if !force && (a != nil || cfg != nil) {
		pinned := ""
		if cfg != nil {
			pinned = cfg.CACert
		}
		if why := releaseCARefusal(name, pinned, newCA); why != "" {
			return fmt.Errorf("%s — nothing was released. If the Host really is gone, run from an Administrator terminal: "+
				"privatae-bastion release-anchor --host %s --force", why, name)
		}
	}

	// 1. The anchor, if it is this host.
	released := false
	if a != nil {
		devices := len(deviceKeys())
		anchorMu.Lock()
		err := removeAnchorFiles()
		anchorMu.Unlock()
		if err != nil {
			return fmt.Errorf("could not release the anchor: %w", err)
		}
		released = true
		fmt.Printf("released the anchor (%s)\n", name)
		if devices > 0 {
			fmt.Printf("  %d approval device key(s) were pinned on it; pin them again after claim-anchor (privatae-bastion pin-device <key>)\n", devices)
		}
	} else if f, err := loadAnchorFile(); err == nil && f != nil && f.AnchorHost != "" && f.AnchorHost != name {
		// An anchor file that does not verify is no anchor, but one naming
		// another host is still not this command's to remove.
		return fmt.Errorf("this box's anchor file names %s, not %s — release-anchor names the anchor it releases", f.AnchorHost, name)
	}

	// 2 and 3. The pairing, and its DCN state set aside.
	if cfg == nil {
		if !released {
			fmt.Printf("nothing to release: %s is neither this box's anchor nor one of its pairings\n", name)
		}
		return nil
	}
	dcn := cfg.DCNDir
	if dcn == "" {
		if d, err := configDirPath(); err == nil {
			dcn = d + string(os.PathSeparator) + "dcn" + string(os.PathSeparator) + cfg.HostName
		}
	}
	if _, err := unpairHost(cfg.HostName); err != nil {
		return fmt.Errorf("released the anchor, but could not unpair %s: %w", cfg.HostName, err)
	}
	fmt.Printf("unpaired %s\n", cfg.HostName)
	if dcn != "" {
		aside, err := setDCNStateAside(dcn, time.Now())
		switch {
		case err != nil:
			return fmt.Errorf("unpaired %s, but could not set its DCN state aside (%s): %w — move it away by hand before pairing the new Host", cfg.HostName, dcn, err)
		case aside != "":
			fmt.Printf("  its key pin, second factor and grants are kept, set aside, in %s\n", aside)
		}
	}
	fmt.Println("  Next: pair the new Host, then `privatae-bastion claim-anchor`. Until then this box serves nothing.")
	return nil
}

// removeAnchorFiles removes anchor.json and a consent left for rotating it.
// The caller holds anchorMu.
func removeAnchorFiles() error {
	p, err := anchorPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if c, err := anchorConsentPath(); err == nil {
		_ = os.Remove(c)
	}
	return nil
}

// setDCNStateAside renames a released pairing's DCN directory out of the way of
// a new pairing under the same name. "" when there was none.
func setDCNStateAside(dir string, now time.Time) (string, error) {
	if _, err := os.Lstat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	aside := dir + ".released-" + now.UTC().Format("20060102T150405Z")
	if err := os.Rename(dir, aside); err != nil {
		return "", err
	}
	return aside, nil
}
