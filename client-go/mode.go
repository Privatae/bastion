package main

// Box mode — local or networked. One binary, two shapes.
//
// The bastion that existed before this file is the LOCAL bastion: one person,
// one host, and on a home machine it runs as that person, not root. The
// NETWORKED bastion is the same binary on a machine several people share: it
// runs as root (the ops it will grow need root), it serves many hosts, and
// every host after the first is held pending until the anchor host approves
// it (anchor.go).
//
// Why a mode at all, instead of inferring the shape from the pairing count:
// the two differ in what `pair` is ALLOWED to do. A local box refuses a second
// pairing outright — that is the whole protection for a single-user machine,
// where a second host appearing means someone else got a token onto your
// box. A networked box accepts it and parks it pending. The box has to know
// which rule it is enforcing before the second token arrives, so the choice
// is made at install and written down, never guessed.
//
// The systemd unit the installer writes (deploy/install.sh) has no User= and
// HOME=/root, so every install made through it already runs as root. Existing
// installs default to LOCAL here regardless, because a mode that silently
// widened what `pair` accepts on every machine already installed would be the
// takeover hole this work exists to close. Root + local is fine;
// non-root + networked is refused (set-mode needs root).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	modeLocal     = "local"
	modeNetworked = "networked"
)

// modePath is <configDir>/mode.json — beside owner.json and anchor.json, NOT
// inside pairings/: the mode belongs to the box, not to any host it serves.
func modePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "mode.json"), nil
}

type modeFile struct {
	Mode string `json:"mode"`
}

// boxMode returns the box's mode. Absent, unreadable or unrecognised all read
// as LOCAL: the narrower rule is the safe default, and it is exactly what
// every install that predates the mode file was doing.
func boxMode() string {
	p, err := modePath()
	if err != nil {
		return modeLocal
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return modeLocal
	}
	var f modeFile
	if json.Unmarshal(raw, &f) != nil {
		return modeLocal
	}
	if f.Mode == modeNetworked {
		return modeNetworked
	}
	return modeLocal
}

// setBoxMode writes the mode. Networked needs root because the networked shape
// is root-owned by definition — a non-root user flipping a shared
// machine to "accepts more pairings" is the thing the mode prevents.
func setBoxMode(mode string) error {
	mode = strings.TrimSpace(mode)
	if mode != modeLocal && mode != modeNetworked {
		return fmt.Errorf("mode must be %q or %q", modeLocal, modeNetworked)
	}
	if mode == modeNetworked {
		if err := requireMachineAuthority("set-mode networked"); err != nil {
			return err
		}
	}
	if mode == modeLocal {
		// Going back to local must not strand hosts: a local box serves a second
		// host only on a yes typed at this machine (pair_terminal.go), and these
		// were paired under the networked rules, so with several pairings the box
		// would serve hosts nobody here said yes to.
		cfgs, err := loadPairings()
		if err == nil && len(cfgs) > 1 {
			return fmt.Errorf("cannot switch to local mode: %d hosts are paired, and a local bastion adds a second host only on a yes typed at this machine — remove the others first, then pair them again here", len(cfgs))
		}
		if currentAnchor() != nil {
			return errors.New("cannot switch to local mode: this box is anchored (anchor.json) — anchoring is a networked-mode concept")
		}
	}
	p, err := modePath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(modeFile{Mode: mode}, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(p, b); err != nil {
		return err
	}
	// The marker carries the mode, so it moves with it (singleton.go). Also the
	// point at which a networked box first claims the machine: `set-mode
	// networked` is root by definition, and install.sh runs it before anything is
	// paired.
	_ = maybeWriteMarker()
	return nil
}

// cmdSetMode is `privatae-bastion set-mode <local|networked>`; install.sh
// --networked calls it as root at install time.
func cmdSetMode(mode string) error {
	if err := setBoxMode(mode); err != nil {
		return err
	}
	fmt.Printf("mode set to %s\n", mode)
	if mode == modeNetworked {
		// Platform-correct, for the same reason the refusal text is: telling a
		// Windows user to run `sudo` is how a real instruction becomes noise.
		fmt.Printf("  Next: anchor this machine to your host —  %s\n", anchorCommandHint())
		fmt.Println("  Every host paired after the anchor waits, pending, until the anchor host approves it.")
	}
	return nil
}
