package main

// askquarantine.go — the machine holds an account whose asks keep being
// refused, the way quarantine.go holds a Host pairing: five refused asks
// inside ten minutes hold that account's asks for ten minutes, doubling on
// every repeat, forgiven after a clean day (the same arithmetic,
// quarantineEntry.strike). Asking is how an agent on this computer reaches
// the owner, so an agent that keeps asking for what is refused is the local
// form of a Host probing the management lane.
//
// Keyed by the asking account (the kernel's answer on ask.sock, not anything
// the asker says), and kept in the owner's factor directory beside the
// requests themselves, never on the heartbeat: which accounts on this
// computer asked for what is not a Host's business.
//
// What strikes: the owner denying an ask, and refusals that are the asker's
// own doing (not an agent this bastion sees, an ask the owner refused in the
// last day, too many waiting). What does not: the owner having no code set
// up, a store that could not be written — this machine's state, not the
// asker's.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const askQuarantineFile = "ask_quarantine.json"

var askQuarantineMu sync.Mutex

func askQuarantinePath(dir string) string { return filepath.Join(dir, askQuarantineFile) }

func askQuarantineLoad(dir string) map[string]*quarantineEntry {
	m := map[string]*quarantineEntry{}
	if raw, err := os.ReadFile(askQuarantinePath(dir)); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func askQuarantineSave(dir string, m map[string]*quarantineEntry) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(askQuarantinePath(dir), raw)
}

// askStrike counts one refused ask from account. The hold that starts on the
// last strike is audited, so the owner sees it in Activity.
func askStrike(dir, account string, now time.Time) {
	if dir == "" || account == "" {
		return
	}
	askQuarantineMu.Lock()
	defer askQuarantineMu.Unlock()
	m := askQuarantineLoad(dir)
	e := m[account]
	if e == nil {
		e = &quarantineEntry{}
		m[account] = e
	}
	held := e.strike(now)
	askQuarantinePrune(m, now)
	_ = askQuarantineSave(dir, m)
	if held {
		dcnAudit(dir, askHoldOp, 0, account, "held until "+e.Until+": "+strconv.Itoa(quarantineStrikes)+
			" refused asks within "+askWindowWords())
	}
}

const askHoldOp = "local_ask_hold"

// askQuarantinePrune drops the accounts there is nothing left to remember
// about: not held, no refusal inside the window, and no hold within the
// forgiving day (strike would reset their doubling anyway). Accounts are the
// kernel's names, and a user with subordinate ids can present thousands of
// them, so without this the file grows by one entry per id that was ever
// refused and is rewritten whole on every strike.
func askQuarantinePrune(m map[string]*quarantineEntry, now time.Time) {
	for acct, e := range m {
		if e == nil {
			delete(m, acct)
			continue
		}
		if quarantinedAt(e, now) {
			continue
		}
		recent := false
		for _, ts := range e.Refusals {
			if t, err := time.Parse(time.RFC3339, ts); err == nil && now.Sub(t) < quarantineWindow {
				recent = true
				break
			}
		}
		if recent {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.LastHold); err == nil && now.Sub(t) <= quarantineForgive {
			continue
		}
		delete(m, acct)
	}
}

// askHeldUntil: when account may ask again, or the zero time.
func askHeldUntil(dir, account string, now time.Time) time.Time {
	if dir == "" || account == "" {
		return time.Time{}
	}
	askQuarantineMu.Lock()
	defer askQuarantineMu.Unlock()
	e := askQuarantineLoad(dir)[account]
	if !quarantinedAt(e, now) {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, e.Until)
	return t
}

// askHoldRefusal is what a held account is told.
func askHoldRefusal(account string, until time.Time) string {
	return fmt.Sprintf("asks from %s are on hold until %s: %d of them were refused within %s. "+
		"The machine's owner can lift the hold", account, until.Local().Format("15:04"), quarantineStrikes,
		askWindowWords())
}

func askWindowWords() string { return strconv.Itoa(int(quarantineWindow.Minutes())) + " minutes" }

// askQuarantineClear — the owner lifts the hold, and the strikes with it.
func askQuarantineClear(dir, account string) error {
	askQuarantineMu.Lock()
	defer askQuarantineMu.Unlock()
	m := askQuarantineLoad(dir)
	if _, ok := m[account]; !ok {
		return fmt.Errorf("asks from %s are not held, and none of theirs were refused recently", account)
	}
	delete(m, account)
	if err := askQuarantineSave(dir, m); err != nil {
		return err
	}
	dcnAudit(dir, askHoldOp, 0, account, "lifted by the owner")
	return nil
}

// cmdQuarantineClearAsker is `quarantine clear --asker <account>`. The holds
// live in the owner's factor directory, so only the account that holds it —
// the administrator, on a whole-machine install — finds them.
func cmdQuarantineClearAsker(account string) error {
	if account == "" {
		return errors.New("which account? the hold names it")
	}
	dir := existingMachineFactorDir()
	if dir == "" {
		return errors.New("no holds on asks are kept for this account. On a machine the bastion is installed " +
			"for as a whole, they are the administrator's: `sudo -H privatae-bastion quarantine clear --asker " +
			account + "`")
	}
	if err := askQuarantineClear(dir, account); err != nil {
		return err
	}
	fmt.Printf("agents running as %s may ask this machine again\n", account)
	return nil
}
