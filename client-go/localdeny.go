package main

// localdeny.go — the switch that turns a granted capability OFF, on this
// machine, by the person sitting at it.
//
// The bastion console can turn a granted capability off: that is local
// control, and it is needed.
//
// THE INVARIANT, AND IT IS NOT A PHASE: this can only ever REMOVE reach. There
// is no code path here that lets a host do something its signed grant does not
// already allow, and the test that holds that line drives every op in the
// vocabulary against every combination rather than asserting it in prose.
//
// Turning something back ON does not grant it — it clears a local denial, and
// the host's signed grant remains the ceiling it was before. That distinction is
// the whole safety argument: a switch that could widen would make the machine a
// place to escalate FROM, which inverts the product. So the state stored here is
// a DENY LIST, never an allow list. An empty file means "nothing switched off",
// which is exactly the behaviour that existed before this file, and an
// unreadable file means the same — see localDenyLoad.
//
// WHY THE MACHINE MAY DO THIS AT ALL. It already decides what it actually
// executes: every op passes capsAllow (anchor.go) on the way in, and the box
// refuses whatever it will not carry out. This adds no power to the machine. It
// makes an existing refusal reachable by the person whose computer it is,
// instead of only by the host that holds the grant.
//
// THE HOST IS TOLD, and told WHY. A refusal here travels the same way every
// other refused directive does (directive_refusal.go), so the host sees
// "refused, switched off here" rather than a silent failure it will retry for
// ever. A local control the far end cannot see is a control that reads, to the
// far end, as a fault.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// localDenyFile is the on-disk shape: host -> the families switched off for it.
type localDenyFile struct {
	// Off maps a pairing's host name to the capability families the person at
	// this machine has switched off for that host.
	Off map[string][]string `json:"off"`
	// At records when each was switched, so the page can say how long something
	// has been off rather than only that it is.
	At map[string]string `json:"at,omitempty"`
}

var localDenyMu sync.Mutex

func localDenyPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "local-deny.json"), nil
}

// localDenyLoad reads the deny list.
//
// EVERY FAILURE RETURNS AN EMPTY LIST, and that direction is deliberate. A
// deny list that cannot be read must not become a deny-everything: the machine
// would stop serving its host because of a corrupt file, which is a far worse
// outcome than a switch not taking effect. The page reports the read error
// separately so the person is not left believing something is off when it is
// not.
func localDenyLoad() (*localDenyFile, error) {
	p, err := localDenyPath()
	if err != nil {
		return &localDenyFile{Off: map[string][]string{}}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &localDenyFile{Off: map[string][]string{}}, nil
		}
		return &localDenyFile{Off: map[string][]string{}}, err
	}
	var f localDenyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return &localDenyFile{Off: map[string][]string{}}, fmt.Errorf(
			"this machine's list of switched-off capabilities cannot be read (%w). "+
				"Nothing is being blocked by it while that is true", err)
	}
	if f.Off == nil {
		f.Off = map[string][]string{}
	}
	return &f, nil
}

// localDenySave replaces the list whole, through atomicWrite (ctx.go): temp
// file, fsync, rename. Two processes use this file, the daemon (the console
// page, and the gate reading it on every op) and `switch` from a terminal
// (switch_cli.go), and localDenyMu covers only one of them. A write that
// truncated in place let the daemon read an empty file mid-write, and
// localDenyLoad fails OPEN on a file it cannot parse, so a family switched off
// was let through. A rename shows a reader the old list or the new one.
func localDenySave(f *localDenyFile) error {
	p, err := localDenyPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// withLocalDenyLock runs a read-modify-write of the list holding localDenyMu
// and an exclusive lock on <configDir>/local-deny.lock, so a switch from the
// console page and one from `switch` in another process cannot each read the
// same list and have the second write drop the first one's change. The same
// shape as withPairingsLock (config.go).
func withLocalDenyLock(fn func() error) error {
	localDenyMu.Lock()
	defer localDenyMu.Unlock()
	d, err := configDir()
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(d, "local-deny.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close() // closing releases the lock on every platform
	if err := flockFile(lf); err != nil {
		return err
	}
	return fn()
}

// localSwitchFamilies is what the person can switch off: every caps family,
// plus the box-wide directives (writes.go localFamilyDirectives) — contain,
// self-update and mirror placement are not in any grant's caps, and before this
// the anchor host's directives were the one lane the person at the machine had
// no switch for.
func localSwitchFamilies() []string {
	return append(append([]string(nil), allCaps...), localFamilyDirectives)
}

// localDenied reports whether a family is switched off for a host here.
func localDenied(host, family string) bool {
	if host == "" || family == "" {
		return false
	}
	localDenyMu.Lock()
	defer localDenyMu.Unlock()
	f, _ := localDenyLoad()
	for _, c := range f.Off[host] {
		if c == family {
			return true
		}
	}
	return false
}

// localDenyFamilies is what is switched off for one host, sorted.
func localDenyFamilies(host string) []string {
	localDenyMu.Lock()
	defer localDenyMu.Unlock()
	f, _ := localDenyLoad()
	out := append([]string(nil), f.Off[host]...)
	sort.Strings(out)
	return out
}

// localDenySet switches a family off, or back on.
//
// `family` MUST be one of allCaps. An unknown family is refused rather than
// stored: a deny list holding a string nothing will ever match is a switch that
// silently does nothing, and the person would have no way to tell.
func localDenySet(host, family string, off bool) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("no host named")
	}
	known := false
	for _, c := range localSwitchFamilies() {
		if c == family {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("%q is not a capability this machine knows about (%s)",
			family, strings.Join(localSwitchFamilies(), ", "))
	}
	// AND THE HOST HAS TO BE ONE THIS MACHINE HAS HEARD OF. Deny-only means a
	// bogus host name is harmless to the gate — nothing matches it — but the
	// page would answer "X can no longer read your files" about a host that was
	// never paired here, which is a sentence that lies by typo. An
	// unreadable pairing store is NOT a reason to refuse: the switch
	// still only removes reach, and refusing would make a corrupt file block a
	// person from tightening their own machine.
	if ps, err := loadPairings(); err == nil {
		seen := false
		for _, p := range ps {
			if p.HostName == host {
				seen = true
				break
			}
		}
		if !seen {
			return fmt.Errorf("no host called %q is paired with this machine, so there is "+
				"nothing of its to switch off", host)
		}
	}

	return withLocalDenyLock(func() error {
		f, err := localDenyLoad()
		if err != nil {
			// Refuse rather than overwrite: writing a fresh file over one that did
			// not parse would silently discard whatever the person had already
			// switched off.
			return err
		}
		if f.At == nil {
			f.At = map[string]string{}
		}
		cur := f.Off[host]
		out := cur[:0:0]
		for _, c := range cur {
			if c != family {
				out = append(out, c)
			}
		}
		key := host + "/" + family
		if off {
			out = append(out, family)
			f.At[key] = time.Now().UTC().Format(time.RFC3339)
		} else {
			delete(f.At, key)
		}
		sort.Strings(out)
		if len(out) == 0 {
			delete(f.Off, host)
		} else {
			f.Off[host] = out
		}
		return localDenySave(f)
	})
}

// localDenyRefusal is the sentence a host gets back, and the one the person at
// the machine reads. One string so the two can never disagree about why.
func localDenyRefusal(family string) string {
	return "refused: '" + family + "' is switched off on this machine by the person at it. " +
		"The grant is untouched — turning it back on is done here, not from the host."
}

// localDenyIndex is every switched-off (host, family) plus WHY the list could
// not be read, when it could not.
//
// It exists because the per-family localDenied() swallows that error by design
// — it has to, since a gate must not fail closed on a corrupt file — and the
// PAGE has the opposite obligation: it must say so, or it shows a person their
// switches as not existing rather than as not working.
func localDenyIndex() (map[string]bool, string) {
	localDenyMu.Lock()
	defer localDenyMu.Unlock()
	f, err := localDenyLoad()
	out := map[string]bool{}
	for host, fams := range f.Off {
		for _, fam := range fams {
			out[host+"/"+fam] = true
		}
	}
	if err != nil {
		return out, "This machine's list of switched-off capabilities cannot be read (" +
			err.Error() + "). NOTHING below is being blocked by it while that is true — " +
			"anything you switched off is not in effect."
	}
	return out, ""
}
