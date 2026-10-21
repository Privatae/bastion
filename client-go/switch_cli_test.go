package main

import (
	"bytes"
	"strings"
	"testing"
)

// switchAuthority holds machine authority on or off for one test. Its own
// seam rather than claims_unix_test.go's, so these tests also build and run
// on Windows, where the switch exists too.
func switchAuthority(t *testing.T, held bool) {
	t.Helper()
	old := machineAuthorityHeld
	machineAuthorityHeld = func() bool { return held }
	t.Cleanup(func() { machineAuthorityHeld = old })
}

// The switch from a terminal writes nothing without machine authority, in
// either direction, whatever euid the suite runs under.
func TestSwitchNeedsMachineAuthority(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)

	switchAuthority(t, false)
	for _, word := range []string{"off", "on"} {
		err := cmdSwitch([]string{host, "ops", word})
		if err == nil || !strings.Contains(err.Error(), "machine authority") {
			t.Fatalf("switch %s without machine authority must be refused, got %v", word, err)
		}
	}
	if got := localDenyFamilies(host); len(got) != 0 {
		t.Fatalf("a refused switch must write nothing, deny list is %v", got)
	}
}

// Off lands in the same deny list the gate reads; on takes it out again.
func TestSwitchOffAndOnGoThroughTheDenyList(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	switchAuthority(t, true)

	for _, fam := range []string{"ops", "dcn", localFamilyDirectives} {
		if err := cmdSwitch([]string{host, fam, "off"}); err != nil {
			t.Fatalf("switch %s off: %v", fam, err)
		}
		if !localDenied(host, fam) {
			t.Fatalf("%s must be denied after switch off", fam)
		}
	}
	if err := cmdSwitch([]string{host, "dcn", "ON"}); err != nil {
		t.Fatalf("switch dcn on: %v", err)
	}
	if localDenied(host, "dcn") {
		t.Fatal("dcn must no longer be denied after switch on")
	}
	got := strings.Join(localDenyFamilies(host), ",")
	if got != "directives,ops" {
		t.Fatalf("deny list after off/off/off/on: %q", got)
	}
}

// A unique prefix names the host, as --host does; an unknown family, an
// unknown host and a last word other than on/off are refused and write nothing.
func TestSwitchResolvesAPrefixAndRefusesWhatItCannotMatch(t *testing.T) {
	uiTestConfigDir(t)
	givenPairing(t, "box-one.example", pairingActive)
	givenPairing(t, "box-two.example", pairingActive)
	switchAuthority(t, true)

	if err := cmdSwitch([]string{"box-t", "session", "off"}); err != nil {
		t.Fatalf("a unique prefix must resolve: %v", err)
	}
	if !localDenied("box-two.example", "session") {
		t.Fatal("the prefix must switch the host it names")
	}
	if err := cmdSwitch([]string{"box-", "session", "off"}); err == nil {
		t.Fatal("an ambiguous prefix must be refused")
	}
	for _, c := range [][]string{
		{"box-one.example", "everything", "off"},
		{"nobody.example", "ops", "off"},
		{"box-one.example", "ops", "maybe"},
		{"box-one.example", "ops"},
	} {
		if err := cmdSwitch(c); err == nil {
			t.Fatalf("%q must be refused", c)
		}
	}
	if got := localDenyFamilies("box-one.example"); len(got) != 0 {
		t.Fatalf("refused switches must write nothing, got %v", got)
	}
}

// With nothing paired in the state it read, --list names that state rather
// than saying nothing is paired with the machine: on Linux an ordinary
// account's --list reads its own state, not the root service's.
func TestSwitchListWithNoPairingNamesTheStateItRead(t *testing.T) {
	d := uiTestConfigDir(t)
	var buf bytes.Buffer
	if err := switchList(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "with this machine") || !strings.Contains(out, d) {
		t.Fatalf("--list must name the state it read (%s), got %q", d, out)
	}
}

// --list prints every family of every paired host, on or off, one per line,
// and needs no machine authority.
func TestSwitchListPrintsEveryFamily(t *testing.T) {
	uiTestConfigDir(t)
	const host = "box-one.example"
	givenPairing(t, host, pairingActive)
	if err := localDenySet(host, "ops", true); err != nil {
		t.Fatal(err)
	}
	switchAuthority(t, false)

	var buf bytes.Buffer
	if err := switchList(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(localSwitchFamilies()) {
		t.Fatalf("want one line per family (%d), got %d:\n%s", len(localSwitchFamilies()), len(lines), buf.String())
	}
	seenOff := false
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != host {
			t.Fatalf("malformed line %q", l)
		}
		switch f[1] {
		case "ops":
			if f[2] != "off" || len(f) != 5 || f[3] != "since" {
				t.Fatalf("ops must read off with its time: %q", l)
			}
			seenOff = true
		default:
			if f[2] != "on" {
				t.Fatalf("%s must read on: %q", f[1], l)
			}
		}
	}
	if !seenOff {
		t.Fatal("the switched-off family is missing from the list")
	}
	if err := cmdSwitch([]string{"--list"}); err != nil {
		t.Fatalf("--list must not need machine authority: %v", err)
	}
}
