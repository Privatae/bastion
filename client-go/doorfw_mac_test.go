package main

import "testing"

// --listapps as macOS prints it before 15 (the state on the entry's line, or
// on the next) and from 15 (names alone, "(state: 1)" allowed, 4 blocked),
// as shown in developer.apple.com/forums/thread/757909.
func TestTheMacListOfAppsIsReadEntryByEntry(t *testing.T) {
	const before15 = "ALF: total number of apps = 4 \n\n" +
		"1 : /Applications/Google Chrome.app ( Block incoming connections )\n" +
		"2 : /usr/local/bin/privatae-bastion.old ( Allow incoming connections )\n" +
		"3 :  /usr/local/bin/privatae-bastion \n \t ( Allow incoming connections ) \n\n" +
		"4 : /opt/example/privatae-bastion ( Block incoming connections )\n"
	apps := parseMacListApps(before15)
	if len(apps) != 4 {
		t.Fatalf("entries: %+v", apps)
	}
	for _, c := range []struct {
		prog            string
		listed, allowed bool
	}{
		{"/usr/local/bin/privatae-bastion", true, true},
		{"/opt/example/privatae-bastion", true, false},
		{"/usr/local/bin/privatae", false, false},
		{"/Applications/Google Chrome.app", true, false},
		{"/usr/local/bin/privatae-bastion.old", true, true},
	} {
		if l, a := macAppState(apps, c.prog); l != c.listed || a != c.allowed {
			t.Fatalf("%s: listed %v allowed %v", c.prog, l, a)
		}
	}

	const from15 = "2024-06-24 16:21:15.599 socketfilterfw[2988:52866] ApplicationFirewall::AFGetAllApplications() processing response dictionary\n\n" +
		"Total number of apps = 3 \n\n" +
		"privatae-bastion.old (state: 1)\n" +
		"privatae-bastion (state: 4)\n" +
		"cupsd (state: 1)\n"
	apps = parseMacListApps(from15)
	if len(apps) != 3 {
		t.Fatalf("entries: %+v", apps)
	}
	if l, a := macAppState(apps, "/usr/local/bin/privatae-bastion"); !l || a {
		t.Fatalf("blocked by name: listed %v allowed %v", l, a)
	}
	if l, a := macAppState(apps, "/usr/sbin/cupsd"); !l || !a {
		t.Fatalf("allowed by name: listed %v allowed %v", l, a)
	}
	// MUTATION: the next line's state ignored. RESULT: red, /usr/local/bin/privatae-bastion not allowed.
	// MUTATION: any state counts as allowed. RESULT: red, blocked read as allowed.
}
