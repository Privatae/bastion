package main

import (
	"os/user"
	"runtime"
	"strings"
	"testing"
)

// What uninstalling removes, per platform and install: the thing that starts
// the bastion and the program in the installers' own places. Never the state
// (that is --delete-data's, in cmdUninstall), and never a path outside what
// the installers write.
func TestUninstallRemovesWhatTheInstallersPutInPlace(t *testing.T) {
	const home = "/home/sam"
	cases := []struct {
		goos  string
		whole bool
		want  []string
	}{
		{"linux", true, []string{"systemctl disable --now privatae-bastion", "rm " + linuxSystemUnitPath, "systemctl daemon-reload", "rm /usr/local/bin/privatae-bastion"}},
		{"linux", false, []string{"systemctl --user disable --now privatae-bastion", "rm " + home + "/.config/systemd/user/privatae-bastion.service", "rm " + home + "/.local/bin/privatae-bastion"}},
		{"darwin", true, []string{"call system-service", "rm /Library/Application Support/privatae/bin/privatae-bastion", "rm /usr/local/bin/privatae-bastion"}},
		{"darwin", false, []string{"/bin/launchctl bootout gui/501/ai.privatae.bastion.user", "rm " + home + "/Library/LaunchAgents/ai.privatae.bastion.user.plist"}},
		{"windows", true, []string{"call system-service"}},
		{"windows", false, []string{"schtasks /Delete /TN PrivataeBastion /F"}},
	}
	for _, c := range cases {
		t.Setenv("XDG_CONFIG_HOME", "")
		var got []string
		for _, st := range uninstallSteps(c.goos, c.whole, home, 501) {
			switch {
			case st.Call != "":
				got = append(got, "call "+st.Call)
			case len(st.Run) > 0:
				got = append(got, strings.Join(st.Run, " "))
			default:
				got = append(got, "rm "+st.Remove)
			}
		}
		all := strings.Join(got, "\n")
		for _, w := range c.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s whole=%v: no %q in\n%s", c.goos, c.whole, w, all)
			}
		}
		if strings.Contains(all, "privatae-bastion/") && !strings.Contains(all, "privatae/bin/privatae-bastion") {
			t.Errorf("%s whole=%v: a step reaches into the state directory:\n%s", c.goos, c.whole, all)
		}
	}
}

// On Linux a sudo without -H keeps the person's HOME, and the state uninstall
// names (and --delete-data deletes) would be theirs, not the machine's.
func TestUninstallAsRootRefusesTheCallersHome(t *testing.T) {
	for _, dir := range []string{"/home/sam/.config/privatae-bastion", ""} {
		if why := uninstallHomeRefusal("linux", true, dir, "/root"); !strings.Contains(why, "sudo -H") {
			t.Errorf("root naming %q was not refused: %q", dir, why)
		}
	}
	for _, c := range []struct {
		goos        string
		root        bool
		home, root2 string
	}{{"linux", true, "/root/.config/privatae-bastion", "/root"}, {"linux", true, "/root/.config/privatae-bastion/", "/root/"},
		{"linux", false, "/home/sam/.config/privatae-bastion", "/root"}, {"darwin", true, "/Users/sam/Library/Application Support/privatae-bastion", "/var/root"}} {
		if why := uninstallHomeRefusal(c.goos, c.root, c.home, c.root2); why != "" {
			t.Errorf("%+v refused: %q", c, why)
		}
	}
}

// What uninstall names, and --delete-data deletes, is the config folder,
// which reads XDG_CONFIG_HOME before HOME. A sudo that keeps the person's
// XDG_CONFIG_HOME (sudo -E, or env_keep) names their state even with
// HOME set to root's.
func TestUninstallAsRootRefusesTheCallersConfigFolder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("root's state is found through its HOME on Linux only")
	}
	u, err := user.LookupId("0")
	if err != nil {
		t.Skip(err)
	}
	prev := machineAuthorityHeld
	t.Cleanup(func() { machineAuthorityHeld = prev })
	machineAuthorityHeld = func() bool { return true }
	t.Setenv("HOME", u.HomeDir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if why := uninstallRootStateRefusal(); !strings.Contains(why, "sudo -H") {
		t.Errorf("root with the caller's XDG_CONFIG_HOME was not refused: %q", why)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	if why := uninstallRootStateRefusal(); why != "" {
		t.Errorf("root with its own HOME was refused: %q", why)
	}
}
