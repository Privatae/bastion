package main

// Fuzz the walls a host's value meets in observe:folders, observe:journal,
// observe:cert and observe:logins. Whatever the input, a path that passes is
// absolute, clean and outside the kernel's trees; a unit that passes is in
// systemd's alphabet and shaped like no flag; a server name that passes is a
// DNS name; and the sshd parser names only addresses as sources and bounded
// names as users, whatever a remote side put in a user name.

import (
	"net/netip"
	"path"
	"strings"
	"testing"
)

func FuzzFolderPathIsAbsoluteCleanAndOffTheKernelTrees(f *testing.F) {
	for _, s := range []string{"/", "/var/lib", "/var//lib/", "/proc", "//proc/1", "/a/../proc", "/a..b",
		"rel", "/dev/shm", "/x\x00y", "/\xff", "/srv/./data", "/sys/", "/devices"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p, err := checkFolderPath(in)
		if err != nil {
			return
		}
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "..") {
			t.Fatalf("%q passed as %q", in, p)
		}
		for _, r := range p {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("%q passed with a control character", in)
			}
		}
		for _, root := range folderRefusedRoots {
			if p == root || strings.HasPrefix(p, root+"/") {
				t.Fatalf("%q passed into %s", in, root)
			}
		}
	})
}

func FuzzUnitNameIsSystemdsAlphabet(f *testing.F) {
	for _, s := range []string{"example", "getty@tty1", `dev-disk-by\x2dlabel-data.device`, "-.mount", "--unit=x",
		"worker@.service", "a@b@c", "x;id", "data.mount", ".service", "@x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		u, err := normalizeUnitName(in)
		if err != nil {
			return
		}
		if !unitNameRe.MatchString(u) || len(u) > unitNameMax || !hasUnitSuffix(u) {
			t.Fatalf("%q passed as %q", in, u)
		}
		if strings.HasPrefix(u, "-") || strings.HasPrefix(u, ".") || strings.HasPrefix(u, "@") {
			t.Fatalf("%q passed as a flag-shaped %q", in, u)
		}
		if u != in && u != in+".service" {
			t.Fatalf("%q became %q: the name is kept or given .service, nothing else", in, u)
		}
	})
}

func FuzzCertArgsAreAPortAndADNSName(f *testing.F) {
	for _, s := range [][2]string{{"443", "box-a.example"}, {"0", ""}, {"65536", "x"}, {"443", "-x"},
		{"443", "a..b"}, {"8443", "192.0.2.10"}, {" 443 ", "A.EXAMPLE"}, {"443", "a_b"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, port, name string) {
		p, n, err := parseCertArgs([]string{port, name})
		if err != nil {
			return
		}
		if p < 1 || p > 65535 || !serverNameRe.MatchString(n) || n != strings.ToLower(n) ||
			strings.HasPrefix(n, "-") || strings.HasPrefix(n, ".") || strings.Contains(n, "..") {
			t.Fatalf("(%q, %q) passed as (%d, %q)", port, name, p, n)
		}
	})
}

func FuzzSSHLoginsNameOnlyAddressesAndBoundedNames(f *testing.F) {
	f.Add(fxSSHD)
	f.Add("2026-10-29T10:00:01+00:00 h sshd[1]: Invalid user a from 1.2.3.4 port 1 from 203.0.113.5 port 2\n")
	f.Add("2026-10-29T10:00:01+00:00 h sshd[1]: Failed password for x from evil/host port 1 ssh2\n")
	f.Add("x y z: Accepted publickey for \x00 from ::1 port 9 ssh2: K\n")
	f.Fuzz(func(t *testing.T, text string) {
		tally := parseSSHLogins(text)
		var rep loginsReport
		tally.fill(&rep)
		sum := 0
		for src, n := range tally.bySource {
			sum += n
			if _, err := netip.ParseAddr(src); err != nil && !loginHostRe.MatchString(src) {
				t.Fatalf("source %q is not an address or a host name", src)
			}
		}
		if sum != rep.FailedTotal {
			t.Fatalf("sources count %d, total %d", sum, rep.FailedTotal)
		}
		users := 0
		for name, u := range tally.byUser {
			users += u.Count
			if len(name) > loginNameMax || loginName(name) != name {
				t.Fatalf("user %q is not a bounded name", name)
			}
		}
		if users != rep.FailedTotal {
			t.Fatalf("users count %d, total %d", users, rep.FailedTotal)
		}
		if len(rep.Accepted) > loginsTopN || rep.AcceptedTotal < len(rep.Accepted) {
			t.Fatalf("accepted %d of %d", len(rep.Accepted), rep.AcceptedTotal)
		}
		for _, a := range rep.Accepted {
			if _, err := netip.ParseAddr(a.Source); err != nil && !loginHostRe.MatchString(a.Source) {
				t.Fatalf("accepted source %q", a.Source)
			}
			if loginName(a.User) != a.User || loginMethod(a.Method) != a.Method {
				t.Fatalf("accepted %+v", a)
			}
		}
	})
}
