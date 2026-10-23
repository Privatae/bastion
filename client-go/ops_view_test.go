//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpViewDecideKeepsTheBaseAndWhatIsDeclaredAndCoversTheRest(t *testing.T) {
	m := &opManifest{Effects: opEffects{Files: []string{"/srv/app/"}}, Reads: []string{"/etc/nginx/*.conf"}}
	segs := opViewSegments(opViewVisible(opViewDeclared(m)))
	for p, want := range map[string]opViewAction{
		"/usr/bin/python3":         opViewKeep,
		"/usr":                     opViewDescend, // /usr/local/sbin and friends are covered
		"/usr/local/sbin":          opViewHide,
		"/etc":                     opViewDescend,
		"/etc/passwd":              opViewKeep,
		"/etc/shadow":              opViewHide,
		"/etc/ssl":                 opViewDescend,
		"/etc/ssl/certs/ca.pem":    opViewKeep,
		"/etc/ssl/private":         opViewHide,
		"/etc/nginx":               opViewDescend,
		"/etc/nginx/site.conf":     opViewKeep,
		"/etc/nginx/site.key":      opViewHide,
		"/srv":                     opViewDescend,
		"/srv/app":                 opViewKeep,
		"/srv/app/deep/file":       opViewKeep,
		"/srv/other":               opViewHide,
		"/root":                    opViewHide,
		"/home":                    opViewHide,
		"/var":                     opViewDescend, // for /var/tmp
		"/var/tmp":                 opViewKeep,
		"/var/lib":                 opViewHide,
		"/opt":                     opViewDescend, // for the op's own directory
		"/opt/bastion-op/run":      opViewKeep,
		"/opt/acme":                opViewHide,
		"/proc/1/environ":          opViewKeep, // a fresh proc of the op's own pid namespace
		"/boot":                    opViewHide,
		"/etc/systemd/system/x.sh": opViewHide,
	} {
		if got := opViewDecide(p, segs); got != want {
			t.Errorf("%s: got %d, want %d", p, got, want)
		}
	}
}

func TestOpSensitivePathsAreRefusedAtUnderOrAboveAndThroughLinks(t *testing.T) {
	setupBox(t)
	for _, p := range []string{
		"/etc/shadow", "/etc/", "/etc/*", "/etc/ssh/sshd_config", "/etc/systemd/system/app.service",
		"/root/.git-credentials", "/home/alice/.ssh/authorized_keys", "/home/*/.docker/config.json",
		"/etc/wireguard/wg0.conf", "/var/lib/rancher/k3s/agent/client.key", "/etc/privatae/config.json",
		"/var/lib/", "/home/",
	} {
		sens, err := opSensitiveMatch(p)
		if err != nil {
			t.Fatal(err)
		}
		if sens == "" {
			t.Errorf("%s must reach a sensitive path", p)
		}
		// Refused either as sensitive or, above the record (/etc/, /var/lib/),
		// by the record's own rule first — refused either way.
		if err := effectOK(p); err == nil {
			t.Errorf("%s: effectOK must refuse it", p)
		}
	}
	for _, p := range []string{"/etc/nginx/", "/etc/*.conf", "/srv/app/", "/opt/acme/app/main.py", "/home/alice/site/"} {
		sens, err := opSensitiveMatch(p)
		if err != nil {
			t.Fatal(err)
		}
		if sens != "" {
			t.Errorf("%s reaches no credential store, got %s", p, sens)
		}
	}
	// A plain path that is a link onto a store the person named is refused as
	// what it resolves to.
	store := t.TempDir()
	cfg, _ := configDirPath()
	_ = os.MkdirAll(cfg, 0o700)
	if err := os.WriteFile(filepath.Join(cfg, opSensitiveFileName), []byte("# ours\n"+store+"  # the vault\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "innocent")
	if err := os.Symlink(store, link); err != nil {
		t.Fatal(err)
	}
	if sens, _ := opSensitiveMatch(link + "/token"); sens == "" {
		t.Fatal("a link onto a sensitive path is refused as what it names")
	}
	// A line that is not an absolute path refuses every op rather than drop
	// the store the person meant to name.
	_ = os.WriteFile(filepath.Join(cfg, opSensitiveFileName), []byte("relative/path\n"), 0o600)
	if _, err := opSensitiveMatch("/srv/app/"); err == nil {
		t.Fatal("a malformed sensitive_paths refuses every op")
	}
}

func TestOpManifestReadsAreJudgedLikeEffects(t *testing.T) {
	setupBox(t)
	base := strings.Replace(opTestManifest, "modes:", "reads: [%s]\nmodes:", 1)
	for read, ok := range map[string]bool{
		`"/etc/nginx/site.conf"`: true,
		`"/etc/shadow"`:          false,
		`"relative"`:             false,
		`"/proc/1/environ"`:      false,
		`"/"`:                    false,
	} {
		_, err := parseOpManifest([]byte(strings.Replace(strings.Replace(base, "%s/", "/srv/optest/x/", 1), "%s", read, 1)))
		if (err == nil) != ok {
			t.Errorf("reads %s: ok=%v err=%v", read, ok, err)
		}
	}
}
