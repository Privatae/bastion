//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// installShFunc returns one shell function's text from deploy/install.sh.
func installShFunc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{\n.*?^\}\n`).Find(raw)
	if m == nil {
		t.Fatalf("install.sh defines no %s()", name)
	}
	return string(m)
}

// TestInstallShKeepsAPairedLocalMachineLocal: a root reinstall defaults to
// networked, except on a machine already paired in local mode, which keeps
// its mode (paired_local). Switched, its pairing would sit on an unanchored
// networked machine, which refuses every op until claim-anchor.
func TestInstallShKeepsAPairedLocalMachineLocal(t *testing.T) {
	fn := installShFunc(t, "paired_local")
	run := func(dirs ...string) bool {
		t.Helper()
		args := append([]string{"-c", fn + `paired_local "$@"`, "sh"}, dirs...)
		err := exec.Command("sh", args...).Run()
		if _, ok := err.(*exec.ExitError); err != nil && !ok {
			t.Fatal(err)
		}
		return err == nil
	}
	mk := func(t *testing.T, files map[string]string) string {
		t.Helper()
		d := t.TempDir()
		for name, body := range files {
			p := filepath.Join(d, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	missing := filepath.Join(t.TempDir(), "none")

	if !run(mk(t, map[string]string{"pairings/a.host.example.json": "{}"}), missing) {
		t.Fatal("a paired machine with no mode file is local and must stay local")
	}
	if !run(mk(t, map[string]string{"pairings/a.json": "{}", "mode.json": `{"mode":"local"}`})) {
		t.Fatal("a paired machine in local mode must stay local")
	}
	if !run(mk(t, map[string]string{"config.json": "{}"})) {
		t.Fatal("a pre-0.10 single pairing (config.json) is a pairing")
	}
	if !run(missing, mk(t, map[string]string{"pairings/a.json": "{}"})) {
		t.Fatal("a pairing in the second folder counts")
	}
	if run(mk(t, map[string]string{"pairings/a.json": "{}", "mode.json": "{\n  \"mode\": \"networked\"\n}"})) {
		t.Fatal("a networked machine is not kept local")
	}
	if run(mk(t, map[string]string{"pairings/.keep": ""}), missing) {
		t.Fatal("a machine with no pairing gets the networked default")
	}
}
