package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// install.ps1 has no Windows runner here, so its -Pair shape is read from the
// file: the code is checked before anything is downloaded, reaches `pair -`
// on standard input and never an argument, exit 3 is success, and the
// install with no flag still ends the way it did.
func TestInstallPs1PairShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"param([switch]$Networked, [string]$Pair)",
		"$Pair | & $exe pair -",
		"elseif ($rc -eq 3)",
		"Start-ScheduledTask -TaskName 'PrivataeBastion'",
		"Restart-Service -Name 'PrivataeBastion'",
		`Write-Host "Open a NEW terminal, then:  privatae-bastion pair <token>"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.ps1 lacks %q", want)
		}
	}
	for _, bad := range []string{"pair $Pair", "pair -- $Pair", "-ArgumentList $Pair", "Write-Host $Pair", "$Pair\"", "'$Pair'"} {
		if strings.Contains(s, bad) {
			t.Errorf("install.ps1 must never put the code in an argument or the output: %q", bad)
		}
	}
	check, fetch := strings.Index(s, "StartsWith('skp_')"), strings.Index(s, `Write-Host "Fetching manifest..."`)
	if check < 0 || fetch < 0 || check > fetch {
		t.Error("the pairing code must be checked before the manifest is fetched")
	}
}

// The -Pair block itself, run by pwsh against a stand-in bastion
// (testdata/install_ps1_pair.ps1). Skipped where pwsh is not installed.
func TestInstallPs1PairBlockRunsUnderPwsh(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not installed: install.ps1's -Pair block is checked only by TestInstallPs1PairShape here")
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File",
		filepath.Join("testdata", "install_ps1_pair.ps1"), filepath.Join("..", "deploy", "install.ps1")).CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "ok:") {
		t.Fatalf("%v\n%s", err, out)
	}
}
