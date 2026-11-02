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
		"param([switch]$Networked, [switch]$Shared, [switch]$Personal, [switch]$JustMe, [string]$Pair,",
		"$Pair | & $exe pair -",
		"elseif ($rc -eq 3)",
		"Start-ScheduledTask -TaskName 'PrivataeBastion'",
		"Restart-Service -Name 'PrivataeBastion'",
		// The whole machine by default, through one UAC prompt; the code
		// reaches the elevated step in a file, and the owner by SID.
		"Start-Process -FilePath 'powershell.exe' -Verb RunAs",
		"[IO.File]::WriteAllText($pf, $Pair)",
		"& $exe approvals-owner --sid $owner",
		"if (-not $elevatedDone) {",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.ps1 lacks %q", want)
		}
	}
	for _, bad := range []string{"pair $Pair", "pair -- $Pair", "-ArgumentList $Pair", "Write-Host $Pair", "$Pair\"", "'$Pair'",
		"-Pair '$Pair'", "-Pair $Pair"} {
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

// The elevation block, run by pwsh with Windows' prompt stood in
// (testdata/install_ps1_elevate.ps1). Skipped where pwsh is not installed.
func TestInstallPs1ElevatesForTheWholeMachineUnderPwsh(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not installed: install.ps1's elevation is checked only by TestInstallPs1PairShape here")
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File",
		filepath.Join("testdata", "install_ps1_elevate.ps1"), filepath.Join("..", "deploy", "install.ps1")).CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "ok:") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// A whole-machine install replaces a program the tray holds open. The tray
// runs from the service's own file in every session, Windows will not replace
// a running program, and the install stopped with "Cannot create a file when
// that file already exists." with the service it had stopped left stopped.
// The program is moved aside instead, a failure starts the service again, and
// this person's tray is started from the new program.
//
// MUTATIONS (run with testdata/install_ps1_swap.ps1 under pwsh): drop the move
// aside from Install-Program; drop Start-Service from Stop-InstallFailed; drop
// the session filter from Restart-Tray; let Unregister-ScheduledTask's failure
// escape; drop the .old/.bak exclusion from the earlier-install stop. RESULT:
// each red.
func TestInstallPs1ReplacesAProgramTheTrayHoldsOpen(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "deploy", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"Install-Program $tmp $exe",
		"Move-Item -LiteralPath $target -Destination $aside",
		`foreach ($name in @("$target.old", "$target.bak"))`,
		"$stoppedService = $true",
		`Stop-InstallFailed $stoppedService "The Windows service could not be registered`,
		"Start-Service -Name 'PrivataeBastion' -ErrorAction Stop",
		"if (Restart-Tray $installedExe)",
		// The logon task is removed with the service stopped: a failure starts it again.
		`Stop-InstallFailed $stoppedService ("The logon task from an earlier install could not be removed`,
		// The trays running from the program moved aside are not an earlier install.
		"($asideNames -notcontains $_.Path)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.ps1 lacks %q", want)
		}
	}
	if strings.Contains(s, "Move-Item -Force -Path $tmp -Destination $exe") {
		t.Error("install.ps1 moves the download over the program in place, which fails while a tray runs it")
	}
	// A per-user reinstall with no -Pair stops the copy already running (the
	// old program, moved aside) before it starts the task again, or it would
	// say "running now" over the old version.
	//
	// MUTATION: drop the Stop-Process loop from that branch. RESULT: red.
	if i := strings.Index(s, "# Started now, not only at the next sign-in"); i < 0 {
		t.Error("install.ps1 no longer starts a per-user bastion at install")
	} else if seg := s[i:]; !strings.Contains(seg[:strings.Index(seg, "Start-ScheduledTask")], "Stop-Process -Id $_.Id -Force") {
		t.Error("a per-user reinstall starts the task without stopping the copy already running the old program")
	}
	if strings.Contains(s, `throw "could not register the Windows service`) {
		t.Error("a failed service registration throws with the service it stopped left stopped")
	}
	// The aside names are ones the bastion clears at its next start.
	src, err := os.ReadFile("update.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `[]string{".old", ".new", ".bak"}`) {
		t.Error("cleanupStaleBinaries no longer clears .old and .bak, which the installer leaves beside the program")
	}
	// The tray is started from the ordinary account, after the elevated step.
	if r, e := strings.Index(s, "if (Restart-Tray $installedExe)"), strings.Index(s, "-Verb RunAs"); r < 0 || e < 0 || r < e {
		t.Error("the tray is not restarted after the elevated step")
	}
}

// Install-Program, Stop-InstallFailed and Restart-Tray, run by pwsh with
// Windows stood in (testdata/install_ps1_swap.ps1). Skipped where pwsh is not
// installed.
func TestInstallPs1SwapRunsUnderPwsh(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not installed: install.ps1's swap is checked only by TestInstallPs1ReplacesAProgramTheTrayHoldsOpen here")
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File",
		filepath.Join("testdata", "install_ps1_swap.ps1"), filepath.Join("..", "deploy", "install.ps1")).CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "ok:") {
		t.Fatalf("%v\n%s", err, out)
	}
}
