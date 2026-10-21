//go:build windows

package main

import (
	"encoding/base64"
	"unicode/utf16"
)

// Windows scheduler inventory: Get-ScheduledTask through PowerShell, the
// same fixed -EncodedCommand shape computer_tree_windows.go uses. Not
// `schtasks /query /fo csv`: its column headers are localised, and parsing
// them would silently find nothing on a non-English Windows. The script
// emits one compact JSON object per task with the fields parseWinTasksJSON
// reads; disabled tasks are skipped (they cannot fire).

const windowsTasksScript = `
$ErrorActionPreference = 'SilentlyContinue'
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  [pscustomobject]@{
    n = $_.TaskName
    p = $_.TaskPath
    u = $_.Principal.UserId
    s = [string]$_.State
    a = @($_.Actions | ForEach-Object { ('"' + ([string]$_.Execute) + '" ' + ([string]$_.Arguments)).Trim() })
    t = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  }
} | ConvertTo-Json -Compress -Depth 4
`

// encodePowerShell renders a script as -EncodedCommand wants it: UTF-16LE, base64.
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

var windowsTasksEncoded = encodePowerShell(windowsTasksScript)

func platformSchedulers() ([]schedEntry, []string, bool) {
	out, err := runTimed("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", windowsTasksEncoded)
	if err != nil {
		return nil, []string{}, true // PowerShell present but the query failed: supported, nothing read
	}
	return parseWinTasksJSON(out), []string{"task-scheduler"}, true
}
