//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"
	"unicode/utf16"
)

// Windows: UI Automation through the UIAutomationClient .NET assembly, driven
// by a fixed PowerShell script. The script is one string, handed over as
// -EncodedCommand (UTF-16LE base64) so no quoting question arises; the pid
// and node cap arrive as environment variables it reads and casts to [int].
// It walks every top-level window owned by the pid with the control-view
// TreeWalker and prints one compact JSON document.
//
// ConvertTo-Json counts a depth level for every dictionary AND every array,
// so a node at tree depth d sits at JSON depth 2+2d; the walk's depth cap of
// 40 needs -Depth 83 — 100 is the serializer's
// maximum and is used. A control that vanishes mid-walk (a closing menu)
// throws ElementNotAvailableException; it is skipped, the rest of the tree
// still answers.

const computerTreeKind = "uiautomation-powershell"

const windowsTreeScript = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$targetPid = [int]$env:PRIVATAE_TARGET_PID
$maxNodes = [int]$env:PRIVATAE_MAX_NODES
$script:count = 0
$script:trunc = $false
$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
function Node($el, $depth) {
    if ($script:count -ge $maxNodes -or $depth -gt 40) { $script:trunc = $true; return $null }
    try { $c = $el.Current } catch { return $null }
    $script:count++
    $n = [ordered]@{ role = ($c.ControlType.ProgrammaticName -replace '^ControlType\.', '').ToLower() }
    if ($c.Name) { $n.name = $c.Name }
    if ($c.AutomationId) { $n.id = $c.AutomationId }
    $r = $c.BoundingRectangle
    if (-not [double]::IsInfinity($r.X)) { $n.x = [int]$r.X; $n.y = [int]$r.Y; $n.w = [int]$r.Width; $n.h = [int]$r.Height }
    $n.enabled = [bool]$c.IsEnabled
    if ($c.HasKeyboardFocus) { $n.focused = $true }
    if ($c.IsOffscreen) { $n.offscreen = $true }
    try {
        $vp = $null
        if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
            $v = $vp.Current.Value
            if ($v -and $v.Length -le 200) { $n.value = $v }
        }
    } catch {}
    $kids = @()
    try { $ch = $walker.GetFirstChild($el) } catch { $ch = $null }
    while ($ch -ne $null) {
        $k = Node $ch ($depth + 1)
        if ($k -ne $null) { $kids += ,$k }
        if ($script:trunc) { break }
        try { $ch = $walker.GetNextSibling($ch) } catch { $ch = $null }
    }
    if ($kids.Count -gt 0) { $n.children = $kids }
    return $n
}
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $targetPid)
$tops = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)
$wins = @()
$app = ''
foreach ($w in $tops) {
    if (-not $app) { try { $app = (Get-Process -Id $targetPid).ProcessName } catch {} }
    $t = Node $w 0
    if ($t -ne $null) { $wins += ,$t }
}
if ($tops.Count -eq 0) {
    @{ error = "no top-level window owned by pid $targetPid" } | ConvertTo-Json -Compress
} else {
    @{ app = $app; truncated = $script:trunc; windows = $wins } | ConvertTo-Json -Compress -Depth 100
}
`

// encodedCommand is the script as PowerShell's -EncodedCommand wants it:
// UTF-16LE, base64. Computed once.
var windowsTreeEncoded = func() string {
	u := utf16.Encode([]rune(windowsTreeScript))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}()

func readTree(pid, maxNodes int) ([]byte, error) {
	out, err := runFixedEnv(helperEnv(pid, maxNodes), "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", windowsTreeEncoded)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, errors.New("UI Automation walk failed: " + truncate(strings.TrimSpace(string(ee.Stderr)), 300))
		}
		return nil, errors.New("powershell failed: " + err.Error())
	}
	return out, nil
}
