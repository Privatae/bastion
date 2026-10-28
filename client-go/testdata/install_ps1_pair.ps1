# Runs install.ps1's -Pair block against a stand-in bastion, with the Windows
# cmdlets it calls stood in by functions that log their call. pwsh on Linux:
#   pwsh -NoProfile -File testdata/install_ps1_pair.ps1 ../deploy/install.ps1
# Exits 0 when every case holds, and prints the first that does not.
param([string]$Script)
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw $Script
$m = [regex]::Match($src, '(?ms)^if \(\$Pair\) \{\r?\n.*?^\}\r?\n')
if (-not $m.Success) { Write-Output 'FAIL: install.ps1 has no top-level if ($Pair) { … } block'; exit 1 }
$block = [scriptblock]::Create($m.Value)

$dir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir | Out-Null
$log = Join-Path $dir 'log'
$exe = Join-Path $dir 'privatae-bastion'
Set-Content -Path $exe -Value ("#!/bin/sh`necho ""ARGV `$*"" >> '$log'`n" +
    "if [ ""`$1"" = pair ]; then sed 's/^/STDIN /' >> '$log'; exit `$FAKE_RC; fi`necho status-ok`n")
chmod 755 $exe

function Stop-ScheduledTask { $script:calls += 'stop-task' }
function Start-ScheduledTask { $script:calls += 'start-task' }
function Restart-Service { $script:calls += 'restart-service' }
function Start-Process { $script:calls += 'start-process' }
function Stop-Process { $script:calls += 'stop-process' }
function Get-Process { @() }
function Start-Sleep { }
function Write-Host { param($Object) $script:out += "$Object`n" }

function Run-Case([string]$rc, [bool]$networked) {
    $script:calls = @(); $script:out = ''
    if (Test-Path $log) { Remove-Item $log }
    $env:FAKE_RC = $rc
    $Pair = 'skp_INVENTEDCODE'; $Networked = $networked
    $threw = $null
    try { . $block } catch { $threw = $_.Exception.Message }
    $l = if (Test-Path $log) { Get-Content -Raw $log } else { '' }
    return @{ log = $l; calls = ($script:calls -join ','); out = $script:out; threw = $threw }
}
function Fail([string]$why) { Write-Output "FAIL: $why"; exit 1 }

$r = Run-Case '0' $false
if ($r.threw) { Fail "rc 0 threw: $($r.threw)" }
if ($r.log -notmatch '(?m)^ARGV pair -$' -or $r.log -match 'ARGV .*skp_') { Fail "the code must reach 'pair -' on stdin, never argv: $($r.log)" }
if ($r.log -notmatch '(?m)^STDIN skp_INVENTEDCODE\r?$') { Fail "pair's stdin: $($r.log)" }
if ($r.calls -ne 'stop-task,start-task') { Fail "per-user: stop, then start the logon task: $($r.calls)" }
if ($r.out -notmatch 'This computer is paired\. The bastion is running, and starts again each time you sign in to Windows\.') { Fail "the ending: $($r.out)" }

$r = Run-Case '3' $false
if ($r.threw -or $r.out -notmatch 'already paired with this Host') { Fail "exit 3 is success: $($r.threw) $($r.out)" }

$r = Run-Case '1' $false
if (-not $r.threw -or $r.calls -ne '') { Fail "a failed pair must throw before starting anything: $($r.threw) $($r.calls)" }

$r = Run-Case '0' $true
if ($r.threw -or $r.calls -ne 'restart-service' -or $r.out -notmatch 'Windows service PrivataeBastion') { Fail "networked restarts the service: $($r.threw) $($r.calls)" }

Remove-Item -Recurse -Force $dir
Write-Output 'ok: install.ps1 -Pair pairs over stdin, treats exit 3 as success, stops on a failure, restarts task or service'
