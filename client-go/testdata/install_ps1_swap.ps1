# Runs install.ps1's Install-Program, Stop-InstallFailed and Restart-Tray with
# Windows' services and processes stood in. pwsh on Linux:
#   pwsh -NoProfile -File testdata/install_ps1_swap.ps1 ../deploy/install.ps1
# Exits 0 when every case holds, and prints the first that does not.
param([string]$Script)
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw $Script
foreach ($name in 'Install-Program', 'Stop-InstallFailed', 'Restart-Tray') {
    $m = [regex]::Match($src, "(?ms)^function $name\(.*?^\}\r?\n")
    if (-not $m.Success) { Write-Output "FAIL: install.ps1 has no $name"; exit 1 }
    . ([scriptblock]::Create($m.Value))
}
function Fail([string]$why) { Write-Output "FAIL: $why"; exit 1 }

$dir = Join-Path ([IO.Path]::GetTempPath()) ("install-swap-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir | Out-Null
$exe = Join-Path $dir 'privatae-bastion.exe'
$new = Join-Path $dir 'download.exe'

# The program in place moves aside to .old and the new one takes its name.
Set-Content -LiteralPath $exe -Value 'old'
Set-Content -LiteralPath "$exe.old" -Value 'older'
Set-Content -LiteralPath $new -Value 'new'
Install-Program $new $exe
if ((Get-Content -LiteralPath $exe) -ne 'new') { Fail 'the new program is not in place' }
if ((Get-Content -LiteralPath "$exe.old") -ne 'old') { Fail 'the earlier program was not moved aside to .old' }
if (Test-Path -LiteralPath $new) { Fail 'the download was left behind' }

# A new file that cannot be moved in puts the earlier program back.
$threw = $false
try { Install-Program (Join-Path $dir 'missing.exe') $exe } catch { $threw = $true }
if (-not $threw) { Fail 'a failed move did not fail the install' }
if ((Get-Content -LiteralPath $exe) -ne 'new') { Fail 'a failed move left no program in place' }

# A first install has nothing to move aside.
$fresh = Join-Path $dir 'fresh.exe'
Set-Content -LiteralPath $new -Value 'new'
Install-Program $new $fresh
if ((Get-Content -LiteralPath $fresh) -ne 'new' -or (Test-Path -LiteralPath "$fresh.old")) { Fail 'a first install' }

# A stopped service is started again before the failure is reported.
$script:started = 0
function Start-Service { param($Name, $ErrorAction) $script:started++ }
try { Stop-InstallFailed $true 'It failed.' } catch { $msg = $_.Exception.Message }
if ($script:started -ne 1 -or $msg -notmatch 'It failed\. The bastion''s service is running again\.') { Fail "restart after a failure: $script:started, $msg" }
function Start-Service { param($Name, $ErrorAction) throw 'access denied' }
try { Stop-InstallFailed $true 'It failed.' } catch { $msg = $_.Exception.Message }
if ($msg -notmatch 'could not be started again \(access denied\)' -or $msg -notmatch 'Start-Service PrivataeBastion') { Fail "a restart that fails: $msg" }
$script:started = 0
function Start-Service { param($Name, $ErrorAction) $script:started++ }
try { Stop-InstallFailed $false 'It failed.' } catch { $msg = $_.Exception.Message }
if ($script:started -ne 0 -or $msg -ne 'It failed.') { Fail "a service this install did not stop was started: $msg" }

# Only this session's trays from the installed program are stopped, and the
# tray is started from the new one.
$me = (Get-Process -Id $PID).SessionId
$script:stopped = @(); $script:launched = $null
function Get-CimInstance { param($ClassName, $Filter, $ErrorAction)
    @([pscustomobject]@{ ProcessId = 11; SessionId = $me; ExecutablePath = "$exe.old"; CommandLine = "`"$exe`" tray" },
      [pscustomobject]@{ ProcessId = 12; SessionId = $me + 1; ExecutablePath = $exe; CommandLine = "`"$exe`" tray" },
      [pscustomobject]@{ ProcessId = 13; SessionId = $me; ExecutablePath = $exe; CommandLine = "`"$exe`" run" },
      [pscustomobject]@{ ProcessId = 14; SessionId = $me; ExecutablePath = 'C:\elsewhere\privatae-bastion.exe'; CommandLine = 'x tray' }) }
function Stop-Process { param($Id, [switch]$Force, $ErrorAction) $script:stopped += $Id }
function Wait-Process { param($Id, $Timeout, $ErrorAction) }
function Start-Process { param($FilePath, $ArgumentList) $script:launched = "$FilePath $ArgumentList" }
if (-not (Restart-Tray $exe)) { Fail 'the tray was not started' }
if (($script:stopped -join ',') -ne '11') { Fail "stopped: $($script:stopped -join ',')" }
if ($script:launched -ne "$exe tray") { Fail "started: $script:launched" }

# The service block that follows the swap: the service is stopped by then, so
# a logon task that cannot be removed starts it again, and the trays running
# from the program moved aside are not stopped as an earlier install.
$m = [regex]::Match($src, '(?ms)^    if \(\$Service\) \{\r?\n        \$task = .*?(?=^    \} else \{)')
if (-not $m.Success) { Write-Output 'FAIL: install.ps1 has no service block'; exit 1 }
$serviceBlock = [scriptblock]::Create($m.Value + "}`n")
function Write-Host { param($Object) }
$Service = $true; $OwnerSid = 'S-1-5-21-1-2-3-1001'; $stoppedService = $true
$exe = Join-Path $dir 'privatae-bastion.exe'
function Get-ScheduledTask { param($TaskName, $ErrorAction) [pscustomobject]@{ TaskName = $TaskName } }
function Unregister-ScheduledTask { param($TaskName, $Confirm) throw 'access denied' }
$script:started = 0; $msg = $null
function Start-Service { param($Name, $ErrorAction) $script:started++ }
try { . $serviceBlock } catch { $msg = $_.Exception.Message }
if ($script:started -ne 1 -or $msg -notmatch 'could not be removed \(access denied\)' -or $msg -notmatch 'service is running again') {
    Fail "a logon task that cannot be removed left the service stopped: $script:started, $msg"
}
function Unregister-ScheduledTask { param($TaskName, $Confirm) }
$script:stopped = @()
function Get-Process { param($Name, $Id, $ErrorAction)
    @([pscustomobject]@{ Id = 21; Path = "$exe.old" }, [pscustomobject]@{ Id = 22; Path = "$exe.bak" },
      [pscustomobject]@{ Id = 23; Path = $exe }, [pscustomobject]@{ Id = 24; Path = 'C:\Users\a\AppData\Local\Programs\privatae-bastion\privatae-bastion.exe' }) }
function Stop-Process { param($Id, [switch]$Force, $ErrorAction) $script:stopped += $Id }
# A stand-in bastion whose `service install` succeeds.
Set-Content -LiteralPath $exe -Value "#!/bin/sh`nexit 0"
if ($IsLinux) { chmod +x $exe }
try { . $serviceBlock } catch { Fail "the service block failed: $($_.Exception.Message)" }
if (($script:stopped -join ',') -ne '24') { Fail "stopped as an earlier install: $($script:stopped -join ',')" }

Remove-Item -Recurse -Force $dir
Write-Output 'ok: the program is moved aside, put back on failure, the service restarted, and the tray restarted'
