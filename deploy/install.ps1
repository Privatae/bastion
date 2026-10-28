# privatae-bastion installer — Windows.  Usage:  irm https://privatae.ai/bastion/install.ps1 | iex
#
# -Networked: install the NETWORKED bastion — a machine several hosts share,
# where every host after the first waits until the anchor host approves it. It
# runs as a Windows service under LocalSystem, so it runs whoever is signed in
# and only an administrator can stop it. Needs an ELEVATED terminal
# (right-click → Run as administrator), because whoever administers the box is
# what stands behind the anchor.
#     & ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Networked
# (NOT `irm ... | iex -Networked` — Invoke-Expression takes no such parameter and
# that form errors without installing anything.)
# On an install that already exists, `privatae-bastion set-mode networked` (from
# an Administrator terminal) changes the mode but not how it runs: it stays a
# logon task. Re-run this installer with -Networked to make it a service. The
# service starts with its own state: pairings made by the earlier per-user
# install stay in that user's profile and are not carried over, so the machine
# is paired again (claim-anchor with a token from the host).
#
# ELEVATE AS YOURSELF, not as a different administrator account. The state
# directory is per-user (a folder under %APPDATA%), and UAC elevation of your
# OWN account keeps the same profile — but "Run as different user" does not, and
# the bastion would then read an empty directory and refuse to see its pairings.
# This is the Windows shape of the same trap `sudo -H` exists for on Unix.
#
# -Pair '<code>': pair as well, with the code from your Host's "Set up a
# bastion" card, and start the bastion so it serves now and at every sign-in.
# The one line the card gives is
#     & ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Pair 'skp_…'
# The code reaches the bastion on standard input, never as an argument, so it
# is not in the process list. On a machine whose bastion is already the
# Windows service (installed with -Networked, or by `npx cseries`), -Pair pairs
# that service from an Administrator PowerShell instead of installing a second
# bastion beside it.
param([switch]$Networked, [string]$Pair)
#
# Brought into the repo (this file previously existed ONLY as bytes in the
# edge webroot, so what customers piped to `iex` had no review history) and
# given digest verification (version.json had always published correct
# sha256s and neither installer read them).
$ErrorActionPreference = 'Stop'
# dl.privatae.ai — see the note in install.sh. Hardcoded on purpose: the digest
# is verified against the manifest from this same base, so a redirectable base
# would defeat the verification it is paired with.
$base = 'https://dl.privatae.ai'
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') {'arm64'} else {'amd64'}
$key  = "windows-$arch.exe"

# Checked before anything is downloaded. Never echoed: it holds the token.
if ($Pair -and -not $Pair.StartsWith('skp_')) {
    throw "-Pair takes the pairing code from your Host's card, which starts skp_. Nothing was installed."
}
# A machine whose bastion already runs as the Windows service is paired
# through that service. A per-user install beside it would be a second
# bastion, which the service's own guard refuses to pair anyway.
if ($Pair -and -not $Networked -and (Get-Service -Name 'PrivataeBastion' -ErrorAction SilentlyContinue)) {
    $Networked = $true
    Write-Host "This computer's bastion runs as the Windows service PrivataeBastion; pairing that service."
}

if ($Networked) {
    # Checked before anything is downloaded, so a refusal leaves nothing behind
    # and is one clear sentence at the moment it can be acted on.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw ("-Networked needs an elevated terminal. A networked bastion runs as a Windows service, " +
               "and whoever administers the machine is what stands behind it.`n" +
               "Close this window, right-click your terminal, choose 'Run as administrator', and run the same line again.")
    }
}

# A networked bastion runs as a Windows service under LocalSystem, so its
# program goes under Program Files, which only administrators can change. In
# the per-user folder anyone signed in could replace the file the service runs
# as the system, and the bastion refuses to register a service from there.
$dest = if ($Networked) { Join-Path $env:ProgramFiles 'Privatae' } else { Join-Path $env:LOCALAPPDATA 'Programs\privatae-bastion' }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$exe = Join-Path $dest 'privatae-bastion.exe'

Write-Host "Fetching manifest..."
try { $manifest = Invoke-RestMethod -Uri "$base/version.json" }
catch { throw "cannot fetch $base/version.json - refusing to install unverified" }

$expected = $manifest.binaries.$key.sha256
if (-not $expected -or $expected -notmatch '^[0-9a-f]{64}$') {
    throw "manifest has no usable sha256 for $key - refusing to install unverified"
}

# Download to a TEMP path and only move it into place after the digest matches,
# so a failed verification can never leave a runnable executable behind.
# For -Networked the download is made inside the destination folder. A file
# moved within one volume keeps the permissions it was created with, so one
# made under %TEMP% would carry this account's full control into Program Files
# and let this account, unelevated, replace the program the service runs as
# the system. Made here, it has the folder's permissions from the start.
$tmpDir = if ($Networked) { $dest } else { [System.IO.Path]::GetTempPath() }
$tmp = Join-Path $tmpDir ("privatae-bastion-" + [System.Guid]::NewGuid().ToString() + ".exe")
try {
    # Take the URL FROM THE MANIFEST, never build one. The manifest's url now
    # carries ?v=<version>, which is what stops Cloudflare handing back the
    # PREVIOUS release's binary against the CURRENT release's digest — a stale
    # cache that surfaces as "checksum MISMATCH" and reads like a corrupt or
    # tampered download. Building the path here would silently opt out of that.
    # Falls back to the constructed path for a manifest that predates the field.
    $url = $manifest.binaries.$key.url
    if (-not $url) { $url = "$base/dl/privatae-bastion-$key" }
    Write-Host "Downloading privatae-bastion ($key)..."
    Invoke-WebRequest -Uri $url -OutFile $tmp

    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        throw ("checksum MISMATCH for privatae-bastion-$key`n  expected $expected`n  actual   $actual`n" +
               "The downloaded binary is not the one the platform published. Nothing was installed.")
    }
    Write-Host "Checksum verified ($expected)."
    # A running service holds its program open, and Windows will not replace an
    # open program. Stop it first; `service install` below starts it again.
    if ($Networked -and (Get-Service -Name 'PrivataeBastion' -ErrorAction SilentlyContinue)) {
        Stop-Service -Name 'PrivataeBastion' -Force -ErrorAction SilentlyContinue
    }
    Move-Item -Force -Path $tmp -Destination $exe
} finally {
    if (Test-Path $tmp) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
}

# ── AUTOSTART: a Scheduled Task at logon ──────────────────────────────────────
# Until now this installer registered NOTHING: no service, no task, no Run key.
# So the bastion lived in whatever terminal you happened to start it in, died
# with that window, and never came back after a reboot. A person with no
# terminal open had no way to tell where it was running — a fair question
# whose real answer was that 0.24.0 restarts itself DETACHED after a self-update,
# so it was serving with no console and nothing on screen saying so.
#
# A SCHEDULED TASK, NOT A WINDOWS SERVICE, and that is not laziness. The
# bastion's state directory is per-USER (under %APPDATA% — see the note at the
# top of this file). A service registered with the SCM runs as SYSTEM or
# a service account, which has a DIFFERENT %APPDATA%, so it would start cleanly
# and then read an empty state directory and see no pairings at all. That is the
# same "Run as different user" trap this installer already warns about, wearing
# a service's clothes. A logon task runs as the user, so the state is the state.
#
# -Force replaces an existing registration, so re-running the installer updates
# the task instead of failing on a duplicate.
#
# -NETWORKED IS THE EXCEPTION, AND THE SERVICE IS THE POINT OF IT. A machine an
# organisation enrols needs the bastion to run whoever is signed in, and not be
# stoppable by them. So there the bastion registers itself as a Windows service
# running as LocalSystem (`privatae-bastion service install`). The state-folder
# trap above does not apply: the bastion keeps a service's state in
# LocalSystem's own profile and points an administrator's commands at the same
# folder (client-go/sysservice.go). A logon task left over from an earlier
# install would start a second bastion beside the service, so it is removed.
#
# Removing the task does not stop a copy it already started, and after a
# self-update that copy runs detached, outside the task altogether. It holds
# 127.0.0.1:7878, which is the port the service's first pairing is given, so the
# service would fail to bind and restart every few seconds until that copy
# exited at sign-out. So any bastion running from another path is stopped here.
if ($Networked) {
    $task = Get-ScheduledTask -TaskName 'PrivataeBastion' -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName 'PrivataeBastion' -Confirm:$false
        Write-Host "Removed the logon task from an earlier install; the service replaces it."
    }
    Get-Process -Name 'privatae-bastion' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and ($_.Path -ne $exe) } |
        ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped the bastion running from $($_.Path) (an earlier per-user install)."
        }
    & $exe service install
    if ($LASTEXITCODE -ne 0) { throw "could not register the Windows service (exit $LASTEXITCODE)" }
} else {
try {
    $taskName = 'PrivataeBastion'
    # DOMAIN\user rather than a bare name: a bare one is ambiguous on a machine
    # that is domain-joined, and the task would be registered for the wrong
    # identity — which is the same empty-%APPDATA% trap as a service.
    $me       = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $action   = New-ScheduledTaskAction -Execute $exe -Argument 'run'
    $trigger  = New-ScheduledTaskTrigger -AtLogOn -User $me
    # LogonType Interactive is LOAD-BEARING, not a default worth inheriting. A
    # task that runs with a background (S4U) or service logon has no window
    # station, so the tray icon (tray_windows.go) would never appear and the
    # bastion would be exactly as invisible as it was before any of this — while
    # still reporting itself as started. Interactive puts it in the session the
    # person is actually looking at. RunLevel Limited because the bastion needs
    # no elevation to serve; only `claim-anchor` and friends do, and those are
    # typed by hand.
    $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
    # RunOnlyIfNetworkAvailable is deliberately OFF: the tunnel dials out and
    # retries, and a machine that boots before its NIC is up would otherwise
    # never start the bastion at all.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal `
        -Settings $settings -Description 'Privatae bastion — serves this machine to your Hosts.' `
        -Force | Out-Null
    Write-Host "Autostart registered: Task Scheduler -> $taskName (runs at your logon)."
    Write-Host "  Stop it with:  Stop-ScheduledTask -TaskName $taskName"
    Write-Host "  Remove it with: Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false"
} catch {
    # Never fail the install over autostart — the binary is on disk and usable.
    Write-Host "NOTE: could not register autostart ($($_.Exception.Message))."
    Write-Host "      The bastion still works; start it with 'privatae-bastion run'."
}
}

# A networked install is the machine's, so its command goes on the MACHINE
# path, where an administrator's terminal finds it whoever installed it.
#
# The machine Path is read and written in the registry as it is stored, NOT
# through [Environment]::GetEnvironmentVariable: that returns it with every
# %VARIABLE% already expanded, and writing it back stores the expanded text as
# a plain string, which fixes those entries for the whole machine. The new
# value takes effect in new sessions; this terminal is updated below.
if ($Networked) {
    $envKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
    try {
        $raw = [string]$envKey.GetValue('Path', '',
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (($raw -split ';') -notcontains $dest) {
            $envKey.SetValue('Path', ($raw.TrimEnd(';') + ';' + $dest),
                [Microsoft.Win32.RegistryValueKind]::ExpandString)
        }
    } finally {
        $envKey.Close()
    }
} else {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$dest*") { [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $dest), 'User') }
}
$env:Path = "$env:Path;$dest"
Write-Host ""
Write-Host "Installed: $exe"

if ($Networked) {
    # After `service install`, so this elevated command already writes into the
    # service's state folder rather than this administrator's own profile.
    & $exe set-mode networked
    if ($LASTEXITCODE -ne 0) { throw "could not set networked mode (exit $LASTEXITCODE)" }
    Write-Host ""
    Write-Host "The bastion runs as the Windows service 'PrivataeBastion' (LocalSystem). It starts"
    Write-Host "serving as soon as this machine is paired."
    if (-not $Pair) {
    Write-Host "Next, anchor this machine to the Host that should govern it:"
    Write-Host "  privatae-bastion claim-anchor"
    Write-Host "  (add --host <name> if this machine already serves several Hosts)"
    Write-Host "Every host paired after the anchor waits, pending, until that Host approves it."
    }
} elseif (-not $Pair) {
    Write-Host "Open a NEW terminal, then:  privatae-bastion pair <token>"
}

if ($Pair) {
    Write-Host ""
    # The full path, never the name on PATH, which this window may not have
    # picked up yet. The code goes on standard input: `pair -` reads its first
    # line. `pair` exits 3 when this computer is already paired with that Host,
    # which is success here too. On a computer that already serves another
    # Host, `pair` asks in this window whether to add this one.
    $Pair | & $exe pair -
    $rc = $LASTEXITCODE
    if ($rc -eq 0) { $done = 'This computer is paired.' }
    elseif ($rc -eq 3) { $done = 'This computer was already paired with this Host; nothing changed there.' }
    else { throw "Pairing did not finish (the reason is above). The bastion is installed; nothing else changed." }

    # A running bastion reads a new pairing at its next start, so it is
    # restarted, not just started.
    if ($Networked) {
        Restart-Service -Name 'PrivataeBastion'
        $how = 'The bastion runs as the Windows service PrivataeBastion, and starts with Windows.'
    } else {
        # Every copy is stopped first, from wherever it was started (a terminal,
        # an older install, a detached copy after a self-update): each would
        # hold this machine's first control port, 127.0.0.1:7878, and the new
        # one would fail to start beside it.
        Stop-ScheduledTask -TaskName 'PrivataeBastion' -ErrorAction SilentlyContinue
        Get-Process -Name 'privatae-bastion' -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        try {
            Start-ScheduledTask -TaskName 'PrivataeBastion'
            $how = 'The bastion is running, and starts again each time you sign in to Windows.'
        } catch {
            Start-Process -FilePath $exe -ArgumentList 'run' -WindowStyle Hidden
            $how = "The bastion is running until you sign out (its sign-in task could not be started: $($_.Exception.Message))."
        }
    }
    Start-Sleep -Seconds 3
    & $exe status
    Write-Host ""
    Write-Host "$done $how"
}
Write-Host "privatae-bastion is free software under the GNU GPL v3 or later: https://privatae.ai/bastion/LICENSE.txt"
