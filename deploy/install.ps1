# privatae-bastion installer — Windows.  Usage:  irm https://privatae.ai/bastion/install.ps1 | iex
#
# It installs the bastion FOR THE WHOLE MACHINE: the Windows service
# PrivataeBastion, running as LocalSystem, so that no program running as you,
# an AI agent included, can stop it or change what it allows. Run from an
# ordinary terminal, it asks Windows for an administrator's yes once (UAC) and
# runs the install in that elevated window, which fetches this installer again
# itself; what it printed is shown here afterwards. Your account is recorded as
# the machine's owner (approvals-owner --sid), whose tray answers approvals.
# Your own computer is the default (-Personal: one Host at most, chosen at the
# machine).
#
# -JustMe installs it for your account alone, as a logon task, and says what
# that means: any program running as you can stop it. Where Windows gives no
# administrator's yes, that is what it falls back to, and it says so; but
# never beside a bastion already installed for the whole machine.
#
# -Shared (also spelled -Networked, its earlier name): a machine several Hosts
# share, where every Host after the first waits until the one in charge
# approves it.
#     & ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Shared
# (NOT `irm ... | iex -Shared` — Invoke-Expression takes no such parameter and
# that form errors without installing anything.)
# On an install that already exists, `privatae-bastion set-mode networked` (from
# an Administrator terminal) changes the mode but not how it runs: it stays a
# logon task. Re-run this installer with -Networked to make it a service. When
# an install moves the bastion from your account to the service, the service
# takes over your account's bastion state before it first starts: its
# pairings, keys and grants, so every Host it served goes on being served and
# nothing is paired again (`service install --from-account`, servicecarry.go).
# The copy in your profile is then removed, so the keys no longer sit where
# programs running as you can read them.
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
param([switch]$Networked, [switch]$Shared, [switch]$Personal, [switch]$JustMe, [string]$Pair,
      [string]$PairFile, [string]$OwnerSid)
# -PairFile and -OwnerSid are the elevated step's own (see the elevation
# below): the pairing code in a file, never an argument, and the SID of the
# account that asked, recorded as the machine's owner.
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
# What the elevated step runs: this installer, fetched again by that step. Like
# $base, never taken from anywhere else.
$installScript = 'https://privatae.ai/bastion/install.ps1'
if ($Networked) { $Shared = $true }
if ($Shared -and $Personal) { throw "-Shared and -Personal contradict each other; pass one. Nothing was installed." }
if ($JustMe -and $Shared) { throw "A shared machine's bastion runs for the whole machine; -JustMe and -Shared contradict each other. Nothing was installed." }
if ($PairFile) {
    $Pair = ([IO.File]::ReadAllText($PairFile)).Trim()
    Remove-Item -Force -LiteralPath $PairFile -ErrorAction SilentlyContinue
}
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') {'arm64'} else {'amd64'}
$key  = "windows-$arch.exe"

# Puts the verified download $new at $target. The program already there may be
# running, and not only as the service: a whole-machine install starts the tray
# from the same file in every signed-in session (`"<exe>" tray`, tray.go
# trayRunValue). Windows will not replace or delete a running program, but it
# will rename one, so the old file is moved aside to <exe>.old and the new one
# takes its name, as the bastion's own self-update does (update.go
# swapBinaryAt). The bastion removes the .old at its next start
# (cleanupStaleBinaries). Without this, an install beside an open tray stopped
# with "Cannot create a file when that file already exists." If the new file
# cannot be moved in, the old one is put back, so there is always a program.
function Install-Program([string]$new, [string]$target) {
    $aside = $null
    if (Test-Path -LiteralPath $target) {
        # An .old still running (a tray from before the last update) cannot be
        # removed; .bak is the other name the bastion clears at its start.
        foreach ($name in @("$target.old", "$target.bak")) {
            Remove-Item -Force -LiteralPath $name -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $name)) { $aside = $name; break }
        }
        if (-not $aside) {
            throw "$target.old and $target.bak are both still in use by a running bastion, so the program could not be moved aside."
        }
        Move-Item -LiteralPath $target -Destination $aside
    }
    try {
        Move-Item -LiteralPath $new -Destination $target
    } catch {
        if ($aside) { Move-Item -LiteralPath $aside -Destination $target -ErrorAction SilentlyContinue }
        throw
    }
}

# A failed install never leaves the machine's bastion stopped: the service this
# installer stopped is started again before the failure is reported.
function Stop-InstallFailed([bool]$stopped, [string]$why) {
    if ($stopped) {
        try {
            Start-Service -Name 'PrivataeBastion' -ErrorAction Stop
            $why += " The bastion's service is running again."
        } catch {
            $why += (" The bastion could not be started again ($($_.Exception.Message)); " +
                     "start it from an Administrator terminal:  Start-Service PrivataeBastion")
        }
    }
    throw $why
}

# After an install for the whole machine, the tray in this person's session is
# still the earlier program (it holds the file the install moved aside). It is
# stopped and started again from the new one, so the tray and the service are
# the same version. Only this session's trays, found by their command line.
function Restart-Tray([string]$exe) {
    $session = (Get-Process -Id $PID).SessionId
    $paths = @($exe, "$exe.old", "$exe.bak")
    Get-CimInstance Win32_Process -Filter "Name='privatae-bastion.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $session -and $_.ExecutablePath -and ($paths -contains $_.ExecutablePath) -and
                       ($_.CommandLine -match '\stray\s*$') } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $_.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
        }
    try { Start-Process -FilePath $exe -ArgumentList 'tray' | Out-Null; return $true } catch { return $false }
}

# Checked before anything is downloaded. Never echoed: it holds the token.
if ($Pair -and -not $Pair.StartsWith('skp_')) {
    throw "-Pair takes the pairing code from your Host's card, which starts skp_. Nothing was installed."
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$serviceInstalled = [bool](Get-Service -Name 'PrivataeBastion' -ErrorAction SilentlyContinue)
# A bastion installed for the whole machine is never joined by a second one for
# an account: the service's own guard would refuse to run it.
if ($JustMe -and $serviceInstalled) {
    throw ("This machine's bastion is installed for the whole machine, as the Windows service PrivataeBastion, " +
           "and a second one for your account would be refused beside it. Nothing was installed.")
}
$Service = -not $JustMe
$elevatedDone = $false
$fellBack = $false
if ($Service -and -not $isAdmin) {
    # The elevated step. Its window cannot show its output here, so it writes
    # it to a file this account reads afterwards. The pairing code goes in a
    # file of this account's, never in the elevated command line.
    Write-Host "Installing the bastion for the whole machine, so that no program running as you, an AI agent included, can stop it or change what it allows."
    Write-Host "Windows asks for an administrator's yes once."
    $kind = if ($Shared) { '-Shared' } else { '-Personal' }
    $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $tmpRoot = [IO.Path]::GetTempPath()
    $log = Join-Path $tmpRoot ("privatae-bastion-install-" + [guid]::NewGuid().ToString() + ".log")
    $pf = ''
    if ($Pair) {
        $pf = Join-Path $tmpRoot ("privatae-bastion-pair-" + [guid]::NewGuid().ToString())
        [IO.File]::WriteAllText($pf, $Pair)
    }
    # Every value goes into the elevated command as a single-quoted literal,
    # its own quotes doubled: a profile path like C:\Users\O'Brien would
    # otherwise end the literal and the elevated command would not parse.
    # PowerShell's own escaper: it also doubles the typographic quotes
    # (U+2018-U+201B), which PowerShell reads as single quotes too.
    $q = { param($v) "'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent([string]$v) + "'" }
    $inner = "& ([scriptblock]::Create((irm $(& $q $installScript)))) $kind -OwnerSid $(& $q $sid)"
    if ($pf) { $inner += " -PairFile $(& $q $pf)" }
    $cmd = "try { $inner *>&1 | Out-File -Encoding utf8 -Append -LiteralPath $(& $q $log); exit 0 } " +
           "catch { `$_.Exception.Message | Out-File -Encoding utf8 -Append -LiteralPath $(& $q $log); exit 1 }"
    $declined = $false
    try {
        # -EncodedCommand, not -Command: Start-Process joins its arguments
        # with spaces and quotes none of them, so a command carried as text
        # loses runs of spaces and double quotes on the way. Base64 of its
        # UTF-16 bytes arrives exactly as written.
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
                 -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc)
    } catch {
        $declined = $true
    }
    if ($pf -and (Test-Path -LiteralPath $pf)) { Remove-Item -Force -LiteralPath $pf -ErrorAction SilentlyContinue }
    if (-not $declined) {
        if (Test-Path -LiteralPath $log) {
            Get-Content -LiteralPath $log | ForEach-Object { Write-Host $_ }
            Remove-Item -Force -LiteralPath $log -ErrorAction SilentlyContinue
        }
        if ($p.ExitCode -ne 0) { throw "The install for the whole machine did not finish (the reason is above)." }
        # What an earlier install for this account alone left that would run
        # a second bastion beside the service.
        $own = Join-Path $env:LOCALAPPDATA 'Programs\privatae-bastion\privatae-bastion.exe'
        if (Test-Path -LiteralPath $own) {
            Remove-Item -Force -LiteralPath $own -ErrorAction SilentlyContinue
            Write-Host "Removed $own, an earlier copy for your account alone."
        }
        $installedExe = Join-Path $env:ProgramFiles 'Privatae\privatae-bastion.exe'
        if (Restart-Tray $installedExe) { Write-Host "The tray was started again from the new program." }
        else { Write-Host "The tray could not be started now; it starts at your next sign-in." }
        $elevatedDone = $true
    } elseif ($serviceInstalled) {
        throw ("This machine's bastion is installed for the whole machine, and updating it needs an administrator's yes. " +
               "Nothing was installed.")
    } else {
        Write-Host "Windows gave no administrator's yes, so the bastion is installed for your account only."
        $Service = $false
        $fellBack = $true
    }
}

# Everything below is the install itself, run here when no elevated step did it.
if (-not $elevatedDone) {
    # Installed for the whole machine, the bastion runs as a Windows service under
    # LocalSystem, so its program goes under Program Files, which only administrators can change. In
    # the per-user folder anyone signed in could replace the file the service runs
    # as the system, and the bastion refuses to register a service from there.
    $dest = if ($Service) { Join-Path $env:ProgramFiles 'Privatae' } else { Join-Path $env:LOCALAPPDATA 'Programs\privatae-bastion' }
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
    # For the service the download is made inside the destination folder. A file
    # moved within one volume keeps the permissions it was created with, so one
    # made under %TEMP% would carry this account's full control into Program Files
    # and let this account, unelevated, replace the program the service runs as
    # the system. Made here, it has the folder's permissions from the start.
    $tmpDir = if ($Service) { $dest } else { [System.IO.Path]::GetTempPath() }
    $tmp = Join-Path $tmpDir ("privatae-bastion-" + [System.Guid]::NewGuid().ToString() + ".exe")
    $stoppedService = $false
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
        # The service is stopped so that it restarts on the new program;
        # `service install` below starts it again. Its program, and any tray's,
        # is moved aside rather than replaced (Install-Program).
        if ($Service -and (Get-Service -Name 'PrivataeBastion' -ErrorAction SilentlyContinue)) {
            Stop-Service -Name 'PrivataeBastion' -Force -ErrorAction SilentlyContinue
            $stoppedService = $true
        }
        try {
            Install-Program $tmp $exe
        } catch {
            Stop-InstallFailed $stoppedService ("The new program could not be put in place of $exe ($($_.Exception.Message)). " +
                                                "Nothing was installed.")
        }
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
    # THE WHOLE MACHINE IS THE DEFAULT, AND THE SERVICE IS THE POINT OF IT. A machine an
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
    if ($Service) {
        $task = Get-ScheduledTask -TaskName 'PrivataeBastion' -ErrorAction SilentlyContinue
        if ($task) {
            # The service is stopped by now, so a failure here starts it again
            # before it is reported (Stop-InstallFailed).
            try { Unregister-ScheduledTask -TaskName 'PrivataeBastion' -Confirm:$false }
            catch {
                Stop-InstallFailed $stoppedService ("The logon task from an earlier install could not be removed " +
                                                    "($($_.Exception.Message)), and it would start a second bastion beside the service.")
            }
            Write-Host "Removed the logon task from an earlier install; the service replaces it."
        }
        # Not the program Install-Program moved aside: every session's tray
        # runs from it now, and Windows may report a running program under the
        # name it was renamed to. Those trays are not an earlier install; they
        # go on as the earlier program until their next sign-in.
        $asideNames = @("$exe.old", "$exe.bak")
        Get-Process -Name 'privatae-bastion' -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and ($_.Path -ne $exe) -and ($asideNames -notcontains $_.Path) } |
            ForEach-Object {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                # Stop-Process returns before the process is gone, and its run
                # lock goes with it; the carry below needs that lock free.
                Wait-Process -Id $_.Id -Timeout 10 -ErrorAction SilentlyContinue
                Write-Host "Stopped the bastion running from $($_.Path) (an earlier per-user install)."
            }
        # The account that asked for this install, or this one when run elevated
        # by hand: its bastion's pairings go into the service, and it is recorded
        # as the machine's owner below.
        $owner = if ($OwnerSid) { $OwnerSid } else { ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value }
        & $exe service install --from-account $owner
        if ($LASTEXITCODE -ne 0) {
            Stop-InstallFailed $stoppedService "The Windows service could not be registered (exit $LASTEXITCODE; the reason is above)."
        }
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

    # A whole-machine install is the machine's, so its command goes on the MACHINE
    # path, where an administrator's terminal finds it whoever installed it.
    #
    # The machine Path is read and written in the registry as it is stored, NOT
    # through [Environment]::GetEnvironmentVariable: that returns it with every
    # %VARIABLE% already expanded, and writing it back stores the expanded text as
    # a plain string, which fixes those entries for the whole machine. The new
    # value takes effect in new sessions; this terminal is updated below.
    if ($Service) {
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

    if ($Service) {
        # After `service install`, so these elevated commands already write into
        # the service's state folder rather than this administrator's own profile.
        if ($Shared) {
            & $exe set-mode networked
            if ($LASTEXITCODE -ne 0) { throw "could not set networked mode (exit $LASTEXITCODE)" }
        }
        # The machine's owner ($owner, above). A second administrator's
        # reinstall leaves the first owner in place; the bastion says so.
        & $exe approvals-owner --sid $owner
        if ($LASTEXITCODE -ne 0) { Write-Host "NOTE: your account was not recorded as this machine's owner (the reason is above)." }
        Write-Host ""
        Write-Host "The bastion runs for the whole machine as the Windows service 'PrivataeBastion' (LocalSystem), and starts with Windows."
        # Run elevated by hand, there is no ordinary-account step afterwards to
        # start the tray again (Restart-Tray), and this window would start it
        # elevated, so an open tray goes on as the earlier program until sign-in.
        if (-not $OwnerSid) {
            Write-Host "  A tray already open keeps running the earlier program until you next sign in; it then starts from the new one."
        }
        # What the service serves now, and what waits for the Host in charge
        # to admit it, from the service's own state (`status --json`, read
        # with this terminal's machine authority): the move above carries
        # every pairing this account's bastion had, and on a machine with a
        # Host in charge (the anchor) each carried one waits for it.
        $served = @(); $waits = @()
        if (-not $Pair) {
            try {
                $st = (& $exe status --json 2>$null | Out-String) | ConvertFrom-Json
                foreach ($p in @($st.pairings)) {
                    if ($p.waiting_for) { $waits += "$($p.host) waits for $($p.waiting_for) to admit it; $($p.waiting_for) asks you to approve it." }
                    elseif ($p.state -eq 'active') { $served += [string]$p.host }
                }
            } catch { }
        }
        if ($served -or $waits) {
            if ($served) { Write-Host "It serves $($served -join ', ') from this computer, and watches the AI agents on it." }
            else { Write-Host "It watches the AI agents on this computer. No Host is served yet:" }
            foreach ($w in $waits) { Write-Host "  $w Once you do, it is served at once, with no restart." }
            Write-Host "  Its approvals open from the tray. See what it serves any time:  privatae-bastion status"
        } elseif (-not $Pair -and $Shared) {
        Write-Host "Next, anchor this machine to the Host that should govern it:"
        Write-Host "  privatae-bastion claim-anchor"
        Write-Host "  (add --host <name> if this machine already serves several Hosts)"
        Write-Host "Every host paired after the anchor waits, pending, until that Host approves it."
        } elseif (-not $Pair) {
        Write-Host "It is watching the AI agents on this computer now; no Host is needed."
        Write-Host "  Its approvals open from the tray. Set up your code, from an Administrator terminal:"
        Write-Host "  privatae-bastion stepup-enroll --machine"
        Write-Host "  Connect a Host, if you run one (optional), from an Administrator terminal:  privatae-bastion pair <token>"
        }
    } else {
        Write-Host "WARNING: installed for your account only. Any program running as you, an AI agent included, can stop"
        Write-Host "  the bastion or change what it allows."
        if ($JustMe) { Write-Host "  To install it for the whole machine instead, run this installer again without -JustMe." }
        elseif ($fellBack) { Write-Host "  To install it for the whole machine, run this installer again and answer Windows' prompt with an administrator's yes." }
        if (-not $Pair) {
            # Started now, not only at the next sign-in: it watches with no Host.
            # A copy already running is the old program (moved aside above), and
            # starting a task that is already running does nothing, so every copy
            # is stopped first, as for -Pair below.
            Stop-ScheduledTask -TaskName 'PrivataeBastion' -ErrorAction SilentlyContinue
            Get-Process -Name 'privatae-bastion' -ErrorAction SilentlyContinue | ForEach-Object {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
            try { Start-ScheduledTask -TaskName 'PrivataeBastion'; $now = 'It is running now, and' } catch { $now = 'It' }
            Write-Host "$now starts each time you sign in. Open a NEW terminal, then:  privatae-bastion ui"
            Write-Host "Connect a Host, if you run one (optional):  privatae-bastion pair <token>"
        }
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
        if ($Service) {
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
}
