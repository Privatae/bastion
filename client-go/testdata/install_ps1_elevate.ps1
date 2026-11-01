# Runs install.ps1's elevation block (an ordinary account installing for the
# whole machine) with Start-Process stood in: Windows' prompt answered yes, or
# declined. pwsh on Linux:
#   pwsh -NoProfile -File testdata/install_ps1_elevate.ps1 ../deploy/install.ps1
# Exits 0 when every case holds, and prints the first that does not.
param([string]$Script)
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw $Script
$m = [regex]::Match($src, '(?ms)^if \(\$Service -and -not \$isAdmin\) \{\r?\n.*?^\}\r?\n')
if (-not $m.Success) { Write-Output 'FAIL: install.ps1 has no elevation block'; exit 1 }
# The account's SID comes from a Windows API pwsh on Linux does not have.
$text = $m.Value.Replace('([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value', "'S-1-5-21-1-2-3-1001'")
$block = [scriptblock]::Create($text)

# A temp folder with quotes in its name, as under a profile like O'Brien, or
# O’Brien typed with a typographic apostrophe, which PowerShell also reads
# as a single quote.
$dir = Join-Path ([IO.Path]::GetTempPath()) ("o'brien-o$([char]0x2019)neil  two-spaces-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir | Out-Null
$env:LOCALAPPDATA = $dir
$env:TMPDIR = $dir
function Write-Host { param($Object) $script:out += "$Object`n" }

function Run-Case([string]$answer, [bool]$installed, [string]$pair) {
    $script:out = ''; $script:cmd = ''; $script:pairSeen = ''
    $Service = $true; $isAdmin = $false; $serviceInstalled = $installed; $Shared = $false
    $elevatedDone = $false; $fellBack = $false; $Pair = $pair
    $installScript = 'https://privatae.ai/bastion/install.ps1'
    function Start-Process {
        param($FilePath, $Verb, [switch]$Wait, [switch]$PassThru, $WindowStyle, $ArgumentList)
        if ($answer -eq 'no') { throw 'The operation was canceled by the user.' }
        if ($ArgumentList[-2] -ne '-EncodedCommand') { throw "the elevated command is not passed encoded: $($ArgumentList -join ' ')" }
        $script:cmd = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1]))
        # The elevated command must parse as PowerShell, whatever the temp
        # folder is called.
        $errs = $null; $toks = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:cmd, [ref]$toks, [ref]$errs)
        if ($errs) { throw "the elevated command does not parse: $($errs[0].Message)" }
        # Each value as the elevated PowerShell reads it: the string after
        # the named parameter, quotes undone by the parser itself.
        $arg = {
            param($name)
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $el = $c.CommandElements
                for ($i = 0; $i -lt $el.Count - 1; $i++) {
                    if ($el[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $el[$i].ParameterName -eq $name) {
                        return $el[$i + 1].Value
                    }
                }
            }
        }
        $pfArg = & $arg 'PairFile'
        if ($pfArg) { $script:pairSeen = [IO.File]::ReadAllText($pfArg) }
        $log = & $arg 'LiteralPath'
        Set-Content -LiteralPath $log -Value 'Installed: C:\Program Files\Privatae\privatae-bastion.exe'
        return [pscustomobject]@{ ExitCode = 0 }
    }
    $threw = $null
    try { . $block } catch { $threw = $_.Exception.Message }
    return @{ threw = $threw; out = $script:out; cmd = $script:cmd; pairSeen = $script:pairSeen;
              service = $Service; done = $elevatedDone; fellBack = $fellBack }
}
function Fail([string]$why) { Write-Output "FAIL: $why"; exit 1 }

$r = Run-Case 'yes' $false 'skp_INVENTEDCODE'
if ($r.threw -or -not $r.done) { Fail "a yes did not finish: $($r.threw)" }
if ($r.cmd -match 'skp_') { Fail "the code is in the elevated command line: $($r.cmd)" }
if ($r.pairSeen -ne 'skp_INVENTEDCODE') { Fail "the elevated step could not read the code: '$($r.pairSeen)'" }
if ($r.cmd -notmatch "-Personal -OwnerSid 'S-1-5-21-1-2-3-1001'") { Fail "kind or owner: $($r.cmd)" }
if ($r.cmd -notmatch "o''brien-o$([char]0x2019)$([char]0x2019)neil") { Fail "the temp folder's quotes are not doubled: $($r.cmd)" }
if ($r.out -notmatch 'Installed: C:\\Program Files') { Fail "the elevated step's output is not shown: $($r.out)" }
if (Get-ChildItem -LiteralPath $dir -Filter 'privatae-bastion-pair-*' -ErrorAction SilentlyContinue) { Fail 'the code file was left behind' }

$r = Run-Case 'no' $false ''
if ($r.threw -or $r.done -or $r.service -or -not $r.fellBack -or $r.out -notmatch 'installed for your account only') { Fail "a no must fall back to this account: $($r.threw) $($r.out)" }

$r = Run-Case 'no' $true ''
if (-not $r.threw -or $r.threw -notmatch 'installed for the whole machine') { Fail "beside the service, a no must install nothing: $($r.threw)" }

Remove-Item -Recurse -Force $dir
Write-Output 'ok: install.ps1 elevates for the whole machine, passes the code in a file, shows the output, falls back on a no'
