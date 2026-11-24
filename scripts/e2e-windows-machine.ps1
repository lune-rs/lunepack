# Windows per-machine end-to-end run (M10 step 19), native, no Docker.
#
# Builds the release runtime, both stubs, the update service, `lunepack`, the e2e app and the
# stand-in UI, packs a `windows-x86_64` release of one small app WITH the service (`pack
# --service`), builds its `Setup.exe`, and checks what the packager and the files hold. With
# -Install (the default on CI) and as an administrator it also installs the app for all users into
# the real Program Files, creates ONE local standard user (a random password made at run time,
# never printed or written to a file), and drives the whole cycle as that user: updates through the
# update service with no prompt, health checks and rollbacks, negative requests, a pipe taken first
# by the user, the administrator's policy, the garbage collection of an old tree, and the
# administrator's uninstall. Everything the run creates (the user and its profile, the service, the
# registry keys, the folders under Program Files, ProgramData and the Start menu) is removed in a
# `finally`, and the script asserts it.
#
# The install rows write under the real machine locations, so a developer machine runs them only on
# request, and a shared test machine not at all. They need an administrator; elsewhere they are
# skipped by name and the static rows still run (on CI a skip fails the script).
#
# One app, `M` (the e2e app behind the GUI stub, with the stand-in UI, display name
# `Lunepack E2E Machine <hex>`: ASCII, because the standard user's commands are batch files), versions
# 1.0.0 to 1.13.0 in one `file:` feed under a folder the standard user may read.
#
# Rows (the numbers are the plan's; each row is named in the output):
#   1   silent machine install by the administrator (`Setup.exe /S --all-users`, run beside the
#       planted-DLL garbage files); the tree, its descriptors, the record, HKLM, the shortcut, the
#       service; the standard user cannot write under R
#   2   the standard user starts the app through the stub and updates it (check, download, stage,
#       apply, confirm) with no prompt; the new tree is readable and executable by the user; the
#       service's image follows the confirm
#   3   the same update through the runtime's command line with --json
#   4   a version that crashes on start (rollback through the token, marked bad, not offered again);
#       a version that confirms too slowly (rollback)
#   5   the supervisor killed after the apply: starts inside the lease are not counted, three more
#       starts past it count, the fourth rolls back in the service; a wrong token confirms and rolls
#       back nothing; a healthy version whose first run did not confirm confirms through `attempt`
#   6   negatives as the standard user: a flipped byte in the upload (the service refuses it, the
#       library drops it from the cache; its refetch is cut off), documents signed by another root,
#       an older feed, garbage and an oversize frame, `sc.exe config`, a write under R
#   7   a pipe taken first by the standard user while the service is stopped is refused; updates
#       work again when it is gone
#   8   the policy: DisableSelfUpdate (33; the service refuses stage_begin), NoUpdateUi
#   9   interactive Setup with the stand-in UI ticking "all users" (the hand-off through `runas`),
#       and the same with the UI killed mid-install
#   10  `--all-users --silent` as the standard user: exit 30, nothing written
#   11  a service switch serves the next update; an old tree is kept while the user runs from it and
#       is collected after
#   11b an update by delta through the service (protocol version 2, M12): one file changes by 16
#       bytes, the packer writes the delta, the user's download fetches the file as a patch and the
#       service stages it against its own tree; the update confirms
#   12  the administrator's uninstall: refused while the user runs the app, nothing changed;
#       complete after
#
# The row "Run as administrator without --all-users" (the fixed message box, standing UacElevated)
# cannot run here: a hosted runner's administrator holds no split token (assumption A5). It is a
# script-checked row of scripts/windows-machine-user-check.ps1 and is named as skipped below.
#
# The harness never prints environment or registry dumps; a failure names a differing field, and
# prints only versions, outcome words and exit codes.
param([switch]$Install)
$ErrorActionPreference = 'Stop'
if ($env:CI -eq 'true' -or $env:LUNEPACK_E2E_INSTALL -eq '1') { $Install = $true }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tdir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
$rel = Join-Path $tdir 'release'

$hex = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$pf = [Environment]::GetFolderPath('ProgramFiles')
$commonPrograms = [Environment]::GetFolderPath('CommonPrograms')
$work = Join-Path ([IO.Path]::GetTempPath()) "lunepack-e2e-machine-$hex"
$tempRoot = [IO.Path]::GetTempPath()
$tempBefore = @(Get-ChildItem $tempRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
$pfBefore = @(Get-ChildItem $pf -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
# What the standard user may read and write: one folder under ProgramData (admin-owned; Users read
# and execute, the feeds and Setup copies below it, and Users modify only in `out`).
$base = Join-Path $env:ProgramData "lunepack-e2e-machine-$hex"
$workDir = Join-Path $base 'work'
$outDir = Join-Path $base 'out'
$feeds = Join-Path $base 'feeds'
$failures = New-Object System.Collections.Generic.List[string]
$utf8 = New-Object System.Text.UTF8Encoding($false)
$apps = New-Object System.Collections.ArrayList
$user = $null
$launchMethods = @{}
$lastUser = $null
$cliExit = 0
$policyParent = 'HKLM:\SOFTWARE\Policies\lunepack'
$madePolicyParent = $false
$uninstallKeyRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
# SYSTEM, Administrators, TrustedInstaller: the accounts that may own and write the machine tree.
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$usersSid = 'S-1-5-32-545'

if (-not ('Lpe2eProc' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'ci\e2e-native.cs') }
. (Join-Path $PSScriptRoot 'ci\lib-user.ps1')
# The planted-DLL list and the loader-failure set live in plant-dll-test.ps1, nowhere else.
$plant = & (Join-Path $PSScriptRoot 'ci\plant-dll-test.ps1') -Describe

# ---- small helpers ---------------------------------------------------------------------------------

# Runs one row. A failure is reported with the row's own line (not a helper's), then -Undo puts
# back what the failed row left, so one failure does not cascade into the rows after it.
function Row([string]$id, [scriptblock]$body, [scriptblock]$Undo = $null) {
    try {
        & $body
        Write-Output "ok   row $id"
    } catch {
        $failures.Add("row $id")
        $line = $_.InvocationInfo.ScriptLineNumber
        foreach ($frame in @("$($_.ScriptStackTrace)" -split "`r?`n")) {
            if ($frame -notmatch '^at (Require|Same|SameV),' -and $frame -match 'line (\d+)$') { $line = $Matches[1]; break }
        }
        Write-Output "FAIL row ${id}: $($_.Exception.Message) (script line $line)"
        Write-Diagnostics
        if ($Undo) {
            try { & $Undo } catch { Write-Output "     undo of row ${id} failed: $($_.Exception.Message)" }
        }
    }
}

function Require([bool]$condition, [string]$what) {
    if (-not $condition) { throw "expected: $what" }
}

# A field that differs is named, never printed.
function Same([string]$what, $got, $want) {
    if ($got -ne $want) { throw "field $what differs" }
}

# For values that are versions, outcome words or counts: both sides are printed.
function SameV([string]$what, $got, $want) {
    if ($got -ne $want) { throw "$what is '$got', want '$want'" }
}

# A Windows PE's subsystem (optional header offset 68).
function PeSubsystem([string]$path) {
    $b = [IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    return [BitConverter]::ToUInt16($b, $pe + 24 + 68)
}

function Read-Text([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    try {
        $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { return (New-Object IO.StreamReader($fs, $utf8)).ReadToEnd() } finally { $fs.Dispose() }
    } catch { return '' }
}

function Read-Lines([string]$path) {
    $text = Read-Text $path
    if ($text -eq '') { return @() }
    return @($text -split "`r?`n" | Where-Object { $_ -ne '' })
}

function Wait-Until([scriptblock]$condition, [int]$seconds, [string]$what) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        if (& $condition) { return }
        if ((Get-Date) -gt $deadline) { throw "timed out waiting for: $what" }
        Start-Sleep -Milliseconds 300
    }
}

# A fresh outcome file in the folder the standard user may write; the apps the user starts from
# now on (and what they start) write their lines to it (see `Env-Lines`).
function New-Out([string]$tag) {
    $path = Join-Path $outDir "out-$tag.txt"
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    return $path
}

function Expect-Lines([string]$file, [string[]]$want, [switch]$Unordered, [int]$seconds = 120) {
    Wait-Until { @(Read-Lines $file).Count -ge $want.Count } $seconds "$($want.Count) outcome lines"
    Start-Sleep -Milliseconds 800
    $got = @(Read-Lines $file)
    if ($Unordered) {
        if ((($got | Sort-Object) -join '|') -ne (($want | Sort-Object) -join '|')) { throw "outcome lines differ (unordered): [$($got -join '; ')]" }
        return
    }
    if ($got.Count -ne $want.Count) { throw "got $($got.Count) outcome lines, want $($want.Count): [$($got -join '; ')]" }
    for ($i = 0; $i -lt $want.Count; $i++) {
        if ($got[$i] -ne $want[$i]) { throw "outcome line $($i + 1) is '$($got[$i])', want '$($want[$i])'" }
    }
}

# Runs a program to its end with its output captured; returns Code, Out and Err (lines) and Notices.
# While it runs, every message box it owns is recorded (Title, Text) and closed, so no run can hang
# on one; a notice is a failure unless -AllowNotice is given (as in scripts/e2e-windows.ps1).
function Run-Tool([string]$file, [string[]]$arguments = @(), [int]$seconds = 240, [switch]$AllowNotice, [hashtable]$Env = @{}) {
    $o = Join-Path $work ('tool-' + [Guid]::NewGuid().ToString('N') + '.out')
    $e = $o + '.err'
    $params = @{ FilePath = $file; PassThru = $true; WindowStyle = 'Hidden'; RedirectStandardOutput = $o; RedirectStandardError = $e }
    if ($arguments.Count -gt 0) { $params.ArgumentList = $arguments }
    $saved = @{}
    foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $Env[$k]) }
    try {
        $p = Start-Process @params
        $null = $p.Handle
    } finally {
        foreach ($k in $Env.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
    $notices = New-Object System.Collections.ArrayList
    $closed = @{}
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while (-not $p.WaitForExit(200)) {
        foreach ($n in [Lpe2eWin]::CloseNotices($p.Id)) {
            if (-not $closed.ContainsKey($n.Handle)) { $closed[$n.Handle] = $true; $null = $notices.Add($n) }
        }
        if ([DateTime]::UtcNow -gt $deadline) {
            try { $p.Kill() } catch { }
            throw "timed out running $(Split-Path $file -Leaf)"
        }
    }
    $p.WaitForExit()
    $result = [pscustomobject]@{ Code = $p.ExitCode; Out = @(Read-Lines $o); Err = (Read-Text $e); Notices = @($notices) }
    Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue
    if ($notices.Count -gt 0 -and -not $AllowNotice) {
        throw "$(Split-Path $file -Leaf) showed $($notices.Count) unexpected notice(s), the first titled '$($notices[0].Title)': '$($notices[0].Text)'"
    }
    return $result
}

# A native program with its text and exit code; stderr is never an error here.
function Native([string]$file, [string[]]$a) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $o = & $file @a 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $code; Text = (($o) -join "`n").Trim() }
}

# The processes whose image lies under `dir` (admin: every user's).
function Get-ProcsUnder([string]$dir) {
    $prefix = $dir.TrimEnd('\') + '\'
    return @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $path = $null
            try { $path = $_.Path } catch { }
            $path -and $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
        })
}

function Stop-Under([string]$dir) {
    foreach ($p in @(Get-ProcsUnder $dir)) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { } }
}

# Whether an exit code is one of the loader failures of the planted-DLL test.
function Test-LoaderFailure([int]$code) {
    $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes($code), 0)
    return ($plant.LoaderFailures -contains $u)
}

# A fresh folder holding garbage files named after DLLs the binaries do not import, with `file`
# copied in; returns the copy's path.
function New-PlantedCopy([string]$file, [string]$tag) {
    $dir = Join-Path $base "plant-$tag"
    New-Item -ItemType Directory -Force $dir | Out-Null
    foreach ($d in $plant.Planted) { [IO.File]::WriteAllBytes((Join-Path $dir "$d.dll"), $plant.Content) }
    $copy = Join-Path $dir (Split-Path $file -Leaf)
    Copy-Item -LiteralPath $file -Destination $copy
    return $copy
}

# ---- services, descriptors, the registry ------------------------------------------------------------

function Service-State([string]$name) {
    $q = (Native 'sc.exe' @('query', $name)).Text
    if ($q -match 'STATE\s*:\s*\d+\s+(\w+)') { return $Matches[1] }
    return 'MISSING'
}

function Wait-ServiceState([string]$name, [string]$state, [int]$sec = 60) {
    $deadline = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $deadline) {
        if ((Service-State $name) -eq $state) { return }
        Start-Sleep -Milliseconds 500
    }
    throw "the service '$name' did not reach $state (it is $(Service-State $name))"
}

function Stop-AppService($app) {
    $name = $app.ServiceName
    if ((Service-State $name) -eq 'RUNNING') { Native 'sc.exe' @('stop', $name) | Out-Null }
    if ((Service-State $name) -notin @('MISSING')) { Wait-ServiceState $name 'STOPPED' }
}

# The service's registration as text: the configuration and the descriptor, to compare before and after.
function Service-Registration($app) {
    $qc = (Native 'sc.exe' @('qc', $app.ServiceName)).Text
    $sd = (Native 'sc.exe' @('sdshow', $app.ServiceName)).Text
    return "$qc`n$sd"
}

# The registered image path of the service (unquoted), or $null.
function Service-Image($app) {
    $qc = (Native 'sc.exe' @('qc', $app.ServiceName)).Text
    if ($qc -match 'BINARY_PATH_NAME\s*:\s*"([^"]+)"') { return ($Matches[1] -replace '^\\\\\?\\', '') }
    return $null
}

function Assert-ServiceRegistered($app, [string]$version) {
    $name = $app.ServiceName
    $qc = (Native 'sc.exe' @('qc', $name)).Text
    $want = Join-Path $app.Root ".lunepack\machine\service\$version\lunepack-service.exe"
    Require ($qc -match 'BINARY_PATH_NAME\s*:\s*"([^"]+)"[ \t]*\r?\n') "the stored image path is quoted, with no arguments (qc: $($qc -replace '\s+', ' '))"
    # The engine registers the canonical path, which carries the verbatim prefix `\\?\`.
    SameV 'registered image' (($Matches[1] -replace '^\\\\\?\\', '').ToLowerInvariant()) $want.ToLowerInvariant()
    Require ($qc -match 'DEMAND_START') 'the start type is demand'
    Require ($qc -match 'SERVICE_START_NAME\s*:\s*LocalSystem') 'the service runs as LocalSystem'
    # Users hold start, query status and read control only; no other non-administrator entry holds
    # change config, stop, delete, write DAC or write owner.
    $sd = (Native 'sc.exe' @('sdshow', $name)).Text
    $bu = @([regex]::Matches($sd, '\(A;[^;]*;([A-Za-z0-9]*);;;BU\)'))
    Require ($bu.Count -eq 1) "one allow entry for Users (sdshow: $sd)"
    $rights = (@([regex]::Matches($bu[0].Groups[1].Value, '..') | ForEach-Object { $_.Value }) | Sort-Object) -join ','
    Require ($rights -eq 'LC,RC,RP') "Users hold exactly query status, read control and start (got $rights)"
    foreach ($m in [regex]::Matches($sd, '\(A;[^;]*;([A-Za-z0-9]*);;;([A-Z0-9-]+)\)')) {
        if ($m.Groups[2].Value -in @('SY', 'BA', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { continue }
        Require ($m.Groups[1].Value -notmatch '^0x') "every entry for a non-administrator names its rights by letters (trustee $($m.Groups[2].Value))"
        $held = @([regex]::Matches($m.Groups[1].Value, '..') | ForEach-Object { $_.Value })
        foreach ($bad in 'DC', 'WP', 'DT', 'SD', 'WD', 'WO', 'GA', 'GW') {
            Require ($held -notcontains $bad) "no non-administrator entry holds $bad (trustee $($m.Groups[2].Value))"
        }
    }
}

function Sid-Of($identity) {
    try { return $identity.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return "$identity" }
}

# The descriptor rules of M10-D9, read independently of the engine's own check: the owner is one of
# the trusted accounts and no one else holds a write-class right (class `machine`: everyone may
# read and execute; class `admin`: no one else holds any right at all).
$writeRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
function Assert-Protected([string]$path, [string]$class) {
    $leaf = Split-Path $path -Leaf
    $acl = Get-Acl -LiteralPath $path
    $owner = Sid-Of ([Security.Principal.NTAccount]$acl.Owner)
    Require ($trusted -contains $owner) "the owner of '$leaf' is one of SYSTEM, Administrators, TrustedInstaller"
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = Sid-Of $ace.IdentityReference
        if ($trusted -contains $sid) { continue }
        if ($class -eq 'admin') { throw "'$leaf' (admin only) has an entry for $sid" }
        if (($ace.FileSystemRights -band $writeRights) -ne 0) { throw "'$leaf' gives $sid a write-class right ($($ace.FileSystemRights))" }
    }
}

# ---- the standard user ----------------------------------------------------------------------------------

# Runs cmd lines as the standard user, its profile loaded (so it has its own LocalAppData); the
# lines may use `%OUT%`. Returns ExitCode and Output; a timeout is a failure naming the launch.
function AsUser([string]$tag, [string[]]$lines, [int]$timeout = 180) {
    $r = Invoke-AsUser -User $user -Lines $lines -WorkDir $workDir -OutDir $outDir -Tag $tag -TimeoutSec $timeout -WithProfile
    $script:launchMethods[$r.Method] = 1 + [int]$script:launchMethods[$r.Method]
    $seen = "$($r.Output)" -replace '\s+', ' '
    $script:lastUser = "$tag rc=$($r.ExitCode) output=[$($seen.Substring(0, [Math]::Min(300, $seen.Length)))]"
    if ($r.TimedOut) { throw "the standard user's command '$tag' did not finish (launch method: $($r.Method))" }
    return [pscustomobject]$r
}

# `set` lines for the environment of what the user starts: the outcome file and the extras.
function Env-Lines([string]$out, [hashtable]$extra = @{}) {
    $l = @("set `"LUNEPACK_E2E_OUT=$out`"")
    foreach ($k in $extra.Keys) { $l += "set `"$k=$($extra[$k])`"" }
    return $l
}

# Starts the app $exe as the user in the background (the batch ends at once; the process lives on).
function UStart([string]$tag, [string]$exe, [string]$exeArgs, [string]$out, [hashtable]$extra = @{}) {
    $line = "start `"`" /b `"$exe`" $exeArgs >> `"%OUT%`" 2>&1"
    return AsUser $tag (@(Env-Lines $out $extra) + $line)
}

# Runs a program as the user to its end; the exit code and the output (also appended to %OUT%).
function URun([string]$tag, [string]$exe, [string]$exeArgs, [string]$out = $null, [hashtable]$extra = @{}) {
    if (-not $out) { $out = New-Out $tag }
    return AsUser $tag (@(Env-Lines $out $extra) + "`"$exe`" $exeArgs >> `"%OUT%`" 2>&1")
}

# The user's home for the app's counters, cache and logs (`<LocalAppData>\lunepack\<app id>`).
function User-Home($app) { return Join-Path $env:SystemDrive "Users\$($user.Name)\AppData\Local\lunepack\$($app.Id)" }

# ---- the publisher ------------------------------------------------------------------------------------------

# `$cli` is read through the call stack, never as `$script:cli`.
function Invoke-Lunepack([string]$config, [string[]]$cliArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = @(& $cli --config $config @cliArgs 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $old }
    $script:cliExit = $LASTEXITCODE
    return $out
}

function Invoke-LunepackOk([string]$config, [string[]]$cliArgs) {
    $out = @(Invoke-Lunepack $config $cliArgs)
    if ($script:cliExit -ne 0) { throw "lunepack $($cliArgs[0]) failed with exit $($script:cliExit): $((@($out | Select-Object -First 3)) -join ' | ')" }
    return $out
}

function Pub([string]$config, [string]$base) {
    $lines = @(Invoke-LunepackOk $config @('keys', 'gen', $base))
    $m = $lines | Select-String '^public:' | Select-Object -First 1
    Require ($null -ne $m) 'keys gen prints a public line'
    return ($m.Line -replace '^public:\s*', '').Trim()
}

# `file:///C:/dir/` for a directory (FORMAT 13.3: an uppercase drive, forward slashes).
function FileFeed([string]$dir) {
    $p = $dir -replace '\\', '/'
    return 'file:///' + $p.Substring(0, 1).ToUpperInvariant() + $p.Substring(1) + '/'
}

# A publisher for one app: keys, key set, an empty release directory (in the folder the standard
# user reads), a config to extend per release. `IdOverride` makes a second publisher (another root)
# for the same app id.
function New-App([string]$tag, [string]$entryRel, [string]$entrySource, [string]$ui, [string]$idOverride = $null) {
    $dir = Join-Path $work $tag
    $relDir = Join-Path $feeds $tag
    New-Item -ItemType Directory $dir, $relDir | Out-Null
    $cfg = Join-Path $dir 'lunepack.toml'
    $id = if ($idOverride) { $idOverride } else { "org.example.lpe2em$hex" }
    $app = @{
        Tag = $tag; Id = $id; BaseName = "Lunepack E2E Machine $hex"
        EntryRel = $entryRel; EntryFile = ($entryRel -split '/')[-1]; EntrySource = $entrySource
        Ui = $ui; Dir = $dir; Cfg = $cfg; Rel = $relDir; RelKey = (Join-Path $dir 'rel0.key')
        Root = $null; ServiceName = "lunepack-$id"; PipeName = "lunepack-$id"
    }
    $app.Name = $app.BaseName
    $app.Feed = FileFeed $app.Rel
    $rootPub = Pub $cfg (Join-Path $dir 'rootk')
    $relPub = Pub $cfg (Join-Path $dir 'rel0')
    Invoke-LunepackOk $cfg @('init', '--app-id', $app.Id, '--root-key', $rootPub) | Out-Null
    $app.Base = [IO.File]::ReadAllText($cfg)
    Invoke-LunepackOk $cfg @('keys', 'set', '--release-dir', $app.Rel, '--threshold', '1', '--release-key', $relPub, '--sign', "file:$dir\rootk.key") | Out-Null
    [void]$apps.Add($app)
    return $app
}

# Packs and publishes one version of an app, WITH the update service. Options: Flags (lines of
# e2e-flags), Timeout (health_timeout_secs), Files (relative path -> source file, put into the input).
function Publish-Version($app, [string]$version, [hashtable]$options = @{}) {
    $flags = @()
    if ($options.ContainsKey('Flags')) { $flags = $options.Flags }
    $timeout = 30
    if ($options.ContainsKey('Timeout')) { $timeout = $options.Timeout }
    $in = Join-Path $app.Dir "in-$version"
    $dest = Join-Path $in ($app.EntryRel -replace '/', '\')
    [void][IO.Directory]::CreateDirectory((Split-Path $dest -Parent))
    [IO.File]::Copy($app.EntrySource, $dest, $true)
    if ($options.ContainsKey('Files')) {
        foreach ($name in $options.Files.Keys) {
            $to = Join-Path $in $name
            [void][IO.Directory]::CreateDirectory((Split-Path $to -Parent))
            [IO.File]::Copy($options.Files[$name], $to, $true)
        }
    }
    if ($flags.Count -gt 0) { [IO.File]::WriteAllText((Join-Path $in 'e2e-flags'), (($flags -join "`n") + "`n"), $utf8) }
    $toml = "`n[update]`nfeed = `"$($app.Feed)`"`nchannel = `"stable`"`nhealth_timeout_secs = $timeout`n`n[install]`nentry = `"$($app.EntryRel)`"`nname = `"$($app.Name)`"`npublisher = `"Lunepack E2E`"`n"
    [IO.File]::WriteAllText($app.Cfg, $app.Base + $toml, $utf8)
    $packArgs = @('pack', '--input', $in, '--version', $version, '--target', 'windows-x86_64', '--release-dir', $app.Rel, '--sign', "file:$($app.RelKey)", '--runtime', $runtime, '--stub', $stub, '--service', $service)
    if ($app.Ui) { $packArgs += @('--ui', $app.Ui) }
    Invoke-LunepackOk $app.Cfg $packArgs | Out-Null
    Invoke-LunepackOk $app.Cfg @('feed', 'add', '--release-dir', $app.Rel, '--channel', 'stable', '--version', $version, '--sign', "file:$($app.RelKey)") | Out-Null
}

# A Setup.exe of one version, in a folder of its own.
function Build-Setup($app, [string]$version, [string]$dir) {
    New-Item -ItemType Directory -Force $dir | Out-Null
    $out = Join-Path $dir 'Setup.exe'
    Invoke-LunepackOk $app.Cfg @('setup', $app.Rel, '--version', $version, '--target', 'windows-x86_64', '--out', $out) | Out-Null
    return $out
}

# ---- the install record, the tree ------------------------------------------------------------------------------

# The newest install-state record of an install (FORMAT 12): read only, frame checked by shape.
function Get-Record([string]$root) {
    $dir = Join-Path $root '.lunepack\state'
    $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.rec' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    foreach ($f in $files) {
        try {
            $b = [IO.File]::ReadAllBytes($f.FullName)
            if ($b.Length -lt 41 -or $b[0] -ne 0x4C -or $b[1] -ne 0x50 -or $b[2] -ne 0x53 -or $b[3] -ne 0x54) { continue }
            $len = ([int]$b[5] -shl 24) -bor ([int]$b[6] -shl 16) -bor ([int]$b[7] -shl 8) -bor [int]$b[8]
            $json = [Text.Encoding]::UTF8.GetString($b, 9, $len) | ConvertFrom-Json
            if ($json.kind -eq 'install-state') { return $json }
        } catch { }
    }
    return $null
}

function Assert-Record($app, [string]$current, $previous, [string[]]$bad, $pending = $null) {
    $r = Get-Record $app.Root
    Require ($null -ne $r) 'a readable install record'
    SameV 'scope' $r.scope 'machine'
    SameV 'current' $r.current.version $current
    $prev = $null
    if ($r.previous) { $prev = $r.previous.version }
    SameV 'previous' $prev $previous
    SameV 'bad versions' ((@($r.bad)) -join ',') (($bad) -join ',')
    if ($null -eq $pending) {
        Require ($null -eq $r.pending) 'no pending version'
    } else {
        Require ($null -ne $r.pending) 'a pending version'
        SameV 'pending version' $r.pending.version $pending[0]
        SameV 'pending attempts' ([int]$r.pending.attempts) ([int]$pending[1])
    }
}

function App-Versions($app) {
    return @(Get-ChildItem -LiteralPath (Join-Path $app.Root 'app') -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object)
}

function Stub-Path($app) { return (Join-Path $app.Root $app.EntryFile) }

function Get-Runtimes($app) {
    return @(Get-ProcsUnder (Join-Path $app.Root 'app') | Where-Object { $_.ProcessName -eq 'lunepack-runtime' })
}

function Wait-Runtimes-Gone($app) {
    Wait-Until { @(Get-Runtimes $app).Count -eq 0 } 90 'the runtime to finish'
}

function Wait-Updated($app, [string]$to) {
    Wait-Until { $r = Get-Record $app.Root; $null -ne $r -and $r.current.version -eq $to -and $null -eq $r.pending } 150 "the update to $to to settle"
    Wait-Runtimes-Gone $app
}

# Every file under a tree, with its size, as one comparable text (names relative to the tree).
# The service's and the runtime's own log files under `.lunepack\logs` grow whenever a process of
# theirs runs (a refused uninstall stops and starts the service again), so their names count, their sizes do not.
function Tree-Listing([string]$dir) {
    $prefix = $dir.TrimEnd('\') + '\'
    return ((Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object FullName | ForEach-Object {
                $rel = $_.FullName.Substring($prefix.Length)
                $kind = if ($_.PSIsContainer) { 'd' } elseif ($rel -like '.lunepack\logs\*') { 'f' } else { "f$($_.Length)" }
                "$kind $rel"
            }) -join "`n")
}

# The entries of two listings that are not in both, for a failure message (names only).
function Listing-Diff([string]$a, [string]$b) {
    $x = @($a -split "`n"); $y = @($b -split "`n")
    return @(@($x | Where-Object { $y -notcontains $_ }) + @($y | Where-Object { $x -notcontains $_ }) | Select-Object -First 6) -join '; '
}

# The lines of an update from $from to $to that the new version confirms (the library's path).
function Confirmed-Lines([string]$from, [string]$to) {
    return @("$from start", "$from nothing-pending", "$from check $to", "$from staged $to", "$from apply-scheduled",
        "$to start", "$to arg after-update", "$to event updated $from", "$to event first_run", "$to confirmed")
}

# A signed document's JSON (the payload of its envelope).
function Doc-Payload([string]$path) {
    $env = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env.payload)) | ConvertFrom-Json
}

# The documents of one release as the service probe takes them (`--service-probe stage-docs`):
# the rotation documents (`root-<n>.json`, none until a rotation), `keys.json`, the channel's feed
# as `feed.json` and the version's manifest as `manifest.json`, copied into `dest`.
function Save-Docs($app, [string]$version, [string]$dest) {
    New-Item -ItemType Directory -Force $dest | Out-Null
    foreach ($f in @(Get-ChildItem -LiteralPath $app.Rel -File -Filter 'root-*.json')) { Copy-Item -LiteralPath $f.FullName -Destination $dest }
    Copy-Item -LiteralPath (Join-Path $app.Rel 'keys.json') -Destination (Join-Path $dest 'keys.json')
    Copy-Item -LiteralPath (Join-Path $app.Rel 'feed-stable.json') -Destination (Join-Path $dest 'feed.json')
    Copy-Item -LiteralPath (Join-Path $app.Rel "$version\windows-x86_64.manifest.json") -Destination (Join-Path $dest 'manifest.json')
}

# The Programs-menu shortcut every user sees.
function Common-Shortcut($app) { return Join-Path $commonPrograms "$($app.Name).lnk" }

# What a machine install of $version leaves: the tree and its descriptors, the record, HKLM, the
# common shortcut and the service.
function Assert-Installed($app, [string]$version) {
    $root = $app.Root
    Require (Test-Path -LiteralPath $root) 'the install folder exists'
    $top = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object)
    Same 'top level of R' ($top -join '|') ((@('.lunepack', 'app', $app.EntryFile) | Sort-Object) -join '|')
    Require (Test-Path -LiteralPath (Join-Path $root "app\$version")) "app\$version exists"
    Assert-Protected $root 'machine'
    Assert-Protected (Join-Path $root 'app') 'machine'
    Assert-Protected (Join-Path $root "app\$version") 'machine'
    Assert-Protected (Join-Path $root '.lunepack') 'machine'
    Assert-Protected (Join-Path $root '.lunepack\state') 'machine'
    Assert-Protected (Join-Path $root '.lunepack\machine') 'admin'
    $v = (Get-Item -LiteralPath (Stub-Path $app)).VersionInfo
    Same 'stub FileDescription' $v.FileDescription $app.Name
    SameV 'stub ProductVersion' $v.ProductVersion $version
    $r = Get-Record $root
    Require ($null -ne $r) 'a readable install record'
    SameV 'scope' $r.scope 'machine'
    SameV 'current' $r.current.version $version
    $key = Join-Path $uninstallKeyRoot $app.Id
    $u = Get-ItemProperty $key
    Same 'DisplayName' $u.DisplayName $app.Name
    Same 'InstallLocation' $u.InstallLocation $root
    SameV 'DisplayVersion' $u.DisplayVersion $version
    Same 'QuietUninstallString' $u.QuietUninstallString "`"$(Stub-Path $app)`" --lunepack-uninstall /S"
    $lnk = Common-Shortcut $app
    Require (Test-Path -LiteralPath $lnk) 'the common Start-menu shortcut exists'
    $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    Same 'shortcut target' $sc.TargetPath (Stub-Path $app)
    Assert-ServiceRegistered $app $version
}

# ---- machine uninstall -----------------------------------------------------------------------------------------------

# The administrator's uninstall through the Uninstall entry's own quiet command, split by the
# documented rule. The stub starts the runtime detached and exits 0; the runtime, holding the
# administrator's token, makes no copy under the temp folder (S1): it runs phase 1 itself, which
# starts phase 2 from a copy in an admin-only `.lunepack-uninstall-<32 hex>` folder under Program
# Files, and that copy's exit code is the result: it is read from the copy's process, found while it
# runs. Returns the copy's exit code.
function Invoke-MachineUninstall($app) {
    $key = Join-Path $uninstallKeyRoot $app.Id
    $quiet = (Get-ItemProperty $key).QuietUninstallString
    Require ($quiet -match '^"([^"]+)"\s*(.*)$') 'the string has the documented shape'
    $program = $Matches[1]
    $rest = $Matches[2]
    # No -Wait: it would also wait for every process the stub started, and the copy's exit code
    # is read from its own process below.
    $u = Start-Process -FilePath $program -ArgumentList $rest -PassThru -WindowStyle Hidden
    $null = $u.Handle
    if (-not $u.WaitForExit(60000)) { throw 'the stub did not exit' }
    SameV 'stub exit code' $u.ExitCode 0
    $copy = $null
    $deadline = (Get-Date).AddSeconds(120)
    while ($null -eq $copy -and (Get-Date) -lt $deadline) {
        foreach ($p in @(Get-Process -Name 'lunepack-runtime' -ErrorAction SilentlyContinue)) {
            $path = $null
            try { $path = $p.Path } catch { }
            if ($path -and $path -match '\\\.lunepack-uninstall-[0-9a-f]{32}\\lunepack-runtime\.exe$') { $copy = $p; $null = $copy.Handle; break }
        }
        if ($null -eq $copy) { Start-Sleep -Milliseconds 50 }
    }
    Require ($null -ne $copy) 'the uninstaller copy was started (none seen within 120 s)'
    if (-not $copy.WaitForExit(240000)) { try { $copy.Kill() } catch { }; throw 'the uninstaller copy did not finish' }
    return $copy.ExitCode
}

# Removes the `delete at restart` entries this run's uninstaller folders left in the session manager's
# list (the folders themselves are removed by the cleanup), and returns how many it found.
function Pending-Deletes([switch]$Remove) {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $v = (Get-ItemProperty -LiteralPath $k -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if (-not $v) { return 0 }
    $items = @($v)
    $ours = '\.lunepack-uninstall-'
    $keep = New-Object System.Collections.Generic.List[string]
    $found = 0
    for ($i = 0; $i -lt $items.Count; $i += 2) {
        $src = $items[$i]
        $dst = if ($i + 1 -lt $items.Count) { $items[$i + 1] } else { '' }
        # The registered path is `*1\??\C:\...` (a flag word, then the NT prefix).
        $plain = $src -replace '^\*\d+', '' -replace '^\\\?\?\\', '' -replace '^\\\\\?\\', ''
        if ($plain -and $plain.StartsWith($pf, [StringComparison]::OrdinalIgnoreCase) -and $plain.IndexOf($ours, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $found++
        } else {
            $keep.Add($src); $keep.Add($dst)
        }
    }
    if ($Remove -and $found -gt 0) {
        if ($keep.Count -gt 0) { Set-ItemProperty -LiteralPath $k -Name PendingFileRenameOperations -Value ([string[]]$keep.ToArray()) -Type MultiString }
        else { Remove-ItemProperty -LiteralPath $k -Name PendingFileRenameOperations -ErrorAction SilentlyContinue }
    }
    return $found
}

# ---- cleanup -------------------------------------------------------------------------------------------------------------

function Remove-Tree([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    try { [IO.Directory]::Delete($path, $true) } catch {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# What this run added under Program Files by name: the install folders, the staging and the uninstaller's.
function New-ProgramFilesDirs {
    return @(Get-ChildItem $pf -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
            $pfBefore -notcontains $_.Name -and ($_.Name -like "Lunepack E2E Machine $hex*" -or $_.Name -match '^\.lunepack-(install|uninstall)-[0-9a-f]{32}$')
        })
}

function Write-Diagnostics {
    if ($script:lastUser) { Write-Output "     last command of the standard user: $($script:lastUser)" }
    # Names, versions and fixed lines only (the service's log is fixed text by construction).
    foreach ($app in @($apps | Where-Object { $_.Root })) {
        $log = Join-Path $app.Root '.lunepack\logs\service.log'
        if (Test-Path -LiteralPath $log) {
            Write-Output "     service log (last lines): $((@(Read-Lines $log) | Select-Object -Last 6) -join ' | ')"
        }
        $r = Get-Record $app.Root
        if ($r) {
            $p = if ($r.pending) { "$($r.pending.version)/$($r.pending.attempts)" } else { 'none' }
            Write-Output "     record: current $($r.current.version) pending $p bad [$(@($r.bad) -join ',')]"
        }
    }
}

function Remove-Everything {
    foreach ($app in $apps) {
        if (-not $app.Root) { continue }
        Stop-Under $app.Root
    }
    foreach ($app in $apps | Select-Object -First 1) {
        $name = $app.ServiceName
        if ((Service-State $name) -ne 'MISSING') {
            Native 'sc.exe' @('stop', $name) | Out-Null
            Start-Sleep -Seconds 1
            Native 'sc.exe' @('delete', $name) | Out-Null
        }
        Native 'reg.exe' @('delete', "HKLM\SOFTWARE\Policies\lunepack\$($app.Id)", '/f') | Out-Null
        Remove-Item -LiteralPath (Join-Path $uninstallKeyRoot $app.Id) -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Common-Shortcut $app) -Force -ErrorAction SilentlyContinue
        if ($app.Name -ne $app.BaseName) { Remove-Item -LiteralPath (Join-Path $commonPrograms "$($app.BaseName).lnk") -Force -ErrorAction SilentlyContinue }
    }
    if ($madePolicyParent) { Native 'reg.exe' @('delete', 'HKLM\SOFTWARE\Policies\lunepack', '/f') | Out-Null }
    foreach ($d in New-ProgramFilesDirs) {
        Stop-Under $d.FullName
        Remove-Tree $d.FullName
    }
    $null = Pending-Deletes -Remove
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -in @('machine_probe') })) {
        $path = $null
        try { $path = $p.Path } catch { }
        if ($path -and $path.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { try { Stop-Process -Id $p.Id -Force } catch { } }
    }
    foreach ($d in Get-ChildItem $tempRoot -Directory -ErrorAction SilentlyContinue) {
        if ($tempBefore -notcontains $d.Name -and $d.Name -match '^lunepack-(uninstall|setup-ui|setup)-[0-9a-f]{16}$') {
            Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Stop-Under $work
    Remove-Tree $work
    if ($user) {
        # Anything the user left running holds its profile loaded.
        foreach ($p in @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like "*\$($user.Name)" })) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
        Start-Sleep -Seconds 2
    }
    Remove-Tree $base
    Remove-StandardUser $user
    Remove-Tree $base
}

# What is left of everything this script made, by name only.
function Find-Leftovers {
    $left = @()
    foreach ($app in $apps | Select-Object -First 1) {
        if ($app.Root -and (Test-Path -LiteralPath $app.Root)) { $left += 'the install folder' }
        if ((Service-State $app.ServiceName) -ne 'MISSING') { $left += 'the service' }
        if (Test-Path -LiteralPath (Join-Path $uninstallKeyRoot $app.Id)) { $left += 'the uninstall key' }
        if (Test-Path -LiteralPath "$policyParent\$($app.Id)") { $left += 'the policy key' }
        if (Test-Path -LiteralPath (Common-Shortcut $app)) { $left += 'the shortcut' }
    }
    foreach ($d in New-ProgramFilesDirs) { $left += "a folder named $($d.Name)" }
    if (Test-Path -LiteralPath $base) { $left += 'the work folder' }
    if ($madePolicyParent -and (Test-Path -LiteralPath $policyParent)) { $left += 'the policy parent key' }
    if ((Pending-Deletes) -gt 0) { $left += 'a delete-at-restart entry' }
    if ($user) {
        if (Get-LocalUser -Name $user.Name -ErrorAction SilentlyContinue) { $left += 'the standard user' }
        if (Test-Path -LiteralPath (Join-Path $env:SystemDrive "Users\$($user.Name)")) { $left += 'the user profile folder' }
    }
    return $left
}

# ---- the work -----------------------------------------------------------------------------------------------------------------

$runInstall = $Install -and $isAdmin
try {
    if ($Install -and -not $isAdmin) {
        if ($env:CI -eq 'true') { throw 'the install rows need an administrator and this session is not one' }
        Write-Output 'e2e-windows-machine: not an administrator: the install rows are skipped'
    }
    Write-Output 'e2e-windows-machine: building'
    Push-Location $repo
    try {
        cargo build --locked --release -p lunepack-cli -p lunepack-runtime -p lunepack-stub -p lunepack-service
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
        cargo build --locked --release -p lunepack --example e2e_app
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (example) failed' }
        cargo build --locked --release -p lunepack-runtime --example e2e_fake_ui
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (stand-in UI) failed' }
        cargo build --locked -p lunepack-os-windows --example machine_probe
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (machine_probe) failed' }
    } finally { Pop-Location }
    $cli = Join-Path $rel 'lunepack.exe'
    $runtime = Join-Path $rel 'lunepack-runtime.exe'
    $stub = Join-Path $rel 'lunepack-stub.exe'
    $service = Join-Path $rel 'lunepack-service.exe'
    $appExe = Join-Path $rel 'examples\e2e_app.exe'
    $fakeUi = Join-Path $rel 'examples\e2e_fake_ui.exe'
    $probeExe = Join-Path $tdir 'debug\examples\machine_probe.exe'
    foreach ($f in $cli, $runtime, $stub, $service, $appExe, $fakeUi, $probeExe) { Require (Test-Path $f) 'a built file exists' }

    # The folders: `work` (batch files; the user reads them), `out` (the user writes), `feeds` and
    # the Setup copies (the user reads them). Admin-owned, nothing inherited from ProgramData.
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    New-Item -ItemType Directory $work | Out-Null
    if ($runInstall) {
        Set-DirAcl $base $grants
        & icacls.exe $base /grant '*S-1-5-32-545:RX' | Out-Null
        Set-DirAcl $workDir ($grants + '*S-1-5-32-545:(OI)(CI)RX')
        Set-DirAcl $outDir ($grants + '*S-1-5-32-545:(OI)(CI)M')
        Set-DirAcl $feeds ($grants + '*S-1-5-32-545:(OI)(CI)RX')
    } else {
        New-Item -ItemType Directory -Force $base, $feeds | Out-Null
    }

    $M = New-App 'm' "lpm$hex.exe" $appExe $fakeUi
    # Two payload files of random bytes: a new file in a version is an object the user's download holds.
    $payloadA = Join-Path $work 'payload-a.bin'
    $payloadB = Join-Path $work 'payload-b.bin'
    $rng = New-Object byte[] 196608
    (New-Object Random 7).NextBytes($rng)
    [IO.File]::WriteAllBytes($payloadA, $rng)
    (New-Object Random 11).NextBytes($rng)
    [IO.File]::WriteAllBytes($payloadB, $rng)
    # The delta row's second file (M12 step 7): payload A with 16 bytes of its middle changed, so a
    # patch from A is a few dozen bytes against a frame of the file's size.
    $payloadDelta = Join-Path $work 'payload-delta.bin'
    $changed = [IO.File]::ReadAllBytes($payloadA)
    foreach ($i in 0..15) { $changed[98304 + $i] = [byte]($changed[98304 + $i] -bxor 0x5A) }
    [IO.File]::WriteAllBytes($payloadDelta, $changed)
    Publish-Version $M '1.0.0'
    $setup = Build-Setup $M '1.0.0' (Join-Path $work 'setup-1.0.0')

    # ---- rows that install nothing ---------------------------------------------------------------------------------------
    Row 'static: the packager places the service, the image rules hold' {
        Same 'service subsystem' (PeSubsystem $service) 3
        Same 'runtime subsystem' (PeSubsystem $runtime) 2
        Same 'Setup subsystem' (PeSubsystem $setup) 2
        $v = (Get-Item $setup).VersionInfo
        Same 'Setup FileDescription' $v.FileDescription "$($M.BaseName) Setup"
        SameV 'Setup ProductVersion' $v.ProductVersion '1.0.0'
        # The release's signed manifest lists the service beside the entry (Windows has no exec bit:
        # every entry is `exec: false`).
        $manifest = Doc-Payload (Join-Path $M.Rel '1.0.0\windows-x86_64.manifest.json')
        $entry = @($manifest.entries | Where-Object { $_.path -eq 'lunepack-service.exe' })
        Require ($entry.Count -eq 1) 'the signed manifest lists lunepack-service.exe once'
    }
    Row 'static: planted DLLs (garbage-file form): the service, its self-test, the machine-install mode' {
        $cases = @(
            "service=$service=",
            "service-self-test=$service=--self-test",
            "setup-machine-install=$setup=machine-install --events 00 --for-sid S-1-5-0")
        $out = & (Join-Path $PSScriptRoot 'ci\plant-dll-test.ps1') -Case $cases
        $out | ForEach-Object { Write-Output "     $_" }
        Require ($LASTEXITCODE -eq 0) 'no planted DLL breaks a start'
    }
    Write-Output 'skipped: Setup.exe started through "Run as administrator" without --all-users (the fixed message box, standing UacElevated): an administrator on a hosted runner holds no split token (A5); it is a row of scripts/windows-machine-user-check.ps1'

    if (-not $runInstall) {
        Write-Output 'skipped: the install rows 1 to 12 (they install for all users into the real Program Files and create a local user; they run on CI as an administrator, or with -Install or LUNEPACK_E2E_INSTALL=1 as an administrator on a disposable machine)'
    } else {
        $user = New-StandardUser -Prefix 'lpe2em'
        Write-Output "standard user created: $($user.Name)"
        $probeCopy = Join-Path $workDir 'machine_probe.exe'
        Copy-Item -LiteralPath $probeExe -Destination $probeCopy
        # Whether the standard user opens the service manager, by logon kind (F12).
        Write-ScmOpenReport -User $user -Probe $probeCopy -AppId $M.Id -WorkDir $workDir -OutDir $outDir -WithProfile
        $M.Root = Join-Path $pf $M.BaseName
        Require (-not (Test-Path -LiteralPath $M.Root)) 'no earlier install of this unique name'
        $key = Join-Path $uninstallKeyRoot $M.Id
        $stubM = Stub-Path $M
        # The publisher of another root for the same app id (row 6).
        $evil = New-App 'x' "lpm$hex.exe" $appExe $fakeUi $M.Id
        Publish-Version $evil '9.0.0'

        # ---- row 1 --------------------------------------------------------------------------------------------------------
        Row '1 (silent machine install by the administrator, beside planted DLL files)' {
            $copy = New-PlantedCopy $setup 'row1'
            $r = Run-Tool $copy @('/S', '--all-users')
            if (Test-LoaderFailure $r.Code) { throw "Setup ended with a loader failure (0x$('{0:X8}' -f $r.Code)) beside the planted files" }
            SameV 'setup exit code' $r.Code 0
            Assert-Installed $M '1.0.0'
            # The standard user can read the tree and cannot write under R.
            $u = AsUser 'r1-list' @("dir `"$($M.Root)`" >> `"%OUT%`" 2>&1")
            SameV 'the user lists R (exit code)' $u.ExitCode 0
            AsUser 'r1-create' @("echo x > `"$($M.Root)\new.txt`" 2>> `"%OUT%`"") | Out-Null
            Require (-not (Test-Path -LiteralPath (Join-Path $M.Root 'new.txt'))) 'the standard user cannot create a file under R'
            AsUser 'r1-mkdir' @("mkdir `"$($M.Root)\newdir`" >> `"%OUT%`" 2>&1") | Out-Null
            Require (-not (Test-Path -LiteralPath (Join-Path $M.Root 'newdir'))) 'the standard user cannot create a folder under R'
            $u = AsUser 'r1-machine' @("dir `"$($M.Root)\.lunepack\machine`" >> `"%OUT%`" 2>&1")
            Require ($u.ExitCode -ne 0) 'the standard user cannot list the admin-only folder'
        }

        # ---- row 2 --------------------------------------------------------------------------------------------------------
        Row '2 (the standard user starts the app and updates it with no prompt, no elevation)' {
            $o = New-Out 'row2a'
            $null = UStart 'r2-start' $stubM '' $o
            Expect-Lines $o @('1.0.0 start', '1.0.0 event first_run', '1.0.0 nothing-pending')
            Require (Test-Path -LiteralPath (Join-Path (User-Home $M) 'state')) "the user's own state folder exists"
            Publish-Version $M '1.1.0' @{ Files = @{ 'payload.bin' = $payloadA } }
            $o = New-Out 'row2b'
            $null = UStart 'r2-update' $stubM '--update --no-ui' $o
            Expect-Lines $o (Confirmed-Lines '1.0.0' '1.1.0')
            Wait-Updated $M '1.1.0'
            Assert-Record $M '1.1.0' '1.0.0' @()
            # Every file of the new tree is readable and executable by the standard user.
            $u = AsUser 'r2-read' @("for /r `"$($M.Root)\app\1.1.0`" %%f in (*) do type `"%%f`" >nul 2>&1 || echo unreadable>>`"%OUT%`"")
            Require ($u.Output -notmatch 'unreadable') "the standard user reads every file of the new tree ($($u.Output))"
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $M.Root 'app\1.1.0') -Recurse -File -Include *.exe, *.dll)) {
                $users = @((Get-Acl -LiteralPath $f.FullName).Access | Where-Object { (Sid-Of $_.IdentityReference) -eq $usersSid -and $_.AccessControlType -eq 'Allow' })
                Require (@($users | Where-Object { ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile) -ne 0 }).Count -ge 1) "Users may execute $($f.Name)"
            }
            Assert-Protected (Join-Path $M.Root 'app\1.1.0') 'machine'
            # The service's registered image follows the confirm.
            Wait-Until { "$(Service-Image $M)" -like '*\service\1.1.0\lunepack-service.exe' } 60 "the service's image to be 1.1.0's"
            Assert-ServiceRegistered $M '1.1.0'
        }

        # ---- row 3 --------------------------------------------------------------------------------------------------------
        Row '3 (the same update through the runtime command line, --json)' {
            Publish-Version $M '1.2.0' @{ Files = @{ 'payload.bin' = $payloadA } }
            Save-Docs $M '1.2.0' (Join-Path $outDir 'docs-1.2.0')
            $rt = Join-Path $M.Root 'app\1.1.0\lunepack-runtime.exe'
            $c = URun 'r3-check' $rt 'check --json'
            SameV 'check exit code' $c.ExitCode 0
            $last = @($c.Output -split "`n")[-1]
            Require ($last -match '"type":"result"' -and $last -match '"command":"check"' -and $last -match '"version":"1.2.0"') "check ends with its result and offers 1.2.0: $last"
            $d = URun 'r3-download' $rt 'download --json --expect-version 1.2.0'
            SameV 'download exit code' $d.ExitCode 0
            Require (@($d.Output -split "`n")[-1] -match '"staged":true') 'download stages the update'
            $o = New-Out 'row3'
            $a = URun 'r3-apply' $rt 'apply-and-restart --json --expect-version 1.2.0 -- --after-update' $o
            SameV 'apply-and-restart exit code' $a.ExitCode 0
            Require (@($a.Output -split "`n")[-1] -match '"scheduled":true') 'apply-and-restart schedules the apply'
            Expect-Lines $o @('1.2.0 start', '1.2.0 arg after-update', '1.2.0 event updated 1.1.0', '1.2.0 event first_run', '1.2.0 confirmed')
            Wait-Updated $M '1.2.0'
            Assert-Record $M '1.2.0' '1.1.0' @()
            $rt2 = Join-Path $M.Root 'app\1.2.0\lunepack-runtime.exe'
            $s = URun 'r3-startup' $rt2 'startup --json'
            SameV 'startup exit code' $s.ExitCode 0
            Require (@($s.Output -split "`n")[-1] -match '"action":"continue"') 'startup says to go on'
            $cf = URun 'r3-confirm' $rt2 'confirm --json'
            SameV 'confirm exit code' $cf.ExitCode 0
            Require (@($cf.Output -split "`n")[-1] -match '"outcome":"nothing_pending"') 'confirm finds nothing pending'
            $k = URun 'r3-check2' $rt2 'check --json'
            SameV 'second check exit code' $k.ExitCode 0
            Require (@($k.Output -split "`n")[-1] -match '"update":null') 'nothing is offered after the update'
        }

        # ---- row 4 --------------------------------------------------------------------------------------------------------
        Row '4 (a version that crashes on start is rolled back through the token, marked bad, not offered again)' {
            Publish-Version $M '1.3.0' @{ Flags = @('crash-on-start') }
            $o = New-Out 'row4a'
            $null = UStart 'r4a' $stubM '--update --no-ui' $o
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.3.0', '1.2.0 staged 1.3.0', '1.2.0 apply-scheduled',
                '1.3.0 start', '1.3.0 arg after-update', '1.3.0 event updated 1.2.0', '1.3.0 event first_run', '1.3.0 crash',
                '1.2.0 start', '1.2.0 arg after-update', '1.2.0 nothing-pending')
            Wait-Runtimes-Gone $M
            Assert-Record $M '1.2.0' $null @('1.3.0')
            $o = New-Out 'row4b'
            $null = UStart 'r4b' $stubM '--update --no-ui' $o
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check none')
        }

        Row '4 (a version that confirms too slowly is rolled back)' {
            Publish-Version $M '1.4.0' @{ Flags = @('slow-confirm 60'); Timeout = 5 }
            $o = New-Out 'row4c'
            $null = UStart 'r4c' $stubM '--update --no-ui' $o
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.4.0', '1.2.0 staged 1.4.0', '1.2.0 apply-scheduled',
                '1.4.0 start', '1.4.0 arg after-update', '1.4.0 event updated 1.2.0', '1.4.0 event first_run', '1.4.0 slow-confirm',
                '1.2.0 start', '1.2.0 arg after-update', '1.2.0 nothing-pending') -Seconds 150
            Wait-Runtimes-Gone $M
            Assert-Record $M '1.2.0' $null @('1.3.0', '1.4.0')
        }

        # ---- row 5 --------------------------------------------------------------------------------------------------------
        # The lease of a pending version is its health timeout (10 s) plus 15 s; a start is counted
        # only when no lease runs, so the starts below are spaced past it.
        Row '5 (the supervisor killed: starts inside the lease are not counted, three past it are, the fourth rolls back)' {
            Publish-Version $M '1.5.0' @{ Flags = @('exit-without-confirm'); Timeout = 10 }
            $o = New-Out 'row5a'
            $null = UStart 'r5a' $stubM '--update --no-ui' $o
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.5.0', '1.2.0 staged 1.5.0', '1.2.0 apply-scheduled',
                '1.5.0 start', '1.5.0 arg after-update', '1.5.0 event updated 1.2.0', '1.5.0 event first_run', '1.5.0 exit-without-confirm')
            $seen = Get-Date
            Wait-Until { @(Get-Runtimes $M).Count -ge 1 } 30 'a runtime in apply mode'
            foreach ($p in @(Get-Runtimes $M)) { Stop-Process -Id $p.Id -Force }
            Wait-Runtimes-Gone $M
            Assert-Record $M '1.5.0' '1.2.0' @('1.3.0', '1.4.0') @('1.5.0', 0)
            # Inside the lease: the service answers `supervised`, nothing is counted.
            $o = New-Out 'row5b'
            $null = UStart 'r5b' $stubM '' $o
            Expect-Lines $o @('1.5.0 start', '1.5.0 exit-without-confirm')
            Assert-Record $M '1.5.0' '1.2.0' @('1.3.0', '1.4.0') @('1.5.0', 0)
            # A wrong token confirms nothing and rolls nothing back, while this update is pending.
            $o = New-Out 'row5c'
            $pr = URun 'r5c' (Join-Path $M.Root "app\1.2.0\$($M.EntryFile)") '--service-probe wrong-token' $o
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 probe wrong-token confirm token_mismatch', '1.2.0 probe wrong-token rollback token_mismatch', '1.2.0 probe wrong-token still-pending=True') -Seconds 60
            Assert-Record $M '1.5.0' '1.2.0' @('1.3.0', '1.4.0') @('1.5.0', 0)
            # Past the lease, each unsupervised start counts one attempt. The user's `last_run` is
            # the tree the probe just ran from (1.2.0), so the first of these starts of 1.5.0
            # delivers its events again (M10-D16: a lower `last_run` gives `updated` and `first_run`).
            foreach ($attempt in 1..3) {
                Start-Sleep -Seconds ([Math]::Max(1, [int](28 - ((Get-Date) - $seen).TotalSeconds)))
                $o = New-Out "row5d$attempt"
                $null = UStart "r5d$attempt" $stubM '' $o
                if ($attempt -eq 1) {
                    Expect-Lines $o @('1.5.0 start', '1.5.0 event updated 1.2.0', '1.5.0 event first_run', '1.5.0 exit-without-confirm')
                } else {
                    Expect-Lines $o @('1.5.0 start', '1.5.0 exit-without-confirm')
                }
                $seen = Get-Date
                Assert-Record $M '1.5.0' '1.2.0' @('1.3.0', '1.4.0') @('1.5.0', $attempt)
            }
            # The fourth rolls back in the service and starts 1.2.0 in its place.
            Start-Sleep -Seconds ([Math]::Max(1, [int](28 - ((Get-Date) - $seen).TotalSeconds)))
            $o = New-Out 'row5e'
            $null = UStart 'r5e' $stubM '' $o
            Expect-Lines $o @('1.5.0 start', '1.5.0 exit rolled-back', '1.2.0 start', '1.2.0 nothing-pending') -Unordered
            Assert-Record $M '1.2.0' $null @('1.3.0', '1.4.0', '1.5.0')
        }

        Row '5 (control: a healthy version whose first run did not confirm confirms through `attempt`)' {
            Publish-Version $M '1.6.0' @{ Timeout = 10 }
            $o = New-Out 'row5f'
            $null = UStart 'r5f' $stubM '--update --no-ui' $o @{ LUNEPACK_E2E_NO_CONFIRM = '1.6.0' }
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.6.0', '1.2.0 staged 1.6.0', '1.2.0 apply-scheduled',
                '1.6.0 start', '1.6.0 arg after-update', '1.6.0 event updated 1.2.0', '1.6.0 event first_run', '1.6.0 exit-without-confirm')
            $seen = Get-Date
            Wait-Until { @(Get-Runtimes $M).Count -ge 1 } 30 'a runtime in apply mode'
            foreach ($p in @(Get-Runtimes $M)) { Stop-Process -Id $p.Id -Force }
            Wait-Runtimes-Gone $M
            Assert-Record $M '1.6.0' '1.2.0' @('1.3.0', '1.4.0', '1.5.0') @('1.6.0', 0)
            Start-Sleep -Seconds ([Math]::Max(1, [int](28 - ((Get-Date) - $seen).TotalSeconds)))
            $o = New-Out 'row5g'
            $null = UStart 'r5g' $stubM '' $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 confirmed')
            Assert-Record $M '1.6.0' '1.2.0' @('1.3.0', '1.4.0', '1.5.0')
        }

        # ---- row 6 --------------------------------------------------------------------------------------------------------
        # The current version is 1.6.0 and nothing is pending. Every negative is asked of the real
        # service as the standard user; the positive controls are in the same row.
        Row '6 (negatives as the standard user: a flipped byte, another root, an older feed, garbage, an oversize frame, sc.exe, writes under R)' {
            $app16 = Join-Path $M.Root "app\1.6.0\$($M.EntryFile)"
            $recBefore = Get-Record $M.Root
            # (a) one byte of the upload flipped between the download and the stage: the service refuses
            # the object, nothing is staged, no session folder is left under the staging directory. The
            # library drops a refused object from the user's cache and fetches it again (F2), so the
            # release's pack is moved aside for the stage: the refetch fails and the stage ends with an
            # error. The damaged entry gone from the cache is the trace of the service's refusal (only a
            # put answered hash_mismatch or size_mismatch removes it).
            Publish-Version $M '1.7.0' @{ Files = @{ 'payload.bin' = $payloadB } }
            Save-Docs $M '1.7.0' (Join-Path $outDir 'docs-1.7.0')
            $pack17 = Join-Path $M.Rel '1.7.0\windows-x86_64.pack'
            $packAway = "$pack17.away"
            Require (Test-Path -LiteralPath $pack17) 'the release of 1.7.0 holds its pack'
            $go = Join-Path $outDir 'go-flip'
            Remove-Item -LiteralPath $go -Force -ErrorAction SilentlyContinue
            $o = New-Out 'row6a'
            $null = UStart 'r6a' $stubM "--update --no-ui --stage-after `"$go`"" $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 check 1.7.0', '1.6.0 downloaded')
            $cache = Join-Path (User-Home $M) 'cache'
            $big = @(Get-ChildItem -LiteralPath $cache -Recurse -File -Force | Sort-Object Length -Descending | Select-Object -First 1)
            Require ($big.Count -eq 1 -and $big[0].Length -gt 1000) 'the download holds a file to change'
            $bytes = [IO.File]::ReadAllBytes($big[0].FullName)
            $bytes[[int]($bytes.Length / 2)] = $bytes[[int]($bytes.Length / 2)] -bxor 0xFF
            [IO.File]::WriteAllBytes($big[0].FullName, $bytes)
            Move-Item -LiteralPath $pack17 -Destination $packAway
            try {
                New-Item -ItemType File $go | Out-Null
                Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 check 1.7.0', '1.6.0 downloaded', '1.6.0 error stage')
            } finally {
                Move-Item -LiteralPath $packAway -Destination $pack17
            }
            Require (-not (Test-Path -LiteralPath $big[0].FullName)) 'the object the service refused is gone from the user''s cache'
            $r = Get-Record $M.Root
            Require ($null -eq $r.staged) 'nothing is staged after the flipped byte'
            Assert-Record $M '1.6.0' '1.2.0' @('1.3.0', '1.4.0', '1.5.0')
            $incoming = Join-Path $M.Root '.lunepack\machine\incoming'
            SameV 'session folders under incoming' @(Get-ChildItem -LiteralPath $incoming -Force -ErrorAction SilentlyContinue).Count 0
            # The later rows start from a clean cache.
            Remove-Item -LiteralPath $cache -Recurse -Force

            # (b) documents of another publisher (another root) for this app: refused as a signature failure.
            $evilDocs = Join-Path $outDir 'docs-evil'
            Save-Docs $evil '9.0.0' $evilDocs
            $o = New-Out 'row6b'
            $null = URun 'r6b' $app16 "--service-probe stage-docs --docs `"$evilDocs`"" $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe stage-docs refused verify_failed signature') -Seconds 60
            # The control in the same row: this publisher's own documents of 1.7.0 are accepted.
            $o = New-Out 'row6c'
            $null = URun 'r6c' $app16 "--service-probe stage-docs --docs `"$(Join-Path $outDir 'docs-1.7.0')`"" $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe stage-docs ready 1.7.0') -Seconds 60

            # (c) the feed of 1.2.0, replayed: older than the floor the machine record holds.
            $o = New-Out 'row6d'
            $null = URun 'r6d' $app16 "--service-probe stage-docs --docs `"$(Join-Path $outDir 'docs-1.2.0')`"" $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe stage-docs refused verify_failed rollback') -Seconds 60

            # (d) garbage in place of the hello, and a frame of 2 MiB: the connection is closed and the service serves on.
            $o = New-Out 'row6e'
            $null = URun 'r6e' $app16 '--service-probe garbage' $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe garbage closed=True', '1.6.0 probe garbage serving') -Seconds 90
            $o = New-Out 'row6f'
            $null = URun 'r6f' $app16 '--service-probe oversize' $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe oversize closed=True', '1.6.0 probe oversize serving') -Seconds 90

            # (e) the user cannot reconfigure the service or write under R.
            foreach ($case in @(
                    @('config', "sc.exe config $($M.ServiceName) binPath= C:\Windows\System32\cmd.exe"),
                    @('stop', "sc.exe stop $($M.ServiceName)"),
                    @('delete', "sc.exe delete $($M.ServiceName)"))) {
                $u = AsUser "r6-sc-$($case[0])" @("$($case[1]) >> `"%OUT%`" 2>&1")
                SameV "sc $($case[0]) by the standard user (exit code, access denied)" $u.ExitCode 5
            }
            AsUser 'r6-write' @("echo x > `"$($M.Root)\app\1.6.0\new.txt`" 2>> `"%OUT%`"", "echo x > `"$($M.Root)\.lunepack\state\new.rec`" 2>> `"%OUT%`"") | Out-Null
            Require (-not (Test-Path -LiteralPath (Join-Path $M.Root 'app\1.6.0\new.txt'))) 'the user cannot write into a version tree'
            Require (-not (Test-Path -LiteralPath (Join-Path $M.Root '.lunepack\state\new.rec'))) 'the user cannot write into the state folder'
            # None of it changed the install.
            Assert-Record $M '1.6.0' '1.2.0' @('1.3.0', '1.4.0', '1.5.0')
            Assert-ServiceRegistered $M '1.6.0'
        }

        # ---- row 7 --------------------------------------------------------------------------------------------------------
        Row '7 (a pipe the standard user created first is refused; updates work again when it is gone)' {
            $rt = Join-Path $M.Root 'app\1.6.0\lunepack-runtime.exe'
            Stop-AppService $M
            $ready = Join-Path $outDir 'squat-r7.ready'
            Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
            $null = UStart 'r7-squat' $probeCopy "squat $($M.PipeName) 120 `"$ready`"" (New-Out 'row7-squat')
            Wait-Until { Test-Path -LiteralPath $ready } 30 'the squatter to hold the pipe name'
            $d = URun 'r7-download' $rt 'download --json --expect-version 1.7.0'
            SameV 'download exit code (the pipe is not the service)' $d.ExitCode 32
            $last = @($d.Output -split "`n")[-1]
            Require ($last -match '"kind":"service_unavailable"' -and $last -match '"reason":"untrusted"') "the error names service_unavailable and untrusted: $last"
            foreach ($p in @(Get-Process -Name 'machine_probe' -ErrorAction SilentlyContinue)) {
                $path = $null
                try { $path = $p.Path } catch { }
                if ($path -and $path.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { Stop-Process -Id $p.Id -Force }
            }
            Wait-Until { @(Get-Process -Name 'machine_probe' -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -like "$base*" } catch { $false } }).Count -eq 0 } 30 'the squatter to end'
            $d = URun 'r7-download2' $rt 'download --json --expect-version 1.7.0'
            SameV 'download exit code (the pipe is gone)' $d.ExitCode 0
            Require (@($d.Output -split "`n")[-1] -match '"staged":true') 'the update is staged once the pipe is the service again'
        } -Undo { foreach ($p in @(Get-Process -Name 'machine_probe' -ErrorAction SilentlyContinue)) { try { Stop-Process -Id $p.Id -Force } catch { } } }

        # ---- row 8 --------------------------------------------------------------------------------------------------------
        Row '8 (the policy: DisableSelfUpdate answers 33 and the service refuses; NoUpdateUi shows no update window)' {
            $pk = "$policyParent\$($M.Id)"
            if (-not (Test-Path -LiteralPath $policyParent)) { $script:madePolicyParent = $true }
            $rt = Join-Path $M.Root 'app\1.6.0\lunepack-runtime.exe'
            $app16 = Join-Path $M.Root "app\1.6.0\$($M.EntryFile)"
            Native 'reg.exe' @('add', "HKLM\SOFTWARE\Policies\lunepack\$($M.Id)", '/v', 'DisableSelfUpdate', '/t', 'REG_DWORD', '/d', '1', '/f') | Out-Null
            $c = URun 'r8-check' $rt 'check --json'
            SameV 'check exit code (policy)' $c.ExitCode 33
            Require (@($c.Output -split "`n")[-1] -match '"kind":"disabled_by_policy"') 'the error names disabled_by_policy'
            $o = New-Out 'row8a'
            $null = URun 'r8-stage' $app16 "--service-probe stage-docs --docs `"$(Join-Path $outDir 'docs-1.7.0')`"" $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe stage-docs refused disabled_by_policy') -Seconds 60
            Native 'reg.exe' @('delete', "HKLM\SOFTWARE\Policies\lunepack\$($M.Id)", '/v', 'DisableSelfUpdate', '/f') | Out-Null
            $c = URun 'r8-check2' $rt 'check --json'
            SameV 'check exit code (policy removed)' $c.ExitCode 0
            $o = New-Out 'row8b'
            $null = URun 'r8-stage2' $app16 "--service-probe stage-docs --docs `"$(Join-Path $outDir 'docs-1.7.0')`"" $o
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending', '1.6.0 probe stage-docs ready 1.7.0') -Seconds 60
            # NoUpdateUi: the update goes through and no update window process is started; without it one is.
            Native 'reg.exe' @('add', "HKLM\SOFTWARE\Policies\lunepack\$($M.Id)", '/v', 'NoUpdateUi', '/t', 'REG_DWORD', '/d', '1', '/f') | Out-Null
            $ui1 = Join-Path $outDir 'ui-r8a'
            New-Item -ItemType Directory -Force $ui1 | Out-Null
            $o = New-Out 'row8c'
            $null = UStart 'r8-noui' $stubM '--update' $o @{ LUNEPACK_E2E_UI_DIR = $ui1 }
            Expect-Lines $o (Confirmed-Lines '1.6.0' '1.7.0')
            Wait-Updated $M '1.7.0'
            SameV 'update windows started under NoUpdateUi' (@(Read-Lines (Join-Path $ui1 'ui-spawns'))).Count 0
            Native 'reg.exe' @('delete', "HKLM\SOFTWARE\Policies\lunepack\$($M.Id)", '/f') | Out-Null
            Publish-Version $M '1.8.0'
            $ui2 = Join-Path $outDir 'ui-r8b'
            New-Item -ItemType Directory -Force $ui2 | Out-Null
            $o = New-Out 'row8d'
            $null = UStart 'r8-ui' $stubM '--update' $o @{ LUNEPACK_E2E_UI_DIR = $ui2 }
            Expect-Lines $o (Confirmed-Lines '1.7.0' '1.8.0')
            Wait-Updated $M '1.8.0'
            SameV 'update windows started without the policy' (@(Read-Lines (Join-Path $ui2 'ui-spawns'))).Count 1
        } -Undo { Native 'reg.exe' @('delete', "HKLM\SOFTWARE\Policies\lunepack\$($M.Id)", '/f') | Out-Null }

        # ---- row 11 -------------------------------------------------------------------------------------------------------
        # The current version is 1.8.0 (previous 1.7.0). A process of the user runs from the tree of 1.7.0
        # while two more updates are confirmed: the first leaves 1.7.0 outside "current and previous", but
        # the removal guard keeps it, whole; after the process ends, the next update collects it.
        Row '11 (a service switch serves the next update; an old tree is kept while the user runs from it and removed after)' {
            $tree17 = Join-Path $M.Root 'app\1.7.0'
            $holdOut = New-Out 'hold11'
            $null = UStart 'r11-hold' (Join-Path $tree17 $M.EntryFile) '--hold 900' $holdOut
            Expect-Lines $holdOut @('1.7.0 start', '1.7.0 nothing-pending', '1.7.0 hold')
            $listing = Tree-Listing $tree17
            Require ($listing.Length -gt 0) 'the old tree has files'
            Publish-Version $M '1.9.0'
            # The registered image is 1.8.0's now; with the service stopped, the user's start runs it.
            Wait-Until { "$(Service-Image $M)" -like '*\service\1.8.0\lunepack-service.exe' } 60 "the service's image to be 1.8.0's"
            Stop-AppService $M
            $o = New-Out 'row11a'
            $null = URun 'r11-status' (Join-Path $M.Root "app\1.8.0\$($M.EntryFile)") '--service-probe status' $o
            # (The user ran the 1.7.0 tree last, so this first start of 1.8.0 delivers its events.)
            Expect-Lines $o @('1.8.0 start', '1.8.0 event updated 1.7.0', '1.8.0 event first_run', '1.8.0 nothing-pending', '1.8.0 probe status current=1.8.0 pending=none staged=none service=1.8.0 disabled=false') -Seconds 60
            $o = New-Out 'row11b'
            $null = UStart 'r11-update' $stubM '--update --no-ui' $o
            Expect-Lines $o (Confirmed-Lines '1.8.0' '1.9.0')
            Wait-Updated $M '1.9.0'
            # After the GC of that confirm: 1.7.0 is kept, every file of it present, and no collection folder holds any of them.
            SameV 'the old tree after the collection' (Tree-Listing $tree17) $listing
            $gc = @(Get-ChildItem -LiteralPath (Join-Path $M.Root 'app') -Directory -Force -Filter '.gc-*')
            SameV 'collection folders holding files' (@($gc | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Force }).Count) 0
            Require ((App-Versions $M) -contains '1.7.0') 'the tree of 1.7.0 is still there'
            # The service switched at the confirm: the next start of it runs 1.9.0's binary.
            Wait-Until { "$(Service-Image $M)" -like '*\service\1.9.0\lunepack-service.exe' } 60 "the service's image to be 1.9.0's"
            Stop-AppService $M
            $o = New-Out 'row11c'
            $null = URun 'r11-status2' (Join-Path $M.Root "app\1.9.0\$($M.EntryFile)") '--service-probe status' $o
            Expect-Lines $o @('1.9.0 start', '1.9.0 nothing-pending', '1.9.0 probe status current=1.9.0 pending=none staged=none service=1.9.0 disabled=false') -Seconds 60
            # The process ends: the next update collects the old tree, and no collection folder is left.
            foreach ($p in @(Get-ProcsUnder $tree17)) { Stop-Process -Id $p.Id -Force }
            Wait-Until { @(Get-ProcsUnder $tree17).Count -eq 0 } 30 'the process of 1.7.0 to end'
            Publish-Version $M '1.10.0'
            $o = New-Out 'row11d'
            $null = UStart 'r11-update2' $stubM '--update --no-ui' $o
            Expect-Lines $o (Confirmed-Lines '1.9.0' '1.10.0')
            Wait-Updated $M '1.10.0'
            Wait-Until { ((App-Versions $M) -join ',') -eq '1.10.0,1.9.0' } 60 'the old trees to be collected'
            SameV 'collection folders left' @(Get-ChildItem -LiteralPath (Join-Path $M.Root 'app') -Directory -Force -Filter '.gc-*').Count 0
        }

        # ---- row 11b ------------------------------------------------------------------------------------------------------
        Row '11b (an update by delta through the service, protocol version 2: the changed file arrives as a patch)' {
            # 1.10.1 brings payload.bin whole; 1.10.2 changes 16 bytes of it.
            Publish-Version $M '1.10.1' @{ Files = @{ 'payload.bin' = $payloadA } }
            $o = New-Out 'row11e'
            $null = UStart 'r11e-update' $stubM '--update --no-ui' $o
            Expect-Lines $o (Confirmed-Lines '1.10.0' '1.10.1')
            Wait-Updated $M '1.10.1'
            Publish-Version $M '1.10.2' @{ Files = @{ 'payload.bin' = $payloadDelta } }
            Require (Test-Path -LiteralPath (Join-Path $M.Rel '1.10.2\windows-x86_64.from-1.10.1.delta')) 'the packer wrote the delta from 1.10.1'
            $rt = Join-Path $M.Root 'app\1.10.1\lunepack-runtime.exe'
            $d = URun 'r11f-download' $rt 'download --json --expect-version 1.10.2'
            SameV 'download exit code' $d.ExitCode 0
            $lines = @($d.Output -split "`r?`n")
            Require (@(@($lines[-1], $lines[-2]) | Where-Object { $_ -match '"staged":true' }).Count -gt 0) 'download stages the update'
            # The runtime writes at most ten progress lines a second (and a phase's last one), so the
            # file's own `stage` line may be missing: the download's size says it was a patch, and any
            # line that is there names the patch.
            $fetched = -1
            foreach ($l in $lines) {
                if ($l.StartsWith('{"schema":1,"type":"progress","phase":"download","done":')) { $fetched = [long]($l | ConvertFrom-Json).done }
            }
            Require ($fetched -ge 0 -and $fetched -lt 65536) "the download fetched a patch, not the file's frame ($fetched bytes)"
            $notPatch = @($lines | Where-Object { $_ -like '*"phase":"stage"*' -and $_ -like '*"file":{"path":"payload.bin",*' -and $_ -notlike '*"source":"patch"*' })
            Require ($notPatch.Count -eq 0) 'every stage line of payload.bin names the patch'
            $want = (Get-FileHash -LiteralPath $payloadDelta -Algorithm SHA256).Hash
            Same 'the staged payload.bin' (Get-FileHash -LiteralPath (Join-Path $M.Root 'app\1.10.2\payload.bin') -Algorithm SHA256).Hash $want
            $o = New-Out 'row11f'
            $a = URun 'r11f-apply' $rt 'apply-and-restart --json --expect-version 1.10.2 -- --after-update' $o
            SameV 'apply-and-restart exit code' $a.ExitCode 0
            Expect-Lines $o @('1.10.2 start', '1.10.2 arg after-update', '1.10.2 event updated 1.10.1', '1.10.2 event first_run', '1.10.2 confirmed')
            Wait-Updated $M '1.10.2'
            Same 'the updated payload.bin' (Get-FileHash -LiteralPath (Join-Path $M.Root 'app\1.10.2\payload.bin') -Algorithm SHA256).Hash $want
            Assert-Protected (Join-Path $M.Root 'app\1.10.2') 'machine'
        }

        # ---- row 12 -------------------------------------------------------------------------------------------------------
        Row '12 (the administrator''s uninstall is refused while the user runs the app and changes nothing; complete after)' {
            # The version the earlier rows ended on (row 11b moves it on).
            $cur = (Get-Record $M.Root).current.version
            $tree = Join-Path $M.Root "app\$cur"
            $holdOut = New-Out 'hold12'
            $null = UStart 'r12-hold' (Join-Path $tree $M.EntryFile) '--hold 900' $holdOut
            Expect-Lines $holdOut @("$cur start", "$cur nothing-pending", "$cur hold")
            $snapshot = {
                [pscustomobject]@{
                    Tree = Tree-Listing $M.Root
                    Registry = (Get-ItemProperty -LiteralPath $key | ForEach-Object { "$($_.DisplayName)|$($_.InstallLocation)|$($_.DisplayVersion)|$($_.QuietUninstallString)" })
                    Shortcut = (Test-Path -LiteralPath (Common-Shortcut $M))
                    Service = Service-Registration $M
                    Record = (Get-Record $M.Root | ConvertTo-Json -Depth 8 -Compress)
                }
            }
            $before = & $snapshot
            $code = Invoke-MachineUninstall $M
            SameV 'uninstall exit code while the user runs the app (in_use)' $code 25
            $after = & $snapshot
            if ($after.Tree -ne $before.Tree) { throw "the tree under R changed: $(Listing-Diff $before.Tree $after.Tree)" }
            Same 'the uninstall entry' $after.Registry $before.Registry
            Require ($after.Shortcut) 'the shortcut is still there'
            Same 'the service registration (image path, start type, descriptor)' $after.Service $before.Service
            Same 'the record' $after.Record $before.Record
            Require (@(Get-ProcsUnder $tree).Count -ge 1) 'the process of the user still runs'
            $o = New-Out 'row12a'
            $null = UStart 'r12-run' $stubM '' $o
            Expect-Lines $o @("$cur start", "$cur nothing-pending")
            # The user's processes end: the uninstall now removes everything.
            Stop-Under $M.Root
            Wait-Until { @(Get-ProcsUnder $M.Root).Count -eq 0 } 30 'the user''s processes to end'
            $code = Invoke-MachineUninstall $M
            SameV 'uninstall exit code' $code 0
            Wait-Until { -not (Test-Path -LiteralPath $M.Root) } 90 'R to go'
            Wait-Until { -not (Test-Path -LiteralPath $key) } 30 'the Uninstall key to go'
            Require (-not (Test-Path -LiteralPath (Common-Shortcut $M))) 'the shortcut is gone'
            SameV 'the service' (Service-State $M.ServiceName) 'MISSING'
            Require (Test-Path -LiteralPath (User-Home $M)) "another user's home is left by the uninstall"
            # The administrator's elevated copy removes itself at the next restart: registered, not done now.
            $pendingNow = Pending-Deletes
            if ($pendingNow -lt 1) {
                $all = @((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations | Where-Object { $_ })
                throw "the uninstaller folder is not registered for deletion at restart (uninstaller folders under Program Files: $(@(New-ProgramFilesDirs | Where-Object { $_.Name -like '.lunepack-uninstall-*' }).Count); pending entries in all: $($all.Count); of lunepack's: $(@($all | Where-Object { $_ -like '*lunepack*' }).Count))"
            }
            foreach ($d in New-ProgramFilesDirs) { Stop-Under $d.FullName; Remove-Tree $d.FullName }
            $null = Pending-Deletes -Remove
        }

        # ---- rows 9 and 10 (a fresh install each; the machine has none now) -------------------------------------------------
        Row '9 (interactive Setup with the stand-in UI ticking "all users": the hand-off installs; with the UI lost mid-install too)' {
            $uiDir = Join-Path $work 'ui-notes'
            New-Item -ItemType Directory -Force $uiDir | Out-Null
            $copy = New-PlantedCopy $setup 'row9'
            $r = Run-Tool $copy @() -Env @{ LUNEPACK_E2E_UI_MODE = 'all-users'; LUNEPACK_E2E_UI_DIR = $uiDir }
            if (Test-LoaderFailure $r.Code) { throw "Setup ended with a loader failure (0x$('{0:X8}' -f $r.Code)) beside the planted files" }
            SameV 'interactive Setup exit code' $r.Code 0
            Require ((@($r.Out) -join '') -match '"outcome":"installed"') "the result line says installed: $(@($r.Out) -join ' ')"
            Assert-Installed $M '1.0.0'
            SameV 'windows started' @(Read-Lines (Join-Path $uiDir 'ui-spawns')).Count 1
            Require ((Read-Text (Join-Path $uiDir 'ui-hello')) -like "*$($M.BaseName)*") 'the window was told the app name'
            $code = Invoke-MachineUninstall $M
            SameV 'uninstall exit code' $code 0
            Wait-Until { -not (Test-Path -LiteralPath $M.Root) } 90 'R to go'
            foreach ($d in New-ProgramFilesDirs) { Stop-Under $d.FullName; Remove-Tree $d.FullName }
            $null = Pending-Deletes -Remove
            # The window is lost after the hand-off began: the install still completes, with a warning and one notice.
            Remove-Item -LiteralPath $uiDir -Recurse -Force
            New-Item -ItemType Directory $uiDir | Out-Null
            $r = Run-Tool $copy @() -AllowNotice -Env @{ LUNEPACK_E2E_UI_MODE = 'all-users-die'; LUNEPACK_E2E_UI_DIR = $uiDir }
            if (Test-LoaderFailure $r.Code) { throw "Setup ended with a loader failure (0x$('{0:X8}' -f $r.Code)) beside the planted files" }
            SameV 'Setup exit code with a lost window' $r.Code 0
            Require ($r.Err -match 'ui_stopped') 'the lost window is reported as a warning'
            Assert-Installed $M '1.0.0'
            $code = Invoke-MachineUninstall $M
            SameV 'uninstall exit code' $code 0
            Wait-Until { -not (Test-Path -LiteralPath $M.Root) } 90 'R to go'
            foreach ($d in New-ProgramFilesDirs) { Stop-Under $d.FullName; Remove-Tree $d.FullName }
            $null = Pending-Deletes -Remove
        }

        Row '10 (--all-users --silent as the standard user: exit 30, nothing written)' {
            $userSetup = Join-Path $base 'setup-user'
            Set-DirAcl $userSetup (@('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') + '*S-1-5-32-545:(OI)(CI)RX')
            Copy-Item -LiteralPath $setup -Destination (Join-Path $userSetup 'Setup.exe')
            $pfNow = @(Get-ChildItem $pf -Directory -Force | ForEach-Object { $_.Name })
            $r = URun 'r10' (Join-Path $userSetup 'Setup.exe') '--all-users --silent'
            SameV 'exit code (elevation_required)' $r.ExitCode 30
            Require (-not (Test-Path -LiteralPath $M.Root)) 'no folder under Program Files'
            SameV 'folders added under Program Files' (@(Get-ChildItem $pf -Directory -Force | Where-Object { $pfNow -notcontains $_.Name }).Count) 0
            Require (-not (Test-Path -LiteralPath $key)) 'no uninstall entry'
            SameV 'the service' (Service-State $M.ServiceName) 'MISSING'
            Require (-not (Test-Path -LiteralPath (Common-Shortcut $M))) 'no shortcut'
            Require (-not (Test-Path -LiteralPath (Join-Path $env:SystemDrive "Users\$($user.Name)\AppData\Local\Programs\$($M.BaseName)"))) "no per-user install for the user"
        }
    }
} catch {
    $failures.Add('setup')
    Write-Output "FAIL setup: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
} finally {
    try { Remove-Everything } catch { Write-Output "cleanup error: $($_.Exception.Message)" }
}

foreach ($m in $launchMethods.Keys) { Write-Output "the standard user's commands ran through: $m ($($launchMethods[$m]) commands)" }
$left = @(Find-Leftovers)
if ($left.Count -gt 0) { $failures.Add('leftovers'); Write-Output "FAIL leftovers: $($left -join '; ')" } else { Write-Output 'ok   nothing this script created is left' }
if ($failures.Count -gt 0) {
    Write-Output "e2e-windows-machine: FAILED ($($failures -join ', '))"
    exit 1
}
Write-Output 'e2e-windows-machine: ok'
exit 0
