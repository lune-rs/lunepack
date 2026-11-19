# Windows end-to-end run (M7 step 13), native, no Docker.
#
# Builds the release runtime, both stubs, `lunepack`, the e2e app and the stand-in UI, packs
# `windows-x86_64` releases of four small apps under a unique app id and a display name with a
# space and a non-ASCII letter, builds their `Setup.exe` files with `lunepack setup`, and checks
# what the packager and the setup files hold. With -Install (the default on CI) it also installs
# for real into the current user's %LOCALAPPDATA%\Programs, drives the apps through updates,
# rollbacks and uninstalls, and checks the state on disk, in the install record, in the registry
# and in the Start menu. The install rows write under the real per-user locations, so a developer
# machine runs them only on request, and a shared test machine not at all. Everything the run
# creates is removed, also after a failure, and the script asserts it.
#
# The apps (all `windows-x86_64`, one release directory and `file:` feed each):
#   A  the e2e app behind the GUI stub, with the stand-in UI: rows 1, 2, 3, 4, 5, 8, 10, 11, 12
#   B  the e2e app behind the console stub: row 3's stub replaced while it runs
#   C  the e2e app at an entry path over 260 characters: row 7
#   D  a small console program (scripts/ci/e2e-ctl-app.cs): row 6 and the console-event proof
#
# Rows without -Install: the packaging half of every row (releases pack, setup files build, the
# images carry the hardening and the stamps), row 9 (planted DLLs), row 10's static half.
# With -Install: row 1 (install and its state), 2 (interactive Setup with the stand-in UI, a UI
# that dies), 3 (update by the library with the update window, by the command line, stub replaced
# while a console stub runs), 4 (crash, slow confirm, attempt counter), 5 (deferred GC), 6 (console
# stub stdio and exit code), 7 (long path), 8 (uninstall by QuietUninstallString), 10 (no console
# of the runtime's own), 11 (display-name change, Setup rerun, a user's rename), 12 (taken folder),
# the console Ctrl+C / Ctrl+Break proof (scripts/ci/console-ctrl-test.ps1) and, on CI, the signed
# Setup.exe (scripts/ci/windows-sign-test.ps1).
#
# The harness never prints environment or registry dumps; a failure names a differing field, and
# prints only versions, outcome words and exit codes.
param([switch]$Install)
$ErrorActionPreference = 'Stop'
if ($env:CI -eq 'true' -or $env:LUNEPACK_E2E_INSTALL -eq '1') { $Install = $true }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tdir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
$rel = Join-Path $tdir 'release'

$hex = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$programs = Join-Path $env:LOCALAPPDATA 'Programs'
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$uninstallKeyRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$work = Join-Path ([IO.Path]::GetTempPath()) "lunepack-e2e-$hex"
$tempRoot = [IO.Path]::GetTempPath()
$tempBefore = @(Get-ChildItem $tempRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
$failures = New-Object System.Collections.Generic.List[string]
$utf8 = New-Object System.Text.UTF8Encoding($false)
$apps = New-Object System.Collections.ArrayList
$uiDir = Join-Path $work 'ui-notes'
$cliExit = 0

if (-not ('Lpe2eProc' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'ci\e2e-native.cs') }

# ---- small helpers ---------------------------------------------------------------------------------

# Runs one row. A failure is reported with the row's own line (not a helper's), then -Undo removes
# what the failed row left (an install it would have removed itself), so one failure does not
# cascade into the rows after it.
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

# A path the Win32 file functions of Windows PowerShell 5.1 take however long it is.
function Long([string]$path) {
    if ($path.Length -ge 240 -and -not $path.StartsWith('\\?\')) { return '\\?\' + $path }
    return $path
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

# A fresh outcome file; the apps started from now on (and what they start) write their lines to it.
function New-Out([string]$tag) {
    $path = Join-Path $work "out-$tag.txt"
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    $env:LUNEPACK_E2E_OUT = $path
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

# Starts a program (hidden window) without waiting; $ArgumentList may be empty.
function Start-Proc([string]$file, [string[]]$arguments = @()) {
    $params = @{ FilePath = $file; PassThru = $true; WindowStyle = 'Hidden' }
    if ($arguments.Count -gt 0) { $params.ArgumentList = $arguments }
    $p = Start-Process @params
    $null = $p.Handle
    return $p
}

# Runs a program to its end with its output captured; returns Code, Out and Err (lines).
function Run-Tool([string]$file, [string[]]$arguments = @(), [int]$seconds = 180) {
    $o = Join-Path $work ('tool-' + [Guid]::NewGuid().ToString('N') + '.out')
    $e = $o + '.err'
    $params = @{ FilePath = $file; PassThru = $true; WindowStyle = 'Hidden'; RedirectStandardOutput = $o; RedirectStandardError = $e }
    if ($arguments.Count -gt 0) { $params.ArgumentList = $arguments }
    $p = Start-Process @params
    $null = $p.Handle
    if (-not $p.WaitForExit($seconds * 1000)) {
        try { $p.Kill() } catch { }
        throw "timed out running $(Split-Path $file -Leaf)"
    }
    $p.WaitForExit()
    $result = [pscustomobject]@{ Code = $p.ExitCode; Out = @(Read-Lines $o); Err = (Read-Text $e) }
    Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue
    return $result
}

# Runs a console program with its standard input, output and error redirected.
function Run-Console([string]$exe, [string]$argumentLine, [string]$stdin) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = $argumentLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.Write($stdin)
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(60000)) {
        try { $p.Kill() } catch { }
        throw "timed out running $(Split-Path $exe -Leaf)"
    }
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $out.Result; Err = $err.Result }
}

function Stop-Under([string]$dir) {
    $prefix = $dir.TrimEnd('\') + '\'
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch { }
        if ($path -and $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

function Get-Runtimes([string]$root) {
    $prefix = $root.TrimEnd('\') + '\'
    return @(Get-Process -Name 'lunepack-runtime' -ErrorAction SilentlyContinue | Where-Object {
            $path = $null
            try { $path = $_.Path } catch { }
            $path -and $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
        })
}

function Wait-Runtimes-Gone([string]$root) {
    Wait-Until { @(Get-Runtimes $root).Count -eq 0 } 90 'the runtime to finish'
}

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
    return @(Get-ChildItem -LiteralPath (Join-Path $app.Root 'app') -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object)
}

function Stub-Path($app) { return (Join-Path $app.Root $app.EntryFile) }

# The set of temp directories of lunepack's own that this run did not start with.
function New-TempDirs([string]$prefix) {
    return @(Get-ChildItem $tempRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $tempBefore -notcontains $_.Name -and $_.Name -like "$prefix*" } | ForEach-Object { $_.Name })
}

# The stand-in UI's notes (one line per event), then forgotten.
function Ui-Notes([string]$name) {
    $f = Join-Path $uiDir $name
    $lines = @(Read-Lines $f)
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    return $lines
}

function Reset-Ui { foreach ($n in 'ui-spawns', 'ui-hello', 'ui-prompts') { Remove-Item -LiteralPath (Join-Path $uiDir $n) -Force -ErrorAction SilentlyContinue } }

# ---- the publisher ------------------------------------------------------------------------------------

# Native stderr is not an error here (`keys gen` reports on it), so the preference is relaxed per call.
function Invoke-Lunepack([string]$config, [string[]]$cliArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = @(& $script:cli --config $config @cliArgs 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $old }
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

# A publisher for one app: keys, key set, an empty release directory, a config to extend per release.
function New-App([string]$tag, [string]$idSuffix, [string]$nameSuffix, [string]$entryRel, [string]$entrySource, [bool]$terminal, [string]$ui) {
    $dir = Join-Path $work $tag
    New-Item -ItemType Directory $dir, (Join-Path $dir 'rel') | Out-Null
    $cfg = Join-Path $dir 'lunepack.toml'
    $app = @{
        Tag = $tag; Id = "org.example.lpe2e$hex$idSuffix"; BaseName = "Lunepack E2E $([char]0xC4) $hex$nameSuffix"
        EntryRel = $entryRel; EntryFile = ($entryRel -split '/')[-1]; EntrySource = $entrySource
        Terminal = $terminal; Ui = $ui; Dir = $dir; Cfg = $cfg; Rel = (Join-Path $dir 'rel'); RelKey = (Join-Path $dir 'rel0.key')
        Root = $null; Declare = $false; Ext = ''
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

# Packs and publishes one version of an app. Options: Flags (lines of e2e-flags), Timeout
# (health_timeout_secs), Name (a new display name from this version on).
function Publish-Version($app, [string]$version, [hashtable]$options = @{}) {
    $flags = @()
    if ($options.ContainsKey('Flags')) { $flags = $options.Flags }
    $timeout = 30
    if ($options.ContainsKey('Timeout')) { $timeout = $options.Timeout }
    if ($options.ContainsKey('Name')) { $app.Name = $options.Name }
    $in = Join-Path $app.Dir "in-$version"
    $dest = Join-Path $in ($app.EntryRel -replace '/', '\')
    [void][IO.Directory]::CreateDirectory((Long (Split-Path $dest -Parent)))
    [IO.File]::Copy($app.EntrySource, (Long $dest), $true)
    if ($flags.Count -gt 0) { [IO.File]::WriteAllText((Join-Path $in 'e2e-flags'), (($flags -join "`n") + "`n"), $utf8) }
    $toml = "`n[update]`nfeed = `"$($app.Feed)`"`nchannel = `"stable`"`nhealth_timeout_secs = $timeout`n`n[install]`nentry = `"$($app.EntryRel)`"`nname = `"$($app.Name)`"`npublisher = `"Lunepack E2E`"`n"
    if ($app.Terminal) { $toml += "terminal = true`n" }
    if ($app.Declare) {
        # M7-D3: a file type ("Open with"), a URL scheme and autostart; each name is unique to this run.
        $toml += "url_schemes = [`"$($app.Ext)`"]`nautostart = true`n`n[[install.file_types]]`next = `"$($app.Ext)`"`nmime = `"application/x-$($app.Ext)`"`nname = `"Lunepack E2E file`"`n"
    }
    [IO.File]::WriteAllText($app.Cfg, $app.Base + $toml, $utf8)
    $stubFile = $stub
    if ($app.Terminal) { $stubFile = $stubConsole }
    $packArgs = @('pack', '--input', $in, '--version', $version, '--target', 'windows-x86_64', '--release-dir', $app.Rel, '--sign', "file:$($app.RelKey)", '--runtime', $runtime, '--stub', $stubFile)
    if ($app.Ui) { $packArgs += @('--ui', $app.Ui) }
    Invoke-LunepackOk $app.Cfg $packArgs | Out-Null
    Invoke-LunepackOk $app.Cfg @('feed', 'add', '--release-dir', $app.Rel, '--channel', 'stable', '--version', $version, '--sign', "file:$($app.RelKey)") | Out-Null
}

function Build-Setup($app, [string]$version) {
    $dir = Join-Path $app.Dir "setup-$version"
    New-Item -ItemType Directory $dir | Out-Null
    $out = Join-Path $dir 'Setup.exe'
    Invoke-LunepackOk $app.Cfg @('setup', $app.Rel, '--version', $version, '--target', 'windows-x86_64', '--out', $out) | Out-Null
    return $out
}

# ---- install and uninstall -------------------------------------------------------------------------------

function Install-Silent($app, [string]$setupExe) {
    $r = Run-Tool $setupExe @('/S')
    SameV 'setup exit code' $r.Code 0
    $app.Root = Join-Path $programs $app.BaseName
    return $r
}

$classesKey = 'HKCU:\Software\Classes'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# A `Run` value's data (null when the key or the value is absent).
function Run-Value([string]$name) {
    if (-not (Test-Path -LiteralPath $runKey)) { return $null }
    return (Get-Item -LiteralPath $runKey).GetValue($name)
}

# A registry key's default value (null when the key or the value is absent); never printed.
function Reg-Default([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    return (Get-Item -LiteralPath $path).GetValue('')
}

# `System.AppUserModel.ID` of a shortcut, read through the shell's property system.
function Get-LinkAumid([string]$lnk) {
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace((Split-Path $lnk -Parent))
    $item = $folder.ParseName((Split-Path $lnk -Leaf))
    return "$($item.ExtendedProperty('System.AppUserModel.ID'))"
}

# The declarations of M7-D3 an app with `Declare` carries: the ProgID and the "Open with" entry of
# its file type (never the extension's default value), the URL-scheme class and the Run value; each
# one carries the marker and runs the stub.
function Assert-Declarations($app) {
    $stubPath = Stub-Path $app
    $openCommand = "`"$stubPath`" `"%1`""
    $progid = "$($app.Id).$($app.Ext)"
    $pk = Join-Path $classesKey $progid
    Require (Test-Path -LiteralPath $pk) 'the ProgID key exists'
    Same 'ProgID marker' (Get-Item -LiteralPath $pk).GetValue('LunepackAppId') $app.Id
    Same 'ProgID open command' (Reg-Default (Join-Path $pk 'shell\open\command')) $openCommand
    $extKey = Join-Path $classesKey ".$($app.Ext)"
    $with = Join-Path $extKey 'OpenWithProgids'
    Require (Test-Path -LiteralPath $with) 'the OpenWithProgids key exists'
    Require (@((Get-Item -LiteralPath $with).GetValueNames()) -contains $progid) 'OpenWithProgids lists the ProgID'
    Require ($null -eq (Reg-Default $extKey)) 'the extension key has no default value (no default handler)'
    $sk = Join-Path $classesKey $app.Ext
    Require (Test-Path -LiteralPath $sk) 'the URL-scheme key exists'
    Same 'scheme marker' (Get-Item -LiteralPath $sk).GetValue('LunepackAppId') $app.Id
    Require (@((Get-Item -LiteralPath $sk).GetValueNames()) -contains 'URL Protocol') 'the scheme key has URL Protocol'
    Same 'scheme open command' (Reg-Default (Join-Path $sk 'shell\open\command')) $openCommand
    Same 'Run value' (Run-Value $app.Id) "`"$stubPath`""
}

# Everything Assert-Declarations looked at is gone.
function Assert-NoDeclarations($app) {
    Require (-not (Test-Path -LiteralPath (Join-Path $classesKey "$($app.Id).$($app.Ext)"))) 'the ProgID is gone'
    Require (-not (Test-Path -LiteralPath (Join-Path $classesKey ".$($app.Ext)"))) 'the extension key is gone'
    Require (-not (Test-Path -LiteralPath (Join-Path $classesKey $app.Ext))) 'the URL-scheme key is gone'
    Require ($null -eq (Run-Value $app.Id)) 'the Run value is gone'
}

# How many entries Windows' installed-programs inventory (`Get-Package -ProviderName Programs`)
# has under exactly this display name. The Programs provider ships only with Windows PowerShell
# 5.1 (PowerShell 7, which CI runs this script in, has no such provider), so the query runs in
# powershell.exe; the command goes encoded, so the name's space and non-ASCII letter pass intact.
function Programs-Count([string]$name) {
    $quoted = $name -replace "'", "''"
    $command = "`$ProgressPreference = 'SilentlyContinue'; @(Get-Package -ProviderName Programs -Name '$quoted' -ErrorAction SilentlyContinue).Count"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $out = @(& powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded)
    if ($LASTEXITCODE -ne 0) { throw "powershell.exe (Get-Package) exited $LASTEXITCODE" }
    $last = "$($out | Select-Object -Last 1)".Trim()
    if ($last -notmatch '^\d+$') { throw 'powershell.exe (Get-Package) printed no count' }
    return [int]$last
}

# What a first install of $version leaves in $app.Root, in the registry and in the Start menu.
function Assert-Installed($app, [string]$version) {
    $root = $app.Root
    Require ($null -ne $root -and (Test-Path -LiteralPath $root)) 'the install folder exists'
    $top = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object)
    Same 'top level of R' ($top -join '|') ((@('.lunepack', 'app', $app.EntryFile) | Sort-Object) -join '|')
    $hidden = (Get-Item -LiteralPath (Join-Path $root '.lunepack') -Force).Attributes -band [IO.FileAttributes]::Hidden
    Require ($hidden -ne 0) '.lunepack is hidden'
    Require (Test-Path -LiteralPath (Long (Join-Path $root "app\$version"))) "app\$version exists"
    Require (Test-Path -LiteralPath (Join-Path $root '.lunepack\state')) '.lunepack\state exists'
    $v = (Get-Item -LiteralPath (Stub-Path $app)).VersionInfo
    Same 'stub FileDescription' $v.FileDescription $app.Name
    SameV 'stub ProductVersion' $v.ProductVersion $version
    Same 'stub OriginalFilename' $v.OriginalFilename $app.EntryFile
    $key = Join-Path $uninstallKeyRoot $app.Id
    $u = Get-ItemProperty $key
    Same 'DisplayName' $u.DisplayName $app.Name
    Same 'InstallLocation' $u.InstallLocation $root
    SameV 'DisplayVersion' $u.DisplayVersion $version
    Same 'QuietUninstallString' $u.QuietUninstallString "`"$(Stub-Path $app)`" --lunepack-uninstall /S"
    SameV 'Get-Package -ProviderName Programs entries of the app' (Programs-Count $app.Name) 1
    $lnk = Join-Path $startMenu "$($app.Name).lnk"
    Require (Test-Path -LiteralPath $lnk) 'the Start-menu shortcut exists'
    $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    Same 'shortcut target' $sc.TargetPath (Stub-Path $app)
    Same 'shortcut AUMID' (Get-LinkAumid $lnk) $app.Id
    if ($app.Declare) { Assert-Declarations $app }
}

# Uninstalls through the Uninstall entry's own quiet command, split by the documented rule (a
# quoted program path, then the arguments; no shell), and waits for the folder to go.
function Invoke-Uninstall($app) {
    $key = Join-Path $uninstallKeyRoot $app.Id
    $quiet = (Get-ItemProperty $key).QuietUninstallString
    Require ($quiet -match '^"([^"]+)"\s*(.*)$') 'the string has the documented shape'
    $program = $Matches[1]
    $rest = $Matches[2]
    Stop-Under $app.Root
    $u = Start-Process -FilePath $program -ArgumentList $rest -Wait -PassThru -WindowStyle Hidden
    SameV 'stub exit code' $u.ExitCode 0
    $root = $app.Root
    Wait-Until { -not (Test-Path -LiteralPath (Long $root)) } 90 'R to go'
    Wait-Until { -not (Test-Path $key) } 30 'the Uninstall key to go'
    Require (-not (Test-Path -LiteralPath (Join-Path $startMenu "$($app.Name).lnk"))) 'the shortcut is gone'
    if ($app.Declare) { Assert-NoDeclarations $app }
}

# Removes a tree however long its paths are.
function Remove-Tree([string]$path) {
    if (-not (Test-Path -LiteralPath (Long $path))) { return }
    try { [IO.Directory]::Delete((Long $path), $true) } catch {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Removes one app's install, if there is one: through its Uninstall entry's own command first, then
# what is left of it by name (its folders, shortcuts, Uninstall key and declarations). A no-op when
# the app is not installed.
function Reset-App($app) {
    $key = Join-Path $uninstallKeyRoot $app.Id
    if (Test-Path $key) {
        $quiet = (Get-ItemProperty $key).QuietUninstallString
        if ($quiet -match '^"([^"]+)"\s*(.*)$' -and (Test-Path -LiteralPath $Matches[1])) {
            $program = $Matches[1]
            $rest = $Matches[2]
            Stop-Under (Split-Path $program -Parent)
            try { Start-Process -FilePath $program -ArgumentList $rest -Wait -WindowStyle Hidden } catch { }
            for ($i = 0; $i -lt 30 -and (Test-Path $key); $i++) { Start-Sleep -Seconds 1 }
        }
    }
    $names = @($app.BaseName, $app.Name, "$($app.BaseName) ($($app.Id))", "$($app.Name) ($($app.Id))")
    foreach ($n in ($names | Select-Object -Unique)) {
        $d = Join-Path $programs $n
        if (Test-Path -LiteralPath (Long $d)) {
            Stop-Under $d
            Remove-Tree $d
        }
    }
    foreach ($n in (@($app.BaseName, $app.Name) | Select-Object -Unique)) {
        Remove-Item -LiteralPath (Join-Path $startMenu "$n.lnk") -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    if ($app.Declare) {
        # The declarations of M7-D3, when the uninstall did not remove them (all names are unique to this run).
        foreach ($k in "$($app.Id).$($app.Ext)", ".$($app.Ext)", $app.Ext) {
            Remove-Item -LiteralPath (Join-Path $classesKey $k) -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-ItemProperty -LiteralPath $runKey -Name $app.Id -ErrorAction SilentlyContinue
    }
}

function Cleanup {
    # Each app through its entry's own command first, then a sweep of what is ours by name.
    foreach ($app in $apps) { Reset-App $app }
    foreach ($d in @(Get-ChildItem $programs -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Lunepack E2E*$hex*" })) {
        Stop-Under $d.FullName
        Remove-Tree $d.FullName
    }
    foreach ($f in @(Get-ChildItem $startMenu -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Lunepack E2E*$hex*" })) {
        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
    }
    foreach ($d in Get-ChildItem $tempRoot -Directory -ErrorAction SilentlyContinue) {
        # Only what this run created: uninstall copies and UI dirs that were not there at the start.
        if ($tempBefore -notcontains $d.Name -and $d.Name -match '^lunepack-(uninstall|setup-ui)-[0-9a-f]{16}$') {
            Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item Env:LUNEPACK_E2E_OUT, Env:LUNEPACK_E2E_UI_DIR, Env:LUNEPACK_E2E_UI_MODE -ErrorAction SilentlyContinue
    Stop-Under $work
    Remove-Tree $work
}

function Leftovers {
    $left = @()
    foreach ($d in Get-ChildItem $programs -Directory -Force -ErrorAction SilentlyContinue) { if ($d.Name -like "Lunepack E2E*$hex*") { $left += 'folder' } }
    foreach ($f in Get-ChildItem $startMenu -Filter '*.lnk' -ErrorAction SilentlyContinue) { if ($f.Name -like "Lunepack E2E*$hex*") { $left += 'shortcut' } }
    foreach ($app in $apps) { if (Test-Path (Join-Path $uninstallKeyRoot $app.Id)) { $left += 'uninstall key' } }
    foreach ($app in @($apps | Where-Object { $_.Declare })) {
        foreach ($k in "$($app.Id).$($app.Ext)", ".$($app.Ext)", $app.Ext) {
            if (Test-Path -LiteralPath (Join-Path $classesKey $k)) { $left += 'class key' }
        }
        if ($null -ne (Run-Value $app.Id)) { $left += 'Run value' }
    }
    return $left
}

# ---- the update helpers ---------------------------------------------------------------------------------

# The lines of an update from $from to $to that the new version confirms (the library's path).
function Confirmed-Lines([string]$from, [string]$to) {
    return @("$from start", "$from nothing-pending", "$from check $to", "$from staged $to", "$from apply-scheduled",
        "$to start", "$to arg after-update", "$to event updated $from", "$to event first_run", "$to confirmed")
}

# The command-line path: check, download, apply-and-restart, as an app in any language runs them.
# The runtime that answers is the installed $from tree's own.
function Update-ViaRuntime($app, [string]$from, [string]$to, [switch]$NoUi, [string[]]$restartArgs = @()) {
    $rt = Join-Path $app.Root "app\$from\lunepack-runtime.exe"
    $c = Run-Tool $rt @('check', '--json')
    SameV 'check exit code' $c.Code 0
    $last = @($c.Out)[-1]
    Require ($last -match '"type":"result"' -and $last -match '"command":"check"') 'check ends with its result object'
    Require ($last -match ('"version":"' + [regex]::Escape($to) + '"')) "check offers $to"
    $d = Run-Tool $rt @('download', '--json', '--expect-version', $to)
    SameV 'download exit code' $d.Code 0
    Require (@($d.Out)[-1] -match '"staged":true') 'download stages the update'
    # The waited-for process stands in for the app that exits to be updated.
    $waited = Start-Proc "$env:SystemRoot\System32\PING.EXE" @('-n', '6', '127.0.0.1')
    $a = @('apply-and-restart', '--json', '--wait-pid', "$($waited.Id)", '--expect-version', $to)
    if ($NoUi) { $a += '--no-ui' }
    if ($restartArgs.Count -gt 0) { $a += '--'; $a += $restartArgs }
    $r = Run-Tool $rt $a
    SameV 'apply-and-restart exit code' $r.Code 0
    Require (@($r.Out)[-1] -match '"scheduled":true') 'apply-and-restart schedules the apply'
}

function Wait-Updated($app, [string]$to) {
    Wait-Until { $r = Get-Record $app.Root; $null -ne $r -and $r.current.version -eq $to -and $null -eq $r.pending } 120 "the update to $to to settle"
    Wait-Runtimes-Gone $app.Root
}

# ---- the work -----------------------------------------------------------------------------------------------

try {
    Write-Output "e2e-windows: building"
    Push-Location $repo
    try {
        cargo build --locked --release -p lunepack-cli -p lunepack-runtime -p lunepack-stub
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
        cargo build --locked --release -p lunepack --example e2e_app
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (example) failed' }
        cargo build --locked --release -p lunepack-runtime --example e2e_fake_ui
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (stand-in UI) failed' }
    } finally { Pop-Location }
    $cli = Join-Path $rel 'lunepack.exe'
    $runtime = Join-Path $rel 'lunepack-runtime.exe'
    $stub = Join-Path $rel 'lunepack-stub.exe'
    $stubConsole = Join-Path $rel 'lunepack-stub-console.exe'
    $appExe = Join-Path $rel 'examples\e2e_app.exe'
    $fakeUi = Join-Path $rel 'examples\e2e_fake_ui.exe'
    foreach ($f in $cli, $runtime, $stub, $stubConsole, $appExe, $fakeUi) { Require (Test-Path $f) "a built file exists" }
    New-Item -ItemType Directory $work, $uiDir | Out-Null
    $env:LUNEPACK_E2E_UI_DIR = $uiDir

    # The console stand-in app (row 6 and the console-event proof) is compiled with the .NET
    # Framework's own compiler, so no toolchain or download is involved.
    $csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    Require (Test-Path $csc) 'csc.exe (the .NET Framework compiler) exists'
    $ctlExe = Join-Path $work 'ctl.exe'
    $compiled = Run-Tool $csc @('/nologo', '/optimize+', '/target:exe', "/out:`"$ctlExe`"", "`"$(Join-Path $PSScriptRoot 'ci\e2e-ctl-app.cs')`"")
    Require ($compiled.Code -eq 0) 'csc compiles the console stand-in app'

    # ---- the releases ------------------------------------------------------------------------------------------
    $A = New-App 'a' '' '' "lpe2e$hex.exe" $appExe $false $fakeUi
    $A.Declare = $true
    $A.Ext = "lpe$hex"
    $B = New-App 'b' '-b' ' Console' "lpe2e${hex}b.exe" $appExe $true $null
    $D = New-App 'd' '-d' ' Ctl' "ctl$hex.exe" $ctlExe $true $null
    # A path of well over 260 characters from R to the entry (row 7): four directories of 50 characters.
    $longDirs = (1..4 | ForEach-Object { 'd' + $_ + ('x' * 48) }) -join '/'
    $C = New-App 'c' '-c' ' Long' "$longDirs/lpe2e${hex}c.exe" $appExe $true $null
    Publish-Version $A '1.0.0'
    Publish-Version $B '1.0.0'
    Publish-Version $D '1.0.0'
    Publish-Version $C '1.0.0'
    $setup = Build-Setup $A '1.0.0'
    $setupB = Build-Setup $B '1.0.0'
    $setupD = Build-Setup $D '1.0.0'
    $setupC = Build-Setup $C '1.0.0'

    # ---- rows that install nothing -------------------------------------------------------------------------------
    Row '10 (static)' {
        Same 'runtime subsystem' (PeSubsystem $runtime) 2
        Same 'setup subsystem' (PeSubsystem $setup) 2
        Same 'GUI stub subsystem' (PeSubsystem $stub) 2
        Same 'console stub subsystem' (PeSubsystem $stubConsole) 3
        Same 'stand-in UI subsystem' (PeSubsystem $fakeUi) 2
        $v = (Get-Item $setup).VersionInfo
        Same 'Setup FileDescription' $v.FileDescription "$($A.BaseName) Setup"
        Same 'Setup ProductName' $v.ProductName $A.BaseName
        Same 'Setup CompanyName' $v.CompanyName 'Lunepack E2E'
        SameV 'Setup ProductVersion' $v.ProductVersion '1.0.0'
        Same 'Setup OriginalFilename' $v.OriginalFilename 'Setup.exe'
    }
    Row '9 (planted DLLs, garbage-file form)' {
        $out = & (Join-Path $PSScriptRoot 'ci\plant-dll-test.ps1') -Case "setup=$setup=--no-such-option", "runtime=$runtime=--no-such-option", "console-stub=$stubConsole="
        $out | ForEach-Object { Write-Output "     $_" }
        Require ($LASTEXITCODE -eq 0) 'no planted DLL breaks a start'
    }

    # ---- rows that install -------------------------------------------------------------------------------------------
    if (-not $Install) {
        # What each install row needs from the packager, checked without installing anything.
        Row 'releases of rows 2-7 and 11 pack (dry run)' {
            Publish-Version $A '1.1.0'
            Publish-Version $A '1.2.0'
            Publish-Version $A '1.3.0' @{ Flags = @('crash-on-start') }
            Publish-Version $A '1.4.0' @{ Flags = @('slow-confirm 60'); Timeout = 5 }
            Publish-Version $A '1.5.0' @{ Flags = @('exit-without-confirm'); Timeout = 120 }
            Publish-Version $A '1.6.0' @{ Name = "$($A.BaseName) Renamed" }
            $null = Build-Setup $A '1.6.0'
            Publish-Version $B '1.1.0'
            Publish-Version $B '1.2.0'
            $longInput = Join-Path $C.Dir ('in-1.0.0\' + ($C.EntryRel -replace '/', '\'))
            Require ((Long $longInput).Length -gt 260) 'the long-path entry path is over 260 characters'
            Require (Test-Path -LiteralPath (Long $longInput)) 'the long-path input exists'
            $vi = (Get-Item $setupB).VersionInfo
            Same 'console app Setup FileDescription' $vi.FileDescription "$($B.BaseName) Setup"
        }
        Write-Output 'skipped: the install rows (1 to 8, 11, 12, the console-event proof; they install into the real per-user locations, so they run on CI; pass -Install or set LUNEPACK_E2E_INSTALL=1 elsewhere)'
    } else {
        $key = Join-Path $uninstallKeyRoot $A.Id
        Require (-not (Test-Path -LiteralPath (Join-Path $programs $A.BaseName))) 'no earlier install of this unique name'
        $state = @{}
        $holdOut = $null

        Row '1 (install, state)' {
            $o = New-Out 'row1'
            Reset-Ui
            $null = Install-Silent $A $setup
            Assert-Installed $A '1.0.0'
            # /S shows no window: the stand-in UI was never started.
            SameV 'UI starts under /S' (@(Ui-Notes 'ui-spawns')).Count 0
            SameV 'UI directories left in temp' (@(New-TempDirs 'lunepack-setup-ui-')).Count 0
            # The app, started through the stub, writes its marker lines.
            # `--aumid`: the app reports its process's explicit app user model id, which is the
            # shortcut's (M7-D9; Assert-Installed read the shortcut's and compared it with the app id).
            $null = Start-Proc (Stub-Path $A) @('--aumid')
            Expect-Lines $o @('1.0.0 start', '1.0.0 event installed', '1.0.0 event first_run', '1.0.0 nothing-pending', ('1.0.0 aumid ' + $A.Id))
            Assert-Record $A '1.0.0' $null @()
        }

        Row '10 (dynamic: the runtime opens no console)' {
            # An app with no console (detached) runs the runtime with default process flags, and a
            # console program (cmd.exe) the same way as the control: only the control may get a console host.
            $o = New-Out 'row10'
            $exe = Join-Path $A.Root "app\1.0.0\$($A.EntryFile)"
            $pidStarted = 0
            $h = [Lpe2eProc]::Start("`"$exe`" --check 12", [Lpe2eProc]::Detached, [ref]$pidStarted)
            try {
                $seen = [Lpe2eSnap]::Watch('lunepack-runtime.exe', 'ping.exe', 9000)
                Wait-Until { [Lpe2eProc]::Exited($h, 0) } 60 'the app to finish its checks'
            } finally { [Lpe2eProc]::Close($h) }
            $lines = @(Read-Lines $o)
            Require (@($lines | Where-Object { $_ -eq '1.0.0 check-run 0' }).Count -eq 12) 'twelve runtime checks ended with exit 0'
            if ($seen[0] -lt 1 -or $seen[3] -lt 1) {
                Write-Output "     note: instrument INVALID, skipped (runtimes seen $($seen[0]), console hosts under the control $($seen[3])); the static half of row 10 stands"
            } else {
                SameV 'console hosts under the runtime' $seen[1] 0
            }
        }

        Row '3 (update to 1.1.0 by the library, with the update window)' {
            Publish-Version $A '1.1.0'
            $o = New-Out 'row3a'
            Reset-Ui
            $null = Start-Proc (Stub-Path $A) @('--update')
            Expect-Lines $o (Confirmed-Lines '1.0.0' '1.1.0')
            Wait-Runtimes-Gone $A.Root
            Assert-Record $A '1.1.0' '1.0.0' @()
            SameV 'versions on disk' ((App-Versions $A) -join ',') '1.0.0,1.1.0'
            SameV 'update windows started' (@(Ui-Notes 'ui-spawns')).Count 1
            # The stub at R follows the current version: the same bytes as that tree's own.
            $want = (Get-FileHash -LiteralPath (Join-Path $A.Root 'app\1.1.0\lunepack-stub.exe') -Algorithm SHA256).Hash
            Same 'stub bytes' (Get-FileHash -LiteralPath (Stub-Path $A) -Algorithm SHA256).Hash $want
            SameV 'stub ProductVersion' (Get-Item -LiteralPath (Stub-Path $A)).VersionInfo.ProductVersion '1.1.0'
            SameV 'DisplayVersion' (Get-ItemProperty $key).DisplayVersion '1.1.0'
            $top = @(Get-ChildItem -LiteralPath $A.Root -Force | ForEach-Object { $_.Name } | Sort-Object)
            Same 'top level of R' ($top -join '|') ((@('.lunepack', 'app', $A.EntryFile) | Sort-Object) -join '|')
        }

        Row '3 and 5 (update to 1.2.0 by the command line; GC waits for a process of 1.0.0)' {
            Publish-Version $A '1.2.0'
            # A process runs from the tree of 1.0.0 (not current any more) through the update.
            $holdOut = New-Out 'hold-a'
            $state.Holder = Start-Proc (Join-Path $A.Root "app\1.0.0\$($A.EntryFile)") @('--hold', '600')
            Expect-Lines $holdOut @('1.0.0 start', '1.0.0 nothing-pending', '1.0.0 hold')
            $o = New-Out 'row3b'
            Update-ViaRuntime $A '1.1.0' '1.2.0' -NoUi -restartArgs @('--after-update')
            Expect-Lines $o @('1.2.0 start', '1.2.0 arg after-update', '1.2.0 event updated 1.1.0', '1.2.0 event first_run', '1.2.0 confirmed')
            Wait-Updated $A '1.2.0'
            Assert-Record $A '1.2.0' '1.1.0' @()
            # Row 5: 1.0.0 is outside current and previous, so the apply would collect it, but a
            # process still runs from it, so its tree stays.
            SameV 'versions on disk while 1.0.0 runs' ((App-Versions $A) -join ',') '1.0.0,1.1.0,1.2.0'
            Require (-not $state.Holder.HasExited) 'the process from 1.0.0 still runs'
            $state.Holder.Kill()
            $null = $state.Holder.WaitForExit(20000)
        }

        Row '4 (1.3.0 crashes on start: rollback, the bad version is not offered again)' {
            Publish-Version $A '1.3.0' @{ Flags = @('crash-on-start') }
            $o = New-Out 'row4a'
            $null = Start-Proc (Stub-Path $A) @('--update', '--no-ui')
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.3.0', '1.2.0 staged 1.3.0', '1.2.0 apply-scheduled',
                '1.3.0 start', '1.3.0 arg after-update', '1.3.0 event updated 1.2.0', '1.3.0 event first_run', '1.3.0 crash',
                '1.2.0 start', '1.2.0 arg after-update', '1.2.0 nothing-pending')
            Wait-Runtimes-Gone $A.Root
            Assert-Record $A '1.2.0' $null @('1.3.0')
            # The rollback's collection: only the current version stays, and now the tree of 1.0.0 goes (row 5).
            Wait-Until { ((App-Versions $A) -join ',') -eq '1.2.0' } 60 'the trees of 1.0.0, 1.1.0 and 1.3.0 to be collected'
            $o = New-Out 'row4b'
            $null = Start-Proc (Stub-Path $A) @('--update', '--no-ui')
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check none')
        }

        Row '4 (1.4.0 confirms too slowly: rollback)' {
            Publish-Version $A '1.4.0' @{ Flags = @('slow-confirm 60'); Timeout = 5 }
            $o = New-Out 'row4c'
            $null = Start-Proc (Stub-Path $A) @('--update', '--no-ui')
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.4.0', '1.2.0 staged 1.4.0', '1.2.0 apply-scheduled',
                '1.4.0 start', '1.4.0 arg after-update', '1.4.0 event updated 1.2.0', '1.4.0 event first_run', '1.4.0 slow-confirm',
                '1.2.0 start', '1.2.0 arg after-update', '1.2.0 nothing-pending') -Seconds 150
            Wait-Runtimes-Gone $A.Root
            Assert-Record $A '1.2.0' $null @('1.3.0', '1.4.0')
            Wait-Until { ((App-Versions $A) -join ',') -eq '1.2.0' } 60 'the tree of 1.4.0 to be collected'
        }

        Row '4 (attempt counter after a killed supervisor)' {
            Publish-Version $A '1.5.0' @{ Flags = @('exit-without-confirm'); Timeout = 120 }
            $o = New-Out 'row4d'
            $null = Start-Proc (Stub-Path $A) @('--update', '--no-ui')
            Expect-Lines $o @('1.2.0 start', '1.2.0 nothing-pending', '1.2.0 check 1.5.0', '1.2.0 staged 1.5.0', '1.2.0 apply-scheduled',
                '1.5.0 start', '1.5.0 arg after-update', '1.5.0 event updated 1.2.0', '1.5.0 event first_run', '1.5.0 exit-without-confirm')
            # The app has exited without confirming; the supervisor keeps waiting. Kill it.
            Wait-Until { @(Get-Runtimes $A.Root).Count -eq 1 } 30 'one runtime in apply mode'
            Get-Runtimes $A.Root | ForEach-Object { Stop-Process -Id $_.Id -Force }
            Wait-Runtimes-Gone $A.Root
            Assert-Record $A '1.5.0' '1.2.0' @('1.3.0', '1.4.0') @('1.5.0', 0)
            # Three unsupervised starts count one attempt each.
            foreach ($attempt in 1..3) {
                $o = New-Out "row4d$attempt"
                $null = Start-Proc (Stub-Path $A)
                Expect-Lines $o @('1.5.0 start', '1.5.0 exit-without-confirm')
                Assert-Record $A '1.5.0' '1.2.0' @('1.3.0', '1.4.0') @('1.5.0', $attempt)
            }
            # The fourth rolls back and starts 1.2.0 in its place; the two apps' lines race.
            $o = New-Out 'row4d4'
            $null = Start-Proc (Stub-Path $A)
            Expect-Lines $o @('1.5.0 start', '1.5.0 exit rolled-back', '1.2.0 start', '1.2.0 nothing-pending') -Unordered
            Assert-Record $A '1.2.0' $null @('1.3.0', '1.4.0', '1.5.0')
        }

        Row '11 (display-name change: Setup rerun, update, a user rename)' {
            $oldName = $A.Name
            Publish-Version $A '1.6.0' @{ Name = "$($A.BaseName) Renamed" }
            $newName = $A.Name
            $setup16 = Build-Setup $A '1.6.0'
            $oldRoot = $A.Root
            # (a) The newer Setup over the installed app finds the install by its record: the app is
            # already installed (exit 23), no folder of the new name, nothing of the install changed.
            $r = Run-Tool $setup16 @('/S')
            SameV 'Setup rerun exit code (already installed)' $r.Code 23
            Require (-not (Test-Path -LiteralPath (Join-Path $programs $newName))) 'no folder of the new name after the Setup rerun'
            Require (Test-Path -LiteralPath (Join-Path $oldRoot 'app\1.2.0')) 'the install is intact after the Setup rerun'
            Same 'DisplayName after the Setup rerun' (Get-ItemProperty $key).DisplayName $oldName
            # (b) The update to the release with the new name keeps R and its old folder name.
            $o = New-Out 'row11'
            $null = Start-Proc (Stub-Path $A) @('--update', '--no-ui')
            Expect-Lines $o (Confirmed-Lines '1.2.0' '1.6.0')
            Wait-Updated $A '1.6.0'
            Require (Test-Path -LiteralPath $oldRoot) 'R keeps its folder after the update'
            Require (-not (Test-Path -LiteralPath (Join-Path $programs $newName))) 'no folder of the new name after the update'
            Require (-not (Test-Path -LiteralPath (Join-Path $startMenu "$oldName.lnk"))) 'the old shortcut is gone'
            $lnk = Join-Path $startMenu "$newName.lnk"
            Require (Test-Path -LiteralPath $lnk) 'a shortcut with the new name exists'
            $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
            Same 'shortcut target' $sc.TargetPath (Stub-Path $A)
            Same 'DisplayName' (Get-ItemProperty $key).DisplayName $newName
            $o = New-Out 'row11b'
            $null = Start-Proc (Stub-Path $A)
            Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending')
            # (c) A user renames the folder while nothing runs: the stub there still starts the app,
            # and a Setup rerun finds the install by its record (exit 23), not by its name.
            Stop-Under $oldRoot
            $moved = "$oldName Moved"
            Rename-Item -LiteralPath $oldRoot -NewName $moved
            try {
                $o = New-Out 'row11c'
                $null = Start-Proc (Join-Path (Join-Path $programs $moved) $A.EntryFile)
                Expect-Lines $o @('1.6.0 start', '1.6.0 nothing-pending')
                $r = Run-Tool $setup16 @('/S')
                SameV 'Setup rerun exit code (renamed folder)' $r.Code 23
                Require (-not (Test-Path -LiteralPath (Join-Path $programs $oldName))) 'the rerun made no folder of the old name'
                Require (-not (Test-Path -LiteralPath (Join-Path $programs $newName))) 'the rerun made no folder of the new name'
            } finally {
                Stop-Under (Join-Path $programs $moved)
                Rename-Item -LiteralPath (Join-Path $programs $moved) -NewName $oldName
            }
        }

        Row '8 (uninstall by QuietUninstallString)' {
            Invoke-Uninstall $A
            $copies = @(New-TempDirs 'lunepack-uninstall-')
            Require ($copies.Count -le 1) 'at most the uninstaller copy remains in temp (M7-D5)'
            $state.FirstCopies = $copies
        } -Undo { Reset-App $A }

        Row '2 (interactive Setup with the stand-in UI; a UI that dies; the stale copy goes)' {
            $A.Name = $A.BaseName
            Reset-Ui
            $r = Run-Tool $setup
            SameV 'interactive Setup exit code' $r.Code 0
            Require ((@($r.Out) -join '') -match '"outcome":"installed"') 'the result line says installed'
            $A.Root = Join-Path $programs $A.BaseName
            Assert-Installed $A '1.0.0'
            SameV 'windows started' (@(Ui-Notes 'ui-spawns')).Count 1
            Require ((@(Ui-Notes 'ui-hello') -join '|') -like "*$($A.BaseName)*") 'the window was told the app name'
            SameV 'UI directories left in temp' (@(New-TempDirs 'lunepack-setup-ui-')).Count 0
            Invoke-Uninstall $A
            # The second cycle collected the first uninstaller copy (its owner is gone); only the new one may stay.
            $copies = @(New-TempDirs 'lunepack-uninstall-')
            foreach ($old in @($state.FirstCopies)) { Require ($copies -notcontains $old) 'the stale uninstaller copy of the first cycle was removed' }
            Require ($copies.Count -le 1) 'at most one uninstaller copy remains'
            # A window that dies during the install changes nothing (C10): same install, a warning.
            Reset-Ui
            $env:LUNEPACK_E2E_UI_MODE = 'die'
            try { $r = Run-Tool $setup } finally { Remove-Item Env:LUNEPACK_E2E_UI_MODE -ErrorAction SilentlyContinue }
            SameV 'Setup exit code with a dying window' $r.Code 0
            Require ($r.Err -match 'ui_stopped') 'the dying window is reported as a warning'
            $A.Root = Join-Path $programs $A.BaseName
            Assert-Installed $A '1.0.0'
            Invoke-Uninstall $A
        } -Undo { Remove-Item Env:LUNEPACK_E2E_UI_MODE -ErrorAction SilentlyContinue; Reset-App $A }

        Row '12 (taken folder, M7-D17)' {
            $taken = Join-Path $programs $A.BaseName
            $alt = Join-Path $programs "$($A.BaseName) ($($A.Id))"
            # A foreign folder with one file: the app goes to "<name> (<app id>)" and the folder is untouched.
            New-Item -ItemType Directory $taken | Out-Null
            $foreign = Join-Path $taken 'foreign.txt'
            [IO.File]::WriteAllText($foreign, 'not ours', $utf8)
            $before = (Get-FileHash -LiteralPath $foreign -Algorithm SHA256).Hash
            $r = Run-Tool $setup @('/S')
            SameV 'setup exit code (foreign folder)' $r.Code 0
            Require (Test-Path -LiteralPath (Join-Path $alt 'app\1.0.0')) 'installed beside the foreign folder'
            Same 'foreign file hash' (Get-FileHash -LiteralPath $foreign -Algorithm SHA256).Hash $before
            SameV 'foreign folder entries' (@(Get-ChildItem -LiteralPath $taken -Force).Count) 1
            $A.Root = $alt
            Invoke-Uninstall $A
            Require (-not (Test-Path -LiteralPath $alt)) 'uninstall removed the app folder'
            Same 'foreign file hash after uninstall' (Get-FileHash -LiteralPath $foreign -Algorithm SHA256).Hash $before
            Remove-Item -LiteralPath $taken -Recurse -Force
            # An empty folder with that name is adopted.
            New-Item -ItemType Directory $taken | Out-Null
            $r = Run-Tool $setup @('/S')
            SameV 'setup exit code (empty folder)' $r.Code 0
            Require (Test-Path -LiteralPath (Join-Path $taken 'app\1.0.0')) 'the empty folder was adopted'
            Require (-not (Test-Path -LiteralPath $alt)) 'no second folder was made'
            $A.Root = $taken
            Invoke-Uninstall $A
        } -Undo { Reset-App $A }

        # ---- app B: the stub replaced while a console stub instance runs ------------------------------------------------
        Row '3 (a running console stub is replaced; its aside copy goes with the next GC)' {
            $null = Install-Silent $B $setupB
            Assert-Installed $B '1.0.0'
            Publish-Version $B '1.1.0'
            $o = New-Out 'row3c'
            $holder = Start-Proc (Stub-Path $B) @('--hold', '600')
            Expect-Lines $o @('1.0.0 start', '1.0.0 event installed', '1.0.0 event first_run', '1.0.0 nothing-pending', '1.0.0 hold')
            $o = New-Out 'row3d'
            Update-ViaRuntime $B '1.0.0' '1.1.0' -NoUi
            Wait-Updated $B '1.1.0'
            SameV 'stub ProductVersion after the update' (Get-Item -LiteralPath (Stub-Path $B)).VersionInfo.ProductVersion '1.1.0'
            $aside = @(Get-ChildItem -LiteralPath $B.Root -Force -File | Where-Object { $_.Name -match ('^\.' + [regex]::Escape($B.EntryFile) + '\.old-[0-9a-f]{16}$') })
            SameV 'running stub copies renamed aside' $aside.Count 1
            Require (-not $holder.HasExited) 'the console stub that was running still runs'
            # Let it exit: the app it started goes, then the stub; the next apply collects the aside copy.
            Stop-Under (Join-Path $B.Root 'app\1.0.0')
            Wait-Until { $holder.HasExited } 30 'the console stub to exit'
            Publish-Version $B '1.2.0'
            Update-ViaRuntime $B '1.1.0' '1.2.0' -NoUi
            Wait-Updated $B '1.2.0'
            Wait-Until { @(Get-ChildItem -LiteralPath $B.Root -Force -File | Where-Object { $_.Name -like '.*.old-*' }).Count -eq 0 } 60 'the aside copy to be collected'
            SameV 'stub ProductVersion after the second update' (Get-Item -LiteralPath (Stub-Path $B)).VersionInfo.ProductVersion '1.2.0'
            Invoke-Uninstall $B
        } -Undo { Reset-App $B }

        # ---- app D: console stub stdio, exit code and console events ---------------------------------------------------------
        Row '6 (console stub: stdio and exit code pass through)' {
            $null = Install-Silent $D $setupD
            Assert-Installed $D '1.0.0'
            $r = Run-Console (Stub-Path $D) '--echo out-line --eecho err-line --cat --exit 7' 'in-data'
            SameV 'standard output' $r.Out 'out-linein-data'
            SameV 'standard error' $r.Err 'err-line'
            SameV 'exit code' $r.Code 7
            $r = Run-Console (Stub-Path $D) '--exit 0' ''
            SameV 'exit code 0' $r.Code 0
        } -Undo { Reset-App $D }

        Row 'console events (Ctrl+C and Ctrl+Break reach the app, not the stub)' {
            $ctlCopy = Join-Path $work 'ctl-control.exe'
            Copy-Item $ctlExe $ctlCopy
            $out = & (Join-Path $PSScriptRoot 'ci\console-ctrl-test.ps1') -Stub (Stub-Path $D) -Ctl $ctlCopy -WorkDir $work
            $out | ForEach-Object { Write-Output "     $_" }
            Require ($LASTEXITCODE -eq 0) 'the console-event checks pass'
            Stop-Under $D.Root
            Invoke-Uninstall $D
        } -Undo { Reset-App $D }

        # ---- app C: a long path ---------------------------------------------------------------------------------------------------
        Row '7 (an entry path over 260 characters installs, launches and uninstalls)' {
            $null = Install-Silent $C $setupC
            $entryFull = Join-Path $C.Root ("app\1.0.0\" + ($C.EntryRel -replace '/', '\'))
            Require ($entryFull.Length -gt 260) 'the entry path is over 260 characters'
            Require (Test-Path -LiteralPath (Long $entryFull)) 'the entry is installed'
            Require (Test-Path -LiteralPath (Stub-Path $C)) 'the stub is at R'
            $o = New-Out 'row7'
            $longPaths = $null
            try { $longPaths = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction Stop).LongPathsEnabled } catch { }
            $r = Run-Console (Stub-Path $C) '' ''
            if ($r.Code -eq 0) {
                Expect-Lines $o @('1.0.0 start', '1.0.0 event installed', '1.0.0 event first_run', '1.0.0 nothing-pending') -Seconds 30
            } elseif ($longPaths -eq 1) {
                throw "the launch failed with exit $($r.Code) although LongPathsEnabled is 1"
            } else {
                # The documented limit: the system's own path limit applies to the launch when it is off.
                Write-Output "     note: the launch needs LongPathsEnabled (value '$longPaths'); install and uninstall are checked, exit code $($r.Code)"
            }
            Invoke-Uninstall $C
        } -Undo { Reset-App $C }

        # The certificate is trusted machine-wide, so only a CI runner (a throwaway machine) runs this.
        if ($env:CI -eq 'true') {
            Row 'signed Setup.exe' {
                # The signed copy installs app A with /S: no install of A may be left from a row before.
                Require (-not (Test-Path -LiteralPath $key)) 'app A is not installed before the signed-setup row'
                $out = & (Join-Path $PSScriptRoot 'ci\windows-sign-test.ps1') -Setup $setup
                $out | ForEach-Object { Write-Output "     $_" }
                Require ($LASTEXITCODE -eq 0) 'the signed-setup checks pass'
            }
        } else {
            Write-Output 'skipped: the signed Setup.exe row (CI only: it trusts a certificate machine-wide)'
        }
    }
} catch {
    $failures.Add('setup')
    Write-Output "FAIL setup: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
} finally {
    Cleanup
}

$left = Leftovers
if ($left.Count -gt 0) { $failures.Add('leftovers'); Write-Output "FAIL leftovers: $($left -join ', ')" }
if ($failures.Count -gt 0) {
    Write-Output "e2e-windows: FAILED ($($failures -join ', '))"
    exit 1
}
Write-Output 'e2e-windows: ok'
exit 0
