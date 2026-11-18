# Windows end-to-end run (M7 step 13), native, no Docker.
#
# Builds the release runtime, both stubs, `lunepack` and the e2e app, packs a `windows-x86_64`
# release under a unique app id and a display name with a space and a non-ASCII letter, builds its
# `Setup.exe` with `lunepack setup`, and checks what the packager and the setup file hold. With
# -Install (the default on CI) it also installs for real into the current user's
# %LOCALAPPDATA%\Programs, checks the install's state on disk, in the registry and in the Start
# menu, uninstalls the way the shell would, and checks the taken-folder rule (M7-D17). The install
# rows write under the real per-user locations, so a developer machine runs them only on request.
# Everything the run creates is removed, also after a failure, and the script asserts it.
#
# Rows done here: 1 (install and its state), 8 (uninstall by QuietUninstallString), 9 (planted
# DLLs, garbage-file form), 10 (static half), 12 (taken folder), and on CI the signed Setup.exe
# (scripts/ci/windows-sign-test.ps1). Rows 2 to 7 and 11 are not yet
# in this script; the harness never prints environment or registry dumps, only the name of a
# differing field.
param([switch]$Install)
$ErrorActionPreference = 'Stop'
if ($env:CI -eq 'true' -or $env:LUNEPACK_E2E_INSTALL -eq '1') { $Install = $true }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tdir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
$rel = Join-Path $tdir 'release'

$hex = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$appId = "org.example.lpe2e$hex"
$name = "Lunepack E2E $([char]0xC4) $hex"
$entryFile = "lpe2e$hex.exe"
$programs = Join-Path $env:LOCALAPPDATA 'Programs'
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$uninstallKeyRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$work = Join-Path ([IO.Path]::GetTempPath()) "lunepack-e2e-$hex"
$tempBefore = @(Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
$failures = New-Object System.Collections.Generic.List[string]
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Row([string]$id, [scriptblock]$body) {
    try {
        & $body
        Write-Output "ok   row $id"
    } catch {
        $failures.Add("row $id")
        Write-Output "FAIL row ${id}: $($_.Exception.Message)"
    }
}

function Require([bool]$condition, [string]$what) {
    if (-not $condition) { throw "expected: $what" }
}

function Same([string]$what, $got, $want) {
    if ($got -ne $want) { throw "field $what differs" }
}

# A Windows PE's subsystem (optional header offset 68).
function PeSubsystem([string]$path) {
    $b = [IO.File]::ReadAllBytes($path)
    $pe = [BitConverter]::ToInt32($b, 0x3C)
    return [BitConverter]::ToUInt16($b, $pe + 24 + 68)
}

function RemoveInstall([string]$folderName) {
    $dir = Join-Path $programs $folderName
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

function Cleanup {
    # Uninstall through the entry's own command first, then sweep what is ours by name.
    $key = Join-Path $uninstallKeyRoot $appId
    if (Test-Path $key) {
        $quiet = (Get-ItemProperty $key).QuietUninstallString
        if ($quiet -match '^"([^"]+)"\s*(.*)$' -and (Test-Path -LiteralPath $Matches[1])) {
            try { Start-Process -FilePath $Matches[1] -ArgumentList $Matches[2] -Wait } catch { }
            for ($i = 0; $i -lt 30 -and (Test-Path $key); $i++) { Start-Sleep -Seconds 1 }
        }
    }
    foreach ($folder in @($name, "$name ($appId)")) { RemoveInstall $folder }
    Remove-Item -LiteralPath (Join-Path $startMenu "$name.lnk") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($d in Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -ErrorAction SilentlyContinue) {
        # Only what this run created: uninstall copies and UI dirs that were not there at the start.
        if ($tempBefore -notcontains $d.Name -and $d.Name -match '^lunepack-(uninstall|setup-ui)-[0-9a-f]{16}$') {
            Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

function Leftovers {
    $left = @()
    foreach ($d in Get-ChildItem $programs -Directory -ErrorAction SilentlyContinue) { if ($d.Name -like "Lunepack E2E*$hex*") { $left += "folder" } }
    foreach ($f in Get-ChildItem $startMenu -Filter '*.lnk' -ErrorAction SilentlyContinue) { if ($f.Name -like "Lunepack E2E*$hex*") { $left += "shortcut" } }
    if (Test-Path (Join-Path $uninstallKeyRoot $appId)) { $left += 'uninstall key' }
    return $left
}

try {
    Write-Output "e2e-windows: building"
    Push-Location $repo
    try {
        cargo build --locked --release -p lunepack-cli -p lunepack-runtime -p lunepack-stub
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
        cargo build --locked --release -p lunepack --example e2e_app
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (example) failed' }
    } finally { Pop-Location }
    $cli = Join-Path $rel 'lunepack.exe'
    $runtime = Join-Path $rel 'lunepack-runtime.exe'
    $stub = Join-Path $rel 'lunepack-stub.exe'
    $stubConsole = Join-Path $rel 'lunepack-stub-console.exe'
    $app = Join-Path $rel 'examples\e2e_app.exe'
    foreach ($f in $cli, $runtime, $stub, $stubConsole, $app) { Require (Test-Path $f) "a built file exists" }

    # ---- a release: config, keys, one packed version, its setup file --------------------------
    New-Item -ItemType Directory $work, "$work\rel", "$work\input" | Out-Null
    $cfg = Join-Path $work 'lunepack.toml'
    # Native stderr is not an error here (`keys gen` reports on it), so the preference is relaxed per call.
    function L {
        $old = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & $cli --config $cfg @args 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $old }
    }
    function Pub([string]$base) { ((L keys gen $base) | Select-String '^public:') -replace '^public:\s*', '' }
    $rootPub = Pub (Join-Path $work 'rootk')
    $relPub = Pub (Join-Path $work 'rel0')
    L init --app-id $appId --root-key $rootPub | Out-Null
    $toml = @"

[update]
feed = "https://updates.example.com/$appId"
channel = "stable"
health_timeout_secs = 30

[install]
entry = "$entryFile"
name = "$name"
publisher = "Lunepack E2E"
"@
    [IO.File]::AppendAllText($cfg, $toml, $utf8)
    Copy-Item $app (Join-Path $work "input\$entryFile")
    L keys set --release-dir "$work\rel" --threshold 1 --release-key $relPub --sign "file:$work\rootk.key" | Out-Null
    L pack --input "$work\input" --version 1.0.0 --target windows-x86_64 --release-dir "$work\rel" --sign "file:$work\rel0.key" --runtime $runtime --stub $stub | Out-Null
    Require ($LASTEXITCODE -eq 0) 'pack succeeds'
    $setup = Join-Path $work 'Setup.exe'
    L setup "$work\rel" --version 1.0.0 --target windows-x86_64 --out $setup | Out-Null
    Require ($LASTEXITCODE -eq 0) 'setup file builds'

    # ---- rows that install nothing ---------------------------------------------------------------
    Row '10 (static)' {
        Same 'runtime subsystem' (PeSubsystem $runtime) 2
        Same 'setup subsystem' (PeSubsystem $setup) 2
        Same 'GUI stub subsystem' (PeSubsystem $stub) 2
        Same 'console stub subsystem' (PeSubsystem $stubConsole) 3
        $v = (Get-Item $setup).VersionInfo
        Same 'Setup FileDescription' $v.FileDescription "$name Setup"
        Same 'Setup ProductName' $v.ProductName $name
        Same 'Setup CompanyName' $v.CompanyName 'Lunepack E2E'
        Same 'Setup ProductVersion' $v.ProductVersion '1.0.0'
        Same 'Setup OriginalFilename' $v.OriginalFilename 'Setup.exe'
    }
    Row '9 (planted DLLs, garbage-file form)' {
        $out = & (Join-Path $PSScriptRoot 'ci\plant-dll-test.ps1') -Case "setup=$setup=--no-such-option", "runtime=$runtime=--no-such-option", "console-stub=$stubConsole="
        $out | ForEach-Object { Write-Output "     $_" }
        Require ($LASTEXITCODE -eq 0) 'no planted DLL breaks a start'
    }

    # ---- rows that install -----------------------------------------------------------------------
    if (-not $Install) {
        Write-Output 'skipped: rows 1, 8, 12 (they install into the real per-user locations; pass -Install or set LUNEPACK_E2E_INSTALL=1)'
    } else {
        $root = Join-Path $programs $name
        $key = Join-Path $uninstallKeyRoot $appId
        $lnk = Join-Path $startMenu "$name.lnk"
        Require (-not (Test-Path -LiteralPath $root)) 'no earlier install of this unique name'

        Row '1 (install, state)' {
            $p = Start-Process -FilePath $setup -ArgumentList '/S' -Wait -PassThru
            Same 'setup exit code' $p.ExitCode 0
            Require (Test-Path -LiteralPath $root) 'the install folder exists'
            $top = @(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object)
            Same 'top level of R' ($top -join '|') ((@('.lunepack', 'app', $entryFile) | Sort-Object) -join '|')
            $hidden = (Get-Item -LiteralPath (Join-Path $root '.lunepack') -Force).Attributes -band [IO.FileAttributes]::Hidden
            Require ($hidden -ne 0) '.lunepack is hidden'
            Require (Test-Path -LiteralPath (Join-Path $root 'app\1.0.0')) 'app\1.0.0 exists'
            Require (Test-Path -LiteralPath (Join-Path $root '.lunepack\state')) '.lunepack\state exists'
            $v = (Get-Item -LiteralPath (Join-Path $root $entryFile)).VersionInfo
            Same 'stub FileDescription' $v.FileDescription $name
            Same 'stub ProductVersion' $v.ProductVersion '1.0.0'
            Same 'stub OriginalFilename' $v.OriginalFilename $entryFile
            $u = Get-ItemProperty $key
            Same 'DisplayName' $u.DisplayName $name
            Same 'InstallLocation' $u.InstallLocation $root
            Same 'DisplayVersion' $u.DisplayVersion '1.0.0'
            Same 'QuietUninstallString' $u.QuietUninstallString "`"$(Join-Path $root $entryFile)`" --lunepack-uninstall /S"
            $pkg = Get-Package -ProviderName Programs -Name $name -ErrorAction SilentlyContinue
            Require ($null -ne $pkg) 'Get-Package lists the app'
            Require (Test-Path -LiteralPath $lnk) 'the Start-menu shortcut exists'
            $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
            Same 'shortcut target' $sc.TargetPath (Join-Path $root $entryFile)
            # The app, started through the stub, writes its marker line.
            $marker = Join-Path $work 'marker.txt'
            $env:LUNEPACK_E2E_OUT = $marker
            try { Start-Process -FilePath (Join-Path $root $entryFile) | Out-Null } finally { Remove-Item Env:LUNEPACK_E2E_OUT }
            for ($i = 0; $i -lt 20 -and -not (Test-Path $marker); $i++) { Start-Sleep -Milliseconds 500 }
            Require (Test-Path $marker) 'the app started through the stub wrote its marker'
            Require ((Get-Content $marker -Raw) -match '^1\.0\.0 ') 'the marker names version 1.0.0'
        }

        Row '8 (uninstall by QuietUninstallString)' {
            $quiet = (Get-ItemProperty $key).QuietUninstallString
            # The documented rule: a quoted program path, then the arguments; no shell.
            Require ($quiet -match '^"([^"]+)"\s*(.*)$') 'the string has the documented shape'
            $u = Start-Process -FilePath $Matches[1] -ArgumentList $Matches[2] -Wait -PassThru
            Same 'stub exit code' $u.ExitCode 0
            for ($i = 0; $i -lt 60 -and (Test-Path -LiteralPath $root); $i++) { Start-Sleep -Seconds 1 }
            Require (-not (Test-Path -LiteralPath $root)) 'R is gone'
            Require (-not (Test-Path -LiteralPath $lnk)) 'the shortcut is gone'
            Require (-not (Test-Path $key)) 'the Uninstall key is gone'
            $copies = @(Get-ChildItem ([IO.Path]::GetTempPath()) -Directory | Where-Object { $tempBefore -notcontains $_.Name -and $_.Name -like 'lunepack-uninstall-*' })
            Require ($copies.Count -le 1) 'at most the uninstaller copy remains in temp (M7-D5)'
        }

        Row '12 (taken folder, M7-D17)' {
            $taken = Join-Path $programs $name
            $alt = Join-Path $programs "$name ($appId)"
            # A foreign folder with one file: the app goes to "<name> (<app id>)" and the folder is untouched.
            New-Item -ItemType Directory $taken | Out-Null
            $foreign = Join-Path $taken 'foreign.txt'
            [IO.File]::WriteAllText($foreign, 'not ours', $utf8)
            $before = (Get-FileHash -LiteralPath $foreign -Algorithm SHA256).Hash
            $p = Start-Process -FilePath $setup -ArgumentList '/S' -Wait -PassThru
            Same 'setup exit code (foreign folder)' $p.ExitCode 0
            Require (Test-Path -LiteralPath (Join-Path $alt 'app\1.0.0')) 'installed beside the foreign folder'
            Same 'foreign file hash' (Get-FileHash -LiteralPath $foreign -Algorithm SHA256).Hash $before
            Same 'foreign folder entries' (@(Get-ChildItem -LiteralPath $taken -Force).Count) 1
            $quiet = (Get-ItemProperty $key).QuietUninstallString
            Require ($quiet -match '^"([^"]+)"\s*(.*)$') 'the string has the documented shape'
            Start-Process -FilePath $Matches[1] -ArgumentList $Matches[2] -Wait | Out-Null
            for ($i = 0; $i -lt 60 -and (Test-Path -LiteralPath $alt); $i++) { Start-Sleep -Seconds 1 }
            Require (-not (Test-Path -LiteralPath $alt)) 'uninstall removed the app folder'
            Same 'foreign file hash after uninstall' (Get-FileHash -LiteralPath $foreign -Algorithm SHA256).Hash $before
            Remove-Item -LiteralPath $taken -Recurse -Force
            # An empty folder with that name is adopted.
            New-Item -ItemType Directory $taken | Out-Null
            $p = Start-Process -FilePath $setup -ArgumentList '/S' -Wait -PassThru
            Same 'setup exit code (empty folder)' $p.ExitCode 0
            Require (Test-Path -LiteralPath (Join-Path $taken 'app\1.0.0')) 'the empty folder was adopted'
            Require (-not (Test-Path -LiteralPath $alt)) 'no second folder was made'
            $quiet = (Get-ItemProperty $key).QuietUninstallString
            Require ($quiet -match '^"([^"]+)"\s*(.*)$') 'the string has the documented shape'
            Start-Process -FilePath $Matches[1] -ArgumentList $Matches[2] -Wait | Out-Null
            for ($i = 0; $i -lt 60 -and (Test-Path -LiteralPath (Join-Path $taken 'app')); $i++) { Start-Sleep -Seconds 1 }
        }
        # The certificate is trusted machine-wide, so only a CI runner (a throwaway machine) runs this.
        if ($env:CI -eq 'true') {
            Row 'signed Setup.exe' {
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
    Write-Output "FAIL setup: $($_.Exception.Message)"
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
