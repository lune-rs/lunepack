# Builds the prebuilt binaries of the windows-x86_64 release target (M13 step 14, M13-D19 as revised)
# into <OutDir>, each named lunepack-<kind>-<version>-windows-x86_64.exe: runtime, ui, service, stub
# (the GUI launcher) and stub-console. The C runtime is linked statically (.cargo/config.toml,
# M7-D10). Each file is checked: a PE of the x86-64 machine, with the subsystem the stubs and the
# service must have (GUI for stub, console for stub-console and service; the header checks `pack`
# applies). The Linux and macOS targets are built by build.sh.
#
#   pwsh ./scripts/release/build.ps1 -OutDir <dir>
#
# <OutDir> is created when absent and must be empty. LUNEPACK_BUILD_ID must not be set: the released
# binaries of one version are one build, so the version-based build id is exact (M13 P6).
param(
    [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (Test-Path Env:LUNEPACK_BUILD_ID) {
    throw 'LUNEPACK_BUILD_ID must not be set for a release build (it is set in this environment)'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$OutDir = [System.IO.Path]::GetFullPath($OutDir, (Get-Location).Path)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (@(Get-ChildItem -Force -LiteralPath $OutDir).Count -ne 0) { throw 'the output directory is not empty' }

Push-Location $repo
try {
    $meta = cargo metadata --no-deps --offline --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $pkgs = @(($meta | ConvertFrom-Json).packages | Where-Object { $_.name -eq 'lunepack-cli' })
    if ($pkgs.Count -ne 1) { throw 'the package lunepack-cli is not found once' }
    $version = [string]$pkgs[0].version
    if ($version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'the workspace version is not MAJOR.MINOR.PATCH' }

    $triple = 'x86_64-pc-windows-msvc'
    cargo build --locked --release --target $triple --config profile.release.strip=true `
        -p lunepack-runtime -p lunepack-ui -p lunepack-service -p lunepack-stub
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
    $release = Join-Path $targetDir "$triple/release"

    # kind -> (binary, required subsystem or 0 for any): 2 GUI, 3 console.
    $kinds = [ordered]@{
        'runtime'      = @('lunepack-runtime.exe', 0)
        'service'      = @('lunepack-service.exe', 3)
        'stub'         = @('lunepack-stub.exe', 2)
        'stub-console' = @('lunepack-stub-console.exe', 3)
        'ui'           = @('lunepack-ui.exe', 0)
    }
    foreach ($kind in $kinds.Keys) {
        $bin = Join-Path $release $kinds[$kind][0]
        if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) { throw "the build left no $bin" }
        $bytes = [System.IO.File]::ReadAllBytes($bin)
        if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw "$bin is not a PE file (no MZ)" }
        $pe = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($pe -lt 0 -or $pe + 0x5E -gt $bytes.Length) { throw "$bin has no PE header in the file" }
        if ($bytes[$pe] -ne 0x50 -or $bytes[$pe + 1] -ne 0x45 -or $bytes[$pe + 2] -ne 0 -or $bytes[$pe + 3] -ne 0) { throw "$bin is not a PE file (no PE signature)" }
        $machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
        if ($machine -ne 0x8664) { throw "$bin is not an x86-64 PE (machine 0x$('{0:X4}' -f $machine))" }
        $subsystem = [BitConverter]::ToUInt16($bytes, $pe + 24 + 68)
        $want = $kinds[$kind][1]
        if ($want -ne 0 -and $subsystem -ne $want) { throw "$bin has subsystem $subsystem, not $want" }
        $asset = "lunepack-$kind-$version-windows-x86_64.exe"
        Copy-Item -LiteralPath $bin -Destination (Join-Path $OutDir $asset)
        Write-Output "checked: $asset (PE x86-64, subsystem $subsystem)"
    }
}
finally {
    Pop-Location
}

Write-Output "built in ${OutDir}:"
Get-ChildItem -LiteralPath $OutDir | Sort-Object Name | ForEach-Object { Write-Output "  $($_.Name) $($_.Length) bytes" }
