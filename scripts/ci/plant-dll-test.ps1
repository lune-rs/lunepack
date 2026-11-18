# Planted-DLL test (M7-D10, step 13 row 9), garbage-file form.
#
# A copy of each given binary goes into a fresh directory that also holds files named after DLLs
# the binary does not import statically (the Windows loader would pick them up from the
# application directory if the binary searched there). The files hold garbage, so a binary that
# loaded one would fail to start with a loader error; a binary that searches System32 only starts
# and ends with its own exit code. This is the fallback form of step 0 (c): the module-sampling
# instrument is not part of this script, so the row says "garbage-file form" in its output.
#
# Usage: plant-dll-test.ps1 -Case "<name>=<path>=<args>" [-Case ...]
#   Each case starts `<path> <args>` from a fresh directory (the arguments make the binary exit
#   at once: a usage error, a missing install) and passes when the process ends with an exit
#   code that is not a loader failure.
param(
    [Parameter(Mandatory = $true)][string[]]$Case,
    # DLL names a system DLL (not our binary) is known to load from the application directory
    # before main runs; reported as KNOWN, not a failure (see the finding in notes.md, step 13).
    [string[]]$Known = @('cryptbase')
)
$ErrorActionPreference = 'Stop'
# DLLs no lunepack binary imports statically (step 0 (c)'s fixed list, less the known DLLs).
$planted = 'winhttp', 'version', 'userenv', 'cryptbase', 'dwmapi', 'uxtheme', 'profapi', 'wldp', 'cryptsp', 'bcrypt', 'wtsapi32', 'secur32'
$loaderFailures = @('C0000135', 'C0000142', 'C000007B', 'C0000139', 'C0000005', 'C000012F') | ForEach-Object { [Convert]::ToUInt32($_, 16) }
$failed = 0

# Starts a copy of `path` in a fresh directory holding garbage files named after `dlls`; returns the exit code.
function Start-Planted([string]$path, [string]$arguments, [string[]]$dlls) {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("lunepack-plant-" + [Guid]::NewGuid().ToString('N').Substring(0, 16))
    New-Item -ItemType Directory $dir | Out-Null
    try {
        $copy = Join-Path $dir (Split-Path $path -Leaf)
        Copy-Item $path $copy
        foreach ($d in $dlls) {
            [IO.File]::WriteAllBytes((Join-Path $dir "$d.dll"), [byte[]](0x4C, 0x50, 0x2D, 0x70, 0x6C, 0x61, 0x6E, 0x74))
        }
        $start = @{ FilePath = $copy; PassThru = $true; WindowStyle = 'Hidden'; Wait = $true }
        if ($arguments) { $start['ArgumentList'] = $arguments }
        $p = Start-Process @start
        return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$p.ExitCode), 0)
    } finally {
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
    }
}

foreach ($c in $Case) {
    $name, $path, $arguments = $c.Split('=', 3)
    $code = Start-Planted $path $arguments $planted
    if ($loaderFailures -notcontains $code) {
        Write-Output ("ok   planted-dll {0}: started, exit {1} (garbage-file form)" -f $name, $code)
        continue
    }
    # Which planted names broke the start? Only those outside -Known fail the case.
    $culprits = @($planted | Where-Object { $loaderFailures -contains (Start-Planted $path $arguments @($_)) })
    $unknown = @($culprits | Where-Object { $Known -notcontains $_ })
    if ($unknown.Count -gt 0) {
        Write-Output ("FAIL planted-dll {0}: loaded from the application directory: {1}" -f $name, ($unknown -join ', '))
        $failed++
    } else {
        Write-Output ("KNOWN planted-dll {0}: a system DLL loads {1} from the application directory; everything else is ignored (garbage-file form)" -f $name, ($culprits -join ', '))
    }
}
exit $(if ($failed -gt 0) { 1 } else { 0 })
