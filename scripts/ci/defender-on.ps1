# Windows Defender on, for the `e2e-windows-defender` job (M7 step 14). CI only.
#
# The hosted runner image sets ForceDefenderPassiveMode=1, excludes C:\ and D:\ and turns off
# real-time, behaviour and IOAV protection. Without -Report this script removes that policy value
# and the exclusions, turns the protections on (the sequence of probe P-W4, probes/windows/
# p-w4-defender.ps1), waits up to 60 s for real-time protection, and then runs the decisive
# control: the industry-standard anti-malware test string, assembled here at run time and never
# stored in the repository, is written to a temp directory and must be detected (the write or the
# read refused, the file removed, or a threat detection) within 60 s. A control that fails makes
# the job INVALID (exit 4): a quiet Defender proves nothing. The time after the control is
# recorded for the report.
#
# With -Report <file> (a later step of the same job, whatever the suite's outcome) it lists what
# Defender detected after the control, as names only (the threat name and the leaf name of each
# resource), into <file>, and exits 1 when there is any detection other than the control's own:
# a detection of a lunepack binary fails the job, and the answer is code signing (M9), not an
# exclusion. The runner is disposable; nothing is restored.
param([string]$Report = '')
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true') {
    [Console]::Error.WriteLine('defender-on: refusing to run outside GitHub Actions (it changes the machine''s Defender settings)')
    exit 3
}
$sinceFile = Join-Path $env:RUNNER_TEMP 'defender-since.txt'

function Test-ControlName([string]$name) {
    return $name -match 'EICAR'
}

if ($Report -ne '') {
    if (-not (Test-Path -LiteralPath $sinceFile)) {
        Set-Content -LiteralPath $Report -Value 'no control point: the Defender step did not finish'
        Write-Output 'defender-report: no control point recorded'
        exit 1
    }
    $since = [datetime]::Parse((Get-Content -LiteralPath $sinceFile -Raw).Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    $lines = New-Object System.Collections.Generic.List[string]
    $hits = 0
    $all = @()
    try { $all = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $since }) } catch { $lines.Add('Get-MpThreatDetection failed') }
    $threats = @{}
    try { foreach ($t in @(Get-MpThreat)) { $threats[[string]$t.ThreatID] = [string]$t.ThreatName } } catch { }
    foreach ($d in $all) {
        $name = $threats[[string]$d.ThreatID]
        if (-not $name) { $name = "threat $($d.ThreatID)" }
        $leaves = @(@($d.Resources) | ForEach-Object { ($_ -replace '^[^:]+:_', '') } | ForEach-Object { Split-Path $_ -Leaf }) -join ', '
        $lines.Add("$name :: $leaves")
        if (-not (Test-ControlName $name)) { $hits++ }
    }
    $lines.Insert(0, "detections after the control: $($all.Count) (not the control's own: $hits)")
    Set-Content -LiteralPath $Report -Value $lines
    $lines | ForEach-Object { Write-Output $_ }
    if ($hits -gt 0) { Write-Output 'FAIL: Defender detected something during the run (the answer is code signing, M9)'; exit 1 }
    exit 0
}

$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
Remove-ItemProperty -Path $policyKey -Name ForceDefenderPassiveMode -ErrorAction SilentlyContinue
foreach ($p in @((Get-MpPreference).ExclusionPath)) { if ($p) { Remove-MpPreference -ExclusionPath $p -ErrorAction Stop } }
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -ErrorAction Stop
try { Restart-Service -Name WinDefend -Force -ErrorAction Stop } catch { Write-Output 'note: WinDefend did not restart' }

$on = $false
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    try { if ((Get-MpComputerStatus).RealTimeProtectionEnabled) { $on = $true; break } } catch { }
    Start-Sleep -Seconds 2
}
$st = Get-MpComputerStatus
Write-Output "real-time protection: $($st.RealTimeProtectionEnabled), behaviour monitor: $($st.BehaviorMonitorEnabled), IOAV: $($st.IoavProtectionEnabled)"
if (-not $on) { Write-Output 'INVALID: real-time protection did not come on within 60 s'; exit 4 }

# The decisive control.
$work = Join-Path ([IO.Path]::GetTempPath()) ('lunepack-defender-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
try {
    $t0 = Get-Date
    $file = Join-Path $work 'control.txt'
    $f1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'
    $f2 = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
    $f3 = '!$H+H*'
    $detected = $false
    try { [IO.File]::WriteAllText($file, ($f1 + $f2 + $f3), [Text.Encoding]::ASCII) } catch { $detected = $true }
    $f1 = $null; $f2 = $null; $f3 = $null
    $scanned = $false
    $deadline = (Get-Date).AddSeconds(60)
    while (-not $detected -and (Get-Date) -lt $deadline) {
        $readable = $false
        if (Test-Path -LiteralPath $file) { try { [IO.File]::ReadAllBytes($file) | Out-Null; $readable = $true } catch { } }
        if (-not $readable) { $detected = $true; break }
        $hit = @()
        try { $hit = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $t0 }) } catch { }
        if ($hit.Count -gt 0) { $detected = $true; break }
        if (-not $scanned -and ((Get-Date) - $t0).TotalSeconds -gt 20) {
            $scanned = $true
            try { Start-MpScan -ScanType CustomScan -ScanPath $work -ErrorAction Stop } catch { }
        }
        Start-Sleep -Seconds 1
    }
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    if (-not $detected) { Write-Output 'INVALID: the anti-malware test string was not detected within 60 s'; exit 4 }
    Write-Output "control: the test string was detected after $([int]((Get-Date) - $t0).TotalSeconds) s"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
# Detections from here on belong to the suite (the control's own are named as such in the report).
(Get-Date).ToString('o') | Set-Content -LiteralPath $sinceFile
exit 0
