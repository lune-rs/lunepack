# Console Ctrl+C / Ctrl+Break proof for the console stub (M7-D7, the step 8 caveat, step 13).
#
# The console stub ignores both console events in itself, so that an event meant for the app it
# runs (a terminal app that handles Ctrl+C and cleans up) does not end the launcher first: the
# shell would get its prompt back and the app would run on without a parent. The proof needs a real
# console event, a sender that is not the stub, and a control.
#
# The app is the stand-in `e2e-ctl-app.cs` compiled to an exe (-Ctl is a copy outside any install,
# -Stub the console stub of an install of it). In `--hold` mode it handles the event, writes
# `event <key>`, waits one second and exits 42. Each case starts a program in a console of its own
# (hidden, so a CI runner's console is never touched; for Ctrl+Break also in a process group of
# its own, which is how that event is addressed), waits for `ready`, sends the event from a
# separate process that attached to that console, and reads the exit code:
#
#   control   `<ctl> --parent`: a parent with no handler of its own. It dies of the event (exit
#             0xC000013A) while the app it started handles the event, so the sender works and an
#             unprotected parent is not spared.
#   stub      `<stub> --hold`: the event reaches the stub and the app; the app logs it, takes its
#             second, exits 42, and the stub, still alive, exits 42 as well. A stub that had died
#             of the event would have ended with 0xC000013A.
#
# Run for Ctrl+Break (group-addressed) and for Ctrl+C (console-wide). CI only: it opens consoles.
param(
    [string]$Stub,
    [string]$Ctl,
    [string]$WorkDir,
    [int]$Send = 0,
    [ValidateSet('ctrl-c', 'break')][string]$Kind = 'break'
)
$ErrorActionPreference = 'Stop'

if ($Send -ne 0) {
    # Sender mode: a process of its own, so that attaching to the target's console and ignoring
    # Ctrl+C here cannot touch the caller's console.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Lpe2eSend
{
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GenerateConsoleCtrlEvent(uint ctrlEvent, uint group);
    public static int Run(uint pid, bool breakEvent)
    {
        FreeConsole();
        if (!AttachConsole(pid)) { return 11; }
        SetConsoleCtrlHandler(IntPtr.Zero, true);
        bool sent = GenerateConsoleCtrlEvent(breakEvent ? 1u : 0u, breakEvent ? pid : 0u);
        System.Threading.Thread.Sleep(500);
        FreeConsole();
        return sent ? 0 : 12;
    }
}
'@
    exit ([Lpe2eSend]::Run([uint32]$Send, ($Kind -eq 'break')))
}

if (-not $Stub -or -not $Ctl -or -not $WorkDir) { Write-Output 'usage: console-ctrl-test.ps1 -Stub <console stub> -Ctl <app exe> -WorkDir <dir>'; exit 2 }
if (-not ('Lpe2eProc' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'e2e-native.cs') }
$utf8 = New-Object System.Text.UTF8Encoding($false)
$failed = 0

function Check([string]$what, [bool]$ok) {
    if ($ok) { Write-Output "ok   $what" } else { Write-Output "FAIL $what"; $script:failed++ }
}

function Read-Notes([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try {
        $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { $text = (New-Object IO.StreamReader($fs, $utf8)).ReadToEnd() } finally { $fs.Dispose() }
        return @($text -split "`r?`n" | Where-Object { $_ -ne '' })
    } catch { return @() }
}

# Runs one case; returns the exit code of the program started, the lines the app wrote and the
# sender's exit code ($null when the app never became ready).
function Run-Case([string]$label, [string]$commandLine, [string]$kind) {
    $out = Join-Path $WorkDir "ctrl-$label.txt"
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    $env:LUNEPACK_E2E_OUT = $out
    $flags = [Lpe2eProc]::NewConsole
    if ($kind -eq 'break') { $flags = $flags -bor [Lpe2eProc]::NewProcessGroup }
    $pidStarted = 0
    $h = [Lpe2eProc]::Start($commandLine, $flags, [ref]$pidStarted)
    $senderCode = $null
    $code = $null
    try {
        $deadline = (Get-Date).AddSeconds(40)
        while ((Get-Date) -lt $deadline -and (@(Read-Notes $out) -notcontains 'ready')) { Start-Sleep -Milliseconds 200 }
        if (@(Read-Notes $out) -contains 'ready') {
            $sender = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Send', "$pidStarted", '-Kind', $kind -Wait -PassThru -WindowStyle Hidden
            $senderCode = $sender.ExitCode
        }
        if ([Lpe2eProc]::Exited($h, 30000)) { $code = [Lpe2eProc]::ExitCode($h) }
        # The app handles the event after the control's parent is already gone: give it time.
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline -and -not (@(Read-Notes $out) | Where-Object { $_ -like 'event *' })) { Start-Sleep -Milliseconds 200 }
    } finally {
        if (-not [Lpe2eProc]::Exited($h, 0)) { [Lpe2eProc]::Kill($h) }
        [Lpe2eProc]::Close($h)
        Remove-Item Env:LUNEPACK_E2E_OUT -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ Code = $code; Notes = @(Read-Notes $out); Sender = $senderCode }
}

# A runner may start this script with Ctrl+C disabled (inherited from its own parent); a stub that
# inherited that would pass the Ctrl+C case for the wrong reason, and the control would not die.
[void][Lpe2eProc]::EnableCtrlC()
$diedOfEvent = [uint32]3221225786   # 0xC000013A, STATUS_CONTROL_C_EXIT
foreach ($spec in @(@('break', 'ControlBreak'), @('ctrl-c', 'ControlC'))) {
    $kind = $spec[0]
    $key = $spec[1]
    $control = Run-Case "control-$kind" "`"$Ctl`" --parent" $kind
    Check "[$kind] control: the sender delivered an event (sender exit 0)" ($control.Sender -eq 0)
    Check "[$kind] control: the app saw $key" (@($control.Notes) -contains "event $key")
    Check "[$kind] control: a parent with no handler died of it (0xC000013A)" ($null -ne $control.Code -and [uint32]$control.Code -eq $diedOfEvent)
    $run = Run-Case "stub-$kind" "`"$Stub`" --hold" $kind
    Check "[$kind] stub: the sender delivered an event (sender exit 0)" ($run.Sender -eq 0)
    Check "[$kind] stub: the app saw $key" (@($run.Notes) -contains "event $key")
    Check "[$kind] stub: the stub outlived the event and passed the app's exit code (42, not 0xC000013A)" ($null -ne $run.Code -and [int]$run.Code -eq 42)
}
if ($failed -gt 0) { Write-Output "console-ctrl-test: FAILED ($failed)"; exit 1 }
Write-Output 'console-ctrl-test: ok'
exit 0
