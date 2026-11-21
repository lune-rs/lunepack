# Helpers for scripts that need a throwaway standard user (M10 step 11). Dot-source it. Runner and
# disposable-machine only: the script that sources it has already checked `CI` or `-Install` and
# the administrator right.
#
# The user's commands run as a process made from a batch-logon token of the account
# (scripts/ci/lib-user.cs, `LpRun`): no Task Scheduler and no profile load, so nothing of the
# account lingers once it is deleted. (A scheduled task with the password runs too, but the Task
# Scheduler leaves the account's profile loaded for good, so its folder cannot be deleted; it is
# only the fallback. `Start-Process -Credential` starts a child that dies at once without an error
# in a non-interactive session; measured on the Windows VM over SSH.) A batch logon needs the "log
# on as a batch job" right, which a plain standard user does not hold, and the new process needs
# access to this process's window station and desktop, or it dies at start with 0xC0000142:
# New-StandardUser grants both to the one account it creates and Remove-StandardUser takes them back.
#
# The password is generated at run time and lives only in the returned object: it is never
# printed, written to a file or put on a command line. (The scheduled-task fallback of
# Invoke-AsUser hands it to the Task Scheduler API in memory, as the probes did.)

if (-not ('LpRun' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'lib-user.cs') }

function New-StandardUser {
    param([string]$Prefix = 'lpadapter')
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $plain = [Convert]::ToBase64String($bytes) + 'aA1!'
    $name = $Prefix + (Get-Random -Minimum 10000 -Maximum 99999)
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    New-LocalUser -Name $name -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name
    $cred = New-Object System.Management.Automation.PSCredential($name, $secure)
    $sid = ([Security.Principal.NTAccount]$name).Translate([Security.Principal.SecurityIdentifier]).Value
    # The batch-logon right for this one account, so a scheduled task can run as it.
    $status = [LpLsa]::Change($sid, 'SeBatchLogonRight', $true)
    if ($status -ne 0) { throw ('granting the batch-logon right failed (status 0x{0:X})' -f $status) }
    $access = [LpRun]::Access($sid, $true)
    if ($access) { Write-Output "note: no window station access for the new user ($access); its commands may need the scheduled-task fallback" }
    [pscustomobject]@{ Name = $name; Credential = $cred; Password = $plain; Sid = $sid }
}

# Removes the account and its profile folder, if a logon created one. Quiet when nothing is there.
function Remove-StandardUser {
    param($User)
    if (-not $User) { return }
    [void][LpRun]::Access($User.Sid, $false)
    [void][LpLsa]::Change($User.Sid, 'SeBatchLogonRight', $false)
    Remove-LocalUser -Name $User.Name -ErrorAction SilentlyContinue
    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $User.Sid } |
        ForEach-Object { Remove-CimInstance -InputObject $_ -ErrorAction SilentlyContinue }
    $profileDir = Join-Path $env:SystemDrive "Users\$($User.Name)"
    if (Test-Path -LiteralPath $profileDir) { Remove-Item -Recurse -Force -LiteralPath $profileDir -ErrorAction SilentlyContinue }
}

# A directory with the inheritance cut and only the listed grants (icacls SID forms).
function Set-DirAcl {
    param([string]$Path, [string[]]$Grants)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $acl = @($Path, '/inheritance:r')
    foreach ($g in $Grants) { $acl += @('/grant:r', $g) }
    & icacls.exe @acl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on a work directory (exit $LASTEXITCODE)" }
}

# Runs cmd lines as the standard user and returns @{Method; ExitCode; Output; TimedOut}. The lines
# may use `%OUT%`, the file the output is read from (redirect into it with `>> "%OUT%" 2>&1`).
# `WorkDir` must be admin-owned and readable by Users; `OutDir` must be writable by Users. The
# batch file records its own errorlevel so the exit code does not depend on how the process was
# launched. The redirect comes first: `echo 5> file` is a stream-5 redirect (an empty file), so a
# single-digit errorlevel must never sit directly before the `>`.
# Launch: a process made from the user's batch-logon token (see the head of this file), then a
# scheduled task with the password, then Start-Process -Credential. `Method` says which ran,
# and a caller that times out names it. With -WithProfile the token launch loads (and, at the
# first time, creates) the user's profile, so the commands see the user's own USERPROFILE and
# LocalAppData; the other launches have their own rules.
function Invoke-AsUser {
    param($User, [string[]]$Lines, [string]$WorkDir, [string]$OutDir, [string]$Tag, [int]$TimeoutSec = 120, [switch]$WithProfile)
    $bat = Join-Path $WorkDir "$Tag.cmd"
    $outFile = Join-Path $OutDir "$Tag.out.txt"
    $rcFile = Join-Path $OutDir "$Tag.rc.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $outFile, $rcFile
    $body = @('@echo off', "set `"OUT=$outFile`"") + $Lines + @("> `"$rcFile`" echo %errorlevel%")
    Set-Content -LiteralPath $bat -Value $body -Encoding ASCII
    $timedOut = $false
    $registered = $false
    $taskName = "lpadapter-run-$Tag"
    # Primary: a process made from the user's batch-logon token.
    $err = 0
    $code = [LpRun]::Run($User.Name, $User.Password, "`"$env:windir\System32\cmd.exe`" /c `"$bat`"", $OutDir, $TimeoutSec * 1000, [bool]$WithProfile, [ref]$err)
    $method = if ($WithProfile) { 'CreateProcessWithTokenW (batch logon token, profile loaded)' } else { 'CreateProcessWithTokenW (batch logon token, no profile)' }
    $launched = ($code -ge 0) -and ($code -ne -1073741502)
    if ($code -eq -1) {
        $timedOut = $true
    }
    elseif (-not $launched) {
        # The process could not run (logon refused, not made, or it died at start): the fallback.
        $why = if ($code -eq -2) { "logon failed, error $err" } elseif ($code -eq -3) { "process not made, error $err" } else { 'it died at start (0xC0000142)' }
        $method = "scheduled task (password logon; the token launch failed: $why)"
        try {
            $action = New-ScheduledTaskAction -Execute "$env:windir\System32\cmd.exe" -Argument "/c `"$bat`"" -WorkingDirectory $OutDir
            Register-ScheduledTask -TaskName $taskName -Action $action -User $User.Name -Password $User.Password -RunLevel Limited -Force | Out-Null
            $registered = $true
            Start-ScheduledTask -TaskName $taskName
        }
        catch {
            $method = "Start-Process -Credential (the token launch failed: $why; the task failed: $($_.Exception.Message))"
            $p = Start-Process -FilePath "$env:windir\System32\cmd.exe" -ArgumentList '/c', "`"$bat`"" `
                -Credential $User.Credential -WorkingDirectory $OutDir -WindowStyle Hidden -PassThru
            if (-not $p.WaitForExit($TimeoutSec * 1000)) { $timedOut = $true }
        }
    }
    # The launch may return before the batch finishes: wait for a parseable errorlevel.
    $rc = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($null -eq $rc) {
        if (Test-Path -LiteralPath $rcFile) {
            $txt = ((Get-Content -LiteralPath $rcFile -TotalCount 1) + '').Trim()
            $parsed = 0
            if ([int]::TryParse($txt, [ref]$parsed)) { $rc = $parsed; break }
        }
        if ((Get-Date) -ge $deadline) { $timedOut = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if ($registered) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    $out = ''
    if (Test-Path -LiteralPath $outFile) { $out = ((Get-Content -LiteralPath $outFile) -join "`n").Trim() }
    Remove-Item -Force -ErrorAction SilentlyContinue $bat
    @{ Method = $method; ExitCode = $rc; Output = $out; TimedOut = $timedOut }
}
