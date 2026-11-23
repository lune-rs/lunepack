# Helpers for scripts that need a throwaway standard user (M10 step 11). Dot-source it. Runner and
# disposable-machine only: the script that sources it has already checked `CI` or `-Install` and
# the administrator right.
#
# The user's commands run as a process made from an interactive-logon token of the account (what a
# person who signs in at the machine holds), or, when that logon or process cannot be made, from a
# batch-logon token (scripts/ci/lib-user.cs, `LpRun`): no Task Scheduler and no profile load
# unless asked, so nothing of the account lingers once it is deleted. (A scheduled task with the
# password runs too, but the Task Scheduler leaves the account's profile loaded for good, so its
# folder cannot be deleted; it is only the next fallback. `Start-Process -Credential` starts a child
# that dies at once without an error in a non-interactive session; measured on the Windows VM over
# SSH.) Interactive first because on the windows-2025 runner a batch-logon process of a standard
# user is refused the service manager's connect right (error 5) while an interactive logon opens
# it (F12; Write-ScmOpenReport prints the comparison on every run). A batch logon needs the "log on
# as a batch job" right, which a plain standard user does not hold, and the new process needs
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
# Launch: a process made from the user's interactive-logon token (see the head of this file), then
# one from its batch-logon token, then a scheduled task with the password, then Start-Process
# -Credential. `Method` says which ran, and a caller that times out names it. `-Logon interactive`
# or `-Logon batch` runs only that token launch, with no fallback (a launch that cannot run comes
# back with a null ExitCode and says why in `Method`). With -WithProfile the token launch loads
# (and, at the first time, creates) the user's profile, so the commands see the user's own
# USERPROFILE and LocalAppData; the other launches have their own rules.
function Invoke-AsUser {
    param($User, [string[]]$Lines, [string]$WorkDir, [string]$OutDir, [string]$Tag, [int]$TimeoutSec = 120, [switch]$WithProfile,
        [ValidateSet('auto', 'interactive', 'batch')][string]$Logon = 'auto')
    $bat = Join-Path $WorkDir "$Tag.cmd"
    $outFile = Join-Path $OutDir "$Tag.out.txt"
    $rcFile = Join-Path $OutDir "$Tag.rc.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $outFile, $rcFile
    $body = @('@echo off', "set `"OUT=$outFile`"") + $Lines + @("> `"$rcFile`" echo %errorlevel%")
    Set-Content -LiteralPath $bat -Value $body -Encoding ASCII
    $timedOut = $false
    $registered = $false
    $taskName = "lpadapter-run-$Tag"
    # Primary: a process made from the user's interactive-logon token, then from its batch-logon
    # token. A token launch that cannot run (logon refused, process not made, or it died at start
    # with 0xC0000142) moves on to the next.
    $kinds = switch ($Logon) { 'interactive' { @('interactive') } 'batch' { @('batch') } default { @('interactive', 'batch') } }
    $profileWord = if ($WithProfile) { 'profile loaded' } else { 'no profile' }
    $whys = @()
    $launched = $false
    foreach ($kind in $kinds) {
        $err = 0
        $type = if ($kind -eq 'interactive') { [LpRun]::Interactive } else { [LpRun]::Batch }
        $code = [LpRun]::Run($User.Name, $User.Password, "`"$env:windir\System32\cmd.exe`" /c `"$bat`"", $OutDir, $TimeoutSec * 1000, [bool]$WithProfile, $type, [ref]$err)
        $method = "CreateProcessWithTokenW ($kind logon token, $profileWord)"
        if ($code -eq -1) { $timedOut = $true; $launched = $true; break }
        if (($code -ge 0) -and ($code -ne -1073741502)) { $launched = $true; break }
        $why = if ($code -eq -2) { "logon failed, error $err" } elseif ($code -eq -3) { "process not made, error $err" } else { 'it died at start (0xC0000142)' }
        $whys += "$kind`: $why"
    }
    if ($whys.Count -gt 0 -and $launched) { $method += " (after: $($whys -join '; '))" }
    if (-not $launched -and $Logon -ne 'auto') {
        Remove-Item -Force -ErrorAction SilentlyContinue $bat
        return @{ Method = "CreateProcessWithTokenW ($Logon logon token) could not run: $($whys -join '; ')"; ExitCode = $null; Output = ''; TimedOut = $false }
    }
    if (-not $launched) {
        # No token launch could run: the fallbacks.
        $why = $whys -join '; '
        $method = "scheduled task (password logon; the token launches failed: $why)"
        try {
            $action = New-ScheduledTaskAction -Execute "$env:windir\System32\cmd.exe" -Argument "/c `"$bat`"" -WorkingDirectory $OutDir
            Register-ScheduledTask -TaskName $taskName -Action $action -User $User.Name -Password $User.Password -RunLevel Limited -Force | Out-Null
            $registered = $true
            Start-ScheduledTask -TaskName $taskName
        }
        catch {
            $method = "Start-Process -Credential (the token launches failed: $why; the task failed: $($_.Exception.Message))"
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

# Once per run, before the rows (F12): whether the standard user can open the service manager with
# connect rights, from a process of each logon kind the launches use (`Probe` is machine_probe.exe
# at a path the user may run; its `service-image <AppId>` opens the manager with connect rights only
# before it looks at the service) and from this process impersonating the user after an
# interactive, a batch and a network logon. Prints the Windows build first. When any open is
# refused it also prints what decides it: the manager's descriptor (`sc sdshow scmanager`), the
# groups of each refused process's token (names, SIDs and attributes; no environment), and the
# Security log's record of the refusal (failure auditing of the object-access category is turned on
# for the check and the machine's audit policy restored from a backup right after). The audit
# carries its own control: a create-service request by the same user, which the descriptor refuses,
# must be logged, or the absence of a record says nothing.
function Write-ScmOpenReport {
    param($User, [string]$Probe, [string]$AppId, [string]$WorkDir, [string]$OutDir, [switch]$WithProfile)
    if ($script:scmOpenReported -or -not $User -or -not $Probe) { return }
    $script:scmOpenReported = $true
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        Write-Output "service manager, opened as the standard user (Windows: $($cv.ProductName), $($cv.EditionID), build $($cv.CurrentBuild).$($cv.UBR)):"
        $refused = $false
        $refusedKinds = @()
        foreach ($kind in 'interactive', 'batch') {
            $r = Invoke-AsUser -User $User -Lines @("call `"$Probe`" service-image $AppId >> `"%OUT%`" 2>&1") -WorkDir $WorkDir -OutDir $OutDir -Tag "scm-open-$kind" -TimeoutSec 60 -WithProfile:$WithProfile -Logon $kind
            $seen = ("$($r.Output)" -replace '\s+', ' ').Trim()
            $text = if ($null -eq $r.ExitCode -and -not $r.TimedOut) { "not run: $($r.Method)" }
            elseif ($r.TimedOut -or -not $seen) { "no answer (timed out: $($r.TimedOut))" }
            elseif ($seen -match 'open the service manager') { $refused = $true; $refusedKinds += $kind; "refused: $($seen.Substring(0, [Math]::Min(120, $seen.Length)))" }
            else { "opened (service-image: $($seen.Substring(0, [Math]::Min(60, $seen.Length))))" }
            Write-Output "     process, $kind logon: $text"
        }
        $imp = @()
        foreach ($k in @(@('interactive', [LpRun]::Interactive), @('batch', [LpRun]::Batch), @('network', [LpRun]::Network))) {
            $err = 0
            $c = [LpRun]::ScmOpen($User.Name, $User.Password, $k[1], 1, [ref]$err)
            $imp += switch ($c) { 0 { "$($k[0]) opened" } 1 { $refused = $true; "$($k[0]) refused, error $err" } -2 { "$($k[0]) logon failed, error $err" } default { "$($k[0]) impersonation failed, error $err" } }
        }
        Write-Output "     impersonated in this process: $($imp -join '; ')"
        if (-not $refused) { return }

        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $sd = (@(& sc.exe sdshow scmanager 2>&1 | ForEach-Object { "$_" }) -join ' ').Trim() } finally { $ErrorActionPreference = $prev }
        Write-Output "     sc sdshow scmanager: $sd"
        foreach ($kind in $refusedKinds) {
            $g = Invoke-AsUser -User $User -Lines @('whoami /groups /fo csv /nh >> "%OUT%" 2>&1') -WorkDir $WorkDir -OutDir $OutDir -Tag "scm-groups-$kind" -TimeoutSec 60 -WithProfile:$WithProfile -Logon $kind
            Write-Output "     the standard user's token groups ($kind logon, launch: $($g.Method)):"
            foreach ($line in @("$($g.Output)" -split "`r?`n")) {
                if ($line.Trim()) { Write-Output "       $($line.Trim())" }
            }
        }
        Write-ScmAuditRecord -User $User -Probe $Probe -AppId $AppId -WorkDir $WorkDir -OutDir $OutDir -Kinds $refusedKinds -WithProfile:$WithProfile
    }
    catch { Write-Output "     the service-manager check failed: $($_.Exception.Message)" }
}

# Part of Write-ScmOpenReport: turns on failure auditing of the object-access category (by its GUID,
# so the name's language does not matter), repeats the refused opens, a batch-logon impersonated
# open, and the control (a connect plus create-service request by the same user, impersonated,
# which the descriptor refuses), then puts the audit policy back from its backup and prints the
# access-request part of each record the service manager logged for the standard user.
function Write-ScmAuditRecord {
    param($User, [string]$Probe, [string]$AppId, [string]$WorkDir, [string]$OutDir, [string[]]$Kinds, [switch]$WithProfile)
    $backup = Join-Path $WorkDir 'audit-policy-backup.csv'
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Remove-Item -Force -ErrorAction SilentlyContinue $backup
        $o = & auditpol.exe /backup "/file:$backup" 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backup)) { Write-Output "     audit: no backup of the audit policy ($(("$o" -replace '\s+', ' ').Trim())); not changed"; return }
        $since = (Get-Date).AddSeconds(-1)
        try {
            $o = & auditpol.exe /set '/category:{6997984A-797A-11D9-BED3-505054503030}' /failure:enable 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Output "     audit: could not turn on failure auditing ($(("$o" -replace '\s+', ' ').Trim()))"; return }
            $err = 0
            $control = [LpRun]::ScmOpen($User.Name, $User.Password, [LpRun]::Batch, 3, [ref]$err)
            $null = [LpRun]::ScmOpen($User.Name, $User.Password, [LpRun]::Batch, 1, [ref]$err)
            foreach ($kind in $Kinds) {
                $null = Invoke-AsUser -User $User -Lines @("call `"$Probe`" service-image $AppId >> `"%OUT%`" 2>&1") -WorkDir $WorkDir -OutDir $OutDir -Tag "scm-audit-$kind" -TimeoutSec 60 -WithProfile:$WithProfile -Logon $kind
            }
            Start-Sleep -Seconds 2
        }
        finally {
            $o = & auditpol.exe /restore "/file:$backup" 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Output "     audit: WARNING: the audit policy was not restored ($(("$o" -replace '\s+', ' ').Trim()))" }
            Remove-Item -Force -ErrorAction SilentlyContinue $backup
        }
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4656; StartTime = $since } -ErrorAction SilentlyContinue | Where-Object {
                $x = [xml]$_.ToXml()
                $d = @{}
                foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                $d['ObjectServer'] -eq 'SC Manager' -and $d['SubjectUserSid'] -eq $User.Sid
            })
        Write-Output "     audit: the control (create-service by the standard user, refused: $($control -eq 1)) and the refused opens left $($events.Count) record(s) of the service manager for the standard user:"
        foreach ($e in $events | Sort-Object TimeCreated) {
            $msg = "$($e.Message)"
            $at = [Math]::Max(0, $msg.IndexOf('Object:'))
            $body = ($msg.Substring($at) -replace '\s+', ' ').Trim()
            Write-Output "       $($e.TimeCreated.ToString('HH:mm:ss.fff')) $($body.Substring(0, [Math]::Min(700, $body.Length)))"
        }
    }
    finally { $ErrorActionPreference = $prev }
}
