# Acceptance of the per-machine Windows adapters with a real standard user (M10 step 11).
#
# Builds `crates/lunepack-os-windows/examples/machine_probe.rs` and runs it as the administrator
# and as a standard user this script creates, to settle what the design rests on (A1, A3, A4 and
# the service rows): the owner of a pipe as the client reads it, who may create an instance of it,
# what a standard user may do to a protected folder, to the service and to the machine
# integration. A row that fails is a finding about the design, not a test to adjust: the row's
# output is printed and the script exits non-zero.
#
# What it does to the machine (all removed in `finally`, and a leftover fails the script):
#   - one local standard user (random password made at run time, never printed or kept in a file)
#     and, if a logon made one, its profile;
#   - folders `lunepack-probe-<hex>*` under Program Files and `lunepack-adapter-<hex>` under
#     ProgramData;
#   - one service `lunepack-lunepack.probe<hex>` (LocalSystem, demand start) whose binary is the
#     probe itself;
#   - registry keys under HKLM for a throwaway app id (uninstall entry, Run value, file-type
#     classes, the policy key) and a shortcut in the all-users Start menu.
#
# It refuses to run unless `CI` is `true` or `-Install` is given (a disposable runner or machine),
# and unless it runs as an administrator. Rows:
#   1. protected directories under the real Program Files
#   2. the service's pipe: owner, who may create an instance, a squatter
#   3. the service: registration, descriptor, start by a standard user, re-pointing
#   4. the elevation pipe
#   5. the machine integration and the policy key
param([switch]$Install)
$ErrorActionPreference = 'Stop'
if ($env:CI -eq 'true') { $Install = $true }
if (-not $Install) {
    Write-Output 'refused: this script creates a user, a service, HKLM keys and folders; run it on a CI runner (CI=true) or a disposable machine with -Install'
    exit 3
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Output 'refused: not an administrator'
    exit 3
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $PSScriptRoot 'lib-user.ps1')

$hex = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$pf = $env:ProgramFiles
$root = Join-Path $pf "lunepack-probe-$hex"
$rootB = Join-Path $pf "lunepack-probe-$hex-b"
$rootI = Join-Path $pf "lunepack-probe-$hex-i"
$base = Join-Path $env:ProgramData "lunepack-adapter-$hex"
$workDir = Join-Path $base 'work'
$outDir = Join-Path $base 'out'
$appSvc = "lunepack.probe$hex"
$appInt = "lunepack.probeint$hex"
$ext = "lpprobe$hex"
$svcName = "lunepack-$appSvc"
$pipeSvc = "lunepack-$appSvc"
$uninstallKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$runKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
$policyParent = 'HKLM\SOFTWARE\Policies\lunepack'
$madePolicyParent = $false
$failures = New-Object System.Collections.Generic.List[string]
$user = $null
$exe = $null
$userExe = $null
$shortcut = $null

# ---- helpers -----------------------------------------------------------------------------------

function Row([string]$id, [scriptblock]$body) {
    try {
        & $body
        Write-Output "ok   row $id"
    } catch {
        $failures.Add("row $id")
        Write-Output "FAIL row ${id}: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
    }
}

function Require([bool]$condition, [string]$what) {
    if (-not $condition) { throw "expected: $what" }
}

# The probe as the administrator: @{Code; Text}.
function Probe([string[]]$a) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $o = & $exe @a 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $code; Text = (($o) -join "`n").Trim() }
}

function AsUser([string]$tag, [string[]]$lines, [int]$timeout = 120) {
    $r = Invoke-AsUser -User $user -Lines $lines -WorkDir $workDir -OutDir $outDir -Tag $tag -TimeoutSec $timeout
    if ($r.TimedOut) { throw "the standard user's command '$tag' did not finish" }
    [pscustomobject]$r
}

# The probe as the standard user, from the copy under the machine tree.
function UProbe([string]$tag, [string[]]$a, [int]$timeout = 120) {
    $quoted = ($a | ForEach-Object { '"' + $_ + '"' }) -join ' '
    AsUser $tag @("`"$userExe`" $quoted >> `"%OUT%`" 2>&1") $timeout
}

# Runs one executable with arguments as the administrator and returns its text and exit code.
function Native([string]$file, [string[]]$a) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $o = & $file @a 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $code; Text = (($o) -join "`n").Trim() }
}

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

function Stop-ProbeService {
    if ((Service-State $svcName) -eq 'RUNNING') { Native 'sc.exe' @('stop', $svcName) | Out-Null }
    if ((Service-State $svcName) -ne 'MISSING') { Wait-ServiceState $svcName 'STOPPED' }
}

function Make-Machine-Dir([string]$path, [string]$class) {
    $r = Probe @('protect-make', $path, $class)
    Require ($r.Text -eq 'ok') "protect-make $class of a folder under Program Files answers ok (got '$($r.Text)')"
}

# ---- cleanup -----------------------------------------------------------------------------------

function Remove-Everything {
    # The service first: its binary lives under Program Files.
    if ($exe -and (Test-Path -LiteralPath $exe)) { Probe @('service-remove', $appSvc) | Out-Null }
    if ((Service-State $svcName) -ne 'MISSING') {
        Native 'sc.exe' @('stop', $svcName) | Out-Null
        Native 'sc.exe' @('delete', $svcName) | Out-Null
    }
    # Our own probe processes (a squatter or a server that outlived its row).
    Get-Process -Name 'machine_probe', 'probe-a', 'probe-b' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and ($_.Path -like "$pf\lunepack-probe-$hex*" -or $_.Path -like "$exe") } |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    foreach ($key in @("$uninstallKey\$appInt", "HKLM\Software\Classes\.$ext", "HKLM\Software\Classes\$appInt.$ext",
            "$policyParent\$appInt", "$policyParent\$appSvc")) {
        Native 'reg.exe' @('delete', $key, '/f') | Out-Null
    }
    Native 'reg.exe' @('delete', $runKey, '/v', $appInt, '/f') | Out-Null
    if ($madePolicyParent) { Native 'reg.exe' @('delete', $policyParent, '/f') | Out-Null }
    if ($shortcut -and (Test-Path -LiteralPath $shortcut)) { Remove-Item -Force -LiteralPath $shortcut -ErrorAction SilentlyContinue }
    foreach ($dir in @($root, $rootB, $rootI, $base)) {
        if (Test-Path -LiteralPath $dir) { Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue }
    }
    Remove-StandardUser $user
}

# What is left of everything this script made, by name only.
function Find-Leftovers {
    $left = @()
    if ((Service-State $svcName) -ne 'MISSING') { $left += 'the service' }
    foreach ($dir in @($root, $rootB, $rootI, $base)) {
        if (Test-Path -LiteralPath $dir) { $left += 'a folder named ' + (Split-Path -Leaf $dir) }
    }
    foreach ($key in @("$uninstallKey\$appInt", "HKLM\Software\Classes\.$ext", "HKLM\Software\Classes\$appInt.$ext", "$policyParent\$appInt")) {
        if ((Native 'reg.exe' @('query', $key)).Code -eq 0) { $left += "the registry key $key" }
    }
    if ((Native 'reg.exe' @('query', $runKey, '/v', $appInt)).Code -eq 0) { $left += 'the Run value' }
    if ($shortcut -and (Test-Path -LiteralPath $shortcut)) { $left += 'the shortcut' }
    if ($user) {
        if (Get-LocalUser -Name $user.Name -ErrorAction SilentlyContinue) { $left += 'the standard user' }
        if (Test-Path -LiteralPath (Join-Path $env:SystemDrive "Users\$($user.Name)")) { $left += 'the user profile folder' }
    }
    if ($madePolicyParent) {
        if ((Native 'reg.exe' @('query', $policyParent)).Code -eq 0) { $left += 'the policy parent key' }
    }
    $left
}

# ---- the run -----------------------------------------------------------------------------------

try {
    # Build the probe (the cargo that runs the job's other steps).
    Push-Location $repo
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & cargo build -p lunepack-os-windows --example machine_probe --locked 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 3
        $built = $LASTEXITCODE
        $ErrorActionPreference = $prev
    } finally { Pop-Location }
    if ($built -ne 0) { throw 'the probe did not build' }
    $tdir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
    $exe = Join-Path $tdir 'debug\examples\machine_probe.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'the probe is not where cargo puts it' }
    $standing = (Probe @('standing')).Text
    Write-Output "administrator session; the probe reports its standing as: $standing"

    # The user and the two folders it works through: `work` (admin-owned, Users read and execute)
    # holds the batch files, `out` (Users modify) takes their output.
    $user = New-StandardUser
    Write-Output "standard user created: $($user.Name)"
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    Set-DirAcl $base $grants
    Set-DirAcl $workDir ($grants + '*S-1-5-32-545:(OI)(CI)RX')
    Set-DirAcl $outDir ($grants + '*S-1-5-32-545:(OI)(CI)M')
    # `base` itself needs traverse for Users so the two below can be reached.
    & icacls.exe $base /grant '*S-1-5-32-545:RX' | Out-Null

    # The machine tree every row but 1b and 5 uses, with the probe's copies in it.
    Make-Machine-Dir $root 'machine'
    $private = Join-Path $root 'private'
    Make-Machine-Dir $private 'admin'
    Set-Content -LiteralPath (Join-Path $private 'secret.txt') -Value 'secret' -Encoding ASCII
    $bin = Join-Path $root 'bin'
    $svc = Join-Path $root 'svc'
    New-Item -ItemType Directory -Force -Path $bin, $svc | Out-Null
    $userExe = Join-Path $bin 'machine_probe.exe'
    Copy-Item -LiteralPath $exe -Destination $userExe
    Copy-Item -LiteralPath $exe -Destination (Join-Path $svc 'probe-a.exe')
    Copy-Item -LiteralPath $exe -Destination (Join-Path $svc 'probe-b.exe')
    Set-Content -LiteralPath (Join-Path $svc 'app-id.txt') -Value $appSvc -Encoding ASCII
    $f = Join-Path $root 'f.txt'
    Set-Content -LiteralPath $f -Value 'x' -Encoding ASCII -NoNewline

    # ---- row 1: protected directories ------------------------------------------------------------
    Row '1 protected directories under Program Files' {
        $r = Probe @('protect-check', $root, 'machine')
        Require ($r.Text -eq 'ok') "check passes for the machine tree (got '$($r.Text)')"
        $r = Probe @('protect-check', $private, 'admin')
        Require ($r.Text -eq 'ok') "check passes for the admin-only folder (got '$($r.Text)')"
        # What the standard user may do to the machine tree.
        $u = AsUser 'r1-read' @("type `"$f`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0 -and $u.Output -eq 'x') "the standard user reads a file of the machine tree (rc $($u.ExitCode), '$($u.Output)')"
        $u = AsUser 'r1-list' @("dir `"$root`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0) "the standard user lists the machine tree (rc $($u.ExitCode))"
        AsUser 'r1-create' @("echo hello > `"$root\new.txt`" 2>> `"%OUT%`"") | Out-Null
        Require (-not (Test-Path -LiteralPath (Join-Path $root 'new.txt'))) 'the standard user cannot create a file in the machine tree'
        AsUser 'r1-mkdir' @("mkdir `"$root\newdir`" >> `"%OUT%`" 2>&1") | Out-Null
        Require (-not (Test-Path -LiteralPath (Join-Path $root 'newdir'))) 'the standard user cannot create a folder in the machine tree'
        AsUser 'r1-write' @("echo more >> `"$f`" 2>> `"%OUT%`"") | Out-Null
        Require ((Get-Content -LiteralPath $f -Raw) -eq 'x') 'the standard user cannot write a file of the machine tree'
        AsUser 'r1-rename' @("ren `"$f`" g.txt >> `"%OUT%`" 2>&1") | Out-Null
        Require ((Test-Path -LiteralPath $f) -and -not (Test-Path -LiteralPath (Join-Path $root 'g.txt'))) 'the standard user cannot rename a file of the machine tree'
        AsUser 'r1-delete' @("del /f /q `"$f`" >> `"%OUT%`" 2>&1") | Out-Null
        Require (Test-Path -LiteralPath $f) 'the standard user cannot delete a file of the machine tree'
        # The admin-only folder.
        $u = AsUser 'r1-private-list' @("dir `"$private`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -ne 0) "the standard user cannot list the admin-only folder (rc $($u.ExitCode))"
        $u = AsUser 'r1-private-read' @("type `"$private\secret.txt`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -ne 0 -and $u.Output -notmatch 'secret') 'the standard user cannot read inside the admin-only folder'
        # A folder where Users hold modify no longer passes check.
        Make-Machine-Dir $rootB 'machine'
        $r = Probe @('protect-check', $rootB, 'machine')
        Require ($r.Text -eq 'ok') 'control: a second machine-tree folder passes check'
        & icacls.exe $rootB /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
        $r = Probe @('protect-check', $rootB, 'machine')
        Require ($r.Text -like 'err:*') "check fails after icacls grants Users modify (got '$($r.Text)')"
    }

    # ---- rows 2 and 3 share one service ---------------------------------------------------------
    $imageA = Join-Path $svc 'probe-a.exe'
    $imageB = Join-Path $svc 'probe-b.exe'
    $markerA = Join-Path $svc 'started-probe-a.exe.txt'
    $markerB = Join-Path $svc 'started-probe-b.exe.txt'

    Row '2 the service pipe: owner, instances, a squatter' {
        $r = Probe @('service-self-test', $imageA)
        Require ($r.Text -eq 'ok') "the service binary passes its self-test (got '$($r.Text)')"
        $r = Probe @('service-register', $appSvc, $imageA)
        Require ($r.Text -eq 'ok') "the service registers (got '$($r.Text)')"
        # A standard user's connector starts the service and completes a hello.
        $u = UProbe 'r2-connect' @('service-connect', $appSvc)
        Require ($u.Output -match 'hello version=1') "the standard user starts the service and completes a hello (got '$($u.Output)')"
        # Its own client, expecting LocalSystem: the owner check passes, so the owner reads back as LocalSystem.
        $u = UProbe 'r2-client' @('pipe-connect-service', $pipeSvc)
        Require ($u.Output -match 'owner=LocalSystem' -and $u.Output -match 'hello version=1') "the standard user's client reads the owner LocalSystem and exchanges frames (got '$($u.Output)')"
        # A standard user cannot make a pipe whose owner is LocalSystem.
        $u = UProbe 'r2-create' @('pipe-create-service', "lunepack-probe-free-$hex")
        Require ($u.Output -match 'err:OwnerNotAssignable') "a standard user's Service pipe is refused with OwnerNotAssignable (got '$($u.Output)')"
        # While the service runs, a standard user cannot make another instance of its pipe.
        $ready = Join-Path $outDir 'squat-early.ready'
        Remove-Item -Force -ErrorAction SilentlyContinue $ready
        $u = UProbe 'r2-instance' @('squat', $pipeSvc, '0', $ready)
        Require ($u.Output -match 'err:os 5') "while the service runs, a standard user cannot create an instance of its pipe: access denied (got '$($u.Output)')"
        # With the service stopped, a standard user who creates the name first is refused by the client.
        Stop-ProbeService
        $ready = Join-Path $outDir 'squat.ready'
        Remove-Item -Force -ErrorAction SilentlyContinue $ready, (Join-Path $outDir 'squat.txt')
        $u = AsUser 'r2-squat' @(
            "start `"`" /b `"$userExe`" squat $pipeSvc 15 `"$ready`" >> `"$outDir\squat.txt`" 2>&1",
            "for /l %%i in (1,1,20) do if not exist `"$ready`" ping -n 2 127.0.0.1 > nul",
            "`"$userExe`" pipe-connect-service $pipeSvc >> `"%OUT%`" 2>&1"
        ) 90
        $squat = if (Test-Path -LiteralPath (Join-Path $outDir 'squat.txt')) { (Get-Content -LiteralPath (Join-Path $outDir 'squat.txt') -Raw).Trim() } else { '' }
        Require ($squat -match 'created') "control: the squatter created the name (got '$squat')"
        Require ($u.Output -match 'err:Untrusted') "the client refuses a pipe the standard user created (got '$($u.Output)')"
        # Let the squatter end (15 s) before the next row asks for the name.
        $deadline = (Get-Date).AddSeconds(40)
        while ((Get-Date) -lt $deadline -and (Get-Process -Name 'machine_probe' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $userExe })) { Start-Sleep -Milliseconds 500 }
    }

    Row '3 the service: registration, descriptor, start, re-pointing' {
        $qc = (Native 'sc.exe' @('qc', $svcName)).Text
        Require ($qc -match 'BINARY_PATH_NAME\s*:\s*"[^"]+probe-a\.exe"\s*$' -or $qc -match 'BINARY_PATH_NAME\s*:\s*"[^"]+probe-a\.exe"') "the stored image path is quoted, with no arguments (qc: $($qc -replace '\s+', ' '))"
        Require ($qc -match 'DEMAND_START') 'the start type is demand'
        Require ($qc -match 'SERVICE_START_NAME\s*:\s*LocalSystem') 'the service runs as LocalSystem'
        # The descriptor: Users hold start, query status and read control only; no other
        # non-administrator entry holds change config, stop, delete, write DAC or write owner.
        $sd = (Native 'sc.exe' @('sdshow', $svcName)).Text
        $bu = @([regex]::Matches($sd, '\(A;[^;]*;([A-Za-z0-9]*);;;BU\)'))
        Require ($bu.Count -eq 1) "one allow entry for Users (sdshow: $sd)"
        $rights = (@([regex]::Matches($bu[0].Groups[1].Value, '..') | ForEach-Object { $_.Value }) | Sort-Object) -join ','
        Require ($rights -eq 'LC,RC,RP') "Users hold exactly query status, read control and start (got $rights)"
        foreach ($m in [regex]::Matches($sd, '\(A;[^;]*;([A-Za-z0-9]*);;;([A-Z0-9-]+)\)')) {
            # SY and BA are the administrators; the last is TrustedInstaller.
            if ($m.Groups[2].Value -in @('SY', 'BA', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) { continue }
            Require ($m.Groups[1].Value -notmatch '^0x') "every entry for a non-administrator names its rights by letters (trustee $($m.Groups[2].Value))"
            $held = @([regex]::Matches($m.Groups[1].Value, '..') | ForEach-Object { $_.Value })
            foreach ($bad in 'DC', 'WP', 'DT', 'SD', 'WD', 'WO', 'GA', 'GW') {
                Require ($held -notcontains $bad) "no non-administrator entry holds $bad (trustee $($m.Groups[2].Value))"
            }
        }
        # Start by a standard user: the first copy runs.
        Stop-ProbeService
        Remove-Item -Force -ErrorAction SilentlyContinue $markerA, $markerB
        $u = UProbe 'r3-start-a' @('service-connect', $appSvc)
        Require ($u.Output -match 'hello version=1') "the standard user starts the service and completes a hello (got '$($u.Output)')"
        Require ((Test-Path -LiteralPath $markerA) -and -not (Test-Path -LiteralPath $markerB)) 'the service started from the first copy'
        # A standard user cannot reconfigure, stop or delete it.
        foreach ($case in @(
                @('config', @('sc.exe', 'config', $svcName, 'binPath=', 'C:\Windows\System32\cmd.exe')),
                @('stop', @('sc.exe', 'stop', $svcName)),
                @('delete', @('sc.exe', 'delete', $svcName)))) {
            $line = ($case[1] | ForEach-Object { $_ }) -join ' '
            $u = AsUser "r3-$($case[0])" @("$line >> `"%OUT%`" 2>&1")
            Require ($u.ExitCode -eq 5) "sc $($case[0]) by the standard user is refused with access denied (rc $($u.ExitCode): $($u.Output -replace '\s+', ' '))"
        }
        $u = AsUser 'r3-query' @("sc.exe query $svcName >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0) "the standard user may query the service (rc $($u.ExitCode))"
        # Re-point it at the second copy: the next start runs the second copy.
        $r = Probe @('service-set-image', $appSvc, $imageB)
        Require ($r.Text -eq 'ok') "set_image answers ok (got '$($r.Text)')"
        $r = Probe @('service-image', $appSvc)
        Require ($r.Text -eq "image=$imageB") "image reads back the second copy, unquoted (got '$($r.Text)')"
        Stop-ProbeService
        Remove-Item -Force -ErrorAction SilentlyContinue $markerA, $markerB
        $u = UProbe 'r3-start-b' @('service-connect', $appSvc)
        Require ($u.Output -match 'hello version=1') "the next start completes a hello (got '$($u.Output)')"
        Require ((Test-Path -LiteralPath $markerB) -and -not (Test-Path -LiteralPath $markerA)) 'the service started from the second copy'
        # Removing it stops it and deletes it.
        $r = Probe @('service-remove', $appSvc)
        Require ($r.Text -eq 'ok') "remove answers ok (got '$($r.Text)')"
        Require ((Service-State $svcName) -eq 'MISSING') 'the service is gone'
    }

    Row '4 the elevation pipe' {
        $name = "lunepack-probe-elev-$hex"
        $ready = Join-Path $outDir 'elev.ready'
        $log = Join-Path $outDir 'elev-server.txt'
        Remove-Item -Force -ErrorAction SilentlyContinue $ready, $log
        $server = Start-Process -FilePath $exe -ArgumentList @('pipe-serve-elevation', $name, $user.Sid, '60', $ready) `
            -RedirectStandardOutput $log -WindowStyle Hidden -PassThru
        try {
            $deadline = (Get-Date).AddSeconds(30)
            while (-not (Test-Path -LiteralPath $ready) -and (Get-Date) -lt $deadline -and -not $server.HasExited) { Start-Sleep -Milliseconds 200 }
            $serverText = if (Test-Path -LiteralPath $log) { (Get-Content -LiteralPath $log -Raw) } else { '' }
            Require (Test-Path -LiteralPath $ready) "the elevation pipe was created by the administrator process (server said: $serverText)"
            Require ($serverText -match 'owner=S-1-5-32-544') "the elevation pipe's owner reads back as Administrators (server said: $serverText)"
            $u = UProbe 'r4-write' @('pipe-open-write', $name)
            Require ($u.Output -match 'err:os 5') "a client opening the elevation pipe for writing is refused (got '$($u.Output)')"
            $u = UProbe 'r4-read' @('pipe-read-elevation', $name)
            Require ($u.Output -match 'read=elevation-stream') "the standard user reads the stream, the owner check expecting Administrators passing (got '$($u.Output)')"
            $null = $server.WaitForExit(20000)
        } finally {
            if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    Row '5 the machine integration and the policy key' {
        Make-Machine-Dir $rootI 'machine'
        $r = Probe @('integration-write', $rootI, $appInt, $ext)
        Require ($r.Text -match '^ok kept=0') "the machine integration is written (got '$($r.Text)')"
        if ($r.Text -match 'shortcut=(.+)$') { $script:shortcut = $Matches[1].Trim() }
        Require ($shortcut -and (Test-Path -LiteralPath $shortcut)) 'the shortcut is in the all-users Start menu'
        $u = AsUser 'r5-uninstall' @("reg query `"$uninstallKey\$appInt`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0) 'the standard user sees the uninstall entry'
        $u = AsUser 'r5-run' @("reg query `"$runKey`" /v $appInt >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0) 'the standard user sees the Run value'
        $u = AsUser 'r5-class' @("reg query `"HKLM\Software\Classes\.$ext`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0) 'the standard user sees the file-type class'
        $u = AsUser 'r5-shortcut' @("dir `"$shortcut`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -eq 0) 'the standard user sees the shortcut'
        # The standard user's own hive has none of it.
        Require ((Native 'reg.exe' @('query', "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\$appInt")).Code -ne 0) 'nothing was written under the administrator''s HKCU'
        # The policy key.
        if ((Native 'reg.exe' @('query', $policyParent)).Code -ne 0) { $script:madePolicyParent = $true }
        $u = UProbe 'r5-policy-off' @('policy-read', $appInt)
        Require ($u.Output -eq 'self_update_disabled=false no_update_ui=false') "no key: both off (got '$($u.Output)')"
        Native 'reg.exe' @('add', "$policyParent\$appInt", '/v', 'DisableSelfUpdate', '/t', 'REG_DWORD', '/d', '1', '/f') | Out-Null
        $u = UProbe 'r5-policy-on' @('policy-read', $appInt)
        Require ($u.Output -eq 'self_update_disabled=true no_update_ui=false') "the standard user reads the policy (got '$($u.Output)')"
        Native 'reg.exe' @('delete', "$policyParent\$appInt", '/f') | Out-Null
        # Removal.
        $r = Probe @('integration-remove', $rootI, $appInt, $ext)
        Require ($r.Text -match '^ok kept=0') "the machine integration is removed (got '$($r.Text)')"
        $u = AsUser 'r5-gone' @("reg query `"$uninstallKey\$appInt`" >> `"%OUT%`" 2>&1")
        Require ($u.ExitCode -ne 0) 'the uninstall entry is gone'
        Require (-not (Test-Path -LiteralPath $shortcut)) 'the shortcut is gone'
    }
}
catch {
    $failures.Add('setup')
    Write-Output "FAIL setup: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
}
finally {
    try { Remove-Everything } catch { Write-Output "cleanup error: $($_.Exception.Message)" }
}

$left = @(Find-Leftovers)
if ($left.Count -gt 0) {
    $failures.Add('leftovers')
    Write-Output "FAIL leftovers: $($left -join '; ')"
} else {
    Write-Output 'ok   nothing this script created is left'
}
if ($failures.Count -gt 0) {
    Write-Output "windows-machine-adapter-test: FAILED ($($failures -join ', '))"
    exit 1
}
Write-Output 'windows-machine-adapter-test: all rows passed'
exit 0
