# The user-run check of the Windows all-users install (M10 step 20; roadmap P6). CI cannot see
# a real UAC prompt: its runners hold no split token and nobody answers. So a person walks the real
# flow once, on a disposable Windows machine with UAC on, and answers a few questions; the script
# checks what it can read for itself and writes both to a report.
#
#   scripts/windows-machine-user-check.ps1 -Install [-StandardUser <name>] [-Report <file>]
#   scripts/windows-machine-user-check.ps1 -DryRun
#
# Needs: a Windows machine with UAC on (the default), two accounts on it: an administrator (this
# script runs as that account, from an ordinary, NOT elevated, window) and an existing standard
# account (-StandardUser). The Rust toolchain of rust-toolchain.toml (it builds the release files,
# the real `lunepack-ui` included). The script never asks for, reads or stores a password: the
# standard account's password goes to `runas` (or to the sign-in screen), and the administrator's
# credentials go to the Windows prompt.
#
# What the person does and what the script checks (the numbers are the plan's; the order is
# 1, 2, 4, 6, 3, because only one install of the app may exist at a time):
#   1  as the standard account: Setup, tick "Install for all users"; the credential prompt must name
#      the program; decline once (the installer shows a retry screen), then approve
#   2  as the standard account: the app updates with no prompt of any kind
#   4  as the administrator: uninstall from Settings
#   6  as the administrator: Setup.exe started with "Run as administrator" (no --all-users), from a
#      folder holding the planted-DLL garbage files: one fixed message box, the usage exit code, and
#      nothing installed (checked by the script, not asked)
#   3  as the administrator: Setup, tick "all users"; the consent prompt; afterwards THIS script,
#      unelevated, tries to write under R and must be denied (assumption A3; checked, not asked)
#   5  at every prompt: where did it appear (in front, taskbar only, behind another window)
# Then the script removes the install (one more prompt) and everything else it made.
#
# What it touches: its own folder under ProgramData (readable by Users, the signing keys in an
# administrator-only subfolder), Program Files (the app's folder), HKLM (the Uninstall key), the
# service list (one service) and the all-users Start menu, all named with one random suffix, and
# the standard account's per-user home of that app. Nothing else. Everything is removed at the end
# and after a failure; what an unelevated process cannot remove is removed by a second copy of this
# script that Windows starts elevated after one more prompt (-ElevatedCleanup, internal). The
# script refuses to run in CI, without -Install, without UAC, when elevated, or without a terminal.
# It is not part of the Gate or of CI.
#
# The report holds the answers, the checks' verdicts, versions and exit codes: no password, no
# environment, no registry dump; the temporary root is written as <root>.
param(
    [switch]$Install,
    [switch]$DryRun,
    [string]$StandardUser = '',
    [string]$Report = '',
    [string]$ElevatedCleanup = ''
)
$ErrorActionPreference = 'Stop'

# ---- names ------------------------------------------------------------------------------------------

$hex = if ($ElevatedCleanup) { $ElevatedCleanup } else { [Guid]::NewGuid().ToString('N').Substring(0, 8) }
if ($hex -notmatch '^[0-9a-f]{8}$') { Write-Output 'refused: bad suffix'; exit 2 }
$appId = "org.example.lpcheck$hex"
$appName = "Lunepack Machine Check $hex"
$entryFile = "lpcheck$hex.exe"
$serviceName = "lunepack-$appId"
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$appId"
# SYSTEM, Administrators, TrustedInstaller: the accounts that may own and write the machine tree.
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$usersSid = 'S-1-5-32-545'
$usageExit = 2

# ---- the walk: every question and every check, by id (-DryRun prints this table) -------------------------

$questions = [ordered]@{
    '1.offered'          = @{ Kind = 'yn'; Expect = 'y'; Text = 'The welcome screen offered "Install for all users" (a tick box)?' }
    '1.prompt-program'   = @{ Kind = 'yn'; Expect = 'y'; Text = "The credential prompt named the program ('$appName Setup')?" }
    '1.prompt-publisher' = @{ Kind = 'choice'; Choices = @('unknown', 'named', 'none-shown'); Expect = 'unknown'; Text = 'What did the prompt say about the publisher? (this Setup.exe is not signed: "Unknown publisher" is expected)' }
    '1.prompt-where'     = @{ Kind = 'choice'; Choices = @('front', 'taskbar', 'behind', 'other'); Text = 'Where did the prompt appear: in front, as a flashing taskbar button only, behind another window, other?' }
    '1.retry'            = @{ Kind = 'yn'; Expect = 'y'; Text = 'After you declined once, the installer window showed a retry screen, and the install completed after you approved?' }
    '2.prompt'           = @{ Kind = 'yn'; Expect = 'n'; Text = 'Did any prompt appear while the app updated (UAC, credentials, a firewall box, anything asking for something)?' }
    '4.settings'         = @{ Kind = 'yn'; Expect = 'y'; Text = "Settings > Apps listed '$appName' under that name, and Uninstall started the uninstaller?" }
    '4.confirm-window'   = @{ Kind = 'yn'; Expect = 'y'; Text = 'The uninstaller asked for confirmation in its own window before the administrator prompt?' }
    '4.prompt-where'     = @{ Kind = 'choice'; Choices = @('front', 'taskbar', 'behind', 'other'); Text = 'Where did the consent prompt appear: in front, taskbar only, behind another window, other?' }
    '6.message-box'      = @{ Kind = 'yn'; Expect = 'y'; Text = 'Exactly one message box appeared, titled "Setup", saying the installer does not run with administrator rights (you closed it)?' }
    '6.prompt-where'     = @{ Kind = 'choice'; Choices = @('front', 'taskbar', 'behind', 'other'); Text = 'Where did the consent prompt appear: in front, taskbar only, behind another window, other?' }
    '3.offered'          = @{ Kind = 'yn'; Expect = 'y'; Text = 'The welcome screen offered "Install for all users" to you as an administrator?' }
    '3.prompt-kind'      = @{ Kind = 'choice'; Choices = @('consent', 'credentials', 'none'); Expect = 'consent'; Text = 'Which prompt appeared: consent (a Yes/No box), credentials (asks for a password), none?' }
    '3.prompt-publisher' = @{ Kind = 'choice'; Choices = @('unknown', 'named', 'none-shown'); Expect = 'unknown'; Text = 'What did the prompt say about the publisher? ("Unknown publisher" is expected)' }
    '3.prompt-where'     = @{ Kind = 'choice'; Choices = @('front', 'taskbar', 'behind', 'other'); Text = 'Where did the prompt appear: in front, taskbar only, behind another window, other?' }
    'z.last-prompt'      = @{ Kind = 'yn'; Expect = 'y'; Text = 'The final uninstall asked for confirmation and then showed one consent prompt, and nothing else?' }
}

$checks = [ordered]@{
    '1.installed'        = 'the app is installed for all users: its folder under Program Files, a machine record naming version 1.0.0, the Uninstall key, the common Start-menu shortcut, the registered service'
    '2.updated'          = 'the record shows version 1.1.0 current, 1.0.0 previous, nothing pending, nothing bad; the service image follows the confirmed version'
    '4.removed'          = 'the install folder, the Uninstall key, the shortcut and the service are gone'
    '6.usage-exit'       = 'the elevated Setup without --all-users exits with the usage code (2), which is not one of the loader failures of the planted-DLL test'
    '6.nothing-installed' = 'nothing was installed by that run: no folder, key, shortcut or service, and no new folder under Program Files'
    '3.installed'        = 'the app is installed for all users, as in 1.installed'
    '3.write-denied'     = 'this unelevated administrator cannot create a file or a folder under R, R\app, R\.lunepack or R\.lunepack\state, and cannot open the record for writing (A3)'
    '3.machine-denied'   = 'it cannot list R\.lunepack\machine (administrators only)'
    '3.descriptors'      = 'the owner of R, R\app, R\.lunepack and R\.lunepack\state is SYSTEM, Administrators or TrustedInstaller, and no one else holds a write-class right there'
    'z.removed'          = 'after the final uninstall: nothing this run made is left (folder, key, shortcut, service, new folders under Program Files, the standard account''s per-user home)'
}

$walk = @(
    @{ Id = '1'; Title = 'Install for all users from a standard account'
        Person = 'as the standard account: start Setup.exe, tick "Install for all users", press Install; DECLINE the credential prompt once, retry, then approve it with an administrator''s credentials'
        Questions = @('1.offered', '1.prompt-program', '1.prompt-publisher', '1.prompt-where', '1.retry'); Checks = @('1.installed') }
    @{ Id = '2'; Title = 'The app updates with no prompt'
        Person = 'as the standard account: run the update launcher the script names (checks the feed, downloads, stages, applies, restarts the app)'
        Questions = @('2.prompt'); Checks = @('2.updated') }
    @{ Id = '4'; Title = 'Uninstall from Settings'
        Person = 'as the administrator: Settings > Apps > Installed apps > the app > Uninstall; confirm in the uninstaller''s window; approve the consent prompt'
        Questions = @('4.settings', '4.confirm-window', '4.prompt-where'); Checks = @('4.removed') }
    @{ Id = '6'; Title = '"Run as administrator" without --all-users, beside planted DLL files'
        Person = 'as the administrator: approve the consent prompt of the elevated Setup the script starts (from a folder holding garbage files named like DLLs), then close the one message box it shows'
        Questions = @('6.message-box', '6.prompt-where'); Checks = @('6.usage-exit', '6.nothing-installed') }
    @{ Id = '3'; Title = 'Install for all users from the administrator account; the folder is closed to the unelevated administrator'
        Person = 'as the administrator, from an ordinary window: start Setup.exe, tick "Install for all users", press Install, approve the consent prompt'
        Questions = @('3.offered', '3.prompt-kind', '3.prompt-publisher', '3.prompt-where'); Checks = @('3.installed', '3.write-denied', '3.machine-denied', '3.descriptors') }
    @{ Id = 'z'; Title = 'The final uninstall and the clean-up'
        Person = 'as the administrator: confirm the uninstall in its window and approve the consent prompt; if anything is left Windows asks once more for the script''s elevated clean-up'
        Questions = @('z.last-prompt'); Checks = @('z.removed') }
)

# -DryRun: the list above, as it will be asked and checked; nothing is touched, nothing is built.
if ($DryRun) {
    Write-Output 'dry-run: windows-machine-user-check (nothing is built, created, started or changed)'
    Write-Output 'dry-run: refuses to run: off Windows, in CI, without -Install, without a terminal, from an elevated window, as a non-administrator, with UAC off (EnableLUA 0, or administrator consent behaviour 0), when the standard account is missing, disabled or an administrator, when the app''s folder exists'
    Write-Output "dry-run: touches: <ProgramData>\lunepack-usercheck-<hex> (own folder; keys in an administrator-only subfolder), <Program Files>\$appName, HKLM Uninstall\$appId, the service $serviceName, the all-users Start-menu shortcut, the standard account's per-user home of $appId"
    foreach ($s in $walk) {
        Write-Output ''
        Write-Output "dry-run: item $($s.Id): $($s.Title)"
        Write-Output "dry-run:   the person: $($s.Person)"
        foreach ($q in $s.Questions) {
            $d = $questions[$q]
            $form = if ($d.Kind -eq 'yn') { 'y/n' } else { $d.Choices -join '/' }
            $exp = if ($d.Expect) { "; expected: $($d.Expect)" } else { '; informational' }
            Write-Output "dry-run:   question $q [$form$exp]: $($d.Text)"
        }
        foreach ($c in $s.Checks) { Write-Output "dry-run:   check $c (the script, not asked): $($checks[$c])" }
    }
    Write-Output ''
    Write-Output "dry-run: ok ($(@($walk | ForEach-Object { $_.Questions }).Count) questions, $(@($walk | ForEach-Object { $_.Checks }).Count) checks)"
    exit 0
}

function Refuse([string]$why) { Write-Output "refused: $why"; exit 3 }

if ($env:OS -ne 'Windows_NT') { Refuse 'Windows only' }

# ---- locations (Windows only; the -DryRun above needs none) ------------------------------------------------------

$pf = [Environment]::GetFolderPath('ProgramFiles')
$commonPrograms = [Environment]::GetFolderPath('CommonPrograms')
$R = Join-Path $pf $appName
$root = Join-Path $env:ProgramData "lunepack-usercheck-$hex"
$private = Join-Path $root 'private'
$feedDir = Join-Path $root 'feed'
$setupDir = Join-Path $root 'setup'
$runDir = Join-Path $root 'run'

# ---- small helpers ---------------------------------------------------------------------------------------

function Require([bool]$condition, [string]$what) {
    if (-not $condition) { throw "expected: $what" }
}

function SameV([string]$what, $got, $want) {
    if ("$got" -ne "$want") { throw "$what is '$got', want '$want'" }
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

function Service-State([string]$name) {
    $q = (Native 'sc.exe' @('query', $name)).Text
    if ($q -match 'STATE\s*:\s*\d+\s+(\w+)') { return $Matches[1] }
    return 'MISSING'
}

function Sid-Of($identity) {
    try { return $identity.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return "$identity" }
}

function Remove-Tree([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    try { [IO.Directory]::Delete($path, $true) } catch {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Who runs this process: `UacElevated` (a full administrator token), `AdminUnelevated` (an
# administrator's filtered token), `Standard`. From the token's groups by SID (the names are
# localised): the Administrators group is in an administrator's filtered token too, as deny-only;
# the integrity level tells the two tokens apart (S-1-16-12288 high, S-1-16-8192 medium).
function Get-Standing {
    $rows = @(& whoami.exe /groups /fo csv /nh | ConvertFrom-Csv -Header 'Name', 'Type', 'Sid', 'Attributes')
    $sids = @($rows | ForEach-Object { $_.Sid })
    if ($sids -notcontains 'S-1-5-32-544') { return 'Standard' }
    if ($sids -contains 'S-1-16-12288') { return 'UacElevated' }
    return 'AdminUnelevated'
}

# The newest install-state record of an install (FORMAT 12), read only.
function Get-Record([string]$dir) {
    $files = @(Get-ChildItem -LiteralPath (Join-Path $dir '.lunepack\state') -Filter '*.rec' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
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

function Common-Shortcut { return Join-Path $commonPrograms "$appName.lnk" }

function Stub-Path { return Join-Path $R $entryFile }

# Folder names directly under a folder (for the before/after lists).
function Names-In([string]$dir) {
    return @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
}

# What this run added under Program Files by name: its own app folder and the machine installs' staging
# and uninstaller folders. `before` is the list taken before the first install (a file in the root).
function New-ProgramFilesDirs {
    $listFile = Join-Path $root 'pf-before.txt'
    if (-not (Test-Path -LiteralPath $listFile)) { return @() }
    $before = @(Get-Content -LiteralPath $listFile)
    return @(Get-ChildItem -LiteralPath $pf -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
            $before -notcontains $_.Name -and ($_.Name -eq $appName -or $_.Name -match '^\.lunepack-(install|uninstall)-[0-9a-f]{32}$')
        })
}

# The `delete at restart` entries naming the uninstaller folders of this run; returns how many it
# found, and removes them with -Remove (administrator only).
function Pending-Deletes([switch]$Remove) {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $v = (Get-ItemProperty -LiteralPath $k -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if (-not $v) { return 0 }
    $items = @($v)
    $ours = @(New-ProgramFilesDirs | Where-Object { $_.Name -like '.lunepack-uninstall-*' } | ForEach-Object { $_.Name })
    $keep = New-Object System.Collections.Generic.List[string]
    $found = 0
    for ($i = 0; $i -lt $items.Count; $i += 2) {
        $src = $items[$i]
        $dst = if ($i + 1 -lt $items.Count) { $items[$i + 1] } else { '' }
        $plain = $src -replace '^\*\d+', '' -replace '^\\\?\?\\', '' -replace '^\\\\\?\\', ''
        $mine = $false
        foreach ($n in $ours) { if ($plain -and $plain.StartsWith($pf, [StringComparison]::OrdinalIgnoreCase) -and $plain.IndexOf("\$n", [StringComparison]::OrdinalIgnoreCase) -ge 0) { $mine = $true } }
        if ($mine) { $found++ } else { $keep.Add($src); $keep.Add($dst) }
    }
    if ($Remove -and $found -gt 0) {
        if ($keep.Count -gt 0) { Set-ItemProperty -LiteralPath $k -Name PendingFileRenameOperations -Value ([string[]]$keep.ToArray()) -Type MultiString }
        else { Remove-ItemProperty -LiteralPath $k -Name PendingFileRenameOperations -ErrorAction SilentlyContinue }
    }
    return $found
}

# The standard account's per-user home of the app, from its name (validated by the caller).
function Std-Home([string]$name) { return Join-Path $env:SystemDrive "Users\$name\AppData\Local\lunepack\$appId" }

# ---- the elevated clean-up (internal; a second copy of this script, started through UAC) --------------------

# Removes what the walk made and an unelevated process cannot remove, by name only: the app's own
# names (from the suffix), the new folders under Program Files, the standard account's home of the
# app. Writes what it did to `cleanup.log` in the root.
function Invoke-ElevatedCleanup {
    if ((Get-Standing) -ne 'UacElevated') { throw 'the clean-up runs only with a full administrator token' }
    if ($StandardUser -notmatch '^[A-Za-z0-9._-]{1,20}$') { throw 'bad account name' }
    if (-not (Test-Path -LiteralPath $root)) { throw 'no such run' }
    $log = Join-Path $root 'cleanup.log'
    function Say([string]$t) { Add-Content -LiteralPath $log -Value $t -Encoding UTF8 }
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch { }
        if ($path -and $path.StartsWith($R + '\', [StringComparison]::OrdinalIgnoreCase)) { try { Stop-Process -Id $p.Id -Force; Say "stopped a process under the app folder" } catch { } }
    }
    if ((Service-State $serviceName) -ne 'MISSING') {
        Native 'sc.exe' @('stop', $serviceName) | Out-Null
        Start-Sleep -Seconds 2
        $r = Native 'sc.exe' @('delete', $serviceName)
        Say "service deleted (sc exit $($r.Code))"
    }
    if (Test-Path -LiteralPath $uninstallKey) { Remove-Item -LiteralPath $uninstallKey -Recurse -Force; Say 'the Uninstall key removed' }
    if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\lunepack\$appId") { Remove-Item -LiteralPath "HKLM:\SOFTWARE\Policies\lunepack\$appId" -Recurse -Force; Say 'the policy key removed' }
    if (Test-Path -LiteralPath (Common-Shortcut)) { Remove-Item -LiteralPath (Common-Shortcut) -Force; Say 'the shortcut removed' }
    foreach ($d in @(New-ProgramFilesDirs)) { Remove-Tree $d.FullName; Say "folder $($d.Name) removed" }
    $null = Pending-Deletes -Remove
    $home1 = Std-Home $StandardUser
    $parent = Split-Path $home1 -Parent
    if (Test-Path -LiteralPath $home1) { Remove-Tree $home1; Say "the standard account's home of the app removed" }
    foreach ($h in @($parent, (Join-Path $env:SystemDrive "Users\$StandardUser\AppData\Local\lunepack"))) {
        if ((Test-Path -LiteralPath $h) -and @(Get-ChildItem -LiteralPath $h -Force -ErrorAction SilentlyContinue).Count -eq 0) { Remove-Item -LiteralPath $h -Force -ErrorAction SilentlyContinue }
    }
    $mine = Join-Path $env:LOCALAPPDATA "lunepack\$appId"
    if (Test-Path -LiteralPath $mine) { Remove-Tree $mine; Say "the administrator's home of the app removed" }
    $tempBeforeFile = Join-Path $root 'temp-before.txt'
    if (Test-Path -LiteralPath $tempBeforeFile) {
        $tb = @(Get-Content -LiteralPath $tempBeforeFile)
        foreach ($d in @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -ErrorAction SilentlyContinue)) {
            if ($tb -notcontains $d.Name -and $d.Name -match '^lunepack-(uninstall|setup-ui|setup)-[0-9a-f]{16}$') { Remove-Tree $d.FullName }
        }
    }
    Say 'done'
}

if ($ElevatedCleanup) {
    try { Invoke-ElevatedCleanup; exit 0 } catch { Add-Content -LiteralPath (Join-Path $root 'cleanup.log') -Value "error: $($_.Exception.Message)"; exit 1 }
}

# ---- refusals -------------------------------------------------------------------------------------------------

if ($env:CI -eq 'true' -or $env:GITHUB_ACTIONS -eq 'true') { Refuse 'this check is run by a person, never in CI' }
if (-not $Install) { Refuse 'this script installs for all users into the real Program Files, adds a service and HKLM keys; run it with -Install on a disposable machine (or -DryRun to list what it does)' }
if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { Refuse 'it asks questions: run it in a terminal window' }
$standing = Get-Standing
if ($standing -eq 'UacElevated') { Refuse 'this window is elevated; start it from an ordinary (not "Run as administrator") window, as an administrator account: the check needs the filtered token' }
if ($standing -ne 'AdminUnelevated') { Refuse 'this account is not an administrator' }
$sys = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
if ($null -eq $sys -or $sys.EnableLUA -ne 1) { Refuse 'UAC is off (EnableLUA); turn it on and restart' }
if ($null -ne $sys.ConsentPromptBehaviorAdmin -and $sys.ConsentPromptBehaviorAdmin -eq 0) { Refuse 'administrators are elevated without a prompt (ConsentPromptBehaviorAdmin 0); the consent prompt is what this checks' }
if (-not $StandardUser) { $StandardUser = Read-Host 'Name of an existing standard (not administrator) account on this machine' }
$StandardUser = ($StandardUser -replace '^.*\\', '').Trim()
if ($StandardUser -notmatch '^[A-Za-z0-9._-]{1,20}$') { Refuse 'the account name has characters this script does not accept' }
$acct = Get-LocalUser -Name $StandardUser -ErrorAction SilentlyContinue
if (-not $acct) { Refuse "no local account named '$StandardUser'" }
if (-not $acct.Enabled) { Refuse "the account '$StandardUser' is disabled" }
if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$StandardUser" }).Count -gt 0) { Refuse "'$StandardUser' is an administrator" }
if (Test-Path -LiteralPath $R) { Refuse 'the app folder of this run exists already' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tdir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
$rel = Join-Path $tdir 'release'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$hostName = $env:COMPUTERNAME

# ---- the report and the questions ------------------------------------------------------------------------------------

$lines = New-Object System.Collections.Generic.List[string]
$problems = New-Object System.Collections.Generic.List[string]
$script:step = $null

# Everything printed or written passes here: control characters out, the root named, long lines cut.
function Clean([string]$t) {
    $t = ($t -replace '[\x00-\x08\x0B-\x1F\x7F]', '')
    $t = $t.Replace($root, '<root>')
    if ($t.Length -gt 240) { $t = $t.Substring(0, 240) + '...' }
    return $t
}
function Note([string]$t) { $lines.Add((Clean $t)) }
function Say([string]$t) { Write-Output (Clean $t) }

function Pause-For([string]$what) {
    $a = Read-Host "$what  Press Enter when done"
    if ($null -eq $a) { throw 'input closed' }
}

function Ask([string]$id) {
    Require ($script:step.Questions -contains $id) "question $id belongs to item $($script:step.Id)"
    $q = $questions[$id]
    while ($true) {
        $form = if ($q.Kind -eq 'yn') { 'y/n' } else { $q.Choices -join '/' }
        $a = Read-Host "$($q.Text) [$form]"
        if ($null -eq $a) { throw 'input closed' }
        $a = (Clean $a).Trim().ToLowerInvariant()
        if ($q.Kind -eq 'yn' -and $a -in @('y', 'yes')) { $a = 'y' }
        if ($q.Kind -eq 'yn' -and $a -in @('n', 'no')) { $a = 'n' }
        if ($q.Kind -eq 'yn' -and $a -notin @('y', 'n')) { continue }
        if ($q.Kind -eq 'choice' -and $q.Choices -notcontains $a) { continue }
        break
    }
    $verdict = if ($q.Expect) { if ($a -eq $q.Expect) { 'as expected' } else { "DIFFERS (expected $($q.Expect))" } } else { 'noted' }
    if ($q.Expect -and $a -ne $q.Expect) { $problems.Add("question $id") }
    Note "question $id : $a ($verdict) - $($q.Text)"
}

function Check([string]$id, [scriptblock]$body) {
    Require ($script:step.Checks -contains $id) "check $id belongs to item $($script:step.Id)"
    try {
        & $body
        Say "ok   check $id"
        Note "check $id : ok - $($checks[$id])"
    } catch {
        $problems.Add("check $id")
        Say "FAIL check ${id}: $($_.Exception.Message)"
        Note "check $id : FAIL ($($_.Exception.Message)) - $($checks[$id])"
    }
}

function Wait-Until([scriptblock]$condition, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ($true) {
        if (& $condition) { return $true }
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 500
    }
}

# What an install for all users leaves, as far as an unelevated reader can see.
function Assert-Installed([string]$version) {
    Require (Test-Path -LiteralPath $R) 'the install folder exists'
    $r = Get-Record $R
    Require ($null -ne $r) 'a readable install record'
    SameV 'scope' $r.scope 'machine'
    SameV 'current' $r.current.version $version
    Require (Test-Path -LiteralPath $uninstallKey) 'the Uninstall key exists'
    Require (Test-Path -LiteralPath (Common-Shortcut)) 'the common Start-menu shortcut exists'
    Require ((Service-State $serviceName) -ne 'MISSING') 'the service is registered'
}

function Assert-Removed {
    Require (-not (Test-Path -LiteralPath $R)) 'the install folder is gone'
    Require (-not (Test-Path -LiteralPath $uninstallKey)) 'the Uninstall key is gone'
    Require (-not (Test-Path -LiteralPath (Common-Shortcut))) 'the shortcut is gone'
    SameV 'the service' (Service-State $serviceName) 'MISSING'
}

# A write the filtered token must be refused: only an access-denied counts, anything else is a finding.
function Assert-WriteDenied([string]$dir) {
    Require (Test-Path -LiteralPath $dir) "$(Split-Path $dir -Leaf) exists"
    $f = Join-Path $dir "lpcheck-$hex.tmp"
    $d = Join-Path $dir "lpcheck-$hex-dir"
    foreach ($case in @(@('file', { [IO.File]::WriteAllText($f, 'x') }, $f), @('folder', { [void][IO.Directory]::CreateDirectory($d) }, $d))) {
        $denied = $false
        try { & $case[1] } catch [UnauthorizedAccessException] { $denied = $true }
        if (Test-Path -LiteralPath $case[2]) { Remove-Tree $case[2]; throw "a $($case[0]) could be created under '$(Split-Path $dir -Leaf)'" }
        Require $denied "creating a $($case[0]) under '$(Split-Path $dir -Leaf)' is refused with access denied"
    }
}

function Assert-Protected([string]$path) {
    $leaf = Split-Path $path -Leaf
    $acl = Get-Acl -LiteralPath $path
    $owner = Sid-Of ([Security.Principal.NTAccount]$acl.Owner)
    Require ($trusted -contains $owner) "the owner of '$leaf' is one of SYSTEM, Administrators, TrustedInstaller"
    $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = Sid-Of $ace.IdentityReference
        if ($trusted -contains $sid) { continue }
        if (($ace.FileSystemRights -band $write) -ne 0) { throw "'$leaf' gives $sid a write-class right ($($ace.FileSystemRights))" }
    }
}

# ---- the publisher ----------------------------------------------------------------------------------------------------

$cli = Join-Path $rel 'lunepack.exe'
$cliExit = 0
$utf8 = New-Object System.Text.UTF8Encoding($false)

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
    $out = @(Invoke-LunepackOk $config @('keys', 'gen', $base))
    $m = $out | Select-String '^public:' | Select-Object -First 1
    Require ($null -ne $m) 'keys gen prints a public line'
    return ($m.Line -replace '^public:\s*', '').Trim()
}

# `file:///C:/dir/` for a directory (FORMAT 13.3: an uppercase drive, forward slashes).
function FileFeed([string]$dir) {
    $p = $dir -replace '\\', '/'
    return 'file:///' + $p.Substring(0, 1).ToUpperInvariant() + $p.Substring(1) + '/'
}

# Packs and publishes one version, with the update service and the real installer window.
function Publish-Version([string]$version) {
    $in = Join-Path $private "in-$version"
    [void][IO.Directory]::CreateDirectory($in)
    [IO.File]::Copy((Join-Path $rel 'examples\e2e_app.exe'), (Join-Path $in $entryFile), $true)
    $toml = "`n[update]`nfeed = `"$(FileFeed $feedDir)`"`nchannel = `"stable`"`nhealth_timeout_secs = 60`n`n[install]`nentry = `"$entryFile`"`nname = `"$appName`"`npublisher = `"Lunepack User Check`"`n"
    [IO.File]::WriteAllText($cfg, $baseToml + $toml, $utf8)
    Invoke-LunepackOk $cfg @('pack', '--input', $in, '--version', $version, '--target', 'windows-x86_64', '--release-dir', $feedDir, '--sign', "file:$private\rel0.key",
        '--runtime', (Join-Path $rel 'lunepack-runtime.exe'), '--stub', (Join-Path $rel 'lunepack-stub.exe'), '--service', (Join-Path $rel 'lunepack-service.exe'), '--ui', (Join-Path $rel 'lunepack-ui.exe')) | Out-Null
    Invoke-LunepackOk $cfg @('feed', 'add', '--release-dir', $feedDir, '--channel', 'stable', '--version', $version, '--sign', "file:$private\rel0.key") | Out-Null
}

# ---- the work -----------------------------------------------------------------------------------------------------------

$cfg = Join-Path $private 'lunepack.toml'
$baseToml = ''
$installedAnything = $false

function Build-All {
    Say 'building the release files (a few minutes the first time)'
    Push-Location $repo
    try {
        cargo build --locked --release -p lunepack-cli -p lunepack-runtime -p lunepack-stub -p lunepack-service -p lunepack-ui
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
        cargo build --locked --release -p lunepack --example e2e_app
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (example) failed' }
    } finally { Pop-Location }
    foreach ($f in 'lunepack.exe', 'lunepack-runtime.exe', 'lunepack-stub.exe', 'lunepack-service.exe', 'lunepack-ui.exe', 'examples\e2e_app.exe') {
        Require (Test-Path -LiteralPath (Join-Path $rel $f)) "the build left $f"
    }
}

function Acl-Dir([string]$path, [string[]]$grants) {
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    $a = @($path, '/inheritance:r')
    foreach ($g in $grants) { $a += @('/grant:r', $g) }
    & icacls.exe @a | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed (exit $LASTEXITCODE)" }
}

function Prepare {
    # The root: administrators and the person full, Users read and execute (the standard account
    # reads Setup.exe, the launchers and the feed). The signing keys: administrators and the person only.
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "*${me}:(OI)(CI)F")
    Acl-Dir $root ($grants + "*${usersSid}:(OI)(CI)RX")
    Acl-Dir $private $grants
    foreach ($d in $feedDir, $setupDir, $runDir) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    Set-Content -LiteralPath (Join-Path $root 'pf-before.txt') -Value (Names-In $pf) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $root 'temp-before.txt') -Value (Names-In ([IO.Path]::GetTempPath())) -Encoding UTF8
    $rootPub = Pub $cfg (Join-Path $private 'rootk')
    $relPub = Pub $cfg (Join-Path $private 'rel0')
    Invoke-LunepackOk $cfg @('init', '--app-id', $appId, '--root-key', $rootPub) | Out-Null
    $script:baseToml = [IO.File]::ReadAllText($cfg)
    Invoke-LunepackOk $cfg @('keys', 'set', '--release-dir', $feedDir, '--threshold', '1', '--release-key', $relPub, '--sign', "file:$private\rootk.key") | Out-Null
    Publish-Version '1.0.0'
    Invoke-LunepackOk $cfg @('setup', $feedDir, '--version', '1.0.0', '--target', 'windows-x86_64', '--out', (Join-Path $setupDir 'Setup.exe')) | Out-Null
    Require (Test-Path -LiteralPath (Join-Path $setupDir 'Setup.exe')) 'Setup.exe was built'
}

function Step-1 {
    Say ''
    Say "item 1: install for all users from the standard account '$StandardUser'"
    Say '  Start Setup.exe AS THAT ACCOUNT: either sign in as it, or in a command prompt of this account run'
    Say "    runas /user:$hostName\$StandardUser $setupDir\Setup.exe"
    Say '  (runas asks for that account''s password itself; this script never sees it).'
    Say '  On the welcome screen tick "Install for all users" and press Install. A credential prompt appears.'
    Say '  First DECLINE it (Cancel/No): the installer should show a retry screen. Retry, and this time approve it'
    Say '  with an administrator''s name and password typed into the Windows prompt.'
    Pause-For 'Wait for the installer to finish.'
    $null = Wait-Until { Test-Path -LiteralPath (Join-Path $R '.lunepack\state') } 60
    Check '1.installed' { Assert-Installed '1.0.0' }
    foreach ($q in $script:step.Questions) { Ask $q }
}

function Step-2 {
    Say ''
    Say 'item 2: the app updates with no prompt'
    Publish-Version '1.1.0'
    $launcher = Join-Path $runDir 'update.cmd'
    [IO.File]::WriteAllText($launcher, "@echo off`r`n`"$(Stub-Path)`" --update --no-ui`r`n", [Text.Encoding]::ASCII)
    Say "  1.1.0 is in the feed. As the standard account '$StandardUser' run the update launcher (it starts the app with --update):"
    Say "    runas /user:$hostName\$StandardUser $launcher"
    Say '  Watch for any prompt. The app has no window; the update takes up to a minute.'
    Pause-For 'Wait about a minute.'
    $null = Wait-Until { $r = Get-Record $R; $r -and $r.current.version -eq '1.1.0' -and -not $r.pending } 120
    Check '2.updated' {
        $r = Get-Record $R
        Require ($null -ne $r) 'a readable install record'
        SameV 'current' $r.current.version '1.1.0'
        SameV 'previous' $r.previous.version '1.0.0'
        Require ($null -eq $r.pending) 'nothing pending'
        SameV 'bad versions' ((@($r.bad)) -join ',') ''
        $qc = (Native 'sc.exe' @('qc', $serviceName)).Text
        Require ($qc -match 'BINARY_PATH_NAME\s*:\s*"?([^"\r\n]+)"?') 'the service has an image path'
        $want = (Join-Path $R '.lunepack\machine\service\1.1.0\lunepack-service.exe').ToLowerInvariant()
        SameV 'the service image' (($Matches[1].Trim() -replace '^\\\\\?\\', '').ToLowerInvariant()) $want
    }
    foreach ($q in $script:step.Questions) { Ask $q }
}

function Step-4 {
    Say ''
    Say 'item 4: uninstall from Settings (as this administrator account)'
    Say "  Open Settings > Apps > Installed apps, find '$appName', Uninstall. Confirm in the uninstaller's window,"
    Say '  then approve the consent prompt.'
    Pause-For 'Wait for the uninstaller to finish.'
    $null = Wait-Until { -not (Test-Path -LiteralPath $R) -and -not (Test-Path -LiteralPath $uninstallKey) } 120
    Check '4.removed' { Assert-Removed }
    foreach ($q in $script:step.Questions) { Ask $q }
}

function Step-6 {
    Say ''
    Say 'item 6: "Run as administrator" without --all-users, beside planted DLL files'
    $plant = & (Join-Path $PSScriptRoot 'ci\plant-dll-test.ps1') -Describe
    $dir = Join-Path $root 'plant-6'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($d in $plant.Planted) { [IO.File]::WriteAllBytes((Join-Path $dir "$d.dll"), $plant.Content) }
    $copy = Join-Path $dir 'Setup.exe'
    Copy-Item -LiteralPath (Join-Path $setupDir 'Setup.exe') -Destination $copy
    $pfNow = Names-In $pf
    Say '  The script starts that Setup elevated now. Approve the consent prompt, then close the one message box.'
    Pause-For 'Ready?'
    $code = $null
    try {
        $p = Start-Process -FilePath $copy -Verb RunAs -Wait -PassThru
        if ($null -ne $p) { $code = [int]$p.ExitCode }
    } catch { Say "  the elevated Setup could not be started or its exit code not read: $($_.Exception.Message)" }
    Check '6.usage-exit' {
        Require ($null -ne $code) 'the elevated Setup was started and its exit code could be read'
        $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$code), 0)
        Require ($plant.LoaderFailures -notcontains $u) ("the exit code 0x{0:X8} is not a loader failure" -f $u)
        SameV 'the exit code' $code $usageExit
    }
    Check '6.nothing-installed' {
        Assert-Removed
        $now = Names-In $pf
        SameV 'folders added under Program Files' (@($now | Where-Object { $pfNow -notcontains $_ }).Count) 0
    }
    foreach ($q in $script:step.Questions) { Ask $q }
}

function Step-3 {
    Say ''
    Say 'item 3: install for all users from this administrator account'
    Say "  Start $setupDir\Setup.exe from an ordinary window (double-click it), tick 'Install for all users',"
    Say '  press Install and approve the consent prompt.'
    Pause-For 'Wait for the installer to finish.'
    $null = Wait-Until { Test-Path -LiteralPath (Join-Path $R '.lunepack\state') } 60
    Check '3.installed' { Assert-Installed '1.0.0' }
    Check '3.write-denied' {
        foreach ($sub in '', 'app', '.lunepack', '.lunepack\state') { Assert-WriteDenied (Join-Path $R $sub).TrimEnd('\') }
        $rec = Get-ChildItem -LiteralPath (Join-Path $R '.lunepack\state') -Filter '*.rec' -File | Select-Object -First 1
        Require ($null -ne $rec) 'a record file to try'
        $denied = $false
        try { $fs = [IO.File]::Open($rec.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite); $fs.Dispose() } catch [UnauthorizedAccessException] { $denied = $true }
        Require $denied 'opening the install record for writing is refused with access denied'
    }
    Check '3.machine-denied' {
        $m = Join-Path $R '.lunepack\machine'
        Require (Test-Path -LiteralPath $m) 'the machine folder exists'
        $denied = $false
        try { [void][IO.Directory]::GetFileSystemEntries($m) } catch [UnauthorizedAccessException] { $denied = $true }
        Require $denied 'listing .lunepack\machine is refused with access denied'
    }
    Check '3.descriptors' {
        foreach ($sub in '', 'app', '.lunepack', '.lunepack\state') { Assert-Protected (Join-Path $R $sub).TrimEnd('\') }
    }
    foreach ($q in $script:step.Questions) { Ask $q }
}

function Find-Leftovers {
    $left = @()
    if (Test-Path -LiteralPath $R) { $left += 'the install folder' }
    if ((Service-State $serviceName) -ne 'MISSING') { $left += 'the service' }
    if (Test-Path -LiteralPath $uninstallKey) { $left += 'the Uninstall key' }
    if (Test-Path -LiteralPath (Common-Shortcut)) { $left += 'the shortcut' }
    foreach ($d in @(New-ProgramFilesDirs)) { $left += "a folder named $($d.Name)" }
    if ((Pending-Deletes) -gt 0) { $left += 'a delete-at-restart entry' }
    $h = Std-Home $StandardUser
    if (Test-Path -LiteralPath $h) { $left += "the standard account's home of the app" }
    return $left
}

# The elevated clean-up: one more consent prompt, then a second copy of this script removes the rest.
function Invoke-Cleanup {
    $left = @(Find-Leftovers)
    if ($left.Count -eq 0) { return }
    Say "left: $($left -join '; ')"
    Say 'Windows will ask once more (consent prompt) to start the elevated clean-up of exactly these names.'
    $shell = (Get-Process -Id $PID).Path
    $p = $null
    try {
        $p = Start-Process -FilePath $shell -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-ElevatedCleanup', $hex, '-StandardUser', $StandardUser)
    } catch { Say "the elevated clean-up was not started: $($_.Exception.Message)" }
    $log = Join-Path $root 'cleanup.log'
    if (Test-Path -LiteralPath $log) { foreach ($l in @(Get-Content -LiteralPath $log)) { Say "  clean-up: $l" } }
    if ($null -eq $p -or $p.ExitCode -ne 0) { Say 'the elevated clean-up did not finish cleanly' }
}

function Step-z {
    Say ''
    Say 'final: uninstall (as this administrator account)'
    if (Test-Path -LiteralPath $R) {
        $u = (Get-ItemProperty -LiteralPath $uninstallKey -ErrorAction SilentlyContinue).UninstallString
        if ($u -and $u -match '^"([^"]+)"\s*(.*)$') {
            Say '  The uninstaller starts now: confirm in its window and approve the consent prompt.'
            $args2 = if ($Matches[2]) { $Matches[2] } else { $null }
            $params = @{ FilePath = $Matches[1]; PassThru = $true }
            if ($args2) { $params['ArgumentList'] = $args2 }
            $p = Start-Process @params
            $null = $p.Handle
            [void]$p.WaitForExit(60000)
            $null = Wait-Until { -not (Test-Path -LiteralPath $R) } 180
        } else {
            Say '  no usable uninstall command is registered; the clean-up below removes the install by name'
        }
    }
    Invoke-Cleanup
    Remove-Item -LiteralPath (Join-Path $root 'plant-6') -Recurse -Force -ErrorAction SilentlyContinue
    Check 'z.removed' {
        $left = @(Find-Leftovers)
        Require ($left.Count -eq 0) "nothing is left (found: $($left -join '; '))"
    }
    foreach ($q in $script:step.Questions) { Ask $q }
}

# ---- run ------------------------------------------------------------------------------------------------------------------

$exit = 0
try {
    Say "windows-machine-user-check: standard account '$StandardUser'; the app is '$appName'"
    Say 'This installs for all users into the real Program Files and adds a service and an HKLM key; it removes them at the end.'
    $yes = Read-Host 'Type yes to go on'
    if ($yes -ne 'yes') { Refuse 'not confirmed; nothing was touched' }
    Note "windows-machine-user-check report for '$appName' ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
    Note 'administrator account: unelevated (filtered token); UAC on; a separate standard account'
    Build-All
    $installedAnything = $true
    Prepare
    foreach ($s in $walk) {
        $script:step = $s
        & ("Step-" + $s.Id)
    }
} catch {
    $exit = 1
    $problems.Add('the walk stopped')
    Say "the walk stopped: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
    Note "the walk stopped: $($_.Exception.Message)"
} finally {
    if ($installedAnything) {
        try {
            $left = @(Find-Leftovers)
            if ($left.Count -gt 0) { Invoke-Cleanup }
        } catch { Say "clean-up error: $($_.Exception.Message)" }
    }
}

Note ''
Note "verdict: $(if ($problems.Count -eq 0) { 'everything as expected' } else { 'differences: ' + ($problems -join ', ') })"
Say ''
Say '---- report ----'
foreach ($l in $lines) { Write-Output $l }
if ($Report) {
    try { [IO.File]::WriteAllLines($Report, [string[]]$lines, $utf8); Say "the report was also written to the file you named" } catch { Say 'the report file could not be written' }
}
try { Remove-Tree $root } catch { }
if (Test-Path -LiteralPath $root) { Say 'the temporary root could not be removed; remove it by hand' }
if ($problems.Count -gt 0) { exit 1 }
exit $exit
