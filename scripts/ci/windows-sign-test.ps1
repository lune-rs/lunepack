# Signed Setup.exe and publisher-continuity test (M7-D11 step 13, M9 step 9), CI only.
#
# Makes throwaway self-signed code-signing certificates for this job (A, and B when -Continue is
# given), trusts them in LocalMachine\Root and LocalMachine\TrustedPublisher, and hands them to the
# caller's script blocks:
#   -Publish  a script block called with the context ($ctx: Signtool, ThumbA, ThumbB, SubjectA,
#             SubjectB); it publishes a release through the packager's [codesign.windows] templates
#             (signtool is only ever called by lunepack, never by this script) and returns the path
#             of the Setup.exe `lunepack setup` made and signed from it;
# and checks the claims of M7-D11 on that file:
#   1. `signtool verify /pa` passes and the signed file installs (`/S`, exit 0; with -NoInstall the
#      install is skipped and a signed file must still be recognised as a setup file: a usage
#      error, exit 2, instead of a verify error);
#   2. one byte flipped inside the trailer area (the 4096 bytes before the certificate table)
#      makes `signtool verify` fail and the setup exit 7;
#   3. one byte appended after the signed file makes the setup exit 7.
# Then
#   -Continue a script block called with the same context after the install: the caller's
#             publisher-continuity rows (an update by the same certificate, by another one, a
#             release with an unsigned DLL) run against that install.
# (This script's own variables have unusual names on purpose: the caller's functions read variables
# through the call stack, so a common name here could change what they see.)
# Every certificate is generated at run time and removed from every store afterwards, whatever
# happens; nothing is committed and no key file is kept. Without signtool, or without the rights to
# trust a certificate, the script prints "skipped: ..." and exits 0 on a developer machine and 1 on
# CI (a skip is not a pass there).
param(
    [Parameter(Mandatory = $true)][scriptblock]$Publish,
    [scriptblock]$Continue = $null,
    [switch]$NoInstall
)
$ErrorActionPreference = 'Stop'
$skipCode = $(if ($env:CI -eq 'true') { 1 } else { 0 })
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Write-Output 'skipped: no signtool'; exit $skipCode }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Output 'skipped: not elevated (the certificate must be trusted machine-wide)'; exit $skipCode }

$runId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) "lunepack-sign-$runId"
New-Item -ItemType Directory $tmpDir | Out-Null
$certs = @()
$trusted = @()
$failed = 0
function Check([string]$what, [bool]$ok, [string]$detail = '') {
    if ($ok) { Write-Output "ok   $what" } else { Write-Output "FAIL $what$(if ($detail) { " ($detail)" })"; $script:failed++ }
}
# An exit code check prints the code it got beside the one it wanted.
function CheckExit([string]$what, $got, [int]$want) {
    Check "$what (exit $want)" ($got -eq $want) "exit $got"
}
# A throwaway code-signing certificate, trusted for this job's length.
function New-TestCert([string]$name) {
    $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$name" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $script:certs += $c
    $cer = Join-Path $tmpDir "$name.cer"
    Export-Certificate -Cert $c -FilePath $cer | Out-Null
    foreach ($store in 'Root', 'TrustedPublisher') {
        Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
        $script:trusted += "Cert:\LocalMachine\$store\$($c.Thumbprint)"
    }
    return $c
}
try {
    $certA = New-TestCert "lunepack-e2e-$runId"
    $certB = $null
    if ($Continue) { $certB = New-TestCert "lunepack-e2e-b-$runId" }
    $ctx = [pscustomobject]@{
        Signtool = $signtool.FullName
        ThumbA = $certA.Thumbprint
        ThumbB = $(if ($certB) { $certB.Thumbprint } else { '' })
        SubjectA = $certA.Subject
        SubjectB = $(if ($certB) { $certB.Subject } else { '' })
    }

    $setupSigned = [string]@(& $Publish $ctx)[-1]
    Check 'the packager made a signed Setup.exe' (($setupSigned -ne '') -and (Test-Path -LiteralPath $setupSigned))
    if (-not (Test-Path -LiteralPath $setupSigned)) { throw 'no Setup.exe to check' }
    & $signtool.FullName verify /pa $setupSigned | Out-Null
    Check 'signtool verify /pa passes on the Setup.exe the packager signed' ($LASTEXITCODE -eq 0)

    # The certificate table: PE32+ optional header at e_lfanew + 24, data directory 4 at +112 + 32.
    $bytes = [IO.File]::ReadAllBytes($setupSigned)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $tableAt = [BitConverter]::ToUInt32($bytes, $pe + 24 + 112 + 32)
    Check 'the signed file has a certificate table at its end' ($tableAt -gt 4096 -and $tableAt -lt $bytes.Length)
    # FORMAT 14.3 reads the trailer as the 4096 bytes before the table, so the table must start
    # where the unsigned file ended: the packager pads the unsigned file to a multiple of 8 (Q89),
    # and the PE format puts the table at one. The install below is the claim that matters.
    Check 'the certificate table starts on an 8-byte boundary' (($tableAt % 8) -eq 0) "table at $tableAt"

    if (-not $NoInstall) {
        $proc = Start-Process -FilePath $setupSigned -ArgumentList '/S' -Wait -PassThru
        CheckExit 'the signed Setup.exe installs with /S' $proc.ExitCode 0
        # The caller's script removes what installed, by the app's own uninstall entry.
    } else {
        $proc = Start-Process -FilePath $setupSigned -ArgumentList '--no-such-option' -Wait -PassThru
        CheckExit 'a signed Setup.exe is recognised as a setup file (usage error, not verify 7)' $proc.ExitCode 2
    }

    $flipped = Join-Path $tmpDir 'Setup-flipped.exe'
    $tampered = [byte[]]$bytes.Clone()
    $tampered[[int]$tableAt - 100] = $tampered[[int]$tableAt - 100] -bxor 0x01
    [IO.File]::WriteAllBytes($flipped, $tampered)
    & $signtool.FullName verify /pa $flipped 2>&1 | Out-Null
    Check 'signtool verify fails after one trailer byte is flipped' ($LASTEXITCODE -ne 0)
    $proc = Start-Process -FilePath $flipped -ArgumentList '/S' -Wait -PassThru
    CheckExit 'the setup with a flipped trailer byte is refused' $proc.ExitCode 7

    $appended = Join-Path $tmpDir 'Setup-appended.exe'
    [IO.File]::WriteAllBytes($appended, [byte[]]($bytes + [byte]0))
    $proc = Start-Process -FilePath $appended -ArgumentList '/S' -Wait -PassThru
    CheckExit 'the setup with one appended byte is refused' $proc.ExitCode 7

    if ($Continue -and ($failed -eq 0)) {
        & $Continue $ctx
    } elseif ($Continue) {
        Write-Output 'skipped: the publisher-continuity rows (the signed Setup.exe checks failed)'
    }
} catch {
    Write-Output "FAIL $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
    $failed++
} finally {
    foreach ($t in $trusted) { Remove-Item -Path $t -Force -ErrorAction SilentlyContinue }
    foreach ($c in $certs) { Remove-Item -Path "Cert:\CurrentUser\My\$($c.Thumbprint)" -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
exit $(if ($failed -gt 0) { 1 } else { 0 })
