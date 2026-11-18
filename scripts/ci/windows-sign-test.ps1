# Signed Setup.exe test (M7-D11, step 13), CI only.
#
# Makes a throwaway self-signed code-signing certificate for this job, trusts it in
# LocalMachine\Root and LocalMachine\TrustedPublisher, signs a copy of the given Setup.exe with
# signtool, and checks the three claims of M7-D11:
#   1. `signtool verify /pa` passes and the signed file installs (`/S`, exit 0; with -NoInstall the
#      install is skipped and a signed file must still be recognised as a setup file: a usage
#      error, exit 2, instead of a verify error);
#   2. one byte flipped inside the trailer area (the 4096 bytes before the certificate table)
#      makes `signtool verify` fail and the setup exit 7;
#   3. one byte appended after the signed file makes the setup exit 7.
# The certificate is generated at run time and removed afterwards; nothing is committed. Without
# signtool, or without the rights to trust a certificate, the script prints "skipped: ..." and
# exits 0.
param([Parameter(Mandatory = $true)][string]$Setup, [switch]$NoInstall)
$ErrorActionPreference = 'Stop'
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Write-Output 'skipped: no signtool'; exit 0 }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Output 'skipped: not elevated (the certificate must be trusted machine-wide)'; exit 0 }

$hex = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$dir = Join-Path ([IO.Path]::GetTempPath()) "lunepack-sign-$hex"
New-Item -ItemType Directory $dir | Out-Null
$cert = $null
$trusted = @()
$failed = 0
function Check([string]$what, [bool]$ok) {
    if ($ok) { Write-Output "ok   $what" } else { Write-Output "FAIL $what"; $script:failed++ }
}
try {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=lunepack-e2e-$hex" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $cer = Join-Path $dir 'e2e.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    foreach ($store in 'Root', 'TrustedPublisher') {
        Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
        $trusted += "Cert:\LocalMachine\$store\$($cert.Thumbprint)"
    }

    $signed = Join-Path $dir 'Setup-signed.exe'
    Copy-Item $Setup $signed
    & $signtool.FullName sign /fd sha256 /sha1 $cert.Thumbprint /s My $signed | Out-Null
    Check 'signtool sign' ($LASTEXITCODE -eq 0)
    & $signtool.FullName verify /pa $signed | Out-Null
    Check 'signtool verify /pa passes on the signed Setup.exe' ($LASTEXITCODE -eq 0)

    # The certificate table: PE32+ optional header at e_lfanew + 24, data directory 4 at +112 + 32.
    $bytes = [IO.File]::ReadAllBytes($signed)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $tableAt = [BitConverter]::ToUInt32($bytes, $pe + 24 + 112 + 32)
    Check 'the signed file has a certificate table at its end' ($tableAt -gt 4096 -and $tableAt -lt $bytes.Length)

    if (-not $NoInstall) {
        $p = Start-Process -FilePath $signed -ArgumentList '/S' -Wait -PassThru
        Check 'the signed Setup.exe installs with /S (exit 0)' ($p.ExitCode -eq 0)
        # The caller's script removes what installed, by the app's own uninstall entry.
    } else {
        $p = Start-Process -FilePath $signed -ArgumentList '--no-such-option' -Wait -PassThru
        Check 'a signed Setup.exe is recognised as a setup file (usage error 2, not verify 7)' ($p.ExitCode -eq 2)
    }

    $flipped = Join-Path $dir 'Setup-flipped.exe'
    $b = [byte[]]$bytes.Clone()
    $b[[int]$tableAt - 100] = $b[[int]$tableAt - 100] -bxor 0x01
    [IO.File]::WriteAllBytes($flipped, $b)
    & $signtool.FullName verify /pa $flipped 2>&1 | Out-Null
    Check 'signtool verify fails after one trailer byte is flipped' ($LASTEXITCODE -ne 0)
    $p = Start-Process -FilePath $flipped -ArgumentList '/S' -Wait -PassThru
    Check 'the setup with a flipped trailer byte exits 7' ($p.ExitCode -eq 7)

    $appended = Join-Path $dir 'Setup-appended.exe'
    [IO.File]::WriteAllBytes($appended, [byte[]]($bytes + [byte]0))
    $p = Start-Process -FilePath $appended -ArgumentList '/S' -Wait -PassThru
    Check 'the setup with one appended byte exits 7' ($p.ExitCode -eq 7)
} finally {
    foreach ($t in $trusted) { Remove-Item -Path $t -Force -ErrorAction SilentlyContinue }
    if ($cert) { Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
exit $(if ($failed -gt 0) { 1 } else { 0 })
