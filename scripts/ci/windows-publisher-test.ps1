# Publisher-continuity test (M9-D8, step 6), CI only.
#
# Runs `cargo test -p lunepack-os-windows --test publisher`, which makes throwaway self-signed
# code-signing certificates at run time, trusts them machine-wide for the length of each test (so
# the session must be elevated), signs small PE images with signtool and asks `WinPublisherCheck`
# about pairs of trees. Each certificate is removed from every store when its test ends; this script
# also removes any `lunepack-publisher-test-*` certificate a killed run left behind, in a `finally`
# block. Nothing is written into the repo and no key file is kept.
#
# Any row that was skipped (no signtool, not elevated) is named in the output; on CI (`CI` set) a
# skip fails the script, so a row cannot be dropped to make the job pass. Locally the skips are
# printed and the script exits 0.
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$onCi = [bool]$env:CI
if (-not $admin) {
    Write-Output 'skipped: not elevated (the test roots must be trusted machine-wide)'
    exit $(if ($onCi) { 1 } else { 0 })
}
function Remove-TestCerts {
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher') {
        Get-ChildItem $store -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like 'CN=lunepack-publisher-test-*' } |
            ForEach-Object { Remove-Item -Path "$store\$($_.Thumbprint)" -Force -ErrorAction SilentlyContinue }
    }
}
$code = 1
try {
    Remove-TestCerts
    $output = & cargo test -p lunepack-os-windows --locked --test publisher -- --nocapture --test-threads=2 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Output $_ }
    $skips = @($output | Where-Object { $_ -match '^skipped:' })
    if ($skips.Count -gt 0) {
        Write-Output "publisher test: $($skips.Count) skipped row group(s) (named above)"
        if ($onCi) { $code = 1 }
    }
} finally {
    Remove-TestCerts
}
exit $code
