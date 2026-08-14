$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$env:FIREFOX_REPOSITORY -or !$env:FIREFOX_REF -or !$env:FIREFOX_REVISION) { throw 'Firefox source identity missing' }
$source = "$env:RUNNER_TEMP\firefox-source"
git init $source
git -C $source remote add origin $env:FIREFOX_REPOSITORY
git -C $source fetch --depth=1 origin "refs/tags/$($env:FIREFOX_REF):refs/tags/$($env:FIREFOX_REF)"
git -C $source checkout --detach $env:FIREFOX_REVISION
if ((git -C $source rev-parse HEAD) -ne $env:FIREFOX_REVISION) { throw 'Firefox revision mismatch' }
$profileServer = "$source\build\pgo\profileserver.py"
if (!(Test-Path $profileServer)) { throw 'exact upstream profileserver.py is missing' }
$recorded = Get-Content "$env:RUNNER_TEMP\provenance\build.json" | ConvertFrom-Json
$actualHash = (Get-FileHash -Algorithm SHA256 $profileServer).Hash.ToLowerInvariant()
if ($actualHash -ne $recorded.profileserver.sha256) { throw 'profileserver.py SHA-256 does not match generation provenance' }
$package = Get-ChildItem "$env:RUNNER_TEMP\instrumented" -File | Where-Object { $_.Name -match '\.tar\.(xz|zst)$' }
if (@($package).Count -ne 1) { throw 'expected exactly one instrumented package' }
$staged = "$env:RUNNER_TEMP\staged"
New-Item -ItemType Directory -Force $staged | Out-Null
& 7z x $package.FullName "-o$staged" -y | Out-Host
& 7z x (Get-ChildItem $staged -Filter '*.tar').FullName "-o$staged" -y | Out-Host
$firefox = Get-ChildItem $staged -Recurse -Filter firefox.exe | Select-Object -First 1
if (!$firefox) { throw 'Firefox cannot start: firefox.exe absent from staged package' }
$out = "$env:RUNNER_TEMP\training-output"
New-Item -ItemType Directory -Force $out | Out-Null
$env:JARLOG_FILE = "$out\jarlog"
$log = "$out\profileserver.log"

# profileserver.py overrides LLVM_PROFILE_FILE with a path rooted at its current
# working directory. Run at topsrcdir for MozbuildObject.from_environment(),
# remove stale profiles first, then collect exactly the files created there.
Get-ChildItem $source -File -Filter '*.profraw' -ErrorAction SilentlyContinue | Remove-Item -Force
Push-Location $source
try {
    & python mach python --virtualenv build build/pgo/profileserver.py --binary $firefox.FullName *>&1 | Tee-Object -FilePath $log
    $profileStatus = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($profileStatus -ne 0) { throw "profileserver workload exited $profileStatus" }
if (Select-String -Path $log -SimpleMatch 'LLVM Profile Error') { throw 'LLVM Profile Error reported' }
$raw = @(Get-ChildItem $source -File -Filter '*.profraw' | Where-Object Length -gt 0)
if ($raw.Count -eq 0) { throw 'no newly produced non-empty *.profraw files were produced' }
foreach ($profile in $raw) { Move-Item -LiteralPath $profile.FullName -Destination $out }
if (!(Test-Path $env:JARLOG_FILE) -or (Get-Item $env:JARLOG_FILE).Length -eq 0) { throw 'no non-empty jarlog was produced' }
Write-Host "Produced $($raw.Count) non-empty raw LLVM profiles and $((Get-Item $env:JARLOG_FILE).Length) jarlog bytes."
