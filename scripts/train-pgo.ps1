$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$env:FIREFOX_REPOSITORY -or !$env:FIREFOX_REVISION) { throw 'Firefox source identity missing' }
git init $env:RUNNER_TEMP\firefox-source
git -C $env:RUNNER_TEMP\firefox-source remote add origin $env:FIREFOX_REPOSITORY
git -C $env:RUNNER_TEMP\firefox-source fetch --depth=1 origin $env:FIREFOX_REVISION
git -C $env:RUNNER_TEMP\firefox-source checkout --detach $env:FIREFOX_REVISION
if ((git -C $env:RUNNER_TEMP\firefox-source rev-parse HEAD) -ne $env:FIREFOX_REVISION) { throw 'Firefox revision mismatch' }
$profileServer = "$env:RUNNER_TEMP\firefox-source\build\pgo\profileserver.py"
if (!(Test-Path $profileServer)) { throw 'exact upstream profileserver.py is missing' }
$package = Get-ChildItem "$env:RUNNER_TEMP\instrumented" -File | Where-Object { $_.Name -match '\.tar\.(xz|zst)$' }
if (@($package).Count -ne 1) { throw 'expected exactly one instrumented package' }
$staged = "$env:RUNNER_TEMP\staged"
New-Item -ItemType Directory -Force $staged | Out-Null
& 7z x $package.FullName "-o$staged" -y | Out-Host
& 7z x (Get-ChildItem $staged -Filter '*.tar').FullName "-o$staged" -y | Out-Host
$firefox = Get-ChildItem $staged -Recurse -Filter firefox.exe | Select-Object -First 1
if (!$firefox) { throw 'Firefox cannot start: firefox.exe absent from staged package' }
$out = "$env:RUNNER_TEMP\training-output"; New-Item -ItemType Directory -Force $out | Out-Null
$env:LLVM_PROFILE_FILE = "$out\firefox-%p-%m.profraw"
$env:JARLOG_FILE = "$out\jarlog"
$log = "$out\profileserver.log"
& python $profileServer --binary $firefox.FullName *>&1 | Tee-Object -FilePath $log
if ($LASTEXITCODE -ne 0) { throw "profileserver workload exited $LASTEXITCODE" }
if (Select-String -Path $log -SimpleMatch 'LLVM Profile Error') { throw 'LLVM Profile Error reported' }
$raw = @(Get-ChildItem $out -Filter '*.profraw' | Where-Object Length -gt 0)
if ($raw.Count -eq 0) { throw 'no non-empty *.profraw files were produced' }
if (!(Test-Path $env:JARLOG_FILE) -or (Get-Item $env:JARLOG_FILE).Length -eq 0) { throw 'no non-empty jarlog was produced' }
Write-Host "Produced $($raw.Count) non-empty raw LLVM profiles and $((Get-Item $env:JARLOG_FILE).Length) jarlog bytes."
