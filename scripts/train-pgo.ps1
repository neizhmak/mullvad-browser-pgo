# Train only the generation-proven Firefox package with its exact source.
# The Python helper runs pinned mach Python, applies timeouts, and saves native
# bootstrap/browser/profile diagnostics even when a child exits nonzero.
[CmdletBinding()]
param(
    [int]$WorkloadTimeoutSeconds = 3600,
    [int]$BootstrapTimeoutSeconds = 600
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false
$script:failureExitCode = 1
$script:sourceReady = $false
$source = "$env:RUNNER_TEMP\firefox-source"
$out = "$env:RUNNER_TEMP\training-output"
$staged = "$env:RUNNER_TEMP\staged"
$helper = Join-Path $PSScriptRoot 'profile-artifacts.py'

function Invoke-NativeChecked {
    param([string]$Program, [string[]]$Arguments, [string]$Log)
    & $Program @Arguments *>&1 | Tee-Object -FilePath $Log -Append | Out-Host
    $status = $LASTEXITCODE
    if ($status -ne 0) {
        $script:failureExitCode = $status
        throw "native command $Program exited $status (see $Log)"
    }
}

try {
    if (!$env:RUNNER_TEMP -or !$env:FIREFOX_REPOSITORY -or !$env:FIREFOX_REF -or !$env:FIREFOX_REVISION) {
        throw 'Firefox source identity missing'
    }
    if ($WorkloadTimeoutSeconds -le 0 -or $BootstrapTimeoutSeconds -le 0) { throw 'timeouts must be positive' }
    # A reused work directory must never silently mix old training data.
    if ((Test-Path $out) -and @(Get-ChildItem $out -Force).Count -ne 0) { throw 'refusing stale training-output directory' }
    New-Item -ItemType Directory -Force $out | Out-Null
    $recorded = Get-Content -Raw "$env:RUNNER_TEMP\provenance\build.json" | ConvertFrom-Json
    if ($recorded.firefox.repository -ne $env:FIREFOX_REPOSITORY -or
        $recorded.firefox.ref -ne $env:FIREFOX_REF -or
        $recorded.firefox.revision -ne $env:FIREFOX_REVISION) { throw 'Firefox environment does not match build provenance' }
    if ($recorded.browser_executable -cne 'mullvadbrowser.exe') { throw 'browser executable does not match locked Mullvad Windows scope' }
    if ($env:FIREFOX_REVISION -notmatch '^[0-9a-f]{40}$') { throw 'invalid Firefox revision' }
    if (Test-Path $source) { throw 'refusing stale Firefox source directory' }
    $gitLog = "$out\source-fetch.log"
    Invoke-NativeChecked 'git' @('init', $source) $gitLog
    # Windows global autocrlf=true changes the workload bytes and defeats exact
    # upstream hash verification. Long paths are needed by vendored test assets.
    Invoke-NativeChecked 'git' @('-C', $source, 'config', 'core.autocrlf', 'false') $gitLog
    Invoke-NativeChecked 'git' @('-C', $source, 'config', 'core.eol', 'lf') $gitLog
    Invoke-NativeChecked 'git' @('-C', $source, 'config', 'core.longpaths', 'true') $gitLog
    Invoke-NativeChecked 'git' @('-C', $source, 'remote', 'add', 'origin', $env:FIREFOX_REPOSITORY) $gitLog
    Invoke-NativeChecked 'git' @('-C', $source, 'fetch', '--depth=1', 'origin', "refs/tags/$($env:FIREFOX_REF):refs/tags/$($env:FIREFOX_REF)") $gitLog
    $tagRevision = & git -C $source rev-parse "refs/tags/$($env:FIREFOX_REF)^{commit}"
    $status = $LASTEXITCODE
    if ($status -ne 0) { $script:failureExitCode = $status; throw "git tag resolution exited $status" }
    if ($tagRevision.Trim() -ne $env:FIREFOX_REVISION) { throw 'Firefox tag revision mismatch' }
    Invoke-NativeChecked 'git' @('-C', $source, 'checkout', '--detach', $env:FIREFOX_REVISION) $gitLog
    $actualRevision = & git -C $source rev-parse HEAD
    $status = $LASTEXITCODE
    if ($status -ne 0) { $script:failureExitCode = $status; throw "git rev-parse exited $status" }
    if ($actualRevision.Trim() -ne $env:FIREFOX_REVISION) { throw 'Firefox revision mismatch' }
    $profileServer = "$source\build\pgo\profileserver.py"
    if (!(Test-Path $profileServer)) { throw 'exact upstream profileserver.py is missing' }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $profileServer).Hash.ToLowerInvariant()
    if ($actualHash -ne $recorded.profileserver.sha256) { throw 'profileserver.py SHA-256 does not match generation provenance' }
    $script:sourceReady = $true
    $package = @(Get-ChildItem "$env:RUNNER_TEMP\instrumented" -File | Where-Object { $_.Name -match '\.tar\.(xz|zst)$' })
    if ($package.Count -ne 1) { throw 'expected exactly one instrumented package' }
    $package = $package[0]
    $actualPackageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $package.FullName).Hash.ToLowerInvariant()
    if ($actualPackageHash -ne $recorded.instrumented_package_sha256) { throw 'instrumented package SHA-256 does not match generation provenance' }
    if (Test-Path $staged) { throw 'refusing stale staged package directory' }
    New-Item -ItemType Directory $staged | Out-Null
    $unpackLog = "$out\unpack.log"
    Invoke-NativeChecked '7z' @('x', $package.FullName, "-o$staged", '-y') $unpackLog
    $tar = @(Get-ChildItem $staged -File -Filter '*.tar')
    if ($tar.Count -ne 1) { throw 'expected exactly one intermediate package tar' }
    Invoke-NativeChecked '7z' @('x', $tar[0].FullName, "-o$staged", '-y') $unpackLog
    # Locked Mullvad Windows scope: upstream rbm.conf var/exe_name is
    # mullvadbrowser, not firefox. Do not select the first Mozilla executable.
    $firefox = @(Get-ChildItem $staged -Recurse -File -Filter $recorded.browser_executable)
    if ($firefox.Count -ne 1) { throw 'Mullvad Browser cannot start: expected exactly one mullvadbrowser.exe in staged package' }
    $firefox = $firefox[0]
    $stageRoot = (Resolve-Path -LiteralPath $staged).Path.TrimEnd([char[]]'\/') + [System.IO.Path]::DirectorySeparatorChar
    if ($firefox.Name -ine $recorded.browser_executable -or
        [System.IO.Path]::GetFileName($firefox.FullName) -ine $recorded.browser_executable -or
        !$firefox.FullName.StartsWith($stageRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mullvad Browser executable does not match the locked staged package'
    }
    $log = "$out\profileserver.log"
    # The exact profileserver sets its own absolute LLVM profile path at
    # topsrcdir. Its mozrunner adds --wait-for-browser on Windows and propagates
    # both initialization and workload native exit codes. No wrapper workload or
    # extra Firefox launch contributes profile data.
    # Ensure MozillaBuild directory exists on Windows runners where C:\mozilla-build is absent
    $mozillabuild = "$env:RUNNER_TEMP\mozilla-build"
    New-Item -ItemType Directory -Force "$mozillabuild\msys2\usr\bin" | Out-Null
    New-Item -ItemType Directory -Force "$mozillabuild\msys\bin" | Out-Null
    New-Item -ItemType Directory -Force "$mozillabuild\bin" | Out-Null
    $env:MOZILLABUILD = $mozillabuild
    # Command executed by helper: python mach python --virtualenv build build/pgo/profileserver.py --binary ...
    Get-ChildItem $source -File -Filter '*.profraw' -ErrorAction SilentlyContinue | Remove-Item -Force
    Invoke-NativeChecked 'python' @($helper, 'run-profileserver', '--source-directory', $source,
        '--binary', $firefox.FullName, '--output-directory', $out,
        '--build-provenance', "$env:RUNNER_TEMP\provenance\build.json",
        '--timeout-seconds', "$WorkloadTimeoutSeconds", '--bootstrap-timeout-seconds', "$BootstrapTimeoutSeconds") "$out\training-driver.log"
    # The helper moves every raw file (including empty diagnostics on failure).
    $raw = @(Get-ChildItem $out -File -Filter '*.profraw' | Where-Object Length -gt 0)
    if ($raw.Count -eq 0) { throw 'no newly produced non-empty *.profraw files were produced' }
    if (!(Test-Path "$out\jarlog") -or (Get-Item "$out\jarlog").Length -eq 0) { throw 'no non-empty jarlog was produced' }
    Invoke-NativeChecked 'python' @($helper, 'record-training', '--training-directory', $out,
        '--build-provenance', "$env:RUNNER_TEMP\provenance\build.json",
        '--source-directory', $source, '--instrumented-package', $package.FullName) "$out\training-driver.log"
    Write-Host "Produced $($raw.Count) verified raw LLVM profiles and $((Get-Item "$out\jarlog").Length) jarlog bytes."
} catch {
    if (Test-Path $out) {
        # Preserve native status/partial profiles as diagnostics, not success.
        if ($script:sourceReady) {
            foreach ($profile in @(Get-ChildItem $source -File -Filter '*.profraw' -ErrorAction SilentlyContinue)) {
                Move-Item -LiteralPath $profile.FullName -Destination $out -ErrorAction Continue
            }
        }
        $_.ToString() | Out-File -Encoding utf8 "$out\training-failure.log"
        @{ schema = 1; exit_code = $script:failureExitCode; error = $_.ToString() } |
            ConvertTo-Json | Out-File -Encoding utf8 "$out\training-failure.json"
    }
    Write-Error $_ -ErrorAction Continue
    exit $script:failureExitCode
}
