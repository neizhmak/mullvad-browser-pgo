# Run native hash-verified package checks without changing browser defaults.
[CmdletBinding()]
param(
    [string]$PackageDirectory = "$env:RUNNER_TEMP\pgo-packages",
    [string]$OutputDirectory = "$env:RUNNER_TEMP\pgo-runtime-check",
    [string]$BaselineDirectory = "$env:RUNNER_TEMP\baseline",
    [switch]$AllowNoBaselineExperiment,
    [ValidateRange(3, 30)][int]$Samples = 5,
    [ValidateRange(1000, 60000)][int]$TargetMilliseconds = 1200,
    [ValidateRange(1, 3600)][int]$BrowserTimeoutSeconds = 180,
    [ValidateRange(1, 3600)][int]$InstallerTimeoutSeconds = 300,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false
$helper = Join-Path $PSScriptRoot 'windows-runtime-check.py'
if ($AllowNoBaselineExperiment -and !(Test-Path -LiteralPath $BaselineDirectory)) { $BaselineDirectory = '' }
if (!$BaselineDirectory -and !$AllowNoBaselineExperiment) {
    throw 'A same-lock baseline is required. Prepare it with windows-runtime-check.py prepare-baseline.'
}
$arguments = @($helper, 'check', '--package-directory', $PackageDirectory,
    '--output-directory', $OutputDirectory, '--samples', "$Samples",
    '--target-milliseconds', "$TargetMilliseconds", '--browser-timeout-seconds', "$BrowserTimeoutSeconds",
    '--installer-timeout-seconds', "$InstallerTimeoutSeconds")
if ($BaselineDirectory) { $arguments += @('--baseline-directory', $BaselineDirectory) }
if ($AllowNoBaselineExperiment) { $arguments += '--allow-no-baseline-experiment' }
& $Python @arguments
$status = $LASTEXITCODE
if ($status -ne 0) { exit $status }
