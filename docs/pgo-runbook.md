# Windows Alpha PGO runbook

## Scope and completion

Keep `upstream.lock.json` unchanged for the current Windows x86_64 Alpha
validation. Stable is unsupported. Use standard `ubuntu-24.04` and
`windows-2025` GitHub-hosted runners, not paid larger or self-hosted runners.
Both C++ and Rust profile generation/use are required.

The end-to-end entry point is `pgo-stage4a.yml` with `toolchain_only=false`
and `finish_pipeline=true`. A successful build is not sufficient. Completion
requires native training, a checked two-language profile, final Firefox,
installer and portable ZIP, and a successful same-lock Windows runtime report.
Do not mark a PR ready because only fixture tests or the Rust checkpoint pass.

## Durable checkpoints

- Official compiler inputs: `rbm-dependencies-<locked-tag>`, retaining the
  official `clang`, `mingw-w64-clang`, and `rust` identities.
- Profiler Rust: `pgo-toolchains-<locked-tag>-<sha256(identity.json)>`. Identity
  binds the overlay, exact recipes/source inputs, target scope, selected
  MinGW archive bytes, and output filename. Publish only after Linux
  compile/link and native Windows profile emission succeed.
- Trained profile: `pgo-profile-<locked-tag>-<full-profile-identity>`. Schema 2
  binds exact source/workload, compiler bytes/versions, raw profile inventory,
  jarlog, instrumented package, checked counters, and merged payload.
  Retraining can produce a new identity; do not overwrite an existing one.
- Optimized Firefox handoff: Actions artifact `pgo-optimized-firefox`, containing
  `firefox-output.tar` and `firefox-output.json`. Verify every listed member,
  source revision, configure proof, profile identity, and archive digest
  before packaging.

Registries are commit markers, uploaded after verified payloads. Conflicting
or corrupt committed bytes are fatal. `rbm-release-artifacts.py stage-complete`
returns 0 for verified complete, 1 for absent/incomplete, and 2 for integrity
or access/transport failure. Only 1 permits rebuilding. Do not delete a
checkpoint merely to hide a failed integrity check.

## Re-run boundaries

1. Dispatch `pgo-stage4a.yml -f toolchain_only=true` to test Rust alone. The
   full flow restores its immutable verified release rather than rebuilding.
2. Dispatch Stage 4A normally for native training and the complete pipeline.
   Use `finish_pipeline=false` only to stop at the technical profile release.
3. If final compilation/packaging fails after profile publication, dispatch
   `windows-pgo.yml` with its exact `profile_release` and full
   `profile_identity`, or re-run failed jobs in the original run. Standalone
   workflow discovery can require its registration on the default branch;
   the existing Stage 4A entry point supports branch testing.
4. Packaging consumes a verified Firefox handoff and disables the Firefox
   project dependency for `pgo-use`. Never replace it with a bare executable or
   silently compile a different Firefox in the packaging runner.

Actions handoffs expire. If a handoff has expired, repeat the appropriate
build, not its proof alone. Technical release checkpoints remain durable.

## Native runtime and baseline

For an early real-browser check of the measurement harness, dispatch
`gh workflow run tests.yml --ref YOUR_BRANCH -f baseline_smoke=true`.
The optional Windows job authenticates the existing control artifact, silently
installs the stock browser, runs native offline calibration and a measured
PNG/JavaScript smoke, then uninstalls it. Its report explicitly says
`baseline_only=true` and `validated_pipeline=false`. This does not replace the
final PGO installer/portable comparison. Ordinary push/PR checks use fixtures.

The known control is successful baseline run `31777871357`, artifact
`mullvad-browser-alpha-windows-x86_64-baseline`. `prepare-baseline` requests run
metadata, its original Actions archive, and `upstream.lock.json` at that run's
head commit. It verifies the GitHub artifact digest before safe extraction
and requires the exact same lock before recording `baseline.json`.

Run on a disposable 64-bit Windows machine/runner:

```powershell
python scripts/windows-runtime-check.py prepare-baseline --output-directory "$env:RUNNER_TEMP\baseline" --repository $env:GITHUB_REPOSITORY
./scripts/check-windows-packages.ps1
```

Default input/output directories are `RUNNER_TEMP/pgo-packages`, `baseline`,
and `pgo-runtime-check`. Hash-verified installers use silent installation into
disposable paths. The pinned Mullvad target sets `var/exe_name=mullvadbrowser`;
its installed executable is `mullvadbrowser.exe`, not Firefox's default name.
System installation flattens the `Browser/` contents into the install root.
Portable mode retains `Browser/mullvadbrowser.exe`, the launcher, and the full
tree. Source/profile/package provenance binds this exact product basename.
Installed-file inventories are saved before validation and cleanup. Test profiles are isolated; browser privacy settings are unchanged.
The self-contained `file://` workload uses offline headless rendering and
records its result through a PNG pixel grid. Baseline calibration accommodates
privacy-reduced timer precision. Measured launches use identical workloads,
warmup, interleaved ordering, and raw samples. These are descriptive
JavaScript/JSON/DOM throughput results, not startup or whole-browser claims.

The baseline is mandatory for validated final CI. An explicit
`AllowNoBaselineExperiment` can debug smoke tests, but its report must remain
unvalidated. If the control archive expires, re-establish a reviewed successful
same-lock baseline and update the trusted run metadata/contract; do not compare
with a newer stock browser and call it the same control.

The baseline is installed to a disposable path, copied and byte-verified,
then uninstalled before the PGO installer runs. This avoids conflicting
Windows uninstall registry entries. The report labels baseline execution as
an installed-tree copy; it does not pretend both system installers coexist.
The PGO installer tree and standalone ZIP are launched directly.

Native commands have bounded process-tree lifetime. Keep install, browser,
uninstall logs, screenshot payloads, raw samples, and `runtime-report.json`.
A cleanup failure also fails the runtime gate. Do not run installer tests over
an existing user installation.

## Diagnostics and compatibility

- Training: `pgo-training-logs` preserves failed browser output/minidumps and
  raw profiles. A nonzero native command status or crash is never turned into
  a successful manifest.
- Generation/use: inspect the Firefox project log, not only RBM stdout. Require
  actual C++ and Rust compiler instrumentation/profile-use evidence.
- Merge: use restored matching LLVM, not a runner's unrelated `llvm-profdata`.
  LLVM 21 does not support the removed `--summary-only` usage.
- Toolchains: official Linux-host executables were built in the upstream
  container. If Ubuntu cannot load them because of GLIBC/libstdc++/library
  requirements, use the matching verified upstream container; never replace
  compiler bytes or weaken preflight. Record ELF/library evidence first.
- Job limits: preserve separate Rust, instrumented Firefox, training, merge,
  optimized Firefox, package, and Windows validation jobs. Every job remains
  within GitHub's six-hour hosted-runner limit.

Official Firefox/browser packaging re-zips and edits `omni.ja` to retain
upstream ZIP correctness and privacy defaults. That can reduce startup jar
ordering benefits from the trained jarlog. Do not skip those official steps.
Compiler C++ and Rust PGO is distinct from any later measured jar-order
optimization.

## Updates and publication

Keep the official signed Alpha update track for now. This protects update
integrity but replaces PGO with stock binaries on update. The example update
manifest is a non-consumed planning document, not a deployed updater. A
private signed track requires reviewed hosting, both Alpha certificate slots,
version/routing policy, protected signing, rollback/rotation, and positive and
negative update integration tests. See `updates.md`.

The current jobs create Actions installer/portable artifacts and technical
prereleases only. Public browser publication and additional/current-version
platforms remain later work. Never treat unsigned installer bootstrap identity
as permission to bypass MAR signatures.
