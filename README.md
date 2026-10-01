# Mullvad Browser PGO overlay

This is an **unofficial** project and is not affiliated with or endorsed by the
Tor Project or Mullvad. Mullvad Browser and Tor Project names remain the
property of their respective owners.

This repository is intentionally a small overlay. It contains build
orchestration (and, in later stages, PGO-specific patches), while source is
fetched directly from the official Tor Project
[`tor-browser-build`](https://gitlab.torproject.org/tpo/applications/tor-browser-build)
repository. Builds use immutable official Mullvad Browser `mb-*` build tags;
arbitrary upstream `main` revisions are never used as a build base.

The current upstream tag, annotated-tag object ID, and peeled commit ID are in
[`upstream.lock.json`](upstream.lock.json). The lock records Git object IDs for
reproducibility. These SHA-1 object checks detect mismatched or corrupted Git
objects, but they are not signer-authenticity verification: the scripts do not
import a trusted OpenPGP keyring or run `git verify-tag`.

## Upstream utilities

Requirements are Bash, Git, and Python 3.

```sh
# Report the lock and the newest available Alpha tag (does not modify files).
./scripts/resolve-upstream.sh

# Fail when the lock is not the newest Alpha tag.
./scripts/resolve-upstream.sh --check

# Explicitly replace the lock with the newest Alpha tag.
./scripts/resolve-upstream.sh --update-lock

# Create an exact, detached checkout in a temporary directory.
./scripts/fetch-upstream.sh

# Or use/reuse a chosen disposable destination (it is cleaned on each run).
./scripts/fetch-upstream.sh --destination /tmp/tor-browser-build
```

Resolution accepts only tags of the exact form
`mb-MAJOR.MINORaALPHA-buildBUILD`. Every component is converted to an integer
and tags are ordered by `(MAJOR, MINOR, ALPHA, BUILD)`, so `a10` follows `a9`
and `build2` follows `build1`. Suspicious Alpha-like names, duplicate refs,
missing peeled refs, and non-annotated candidate tags cause an error rather
than being guessed at. If the already locked tag name is still upstream but
either of its object IDs changed, resolution treats that as an integrity
anomaly in every mode; even `--update-lock` refuses to overwrite it. Lock
updates are limited to tags that are numerically newer than the locked tag.

## Reusable official RBM dependencies

The manually dispatched **Build official RBM dependencies** workflow persists
the expensive compiler chain for the pinned Mullvad Browser Alpha Windows
x86_64 build. Inspection of RBM's evaluated `input_files` showed these useful
checkpoint boundaries:

1. `clang`, which recursively obtains/builds its container image, CMake,
   Ninja, LLVM source, and the native build tools selected by RBM;
2. `mingw-w64-clang`, which consumes that `clang` output and recursively adds
   the MinGW sources, WASI compiler-rt, CMake, and LLVM source;
3. `rust`, which consumes `mingw-w64-clang` as `var/compiler` for the Windows
   target and recursively obtains/builds CMake, Ninja, the official bootstrap
   Rust, and its other RBM inputs.

Each stage uses the target list which the official release project passes to
the Windows browser dependency chain:

```sh
./rbm/rbm build clang --target alpha --target mullvadbrowser-windows-x86_64
./rbm/rbm build mingw-w64-clang --target alpha --target mullvadbrowser-windows-x86_64
./rbm/rbm build rust --target alpha --target mullvadbrowser-windows-x86_64
```

There is deliberately no repository-owned dependency graph. Before each build,
the workflow also prints RBM's evaluated `input_files`; RBM alone decides what
is missing and recursively builds it. The split follows the two LLVM-scale
compiler builds and Rust so that each completed expensive boundary survives a
later timeout. The workflow stops after Rust and never invokes `firefox`,
`browser`, `release`, or the official `make
mullvadbrowser-alpha-windows-x86_64` browser target.

Every job starts with a clean runner and exact checkout from
`upstream.lock.json`. It downloads each prior release registry, checks the full
locked upstream provenance plus every byte's SHA-256 and size, and copies each
unchanged asset back to its recorded `out/<project>/<filename>` location. A
normal subsequent `rbm build` therefore finds the artifact by its own expected
filename/build ID through its normal `input_files` mechanism. Newly created
files under `out/` are uploaded byte-for-byte, followed by a small stage
registry recording project, original filename/path, digest, size, and upstream
lock. The registry is uploaded last as the stage's commit record. Existing,
verified registries make reruns no-ops; provenance, checksum, or unexpected
identity conflicts fail instead of being overwritten.

## Baseline Windows build

The manually dispatched **Build baseline Mullvad Browser** workflow is the
Stage 3 control build. It fetches the exact locked official tree, initializes
its pinned RBM, and requires the `clang`, `mingw-w64-clang`, and `rust`
registries from the lock-derived dependency Release. Every persisted artifact
is size- and SHA-256-verified before any output is restored to its recorded
upstream `out/` path. A missing, empty, conflicting, or unverifiable required
stage stops the job before the browser build; those heavyweight stages are
never silently rebuilt.

After restoration the workflow invokes the official, unmodified target:

```sh
make mullvadbrowser-alpha-windows-x86_64
```

RBM remains responsible for resolving every other dependency. The workflow
uploads resulting Windows `.exe` and `.mar` packages as private workflow-run
artifacts for inspection, and always uploads available RBM/browser logs. It
does not publish a product Release and applies no Firefox, recipe, or PGO
changes.

## Verified Windows Alpha C++ and Rust PGO

Current scope is **Alpha, Windows x86_64 only**, using the existing
`mb-16.0a9-build1` lock. Stable is not selected. Both C++ and Rust PGO are
mandatory. No Firefox privacy, extension, RLBox, or MAR-verification setting
is weakened. This is still an unofficial build.

The **Stage 4A - Generate verified Windows PGO profile** workflow separates
long work across standard GitHub-hosted runners. Every job is at most six
hours. Run it on the overlay branch you want to test:

```sh
# First validate the durable Rust toolchain checkpoint on native Windows.
gh workflow run pgo-stage4a.yml --ref YOUR_BRANCH -f toolchain_only=true

# Complete instrumented build -> native training -> checked profile ->
# optimized Firefox -> installer + portable ZIP -> native Windows comparison.
gh workflow run pgo-stage4a.yml --ref YOUR_BRANCH
```

The default dispatch completes the pipeline (`finish_pipeline=true`). For a
profile checkpoint only, pass `-f finish_pipeline=false`. The reusable
workflow defaults to profile generation only; a caller must explicitly enable
`finish_pipeline` to build and validate the final packages.

1. **Rust:** target-scoped `profiler=true` only for
   `x86_64-pc-windows-gnullvm`. Stock Linux, bare WASM, and i686 settings stay
   unchanged. Generation and use select the same distinct profiler Rust
   artifact. A real cross-compile/link test and native Windows `.profraw`
   emission must pass before publication.
2. **Generation:** build the exact RBM-selected Firefox output. Require
   configure and actual C++/Rust instrumentation evidence. Select only its
   `browser.tar.*`, never an NSIS or unrelated archive.
3. **Training:** use the exact pinned Firefox `profileserver.py`, its mach
   build virtualenv, and a native Windows runner. Bind raw profiles and jarlog
   to the source, workload, instrumented package, overlay, and compiler bytes.
   Failures retain logs, raw files, and crash evidence.
4. **Merge:** use matching restored LLVM tools. Require positive function,
   block, and execution counts, including at least one positive C++ function
   and one positive Rust function. An empty or single-language profile fails.
5. **Use:** independently recompute source and compiler provenance in each
   final runner before strict profile restoration. Build optimized Firefox
   with cross-language profile use. Hand off its verified output to a separate
   packaging job, which must not recursively rebuild Firefox.
6. **Packages:** produce both the stock installer and a complete standalone
   portable ZIP with `Start Mullvad Browser.cmd`. Portable mode preserves the
   full `Browser/` tree and has no `Browser/system-install` marker.
7. **Validation:** verify hashes before extraction/execution, install to
   disposable paths, check both layouts and common product bytes, and run an
   offline native screenshot/JavaScript workload. Compare interleaved samples
   with the successful same-lock baseline. Reports include raw samples and
   descriptive medians; they do not promise a speedup or invent a performance
   threshold.

Successful final packages are Actions artifacts named
`mullvad-browser-alpha-windows-x86_64-pgo`, with a `packages.json` inventory.
This workflow does **not** publish a browser product Release. Technical Rust
and profile checkpoints are prereleases and never GitHub's latest release.
A workflow file or artifact alone is not evidence that the full pipeline
passed: require successful generation, training, merge, both builds, and the
native Windows report.

For retrying only final use/packaging after a verified profile is published:

```sh
gh workflow run windows-pgo.yml --ref YOUR_BRANCH \
  -f profile_release='pgo-profile-mb-16.0a9-build1-FULL_IDENTITY_SHA256' \
  -f profile_identity='FULL_IDENTITY_SHA256'
```

GitHub may not list a new standalone workflow until it has reached the default
branch. In that case dispatch the already registered `pgo-stage4a.yml` on the
implementation branch. See [the runbook](docs/pgo-runbook.md) for checkpoints,
retries, diagnostics, and known limits.

## Updates and publication limits

Automatic updates keep the **official signed Mullvad Alpha track** intact in
the interim. An official update replaces this unofficial PGO build with the
standard upstream browser. Authenticode signing is separate from signed MAR
verification; omitting Authenticode never permits an unsigned MAR.

A private signed PGO track is preparation only. It still needs user-owned
hosting, protected signing keys, deliberate public-certificate embedding, a
monotonic version policy, and real update tests. Nothing is deployed by the
example configuration. Read [the update design](docs/updates.md) before
changing updater settings. Full public browser publication is deferred.

## Lightweight regression checks

```sh
python3 scripts/run-tests.py
```

This runs every Python test directly, including historical hyphenated names,
plus shell integrity and syntax checks. Install Template Toolkit to execute
native recipe-rendering tests and PowerShell to execute its optional training
wrapper tests. CI provisions these requirements. A separate Windows job tests
native process isolation and parses all PowerShell entry points. Tests use
local fixtures and fake tool commands, not heavy browser builds.
