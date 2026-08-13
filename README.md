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
