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
than being guessed at.

This first stage only pins, resolves, validates, and fetches upstream. It does
not compile a toolchain or browser, apply PGO, publish releases, or poll on a
schedule.
