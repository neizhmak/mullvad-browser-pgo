#!/usr/bin/env python3
"""Record exact RBM-selected Firefox source without a duplicate full checkout."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def output(*arguments, cwd=None):
    return subprocess.check_output(arguments, cwd=cwd, text=True).strip()


def main():
    root = Path(__file__).resolve().parents[1]
    upstream = Path(os.environ["UPSTREAM"]).resolve()
    temporary = Path(os.environ["RUNNER_TEMP"])
    common = ["--target", "alpha", "--target", "mullvadbrowser-windows-x86_64", "--target", "pgo-generate"]
    def show(key):
        return output(str(upstream / "rbm/rbm"), "showconf", "firefox", key, *common, cwd=upstream)
    repository, ref, revision = show("git_url"), show("git_hash"), show("var/git_commit")
    executable = show("var/exe_name")
    if executable != "mullvadbrowser":
        raise SystemExit("pinned Mullvad target did not select mullvadbrowser.exe")
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise SystemExit("invalid exact Firefox revision")
    clone_root = Path(show("git_clone_dir"))
    if not clone_root.is_absolute():
        clone_root = upstream / clone_root
    checkout = clone_root / "firefox"
    provenance = temporary / "provenance"
    provenance.mkdir(parents=True, exist_ok=True)
    if not checkout.is_dir():
        # A fresh shallow source object fetch is enough to read the workload.
        checkout = temporary / "firefox-provenance-source"
        subprocess.run(["git", "init", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", repository], check=True)
        subprocess.run(["git", "-C", str(checkout), "fetch", "--depth=1", "origin", f"refs/tags/{ref}:refs/tags/{ref}"], check=True)
    if output("git", "-C", str(checkout), "rev-parse", ref + "^{commit}") != revision:
        raise SystemExit("RBM-selected Firefox tag does not match exact source revision")
    if output("git", "-C", str(checkout), "remote", "get-url", "origin") != repository:
        raise SystemExit("Firefox provenance repository does not match RBM source")
    path = "build/pgo/profileserver.py"
    server = subprocess.check_output(["git", "-C", str(checkout), "show", f"{revision}:{path}"])
    if not server:
        raise SystemExit("empty exact profileserver.py")
    (provenance / "profileserver.py").write_bytes(server)
    data = {
        "schema": 2,
        "upstream_lock": json.loads((root / "upstream.lock.json").read_text()),
        "firefox": {"repository": repository, "ref": ref, "revision": revision},
        "browser_executable": executable + ".exe",
        "pgo_overlay_sha256": hashlib.sha256((root / "patches/firefox-pgo-generate.patch").read_bytes()).hexdigest(),
        "profileserver": {"path": path, "revision": revision, "sha256": hashlib.sha256(server).hexdigest()},
        "pgo_languages": ["c++", "rust"],
        "generation_targets": ["alpha", "mullvadbrowser-windows-x86_64", "pgo-generate"],
        "generation_configure_flags": ["--enable-profile-generate=cross"],
    }
    (provenance / "build.json").write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as stream:
            for key, value in [("FIREFOX_REPOSITORY", repository), ("FIREFOX_REF", ref), ("FIREFOX_REVISION", revision)]:
                if "\n" in value or "\r" in value:
                    raise SystemExit("unsafe source identity for environment output")
                stream.write(f"{key}={value}\n")
    print(f"Recorded exact Firefox source {revision}; reused RBM source objects.")


if __name__ == "__main__":
    main()
