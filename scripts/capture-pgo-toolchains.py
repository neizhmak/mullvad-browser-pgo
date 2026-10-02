#!/usr/bin/env python3
"""Bind build/profile provenance to exact restored compiler archive bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from rbm_network import showconf


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--rust-identity", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--instrumented-package", type=Path)
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    provenance = json.loads(args.provenance.read_text())
    identity = json.loads(args.rust_identity.read_text())
    if identity.get("upstream") != provenance["upstream_lock"]:
        raise SystemExit("Rust/source upstream provenance mismatch")
    if identity["overlay"]["sha256"] != provenance["pgo_overlay_sha256"]:
        raise SystemExit("Rust/source overlay provenance mismatch")
    targets = ["alpha", "mullvadbrowser-windows-x86_64", "pgo-generate"]
    toolchains = {}
    entries = [
        ("clang", "mingw-w64-clang", args.tools / "mingw/mingw-w64-clang/bin/clang"),
        ("rust", "rust", args.tools / "rust/rust/bin/rustc"),
    ]
    for name, project, executable in entries:
        filename = showconf(upstream, project, "filename", targets)
        if not filename or Path(filename).name != filename:
            raise SystemExit("unsafe exact compiler output filename")
        archive = upstream / "out" / project / filename
        if not archive.is_file() or not archive.stat().st_size:
            raise SystemExit(f"missing exact compiler artifact: {filename}")
        executable.resolve(strict=True).relative_to(args.tools.resolve())
        version = subprocess.check_output([str(executable), "--version"], text=True).strip()
        if not version:
            raise SystemExit(f"empty {name} identity")
        toolchains[name] = {"archive_filename": filename, "sha256": sha(archive),
                            "size": archive.stat().st_size, "version": version.splitlines()[0]}
        provenance[name + "_identity"] = version.splitlines()[0]
    selected_mingw = identity["mingw_w64_clang"]
    if len(selected_mingw) != 1 or selected_mingw[0]["sha256"] != toolchains["clang"]["sha256"]:
        raise SystemExit("Rust preflight and Firefox clang archive mismatch")
    if toolchains["rust"]["archive_filename"] != identity["rust"]["output_filename"]:
        raise SystemExit("Firefox did not select the identity-bound profiler Rust artifact")
    provenance.update({"toolchains": toolchains, "pgo_rust_identity": identity,
                       "rust_pgo_identity_sha256": sha(args.rust_identity)})
    if args.instrumented_package:
        if not args.instrumented_package.is_file() or not args.instrumented_package.stat().st_size:
            raise SystemExit("instrumented browser package is missing or empty")
        provenance["instrumented_package_sha256"] = sha(args.instrumented_package)
    temporary = args.provenance.with_suffix(".tmp")
    temporary.write_text(json.dumps(provenance, sort_keys=True, indent=2) + "\n")
    temporary.replace(args.provenance)
    print("Bound exact clang/Rust archive bytes and cross-language PGO identity.")


if __name__ == "__main__":
    main()
