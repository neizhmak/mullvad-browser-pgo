#!/usr/bin/env python3
"""Resolve the immutable identity of the Windows-scoped PGO Rust sysroot."""
import argparse
import hashlib
import json
import pathlib
import subprocess


WINDOWS_TARGET = "x86_64-pc-windows-gnullvm"
TARGETS = ["alpha", "mullvadbrowser-windows-x86_64"]


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def show(upstream, project, key, pgo=True):
    command = [str(upstream / "rbm/rbm"), "showconf", project, key]
    for target in TARGETS + (["pgo-generate"] if pgo else []):
        command += ["--target", target]
    return subprocess.check_output(command, cwd=upstream, text=True).strip()


def selected_mingw(upstream):
    # Bind only the input RBM selects. Unrelated/stale outputs must not alter the
    # identity or silently satisfy a missing compiler dependency.
    filename = show(upstream, "mingw-w64-clang", "filename")
    if not filename or pathlib.Path(filename).name != filename:
        raise SystemExit("invalid pinned mingw-w64-clang filename")
    path = upstream / "out/mingw-w64-clang" / filename
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"missing pinned mingw-w64-clang dependency: {filename}")
    try:
        path.resolve(strict=True).relative_to(upstream)
    except ValueError:
        raise SystemExit("pinned mingw-w64-clang dependency escapes upstream")
    return [{"path": str(path.relative_to(upstream)),
             "sha256": sha(path), "size": path.stat().st_size}]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    root = pathlib.Path(__file__).resolve().parents[1]
    lock = json.loads((root / "upstream.lock.json").read_text())
    normal = show(upstream, "rust", "filename", False)
    pgo = show(upstream, "rust", "filename")
    if normal == pgo or "-profiler" not in pgo:
        raise SystemExit("PGO Rust output identity is not distinct from official Rust")
    if not pgo or pathlib.Path(pgo).name != pgo:
        raise SystemExit("invalid PGO Rust output filename")
    targets = show(upstream, "rust", "var/target").split(",")
    if targets.count(WINDOWS_TARGET) != 1:
        raise SystemExit("missing or ambiguous pinned Windows x86_64 Rust target")
    data = {
        "schema": 1,
        "kind": "firefox-cross-pgo-rust",
        "upstream": lock,
        "rust": {
            "version": show(upstream, "rust", "version"),
            "source_inputs": show(upstream, "rust", "input_files"),
            "rbm_target": ",".join(TARGETS + ["pgo-generate"]),
            "output_filename": pgo,
            "official_output_filename": normal,
            "std_targets": targets,
            # Rust 1.94.1 target.profiler overrides build.profiler. Do not turn
            # on the libc-dependent runtime for the bare wasm target.
            "profiler_targets": [WINDOWS_TARGET],
            "config_sha256": sha(upstream / "projects/rust/config"),
            "build_sha256": sha(upstream / "projects/rust/build"),
        },
        "overlay": {
            "path": "patches/firefox-pgo-generate.patch",
            "sha256": sha(root / "patches/firefox-pgo-generate.patch"),
        },
        "mingw_w64_clang": selected_mingw(upstream),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(data, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
