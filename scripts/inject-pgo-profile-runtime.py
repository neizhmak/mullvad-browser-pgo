#!/usr/bin/env python3
"""Asynchronously inject the verified Windows x86_64 PGO compiler runtime.

When compiling instrumented Firefox for Windows x86_64, the Clang driver passes
libclang_rt.profile.a at link time. In the Tor Browser Build / RBM container,
the official mingw-w64-clang toolchain contains compiler-rt builtins but lacks
compiler-rt profile runtime. Rust's toolchain (built with profiler=true) already
contains the exact bit-compatible Windows x86_64 compiler-rt profile object files
in libprofiler_builtins.

This watcher monitors the container filesystem under upstream/tmp/ and automatically
installs libclang_rt.profile.a into the unpacked mingw-w64-clang toolchain inside the
container rootfs as soon as it appears.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def find_runtime(upstream=None, tools_dir=None, runner_temp=None):
    candidates = []
    if tools_dir and Path(tools_dir).is_dir():
        candidates.extend(Path(tools_dir).rglob("libprofiler_builtins-*.rlib"))
    if runner_temp and Path(runner_temp).is_dir():
        candidates.extend(Path(runner_temp).rglob("libprofiler_builtins-*.rlib"))
    cache_dir = Path("/tmp/.pgo_profiler_runtime")
    if cache_dir.is_dir():
        candidates.extend(cache_dir.rglob("libprofiler_builtins-*.rlib"))
    for c in candidates:
        if c.is_file() and c.stat().st_size > 0:
            return c
    # Fallback: extract from upstream/out/rust/*.tar.zst
    if upstream and Path(upstream).is_dir():
        rust_out = Path(upstream) / "out/rust"
        if rust_out.is_dir():
            for archive in rust_out.glob("rust-*-profiler-*.tar.*"):
                cache_dir.mkdir(parents=True, exist_ok=True)
                try:
                    subprocess.run(
                        ["tar", "-xaf", str(archive), "--wildcards", "*libprofiler_builtins-*.rlib", "-C", str(cache_dir)],
                        check=True
                    )
                    cached = list(cache_dir.rglob("libprofiler_builtins-*.rlib"))
                    if cached and cached[0].stat().st_size > 0:
                        return cached[0]
                except Exception:
                    pass
    return None


def inject_into_containers(upstream, runtime, log_file=None):
    injected = 0
    tmp_dir = Path(upstream) / "tmp"
    if not tmp_dir.is_dir():
        return injected
    for version_dir in tmp_dir.glob("**/mingw-w64-clang/lib/clang/*"):
        if not version_dir.is_dir():
            continue
        dest1 = version_dir / "lib/x86_64-w64-windows-gnu"
        dest1_file = dest1 / "libclang_rt.profile.a"
        dest2 = version_dir / "lib/windows"
        dest2_file = dest2 / "libclang_rt.profile-x86_64.a"
        dest3_file = dest2 / "libclang_rt.profile.a"
        dest4_file = dest1 / "libclang_rt.profile-x86_64.a"

        need_inject = False
        for f in (dest1_file, dest2_file, dest3_file, dest4_file):
            if not f.exists() or f.stat().st_size != runtime.stat().st_size:
                need_inject = True
                break

        if need_inject:
            dest1.mkdir(parents=True, exist_ok=True)
            dest2.mkdir(parents=True, exist_ok=True)
            for f in (dest1_file, dest2_file, dest3_file, dest4_file):
                shutil.copyfile(runtime, f)
                try:
                    os.chmod(f, 0o644)
                except OSError:
                    pass
            injected += 1
            msg = f"[inject-pgo-profile-runtime] Injected profile runtime into {version_dir}"
            print(msg, file=sys.stderr, flush=True)
            if log_file:
                try:
                    with open(log_file, "a") as lf:
                        lf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
                except OSError:
                    pass
    return injected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args()

    upstream = args.upstream.resolve()
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    tools_dir = args.tools.resolve() if args.tools else runner_temp / "pgo-rust-preflight-tools"
    log_file = args.log_file.resolve() if args.log_file else None

    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a") as lf:
                lf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [inject-pgo-profile-runtime] Started watcher for {upstream}\n")
        except OSError:
            pass

    parent_pid = os.getppid()
    start_time = time.time()
    max_duration = 280 * 60  # 280 minutes

    while time.time() - start_time < max_duration:
        try:
            if os.getppid() != parent_pid:
                break
        except Exception:
            break

        runtime = find_runtime(upstream, tools_dir, runner_temp)
        if runtime:
            inject_into_containers(upstream, runtime, log_file)

        time.sleep(2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
