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


def log_msg(log_file, msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n"
    sys.stderr.write(line)
    sys.stderr.flush()
    if log_file:
        try:
            with open(log_file, "a") as lf:
                lf.write(line)
                lf.flush()
        except OSError:
            pass


def is_process_alive(pid):
    if pid is None or pid <= 1:
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def find_runtime(upstream=None, tools_dir=None, runner_temp=None, log_file=None):
    # 1. Check direct known paths in tools_dir
    if tools_dir and Path(tools_dir).is_dir():
        for subpath in (
            "rust/lib/rustlib/x86_64-pc-windows-gnullvm/lib",
            "rust/rust/lib/rustlib/x86_64-pc-windows-gnullvm/lib",
        ):
            target_dir = Path(tools_dir) / subpath
            if target_dir.is_dir():
                for f in target_dir.glob("libprofiler_builtins-*.rlib"):
                    if f.is_file() and f.stat().st_size > 0:
                        return f

    # 2. Targeted search in tools_dir
    if tools_dir and Path(tools_dir).is_dir():
        for f in Path(tools_dir).glob("**/libprofiler_builtins-*.rlib"):
            if f.is_file() and f.stat().st_size > 0:
                return f

    # 3. Cache directory
    cache_dir = Path("/tmp/.pgo_profiler_runtime")
    if cache_dir.is_dir():
        for f in cache_dir.glob("libprofiler_builtins-*.rlib"):
            if f.is_file() and f.stat().st_size > 0:
                return f

    # 4. Fallback: extract from upstream/out/rust/*.tar.zst
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
                    for f in cache_dir.rglob("libprofiler_builtins-*.rlib"):
                        if f.is_file() and f.stat().st_size > 0:
                            return f
                except Exception as ex:
                    log_msg(log_file, f"Extraction from {archive.name} failed: {ex}")

    return None


def find_clang_version_dirs(upstream):
    dirs = []
    tmp_dir = Path(upstream) / "tmp"
    if not tmp_dir.is_dir():
        return dirs

    # 1. Direct glob for RBM temporary container paths
    for p in tmp_dir.glob("rbm-*/rbm-containers/*/var/tmp/dist/mingw-w64-clang/lib/clang/*"):
        if p.is_dir():
            dirs.append(p)
    # 2. Alternative RBM container structure
    for p in tmp_dir.glob("rbm-containers/*/var/tmp/dist/mingw-w64-clang/lib/clang/*"):
        if p.is_dir():
            dirs.append(p)
    # 3. General fallback under tmp
    if not dirs:
        for p in tmp_dir.glob("**/mingw-w64-clang/lib/clang/*"):
            if p.is_dir():
                dirs.append(p)
    return dirs


def inject_into_containers(upstream, runtime, log_file=None):
    injected = 0
    version_dirs = find_clang_version_dirs(upstream)
    for version_dir in version_dirs:
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
            log_msg(log_file, f"[inject-pgo-profile-runtime] Injected profile runtime into {version_dir}")
    return injected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args()

    upstream = args.upstream.resolve()
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    tools_dir = args.tools.resolve() if args.tools else runner_temp / "pgo-rust-preflight-tools"
    log_file = args.log_file.resolve() if args.log_file else None
    parent_pid = args.parent_pid or os.getppid()

    log_msg(log_file, f"[inject-pgo-profile-runtime] Started watcher for {upstream} (parent PID: {parent_pid})")

    runtime = find_runtime(upstream, tools_dir, runner_temp, log_file)
    if not runtime:
        log_msg(log_file, "[inject-pgo-profile-runtime] WARNING: Initial runtime resolution found no file; will keep retrying.")
    else:
        log_msg(log_file, f"[inject-pgo-profile-runtime] Resolved profiler runtime: {runtime} ({runtime.stat().st_size} bytes)")

    start_time = time.time()
    last_heartbeat = start_time
    max_duration = 280 * 60  # 280 minutes
    injected_total = 0

    while time.time() - start_time < max_duration:
        if not is_process_alive(parent_pid):
            log_msg(log_file, f"[inject-pgo-profile-runtime] Monitored parent PID {parent_pid} has exited. Terminating watcher.")
            break

        if not runtime:
            runtime = find_runtime(upstream, tools_dir, runner_temp, log_file)
            if runtime:
                log_msg(log_file, f"[inject-pgo-profile-runtime] Resolved profiler runtime: {runtime} ({runtime.stat().st_size} bytes)")

        if runtime:
            count = inject_into_containers(upstream, runtime, log_file)
            injected_total += count

        now = time.time()
        if now - last_heartbeat >= 60:
            last_heartbeat = now
            elapsed_min = (now - start_time) / 60
            version_dirs = find_clang_version_dirs(upstream)
            log_msg(log_file, f"[inject-pgo-profile-runtime] Heartbeat: elapsed {elapsed_min:.1f}m, containers seen: {len(version_dirs)}, injected: {injected_total}")

        time.sleep(2)

    log_msg(log_file, f"[inject-pgo-profile-runtime] Finished watcher. Injected total: {injected_total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
