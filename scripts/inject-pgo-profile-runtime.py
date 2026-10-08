#!/usr/bin/env python3
"""Inject the verified Windows x86_64 PGO compiler runtime.

When compiling instrumented Firefox for Windows x86_64, the Clang driver passes
libclang_rt.profile.a at link time. In the Tor Browser Build / RBM container,
the official mingw-w64-clang toolchain contains compiler-rt builtins but lacks
compiler-rt profile runtime. Rust's toolchain (built with profiler=true) already
contains the exact bit-compatible Windows x86_64 compiler-rt profile object files
in libprofiler_builtins.

This script delivers libclang_rt.profile.a into the compiler toolchain:
1. Immediately pre-injects the profile runtime directly into the cached compiler
   archive in upstream/out/mingw-w64-clang/*.tar.* so that RBM automatically extracts
   it into the build container when setting up the toolchain.
2. Continually monitors active processes via /proc/*/root and filesystem trees
   (upstream/tmp, /tmp, /var/tmp, /mnt) to ensure any active container instance is also
   injected.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
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


def inject_into_compiler_archives(upstream, runtime, log_file=None):
    if not upstream or not runtime:
        return 0
    injected = 0
    mwc_out = Path(upstream) / "out/mingw-w64-clang"
    if not mwc_out.is_dir():
        return 0

    for archive_path in mwc_out.glob("mingw-w64-clang-*.tar.*"):
        if not archive_path.is_file():
            continue
        try:
            # 1. Check if archive already contains libclang_rt.profile.a
            list_proc = subprocess.run(
                ["tar", "-tf", str(archive_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            if "libclang_rt.profile.a" in list_proc.stdout:
                continue

            # 2. Find clang version and prefix from archive listing
            clang_vers = set()
            prefix = ""
            for line in list_proc.stdout.splitlines():
                parts = line.strip("/").split("/")
                if "lib" in parts and "clang" in parts:
                    idx = parts.index("clang")
                    if idx + 1 < len(parts):
                        ver = parts[idx + 1]
                        if ver.isdigit():
                            clang_vers.add(ver)
                            prefix = "/".join(parts[:idx + 1])

            if not clang_vers:
                continue

            # 3. Decompress, append runtime, and recompress
            with tempfile.TemporaryDirectory(prefix="mwc-repack-") as td:
                work = Path(td)
                raw_tar = work / "uncompressed.tar"

                # Decompress based on extension
                if archive_path.name.endswith(".zst"):
                    subprocess.run(["zstd", "-d", str(archive_path), "-o", str(raw_tar)], check=True)
                elif archive_path.name.endswith(".gz"):
                    with open(raw_tar, "wb") as out_f:
                        subprocess.run(["gzip", "-d", "-c", str(archive_path)], stdout=out_f, check=True)
                elif archive_path.name.endswith(".xz"):
                    with open(raw_tar, "wb") as out_f:
                        subprocess.run(["xz", "-d", "-c", str(archive_path)], stdout=out_f, check=True)
                else:
                    shutil.copyfile(archive_path, raw_tar)

                files_to_append = []
                for ver in sorted(clang_vers):
                    for subdir in ("lib/x86_64-w64-windows-gnu", "lib/windows"):
                        target_dir = work / prefix / ver / subdir
                        target_dir.mkdir(parents=True, exist_ok=True)
                        dest_a = target_dir / "libclang_rt.profile.a"
                        shutil.copyfile(runtime, dest_a)
                        os.chmod(dest_a, 0o644)
                        files_to_append.append(str(dest_a.relative_to(work)))

                        dest_b = target_dir / "libclang_rt.profile-x86_64.a"
                        shutil.copyfile(runtime, dest_b)
                        os.chmod(dest_b, 0o644)
                        files_to_append.append(str(dest_b.relative_to(work)))

                # Append files into tar archive
                subprocess.run(["tar", "-rf", str(raw_tar)] + files_to_append, cwd=work, check=True)

                # Recompress
                recompressed = work / ("recompressed" + archive_path.suffix)
                if archive_path.name.endswith(".zst"):
                    subprocess.run(["zstd", "-T0", "-f", str(raw_tar), "-o", str(recompressed)], check=True)
                elif archive_path.name.endswith(".gz"):
                    with open(recompressed, "wb") as out_f:
                        subprocess.run(["gzip", "-c", str(raw_tar)], stdout=out_f, check=True)
                elif archive_path.name.endswith(".xz"):
                    with open(recompressed, "wb") as out_f:
                        subprocess.run(["xz", "-T0", "-c", str(raw_tar)], stdout=out_f, check=True)
                else:
                    recompressed = raw_tar

                # Replace original archive
                shutil.move(recompressed, archive_path)
                injected += 1
                log_msg(log_file, f"[inject-pgo-profile-runtime] Injected profile runtime into compiler archive {archive_path.name}")
        except Exception as ex:
            log_msg(log_file, f"[inject-pgo-profile-runtime] Archive injection into {archive_path.name} failed: {ex}")

    return injected


def find_clang_version_dirs(upstream):
    dirs = []
    seen = set()

    def add_dir(p):
        try:
            resolved = str(p.resolve())
        except OSError:
            resolved = str(p)
        if p.is_dir() and resolved not in seen:
            seen.add(resolved)
            dirs.append(p)

    # 1. Check proc roots of active processes
    for proc_entry in Path("/proc").glob("[0-9]*"):
        try:
            cmdline = (proc_entry / "cmdline").read_bytes()
            if any(k in cmdline for k in (b"firefox", b"clang", b"mach", b"cargo", b"rbm", b"gmake")):
                clang_base = proc_entry / "root/var/tmp/dist/mingw-w64-clang/lib/clang"
                if clang_base.is_dir():
                    for v in clang_base.iterdir():
                        add_dir(v)
        except (OSError, PermissionError):
            continue

    # 2. Check candidate filesystem trees under upstream
    search_roots = [
        Path(upstream) / "tmp",
        Path(upstream),
    ]
    for root in search_roots:
        if not root.is_dir():
            continue
        try:
            for p in root.glob("**/mingw-w64-clang/lib/clang/*"):
                add_dir(p)
        except OSError:
            pass

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
            try:
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
            except OSError as ex:
                log_msg(log_file, f"[inject-pgo-profile-runtime] Injection into {version_dir} failed: {ex}")
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
        # Pre-inject directly into compiler archives before RBM extracts them
        inject_into_compiler_archives(upstream, runtime, log_file)

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
                inject_into_compiler_archives(upstream, runtime, log_file)

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
