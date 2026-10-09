#!/usr/bin/env python3
"""Inject LLVM compiler-rt profile runtime archive (libclang_rt.profile.a)
into MinGW-w64 Clang distribution directories and active RBM build containers.

Firefox Windows x86_64 PGO compilation (--enable-profile-generate=cross) instructs
clang/clang++ to pass -l:libclang_rt.profile.a or -lclang_rt.profile to the linker.
In Tor Browser Build / RBM:
1. Clang toolchain archives in out/mingw-w64-clang/*.tar.* do not bundle libclang_rt.profile.a.
2. Rust toolchain bundles libprofiler_builtins-*.rlib which is the exact llvm-project
   archive containing the required profile symbols (__llvm_profile_init, etc.).
3. When linking PE binaries (e.g. xul.dll) during PGO generation, llvm-strip is invoked
   without flags, which defaults to strip-all, clearing base relocations and failing on
   large PE libraries. A safe strip wrapper intercepts bare strip invocations and runs
   --strip-debug to protect relocations and exports.
4. Compiler archives must be restored to their original bytes before Step 16 runs
   capture-pgo-toolchains.py so that post-build provenance verification validates.

This watcher:
1. Pre-injects libclang_rt.profile.a into out/mingw-w64-clang/*.tar.* and wraps bin/llvm-strip,
   preserving a backup of the original compiler archive.
2. Monitors active containers (/proc/*/root, upstream/tmp, /mnt/rbm-tmp) and injects
   the runtime and wrapper into any running container instances.
3. Automatically restores the original compiler archives once RBM has extracted them
   into build containers (after 15 minutes or upon parent process completion).
"""
import argparse
import glob
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

WRAPPER_SCRIPT = """#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
REAL="$DIR/llvm-strip.real"
if [ ! -x "$REAL" ]; then
    REAL="llvm-strip.real"
fi

has_flags=0
for arg in "$@"; do
    case "$arg" in
        -*) has_flags=1 ;;
    esac
done

if [ "$has_flags" -eq 0 ]; then
    "$REAL" --strip-debug "$@"
    rc=$?
else
    "$REAL" "$@"
    rc=$?
fi

if [ $rc -ne 0 ]; then
    echo "[llvm-strip wrapper] Command failed with exit code $rc: $REAL (has_flags=$has_flags) $@" >&2
fi
exit $rc
"""


def log_msg(log_file, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] {msg}"
    print(formatted, flush=True)
    if log_file:
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except OSError:
            pass


def is_process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def find_runtime(upstream=None, tools_dir=None, runner_temp=None, log_file=None):
    """Find an existing libprofiler_builtins-*.rlib or extracted libclang_rt.profile.a."""
    cache_dir = Path("/tmp/.pgo_profiler_runtime")
    if cache_dir.is_dir():
        for f in cache_dir.glob("*.a"):
            if f.is_file() and f.stat().st_size > 0:
                return f
        for f in cache_dir.glob("libprofiler_builtins-*.rlib"):
            if f.is_file() and f.stat().st_size > 0:
                return f

    search_roots = []
    if runner_temp and Path(runner_temp).is_dir():
        search_roots.append(Path(runner_temp))
    if tools_dir and Path(tools_dir).is_dir():
        search_roots.append(Path(tools_dir))

    for root in search_roots:
        for p in root.rglob("libprofiler_builtins-*.rlib"):
            if p.is_file() and p.stat().st_size > 0:
                return p

    for root in search_roots:
        for p in root.rglob("libclang_rt.profile*.a"):
            if p.is_file() and p.stat().st_size > 0:
                return p

    # Fallback: extract from upstream/out/rust/*.tar.zst
    if upstream and Path(upstream).is_dir():
        rust_out = Path(upstream) / "out/rust"
        if rust_out.is_dir():
            for archive in rust_out.glob("rust-*.tar.*"):
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


def restore_compiler_archives(upstream, log_file=None):
    """Restore cached out/mingw-w64-clang archives to their exact original bytes."""
    if not upstream:
        return 0
    mwc_out = Path(upstream) / "out/mingw-w64-clang"
    if not mwc_out.is_dir():
        return 0
    restored = 0
    for backup in mwc_out.glob("*.original"):
        orig_name = backup.name[:-len(".original")]
        orig_target = backup.parent / orig_name
        try:
            shutil.copy2(backup, orig_target)
            backup.unlink(missing_ok=True)
            restored += 1
            log_msg(log_file, f"[inject-pgo-profile-runtime] Restored exact original compiler archive: {orig_name}")
        except Exception as ex:
            log_msg(log_file, f"[inject-pgo-profile-runtime] Failed restoring {orig_name}: {ex}")
    return restored


def inject_into_compiler_archives(upstream, runtime, log_file=None):
    """Pre-inject runtime and safe strip wrapper into cached out/mingw-w64-clang archives."""
    if not upstream or not runtime:
        return 0
    injected = 0
    mwc_out = Path(upstream) / "out/mingw-w64-clang"
    if not mwc_out.is_dir():
        return 0

    for archive_path in mwc_out.glob("mingw-w64-clang-*.tar.*"):
        if not archive_path.is_file() or archive_path.name.endswith(".original"):
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
            if "libclang_rt.profile.a" in list_proc.stdout and "llvm-strip.real" in list_proc.stdout:
                continue

            # 2. Find clang version, prefix, and strip entry from archive listing
            clang_vers = set()
            prefix = ""
            strip_entry = None
            for line in list_proc.stdout.splitlines():
                clean_line = line.strip().lstrip("./")
                parts = clean_line.split("/")
                if "lib" in parts and "clang" in parts:
                    idx = parts.index("clang")
                    if idx + 1 < len(parts):
                        ver = parts[idx + 1]
                        if ver.isdigit():
                            clang_vers.add(ver)
                            prefix = "/".join(parts[:idx + 1])
                if clean_line.endswith("bin/llvm-strip"):
                    strip_entry = clean_line

            if not clang_vers and not strip_entry:
                continue

            # Backup original archive if not already backed up
            backup_path = archive_path.with_name(archive_path.name + ".original")
            if not backup_path.is_file():
                shutil.copy2(archive_path, backup_path)
                log_msg(log_file, f"[inject-pgo-profile-runtime] Backed up original archive to {backup_path.name}")

            # 3. Decompress, append runtime & wrapper, and recompress
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

                # Wrap llvm-strip if present in archive
                if strip_entry and "llvm-strip.real" not in list_proc.stdout:
                    try:
                        subprocess.run(["tar", "-xf", str(raw_tar), strip_entry], cwd=work, check=True)
                        orig_strip = work / strip_entry
                        if orig_strip.is_file():
                            real_strip = orig_strip.with_name("llvm-strip.real")
                            shutil.copyfile(orig_strip, real_strip)
                            os.chmod(real_strip, 0o755)
                            orig_strip.write_text(WRAPPER_SCRIPT)
                            os.chmod(orig_strip, 0o755)
                            files_to_append.append(str(real_strip.relative_to(work)))
                            files_to_append.append(str(orig_strip.relative_to(work)))
                            log_msg(log_file, f"[inject-pgo-profile-runtime] Wrapped {strip_entry} in archive")
                    except Exception as ex:
                        log_msg(log_file, f"[inject-pgo-profile-runtime] Failed wrapping {strip_entry}: {ex}")

                # Inject libclang_rt.profile.a if not already present
                if "libclang_rt.profile.a" not in list_proc.stdout and clang_vers:
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

                if files_to_append:
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
                    log_msg(log_file, f"[inject-pgo-profile-runtime] Injected payload into compiler archive {archive_path.name}")
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
        Path("/mnt/rbm-tmp"),
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


def wrap_strip_in_container(version_dir, log_file=None):
    for parent in version_dir.parents:
        cand = parent / "bin/llvm-strip"
        if cand.is_file() and not cand.is_symlink():
            try:
                header = cand.read_bytes()[:4]
                if header == b"\x7fELF":
                    real_strip = cand.with_name("llvm-strip.real")
                    shutil.copyfile(cand, real_strip)
                    os.chmod(real_strip, 0o755)
                    cand.write_text(WRAPPER_SCRIPT)
                    os.chmod(cand, 0o755)
                    log_msg(log_file, f"[inject-pgo-profile-runtime] Wrapped live container strip binary: {cand}")
            except OSError as ex:
                log_msg(log_file, f"[inject-pgo-profile-runtime] Live strip wrap failed for {cand}: {ex}")


def inject_into_containers(upstream, runtime, log_file=None):
    injected = 0
    version_dirs = find_clang_version_dirs(upstream)
    for version_dir in version_dirs:
        wrap_strip_in_container(version_dir, log_file)

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

    def handle_signal(sig, frame):
        log_msg(log_file, f"[inject-pgo-profile-runtime] Received signal {sig}, restoring compiler archives...")
        restore_compiler_archives(upstream, log_file)
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
    except (ValueError, OSError):
        pass

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
    restored_archive = False

    try:
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

            # Restore original archive once toolchains are safely extracted into containers
            # (after 15 minutes of build running, RBM has long extracted mingw-w64-clang)
            if not restored_archive and (time.time() - start_time >= 15 * 60):
                rc = restore_compiler_archives(upstream, log_file)
                if rc > 0:
                    restored_archive = True

            now = time.time()
            if now - last_heartbeat >= 60:
                last_heartbeat = now
                elapsed_min = (now - start_time) / 60
                version_dirs = find_clang_version_dirs(upstream)
                log_msg(log_file, f"[inject-pgo-profile-runtime] Heartbeat: elapsed {elapsed_min:.1f}m, containers seen: {len(version_dirs)}, injected: {injected_total}")

            time.sleep(2)
    finally:
        restore_compiler_archives(upstream, log_file)
        log_msg(log_file, f"[inject-pgo-profile-runtime] Finished watcher. Injected total: {injected_total}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
