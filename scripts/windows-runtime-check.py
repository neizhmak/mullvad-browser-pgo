#!/usr/bin/env python3
"""Hash-verified Windows package smoke checks and same-run offline JS comparison.

Only the private test HTML and temporary profiles are written. Product privacy,
security, update and timer preferences are never changed. Performance is a
measurement of these local workloads, not a promise about general browsing.
"""
import argparse
import base64
import configparser
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import stat
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
BASELINE_RUN = 31777871357
BASELINE_ARTIFACT = "mullvad-browser-alpha-windows-x86_64-baseline"
DEFAULT_REPOSITORY = "neizhmak/mullvad-browser-pgo"
SUITE = "mb-offline-js-dom-v1"
CHECKSUMS = {"integer-array": 128329279, "json-roundtrip": 300360, "dom-layout": 167406}
MAX_ZIP_BYTES = 3 * 1024 ** 3


class CheckError(Exception):
    pass


class NativeError(CheckError):
    def __init__(self, message, returncode=1):
        super().__init__(message)
        self.returncode = (128 - returncode if returncode < 0 else returncode) if type(returncode) is int and returncode != 0 else 1


def fail(message):
    raise CheckError(message)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise CheckError("cannot read JSON " + str(path) + ": " + str(error)) from error


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha256(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def is_int(value):
    return type(value) is int


def safe_path(name):
    if not isinstance(name, str) or not name:
        fail("empty artifact path")
    path = PurePosixPath(name)
    if (path.is_absolute() or str(path) != name or "\\" in name or ":" in name or any(c in name for c in '<>"|?*')
            or any(part in (".", "..", "") for part in path.parts)
            or any(ord(c) < 32 for c in name)):
        fail("unsafe artifact path: " + name)
    for part in path.parts:
        if part.endswith((".", " ")) or re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?", part):
            fail("unsafe Windows artifact path: " + name)
    return path


def checked_file(directory, record):
    if not isinstance(record, dict):
        fail("invalid file record")
    name = record.get("filename")
    relative = safe_path(name)
    path = Path(directory).joinpath(*relative.parts)
    for item in [path] + list(path.parents)[:len(relative.parts) - 1]:
        if item.is_symlink():
            fail("symlink in artifact path: " + name)
    if (not is_int(record.get("size")) or record["size"] <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))
            or not path.is_file() or path.stat().st_size != record["size"]
            or sha256(path) != record["sha256"]):
        fail("artifact size or SHA-256 mismatch: " + str(name))
    return path


def zip_inventory(archive):
    infos = archive.infolist()
    if not infos or len(infos) > 50000:
        fail("empty or oversized ZIP inventory")
    seen, entries, total = {}, [], 0
    for info in infos:
        name = info.filename[:-1] if info.is_dir() else info.filename
        relative = safe_path(name)
        key = name.casefold()
        mode = info.external_attr >> 16
        if key in seen or info.flag_bits & 1 or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            fail("duplicate, encrypted or non-regular ZIP entry: " + name)
        seen[key] = info.is_dir()
        total += info.file_size
        if info.file_size < 0 or total > MAX_ZIP_BYTES:
            fail("ZIP exceeds extraction size limit")
        entries.append((info, relative))
    for info, relative in entries:
        for parent in relative.parents:
            if str(parent) != "." and seen.get(str(parent).casefold()) is False:
                fail("ZIP file used as a directory")
    return entries


def safe_extract_zip(path, destination):
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        fail("refusing to extract into a nonempty directory")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive:
        entries = zip_inventory(archive)  # Check every name before writing any member.
        for info, relative in entries:
            target = destination.joinpath(*relative.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as out:
                    shutil.copyfileobj(source, out, length=1024 * 1024)


def locked_version(lock):
    if not isinstance(lock, dict):
        fail("invalid upstream lock")
    match = re.fullmatch(r"mb-([0-9]+\.[0-9]+a[0-9]+)-build[0-9]+", str(lock.get("tag", "")))
    if not match:
        fail("only a locked Mullvad Alpha build is supported")
    return match[1]


def verify_packages(directory, lock):
    directory = Path(directory)
    manifest = read_json(directory / "packages.json")
    version = locked_version(lock)
    if (type(manifest.get("schema")) is not int or manifest["schema"] != 1
            or manifest.get("kind") != "unofficial-mullvad-windows-alpha-pgo"
            or manifest.get("version") != version or manifest.get("channel") != "alpha"
            or manifest.get("platform") != "windows-x86_64" or manifest.get("upstream_lock") != lock
            or manifest.get("public_browser_release") is not False
            or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("profile_identity", "")))):
        fail("final package identity, lock or non-public status mismatch")
    firefox = manifest.get("firefox", {})
    proof = firefox.get("proof", {})
    substs = proof.get("substs", {})
    if (firefox.get("upstream_lock") != lock
            or firefox.get("profile_identity") != manifest["profile_identity"]
            or not substs.get("MOZ_PROFILE_USE") or not substs.get("MOZ_PGO_RUST")
            or substs.get("MOZ_PROFILE_GENERATE")):
        fail("package manifest lacks the matching C++ and Rust profile-use proof")
    layout = manifest.get("portable_layout", {})
    root = layout.get("root")
    if (not isinstance(root, str) or len(safe_path(root).parts) != 1
            or layout.get("launcher") != "Start Mullvad Browser.cmd"
            or layout.get("portable_detection") != "absence of Browser/system-install"
            or layout.get("complete_browser_tree") is not True):
        fail("invalid portable layout declaration")
    records = manifest.get("assets")
    if not isinstance(records, list) or len(records) != 2:
        fail("expected exactly installer and portable assets")
    assets = {}
    expected = {"installer": f"mullvad-browser-windows-x86_64-{version}.exe",
                "portable": f"mullvad-browser-windows-x86_64-portable-{version}.zip"}
    for record in records:
        if not isinstance(record, dict) or record.get("kind") not in expected:
            fail("unexpected final package asset")
        kind = record["kind"]
        if kind in assets or record.get("filename") != expected[kind]:
            fail("duplicate or incorrectly named package asset")
        assets[kind] = checked_file(directory, record)
    with assets["installer"].open("rb") as stream:
        if stream.read(2) != b"MZ":
            fail("installer is not a Windows PE executable")
    return manifest, assets


class WindowsJob:
    """Kill-on-close job contains the native child and every descendant."""
    def __init__(self, process):
        from ctypes import wintypes
        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t),
                        ("active_limit", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class Limits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", IO), ("process_mem", ctypes.c_size_t),
                        ("job_mem", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        limits = Limits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            code = ctypes.get_last_error()
            self.close()
            raise OSError(code, "SetInformationJobObject failed")
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            code = ctypes.get_last_error()
            self.close()
            raise OSError(code, "AssignProcessToJobObject failed")

    def active(self):
        class Accounting(ctypes.Structure):
            _fields_ = [("user", ctypes.c_longlong), ("kernel", ctypes.c_longlong),
                        ("period_user", ctypes.c_longlong), ("period_kernel", ctypes.c_longlong),
                        ("faults", ctypes.c_uint32), ("total", ctypes.c_uint32),
                        ("active", ctypes.c_uint32), ("terminated", ctypes.c_uint32)]
        data = Accounting()
        if not self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(data), ctypes.sizeof(data), None):
            raise OSError(ctypes.get_last_error(), "QueryInformationJobObject failed")
        return data.active

    def terminate(self):
        self.api.TerminateJobObject(self.handle, 124)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


class WindowsProcess:
    """CreateProcessW suspended, assign a job, then resume the primary thread.

    CPython's _winapi wrapper exposes the native handles. Suspension removes the
    child-spawn race that a Popen-then-assign implementation would have.
    """
    def __init__(self, command, cwd, output, diagnostics):
        import _winapi
        import msvcrt
        self.api, self.command, self.returncode = _winapi, command, None
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESTDHANDLES
        with open(os.devnull, "rb") as null:
            startup.hStdInput = msvcrt.get_osfhandle(null.fileno())
            startup.hStdOutput = msvcrt.get_osfhandle(output.fileno())
            startup.hStdError = msvcrt.get_osfhandle(diagnostics.fileno())
            handles = list(set([startup.hStdInput, startup.hStdOutput, startup.hStdError]))
            startup.lpAttributeList = {"handle_list": handles}
            old_flags = [os.get_handle_inheritable(handle) for handle in handles]
            try:
                for handle in handles:
                    os.set_handle_inheritable(handle, True)
                line = command if isinstance(command, str) else subprocess.list2cmdline(command)
                self._handle, self.thread, self.pid, _ = _winapi.CreateProcess(
                    None, line, None, None, True, 0x4 | subprocess.CREATE_NO_WINDOW,
                    None, str(cwd) if cwd else None, startup)
            finally:
                for handle, old in zip(handles, old_flags):
                    os.set_handle_inheritable(handle, old)

    def resume(self):
        from ctypes import wintypes
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.ResumeThread.argtypes = [wintypes.HANDLE]
        api.ResumeThread.restype = wintypes.DWORD
        if api.ResumeThread(self.thread) == 0xffffffff:
            raise OSError(ctypes.get_last_error(), "ResumeThread failed")
        self.api.CloseHandle(self.thread)
        self.thread = None

    def wait(self, timeout=None):
        milliseconds = self.api.INFINITE if timeout is None else max(0, int(timeout * 1000))
        result = self.api.WaitForSingleObject(self._handle, milliseconds)
        if result == self.api.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.command, timeout)
        if result != self.api.WAIT_OBJECT_0:
            raise OSError("native process wait failed")
        self.returncode = self.api.GetExitCodeProcess(self._handle)
        return self.returncode

    def poll(self):
        try:
            return self.wait(timeout=0)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        self.api.TerminateProcess(self._handle, 124)

    def close(self):
        if self.thread is not None:
            self.api.CloseHandle(self.thread)
        self.api.CloseHandle(self._handle)


def run_native(command, log, timeout, *, cwd=None, stdout_file=None):
    """Bound the full native process tree and retain logs/status even on failure."""
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        fail("native timeout must be positive")
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"command": command, "timeout_seconds": timeout, "timed_out": False}
    started = time.monotonic()
    process, job = None, None
    status, error = 1, None
    with log.open("wb") as diagnostics:
        output = Path(stdout_file).open("wb") if stdout_file else diagnostics
        try:
            if os.name == "nt":
                process = WindowsProcess(command, cwd, output, diagnostics)
                job = WindowsJob(process)
                process.resume()
            else:
                process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=output,
                                           stderr=diagnostics, start_new_session=True)
            metadata["pid"] = process.pid
            try:
                status = process.wait(timeout=timeout)
                if job and status == 0:
                    # NSIS uninstallers may hand work to a second native process.
                    while job.active():
                        remaining = timeout - (time.monotonic() - started)
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command, timeout)
                        threading.Event().wait(min(0.05, remaining))
            except subprocess.TimeoutExpired:
                metadata["timed_out"] = True
                status = 124
                error = "native process tree exceeded timeout"
        except OSError as native_error:
            error = "native process failed to start or isolate: " + str(native_error)
            status = 1
        finally:
            if process:
                if job:
                    job.terminate()
                    job.close()
                elif os.name != "nt":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif process.poll() is None:
                    # Job assignment failed before the suspended child could spawn.
                    process.kill()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if isinstance(process, WindowsProcess):
                    process.close()
            if stdout_file:
                output.close()
    metadata.update(returncode=status, elapsed_seconds=time.monotonic() - started)
    if error:
        metadata["error"] = error
    write_json(log.with_suffix(log.suffix + ".json"), metadata)
    if status != 0:
        raise NativeError((error or "native command exited " + str(status)) + "; see " + str(log), status)
    return metadata


def validate_baseline_origin(run, artifact, source, lock, repository):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        fail("invalid baseline repository")
    if (not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] != BASELINE_RUN
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("repository", {}).get("full_name") != repository
            or not re.fullmatch(r"[0-9a-f]{40}", str(run.get("head_sha", "")))):
        fail("baseline must come from the known successful run")
    if isinstance(artifact, dict) and "artifacts" in artifact:
        candidates = [item for item in artifact["artifacts"] if item.get("name") == BASELINE_ARTIFACT]
        if len(candidates) != 1:
            fail("expected one known baseline artifact")
        artifact = candidates[0]
    if (not isinstance(artifact, dict) or artifact.get("name") != BASELINE_ARTIFACT
            or type(artifact.get("id")) is not int or artifact["id"] <= 0
            or artifact.get("expired") is not False
            or artifact.get("workflow_run", {}).get("id") != BASELINE_RUN
            or artifact.get("workflow_run", {}).get("head_sha") != run["head_sha"]
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(artifact.get("digest", "")))
            or artifact.get("archive_download_url") != f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact['id']}/zip"):
        fail("baseline artifact run, name or digest mismatch")
    head = run["head_sha"]
    if (not isinstance(source, dict) or source.get("path") != "upstream.lock.json" or source.get("type") != "file"
            or source.get("encoding") != "base64"
            or source.get("html_url") != f"https://github.com/{repository}/blob/{head}/upstream.lock.json"
            or source.get("download_url") != f"https://raw.githubusercontent.com/{repository}/{head}/upstream.lock.json"):
        fail("baseline source lock is not tied to the run commit")
    try:
        raw = base64.b64decode("".join(source["content"].split()), validate=True)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        parsed = json.loads(raw)
    except (KeyError, ValueError, TypeError) as error:
        raise CheckError("invalid committed baseline lock") from error
    if source.get("sha") != blob or source.get("size") != len(raw) or parsed != lock:
        fail("baseline source lock differs from current locked build")
    return artifact


def prepare_baseline(args):
    destination = args.output_directory.resolve()
    if destination.exists() and any(destination.iterdir()):
        fail("refusing a stale baseline directory")
    destination.mkdir(parents=True, exist_ok=True)
    lock = read_json(args.upstream_lock)
    version = locked_version(lock)
    repository = args.repository
    inputs = [args.artifact_archive, args.run_metadata, args.artifact_metadata, args.source_lock]
    if any(inputs) and not all(inputs):
        fail("offline baseline inputs must include archive, run metadata, artifact metadata and committed lock response")
    if all(inputs):
        run, artifacts, source = [read_json(path) for path in inputs[1:]]
    else:
        endpoint = f"repos/{repository}"
        run_path, artifact_path, source_path = [destination / name for name in ("run.json", "artifact.json", "source-lock.json")]
        run_native(["gh", "api", endpoint + f"/actions/runs/{BASELINE_RUN}"], destination / "fetch-run.log", args.timeout_seconds, stdout_file=run_path)
        run = read_json(run_path)
        if not re.fullmatch(r"[0-9a-f]{40}", str(run.get("head_sha", ""))):
            fail("invalid baseline run commit")
        run_native(["gh", "api", endpoint + f"/actions/runs/{BASELINE_RUN}/artifacts"], destination / "fetch-artifact.log", args.timeout_seconds, stdout_file=artifact_path)
        artifacts = read_json(artifact_path)
        run_native(["gh", "api", endpoint + "/contents/upstream.lock.json?ref=" + run["head_sha"]], destination / "fetch-lock.log", args.timeout_seconds, stdout_file=source_path)
        source = read_json(source_path)
    artifact = validate_baseline_origin(run, artifacts, source, lock, repository)
    archive = destination / "artifact.zip"
    if all(inputs):
        shutil.copyfile(args.artifact_archive, archive)
    else:
        run_native(["gh", "api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"], destination / "download-artifact.log", args.timeout_seconds, stdout_file=archive)
    expected_digest = artifact["digest"].split(":", 1)[1]
    if archive.is_symlink() or sha256(archive) != expected_digest:
        fail("downloaded Actions archive SHA-256 differs from GitHub digest; not extracting")
    extracted = destination / "packages"
    safe_extract_zip(archive, extracted)
    filename = f"mullvad-browser-windows-x86_64-{version}.exe"
    installers = [path for path in extracted.rglob(filename) if path.is_file() and not path.is_symlink()]
    if len(installers) != 1:
        fail("expected one same-version baseline installer")
    installer = installers[0]
    with installer.open("rb") as stream:
        if stream.read(2) != b"MZ":
            fail("baseline installer is not a Windows PE executable")
    manifest = {"schema": 1, "kind": "same-lock-windows-alpha-baseline", "repository": repository,
                "run_id": BASELINE_RUN, "head_sha": run["head_sha"], "artifact_id": artifact["id"],
                "artifact_name": BASELINE_ARTIFACT, "artifact_digest": artifact["digest"], "upstream_lock": lock,
                "installer": {"filename": installer.relative_to(destination).as_posix(), "size": installer.stat().st_size, "sha256": sha256(installer)}}
    write_json(destination / "run.json", run)
    write_json(destination / "artifact.json", artifact)
    write_json(destination / "source-lock.json", source)
    write_json(destination / "baseline.json", manifest)
    print("Prepared digest-verified, same-lock baseline from run " + str(BASELINE_RUN))
    return manifest


def verify_baseline(directory, lock):
    directory = Path(directory)
    manifest = read_json(directory / "baseline.json")
    artifact = validate_baseline_origin(read_json(directory / "run.json"), read_json(directory / "artifact.json"),
                                       read_json(directory / "source-lock.json"), lock, manifest.get("repository", ""))
    if (type(manifest.get("schema")) is not int or manifest["schema"] != 1
            or manifest.get("kind") != "same-lock-windows-alpha-baseline" or manifest.get("run_id") != BASELINE_RUN
            or manifest.get("head_sha") != artifact["workflow_run"]["head_sha"]
            or manifest.get("artifact_id") != artifact["id"] or manifest.get("artifact_name") != BASELINE_ARTIFACT
            or manifest.get("artifact_digest") != artifact["digest"] or manifest.get("upstream_lock") != lock):
        fail("baseline manifest origin mismatch")
    archive = directory / "artifact.zip"
    if archive.is_symlink() or not archive.is_file() or sha256(archive) != artifact["digest"].split(":", 1)[1]:
        fail("baseline archive SHA-256 mismatch")
    installer = checked_file(directory, manifest["installer"])
    relative = installer.relative_to(directory).as_posix()
    if not relative.startswith("packages/") or installer.name != f"mullvad-browser-windows-x86_64-{locked_version(lock)}.exe":
        fail("baseline installer filename mismatch")
    # Bind extracted bytes to the authenticated ZIP, not a self-written inventory.
    member = relative[len("packages/"):]
    with zipfile.ZipFile(archive) as data:
        inventory = zip_inventory(data)
        matches = [info for info, path in inventory if str(path) == member and not info.is_dir()]
        if len(matches) != 1:
            fail("baseline installer missing from authenticated archive")
        value = hashlib.sha256()
        with data.open(matches[0]) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
        if value.hexdigest() != manifest["installer"]["sha256"]:
            fail("baseline installer differs from authenticated archive")
    return manifest, installer


def png_pixels(path):
    """Decode native Firefox 8-bit RGB/RGBA screenshots with PNG filter checks."""
    raw = Path(path).read_bytes()
    if len(raw) > 32 * 1024 * 1024 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        fail("missing or invalid native PNG screenshot")
    offset, header, chunks, ended = 8, None, [], False
    while offset < len(raw):
        if offset + 12 > len(raw):
            fail("truncated PNG")
        size = struct.unpack_from(">I", raw, offset)[0]
        kind = raw[offset + 4:offset + 8]
        data = raw[offset + 8:offset + 8 + size]
        if offset + size + 12 > len(raw) or zlib.crc32(kind + data) & 0xffffffff != struct.unpack_from(">I", raw, offset + 8 + size)[0]:
            fail("PNG chunk checksum mismatch")
        offset += size + 12
        if kind == b"IHDR":
            if header is not None or len(data) != 13:
                fail("invalid PNG header")
            header = struct.unpack(">IIBBBBB", data)
        elif kind == b"IDAT":
            chunks.append(data)
        elif kind == b"IEND":
            ended = True
            break
    if not ended or header is None:
        fail("incomplete PNG screenshot")
    width, height, depth, color, compression, filtering, interlace = header
    if (not 520 <= width <= 4096 or not 600 <= height <= 4096 or depth != 8 or color not in (2, 6)
            or compression or filtering or interlace):
        fail("unsupported screenshot size or PNG format")
    channels = 3 if color == 2 else 4
    stride = width * channels
    expected_size = (stride + 1) * height
    decoder = zlib.decompressobj()
    decoded = decoder.decompress(b"".join(chunks), expected_size + 1)
    if len(decoded) != expected_size or not decoder.eof or decoder.unused_data:
        fail("invalid PNG pixel stream")
    rows, previous = [], bytearray(stride)
    def paeth(a, b, c):
        p = a + b - c
        da, db, dc = abs(p - a), abs(p - b), abs(p - c)
        return a if da <= db and da <= dc else b if db <= dc else c
    # The report is at most 2048 bytes and ends above row 540. Decode only
    # those rows; still validate the complete compressed stream and its size.
    for y in range(min(height, 540)):
        start = y * (stride + 1)
        mode = decoded[start]
        row = bytearray(decoded[start + 1:start + 1 + stride])
        if mode > 4:
            fail("invalid PNG row filter")
        if mode:
            for x in range(stride):
                left = row[x - channels] if x >= channels else 0
                above = previous[x]
                corner = previous[x - channels] if x >= channels else 0
                delta = left if mode == 1 else above if mode == 2 else (left + above) // 2 if mode == 3 else paeth(left, above, corner)
                row[x] = (row[x] + delta) & 255
        rows.append(row)
        previous = row
    return width, height, channels, rows


def screenshot_report(path, nonce):
    width, height, channels, rows = png_pixels(path)
    def read_byte(index):
        value = 0
        for bit in range(8):
            position = index * 8 + bit
            x, y = 8 + (position % 128) * 4 + 2, 8 + (position // 128) * 4 + 2
            if x >= width or y >= height:
                fail("screenshot report outside viewport")
            color = rows[y][x * channels:x * channels + channels]
            if channels == 4 and color[3] != 255:
                fail("transparent screenshot report pixel")
            if max(color[:3]) < 32:
                value |= 1 << bit
            elif min(color[:3]) <= 223:
                fail("screenshot report is not a solid black/white rendering")
        return value
    header = bytes(read_byte(i) for i in range(14))
    if header[:6] != b"MBPGO1":
        fail("screenshot does not contain the offline JS report")
    length, expected_hash = struct.unpack("<II", header[6:])
    if length <= 0 or length > 2048:
        fail("invalid screenshot report length")
    data = bytes(read_byte(i + 14) for i in range(length))
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    if value != expected_hash:
        fail("screenshot report checksum mismatch")
    try:
        report = json.loads(data)
    except ValueError as error:
        raise CheckError("invalid screenshot report JSON") from error
    if (type(report.get("schema")) is not int or report["schema"] != 1 or report.get("suite") != SUITE or report.get("nonce") != nonce
            or report.get("error")):
        fail("offline JavaScript smoke failed: " + str(report.get("error", "report identity mismatch")))
    report["screenshot"] = {"filename": Path(path).name, "sha256": sha256(path), "width": width, "height": height}
    return report


def validate_workloads(report, iterations=None):
    workloads = report.get("workloads", {})
    if set(workloads) != set(CHECKSUMS):
        fail("missing local JS workload result")
    for name, expected_checksum in CHECKSUMS.items():
        item = workloads[name]
        n, elapsed = item.get("iterations"), item.get("elapsed_ms")
        if (not is_int(n) or not 1 <= n <= 65536 or type(elapsed) not in (int, float)
                or not math.isfinite(elapsed) or elapsed <= 0 or item.get("unit_checksum") != expected_checksum
                or item.get("digest") != (expected_checksum * (n * (n + 1) // 2)) & 0xffffffff):
            fail("offline JS correctness or timing failure: " + name)
        if iterations and n != iterations[name]:
            fail("benchmark iteration counts differ between browsers")
    return {name: item["iterations"] for name, item in workloads.items()}


def browser_command(binary, profile, screenshot, page):
    return [str(binary), "--headless", "--offline", "--no-remote", "--new-instance", "--wait-for-browser",
            "--profile", str(profile), "--window-size", "1280,960", "--screenshot", str(screenshot), page.as_uri()]


def run_browser(binary, directory, label, timeout, *, iterations=None, target_ms=1200):
    directory = Path(directory) / label
    directory.mkdir(parents=True, exist_ok=False)
    profile, page, screenshot = directory / "profile", directory / "workload.html", directory / "screenshot.png"
    profile.mkdir()
    nonce = secrets.token_hex(16)
    config = {"nonce": nonce, "mode": "measure" if iterations else "calibrate", "target_ms": target_ms,
              "iterations": iterations or {}}
    template = (ROOT / "scripts/benchmark-page.html").read_text(encoding="utf-8")
    if template.count("__RUNTIME_CONFIG__") != 1:
        fail("invalid offline workload template")
    page.write_text(template.replace("__RUNTIME_CONFIG__", json.dumps(config, sort_keys=True)), encoding="utf-8")
    try:
        metadata = run_native(browser_command(binary, profile, screenshot, page), directory / "browser.log", timeout, cwd=binary.parent)
        if not screenshot.is_file():
            fail("browser exited without producing the native offline screenshot: " + label)
        result = screenshot_report(screenshot, nonce)
        if result.get("mode") != config["mode"]:
            fail("offline JS measurement mode mismatch")
        validate_workloads(result, iterations)
        if not iterations and any(item["elapsed_ms"] < target_ms for item in result["workloads"].values()):
            fail("offline timer calibration did not meet its target")
        result["native_process"] = metadata
        write_json(directory / "result.json", result)
        return result
    finally:
        # Keep crash diagnostics even on failure, but never upload the private
        # profile, cache or prefs. No existing user profile is read or modified.
        for source in profile.rglob("*"):
            if source.is_file() and source.suffix in (".dmp", ".extra") and source.stat().st_size <= 128 * 1024 * 1024:
                target = directory / "crash-diagnostics" / source.relative_to(profile)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        shutil.rmtree(profile)


def verify_browser_tree(directory, version, *, portable):
    directory = Path(directory)
    required = ["firefox.exe", "xul.dll", "omni.ja", "browser/omni.ja", "application.ini", "updater.exe", "postupdate.exe",
                "distribution/extensions/uBlock0@raymondhill.net.xpi",
                "distribution/extensions/{73a6fe31-595d-460b-a920-fcc0f8843232}.xpi",
                "distribution/extensions/{d19a89b9-76c1-4a61-bcd4-49e8de916403}.xpi", "version.json", "update-settings.ini"]
    for name in required:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            fail("incomplete native browser tree: " + name)
    for name in ("firefox.exe", "xul.dll", "updater.exe", "postupdate.exe"):
        with (directory / name).open("rb") as stream:
            if stream.read(2) != b"MZ":
                fail("browser tree contains a non-PE binary: " + name)
    marker = directory / "system-install"
    if marker.exists() == portable:
        fail("native package system-install marker does not match its mode")
    config = configparser.ConfigParser(interpolation=None)
    config.read(directory / "application.ini", encoding="utf-8-sig")
    if not config.get("App", "Version", fallback="") or not config.get("App", "Name", fallback=""):
        fail("installed browser application identity is missing")
    product = read_json(directory / "version.json")
    if (product.get("version") != version or product.get("channel") != "alpha"
            or product.get("architecture") != "windows-x86_64"):
        fail("installed browser locked Alpha version or architecture mismatch")
    settings = configparser.ConfigParser(interpolation=None)
    settings.read(directory / "update-settings.ini", encoding="utf-8-sig")
    update_url = config.get("AppUpdate", "URL", fallback="")
    mar_channel = settings.get("Settings", "ACCEPTED_MAR_CHANNEL_IDS", fallback="")
    if (update_url != "https://cdn.mullvad.net/browser/update_responses/update_1/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL"
            or mar_channel != "mullvadbrowser-mullvad-alpha"):
        fail("native package changed the official signed Mullvad Alpha update route")
    return {"version": version, "gecko_version": config.get("App", "Version"),
            "application_name": config.get("App", "Name"), "build_id": config.get("App", "BuildID", fallback=""),
            "system_install": not portable, "update_config": {"url": update_url, "accepted_mar_channel": mar_channel,
            "evidence_scope": "unchanged configuration only; no live MAR update or signature acceptance test"}}


def installer_command(installer, destination):
    # NSIS requires /D last and without surrounding quotes, even with spaces.
    # Popen uses the raw command line on Windows; the paths are our own temp paths.
    if os.name == "nt":
        return subprocess.list2cmdline([str(installer), "/S"]) + " /D=" + str(destination)
    return [str(installer), "/S", "/D=" + str(destination)]


def reject_existing_install():
    import winreg
    key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\MullvadBrowserAlpha"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | view):
                    fail("refusing to overwrite a pre-existing Mullvad Alpha system installation")
            except FileNotFoundError:
                pass


def performance_summary(samples, baseline_present):
    summary = {"suite": SUITE, "scope": "offline JavaScript/JSON/DOM throughput; excludes installer and browser startup time",
               "samples_per_variant": {name: len(values) for name, values in samples.items()}, "workloads": {},
               "threshold": None, "claim": "descriptive same-run measurements only; no speedup guarantee or pass/fail performance threshold",
               "timer_precision_note": "privacy timer preferences unchanged; raw elapsed times can be quantized; baseline-calibrated counts are identical across variants"}
    for workload in CHECKSUMS:
        variants = {}
        for name, values in samples.items():
            raw = [item["workloads"][workload] for item in values]
            normalized = [item["elapsed_ms"] / item["iterations"] for item in raw]
            variants[name] = {"raw_samples": raw, "milliseconds_per_iteration": normalized,
                              "median_ms_per_iteration": statistics.median(normalized)}
        if baseline_present:
            baseline_median = variants["baseline"]["median_ms_per_iteration"]
            for name in ("installer", "portable"):
                median = variants[name]["median_ms_per_iteration"]
                variants[name]["baseline_over_variant_ratio"] = baseline_median / median
                variants[name]["time_change_percent_vs_baseline"] = 100 * (median / baseline_median - 1)
        summary["workloads"][workload] = variants
    return summary


def require_windows():
    import platform
    if os.name != "nt" or struct.calcsize("P") != 8 or platform.machine().lower() not in ("amd64", "x86_64"):
        fail("native package checks require 64-bit Windows Python on a Windows x86_64 runner")


def run_checks(args):
    output = args.output_directory.resolve()
    if output.exists() and any(output.iterdir()):
        fail("refusing a stale runtime output directory")
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": 1, "status": "failed", "validated_pipeline": False, "public_browser_release": False,
              "baseline_required": not args.allow_no_baseline_experiment, "offline": True,
              "network_scope": "Firefox --offline and file-only CSP-denied workload; not an OS-wide egress sandbox",
              "default_preferences_modified": False, "samples": {}, "cleanup": []}
    work = None
    installed = []
    error = None
    try:
        require_windows()
        if not args.baseline_directory and not args.allow_no_baseline_experiment:
            fail("same-lock native baseline is required; use explicit --allow-no-baseline-experiment only for incomplete experiments")
        lock = read_json(args.upstream_lock)
        manifest, assets = verify_packages(args.package_directory, lock)
        baseline, baseline_installer = verify_baseline(args.baseline_directory, lock) if args.baseline_directory else (None, None)
        report.update(upstream_lock=lock, profile_identity=manifest["profile_identity"], package_assets=manifest["assets"], baseline=baseline,
                      benchmark_template_sha256=sha256(ROOT / "scripts/benchmark-page.html"))
        import platform
        report["runner"] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                            "python": platform.python_version(), "github_run_id": os.environ.get("GITHUB_RUN_ID"),
                            "github_sha": os.environ.get("GITHUB_SHA")}
        if baseline:
            report["baseline_installer_sha256"] = baseline["installer"]["sha256"]
        reject_existing_install()
        work = Path(tempfile.mkdtemp(prefix="mbpgo-runtime-"))
        # Stage immutable copies and recheck their manifest hashes before native execution or extraction.
        staged = work / "assets"
        staged.mkdir()
        for item in manifest["assets"]:
            shutil.copyfile(assets[item["kind"]], staged / item["filename"])
            assets[item["kind"]] = checked_file(staged, item)
        if baseline:
            shutil.copyfile(baseline_installer, staged / "baseline.exe")
            baseline_record = dict(baseline["installer"], filename="baseline.exe")
            baseline_installer = checked_file(staged, baseline_record)
        portable = work / "portable"
        with zipfile.ZipFile(assets["portable"]) as archive:
            entries = zip_inventory(archive)
            prefix = manifest["portable_layout"]["root"] + "/"
            for info, path in entries:
                name = str(path)
                if name != prefix[:-1] and not name.startswith(prefix):
                    fail("portable ZIP contains an unexpected package root")
                if name.casefold() == (prefix + "Browser/system-install").casefold():
                    fail("portable ZIP contains a system-install marker")
        safe_extract_zip(assets["portable"], portable)
        portable_root = portable / manifest["portable_layout"]["root"]
        launcher = portable_root / "Start Mullvad Browser.cmd"
        if not launcher.is_file() or b'"%~dp0Browser\\firefox.exe" %*' not in launcher.read_bytes():
            fail("portable launcher does not point at its own browser")
        browsers = {"portable": portable_root / "Browser/firefox.exe"}
        report["packages"] = {"portable": verify_browser_tree(browsers["portable"].parent, manifest["version"], portable=True)}
        if baseline:
            destination = work / "baseline-install"
            destination.mkdir()
            installed.append(("baseline", destination))
            run_native(installer_command(baseline_installer, destination), output / "baseline-install.log", args.installer_timeout_seconds)
            report["packages"]["baseline"] = verify_browser_tree(destination, manifest["version"], portable=False)
            # Two stock installers share an uninstall key and shortcut names.
            # Copy the verified baseline tree and uninstall it before installing
            # PGO. Never overwrite another system installation's registration.
            baseline_runtime = work / "baseline"
            shutil.copytree(destination, baseline_runtime)
            for source in destination.rglob("*"):
                if source.is_file() and sha256(source) != sha256(baseline_runtime / source.relative_to(destination)):
                    fail("baseline installed-copy checksum mismatch")
            browsers["baseline"] = baseline_runtime / "firefox.exe"
            verify_browser_tree(baseline_runtime, manifest["version"], portable=False)
            run_native([str(destination / "uninstall.exe"), "/S"], output / "baseline-uninstall.log", args.installer_timeout_seconds)
            report["cleanup"].append({"variant": "baseline", "uninstalled": True})
            installed.remove(("baseline", destination))
            reject_existing_install()
            report["baseline_execution"] = "byte-verified copy of a silent-installed baseline; stock installation removed before PGO install to avoid registry conflict"
        destination = work / "installer"
        destination.mkdir()
        installed.append(("installer", destination))  # Clean partially completed installers too.
        run_native(installer_command(assets["installer"], destination), output / "installer-install.log", args.installer_timeout_seconds)
        browsers["installer"] = destination / "firefox.exe"
        report["packages"]["installer"] = verify_browser_tree(destination, manifest["version"], portable=False)
        report["installed_portable_same_binaries"] = {}
        for name in ("firefox.exe", "xul.dll", "application.ini"):
            installed_hash = sha256(browsers["installer"].parent / name)
            if installed_hash != sha256(browsers["portable"].parent / name):
                fail("installer and portable contain different product bytes: " + name)
            report["installed_portable_same_binaries"][name] = installed_hash
        calibration_variant = "baseline" if baseline else "installer"
        calibration = run_browser(browsers[calibration_variant], output, "calibration-" + calibration_variant,
                                  args.browser_timeout_seconds, target_ms=args.target_milliseconds)
        iterations = validate_workloads(calibration)
        report["calibration"] = calibration
        report["iterations"] = iterations
        order = ["baseline", "installer", "portable"] if baseline else ["installer", "portable"]
        report["samples"] = {name: [] for name in order}
        report["sample_order"] = []
        # Every measured launch has an empty private profile and the same within-page warmup.
        # One complete interleaved round is discarded to reduce first-launch cache bias.
        for round_number in range(args.samples + 1):
            current_order = order if round_number % 2 == 0 else list(reversed(order))
            report["sample_order"].append({"round": round_number, "warmup": round_number == 0, "variants": current_order})
            for name in current_order:
                result = run_browser(browsers[name], output, f"round-{round_number:02d}-{name}", args.browser_timeout_seconds,
                                     iterations=iterations, target_ms=args.target_milliseconds)
                if round_number:
                    report["samples"][name].append(result)
                else:
                    report.setdefault("warmups", {})[name] = result
                write_json(output / "runtime-report.json", report)
        report["performance"] = performance_summary(report["samples"], baseline is not None)
        report["status"] = "passed" if baseline else "experiment-without-baseline"
        report["validated_pipeline"] = baseline is not None
    except Exception as exception:
        error = exception
        report["error"] = str(exception)
    finally:
        for name, destination in reversed(installed):
            uninstaller = destination / "uninstall.exe"
            try:
                if not uninstaller.is_file():
                    fail("installed tree has no uninstaller (partial install may need runner disposal)")
                run_native([str(uninstaller), "/S"], output / (name + "-uninstall.log"), args.installer_timeout_seconds)
                report["cleanup"].append({"variant": name, "uninstalled": True})
            except Exception as cleanup_error:
                report["cleanup"].append({"variant": name, "uninstalled": False, "error": str(cleanup_error)})
                report["status"], report["validated_pipeline"] = "failed", False
                if error is None:
                    error = cleanup_error
                    report["error"] = str(cleanup_error)
        if installed:
            try:
                reject_existing_install()
                report["registry_cleanup_verified"] = True
            except Exception as cleanup_error:
                report["registry_cleanup_verified"] = False
                report["status"], report["validated_pipeline"] = "failed", False
                if error is None:
                    error = cleanup_error
                    report["error"] = "uninstall registration remains after cleanup: " + str(cleanup_error)
        if work:
            try:
                shutil.rmtree(work)
            except OSError as cleanup_error:
                report["temporary_cleanup_error"] = str(cleanup_error)
                report["status"], report["validated_pipeline"] = "failed", False
                if error is None:
                    error = cleanup_error
        # A failed launch may leave a profile; do not include it in diagnostic uploads.
        for profile in output.glob("*/profile"):
            shutil.rmtree(profile, ignore_errors=True)
        write_json(output / "runtime-report.json", report)
    if error:
        raise error
    print("Offline native installer and portable checks: " + report["status"])
    print("Raw samples and descriptive medians: " + str(output / "runtime-report.json"))
    return report


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-baseline", help="download the known same-lock Actions artifact and verify digest before extraction")
    prepare.add_argument("--output-directory", "--baseline-directory", dest="output_directory", type=Path, required=True)
    prepare.add_argument("--repository", default=DEFAULT_REPOSITORY)
    prepare.add_argument("--upstream-lock", type=Path, default=ROOT / "upstream.lock.json")
    prepare.add_argument("--timeout-seconds", type=positive_int, default=300)
    prepare.add_argument("--artifact-archive", type=Path)
    prepare.add_argument("--run-metadata", type=Path)
    prepare.add_argument("--artifact-metadata", type=Path)
    prepare.add_argument("--source-lock", type=Path, help="GitHub contents API response tied to run.head_sha, not a detached lock file")
    prepare.set_defaults(function=prepare_baseline)
    check = commands.add_parser("check")
    check.add_argument("--package-directory", type=Path, required=True)
    check.add_argument("--baseline-directory", type=Path)
    check.add_argument("--allow-no-baseline-experiment", action="store_true")
    check.add_argument("--output-directory", type=Path, required=True)
    check.add_argument("--upstream-lock", type=Path, default=ROOT / "upstream.lock.json")
    check.add_argument("--samples", type=positive_int, default=5)
    check.add_argument("--target-milliseconds", type=positive_int, default=1200)
    check.add_argument("--browser-timeout-seconds", type=positive_int, default=180)
    check.add_argument("--installer-timeout-seconds", type=positive_int, default=300)
    check.set_defaults(function=run_checks)
    args = parser.parse_args(argv)
    if args.command == "check" and (args.samples < 3 or args.samples > 30 or args.target_milliseconds < 1000):
        parser.error("use 3..30 samples and calibration target >=1000ms; keep privacy timer defaults")
    try:
        args.function(args)
        return 0
    except Exception as error:
        print("Runtime check failed: " + str(error), file=sys.stderr)
        return error.returncode if isinstance(error, NativeError) else 1


def exit_process(status):
    if os.name == "nt":
        # sys.exit may truncate high-bit native exception DWORDs through C int.
        # Preserve the actual Windows native status for the PowerShell wrapper.
        sys.stdout.flush()
        sys.stderr.flush()
        from ctypes import wintypes
        api = ctypes.WinDLL("kernel32")
        api.ExitProcess.argtypes = [wintypes.UINT]
        api.ExitProcess.restype = None
        api.ExitProcess(status & 0xffffffff)
    raise SystemExit(status)


if __name__ == "__main__":
    exit_process(main())
