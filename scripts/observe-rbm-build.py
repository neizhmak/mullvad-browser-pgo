#!/usr/bin/env python3
"""Observe one exact RBM command; diagnostics never explain or retry a failure.

The build log contains only combined child stdout/stderr (bytes, appended).
Resources are appended as JSONL and also printed to stdout. Only the two fixed
RBM project logs below are tailed, read-only, at most 8 KiB each per snapshot.
Linux uses a new child session and bounded signal/process-group cleanup.
"""
import argparse
from datetime import datetime, timezone
import errno
import json
import math
import os
from pathlib import Path
import queue
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

PROJECT_LOGS = ("firefox-windows-x86_64.log", "node-windows-x86_64.log")
TAIL_BYTES = 8192
CHUNK_BYTES = 65536
SIGNAL_GRACE_SECONDS = 2.0
DRAIN_GRACE_SECONDS = 1.0


def safe_error(error):
    """Do not print exception text, command arguments, or environment values."""
    number = getattr(error, "errno", None)
    return type(error).__name__ + (f"(errno={number})" if number is not None else "")


def absolute_no_links(value):
    path = Path(value)
    if ".." in path.parts:
        raise ValueError("log destinations must not contain '..'")
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        try:
            if stat.S_ISLNK(component.lstat().st_mode):
                raise ValueError("log destinations must not use symlinks")
        except FileNotFoundError:
            if component != path:
                raise ValueError("log destination parent must exist")
    if not path.parent.is_dir():
        raise ValueError("log destination parent must be a directory")
    return path


def open_directory(path):
    """Open every POSIX directory component without following a symlink."""
    if os.name != "posix":
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_destination(path):
    parent_fd = open_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = None
    try:
        fd = os.open(path.name if parent_fd is not None else path, flags,
                     0o600, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("log destination must be a regular, unshared file")
        return os.fdopen(fd, "ab", buffering=0)
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


class Output:
    def __init__(self, build_log, resource_log):
        self.build_log = build_log
        self.resource_log = resource_log
        self.console = getattr(sys.stdout, "buffer", sys.stdout)
        self.warned = set()

    def warn(self, label, error):
        if label in self.warned:
            return
        self.warned.add(label)
        self.console_bytes(f"[rbm-observe] {label}: {safe_error(error)}\n".encode())

    def console_bytes(self, payload):
        if self.console is not None:
            try:
                self.console.write(payload)
                self.console.flush()
            except (OSError, ValueError):
                self.console = None

    def write(self, target, payload, label):
        try:
            remaining = memoryview(payload)
            while remaining:
                written = target.write(remaining)
                if not written:
                    raise OSError(errno.EIO, "short diagnostic write")
                remaining = remaining[written:]
            target.flush()
        except (OSError, ValueError) as error:
            self.warn(label, error)

    def child_bytes(self, payload):
        self.console_bytes(payload)
        self.write(self.build_log, payload, "child log write failed")

    def record(self, snapshot):
        payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.console_bytes(b"[rbm-resource] " + payload)
        self.write(self.resource_log, payload, "resource log write failed")

    def flush(self):
        for target in (self.build_log, self.resource_log):
            try:
                target.flush()
            except (OSError, ValueError) as error:
                self.warn("diagnostic flush failed", error)
        if self.console is not None:
            try:
                self.console.flush()
            except (OSError, ValueError):
                self.console = None


def mount_unescape(text):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), text)


def self_cgroup_v2():
    """Resolve only this process's cgroup; never walk the cgroup filesystem."""
    cgroup = None
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            cgroup = Path(line[3:])
            break
    if cgroup is None or not cgroup.is_absolute() or ".." in cgroup.parts:
        return None
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, separator, right = line.partition(" - ")
        if separator and right.split()[0] == "cgroup2":
            fields = left.split()
            root = Path(mount_unescape(fields[3]))
            mount = Path(mount_unescape(fields[4]))
            try:
                relative = cgroup.relative_to(root)
            except ValueError:
                continue
            candidate = mount / relative
            # Reject unexpected traversal/links rather than read outside mount.
            if candidate.resolve().is_relative_to(mount.resolve()):
                return candidate
    return None


def resource_snapshot(upstream, log_dir, reason, started, **extra):
    snapshot = {"time": datetime.now(timezone.utc).isoformat(), "reason": reason,
                "elapsed_seconds": round(time.monotonic() - started, 3), **extra}
    errors = []

    def collect(label, operation):
        try:
            snapshot[label] = operation()
        except Exception as error:
            errors.append(label + ":" + safe_error(error))

    def meminfo():
        wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
        result = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in wanted:
                result[key] = int(value.split()[0])
        return result

    def oom_kill():
        for line in Path("/proc/vmstat").read_text().splitlines():
            key, value = line.split()
            if key == "oom_kill":
                return int(value)
        return None

    def disks():
        result = {}
        for label, path in (("upstream", upstream), ("log", log_dir)):
            try:
                if hasattr(os, "statvfs"):
                    usage = os.statvfs(path)
                    result[label] = {"total_bytes": usage.f_blocks * usage.f_frsize,
                                     "free_bytes": usage.f_bavail * usage.f_frsize,
                                     "total_inodes": usage.f_files,
                                     "free_inodes": usage.f_favail}
                else:
                    import shutil
                    usage = shutil.disk_usage(path)
                    result[label] = {"total_bytes": usage.total, "free_bytes": usage.free}
            except Exception as error:
                errors.append("disk_" + label + ":" + safe_error(error))
        return result

    def cpu_counts():
        values = {"logical": os.cpu_count()}
        if hasattr(os, "sched_getaffinity"):
            try:
                values["affinity"] = len(os.sched_getaffinity(0))
            except OSError as error:
                errors.append("cpu_affinity:" + safe_error(error))
        return values

    collect("meminfo_kib", meminfo)
    collect("oom_kill", oom_kill)
    collect("disks", disks)
    collect("cpu", cpu_counts)
    try:
        directory = self_cgroup_v2()
        if directory is not None:
            values = {}
            for name in ("memory.current", "memory.max", "memory.events"):
                try:
                    text = (directory / name).read_text().strip()
                    if name == "memory.events":
                        values[name] = {key: int(value) for key, value in
                                        (line.split() for line in text.splitlines())}
                    else:
                        values[name] = text if text == "max" else int(text)
                except Exception as error:
                    errors.append("cgroup_" + name + ":" + safe_error(error))
            snapshot["cgroup_v2"] = values
    except Exception as error:
        errors.append("cgroup_v2:" + safe_error(error))
    if errors:
        snapshot["errors"] = errors
    return snapshot


class ProjectTails:
    def __init__(self, upstream, output):
        self.upstream = upstream
        self.output = output
        self.offsets = {}

    def sample(self):
        root_fd = logs_fd = None
        try:
            root_fd = open_directory(self.upstream)
            if root_fd is not None:
                logs_fd = os.open("logs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=root_fd)
            else:
                absolute_no_links(self.upstream / "logs" / PROJECT_LOGS[0])
            for name in PROJECT_LOGS:
                self.one(name, logs_fd)
        except FileNotFoundError:
            pass  # RBM may not have created its log directory yet.
        except Exception as error:
            self.output.warn("project log directory unavailable", error)
        finally:
            for fd in (logs_fd, root_fd):
                if fd is not None:
                    os.close(fd)

    def one(self, name, logs_fd):
        fd = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            path = name if logs_fd is not None else self.upstream / "logs" / name
            if logs_fd is None:
                absolute_no_links(path)
            fd = os.open(path, flags, dir_fd=logs_fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("project log must be regular and unshared")
            identity = (info.st_dev, info.st_ino)
            previous_identity, previous_offset = self.offsets.get(name, (None, 0))
            if identity != previous_identity or info.st_size < previous_offset:
                previous_offset = 0
            start = max(previous_offset, info.st_size - TAIL_BYTES)
            os.lseek(fd, start, os.SEEK_SET)
            payload = os.read(fd, min(TAIL_BYTES, info.st_size - start))
            self.offsets[name] = (identity, start + len(payload))
            if payload:
                record = {"project": name, "start": start, "end": start + len(payload),
                          "bytes": len(payload), "text": payload.decode("utf-8", "replace")}
                # V2 requires a line-start marker; legacy scans for ##[ anywhere.
                # JSON escapes round-trip the text without exposing legacy markers.
                encoded = json.dumps(record).replace("##[", r"\u0023\u0023[").encode()
                self.output.console_bytes(b"[rbm-project] " + encoded + b"\n")
        except FileNotFoundError:
            pass
        except Exception as error:
            self.output.warn("project log unavailable: " + name, error)
        finally:
            if fd is not None:
                os.close(fd)


class ChildStream:
    """Selectors on Linux; a bounded pipe-reader queue for Windows portability."""
    def __init__(self, pipe):
        self.pipe = pipe
        self.eof = False
        self.thread = None
        self.selector = None
        if os.name == "posix":
            os.set_blocking(pipe.fileno(), False)
            self.selector = selectors.DefaultSelector()
            self.selector.register(pipe, selectors.EVENT_READ)
        else:
            self.queue = queue.Queue(maxsize=16)
            self.thread = threading.Thread(target=self.read_pipe, daemon=True)
            self.thread.start()

    def read_pipe(self):
        try:
            while True:
                payload = self.pipe.read(CHUNK_BYTES)
                if not payload:
                    break
                self.queue.put(payload)
        finally:
            self.queue.put(b"")

    def read(self, timeout):
        if self.eof:
            # Waiting for the child, not an agent polling loop.
            threading.Event().wait(timeout)
            return None
        if self.selector is not None:
            if not self.selector.select(timeout):
                return None
            try:
                payload = os.read(self.pipe.fileno(), CHUNK_BYTES)
            except BlockingIOError:
                return None
        else:
            try:
                payload = self.queue.get(timeout=timeout)
            except queue.Empty:
                return None
        if not payload:
            self.eof = True
            if self.selector is not None:
                self.selector.unregister(self.pipe)
        return payload

    def close(self):
        if self.selector is not None:
            self.selector.close()
        self.pipe.close()
        if self.thread is not None:
            self.thread.join(timeout=DRAIN_GRACE_SECONDS)


def run_build(command, upstream, log_path, build_log, resource_log, interval):
    output = Output(build_log, resource_log)
    tails = ProjectTails(upstream, output)
    started = time.monotonic()
    pending_signals = []
    observed_signal = None
    old_handlers = {}
    process = stream = None

    def capture(signum, _frame):
        pending_signals.append(signum)

    def snapshot(reason, **extra):
        try:
            extra.setdefault("observed_supervisor_signal",
                             signal.Signals(observed_signal).name if observed_signal else None)
            extra.setdefault("child_returncode", process.poll() if process is not None else None)
            output.record(resource_snapshot(upstream, log_path.parent, reason, started, **extra))
        except Exception as error:
            output.warn("resource snapshot failed", error)
        try:
            tails.sample()
        except Exception as error:
            output.warn("project snapshot failed", error)
        output.flush()

    def forward(signum):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signum)
            elif process.poll() is None:
                process.send_signal(signum)
        except ProcessLookupError:
            pass
        except OSError as error:
            output.warn("signal forwarding failed", error)

    def group_alive():
        if os.name != "posix":
            return process.poll() is None
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except OSError:
            return True

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, capture)
        try:
            process = subprocess.Popen(command, cwd=upstream, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, bufsize=0,
                                       start_new_session=(os.name == "posix"))
        except OSError as error:
            output.warn("build launch failed", error)
            snapshot("launch-error")
            return 127 if error.errno == errno.ENOENT else 126
        stream = ChildStream(process.stdout)
        snapshot("start", child_pid=process.pid)
        next_sample = time.monotonic() + interval
        deadline = killed_at = None
        while True:
            now = time.monotonic()
            while pending_signals:
                signum = pending_signals.pop(0)
                observed_signal = signum
                snapshot("signal", signal=signal.Signals(signum).name)
                forward(signum)  # Snapshot and flush BEFORE forwarding.
                deadline = now + SIGNAL_GRACE_SECONDS if deadline is None else now
            returncode = process.poll()
            if returncode is not None and deadline is None:
                # Bound pipe draining even if an escaped session retains stdout.
                # Only signal the original owned group, never an escaped PID.
                if group_alive():
                    forward(signal.SIGTERM)
                deadline = now + SIGNAL_GRACE_SECONDS
            if deadline is not None and killed_at is None and now >= deadline:
                if group_alive():
                    forward(getattr(signal, "SIGKILL", signal.SIGTERM))
                killed_at = now
            if returncode is not None and stream.eof:
                if not group_alive() or killed_at is not None:
                    break
            if killed_at is not None and now >= killed_at + DRAIN_GRACE_SECONDS:
                # Covers a descendant that escaped the session but retained stdout.
                break
            if now >= next_sample:
                snapshot("interval")
                next_sample = time.monotonic() + interval
            timeout = min(0.1, max(0.0, next_sample - time.monotonic()))
            try:
                payload = stream.read(timeout)
                if payload:
                    output.child_bytes(payload)
            except OSError as error:
                output.warn("child stdout read failed", error)
                stream.eof = True
        if process.poll() is None:
            forward(getattr(signal, "SIGKILL", signal.SIGTERM))
        returncode = process.wait(timeout=SIGNAL_GRACE_SECONDS)
        code = returncode if returncode >= 0 else 128 - returncode
        if code == 0 and observed_signal is not None:
            # A handled cancellation must not look like a completed build.
            code = 128 + observed_signal
        snapshot("exit", child_returncode=returncode, exit_code=code)
        return code
    finally:
        if process is not None and process.poll() is None:
            forward(getattr(signal, "SIGKILL", signal.SIGTERM))
            try:
                process.wait(timeout=SIGNAL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError) as error:
                output.warn("stdout stream close failed", error)
        output.flush()
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--resource-log", required=True, type=Path)
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.command or args.command[0] != "--" or len(args.command) == 1:
        parser.error("an exact build command is required after --")
    if not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("--interval must be a finite positive number")
    build_log = resource_log = None
    try:
        upstream = args.upstream.resolve(strict=True)
        if not upstream.is_dir():
            raise ValueError("upstream must be a directory")
        log_path = absolute_no_links(args.log)
        resource_path = absolute_no_links(args.resource_log)
        for path in (log_path, resource_path):
            if path.is_relative_to(upstream / "logs"):
                raise ValueError("diagnostic destinations must not be inside RBM logs")
        if log_path == resource_path:
            raise ValueError("build and resource logs must be different files")
        build_log = open_destination(log_path)
        resource_log = open_destination(resource_path)
        if os.path.samestat(os.fstat(build_log.fileno()), os.fstat(resource_log.fileno())):
            raise ValueError("build and resource logs must be different files")
    except (OSError, ValueError) as error:
        for target in (build_log, resource_log):
            if target is not None:
                target.close()
        # Errors are safe fixed messages, not arguments or exception path text.
        parser.error(str(error) if isinstance(error, ValueError) else
                     "cannot open required upstream/log destinations: " + safe_error(error))
    try:
        return run_build(args.command[1:], upstream, log_path, build_log,
                         resource_log, args.interval)
    finally:
        for target in (build_log, resource_log):
            try:
                target.close()
            except OSError:
                pass  # Diagnostic close failures must not replace the build code.


if __name__ == "__main__":
    sys.exit(main())
