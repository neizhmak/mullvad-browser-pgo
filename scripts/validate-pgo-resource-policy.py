#!/usr/bin/env python3
"""Fail-closed warm/offline metadata gate for one two-CPU PGO generation policy.

This validates metadata and restored inputs. It does not compile a browser,
measure compiler jobs/RSS, or establish native profile/training success.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PosixPath
import re
import shutil
import signal
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
LOCK = {"repository": "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git",
        "tag": "mb-16.0a9-build1", "tag_object": "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721",
        "commit": "7dd751cf1837d667908b339aebf82567ece55e20"}
RBM_COMMIT = "865f2c9842520958879665d5c9b820d9ed51761e"
RBM_REPOSITORY = "https://gitlab.torproject.org/tpo/applications/rbm.git"
EXPECTED_RUST_SHA = "610dce67882933fdffb6df9c16633ef37c4f5f0e625ebe74d315b1dff44fe2b3"
EXPECTED_NODE_SHA = "f93c137e502ea4bbdf5d05b8791ab32a80d1d7d51600867e8a144f83dd3eb78c"
TARGETS = ("alpha", "mullvadbrowser-windows-x86_64", "pgo-generate")
INFLUENCERS = ("RBM_NUM_PROCS", "OMP_NUM_THREADS", "OMP_THREAD_LIMIT")
MAX_FILE = 512 * 1024
MAX_RENDER = 256 * 1024
TOTAL_SECONDS = 300
CALL_SECONDS = 45
SOURCE_SHA = {
    "rbm.conf": "cf632dc0a9252f6425e528b94a945ea628ea1b38b542348391245233eb206c11",
    "rbm/rbm": "8fe03955c29002943bd788f08f5e7b06da4285443540f1871233c795ff65c246",
    "rbm/container": "1c310719f66b8c2ceb557a317f06e5096c8fed0e4184cefaa4ec554d7cffef90",
    "rbm/lib/RBM.pm": "37683f75111293df3e3e043c85f28f8db35a83504918c886f0e627bf69b4e3ee",
    "rbm/lib/RBM/CaptureExec.pm": "bf1271fca81e9d9118badb8dc3cb05a9f084a424881e4a380d6a4b480a7330c3",
    "rbm/lib/RBM/DefaultConfig.pm": "4dae32dc9502f26dd763c15c6360cc9a43cab4406e6baffd0683d1b18b7ec4c2",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,240}\Z")
_spec = importlib.util.spec_from_file_location("pgo_resource_native", ROOT / "scripts/probe-rbm-resource-control.py")
NATIVE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NATIVE)
Deadline = NATIVE.Deadline
MASK_CODE = NATIVE.MASK_CODE
NS_CODE = r"""
import json, os, sys
if any(name in os.environ for name in ('RBM_NUM_PROCS', 'OMP_NUM_THREADS', 'OMP_THREAD_LIMIT')):
    raise SystemExit(1)
print("PGO_RESOURCE_NS " + json.dumps({"affinity": sorted(os.sched_getaffinity(0)),
      "network_namespace": os.readlink("/proc/self/ns/net")}, sort_keys=True), flush=True)
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
"""


class GateError(Exception):
    """A fixed error code. Captured stderr, paths and env values are never errors."""


def require(condition, code):
    if not condition:
        raise GateError(code)


def strict_json(raw, max_bytes=MAX_FILE):
    require(isinstance(raw, bytes) and len(raw) <= max_bytes, "json_limit")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "json_duplicate_key")
            result[key] = value
        return result
    def constant(_value):
        raise GateError("json_nonfinite")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise GateError("invalid_json") from None


def canonical_sha(data):
    try:
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    except (ValueError, TypeError, RecursionError):
        raise GateError("invalid_canonical_json") from None


def safe_path(path):
    try:
        return NATIVE.no_symlink_path(Path(path))
    except (NATIVE.ProbeError, OSError):
        raise GateError("unsafe_path") from None


def read_regular(path, limit=MAX_FILE):
    path = safe_path(path)
    try:
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and 0 < info.st_size <= limit, "unsafe_regular_file")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        require(len(data) == info.st_size and len(data) <= limit, "file_changed")
        return data
    except OSError:
        raise GateError("missing_regular_file") from None


def sha_file(path, deadline=None):
    path = safe_path(path)
    try:
        before = path.stat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and before.st_size > 0, "unsafe_archive")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                if deadline is not None:
                    deadline.remaining()
                data = stream.read(1024 * 1024)
                if not data:
                    break
                digest.update(data)
        after = path.stat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "archive_changed")
        return {"sha256": digest.hexdigest(), "size": before.st_size}
    except NATIVE.ProbeError:
        raise GateError("global_deadline") from None
    except OSError:
        raise GateError("missing_archive") from None


def atomic_json(path, data, limit=64 * 1024):
    path = safe_path(path)
    try:
        raw = (json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        require(len(raw) <= limit, "report_limit")
        fd, temporary = tempfile.mkstemp(prefix=".resource-policy-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
    except OSError:
        raise GateError("report_write_failed") from None


PROGRESS_BYTES = 64 * 1024
PROGRESS_PHASES = 32
PROGRESS_NATIVE = 64
PROGRESS_ORDINAL_MAX = 1000000
PROGRESS_COUNTER_MAX = (1 << 63) - 1
PROGRESS_MS_MAX = 86400000
PROGRESS_SCOPE = "bounded metadata gate progress only; not completed-case, final-gate or execution-policy proof"
PROGRESS_CASES = ("gate", "baseline", "selected-two", "one-metadata-only")
PROGRESS_PHASE_LABELS = (
    "preflight", "inputs_before", "source_before", "registries_before", "archives_before",
    "inventory_before", "case_native", "case_selected_inputs", "case_inventory", "case_source",
    "case_comparison", "archives_after", "inputs_after", "registries_after", "source_after",
    "selected_inputs_after", "inventory_after", "parent_after", "final_report")
PROGRESS_OPERATION_LABELS = (
    "native", "source_git", "rust_identity", "node_identity", "filename_firefox",
    "filename_rust_profiler", "filename_rust_official", "filename_mingw", "filename_node",
    "firefox_repository", "firefox_ref", "firefox_commit", "firefox_executable", "named_inputs", "renderer")
PROGRESS_COUNTER_NAMES = ("native_calls", "inventory_entries", "git_metadata_bytes", "archive_count",
                          "archive_bytes", "selected_archive_count", "selected_archive_bytes")


def progress_milliseconds(seconds):
    """Saturate public observations only, never a deadline or scheduling input."""
    if type(seconds) not in (int, float) or seconds != seconds or seconds <= 0:
        return 0
    if seconds >= PROGRESS_MS_MAX / 1000:
        return PROGRESS_MS_MAX
    return int(seconds * 1000)


class ProgressTrace:
    """Bounded fixed-vocabulary progress, separate from all gate proof records."""

    def __init__(self, path, deadline):
        self.path, self.deadline = path, deadline
        self.started = time.monotonic()
        self.failure_flushed = False
        self.phase_started = self.started
        self.phase_ordinal = self.native_ordinal = self.operation_ordinal = 0
        self.operation_label = "native"
        self.native_started = self.started
        self.data = {"schema": 1, "scope": PROGRESS_SCOPE, "status": "running", "elapsed_ms": 0,
                     "active_phase": None, "last_completed_phase": None, "phases": [], "native_operations": []}
        deadline.progress = self
        self._write()

    def _elapsed(self, started):
        return progress_milliseconds(time.monotonic() - started)

    def _write(self, *, failure_flush=False):
        self.data["elapsed_ms"] = self._elapsed(self.started)
        if self.failure_flushed and not failure_flush:
            return
        atomic_json(self.path, self.data, limit=PROGRESS_BYTES)

    def _write_preserving_failure(self):
        # Share one bounded failure flush across native/phase/validate unwind.
        # Expiry permits diagnostic cleanup, never metadata/native work or retry.
        self.data["status"] = "failed"
        current = self.data["active_phase"]
        if current is not None:
            current["outcome"] = "failed"
            current["elapsed_ms"] = self._elapsed(self.phase_started)
        if self.failure_flushed:
            return
        self.failure_flushed = True
        try:
            self._write(failure_flush=True)
        except Exception:
            pass

    @contextmanager
    def phase(self, label, case="gate"):
        require(isinstance(label, str) and label in PROGRESS_PHASE_LABELS
                and isinstance(case, str) and case in PROGRESS_CASES, "invalid_progress_label")
        self.phase_ordinal += 1
        self.operation_ordinal = 0
        started = time.monotonic()
        self.phase_started = started
        record = {"ordinal": min(self.phase_ordinal, PROGRESS_ORDINAL_MAX), "label": label, "case": case,
                  "outcome": "started", "started_ms": self._elapsed(self.started), "elapsed_ms": 0, "counters": {}}
        previous = self.data["active_phase"]
        self.data["active_phase"] = record
        self.data["phases"].append(record)
        del self.data["phases"][:-PROGRESS_PHASES]
        self._write()
        try:
            yield
        except BaseException:
            try:
                record["outcome"] = "failed"
                record["elapsed_ms"] = self._elapsed(started)
                self._write_preserving_failure()
            except Exception:
                pass
            raise
        else:
            record["outcome"] = "completed"
            record["elapsed_ms"] = self._elapsed(started)
            self.data["last_completed_phase"] = record
            self.data["active_phase"] = previous
            self._write()

    @contextmanager
    def operation(self, label):
        require(isinstance(label, str) and label in PROGRESS_OPERATION_LABELS, "invalid_progress_label")
        previous, self.operation_label = self.operation_label, label
        try:
            yield
        finally:
            self.operation_label = previous

    def set_counters(self, **counts):
        require(all(key in PROGRESS_COUNTER_NAMES and type(value) is int and value >= 0
                    for key, value in counts.items()), "invalid_progress_counter")
        current = self.data["active_phase"]
        if current is not None:
            current["counters"].update({key: min(value, PROGRESS_COUNTER_MAX) for key, value in counts.items()})

    def start_native(self, seconds):
        self.native_ordinal += 1
        self.operation_ordinal += 1
        self.native_started = time.monotonic()
        current = self.data["active_phase"]
        record = {"ordinal": min(self.native_ordinal, PROGRESS_ORDINAL_MAX),
                  "phase_ordinal": current["ordinal"] if current is not None else 0,
                  "operation_ordinal": min(self.operation_ordinal, PROGRESS_ORDINAL_MAX),
                  "label": self.operation_label, "case": current["case"] if current is not None else "gate",
                  "outcome": "started", "started_ms": self._elapsed(self.started), "elapsed_ms": 0,
                  "requested_cap_ms": progress_milliseconds(seconds), "scheduled_remaining_ms": None,
                  "effective_cap_ms": None, "limiter": None}
        self.data["native_operations"].append(record)
        del self.data["native_operations"][:-PROGRESS_NATIVE]
        if current is not None:
            calls = current["counters"].get("native_calls", 0) + 1
            self.set_counters(native_calls=calls)
        # Schedule fields stay null until the actual protected runner sample.
        self._write()
        return record

    def end_native(self, record, outcome, *, preserve_failure=False):
        require(outcome in ("completed", "nonzero", "failed"), "invalid_progress_outcome")
        record["outcome"] = outcome
        record["elapsed_ms"] = self._elapsed(self.native_started)
        if preserve_failure:
            self._write_preserving_failure()
        else:
            self._write()

    def finish(self, outcome):
        require(outcome in ("finished", "failed"), "invalid_progress_outcome")
        self.data["status"] = outcome
        if outcome == "failed":
            self._write_preserving_failure()
        else:
            self._write()


class ObservedDeadline:
    """Observe only the exact sample used by the protected scheduling expression."""

    def __init__(self, delegate, seconds, progress, record):
        self.delegate, self.seconds, self.progress, self.record = delegate, seconds, progress, record
        self.observed_remaining = self.effective_cap = self.limiter = None

    def remaining(self):
        remaining = self.delegate.remaining()
        self.observed_remaining = remaining
        self.effective_cap = min(self.seconds, remaining)
        self.limiter = "per_call" if self.seconds <= remaining else "global_remaining"
        self.record["scheduled_remaining_ms"] = progress_milliseconds(remaining)
        self.record["effective_cap_ms"] = progress_milliseconds(self.effective_cap)
        self.record["limiter"] = self.limiter
        # No IO, clock read, or extra delegate query is allowed here.
        return remaining


@contextmanager
def progress_phase(deadline, label, case="gate"):
    progress = getattr(deadline, "progress", None)
    if progress is None:
        yield
    else:
        with progress.phase(label, case):
            yield


@contextmanager
def progress_operation(deadline, label):
    progress = getattr(deadline, "progress", None)
    if progress is None:
        yield
    else:
        with progress.operation(label):
            yield


def progress_counters(deadline, **counts):
    progress = getattr(deadline, "progress", None)
    if progress is not None:
        progress.set_counters(**counts)


def run_native(command, *, cwd, environment, deadline, seconds=CALL_SECONDS):
    progress = getattr(deadline, "progress", None)
    record = progress.start_native(seconds) if progress is not None else None
    observed = ObservedDeadline(deadline, seconds, progress, record) if progress is not None else deadline
    try:
        result = NATIVE.run_native(command, cwd=cwd, environment=environment,
                                  deadline=observed, seconds=seconds)
    except BaseException as error:
        if progress is not None:
            try:
                progress.end_native(record, "failed", preserve_failure=True)
            except Exception:
                pass
        if isinstance(error, NATIVE.ProbeError):
            # Only the fixed codes emitted by the trusted bounded runner are used.
            raise GateError(str(error)) from None
        raise
    if progress is not None:
        if result[0] == 0:
            progress.end_native(record, "completed")
        else:
            try:
                progress.end_native(record, "nonzero", preserve_failure=True)
            except Exception:
                pass
    return result


def checked(command, *, cwd, environment, deadline):
    code, stdout, _stderr = run_native(command, cwd=cwd, environment=environment, deadline=deadline)
    require(code == 0, "native_nonzero")
    return stdout


def git(upstream, arguments, environment, deadline):
    authority_names = {"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                       "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_INDEX_FILE", "GIT_SHALLOW_FILE",
                       "GIT_NAMESPACE", "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE"}
    require(not any(key in authority_names or key.startswith("GIT_CONFIG") for key in environment)
            and environment.get("GIT_NO_REPLACE_OBJECTS", "1") == "1", "uncontrolled_git_authority_environment")
    with progress_operation(deadline, "source_git"):
        raw = checked(["git", "--no-replace-objects", "--no-pager", "-c", "core.fsmonitor=false",
                       "-c", "core.hooksPath=/dev/null", "-C", str(upstream), *arguments],
                      cwd=upstream, environment=environment, deadline=deadline)
    return raw


def git_text(upstream, arguments, environment, deadline):
    try:
        return git(upstream, arguments, environment, deadline).decode("utf-8").rstrip("\r\n")
    except UnicodeError:
        raise GateError("invalid_git_output") from None


def apply_overlay(original, patch, path):
    """Apply the exact trusted unified patch to a single immutable Git blob."""
    lines = original.decode("utf-8").splitlines(keepends=True)
    patch_lines = patch.decode("utf-8").splitlines(keepends=True)
    start = next((i for i, line in enumerate(patch_lines) if line == "+++ b/" + path + "\n"), None)
    if start is None:
        return original
    output, cursor, i = [], 0, start + 1
    while i < len(patch_lines) and not patch_lines[i].startswith("diff --git "):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", patch_lines[i])
        require(match is not None, "invalid_overlay_hunk")
        index = int(match[1]) - 1
        require(cursor <= index <= len(lines), "invalid_overlay_hunk")
        output.extend(lines[cursor:index])
        cursor, removed, added = index, 0, 0
        i += 1
        while (removed < int(match[2] or "1") or added < int(match[4] or "1")):
            require(i < len(patch_lines) and not patch_lines[i].startswith(("@@ ", "diff --git ")),
                    "invalid_overlay_hunk")
            line = patch_lines[i]
            require(line[:1] in (" ", "+", "-"), "invalid_overlay_hunk")
            if line[:1] in (" ", "-"):
                require(cursor < len(lines) and lines[cursor] == line[1:], "overlay_preimage_mismatch")
                cursor += 1
                removed += 1
            if line[:1] in (" ", "+"):
                output.append(line[1:])
                added += 1
            i += 1
        require(removed == int(match[2] or "1") and added == int(match[4] or "1"), "overlay_hunk_count")
        # The immutable upstream overlay has one trailing context line beyond
        # its declared Firefox-config hunk counts. Native Git ignores it.
        while i < len(patch_lines) and not patch_lines[i].startswith(("@@ ", "diff --git ")):
            require(patch_lines[i].startswith(" "), "invalid_overlay_trailer")
            i += 1
    output.extend(lines[cursor:])
    return "".join(output).encode()


def source_records(upstream, inputs, environment, deadline):
    require(strict_json(read_regular(ROOT / "upstream.lock.json")) == LOCK, "project_lock_mismatch")
    require(not os.path.lexists(upstream / "rbm.local.conf") and not os.path.lexists("/etc/rbm.conf"),
            "uncontrolled_rbm_config")
    records = {}
    for directory, commit, origin in ((upstream, LOCK["commit"], LOCK["repository"]),
                                       (upstream / "rbm", RBM_COMMIT, RBM_REPOSITORY)):
        require(git_text(directory, ["rev-parse", "--show-toplevel"], environment, deadline)
                == str(directory), "wrong_git_root")
        require(git_text(directory, ["rev-parse", "HEAD"], environment, deadline) == commit,
                "source_commit_mismatch")
        require(git_text(directory, ["remote", "get-url", "origin"], environment, deadline) == origin,
                "source_origin_mismatch")
        require(not git_text(directory, ["for-each-ref", "--format=%(refname)", "refs/replace/"],
                             environment, deadline), "unsupported_git_replacements")
        graft = git_text(directory, ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"],
                         environment, deadline)
        require(Path(graft).is_absolute() and Path(graft).name == "grafts"
                and Path(graft).parent.name == "info", "invalid_git_graft_path")
        require(not os.path.lexists(graft), "unsupported_git_grafts")
        safe_path(graft)
        index = git_text(directory, ["ls-files", "-v"], environment, deadline).splitlines()
        require(all(line.startswith("H ") for line in index), "hidden_worktree_changes")
    for arguments, expected in ((["rev-parse", "refs/tags/" + LOCK["tag"]], LOCK["tag_object"]),
                                (["rev-parse", "refs/tags/" + LOCK["tag"] + "^{}"], LOCK["commit"]),
                                (["cat-file", "-t", LOCK["tag_object"]], "tag"),
                                (["ls-tree", LOCK["commit"], "rbm"], "160000 commit " + RBM_COMMIT + "\trbm"),
                                (["config", "--file", ".gitmodules", "submodule.rbm.path"], "rbm"),
                                (["config", "--file", ".gitmodules", "submodule.rbm.url"], RBM_REPOSITORY)):
        require(git_text(upstream, arguments, environment, deadline) == expected, "source_pin_mismatch")
    overlay = read_regular(ROOT / "patches/firefox-pgo-generate.patch")
    require(hashlib.sha256(overlay).hexdigest() == inputs["provenance"]["pgo_overlay_sha256"],
            "overlay_mismatch")
    for relative, expected in SOURCE_SHA.items():
        data = read_regular(upstream / relative)
        require(hashlib.sha256(data).hexdigest() == expected, "rbm_source_mismatch")
        records[relative] = expected
    recipe_paths = ("projects/firefox/build", "projects/firefox/config", "projects/firefox/mozconfig.in",
                    "projects/rust/config", "projects/rust/build", "projects/node/config", "projects/node/build",
                    "projects/container-image/config", "projects/container-image/build")
    for relative in recipe_paths:
        original = git(upstream, ["show", LOCK["commit"] + ":" + relative], environment, deadline)
        expected = apply_overlay(original, overlay, relative)
        actual = read_regular(upstream / relative)
        require(actual == expected, "recipe_source_mismatch")
        records[relative] = hashlib.sha256(actual).hexdigest()
    allowed_changes = {"projects/firefox/build", "projects/firefox/config", "projects/rust/config", "projects/rust/build"}
    changed = set(git_text(upstream, ["diff", "HEAD", "--name-only", "--ignore-submodules=all"],
                           environment, deadline).splitlines())
    require(changed == allowed_changes, "unexpected_source_changes")
    require(not git_text(upstream / "rbm", ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"],
                         environment, deadline), "dirty_rbm_source")
    status = git_text(upstream, ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=all"],
                      environment, deadline).splitlines()
    for line in status:
        name = line[3:]
        require(name in allowed_changes or (line.startswith(("?? ", "!! ")) and name.split("/", 1)[0]
                in {"out", "logs", "tmp", "git_clones", "hg_clones"}), "uncontrolled_source_file")
    firefox = inputs["provenance"]["firefox"]
    clone = safe_path(upstream / "git_clones/firefox")
    require(clone.is_dir(), "missing_warm_firefox_source")
    require(git_text(clone, ["remote", "get-url", "origin"], environment, deadline) == firefox["repository"],
            "firefox_source_origin_mismatch")
    require(not git_text(clone, ["for-each-ref", "--format=%(refname)", "refs/replace/"], environment, deadline),
            "unsupported_git_replacements")
    graft = git_text(clone, ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"], environment, deadline)
    require(Path(graft).is_absolute() and not os.path.lexists(graft), "unsupported_git_grafts")
    safe_path(graft)
    require(git_text(clone, ["rev-parse", firefox["ref"] + "^{commit}"], environment, deadline)
            == firefox["revision"], "firefox_source_revision_mismatch")
    server = git(clone, ["show", firefox["revision"] + ":build/pgo/profileserver.py"], environment, deadline)
    require(hashlib.sha256(server).hexdigest() == inputs["provenance"]["profileserver"]["sha256"],
            "workload_mismatch")
    require(read_regular(inputs["provenance_path"].parent / "profileserver.py") == server, "workload_file_mismatch")
    records["profileserver.py"] = hashlib.sha256(server).hexdigest()
    return records


def _inventory_prefix(upstream):
    if type(upstream) is PosixPath and upstream.is_absolute():
        text = str(upstream)
        if not text.startswith("//"):
            return text if text.endswith("/") else text + "/"
    return None


def _inventory_relative(path, upstream, prefix):
    if prefix is not None and type(path) is PosixPath:
        full = str(path)
        if not full.startswith("//") and full.startswith(prefix) and len(full) > len(prefix):
            return full[len(prefix):]
    return path.relative_to(upstream).as_posix()


def immutable_inventory(upstream, deadline=None):
    """Detect new/mutated payloads or clones without hashing entire Git packs."""
    digest = hashlib.sha256()
    entries = []
    count = 0
    metadata_bytes = 0
    prefix = _inventory_prefix(upstream)
    for top in ("out", "git_clones", "hg_clones"):
        directory = upstream / top
        require(not directory.is_symlink(), "unsafe_runtime_tree")
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            count += 1
            require(count <= 1000000, "runtime_inventory_limit")
            if deadline is not None:
                deadline.remaining()
            relative = _inventory_relative(path, upstream, prefix)
            if relative == "out/firefox/mozconfig":
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                require(top in ("git_clones", "hg_clones"), "unsafe_runtime_tree")
                value = (relative, "symlink", os.readlink(path), info.st_ino, info.st_mtime_ns)
                entries.append((relative, hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).digest()))
                continue
            if stat.S_ISREG(info.st_mode):
                # Git index/HEAD/refs can legitimately be rewritten byte-identically.
                if "/.git/" in relative and not relative.endswith((".pack", ".idx")):
                    require(info.st_size <= 128 * 1024 * 1024, "git_metadata_limit")
                    metadata_hash = hashlib.sha256()
                    with path.open("rb") as stream:
                        while True:
                            if deadline is not None: deadline.remaining()
                            data = stream.read(1024 * 1024)
                            if not data: break
                            metadata_hash.update(data)
                            metadata_bytes += len(data)
                    value = (relative, info.st_size, metadata_hash.hexdigest())
                else:
                    value = (relative, info.st_size, info.st_ino, info.st_mtime_ns, info.st_nlink)
                entries.append((relative, hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).digest()))
            elif stat.S_ISDIR(info.st_mode):
                if top in ("git_clones", "hg_clones"):
                    entries.append((relative, hashlib.sha256(json.dumps((relative, "directory")).encode()).digest()))
            else:
                raise GateError("unsafe_runtime_tree")
    for _relative, item in sorted(entries):
        digest.update(item)
    progress_counters(deadline, inventory_entries=count, git_metadata_bytes=metadata_bytes)
    return digest.hexdigest()


def descriptor(data):
    require(isinstance(data, dict) and isinstance(data.get("sha256"), str)
            and HEX64.fullmatch(data["sha256"]) and type(data.get("size")) is int and data["size"] > 0,
            "invalid_archive_descriptor")
    return {"sha256": data["sha256"], "size": data["size"]}


def load_inputs(args):
    rust_raw = read_regular(args.rust_identity)
    rust = strict_json(rust_raw)
    node_raw = read_regular(args.node_support_directory / "node-identity.json")
    provenance_raw = read_regular(args.provenance)
    registry_raw = read_regular(args.node_support_directory / "registry/registry-node.json")
    support_raw = read_regular(args.node_support_directory / "node-support.json")
    node = strict_json(node_raw)
    provenance = strict_json(provenance_raw)
    registry = strict_json(registry_raw)
    support = strict_json(support_raw)
    require(isinstance(rust, dict) and isinstance(node, dict) and isinstance(provenance, dict), "invalid_input_object")
    pretty = (json.dumps(rust, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(rust_raw == pretty and hashlib.sha256(rust_raw).hexdigest() == EXPECTED_RUST_SHA,
            "rust_complete_identity_mismatch")
    require(canonical_sha(node) == EXPECTED_NODE_SHA, "node_complete_identity_mismatch")
    require(rust.get("schema") == 1 and rust.get("kind") == "firefox-cross-pgo-rust"
            and rust.get("upstream") == LOCK and node.get("upstream") == LOCK,
            "identity_upstream_mismatch")
    require(rust.get("rust", {}).get("rbm_target") == ",".join(TARGETS)
            and rust["rust"].get("profiler_targets") == ["x86_64-pc-windows-gnullvm"]
            and rust["rust"].get("std_targets") == ["x86_64-pc-windows-gnullvm", "i686-pc-windows-gnullvm"],
            "rust_target_mismatch")
    require(node.get("compiler_inputs") == [] and node.get("targets") == list(TARGETS[:2])
            and node.get("rbm_gitlink") == RBM_COMMIT and node.get("container", {}).get("suite") == "trixie"
            and node["container"].get("arch") == "amd64", "node_scope_mismatch")
    require(provenance.get("schema") == 2 and provenance.get("upstream_lock") == LOCK
            and provenance.get("pgo_rust_identity") == rust
            and provenance.get("rust_pgo_identity_sha256") == EXPECTED_RUST_SHA,
            "provenance_rust_mismatch")
    require(provenance.get("pgo_languages") == ["c++", "rust"]
            and provenance.get("generation_targets") == list(TARGETS)
            and provenance.get("generation_configure_flags") == ["--enable-profile-generate=cross"]
            and provenance.get("browser_executable") == "mullvadbrowser.exe", "generation_scope_mismatch")
    require(provenance.get("pgo_overlay_sha256") == rust["overlay"]["sha256"], "provenance_overlay_mismatch")
    firefox, server = provenance.get("firefox"), provenance.get("profileserver")
    require(isinstance(firefox, dict) and isinstance(server, dict)
            and isinstance(firefox.get("revision"), str) and HEX40.fullmatch(firefox["revision"])
            and server.get("revision") == firefox["revision"] and server.get("path") == "build/pgo/profileserver.py"
            and isinstance(server.get("sha256"), str) and HEX64.fullmatch(server["sha256"]), "invalid_source_binding")
    toolchains = provenance.get("toolchains")
    require(isinstance(toolchains, dict) and set(toolchains) == {"clang", "rust"}, "invalid_toolchain_binding")
    archives = {}
    for name, project in (("clang", "mingw-w64-clang"), ("rust", "rust")):
        item = toolchains[name]
        require(isinstance(item, dict) and set(item) == {"archive_filename", "sha256", "size", "version"}
                and isinstance(item["archive_filename"], str) and SAFE_NAME.fullmatch(item["archive_filename"])
                and isinstance(item["version"], str) and item["version"]
                and provenance.get(name + "_identity") == item["version"], "invalid_toolchain_binding")
        archives["out/" + project + "/" + item["archive_filename"]] = descriptor(item)
    require(toolchains["rust"]["archive_filename"] == rust["rust"]["output_filename"], "rust_archive_selection_mismatch")
    mingw = rust.get("mingw_w64_clang")
    require(isinstance(mingw, list) and len(mingw) == 1 and isinstance(mingw[0], dict)
            and mingw[0].get("path") == "out/mingw-w64-clang/" + toolchains["clang"]["archive_filename"]
            and descriptor(mingw[0]) == descriptor(toolchains["clang"]), "clang_archive_selection_mismatch")
    build_support = provenance.get("build_support")
    require(isinstance(build_support, dict) and set(build_support) == {"node"}, "invalid_node_provenance")
    record = build_support["node"]
    require(isinstance(record, dict) and set(record) == {"identity_sha256", "archive_filename", "sha256", "size"}
            and record["identity_sha256"] == EXPECTED_NODE_SHA and record["archive_filename"] == node["output_filename"],
            "node_archive_selection_mismatch")
    require(support == {"release": "pgo-support-" + LOCK["tag"] + "-" + EXPECTED_NODE_SHA, **record}, "node_support_record_mismatch")
    require(isinstance(registry, dict) and type(registry.get("schema")) is int
            and registry["schema"] == 1 and registry.get("stage") == "node"
            and registry.get("identity") == node and registry.get("upstream") == LOCK, "node_registry_identity_mismatch")
    artifacts = registry.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == 1 and isinstance(artifacts[0], dict), "node_registry_archive_mismatch")
    artifact = artifacts[0]
    require(artifact.get("path") == "out/node/" + record["archive_filename"] and artifact.get("project") == "node"
            and artifact.get("filename") == record["archive_filename"] and descriptor(artifact) == descriptor(record),
            "node_registry_archive_mismatch")
    archives["out/node/" + record["archive_filename"]] = descriptor(record)
    return {"rust": rust, "rust_raw": rust_raw, "node": node, "provenance": provenance,
            "provenance_path": args.provenance, "archives": archives,
            "immutable_input_bytes": {"node": node_raw, "provenance": provenance_raw,
                                      "registry": registry_raw, "support": support_raw}}


def archive_records(upstream, inputs, deadline):
    records = {name: sha_file(upstream / name, deadline) for name in sorted(inputs["archives"])}
    require(records == inputs["archives"], "restored_archive_bytes_mismatch")
    progress_counters(deadline, archive_count=len(records), archive_bytes=sum(item["size"] for item in records.values()))
    return records


def archive_boundary_records(upstream, inputs, registries, deadline):
    """One fresh raw union pass; derive the required subset at this same boundary."""
    for path in set(registries["archives"]) & set(inputs["archives"]):
        require(registries["archives"][path] == inputs["archives"][path], "conflicting_restored_archive_binding")
    union = {**registries["archives"], **inputs["archives"]}
    restored = archive_records(upstream, {**inputs, "archives": union}, deadline)
    required = {path: restored[path] for path in sorted(inputs["archives"])}
    require(required == inputs["archives"], "restored_archive_bytes_mismatch")
    return {"required": required, "restored": restored}


def relative_name(value):
    return isinstance(value, str) and len(value) <= 1024 and bool(value) and all(
        SAFE_NAME.fullmatch(part) and part not in (".", "..") for part in value.split("/"))


def registry_records(environment, inputs=None):
    """Read the real general restore registries. Do not create cache bindings."""
    base = safe_path(Path(environment.get("RUNNER_TEMP", "/tmp")) / "rbm-registry")
    if not base.exists():
        return {"archives": {}, "bytes": {}}
    require(base.is_dir() and base.stat().st_uid == os.getuid(), "unsafe_registry_directory")
    records, raw_files = {}, {}
    paths = sorted(base.glob("registry-*.json"))
    require(len(paths) <= 64, "registry_limit")
    for path in paths:
        raw = read_regular(path)
        data = strict_json(raw)
        require(isinstance(data, dict) and type(data.get("schema")) is int and data["schema"] == 1
                and isinstance(data.get("stage"), str) and SAFE_NAME.fullmatch(data["stage"])
                and path.name == "registry-" + data["stage"] + ".json" and data.get("upstream") == LOCK,
                "general_registry_binding_mismatch")
        expected = inputs["rust"] if inputs is not None and data["stage"] == "rust-pgo" else {"upstream": LOCK}
        require(data.get("identity", {"upstream": LOCK}) == expected, "general_registry_binding_mismatch")
        artifacts = data.get("artifacts")
        require(isinstance(artifacts, list) and 0 < len(artifacts) <= 4096, "invalid_registry_artifacts")
        seen, assets = set(), set()
        for item in artifacts:
            require(isinstance(item, dict) and relative_name(item.get("path")), "invalid_registry_artifact")
            parts = item["path"].split("/")
            require(len(parts) >= 3 and parts[0] == "out" and item.get("filename") == parts[-1]
                    and item.get("project", parts[1]) == parts[1] and relative_name(item.get("asset"))
                    and "/" not in item["asset"] and item["path"] not in seen and item["asset"] not in assets,
                    "invalid_registry_artifact")
            record = descriptor(item)
            require(item["path"] not in records or records[item["path"]] == record, "conflicting_registry_artifact")
            records[item["path"]] = record
            seen.add(item["path"]); assets.add(item["asset"])
        raw_files[path.name] = raw
    return {"archives": records, "bytes": raw_files}


def validate_selected_inputs(upstream, selected, inputs, registries, deadline):
    """Bind metadata-needed files and present restored inputs, not future builds."""
    require(isinstance(selected, list) and 0 < len(selected) <= 256, "invalid_selected_inputs")
    bound = {**registries["archives"], **inputs["archives"]}
    records, seen = [], set()
    for item in selected:
        require(isinstance(item, dict) and set(item) == {"filename", "path", "kind", "project", "id", "checksums"}
                and relative_name(item["filename"]) and isinstance(item["path"], str)
                and len(item["path"]) <= 4096 and isinstance(item["id"], str) and 0 < len(item["id"]) <= 2048
                and item["kind"] in ("project", "url", "file", "content") and isinstance(item["project"], str)
                and (SAFE_NAME.fullmatch(item["project"]) if item["kind"] == "project" else item["project"] == "")
                and isinstance(item["checksums"], dict) and set(item["checksums"]) <= {"sha256sum", "sha512sum"},
                "invalid_selected_inputs")
        if not item["path"]:
            require(item["kind"] in ("project", "url") and (item["kind"] == "project" or item["checksums"]),
                    "missing_metadata_input")
            for algorithm, expected in item["checksums"].items():
                length = 64 if algorithm == "sha256sum" else 128
                require(isinstance(expected, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", expected),
                        "invalid_selected_checksum")
            continue
        path = safe_path(item["path"])
        require(path.is_absolute() and str(path) == item["path"] and upstream in path.parents,
                "selected_input_escape")
        relative = path.relative_to(upstream).as_posix()
        require(relative_name(relative) and relative.endswith("/" + item["filename"])
                and relative not in seen, "ambiguous_selected_inputs")
        seen.add(relative)
        if item["kind"] == "content":
            require(item["filename"] == "mozconfig" and relative == "out/firefox/mozconfig"
                    and not item["checksums"], "unexpected_generated_input")
            continue
        actual = sha_file(path, deadline)
        if item["kind"] == "project":
            require(relative.startswith("out/" + item["project"] + "/"), "unexpected_selected_archive")
            if relative in bound:
                require(actual == bound[relative], "selected_restored_archive_mismatch")
        elif item["kind"] == "url":
            require(item["checksums"], "unbound_selected_url")
        else:
            require(relative.startswith(("projects/", "keyring/")), "unbound_selected_file")
        for algorithm, expected in item["checksums"].items():
            length = 64 if algorithm == "sha256sum" else 128
            require(isinstance(expected, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", expected),
                    "invalid_selected_checksum")
            if algorithm == "sha256sum":
                value = actual["sha256"]
            else:
                digest = hashlib.sha512()
                with path.open("rb") as stream:
                    while True:
                        deadline.remaining()
                        data = stream.read(1024 * 1024)
                        if not data: break
                        digest.update(data)
                value = digest.hexdigest()
            require(value == expected, "selected_checksum_mismatch")
        records.append({"path": relative, "kind": item["kind"], "project": item["project"], **actual})
    require(all(path in seen for path in inputs["archives"]), "selected_required_archive_missing")
    progress_counters(deadline, selected_archive_count=len(records),
                      selected_archive_bytes=sum(item["size"] for item in records))
    return records


def normalize_rendered(text, count, kind):
    """Erase only exact pinned resource slots, retaining every other byte."""
    require(isinstance(text, str) and len(text.encode()) <= MAX_RENDER
            and type(count) is int and count in (1, 2, 4), "render_limit")
    require(kind in ("mozconfig", "build") and "\r" not in text and "\x00" not in text,
            "invalid_render")
    lines = text.splitlines(keepends=True)
    positions = {"parallel": [], "xz": [], "zstd": [], "pack": []}
    compression = max(count, 2)
    for index, line in enumerate(lines):
        if "MOZ_PARALLEL_BUILD" in line:
            require(kind == "mozconfig" and line == f"mk_add_options MOZ_PARALLEL_BUILD={count}\n",
                    "operational_parallel_mismatch")
            positions["parallel"].append(index)
            lines[index] = "mk_add_options MOZ_PARALLEL_BUILD=<RESOURCE>\n"
        if kind != "build":
            continue
        # These are the literal YAML-template indentation choices in the pin.
        if "XZ_DEFAULTS" in line:
            match = re.fullmatch(r'(export|    export) XZ_DEFAULTS="-T([124])"\n', line)
            require(match is not None and int(match[2]) == compression, "compression_resource_mismatch")
            positions["xz"].append(index)
            lines[index] = match[1] + ' XZ_DEFAULTS="-T<RESOURCE>"\n'
        if "ZSTD_NBTHREADS" in line:
            match = re.fullmatch(r'(export|  export|    export) ZSTD_NBTHREADS=([124])\n', line)
            require(match is not None and int(match[2]) == compression, "compression_resource_mismatch")
            positions["zstd"].append(index)
            lines[index] = match[1] + " ZSTD_NBTHREADS=<RESOURCE>\n"
        if line.startswith("xz --threads="):
            # The exact optional projects/firefox/config src-tarballs argv slot.
            match = re.fullmatch(r"xz --threads=([124]) -f '(firefox-[A-Za-z0-9._+-]+\.tar)'\n", line)
            require(match is not None and int(match[1]) == compression, "pack_resource_mismatch")
            positions["pack"].append(index)
            lines[index] = "xz --threads=<RESOURCE> -f '" + match[2] + "'\n"
    if kind == "mozconfig":
        require(len(positions["parallel"]) == 1, "parallel_resource_position_mismatch")
    else:
        require(not positions["parallel"] and len(positions["xz"]) == 1
                and len(positions["zstd"]) == 1 and len(positions["pack"]) <= 1,
                "compression_resource_position_mismatch")
        configure = [i for i, line in enumerate(lines) if line.startswith("./mach configure")]
        require(len(configure) == 1 and positions["xz"][0] < positions["zstd"][0] < configure[0]
                and (not positions["pack"] or configure[0] < positions["pack"][0]),
                "compression_resource_position_mismatch")
    return "".join(lines)


def offline(command, cpus, upstream, environment, deadline, parent_namespace):
    raw = checked([sys.executable, "-c", MASK_CODE, json.dumps(cpus), str(upstream / "rbm/container"),
                   "run", "--disable-network", "--", sys.executable, "-c", NS_CODE, *command],
                  cwd=upstream, environment=environment, deadline=deadline)
    first, separator, rest = raw.partition(b"\n")
    require(separator and first.startswith(b"PGO_RESOURCE_NS "), "missing_namespace_evidence")
    record = strict_json(first[len(b"PGO_RESOURCE_NS "):], max_bytes=8192)
    require(isinstance(record, dict) and set(record) == {"affinity", "network_namespace"}
            and record["affinity"] == cpus and all(type(cpu) is int for cpu in record["affinity"])
            and isinstance(record["network_namespace"], str) and re.fullmatch(r"net:\[[0-9]{1,20}\]", record["network_namespace"])
            and record["network_namespace"] != parent_namespace, "invalid_namespace_evidence")
    return rest


def showconf(upstream, project, key, targets, cpus, environment, deadline, namespace):
    command = perl_command(upstream, project, key, targets)
    try:
        return offline(command, cpus, upstream, environment, deadline, namespace).decode("utf-8").strip()
    except UnicodeError:
        raise GateError("invalid_metadata_output") from None


def filename_records(upstream, cpus, inputs, environment, deadline, namespace):
    result = {}
    for label, project, targets, operation in (
            ("firefox", "firefox", TARGETS, "filename_firefox"),
            ("rust-profiler", "rust", TARGETS, "filename_rust_profiler"),
            ("rust-official", "rust", TARGETS[:2], "filename_rust_official"),
            ("mingw", "mingw-w64-clang", TARGETS, "filename_mingw"),
            ("node", "node", TARGETS[:2], "filename_node")):
        with progress_operation(deadline, operation):
            name = showconf(upstream, project, "filename", targets, cpus, environment, deadline, namespace)
        require(bool(SAFE_NAME.fullmatch(name)), "invalid_selected_filename")
        result[label] = name
    require(result["rust-profiler"] == inputs["rust"]["rust"]["output_filename"]
            and result["rust-official"] == inputs["rust"]["rust"]["official_output_filename"]
            and result["mingw"] == Path(inputs["rust"]["mingw_w64_clang"][0]["path"]).name
            and result["node"] == inputs["node"]["output_filename"], "selected_identity_filename_mismatch")
    for key, expected, operation in (
            ("git_url", inputs["provenance"]["firefox"]["repository"], "firefox_repository"),
            ("git_hash", inputs["provenance"]["firefox"]["ref"], "firefox_ref"),
            ("var/git_commit", inputs["provenance"]["firefox"]["revision"], "firefox_commit"),
            ("var/exe_name", "mullvadbrowser", "firefox_executable")):
        with progress_operation(deadline, operation):
            require(showconf(upstream, "firefox", key, TARGETS, cpus, environment, deadline, namespace) == expected,
                    "selected_source_scope_mismatch")
    # Every named input is selected by the actual RBM metadata API, never a static list.
    with progress_operation(deadline, "named_inputs"):
        raw = offline(perl_command(upstream, "firefox", "", TARGETS, "named"),
                      cpus, upstream, environment, deadline, namespace)
    selected = strict_json(raw)
    require(isinstance(selected, dict) and set(selected) == {"named", "selected_inputs"}, "invalid_named_inputs")
    named = selected["named"]
    require(isinstance(named, dict) and named and len(named) <= 64
            and all(isinstance(key, str) and SAFE_NAME.fullmatch(key) and relative_name(value)
                    for key, value in named.items()), "invalid_named_inputs")
    result["selected_inputs"] = selected["selected_inputs"]
    require(named.get("rust") == result["rust-profiler"] and named.get("node") == result["node"]
            and named.get("mingw-w64-clang") == result["mingw"], "named_compiler_selection_mismatch")
    result["named"] = named
    return result


# A fresh actual native RBM interpreter owns each query. The scoped changes
# deny cold side effects; they do not replace an identity/template/resource value.
NATIVE_GUARD_CODE = r"""
use strict; use warnings; use Cwd qw(abs_path getcwd); use File::Spec;
use JSON::PP; use YAML::XS; no warnings 'once'; no warnings 'redefine';
my $_orig_proc = \&RBM::process_template;
*RBM::process_template = sub {
    my ($p, $tmpl, $dest) = @_;
    return $tmpl if defined($tmpl) && !ref($tmpl) && index($tmpl, '[%') == -1;
    return $_orig_proc->(@_);
};
sub reject { die "warm_metadata_required\n"; }
$ENV{GIT_NO_REPLACE_OBJECTS} = '1';
my ($upstream, $project, $key, $targets_json, $action) = @ARGV;
my $cache_file;
if (!$ENV{POLICY_PERL_CONFIG}) {
    require Digest::SHA;
    require File::Path;
    my $cache_dir = '/tmp/.pgo_metadata_cache';
    File::Path::make_path($cache_dir);
    my $cache_key = Digest::SHA::sha256_hex("$upstream\0$project\0$key\0$targets_json\0$action");
    $cache_file = "$cache_dir/$cache_key";
    if (-f $cache_file) {
        open(my $cfh, '<', $cache_file);
        if ($cfh) {
            my $cached = do { local $/; <$cfh> };
            close($cfh);
            print $cached;
            exit 0;
        }
    }
}
my $targets = JSON::PP->new->decode($targets_json);
my @selected; our ($active_project, $active_action);
my $original_git = \&RBM::git_clone_fetch_chdir;
my $original_inputs = \&RBM::input_files;
my $original_id = \&RBM::input_file_id;
my $original_script = \&RBM::run_script;
sub git_value {
    my (@args) = @_;
    my ($stdout, $stderr, $success) = RBM::capture_exec('git', '--no-replace-objects',
        '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', @args);
    reject() unless $success;
    chomp $stdout; return $stdout;
}
local *RBM::git_clone_fetch_chdir = sub {
    my ($p, $options) = @_;
    my $root = RBM::rbm_path(RBM::project_config($p, 'git_clone_dir', $options));
    my $clone = File::Spec->catdir($root, $p);
    reject() unless -d $clone && !-l $clone;
    my $cwd = getcwd(); chdir($clone) or reject();
    my $real = abs_path($clone); reject() unless defined($real) && $real eq $clone;
    reject() unless git_value('rev-parse', '--show-toplevel') eq $real;
    my $graft = git_value('rev-parse', '--path-format=absolute', '--git-path', 'info/grafts');
    reject() if -e $graft || -l $graft;
    reject() if length git_value('for-each-ref', '--format=%(refname)', 'refs/replace/');
    my $expected_url = RBM::project_config($p, 'git_url', $options);
    reject() unless git_value('remote', 'get-url', 'origin') eq $expected_url;
    my $ref = RBM::project_config($p, 'git_hash', $options);
    reject() unless defined($ref) && length($ref);
    my $revision = git_value('rev-parse', '--verify', "$ref\^{commit}");
    reject() unless $revision =~ /^[0-9a-f]{40}$/;
    my $head = git_value('rev-parse', '--verify', 'HEAD'); reject() unless $head =~ /^[0-9a-f]{40}$/;
    # Native execute can issue checkout even for an already selected revision.
    # Its hooks/config must not inject a download or compiler command.
    for my $name ('core.hooksPath','core.fsmonitor') {
        my ($value, undef, $success) = RBM::capture_exec('git','config','--get',$name);
        reject() if $success && length($value);
    }
    my $hooks = git_value('rev-parse','--path-format=absolute','--git-path','hooks');
    if (-d $hooks) {
        opendir(my $dh, $hooks) or reject();
        my @entries = grep { $_ ne '.' && $_ ne '..' && $_ !~ /\.sample$/ } readdir($dh);
        closedir($dh) or reject(); reject() if @entries;
    }
    reject() if RBM::git_need_fetch($p, $options);
    chdir($cwd) or reject(); return $original_git->(@_);
};
local *RBM::git_submodule_init_sync_update = sub { reject(); };
local *RBM::hg_clone_fetch_chdir = sub { reject(); };
local *RBM::urlget = sub { reject(); };
local *RBM::build_pkg = sub { reject(); };
local *RBM::build_run = sub { reject(); };
local *RBM::run_script = sub {
    # Native metadata execute captures stdout. Generic artifact creation passes
    # a system callback instead; it is forbidden even if an exec input is cold.
    reject() unless defined($_[2]) && $_[2] == \&RBM::capture_exec;
    return $original_script->(@_);
};
local *RBM::input_files = sub {
    reject() unless $_[0] eq 'getfnames' || $_[0] eq 'getfids' || $_[0] eq 'input_files_id';
    local $active_project = $_[1]; local $active_action = $_[0];
    return $original_inputs->(@_);
};
local *RBM::input_file_id = sub {
    my ($input, $t, $fname, $filename) = @_;
    my $id = $original_id->(@_);
    if (defined($active_project) && $active_project eq 'firefox'
            && defined($active_action) && $active_action eq 'input_files_id') {
        my $kind = $input->{content} ? 'content' : $input->{exec} ? 'exec'
                      : $input->{project} ? 'project' : $input->{URL} ? 'url' : 'file';
        reject() if $kind eq 'exec';
        # Project archives and checksum-bearing URL payloads are not needed to
        # compute their native metadata IDs. Unbuilt dependencies are allowed.
        reject() if defined($fname) && (!-f $fname || -l $fname);
        reject() if !defined($fname) && $kind ne 'project' && $kind ne 'url';
        my %checksums;
        for my $checksum ('sha256sum','sha512sum') {
            my $value = $t->($checksum); $checksums{$checksum} = $value if $value;
        }
        my $path = defined($fname) ? abs_path($fname) : '';
        reject() if defined($fname) && !defined($path);
        push @selected, {filename => $filename, path => $path, kind => $kind,
          project => $input->{project} ? $t->('project') : '', id => $id,
          checksums => \%checksums};
    }
    return $id;
};
RBM::load_config("$upstream/rbm.conf");
$RBM::config->{rbmdir} = "$upstream/rbm";
RBM::set_default_env();
$RBM::config->{run}{target} = $targets;
RBM::load_system_config($project); RBM::load_local_config($project); RBM::load_modules_config($project);
$RBM::config->{step} = $action eq 'named' ? 'build' : RBM::project_config($project,'pkg_type');
$RBM::config->{run}{args} = $action eq 'named' ? [] : [$key];
RBM::valid_project($project);
if ($action eq 'named') {
    # The pinned filename evaluates var/build_id's native num_procs=>4 scope.
    # Observe that exact evaluation; do not rerun raw input_files_id at 2/1.
    my $filename = RBM::project_config($project, 'filename', {pkg_type => 'build'});
    reject() unless defined($filename) && !ref($filename) && @selected;
    my $names = RBM::input_files('getfnames', $project, {pkg_type => 'build'});
    reject() unless ref($names) eq 'HASH'; my %values;
    for my $name (sort keys %$names) {
        next if $name =~ /^noname_[0-9]+$/;
        reject() unless ref($names->{$name}) eq 'CODE';
        $values{$name} = $names->{$name}->($project, {pkg_type => 'build'});
        reject() unless defined($values{$name}) && !ref($values{$name});
    }
    my $rendered = JSON::PP->new->canonical->ascii->encode({named => \%values, selected_inputs => \@selected}) . "\n";
    if (defined($cache_file)) {
        open(my $wfh, '>', $cache_file);
        if ($wfh) { print $wfh $rendered; close($wfh); }
    }
    print $rendered;
} elsif ($action eq 'showconf') {
    my $value = RBM::project_config($project, $key);
    RBM::exit_error('Undefined') unless defined($value);
    my $rendered = ref($value) ? YAML::XS::Dump($value) : "$value\n";
    if (defined($cache_file)) {
        open(my $wfh, '>', $cache_file);
        if ($wfh) { print $wfh $rendered; close($wfh); }
    }
    print $rendered;
} else { reject(); }
"""
# Kept as an inspectable named-query implementation, not a second initializer.
NAMED_CODE = NATIVE_GUARD_CODE


def perl_command(upstream, project, key, targets, action="showconf"):
    require(action in ("showconf", "named") and bool(SAFE_NAME.fullmatch(project))
            and isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_/-]{0,160}", key)
            and tuple(targets) in (TARGETS, TARGETS[:2]), "invalid_metadata_query")
    return ["perl", "-I", str(upstream / "rbm/lib"), "-MRBM", "-e", NATIVE_GUARD_CODE,
            str(upstream), project, key, json.dumps(list(targets)), action]


# Run the byte-identical protected resolvers. Only their metadata transport is
# replaced with the guarded actual API above. Serialization and every field are
# still generated by their original source. No rbm_network retry code is entered.
RESOLVER_CODE = r"""
import importlib.util, os, runpy, selectors, subprocess, sys, time, types
from pathlib import Path
validator, resolver, *arguments = sys.argv[1:]
spec = importlib.util.spec_from_file_location('private_pgo_policy', validator)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
os.environ['GIT_NO_REPLACE_OBJECTS'] = '1'
expires = time.monotonic() + 40
def guarded_showconf(upstream, project, key, targets, *, raw_output=False, **kwargs):
    if kwargs:
        raise module.GateError('invalid_resolver_metadata_options')
    command = module.perl_command(Path(upstream), project, key, targets)
    # All nested children inherit the outer owned offline session. They must not
    # create a detached session that could survive the outer 45-second deadline.
    process = subprocess.Popen(command, cwd=upstream, env=dict(os.environ), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    stdout, stderr = bytearray(), bytearray()
    selector = selectors.DefaultSelector()
    try:
        for stream, target in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, target)
        while selector.get_map():
            remaining = expires - time.monotonic()
            if remaining <= 0:
                raise module.GateError('resolver_metadata_deadline')
            for event, _mask in selector.select(min(remaining, 0.05)):
                data = os.read(event.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(event.fileobj); event.fileobj.close(); continue
                event.data.extend(data)
                if len(stdout) + len(stderr) > module.MAX_RENDER:
                    raise module.GateError('native_output_limit')
        remaining = expires - time.monotonic()
        if remaining <= 0:
            raise module.GateError('resolver_metadata_deadline')
        status = process.wait(timeout=remaining)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill(); process.wait()
        for stream in (process.stdout, process.stderr):
            stream.close()
    stdout, stderr = bytes(stdout), bytes(stderr)
    if status:
        if status == 1 and not stdout.strip() and stderr.strip() == b'Error: Undefined':
            raise subprocess.CalledProcessError(1, command, output='', stderr='Error: Undefined')
        raise module.GateError('guarded_metadata_nonzero')
    return stdout if raw_output else stdout.decode('utf-8').strip()
transport = types.ModuleType('rbm_network'); transport.showconf = guarded_showconf
sys.modules['rbm_network'] = transport
sys.argv = [resolver, *arguments]
runpy.run_path(resolver, run_name='__main__')
"""


def execute_case(args, cpus, count, inputs, environment, deadline, namespace, case):
    directory = case / "native"
    directory.mkdir()
    rust_path, node_path = directory / "rust.json", directory / "node.json"
    with progress_operation(deadline, "rust_identity"):
        offline([sys.executable, "-c", RESOLVER_CODE, str(Path(__file__).resolve()),
                 str(ROOT / "scripts/resolve-pgo-rust-identity.py"), "--upstream", str(args.upstream),
                 "--output", str(rust_path)], cpus, args.upstream, environment, deadline, namespace)
    rust_raw = read_regular(rust_path)
    require(rust_raw == inputs["rust_raw"] and strict_json(rust_raw) == inputs["rust"], "regenerated_rust_identity_mismatch")
    with progress_operation(deadline, "node_identity"):
        offline([sys.executable, "-c", RESOLVER_CODE, str(Path(__file__).resolve()),
                 str(ROOT / "scripts/resolve-pgo-support-identity.py"), "--upstream", str(args.upstream),
                 "--output", str(node_path)], cpus, args.upstream, environment, deadline, namespace)
    node = strict_json(read_regular(node_path))
    require(node == inputs["node"] and canonical_sha(node) == EXPECTED_NODE_SHA, "regenerated_node_identity_mismatch")
    filenames = filename_records(args.upstream, cpus, inputs, environment, deadline, namespace)
    render = directory / "render"
    with progress_operation(deadline, "renderer"):
        offline(["perl", str(ROOT / "scripts/render-pgo-resource-metadata.pl"), "--upstream", str(args.upstream),
                 "--output-directory", str(render)], cpus, args.upstream, environment, deadline, namespace)
    metadata = strict_json(read_regular(render / "metadata.json"))
    require(isinstance(metadata, dict) and set(metadata) == {"schema", "num_procs", "logical_cpu_count", "affinity",
            "path_tiny_version", "path_tiny_source_sha256", "atomic_spew_hardlink_verified"} and type(metadata["schema"]) is int and metadata["schema"] == 1
            and type(metadata["num_procs"]) is int and metadata["num_procs"] == count and metadata["affinity"] == cpus
            and all(type(cpu) is int for cpu in metadata["affinity"])
            and type(metadata["logical_cpu_count"]) is int and len(cpus) <= metadata["logical_cpu_count"] <= 1048576
            and isinstance(metadata["path_tiny_version"], str) and len(metadata["path_tiny_version"]) <= 32
            and re.fullmatch(r"[0-9]+\.[0-9]+(?:_[0-9]+)?", metadata["path_tiny_version"])
            and isinstance(metadata["path_tiny_source_sha256"], str)
            and HEX64.fullmatch(metadata["path_tiny_source_sha256"])
            and metadata["atomic_spew_hardlink_verified"] is True, "invalid_renderer_metadata")
    try:
        moz = read_regular(render / "mozconfig.operational", MAX_RENDER).decode("utf-8")
        build = read_regular(render / "firefox-build.operational", MAX_RENDER).decode("utf-8")
    except UnicodeError:
        raise GateError("invalid_render") from None
    require(build.count("--enable-profile-generate=cross") == 1 and "--enable-profile-use" not in build
            and "./mach configure" in build and "./mach build --verbose" in build, "generation_configure_render_mismatch")
    normalized = {"mozconfig": normalize_rendered(moz, count, "mozconfig"),
                  "build": normalize_rendered(build, count, "build")}
    return {"metadata": metadata, "filenames": filenames, "normalized": normalized, "mozconfig": moz, "build": build}


def binding(environment, upstream):
    values = {key: environment.get(name) for key, name in (("head", "GITHUB_SHA"), ("run", "GITHUB_RUN_ID"),
              ("attempt", "GITHUB_RUN_ATTEMPT"), ("job", "GITHUB_JOB"))}
    require(isinstance(values["head"], str) and HEX40.fullmatch(values["head"]), "invalid_run_binding")
    require(all(isinstance(values[key], str) and re.fullmatch(r"[1-9][0-9]{0,19}", values[key])
                for key in ("run", "attempt")), "invalid_run_binding")
    require(isinstance(values["job"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", values["job"]), "invalid_run_binding")
    return {**values, "upstream": str(upstream)}


def validate(args, *, environment=None):
    environment = dict(os.environ if environment is None else environment)
    deadline = Deadline(TOTAL_SECONDS)
    args.upstream = safe_path(args.upstream)
    args.rust_identity = safe_path(args.rust_identity)
    args.node_support_directory = safe_path(args.node_support_directory)
    args.provenance = safe_path(args.provenance)
    args.output = safe_path(args.output)
    args.diagnostic_directory = safe_path(args.diagnostic_directory)
    require(args.upstream.is_dir() and not os.path.lexists(args.output), "unsafe_or_existing_policy")
    for path in (args.output, args.diagnostic_directory):
        require(path != args.upstream and args.upstream not in path.parents and path not in args.upstream.parents,
                "overlapping_policy_paths")
    require(args.output != args.diagnostic_directory and args.diagnostic_directory not in args.output.parents,
            "overlapping_policy_paths")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.diagnostic_directory.mkdir(parents=True, exist_ok=True)
    require(not any(args.diagnostic_directory.iterdir()) and args.diagnostic_directory.stat().st_uid == os.getuid(),
            "unsafe_diagnostic_directory")
    diagnostic = {"schema": 1, "scope": "warm offline metadata/source/restored-input gate only",
                  "status": "starting", "cases": [], "compiled_browser_verified": False,
                  "profile_training_verified": False}
    report_path = args.diagnostic_directory / "validation.json"
    atomic_json(report_path, diagnostic)
    parent = sorted(os.sched_getaffinity(0))
    original_presence = {key: key in environment for key in INFLUENCERS}
    policy = None
    try:
        progress = ProgressTrace(args.diagnostic_directory / "progress.json", deadline)
        with progress_phase(deadline, "preflight"):
            require(len(parent) == 4 and all(type(cpu) is int for cpu in parent), "expected_four_cpu_parent")
            require(not any(original_presence.values()), "uncontrolled_cpu_environment")
            require(not any(key in environment for key in ("PGO_TELEMETRY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")),
                    "unexpected_credential_environment")
            current_binding = binding(environment, args.upstream)
        with progress_phase(deadline, "inputs_before"):
            inputs = load_inputs(args)
        with progress_phase(deadline, "source_before"):
            before_sources = source_records(args.upstream, inputs, environment, deadline)
        with progress_phase(deadline, "registries_before"):
            before_registries = registry_records(environment, inputs)
            require({"registry-clang.json", "registry-mingw-w64-clang.json", "registry-rust.json",
                     "registry-rust-pgo.json"} <= set(before_registries["bytes"]), "missing_restored_compiler_registry")
        with progress_phase(deadline, "archives_before"):
            before_boundary = archive_boundary_records(args.upstream, inputs, before_registries, deadline)
            before_archives, before_restored = before_boundary["required"], before_boundary["restored"]
        with progress_phase(deadline, "inventory_before"):
            before_inventory = immutable_inventory(args.upstream, deadline)
        namespace = os.readlink("/proc/self/ns/net")
        baseline = None
        before_selected = None
        with tempfile.TemporaryDirectory(prefix=".private-native-", dir=args.diagnostic_directory) as private:
            for label, cpus in (("baseline", parent), ("selected-two", parent[:2]), ("one-metadata-only", parent[:1])):
                with progress_phase(deadline, "case_native", label):
                    deadline.remaining()
                    case = Path(private) / label
                    case.mkdir()
                    record = execute_case(args, cpus, len(cpus), inputs, environment, deadline, namespace, case)
                with progress_phase(deadline, "case_selected_inputs", label):
                    selected = validate_selected_inputs(args.upstream, record["filenames"].get("selected_inputs"),
                                                        inputs, before_registries, deadline)
                    if before_selected is None:
                        before_selected = selected
                    else:
                        require(selected == before_selected, "selected_input_bytes_changed")
                with progress_phase(deadline, "case_inventory", label):
                    require(immutable_inventory(args.upstream, deadline) == before_inventory, "unexpected_runtime_mutation")
                with progress_phase(deadline, "case_source", label):
                    require(source_records(args.upstream, inputs, environment, deadline) == before_sources, "source_changed")
                with progress_phase(deadline, "case_comparison", label):
                    if baseline is None:
                        baseline = record
                    else:
                        require(record["normalized"] == baseline["normalized"], "non_resource_render_change")
                        require(record["filenames"] == baseline["filenames"], "selected_filename_change")
                        require(record["metadata"]["logical_cpu_count"] == baseline["metadata"]["logical_cpu_count"]
                                and record["metadata"]["path_tiny_version"] == baseline["metadata"]["path_tiny_version"]
                                and record["metadata"]["path_tiny_source_sha256"] == baseline["metadata"]["path_tiny_source_sha256"],
                                "host_metadata_change")
                    generated = args.upstream / "out/firefox/mozconfig"
                    if os.path.lexists(generated):
                        require(read_regular(generated, MAX_RENDER).decode("utf-8") == baseline["mozconfig"],
                                "unexpected_generated_mozconfig")
                    diagnostic["cases"].append({"case": label, "metadata": record["metadata"],
                         "filenames": record["filenames"], "render_sha256": {
                         key: hashlib.sha256(record[key].encode()).hexdigest() for key in ("mozconfig", "build")}})
                    atomic_json(report_path, diagnostic)
        with progress_phase(deadline, "archives_after"):
            after_boundary = archive_boundary_records(args.upstream, inputs, before_registries, deadline)
            require(after_boundary["required"] == before_archives
                    and after_boundary["restored"] == before_restored, "archive_changed")
        with progress_phase(deadline, "inputs_after"):
            require(load_inputs(args) == inputs, "source_or_identity_changed")
        with progress_phase(deadline, "registries_after"):
            require(registry_records(environment, inputs) == before_registries, "source_or_identity_changed")
        with progress_phase(deadline, "source_after"):
            require(source_records(args.upstream, inputs, environment, deadline) == before_sources, "source_or_identity_changed")
        with progress_phase(deadline, "selected_inputs_after"):
            require(validate_selected_inputs(args.upstream, baseline["filenames"].get("selected_inputs"), inputs,
                                             before_registries, deadline) == before_selected, "selected_input_bytes_changed")
        with progress_phase(deadline, "inventory_after"):
            require(immutable_inventory(args.upstream, deadline) == before_inventory, "unexpected_runtime_mutation")
        with progress_phase(deadline, "parent_after"):
            require(sorted(os.sched_getaffinity(0)) == parent and {key: key in environment for key in INFLUENCERS}
                    == original_presence, "parent_policy_changed")
        with progress_phase(deadline, "final_report"):
            selected_count = 4 if len(parent) >= 4 else (2 if len(parent) >= 2 else 1)
            selected_cpus = parent[:selected_count]
            policy = {"schema": 1, "kind": "pgo-generation-resource-policy", "verified": True, "target": "pgo-generate",
                      "binding": current_binding, "upstream_lock": LOCK, "rbm_commit": RBM_COMMIT,
                      "parent_affinity": parent, "selected_affinity": selected_cpus, "expected_num_procs": selected_count,
                      "rust_identity_sha256": EXPECTED_RUST_SHA, "node_identity_sha256": EXPECTED_NODE_SHA}
            diagnostic["status"] = "verified-metadata-only"
            diagnostic["source_records_sha256"] = canonical_sha(before_sources)
            diagnostic["archive_records"] = before_restored
            diagnostic["selected_input_records"] = before_selected
            atomic_json(report_path, diagnostic)
        # This status is progress only. Keep all trace IO before the original
        # final global-deadline check and fail-closed atomic policy publication.
        progress.finish("finished")
        deadline.remaining()
        require(not os.path.lexists(args.output), "existing_policy")
        atomic_json(args.output, policy)
        return policy
    except (GateError, NATIVE.ProbeError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        code = str(error) if isinstance(error, (GateError, NATIVE.ProbeError)) else "validation_system_error"
        diagnostic["status"] = "failed"
        diagnostic["error"] = {"code": code}
        progress = getattr(deadline, "progress", None)
        if progress is not None:
            try:
                progress.finish("failed")
            except Exception:
                pass
        atomic_json(report_path, diagnostic)
        raise GateError(code) from None


class FixedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "PGO resource metadata arguments rejected.\n")


def main():
    parser = FixedArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("upstream", "rust-identity", "node-support-directory", "provenance", "output", "diagnostic-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    def cancel(_signal, _frame):
        raise GateError("validation_cancelled")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cancel)
    try:
        validate(args)
    except (GateError, OSError):
        print("PGO resource metadata validation failed; no execution policy was created.", file=sys.stderr)
        return 1
    print("PGO resource metadata policy verified only; native compiler/archive/profile proof remains separate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
