#!/usr/bin/env python3
"""Read-only exact-pinned RBM CPU authority probe, not a PGO/cache proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LOCK = {
    "repository": "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git",
    "tag": "mb-16.0a9-build1",
    "tag_object": "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721",
    "commit": "7dd751cf1837d667908b339aebf82567ece55e20",
}
RBM_COMMIT = "865f2c9842520958879665d5c9b820d9ed51761e"
RBM_REPOSITORY = "https://gitlab.torproject.org/tpo/applications/rbm.git"
GLOBAL_SECONDS = 178.0  # Leave two seconds for fixed-size report/cleanup work.
CALL_SECONDS = 12.0
MAX_OUTPUT = 256 * 1024
MAX_SOURCE = 256 * 1024
MAX_SOURCE_FILES = 32
INFLUENCERS = ("RBM_NUM_PROCS", "OMP_NUM_THREADS", "OMP_THREAD_LIMIT")
RUNTIME_PATHS = ("git_clones", "hg_clones", "out", "logs")
CASES = ("baseline", "controller-env-two", "affinity-two", "affinity-one")
DEFERRED = [
    "Capped filename / Rust610 / Nodef93 identity comparison with verified inputs",
    "Actual C++ and Rust PGO compiler flags and a completed instrumented archive",
    "Native training, positive both-language merge/use, packages and comparison",
]
MASK_CODE = r"""
import json, os, sys
cpus = json.loads(sys.argv[1])
allowed = os.sched_getaffinity(0)
if not cpus or not set(cpus).issubset(allowed):
    raise SystemExit(70)
os.sched_setaffinity(0, set(cpus))
os.execv(sys.argv[2], sys.argv[2:])
"""
# Print only fixed, public counts/presence, then exec the original native tool.
# The parent captures bounded output. No nested unbounded PIPE capture is used.
CHILD_CODE = r"""
import json, os, sys
keys = ("RBM_NUM_PROCS", "OMP_NUM_THREADS", "OMP_THREAD_LIMIT")
payload = {
    "affinity": sorted(os.sched_getaffinity(0)),
    "logical_cpu_count": os.cpu_count(),
    "influencer_presence": {key: key in os.environ for key in keys},
    "network_namespace": os.readlink("/proc/self/ns/net"),
}
print("RBM_RESOURCE_CHILD " + json.dumps(payload, sort_keys=True), flush=True)
if sys.argv[1] == "nproc":
    command = [sys.argv[2]]
elif sys.argv[1] == "num_procs":
    command = [sys.argv[2], "showconf", "firefox", "num_procs",
               "--target", "alpha", "--target", "mullvadbrowser-windows-x86_64"]
else:
    raise SystemExit(71)
os.execv(command[0], command)
"""


class ProbeError(Exception):
    """Fixed diagnostic code; never include captured native output or argv."""


class Deadline:
    def __init__(self, seconds=GLOBAL_SECONDS):
        self.end = time.monotonic() + seconds

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise ProbeError("global_deadline")
        return remaining


def run_native(command, *, cwd, environment, deadline, seconds=CALL_SECONDS):
    """Bound one owned session; retain its leader until descendant cleanup.

    waitid(WNOWAIT) avoids reaping/reusing the session-leader PID before killpg.
    Native stderr/argv are never printed or written into the public report.
    """
    end = time.monotonic() + min(seconds, deadline.remaining())
    try:
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        raise ProbeError("native_start_failed") from None
    selector = None
    stdout, stderr = bytearray(), bytearray()
    try:
        selector = selectors.DefaultSelector()
        for stream, buffer in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, buffer)
        exited = None
        while True:
            now = time.monotonic()
            if now >= end:
                raise ProbeError("native_deadline")
            for key, _ in selector.select(min(0.05, end - now)):
                try:
                    data = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(data)
                if len(stdout) + len(stderr) > MAX_OUTPUT:
                    raise ProbeError("native_output_limit")
            if exited is None:
                exited = os.waitid(os.P_PID, process.pid,
                                   os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not selector.get_map():
                break
    finally:
        # The unreaped leader still owns this private session/group identifier.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            raise ProbeError("native_cleanup_failed") from None
        if selector is not None:
            selector.close()
        process.stdout.close()
        process.stderr.close()
    return process.returncode, bytes(stdout), bytes(stderr)


def checked(command, *, cwd, environment, deadline):
    code, stdout, _ = run_native(command, cwd=cwd, environment=environment,
                                deadline=deadline)
    if code != 0:
        raise ProbeError("native_nonzero")
    return stdout


def git_bytes(directory, arguments, environment, deadline):
    if "GIT_GRAFT_FILE" in environment:
        raise ProbeError("uncontrolled_git_graft_environment")
    return checked(["git", "--no-replace-objects", "--no-pager", "-c", "core.fsmonitor=false",
                    "-c", "core.hooksPath=/dev/null", "-C", str(directory),
                    *arguments], cwd=directory, environment=environment,
                   deadline=deadline)


def git_text(directory, arguments, environment, deadline):
    try:
        return git_bytes(directory, arguments, environment, deadline).decode("utf-8").strip()
    except UnicodeError:
        raise ProbeError("invalid_git_output") from None


def no_symlink_path(path):
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ProbeError("symlink_path")
    return path


def regular_bytes(base, relative):
    path = no_symlink_path(base / relative)
    try:
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_SOURCE):
            raise ProbeError("unsafe_source_file")
        data = path.read_bytes()
    except OSError:
        raise ProbeError("missing_source_file") from None
    if len(data) != info.st_size or len(data) > MAX_SOURCE:
        raise ProbeError("source_file_changed")
    return data


def load_lock():
    try:
        actual = json.loads((ROOT / "upstream.lock.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ProbeError("invalid_project_lock") from None
    if actual != EXPECTED_LOCK:
        raise ProbeError("unsupported_project_lock")
    return actual


def tree_guard(upstream, environment, deadline):
    if any(os.path.lexists(upstream / name) for name in RUNTIME_PATHS):
        raise ProbeError("source_clone_or_output_present")
    if (os.path.lexists(upstream / "rbm.local.conf")
            or os.path.lexists("/etc/rbm.conf")):
        raise ProbeError("uncontrolled_rbm_config")
    for directory in (upstream, upstream / "rbm"):
        flags = git_text(directory, ["ls-files", "-v"], environment, deadline).splitlines()
        if any(not line.startswith("H ") for line in flags):
            raise ProbeError("hidden_worktree_changes")
        if git_text(directory, ["status", "--porcelain=v1", "--untracked-files=all"],
                    environment, deadline):
            raise ProbeError("dirty_source_tree")


def reject_grafts(directory, environment, deadline):
    # Ask Git for the real metadata path: submodules/worktrees can use gitfiles.
    value = git_text(directory, ["rev-parse", "--path-format=absolute", "--git-path",
                                "info/grafts"], environment, deadline)
    path = Path(value)
    if not path.is_absolute() or path.name != "grafts" or path.parent.name != "info":
        raise ProbeError("invalid_git_graft_path")
    if os.path.lexists(path):
        raise ProbeError("unsupported_git_grafts")
    try:
        no_symlink_path(path)
    except ProbeError:
        raise ProbeError("unsafe_git_graft_path") from None


def verify_bindings(upstream, lock, environment, deadline):
    for directory, expected_commit, expected_origin in (
            (upstream, lock["commit"], lock["repository"]),
            (upstream / "rbm", RBM_COMMIT, RBM_REPOSITORY)):
        no_symlink_path(directory)
        if git_text(directory, ["rev-parse", "--show-toplevel"],
                    environment, deadline) != str(directory):
            raise ProbeError("wrong_git_root")
        if git_text(directory, ["rev-parse", "HEAD"], environment, deadline) != expected_commit:
            raise ProbeError("wrong_source_commit")
        if git_text(directory, ["remote", "get-url", "origin"],
                    environment, deadline) != expected_origin:
            raise ProbeError("noncanonical_origin")
        reject_grafts(directory, environment, deadline)
    link = git_text(upstream, ["ls-tree", lock["commit"], "rbm"], environment, deadline)
    if link != "160000 commit " + RBM_COMMIT + "\trbm":
        raise ProbeError("wrong_rbm_gitlink")
    for arguments, expected in (
            (["rev-parse", "refs/tags/" + lock["tag"]], lock["tag_object"]),
            (["rev-parse", "refs/tags/" + lock["tag"] + "^{}"], lock["commit"]),
            (["cat-file", "-t", lock["tag_object"]], "tag"),
            (["config", "--file", ".gitmodules", "submodule.rbm.path"], "rbm"),
            (["config", "--file", ".gitmodules", "submodule.rbm.url"], RBM_REPOSITORY)):
        if git_text(upstream, arguments, environment, deadline) != expected:
            raise ProbeError("source_pin_mismatch")
    tree_guard(upstream, environment, deadline)


def snapshot_sources(upstream, output, environment, deadline, records=None):
    names = git_text(upstream / "rbm", ["ls-tree", "-r", "--name-only", "HEAD", "lib"],
                     environment, deadline).splitlines()
    names = [name for name in names if name.endswith(".pm")]
    if (not {"lib/RBM.pm", "lib/RBM/DefaultConfig.pm"}.issubset(names)
            or not 2 <= len(names) <= MAX_SOURCE_FILES - 3
            or any(not re.fullmatch(r"lib/[A-Za-z0-9_/.-]+\.pm", name)
                   or ".." in Path(name).parts for name in names)):
        raise ProbeError("unsupported_rbm_module_layout")
    sources = [(upstream, "rbm.conf", "rbm.conf")]
    sources += [(upstream / "rbm", name, "rbm/" + name)
                for name in ["rbm", "container", *sorted(names)]]
    records = [] if records is None else records
    for directory, relative, artifact in sources:
        deadline.remaining()
        data = regular_bytes(directory, relative)
        tracked = git_bytes(directory, ["show", "HEAD:" + relative], environment, deadline)
        if data != tracked:
            raise ProbeError("working_source_differs_from_commit")
        destination = output / "sources" / artifact
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        records.append({"source": artifact, "artifact": "sources/" + artifact,
                        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    return records


def write_report(output, report):
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if len(serialized.encode("utf-8")) > 64 * 1024:
        raise ProbeError("report_limit")
    fd, temporary = tempfile.mkstemp(prefix=".probe-", dir=output)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output / "probe.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare_output(upstream, output):
    upstream, output = no_symlink_path(upstream), no_symlink_path(output)
    if not upstream.is_dir():
        raise ProbeError("missing_upstream")
    if upstream == output or upstream in output.parents or output in upstream.parents:
        raise ProbeError("overlapping_output")
    try:
        output.mkdir(parents=True, exist_ok=True)
        info = output.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or any(output.iterdir()):
            raise ProbeError("unsafe_output_directory")
    except OSError:
        raise ProbeError("unsafe_output_directory") from None
    return upstream, output


def parse_child(stdout, parent_namespace, expected_affinity, env_two):
    try:
        lines = stdout.decode("ascii").splitlines()
        if len(lines) != 2 or not lines[0].startswith("RBM_RESOURCE_CHILD "):
            raise ValueError
        data = json.loads(lines[0][len("RBM_RESOURCE_CHILD "):])
        if set(data) != {"affinity", "logical_cpu_count", "influencer_presence", "network_namespace"}:
            raise ValueError
        affinity = data["affinity"]
        if (not isinstance(affinity, list) or not affinity
                or any(type(cpu) is not int or not 0 <= cpu <= 1048576 for cpu in affinity)
                or affinity != expected_affinity):
            raise ValueError
        logical = data["logical_cpu_count"]
        if type(logical) is not int or not 1 <= logical <= 1048576:
            raise ValueError
        presence = data["influencer_presence"]
        if (not isinstance(presence, dict) or set(presence) != set(INFLUENCERS)
                or any(type(v) is not bool for v in presence.values())):
            raise ValueError
        namespace = data["network_namespace"]
        if (not isinstance(namespace, str) or not re.fullmatch(r"net:\[[0-9]{1,20}\]", namespace)
                or namespace == parent_namespace):
            raise ValueError
        if not re.fullmatch(r"[1-9][0-9]{0,5}", lines[1]):
            raise ValueError
        return data, int(lines[1])
    except (UnicodeError, ValueError, TypeError, KeyError):
        raise ProbeError("invalid_child_evidence") from None


def execute_case(upstream, case, parent, environment, deadline, nproc):
    env_two = case == "controller-env-two"
    cpus = (parent["affinity"][:2] if case == "affinity-two" else
            parent["affinity"][:1] if case == "affinity-one" else parent["affinity"])
    child_environment = environment.copy()
    if env_two:
        child_environment["RBM_NUM_PROCS"] = "2"
    measurements = {}
    for operation, executable in (("nproc", nproc), ("num_procs", str(upstream / "rbm/rbm"))):
        tree_guard(upstream, environment, deadline)
        command = [sys.executable, "-c", MASK_CODE, json.dumps(cpus),
                   str(upstream / "rbm/container"), "run", "--disable-network", "--",
                   sys.executable, "-c", CHILD_CODE, operation, executable]
        stdout = checked(command, cwd=upstream, environment=child_environment, deadline=deadline)
        child, count = parse_child(stdout, parent["network_namespace"], cpus, env_two)
        measurements[operation] = {"count": count, **child}
        tree_guard(upstream, environment, deadline)
    errors = []
    expected_presence = {key: key == "RBM_NUM_PROCS" and env_two for key in INFLUENCERS}
    if any(item["influencer_presence"] != expected_presence for item in measurements.values()):
        errors.append("namespace_cpu_environment_not_preserved")
    if measurements["nproc"]["count"] != len(cpus):
        errors.append("namespace_nproc_affinity_mismatch")
    if measurements["num_procs"]["count"] != (2 if env_two else len(cpus)):
        errors.append("namespace_controller_count_mismatch")
    if measurements["nproc"]["logical_cpu_count"] != measurements["num_procs"]["logical_cpu_count"]:
        errors.append("inconsistent_child_cpu_count")
    return {"case": case, "expected_affinity": cpus, "measurements": measurements,
            "query_location": "actual RBM --disable-network no-chroot namespace",
            "errors": errors, "verified": not errors}


def probe(upstream, output, *, environment=None):
    deadline = Deadline()
    environment = dict(os.environ if environment is None else environment)
    upstream, output = prepare_output(Path(upstream), Path(output))
    report = {"schema": 1, "purpose": "source/controller authority only",
              "status": "starting", "source_verified": False, "controller_verified": False,
              "cache_identity_verified": False, "production_policy_changed": False,
              "scope": {"network_disabled": True, "chroot": False,
                        "no_chroot_environment_inheritance_only": True,
                        "full_mozconfig_rendered": False, "filename_identity_rendered": False,
                        "compiler_or_browser_build": False},
              "deferred": DEFERRED, "sources": [], "cases": [],
              "post_runtime_guard_verified": False}
    write_report(output, report)
    error = None
    parent = None
    bindings_verified = False
    try:
        lock = load_lock()
        report["upstream"] = lock
        report["rbm"] = {"commit": RBM_COMMIT, "repository": RBM_REPOSITORY}
        verify_bindings(upstream, lock, environment, deadline)
        bindings_verified = True
        snapshot_sources(upstream, output, environment, deadline, report["sources"])
        report["source_verified"] = True
        report["status"] = "source-verified"
        write_report(output, report)
        if not hasattr(os, "sched_getaffinity") or not hasattr(os, "waitid"):
            raise ProbeError("unsupported_platform")
        presence = {key: key in environment for key in INFLUENCERS}
        parent = {"affinity": sorted(os.sched_getaffinity(0)),
                  "logical_cpu_count": os.cpu_count(),
                  "network_namespace": os.readlink("/proc/self/ns/net"),
                  "influencer_presence": presence}
        report["parent"] = parent
        write_report(output, report)
        if any(presence.values()):
            raise ProbeError("uncontrolled_cpu_environment")
        if len(parent["affinity"]) < 2:
            raise ProbeError("insufficient_allowed_cpus")
        nproc = shutil.which("nproc", path=environment.get("PATH"))
        if nproc is None:
            raise ProbeError("missing_nproc")
        for case in CASES:
            deadline.remaining()
            tree_guard(upstream, environment, deadline)
            record = execute_case(upstream, case, parent, environment, deadline, nproc)
            report["cases"].append(record)
            write_report(output, report)
            if not record["verified"]:
                raise ProbeError(record["errors"][0])
            tree_guard(upstream, environment, deadline)
            write_report(output, report)
        report["controller_verified"] = True
    except ProbeError as failure:
        error = str(failure)
    except (OSError, ValueError, TypeError):
        error = "runtime_system_error"
    finally:
        if bindings_verified:
            try:
                verify_bindings(upstream, EXPECTED_LOCK, environment, deadline)
                report["post_runtime_guard_verified"] = True
            except ProbeError:
                report["post_runtime_guard_verified"] = False
                error = error or "post_runtime_guard_failed"
        if parent is not None:
            report["parent_affinity_unchanged"] = sorted(os.sched_getaffinity(0)) == parent["affinity"]
            if not report["parent_affinity_unchanged"]:
                error = error or "parent_affinity_changed"
        if error is not None:
            report["controller_verified"] = False
            report["status"] = "failed"
            report["error"] = {"code": error}
        else:
            report["status"] = "source-controller-verified-only"
        write_report(output, report)
    return report


def cancelled(_signal, _frame):
    raise ProbeError("probe_cancelled")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, cancelled)
    try:
        report = probe(args.upstream, args.output_directory)
    except (ProbeError, OSError):
        print("RBM source/controller probe failed before a safe report could be saved.", file=sys.stderr)
        return 1
    if report["status"] == "failed":
        print("RBM source/controller probe failed; see probe.json (identity remains deferred).", file=sys.stderr)
        return 1
    print("RBM source/controller authority verified only; cache identity and PGO remain deferred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
