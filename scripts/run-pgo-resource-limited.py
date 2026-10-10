#!/usr/bin/env python3
"""Validate a bound two-CPU policy, then replace this process with the command."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

MAX_POLICY_BYTES = 64 * 1024
MAX_CPUS = 4096
EXPECTED_LOCK = {
    "repository": "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git",
    "tag": "mb-16.0a9-build1",
    "tag_object": "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721",
    "commit": "7dd751cf1837d667908b339aebf82567ece55e20",
}
EXPECTED_RBM = "865f2c9842520958879665d5c9b820d9ed51761e"
EXPECTED_RUST = "610dce67882933fdffb6df9c16633ef37c4f5f0e625ebe74d315b1dff44fe2b3"
EXPECTED_NODE = "f93c137e502ea4bbdf5d05b8791ab32a80d1d7d51600867e8a144f83dd3eb78c"
POLICY_KEYS = {
    "schema", "kind", "verified", "target", "binding", "upstream_lock", "rbm_commit",
    "parent_affinity", "selected_affinity", "expected_num_procs",
    "rust_identity_sha256", "node_identity_sha256",
}
BINDING_ENV = {"head": "GITHUB_SHA", "run": "GITHUB_RUN_ID", "attempt": "GITHUB_RUN_ATTEMPT",
               "job": "GITHUB_JOB", "upstream": "UPSTREAM"}
CPU_ENV = ("RBM_NUM_PROCS", "OMP_NUM_THREADS", "OMP_THREAD_LIMIT")


class Rejected(Exception):
    """No private input values or native error text in public failures."""


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise Rejected("invalid_arguments")


def exact_keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Rejected("invalid_shape")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_key")
        result[key] = value
    return result


def no_float(_value):
    raise Rejected("non_integer_number")


def bounded_integer(value):
    if len(value) > 20:
        raise Rejected("integer_limit")
    return int(value)


def open_parent(path):
    """Open each ancestor without following links; leave no helper FD at exec."""
    text = os.path.abspath(path)
    if "\x00" in text:
        raise Rejected("unsafe_path")
    parts = Path(text).parts
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def read_policy(path):
    parent = descriptor = None
    try:
        parent, name = open_parent(path)
        descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or not 0 < before.st_size <= MAX_POLICY_BYTES):
            raise Rejected("unsafe_policy_file")
        chunks = []
        size = 0
        while size <= MAX_POLICY_BYTES:
            block = os.read(descriptor, min(8192, MAX_POLICY_BYTES + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        after = os.fstat(descriptor)
        if (size != before.st_size or size > MAX_POLICY_BYTES
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                            after.st_mtime_ns, after.st_ctime_ns)):
            raise Rejected("policy_file_changed")
        return json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=no_duplicates,
                          parse_float=no_float, parse_constant=no_float,
                          parse_int=bounded_integer)
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise Rejected("invalid_policy_file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def bounded_text(value, limit):
    if type(value) is not str or not value or len(value) > limit:
        raise Rejected("invalid_text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise Rejected("invalid_text") from None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise Rejected("invalid_text")
    return value


def safe_directory(value):
    value = bounded_text(value, 4096)
    if not os.path.isabs(value) or os.path.normpath(value) != value or value == "/":
        raise Rejected("noncanonical_upstream")
    parent = descriptor = None
    try:
        parent, name = open_parent(value)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise Rejected("unsafe_upstream")
    except OSError:
        raise Rejected("unsafe_upstream") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)
    return value


def cpus(value):
    if (type(value) is not list or not 1 <= len(value) <= MAX_CPUS
            or any(type(cpu) is not int or not 0 <= cpu <= 1048576 for cpu in value)
            or value != sorted(set(value))):
        raise Rejected("invalid_affinity")
    return value


def validate_policy(policy, environment, current_affinity):
    exact_keys(policy, POLICY_KEYS)
    if (type(policy["schema"]) is not int or policy["schema"] != 1
            or policy["kind"] != "pgo-generation-resource-policy"
            or policy["verified"] is not True or policy["target"] != "pgo-generate"
            or type(policy["expected_num_procs"]) is not int or policy["expected_num_procs"] not in (2, 4)):
        raise Rejected("unverified_policy")
    exact_keys(policy["upstream_lock"], EXPECTED_LOCK)
    if policy["upstream_lock"] != EXPECTED_LOCK or policy["rbm_commit"] != EXPECTED_RBM:
        raise Rejected("wrong_source_pin")
    if policy["rust_identity_sha256"] != EXPECTED_RUST or policy["node_identity_sha256"] != EXPECTED_NODE:
        raise Rejected("wrong_cache_identity")
    binding = policy["binding"]
    exact_keys(binding, BINDING_ENV)
    for key in BINDING_ENV:
        bounded_text(binding[key], 4096 if key == "upstream" else 128)
        if binding[key] != environment.get(BINDING_ENV[key]):
            raise Rejected("stale_execution_binding")
    if not re.fullmatch(r"[0-9a-f]{40}", binding["head"]):
        raise Rejected("invalid_head")
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", binding[key]) for key in ("run", "attempt")):
        raise Rejected("invalid_run")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,127}", binding["job"]):
        raise Rejected("invalid_job")
    safe_directory(binding["upstream"])
    parent, selected = cpus(policy["parent_affinity"]), cpus(policy["selected_affinity"])
    if (parent != sorted(current_affinity) or len(selected) != policy["expected_num_procs"]
            or not set(selected).issubset(parent)):
        raise Rejected("stale_affinity")
    if any(key in environment for key in CPU_ENV):
        raise Rejected("uncontrolled_cpu_environment")
    return selected


def main():
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    try:
        args = parser.parse_args()
        if not args.command or args.command[0] != "--" or len(args.command) < 2:
            raise Rejected("invalid_arguments")
        command = args.command[1:]
        if not command[0] or any("\x00" in argument for argument in command):
            raise Rejected("invalid_arguments")
        if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
            raise Rejected("unsupported_platform")
        policy = read_policy(args.policy)
        selected = validate_policy(policy, os.environ, os.sched_getaffinity(0))
        os.sched_setaffinity(0, set(selected))
    except (Rejected, OSError):
        print("PGO resource policy rejected; command was not started.", file=sys.stderr)
        return 2
    if any("run-pgo-generate.sh" in argument for argument in command):
        injector = Path(__file__).resolve().parent / "inject-pgo-profile-runtime.py"
        if injector.is_file():
            try:
                log_dir = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "pgo-resource-validation"
                log_dir.mkdir(parents=True, exist_ok=True)
                log_file = log_dir / "pgo-injector.log"
                tools_dir = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "pgo-rust-preflight-tools"
                log_handle = open(log_file, "a")
                subprocess.Popen(
                    [sys.executable, str(injector),
                     "--upstream", str(policy["binding"]["upstream"]),
                     "--tools", str(tools_dir),
                     "--parent-pid", str(os.getpid()),
                     "--log-file", str(log_file)],
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                )
            except OSError:
                pass
    try:
        # No fork, session, signal, cwd, ENV or inherited-FD change here.
        os.execvpe(command[0], command, os.environ)
    except FileNotFoundError:
        print("PGO resource command could not be executed.", file=sys.stderr)
        return 127
    except (OSError, ValueError):
        print("PGO resource command could not be executed.", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
