#!/usr/bin/env python3
"""Short native resource/Checks durability smoke. This does not validate a browser."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts/publish-rbm-telemetry.py"
OBSERVER = ROOT / "scripts/observe-rbm-build.py"
TOKEN_NAME = "PGO_TELEMETRY_TOKEN"
READ_LIMIT = 1024 * 1024
TOKEN_ABSENT_MARKER = "NATIVE_WORKLOAD_TELEMETRY_TOKEN_ABSENT"
WORKLOAD = r"""import hashlib, os, threading
assert 'PGO_TELEMETRY_TOKEN' not in os.environ, 'publisher token reached native workload'
print('NATIVE_WORKLOAD_TELEMETRY_TOKEN_ABSENT', flush=True)
value = b'lightweight resource smoke, not a browser or compiler build'
for _ in range(1000):
 value = hashlib.sha256(value).digest()
threading.Event().wait(25)
print('NATIVE_RESOURCE_WORKLOAD_FINISHED', flush=True)
"""


class SmokeError(Exception):
    pass


def publisher_api():
    spec = importlib.util.spec_from_file_location("rbm_durable_telemetry", PUBLISHER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_bytes(path, limit=READ_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise SmokeError("unsafe or oversized smoke evidence")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise SmokeError("oversized smoke evidence")
        return data
    finally:
        os.close(fd)


def read_json(path):
    value = json.loads(read_bytes(path))
    if not isinstance(value, dict):
        raise SmokeError("smoke evidence must be an object")
    return value


def write_json(path, value):
    path = Path(path)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(payload) > READ_LIMIT:
        raise SmokeError("oversized smoke evidence")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
    except BaseException:
        raise


def records(path):
    data = read_bytes(path)
    lines = data.splitlines(keepends=True)
    result = []
    for line in lines:
        if not line.endswith(b"\n"):
            continue  # A native writer may still be appending the last record.
        value = json.loads(line)
        if not isinstance(value, dict):
            raise SmokeError("invalid resource record")
        result.append(value)
    return result


def required_int(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise SmokeError("invalid numeric evidence")
    return value


def utc(value):
    if not isinstance(value, str):
        raise SmokeError("missing sample time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise SmokeError("sample time must have a timezone")
    return parsed


def binding(api):
    return api.Binding(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
                       os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"],
                       os.environ["GITHUB_JOB"])


def bound_state(api, path, expected):
    state = api.read_state(path)
    wanted = {"repository": expected.repository, "head_sha": expected.head,
              "run_id": expected.run, "run_attempt": expected.attempt,
              "job_key": expected.job, "external_id": expected.external_id,
              "check_name": api.CHECK_NAME}
    for key, value in wanted.items():
        if state.get(key) != value:
            raise SmokeError("telemetry state binding mismatch")
    required_int(state.get("check_id"), 1)
    required_int(state.get("last_ack_seq"))
    required_int(state.get("resource_ack_count"))
    utc(state.get("ready_at"))
    return state


def process_identity(pid):
    required_int(pid, 2)
    proc = Path("/proc") / str(pid)
    try:
        proc_stat = (proc / "stat").read_text()
        fields = proc_stat.rsplit(")", 1)[1].split()
        return {"start_ticks": int(fields[19]), "state": fields[0],
                "owner": proc.stat().st_uid, "argv": (proc / "cmdline").read_bytes().split(b"\0")}
    except FileNotFoundError:
        return None


def owned_publisher(state, state_path):
    pid = required_int(state.get("pid"), 2)
    ticks = required_int(state.get("start_ticks"), 1)
    if pid == os.getpid():
        raise SmokeError("publisher identity is the smoke process")
    identity = process_identity(pid)
    if identity is None or identity["state"] == "Z":
        raise SmokeError("publisher exited before durability smoke")
    if identity["start_ticks"] != ticks or identity["owner"] != os.getuid():
        raise SmokeError("publisher process identity changed")
    argv = identity["argv"]
    if str(PUBLISHER.resolve()).encode() not in argv or b"_worker" not in argv:
        raise SmokeError("publisher worker/script marker mismatch")
    try:
        at = argv.index(b"--state")
    except ValueError:
        raise SmokeError("publisher state argument missing") from None
    if at + 1 >= len(argv) or argv[at + 1] != str(Path(state_path).resolve()).encode():
        raise SmokeError("publisher state argument mismatch")
    return pid, ticks


def publisher_dead(pid, ticks):
    identity = process_identity(pid)
    return identity is None or identity["state"] == "Z" or identity["start_ticks"] != ticks


def kill_owned_publisher(state, state_path):
    pid = required_int(state.get("pid"), 2)
    ticks = required_int(state.get("start_ticks"), 1)
    if pid == os.getpid() or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise SmokeError("publisher kill requires a separate process and Linux pidfd support")
    pidfd = os.pidfd_open(pid)
    try:
        # Pin BEFORE reading /proc metadata. Never signal a recycled numeric PID.
        if owned_publisher(state, state_path) != (pid, ticks):
            raise SmokeError("publisher identity changed before signal")
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)  # ONLY this verified publisher.
    finally:
        os.close(pidfd)
    deadline = time.monotonic() + 2
    event = threading.Event()
    while not publisher_dead(pid, ticks):
        if time.monotonic() >= deadline:
            raise SmokeError("publisher did not stop after SIGKILL")
        event.wait(0.02)
    return pid, ticks


def capture(args):
    if TOKEN_NAME in os.environ:
        raise SmokeError("capture step must not receive the publisher token")
    if not sys.platform.startswith("linux") or not (30 <= args.deadline <= 90):
        raise SmokeError("capture needs Linux and a bounded 30-90 second deadline")
    api = publisher_api()
    expected = binding(api)
    initial = bound_state(api, args.state, expected)
    if initial["last_ack_seq"] != 0 or initial["resource_ack_count"] != 0:
        raise SmokeError("smoke must start from a confirmed readiness ACK without fake samples")
    work = args.work.resolve()
    work.mkdir(mode=0o700)
    (work / "logs").mkdir(mode=0o700)
    console_path = work / "observer-console.log"
    build_log = work / "native-workload.log"
    deadline = time.monotonic() + args.deadline
    observed_first_seq = None
    process = None
    killed = False
    state = initial
    try:
        with console_path.open("xb") as console:
            command = [sys.executable, str(OBSERVER), "--upstream", str(work),
                       "--log", str(build_log), "--resource-log", str(args.resource_log),
                       "--interval", "0.2", "--", sys.executable, "-c", WORKLOAD]
            process = subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            event = threading.Event()
            while True:
                if time.monotonic() >= deadline:
                    raise SmokeError("two measured remote ACKs were not observed before deadline")
                if process.poll() is not None:
                    raise SmokeError("native observer exited before two measured remote ACKs")
                state = bound_state(api, args.state, expected)
                count = state["resource_ack_count"]
                sequence = state["last_ack_seq"]
                if count >= 1 and observed_first_seq is None:
                    observed_first_seq = sequence
                if count >= 2 and observed_first_seq is not None and sequence > observed_first_seq:
                    break
                event.wait(0.05)
            # The token-absence marker is produced by the actual child under the unmodified observer.
            if TOKEN_ABSENT_MARKER.encode() not in read_bytes(build_log):
                raise SmokeError("native child token-absence assertion did not pass")
            pid, ticks = kill_owned_publisher(state, args.state)
            killed_at = datetime.now(timezone.utc).isoformat()
            killed = True
            # Re-read only ACKed state after death to capture an ACK that raced the kill boundary.
            state = bound_state(api, args.state, expected)
            if state["resource_ack_count"] < 2 or state["last_ack_seq"] <= observed_first_seq:
                raise SmokeError("two measured ACKs were not retained after publisher death")
            native_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if native_code != 0:
                raise SmokeError("native workload failed")
        resources = records(args.resource_log)
        suffix = [row for row in resources if utc(row.get("time")) > utc(killed_at)]
        if not suffix or resources[-1].get("reason") != "exit" or resources[-1].get("exit_code") != 0:
            raise SmokeError("real unacknowledged native-resource suffix was not captured")
        if not publisher_dead(pid, ticks):
            raise SmokeError("verified publisher is still running")
        evidence = {"schema": 1, "purpose": "resource telemetry smoke; not browser validation",
                    "repository": expected.repository, "head_sha": expected.head,
                    "run_id": expected.run, "run_attempt": expected.attempt, "job_key": expected.job,
                    "external_id": expected.external_id, "check_id": state["check_id"],
                    "pid": pid, "start_ticks": ticks, "kill_signal": "SIGKILL",
                    "first_resource_ack_seq": observed_first_seq, "last_ack_seq": state["last_ack_seq"],
                    "resource_ack_count": state["resource_ack_count"], "last_ack_at": state["last_ack_at"],
                    "last_sample_at": state["last_sample_at"], "publisher_killed_at": killed_at,
                    "unacknowledged_first_sample_at": suffix[0]["time"],
                    "unacknowledged_last_sample_at": resources[-1]["time"],
                    "unacknowledged_resource_count": len(suffix), "native_exit_code": native_code,
                    "native_token_absent": True}
        write_json(args.evidence, evidence)
        print(json.dumps({"purpose": evidence["purpose"], "resource_ack_count": evidence["resource_ack_count"],
                          "publisher_killed": True, "native_token_absent": True}, sort_keys=True))
        return 0
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=4)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        if not killed:
            # Failure cleanup signals only a publisher whose identity still matches.
            try:
                kill_owned_publisher(state, args.state)
            except (SmokeError, OSError):
                pass


def verify(args):
    token = os.environ.get(TOKEN_NAME)
    if not token:
        raise SmokeError("verify step requires its own scoped publisher token")
    api = publisher_api()
    expected = binding(api)
    state = bound_state(api, args.state, expected)
    evidence = read_json(args.evidence)
    for key in ["repository", "head_sha", "run_id", "run_attempt", "job_key", "external_id", "check_id",
                "pid", "start_ticks", "last_ack_seq", "resource_ack_count", "last_ack_at", "last_sample_at"]:
        if evidence.get(key) != state.get(key):
            raise SmokeError("captured evidence and ACKed state differ")
    if evidence.get("schema") != 1 or evidence.get("kill_signal") != "SIGKILL" or evidence.get("native_token_absent") is not True:
        raise SmokeError("native kill/token evidence is invalid")
    if evidence.get("native_exit_code") != 0 or evidence.get("unacknowledged_resource_count", 0) < 1:
        raise SmokeError("native suffix evidence is missing")
    if state["resource_ack_count"] < 2 or state["last_ack_seq"] <= evidence["first_resource_ack_seq"]:
        raise SmokeError("two increasing measured ACKs are required")
    if not publisher_dead(evidence["pid"], evidence["start_ticks"]):
        raise SmokeError("publisher was not killed")
    check = api.GitHubChecks(expected, token).get(state["check_id"])
    api.validate_check(check, expected, state["check_id"])
    if check.get("status") != "completed" or check.get("conclusion") != "neutral":
        raise SmokeError("diagnostic check must remain completed neutral, not a build result")
    output = api.decode_output(check)
    if output.get("phase") != "OBSERVING":
        raise SmokeError("last remote snapshot must not claim completion after publisher death")
    if required_int(output.get("seq")) < state["last_ack_seq"]:
        raise SmokeError("independent remote GET lost a locally acknowledged sample")
    if required_int(output.get("resource_ack_count")) < state["resource_ack_count"]:
        raise SmokeError("independent remote GET lost a measured ACK")
    if utc(output.get("last_sample_at")) < utc(state["last_sample_at"]):
        raise SmokeError("remote sample time regressed")
    # A serialized API child may finish a PRE-kill request after the publisher dies.
    # Such an ACK may advance the remote sequence beyond the last local ACK.
    cutoff = utc(evidence["publisher_killed_at"])
    if not (cutoff < utc(evidence["unacknowledged_first_sample_at"]) <= utc(evidence["unacknowledged_last_sample_at"])):
        raise SmokeError("post-kill resource suffix timing is invalid")
    snapshots = output.get("snapshots")
    if not isinstance(snapshots, list) or not snapshots:
        raise SmokeError("remote measured resource snapshots are missing")
    if utc(output.get("published_at")) > cutoff:
        raise SmokeError("remote payload was constructed after the publisher kill boundary")
    if utc(output["last_sample_at"]) > cutoff or any(utc(row.get("time")) > cutoff for row in snapshots):
        raise SmokeError("post-kill unacknowledged resource suffix was published")
    print(json.dumps({"purpose": "resource telemetry smoke; not browser validation",
                      "check_id": state["check_id"], "resource_ack_count": state["resource_ack_count"],
                      "last_ack_seq": state["last_ack_seq"], "remote_last_ack_seq": output["seq"],
                      "independent_remote_get": True,
                      "publisher_killed": True, "status": "completed", "conclusion": "neutral",
                      "unacknowledged_suffix_absent": True}, sort_keys=True))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--resource-log", type=Path, required=True)
    capture_parser.add_argument("--state", type=Path, required=True)
    capture_parser.add_argument("--evidence", type=Path, required=True)
    capture_parser.add_argument("--work", type=Path, required=True)
    capture_parser.add_argument("--deadline", type=float, default=60)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--state", type=Path, required=True)
    verify_parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return capture(args) if args.command == "capture" else verify(args)
    except Exception as error:
        # Do not expose response bodies, environment values, tokens or command lines.
        print("Telemetry smoke failed: " + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
