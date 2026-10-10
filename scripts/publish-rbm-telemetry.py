#!/usr/bin/env python3
"""Durable diagnostic Checks snapshots. This never supervises the native build.

Token input: PGO_TELEMETRY_TOKEN in the starter step only. No test API URL exists.
Public smoke API: Binding, GitHubChecks.get, validate_check, decode_output,
read_state. seq counts sanitized resource records; resource_ack_count counts
successful measured PATCHes. Readiness is the single acknowledged POST (seq 0).
The check remains completed/neutral throughout; it is NOT a build result.
"""
import argparse
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import select
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com"
CHECK_NAME = "RBM resource telemetry (not a build result)"
TOKEN_ENV = "PGO_TELEMETRY_TOKEN"
SCRIPT = Path(__file__).resolve()
REQUEST_SECONDS = 5.0
READINESS_SECONDS = 15.0
MAX_LIFETIME = 6 * 60 * 60
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 512 * 1024
MAX_STATE = 16 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_READ = 64 * 1024
MAX_LINE = 8 * 1024
MAX_BURST = 64
MAX_PAGES = 8
UINT_MAX = 2 ** 64 - 1
REASONS = {"start", "interval", "signal", "exit", "launch-error"}
TERMINAL = {"exit", "launch-error"}
MEMORY = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
DISK = {"total_bytes", "free_bytes", "total_inodes", "free_inodes"}
EVENTS = {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}
STATE_KEYS = {"schema", "repository", "head_sha", "run_id", "run_attempt",
              "job_key", "external_id", "check_name", "check_id", "pid",
              "start_ticks", "started_at", "ready_at", "last_ack_seq",
              "last_ack_at", "last_sample_at", "resource_ack_count", "phase"}


class TelemetryError(Exception):
    """Only fixed categories, never an HTTP body, URL, token or raw exception."""
    def __init__(self, category="invalid", status=0, retry_after=0):
        super().__init__("telemetry " + category)
        self.category = category
        self.status = status
        self.retry_after = retry_after


class WorkerStop(BaseException):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalized_utc(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        raise TelemetryError("timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TelemetryError("timestamp") from None
    return parsed.isoformat()


def integer(value, positive=False):
    if type(value) is not int or not (1 if positive else 0) <= value <= UINT_MAX:
        raise TelemetryError("number")
    return value


def number(value):
    if type(value) not in (int, float) or not 0 <= value <= UINT_MAX or not math.isfinite(value):
        raise TelemetryError("number")
    return value


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TelemetryError("json")
            result[key] = value
        return result
    def invalid(_):
        raise TelemetryError("json")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise TelemetryError("json") from None


@dataclass(frozen=True)
class Binding:
    repository: str
    head: str
    run: str
    attempt: str
    job: str

    def __post_init__(self):
        if (not isinstance(self.repository, str) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", self.repository)
                or any(part in {".", ".."} for part in self.repository.split("/"))):
            raise TelemetryError("binding")
        if not isinstance(self.head, str) or not re.fullmatch(r"[0-9a-f]{40}", self.head):
            raise TelemetryError("binding")
        for value in (self.run, self.attempt):
            if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value):
                raise TelemetryError("binding")
        if not isinstance(self.job, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", self.job):
            raise TelemetryError("binding")

    @property
    def external_id(self):
        return f"{self.run}:{self.attempt}:{self.job}"

    @property
    def prefix(self):
        return f"/repos/{self.repository}"

    def public(self):
        return {"repository": self.repository, "head_sha": self.head,
                "run_id": self.run, "run_attempt": self.attempt,
                "job_key": self.job, "external_id": self.external_id,
                "check_name": CHECK_NAME}


def validate_check(check, binding, check_id=None):
    if not isinstance(check, dict):
        raise TelemetryError("response")
    observed_id = integer(check.get("id"), positive=True)
    if check_id is not None and observed_id != check_id:
        raise TelemetryError("response")
    expected_url = API_ROOT + binding.prefix + f"/check-runs/{observed_id}"
    if (check.get("head_sha") != binding.head or check.get("external_id") != binding.external_id
            or check.get("name") != CHECK_NAME or check.get("url") != expected_url
            or check.get("status") != "completed" or check.get("conclusion") != "neutral"
            or not isinstance(check.get("app"), dict)
            or check["app"].get("slug") != "github-actions"):
        raise TelemetryError("response")
    return check


def decode_output(check):
    output = check.get("output") if isinstance(check, dict) else None
    text = output.get("text") if isinstance(output, dict) else None
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_REQUEST:
        raise TelemetryError("output")
    if not text.startswith("```json\n") or not text.endswith("\n```"):
        raise TelemetryError("output")
    payload = parse_json(text[8:-4])
    if not isinstance(payload, dict) or type(payload.get("schema")) is not int or payload["schema"] != 1:
        raise TelemetryError("output")
    return payload


def retry_delay(headers):
    try:
        raw = headers.get("Retry-After", "0")
        if not isinstance(raw, str) or len(raw) > 80:
            return 0
        if re.fullmatch(r"[0-9]{1,8}", raw):
            return min(int(raw), MAX_LIFETIME)
        from email.utils import parsedate_to_datetime
        parsed = parsedate_to_datetime(raw)
        return min(MAX_LIFETIME, max(0, (parsed - datetime.now(timezone.utc)).total_seconds()))
    except (ValueError, TypeError, OverflowError):
        return 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_request(token, method, path, body):
    if method not in {"GET", "POST", "PATCH"} or not path.startswith("/repos/"):
        raise TelemetryError("request")
    if not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,4096}", token):
        raise TelemetryError("token")
    raw = None if body is None else json_bytes(body)
    if raw is not None and len(raw) > MAX_REQUEST:
        raise TelemetryError("payload")
    req = urllib.request.Request(API_ROOT + path, data=raw, method=method, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "rbm-resource-telemetry",
        "Content-Type": "application/json"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=REQUEST_SECONDS) as response:
            headers = {"Retry-After": response.headers.get("Retry-After", "0"),
                       "Link": response.headers.get("Link", "")}
            if any(len(value) > 8192 for value in headers.values()):
                raise TelemetryError("response")
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None and (not raw_length.isdecimal() or int(raw_length) > MAX_RESPONSE):
                raise TelemetryError("response")
            raw_body = response.read(MAX_RESPONSE + 1)
            if len(raw_body) > MAX_RESPONSE:
                raise TelemetryError("response")
            return response.status, parse_json(raw_body), headers
    except urllib.error.HTTPError as error:
        status, delay = error.code, retry_delay(error.headers)
        error.close()
        raise TelemetryError("http", status, delay) from None
    except (OSError, urllib.error.URLError, ValueError):
        raise TelemetryError("transport") from None


def _reap_request(pid):
    # An unreaped direct child cannot have its PID reused. Never signal a group.
    try:
        if os.waitpid(pid, os.WNOHANG)[0]:
            return
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 0.15
        while time.monotonic() < deadline:
            if os.waitpid(pid, os.WNOHANG)[0]:
                return
            time.sleep(0.01)
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            if os.waitpid(pid, os.WNOHANG)[0]:
                return
            time.sleep(0.01)
    except (ChildProcessError, ProcessLookupError):
        pass


def bounded_request(operation, timeout=REQUEST_SECONDS):
    """A supervised private pipe bounds DNS/connect/read AND response serialization."""
    read_fd, write_fd = os.pipe()
    parent_pid = os.getpid()
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        # API helper use in a credentialed smoke step must not inherit log streams.
        null_fd = os.open(os.devnull, os.O_RDWR)
        for stream_fd in (0, 1, 2):
            os.dup2(null_fd, stream_fd)
        if null_fd > 2:
            os.close(null_fd)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        # Kill an API child if its owning daemon vanishes. Do not evade runner cleanup.
        import ctypes
        if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            os._exit(1)
        # The token is already private in memory, never inherited as API child ENV.
        os.environ.pop(TOKEN_ENV, None)
        try:
            try:
                result = operation()
                envelope = {"ok": True, "result": result}
            except TelemetryError as error:
                envelope = {"ok": False, "category": error.category,
                            "status": error.status, "retry_after": error.retry_after}
            except BaseException:
                envelope = {"ok": False, "category": "transport", "status": 0, "retry_after": 0}
            data = json_bytes(envelope)
            if len(data) > MAX_RESPONSE + 16384:
                data = json_bytes({"ok": False, "category": "response", "status": 0, "retry_after": 0})
            position = 0
            while position < len(data):
                position += os.write(write_fd, data[position:])
        except BaseException:
            pass
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TelemetryError("timeout")
            readable, _, _ = select.select([read_fd], [], [], remaining)
            if not readable:
                raise TelemetryError("timeout")
            block = os.read(read_fd, 65536)
            if not block:
                break
            data.extend(block)
            if len(data) > MAX_RESPONSE + 16384:
                raise TelemetryError("response")
        envelope = parse_json(data)
        if not isinstance(envelope, dict):
            raise TelemetryError("response")
        if envelope.get("ok") is not True:
            raise TelemetryError(envelope.get("category", "transport"),
                                 envelope.get("status", 0), envelope.get("retry_after", 0))
        result = envelope.get("result")
        if not isinstance(result, list) or len(result) != 3:
            raise TelemetryError("response")
        return result
    finally:
        os.close(read_fd)
        _reap_request(pid)


class GitHubChecks:
    def __init__(self, binding, token, transport=None):
        self.binding, self.token = binding, token
        # Python-only injection for offline fixtures; no CLI/environment URL bypass.
        self.transport = transport or https_request

    def request(self, method, path, body=None, expected=200):
        if body is not None and len(json_bytes(body)) > MAX_REQUEST:
            raise TelemetryError("payload")
        status, data, headers = bounded_request(lambda: self.transport(self.token, method, path, body))
        if type(status) is not int or status != expected or not isinstance(headers, dict):
            raise TelemetryError("response")
        return data, headers

    def ensure_absent(self):
        # Never blindly retry POST after an uncertain acknowledgment, even on restart.
        for page in range(1, MAX_PAGES + 1):
            query = urllib.parse.urlencode({"check_name": CHECK_NAME, "filter": "all", "per_page": 10, "page": page})
            path = self.binding.prefix + f"/commits/{self.binding.head}/check-runs?{query}"
            result, headers = self.request("GET", path)
            runs = result.get("check_runs") if isinstance(result, dict) else None
            if (not isinstance(runs, list) or len(runs) > 10
                    or type(result.get("total_count")) is not int
                    or not len(runs) <= result["total_count"] <= UINT_MAX):
                raise TelemetryError("lookup")
            for check in runs:
                if not isinstance(check, dict):
                    raise TelemetryError("lookup")
                if (check.get("head_sha") == self.binding.head and check.get("name") == CHECK_NAME
                        and check.get("external_id") == self.binding.external_id):
                    raise TelemetryError("exists")
            link = headers.get("Link", "")
            if not isinstance(link, str) or len(link) > 8192:
                raise TelemetryError("lookup")
            if 'rel="next"' not in link:
                if result["total_count"] > page * 10:
                    raise TelemetryError("lookup")
                return
        raise TelemetryError("lookup")

    def create(self, output):
        self.ensure_absent()
        now = utc_now()
        body = {"name": CHECK_NAME, "head_sha": self.binding.head,
                "external_id": self.binding.external_id, "status": "completed",
                "conclusion": "neutral", "started_at": now, "completed_at": now,
                "details_url": f"https://github.com/{self.binding.repository}/actions/runs/{self.binding.run}",
                "output": output}
        result, _ = self.request("POST", self.binding.prefix + "/check-runs", body, expected=201)
        validate_check(result, self.binding)
        if not isinstance(result.get("output"), dict) or result["output"].get("text") != output["text"]:
            raise TelemetryError("response")
        return result

    def patch(self, check_id, output):
        result, _ = self.request("PATCH", self.binding.prefix + f"/check-runs/{integer(check_id, True)}", {"output": output})
        validate_check(result, self.binding, check_id)
        if not isinstance(result.get("output"), dict) or result["output"].get("text") != output["text"]:
            raise TelemetryError("response")
        return result

    def get(self, check_id):
        result, _ = self.request("GET", self.binding.prefix + f"/check-runs/{integer(check_id, True)}")
        return validate_check(result, self.binding, check_id)


def open_parent(path):
    # Each ancestor is opened without following symlinks. Never resolve a hostile path.
    absolute = Path(os.path.abspath(path))
    parts = absolute.parts
    if len(parts) < 2 or parts[-1] in {".", ".."}:
        raise TelemetryError("file")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(parts[0], flags)
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def regular_info(fd, limit):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or not 0 <= info.st_size <= limit):
        raise TelemetryError("file")
    return info


def open_regular(path, limit):
    directory, basename = open_parent(path)
    try:
        fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        return fd, regular_info(fd, limit)
    except BaseException:
        os.close(fd)
        raise


def safe_mapping(value, keys, validator=integer):
    if not isinstance(value, dict):
        raise TelemetryError("record")
    return {key: validator(value[key]) for key in keys if key in value}


def sanitize_sample(record):
    if (not isinstance(record, dict) or not isinstance(record.get("reason"), str)
            or record["reason"] not in REASONS):
        raise TelemetryError("record")
    sample = {"time": normalized_utc(record.get("time")), "reason": record["reason"],
              "elapsed_seconds": number(record.get("elapsed_seconds"))}
    if sample["elapsed_seconds"] > MAX_LIFETIME + 60:
        raise TelemetryError("record")
    if "meminfo_kib" in record:
        sample["meminfo_kib"] = safe_mapping(record["meminfo_kib"], MEMORY)
    if "oom_kill" in record and record["oom_kill"] is not None:
        sample["oom_kill"] = integer(record["oom_kill"])
    if "cpu" in record:
        sample["cpu"] = safe_mapping(record["cpu"], {"logical", "affinity"})
    if "disks" in record:
        disks = record["disks"]
        if not isinstance(disks, dict):
            raise TelemetryError("record")
        sample["disks"] = {key: safe_mapping(disks[key], DISK)
                           for key in ("upstream", "log") if key in disks}
    if "cgroup_v2" in record:
        group = record["cgroup_v2"]
        if not isinstance(group, dict):
            raise TelemetryError("record")
        values = {}
        for key in ("memory.current", "memory.max"):
            if key in group and not (key == "memory.max" and group[key] == "max"):
                values[key] = integer(group[key])
        if "memory.events" in group:
            values["memory.events"] = safe_mapping(group["memory.events"], EVENTS)
        sample["cgroup_v2"] = values
    return sample


class ResourceReader:
    def __init__(self, path):
        self.path = Path(path)
        self.identity = None
        self.offset = 0

    def read(self):
        try:
            fd, info = open_regular(self.path, MAX_FILE)
        except FileNotFoundError:
            return []
        try:
            identity = info.st_dev, info.st_ino
            if self.identity is not None and identity != self.identity:
                raise TelemetryError("file")
            if info.st_size < self.offset:
                raise TelemetryError("file")
            self.identity = identity
            os.lseek(fd, self.offset, os.SEEK_SET)
            chunk = os.read(fd, MAX_READ)
            if b"\n" not in chunk and len(chunk) > MAX_LINE:
                raise TelemetryError("file")
            result = []
            consumed = 0
            for _ in range(MAX_BURST):
                end = chunk.find(b"\n", consumed)
                if end < 0:
                    break
                line = chunk[consumed:end]
                consumed = end + 1
                if not line or len(line) > MAX_LINE:
                    continue
                try:
                    result.append(sanitize_sample(parse_json(line)))
                except (TelemetryError, TypeError):
                    continue
            regular_info(fd, MAX_FILE)
            self.offset += consumed
            return result
        finally:
            os.close(fd)


def flatten(value, prefix=""):
    for key, item in value.items():
        path = prefix + key
        if isinstance(item, dict):
            yield from flatten(item, path + ".")
        elif type(item) in (int, float):
            yield path, item


class Measurements:
    def __init__(self):
        self.snapshots = deque(maxlen=6)
        self.seq = 0
        self.minima, self.peaks, self.counters = {}, {}, {}
        self.last_time = None
        self.terminal = False

    def add(self, sample):
        sample = sanitize_sample(sample)
        if self.last_time is not None and sample["time"] <= self.last_time:
            return False
        self.seq += 1
        sample["seq"] = self.seq
        self.last_time = sample["time"]
        self.snapshots.append(sample)
        self.terminal = sample["reason"] in TERMINAL
        for key, value in flatten(sample):
            if key == "oom_kill" or key.startswith("cgroup_v2.memory.events."):
                if key not in self.counters:
                    self.counters[key] = {"baseline": value, "latest": value, "delta": 0, "resets": 0}
                else:
                    counter = self.counters[key]
                    if value < counter["latest"]:
                        counter["resets"] += 1
                    counter["delta"] = None if counter["resets"] else value - counter["baseline"]
                    counter["latest"] = value
            elif key in {"meminfo_kib.MemAvailable", "meminfo_kib.SwapFree"} or key.endswith((".free_bytes", ".free_inodes")):
                self.minima[key] = min(value, self.minima.get(key, value))
            elif key == "cgroup_v2.memory.current":
                self.peaks[key] = max(value, self.peaks.get(key, value))
        return True

    def output(self, ack_seq=0, ack_at=None, ack_count=0, measured=False):
        now = utc_now()
        phase = "ENDED" if self.terminal else "OBSERVING" if self.seq else "WAITING"
        payload = {"schema": 1, "seq": self.seq,
                   "resource_ack_count": ack_count + int(measured),
                   "last_sample_at": self.last_time, "published_at": now,
                   "previous_ack_seq": ack_seq, "previous_ack_at": ack_at,
                   "phase": phase, "snapshots": list(self.snapshots),
                   "minima": self.minima, "peaks": self.peaks, "counters": self.counters}
        summary = ("Diagnostic-only last server-stored resource snapshot. Neutral is NOT a build result. "
                   "No measured resources yet (WAITING)." if not self.seq else
                   f"Diagnostic-only resource snapshot {self.seq}; last sample {self.last_time}. "
                   "Neutral is NOT a build result. Missing/newer samples can be lost; cause remains unknown.")
        output = {"title": "Last acknowledged RBM snapshot — not a build result", "summary": summary,
                  "text": "```json\n" + json_bytes(payload).decode("ascii") + "\n```"}
        if len(json_bytes({"output": output})) > MAX_REQUEST - 2048:
            raise TelemetryError("payload")
        return output


def process_ticks(pid):
    integer(pid, positive=True)
    path = Path(f"/proc/{pid}/stat")
    with path.open("rb") as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise TelemetryError("process")
    try:
        return int(raw[raw.rindex(b")") + 2:].split()[19])
    except (ValueError, IndexError):
        raise TelemetryError("process") from None


def state_binding(state):
    return Binding(state["repository"], state["head_sha"], state["run_id"],
                   state["run_attempt"], state["job_key"])


def validate_state(value):
    if (not isinstance(value, dict) or set(value) != STATE_KEYS
            or type(value.get("schema")) is not int or value["schema"] != 1):
        raise TelemetryError("state")
    binding = state_binding(value)
    for key, expected in binding.public().items():
        if value[key] != expected:
            raise TelemetryError("state")
    if not isinstance(value["phase"], str) or value["phase"] not in {"starting", "ready", "running", "ended"}:
        raise TelemetryError("state")
    for key in ("last_ack_seq", "resource_ack_count"):
        integer(value[key])
    for key in ("pid", "start_ticks", "check_id"):
        if value[key] is not None:
            integer(value[key], positive=True)
        elif value["phase"] != "starting":
            raise TelemetryError("state")
    if value["pid"] is not None and value["pid"] > 2 ** 31 - 1:
        raise TelemetryError("state")
    if value["resource_ack_count"] > value["last_ack_seq"]:
        raise TelemetryError("state")
    if value["resource_ack_count"] > 0 and value["last_sample_at"] is None:
        raise TelemetryError("state")
    normalized_utc(value["started_at"])
    for key in ("ready_at", "last_ack_at", "last_sample_at"):
        if value[key] is not None:
            normalized_utc(value[key])
    if value["phase"] != "starting" and (value["ready_at"] is None or value["last_ack_at"] is None):
        raise TelemetryError("state")
    return value


def read_state(path):
    fd, _ = open_regular(path, MAX_STATE)
    try:
        return validate_state(parse_json(os.read(fd, MAX_STATE + 1)))
    finally:
        os.close(fd)


def write_state(path, value):
    value = validate_state(value)
    raw = json_bytes(value) + b"\n"
    if len(raw) > MAX_STATE:
        raise TelemetryError("state")
    directory, basename = open_parent(path)
    name = ".rbm-telemetry-" + secrets.token_hex(12)
    try:
        try:
            current = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            current = None
        if current is not None:
            try:
                regular_info(current, MAX_STATE)
            finally:
                os.close(current)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as destination:
            destination.write(raw)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(name, basename, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def initial_state(binding):
    return {"schema": 1, **binding.public(), "check_id": None, "pid": None,
            "start_ticks": None, "started_at": utc_now(), "ready_at": None,
            "last_ack_seq": 0, "last_ack_at": None, "last_sample_at": None,
            "resource_ack_count": 0, "phase": "starting"}


class RequestBudget:
    """Count attempted writes, including failures. No burst/backlog replay."""
    def __init__(self, now):
        self.writes = deque([now])  # Initial POST already consumed one write.

    def delay(self, now):
        while self.writes and self.writes[0] <= now - 3600:
            self.writes.popleft()
        recent = [item for item in self.writes if item > now - 60]
        wait = 0
        if len(recent) >= 30:
            wait = max(wait, recent[0] + 60 - now)
        if len(self.writes) >= 400:
            wait = max(wait, self.writes[0] + 3600 - now)
        return wait

    def record(self, now):
        if self.delay(now) > 0:
            raise TelemetryError("rate")
        self.writes.append(now)


def run_worker(args, client_factory=GitHubChecks):
    os.environ.pop(TOKEN_ENV, None)
    binding = Binding(args.repository, args.head, args.run, args.attempt, args.job)
    try:
        token_bytes = os.read(args.credential_fd, 4097)
    finally:
        os.close(args.credential_fd)
    if not token_bytes or len(token_bytes) > 4096:
        raise TelemetryError("token")
    try:
        token = token_bytes.decode("ascii")
    except UnicodeError:
        raise TelemetryError("token") from None
    reserved = read_state(args.state)
    if state_binding(reserved) != binding or reserved["phase"] != "starting" or reserved["pid"] is not None:
        raise TelemetryError("state")
    state = initial_state(binding)
    state.update(pid=os.getpid(), start_ticks=process_ticks(os.getpid()))
    write_state(args.state, state)
    measurements = Measurements()
    reader = ResourceReader(args.resource_log)
    client = client_factory(binding, token)
    old_handlers = {}
    def stop(_signum, _frame):
        raise WorkerStop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, stop)
    started = time.monotonic()
    ready = False
    try:
        check = client.create(measurements.output())
        state.update(check_id=check["id"], ready_at=utc_now(), last_ack_at=utc_now(), phase="ready")
        # A cancellation can arrive as soon as the atomic ready marker is visible.
        # Record the known remote ACK before writing it so finally preserves that state.
        ready = True
        write_state(args.state, state)
        next_publish = time.monotonic() + args.interval
        failures = 0
        budget = RequestBudget(time.monotonic())
        while time.monotonic() - started < MAX_LIFETIME:
            try:
                for sample in reader.read():
                    measurements.add(sample)
            except (TelemetryError, OSError):
                pass  # Diagnostic-only; raw exceptions must never leave this worker.
            now = time.monotonic()
            if now >= next_publish:
                if measurements.seq > state["last_ack_seq"]:
                    wait = budget.delay(now)
                    if wait > 0:
                        next_publish = now + wait
                        continue
                    budget.record(now)
                    try:
                        output = measurements.output(state["last_ack_seq"], state["last_ack_at"],
                                                     state["resource_ack_count"], measured=True)
                        client.patch(state["check_id"], output)
                        state.update(last_ack_seq=measurements.seq, last_ack_at=utc_now(),
                                     last_sample_at=measurements.last_time,
                                     resource_ack_count=state["resource_ack_count"] + 1, phase="running")
                        write_state(args.state, state)
                        failures = 0
                        next_publish = time.monotonic() + args.interval
                    except (TelemetryError, OSError) as error:
                        failures = min(failures + 1, 10)
                        requested = error.retry_after if isinstance(error, TelemetryError) else 0
                        next_publish = time.monotonic() + max(args.interval, min(3600, 2 ** failures), requested)
                else:
                    next_publish = now + args.interval
                if measurements.terminal:
                    break
            time.sleep(min(0.25, max(0.01, next_publish - time.monotonic())))
    except WorkerStop:
        pass
    finally:
        if ready:
            state["phase"] = "ended"
            try:
                write_state(args.state, state)
            except (TelemetryError, OSError):
                pass
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def owned_process(pid, ticks, state_path, binding=None):
    try:
        if process_ticks(pid) != ticks:
            return False
        with Path(f"/proc/{pid}/cmdline").open("rb") as source:
            if os.fstat(source.fileno()).st_uid != os.getuid():
                return False
            raw = source.read(16385)
        if len(raw) > 16384:
            return False
        args = raw.rstrip(b"\0").decode("utf-8").split("\0")
        if len(args) < 4 or args[1] != str(SCRIPT) or args[2] != "_worker":
            return False
        if args.count("--state") != 1:
            return False
        index = args.index("--state")
        if Path(args[index + 1]).absolute() != Path(state_path).absolute():
            return False
        if binding is not None:
            expected = {"--repository": binding.repository, "--head": binding.head,
                        "--run": binding.run, "--attempt": binding.attempt, "--job": binding.job}
            for key, value in expected.items():
                if args.count(key) != 1 or args[args.index(key) + 1] != value:
                    return False
        return True
    except (OSError, ValueError, IndexError, UnicodeError, TelemetryError):
        return False


def signal_owned(pid, ticks, state_path, signum, binding=None):
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise TelemetryError("platform")
    try:
        handle = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        if not owned_process(pid, ticks, state_path, binding):
            raise TelemetryError("ownership")
        signal.pidfd_send_signal(handle, signum)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(handle)


def spawn_worker(args, token):
    command = [sys.executable, str(SCRIPT), "_worker", "--resource-log", str(args.resource_log),
               "--state", str(args.state), "--repository", args.repository, "--head", args.head,
               "--run", args.run, "--attempt", args.attempt, "--job", args.job,
               "--interval", str(args.interval)]
    env = dict(os.environ)
    env.pop(TOKEN_ENV, None)
    read_fd, write_fd = os.pipe()
    try:
        raw = token.encode("ascii")
        if not re.fullmatch(rb"[\x21-\x7e]{1,4096}", raw):
            raise TelemetryError("token")
        os.write(write_fd, raw)
        os.close(write_fd)
        write_fd = None
        command += ["--credential-fd", str(read_fd)]
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                close_fds=True, pass_fds=(read_fd,), env=env)
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def start(args, launch=spawn_worker, readiness=READINESS_SECONDS):
    binding = Binding(args.repository, args.head, args.run, args.attempt, args.job)
    token = os.environ.pop(TOKEN_ENV, None)
    if not token:
        raise TelemetryError("token")
    if Path(args.state).absolute() == Path(args.resource_log).absolute():
        raise TelemetryError("file")
    # An exclusive public marker forbids concurrent/repeated starts in this state.
    directory, basename = open_parent(args.state)
    try:
        fd = os.open(basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            os.write(fd, json_bytes(initial_state(binding)) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)
    process = launch(args, token)
    ticks = process_ticks(process.pid)
    ready = False
    deadline = time.monotonic() + readiness
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise TelemetryError("readiness")
            try:
                state = read_state(args.state)
                if (state_binding(state) == binding and state["pid"] == process.pid
                        and state["start_ticks"] == ticks and state["check_id"] is not None
                        and state["phase"] in {"ready", "running"}):
                    ready = True
                    return state
            except (TelemetryError, OSError):
                pass
            time.sleep(0.05)
        raise TelemetryError("readiness")
    finally:
        if not ready and process.poll() is None:
            # This is an unreaped direct child: PID reuse is impossible.
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass  # Keep the starter deadline; never wait on a build process.


def stop(args):
    state = read_state(args.state)
    if state["pid"] is None:
        return
    if not Path(f"/proc/{state['pid']}").exists():
        return
    binding = state_binding(state)
    if not signal_owned(state["pid"], state["start_ticks"], args.state, signal.SIGTERM, binding):
        return
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if not owned_process(state["pid"], state["start_ticks"], args.state, binding):
            return
        time.sleep(0.05)
    signal_owned(state["pid"], state["start_ticks"], args.state, signal.SIGKILL, binding)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("start", "_worker"):
        item = sub.add_parser(mode)
        item.add_argument("--resource-log", required=True, type=Path)
        item.add_argument("--state", required=True, type=Path)
        item.add_argument("--repository", required=True)
        item.add_argument("--head", required=True)
        item.add_argument("--run", required=True)
        item.add_argument("--attempt", required=True)
        item.add_argument("--job", required=True)
        item.add_argument("--interval", type=float, default=120)
        if mode == "_worker":
            item.add_argument("--credential-fd", type=int, required=True)
    item = sub.add_parser("stop")
    item.add_argument("--state", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.mode != "stop":
        if not math.isfinite(args.interval) or not 1 <= args.interval <= 3600:
            parser.error("interval must be finite and between 1 and 3600 seconds")
        args.resource_log = args.resource_log.absolute()
        args.state = args.state.absolute()
    return args


def main(argv=None):
    try:
        args = parse_args(argv)
        if args.mode == "start":
            start(args)
            print("RBM telemetry ready. Neutral diagnostic snapshots are not a build result.")
        elif args.mode == "stop":
            stop(args)
        else:
            run_worker(args)
        return 0
    except (TelemetryError, OSError, ValueError):
        print("RBM diagnostic telemetry could not complete this operation.", file=sys.stderr)
        return 1
    except WorkerStop:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
