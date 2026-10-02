#!/usr/bin/env python3
"""Offline native fixtures for authorized durable Checks telemetry.

Run in the cached project environment:
  nix --extra-experimental-features "nix-command flakes" develop \
    /home/nixos/workspaces/mullvad-browser-pgo-review/rbm-native-env \
    --command python3 tests/test_rbm_telemetry.py -v

All Checks requests use Python-injected transports. No fixture uses a live API,
URL override, workflow, download or GitHub write. Forked request children record
public request bodies, never tokens, in trace files. Mocked acknowledgments are
not production or CI evidence. Native helper processes exercise the real worker,
private credential pipe, EOF, process identity, pidfd and cancellation paths.
"""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
PUBLISHER = ROOT / "scripts/publish-rbm-telemetry.py"
MODULE_NAME = "rbm_telemetry_offline_native_tests"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, PUBLISHER)
telemetry = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = telemetry
SPEC.loader.exec_module(telemetry)


def forbid_live_request(*_args, **_kwargs):
    raise AssertionError("offline fixtures forbid live HTTP")


# A fail-closed safety net. Injection remains Python-only and changes no source,
# production CLI, API root or environment-based transport selection.
HTTPS_REQUEST = telemetry.https_request
telemetry.https_request = forbid_live_request
telemetry.urllib.request.build_opener = forbid_live_request
BINDING = telemetry.Binding("offline-owner/offline-repo", "a" * 40, "31415", "2", "pgo_generate")
WHEN = "2026-10-02T00:00:00+00:00"


def sample(index=0, reason="interval", **values):
    result = {"time": (datetime(2026, 10, 2, tzinfo=timezone.utc)
                       + timedelta(seconds=index)).isoformat(),
              "reason": reason, "elapsed_seconds": index}
    result.update(values)
    return result


def check(binding=BINDING, check_id=731, output=None):
    result = {"id": check_id, "head_sha": binding.head,
              "external_id": binding.external_id, "name": telemetry.CHECK_NAME,
              "url": telemetry.API_ROOT + binding.prefix + f"/check-runs/{check_id}",
              "status": "completed", "conclusion": "neutral",
              "app": {"slug": "github-actions"}}
    if output is not None:
        result["output"] = copy.deepcopy(output)
    return result


def append_public(path, value):
    # Only public fixture data reaches this file; credentials never do.
    raw = telemetry.json_bytes(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise AssertionError("short public fixture write")
    finally:
        os.close(fd)


def entries(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


class TraceTransport:
    """Recording survives bounded_request's fork; token never enters trace."""
    def __init__(self, binding, trace, token, reply=None):
        self.binding, self.trace, self.expected_token = binding, Path(trace), token
        self.reply = reply

    def __call__(self, token, method, path, body):
        if token != self.expected_token:
            raise telemetry.TelemetryError("token")
        append_public(self.trace, {"method": method, "path": path, "body": body})
        if self.reply is not None:
            return self.reply(method, path, body)
        if method == "GET" and "/commits/" in path:
            return 200, {"total_count": 0, "check_runs": []}, {}
        if method == "POST":
            return 201, check(self.binding, output=body["output"]), {}
        if method == "PATCH":
            return 200, check(self.binding, output=body["output"]), {}
        return 200, check(self.binding), {}


def ready_state(binding=BINDING, pid=None, ticks=None, phase="ready"):
    state = telemetry.initial_state(binding)
    state.update(check_id=731, pid=pid or os.getpid(),
                 start_ticks=ticks or telemetry.process_ticks(os.getpid()),
                 ready_at=WHEN, last_ack_at=WHEN, phase=phase)
    return state


def worker_args(base, credential_fd=None, binding=BINDING, interval=0.05):
    return types.SimpleNamespace(repository=binding.repository, head=binding.head,
                                 run=binding.run, attempt=binding.attempt,
                                 job=binding.job, resource_log=Path(base) / "resources.jsonl",
                                 state=Path(base) / "public-state.json", interval=interval,
                                 credential_fd=credential_fd)


def credential_pipe(token):
    read_fd, write_fd = os.pipe()
    try:
        raw = token.encode("ascii") if isinstance(token, str) else token
        if raw:
            os.write(write_fd, raw)
    finally:
        os.close(write_fd)
    return read_fd


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        # Native fixture synchronization, never agent/kernel polling.
        select.select([], [], [], 0.01)
    raise AssertionError("native fixture did not reach its public milestone")


def process_alive(pid, ticks=None):
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        fields = raw.rsplit(b")", 1)[1].split()
        return fields[0] != b"Z" and (ticks is None or int(fields[19]) == ticks)
    except (FileNotFoundError, ProcessLookupError):
        return False


def close_native_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def fixture_options(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fixture-mode", default="hold")
    parser.add_argument("--fixture-trace", type=Path, required=True)
    parser.add_argument("--fixture-interval", type=float, default=0.08)
    options, remaining = parser.parse_known_args(argv)
    return options, remaining


def fixture_worker(argv):
    options, remaining = fixture_options(argv)
    if options.fixture_mode == "identity-only":
        while True:
            signal.pause()
    args = telemetry.parse_args(["_worker", *remaining])
    # The public run_worker API accepts a short fixture interval. The production
    # CLI itself is still tested separately at its real one-second lower bound.
    args.interval = options.fixture_interval

    def factory(binding, token):
        try:
            os.fstat(args.credential_fd)
            credential_closed = False
        except OSError:
            credential_closed = True
        append_public(options.fixture_trace, {
            "event": "worker_metadata", "pid": os.getpid(),
            "token_env_present": telemetry.TOKEN_ENV in os.environ,
            "credential_fd_closed": credential_closed,
            "stdin_eof": os.read(0, 1) == b"",
            "stdio_devnull": all(os.readlink(f"/proc/self/fd/{fd}") == os.devnull for fd in (0, 1, 2)),
            "tracking_retained": os.environ.get("RUNNER_TRACKING_ID") == "offline-tracking",
            "session_is_private": os.getsid(0) == os.getpid()})

        def reply(method, path, body):
            if method == "GET":
                return 200, {"total_count": 0, "check_runs": []}, {}
            if method == "POST":
                if options.fixture_mode == "create-denied":
                    return 403, {}, {}
                if options.fixture_mode == "create-500":
                    return 500, {}, {}
                return 201, check(binding, output=body["output"]), {}
            payload = telemetry.decode_output({"output": body["output"]})
            if options.fixture_mode == "patch-denied":
                return 403, {}, {}
            if options.fixture_mode == "patch-500":
                return 500, {}, {}
            if options.fixture_mode == "progress" and payload["seq"] < 3:
                following = sample(payload["seq"] + 1,
                                   "exit" if payload["seq"] == 2 else "interval",
                                   meminfo_kib={"MemAvailable": 100 - payload["seq"]},
                                   oom_kill=payload["seq"])
                append_public(args.resource_log, following)
            return 200, check(binding, output=body["output"]), {}

        return telemetry.GitHubChecks(binding, token,
                                      TraceTransport(binding, options.fixture_trace, token, reply))

    try:
        if options.fixture_mode == "cancel-ready-write":
            native_write = telemetry.write_state
            def interrupt_ready(path, value):
                native_write(path, value)
                if value["phase"] == "ready":
                    os.kill(os.getpid(), signal.SIGTERM)
            with mock.patch.object(telemetry, "write_state", side_effect=interrupt_ready):
                telemetry.run_worker(args, client_factory=factory)
        else:
            telemetry.run_worker(args, client_factory=factory)
        return 0
    except (telemetry.TelemetryError, OSError, ValueError):
        # Do not print exception text, response bodies, environment or credentials.
        print("offline worker rejected the operation", file=sys.stderr)
        return 1


def fixture_starter(argv):
    options, remaining = fixture_options(argv)
    args = telemetry.parse_args(["start", *remaining])
    captured = {}
    private_token = os.environ.get(telemetry.TOKEN_ENV)
    original_popen = subprocess.Popen

    def native_launcher(command, **kwargs):
        captured.update({"private_pipe": len(kwargs.get("pass_fds", ())) == 1,
                         "stdio_devnull": all(kwargs[name] == subprocess.DEVNULL
                                              for name in ("stdin", "stdout", "stderr")),
                         "new_session": kwargs.get("start_new_session") is True,
                         "close_fds": kwargs.get("close_fds") is True,
                         "token_env_present": telemetry.TOKEN_ENV in kwargs["env"],
                         "tracking_retained": kwargs["env"].get("RUNNER_TRACKING_ID") == "offline-tracking",
                         "token_in_argv": any(private_token in argument for argument in command),
                         "credential_flag": command[-2] == "--credential-fd"})
        # Only substitute the executable fixture script. The real spawn_worker
        # chooses stdio, session, env, pass_fds and its private credential pipe.
        native = [command[0], str(SELF), "_worker", *command[3:],
                  "--fixture-mode", options.fixture_mode,
                  "--fixture-trace", str(options.fixture_trace),
                  "--fixture-interval", str(options.fixture_interval)]
        return original_popen(native, **kwargs)

    try:
        with mock.patch.object(telemetry.subprocess, "Popen", side_effect=native_launcher):
            state = telemetry.start(args, readiness=4)
        print(json.dumps({"state": state, "launch": captured}, sort_keys=True), flush=True)
        return 0
    except (telemetry.TelemetryError, OSError, ValueError):
        print("offline starter rejected the operation", file=sys.stderr)
        return 1


def fixture_orphan(trace):
    # Control is an ordinary native grandchild of the unittest process, not an
    # API child. No group signal is used to cancel the request owner.
    control = subprocess.Popen([sys.executable, str(SELF), "--fixture-idle"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    append_public(trace, {"event": "control", "pid": control.pid,
                          "ticks": telemetry.process_ticks(control.pid)})

    def blocked():
        append_public(trace, {"event": "api_child", "pid": os.getpid(),
                              "ticks": telemetry.process_ticks(os.getpid()),
                              "token_env_present": telemetry.TOKEN_ENV in os.environ})
        while True:
            signal.pause()
    telemetry.bounded_request(blocked, timeout=30)
    return 0


class OfflineFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rbm-telemetry-offline-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.trace = self.base / "public-requests.jsonl"
        self.resources = self.base / "resources.jsonl"
        self.state = self.base / "public-state.json"
        # Credentials are private runtime values. No fixture file contains one.
        self.token = "offline-sentinel-" + secrets.token_hex(24)
        self.environment = dict(os.environ)
        self.environment.pop(telemetry.TOKEN_ENV, None)
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.environment["RUNNER_TRACKING_ID"] = "offline-tracking"

    def client(self, reply=None):
        return telemetry.GitHubChecks(BINDING, self.token,
                                      TraceTransport(BINDING, self.trace, self.token, reply))

    def requests(self):
        return [item for item in entries(self.trace) if "method" in item]

    def assert_private_files(self):
        for path in self.base.rglob("*"):
            if path.is_file():
                self.assertTrue(self.token.encode("ascii") not in path.read_bytes(), "credential appeared in " + path.name)

    def write_samples(self, *records):
        self.resources.write_bytes(b"".join(telemetry.json_bytes(record) + b"\n"
                                           for record in records))

    def cli_arguments(self):
        return ["--resource-log", str(self.resources), "--state", str(self.state),
                "--repository", BINDING.repository, "--head", BINDING.head,
                "--run", BINDING.run, "--attempt", BINDING.attempt,
                "--job", BINDING.job, "--interval", "1"]

    def native_worker(self, mode="hold", interval=0.08, reserve=True):
        if reserve:
            telemetry.write_state(self.state, telemetry.initial_state(BINDING))
        read_fd = credential_pipe(self.token)
        try:
            process = subprocess.Popen(
                [sys.executable, str(SELF), "_worker", *self.cli_arguments(),
                 "--credential-fd", str(read_fd), "--fixture-mode", mode,
                 "--fixture-trace", str(self.trace), "--fixture-interval", str(interval)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(read_fd,), start_new_session=True,
                env=self.environment)
        finally:
            os.close(read_fd)
        self.addCleanup(close_native_process, process)
        return process

    def wait_state(self, predicate):
        def observed():
            try:
                state = telemetry.read_state(self.state)
                return state if predicate(state) else None
            except (FileNotFoundError, telemetry.TelemetryError):
                return None
        return wait_until(observed)

    def starter(self, mode="hold", interval=0.08):
        env = self.environment | {telemetry.TOKEN_ENV: self.token}
        result = subprocess.run(
            [sys.executable, str(SELF), "--fixture-starter", *self.cli_arguments(),
             "--fixture-mode", mode, "--fixture-trace", str(self.trace),
             "--fixture-interval", str(interval)],
            env=env, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
        self.assertTrue(self.token.encode() not in result.stdout + result.stderr, "credential reached native console")
        return result

    def stop_orphan_worker(self, state):
        if process_alive(state["pid"], state["start_ticks"]):
            with mock.patch.object(telemetry, "SCRIPT", SELF):
                telemetry.stop(types.SimpleNamespace(state=self.state))
            wait_until(lambda: not process_alive(state["pid"], state["start_ticks"]))


class BindingAndChecksTests(OfflineFixture):
    def test_binding_is_exact_strings_with_public_identity(self):
        self.assertEqual(BINDING.external_id, "31415:2:pgo_generate")
        self.assertEqual(BINDING.prefix, "/repos/offline-owner/offline-repo")
        self.assertEqual(BINDING.public(), {
            "repository": BINDING.repository, "head_sha": "a" * 40,
            "run_id": "31415", "run_attempt": "2", "job_key": "pgo_generate",
            "external_id": "31415:2:pgo_generate", "check_name": telemetry.CHECK_NAME})

    def test_binding_rejects_bad_repository_head_run_attempt_and_job(self):
        original = [BINDING.repository, BINDING.head, BINDING.run, BINDING.attempt, BINDING.job]
        cases = [(0, "../repo"), (0, "owner/repo/extra"), (0, "owner/r?x"),
                 (1, "A" * 40), (1, "a" * 39), (2, 31415), (2, "0"),
                 (2, "01"), (3, 2), (3, "-1"), (4, "job/name"), (4, "job name")]
        for index, value in cases:
            with self.subTest(index=index, value=value):
                values = original.copy()
                values[index] = value
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.Binding(*values)

    def test_readiness_get_empty_then_exact_completed_neutral_post201(self):
        output = telemetry.Measurements().output()
        observed = self.client().create(output)
        self.assertEqual(observed, check(output=output))
        calls = self.requests()
        self.assertEqual([item["method"] for item in calls], ["GET", "POST"])
        lookup = calls[0]
        self.assertIsNone(lookup["body"])
        parsed = telemetry.urllib.parse.urlsplit(lookup["path"])
        self.assertEqual(parsed.path, BINDING.prefix + f"/commits/{BINDING.head}/check-runs")
        self.assertEqual(telemetry.urllib.parse.parse_qs(parsed.query), {
            "check_name": [telemetry.CHECK_NAME], "filter": ["all"],
            "per_page": ["10"], "page": ["1"]})
        self.assertEqual(calls[1]["path"], BINDING.prefix + "/check-runs")
        body = calls[1]["body"]
        self.assertEqual(set(body), {"name", "head_sha", "external_id", "status", "conclusion",
                                     "started_at", "completed_at", "details_url", "output"})
        self.assertEqual(body["head_sha"], BINDING.head)
        self.assertEqual(body["external_id"], BINDING.external_id)
        self.assertEqual((body["status"], body["conclusion"]), ("completed", "neutral"))
        self.assertEqual(body["details_url"], f"https://github.com/{BINDING.repository}/actions/runs/{BINDING.run}")
        self.assertEqual(body["started_at"], body["completed_at"])
        telemetry.normalized_utc(body["started_at"])
        payload = telemetry.decode_output(observed)
        self.assertEqual((payload["seq"], payload["resource_ack_count"], payload["phase"]),
                         (0, 0, "WAITING"))
        self.assertEqual(payload["snapshots"], [])
        self.assert_private_files()

    def test_patch200_is_output_only_and_echoed_text_is_exact(self):
        measurements = telemetry.Measurements()
        measurements.add(sample(1, meminfo_kib={"MemAvailable": 400}))
        output = measurements.output(measured=True)
        observed = self.client().patch(731, output)
        self.assertEqual(observed["output"]["text"], output["text"])
        self.assertEqual(self.requests(), [{"method": "PATCH", "path": BINDING.prefix + "/check-runs/731",
                                          "body": {"output": output}}])
        self.assertEqual((observed["status"], observed["conclusion"]), ("completed", "neutral"))
        self.assert_private_files()

    def test_get_validates_bound_check_and_uses_no_body(self):
        self.assertEqual(self.client().get(731), check())
        self.assertEqual(self.requests(), [{"method": "GET", "path": BINDING.prefix + "/check-runs/731",
                                          "body": None}])

    def test_check_rejects_every_identity_status_url_and_app_mismatch(self):
        changes = [{"id": True}, {"id": 0}, {"id": 732}, {"head_sha": "b" * 40},
                   {"external_id": "31415:3:pgo_generate"}, {"name": "build"},
                   {"url": "https://example.invalid/repos/offline-owner/offline-repo/check-runs/731"},
                   {"url": telemetry.API_ROOT + "/repos/other/repo/check-runs/731"},
                   {"status": "in_progress"}, {"conclusion": "success"},
                   {"app": {"slug": "untrusted-app"}}, {"app": None}]
        for changed in changes:
            with self.subTest(changed=changed):
                value = check()
                value.update(changed)
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.validate_check(value, BINDING, 731)

    def test_post_does_not_accept200_or_acknowledge_a_changed_echo(self):
        output = telemetry.Measurements().output()
        for wrong_status, wrong_text in ((200, False), (201, True)):
            with self.subTest(status=wrong_status, text_changed=wrong_text):
                def reply(method, _path, body):
                    if method == "GET":
                        return 200, {"total_count": 0, "check_runs": []}, {}
                    observed = check(output=body["output"])
                    if wrong_text:
                        observed["output"]["text"] += " "
                    return wrong_status, observed, {}
                with self.assertRaises(telemetry.TelemetryError):
                    self.client(reply).create(output)

    def test_patch_rejects_failed_status_changed_text_and_changed_binding(self):
        output = telemetry.Measurements().output()
        for status, change in ((201, {}), (200, {"head_sha": "b" * 40}),
                               (200, {"output": {"text": "different"}})):
            with self.subTest(status=status, change=change):
                def reply(_method, _path, _body):
                    observed = check(output=output)
                    observed.update(change)
                    return status, observed, {}
                with self.assertRaises(telemetry.TelemetryError):
                    self.client(reply).patch(731, output)

    def test_denied_auth_and_http500_fail_closed_without_post(self):
        for status in (401, 403, 500):
            with self.subTest(status=status):
                self.trace.unlink(missing_ok=True)
                def reply(_method, _path, _body):
                    return status, {"message": "must not escape"}, {}
                with self.assertRaises(telemetry.TelemetryError) as raised:
                    self.client(reply).create(telemetry.Measurements().output())
                self.assertNotIn("must not escape", str(raised.exception))
                self.assertEqual([item["method"] for item in self.requests()], ["GET"])

    def test_duplicate_lookup_never_posts_even_after_uncertain_restart(self):
        def reply(_method, _path, _body):
            return 200, {"total_count": 1, "check_runs": [check()]}, {}
        with self.assertRaises(telemetry.TelemetryError) as raised:
            self.client(reply).create(telemetry.Measurements().output())
        self.assertEqual(raised.exception.category, "exists")
        self.assertEqual([item["method"] for item in self.requests()], ["GET"])

    def test_other_attempt_does_not_block_current_bound_check(self):
        def reply(method, _path, body):
            if method == "GET":
                foreign = check()
                foreign["external_id"] = "31415:1:pgo_generate"
                return 200, {"total_count": 1, "check_runs": [foreign]}, {}
            return 201, check(output=body["output"]), {}
        self.client(reply).create(telemetry.Measurements().output())
        self.assertEqual([item["method"] for item in self.requests()], ["GET", "POST"])

    def test_lookup_shape_count_and_page_limits_are_bounded(self):
        bad = [{"total_count": True, "check_runs": []}, {"total_count": -1, "check_runs": []},
               {"total_count": 1, "check_runs": [None]}, {"total_count": 11, "check_runs": []},
               {"total_count": 0, "check_runs": {}}, {"total_count": 11, "check_runs": [{}] * 11}]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(telemetry.TelemetryError):
                    self.client(lambda *_: (200, value, {})).ensure_absent()
        self.trace.unlink(missing_ok=True)
        with self.assertRaises(telemetry.TelemetryError):
            self.client(lambda *_: (200, {"total_count": 0, "check_runs": []},
                                   {"Link": '<https://example.invalid/next>; rel="next"'})).ensure_absent()
        self.assertEqual(len(self.requests()), telemetry.MAX_PAGES)
        self.assertEqual([telemetry.urllib.parse.parse_qs(telemetry.urllib.parse.urlsplit(item["path"]).query)["page"][0]
                          for item in self.requests()], [str(i) for i in range(1, telemetry.MAX_PAGES + 1)])

    def test_request_body_limit_is_checked_before_transport(self):
        with self.assertRaises(telemetry.TelemetryError):
            self.client().request("PATCH", BINDING.prefix + "/check-runs/731",
                                  {"output": {"text": "x" * telemetry.MAX_REQUEST}})
        self.assertEqual(self.requests(), [])

    def test_decode_output_requires_fenced_bounded_unique_schema_json(self):
        correct = telemetry.Measurements().output()
        self.assertEqual(telemetry.decode_output({"output": correct})["schema"], 1)
        bad = [None, {"output": {"text": "{}"}}, {"output": {"text": "```json\n[]\n```"}},
               {"output": {"text": "```json\n{\"schema\":2}\n```"}},
               {"output": {"text": "```json\n{\"schema\":true}\n```"}},
               {"output": {"text": "```json\n{\"schema\":1,\"schema\":1}\n```"}},
               {"output": {"text": "```json\n{\"schema\":1,\"value\":NaN}\n```"}},
               {"output": {"text": "x" * (telemetry.MAX_REQUEST + 1)}}]
        for value in bad:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.decode_output(value)


class HttpsBoundaryTests(OfflineFixture):
    """The real encoder/parser run against a Python-only opener, never a socket."""
    def https(self, raw=b"{}", headers=None, status=200, error=None,
              method="GET", path=None, body=None, token=None):
        response = mock.MagicMock()
        response.status = status
        response.headers = headers or {}
        response.read.return_value = raw
        response.__enter__.return_value = response
        opener = mock.Mock()
        opener.open.side_effect = error
        if error is None:
            opener.open.return_value = response
        with mock.patch.object(telemetry.urllib.request, "build_opener", return_value=opener) as build:
            result = HTTPS_REQUEST(self.token if token is None else token,
                                   method, path or BINDING.prefix + "/check-runs/731", body)
        return result, opener, response, build

    def test_authorized_request_is_bound_to_fixed_https_api_and_no_redirect(self):
        result, opener, response, build = self.https(raw=telemetry.json_bytes(check()))
        self.assertEqual(result, (200, check(), {"Retry-After": "0", "Link": ""}))
        handler = build.call_args.args[0]
        self.assertIsInstance(handler, telemetry.NoRedirect)
        self.assertIsNone(handler.redirect_request(None, None, 302, "", {}, "https://example.invalid"))
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, telemetry.API_ROOT + BINDING.prefix + "/check-runs/731")
        self.assertEqual(request.get_method(), "GET")
        self.assertTrue(request.get_header("Authorization") == "Bearer " + self.token, "private authorization was incorrect")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": telemetry.REQUEST_SECONDS})
        response.read.assert_called_once_with(telemetry.MAX_RESPONSE + 1)
        self.assert_private_files()

    def test_post_request_encodes_only_bounded_json_body(self):
        body = {"output": telemetry.Measurements().output()}
        _, opener, _, _ = self.https(method="POST", body=body, status=201)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.data, telemetry.json_bytes(body))
        self.assertEqual(request.get_method(), "POST")
        self.assertLessEqual(len(request.data), telemetry.MAX_REQUEST)
        self.assertTrue(self.token.encode() not in request.data, "credential reached request body")

    def test_https_rejects_bad_method_path_token_and_oversized_body_before_opener(self):
        cases = [{"method": "DELETE"}, {"path": "https://example.invalid/repos/owner/repo"},
                 {"token": ""}, {"token": "line\nbreak"}, {"token": "x" * 4097},
                 {"body": {"text": "x" * telemetry.MAX_REQUEST}}]
        for values in cases:
            with self.subTest(fields=list(values)):
                with mock.patch.object(telemetry.urllib.request, "build_opener",
                                       side_effect=AssertionError("invalid request reached opener")):
                    with self.assertRaises(telemetry.TelemetryError):
                        HTTPS_REQUEST(values.get("token", self.token), values.get("method", "GET"),
                                      values.get("path", BINDING.prefix), values.get("body"))

    def test_content_length_header_and_link_retry_headers_are_bounded(self):
        for headers in ({"Content-Length": str(telemetry.MAX_RESPONSE + 1)},
                        {"Content-Length": "-1"}, {"Content-Length": "unknown"},
                        {"Link": "x" * 8193}, {"Retry-After": "9" * 8193}):
            with self.subTest(headers=list(headers)):
                with self.assertRaises(telemetry.TelemetryError):
                    self.https(headers=headers)

    def test_response_body_cap_invalid_json_duplicates_and_nonfinite_reject(self):
        for raw in (b"x" * (telemetry.MAX_RESPONSE + 1), b"not json", b"\xff", b'{"truncated":',
                    b'{"id":1,"id":2}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(length=len(raw)):
                with self.assertRaises(telemetry.TelemetryError):
                    self.https(raw=raw)

    def test_http_error_429_closes_body_keeps_retry_after_and_drops_body_message(self):
        body = __import__("io").BytesIO(self.token.encode())
        error = telemetry.urllib.error.HTTPError(telemetry.API_ROOT + BINDING.prefix, 429,
                                                self.token, {"Retry-After": "12"}, body)
        with self.assertRaises(telemetry.TelemetryError) as raised:
            self.https(error=error)
        self.assertEqual((raised.exception.category, raised.exception.status, raised.exception.retry_after),
                         ("http", 429, 12))
        self.assertEqual(str(raised.exception), "telemetry http")
        self.assertTrue(body.closed)
        self.assert_private_files()

    def test_redirect_denied_auth500_and_network_errors_are_fixed_categories(self):
        for status in (302, 401, 403, 500):
            with self.subTest(status=status):
                body = __import__("io").BytesIO(self.token.encode())
                error = telemetry.urllib.error.HTTPError(telemetry.API_ROOT + BINDING.prefix,
                                                        status, self.token, {}, body)
                with self.assertRaises(telemetry.TelemetryError) as raised:
                    self.https(error=error)
                self.assertEqual((raised.exception.category, raised.exception.status), ("http", status))
                self.assertTrue(self.token not in str(raised.exception), "credential reached exception text")
                self.assertTrue(body.closed)
        for error in (OSError(self.token), telemetry.urllib.error.URLError(self.token), ValueError(self.token)):
            with self.subTest(type=type(error).__name__):
                with self.assertRaises(telemetry.TelemetryError) as raised:
                    self.https(error=error)
                self.assertEqual(str(raised.exception), "telemetry transport")

    def test_retry_after_is_finite_bounded_and_handles_past_and_invalid_dates(self):
        self.assertEqual(telemetry.retry_delay({"Retry-After": "12"}), 12)
        self.assertEqual(telemetry.retry_delay({"Retry-After": "99999999"}), telemetry.MAX_LIFETIME)
        self.assertEqual(telemetry.retry_delay({"Retry-After": "Thu, 01 Jan 1970 00:00:00 GMT"}), 0)
        self.assertEqual(telemetry.retry_delay({"Retry-After": "Fri, 01 Jan 2100 00:00:00 GMT"}), telemetry.MAX_LIFETIME)
        for value in ("not a date", "-1", "nan", "9" * 81, None, 5, []):
            with self.subTest(type=type(value).__name__):
                self.assertEqual(telemetry.retry_delay({"Retry-After": value}), 0)


class BoundedRequestTests(OfflineFixture):
    def test_result_survives_real_fork_but_parent_call_list_is_not_shared(self):
        calls = []
        def operation():
            calls.append("child-only")
            append_public(self.trace, {"pid": os.getpid(), "parent": os.getppid()})
            return 200, {"public": True}, {}
        self.assertEqual(telemetry.bounded_request(operation, timeout=1), [200, {"public": True}, {}])
        self.assertEqual(calls, [])
        child = entries(self.trace)[0]
        self.assertNotEqual(child["pid"], os.getpid())
        self.assertEqual(child["parent"], os.getpid())
        self.assertFalse(Path(f"/proc/{child['pid']}").exists())

    def test_api_child_stdio_is_devnull_and_stdin_is_native_eof(self):
        def operation():
            return 200, {"stdin_eof": os.read(0, 1) == b"",
                         "devnull_streams": all(os.readlink(f"/proc/self/fd/{fd}") == os.devnull
                                                for fd in (0, 1, 2))}, {}
        self.assertEqual(telemetry.bounded_request(operation, timeout=1),
                         [200, {"stdin_eof": True, "devnull_streams": True}, {}])

    def test_http_error_preserves_only_fixed_category_status_retry(self):
        def denied():
            raise telemetry.TelemetryError("http", 403, 12)
        with self.assertRaises(telemetry.TelemetryError) as raised:
            telemetry.bounded_request(denied, timeout=1)
        self.assertEqual((raised.exception.category, raised.exception.status, raised.exception.retry_after),
                         ("http", 403, 12))
        self.assertEqual(str(raised.exception), "telemetry http")

    def test_arbitrary_exception_does_not_publish_message_or_credentials(self):
        def fail():
            raise RuntimeError(self.token)
        with self.assertRaises(telemetry.TelemetryError) as raised:
            telemetry.bounded_request(fail, timeout=1)
        self.assertEqual(str(raised.exception), "telemetry transport")
        self.assertTrue(self.token not in str(raised.exception), "credential reached exception text")
        self.assert_private_files()

    def test_hung_operation_has_actual_wall_deadline_and_child_is_reaped(self):
        def blocked():
            append_public(self.trace, {"pid": os.getpid()})
            while True:
                signal.pause()
        before = time.monotonic()
        with self.assertRaises(telemetry.TelemetryError) as raised:
            telemetry.bounded_request(blocked, timeout=0.08)
        self.assertEqual(raised.exception.category, "timeout")
        self.assertLess(time.monotonic() - before, 1)
        self.assertFalse(Path(f"/proc/{entries(self.trace)[0]['pid']}").exists())

    def test_github_timeout_uses_native_bounded_child_without_network(self):
        def reply(*_args):
            while True:
                signal.pause()
        native_bound = telemetry.bounded_request
        before = time.monotonic()
        with mock.patch.object(telemetry, "bounded_request",
                               side_effect=lambda op: native_bound(op, timeout=0.08)):
            with self.assertRaises(telemetry.TelemetryError) as raised:
                self.client(reply).create(telemetry.Measurements().output())
        self.assertEqual(raised.exception.category, "timeout")
        self.assertLess(time.monotonic() - before, 1)
        self.assertEqual([item["method"] for item in self.requests()], ["GET"])

    def test_response_serialization_and_result_shape_are_bounded(self):
        for operation in (lambda: {"not": "a triple"}, lambda: [200, {}],
                          lambda: (200, {"huge": "x" * (telemetry.MAX_RESPONSE + 20000)}, {})):
            with self.subTest(operation=operation):
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.bounded_request(operation, timeout=1)

    def test_api_child_removes_token_env_and_retains_runner_tracking(self):
        def operation():
            return 200, {"token_env_present": telemetry.TOKEN_ENV in os.environ,
                         "tracking": os.environ.get("RUNNER_TRACKING_ID")}, {}
        with mock.patch.dict(os.environ, {telemetry.TOKEN_ENV: self.token,
                                          "RUNNER_TRACKING_ID": "offline-tracking"}):
            result = telemetry.bounded_request(operation, timeout=1)
            self.assertEqual(os.environ[telemetry.TOKEN_ENV], self.token)
        self.assertEqual(result, [200, {"token_env_present": False, "tracking": "offline-tracking"}, {}])

    def test_sigkill_owner_kills_api_child_but_not_native_grandchild(self):
        env = self.environment | {telemetry.TOKEN_ENV: self.token}
        owner = subprocess.Popen([sys.executable, str(SELF), "--fixture-orphan", str(self.trace)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=env)
        self.addCleanup(close_native_process, owner)
        records = wait_until(lambda: entries(self.trace) if len(entries(self.trace)) == 2 else None)
        control, api = records
        self.assertEqual((control["event"], api["event"]), ("control", "api_child"))
        self.assertFalse(api["token_env_present"])
        control_fd = os.pidfd_open(control["pid"])
        self.addCleanup(os.close, control_fd)
        self.addCleanup(lambda: signal.pidfd_send_signal(control_fd, signal.SIGKILL)
                        if process_alive(control["pid"], control["ticks"]) else None)
        os.kill(owner.pid, signal.SIGKILL)
        self.assertEqual(owner.wait(timeout=1), -signal.SIGKILL)
        wait_until(lambda: not process_alive(api["pid"], api["ticks"]))
        self.assertTrue(process_alive(control["pid"], control["ticks"]),
                        "owner cancellation must not signal a native process group")
        signal.pidfd_send_signal(control_fd, signal.SIGTERM)
        wait_until(lambda: not process_alive(control["pid"], control["ticks"]))
        self.assert_private_files()


class ResourceReaderTests(OfflineFixture):
    def reader(self):
        return telemetry.ResourceReader(self.resources)

    def test_huge_numeric_and_unhashable_reason_rows_do_not_lose_later_valid_row(self):
        invalid = [sample(1, elapsed_seconds=10 ** 400), sample(2, reason=[]),
                   sample(3, reason={}), sample(4, meminfo_kib={"MemAvailable": 10 ** 400})]
        good = sample(5, meminfo_kib={"MemAvailable": 123})
        self.write_samples(*invalid, good)
        reader = self.reader()
        self.assertEqual(reader.read(), [good])
        self.assertEqual(reader.offset, self.resources.stat().st_size)
        self.assertEqual(reader.read(), [])

    def test_missing_file_is_empty_and_can_appear_later(self):
        reader = self.reader()
        self.assertEqual(reader.read(), [])
        self.write_samples(sample(1))
        self.assertEqual(reader.read(), [sample(1)])

    def test_complete_only_keeps_partial_line_until_newline(self):
        first, following = sample(1), sample(2)
        raw = telemetry.json_bytes(following)
        self.resources.write_bytes(telemetry.json_bytes(first) + b"\n" + raw[:20])
        reader = self.reader()
        self.assertEqual(reader.read(), [first])
        offset = reader.offset
        self.assertEqual(reader.read(), [])
        self.assertEqual(reader.offset, offset)
        with self.resources.open("ab") as destination:
            destination.write(raw[20:] + b"\n")
        self.assertEqual(reader.read(), [following])
        self.assertEqual(reader.read(), [])

    def test_bad_blank_duplicate_and_overlong_lines_are_skipped(self):
        good = sample(3)
        duplicate = b'{"reason":"interval","reason":"exit","time":"2026-10-02T00:00:02Z","elapsed_seconds":2}'
        self.resources.write_bytes(b"\nnot json\n" + duplicate + b"\n"
                                   + b"x" * (telemetry.MAX_LINE + 1) + b"\n"
                                   + telemetry.json_bytes(good) + b"\n")
        self.assertEqual(self.reader().read(), [good])

    def test_single_read_and_burst_have_hard_bounds(self):
        self.write_samples(*(sample(index) for index in range(200)))
        native_read = os.read
        sizes = []
        def capture(fd, size):
            sizes.append(size)
            return native_read(fd, size)
        reader = self.reader()
        with mock.patch.object(telemetry.os, "read", side_effect=capture):
            first = reader.read()
        self.assertEqual(sizes, [telemetry.MAX_READ])
        self.assertEqual(len(first), telemetry.MAX_BURST)
        result = first
        for _ in range(4):
            result += reader.read()
        self.assertEqual(result, [sample(index) for index in range(200)])
        self.assertEqual(reader.offset, self.resources.stat().st_size)

    def test_file_size_and_unterminated_read_limits_reject(self):
        self.resources.write_bytes(b"x" * telemetry.MAX_READ)
        with self.assertRaises(telemetry.TelemetryError):
            self.reader().read()
        with self.resources.open("wb") as destination:
            destination.truncate(telemetry.MAX_FILE + 1)
        with self.assertRaises(telemetry.TelemetryError):
            self.reader().read()

    def test_final_symlink_and_symlink_ancestor_are_not_followed(self):
        target = self.base / "real.jsonl"
        target.write_bytes(telemetry.json_bytes(sample(1)) + b"\n")
        self.resources.symlink_to(target)
        with self.assertRaises((OSError, telemetry.TelemetryError)):
            self.reader().read()
        directory = self.base / "real-dir"
        directory.mkdir()
        (directory / "resources.jsonl").write_bytes(target.read_bytes())
        link = self.base / "linked-dir"
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises((OSError, telemetry.TelemetryError)):
            telemetry.ResourceReader(link / "resources.jsonl").read()

    def test_hardlink_directory_and_fifo_reject_without_blocking(self):
        target = self.base / "shared.jsonl"
        target.write_bytes(telemetry.json_bytes(sample(1)) + b"\n")
        os.link(target, self.resources)
        with self.assertRaises(telemetry.TelemetryError):
            self.reader().read()
        self.resources.unlink()
        self.resources.mkdir()
        with self.assertRaises(telemetry.TelemetryError):
            self.reader().read()
        self.resources.rmdir()
        os.mkfifo(self.resources)
        before = time.monotonic()
        with self.assertRaises(telemetry.TelemetryError):
            self.reader().read()
        self.assertLess(time.monotonic() - before, 0.5)

    def test_replaced_inode_and_truncated_file_are_rejected(self):
        self.write_samples(sample(1))
        reader = self.reader()
        reader.read()
        alternate = self.base / "replacement.jsonl"
        alternate.write_bytes(self.resources.read_bytes())
        alternate.replace(self.resources)
        with self.assertRaises(telemetry.TelemetryError):
            reader.read()
        reader = self.reader()
        reader.read()
        self.resources.write_bytes(b"")
        with self.assertRaises(telemetry.TelemetryError):
            reader.read()

    def test_same_uid_is_required_for_regular_input(self):
        self.write_samples(sample(1))
        native_stat = os.fstat
        def foreign(fd):
            observed = native_stat(fd)
            return types.SimpleNamespace(st_mode=observed.st_mode, st_nlink=observed.st_nlink,
                                         st_size=observed.st_size, st_uid=os.getuid() + 1)
        with mock.patch.object(telemetry.os, "fstat", side_effect=foreign):
            with self.assertRaises(telemetry.TelemetryError):
                self.reader().read()

    def test_all_ancestors_are_checked_not_only_immediate_parent(self):
        real = self.base / "real"
        nested = real / "one" / "two"
        nested.mkdir(parents=True)
        (nested / "resources.jsonl").write_bytes(telemetry.json_bytes(sample(1)) + b"\n")
        link = self.base / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises((OSError, telemetry.TelemetryError)):
            telemetry.ResourceReader(link / "one" / "two" / "resources.jsonl").read()


class SanitizationAndMeasurementsTests(OfflineFixture):
    def test_only_resource_allowlists_survive_not_errors_paths_env_argv_tails(self):
        raw = sample(1, reason="signal", arbitrary=self.token, errors=[self.token],
                     path="/private/path", env={"TOKEN": self.token}, argv=[self.token], tail=self.token,
                     meminfo_kib={"MemTotal": 100, "MemAvailable": 50, "SwapTotal": 20, "SwapFree": 10,
                                  "secret": self.token}, oom_kill=1,
                     cpu={"logical": 4, "affinity": 2, "hostname": self.token},
                     disks={"upstream": {"total_bytes": 20, "free_bytes": 10, "total_inodes": 9,
                                          "free_inodes": 8, "path": self.token},
                            "log": {"free_bytes": 7}, "private": {"free_bytes": 1}},
                     cgroup_v2={"memory.current": 12, "memory.max": "max",
                                "memory.events": {"low": 1, "oom": 2, "oom_kill": 3, "secret": self.token},
                                "path": self.token, "errors": [self.token]})
        clean = telemetry.sanitize_sample(raw)
        self.assertEqual(set(clean), {"time", "reason", "elapsed_seconds", "meminfo_kib", "oom_kill",
                                      "cpu", "disks", "cgroup_v2"})
        self.assertEqual(clean["meminfo_kib"], {"MemTotal": 100, "MemAvailable": 50, "SwapTotal": 20, "SwapFree": 10})
        self.assertEqual(clean["cpu"], {"logical": 4, "affinity": 2})
        self.assertEqual(set(clean["disks"]), {"upstream", "log"})
        self.assertEqual(set(clean["disks"]["upstream"]), telemetry.DISK)
        self.assertEqual(clean["cgroup_v2"], {"memory.current": 12, "memory.events": {"low": 1, "oom": 2, "oom_kill": 3}})
        self.assertTrue(self.token not in telemetry.json_bytes(clean).decode(), "credential survived sanitizer")
        measurements = telemetry.Measurements()
        measurements.add(raw)
        self.assertTrue(self.token not in telemetry.json_bytes(measurements.output()).decode(), "credential reached output")

    def test_nonfinite_boolean_negative_and_unbounded_numbers_reject(self):
        bad = [True, -1, float("nan"), float("inf"), float("-inf"), telemetry.UINT_MAX + 1, 10 ** 400, "5"]
        for value in bad:
            for values in ({"elapsed_seconds": value}, {"oom_kill": value},
                           {"meminfo_kib": {"MemAvailable": value}},
                           {"cpu": {"logical": value}}, {"disks": {"log": {"free_bytes": value}}},
                           {"cgroup_v2": {"memory.events": {"oom_kill": value}}}):
                with self.subTest(type=type(value).__name__, fields=list(values)):
                    with self.assertRaises(telemetry.TelemetryError):
                        telemetry.sanitize_sample(sample(1, **values))
        self.assertEqual(telemetry.sanitize_sample(sample(1, elapsed_seconds=0.5))["elapsed_seconds"], 0.5)
        with self.assertRaises(telemetry.TelemetryError):
            telemetry.sanitize_sample(sample(1, cpu={"logical": 1.5}))

    def test_reason_utc_time_and_elapsed_lifetime_are_strict(self):
        for reason in telemetry.REASONS:
            self.assertEqual(telemetry.sanitize_sample(sample(1, reason))["reason"], reason)
        for changes in ({"reason": "arbitrary"}, {"reason": None}, {"reason": []}, {"reason": {}},
                        {"time": "2026-10-02T00:00:00+03:00"},
                        {"time": "2026-02-30T00:00:00Z"}, {"time": "2026-10-02"},
                        {"elapsed_seconds": telemetry.MAX_LIFETIME + 61}):
            with self.subTest(changes=changes):
                value = sample(1)
                value.update(changes)
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.sanitize_sample(value)
        self.assertEqual(telemetry.sanitize_sample(sample(1, time="2026-10-02T00:00:01Z"))["time"],
                         "2026-10-02T00:00:01+00:00")

    def test_resource_mappings_and_memory_max_have_strict_numeric_types(self):
        for changes in ({"meminfo_kib": []}, {"cpu": None}, {"disks": []},
                        {"disks": {"log": []}}, {"cgroup_v2": []},
                        {"cgroup_v2": {"memory.events": []}}, {"cgroup_v2": {"memory.max": "secret"}}):
            with self.subTest(changes=changes):
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.sanitize_sample(sample(1, **changes))
        self.assertEqual(telemetry.sanitize_sample(sample(1, oom_kill=None, cgroup_v2={"memory.max": 999}))["cgroup_v2"],
                         {"memory.max": 999})

    def test_rolling_six_snapshots_and_monotonic_unique_sequence(self):
        measurements = telemetry.Measurements()
        for index in range(1, 10):
            self.assertTrue(measurements.add(sample(index)))
        self.assertFalse(measurements.add(sample(9)))
        self.assertFalse(measurements.add(sample(4, "exit")))
        self.assertEqual(measurements.seq, 9)
        self.assertEqual([item["seq"] for item in measurements.snapshots], list(range(4, 10)))
        self.assertEqual(measurements.last_time, sample(9)["time"])
        self.assertFalse(measurements.terminal)

    def test_minima_peaks_and_counters_survive_snapshot_eviction(self):
        measurements = telemetry.Measurements()
        for index in range(1, 10):
            measurements.add(sample(index, meminfo_kib={"MemAvailable": 100 + index, "SwapFree": 200 - index},
                                    disks={"upstream": {"free_bytes": 300 - index, "free_inodes": 400 + index},
                                           "log": {"free_bytes": 500 - index}},
                                    cgroup_v2={"memory.current": 1000 - index,
                                               "memory.events": {"oom_kill": index}}, oom_kill=10 + index))
        self.assertEqual(measurements.minima, {"meminfo_kib.MemAvailable": 101, "meminfo_kib.SwapFree": 191,
                                              "disks.upstream.free_bytes": 291, "disks.upstream.free_inodes": 401,
                                              "disks.log.free_bytes": 491})
        self.assertEqual(measurements.peaks, {"cgroup_v2.memory.current": 999})
        self.assertEqual(measurements.counters["oom_kill"], {"baseline": 11, "latest": 19, "delta": 8, "resets": 0})
        self.assertEqual(measurements.counters["cgroup_v2.memory.events.oom_kill"],
                         {"baseline": 1, "latest": 9, "delta": 8, "resets": 0})

    def test_counter_resets_keep_baseline_and_make_delta_null_permanently(self):
        measurements = telemetry.Measurements()
        for index, value in enumerate((5, 9, 2, 7, 1), 1):
            measurements.add(sample(index, oom_kill=value, cgroup_v2={"memory.events": {"high": value}}))
            counter = measurements.counters["oom_kill"]
            self.assertEqual(counter["baseline"], 5)
            self.assertEqual(counter["latest"], value)
            self.assertEqual(counter["delta"], value - 5 if index < 3 else None)
        self.assertEqual(measurements.counters["oom_kill"]["resets"], 2)
        self.assertEqual(measurements.counters["cgroup_v2.memory.events.high"], measurements.counters["oom_kill"])
        measurements.add(sample(6))
        self.assertEqual(measurements.counters["oom_kill"]["latest"], 1)

    def test_waiting_running_ended_phases_and_only_measured_ack_count(self):
        measurements = telemetry.Measurements()
        waiting = telemetry.decode_output({"output": measurements.output()})
        self.assertEqual((waiting["phase"], waiting["seq"], waiting["resource_ack_count"]), ("WAITING", 0, 0))
        measurements.add(sample(1, "start"))
        running = telemetry.decode_output({"output": measurements.output(0, WHEN, 0, measured=True)})
        self.assertEqual((running["phase"], running["seq"], running["resource_ack_count"]), ("OBSERVING", 1, 1))
        self.assertEqual((running["previous_ack_seq"], running["previous_ack_at"]), (0, WHEN))
        measurements.add(sample(2, "exit"))
        ended = telemetry.decode_output({"output": measurements.output(1, WHEN, 1, measured=True)})
        self.assertEqual((ended["phase"], ended["seq"], ended["resource_ack_count"]), ("ENDED", 2, 2))
        self.assertIn("NOT a build result", measurements.output()["summary"])

    def test_full_allowlisted_output_stays_below16kib_and_has_no_secrets(self):
        measurements = telemetry.Measurements()
        for index in range(1, 9):
            measurements.add(sample(index, meminfo_kib={key: telemetry.UINT_MAX - index for key in telemetry.MEMORY},
                                    cpu={"logical": telemetry.UINT_MAX, "affinity": telemetry.UINT_MAX},
                                    disks={slot: {key: telemetry.UINT_MAX - index for key in telemetry.DISK}
                                           for slot in ("upstream", "log")},
                                    cgroup_v2={"memory.current": telemetry.UINT_MAX - index,
                                               "memory.max": telemetry.UINT_MAX,
                                               "memory.events": {key: telemetry.UINT_MAX - index for key in telemetry.EVENTS}},
                                    oom_kill=telemetry.UINT_MAX - index, errors=[self.token * 1000], env={"secret": self.token}))
        output = measurements.output(7, WHEN, 7, measured=True)
        self.assertLessEqual(len(telemetry.json_bytes({"output": output})), 16 * 1024)
        self.assertTrue(self.token not in output["text"], "credential reached output text")
        self.assertEqual(len(telemetry.decode_output({"output": output})["snapshots"]), 6)


class StateTests(OfflineFixture):
    def test_initial_state_has_exact_public_schema_and_starting_reservation(self):
        initial = telemetry.initial_state(BINDING)
        self.assertEqual(set(initial), telemetry.STATE_KEYS)
        self.assertEqual(initial["schema"], 1)
        self.assertEqual(initial["phase"], "starting")
        self.assertEqual((initial["check_id"], initial["pid"], initial["start_ticks"]), (None, None, None))
        self.assertEqual((initial["last_ack_seq"], initial["resource_ack_count"]), (0, 0))
        self.assertEqual(telemetry.state_binding(initial), BINDING)
        telemetry.write_state(self.state, initial)
        self.assertEqual(telemetry.read_state(self.state), initial)
        self.assert_private_files()

    def test_uint_max_pid_is_rejected_by_validate_read_and_stop_without_overflow(self):
        invalid = ready_state()
        invalid["pid"] = telemetry.UINT_MAX
        with self.assertRaises(telemetry.TelemetryError):
            telemetry.validate_state(invalid)
        self.state.write_bytes(telemetry.json_bytes(invalid))
        with self.assertRaises(telemetry.TelemetryError):
            telemetry.read_state(self.state)
        with mock.patch.object(telemetry, "signal_owned", side_effect=AssertionError("unsafe PID must not signal")):
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.stop(types.SimpleNamespace(state=self.state))

    def test_state_measured_ack_count_cannot_exceed_seq_or_omit_sample_time(self):
        for changes in ({"last_ack_seq": 0, "resource_ack_count": 1, "last_sample_at": WHEN},
                        {"last_ack_seq": 1, "resource_ack_count": 1, "last_sample_at": None}):
            value = ready_state()
            value.update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.validate_state(value)

    def test_state_exact_keys_reject_extra_secret_and_missing_fields(self):
        for key in telemetry.STATE_KEYS:
            value = ready_state()
            del value[key]
            with self.subTest(missing=key):
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.validate_state(value)
        value = ready_state()
        value["token"] = self.token
        with self.assertRaises(telemetry.TelemetryError):
            telemetry.write_state(self.state, value)
        self.assertFalse(self.state.exists())

    def test_state_schema_binding_numeric_phase_and_timestamp_are_strict(self):
        bad = [{"schema": True}, {"schema": "1"}, {"external_id": "wrong"},
               {"check_name": "wrong"}, {"run_id": 31415}, {"pid": True},
               {"start_ticks": 0}, {"check_id": -1}, {"last_ack_seq": True},
               {"resource_ack_count": -1}, {"phase": "failed"}, {"phase": []}, {"phase": {}},
               {"ready_at": None}, {"last_ack_at": None},
               {"started_at": "2026-10-02T00:00:00+02:00"}]
        for changed in bad:
            with self.subTest(changed=changed):
                value = ready_state()
                value.update(changed)
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.validate_state(value)

    def test_atomic_state_replacement_fsyncs_file_before_rename_then_directory(self):
        initial = telemetry.initial_state(BINDING)
        telemetry.write_state(self.state, initial)
        old_inode = self.state.stat().st_ino
        events = []
        real_fsync, real_replace = os.fsync, os.replace
        def sync(fd):
            events.append("file-sync" if stat.S_ISREG(os.fstat(fd).st_mode) else "directory-sync")
            return real_fsync(fd)
        def replace(*args, **kwargs):
            events.append("replace")
            return real_replace(*args, **kwargs)
        value = ready_state()
        with mock.patch.object(telemetry.os, "fsync", side_effect=sync), \
             mock.patch.object(telemetry.os, "replace", side_effect=replace):
            telemetry.write_state(self.state, value)
        self.assertEqual(events, ["file-sync", "replace", "directory-sync"])
        self.assertNotEqual(self.state.stat().st_ino, old_inode)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertEqual(telemetry.read_state(self.state), value)
        self.assertEqual(list(self.base.glob(".rbm-telemetry-*")), [])
        self.assert_private_files()

    def test_state_io_rejects_symlink_hardlink_and_symlink_ancestor(self):
        original = self.base / "original-state.json"
        telemetry.write_state(original, ready_state())
        self.state.symlink_to(original)
        for operation in (lambda: telemetry.read_state(self.state),
                          lambda: telemetry.write_state(self.state, ready_state())):
            with self.assertRaises((OSError, telemetry.TelemetryError)):
                operation()
        self.state.unlink()
        os.link(original, self.state)
        for operation in (lambda: telemetry.read_state(self.state),
                          lambda: telemetry.write_state(self.state, ready_state())):
            with self.assertRaises(telemetry.TelemetryError):
                operation()
        directory = self.base / "actual"
        directory.mkdir()
        link = self.base / "linked"
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises((OSError, telemetry.TelemetryError)):
            telemetry.write_state(link / "public.json", ready_state())
        self.assertFalse((directory / "public.json").exists())

    def test_state_rejects_duplicate_json_and_oversized_regular_file(self):
        value = telemetry.json_bytes(ready_state())
        self.state.write_bytes(value[:-1] + b',"schema":1}')
        with self.assertRaises(telemetry.TelemetryError):
            telemetry.read_state(self.state)
        self.state.write_bytes(b"x" * (telemetry.MAX_STATE + 1))
        with self.assertRaises(telemetry.TelemetryError):
            telemetry.read_state(self.state)

    def test_failed_atomic_replace_preserves_old_state_and_removes_temp(self):
        initial = telemetry.initial_state(BINDING)
        telemetry.write_state(self.state, initial)
        with mock.patch.object(telemetry.os, "replace", side_effect=OSError("fixture replace denied")):
            with self.assertRaises(OSError):
                telemetry.write_state(self.state, ready_state())
        self.assertEqual(telemetry.read_state(self.state), initial)
        self.assertEqual(list(self.base.glob(".rbm-telemetry-*")), [])

    def test_worker_requires_exact_reserved_starting_state_before_client(self):
        foreign = telemetry.Binding(BINDING.repository, BINDING.head, BINDING.run, "3", BINDING.job)
        states = [ready_state(), telemetry.initial_state(foreign),
                  dict(telemetry.initial_state(BINDING), pid=os.getpid())]
        for state in states:
            with self.subTest(phase=state["phase"], attempt=state["run_attempt"]):
                telemetry.write_state(self.state, state)
                fd = credential_pipe(self.token)
                args = worker_args(self.base, fd)
                factory = mock.Mock(side_effect=AssertionError("client must not be created"))
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.run_worker(args, client_factory=factory)
                factory.assert_not_called()
                with self.assertRaises(OSError):
                    os.fstat(fd)
        self.assert_private_files()

    def test_worker_rejects_empty_oversized_nonascii_private_credentials(self):
        for raw in (b"", b"x" * 4097, b"\xff"):
            with self.subTest(length=len(raw)):
                telemetry.write_state(self.state, telemetry.initial_state(BINDING))
                fd = credential_pipe(raw)
                args = worker_args(self.base, fd)
                factory = mock.Mock(side_effect=AssertionError("client must not be created"))
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.run_worker(args, client_factory=factory)
                factory.assert_not_called()
                with self.assertRaises(OSError):
                    os.fstat(fd)
        self.assert_private_files()


class RequestBudgetTests(OfflineFixture):
    def test_post_consumes_one_write_and_minute_limit_is30_attempts(self):
        budget = telemetry.RequestBudget(0)
        for instant in range(1, 30):
            budget.record(instant)
        self.assertEqual(len(budget.writes), 30)
        self.assertEqual(budget.delay(29.5), 30.5)
        with self.assertRaises(telemetry.TelemetryError) as raised:
            budget.record(29.5)
        self.assertEqual(raised.exception.category, "rate")
        self.assertEqual(len(budget.writes), 30)
        self.assertEqual(budget.delay(60), 0)
        budget.record(60)
        self.assertEqual(len(budget.writes), 31)
        self.assertEqual(sum(instant > 0 for instant in budget.writes), 30)

    def test_hour_limit_is400_and_exact_window_expiry_allows_one_write(self):
        budget = telemetry.RequestBudget(0)
        for index in range(1, 400):
            budget.record(index * 8)
        self.assertEqual(len(budget.writes), 400)
        self.assertEqual(budget.delay(3200), 400)
        with self.assertRaises(telemetry.TelemetryError):
            budget.record(3200)
        self.assertEqual(budget.delay(3600), 0)
        budget.record(3600)
        self.assertEqual(len(budget.writes), 400)
        self.assertEqual(budget.writes[0], 8)
        self.assertEqual(budget.delay(7201), 0)
        self.assertEqual(list(budget.writes), [])

    def test_failed_attempts_also_consume_budget_no_retry_or_backlog_burst(self):
        budget = telemetry.RequestBudget(100)
        for _ in range(29):
            budget.record(100)
            # No success callback exists: rejected write attempts count too.
        self.assertEqual(budget.delay(100), 60)
        with self.assertRaises(telemetry.TelemetryError):
            budget.record(100)
        self.assertEqual(budget.delay(160), 0)
        self.assertEqual(len(budget.writes), 30)
        budget.record(160)
        self.assertEqual(budget.delay(160), 0)
        self.assertEqual(len([instant for instant in budget.writes if instant > 100]), 1)

    def test_worker_429_retry_after_prevents_retry_backlog_and_false_ack(self):
        args = worker_args(self.base, credential_pipe(self.token), interval=0.001)
        telemetry.write_state(self.state, telemetry.initial_state(BINDING))
        self.write_samples(sample(1, "start"))
        clock = {"now": 0.0}
        def sleep(seconds):
            clock["now"] += seconds
        def reply(method, _path, body):
            if method == "GET":
                return 200, {"total_count": 0, "check_runs": []}, {}
            if method == "POST":
                return 201, check(output=body["output"]), {}
            raise telemetry.TelemetryError("http", 429, 20)
        with mock.patch.object(telemetry.time, "monotonic", side_effect=lambda: clock["now"]), \
             mock.patch.object(telemetry.time, "sleep", side_effect=sleep), \
             mock.patch.object(telemetry, "MAX_LIFETIME", 2):
            telemetry.run_worker(args, client_factory=lambda _binding, _token: self.client(reply))
        self.assertEqual([item["method"] for item in self.requests()], ["GET", "POST", "PATCH"])
        state = telemetry.read_state(self.state)
        self.assertEqual((state["phase"], state["last_ack_seq"], state["resource_ack_count"]), ("ended", 0, 0))
        self.assertIsNone(state["last_sample_at"])
        self.assert_private_files()

    def test_real_worker_enforces_post_plus29_patches_per_synthetic_minute(self):
        args = worker_args(self.base, credential_pipe(self.token), interval=0.001)
        telemetry.write_state(self.state, telemetry.initial_state(BINDING))
        self.write_samples(sample(1, "start"))
        clock = {"now": 0.0}
        def sleep(seconds):
            clock["now"] += seconds
        def reply(method, _path, body):
            if method == "GET":
                return 200, {"total_count": 0, "check_runs": []}, {}
            if method == "POST":
                return 201, check(output=body["output"]), {}
            seq = telemetry.decode_output({"output": body["output"]})["seq"]
            append_public(self.resources, sample(seq + 1))
            return 200, check(output=body["output"]), {}
        def factory(binding, token):
            self.assertTrue(binding == BINDING and token == self.token, "worker binding or private credential mismatch")
            return self.client(reply)
        native_bound = telemetry.bounded_request
        real_monotonic, real_sleep = time.monotonic, time.sleep
        def native_deadline(operation):
            # The worker clock is synthetic. Native request child supervision
            # and reaping must keep their actual wall clock and sleep calls.
            with mock.patch.object(telemetry.time, "monotonic", real_monotonic), \
                 mock.patch.object(telemetry.time, "sleep", real_sleep):
                return native_bound(operation)
        with mock.patch.object(telemetry.time, "monotonic", side_effect=lambda: clock["now"]), \
             mock.patch.object(telemetry.time, "sleep", side_effect=sleep), \
             mock.patch.object(telemetry, "bounded_request", side_effect=native_deadline), \
             mock.patch.object(telemetry, "MAX_LIFETIME", 2):
            telemetry.run_worker(args, client_factory=factory)
        writes = [item for item in self.requests() if item["method"] in {"POST", "PATCH"}]
        self.assertEqual(len(writes), 30)
        self.assertEqual([item["method"] for item in writes], ["POST"] + ["PATCH"] * 29)
        state = telemetry.read_state(self.state)
        self.assertEqual((state["phase"], state["last_ack_seq"], state["resource_ack_count"]), ("ended", 29, 29))
        self.assert_private_files()


class StartAndCliTests(OfflineFixture):
    def idle(self, ignore_term=False):
        mode = "--fixture-ignore-term" if ignore_term else "--fixture-idle"
        process = subprocess.Popen([sys.executable, str(SELF), mode],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=self.environment)
        self.addCleanup(close_native_process, process)
        return process

    def test_injected_start_reserves_state_and_consumes_step_token_before_launch(self):
        args = worker_args(self.base)
        captures = {}
        def launch(received, token):
            captures["same_args"] = received is args
            captures["token_matches"] = token == self.token
            captures["token_env_present"] = telemetry.TOKEN_ENV in os.environ
            reserved = telemetry.read_state(self.state)
            captures["reservation"] = reserved["phase"] == "starting" and reserved["pid"] is None
            process = self.idle()
            telemetry.write_state(self.state, ready_state(pid=process.pid, ticks=telemetry.process_ticks(process.pid)))
            return process
        with mock.patch.dict(os.environ, {telemetry.TOKEN_ENV: self.token}):
            state = telemetry.start(args, launch=launch, readiness=1)
            self.assertNotIn(telemetry.TOKEN_ENV, os.environ)
        self.assertEqual(captures, {"same_args": True, "token_matches": True,
                                    "token_env_present": False, "reservation": True})
        self.assertEqual(state["phase"], "ready")
        self.assertEqual((state["last_ack_seq"], state["resource_ack_count"]), (0, 0))
        self.assert_private_files()

    def test_missing_token_and_state_resource_collision_do_not_launch(self):
        args = worker_args(self.base)
        launch = mock.Mock(side_effect=AssertionError("must not launch"))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.start(args, launch=launch, readiness=0.1)
        self.assertFalse(self.state.exists())
        args.resource_log = args.state
        with mock.patch.dict(os.environ, {telemetry.TOKEN_ENV: self.token}):
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.start(args, launch=launch, readiness=0.1)
        launch.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_existing_reservation_blocks_duplicate_launch(self):
        telemetry.write_state(self.state, telemetry.initial_state(BINDING))
        launch = mock.Mock(side_effect=AssertionError("duplicate must not launch"))
        with mock.patch.dict(os.environ, {telemetry.TOKEN_ENV: self.token}):
            with self.assertRaises((OSError, telemetry.TelemetryError)):
                telemetry.start(worker_args(self.base), launch=launch, readiness=0.1)
        launch.assert_not_called()
        self.assertEqual(telemetry.read_state(self.state)["phase"], "starting")

    def test_readiness_rejects_wrong_binding_wrong_ticks_and_starting_phase(self):
        for changed in ("binding", "ticks", "phase"):
            with self.subTest(changed=changed):
                self.state.unlink(missing_ok=True)
                holder = []
                def launch(_args, _token):
                    process = self.idle()
                    holder.append(process)
                    binding = (telemetry.Binding(BINDING.repository, BINDING.head, BINDING.run, "3", BINDING.job)
                               if changed == "binding" else BINDING)
                    state = ready_state(binding, process.pid, telemetry.process_ticks(process.pid))
                    if changed == "ticks":
                        state["start_ticks"] += 1
                    if changed == "phase":
                        state["phase"] = "starting"
                    telemetry.write_state(self.state, state)
                    return process
                with mock.patch.dict(os.environ, {telemetry.TOKEN_ENV: self.token}):
                    with self.assertRaises(telemetry.TelemetryError) as raised:
                        telemetry.start(worker_args(self.base), launch=launch, readiness=0.12)
                self.assertEqual(raised.exception.category, "readiness")
                self.assertIsNotNone(holder[0].poll())

    def test_readiness_deadline_terminates_real_native_child(self):
        holder = []
        def launch(_args, _token):
            process = self.idle()
            holder.append(process)
            return process
        before = time.monotonic()
        with mock.patch.dict(os.environ, {telemetry.TOKEN_ENV: self.token}):
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.start(worker_args(self.base), launch=launch, readiness=0.08)
        self.assertLess(time.monotonic() - before, 1)
        self.assertIsNotNone(holder[0].poll())

    def test_worker_cli_requires_credential_fd_and_keeps_finite_interval_bounds(self):
        args = telemetry.parse_args(["_worker", *self.cli_arguments(), "--credential-fd", "9"])
        self.assertEqual(args.credential_fd, 9)
        self.assertTrue(args.state.is_absolute())
        for argv in (["_worker", *self.cli_arguments()],
                     ["start", *self.cli_arguments(), "--interval", "nan"],
                     ["start", *self.cli_arguments(), "--interval", "inf"],
                     ["start", *self.cli_arguments(), "--interval", "0.5"],
                     ["start", *self.cli_arguments(), "--interval", "3601"]):
            with self.subTest(argv=argv[:1]), mock.patch("sys.stderr", new=__import__("io").StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    telemetry.parse_args(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_native_starter_reaches_eof_with_private_pipe_and_devnull_daemon_stdio(self):
        before = time.monotonic()
        result = self.starter("hold")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.monotonic() - before, 2, "daemon must not hold the captured stdout/stderr pipe")
        document = json.loads(result.stdout)
        state, launch = document["state"], document["launch"]
        self.addCleanup(self.stop_orphan_worker, state)
        self.assertEqual(launch, {"private_pipe": True, "stdio_devnull": True,
                                  "new_session": True, "close_fds": True,
                                  "token_env_present": False, "tracking_retained": True,
                                  "token_in_argv": False, "credential_flag": True})
        self.assertEqual((state["phase"], state["last_ack_seq"], state["resource_ack_count"]), ("ready", 0, 0))
        metadata = next(item for item in entries(self.trace) if item.get("event") == "worker_metadata")
        self.assertFalse(metadata["token_env_present"])
        self.assertTrue(metadata["credential_fd_closed"])
        self.assertTrue(metadata["stdin_eof"])
        self.assertTrue(metadata["stdio_devnull"])
        self.assertTrue(metadata["tracking_retained"])
        self.assertTrue(metadata["session_is_private"])
        raw_env = Path(f"/proc/{state['pid']}/environ").read_bytes()
        raw_argv = Path(f"/proc/{state['pid']}/cmdline").read_bytes()
        self.assertTrue(self.token.encode() not in raw_env + raw_argv, "credential reached daemon environment or argv")
        self.assertNotIn((telemetry.TOKEN_ENV + "=").encode(), raw_env)
        self.assertIn(b"RUNNER_TRACKING_ID=offline-tracking\0", raw_env)
        self.assertEqual(result.stderr, b"")
        self.assert_private_files()

    def test_native_denied_readiness_and_http500_never_emit_ready_or_token(self):
        for mode in ("create-denied", "create-500"):
            with self.subTest(mode=mode):
                self.state.unlink(missing_ok=True)
                self.trace.unlink(missing_ok=True)
                before = time.monotonic()
                result = self.starter(mode)
                self.assertEqual(result.returncode, 1)
                self.assertLess(time.monotonic() - before, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"offline starter rejected the operation\n")
                state = telemetry.read_state(self.state)
                self.assertEqual(state["phase"], "starting")
                self.assertIsNone(state["ready_at"])
                self.assertEqual(state["resource_ack_count"], 0)
                self.assert_private_files()


class NativeLifecycleAndOwnershipTests(OfflineFixture):
    def test_process_ticks_matches_real_proc_start_field22(self):
        pid = os.getpid()
        independent = int(Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()[19])
        self.assertEqual(telemetry.process_ticks(pid), independent)
        self.assertGreater(independent, 0)
        for invalid in (True, 0, -1, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(telemetry.TelemetryError):
                    telemetry.process_ticks(invalid)

    def test_native_sigterm_at_ready_write_ends_acknowledged_state(self):
        process = self.native_worker("cancel-ready-write")
        self.assertEqual(process.wait(timeout=4), 0)
        state = telemetry.read_state(self.state)
        self.assertEqual((state["phase"], state["check_id"], state["last_ack_seq"], state["resource_ack_count"]),
                         ("ended", 731, 0, 0))
        self.assertIsNotNone(state["ready_at"])
        self.assertIsNotNone(state["last_ack_at"])
        self.assertEqual([item["method"] for item in self.requests()], ["GET", "POST"])
        self.assert_private_files()

    def test_native_two_measured_acks_have_changing_sequence_not_post_only(self):
        self.write_samples(sample(1, "start", meminfo_kib={"MemAvailable": 100}, oom_kill=0))
        process = self.native_worker("progress")
        process.wait(timeout=5)
        self.assertEqual(process.returncode, 0)
        state = telemetry.read_state(self.state)
        self.assertEqual((state["phase"], state["resource_ack_count"], state["last_ack_seq"]), ("ended", 3, 3))
        calls = self.requests()
        self.assertEqual([item["method"] for item in calls], ["GET", "POST", "PATCH", "PATCH", "PATCH"])
        payloads = [telemetry.decode_output({"output": item["body"]["output"]}) for item in calls[1:]]
        self.assertEqual([item["seq"] for item in payloads], [0, 1, 2, 3])
        self.assertEqual([item["resource_ack_count"] for item in payloads], [0, 1, 2, 3])
        self.assertGreaterEqual(state["resource_ack_count"], 2)
        self.assertGreater(len({item["seq"] for item in payloads[1:]}), 1)
        self.assertEqual(payloads[-1]["previous_ack_seq"], 2)
        self.assertEqual(payloads[-1]["phase"], "ENDED")
        for item in calls[2:]:
            self.assertEqual(set(item["body"]), {"output"})
        self.assert_private_files()

    def test_native_worker_skips_invalid_rows_and_acknowledges_later_valid_exit(self):
        self.write_samples(sample(1, elapsed_seconds=10 ** 400), sample(2, reason=[]),
                           sample(3, reason={}), sample(4, "exit", meminfo_kib={"MemAvailable": 321}))
        process = self.native_worker()
        self.assertEqual(process.wait(timeout=4), 0)
        state = telemetry.read_state(self.state)
        self.assertEqual((state["phase"], state["last_ack_seq"], state["resource_ack_count"]), ("ended", 1, 1))
        self.assertEqual(state["last_sample_at"], sample(4)["time"])
        payload = telemetry.decode_output({"output": self.requests()[-1]["body"]["output"]})
        self.assertEqual([item["elapsed_seconds"] for item in payload["snapshots"]], [4])
        self.assertEqual(payload["phase"], "ENDED")
        self.assert_private_files()

    def test_native_failed_patch_does_not_advance_ack_count_or_last_ack_seq(self):
        for mode in ("patch-denied", "patch-500"):
            with self.subTest(mode=mode):
                self.trace.unlink(missing_ok=True)
                self.write_samples(sample(1, "exit"))
                process = self.native_worker(mode)
                self.assertEqual(process.wait(timeout=4), 0)
                state = telemetry.read_state(self.state)
                self.assertEqual((state["phase"], state["last_ack_seq"], state["resource_ack_count"]), ("ended", 0, 0))
                self.assertIsNone(state["last_sample_at"])
                self.assertEqual([item["method"] for item in self.requests()], ["GET", "POST", "PATCH"])
                self.assert_private_files()

    def test_owned_process_uses_real_cmdline_ticks_path_and_optional_binding(self):
        process = self.native_worker()
        state = self.wait_state(lambda state: state["phase"] == "ready")
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            self.assertTrue(telemetry.owned_process(process.pid, state["start_ticks"], self.state))
            self.assertTrue(telemetry.owned_process(process.pid, state["start_ticks"], self.state, BINDING))
            self.assertFalse(telemetry.owned_process(process.pid, state["start_ticks"] + 1, self.state, BINDING))
            self.assertFalse(telemetry.owned_process(process.pid, state["start_ticks"], self.base / "other-state", BINDING))
            foreign = telemetry.Binding(BINDING.repository, BINDING.head, BINDING.run, "3", BINDING.job)
            self.assertFalse(telemetry.owned_process(process.pid, state["start_ticks"], self.state, foreign))
        self.assertFalse(telemetry.owned_process(process.pid, state["start_ticks"], self.state, BINDING),
                         "an injected fixture is not the production publisher identity")

    def test_pid_reuse_ticks_mismatch_cannot_signal_live_native_worker(self):
        process = self.native_worker()
        state = self.wait_state(lambda state: state["phase"] == "ready")
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            with self.assertRaises(telemetry.TelemetryError) as raised:
                telemetry.signal_owned(process.pid, state["start_ticks"] + 1,
                                       self.state, signal.SIGKILL, BINDING)
        self.assertEqual(raised.exception.category, "ownership")
        self.assertIsNone(process.poll())
        self.assertTrue(process_alive(process.pid, state["start_ticks"]))

    def test_pidfd_signal_never_uses_pid_or_group_kill_and_worker_ends(self):
        process = self.native_worker()
        state = self.wait_state(lambda state: state["phase"] == "ready")
        sent = []
        native_send = signal.pidfd_send_signal
        def send(fd, signum):
            os.fstat(fd)
            sent.append(signum)
            return native_send(fd, signum)
        with mock.patch.object(telemetry, "SCRIPT", SELF), \
             mock.patch.object(telemetry.signal, "pidfd_send_signal", side_effect=send), \
             mock.patch.object(telemetry.os, "kill", side_effect=AssertionError("PID kill forbidden")), \
             mock.patch.object(telemetry.os, "killpg", side_effect=AssertionError("group kill forbidden")):
            self.assertTrue(telemetry.signal_owned(process.pid, state["start_ticks"], self.state, signal.SIGTERM, BINDING))
        self.assertEqual(process.wait(timeout=2), 0)
        self.assertEqual(sent, [signal.SIGTERM])
        ended = telemetry.read_state(self.state)
        self.assertEqual((ended["phase"], ended["resource_ack_count"]), ("ended", 0))
        self.assert_private_files()

    def test_native_stop_cancellation_preserves_last_ack_and_tracking(self):
        self.write_samples(sample(1, "start"))
        process = self.native_worker("hold", interval=0.04)
        state = self.wait_state(lambda state: state["resource_ack_count"] == 1)
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            telemetry.stop(types.SimpleNamespace(state=self.state))
        self.assertEqual(process.wait(timeout=2), 0)
        ended = telemetry.read_state(self.state)
        self.assertEqual((ended["phase"], ended["resource_ack_count"], ended["last_ack_seq"]), ("ended", 1, 1))
        self.assertEqual(ended["last_sample_at"], sample(1)["time"])
        self.assertEqual(ended["last_ack_at"], state["last_ack_at"])
        metadata = next(item for item in entries(self.trace) if item.get("event") == "worker_metadata")
        self.assertTrue(metadata["tracking_retained"])
        self.assertFalse(metadata["token_env_present"])
        self.assert_private_files()

    def test_stop_wrong_ticks_refuses_pid_reuse_and_leaves_child_alive(self):
        process = self.native_worker()
        state = self.wait_state(lambda state: state["phase"] == "ready")
        state["start_ticks"] += 1
        telemetry.write_state(self.state, state)
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.stop(types.SimpleNamespace(state=self.state))
        self.assertIsNone(process.poll())

    def test_proc_cmdline_uid_gate_rejects_foreign_owner(self):
        process = self.native_worker()
        state = self.wait_state(lambda state: state["phase"] == "ready")
        native_fstat = os.fstat
        def foreign(fd):
            original = native_fstat(fd)
            return types.SimpleNamespace(st_uid=os.getuid() + 1)
        with mock.patch.object(telemetry, "SCRIPT", SELF), \
             mock.patch.object(telemetry.os, "fstat", side_effect=foreign):
            self.assertFalse(telemetry.owned_process(process.pid, state["start_ticks"], self.state, BINDING))
        self.assertIsNone(process.poll())

    def test_duplicate_binding_flags_cannot_claim_worker_identity(self):
        process = subprocess.Popen(
            [sys.executable, str(SELF), "_worker", *self.cli_arguments(),
             "--run", BINDING.run, "--fixture-mode", "identity-only",
             "--fixture-trace", str(self.trace)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=self.environment)
        self.addCleanup(close_native_process, process)
        ticks = telemetry.process_ticks(process.pid)
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            self.assertFalse(telemetry.owned_process(process.pid, ticks, self.state, BINDING))

    def test_duplicate_state_flags_cannot_claim_first_state_path(self):
        process = subprocess.Popen(
            [sys.executable, str(SELF), "_worker", *self.cli_arguments(),
             "--state", str(self.base / "different-state.json"), "--fixture-mode", "identity-only",
             "--fixture-trace", str(self.trace)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=self.environment)
        self.addCleanup(close_native_process, process)
        ticks = telemetry.process_ticks(process.pid)
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            self.assertFalse(telemetry.owned_process(process.pid, ticks, self.state, BINDING))
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.signal_owned(process.pid, ticks, self.state, signal.SIGKILL, BINDING)
        self.assertIsNone(process.poll())

    def test_non_worker_process_cannot_be_owned_or_signalled(self):
        process = subprocess.Popen([sys.executable, str(SELF), "--fixture-idle"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=self.environment)
        self.addCleanup(close_native_process, process)
        ticks = telemetry.process_ticks(process.pid)
        with mock.patch.object(telemetry, "SCRIPT", SELF):
            self.assertFalse(telemetry.owned_process(process.pid, ticks, self.state, BINDING))
            with self.assertRaises(telemetry.TelemetryError):
                telemetry.signal_owned(process.pid, ticks, self.state, signal.SIGKILL, BINDING)
        self.assertIsNone(process.poll())

    def test_stop_starting_and_gone_process_are_noops(self):
        telemetry.write_state(self.state, telemetry.initial_state(BINDING))
        with mock.patch.object(telemetry, "signal_owned", side_effect=AssertionError("must not signal")):
            telemetry.stop(types.SimpleNamespace(state=self.state))
        process = subprocess.Popen([sys.executable, "-c", "pass"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=self.environment)
        ticks = telemetry.process_ticks(process.pid)
        process.wait(timeout=2)
        telemetry.write_state(self.state, ready_state(pid=process.pid, ticks=ticks))
        with mock.patch.object(telemetry, "signal_owned", side_effect=AssertionError("gone PID must not signal")):
            telemetry.stop(types.SimpleNamespace(state=self.state))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "_worker":
        raise SystemExit(fixture_worker(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture-starter":
        raise SystemExit(fixture_starter(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture-orphan":
        raise SystemExit(fixture_orphan(Path(sys.argv[2])))
    if len(sys.argv) > 1 and sys.argv[1] in {"--fixture-idle", "--fixture-ignore-term"}:
        if sys.argv[1] == "--fixture-ignore-term":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        while True:
            signal.pause()
    unittest.main()
