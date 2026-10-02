#!/usr/bin/env python3
"""Offline workflow/security tests. Mocked Checks results are NOT real CI evidence."""
from datetime import datetime, timezone, timedelta
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
STAGE_PATH = ROOT / ".github/workflows/pgo-stage4a.yml"
SMOKE_PATH = ROOT / ".github/workflows/pgo-diagnostics.yml"
SMOKE_CODE = ROOT / "tests/smoke-rbm-telemetry.py"


def job(text, name):
    begin = text.index("  " + name + ":\n")
    rest = text[begin:]
    for index, line in enumerate(rest.splitlines(keepends=True)[1:], 1):
        if line.startswith("  ") and not line.startswith("    ") and line.strip():
            return "".join(rest.splitlines(keepends=True)[:index])
    return rest


def step(text, name):
    begin = text.index("      - name: " + name + "\n")
    tail = text[begin:]
    end = tail.find("\n      -", 1)
    return tail if end == -1 else tail[:end] + "\n"


def load_smoke():
    spec = importlib.util.spec_from_file_location("rbm_telemetry_smoke_tests", SMOKE_CODE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TelemetryWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.stage = STAGE_PATH.read_text()
        self.generate = job(self.stage, "pgo-generate")
        self.smoke = SMOKE_PATH.read_text()

    def test_checks_write_is_generation_job_only_and_preserves_other_permissions(self):
        self.assertEqual(self.stage.count("      checks: write"), 1)
        self.assertNotIn("checks:", self.stage.split("jobs:", 1)[0])
        self.assertIn("    permissions:\n      contents: write\n      actions: read\n      checks: write\n", self.generate)
        self.assertNotIn("checks:", job(self.stage, "pgo-train"))
        self.assertNotIn("checks:", job(self.stage, "pgo-merge"))

    def test_generation_and_smoke_checkout_do_not_cache_scoped_checks_token(self):
        expected = "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
        self.assertIn(expected, self.generate)
        self.assertIn(expected, self.smoke)

    def test_readiness_gate_before_literal_unchanged_build_step(self):
        policy = step(self.generate, "Validate warm offline generation resource policy")
        start = step(self.generate, "Start acknowledged durable resource telemetry")
        build = step(self.generate, "Build only instrumented Firefox")
        self.assertEqual(build, '      - name: Build only instrumented Firefox\n        timeout-minutes: 285\n'
                         '        run: python3 ./scripts/run-pgo-resource-limited.py '
                         '--policy "$RUNNER_TEMP/pgo-generation-resource-policy.json" -- ./scripts/run-pgo-generate.sh\n')
        self.assertLess(self.generate.index(policy), self.generate.index(start))
        self.assertLess(self.generate.index(start), self.generate.index(build))
        self.assertNotIn("env:", policy)
        self.assertNotIn("continue-on-error", policy)
        self.assertNotIn("||", policy)
        self.assertIn("--interval 120", start)
        self.assertIn("--resource-log \"$RUNNER_TEMP/pgo-generate-resources.jsonl\"", start)
        self.assertIn("--state \"$RUNNER_TEMP/pgo-durable-telemetry.json\"", start)
        self.assertIn("--run \"$GITHUB_RUN_ID\" --attempt \"$GITHUB_RUN_ATTEMPT\"", start)
        self.assertIn("--job \"$GITHUB_JOB\"", start)
        self.assertNotIn("continue-on-error", start)
        self.assertNotIn("|| true", start)
        self.assertNotIn("env:", build)

    def test_publisher_token_step_only_not_job_global_build_or_observer(self):
        start = step(self.generate, "Start acknowledged durable resource telemetry")
        self.assertEqual(self.stage.count("PGO_TELEMETRY_TOKEN:"), 1)
        self.assertIn("          PGO_TELEMETRY_TOKEN: ${{ github.token }}", start)
        self.assertNotIn("PGO_TELEMETRY_TOKEN", self.generate.replace(start, ""))
        self.assertNotIn("PGO_TELEMETRY_TOKEN", (ROOT / "scripts/run-pgo-generate.sh").read_text())
        self.assertNotIn("PGO_TELEMETRY_TOKEN", (ROOT / "scripts/observe-rbm-build.py").read_text())
        self.assertNotIn("GITHUB_ENV", start)
        self.assertNotIn("GITHUB_OUTPUT", start)

    def test_optional_stop_cannot_replace_native_build_failure(self):
        stop = step(self.generate, "Stop durable resource telemetry")
        self.assertIn("        if: always()", stop)
        self.assertIn("        continue-on-error: true", stop)
        self.assertIn(" stop --state ", stop)
        self.assertNotIn("env:", stop)
        self.assertNotIn("PGO_TELEMETRY_TOKEN", stop)
        self.assertNotIn("finalize", stop)
        self.assertIn("${{ runner.temp }}/pgo-durable-telemetry.json", self.generate)

    def test_production_free_runner_deadlines_and_source_build_commands_stay_native(self):
        self.assertIn("    runs-on: ubuntu-24.04", self.generate)
        self.assertIn("    timeout-minutes: 360", self.generate)
        self.assertIn("        run: ./scripts/prepare-binutils-input.sh", self.generate)
        self.assertIn("./scripts/preflight-pgo-rust.sh", self.generate)
        self.assertNotIn("kill", self.generate)
        self.assertNotIn("OMP_NUM_THREADS", self.generate)
        self.assertNotIn("MOZ_PGO_RUST", self.generate)

    def test_diagnostics_dispatch_or_reusable_only_free_runner_short_deadline(self):
        header = self.smoke.split("jobs:", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:\n  workflow_call:\n", header)
        events = header.split("on:\n", 1)[1].split("permissions:\n", 1)[0]
        self.assertEqual(events, "  workflow_dispatch:\n  workflow_call:\n")
        for forbidden in ["schedule", "pull_request", "push:", "workflow_run"]:
            self.assertNotIn(forbidden, header)
        self.assertIn("    runs-on: ubuntu-24.04", self.smoke)
        self.assertIn("    timeout-minutes: 10", self.smoke)
        self.assertIn("      checks: write", self.smoke)
        self.assertIn("      contents: read", self.smoke)
        for forbidden in ["fetch-upstream", "rbm build", "run-pgo-generate.sh", "train-pgo", "windows-", "sudo apt", "git clone"]:
            self.assertNotIn(forbidden, self.smoke)

    def test_registered_caller_requires_explicit_opt_in_and_grants_only_telemetry_checks_write(self):
        caller = (ROOT / ".github/workflows/tests.yml").read_text()
        header = caller.split("jobs:\n", 1)[0]
        input_block = header.split("      telemetry_smoke:\n", 1)[1].split("permissions:\n", 1)[0]
        self.assertIn("        type: boolean\n", input_block)
        self.assertIn("        default: false\n", input_block)
        telemetry = job(caller, "telemetry-smoke")
        self.assertIn("    if: ${{ github.event_name == 'workflow_dispatch' && inputs.telemetry_smoke }}\n", telemetry)
        self.assertIn("    uses: ./.github/workflows/pgo-diagnostics.yml\n", telemetry)
        self.assertIn("    permissions:\n      contents: read\n      actions: read\n      checks: write\n", telemetry)
        self.assertNotIn("steps:", telemetry)
        self.assertNotIn("env:", telemetry)
        self.assertNotIn("checks:", header)
        self.assertEqual(caller.count("      checks: write"), 1)
        baseline = job(caller, "baseline-smoke")
        self.assertIn("    if: ${{ github.event_name == 'workflow_dispatch' && inputs.baseline_smoke }}\n", baseline)
        self.assertNotIn("telemetry_smoke", baseline)
        self.assertNotIn("checks:", baseline)
        # The dispatch plumbing is metadata only; the short callee has no browser path.
        self.assertIn("    timeout-minutes: 10\n", self.smoke)
        for forbidden in ["fetch-upstream", "rbm build", "restore-required", "windows-runtime-check.py", "train-pgo"]:
            self.assertNotIn(forbidden, telemetry + self.smoke)

    def test_smoke_three_phases_have_separate_token_boundaries(self):
        start = step(self.smoke, "Start acknowledged diagnostic-only telemetry")
        capture = step(self.smoke, "Capture real resources and kill only the verified publisher")
        verify = step(self.smoke, "Independently verify last remote ACK survives publisher death")
        self.assertEqual(self.smoke.count("PGO_TELEMETRY_TOKEN:"), 2)
        self.assertIn("PGO_TELEMETRY_TOKEN:", start)
        self.assertIn("--interval 5", start)
        self.assertIn(" capture ", capture)
        self.assertIn("--deadline 60", capture)
        self.assertNotIn("env:", capture)
        self.assertNotIn("TOKEN", capture)
        self.assertIn("PGO_TELEMETRY_TOKEN:", verify)
        self.assertIn(" verify ", verify)
        self.assertLess(self.smoke.index(start), self.smoke.index(capture))
        self.assertLess(self.smoke.index(capture), self.smoke.index(verify))


class SmokeNativeTests(unittest.TestCase):
    def setUp(self):
        self.smoke = load_smoke()
        temporary = tempfile.TemporaryDirectory(prefix="telemetry-smoke-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def test_capture_rejects_inherited_token_before_native_launch_without_leak(self):
        env = dict(os.environ, PGO_TELEMETRY_TOKEN="SECRET_CAPTURE_FIXTURE_DO_NOT_LOG")
        result = subprocess.run([sys.executable, str(SMOKE_CODE), "capture",
            "--state", str(self.base / "state"), "--resource-log", str(self.base / "resources"),
            "--evidence", str(self.base / "evidence"), "--work", str(self.base / "work")],
            env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(env["PGO_TELEMETRY_TOKEN"], result.stdout + result.stderr)
        self.assertFalse((self.base / "work").exists())

    def test_native_workload_asserts_telemetry_token_absent(self):
        source = self.smoke.WORKLOAD.replace("threading.Event().wait(25)", "threading.Event().wait(0.01)")
        env = dict(os.environ)
        env.pop("PGO_TELEMETRY_TOKEN", None)
        result = subprocess.run([sys.executable, "-c", source], env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.smoke.TOKEN_ABSENT_MARKER, result.stdout)
        env["PGO_TELEMETRY_TOKEN"] = "SECRET_CHILD_FIXTURE_DO_NOT_LOG"
        denied = subprocess.run([sys.executable, "-c", source], env=env, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(denied.returncode, 0)
        self.assertNotIn(env["PGO_TELEMETRY_TOKEN"], denied.stdout + denied.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "native proc identity fixture")
    def test_kill_signals_only_identity_verified_publisher_pid(self):
        state_path = self.base / "state.json"
        fixture = self.base / "publisher.py"
        fixture.write_text("import threading; threading.Event().wait(10)\n")
        process = subprocess.Popen([sys.executable, str(fixture), "_worker", "--state", str(state_path)])
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        ticks = self.smoke.process_identity(process.pid)["start_ticks"]
        state = {"pid": process.pid, "start_ticks": ticks}
        with mock.patch.object(self.smoke, "PUBLISHER", fixture):
            with mock.patch.object(self.smoke.signal, "pidfd_send_signal", wraps=signal.pidfd_send_signal) as kill:
                pid, actual_ticks = self.smoke.kill_owned_publisher(state, state_path)
        self.assertEqual((pid, actual_ticks), (process.pid, ticks))
        kill.assert_called_once()
        self.assertEqual(kill.call_args.args[1], signal.SIGKILL)
        self.assertEqual(process.wait(timeout=2), -signal.SIGKILL)

    @unittest.skipUnless(sys.platform.startswith("linux"), "native proc identity fixture")
    def test_wrong_start_time_or_script_marker_never_signals(self):
        state_path = self.base / "state.json"
        process = subprocess.Popen([sys.executable, "-c", "import threading; threading.Event().wait(10)"])
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        ticks = self.smoke.process_identity(process.pid)["start_ticks"]
        with mock.patch.object(self.smoke.os, "kill") as kill:
            for wrong in [ticks + 1, ticks]:
                with self.assertRaises(self.smoke.SmokeError):
                    self.smoke.kill_owned_publisher({"pid": process.pid, "start_ticks": wrong}, state_path)
        kill.assert_not_called()
        process.kill()
        process.wait(timeout=2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "native observer/process integration")
    def test_native_capture_kills_simulated_publisher_and_leaves_real_resource_suffix(self):
        # This is an OFFLINE simulated ACK producer, not GitHub durability evidence.
        state_path, resources = self.base / "state.json", self.base / "resources.jsonl"
        fixture = self.base / "publisher.py"
        bound = types.SimpleNamespace(repository="owner/repo", head="a" * 40, run="12", attempt="1",
                                      job="telemetry-smoke", external_id="12:1:telemetry-smoke")
        initial = {"schema": 1, "repository": bound.repository, "head_sha": bound.head,
                   "run_id": bound.run, "run_attempt": bound.attempt, "job_key": bound.job,
                   "external_id": bound.external_id, "check_name": "offline simulated ACK fixture",
                   "check_id": 123, "last_ack_seq": 0, "resource_ack_count": 0,
                   "last_sample_at": None, "phase": "ready"}
        fixture.write_text("import json,os,pathlib,sys,threading,time\n"
            "from datetime import datetime,timezone\n"
            "state_path=pathlib.Path(sys.argv[sys.argv.index('--state')+1])\n"
            "resource=pathlib.Path(sys.argv[sys.argv.index('--resource-log')+1])\n"
            "state=" + repr(initial) + "\n"
            "state.update(pid=os.getpid(),start_ticks=int(pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),ready_at=datetime.now(timezone.utc).isoformat())\n"
            "def write():\n"
            " temporary=state_path.with_suffix('.new'); temporary.write_text(json.dumps(state)); temporary.replace(state_path)\n"
            "write(); deadline=time.monotonic()+5; event=threading.Event()\n"
            "for count in (1,2):\n"
            " while not resource.exists():\n"
            "  if time.monotonic()>deadline: raise SystemExit(1)\n"
            "  event.wait(.01)\n"
            " event.wait(.25)\n"
            " rows=[json.loads(line) for line in resource.read_text().splitlines() if line]\n"
            " state.update(last_ack_seq=count,resource_ack_count=count,last_sample_at=rows[-1]['time'],last_ack_at=datetime.now(timezone.utc).isoformat(),phase='running'); write()\n"
            "event.wait(5)\n")
        process = subprocess.Popen([sys.executable, str(fixture), "_worker", "--state", str(state_path),
                                    "--resource-log", str(resources)])
        deadline = __import__('time').monotonic() + 3
        while not state_path.exists():
            if __import__('time').monotonic() >= deadline:
                self.fail("offline simulated publisher did not start")
            __import__('threading').Event().wait(.01)
        args = types.SimpleNamespace(state=state_path, resource_log=resources,
            evidence=self.base / "evidence.json", work=self.base / "work", deadline=30)
        api = types.SimpleNamespace(Binding=mock.Mock(return_value=bound),
            CHECK_NAME=initial["check_name"], read_state=lambda path: json.loads(Path(path).read_text()))
        env = {"GITHUB_REPOSITORY": bound.repository, "GITHUB_SHA": bound.head,
               "GITHUB_RUN_ID": bound.run, "GITHUB_RUN_ATTEMPT": bound.attempt, "GITHUB_JOB": bound.job}
        source = self.smoke.WORKLOAD.replace("threading.Event().wait(25)", "threading.Event().wait(1.2)")
        try:
            with mock.patch.dict(os.environ, env), mock.patch.object(self.smoke, "publisher_api", return_value=api), \
                 mock.patch.object(self.smoke, "PUBLISHER", fixture), mock.patch.object(self.smoke, "WORKLOAD", source), \
                 mock.patch("builtins.print"):
                os.environ.pop("PGO_TELEMETRY_TOKEN", None)
                self.assertEqual(self.smoke.capture(args), 0)
            self.assertEqual(process.wait(timeout=2), -signal.SIGKILL)
            evidence = json.loads(args.evidence.read_text())
            self.assertTrue(evidence["native_token_absent"])
            self.assertGreaterEqual(evidence["resource_ack_count"], 2)
            self.assertGreater(evidence["unacknowledged_resource_count"], 0)
            self.assertEqual(evidence["native_exit_code"], 0)
            self.assertEqual(self.smoke.records(resources)[-1]["reason"], "exit")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    def test_actual_publisher_public_api_state_and_machine_phase_are_compatible(self):
        api = self.smoke.publisher_api()
        bound = api.Binding("owner/repo", "a" * 40, "12", "1", "telemetry-smoke")
        state = api.initial_state(bound)
        now = api.utc_now()
        state.update(pid=os.getpid(), start_ticks=1, check_id=123, ready_at=now,
                     last_ack_at=now, phase="ready")
        path = self.base / "native-public-state.json"
        api.write_state(path, state)
        self.assertEqual(self.smoke.bound_state(api, path, bound)["check_id"], 123)
        measured = api.Measurements()
        measured.add({"time": now, "reason": "interval", "elapsed_seconds": 1.0,
                      "meminfo_kib": {"MemAvailable": 123}, "cpu": {"logical": 2}})
        output = api.decode_output({"output": measured.output(ack_count=1, measured=True)})
        self.assertEqual(output["phase"], "OBSERVING")
        self.assertEqual(output["resource_ack_count"], 2)
        self.assertEqual(output["snapshots"][0]["time"], output["last_sample_at"])

    def verify_fixture(self):
        binding = types.SimpleNamespace(repository="owner/repo", head="a" * 40, run="12", attempt="1",
                                        job="telemetry-smoke", external_id="12:1:telemetry-smoke")
        state = {"schema": 1, "repository": binding.repository, "head_sha": binding.head,
                 "run_id": binding.run, "run_attempt": binding.attempt, "job_key": binding.job,
                 "external_id": binding.external_id, "check_name": "diagnostic fixture", "check_id": 123,
                 "pid": 234, "start_ticks": 345, "last_ack_seq": 4, "resource_ack_count": 2,
                 "last_ack_at": "2026-10-02T00:00:04+00:00", "last_sample_at": "2026-10-02T00:00:03+00:00",
                 "ready_at": "2026-10-02T00:00:00+00:00"}
        evidence = dict(state, purpose="resource telemetry smoke; not browser validation", kill_signal="SIGKILL",
                        first_resource_ack_seq=1, native_exit_code=0, native_token_absent=True,
                        unacknowledged_resource_count=5, publisher_killed_at="2026-10-02T00:00:05+00:00",
                        unacknowledged_first_sample_at="2026-10-02T00:00:06+00:00",
                        unacknowledged_last_sample_at="2026-10-02T00:00:09+00:00")
        path = self.base / "evidence.json"
        path.write_text(json.dumps(evidence))
        check = {"status": "completed", "conclusion": "neutral"}
        output = {"seq": state["last_ack_seq"], "resource_ack_count": state["resource_ack_count"],
                  "last_sample_at": state["last_sample_at"], "phase": "OBSERVING",
                  "published_at": "2026-10-02T00:00:04+00:00",
                  "snapshots": [{"time": state["last_sample_at"], "meminfo_kib": {"MemAvailable": 123}}]}
        get = mock.Mock(return_value=check)
        api = types.SimpleNamespace(Binding=mock.Mock(return_value=binding), CHECK_NAME=state["check_name"],
            read_state=mock.Mock(return_value=state), GitHubChecks=mock.Mock(return_value=types.SimpleNamespace(get=get)),
            validate_check=mock.Mock(), decode_output=mock.Mock(return_value=output))
        args = types.SimpleNamespace(state=self.base / "state.json", evidence=path)
        env = {"PGO_TELEMETRY_TOKEN": "SECRET_VERIFY_FIXTURE", "GITHUB_REPOSITORY": binding.repository,
               "GITHUB_SHA": binding.head, "GITHUB_RUN_ID": binding.run, "GITHUB_RUN_ATTEMPT": binding.attempt,
               "GITHUB_JOB": binding.job}
        return state, evidence, path, check, output, get, api, args, env

    def test_independent_get_checks_last_ack_neutral_binding_and_unacked_suffix(self):
        state, evidence, path, check, output, get, api, args, env = self.verify_fixture()
        with mock.patch.dict(os.environ, env), mock.patch.object(self.smoke, "publisher_api", return_value=api), \
             mock.patch.object(self.smoke, "publisher_dead", return_value=True), mock.patch("builtins.print") as printed:
            self.assertEqual(self.smoke.verify(args), 0)
        get.assert_called_once_with(123)
        api.validate_check.assert_called_once_with(check, api.Binding.return_value, 123)
        self.assertNotIn(env["PGO_TELEMETRY_TOKEN"], str(printed.call_args_list))

    def test_pre_kill_inflight_api_ack_may_advance_beyond_last_local_ack(self):
        state, evidence, path, check, output, get, api, args, env = self.verify_fixture()
        output.update(seq=6, resource_ack_count=3, last_sample_at="2026-10-02T00:00:04+00:00",
                      snapshots=[{"time": "2026-10-02T00:00:04+00:00", "cpu": {"logical": 2}}])
        with mock.patch.dict(os.environ, env), mock.patch.object(self.smoke, "publisher_api", return_value=api), \
             mock.patch.object(self.smoke, "publisher_dead", return_value=True), mock.patch("builtins.print"):
            self.assertEqual(self.smoke.verify(args), 0)
        get.assert_called_once_with(123)

    def test_remote_success_conclusion_is_never_telemetry_success(self):
        state, evidence, path, check, output, get, api, args, env = self.verify_fixture()
        check["conclusion"] = "success"
        with mock.patch.dict(os.environ, env), mock.patch.object(self.smoke, "publisher_api", return_value=api), \
             mock.patch.object(self.smoke, "publisher_dead", return_value=True):
            with self.assertRaises(self.smoke.SmokeError):
                self.smoke.verify(args)

    def test_ack_count_or_remote_sequence_mismatch_fails(self):
        for mutate in [lambda state, output: state.update(resource_ack_count=1),
                       lambda state, output: output.update(seq=3),
                       lambda state, output: output.update(phase="ENDED"),
                       lambda state, output: output.update(last_sample_at="2026-10-02T00:00:07+00:00"),
                       lambda state, output: output.update(published_at="2026-10-02T00:00:07+00:00")]:
            state, evidence, path, check, output, get, api, args, env = self.verify_fixture()
            mutate(state, output)
            with mock.patch.dict(os.environ, env), mock.patch.object(self.smoke, "publisher_api", return_value=api), \
                 mock.patch.object(self.smoke, "publisher_dead", return_value=True):
                with self.assertRaises(self.smoke.SmokeError):
                    self.smoke.verify(args)

    def test_wrong_run_binding_or_still_live_publisher_fails_before_get(self):
        for change_evidence, alive in [(True, False), (False, True)]:
            state, evidence, path, check, output, get, api, args, env = self.verify_fixture()
            if change_evidence:
                evidence["run_attempt"] = "2"
                path.write_text(json.dumps(evidence))
            with mock.patch.dict(os.environ, env), mock.patch.object(self.smoke, "publisher_api", return_value=api), \
                 mock.patch.object(self.smoke, "publisher_dead", return_value=not alive):
                with self.assertRaises(self.smoke.SmokeError):
                    self.smoke.verify(args)
            get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
