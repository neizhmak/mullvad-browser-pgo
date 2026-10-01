#!/usr/bin/env python3
"""Native, offline regression tests for narrowly scoped RBM transport retries.

Run from the repository root: python3 tests/test_rbm_network.py -v
The helper is imported only inside this native test process. Tests mock run()
and also invoke real local fixture RBM processes with a no-wait pause callback.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import rbm_network

URL = "https://git.savannah.gnu.org/git/config.git"
TARGETS = ["alpha", "mullvadbrowser-windows-x86_64", "pgo-generate"]


def failure(reason="The requested URL returned error: 500", *, url=URL, clone_url=URL):
    return ("Cloning into 'wasi-config'...\n"
            f"fatal: unable to access '{url}/': {reason}\n"
            f"Error: Error cloning {clone_url}\n")


def outcome(status=0, stdout="selected-profiler.tar.xz\n", stderr=""):
    return subprocess.CompletedProcess([], status, stdout, stderr)


class RetryUnitTests(unittest.TestCase):
    def setUp(self):
        self.upstream = Path("/fixture/upstream with spaces")
        self.command = [str(self.upstream / "rbm/rbm"), "showconf", "rust", "filename",
                        *[arg for target in TARGETS for arg in ("--target", target)]]

    def invoke(self, outcomes, *, default_pause=False, targets=TARGETS):
        pauses = []
        value = error = None
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(rbm_network.subprocess, "run", side_effect=outcomes) as run:
            with mock.patch.object(rbm_network.time, "sleep", side_effect=pauses.append):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    try:
                        value = rbm_network.showconf(self.upstream, "rust", "filename", targets,
                            **({} if default_pause else {"pause": pauses.append}))
                    except subprocess.CalledProcessError as exception:
                        error = exception
        return {"value": value, "error": error, "calls": run.call_args_list,
                "pauses": pauses, "stdout": stdout.getvalue(), "stderr": stderr.getvalue()}

    def assert_native_calls(self, result, count, targets=TARGETS):
        expected = [str(self.upstream / "rbm/rbm"), "showconf", "rust", "filename",
                    *[arg for target in targets for arg in ("--target", target)]]
        self.assertEqual(len(result["calls"]), count)
        for call in result["calls"]:
            self.assertEqual(call.args, (expected,))
            self.assertEqual(call.kwargs, {"cwd": self.upstream, "text": True,
                              "stdout": subprocess.PIPE, "stderr": subprocess.PIPE})
        self.assertEqual(result["stdout"], "")

    def assert_immediate_failure(self, stdout, stderr, status=17):
        result = self.invoke([outcome(status, stdout, stderr)])
        self.assert_native_calls(result, 1)
        self.assertIsNone(result["value"])
        self.assertIsInstance(result["error"], subprocess.CalledProcessError)
        self.assertEqual(result["error"].returncode, status)
        self.assertEqual(result["error"].cmd, self.command)
        self.assertEqual(result["error"].output, stdout)
        self.assertEqual(result["error"].stderr, stderr)
        self.assertEqual(result["pauses"], [])
        self.assertIn(stderr, result["stderr"])
        self.assertIn(stdout, result["stderr"])
        return result

    def test_success_keeps_exact_argv_cwd_stripping_and_stderr_without_ci_env(self):
        for targets in (TARGETS, TARGETS[:2], []):
            with self.subTest(targets=targets), mock.patch.dict(os.environ, {}, clear=True):
                result = self.invoke([outcome(0, " \t exact identity\r\n\n", "clone progress\n")],
                                     targets=targets)
                self.assert_native_calls(result, 1, targets)
                self.assertEqual(result["value"], "exact identity")
                self.assertEqual(result["stderr"], "clone progress\n")
                self.assertEqual(result["pauses"], [])
                self.assertIsNone(result["error"])

    def test_observed_savannah_500_retries_identical_command_then_clean_success(self):
        observed = failure()
        result = self.invoke([outcome(1, "UNTRUSTED FAILED IDENTITY\n", observed),
                              outcome(0, "  exact successful identity\n", "native success progress\n")])
        self.assert_native_calls(result, 2)
        self.assertEqual(result["pauses"], [10])
        self.assertEqual(result["value"], "exact successful identity")
        self.assertNotIn("UNTRUSTED", result["stdout"])
        self.assertIn("UNTRUSTED FAILED IDENTITY\n", result["stderr"])
        self.assertIn(observed, result["stderr"])
        self.assertIn("attempt 1/3", result["stderr"])
        self.assertIn("retrying identical command in 10s", result["stderr"])
        self.assertTrue(result["stderr"].endswith("native success progress\n"))

    def test_three_attempts_use_default_10_then_30_second_backoff(self):
        result = self.invoke([outcome(1, "failed one", failure()),
                              outcome(2, "failed two", failure("The requested URL returned error: 503")),
                              outcome(0, "third exact identity\n")], default_pause=True)
        self.assert_native_calls(result, 3)
        self.assertEqual(result["pauses"], [10, 30])
        self.assertEqual(result["value"], "third exact identity")
        self.assertIn("attempt 1/3", result["stderr"])
        self.assertIn("attempt 2/3", result["stderr"])
        self.assertIn("retrying identical command in 30s", result["stderr"])
        diagnostics = [line for line in result["stderr"].splitlines() if line.startswith("RBM showconf")]
        self.assertEqual(len(diagnostics), 2)
        self.assertTrue(all(len(line) < 200 for line in diagnostics))
        self.assertIn("failed one\n", result["stderr"])
        self.assertIn("failed two\n", result["stderr"])

    def test_exhausted_retry_preserves_last_native_exit_command_and_failure_output(self):
        outputs = [outcome(code, f"untrusted-{code}", failure()) for code in (1, 2, 27)]
        result = self.invoke(outputs)
        self.assert_native_calls(result, 3)
        self.assertEqual(result["pauses"], [10, 30])
        self.assertIsNone(result["value"])
        self.assertEqual(result["error"].returncode, 27)
        self.assertEqual(result["error"].cmd, self.command)
        self.assertEqual(result["error"].output, "untrusted-27")
        self.assertEqual(result["error"].stderr, outputs[-1].stderr)
        self.assertEqual(result["stderr"].count("Error: Error cloning " + URL), 3)
        self.assertIn("attempt 3/3", result["stderr"])
        self.assertIn("retry limit reached", result["stderr"])
        for status in (1, 2, 27):
            self.assertIn(f"untrusted-{status}\n", result["stderr"])

    def test_only_enumerated_transient_http_and_transport_reasons_retry(self):
        reasons = [f"The requested URL returned error: {status}" for status in (500, 502, 503, 504)] + [
            "Operation timed out", "Connection timed out", "Timeout was reached",
            "Operation timed out after 120000 milliseconds with 0 bytes received",
            "Operation timed out after 1000 ms with 8 out of 99 bytes received",
            "Failed to connect to git.savannah.gnu.org port 443 after 1000 ms: Connection timed out",
            "Failed to connect to git.savannah.gnu.org port 443: Timeout was reached",
            "Recv failure: Connection reset by peer", "Send failure: Connection was reset",
            "Connection reset by peer", "Connection was reset",
            "Operation too slow. Less than 1 bytes/sec transferred the last 30 seconds",
        ]
        for reason in reasons:
            with self.subTest(reason=reason):
                result = self.invoke([outcome(1, "failed identity", failure(reason)), outcome()])
                self.assert_native_calls(result, 2)
                self.assertEqual(result["pauses"], [10])
                self.assertEqual(result["value"], "selected-profiler.tar.xz")

    def test_exact_url_signature_accepts_only_optional_trailing_slashes(self):
        for fatal_slash in ("", "/"):
            for clone_slash in ("", "/"):
                with self.subTest(fatal_slash=fatal_slash, clone_slash=clone_slash):
                    text = (f"fatal: unable to access '{URL}{fatal_slash}': "
                            "The requested URL returned error: 500\n"
                            f"Error: Error cloning {URL}{clone_slash}\n")
                    result = self.invoke([outcome(1, "", text), outcome()])
                    self.assert_native_calls(result, 2)
                    self.assertEqual(result["pauses"], [10])

    def test_nontransient_http_status_is_immediate_failure(self):
        for status in (400, 401, 403, 404, 409, 429, 501, 505):
            with self.subTest(status=status):
                self.assert_immediate_failure("not an identity", failure(
                    f"The requested URL returned error: {status}"))

    def test_other_urls_and_mirrors_are_never_retried(self):
        urls = [URL.replace("https:", "http:"), URL + "?mirror=1", URL + ".evil",
                URL.replace("git.savannah.gnu.org", "mirror.example.test"),
                URL.replace("config.git", "other-project.git"),
                URL.replace("git.savannah.gnu.org", "git.savannah.gnu.org:443")]
        for url in urls:
            for changed in ("fatal", "clone", "both"):
                with self.subTest(url=url, changed=changed):
                    self.assert_immediate_failure("", failure(
                        url=url if changed in ("fatal", "both") else URL,
                        clone_url=url if changed in ("clone", "both") else URL))

    def test_both_exact_fatal_and_rbm_clone_signatures_are_required(self):
        candidates = [
            f"fatal: unable to access '{URL}/': The requested URL returned error: 500\n",
            f"Error: Error cloning {URL}\n",
            f"warning: unable to access '{URL}/': The requested URL returned error: 500\nError: Error cloning {URL}\n",
            failure().replace("Error: Error cloning", "Error: Error fetching"),
            failure().replace("fatal: unable to access", "fatal: could not fetch"),
            "fixture generic nonnetwork error\n", "",
        ]
        for stderr in candidates:
            with self.subTest(stderr=stderr):
                self.assert_immediate_failure("no identity", stderr)

    def test_certificate_auth_ref_and_unknown_transport_errors_fail_immediately(self):
        reasons = ["SSL certificate problem: unable to get local issuer certificate",
                   "server certificate verification failed", "Authentication failed",
                   "Could not resolve host: git.savannah.gnu.org", "Connection refused",
                   "remote error: missing revision", "The requested URL returned error: 5000",
                   "The requested URL returned error: 500; certificate verification failed"]
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assert_immediate_failure("no identity", failure(reason))

    def test_mixed_integrity_auth_ref_and_other_project_errors_fail_closed(self):
        guards = ["Error: SHA256 checksum mismatch for compiler.tar.xz",
                  "BAD signature from source signer", "certificate verification failed",
                  "Authentication failed for source repository", "missing commit deadbeef",
                  "couldn't find remote ref missing-tag", "invalid Firefox revision",
                  "fatal: source repository does not exist", "Error: other project failed",
                  "fatal: unable to access 'https://example.test/other.git/': The requested URL returned error: 503"]
        for guard in guards:
            for stream in ("stderr", "stdout"):
                with self.subTest(guard=guard, stream=stream):
                    self.assert_immediate_failure(guard if stream == "stdout" else "failed identity",
                        failure() + (guard + "\n" if stream == "stderr" else ""))

    def test_native_signal_exit_and_executable_failure_do_not_retry(self):
        result = self.assert_immediate_failure("", "terminated by native signal\n", status=-15)
        self.assertEqual(result["error"].returncode, -15)
        self.assert_immediate_failure("", failure(), status=-15)
        pauses = []
        with mock.patch.object(rbm_network.subprocess, "run", side_effect=FileNotFoundError("rbm missing")) as run:
            with self.assertRaises(FileNotFoundError):
                rbm_network.showconf(self.upstream, "rust", "filename", TARGETS, pause=pauses.append)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(pauses, [])


FAKE_RBM = r"""import json, os, sys
from pathlib import Path
state = Path(os.environ['RBM_STATE'])
number = int(state.read_text()) if state.exists() else 0
state.write_text(str(number + 1))
with open(os.environ['RBM_CALLS'], 'a') as stream:
    stream.write(json.dumps({'args': sys.argv[1:], 'cwd': str(Path.cwd())}) + '\n')
result = json.loads(Path(os.environ['RBM_RESULTS']).read_text())[number]
sys.stdout.write(result['stdout'])
sys.stderr.write(result['stderr'])
sys.exit(result['returncode'])
"""

HARNESS = r"""import json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, os.environ['PROJECT_SCRIPTS'])
from rbm_network import showconf
def pause(delay):
    with open(os.environ['PAUSES'], 'a') as stream:
        stream.write(str(delay) + '\n')
try:
    identity = showconf(Path(os.environ['UPSTREAM']), 'rust', 'filename',
                       ['alpha', 'mullvadbrowser-windows-x86_64', 'pgo-generate'], pause=pause)
except subprocess.CalledProcessError as error:
    Path(os.environ['FINAL_ERROR']).write_text(json.dumps({
        'returncode': error.returncode, 'cmd': error.cmd,
        'output': error.output, 'stderr': error.stderr}))
    sys.exit(error.returncode)
sys.stdout.write(identity + '\n')
"""


class NativeProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rbm-network-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream with spaces"
        rbm = self.upstream / "rbm/rbm"
        rbm.parent.mkdir(parents=True)
        rbm.write_text(f"#!{sys.executable}\n" + FAKE_RBM)
        rbm.chmod(0o755)
        self.harness = self.base / "harness.py"
        self.harness.write_text(HARNESS)
        self.results = self.base / "results.json"
        self.calls = self.base / "calls.jsonl"
        self.pauses = self.base / "pauses.txt"
        self.error = self.base / "error.json"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("GITHUB_") and key != "CI"}
        self.env.update({"UPSTREAM": str(self.upstream), "PROJECT_SCRIPTS": str(SCRIPTS),
                         "RBM_RESULTS": str(self.results), "RBM_CALLS": str(self.calls),
                         "RBM_STATE": str(self.base / "state"), "PAUSES": str(self.pauses),
                         "FINAL_ERROR": str(self.error), "PYTHONDONTWRITEBYTECODE": "1"})

    def run_fixture(self, outcomes):
        self.results.write_text(json.dumps([{"returncode": result.returncode,
                                           "stdout": result.stdout, "stderr": result.stderr}
                                          for result in outcomes]))
        return subprocess.run([sys.executable, str(self.harness)], cwd=ROOT, env=self.env,
                              text=True, capture_output=True, timeout=20)

    def assert_attempts(self, count):
        records = [json.loads(line) for line in self.calls.read_text().splitlines()]
        expected = {"args": ["showconf", "rust", "filename",
                             *[arg for target in TARGETS for arg in ("--target", target)]],
                    "cwd": str(self.upstream)}
        self.assertEqual(records, [expected] * count)
        delays = [int(line) for line in self.pauses.read_text().splitlines()] if self.pauses.exists() else []
        self.assertEqual(delays, [10, 30][:count - 1])

    def test_actual_fixture_processes_retry_with_clean_success_stdout(self):
        result = self.run_fixture([outcome(1, "failed selected filename one\n", failure()),
                                   outcome(2, "failed selected filename two\n", failure()),
                                   outcome(0, " \t exact-profiler.tar.xz\n", "final native progress\n")])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "exact-profiler.tar.xz\n")
        self.assert_attempts(3)
        self.assertEqual(result.stderr.count("Error: Error cloning " + URL), 2)
        self.assertIn("attempt 1/3", result.stderr)
        self.assertIn("attempt 2/3", result.stderr)
        self.assertIn("final native progress\n", result.stderr)
        self.assertIn("failed selected filename one\n", result.stderr)
        self.assertIn("failed selected filename two\n", result.stderr)
        self.assertFalse(self.error.exists())

    def test_actual_stdout_only_transient_diagnostics_recover_without_identity_leak(self):
        diagnostic = "native RBM progress on stdout\n" + failure()
        result = self.run_fixture([outcome(1, diagnostic, ""),
                                   outcome(0, " final-exact-profiler.tar.xz\n", "success progress\n")])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "final-exact-profiler.tar.xz\n")
        self.assert_attempts(2)
        self.assertIn(diagnostic, result.stderr)
        self.assertIn("attempt 1/3", result.stderr)
        self.assertIn("success progress\n", result.stderr)
        self.assertFalse(self.error.exists())

    def test_actual_nontransient_failure_never_reaches_planned_success(self):
        diagnostic = failure("The requested URL returned error: 404")
        result = self.run_fixture([outcome(23, "untrusted filename\n", diagnostic),
                                   outcome(0, "must-not-be-used.tar.xz\n")])
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assert_attempts(1)
        self.assertIn(diagnostic, result.stderr)
        self.assertIn("attempt 1/3", result.stderr)
        error = json.loads(self.error.read_text())
        self.assertEqual(error["returncode"], 23)
        self.assertEqual(error["output"], "untrusted filename\n")
        self.assertEqual(error["stderr"], diagnostic)
        self.assertNotIn("must-not-be-used", result.stderr)

    def test_actual_fixture_processes_stop_at_three_with_final_native_exit(self):
        last_stdout = "bad identity final\n" + failure()
        result = self.run_fixture([outcome(1, "bad identity one\n", failure()),
                                   outcome(2, "bad identity two\n", failure()),
                                   outcome(27, last_stdout, "")])
        self.assertEqual(result.returncode, 27, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assert_attempts(3)
        error = json.loads(self.error.read_text())
        self.assertEqual(error, {"returncode": 27,
            "cmd": [str(self.upstream / "rbm/rbm"), "showconf", "rust", "filename",
                    *[arg for target in TARGETS for arg in ("--target", target)]],
            "output": last_stdout, "stderr": ""})
        self.assertIn("attempt 3/3", result.stderr)
        self.assertIn("retry limit reached", result.stderr)
        for suffix in ("one", "two", "final"):
            self.assertIn(f"bad identity {suffix}\n", result.stderr)


if __name__ == "__main__":
    unittest.main()
