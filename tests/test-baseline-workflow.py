#!/usr/bin/env python3
"""Structural checks for the baseline/control build orchestration."""

from pathlib import Path
import re
import os
import subprocess
import tempfile
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/baseline.yml"
RUNNER = WORKFLOW.parents[2] / "scripts/run-baseline-build.sh"

class BaselineWorkflowTests(unittest.TestCase):
    def test_restores_all_required_stages_before_official_make_target(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertLess(workflow.index("restore-required --upstream"),
                        workflow.index("scripts/run-baseline-build.sh"))
        self.assertIn("make mullvadbrowser-alpha-windows-x86_64", runner)
        self.assertIn("--stage clang --stage mingw-w64-clang --stage rust", workflow)
        self.assertNotIn("rbm/rbm build clang", workflow)
        self.assertNotIn("rbm/rbm build rust", workflow)

    def test_uses_pinned_checkout_container_preflight_and_no_debug(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        positions = [workflow.index(value) for value in (
            "./scripts/fetch-upstream.sh",
            'git -C "$UPSTREAM" submodule update --init rbm',
            '"$UPSTREAM/rbm/container" run -- /bin/true',
            "restore-required --upstream")]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('RBM_NO_DEBUG: "1"', workflow)
        self.assertIn("kernel.apparmor_restrict_unprivileged_userns=0", workflow)

    def test_packages_and_always_logs_are_uploaded_without_release(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn("-name '*.exe' -o -name '*.mar'", workflow)
        logs = workflow.index("      - name: Upload RBM and browser build logs\n")
        self.assertIn("        if: always()\n", workflow[logs:])
        self.assertNotIn("gh release create", workflow)

    def test_timeouts_fit_github_hosted_runner_limits(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        timeouts = [int(value) for value in
                    re.findall(r"^\s+timeout-minutes:\s*(\d+)\s*$", workflow,
                               flags=re.MULTILINE)]
        self.assertTrue(timeouts)
        self.assertTrue(all(timeout <= 360 for timeout in timeouts), timeouts)
        self.assertIn("    timeout-minutes: 360\n", workflow)
        self.assertIn("        timeout-minutes: 330\n", workflow)

    def test_dynamic_upstream_is_not_used_as_expression_context(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('echo "UPSTREAM=$RUNNER_TEMP/tor-browser-build" >> "$GITHUB_ENV"',
                      workflow)
        self.assertNotIn("${{ env.UPSTREAM }}", workflow)
        self.assertIn('cd "$UPSTREAM"', RUNNER.read_text(encoding="utf-8"))

    def run_retry_script(self, outcomes):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream"
            fake_bin = root / "bin"
            (upstream / "out").mkdir(parents=True)
            fake_bin.mkdir()
            marker = upstream / "out" / "completed-rbm-output"
            marker.write_text("keep me", encoding="utf-8")
            (root / "outcomes").write_text("\n".join(map(str, outcomes)) + "\n",
                                           encoding="utf-8")
            fake_make = fake_bin / "make"
            fake_make.write_text("""#!/usr/bin/env bash
echo "$*" >> "$CALLS"
test -f "$UPSTREAM/out/completed-rbm-output" || exit 91
status="$(head -n 1 "$OUTCOMES")"
sed -i '1d' "$OUTCOMES"
exit "$status"
""", encoding="utf-8")
            fake_make.chmod(0o755)
            env = os.environ | {
                "UPSTREAM": str(upstream),
                "RUNNER_TEMP": str(root),
                "BASELINE_RETRY_DELAY_SECONDS": "0",
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "CALLS": str(root / "calls"),
                "OUTCOMES": str(root / "outcomes"),
            }
            result = subprocess.run([RUNNER], env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    check=False)
            calls = (root / "calls").read_text(encoding="utf-8").splitlines()
            return result, calls

    def test_retry_keeps_official_target_and_succeeds_on_second_attempt(self):
        result, calls = self.run_retry_script([23, 0])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(calls, ["mullvadbrowser-alpha-windows-x86_64"] * 2)
        self.assertIn("attempt 1/2", result.stdout)
        self.assertIn("attempt 2/2", result.stdout)

    def test_retry_stops_after_two_failures_and_preserves_failure(self):
        result, calls = self.run_retry_script([17, 42, 0])
        self.assertEqual(result.returncode, 42, result.stdout)
        self.assertEqual(calls, ["mullvadbrowser-alpha-windows-x86_64"] * 2)

    def test_runner_preserves_pipefail_and_never_removes_outputs(self):
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("set -o pipefail", runner)
        self.assertNotRegex(runner, r"\b(?:rm|git clean)\b")
        self.assertIn("max_attempts=2", runner)

if __name__ == "__main__":
    unittest.main()
