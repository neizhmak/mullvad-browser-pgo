#!/usr/bin/env python3
"""Structural checks for the baseline/control build orchestration."""

from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/baseline.yml"

class BaselineWorkflowTests(unittest.TestCase):
    def test_restores_all_required_stages_before_official_make_target(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(workflow.index("restore-required --upstream"),
                        workflow.index("make mullvadbrowser-alpha-windows-x86_64"))
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
        self.assertGreaterEqual(workflow.count('cd "$UPSTREAM"'), 2)

if __name__ == "__main__":
    unittest.main()
