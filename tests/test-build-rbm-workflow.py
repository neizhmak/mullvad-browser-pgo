#!/usr/bin/env python3
"""Lightweight structural checks for the RBM dependency workflow."""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/build-rbm-dependencies.yml"


class WorkflowTests(unittest.TestCase):
    def test_pinned_rbm_container_preflight_is_between_fetch_and_build(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        preparation = workflow.index("      - name: Prepare and validate RBM user namespaces\n")
        fetch = workflow.index("      - name: Fetch pinned official build tree\n")
        preflight = workflow.index("      - name: Validate pinned RBM container namespaces\n")
        build = workflow.index("      - name: Build stage through RBM\n")

        self.assertLess(preparation, fetch)
        self.assertLess(fetch, preflight)
        self.assertLess(preflight, build)
        self.assertIn("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0", workflow)
        self.assertIn('build_user="$(id -un)"', workflow)
        self.assertIn("for map_file in /etc/subuid /etc/subgid", workflow)
        self.assertIn('"$UPSTREAM/rbm/container" run -- /bin/true', workflow)
        self.assertNotIn("unshare --user", workflow)
        self.assertNotIn("--map-users", workflow)
        self.assertNotIn("--map-groups", workflow)

    def test_complete_stage_skips_restore_build_and_publish(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        condition = "        if: steps.stage.outputs.complete != 'true'\n"

        self.assertIn("stage-complete --upstream", workflow)
        self.assertEqual(workflow.count(condition), 4)
        self.assertIn('echo "complete=true" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn('echo "complete=false" >> "$GITHUB_OUTPUT"', workflow)

    def test_stage_chain_allows_each_incomplete_job_to_restore_prerequisites(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  mingw-w64-clang:\n    needs: clang", workflow)
        self.assertIn("  rust:\n    needs: mingw-w64-clang", workflow)
        check = workflow.index("      - name: Check whether current RBM stage is complete\n")
        restore = workflow.index("      - name: Restore verified RBM outputs\n")
        build = workflow.index("      - name: Build stage through RBM\n")
        self.assertLess(check, restore)
        self.assertLess(restore, build)

    def test_automated_build_disables_interactive_rbm_debugging(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn('  RBM_NO_DEBUG: "1"\n', workflow)

    def test_build_publishes_before_always_uploading_logs(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        build = workflow.index("      - name: Build stage through RBM\n")
        publish = workflow.index("      - name: Publish new immutable RBM outputs\n")
        logs = workflow.index("      - name: Upload RBM build logs\n")

        self.assertLess(build, publish)
        self.assertLess(publish, logs)
        self.assertIn("        if: always()\n", workflow[logs:])


if __name__ == "__main__":
    unittest.main()
