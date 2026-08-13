#!/usr/bin/env python3
"""Lightweight structural checks for the RBM dependency workflow."""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/build-rbm-dependencies.yml"


class WorkflowTests(unittest.TestCase):
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
