#!/usr/bin/env python3
"""Offline source-only workflow guards, not runtime CPU or browser/PGO proof."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CALLER = ROOT / ".github/workflows/tests.yml"
PROBE = ROOT / ".github/workflows/pgo-resource-probe.yml"
STAGE = ROOT / ".github/workflows/pgo-stage4a.yml"
COMMAND = ('python3 ./scripts/probe-rbm-resource-control.py --upstream "$UPSTREAM" '
           '--output-directory "$RUNNER_TEMP/rbm-resource-probe"')


def job(text, name):
    begin = re.search(r"^  " + re.escape(name) + r":\n", text, re.MULTILINE).start()
    tail = text[begin:]
    lines = tail.splitlines(keepends=True)
    for index, line in enumerate(lines[1:], 1):
        if line.startswith("  ") and not line.startswith("    ") and line.strip():
            return "".join(lines[:index])
    return tail


def step(text, name):
    begin = text.index("      - name: " + name + "\n")
    tail = text[begin:]
    end = tail.find("\n      -", 1)
    return tail if end == -1 else tail[:end] + "\n"


def workflow_input(text, name):
    begin = text.index("      " + name + ":\n")
    lines = text[begin:].splitlines(keepends=True)
    for index, line in enumerate(lines[1:], 1):
        if line.strip() and not line.startswith("        "):
            return "".join(lines[:index])
    return "".join(lines)


class ResourceWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.caller = CALLER.read_text()
        self.probe = PROBE.read_text()
        self.stage = STAGE.read_text()
        self.call = job(self.caller, "resource-probe")
        self.runtime = job(self.probe, "resource-probe")

    def test_registered_resource_input_is_typed_false_and_not_browser_validation(self):
        self.assertEqual(workflow_input(self.caller, "resource_probe"),
            "      resource_probe:\n"
            "        description: Probe exact RBM source and CPU authority only (not a browser build or PGO validation)\n"
            "        type: boolean\n        default: false\n")

    def test_caller_is_exact_dispatch_only_isolated_contents_read_job(self):
        self.assertEqual(self.call,
            "  resource-probe:\n"
            "    if: ${{ github.event_name == 'workflow_dispatch' && inputs.resource_probe }}\n"
            "    permissions:\n      contents: read\n"
            "    uses: ./.github/workflows/pgo-resource-probe.yml\n")
        for forbidden in ["steps:", "secrets:", "env:", "needs:", "with:", "write", "actions:", "checks:"]:
            self.assertNotIn(forbidden, self.call)

    def test_existing_inputs_keep_independent_defaults(self):
        for name, default in [("baseline_smoke", "true"), ("baseline_diagnostics", "false"),
                              ("telemetry_smoke", "false")]:
            block = workflow_input(self.caller, name)
            self.assertIn("        type: boolean\n", block)
            self.assertIn("        default: " + default + "\n", block)
            self.assertNotIn("resource_probe", block)
        self.assertIn("permissions:\n  contents: read\n  actions: read\n", self.caller.split("jobs:\n", 1)[0])

    def test_existing_job_conditions_do_not_depend_on_resource_input(self):
        for name in ["test", "windows-native", "baseline-smoke", "telemetry-smoke"]:
            block = job(self.caller, name)
            self.assertNotIn("resource_probe", block)
            self.assertNotIn("resource-probe", block)
        baseline = job(self.caller, "baseline-smoke")
        telemetry = job(self.caller, "telemetry-smoke")
        self.assertIn("    if: ${{ github.event_name == 'workflow_dispatch' && inputs.baseline_smoke }}\n", baseline)
        self.assertIn("    if: ${{ github.event_name == 'workflow_dispatch' && inputs.telemetry_smoke }}\n", telemetry)
        self.assertNotIn("telemetry_smoke", baseline)
        self.assertNotIn("baseline_smoke", telemetry)

    def test_telemetry_caller_permissions_and_fields_stay_literal(self):
        self.assertEqual(job(self.caller, "telemetry-smoke"),
            "  telemetry-smoke:\n"
            "    if: ${{ github.event_name == 'workflow_dispatch' && inputs.telemetry_smoke }}\n"
            "    permissions:\n      contents: read\n      actions: read\n      checks: write\n"
            "    uses: ./.github/workflows/pgo-diagnostics.yml\n")
        self.assertEqual(self.caller.count("      checks: write"), 1)
        self.assertIn("    timeout-minutes: 20\n", job(self.caller, "baseline-smoke"))

    def test_push_and_pull_request_cannot_run_resource_pilot(self):
        self.assertIn("on:\n  push:\n  pull_request:\n  workflow_dispatch:\n", self.caller)
        self.assertEqual(self.caller.count("inputs.resource_probe"), 1)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.resource_probe", self.call)
        self.assertNotIn("resource_probe", self.caller.replace(workflow_input(self.caller, "resource_probe"), "").replace(self.call, ""))

    def test_callee_only_explicit_dispatch_or_workflow_call(self):
        header = self.probe.split("jobs:\n", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:\n  workflow_call:\n", header)
        self.assertEqual(header.split("on:\n", 1)[1].split("permissions:\n", 1)[0],
                         "  workflow_dispatch:\n  workflow_call:\n")
        for forbidden in ["push:", "pull_request", "schedule", "workflow_run", "repository_dispatch"]:
            self.assertNotIn(forbidden, header)

    def test_callee_free_runner_and_fifteen_minute_job_only(self):
        self.assertIn("    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n", self.runtime)
        self.assertEqual(re.findall(r"^  ([A-Za-z0-9_-]+):$", self.probe.split("jobs:\n", 1)[1], re.MULTILINE),
                         ["resource-probe"])
        for forbidden in ["windows-", "self-hosted", "large", "matrix:", "strategy:"]:
            self.assertNotIn(forbidden, self.runtime)

    def test_callee_global_and_job_permissions_are_contents_read_only(self):
        self.assertTrue(self.probe.split("jobs:\n", 1)[0].endswith("permissions:\n  contents: read\n"))
        self.assertIn("    permissions:\n      contents: read\n    steps:\n", self.runtime)
        for forbidden in [": write", "checks:", "actions:", "id-token:", "secrets:", "inherit"]:
            self.assertNotIn(forbidden, self.probe)

    def test_checkout_does_not_cache_token(self):
        self.assertIn("      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n", self.runtime)
        self.assertEqual(self.runtime.count("actions/checkout@v4"), 1)
        self.assertNotIn("persist-credentials: true", self.runtime)

    def test_only_known_upstream_path_is_written_to_job_environment(self):
        initialize = step(self.runtime, "Initialize pinned source probe")
        self.assertEqual(initialize,
            "      - name: Initialize pinned source probe\n        run: |\n"
            '          echo "UPSTREAM=$RUNNER_TEMP/tor-browser-build" >> "$GITHUB_ENV"\n')
        self.assertEqual(self.runtime.count("GITHUB_ENV"), 1)
        self.assertNotIn("GITHUB_OUTPUT", self.runtime)
        self.assertNotIn("    env:", self.runtime)
        self.assertNotIn("        env:", self.runtime)

    def test_native_perl_and_uidmap_requirements_are_unchanged_copy(self):
        self.assertEqual(step(self.runtime, "Install RBM requirements"),
                         step(job(self.stage, "pgo-generate"), "Install RBM requirements"))
        requirements = step(self.runtime, "Install RBM requirements")
        for package in ["libtemplate-perl", "libyaml-libyaml-perl", "libcapture-tiny-perl", "uidmap", "git"]:
            self.assertIn(package, requirements)

    def test_namespace_mapping_and_apparmor_block_is_exact_original(self):
        self.assertEqual(step(self.runtime, "Prepare and validate RBM user namespaces"),
                         step(job(self.stage, "pgo-generate"), "Prepare and validate RBM user namespaces"))
        namespace = step(self.runtime, "Prepare and validate RBM user namespaces")
        self.assertIn("kernel.apparmor_restrict_unprivileged_userns=0", namespace)
        self.assertIn("/etc/subuid /etc/subgid", namespace)
        self.assertIn("65536", namespace)

    def test_fetch_is_bounded_unmodified_script_and_normal_rbm_submodule_only(self):
        self.assertEqual(step(self.runtime, "Fetch exact source and RBM only"),
            "      - name: Fetch exact source and RBM only\n        timeout-minutes: 4\n        run: |\n"
            "          set -euo pipefail\n"
            '          ./scripts/fetch-upstream.sh --destination "$UPSTREAM"\n'
            '          git -C "$UPSTREAM" submodule update --init rbm\n')
        self.assertEqual(self.runtime.count("fetch-upstream.sh"), 1)
        self.assertEqual(self.runtime.count("submodule update"), 1)
        self.assertNotIn("--recursive", self.runtime)

    def test_native_probe_command_and_step_deadline_match_contract(self):
        self.assertEqual(step(self.runtime, "Probe exact RBM source and namespace controllers"),
            "      - name: Probe exact RBM source and namespace controllers\n"
            "        timeout-minutes: 4\n        run: " + COMMAND + "\n")
        self.assertEqual(self.runtime.count("probe-rbm-resource-control.py"), 1)

    def test_native_failure_is_not_swallowed_or_retried(self):
        probe = step(self.runtime, "Probe exact RBM source and namespace controllers")
        fetch = step(self.runtime, "Fetch exact source and RBM only")
        for block in [probe, fetch]:
            for forbidden in ["continue-on-error", "||", "retry", "attempt", "sleep", "timeout ", " if: "]:
                self.assertNotIn(forbidden, block)
        self.assertNotIn("continue-on-error", self.runtime)

    def test_no_explicit_tokens_secrets_apis_or_telemetry_publisher(self):
        for forbidden in ["GH_TOKEN", "GITHUB_TOKEN", "PGO_TELEMETRY_TOKEN", "github.token", "secrets.",
                          "gh api", "gh release", "curl ", "Checks", "publish-rbm-telemetry", "observe-rbm-build"]:
            self.assertNotIn(forbidden, self.probe + self.call)
        self.assertEqual(self.runtime.count("      - uses:"), 1)
        self.assertEqual(self.runtime.count("        uses: actions/upload-artifact@v4"), 1)

    def test_no_browser_compiler_overlay_restores_or_filename_queries(self):
        for forbidden in ["run-pgo-", "prepare-pgo-", "train-pgo", "cargo build", "cargo rustc", "mach build",
                          "rbm build", "restore-required", "restore-pgo-", "capture-pgo-", "resolve-pgo-",
                          "prepare-binutils", "download-artifact", "showconf firefox filename",
                          "showconf firefox version", "showconf firefox input_files", "compiler archive"]:
            self.assertNotIn(forbidden, self.probe + self.call)

    def test_workflow_does_not_set_production_cpu_memory_or_parallelism_policy(self):
        for forbidden in ["taskset", "sched_setaffinity", "NUMPROC", "MOZ_PARALLEL_BUILD", "MOZ_MAKE_FLAGS",
                          "CARGO_BUILD_JOBS", "MAKEFLAGS", "OMP_NUM_THREADS", "RAYON_NUM_THREADS", "mkswap",
                          "swapon", "drop_caches", "memory.max", "ulimit", "--numprocs", "-j2"]:
            self.assertNotIn(forbidden, self.probe + self.call)
        settings = re.findall(r"sysctl -w ([^\n]+)", self.probe)
        self.assertEqual(settings, ["kernel.apparmor_restrict_unprivileged_userns=0"])

    def test_always_upload_fixed_public_source_directory_warns_if_absent(self):
        self.assertEqual(step(self.runtime, "Preserve public source and partial controller evidence"),
            "      - name: Preserve public source and partial controller evidence\n"
            "        if: always()\n        uses: actions/upload-artifact@v4\n        with:\n"
            "          name: pgo-rbm-resource-probe\n"
            "          path: ${{ runner.temp }}/rbm-resource-probe/\n"
            "          if-no-files-found: warn\n")
        self.assertEqual(self.runtime.count("if: always()"), 1)
        self.assertNotIn("include-hidden-files", self.runtime)
        self.assertNotIn("path: .", self.runtime)

    def test_setup_fetch_probe_and_partial_upload_order_is_fixed(self):
        names = ["Initialize pinned source probe", "Install RBM requirements", "Prepare and validate RBM user namespaces",
                 "Fetch exact source and RBM only", "Probe exact RBM source and namespace controllers",
                 "Preserve public source and partial controller evidence"]
        positions = [self.runtime.index("      - name: " + name + "\n") for name in names]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.runtime.count("      - name:"), len(names))
        self.assertEqual(self.runtime.count("        run:"), 5)

    def test_no_environment_argument_dump_or_shell_tracing(self):
        self.assertNotIn("set -x", self.runtime)
        self.assertNotIn("set -eux", self.runtime)
        self.assertNotIn("printenv", self.runtime)
        self.assertNotIn("/proc/self/environ", self.runtime)
        self.assertIsNone(re.search(r"(?:^|[\n;])\s*(?:env|export)\b", self.runtime))
        self.assertNotIn("GITHUB_CONTEXT", self.runtime)
        self.assertNotIn("toJSON", self.runtime)


if __name__ == "__main__":
    unittest.main()
