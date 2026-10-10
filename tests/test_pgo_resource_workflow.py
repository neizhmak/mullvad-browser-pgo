#!/usr/bin/env python3
"""Exact resource-only generation workflow guards; not real PGO/compiler proof."""
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".github/workflows/pgo-stage4a.yml"
ORIGINAL_STAGE_SHA256 = "7f7dd2e5d8361b6f2f121f6842c4e0f7a257cf3db5065891145544860385b657"
GATE_NAME = "Validate warm offline generation resource policy"
GATE_COMMAND = ('python3 ./scripts/validate-pgo-resource-policy.py --upstream "$UPSTREAM" '
                '--rust-identity "$RUNNER_TEMP/pgo-rust-identity.json" '
                '--node-support-directory "$RUNNER_TEMP/pgo-support" '
                '--provenance "$RUNNER_TEMP/provenance/build.json" '
                '--output "$RUNNER_TEMP/pgo-generation-resource-policy.json" '
                '--diagnostic-directory "$RUNNER_TEMP/pgo-resource-validation"')
BUILD_COMMAND = ('python3 ./scripts/run-pgo-resource-limited.py '
                 '--policy "$RUNNER_TEMP/pgo-generation-resource-policy.json" -- ./scripts/run-pgo-generate.sh')
GATE = "      - name: " + GATE_NAME + "\n        timeout-minutes: 10\n        run: " + GATE_COMMAND + "\n"
OLD_BUILD = "      - name: Build only instrumented Firefox\n        timeout-minutes: 285\n        run: ./scripts/run-pgo-generate.sh\n"
BUILD = "      - name: Build only instrumented Firefox\n        timeout-minutes: 285\n        run: " + BUILD_COMMAND + "\n"
UPLOAD_NAME = "Preserve generation resource policy and validation evidence"
UPLOAD = ("      - name: " + UPLOAD_NAME + "\n"
          "        if: always()\n        uses: actions/upload-artifact@v4\n        with:\n"
          "          name: pgo-generation-resource-validation\n          path: |\n"
          "            ${{ runner.temp }}/pgo-generation-resource-policy.json\n"
          "            ${{ runner.temp }}/pgo-resource-validation/\n"
          "          if-no-files-found: warn\n")
PROTECTED_SHA256 = {'.github/workflows/pgo-diagnostics.yml': 'ddb28401ae10922acfa8db115a8529a7d89385dc217b309fc0df6b5243be691f',
 '.github/workflows/pgo-resource-probe.yml': 'ffc25463bb10e415cdb3346d518d4e39222c0e0a7ba4211c14ab324ebb301f11',
 '.github/workflows/tests.yml': '807a385c0b6b2d86c815397c40ae568c259488ab2eebb477f7ae3b29c8470f8f',
 '.github/workflows/windows-pgo.yml': 'c3fc83f60052716b355f20281c89bd94e48fc516299daab611573fcd1b75a6d5',
 'patches/firefox-pgo-generate.patch': '0cbac319281d57d5136192775c817bb644ae521cb70b320c48a00fcdd5ff466d',
 'patches/firefox-pgo-use.patch': 'fc2ca4605a5f5a9cdbbbb74614a8fb4ccca36e7c3c9e1f7b1d12093ec1aba169',
 'scripts/capture-pgo-toolchains.py': '4f795928a55250d5b41af5b78dd5cbfc0e35b3bede954deee9b95d04b02d54ce',
 'scripts/observe-rbm-build.py': 'e260d356e701dc475159156c7312837cfe1ee2123699952279334f414b61abde',
 'scripts/publish-rbm-telemetry.py': '3691cd61c2a2f1c60c3425b8e5e296742f9cf26142f463a987f3259ac277c1d2',
 'scripts/resolve-pgo-rust-identity.py': '88d302c2e0bddb9108a25394d01b727020234f06dc39b779da926f47921f6b7c',
 'scripts/resolve-pgo-support-identity.py': '8bace4103f28bcf9aaf1604ac4c045f9a4fc630cd4e65c44f1d5b7c996905937',
 'scripts/run-pgo-generate.sh': '45ad6cea8ec626a4151dc6f71f7115e0f559658682be1a1d06517a2b97a5fd4d',
 'scripts/run-pgo-use.sh': 'ad7ae5d1c388abcdf665868cf279646c892809abedee38a090ed80c7e94a742b',
 'tests/test_observe_rbm_build.py': 'c31f53eedad9e78a25379c80ede98f40789cce41da3c29d0c030c8dfab8dd2bf',
 'tests/test_rbm_telemetry.py': 'b34f56eef1525f294f1db258f0376733b28e15de6d885fe81d97d6fcd9e7cbff',
 'upstream.lock.json': '3879a66953ebe9f3f356a14a9126cfa6a76ef51bb1c45b1a87569bdd980ff1c6'}


def job(text, name):
    begin = text.index("  " + name + ":\n")
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


class GenerationResourceWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.stage = STAGE.read_text()
        self.generate = job(self.stage, "pgo-generate")
        self.gate = step(self.generate, GATE_NAME)
        self.build = step(self.generate, "Build only instrumented Firefox")
        self.start = step(self.generate, "Start acknowledged durable resource telemetry")
        self.stop = step(self.generate, "Stop durable resource telemetry")

    def test_only_exact_three_authorized_workflow_changes(self):
        self.assertEqual(self.stage.count(GATE), 1)
        self.assertEqual(self.stage.count(BUILD), 1)
        self.assertEqual(self.stage.count(UPLOAD), 1)
        original = self.stage.replace(GATE, "").replace(BUILD, OLD_BUILD).replace(UPLOAD, "")
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(), ORIGINAL_STAGE_SHA256)

    def test_exact_fatal_warm_gate_arguments_and_ten_minute_deadline(self):
        self.assertEqual(self.gate, GATE)
        self.assertEqual(self.generate.count("validate-pgo-resource-policy.py"), 1)
        for forbidden in ["continue-on-error", "if:", "env:", "||", "retry", "sleep", "attempt", "timeout "]:
            self.assertNotIn(forbidden, self.gate)

    def test_warm_restores_and_binutils_precede_gate_and_ack_precedes_build(self):
        order = ["Fetch exact upstream and restore compilers", "Apply explicit cross-language generation overlay",
                 "Restore exact native-verified profiler Rust", "Record exact Firefox source and compiler archive identities",
                 "Restore exact pinned Node support and bind archive bytes", "Prepare verified Binutils input",
                 GATE_NAME, "Start acknowledged durable resource telemetry", "Build only instrumented Firefox"]
        positions = [self.generate.index("      - name: " + name + "\n") for name in order]
        self.assertEqual(positions, sorted(positions))
        boundary = (step(self.generate, "Prepare verified Binutils input") + GATE + self.start + BUILD)
        self.assertIn(boundary, self.generate)

    def test_real_bound_restored_inputs_not_fixture_or_regenerated_compilers(self):
        for argument in ['--rust-identity "$RUNNER_TEMP/pgo-rust-identity.json"',
                         '--node-support-directory "$RUNNER_TEMP/pgo-support"',
                         '--provenance "$RUNNER_TEMP/provenance/build.json"']:
            self.assertIn(argument, self.gate)
        for forbidden in ["fixture", "skip", "allow", "mock", "restore", "download", "build firefox", "build rust", "clone"]:
            self.assertNotIn(forbidden, self.gate)

    def test_build_exact_outer_wrapper_and_original_inner_native_command(self):
        self.assertEqual(self.build, BUILD)
        self.assertEqual(self.build.count(" -- ./scripts/run-pgo-generate.sh"), 1)
        self.assertEqual(self.generate.count("run-pgo-resource-limited.py"), 1)
        self.assertNotIn("env:", self.build)
        self.assertNotIn("continue-on-error", self.build)
        self.assertNotIn("if:", self.build)

    def test_generation_uses_one_fixed_verified_policy_path_only(self):
        self.assertIn('--output "$RUNNER_TEMP/pgo-generation-resource-policy.json"', self.gate)
        self.assertIn('--policy "$RUNNER_TEMP/pgo-generation-resource-policy.json"', self.build)
        self.assertIn("${{ runner.temp }}/pgo-generation-resource-policy.json", UPLOAD)
        self.assertNotIn("--worker", self.build)
        self.assertNotIn("--cpu", self.build)
        self.assertNotIn("--affinity", self.build)
        self.assertNotIn("--num-procs", self.build)
        self.assertNotIn("--mask", self.build)

    def test_cpu_choice_is_policy_authority_not_hard_coded_workflow_mask(self):
        for forbidden in ["taskset", "0,1", "0-1", "--cpus", "-j2", "NUMPROC", "RBM_NUM_PROCS", "MOZ_PARALLEL_BUILD",
                          "CARGO_BUILD_JOBS", "MAKEFLAGS", "OMP_NUM_THREADS", "OMP_THREAD_LIMIT", "RAYON_NUM_THREADS"]:
            self.assertNotIn(forbidden, self.gate + self.build)
        header = self.stage.split("jobs:", 1)[0]
        self.assertIn('env:\n  RBM_NO_DEBUG: "1"\n', header)
        for key in ["RBM_NUM_PROCS", "OMP_NUM_THREADS", "CARGO_BUILD_JOBS", "MAKEFLAGS"]:
            self.assertNotIn(key, self.stage)

    def test_wrapper_applies_whole_native_gen_not_only_compiler_or_metadata(self):
        self.assertTrue(BUILD_COMMAND.endswith(" -- ./scripts/run-pgo-generate.sh"))
        for forbidden in ["observe-rbm-build.py", "rbm/rbm", "perl ", "nproc", "render-pgo-resource", "cargo", "mach"]:
            self.assertNotIn(forbidden, self.build)
        source = (ROOT / "scripts/run-pgo-generate.sh").read_text()
        self.assertIn("observe-rbm-build.py", source)
        self.assertIn("-- ./rbm/rbm build firefox", source)
        self.assertNotIn("run-pgo-resource-limited.py", source)

    def test_runner_publisher_not_placed_inside_build_wrapper(self):
        self.assertNotIn("run-pgo-resource-limited", self.start + self.stop)
        self.assertLess(self.generate.index(self.start), self.generate.index(self.build))
        self.assertLess(self.generate.index(self.build), self.generate.index(self.stop))
        self.assertNotIn("publish-rbm-telemetry", self.build)
        self.assertNotIn("taskset", self.stage)

    def test_standard_free_runner_and_original_360_and_285_limits(self):
        self.assertIn("    runs-on: ubuntu-24.04\n    timeout-minutes: 360\n", self.generate)
        self.assertIn("        timeout-minutes: 285\n", self.build)
        self.assertIn("        timeout-minutes: 10\n", self.gate)
        self.assertNotIn("self-hosted", self.stage)
        limits = [int(value) for value in re.findall(r"timeout-minutes: ([0-9]+)", self.stage)]
        self.assertTrue(all(0 < value <= 360 for value in limits))

    def test_readiness_start_is_literal_original_token_boundary(self):
        self.assertEqual(self.start,
            "      - name: Start acknowledged durable resource telemetry\n        timeout-minutes: 1\n"
            "        env:\n          PGO_TELEMETRY_TOKEN: ${{ github.token }}\n        run: |\n"
            "          python3 ./scripts/publish-rbm-telemetry.py start \\\n"
            '            --resource-log "$RUNNER_TEMP/pgo-generate-resources.jsonl" \\\n'
            '            --state "$RUNNER_TEMP/pgo-durable-telemetry.json" \\\n'
            '            --repository "$GITHUB_REPOSITORY" --head "$GITHUB_SHA" \\\n'
            '            --run "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT" \\\n'
            '            --job "$GITHUB_JOB" --interval 120\n')

    def test_optional_stop_remains_literal_and_does_not_hide_native_result(self):
        self.assertEqual(self.stop,
            "      - name: Stop durable resource telemetry\n        if: always()\n"
            "        continue-on-error: true\n        timeout-minutes: 1\n"
            '        run: python3 ./scripts/publish-rbm-telemetry.py stop --state "$RUNNER_TEMP/pgo-durable-telemetry.json"\n')
        self.assertEqual(self.generate.count("continue-on-error: true"), 1)

    def test_no_new_token_permission_secret_or_api_in_resource_steps(self):
        for forbidden in ["TOKEN", "github.token", "secrets", "env:", "GITHUB_ENV", "GITHUB_OUTPUT", "gh api", "curl", "checks:"]:
            self.assertNotIn(forbidden, self.gate + self.build + UPLOAD)
        self.assertEqual(self.stage.count("PGO_TELEMETRY_TOKEN:"), 1)
        self.assertNotIn("PGO_TELEMETRY_TOKEN", self.generate.replace(self.start, ""))
        self.assertIn("    permissions:\n      contents: write\n      actions: read\n      checks: write\n", self.generate)
        self.assertEqual(self.stage.count("      checks: write"), 1)
        self.assertNotIn("checks:", self.stage.split("jobs:", 1)[0])

    def test_checkout_still_does_not_persist_scoped_token(self):
        self.assertIn("      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n", self.generate)

    def test_partial_failure_upload_is_always_fixed_public_metadata_only(self):
        self.assertEqual(step(self.generate, UPLOAD_NAME), UPLOAD)
        self.assertEqual(self.generate.count("name: pgo-generation-resource-validation"), 1)
        for forbidden in ["fixture", "rbm-resource-probe", "browser.tar", "instrumented/", "env:", "include-hidden-files", "*.log", "provenance/"]:
            self.assertNotIn(forbidden, UPLOAD)
        self.assertLess(self.generate.index(self.build), self.generate.index(UPLOAD))

    def test_original_generation_diagnostics_preserves_existing_raw_resource_paths(self):
        diagnostic = step(self.generate, "Preserve generation diagnostics")
        self.assertIn("        if: always()\n", diagnostic)
        self.assertIn("          name: pgo-generation-logs\n", diagnostic)
        for suffix in ["pgo-generate-build.log", "pgo-generate-resources.jsonl", "pgo-durable-telemetry.json",
                       "pgo-support/", "tor-browser-build/logs/", "provenance/"]:
            self.assertIn("${{ runner.temp }}/" + suffix, diagnostic)
        self.assertIn("          if-no-files-found: warn\n", diagnostic)
        self.assertNotIn("pgo-generation-resource-policy", diagnostic)

    def test_postcompile_archive_binding_and_positive_output_upload_stay_required(self):
        bind = step(self.generate, "Bind exact instrumented browser package")
        self.assertIn("--instrumented-package", bind)
        self.assertLess(self.generate.index(self.build), self.generate.index(bind))
        self.assertIn("          name: pgo-instrumented-firefox\n", self.generate)
        self.assertIn("          if-no-files-found: error\n", self.generate)
        self.assertNotIn("continue-on-error", bind)
        self.assertNotIn("pgo-generation-resource-validation", bind)

    def test_native_windows_training_and_two_language_merge_remain_after_generation(self):
        train = job(self.stage, "pgo-train")
        merge = job(self.stage, "pgo-merge")
        self.assertIn("    needs: pgo-generate\n", train)
        self.assertIn("    runs-on: windows-2025\n", train)
        self.assertIn("run: ./scripts/train-pgo.ps1", train)
        self.assertIn("    needs: pgo-train\n", merge)
        self.assertIn("merge-pgo", merge)
        self.assertNotIn("run-pgo-resource-limited", train + merge)
        self.assertNotIn("validate-pgo-resource-policy", train + merge)

    def test_finish_pipeline_defaults_and_optimized_route_are_not_reinterpreted(self):
        dispatch = self.stage.split("  workflow_call:", 1)[0]
        self.assertRegex(dispatch, r"finish_pipeline:[\s\S]*?default: true")
        reusable = self.stage.split("  workflow_call:", 1)[1].split("permissions:", 1)[0]
        self.assertRegex(reusable, r"finish_pipeline:[\s\S]*?default: false")
        finish = job(self.stage, "pgo-finish")
        self.assertIn("inputs.finish_pipeline && !inputs.toolchain_only", finish)
        self.assertIn("uses: ./.github/workflows/windows-pgo.yml", finish)
        self.assertNotIn("resource", finish)

    def test_no_new_compiler_flags_privacy_source_or_memory_changes_in_workflow_delta(self):
        delta = self.gate + self.build + UPLOAD
        for forbidden in ["MOZ_PGO_RUST", "profile-generate=", "codegen-units", "-flto", "LTO", "RUSTFLAGS", "CFLAGS",
                          "CXXFLAGS", "ulimit", "mkswap", "swapon", "drop_caches", "memory.max", "sysctl", "RBM_NO_DEBUG",
                          "privacy", "RLBOX", "disable", "skip", "allow", "baseline", "git ", "fetch", "prepare-pgo"]:
            self.assertNotIn(forbidden, delta)

    def test_no_native_build_retry_fallback_or_metadata_only_success(self):
        for forbidden in ["retry", "fallback", "--workers", "||", "continue-on-error", "sleep", "--one", "--dry-run", "echo"]:
            self.assertNotIn(forbidden, self.gate + self.build)
        self.assertEqual(self.build, BUILD)
        self.assertNotIn("if:", self.build)
        self.assertNotIn("return", self.build)

    def test_lightweight_native_setup_adds_only_required_path_tiny_package(self):
        caller = (ROOT / ".github/workflows/tests.yml").read_text()
        original_install = "          sudo apt-get install -y libtemplate-perl libyaml-libyaml-perl openssl\n"
        required_install = "          sudo apt-get install -y libtemplate-perl libyaml-libyaml-perl openssl libpath-tiny-perl\n"
        self.assertEqual(caller.count(required_install), 1)
        self.assertEqual(caller.count("libpath-tiny-perl"), 1)
        original = caller.replace(required_install, original_install)
        # All jobs, opt-ins, defaults, permissions and routes stay byte-identical.
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),
                         "81abcb91b20e61b45654b1e2ddfbd75cdb7f7609f446859404f940609fad2873")

    def test_exact_locked_source_and_rbm_core_hashes_remain_unchanged(self):
        lock = json.loads((ROOT / "upstream.lock.json").read_text())
        self.assertEqual(lock, {"repository": "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git",
            "tag": "mb-16.0a9-build1", "tag_object": "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721",
            "commit": "7dd751cf1837d667908b339aebf82567ece55e20"})
        for path, expected in PROTECTED_SHA256.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), expected)

    def test_no_fixture_source_pilot_used_as_generation_policy(self):
        self.assertNotIn("pgo-resource-probe.yml", self.generate)
        self.assertNotIn("probe-rbm-resource-control.py", self.generate)
        self.assertNotIn("artifact-source-controller", self.generate)
        self.assertNotIn("probe.json", self.gate + self.build)
        self.assertNotIn("cache_identity_verified", self.stage)

    def test_no_environment_argument_dump_or_new_telemetry_scope(self):
        delta = self.gate + self.build + UPLOAD
        for forbidden in ["printenv", "set -x", "GITHUB_CONTEXT", "toJSON", "/proc", "RSS", "PSS", "dmesg", "journalctl"]:
            self.assertNotIn(forbidden, delta)
        self.assertIsNone(re.search(r"(?:^|[\n;])\s*(?:env|export)\b", delta))


if __name__ == "__main__":
    unittest.main()
