#!/usr/bin/env python3
"""Cheap orchestration guards; native helper behavior is tested separately."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
GEN = (ROOT / ".github/workflows/pgo-stage4a.yml").read_text()
USE = (ROOT / ".github/workflows/windows-pgo.yml").read_text()
RUST = (ROOT / ".github/workflows/pgo-toolchain.yml").read_text()
UNIT = (ROOT / ".github/workflows/tests.yml").read_text()
SUPPORT_PATH = ROOT / ".github/workflows/pgo-support.yml"
SUPPORT = SUPPORT_PATH.read_text()


def job(text, name):
    marker = "  " + name + ":\n"
    start = text.index(marker) + len(marker)
    end = re.search(r"(?m)^  [a-z][a-z0-9-]*:\s*$", text[start:])
    return text[start:start + end.start()] if end else text[start:]


class WindowsPGOWorkflowTests(unittest.TestCase):
    def test_all_execution_jobs_use_standard_hosted_runners_and_six_hour_limit(self):
        for text in (GEN, USE, RUST, SUPPORT, UNIT):
            runners = re.findall(r"(?m)^    runs-on: (.+)$", text)
            self.assertTrue(runners)
            self.assertTrue(set(runners) <= {"ubuntu-24.04", "windows-2025"})
            limits = [int(value) for value in re.findall(r"timeout-minutes: ([0-9]+)", text)]
            self.assertTrue(limits)
            self.assertTrue(all(0 < value <= 360 for value in limits))
            self.assertNotIn("self-hosted", text)
            self.assertNotIn("MOZ_PGO_RUST=0", text)

    def test_dispatch_finishes_pipeline_but_toolchain_only_can_stop_early(self):
        dispatch = GEN.split("  workflow_call:", 1)[0]
        self.assertIn("finish_pipeline:", dispatch)
        self.assertRegex(dispatch, r"finish_pipeline:[\s\S]*?default: true")
        self.assertIn("!inputs.toolchain_only", job(GEN, "pgo-generate"))
        finish = job(GEN, "pgo-finish")
        self.assertIn("needs: pgo-merge", finish)
        self.assertIn("inputs.finish_pipeline && !inputs.toolchain_only", finish)
        self.assertIn("uses: ./.github/workflows/windows-pgo.yml", finish)
        self.assertIn("needs.pgo-merge.outputs.release", finish)
        self.assertIn("needs.pgo-merge.outputs.identity", finish)
        self.assertIn("actions: read", GEN)
        self.assertIn("contents: read", USE)

    def test_final_runners_recompute_provenance_before_profile_restore(self):
        for name in ("pgo-firefox", "pgo-package"):
            contents = job(USE, name)
            commands = ["./scripts/fetch-upstream.sh", "./scripts/prepare-pgo-generate.sh",
                        "./scripts/resolve-pgo-rust-identity.py", "--stage rust-pgo",
                        "./scripts/preflight-pgo-rust.sh", "./scripts/resolve-pgo-provenance.sh",
                        "./scripts/capture-pgo-toolchains.py", "./scripts/profile-artifacts.py restore",
                        "./scripts/prepare-pgo-use.sh", "./scripts/run-pgo-use.sh"]
            positions = [contents.index(value) for value in commands]
            self.assertEqual(positions, sorted(positions))
            self.assertIn('--expected-provenance "$PGO_EXPECTED_PROVENANCE"', contents)
            self.assertIn('--expected-identity "$PGO_PROFILE_IDENTITY"', contents)
            self.assertIn('--identity-file "$RUNNER_TEMP/pgo-rust-identity.json"', contents)

    def test_optimized_firefox_and_packaging_are_separate_verified_handoffs(self):
        firefox = job(USE, "pgo-firefox")
        package = job(USE, "pgo-package")
        self.assertIn("--stage firefox", firefox)
        self.assertNotIn("--stage browser", firefox)
        self.assertIn("needs: pgo-firefox", package)
        self.assertIn("--stage browser", package)
        self.assertNotIn("--stage firefox", package)
        self.assertIn("PGO_FIREFOX_ARTIFACT_DIR:", package)
        self.assertIn("name: pgo-optimized-firefox", firefox)
        self.assertIn("name: pgo-optimized-firefox", package)
        self.assertIn("firefox-output.tar", firefox)
        self.assertIn("firefox-output.json", firefox)
        self.assertIn("name: mullvad-browser-alpha-windows-x86_64-pgo", package)
        self.assertNotIn("gh release create", USE)
        self.assertNotIn("gh release upload", USE)

    def test_native_baseline_is_required_before_default_package_checks(self):
        native = job(USE, "pgo-windows-check")
        self.assertIn("needs: pgo-package", native)
        self.assertIn("runs-on: windows-2025", native)
        self.assertLess(native.index("prepare-baseline"), native.index("check-windows-packages.ps1"))
        self.assertIn("GH_TOKEN: ${{ github.token }}", native)
        self.assertNotIn("AllowNoBaselineExperiment", native)
        self.assertNotIn("allow-no-baseline-experiment", native)
        self.assertIn("name: pgo-windows-runtime-report", native)
        self.assertIn("if: always()", native)
        self.assertIn("actions: read", USE)

    def test_rust_publication_depends_on_native_profile_emission(self):
        native = job(RUST, "rust-native-check")
        publish = job(RUST, "rust-publish")
        self.assertIn("LLVM_PROFILE_FILE", native)
        self.assertIn("Length -gt 0", native)
        self.assertIn("needs: [rust-build, rust-native-check]", publish)
        self.assertIn("--stage rust-pgo --project rust", publish)
        cache = job(RUST, "rust-build")
        self.assertIn('test "$status" -eq 1', cache)

    def test_generation_waits_for_independent_rust_and_node_checkpoints(self):
        support = job(GEN, "pgo-support")
        generation = job(GEN, "pgo-generate")
        self.assertIn("!inputs.toolchain_only", support)
        self.assertIn("uses: ./.github/workflows/pgo-support.yml", support)
        self.assertIn("needs: [pgo-rust, pgo-support]", generation)
        self.assertIn("needs.pgo-support.outputs.release", generation)
        self.assertIn("needs.pgo-support.outputs.identity_sha256", generation)
        self.assertIn('--expected-release "$PGO_SUPPORT_RELEASE"', generation)
        self.assertIn('--expected-identity "$PGO_SUPPORT_IDENTITY"', generation)
        self.assertLess(generation.index("./scripts/restore-pgo-support.py"),
                        generation.index("Build only instrumented Firefox"))

    def test_final_node_bytes_are_recomputed_before_profile_restore(self):
        for name in ("pgo-firefox", "pgo-package"):
            contents = job(USE, name)
            support = contents.index("./scripts/restore-pgo-support.py")
            self.assertLess(contents.index("./scripts/capture-pgo-toolchains.py"), support)
            self.assertLess(support, contents.index("./scripts/profile-artifacts.py restore"))
            self.assertIn('--pgo-target pgo-generate', contents)
            self.assertIn('--pgo-target pgo-use', contents)
            self.assertIn('--provenance "$PGO_EXPECTED_PROVENANCE"', contents)
            self.assertLess(contents.index("./scripts/prepare-pgo-use.sh"),
                            contents.index("--pgo-target pgo-use"))
            self.assertNotIn("rbm build node", contents)

    def test_observer_records_resources_before_separate_upload_steps(self):
        generate = (ROOT / "scripts/run-pgo-generate.sh").read_text()
        use = (ROOT / "scripts/run-pgo-use.sh").read_text()
        for contents in (generate, use):
            self.assertIn("observe-rbm-build.py", contents)
            self.assertIn("--resource-log", contents)
            self.assertIn("-- ./rbm/rbm build firefox", contents)
        self.assertIn("pgo-generate-resources.jsonl", GEN)
        self.assertIn("*resources.jsonl", USE)
        self.assertIn("if: always()", job(GEN, "pgo-generate"))

    def test_pgo_shell_metadata_uses_shared_bounded_transport_helper(self):
        for name in ("validate-pgo-overlay.sh", "preflight-pgo-rust.sh",
                     "run-pgo-generate.sh", "prepare-pgo-use.sh", "run-pgo-use.sh"):
            with self.subTest(script=name):
                contents = (ROOT / "scripts" / name).read_text()
                self.assertIn("rbm_network.py", contents)
                self.assertIn('--upstream "$PWD"', contents)
                self.assertIn("--project", contents)
                self.assertIn("--key", contents)
                self.assertNotRegex(contents, r"\./rbm/rbm\s+showconf\b")

    def test_transport_helper_does_not_wrap_actual_compiler_builds(self):
        generation = (ROOT / "scripts/run-pgo-generate.sh").read_text()
        optimized = (ROOT / "scripts/run-pgo-use.sh").read_text()
        for contents in (generation, optimized):
            self.assertIn('-- ./rbm/rbm build firefox', contents)
            self.assertNotRegex(contents, r"rbm_network\.py[^\n]*\./rbm/rbm\s+build\b")
        self.assertIn('./rbm/rbm build browser "${args[@]}"', optimized)
        self.assertIn('./rbm/rbm build rust', RUST)

    def test_native_windows_lightweight_checks_cover_entrypoints(self):
        native = job(UNIT, "windows-native")
        self.assertIn("runs-on: windows-2025", native)
        self.assertIn("Parser]::ParseFile", native)
        self.assertIn("python tests/test_windows_runtime.py -v", native)


if __name__ == "__main__":
    unittest.main()
