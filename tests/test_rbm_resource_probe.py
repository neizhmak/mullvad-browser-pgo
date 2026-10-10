#!/usr/bin/env python3
"""Native fixture tests only: fake Git/RBM is NOT actual pinned authority proof."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/probe-rbm-resource-control.py"
SPEC = importlib.util.spec_from_file_location("rbm_resource_probe", HELPER)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)

# Fake sources/namespace values make the CLI testable without network or userns.
# They prove mechanics and fail-closed behavior, not source identity or real RBM.
FAKE_GIT = r"""
import json, os, sys
from pathlib import Path
cfg = json.loads(Path(os.environ["RESOURCE_FIXTURE_CONFIG"]).read_text())
args = sys.argv[1:]
position = args.index("-C")
cwd = Path(args[position + 1])
command = args[position + 2:]
is_rbm = cwd.name == "rbm"
key = "rbm" if is_rbm else "tbb"
with open(os.environ["RESOURCE_FIXTURE_CALLS"], "a") as out:
    out.write("git:" + command[0] + "\n")
if cfg.get("git_failure"):
    print(cfg.get("private_output", "private-native-error"), file=sys.stderr)
    raise SystemExit(2)
if command[:1] == ["rev-parse"]:
    query = command[1]
    if "--git-path" in command:
        print(cfg.get("graft_path", str(cwd / ".git/info/grafts")))
    elif query == "--show-toplevel":
        print(cfg.get("wrong_root", str(cwd)))
    elif query == "HEAD":
        print(cfg.get(key + "_head", "865f2c9842520958879665d5c9b820d9ed51761e" if is_rbm
                      else "7dd751cf1837d667908b339aebf82567ece55e20"))
    elif query.endswith("^{}"):
        print(cfg.get("peeled", "7dd751cf1837d667908b339aebf82567ece55e20"))
    else:
        print(cfg.get("tag_object", "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721"))
elif command[:1] == ["remote"]:
    print(cfg.get(key + "_origin", "https://gitlab.torproject.org/tpo/applications/"
                  + ("rbm.git" if is_rbm else "tor-browser-build.git")))
elif command[:1] == ["cat-file"]:
    print(cfg.get("tag_type", "tag"))
elif command[:1] == ["config"]:
    print(cfg.get("submodule_path", "rbm") if command[-1].endswith(".path")
          else cfg.get("submodule_url", "https://gitlab.torproject.org/tpo/applications/rbm.git"))
elif command[:1] == ["ls-tree"]:
    if "--name-only" in command:
        print(cfg.get("module_names", "lib/RBM.pm\nlib/RBM/DefaultConfig.pm\nlib/RBM/CaptureExec.pm"))
    else:
        print(cfg.get("gitlink", "160000 commit 865f2c9842520958879665d5c9b820d9ed51761e\trbm"))
elif command[:1] == ["ls-files"]:
    print(cfg.get("index_flags", "H rbm.conf"))
elif command[:1] == ["status"]:
    references = cwd / ".git" / "reference"
    changed = False
    for path in references.rglob("*"):
        if path.is_file():
            working = cwd / path.relative_to(references)
            if not working.is_file() or working.read_bytes() != path.read_bytes():
                changed = True
    if cfg.get("dirty") or changed:
        print(" M tracked-source")
elif command[:1] == ["show"]:
    relative = command[1].split(":", 1)[1]
    data = (cwd / ".git/reference" / relative).read_bytes()
    if cfg.get("wrong_blob") == relative:
        data += b"wrong"
    sys.stdout.buffer.write(data)
else:
    raise SystemExit(90)
"""
FAKE_CONTAINER = r"""
import json, os, sys, time
from pathlib import Path
cfg = json.loads(Path(os.environ["RESOURCE_FIXTURE_CONFIG"]).read_text())
if sys.argv[1:4] != ["run", "--disable-network", "--"]:
    raise SystemExit(91)
with open(os.environ["RESOURCE_FIXTURE_CALLS"], "a") as out:
    out.write("container\n")
if cfg.get("container_failure"):
    print(cfg.get("private_output", "private-native-error"), file=sys.stderr)
    raise SystemExit(23)
if cfg.get("container_flood"):
    print(cfg.get("private_output", "private") * 300000, flush=True)
    raise SystemExit(0)
if cfg.get("container_pause"):
    signal = __import__("signal")
    signal.pause()
if cfg.get("create_output"):
    Path(cfg["create_output"]).mkdir()
if cfg.get("drop_env"):
    os.environ.pop("RBM_NUM_PROCS", None)
if cfg.get("inject_omp"):
    os.environ["OMP_NUM_THREADS"] = "never-print-private"
args = sys.argv[4:]
assert args[1] == "-c"
namespace = os.readlink("/proc/self/ns/net") if cfg.get("same_netns") else "net:[0]"
prefix = "import os; original_readlink=os.readlink; os.readlink=lambda path: " + repr(namespace) + "\n"
if cfg.get("widen_affinity"):
    prefix += "os.sched_setaffinity(0, " + repr(set(cfg["parent_cpus"])) + ")\n"
args[2] = prefix + args[2]
os.execv(args[0], args)
"""
FAKE_RBM = r"""
import json, os, sys
from pathlib import Path
cfg = json.loads(Path(os.environ["RESOURCE_FIXTURE_CONFIG"]).read_text())
if sys.argv[1:] != ["showconf", "firefox", "num_procs", "--target", "alpha",
                    "--target", "mullvadbrowser-windows-x86_64"]:
    raise SystemExit(92)
with open(os.environ["RESOURCE_FIXTURE_CALLS"], "a") as out:
    out.write("num_procs\n")
if cfg.get("mutate_source"):
    path = Path.cwd() / "rbm/lib/RBM.pm"
    path.write_bytes(path.read_bytes() + b"changed")
value = cfg.get("num_procs_override")
if value is None:
    value = os.environ.get("RBM_NUM_PROCS") or len(os.sched_getaffinity(0))
print(value)
"""
FAKE_NPROC = r"""
import json, os
from pathlib import Path
cfg = json.loads(Path(os.environ["RESOURCE_FIXTURE_CONFIG"]).read_text())
print(cfg.get("nproc_override", len(os.sched_getaffinity(0))))
"""


class ResourceProbeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rbm-resource-native-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream"
        self.output = self.base / "evidence"
        self.upstream.mkdir()
        (self.upstream / "rbm").mkdir()
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.config = self.base / "fixture.json"
        self.calls = self.base / "calls"
        self.settings = {"parent_cpus": sorted(os.sched_getaffinity(0))}
        self.config.write_text(json.dumps(self.settings))
        for rel, body in (("rbm.conf", b"# synthetic public source\n"),
                          ("rbm/lib/RBM.pm", b"# synthetic module\n"),
                          ("rbm/lib/RBM/DefaultConfig.pm", b"# synthetic default\n"),
                          ("rbm/lib/RBM/CaptureExec.pm", b"# synthetic capture\n")):
            path = self.upstream / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        self.install(self.bin / "git", FAKE_GIT)
        self.install(self.bin / "nproc", FAKE_NPROC)
        self.install(self.upstream / "rbm/rbm", FAKE_RBM)
        self.install(self.upstream / "rbm/container", FAKE_CONTAINER)
        for directory, files in ((self.upstream, ["rbm.conf"]),
                                 (self.upstream / "rbm", ["rbm", "container", "lib/RBM.pm",
                                  "lib/RBM/DefaultConfig.pm", "lib/RBM/CaptureExec.pm"])):
            for relative in files:
                destination = directory / ".git/reference" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((directory / relative).read_bytes())
        self.environment = dict(os.environ)
        for key in PROBE.INFLUENCERS:
            self.environment.pop(key, None)
        self.environment.update({"PATH": str(self.bin) + os.pathsep + self.environment.get("PATH", ""),
                                 "RESOURCE_FIXTURE_CONFIG": str(self.config),
                                 "RESOURCE_FIXTURE_CALLS": str(self.calls),
                                 "PYTHONDONTWRITEBYTECODE": "1"})
        self.before = os.sched_getaffinity(0)

    def tearDown(self):
        self.assertEqual(os.sched_getaffinity(0), self.before, "parent affinity changed")

    def install(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o755)

    def configure(self, **values):
        self.settings.update(values)
        self.config.write_text(json.dumps(self.settings))

    def execute(self):
        return PROBE.probe(self.upstream, self.output, environment=self.environment)

    def call_lines(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def rejected(self, expected):
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error"]["code"], expected)
        self.assertFalse(report["cache_identity_verified"])
        self.assertNotIn("container", self.call_lines())
        return report

    def require_two(self):
        if len(self.before) < 2:
            self.skipTest("fixture needs two currently allowed CPUs")

    def test_full_native_fixture_uses_only_num_procs_and_defers_identity(self):
        self.require_two()
        report = self.execute()
        self.assertEqual(report["status"], "source-controller-verified-only", report)
        self.assertTrue(report["source_verified"])
        self.assertTrue(report["controller_verified"])
        self.assertTrue(report["post_runtime_guard_verified"])
        self.assertFalse(report["cache_identity_verified"])
        self.assertFalse(report["production_policy_changed"])
        self.assertFalse(report["scope"]["chroot"])
        self.assertFalse(report["scope"]["full_mozconfig_rendered"])
        self.assertFalse(report["scope"]["filename_identity_rendered"])
        self.assertFalse(report["scope"]["compiler_or_browser_build"])
        self.assertEqual([row["case"] for row in report["cases"]], list(PROBE.CASES))
        self.assertEqual(self.call_lines().count("container"), 8)
        self.assertEqual(self.call_lines().count("num_procs"), 4)
        for row, affinity in zip(report["cases"], [sorted(self.before), sorted(self.before),
                                                   sorted(self.before)[:2], sorted(self.before)[:1]]):
            self.assertEqual(row["expected_affinity"], affinity)
            self.assertTrue(row["verified"])
            self.assertIn("no-chroot", row["query_location"])
        self.assertTrue(report["parent_affinity_unchanged"])
        self.assertEqual(json.loads((self.output / "probe.json").read_text()), report)

    def test_cli_fixture_success_is_not_actual_pinned_proof(self):
        self.require_two()
        result = subprocess.run([sys.executable, str(HELPER), "--upstream", str(self.upstream),
                                 "--output-directory", str(self.output)], env=self.environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"cache identity and PGO remain deferred", result.stdout)
        self.assertFalse(json.loads((self.output / "probe.json").read_text())["cache_identity_verified"])

    def test_current_allowed_nonzero_cpu_members_used(self):
        self.require_two()
        report = self.execute()
        self.assertEqual(report["cases"][2]["expected_affinity"], sorted(self.before)[:2])
        self.assertEqual(report["cases"][3]["expected_affinity"], sorted(self.before)[:1])

    def test_source_copy_bytes_hashes_and_all_tracked_modules(self):
        self.configure(container_failure=True)
        report = self.execute()
        self.assertTrue(report["source_verified"])
        self.assertEqual(len(report["sources"]), 6)
        for row in report["sources"]:
            copied = (self.output / row["artifact"]).read_bytes()
            self.assertEqual(copied, (self.upstream / row["source"]).read_bytes())
            self.assertEqual(PROBE.hashlib.sha256(copied).hexdigest(), row["sha256"])
            self.assertEqual(len(copied), row["size"])

    def test_wrong_tbb_head(self):
        self.configure(tbb_head="0" * 40)
        self.rejected("wrong_source_commit")

    def test_wrong_rbm_head_old_c884_is_rejected(self):
        self.configure(rbm_head="c88489ddb9c3749fe8bdfd0442a19a3bef346727")
        self.rejected("wrong_source_commit")

    def test_wrong_tbb_origin_never_prints_origin(self):
        self.configure(tbb_origin="https://private-token@example.invalid/repo")
        report = self.rejected("noncanonical_origin")
        self.assertNotIn("private-token", json.dumps(report))

    def test_wrong_rbm_origin(self):
        self.configure(rbm_origin="https://github.com/boklm/rbm.git")
        self.rejected("noncanonical_origin")

    def test_wrong_git_toplevel(self):
        self.configure(wrong_root="/private/not-the-requested-root")
        self.rejected("wrong_git_root")

    def test_wrong_gitlink(self):
        self.configure(gitlink="160000 commit " + "0" * 40 + "\trbm")
        self.rejected("wrong_rbm_gitlink")

    def test_gitlink_wrong_mode(self):
        self.configure(gitlink="100644 blob " + PROBE.RBM_COMMIT + "\trbm")
        self.rejected("wrong_rbm_gitlink")

    def test_tag_object_mismatch(self):
        self.configure(tag_object="0" * 40)
        self.rejected("source_pin_mismatch")

    def test_tag_peeled_mismatch(self):
        self.configure(peeled="0" * 40)
        self.rejected("source_pin_mismatch")

    def test_tag_not_annotated(self):
        self.configure(tag_type="commit")
        self.rejected("source_pin_mismatch")

    def test_submodule_path_mismatch(self):
        self.configure(submodule_path="other")
        self.rejected("source_pin_mismatch")

    def test_submodule_url_mismatch(self):
        self.configure(submodule_url="https://mirror.invalid/rbm.git")
        self.rejected("source_pin_mismatch")

    def test_native_git_failure_does_not_leak_stderr(self):
        self.configure(git_failure=True, private_output="VERY-PRIVATE-GIT-ERROR")
        report = self.rejected("native_nonzero")
        self.assertNotIn("VERY-PRIVATE", json.dumps(report))

    def test_dirty_source_prevents_runtime(self):
        self.configure(dirty=True)
        self.rejected("dirty_source_tree")

    def test_assume_unchanged_or_skip_worktree_index_rejected(self):
        for flag in ("h rbm.conf", "S rbm.conf"):
            with self.subTest(flag=flag):
                self.configure(index_flags=flag)
                output = self.base / ("case-" + flag[0])
                report = PROBE.probe(self.upstream, output, environment=self.environment)
                self.assertEqual(report["error"]["code"], "hidden_worktree_changes")
        self.assertNotIn("container", self.call_lines())

    def test_tbb_graft_state_rejected_without_content_dump(self):
        path = self.upstream / ".git/info/grafts"
        path.parent.mkdir(parents=True)
        path.write_text("private-graft-content")
        report = self.rejected("unsupported_git_grafts")
        self.assertNotIn("private-graft-content", json.dumps(report))

    def test_rbm_graft_state_rejected(self):
        path = self.upstream / "rbm/.git/info/grafts"
        path.parent.mkdir(parents=True)
        path.write_text("private-graft-content")
        self.rejected("unsupported_git_grafts")

    def test_graft_environment_override_rejected_without_value_dump(self):
        self.environment["GIT_GRAFT_FILE"] = "/private/graft-pointer"
        report = self.rejected("uncontrolled_git_graft_environment")
        self.assertNotIn("/private/graft-pointer", json.dumps(report))

    def test_relative_graft_metadata_path_rejected(self):
        self.configure(graft_path="info/grafts")
        self.rejected("invalid_git_graft_path")

    def test_graft_parent_symlink_is_rejected(self):
        target = self.base / "metadata-info"
        target.mkdir()
        (self.upstream / ".git/info").symlink_to(target, target_is_directory=True)
        self.rejected("unsafe_git_graft_path")

    def test_existing_source_clone_rejected(self):
        (self.upstream / "git_clones").mkdir()
        self.rejected("source_clone_or_output_present")

    def test_existing_hg_clone_rejected(self):
        (self.upstream / "hg_clones").mkdir()
        self.rejected("source_clone_or_output_present")

    def test_existing_out_rejected(self):
        (self.upstream / "out").mkdir()
        self.rejected("source_clone_or_output_present")

    def test_existing_logs_rejected(self):
        (self.upstream / "logs").mkdir()
        self.rejected("source_clone_or_output_present")

    def test_broken_clone_symlink_rejected(self):
        (self.upstream / "git_clones").symlink_to(self.base / "missing")
        self.rejected("source_clone_or_output_present")

    def test_local_rbm_config_rejected(self):
        (self.upstream / "rbm.local.conf").write_text("private override")
        self.rejected("uncontrolled_rbm_config")

    def test_blob_mismatch_still_preserves_earlier_verified_source(self):
        self.configure(wrong_blob="lib/RBM.pm")
        report = self.rejected("working_source_differs_from_commit")
        self.assertFalse(report["source_verified"])
        self.assertTrue(report["sources"])
        self.assertTrue((self.output / "sources/rbm.conf").exists())

    def test_missing_required_module_rejected(self):
        self.configure(module_names="lib/RBM.pm")
        self.rejected("unsupported_rbm_module_layout")

    def test_module_parent_traversal_rejected(self):
        self.configure(module_names="lib/RBM.pm\nlib/RBM/DefaultConfig.pm\nlib/../evil.pm")
        self.rejected("unsupported_rbm_module_layout")

    def test_too_many_modules_rejected(self):
        self.configure(module_names="\n".join(["lib/RBM.pm", "lib/RBM/DefaultConfig.pm"]
                       + [f"lib/Extra{i}.pm" for i in range(40)]))
        self.rejected("unsupported_rbm_module_layout")

    def test_tracked_source_symlink_rejected(self):
        path = self.upstream / "rbm.conf"
        data = path.read_bytes()
        path.unlink()
        target = self.base / "target"
        target.write_bytes(data)
        path.symlink_to(target)
        self.rejected("symlink_path")

    def test_source_hardlink_rejected(self):
        os.link(self.upstream / "rbm.conf", self.base / "linked")
        self.rejected("unsafe_source_file")

    def test_source_empty_rejected(self):
        (self.upstream / "rbm.conf").write_bytes(b"")
        # The dirty tracked source fails even before the empty-source check.
        self.rejected("dirty_source_tree")

    def test_rbm_cpu_env_presence_only_rejected(self):
        self.environment["RBM_NUM_PROCS"] = "PRIVATE-NOT-PRINTED"
        report = self.rejected("uncontrolled_cpu_environment")
        self.assertTrue(report["parent"]["influencer_presence"]["RBM_NUM_PROCS"])
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertTrue(report["source_verified"])

    def test_empty_rbm_cpu_override_also_rejected(self):
        self.environment["RBM_NUM_PROCS"] = ""
        self.rejected("uncontrolled_cpu_environment")

    def test_omp_num_threads_presence_only_rejected(self):
        self.environment["OMP_NUM_THREADS"] = "PRIVATE-NOT-PRINTED"
        self.rejected("uncontrolled_cpu_environment")

    def test_omp_thread_limit_presence_only_rejected(self):
        self.environment["OMP_THREAD_LIMIT"] = "PRIVATE-NOT-PRINTED"
        self.rejected("uncontrolled_cpu_environment")

    def test_env2_lost_in_namespace_is_not_outer_unsupported_claim(self):
        self.require_two()
        self.configure(drop_env=True)
        report = self.execute()
        self.assertEqual(report["error"]["code"], "namespace_cpu_environment_not_preserved")
        row = report["cases"][-1]
        self.assertEqual(row["case"], "controller-env-two")
        self.assertFalse(row["measurements"]["num_procs"]["influencer_presence"]["RBM_NUM_PROCS"])
        self.assertNotIn("unsupported", json.dumps(report))
        self.assertTrue(report["source_verified"])

    def test_namespace_injecting_omp_is_fail_closed(self):
        self.configure(inject_omp=True, nproc_override=len(self.before))
        report = self.execute()
        self.assertEqual(report["error"]["code"], "namespace_cpu_environment_not_preserved")
        self.assertTrue(report["cases"][0]["measurements"]["nproc"]["influencer_presence"]["OMP_NUM_THREADS"])
        self.assertNotIn("never-print-private", json.dumps(report))

    def test_nproc_mismatch(self):
        self.configure(nproc_override=len(self.before) + 1)
        report = self.execute()
        self.assertEqual(report["error"]["code"], "namespace_nproc_affinity_mismatch")
        self.assertFalse(report["controller_verified"])

    def test_controller_mismatch(self):
        self.configure(num_procs_override=len(self.before) + 1)
        report = self.execute()
        self.assertEqual(report["error"]["code"], "namespace_controller_count_mismatch")

    def test_invalid_controller_output(self):
        self.configure(num_procs_override="PRIVATE-NONNUMERIC")
        report = self.execute()
        self.assertEqual(report["error"]["code"], "invalid_child_evidence")
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_namespace_not_isolated_is_rejected(self):
        self.configure(same_netns=True)
        report = self.execute()
        self.assertEqual(report["error"]["code"], "invalid_child_evidence")
        self.assertTrue(report["source_verified"])

    def test_affinity_widening_is_rejected(self):
        self.require_two()
        self.configure(widen_affinity=True)
        report = self.execute()
        self.assertEqual(report["error"]["code"], "invalid_child_evidence")
        self.assertFalse(report["controller_verified"])

    def test_output_side_effect_is_fail_closed(self):
        self.configure(create_output=str(self.upstream / "out"))
        report = self.execute()
        self.assertEqual(report["error"]["code"], "source_clone_or_output_present")
        self.assertFalse(report["post_runtime_guard_verified"])
        self.assertTrue(report["source_verified"])

    def test_source_mutation_is_fail_closed(self):
        self.configure(mutate_source=True)
        report = self.execute()
        self.assertEqual(report["error"]["code"], "dirty_source_tree")
        self.assertFalse(report["post_runtime_guard_verified"])

    def test_container_failure_preserves_source_and_no_private_output(self):
        self.configure(container_failure=True, private_output="PRIVATE-CREDENTIAL-OUTPUT")
        report = self.execute()
        self.assertEqual(report["error"]["code"], "native_nonzero")
        self.assertTrue(report["source_verified"])
        self.assertFalse(report["controller_verified"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_cli_failure_sanitizes_native_stderr(self):
        self.configure(container_failure=True, private_output="PRIVATE-CREDENTIAL-OUTPUT")
        result = subprocess.run([sys.executable, str(HELPER), "--upstream", str(self.upstream),
                                 "--output-directory", str(self.output)], env=self.environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"PRIVATE", result.stdout + result.stderr)
        self.assertFalse(json.loads((self.output / "probe.json").read_text())["cache_identity_verified"])

    def test_native_flood_has_bounded_report(self):
        self.configure(container_flood=True, private_output="SECRET")
        report = self.execute()
        self.assertEqual(report["error"]["code"], "native_output_limit")
        self.assertTrue(report["source_verified"])
        self.assertLess((self.output / "probe.json").stat().st_size, 64 * 1024)
        self.assertNotIn("SECRET", json.dumps(report))

    def test_runtime_deadline_preserves_partial_sources(self):
        self.configure(container_pause=True)
        with patch.object(PROBE, "CALL_SECONDS", 0.12):
            # Default arg is evaluated at definition; shorten this runner explicitly.
            original = PROBE.run_native
            def short(*args, **kwargs):
                kwargs["seconds"] = 0.12
                return original(*args, **kwargs)
            with patch.object(PROBE, "run_native", short):
                report = self.execute()
        self.assertEqual(report["error"]["code"], "native_deadline")
        self.assertTrue(report["source_verified"])
        self.assertTrue(report["sources"])

    def test_missing_nproc_is_fail_closed(self):
        with patch.object(PROBE.shutil, "which", return_value=None):
            self.rejected("missing_nproc")

    def test_one_allowed_cpu_is_not_promoted_to_two(self):
        first = sorted(self.before)[:1]
        with patch.object(PROBE.os, "sched_getaffinity", return_value=set(first)):
            self.rejected("insufficient_allowed_cpus")

    def test_unsupported_platform_is_fail_closed(self):
        with patch.object(PROBE, "hasattr", return_value=False, create=True):
            self.rejected("unsupported_platform")

    def test_bad_lock_never_starts_probe(self):
        with patch.object(PROBE, "load_lock", side_effect=PROBE.ProbeError("unsupported_project_lock")):
            self.rejected("unsupported_project_lock")
        self.assertEqual(self.call_lines(), [])

    def test_output_overlap_never_starts_child(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "overlapping_output"):
            PROBE.probe(self.upstream, self.upstream / "evidence", environment=self.environment)
        self.assertEqual(self.call_lines(), [])

    def test_nonempty_output_rejected(self):
        self.output.mkdir()
        (self.output / "untrusted").write_text("untrusted")
        with self.assertRaisesRegex(PROBE.ProbeError, "unsafe_output_directory"):
            self.execute()
        self.assertEqual(self.call_lines(), [])

    def test_output_symlink_rejected(self):
        target = self.base / "target"
        target.mkdir()
        self.output.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(PROBE.ProbeError, "symlink_path"):
            self.execute()

    def test_upstream_symlink_rejected(self):
        linked = self.base / "linked-upstream"
        linked.symlink_to(self.upstream, target_is_directory=True)
        with self.assertRaisesRegex(PROBE.ProbeError, "symlink_path"):
            PROBE.probe(linked, self.output, environment=self.environment)

    def test_report_is_atomic_and_has_no_temporary_files(self):
        self.configure(container_failure=True)
        self.execute()
        self.assertEqual(list(self.output.glob(".probe-*")), [])
        self.assertEqual(stat.S_IMODE((self.output / "probe.json").stat().st_mode), 0o600)

    def test_secret_environment_never_enters_public_evidence(self):
        self.configure(container_failure=True)
        self.environment["GH_TOKEN"] = "secret-private-token-9123"
        self.environment["ARBITRARY_SECRET"] = "secret-private-other-3219"
        report = self.execute()
        self.assertNotIn("secret-private", json.dumps(report))
        for path in self.output.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"secret-private", path.read_bytes())


class ResourceRunnerAndParsingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rbm-resource-runner-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    def native(self, source, seconds=1):
        return PROBE.run_native([sys.executable, "-c", source], cwd=self.base,
                                environment=self.environment,
                                deadline=PROBE.Deadline(2), seconds=seconds)

    def test_success_and_native_status_preserved(self):
        code, output, error = self.native("import sys; print('7'); print('private', file=sys.stderr); sys.exit(23)")
        self.assertEqual((code, output, error), (23, b"7\n", b"private\n"))

    def test_timed_child_ignoring_term_is_killed(self):
        start = time.monotonic()
        with self.assertRaisesRegex(PROBE.ProbeError, "native_deadline"):
            self.native("import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.pause()", 0.12)
        self.assertLess(time.monotonic() - start, 2)

    def assert_dead(self, pid):
        # SIGKILL delivery is asynchronous. pidfd waits for the kernel exit event,
        # not a sleep or an assumption that one immediate /proc read is a zombie.
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            ready, _, _ = select.select([descriptor], [], [], 1)
            self.assertTrue(ready, "owned native descendant survived cleanup")
        finally:
            os.close(descriptor)

    def test_inherited_pipe_orphan_is_killed_with_owned_group(self):
        pidfile = self.base / "pid"
        source = ("import subprocess, sys; p=subprocess.Popen([sys.executable,'-c',"
                  "'import signal; signal.pause()']); "
                  f"open({str(pidfile)!r},'w').write(str(p.pid)); print('done',flush=True)")
        with self.assertRaisesRegex(PROBE.ProbeError, "native_deadline"):
            self.native(source, 0.15)
        pid = int(pidfile.read_text())
        self.assert_dead(pid)

    def test_completed_child_detached_stdio_orphan_is_killed(self):
        pidfile = self.base / "pid"
        source = ("import subprocess, sys; p=subprocess.Popen([sys.executable,'-c',"
                  "'import signal; signal.pause()'],stdin=subprocess.DEVNULL,"
                  "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                  f"open({str(pidfile)!r},'w').write(str(p.pid)); print('done',flush=True)")
        code, _, _ = self.native(source)
        self.assertEqual(code, 0)
        pid = int(pidfile.read_text())
        self.assert_dead(pid)

    def test_stdout_and_stderr_share_output_cap(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "native_output_limit"):
            self.native("import os; os.write(1,b'A'*140000); os.write(2,b'B'*140000)")

    def test_missing_native_tool_is_fixed_error(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "native_start_failed"):
            PROBE.run_native([str(self.base / "missing")], cwd=self.base,
                             environment=self.environment, deadline=PROBE.Deadline(1))

    def test_expired_global_deadline_starts_no_child(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "global_deadline"):
            PROBE.run_native([sys.executable, "-c", "raise SystemExit(0)"], cwd=self.base,
                             environment=self.environment, deadline=PROBE.Deadline(-1))

    def test_global_deadline_bounds_longer_per_call_limit(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "native_deadline"):
            PROBE.run_native([sys.executable, "-c", "import signal; signal.pause()"],
                             cwd=self.base, environment=self.environment,
                             deadline=PROBE.Deadline(0.12), seconds=5)

    def payload(self, **changes):
        data = {"affinity": [8, 11], "logical_cpu_count": 4,
                "network_namespace": "net:[2]", "influencer_presence":
                {key: False for key in PROBE.INFLUENCERS}}
        data.update(changes)
        return ("RBM_RESOURCE_CHILD " + json.dumps(data) + "\n2\n").encode()

    def test_valid_child_presence_and_count(self):
        data, count = PROBE.parse_child(self.payload(), "net:[1]", [8, 11], False)
        self.assertEqual(count, 2)
        self.assertEqual(data["affinity"], [8, 11])

    def test_expanded_child_affinity_rejected(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "invalid_child_evidence"):
            PROBE.parse_child(self.payload(affinity=[8, 11, 12]), "net:[1]", [8, 11], False)

    def test_duplicate_child_affinity_rejected(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(affinity=[8, 8]), "net:[1]", [8, 11], False)

    def test_boolean_not_cpu_id(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(affinity=[True, 11]), "net:[1]", [8, 11], False)

    def test_boolean_not_cpu_count(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(logical_cpu_count=True), "net:[1]", [8, 11], False)

    def test_presence_cannot_be_integer(self):
        presence = {key: 0 for key in PROBE.INFLUENCERS}
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(influencer_presence=presence), "net:[1]", [8, 11], False)

    def test_presence_must_have_exact_keys(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(influencer_presence={}), "net:[1]", [8, 11], False)

    def test_bad_network_namespace_rejected(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(network_namespace="private"), "net:[1]", [8, 11], False)

    def test_parent_network_namespace_rejected(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(network_namespace="net:[1]"), "net:[1]", [8, 11], False)

    def test_extra_child_fields_rejected(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload(private="never-accept"), "net:[1]", [8, 11], False)

    def test_ambiguous_number_output_rejected(self):
        output = self.payload()[:-2] + b"02\n"
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(output, "net:[1]", [8, 11], False)

    def test_extra_output_line_rejected(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(self.payload() + b"private\n", "net:[1]", [8, 11], False)

    def test_non_ascii_output_rejected(self):
        with self.assertRaises(PROBE.ProbeError):
            PROBE.parse_child(b"\xff\n", "net:[1]", [8, 11], False)

    def test_cancel_is_fixed_failure(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "probe_cancelled"):
            PROBE.cancelled(signal.SIGTERM, None)

    def test_oversized_report_rejected(self):
        with self.assertRaisesRegex(PROBE.ProbeError, "report_limit"):
            PROBE.write_report(self.base, {"bad": "x" * 70000})

    def test_output_invalid_owner_rejected(self):
        with patch.object(PROBE.os, "getuid", return_value=-1):
            with self.assertRaisesRegex(PROBE.ProbeError, "unsafe_output_directory"):
                PROBE.prepare_output(self.base, self.base.parent / (self.base.name + "-owner"))
        other = self.base.parent / (self.base.name + "-owner")
        if other.exists():
            other.rmdir()


class ResourceNativeGitAuthorityTests(unittest.TestCase):
    """Real Git objects exercise authority mechanics, not the unavailable865 pin."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rbm-resource-real-git-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repository = self.base / "repository"
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("GIT_")}
        self.environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                                 "PYTHONDONTWRITEBYTECODE": "1"})
        self.git("init", "--quiet", str(self.repository), outside=True)
        self.source = self.repository / "source.txt"
        self.source.write_bytes(b"original tracked tree\n")
        self.git("add", "source.txt")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "original")
        self.original = self.git("rev-parse", "HEAD").decode().strip()
        self.source.write_bytes(b"replacement tracked tree\n")
        self.git("add", "source.txt")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "-m", "replacement")
        self.replacement = self.git("rev-parse", "HEAD").decode().strip()
        self.git("reset", "--hard", "--quiet", self.original)

    def git(self, *arguments, outside=False):
        result = subprocess.run(["git", "--no-pager", "-c", "core.hooksPath=/dev/null",
                                 *arguments], cwd=self.base if outside else self.repository,
                                env=self.environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_native_replacement_keeps_head_id_but_helper_reads_original_tree(self):
        self.git("replace", self.original, self.replacement)
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), self.original)
        self.assertEqual(self.git("show", "HEAD:source.txt"), b"replacement tracked tree\n")
        self.assertEqual(PROBE.git_bytes(self.repository, ["show", "HEAD:source.txt"],
                                        self.environment, PROBE.Deadline(5)),
                         b"original tracked tree\n")
        # No replacement refs are deleted or user configuration rewritten.
        self.assertIn(self.original.encode(), self.git("replace", "--list"))

    def test_native_custom_replace_ref_base_cannot_change_helper_source(self):
        self.environment["GIT_REPLACE_REF_BASE"] = "refs/fixture-replacements/"
        self.git("replace", self.original, self.replacement)
        self.assertEqual(self.git("show", "HEAD:source.txt"), b"replacement tracked tree\n")
        self.assertEqual(PROBE.git_bytes(self.repository, ["show", "HEAD:source.txt"],
                                        self.environment, PROBE.Deadline(5)),
                         b"original tracked tree\n")

    def test_every_git_bytes_call_has_native_no_replace_objects_flag(self):
        with patch.object(PROBE, "checked", return_value=b"original") as call:
            PROBE.git_bytes(self.repository, ["show", "HEAD:source.txt"],
                            self.environment, PROBE.Deadline(5))
        self.assertEqual(call.call_args.args[0][:3], ["git", "--no-replace-objects", "--no-pager"])

    def test_native_git_path_graft_guard_preserves_existing_state(self):
        PROBE.reject_grafts(self.repository, self.environment, PROBE.Deadline(5))
        raw = self.git("rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
        path = Path(raw.decode().strip())
        path.parent.mkdir(exist_ok=True)
        content = self.original + "\n"
        path.write_text(content)
        with self.assertRaisesRegex(PROBE.ProbeError, "unsupported_git_grafts"):
            PROBE.reject_grafts(self.repository, self.environment, PROBE.Deadline(5))
        self.assertEqual(path.read_text(), content)

    def test_native_gitfile_metadata_path_is_used_for_graft_guard(self):
        # A separate Git directory models real submodule gitfile indirection.
        gitdir = self.base / "separate-git"
        separate = self.base / "gitfile-worktree"
        self.git("init", "--quiet", "--separate-git-dir", str(gitdir), str(separate), outside=True)
        self.assertTrue((separate / ".git").is_file())
        PROBE.reject_grafts(separate, self.environment, PROBE.Deadline(5))
        graft = gitdir / "info/grafts"
        graft.parent.mkdir(exist_ok=True)
        graft.write_text("private-native-graft-state")
        with self.assertRaisesRegex(PROBE.ProbeError, "unsupported_git_grafts"):
            PROBE.reject_grafts(separate, self.environment, PROBE.Deadline(5))
        self.assertEqual(graft.read_text(), "private-native-graft-state")


if __name__ == "__main__":
    unittest.main()
