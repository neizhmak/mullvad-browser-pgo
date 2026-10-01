#!/usr/bin/env python3
"""Lightweight integration tests for resumable RBM Release publication."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/rbm-release-artifacts.py"
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, shutil, sys, time
from pathlib import Path
args = sys.argv[1:]
store = Path(os.environ["FAKE_GH_STORE"])
store.mkdir(parents=True, exist_ok=True)

def metadata(release_dir):
    path = release_dir / ".assets.json"
    return json.loads(path.read_text()) if path.exists() else {}

def save(release_dir, data):
    (release_dir / ".assets.json").write_text(json.dumps(data))

if args[0] == "api":
    asset_id = int(args[-1].rsplit("/", 1)[1])
    for release_dir in store.iterdir():
        if not release_dir.is_dir(): continue
        data = metadata(release_dir)
        for name, asset in list(data.items()):
            if asset["id"] == asset_id:
                (release_dir / name).unlink(missing_ok=True)
                del data[name]
                save(release_dir, data)
                sys.exit(0)
    sys.exit(1)

command, release = args[1], args[2]
with (store / "calls").open("a") as calls:
    calls.write(json.dumps(args) + "\n")
release_dir = store / release
if command == "view":
    if os.environ.get("FAKE_VIEW_ERROR"):
        print(os.environ["FAKE_VIEW_ERROR"], file=sys.stderr)
        sys.exit(4)
    if not release_dir.exists():
        print("release not found", file=sys.stderr)
        sys.exit(1)
    if "--json" in args:
        data = metadata(release_dir)
        print(json.dumps({"assets": [dict(value, name=name) for name, value in data.items()]}))
elif command == "create":
    release_dir.mkdir()
    save(release_dir, {})
    (store / "create-args").write_text(" ".join(args))
elif command == "upload":
    source = Path(args[-1])
    destination = release_dir / source.name
    data = metadata(release_dir)
    if source.name in data: sys.exit(2)
    attempt_file = store / ("attempts-" + source.name)
    attempts = int(attempt_file.read_text()) + 1 if attempt_file.exists() else 1
    attempt_file.write_text(str(attempts))
    failures = int(os.environ.get("FAKE_UPLOAD_FAILURES", "0"))
    if attempts <= failures:
        destination.write_bytes(b"")
        data[source.name] = {"id": 1000 + len(data), "state": "starter", "size": 0}
        save(release_dir, data)
        if os.environ.get("FAKE_UPLOAD_TIMEOUT") == "1": time.sleep(10)
        sys.exit(4)
    if source.name.startswith("rbm-"):
        if os.environ.get("FAKE_REQUIRE_HARDLINK") == "1" and source.stat().st_nlink < 2:
            sys.exit(8)
        if os.environ.get("FAKE_REQUIRE_COPY") == "1" and source.stat().st_nlink != 1:
            sys.exit(9)
    shutil.copyfile(source, destination)
    if os.environ.get("FAKE_CORRUPT_UPLOAD") == "1" and source.name.startswith("rbm-"):
        destination.write_bytes(b"x" * source.stat().st_size)
    data[source.name] = {"id": 1000 + len(data), "state": "uploaded", "size": source.stat().st_size}
    save(release_dir, data)
elif command == "download":
    pattern = args[args.index("--pattern") + 1]
    destination = Path(args[args.index("--dir") + 1])
    destination.mkdir(parents=True, exist_ok=True)
    data = metadata(release_dir)
    matches = [release_dir / name for name, asset in data.items()
               if name == pattern and asset["state"] == "uploaded"]
    if not matches: sys.exit(1)
    for source in matches:
        target = destination / source.name
        if target.exists(): sys.exit(2)
        shutil.copyfile(source, target)
else: sys.exit(3)
'''


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.upstream = self.base / "upstream"
        self.artifact = self.upstream / "out/clang/clang-test.tar.zst"
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(b"official rbm bytes")
        self.before = self.base / "before"
        self.before.write_text("")
        self.registry_dir = self.base / "registry"
        bindir = self.base / "bin"
        bindir.mkdir()
        (bindir / "gh").write_text(FAKE_GH)
        (bindir / "gh").chmod(0o755)
        self.store = self.base / "releases"
        self.env = os.environ | {"PATH": f"{bindir}:{os.environ['PATH']}",
                                 "FAKE_GH_STORE": str(self.store),
                                 "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567"}
        self.release = "rbm-dependencies-mb-test"

    def tearDown(self):
        self.temp.cleanup()

    @property
    def asset_name(self):
        commit = json.loads((ROOT / "upstream.lock.json").read_text())["commit"][:12]
        return f"rbm-{commit}--clang--{self.artifact.name}"

    def run_helper(self, command, *extra, wrapper=None):
        argv = [str(HELPER)] if wrapper is None else ["python3", "-c", wrapper]
        return subprocess.run(
            argv + [command, "--upstream", str(self.upstream),
                    "--repository", "owner/repo", "--release", self.release,
                    "--registry-dir", str(self.registry_dir), *extra],
            env=self.env, text=True, capture_output=True)

    def publish(self, *extra, wrapper=None):
        return self.run_helper("publish", "--before", str(self.before), "--stage", "clang",
                               *extra, wrapper=wrapper)

    def stage_complete(self, stage="clang", *extra):
        return self.run_helper("stage-complete", "--stage", stage, *extra)

    def restore(self):
        return self.run_helper("restore")

    def read_registry(self):
        return json.loads((self.store / self.release / "registry-clang.json").read_text())

    def write_registry(self, data):
        release = self.store / self.release
        registry = release / "registry-clang.json"
        registry.write_text(json.dumps(data) + "\n")
        metadata = json.loads((release / ".assets.json").read_text())
        metadata[registry.name]["size"] = registry.stat().st_size
        metadata[registry.name].pop("digest", None)
        (release / ".assets.json").write_text(json.dumps(metadata))

    def assert_no_temporary_payloads(self):
        self.assertFalse(list(self.registry_dir.glob("rbm-*")))
        self.assertFalse(list(self.registry_dir.glob(".uploads-*")))
        self.assertFalse(list(self.registry_dir.glob(".completion-*")))
        self.assertFalse(list(self.registry_dir.glob(".restore-*")))
        self.assertFalse(list(self.registry_dir.glob(".committed-*")))
        self.assertFalse(list((self.registry_dir / "published").glob("*")))

    def restore_required(self, *stages):
        command = [str(HELPER), "restore-required", "--upstream", str(self.upstream),
                   "--repository", "owner/repo", "--release", self.release,
                   "--registry-dir", str(self.registry_dir)]
        for stage in stages:
            command.extend(("--stage", stage))
        return subprocess.run(command, env=self.env, text=True, capture_output=True)

    def seed_asset(self, content, state="uploaded"):
        release = self.store / self.release
        release.mkdir(parents=True)
        (release / self.asset_name).write_bytes(content)
        (release / ".assets.json").write_text(json.dumps({
            self.asset_name: {"id": 42, "state": state, "size": len(content)}
        }))

    def test_complete_registry_marks_stage_complete(self):
        publish = self.publish()
        self.assertEqual(publish.returncode, 0, publish.stderr)
        result = self.stage_complete()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Stage clang is already complete; skipping RBM build.", result.stdout)

    def test_missing_registry_does_not_mark_stage_complete(self):
        self.seed_asset(self.artifact.read_bytes())
        result = self.stage_complete()
        self.assertEqual(result.returncode, 1)
        self.assertIn("registry-clang.json is missing or incomplete", result.stdout)

    def test_registry_with_incomplete_artifact_does_not_mark_stage_complete(self):
        publish = self.publish()
        self.assertEqual(publish.returncode, 0, publish.stderr)
        metadata = self.store / self.release / ".assets.json"
        assets = json.loads(metadata.read_text())
        assets[self.asset_name]["state"] = "starter"
        metadata.write_text(json.dumps(assets))
        result = self.stage_complete()
        self.assertEqual(result.returncode, 1)
        self.assertIn("is missing or incomplete", result.stdout)

    def test_existing_identical_asset_is_reused(self):
        self.seed_asset(self.artifact.read_bytes())
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Reusing identical published asset", result.stdout)
        self.assertTrue((self.store / self.release / "registry-clang.json").is_file())

    def test_existing_conflicting_asset_fails(self):
        self.seed_asset(b"conflict")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity mismatch", result.stderr)
        self.assertFalse((self.store / self.release / "registry-clang.json").exists())

    def test_incomplete_starter_asset_is_removed_and_retried(self):
        self.seed_asset(b"partial", state="starter")
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Removing interrupted Release asset", result.stdout)
        self.assertEqual((self.store / self.release / self.asset_name).read_bytes(),
                         self.artifact.read_bytes())

    def test_upload_timeout_is_retried_with_a_bound(self):
        self.env.update({"FAKE_UPLOAD_FAILURES": "9", "FAKE_UPLOAD_TIMEOUT": "1",
                         "RBM_UPLOAD_TIMEOUT_SECONDS": "1", "RBM_UPLOAD_ATTEMPTS": "2"})
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out after 1s", result.stderr)
        self.assertIn("upload failed after 2 attempts", result.stderr)
        attempts = self.store / f"attempts-{self.asset_name}"
        self.assertEqual(attempts.read_text(), "2")

    def test_partial_stage_resumes_and_publishes_registry(self):
        self.seed_asset(self.artifact.read_bytes())
        self.assertFalse((self.store / self.release / "registry-clang.json").exists())
        restore = self.restore()
        self.assertEqual(restore.returncode, 0, restore.stderr)
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        registry = json.loads((self.store / self.release / "registry-clang.json").read_text())
        self.assertEqual(registry["artifacts"][0]["sha256"],
                         hashlib.sha256(self.artifact.read_bytes()).hexdigest())

    def test_new_release_is_non_latest_prerelease(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        create_args = (self.store / "create-args").read_text()
        self.assertIn("--prerelease", create_args)
        self.assertIn("--latest=false", create_args)
        self.assertIn("--target 0123456789abcdef0123456789abcdef01234567", create_args)

    def test_two_gibibyte_asset_is_rejected_before_upload(self):
        with self.artifact.open("wb") as stream:
            stream.truncate(2 * 1024 * 1024 * 1024)
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be below 2 GiB", result.stderr)
        self.assertFalse((self.store / self.release).exists())

    def test_required_restore_fails_if_any_stage_is_absent(self):
        self.assertEqual(self.publish().returncode, 0)
        self.artifact.unlink()
        result = self.restore_required("clang", "mingw-w64-clang", "rust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required stage is incomplete: registry-mingw-w64-clang.json",
                      result.stderr)
        self.assertFalse(self.artifact.exists())

    def test_successful_required_restore_removes_temporary_downloads(self):
        self.assertEqual(self.publish().returncode, 0)
        original_clang_bytes = self.artifact.read_bytes()
        release = self.store / self.release
        registry = json.loads((release / "registry-clang.json").read_text())
        for stage in ("mingw-w64-clang", "rust"):
            stage_registry = dict(registry, stage=stage)
            content = f"official {stage} bytes".encode()
            asset_name = f"rbm-test--{stage}--{stage}.tar.zst"
            stage_registry["artifacts"] = [{
                "project": stage,
                "filename": f"{stage}.tar.zst",
                "path": f"out/{stage}/{stage}.tar.zst",
                "asset": asset_name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }]
            name = f"registry-{stage}.json"
            payload = (json.dumps(stage_registry) + "\n").encode()
            (release / name).write_bytes(payload)
            (release / asset_name).write_bytes(content)
            metadata = json.loads((release / ".assets.json").read_text())
            metadata[name] = {"id": 2000 + len(metadata), "state": "uploaded",
                              "size": len(payload)}
            metadata[asset_name] = {"id": 3000 + len(metadata), "state": "uploaded",
                                    "size": len(content)}
            (release / ".assets.json").write_text(json.dumps(metadata))
        self.artifact.unlink()
        result = self.restore_required("clang", "mingw-w64-clang", "rust")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.artifact.is_file())
        self.assertEqual(self.artifact.read_bytes(), original_clang_bytes)
        self.assertFalse((self.registry_dir / "required").exists())
        self.assertIn("Removed verified temporary downloads", result.stdout)

    def test_required_restore_verifies_every_stage_before_copying(self):
        self.assertEqual(self.publish().returncode, 0)
        release = self.store / self.release
        registry = json.loads((release / "registry-clang.json").read_text())
        for stage in ("mingw-w64-clang", "rust"):
            stage_registry = dict(registry, stage=stage)
            stage_registry["artifacts"] = []
            name = f"registry-{stage}.json"
            payload = (json.dumps(stage_registry) + "\n").encode()
            (release / name).write_bytes(payload)
            metadata = json.loads((release / ".assets.json").read_text())
            metadata[name] = {"id": 2000 + len(metadata), "state": "uploaded",
                              "size": len(payload)}
            (release / ".assets.json").write_text(json.dumps(metadata))
        self.artifact.unlink()
        result = self.restore_required("clang", "mingw-w64-clang", "rust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required stage has no artifacts", result.stderr)
        self.assertFalse(self.artifact.exists())


    def test_empty_or_missing_artifacts_never_mark_stage_complete(self):
        self.assertEqual(self.publish().returncode, 0)
        original = self.read_registry()
        for value in ([], None, "missing"):
            with self.subTest(artifacts=value):
                registry = dict(original)
                if value == "missing":
                    registry.pop("artifacts")
                else:
                    registry["artifacts"] = value
                self.write_registry(registry)
                result = self.stage_complete()
                self.assertEqual(result.returncode, 2)
                self.assertIn("stage has no artifacts", result.stderr)
                self.assert_no_temporary_payloads()

    def test_invalid_schema_never_marks_stage_complete(self):
        self.assertEqual(self.publish().returncode, 0)
        original = self.read_registry()
        for schema in (None, 0, 2, "1", True):
            with self.subTest(schema=schema):
                registry = dict(original)
                if schema is None:
                    registry.pop("schema")
                else:
                    registry["schema"] = schema
                self.write_registry(registry)
                result = self.stage_complete()
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid stage registry", result.stderr)

    def test_stage_completion_checks_bytes_with_or_without_github_digest(self):
        self.assertEqual(self.publish().returncode, 0)
        release = self.store / self.release
        (release / self.asset_name).write_bytes(b"x" * self.artifact.stat().st_size)
        metadata = release / ".assets.json"
        for github_digest in (None, "", "sha256:" + self.read_registry()["artifacts"][0]["sha256"]):
            with self.subTest(digest=github_digest):
                assets = json.loads(metadata.read_text())
                assets[self.asset_name]["digest"] = github_digest
                metadata.write_text(json.dumps(assets))
                result = self.stage_complete()
                self.assertEqual(result.returncode, 2)
                self.assertIn("published artifact identity mismatch", result.stderr)
                self.assert_no_temporary_payloads()

    def test_empty_publish_does_not_create_a_commit_marker(self):
        self.artifact.unlink()
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stage has no artifacts", result.stderr)
        self.assertFalse((self.store / self.release).exists())
        self.assertFalse((self.registry_dir / "registry-clang.json").exists())

    def test_restore_rejects_unsafe_or_invalid_records_before_writing(self):
        self.assertEqual(self.publish().returncode, 0)
        original = self.read_registry()
        self.artifact.unlink()
        invalid_fields = [
            ("path", "../escape"), ("path", "/out/clang/escape"),
            ("path", "out/clang/../../../escape"), ("path", "out//clang/escape"),
            ("path", "out/clang/./escape"), ("path", "out\\clang\\escape"),
            ("asset", "../escape"), ("asset", "payload*"),
            ("asset", "payload[1]"), ("asset", "payload\\escape"),
            ("asset", "registry-other.json"), ("filename", "different"),
            ("project", "rust"), ("size", -1), ("size", "17"),
            ("size", True), ("size", 2 * 1024 * 1024 * 1024),
            ("sha256", "a" * 63), ("sha256", "z" * 64), ("sha256", []),
        ]
        for field, value in invalid_fields:
            with self.subTest(field=field, value=value):
                registry = json.loads(json.dumps(original))
                registry["artifacts"][0][field] = value
                self.write_registry(registry)
                result = self.restore()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(self.artifact.exists())
                self.assertFalse((self.base / "escape").exists())
                self.assert_no_temporary_payloads()
        registry = json.loads(json.dumps(original))
        registry["artifacts"] = [None]
        self.write_registry(registry)
        result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid artifact record", result.stderr)

    def test_restore_rejects_duplicate_paths_and_duplicate_assets(self):
        self.assertEqual(self.publish().returncode, 0)
        original = self.read_registry()
        self.artifact.unlink()
        for change_path in (False, True):
            registry = json.loads(json.dumps(original))
            duplicate = dict(registry["artifacts"][0])
            if change_path:
                duplicate["path"] = "out/clang/other.tar.zst"
                duplicate["filename"] = "other.tar.zst"
            registry["artifacts"].append(duplicate)
            self.write_registry(registry)
            result = self.restore()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate artifact path or asset", result.stderr)
            self.assertFalse(self.artifact.exists())
            self.assertFalse((self.artifact.parent / "other.tar.zst").exists())

    def test_restore_rejects_cross_registry_conflicts_before_writing(self):
        self.assertEqual(self.publish().returncode, 0)
        release = self.store / self.release
        duplicate = dict(self.read_registry(), stage="rust")
        registry = release / "registry-rust.json"
        registry.write_text(json.dumps(duplicate))
        metadata = json.loads((release / ".assets.json").read_text())
        metadata[registry.name] = {"id": 4000, "state": "uploaded", "size": registry.stat().st_size}
        (release / ".assets.json").write_text(json.dumps(metadata))
        self.artifact.unlink()
        result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting required output path or asset", result.stderr)
        self.assertFalse(self.artifact.exists())

    def test_restore_rejects_output_symlinks(self):
        self.assertEqual(self.publish().returncode, 0)
        self.artifact.unlink()
        self.artifact.parent.rmdir()
        outside = self.base / "outside"
        outside.mkdir()
        marker = outside / self.artifact.name
        marker.write_bytes(b"outside bytes")
        self.artifact.parent.symlink_to(outside, target_is_directory=True)
        result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe symlink", result.stderr)
        self.assertEqual(marker.read_bytes(), b"outside bytes")

    def test_restore_refuses_to_overwrite_conflicting_existing_output(self):
        self.assertEqual(self.publish().returncode, 0)
        self.artifact.write_bytes(b"changed local bytes")
        result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting existing RBM output", result.stderr)
        self.assertEqual(self.artifact.read_bytes(), b"changed local bytes")
        self.assert_no_temporary_payloads()

    def test_restore_verifies_all_payloads_before_restoring_any(self):
        other = self.artifact.parent / "z-last.tar.zst"
        other.write_bytes(b"other output")
        self.assertEqual(self.publish().returncode, 0)
        registry = self.read_registry()
        last = registry["artifacts"][-1]
        (self.store / self.release / last["asset"]).write_bytes(b"x" * last["size"])
        self.artifact.unlink()
        other.unlink()
        result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("published artifact identity mismatch", result.stderr)
        self.assertFalse(self.artifact.exists())
        self.assertFalse(other.exists())
        self.assert_no_temporary_payloads()

    def test_restore_moves_verified_downloads_without_retained_payload_copies(self):
        original = self.artifact.read_bytes()
        self.assertEqual(self.publish().returncode, 0)
        self.artifact.unlink()
        result = self.restore()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.artifact.read_bytes(), original)
        self.assertTrue((self.registry_dir / "registry-clang.json").is_file())
        self.assert_no_temporary_payloads()

    def test_new_upload_is_verified_before_registry_is_published(self):
        self.env["FAKE_CORRUPT_UPLOAD"] = "1"
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("published artifact identity mismatch", result.stderr)
        self.assertFalse((self.store / self.release / "registry-clang.json").exists())
        self.assert_no_temporary_payloads()

    def test_publish_uses_hardlinks_and_cleans_them(self):
        self.env["FAKE_REQUIRE_HARDLINK"] = "1"
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.artifact.stat().st_nlink, 1)
        self.assert_no_temporary_payloads()
        calls = [json.loads(line) for line in (self.store / "calls").read_text().splitlines()]
        uploads = [Path(call[-1]).name for call in calls if call[1] == "upload"]
        self.assertEqual(uploads, [self.asset_name, "registry-clang.json"])

    def test_cross_filesystem_copy_fallback_is_cleaned(self):
        self.env["FAKE_REQUIRE_COPY"] = "1"
        wrapper = ("import errno, os, runpy; "
                   "os.link=lambda *a, **kw: (_ for _ in ()).throw(OSError(errno.EXDEV, 'cross-device')); "
                   f"runpy.run_path({str(HELPER)!r}, run_name='__main__')")
        result = self.publish(wrapper=wrapper)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_no_temporary_payloads()

    def test_byte_identical_published_rerun_is_a_verified_noop(self):
        self.assertEqual(self.publish().returncode, 0)
        release = self.store / self.release
        committed_bytes = (release / "registry-clang.json").read_bytes()
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Stage already published and fully restored", result.stdout)
        self.assertEqual((release / "registry-clang.json").read_bytes(), committed_bytes)
        calls = [json.loads(line) for line in (self.store / "calls").read_text().splitlines()]
        self.assertEqual(sum(call[1] == "upload" for call in calls), 2)
        self.assert_no_temporary_payloads()

    def test_published_rerun_verifies_committed_payload_bytes(self):
        self.assertEqual(self.publish().returncode, 0)
        release = self.store / self.release
        (release / self.asset_name).write_bytes(b"x" * self.artifact.stat().st_size)
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("published artifact identity mismatch", result.stderr)
        self.assert_no_temporary_payloads()

    def test_local_registry_does_not_hide_interrupted_publication(self):
        self.env["FAKE_UPLOAD_FAILURES"] = "9"
        failed = self.publish()
        self.assertNotEqual(failed.returncode, 0)
        self.assertTrue((self.registry_dir / "registry-clang.json").exists())
        self.assertFalse((self.store / self.release / "registry-clang.json").exists())
        self.env["FAKE_UPLOAD_FAILURES"] = "0"
        resumed = self.publish()
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(self.stage_complete().returncode, 0)
        self.assert_no_temporary_payloads()

    def test_old_schema_one_registry_without_identity_remains_usable(self):
        self.assertEqual(self.publish().returncode, 0)
        registry = self.read_registry()
        registry.pop("identity")
        self.write_registry(registry)
        original_registry_bytes = (self.store / self.release / "registry-clang.json").read_bytes()
        self.assertEqual(self.stage_complete().returncode, 0)
        self.artifact.unlink()
        restored = self.restore_required("clang")
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.before.write_text("out/clang/clang-test.tar.zst\n")
        rerun = self.publish()
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertEqual((self.store / self.release / "registry-clang.json").read_bytes(),
                         original_registry_bytes)

    def test_identity_and_project_scoped_pgo_registry_round_trip(self):
        rust = self.upstream / "out/rust/rust-profiler.tar.zst"
        rust.parent.mkdir()
        rust.write_bytes(b"PGO Rust sysroot")
        identity = {"upstream": json.loads((ROOT / "upstream.lock.json").read_text()),
                    "kind": "test-profiler-rust", "overlay_sha256": "a" * 64}
        identity_file = self.base / "identity.json"
        identity_file.write_text(json.dumps(identity))
        published = self.run_helper("publish", "--before", str(self.before),
                                    "--stage", "rust-pgo", "--project", "rust",
                                    "--identity-file", str(identity_file))
        self.assertEqual(published.returncode, 0, published.stderr)
        registry = json.loads((self.store / self.release / "registry-rust-pgo.json").read_text())
        self.assertEqual(registry["identity"], identity)
        self.assertEqual([artifact["project"] for artifact in registry["artifacts"]], ["rust"])
        self.assertFalse((self.store / self.release / self.asset_name).exists())
        verified = self.stage_complete("rust-pgo", "--identity-file", str(identity_file))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertNotEqual(self.stage_complete("rust-pgo").returncode, 0)
        rust.unlink()
        restored = self.run_helper("restore-required", "--stage", "rust-pgo",
                                   "--identity-file", str(identity_file))
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(rust.read_bytes(), b"PGO Rust sysroot")
        self.assert_no_temporary_payloads()


    def test_missing_release_is_incomplete_exit_one(self):
        result = self.stage_complete()
        self.assertEqual(result.returncode, 1)
        self.assertIn("dependency Release does not exist", result.stdout)

    def test_inspection_failure_is_not_treated_as_missing_release(self):
        self.env["FAKE_VIEW_ERROR"] = "authentication failed"
        result = self.stage_complete()
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot inspect dependency Release", result.stderr)
        self.assertNotIn("does not exist", result.stdout)
        published = self.publish()
        self.assertNotEqual(published.returncode, 0)
        self.assertFalse((self.store / self.release).exists())

    def test_wrong_provenance_is_integrity_exit_two(self):
        self.assertEqual(self.publish().returncode, 0)
        registry = self.read_registry()
        registry["upstream"]["commit"] = "0" * 40
        self.write_registry(registry)
        result = self.stage_complete()
        self.assertEqual(result.returncode, 2)
        self.assertIn("provenance mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
