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
release_dir = store / release
if command == "view":
    if not release_dir.exists(): sys.exit(1)
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
    shutil.copyfile(source, destination)
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

    def publish(self):
        return subprocess.run(
            [str(HELPER), "publish", "--upstream", str(self.upstream),
             "--repository", "owner/repo", "--release", self.release,
             "--registry-dir", str(self.registry_dir), "--before", str(self.before),
             "--stage", "clang"], env=self.env, text=True, capture_output=True)

    def stage_complete(self, stage="clang"):
        return subprocess.run(
            [str(HELPER), "stage-complete", "--upstream", str(self.upstream),
             "--repository", "owner/repo", "--release", self.release,
             "--registry-dir", str(self.registry_dir), "--stage", stage],
            env=self.env, text=True, capture_output=True)

    def restore(self):
        return subprocess.run(
            [str(HELPER), "restore", "--upstream", str(self.upstream),
             "--repository", "owner/repo", "--release", self.release,
             "--registry-dir", str(self.registry_dir)],
            env=self.env, text=True, capture_output=True)

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
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registry-clang.json is missing or incomplete", result.stdout)

    def test_registry_with_incomplete_artifact_does_not_mark_stage_complete(self):
        publish = self.publish()
        self.assertEqual(publish.returncode, 0, publish.stderr)
        metadata = self.store / self.release / ".assets.json"
        assets = json.loads(metadata.read_text())
        assets[self.asset_name]["state"] = "starter"
        metadata.write_text(json.dumps(assets))
        result = self.stage_complete()
        self.assertNotEqual(result.returncode, 0)
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


if __name__ == "__main__":
    unittest.main()
