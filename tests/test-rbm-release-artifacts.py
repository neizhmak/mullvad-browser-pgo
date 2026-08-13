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
import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
store = Path(os.environ["FAKE_GH_STORE"])
store.mkdir(parents=True, exist_ok=True)
command, release = args[1], args[2]
release_dir = store / release
if command == "view":
    if not release_dir.exists(): sys.exit(1)
    if "--json" in args:
        print(json.dumps({"assets": [{"name": p.name} for p in release_dir.iterdir()]}))
elif command == "create":
    release_dir.mkdir()
    (store / "create-args").write_text(" ".join(args))
elif command == "upload":
    source = Path(args[-1])
    destination = release_dir / source.name
    if destination.exists(): sys.exit(2)
    shutil.copyfile(source, destination)
elif command == "download":
    pattern = args[args.index("--pattern") + 1]
    destination = Path(args[args.index("--dir") + 1])
    destination.mkdir(parents=True, exist_ok=True)
    matches = list(release_dir.glob(pattern))
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
                                 "FAKE_GH_STORE": str(self.store)}
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

    def restore(self):
        return subprocess.run(
            [str(HELPER), "restore", "--upstream", str(self.upstream),
             "--repository", "owner/repo", "--release", self.release,
             "--registry-dir", str(self.registry_dir)],
            env=self.env, text=True, capture_output=True)

    def seed_asset(self, content):
        release = self.store / self.release
        release.mkdir(parents=True)
        (release / self.asset_name).write_bytes(content)

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


if __name__ == "__main__":
    unittest.main()
