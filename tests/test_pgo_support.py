#!/usr/bin/env python3
"""Offline native tests for the exact official Node support checkpoint."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ["alpha", "mullvadbrowser-windows-x86_64"]
FILENAME = "node-22.16.0-782ba9.tar.zst"
NODE_BYTES = b"verified official Node archive bytes"
GITLINK = "865f2c9842520958879665d5c9b820d9ed51761e"
SOURCE_FILES = {"projects/node/config": "# official fixture\nversion: 22.16.0\nvar:\n  node_version: 22.16.0\n  node_sha256: 720894f323e5c1ac24968eb2676660c90730d715cb7f090be71a668662a17c37\n  no_crosscompile: 1\n",
                "projects/node/build": "#!/bin/bash\n./configure --prefix=$distdir\nmake\nmake install\n",
                "rbm.conf": "targets:\n  windows:\n    var:\n      container:\n        suite: trixie\n        arch: amd64\n",
                "projects/container-image/config": "filename: container-image_trixie-amd64.tar.zst\n",
                "projects/container-image/build": "#!/bin/sh\nset -e\n# Doing nothing\n"}

FAKE_GIT = r"""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
config = json.loads(Path(os.environ['SUPPORT_FIXTURE']).read_text())
with Path(os.environ['SUPPORT_CALLS']).open('a') as stream:
    stream.write(json.dumps({'program':'git', 'args':args, 'cwd':str(Path.cwd())})+'\n')
assert args[0] == '-C', args
repository, command = Path(args[1]), args[2:]
lock = config['lock']
if command == ['rev-parse', 'HEAD']:
    print(config.get('rbm_head', config['gitlink']) if repository.name == 'rbm' else config.get('head', lock['commit']))
elif command == ['remote', 'get-url', 'origin']:
    print(config.get('origin', lock['repository']))
elif command == ['rev-parse', 'refs/tags/' + lock['tag']]:
    print(config.get('tag_object', lock['tag_object']))
elif command == ['rev-parse', 'refs/tags/' + lock['tag'] + '^{}']:
    print(config.get('peeled', lock['commit']))
elif command == ['cat-file', '-t', lock['tag_object']]:
    print(config.get('tag_type', 'tag'))
elif command == ['ls-tree', lock['commit'], 'rbm']:
    print('160000 commit ' + config['gitlink'] + '\trbm')
elif command[0] == 'show':
    revision, path = command[1].split(':', 1)
    assert revision == lock['commit'], command
    sys.stdout.write(config['source_files'][path])
else:
    print('unexpected fake git command', file=sys.stderr)
    sys.exit(90)
"""

FAKE_RBM = r"""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
config = json.loads(Path(os.environ['SUPPORT_FIXTURE']).read_text())
with Path(os.environ['SUPPORT_CALLS']).open('a') as stream:
    stream.write(json.dumps({'program':'rbm', 'args':args, 'cwd':str(Path.cwd())})+'\n')
assert args[0] == 'showconf', 'support consumer attempted a build'
project, key = args[1:3]
base = ['--target', 'alpha', '--target', 'mullvadbrowser-windows-x86_64']
if project == 'node':
    assert args[3:] == base, args
    value = config['node'][key]
elif project == 'firefox':
    assert args[3:] in [base + ['--target', 'pgo-generate'], base + ['--target', 'pgo-use']], args
    assert key == 'input_files_by_name/node', args
    value = config.get('firefox_node', config['node']['filename'])
else:
    sys.exit(91)
if value is None:
    print('Error: Undefined', file=sys.stderr)
    sys.exit(1)
if isinstance(value, dict):
    sys.stdout.write(value.get('stdout', ''))
    sys.stderr.write(value.get('stderr', 'fixture native failure'))
    sys.exit(value.get('status', 1))
print(value)
"""

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


class SupportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-support-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.overlay = self.base / "overlay with spaces"
        scripts = self.overlay / "scripts"
        scripts.mkdir(parents=True)
        for name in ("resolve-pgo-support-identity.py", "restore-pgo-support.py",
                     "rbm_network.py", "rbm-release-artifacts.py"):
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)
            (scripts / name).chmod(0o755)
        shutil.copyfile(ROOT / "upstream.lock.json", self.overlay / "upstream.lock.json")
        self.lock = json.loads((self.overlay / "upstream.lock.json").read_text())
        self.upstream = self.base / "upstream with spaces"
        self.upstream.mkdir()
        for name, content in SOURCE_FILES.items():
            path = self.upstream / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        rbm = self.upstream / "rbm/rbm"
        rbm.parent.mkdir()
        rbm.write_text(f"#!{sys.executable}\n" + FAKE_RBM)
        rbm.chmod(0o755)
        self.fixture = self.base / "fixture.json"
        self.calls = self.base / "calls.jsonl"
        self.config = {"lock": self.lock, "gitlink": GITLINK, "source_files": dict(SOURCE_FILES),
                       "node": {"var/linux": None, "var/windows-x86_64": "1", "var/windows": "1",
                                "var/no_crosscompile": "1", "version": "22.16.0", "filename": FILENAME,
                                "var/container/suite": "trixie", "var/container/arch": "amd64",
                                "var/node_sha256": "720894f323e5c1ac24968eb2676660c90730d715cb7f090be71a668662a17c37",
                                "input_files": "---\n- URL: https://nodejs.org/dist/v22.16.0/node-v22.16.0.tar.xz\n  name: node\n  sha256sum: 720894f323e5c1ac24968eb2676660c90730d715cb7f090be71a668662a17c37\n- project: container-image\n- project: mingw-w64-clang\n  enable: ''"}}
        bindir = self.base / "bin"
        bindir.mkdir()
        for name, content in (("git", FAKE_GIT), ("gh", FAKE_GH)):
            path = bindir / name
            path.write_text(f"#!{sys.executable}\n" + content)
            path.chmod(0o755)
        self.store = self.base / "releases"
        self.env = os.environ | {"PATH": str(bindir) + os.pathsep + str(Path(sys.executable).parent)
                                        + os.pathsep + os.environ.get("PATH", ""),
                                 "SUPPORT_FIXTURE": str(self.fixture), "SUPPORT_CALLS": str(self.calls),
                                 "FAKE_GH_STORE": str(self.store), "GITHUB_REPOSITORY": "owner/repo",
                                 "PYTHONDONTWRITEBYTECODE": "1"}
        self.identity_file = self.base / "identity.json"
        self.metadata_file = self.base / "metadata.json"
        self.output = self.base / "restored support with spaces"
        self.provenance = self.base / "build.json"
        self.original_provenance = {"schema": 2, "upstream_lock": self.lock, "sentinel": "preserve"}
        self.provenance.write_text(json.dumps(self.original_provenance))
        self.archive = self.upstream / "out/node" / FILENAME

    def invoke(self, name, *arguments):
        self.fixture.write_text(json.dumps(self.config))
        return subprocess.run([sys.executable, str(self.overlay / "scripts" / name), *map(str, arguments)],
                              cwd=self.base, env=self.env, text=True, capture_output=True, timeout=20)

    def resolve(self, *extra):
        return self.invoke("resolve-pgo-support-identity.py", "--upstream", self.upstream,
                           "--project", "node", "--output", self.identity_file,
                           "--metadata-output", self.metadata_file, *extra)

    def good_resolve(self):
        result = self.resolve()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(self.identity_file.read_text()), json.loads(self.metadata_file.read_text())

    def commit(self):
        identity, metadata = self.good_resolve()
        self.archive.parent.mkdir(parents=True, exist_ok=True)
        self.archive.write_bytes(NODE_BYTES)
        before = self.base / "before"
        before.write_text("")
        result = self.invoke("rbm-release-artifacts.py", "publish", "--upstream", self.upstream,
                             "--repository", "owner/repo", "--release", metadata["release"],
                             "--before", before, "--stage", "node", "--project", "node",
                             "--identity-file", self.identity_file, "--registry-dir", self.base / "published")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return identity, metadata

    def consume(self, pgo="pgo-generate", *extra):
        return self.invoke("restore-pgo-support.py", "--upstream", self.upstream, "--pgo-target", pgo,
                           "--output-directory", self.output, "--provenance", self.provenance, *extra)

    def rbm_calls(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()
                if json.loads(line)["program"] == "rbm"] if self.calls.exists() else []

    def assert_no_build(self):
        self.assertTrue(all(call["args"][0] == "showconf" for call in self.rbm_calls()))

    def test_identity_is_canonical_stable_and_exists_before_archive(self):
        identity, metadata = self.good_resolve()
        self.assertFalse(self.archive.exists())
        expected = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(metadata["identity_sha256"], expected)
        self.assertEqual(metadata["release"], f"pgo-support-{self.lock['tag']}-{expected}")
        self.assertEqual(identity["kind"], "official-rbm-support-node")
        self.assertEqual(identity["targets"], TARGETS)
        self.assertEqual(identity["output_filename"], FILENAME)
        self.assertEqual(identity["compiler_inputs"], [])
        self.assertEqual(identity["rbm_gitlink"], GITLINK)
        self.assertEqual(identity["container"]["suite"], "trixie")
        self.assertEqual(identity["config_sha256"], hashlib.sha256(SOURCE_FILES["projects/node/config"].encode()).hexdigest())
        self.assertNotIn(str(self.upstream), self.identity_file.read_text())
        first_bytes = self.identity_file.read_bytes()
        self.env.update({"GITHUB_SHA": "f" * 40, "GITHUB_RUN_ID": "changed", "RUNNER_TEMP": "/different/temp"})
        identity_again, metadata_again = self.good_resolve()
        self.assertEqual((identity_again, metadata_again), (identity, metadata))
        self.assertEqual(self.identity_file.read_bytes(), first_bytes)
        self.assert_no_build()

    def test_current_node_raw_source_inputs_and_hashes_are_bound(self):
        identity, metadata = self.good_resolve()
        self.assertEqual(identity["source_inputs"], self.config["node"]["input_files"])
        self.assertEqual(identity["source"]["sha256"], self.config["node"]["var/node_sha256"])
        self.config["node"]["input_files"] += "\n# different evaluated source input"
        changed, changed_metadata = self.good_resolve()
        self.assertNotEqual(changed_metadata["identity_sha256"], metadata["identity_sha256"])
        self.assertNotEqual(changed["source_inputs"], identity["source_inputs"])

    def test_evaluated_version_and_source_hash_cannot_override_the_official_recipe(self):
        for key, value in (("version", "23.0.0"), ("var/node_sha256", "0" * 64)):
            with self.subTest(key=key):
                original = self.config["node"][key]
                self.config["node"][key] = value
                result = self.resolve()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("differs from the pinned recipe", result.stderr)
                self.config["node"][key] = original
        self.assertFalse(self.identity_file.exists())

    def test_only_node_is_supported(self):
        result = self.resolve("--project", "rust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only the official Node", result.stderr)
        self.assertFalse(self.identity_file.exists())

    def test_windows_linux_blank_zero_or_undefined_are_not_compiler_inputs(self):
        for value in (None, "", "0", "false"):
            with self.subTest(value=value):
                self.config["node"]["var/linux"] = value
                identity, _ = self.good_resolve()
                self.assertEqual(identity["compiler_inputs"], [])
        self.assert_no_build()

    def test_linux_or_ambiguous_flags_fail_without_compiler_builds(self):
        for value in ("1", "true", "yes", "2"):
            with self.subTest(value=value):
                self.config["node"]["var/linux"] = value
                result = self.resolve()
                self.assertNotEqual(result.returncode, 0)
        self.assert_no_build()

    def test_undefined_flag_exception_does_not_swallow_other_native_errors(self):
        self.config["node"]["var/linux"] = {"status": 1, "stderr": "Error: ref missing\n"}
        result = self.resolve()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ref missing", result.stderr)
        self.assertFalse(self.identity_file.exists())

    def test_windows_native_and_container_constraints_fail_closed(self):
        for key, value in [("var/windows", "0"), ("var/windows-x86_64", "0"),
                           ("var/no_crosscompile", "0"), ("var/container/suite", "bookworm"),
                           ("var/container/arch", "arm64")]:
            with self.subTest(key=key):
                original = self.config["node"][key]
                self.config["node"][key] = value
                self.assertNotEqual(self.resolve().returncode, 0)
                self.config["node"][key] = original

    def test_unsafe_or_wrong_version_filename_is_never_recorded(self):
        for filename in ("../node.tar.zst", "/node.tar.zst", "node-other.tar.zst",
                         "node-23.0.0-782ba9.tar.zst", FILENAME + "?", "node-22.16.0-hash\\file.tar.zst"):
            with self.subTest(filename=filename):
                self.config["node"]["filename"] = filename
                result = self.resolve()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid exact Node", result.stderr)
        self.assertFalse(self.identity_file.exists())

    def test_wrong_upstream_or_rbm_identity_is_rejected(self):
        for key, value in [("head", "0" * 40), ("origin", "https://example.test/fork.git"),
                           ("tag_object", "0" * 40), ("peeled", "0" * 40),
                           ("tag_type", "commit"), ("rbm_head", "0" * 40)]:
            with self.subTest(key=key):
                self.config[key] = value
                result = self.resolve()
                self.assertNotEqual(result.returncode, 0)
                self.config.pop(key)
        self.assertFalse(self.identity_file.exists())

    def test_modified_official_recipe_and_symlink_source_are_rejected(self):
        config = self.upstream / "projects/node/config"
        config.write_text("modified Node recipe\n")
        result = self.resolve()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("modified official Node", result.stderr)
        config.unlink()
        outside = self.base / "outside-config"
        outside.write_text(SOURCE_FILES["projects/node/config"])
        config.symlink_to(outside)
        result = self.resolve()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escapes", result.stderr)

    def test_gen_and_use_restore_exact_archive_and_record_actual_bytes(self):
        identity, metadata = self.commit()
        self.archive.unlink()
        original_registry = (self.store / metadata["release"] / "registry-node.json").read_bytes()
        for pgo in ("pgo-generate", "pgo-use"):
            with self.subTest(pgo=pgo):
                result = self.consume(pgo, "--expected-release", metadata["release"],
                                      "--expected-identity", metadata["identity_sha256"])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.archive.read_bytes(), NODE_BYTES)
                provenance = json.loads(self.provenance.read_text())
                self.assertEqual(provenance["sentinel"], "preserve")
                record = provenance["build_support"]["node"]
                self.assertEqual(record, {"identity_sha256": metadata["identity_sha256"],
                                         "archive_filename": FILENAME, "size": len(NODE_BYTES),
                                         "sha256": hashlib.sha256(NODE_BYTES).hexdigest()})
        self.assertEqual((self.store / metadata["release"] / "registry-node.json").read_bytes(), original_registry)
        self.assert_no_build()

    def test_expected_checkpoint_conflicts_fail_before_release_access(self):
        _, metadata = self.commit()
        count = len((self.store / "calls").read_text().splitlines())
        before = self.provenance.read_bytes()
        for option, value in [("--expected-release", metadata["release"] + "-other"),
                              ("--expected-identity", "a" * 64), ("--expected-identity", "invalid")]:
            with self.subTest(option=option):
                result = self.consume("pgo-generate", option, value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len((self.store / "calls").read_text().splitlines()), count)
                self.assertEqual(self.provenance.read_bytes(), before)

    def test_firefox_pgo_target_input_mismatch_fails_before_restore(self):
        self.commit()
        self.config["firefox_node"] = "node-22.16.0-different.tar.zst"
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different Node input", result.stderr)
        self.assertNotIn("build_support", json.loads(self.provenance.read_text()))

    def test_missing_checkpoint_never_falls_back_to_building(self):
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required dependency Release does not exist", result.stderr)
        self.assertFalse(self.archive.exists())
        self.assertNotIn("build_support", json.loads(self.provenance.read_text()))
        self.assert_no_build()

    def test_corrupt_cache_fails_before_provenance_update(self):
        _, metadata = self.commit()
        release = self.store / metadata["release"]
        registry = json.loads((release / "registry-node.json").read_text())
        (release / registry["artifacts"][0]["asset"]).write_bytes(b"x" * len(NODE_BYTES))
        self.archive.unlink()
        before = self.provenance.read_bytes()
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("published artifact identity mismatch", result.stderr)
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.provenance.read_bytes(), before)
        self.assert_no_build()

    def test_symlink_or_empty_existing_archive_never_accepted(self):
        self.commit()
        self.archive.write_bytes(b"")
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.archive.unlink()
        outside = self.base / "outside-node"
        outside.write_bytes(NODE_BYTES)
        self.archive.symlink_to(outside)
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_bytes(), NODE_BYTES)
        self.assertNotIn("build_support", json.loads(self.provenance.read_text()))

    def test_registry_must_bind_the_exact_single_node_archive(self):
        _, metadata = self.commit()
        release = self.store / metadata["release"]
        registry_path = release / "registry-node.json"
        registry = json.loads(registry_path.read_text())
        artifact = dict(registry["artifacts"][0], filename="node-source.tar.xz", path="out/node/node-source.tar.xz",
                        asset="rbm-extra-node-source.tar.xz")
        (release / artifact["asset"]).write_bytes(NODE_BYTES)
        registry["artifacts"].append(artifact)
        registry_path.write_text(json.dumps(registry))
        assets_path = release / ".assets.json"
        assets = json.loads(assets_path.read_text())
        assets[registry_path.name]["size"] = registry_path.stat().st_size
        assets[artifact["asset"]] = {"id": 991, "state": "uploaded", "size": len(NODE_BYTES)}
        assets_path.write_text(json.dumps(assets))
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only its exact built archive", result.stderr)
        self.assertNotIn("build_support", json.loads(self.provenance.read_text()))

    def test_existing_support_provenance_conflict_is_not_overwritten(self):
        self.commit()
        provenance = {**self.original_provenance, "build_support": {"node": {"sha256": "0" * 64}}}
        self.provenance.write_text(json.dumps(provenance))
        before = self.provenance.read_bytes()
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting Node build_support", result.stderr)
        self.assertEqual(self.provenance.read_bytes(), before)

    def test_provenance_and_json_outputs_reject_symlinks(self):
        self.commit()
        self.provenance.unlink()
        outside = self.base / "outside-provenance"
        outside.write_text(json.dumps(self.original_provenance))
        self.provenance.symlink_to(outside)
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provenance must not be a symlink", result.stderr)
        self.assertNotIn("build_support", json.loads(outside.read_text()))


    def test_consumer_allows_absent_provenance_without_writing_a_build_record(self):
        _, metadata = self.commit()
        result = self.invoke("restore-pgo-support.py", "--upstream", self.upstream,
                             "--pgo-target", "pgo-generate", "--output-directory", self.output,
                             "--repository", "owner/repo", "--expected-release", metadata["release"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.provenance.read_text()), self.original_provenance)
        self.assertEqual(json.loads((self.output / "node-support.json").read_text())["archive_filename"], FILENAME)

    def test_wrong_build_lock_is_not_updated_with_support_provenance(self):
        self.commit()
        value = json.loads(json.dumps(self.original_provenance))
        value["upstream_lock"]["commit"] = "0" * 40
        self.provenance.write_text(json.dumps(value))
        before = self.provenance.read_bytes()
        result = self.consume()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different upstream lock", result.stderr)
        self.assertEqual(self.provenance.read_bytes(), before)

    def test_existing_build_support_requires_node_only_and_is_not_repaired(self):
        _, metadata = self.commit()
        valid_node = {"identity_sha256": metadata["identity_sha256"], "archive_filename": FILENAME,
                      "sha256": hashlib.sha256(NODE_BYTES).hexdigest(), "size": len(NODE_BYTES)}
        for previous in (None, [], {}, {"other": {}}, {"node": valid_node, "other": {}}):
            with self.subTest(previous=previous):
                value = {**self.original_provenance, "build_support": previous}
                self.provenance.write_text(json.dumps(value))
                before = self.provenance.read_bytes()
                result = self.consume()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid existing build_support", result.stderr)
                self.assertEqual(self.provenance.read_bytes(), before)

    def test_output_and_provenance_ancestor_symlinks_fail_closed(self):
        self.commit()
        outside = self.base / "outside-dir"
        outside.mkdir()
        alias = self.base / "alias-dir"
        alias.symlink_to(outside, target_is_directory=True)
        before = self.provenance.read_bytes()
        result = self.consume("pgo-generate", "--output-directory", alias / "nested")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("destination symlink", result.stderr)
        self.assertFalse((outside / "nested").exists())
        self.assertEqual(self.provenance.read_bytes(), before)
        (outside / "build.json").write_text(json.dumps(self.original_provenance))
        outside_before = (outside / "build.json").read_bytes()
        result = self.consume("pgo-generate", "--provenance", alias / "build.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("destination symlink", result.stderr)
        self.assertEqual((outside / "build.json").read_bytes(), outside_before)
        result = self.resolve("--output", alias / "identity.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((outside / "identity.json").exists())

    def test_verify_output_selects_only_nonempty_exact_archive(self):
        result = self.resolve("--verify-output")
        self.assertNotEqual(result.returncode, 0)
        self.archive.parent.mkdir(parents=True)
        (self.archive.parent / "node-other.tar.zst").write_bytes(b"unrelated archive")
        result = self.resolve("--verify-output")
        self.assertNotEqual(result.returncode, 0)
        self.archive.write_bytes(b"")
        self.assertNotEqual(self.resolve("--verify-output").returncode, 0)
        self.archive.write_bytes(NODE_BYTES)
        result = self.resolve("--verify-output")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class WorkflowTests(unittest.TestCase):
    def test_reusable_free_node_only_job_and_bounded_observed_build(self):
        workflow = (ROOT / ".github/workflows/pgo-support.yml").read_text()
        self.assertIn("workflow_call:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("identity_sha256:", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("timeout-minutes: 150", workflow)
        self.assertIn("timeout-minutes: 120", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("./scripts/observe-rbm-build.py", workflow)
        self.assertIn("--resource-log", workflow)
        self.assertIn("./rbm/rbm build node --target alpha --target mullvadbrowser-windows-x86_64", workflow)
        self.assertNotRegex(workflow, r"rbm/rbm build (?:rust|clang|firefox|browser|release)")
        self.assertNotIn("prepare-pgo", workflow)
        self.assertNotIn("actions/cache", workflow)
        self.assertNotIn("--target \"$GITHUB_SHA\"", workflow)
        self.assertIn("if: always()", workflow)

    def test_publish_stages_exact_archive_not_raw_node_source_or_recursive_outputs(self):
        workflow = (ROOT / ".github/workflows/pgo-support.yml").read_text()
        self.assertIn("--upstream \"$RUNNER_TEMP/node-payload\"", workflow)
        self.assertIn("--stage node --project node", workflow)
        self.assertIn('ln "$UPSTREAM/out/node/$filename"', workflow)
        self.assertIn("--verify-output", workflow)
        self.assertIn('--before "$RUNNER_TEMP/node-before"', workflow)
        self.assertNotIn("find ", workflow)

    def test_all_support_shell_blocks_parse_without_running_builds(self):
        lines = (ROOT / ".github/workflows/pgo-support.yml").read_text().splitlines()
        blocks = []
        for index, line in enumerate(lines):
            if line == "        run: |":
                following = []
                for command in lines[index + 1:]:
                    if command and not command.startswith("          "):
                        break
                    following.append(command[10:])
                blocks.append("\n".join(following))
        self.assertGreaterEqual(len(blocks), 8)
        for block in blocks:
            result = subprocess.run(["bash", "-n"], input=block, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cache_exit_two_fails_gate_and_cannot_schedule_rebuild(self):
        workflow = (ROOT / ".github/workflows/pgo-support.yml").read_text()
        gate = workflow.split("      - name: Check byte-verified Node checkpoint", 1)[1].split("      - name:", 1)[0]
        gate = gate.split("        run: |\n", 1)[1]
        shell = "\n".join(line[10:] if line.startswith("          ") else line for line in gate.splitlines())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            helper = root / "scripts/rbm-release-artifacts.py"
            helper.write_text("#!/bin/sh\nexit \"$CACHE_STATUS\"\n")
            helper.chmod(0o755)
            for status in (0, 1, 2):
                output = root / "output"
                output.unlink(missing_ok=True)
                env = os.environ | {"CACHE_STATUS": str(status), "GITHUB_OUTPUT": str(output),
                                     "UPSTREAM": "/fixture", "SUPPORT_RELEASE": "technical", "RUNNER_TEMP": str(root)}
                result = subprocess.run(["bash", "-e", "-c", shell], cwd=root, env=env,
                                        text=True, capture_output=True)
                if status == 2:
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("complete=" + ("true" if status == 0 else "false"), output.read_text())


if __name__ == "__main__":
    unittest.main()
