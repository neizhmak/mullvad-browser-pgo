#!/usr/bin/env python3
"""Behavioral checks for profile-use configuration, handoff, and Windows packaging."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COLLECT = ROOT / "scripts/collect-pgo-packages.py"
PATCH = (ROOT / "patches/firefox-pgo-use.patch").read_text()
PROFILE = "/var/tmp/dist/pgo/merged.profdata"
JARLOG = "/var/tmp/dist/pgo/jarlog"
OFFICIAL_UPDATE_URL = "https://cdn.mullvad.net/browser/update_responses/update_1"
MAR_CHANNEL = "mullvadbrowser-mullvad-alpha"
UPDATE_SUBSTS = {"MOZ_UPDATER": "1", "BASE_BROWSER_UPDATE": "1", "MOZ_VERIFY_MAR_SIGNATURE": "1",
                 "MOZ_USE_NSS_FOR_MAR": "1", "MOZ_UPDATE_CHANNEL": "alpha", "BB_UPDATER_URL": OFFICIAL_UPDATE_URL,
                 "MAR_CHANNEL_ID": MAR_CHANNEL, "ACCEPTED_MAR_CHANNEL_IDS": MAR_CHANNEL}
UPDATE_DEFINES = {"MOZ_VERIFY_MAR_SIGNATURE": "1", "BASE_BROWSER_VERSION": "16.0a9",
                  "BASE_BROWSER_VERSION_QUOTED": '"16.0a9"'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def added_block(label):
    lines = PATCH.splitlines()
    begin = next(i for i, line in enumerate(lines) if line.startswith("+") and "<<'" + label + "'" in line)
    end = next(i for i in range(begin + 1, len(lines)) if lines[i] == "+" + label)
    return "\n".join(line[1:] for line in lines[begin + 1:end] if line.startswith("+")) + "\n"


class PGOUseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.profile = self.directory / "profile"
        self.profile.mkdir()
        (self.profile / "merged.profdata").write_bytes(b"profile")
        (self.profile / "jarlog").write_bytes(b"jarlog")
        (self.profile / "provenance.json").write_text(json.dumps({"firefox": {"revision": "a" * 40}}))
        self.identity = "b" * 64
        self.proof = {"schema": 1, "firefox_revision": "a" * 40,
                      "pgo_profile_sha256": digest(self.profile / "merged.profdata"),
                      "pgo_jarlog_sha256": digest(self.profile / "jarlog"),
                      "substs": {"MOZ_PROFILE_USE": "1", "MOZ_PGO_RUST": "1", "MOZ_PROFILE_GENERATE": "",
                                 "PGO_PROFILE_PATH": PROFILE, "PROFILE_USE_CFLAGS": ["-fprofile-use=" + PROFILE],
                                 "PGO_JARLOG_PATH": [JARLOG], **UPDATE_SUBSTS},
                      "defines": dict(UPDATE_DEFINES)}
        self.output = self.directory / "firefox-mullvad-browser-test"
        self.output.mkdir()
        for filename in ["browser.tar.zst", "nsis-plugins.tar.zst", "mar-tools-windows-x86_64-16.0a9.zip"]:
            (self.output / filename).write_bytes(filename.encode())
        (self.output / "pgo-use-proof.json").write_text(json.dumps(self.proof))
        self.artifact = self.directory / "handoff"

    def tearDown(self):
        self.temp.cleanup()

    def command(self, *args):
        return subprocess.run([sys.executable, str(COLLECT), *map(str, args)], text=True, capture_output=True)

    def snapshot(self, destination=None):
        return self.command("snapshot-firefox", "--directory", self.output, "--rbm-filename", self.output.name,
                            "--profile-directory", self.profile, "--profile-identity", self.identity,
                            "--output-directory", destination or self.artifact)

    def verify(self):
        return self.command("verify-firefox", "--artifact-directory", self.artifact,
                            "--profile-directory", self.profile, "--profile-identity", self.identity)

    def make_portable(self, path, system_marker=False, update_url=None, mar_channels=None):
        required = {"Browser/firefox.exe": b"MZfake", "Browser/xul.dll": b"MZfake", "Browser/updater.exe": b"MZfake",
                    "Browser/omni.ja": b"data", "Browser/browser/omni.ja": b"data",
                    "Browser/application.ini": ("[App]\nName=MullvadBrowser\nVersion=153.0esr\n[AppUpdate]\nURL=" +
                        (update_url or OFFICIAL_UPDATE_URL + "/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL") + "\n").encode(),
                    "Browser/update-settings.ini": ("[Settings]\nACCEPTED_MAR_CHANNEL_IDS=" + (mar_channels or MAR_CHANNEL) + "\n").encode(),
                    "Browser/postupdate.exe": b"MZfake", "Start Mullvad Browser.cmd": b'@echo off\r\nstart "" "%~dp0Browser\\firefox.exe" %*\r\n',
                    "Browser/distribution/extensions/uBlock0@raymondhill.net.xpi": b"extension",
                    "Browser/distribution/extensions/{73a6fe31-595d-460b-a920-fcc0f8843232}.xpi": b"extension",
                    "Browser/distribution/extensions/{d19a89b9-76c1-4a61-bcd4-49e8de916403}.xpi": b"extension"}
        if system_marker:
            required["Browser/system-install"] = b""
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in required.items():
                archive.writestr("Mullvad Browser/" + name, data)

    def collect(self):
        return self.command("collect", "--directory", self.directory / "packages", "--destination", self.directory / "final",
                            "--version", "16.0a9", "--firefox-manifest", self.artifact / "firefox-output.json",
                            "--profile-identity", self.identity)

    def test_firefox_handoff_is_deterministic_verified_and_bound(self):
        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stderr)
        other = self.directory / "other"
        second = self.snapshot(other)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(digest(self.artifact / "firefox-output.tar"), digest(other / "firefox-output.tar"))
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), digest(self.artifact / "firefox-output.tar"))
        (self.artifact / "firefox-output.tar").write_bytes(b"changed")
        self.assertNotEqual(self.verify().returncode, 0)

    def test_handoff_rejects_missing_cross_language_proof_and_wrong_profile(self):
        self.proof["substs"]["MOZ_PGO_RUST"] = ""
        (self.output / "pgo-use-proof.json").write_text(json.dumps(self.proof))
        result = self.snapshot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("both C++ and Rust", result.stderr)
        self.proof["substs"]["MOZ_PGO_RUST"] = "1"
        self.proof["pgo_profile_sha256"] = "0" * 64
        (self.output / "pgo-use-proof.json").write_text(json.dumps(self.proof))
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_handoff_rejects_insecure_or_redirected_updater_configuration(self):
        original = json.loads(json.dumps(self.proof))
        mutations = [
            ("substs", "MOZ_VERIFY_MAR_SIGNATURE", ""),
            ("defines", "MOZ_VERIFY_MAR_SIGNATURE", ""),
            ("substs", "MOZ_UPDATER", ""),
            ("substs", "BB_UPDATER_URL", "https://unofficial.example/update"),
            ("substs", "MAR_CHANNEL_ID", "unofficial-alpha"),
            ("substs", "ACCEPTED_MAR_CHANNEL_IDS", "mullvadbrowser-mullvad-alpha,unofficial-alpha"),
            ("substs", "DISABLE_UPDATER_AUTHENTICODE_CHECK", "1"),
            ("defines", "BASE_BROWSER_VERSION", "16.0a8"),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                self.proof = json.loads(json.dumps(original))
                self.proof[section][key] = value
                (self.output / "pgo-use-proof.json").write_text(json.dumps(self.proof))
                result = self.snapshot()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)

    def test_packaged_official_updater_url_and_mar_channel_must_match(self):
        self.assertEqual(self.snapshot().returncode, 0)
        packages = self.directory / "packages"
        packages.mkdir()
        (packages / "mullvad-browser-windows-x86_64-16.0a9.exe").write_bytes(b"MZinstaller")
        portable = packages / "mullvad-browser-windows-x86_64-portable-16.0a9.zip"
        self.make_portable(portable, update_url="https://unofficial.example/%VERSION%")
        wrong_url = self.collect()
        self.assertNotEqual(wrong_url.returncode, 0)
        self.assertIn("official Alpha update URL", wrong_url.stderr)
        self.make_portable(portable, mar_channels="unofficial-alpha")
        wrong_mar = self.collect()
        self.assertNotEqual(wrong_mar.returncode, 0)
        self.assertIn("signed MAR channels", wrong_mar.stderr)
        self.make_portable(portable)
        good = self.collect()
        self.assertEqual(good.returncode, 0, good.stderr)
        updates = json.loads((self.directory / "final/packages.json").read_text())["portable_layout"]["updates"]
        self.assertEqual(updates["accepted_mar_channel_ids"], MAR_CHANNEL)
        self.assertIn("%VERSION%", updates["url"])
        self.assertFalse(updates["mar_update_integration_tested"])

    def test_archive_rejects_unlisted_paths_even_with_rewritten_archive_hash(self):
        self.assertEqual(self.snapshot().returncode, 0)
        archive = self.artifact / "firefox-output.tar"
        with tarfile.open(archive, "a") as stream:
            info = tarfile.TarInfo("../escape")
            stream.addfile(info)
        manifest_path = self.artifact / "firefox-output.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["archive"].update(sha256=digest(archive), size=archive.stat().st_size)
        manifest_path.write_text(json.dumps(manifest))
        self.assertNotEqual(self.verify().returncode, 0)

    def test_collection_requires_both_packages_and_portable_marker_semantics(self):
        self.assertEqual(self.snapshot().returncode, 0)
        packages = self.directory / "packages"
        packages.mkdir()
        (packages / "mullvad-browser-windows-x86_64-16.0a9.exe").write_bytes(b"MZinstaller")
        missing = self.collect()
        self.assertNotEqual(missing.returncode, 0)
        portable = packages / "mullvad-browser-windows-x86_64-portable-16.0a9.zip"
        self.make_portable(portable, system_marker=True)
        bad = self.collect()
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("system-install", bad.stderr)
        self.make_portable(portable)
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.directory / "final/packages.json").read_text())
        self.assertEqual({item["kind"] for item in manifest["assets"]}, {"installer", "portable"})
        self.assertFalse(manifest["public_browser_release"])
        for item in manifest["assets"]:
            self.assertEqual(item["sha256"], digest(self.directory / "final" / item["filename"]))

    def test_config_proof_executes_against_realistic_json_not_a_string_assertion(self):
        code = added_block("PY_PGO_PROOF")
        code = code.replace("[% c('var/git_commit') %]", "a" * 40)
        code = code.replace("[% c('var/pgo_profile_sha256') %]", self.proof["pgo_profile_sha256"])
        code = code.replace("[% c('var/pgo_jarlog_sha256') %]", self.proof["pgo_jarlog_sha256"])
        code = code.replace("[% c('var/torbrowser_version') %]", "16.0a9")
        obj = self.directory / "obj-test"
        obj.mkdir()
        (obj / "config.status.json").write_text(json.dumps({"substs": self.proof["substs"], "defines": self.proof["defines"]}))
        program = self.directory / "proof.py"
        program.write_text(code)
        result = subprocess.run([sys.executable, program, self.directory / "proof.json"], cwd=self.directory, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.proof["substs"]["MOZ_PROFILE_GENERATE"] = "1"
        (obj / "config.status.json").write_text(json.dumps({"substs": self.proof["substs"], "defines": self.proof["defines"]}))
        bad = subprocess.run([sys.executable, program, self.directory / "proof.json"], cwd=self.directory, capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.proof["substs"]["MOZ_PROFILE_GENERATE"] = ""
        for section, key, value in [("substs", "MOZ_VERIFY_MAR_SIGNATURE", ""),
                                    ("substs", "BB_UPDATER_URL", "https://unofficial.example/update"),
                                    ("substs", "ACCEPTED_MAR_CHANNEL_IDS", "unofficial-alpha"),
                                    ("defines", "BASE_BROWSER_VERSION", "16.0a8")]:
            with self.subTest(configure_updater=key):
                configuration = {"substs": dict(self.proof["substs"]), "defines": dict(self.proof["defines"])}
                configuration[section][key] = value
                (obj / "config.status.json").write_text(json.dumps(configuration))
                result = subprocess.run([sys.executable, program, self.directory / "proof.json"], cwd=self.directory,
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)

    def test_portable_packaging_block_is_deterministic_and_uses_full_tree(self):
        root = self.directory / "Mullvad Browser"
        (root / "Browser").mkdir(parents=True)
        (root / "Browser/firefox.exe").write_bytes(b"MZfake")
        (root / "Browser/distribution").mkdir()
        (root / "Browser/distribution/preserved.txt").write_bytes(b"privacy settings")
        program = self.directory / "portable.py"
        program.write_text(added_block("PY_PGO_PORTABLE"))
        first, second = self.directory / "first.zip", self.directory / "second.zip"
        for path in [first, second]:
            result = subprocess.run([sys.executable, program, root.name, path, "1784727000"], cwd=self.directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(digest(first), digest(second))
        with zipfile.ZipFile(first) as archive:
            self.assertIn("Mullvad Browser/Browser/distribution/preserved.txt", archive.namelist())
            self.assertIn(b'"%~dp0Browser\\firefox.exe" %*', archive.read("Mullvad Browser/Start Mullvad Browser.cmd"))
        (root / "Browser/system-install").touch()
        bad = subprocess.run([sys.executable, program, root.name, second, "1784727000"], cwd=self.directory, capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)

    def test_exact_upstream_patch_application_when_fixture_available(self):
        fixture = Path(os.environ.get("PGO_UPSTREAM_FIXTURE", "/home/nixos/workspaces/tor-browser-build-study"))
        if not (fixture / "projects/firefox/build").exists():
            self.skipTest("exact pinned upstream fixture is not available")
        work = self.directory / "patch-study"
        for relative in ["projects/firefox/build", "projects/firefox/config", "projects/browser/build", "projects/browser/config", "projects/rust/build", "projects/rust/config"]:
            destination = work / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture / relative, destination)
        for name in ["firefox-pgo-generate.patch", "firefox-pgo-use.patch"]:
            patch = ROOT / "patches" / name
            check = subprocess.run(["git", "-C", work, "apply", "--check", patch], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            apply = subprocess.run(["git", "-C", work, "apply", patch], capture_output=True, text=True)
            self.assertEqual(apply.returncode, 0, apply.stderr)
        config = (work / "projects/browser/config").read_text()
        self.assertIn('!c("var/pgo_use")', config)
        self.assertIn("pgo_firefox_sha256", config)
        self.assertIn("--with-pgo-profile-path=/var/tmp/dist/pgo/merged.profdata", (work / "projects/firefox/build").read_text())

    def test_browser_stage_never_builds_firefox_and_selects_checksum_bound_input(self):
        self.assertEqual(self.snapshot().returncode, 0)
        project = self.directory / "overlay"
        for relative in ["scripts/run-pgo-use.sh", "scripts/collect-pgo-packages.py", "patches/firefox-pgo-use.patch", "upstream.lock.json"]:
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        (project / "scripts/profile-artifacts.py").write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n")
        upstream = self.directory / "upstream"
        (upstream / "rbm").mkdir(parents=True)
        (upstream / "projects/browser").mkdir(parents=True)
        packages = self.directory / "packages"
        packages.mkdir()
        (packages / "mullvad-browser-windows-x86_64-16.0a9.exe").write_bytes(b"MZinstaller")
        self.make_portable(packages / "mullvad-browser-windows-x86_64-portable-16.0a9.zip")
        rbm = upstream / "rbm/rbm"
        rbm.write_text("#!/usr/bin/env python3\nimport os, pathlib, shutil, sys\n"
                       "root=pathlib.Path(__file__).resolve().parents[1]\nargs=sys.argv[1:]\n"
                       "if args[0]=='showconf':\n"
                       " key=args[2]\n"
                       " values={'filename':'mullvad-browser-pgo-test','build_log':'logs/browser-windows-x86_64.log','version':'16.0a9','var/Project_Name':'Mullvad Browser','input_files':'local verified Firefox input','build':'rendered packaging'}\n"
                       " print('pgo-firefox-'+os.environ['PGO_FIREFOX_SHA256']+'.tar' if key=='input_files_by_name/firefox' else values[key])\n"
                       "else:\n"
                       " assert args[1]=='browser', 'attempted a heavy Firefox rebuild'\n"
                       " (root/'invocations').write_text(' '.join(args))\n"
                       " shutil.copytree(" + repr(str(packages)) + ",root/'out/browser/mullvad-browser-pgo-test')\n")
        rbm.chmod(0o755)
        runner = self.directory / "runner"
        (runner / "pgo-use").mkdir(parents=True)
        shutil.copytree(self.profile, runner / "pgo-use/profile")
        env = dict(os.environ, UPSTREAM=str(upstream), RUNNER_TEMP=str(runner), PGO_PROFILE_IDENTITY=self.identity,
                   PGO_FIREFOX_ARTIFACT_DIR=str(self.artifact))
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
        result = subprocess.run(["bash", project / "scripts/run-pgo-use.sh", "--stage", "browser"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((runner / "final-packages/packages.json").is_file())
        self.assertIn("build browser", (upstream / "invocations").read_text())
        inputs = list((upstream / "projects/browser").glob("pgo-firefox-*.tar"))
        self.assertEqual(len(inputs), 1)
        self.assertEqual(digest(inputs[0]), digest(self.artifact / "firefox-output.tar"))

    def test_stage_firefox_targets_selected_directory_and_reads_project_log(self):
        # Use repository scripts normally, with external RBM/profile helper stand-ins.
        project = self.directory / "overlay"
        for relative in ["scripts/run-pgo-use.sh", "scripts/collect-pgo-packages.py", "patches/firefox-pgo-use.patch", "upstream.lock.json"]:
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        validator = project / "scripts/profile-artifacts.py"
        validator.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n")
        upstream = self.directory / "upstream"
        (upstream / "rbm").mkdir(parents=True)
        selected = upstream / "out/firefox" / self.output.name
        selected.parent.mkdir(parents=True)
        # Another complete output must not be picked by find-first behavior.
        other = selected.parent / "firefox-wrong"
        shutil.copytree(self.output, other)
        rbm = upstream / "rbm/rbm"
        rbm.write_text("#!/usr/bin/env python3\nimport json, pathlib, shutil, sys\n"
                       "root=pathlib.Path(__file__).resolve().parents[1]\n"
                       "args=sys.argv[1:]\n"
                       "if args[0]=='showconf':\n"
                       " key=args[2]\n"
                       " print({'filename':" + repr(self.output.name) + ", 'build_log':'logs/firefox-windows-x86_64.log'}[key])\n"
                       "else:\n"
                       " shutil.copytree(" + repr(str(self.output)) + ",root/'out/firefox'/" + repr(self.output.name) + ")\n"
                       " (root/'logs').mkdir()\n"
                       " (root/'logs/firefox-windows-x86_64.log').write_text('--enable-profile-use=cross\\n-fprofile-use=/var/tmp/dist/pgo/merged.profdata\\nrustc -C profile-use=/var/tmp/dist/pgo/merged.profdata\\n')\n")
        rbm.chmod(0o755)
        runner = self.directory / "runner"
        (runner / "pgo-use").mkdir(parents=True)
        shutil.copytree(self.profile, runner / "pgo-use/profile")
        env = dict(os.environ, UPSTREAM=str(upstream), RUNNER_TEMP=str(runner), PGO_PROFILE_IDENTITY=self.identity)
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
        result = subprocess.run(["bash", project / "scripts/run-pgo-use.sh", "--stage", "firefox"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads((runner / "pgo-use/firefox-output.json").read_text())
        self.assertEqual(manifest["rbm_filename"], self.output.name)
        self.assertTrue((runner / "pgo-use/firefox-project.log").is_file())


if __name__ == "__main__":
    unittest.main()
