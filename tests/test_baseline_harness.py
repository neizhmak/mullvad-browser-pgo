#!/usr/bin/env python3
"""Lightweight native fixture tests; generated PE/PNG bytes are NOT a browser.

Production imports happen in this test program's own Python process. The fixture
uses real child processes and the existing PNG/workload/profile checks. It does
not bypass them or represent an actual baseline/PGO validation result.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import urlparse
from urllib.request import url2pathname
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("baseline_harness", ROOT / "scripts/check-baseline-harness.py")
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)
runtime = harness.runtime
LOCK = json.loads((ROOT / "upstream.lock.json").read_text())
VERSION = runtime.locked_version(LOCK)


def fake_browser_tree(directory):
    directory.mkdir(parents=True, exist_ok=True)
    names = ["firefox.exe", "xul.dll", "omni.ja", "browser/omni.ja", "updater.exe", "postupdate.exe", "uninstall.exe",
             "distribution/extensions/uBlock0@raymondhill.net.xpi",
             "distribution/extensions/{73a6fe31-595d-460b-a920-fcc0f8843232}.xpi",
             "distribution/extensions/{d19a89b9-76c1-4a61-bcd4-49e8de916403}.xpi"]
    for name in names:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"MZ native-test-fixture, not executable browser bytes")
    (directory / "system-install").write_text("")
    (directory / "application.ini").write_text("[App]\nName=MullvadBrowser\nVersion=153.0esr\nBuildID=20260101000000\n[AppUpdate]\nURL=https://cdn.mullvad.net/browser/update_responses/update_1/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL\n")
    (directory / "update-settings.ini").write_text("[Settings]\nACCEPTED_MAR_CHANNEL_IDS=mullvadbrowser-mullvad-alpha\n")
    runtime.write_json(directory / "version.json", {"version": VERSION, "channel": "alpha", "architecture": "windows-x86_64"})


def png_bytes(report):
    raw = json.dumps(report, separators=(",", ":")).encode("ascii")
    value = 2166136261
    for byte in raw:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    packet = b"MBPGO1" + struct.pack("<II", len(raw), value) + raw
    width, height = 600, 600
    rows = [bytearray([255]) * (width * 3) for _ in range(height)]
    for position in range(len(packet) * 8):
        if packet[position // 8] & (1 << (position % 8)):
            x, y = 8 + (position % 128) * 4 + 2, 8 + (position // 128) * 4 + 2
            rows[y][x * 3:x * 3 + 3] = b"\0\0\0"
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)
    pixels = b"".join(b"\0" + row for row in rows)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")


def fixture_main(argv):
    mode, behavior, *args = argv
    print("Native TEST fixture, not a real browser: " + mode, flush=True)
    if mode == "install":
        destination = Path(args[0])
        fake_browser_tree(destination)
        if behavior == "missing-uninstaller":
            (destination / "uninstall.exe").unlink()
        elif behavior == "bad-update-route":
            (destination / "update-settings.ini").write_text("[Settings]\nACCEPTED_MAR_CHANNEL_IDS=release\n")
        elif behavior == "partial-install":
            return 9
        return 0
    if mode == "uninstall":
        if behavior == "failed-uninstall":
            return 7
        shutil.rmtree(Path(args[0]))
        return 0
    if behavior == "nonzero":
        return 7
    if behavior == "hang":
        threading.Event().wait(60)
        return 0
    if behavior == "missing-screenshot":
        return 0
    assert all(flag in args for flag in ("--headless", "--offline", "--no-remote", "--new-instance", "--wait-for-browser", "--profile"))
    assert args[-1].startswith("file://")
    profile = Path(args[args.index("--profile") + 1])
    assert list(profile.iterdir()) == []
    page = Path(url2pathname(urlparse(args[-1]).path))
    config = json.loads(re.search(r"const config = (.*?);\n", page.read_text()).group(1))
    assert config["target_ms"] >= 1000
    counts = config["iterations"] or dict.fromkeys(runtime.CHECKSUMS, 8)
    report = {"schema": 1, "suite": runtime.SUITE, "nonce": config["nonce"], "mode": config["mode"],
              "workloads": {name: {"iterations": counts[name], "elapsed_ms": 1200,
                                    "unit_checksum": checksum,
                                    "digest": (checksum * (counts[name] * (counts[name] + 1) // 2)) & 0xffffffff}
                            for name, checksum in runtime.CHECKSUMS.items()}}
    if behavior == "bad-nonce":
        report["nonce"] = "not-the-private-nonce"
    elif behavior == "bad-checksum":
        report["workloads"]["integer-array"]["unit_checksum"] = 0
    elif behavior == "js-error":
        report["error"] = "fixture JavaScript error"
    elif behavior == "unmeasurable":
        report["workloads"]["integer-array"]["elapsed_ms"] = 0
    Path(args[args.index("--screenshot") + 1]).write_bytes(png_bytes(report))
    return 0


class BaselineHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.baseline = self.prepared_baseline()
        self.args = argparse.Namespace(baseline_directory=self.baseline, output_directory=self.root / "output",
                                       upstream_lock=ROOT / "upstream.lock.json", samples=1, target_milliseconds=1200,
                                       browser_timeout_seconds=5, installer_timeout_seconds=5)
        self.native_commands = []
        self.work = self.root / "disposable-work"

    def tearDown(self):
        self.temp.cleanup()

    def prepared_baseline(self):
        baseline = self.root / "baseline"
        archive = self.root / "input.zip"
        name = f"browser-cache/mullvad-browser-windows-x86_64-{VERSION}.exe"
        with zipfile.ZipFile(archive, "w") as out:
            out.writestr(name, b"MZ test baseline installer")
        head = "a" * 40
        repository = runtime.DEFAULT_REPOSITORY
        run = {"id": runtime.BASELINE_RUN, "status": "completed", "conclusion": "success", "head_sha": head,
               "repository": {"full_name": repository}}
        artifact = {"id": 123, "name": runtime.BASELINE_ARTIFACT, "expired": False,
                    "workflow_run": {"id": runtime.BASELINE_RUN, "head_sha": head},
                    "digest": "sha256:" + runtime.sha256(archive),
                    "archive_download_url": f"https://api.github.com/repos/{repository}/actions/artifacts/123/zip"}
        raw = json.dumps(LOCK).encode()
        source = {"path": "upstream.lock.json", "type": "file", "encoding": "base64", "content": base64.b64encode(raw).decode(),
                  "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), "size": len(raw),
                  "html_url": f"https://github.com/{repository}/blob/{head}/upstream.lock.json",
                  "download_url": f"https://raw.githubusercontent.com/{repository}/{head}/upstream.lock.json"}
        paths = [self.root / name for name in ("input-run.json", "input-artifact.json", "input-source.json")]
        for path, value in zip(paths, (run, artifact, source)):
            runtime.write_json(path, value)
        args = argparse.Namespace(output_directory=baseline, repository=repository, upstream_lock=ROOT / "upstream.lock.json",
                                  artifact_archive=archive, run_metadata=paths[0], artifact_metadata=paths[1], source_lock=paths[2],
                                  timeout_seconds=5)
        runtime.prepare_baseline(args)
        return baseline

    def run_fixture(self, *, browser="pass", installer="pass", uninstall="pass", registry=None):
        original_native, original_browser = runtime.run_native, runtime.browser_command
        def native(command, *args, **kwargs):
            self.native_commands.append(command)
            if isinstance(command, list) and Path(command[0]).name == "uninstall.exe":
                command = [sys.executable, str(Path(__file__).resolve()), "--fixture", "uninstall", uninstall, str(self.work / "baseline-install")]
            return original_native(command, *args, **kwargs)
        def mkdtemp(**kwargs):
            self.work.mkdir()
            return str(self.work)
        with mock.patch.object(runtime, "require_windows"), \
             mock.patch.object(runtime, "reject_existing_install", side_effect=registry) as reject, \
             mock.patch.object(harness.tempfile, "mkdtemp", side_effect=mkdtemp), \
             mock.patch.object(runtime, "installer_command", side_effect=lambda binary, destination: [sys.executable, str(Path(__file__).resolve()), "--fixture", "install", installer, str(destination)]), \
             mock.patch.object(runtime, "browser_command", side_effect=lambda binary, profile, image, page: [sys.executable, str(Path(__file__).resolve()), "--fixture", "browser", browser] + original_browser(binary, profile, image, page)[1:]), \
             mock.patch.object(runtime, "run_native", side_effect=native):
            report = harness.run_smoke(self.args)
        return report, reject.call_count

    def report(self):
        return runtime.read_json(self.args.output_directory / harness.REPORT_NAME)

    def assert_failure_cleanup(self):
        report = self.report()
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["baseline_only"])
        self.assertFalse(report["validated_pipeline"])
        self.assertFalse(any(self.args.output_directory.glob("*/profile")))
        self.assertFalse(self.work.exists())
        return report

    def test_success_runs_real_native_calibration_and_one_fixed_count_sample(self):
        report, registry_calls = self.run_fixture()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["baseline_only"])
        self.assertFalse(report["validated_pipeline"])
        self.assertFalse(report["default_preferences_modified"])
        self.assertFalse(report["timer_preferences_modified"])
        self.assertEqual(registry_calls, 2)
        self.assertEqual(len(self.native_commands), 4)
        self.assertEqual(len(report["samples"]), 1)
        self.assertEqual(report["calibration"]["mode"], "calibrate")
        self.assertEqual(report["samples"][0]["mode"], "measure")
        self.assertEqual(runtime.validate_workloads(report["samples"][0]), report["iterations"])
        self.assertTrue(report["cleanup"][0]["uninstalled"])
        self.assertTrue(report["registry_cleanup_verified"])
        self.assertTrue(report["temporary_cleanup_verified"])
        self.assertTrue(report["profiles_removed"])
        self.assertFalse(self.work.exists())
        for label in ("calibration-baseline", "sample-01-baseline"):
            directory = self.args.output_directory / label
            self.assertTrue((directory / "screenshot.png").is_file())
            self.assertTrue((directory / "result.json").is_file())
            self.assertTrue((directory / "browser.log.json").is_file())
            self.assertFalse((directory / "profile").exists())
        self.assertFalse((self.args.output_directory / "packages.json").exists())
        self.assertEqual(runtime.verify_baseline(self.baseline, LOCK)[0]["run_id"], runtime.BASELINE_RUN)

    def test_optional_three_samples_have_the_same_calibrated_counts(self):
        self.args.samples = 3
        report, _ = self.run_fixture()
        self.assertEqual(len(report["samples"]), 3)
        self.assertEqual(len(self.native_commands), 6)
        for sample in report["samples"]:
            self.assertEqual(runtime.validate_workloads(sample), report["iterations"])

    def test_untrusted_provenance_never_executes_any_native_command(self):
        original = {name: (self.baseline / name).read_bytes() for name in ("artifact.zip", "run.json", "source-lock.json")}
        for case in ("archive-digest", "known-run", "committed-lock"):
            with self.subTest(case=case):
                for name, data in original.items():
                    (self.baseline / name).write_bytes(data)
                if case == "archive-digest":
                    (self.baseline / "artifact.zip").write_bytes(b"not-the-authenticated-archive")
                elif case == "known-run":
                    run = runtime.read_json(self.baseline / "run.json"); run["id"] += 1
                    runtime.write_json(self.baseline / "run.json", run)
                else:
                    source = runtime.read_json(self.baseline / "source-lock.json"); source["sha"] = "0" * 40
                    runtime.write_json(self.baseline / "source-lock.json", source)
                self.args.output_directory = self.root / case
                with self.assertRaises(runtime.CheckError):
                    self.run_fixture()
                self.assert_failure_cleanup()
                self.assertEqual(self.native_commands, [])

    def test_existing_installation_is_not_uninstalled_or_modified(self):
        user_data = self.root / "existing-user-data"; user_data.mkdir()
        (user_data / "prefs.js").write_text("existing preferences")
        with self.assertRaisesRegex(runtime.CheckError, "pre-existing"):
            self.run_fixture(registry=[runtime.CheckError("pre-existing installation")])
        self.assert_failure_cleanup()
        self.assertEqual(self.native_commands, [])
        self.assertEqual((user_data / "prefs.js").read_text(), "existing preferences")

    def test_png_nonce_and_javascript_validation_fail_with_logs_and_cleanup(self):
        for behavior in ("bad-nonce", "bad-checksum", "js-error", "unmeasurable", "missing-screenshot", "nonzero"):
            with self.subTest(behavior=behavior):
                self.args.output_directory = self.root / behavior
                with self.assertRaises(runtime.CheckError):
                    self.run_fixture(browser=behavior)
                report = self.assert_failure_cleanup()
                self.assertTrue(report["cleanup"][0]["uninstalled"])
                self.assertTrue(report["registry_cleanup_verified"])
                self.assertTrue((self.args.output_directory / "calibration-baseline/browser.log.json").is_file())
                if behavior not in ("missing-screenshot", "nonzero"):
                    self.assertTrue((self.args.output_directory / "calibration-baseline/screenshot.png").is_file())

    def test_native_browser_timeout_cleans_profile_and_uninstalls(self):
        self.args.browser_timeout_seconds = 0.2
        with self.assertRaises(runtime.NativeError) as raised:
            self.run_fixture(browser="hang")
        self.assertEqual(raised.exception.returncode, 124)
        report = self.assert_failure_cleanup()
        native = runtime.read_json(self.args.output_directory / "calibration-baseline/browser.log.json")
        self.assertTrue(native["timed_out"])
        self.assertTrue(report["cleanup"][0]["uninstalled"])

    def test_install_failure_still_runs_actual_uninstaller(self):
        with self.assertRaises(runtime.NativeError) as raised:
            self.run_fixture(installer="partial-install")
        self.assertEqual(raised.exception.returncode, 9)
        report = self.assert_failure_cleanup()
        self.assertTrue(report["cleanup"][0]["uninstalled"])
        self.assertNotIn("calibration", report)
        self.assertEqual(len(self.native_commands), 2)

    def test_secure_alpha_tree_must_pass_before_browser_launch(self):
        with self.assertRaisesRegex(runtime.CheckError, "signed Mullvad Alpha"):
            self.run_fixture(installer="bad-update-route")
        self.assert_failure_cleanup()
        self.assertEqual(len(self.native_commands), 2)
        self.assertFalse((self.args.output_directory / "calibration-baseline").exists())

    def test_missing_uninstaller_cannot_report_pass(self):
        with self.assertRaisesRegex(runtime.CheckError, "uninstaller"):
            self.run_fixture(installer="missing-uninstaller")
        report = self.assert_failure_cleanup()
        self.assertFalse(report["cleanup"][0]["uninstalled"])

    def test_uninstaller_native_failure_cannot_report_pass(self):
        with self.assertRaises(runtime.NativeError) as raised:
            self.run_fixture(uninstall="failed-uninstall")
        self.assertEqual(raised.exception.returncode, 7)
        report = self.assert_failure_cleanup()
        self.assertEqual(len(report["samples"]), 1)
        self.assertFalse(report["cleanup"][0]["uninstalled"])

    def test_registry_cleanup_failure_cannot_report_pass(self):
        with self.assertRaisesRegex(runtime.CheckError, "registration remains"):
            self.run_fixture(registry=[None, runtime.CheckError("registration remains")])
        report = self.assert_failure_cleanup()
        self.assertFalse(report["registry_cleanup_verified"])
        self.assertTrue(report["cleanup"][0]["uninstalled"])

    def test_stale_output_is_not_overwritten(self):
        self.args.output_directory.mkdir()
        marker = self.args.output_directory / harness.REPORT_NAME
        marker.write_text("existing diagnostic report")
        with self.assertRaisesRegex(runtime.CheckError, "stale"):
            self.run_fixture()
        self.assertEqual(marker.read_text(), "existing diagnostic report")
        self.assertEqual(self.native_commands, [])

    def test_cli_help_and_argument_bounds(self):
        cli = ROOT / "scripts/check-baseline-harness.py"
        help_result = subprocess.run([sys.executable, str(cli), "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("verified stock baseline", " ".join(help_result.stdout.split()))
        for args in (["--samples", "4"], ["--samples", "0"], ["--target-milliseconds", "999"]):
            result = subprocess.run([sys.executable, str(cli)] + args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(self.args.output_directory.exists())

    @unittest.skipIf(os.name == "nt", "real platform guard requires a non-Windows runner")
    def test_real_cli_rejects_non_windows_and_preserves_status_report(self):
        command = [sys.executable, str(ROOT / "scripts/check-baseline-harness.py"),
                   "--baseline-directory", str(self.baseline), "--output-directory", str(self.args.output_directory)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("64-bit Windows", result.stderr)
        report = self.assert_failure_cleanup()
        self.assertNotIn("baseline", report)
        self.assertNotIn("calibration", report)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture":
        raise SystemExit(fixture_main(sys.argv[2:]))
    unittest.main()
