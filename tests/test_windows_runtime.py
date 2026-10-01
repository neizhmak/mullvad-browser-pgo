#!/usr/bin/env python3
"""Stdlib tests. Fake programs run as real native subprocesses, not browsers."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_runtime", ROOT / "scripts/windows-runtime-check.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
LOCK = json.loads((ROOT / "upstream.lock.json").read_text())
VERSION = runtime.locked_version(LOCK)
REPOSITORY = runtime.DEFAULT_REPOSITORY
HEAD = "a" * 40


def png_bytes(report, color=2, filter_mode=0):
    data = json.dumps(report, separators=(",", ":")).encode("ascii")
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    packet = b"MBPGO1" + struct.pack("<II", len(data), value) + data
    width, height, channels = 600, 600, 3 if color == 2 else 4
    rows = [bytearray([255]) * (width * channels) for _ in range(height)]
    for position in range(len(packet) * 8):
        if packet[position // 8] & (1 << (position % 8)):
            x, y = 8 + (position % 128) * 4 + 2, 8 + (position // 128) * 4 + 2
            rows[y][x * channels:x * channels + 3] = b"\0\0\0"
    raw = bytearray()
    previous = bytearray(width * channels)
    def paeth(a, b, c):
        p = a + b - c
        ds = [abs(p - a), abs(p - b), abs(p - c)]
        return (a, b, c)[ds.index(min(ds))]
    for row in rows:
        raw.append(filter_mode)
        if not filter_mode:
            raw.extend(row)
        else:
            for x, byte in enumerate(row):
                a = row[x - channels] if x >= channels else 0
                b = previous[x]
                c = previous[x - channels] if x >= channels else 0
                delta = a if filter_mode == 1 else b if filter_mode == 2 else (a + b) // 2 if filter_mode == 3 else paeth(a, b, c)
                raw.append((byte - delta) & 255)
        previous = row
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def result(nonce="nonce", iterations=None, elapsed=1200, mode="measure"):
    iterations = iterations or dict.fromkeys(runtime.CHECKSUMS, 8)
    return {"schema": 1, "suite": runtime.SUITE, "nonce": nonce, "mode": mode,
            "workloads": {name: {"iterations": iterations[name], "elapsed_ms": elapsed,
                                 "unit_checksum": value, "digest": (value * (iterations[name] * (iterations[name] + 1) // 2)) & 0xffffffff}
                          for name, value in runtime.CHECKSUMS.items()}}


def origin(archive):
    run = {"id": runtime.BASELINE_RUN, "status": "completed", "conclusion": "success", "head_sha": HEAD,
           "repository": {"full_name": REPOSITORY}}
    artifact = {"id": 123, "name": runtime.BASELINE_ARTIFACT, "expired": False,
                "workflow_run": {"id": runtime.BASELINE_RUN, "head_sha": HEAD},
                "digest": "sha256:" + runtime.sha256(archive),
                "archive_download_url": f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/123/zip"}
    raw = json.dumps(LOCK).encode()
    source = {"path": "upstream.lock.json", "type": "file", "encoding": "base64", "content": base64.b64encode(raw).decode(),
              "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), "size": len(raw),
              "html_url": f"https://github.com/{REPOSITORY}/blob/{HEAD}/upstream.lock.json",
              "download_url": f"https://raw.githubusercontent.com/{REPOSITORY}/{HEAD}/upstream.lock.json"}
    return run, artifact, source


def browser_tree(directory, portable=False):
    directory.mkdir(parents=True, exist_ok=True)
    files = ["mullvadbrowser.exe", "xul.dll", "omni.ja", "browser/omni.ja", "updater.exe", "postupdate.exe",
             "distribution/extensions/uBlock0@raymondhill.net.xpi",
             "distribution/extensions/{73a6fe31-595d-460b-a920-fcc0f8843232}.xpi",
             "distribution/extensions/{d19a89b9-76c1-4a61-bcd4-49e8de916403}.xpi"]
    for name in files:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"MZ fake package bytes")
    (directory / "application.ini").write_text("[App]\nName=MullvadBrowser\nVersion=153.0esr\nBuildID=20260101000000\n[AppUpdate]\nURL=https://cdn.mullvad.net/browser/update_responses/update_1/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL\n")
    (directory / "update-settings.ini").write_text("[Settings]\nACCEPTED_MAR_CHANNEL_IDS=mullvadbrowser-mullvad-alpha\n")
    runtime.write_json(directory / "version.json", {"version": VERSION, "channel": "alpha", "architecture": "windows-x86_64"})
    if not portable:
        (directory / "system-install").write_text("")


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, name="artifact.zip", member=None):
        archive = self.root / name
        with zipfile.ZipFile(archive, "w") as out:
            out.writestr(member or f"browser-cache/mullvad-browser-windows-x86_64-{VERSION}.exe", b"MZ baseline bytes")
        return archive

    def prepared_baseline(self, destination=None):
        archive = self.archive()
        run, artifact, source = origin(archive)
        inputs = [self.root / name for name in ("run.json", "artifact.json", "source.json")]
        for path, value in zip(inputs, (run, artifact, source)):
            runtime.write_json(path, value)
        lock = self.root / "lock.json"
        runtime.write_json(lock, LOCK)
        args = argparse.Namespace(output_directory=destination or self.root / "baseline", repository=REPOSITORY,
                                  upstream_lock=lock, timeout_seconds=5, artifact_archive=archive,
                                  run_metadata=inputs[0], artifact_metadata=inputs[1], source_lock=inputs[2])
        runtime.prepare_baseline(args)
        return args.output_directory, args

    def package_fixture(self):
        packages = self.root / "final"
        packages.mkdir()
        tree = self.root / "tree" / "Mullvad Browser"
        browser_tree(tree / "Browser", portable=True)
        (tree / "Start Mullvad Browser.cmd").write_bytes(b'@echo off\r\n"%~dp0Browser\\mullvadbrowser.exe" %*\r\n')
        installer = packages / f"mullvad-browser-windows-x86_64-{VERSION}.exe"
        installer.write_bytes(b"MZ installer bytes")
        portable = packages / f"mullvad-browser-windows-x86_64-portable-{VERSION}.zip"
        with zipfile.ZipFile(portable, "w") as out:
            for path in tree.rglob("*"):
                if path.is_file():
                    out.write(path, path.relative_to(tree.parent).as_posix())
        assets = [{"kind": kind, "filename": path.name, "size": path.stat().st_size, "sha256": runtime.sha256(path)}
                  for kind, path in (("installer", installer), ("portable", portable))]
        identity = "c" * 64
        manifest = {"schema": 1, "kind": "unofficial-mullvad-windows-alpha-pgo", "version": VERSION, "channel": "alpha",
                    "platform": "windows-x86_64", "upstream_lock": LOCK, "public_browser_release": False, "profile_identity": identity,
                    "browser_executable": "mullvadbrowser.exe",
                    "firefox": {"upstream_lock": LOCK, "profile_identity": identity,
                                "proof": {"executable": "mullvadbrowser.exe", "substs": {"MOZ_PROFILE_USE": True, "MOZ_PGO_RUST": True, "MOZ_PROFILE_GENERATE": False}}},
                    "portable_layout": {"root": "Mullvad Browser", "launcher": "Start Mullvad Browser.cmd", "executable": "Browser/mullvadbrowser.exe",
                                        "portable_detection": "absence of Browser/system-install", "complete_browser_tree": True}, "assets": assets}
        runtime.write_json(packages / "packages.json", manifest)
        return packages, manifest, tree

    def fake_browser(self, behavior="pass"):
        path = self.root / ("fake-browser-" + behavior + ".py")
        # Helpers are copied into the fake native program, not imported from the
        # production helper inside the kernel. It genuinely emits a PNG file.
        helpers = Path(__file__).read_text().split("def png_bytes(", 1)[1].split("def origin(", 1)[0]
        code = "import json,struct,zlib,re,sys\nfrom pathlib import Path\n"
        code += "class Runtime: pass\nruntime=Runtime()\nruntime.CHECKSUMS=" + repr(runtime.CHECKSUMS) + "\nruntime.SUITE=" + repr(runtime.SUITE) + "\n"
        code += "def png_bytes(" + helpers
        code += "print('fake native browser stdout', flush=True)\nprint('fake native browser stderr', file=sys.stderr, flush=True)\n"
        code += "args=sys.argv[1:]\nscreenshot=Path(args[args.index('--screenshot')+1])\n"
        code += "from urllib.parse import urlparse\nfrom urllib.request import url2pathname\npage=Path(url2pathname(urlparse(args[-1]).path))\n"
        code += "config=json.loads(re.search(r'const config = (.*?);\\n',page.read_text()).group(1))\n"
        code += "report=result(config['nonce'],config['iterations'] or None,mode=config['mode'])\n"
        if behavior == "bad-nonce":
            code += "report['nonce']='wrong'\n"
        elif behavior == "bad-checksum":
            code += "report['workloads']['integer-array']['unit_checksum']=0\n"
        elif behavior == "nonzero":
            code += "sys.exit(7)\n"
        elif behavior == "hang":
            code += "import time\ntime.sleep(60)\n"
        code += "screenshot.write_bytes(png_bytes(report))\n"
        path.write_text(code)
        return path

    def patched_browser(self, program):
        original = runtime.browser_command
        return mock.patch.object(runtime, "browser_command", side_effect=lambda binary, profile, image, page: [sys.executable, str(program)] + original(binary, profile, image, page)[1:])

    def test_verified_packages_match_collector_contract(self):
        packages, expected, _ = self.package_fixture()
        actual, assets = runtime.verify_packages(packages, LOCK)
        self.assertEqual(actual, expected)
        self.assertEqual(set(assets), {"installer", "portable"})

    def test_package_checksum_fails_before_native_execution(self):
        packages, manifest, _ = self.package_fixture()
        (packages / manifest["assets"][0]["filename"]).write_bytes(b"MZ corrupt bytes")
        with self.assertRaisesRegex(runtime.CheckError, "SHA-256 mismatch"):
            runtime.verify_packages(packages, LOCK)

    def test_package_identity_rejects_wrong_lock_public_release_or_rust(self):
        packages, original, _ = self.package_fixture()
        variants = []
        for field, value in (("channel", "release"), ("public_browser_release", True), ("schema", True),
                             ("browser_executable", "firefox.exe"), ("browser_executable", None)):
            item = copy.deepcopy(original); item[field] = value; variants.append(item)
        item = copy.deepcopy(original); item["upstream_lock"] = {}; variants.append(item)
        item = copy.deepcopy(original); item["firefox"]["proof"]["substs"]["MOZ_PGO_RUST"] = False; variants.append(item)
        item = copy.deepcopy(original); item["firefox"]["proof"]["executable"] = "firefox.exe"; variants.append(item)
        for manifest in variants:
            with self.subTest(manifest=manifest):
                runtime.write_json(packages / "packages.json", manifest)
                with self.assertRaises(runtime.CheckError):
                    runtime.verify_packages(packages, LOCK)

    def test_size_boolean_and_symlink_records_rejected(self):
        path = self.root / "installer.exe"; path.write_bytes(b"MZ")
        record = {"filename": path.name, "size": True, "sha256": runtime.sha256(path)}
        with self.assertRaises(runtime.CheckError):
            runtime.checked_file(self.root, record)
        if os.name != "nt":
            link = self.root / "link.exe"; link.symlink_to(path)
            with self.assertRaises(runtime.CheckError):
                runtime.checked_file(self.root, dict(record, filename=link.name, size=2))

    def test_windows_paths_reject_traversal_devices_and_ambiguous_names(self):
        for name in ("../evil", "/absolute", "C:/evil", "a\\b", "a/../b", "./a", "a//b", "NUL.exe", "a/CON", "a.", "a ", "a\n", 'a"b', "a?b", "a|b", "a*b", "a<b"):
            with self.subTest(name=name), self.assertRaises(runtime.CheckError):
                runtime.safe_path(name)

    def test_zip_rejects_traversal_before_any_write(self):
        archive = self.archive(member="../evil")
        destination = self.root / "extract"
        with self.assertRaises(runtime.CheckError):
            runtime.safe_extract_zip(archive, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_zip_rejects_case_collisions_symlinks_and_file_parents(self):
        for kind in ("case", "symlink", "parent"):
            archive = self.root / (kind + ".zip")
            with zipfile.ZipFile(archive, "w") as out:
                if kind == "case":
                    out.writestr("A", b"a"); out.writestr("a", b"b")
                elif kind == "symlink":
                    info = zipfile.ZipInfo("link"); info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    out.writestr(info, b"target")
                else:
                    out.writestr("a", b"file"); out.writestr("a/b", b"nested")
            with self.subTest(kind=kind), self.assertRaises(runtime.CheckError):
                runtime.safe_extract_zip(archive, self.root / (kind + "-out"))

    def test_zip_refuses_stale_destination(self):
        destination = self.root / "out"; destination.mkdir(); (destination / "stale").write_text("x")
        with self.assertRaisesRegex(runtime.CheckError, "nonempty"):
            runtime.safe_extract_zip(self.archive(), destination)

    def test_baseline_preparation_and_archive_binding(self):
        directory, _ = self.prepared_baseline()
        manifest, installer = runtime.verify_baseline(directory, LOCK)
        self.assertEqual(manifest["run_id"], runtime.BASELINE_RUN)
        self.assertEqual(installer.read_bytes(), b"MZ baseline bytes")

    def test_baseline_preparation_wrong_digest_never_extracts(self):
        archive = self.archive()
        run, artifact, source = origin(archive)
        artifact["digest"] = "sha256:" + "0" * 64
        files = [self.root / name for name in ("run.json", "artifact.json", "source.json", "lock.json")]
        for path, value in zip(files, (run, artifact, source, LOCK)):
            runtime.write_json(path, value)
        args = argparse.Namespace(output_directory=self.root / "out", upstream_lock=files[3], repository=REPOSITORY,
                                  artifact_archive=archive, run_metadata=files[0], artifact_metadata=files[1], source_lock=files[2], timeout_seconds=5)
        with self.assertRaisesRegex(runtime.CheckError, "not extracting"):
            runtime.prepare_baseline(args)
        self.assertFalse((args.output_directory / "packages").exists())

    def test_baseline_origin_rejects_wrong_run_artifact_or_detached_lock(self):
        original = origin(self.archive())
        changes = [(0, "conclusion", "failure"), (0, "id", runtime.BASELINE_RUN + 1), (1, "name", "other"),
                   (1, "expired", True), (1, "digest", None), (2, "download_url", "https://raw.githubusercontent.com/other/main/upstream.lock.json"),
                   (2, "sha", "0" * 40)]
        for index, key, value in changes:
            values = copy.deepcopy(original); values[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(runtime.CheckError):
                runtime.validate_baseline_origin(*values, LOCK, REPOSITORY)
        values = copy.deepcopy(original); values[1]["workflow_run"]["head_sha"] = "b" * 40
        with self.assertRaises(runtime.CheckError):
            runtime.validate_baseline_origin(*values, LOCK, REPOSITORY)
        with self.assertRaises(runtime.CheckError):
            runtime.validate_baseline_origin(*original, dict(LOCK, commit="b" * 40), REPOSITORY)

    def test_baseline_cannot_forge_inventory_for_different_installer_bytes(self):
        directory, _ = self.prepared_baseline()
        manifest = runtime.read_json(directory / "baseline.json")
        installer = directory / manifest["installer"]["filename"]
        installer.write_bytes(b"MZ substituted")
        manifest["installer"].update(size=installer.stat().st_size, sha256=runtime.sha256(installer))
        runtime.write_json(directory / "baseline.json", manifest)
        with self.assertRaisesRegex(runtime.CheckError, "authenticated archive"):
            runtime.verify_baseline(directory, LOCK)

    def test_baseline_archive_tamper_and_stale_prep_fail(self):
        directory, args = self.prepared_baseline()
        (directory / "artifact.zip").write_bytes(b"wrong")
        with self.assertRaisesRegex(runtime.CheckError, "archive SHA"):
            runtime.verify_baseline(directory, LOCK)
        with self.assertRaisesRegex(runtime.CheckError, "stale"):
            runtime.prepare_baseline(args)

    def test_png_decode_rgb_rgba_and_filters(self):
        for color, mode in ((2, 0), (6, 1), (2, 2), (2, 3), (6, 4)):
            path = self.root / "screenshot.png"; path.write_bytes(png_bytes(result(), color, mode))
            with self.subTest(color=color, mode=mode):
                report = runtime.screenshot_report(path, "nonce")
                self.assertEqual(runtime.validate_workloads(report), dict.fromkeys(runtime.CHECKSUMS, 8))

    def test_png_rejects_crc_nonce_error_and_missing_payload(self):
        path = self.root / "screenshot.png"
        raw = bytearray(png_bytes(result())); raw[40] ^= 1; path.write_bytes(raw)
        with self.assertRaisesRegex(runtime.CheckError, "checksum"):
            runtime.screenshot_report(path, "nonce")
        path.write_bytes(png_bytes(result()))
        with self.assertRaisesRegex(runtime.CheckError, "identity"):
            runtime.screenshot_report(path, "other")
        path.write_bytes(png_bytes({"schema": 1, "suite": runtime.SUITE, "nonce": "nonce", "error": "JavaScript failed"}))
        with self.assertRaisesRegex(runtime.CheckError, "JavaScript failed"):
            runtime.screenshot_report(path, "nonce")
        path.write_bytes(b"not png")
        with self.assertRaisesRegex(runtime.CheckError, "invalid"):
            runtime.screenshot_report(path, "nonce")

    def test_workloads_reject_wrong_checksum_digest_iterations_or_zero_timer(self):
        for key, value in (("elapsed_ms", 0), ("elapsed_ms", float("nan")), ("unit_checksum", 0), ("digest", 0), ("iterations", True)):
            report = result(); report["workloads"]["integer-array"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(runtime.CheckError):
                runtime.validate_workloads(report)
        with self.assertRaises(runtime.CheckError):
            runtime.validate_workloads(result(), dict.fromkeys(runtime.CHECKSUMS, 9))

    def test_native_nonzero_keeps_stdout_stderr_and_exact_status(self):
        log = self.root / "native.log"
        with self.assertRaises(runtime.NativeError) as caught:
            runtime.run_native([sys.executable, "-c", "import sys; print('stdout'); print('stderr',file=sys.stderr); sys.exit(7)"], log, 5)
        self.assertEqual(caught.exception.returncode, 7)
        self.assertIn("stdout", log.read_text()); self.assertIn("stderr", log.read_text())
        metadata = runtime.read_json(log.with_suffix(".log.json"))
        self.assertEqual(metadata["returncode"], 7)
        self.assertEqual(metadata["root_returncode"], 7)
        self.assertEqual(metadata["phase"], "completed")
        self.assertIsNone(metadata["timeout_phase"])

    def test_native_environment_overrides_inherit_without_leaking_or_mutating(self):
        log, output = self.root / "environment.log", self.root / "environment.json"
        program = "import os,json; print(json.dumps({k:os.environ.get(k) for k in ('MB_PARENT','MB_CHILD','MB_UNICODE')}))"
        with mock.patch.dict(os.environ, {"MB_PARENT": "inherited-parent"}, clear=False):
            metadata = runtime.run_native([sys.executable, "-c", program], log, 10, stdout_file=output,
                                          env={"MB_CHILD": "opaque-secret-value", "MB_UNICODE": "Mullvad-\u043f\u0440\u0438\u0432\u0430\u0442\u043d\u043e"})
            self.assertNotIn("MB_CHILD", os.environ)
        observed = runtime.read_json(output)
        self.assertEqual(observed, {"MB_PARENT": "inherited-parent", "MB_CHILD": "opaque-secret-value", "MB_UNICODE": "Mullvad-\u043f\u0440\u0438\u0432\u0430\u0442\u043d\u043e"})
        self.assertNotIn("opaque-secret-value", json.dumps(metadata))
        self.assertNotIn("opaque-secret-value", log.with_suffix(".log.json").read_text())
        self.assertNotIn("env", metadata)
        self.assertEqual(metadata["root_returncode"], 0)
        self.assertEqual(metadata["phase"], "completed")
        self.assertIsNone(metadata["timeout_phase"])
        if os.name == "nt":
            self.assertEqual(metadata["active_job_process_count"], 0)

    def test_native_none_environment_is_inherited_unchanged(self):
        output = self.root / "inherited.txt"
        with mock.patch.dict(os.environ, {"MB_INHERITED": "present-in-child"}, clear=False):
            runtime.run_native([sys.executable, "-c", "import os; print(os.environ.get('MB_INHERITED'))"],
                               self.root / "inherited.log", 10, stdout_file=output)
        self.assertEqual(output.read_text().strip(), "present-in-child")

    def test_native_timeout_bounds_tree_and_preserves_diagnostics(self):
        log = self.root / "timeout.log"
        program = "import subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print(child.pid,flush=True); time.sleep(60)"
        with self.assertRaises(runtime.NativeError) as caught:
            runtime.run_native([sys.executable, "-c", program], log, 1.5)
        self.assertEqual(caught.exception.returncode, 124)
        metadata = runtime.read_json(log.with_suffix(".log.json"))
        self.assertTrue(metadata["timed_out"])
        self.assertEqual(metadata["phase"], "timed_out")
        self.assertEqual(metadata["timeout_phase"], "root_wait")
        self.assertIsNone(metadata["root_returncode"])
        if os.name == "nt":
            self.assertGreaterEqual(metadata["active_job_process_count"], 1)
        if os.name != "nt":
            pid = log.read_text().strip()
            status = Path("/proc") / pid / "status"
            if status.exists():
                self.assertIn("Z (zombie)", status.read_text())
        else:
            import _winapi
            try:
                handle = _winapi.OpenProcess(0x1000, False, int(log.read_text().strip()))
            except OSError:
                pass  # A reaped descendant has no process handle.
            else:
                try:
                    self.assertNotEqual(_winapi.GetExitCodeProcess(handle), 259)  # STILL_ACTIVE
                finally:
                    _winapi.CloseHandle(handle)

    @unittest.skipUnless(os.name == "nt", "Windows job-drain metadata before kill-on-close")
    def test_windows_descendant_timeout_records_successful_root_before_kill(self):
        log = self.root / "descendant-timeout.log"
        program = "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print(p.pid,flush=True)"
        with self.assertRaises(runtime.NativeError) as caught:
            runtime.run_native([sys.executable, "-c", program], log, 1.5)
        self.assertEqual(caught.exception.returncode, 124)
        metadata = runtime.read_json(log.with_suffix(".log.json"))
        self.assertTrue(metadata["timed_out"])
        self.assertEqual(metadata["phase"], "timed_out")
        self.assertEqual(metadata["timeout_phase"], "job_drain")
        self.assertEqual(metadata["root_returncode"], 0)
        self.assertGreaterEqual(metadata["active_job_process_count"], 1)
        import _winapi
        try:
            handle = _winapi.OpenProcess(0x101000, False, int(log.read_text().strip()))
        except OSError:
            pass  # A reaped descendant no longer has a process handle.
        else:
            try:
                self.assertEqual(_winapi.WaitForSingleObject(handle, 5000), _winapi.WAIT_OBJECT_0)
                self.assertNotEqual(_winapi.GetExitCodeProcess(handle), 259)
            finally:
                _winapi.CloseHandle(handle)

    def test_native_binary_stdout_separate_from_stderr(self):
        binary, log = self.root / "archive.bin", self.root / "native.log"
        runtime.run_native([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'PK\\x00\\xff'); print('diagnostic',file=sys.stderr)"], log, 5, stdout_file=binary)
        self.assertEqual(binary.read_bytes(), b"PK\0\xff")
        self.assertIn("diagnostic", log.read_text())

    @unittest.skipUnless(os.name == "nt", "Windows native DWORD and ExitProcess contract")
    def test_windows_high_bit_native_status_is_not_truncated(self):
        log = self.root / "exception.log"
        code = "import ctypes; ctypes.WinDLL('kernel32').ExitProcess(ctypes.c_uint32(0xC0000005))"
        with self.assertRaises(runtime.NativeError) as caught:
            runtime.run_native([sys.executable, "-c", code], log, 10)
        self.assertEqual(caught.exception.returncode, 0xC0000005)
        self.assertEqual(runtime.read_json(log.with_suffix(".log.json"))["returncode"], 0xC0000005)
        load = "import importlib.util; s=importlib.util.spec_from_file_location('check'," + repr(str(ROOT / "scripts/windows-runtime-check.py")) + "); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.exit_process(0xC0000005)"
        with self.assertRaises(runtime.NativeError) as propagated:
            runtime.run_native([sys.executable, "-c", load], self.root / "exit-process.log", 10)
        self.assertEqual(propagated.exception.returncode, 0xC0000005)

    def test_native_start_failure_still_writes_status(self):
        log = self.root / "missing.log"
        with self.assertRaises(runtime.NativeError):
            runtime.run_native([str(self.root / "nonexistent-program")], log, 5)
        metadata = runtime.read_json(log.with_suffix(".log.json"))
        self.assertEqual(metadata["returncode"], 1)
        self.assertEqual(metadata["phase"], "failed")
        self.assertEqual(metadata["failure_phase"], "starting")
        self.assertIsNone(metadata["root_returncode"])
        self.assertIsNone(metadata["timeout_phase"])

    def test_native_browser_smoke_with_real_fake_subprocess(self):
        with self.patched_browser(self.fake_browser()):
            report = runtime.run_browser(self.root / "mullvadbrowser.exe", self.root, "smoke", 10)
        self.assertEqual(report["mode"], "calibrate")
        self.assertFalse((self.root / "smoke/profile").exists())
        self.assertTrue((self.root / "smoke/screenshot.png").is_file())
        command = report["native_process"]["command"]
        self.assertIn("--offline", command); self.assertIn("--no-remote", command)
        self.assertTrue(command[-1].startswith("file://"))
        self.assertFalse(report["browser_diagnostics"])
        self.assertEqual(runtime.read_json(self.root / "smoke/launch.json"), {"schema": 1, "browser_diagnostics": False})
        self.assertFalse((self.root / "smoke/navigation.log").exists())

    def test_browser_diagnostics_forward_native_logging_environment_only_when_enabled(self):
        program = self.fake_browser()
        with program.open("a") as stream:
            stream.write("import os\nfrom pathlib import Path\nPath(os.environ['MOZ_LOG_FILE']).write_text(os.environ['MOZ_LOG'])\n")
        with self.patched_browser(program):
            report = runtime.run_browser(self.root / "mullvadbrowser.exe", self.root, "diagnostic", 10, diagnostics=True)
        self.assertTrue(report["browser_diagnostics"])
        self.assertEqual(runtime.read_json(self.root / "diagnostic/launch.json"), {"schema": 1, "browser_diagnostics": True})
        self.assertEqual((self.root / "diagnostic/navigation.log").read_text(), "timestamp,sync,DocLoader:5,BCWebProgress:5")
        self.assertNotIn("timestamp,sync", json.dumps(report["native_process"]))
        self.assertNotIn("MOZ_LOG_FILE", json.dumps(report["native_process"]))
        self.assertFalse((self.root / "diagnostic/profile").exists())

    def test_browser_diagnostics_remain_disabled_for_default_launch_environment(self):
        program = self.fake_browser()
        with program.open("a") as stream:
            stream.write("import os,json\nfrom pathlib import Path\nPath(__file__).with_suffix('.env.json').write_text(json.dumps([os.environ.get('MOZ_LOG'),os.environ.get('MOZ_LOG_FILE')]))\n")
        with mock.patch.dict(os.environ, {"MOZ_LOG": "parent-value", "MOZ_LOG_FILE": "parent-path"}), self.patched_browser(program):
            runtime.run_browser(self.root / "mullvadbrowser.exe", self.root, "no-diagnostic", 10)
        self.assertEqual(runtime.read_json(program.with_suffix(".env.json")), ["parent-value", "parent-path"])
        self.assertFalse((self.root / "no-diagnostic/navigation.log").exists())

    def test_browser_diagnostics_flag_survives_failure_without_weakening_exit_gate(self):
        with self.patched_browser(self.fake_browser("nonzero")), self.assertRaises(runtime.NativeError) as caught:
            runtime.run_browser(self.root / "mullvadbrowser.exe", self.root, "failed-diagnostic", 10, diagnostics=True)
        self.assertEqual(caught.exception.returncode, 7)
        self.assertEqual(runtime.read_json(self.root / "failed-diagnostic/launch.json"), {"schema": 1, "browser_diagnostics": True})
        self.assertFalse((self.root / "failed-diagnostic/profile").exists())
        metadata = runtime.read_json(self.root / "failed-diagnostic/browser.log.json")
        self.assertEqual(metadata["root_returncode"], 7)
        self.assertEqual(metadata["returncode"], 7)
        self.assertNotIn("MOZ_LOG", json.dumps(metadata))

    def test_native_browser_rejects_bad_js_report_and_propagates_exit(self):
        for behavior in ("bad-nonce", "bad-checksum", "nonzero"):
            with self.subTest(behavior=behavior), self.patched_browser(self.fake_browser(behavior)), self.assertRaises(runtime.CheckError):
                runtime.run_browser(self.root / "mullvadbrowser.exe", self.root, behavior, 10)
            self.assertFalse((self.root / behavior / "profile").exists())

    def test_browser_tree_uses_product_version_not_gecko_version(self):
        tree = self.root / "Browser"; browser_tree(tree, portable=True)
        identity = runtime.verify_browser_tree(tree, VERSION, portable=True)
        self.assertEqual(identity["gecko_version"], "153.0esr")
        (tree / "system-install").write_text("")
        with self.assertRaisesRegex(runtime.CheckError, "marker"):
            runtime.verify_browser_tree(tree, VERSION, portable=True)
        self.assertTrue(runtime.verify_browser_tree(tree, VERSION, portable=False)["system_install"])

    def test_browser_tree_rejects_firefox_name_and_preserves_actual_inventory(self):
        tree = self.root / "Browser"; browser_tree(tree, portable=True)
        (tree / "mullvadbrowser.exe").rename(tree / "firefox.exe")
        output = self.root / "installed-inventory.json"
        with self.assertRaisesRegex(runtime.CheckError, "mullvadbrowser.exe"):
            runtime.verify_browser_tree(tree, VERSION, portable=True, inventory_path=output)
        inventory = runtime.read_json(output)
        files = {entry["path"]: entry for entry in inventory["entries"]}
        self.assertEqual(inventory["expected_executable"], "mullvadbrowser.exe")
        self.assertEqual(files["firefox.exe"]["kind"], "file")
        self.assertEqual(files["firefox.exe"]["size"], len(b"MZ fake package bytes"))
        self.assertNotIn("mullvadbrowser.exe", files)

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture; Windows junctions use reparse detection")
    def test_inventory_does_not_follow_linked_directories(self):
        tree = self.root / "installed"; tree.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        (outside / "private-file").write_text("do not inspect outside test installation")
        (tree / "linked-directory").symlink_to(outside, target_is_directory=True)
        inventory = runtime.record_browser_inventory(tree, self.root / "inventory.json")
        self.assertEqual(inventory["entries"], [{"path": "linked-directory", "kind": "link-or-reparse-point"}])

    def test_packages_reject_missing_or_wrong_portable_executable_identity(self):
        packages, manifest, _ = self.package_fixture()
        for name in (None, "Browser/firefox.exe", "mullvadbrowser.exe"):
            value = copy.deepcopy(manifest)
            value["portable_layout"]["executable"] = name
            runtime.write_json(packages / "packages.json", value)
            with self.subTest(executable=name), self.assertRaisesRegex(runtime.CheckError, "portable layout"):
                runtime.verify_packages(packages, LOCK)

    def test_browser_tree_rejects_changed_official_update_route(self):
        tree = self.root / "Browser"; browser_tree(tree, portable=True)
        (tree / "update-settings.ini").write_text("[Settings]\nACCEPTED_MAR_CHANNEL_IDS=unsigned-other-channel\n")
        with self.assertRaisesRegex(runtime.CheckError, "official signed"):
            runtime.verify_browser_tree(tree, VERSION, portable=True)
        browser_tree(tree, portable=True)
        ini = tree / "application.ini"
        ini.write_text(ini.read_text().replace("https://cdn.mullvad.net/", "https://example.com/"))
        with self.assertRaisesRegex(runtime.CheckError, "official signed"):
            runtime.verify_browser_tree(tree, VERSION, portable=True)

    def test_benchmark_reports_actual_medians_even_if_pgo_is_slower(self):
        samples = {"baseline": [result(elapsed=x) for x in (800, 1200, 400)],
                   "installer": [result(elapsed=x) for x in (1600, 2400, 800)],
                   "portable": [result(elapsed=x) for x in (400, 600, 200)]}
        summary = runtime.performance_summary(samples, True)
        data = summary["workloads"]["json-roundtrip"]
        self.assertEqual(data["baseline"]["median_ms_per_iteration"], 100)
        self.assertEqual(data["installer"]["time_change_percent_vs_baseline"], 100)
        self.assertEqual(data["installer"]["baseline_over_variant_ratio"], 0.5)
        self.assertEqual(data["portable"]["baseline_over_variant_ratio"], 2)
        self.assertIsNone(summary["threshold"])
        self.assertEqual(len(data["installer"]["raw_samples"]), 3)

    def check_args(self, packages, baseline=None, experiment=False):
        lock = self.root / "check-lock.json"; runtime.write_json(lock, LOCK)
        return argparse.Namespace(package_directory=packages, baseline_directory=baseline, allow_no_baseline_experiment=experiment,
                                  output_directory=self.root / "runtime-output", upstream_lock=lock, samples=3,
                                  target_milliseconds=1200, browser_timeout_seconds=10, installer_timeout_seconds=10)

    def test_baseline_required_before_any_native_execution(self):
        args = self.check_args(self.root / "unused")
        with mock.patch.object(runtime, "require_windows"), mock.patch.object(runtime, "run_native") as native:
            with self.assertRaisesRegex(runtime.CheckError, "baseline is required"):
                runtime.run_checks(args)
            native.assert_not_called()
        report = runtime.read_json(args.output_directory / "runtime-report.json")
        self.assertFalse(report["validated_pipeline"])

    def test_full_fake_native_pipeline_and_disposable_cleanup(self):
        packages, _, tree = self.package_fixture()
        baseline, _ = self.prepared_baseline()
        fake_installer = self.root / "fake-installer.py"
        fake_installer.write_text("import pathlib,shutil,sys\nd=pathlib.Path(sys.argv[-1][3:])\nshutil.copytree(" + repr(str(tree / "Browser")) + ",d,dirs_exist_ok=True)\n(d/'system-install').write_text('')\np=d/'uninstall.exe'\np.write_text('#!'+sys.executable+'\\nimport sys\\nprint(\"fake uninstall\")\\n')\np.chmod(0o755)\nprint('fake silent install')\n")
        args = self.check_args(packages, baseline)
        native = runtime.run_native
        def native_command(command, *rest, **kwargs):
            if isinstance(command, list) and str(command[0]).endswith("uninstall.exe"):
                command = [sys.executable] + command
            return native(command, *rest, **kwargs)
        with mock.patch.object(runtime, "require_windows"), mock.patch.object(runtime, "reject_existing_install"), \
             mock.patch.object(runtime, "installer_command", side_effect=lambda installer, directory: [sys.executable, str(fake_installer), "/S", "/D=" + str(directory)]), \
             mock.patch.object(runtime, "run_native", side_effect=native_command), self.patched_browser(self.fake_browser()):
            report = runtime.run_checks(args)
        self.assertTrue(report["validated_pipeline"])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["performance"]["samples_per_variant"], {"baseline": 3, "installer": 3, "portable": 3})
        self.assertEqual([item["variant"] for item in report["cleanup"]], ["baseline", "installer"])
        self.assertEqual(report["sample_order"][1]["variants"], ["portable", "installer", "baseline"])
        self.assertEqual(list(args.output_directory.glob("*/profile")), [])
        self.assertTrue(report["registry_cleanup_verified"])
        self.assertIn("mullvadbrowser.exe", report["installed_portable_same_binaries"])
        for name in ("baseline-install", "baseline-copy", "installer", "portable"):
            inventory = runtime.read_json(args.output_directory / (name + "-inventory.json"))
            paths = {item["path"] for item in inventory["entries"]}
            self.assertIn("mullvadbrowser.exe", paths)
            self.assertNotIn("firefox.exe", paths)

    @unittest.skipUnless(shutil.which("node"), "optional native JavaScript syntax and deterministic workload check")
    def test_javascript_units_have_the_recorded_checksums(self):
        template = (ROOT / "scripts/benchmark-page.html").read_text()
        script = template.split("<script>", 1)[1].split("</script>", 1)[0]
        config = {"nonce": "js-test", "mode": "measure", "target_ms": 1200, "iterations": dict.fromkeys(runtime.CHECKSUMS, 2)}
        script = script.replace("__RUNTIME_CONFIG__", json.dumps(config))
        dom = """
class Element {
 constructor(kind){this.kind=kind;this.style={};this.children=[];this.textContent='';}
 appendChild(node){if(node.kind==='fragment')this.children.push(...node.children);else this.children.push(node);}
 remove(){}
 get offsetWidth(){return parseInt(this.style.width)||0;}
 get offsetHeight(){return parseInt(this.style.height)||0;}
}
const elements={work:new Element('div'),pixels:new Element('div'),caption:new Element('div')};
const document={getElementById:id=>elements[id],createElement:kind=>new Element(kind),createDocumentFragment:()=>new Element('fragment')};
"""
        path = self.root / "workload.js"
        path.write_text(dom + script + "\\nconsole.log(JSON.stringify(Object.fromEntries(Object.entries(units).map(([name,unit])=>[name,unit()]))));\\n".replace("\\n", "\n"))
        output = self.root / "javascript.json"
        # A cold hosted Windows runner can scan/start node.exe slowly. Keep
        # a bounded deadline without turning startup timing into a JS gate.
        runtime.run_native([shutil.which("node"), str(path)], self.root / "javascript.log", 60, stdout_file=output)
        self.assertEqual(runtime.read_json(output), runtime.CHECKSUMS)

    def test_offline_template_does_not_change_preferences_or_fetch_remote_resources(self):
        template = (ROOT / "scripts/benchmark-page.html").read_text()
        for forbidden in ("fetch(", "XMLHttpRequest", "https://", "http://", "localStorage", "getImageData", "toDataURL"):
            self.assertNotIn(forbidden, template)
        self.assertIn("default-src 'none'", template)
        self.assertIn("performance.now()", template)
        source = (ROOT / "scripts/windows-runtime-check.py").read_text()
        self.assertNotIn("privacy.resistFingerprinting", source)
        self.assertNotIn("security.sandbox.content.level", source)
        self.assertNotIn("app.update.enabled", source)
        self.assertNotIn("user.js", source)


if __name__ == "__main__":
    unittest.main()
