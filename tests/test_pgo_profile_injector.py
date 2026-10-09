#!/usr/bin/env python3
"""Unit tests for inject-pgo-profile-runtime.py"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INJECTOR = ROOT / "scripts/inject-pgo-profile-runtime.py"


class InjectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pgo-injector-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.upstream = self.base / "upstream"
        self.upstream.mkdir()
        self.tools = self.base / "tools"
        self.tools.mkdir()

        # Create dummy profiler runtime
        self.runtime = self.tools / "rust/lib/rustlib/x86_64-pc-windows-gnullvm/lib/libprofiler_builtins-dummy.rlib"
        self.runtime.parent.mkdir(parents=True)
        self.runtime.write_bytes(b"!<arch>\ndummy profiler runtime\n")

    def test_find_and_inject_into_container(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("injector", INJECTOR)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # 1. find_runtime
        found = mod.find_runtime(self.upstream, self.tools, self.base)
        self.assertIsNotNone(found)
        self.assertEqual(found, self.runtime)

        # 2. simulate RBM nested container appearance
        container = self.upstream / "tmp/rbm-abc123/rbm-xyz/var/tmp/dist/mingw-w64-clang/lib/clang/21"
        container.mkdir(parents=True)

        log_file = self.base / "injector.log"

        # 3. test find_clang_version_dirs
        dirs = mod.find_clang_version_dirs(self.upstream)
        self.assertIn(container, dirs)

        # 4. run injection logic
        count = mod.inject_into_containers(self.upstream, found, log_file)
        self.assertGreater(count, 0)
        self.assertTrue(log_file.is_file())

        # 5. verify all destinations exist and match
        dest1 = container / "lib/x86_64-w64-windows-gnu/libclang_rt.profile.a"
        dest2 = container / "lib/windows/libclang_rt.profile-x86_64.a"
        dest3 = container / "lib/windows/libclang_rt.profile.a"
        dest4 = container / "lib/x86_64-w64-windows-gnu/libclang_rt.profile-x86_64.a"

        for dest in (dest1, dest2, dest3, dest4):
            self.assertTrue(dest.is_file(), f"Missing {dest}")
            self.assertEqual(dest.read_bytes(), self.runtime.read_bytes())

    def test_inject_into_compiler_archive(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("injector", INJECTOR)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        found = mod.find_runtime(self.upstream, self.tools, self.base)
        self.assertIsNotNone(found)

        # Prepare dummy out/mingw-w64-clang archive
        mwc_dir = self.upstream / "out/mingw-w64-clang"
        mwc_dir.mkdir(parents=True)

        staging = self.base / "staging/mingw-w64-clang/lib/clang/21"
        staging.mkdir(parents=True)
        (staging / "test.txt").write_text("dummy clang header")

        tar_path = self.base / "archive.tar"
        subprocess.run(
            ["tar", "-cf", str(tar_path), "mingw-w64-clang/lib/clang/21/test.txt"],
            cwd=self.base / "staging",
            check=True,
        )

        tar_zst = mwc_dir / "mingw-w64-clang-test-21.1.8.tar.zst"
        subprocess.run(["zstd", "-f", str(tar_path), "-o", str(tar_zst)], check=True)

        log_file = self.base / "archive_injector.log"
        injected = mod.inject_into_compiler_archives(self.upstream, found, log_file)
        self.assertEqual(injected, 1)

        # Verify tar contents
        list_proc = subprocess.run(["tar", "-tf", str(tar_zst)], stdout=subprocess.PIPE, text=True, check=True)
        self.assertIn("mingw-w64-clang/lib/clang/21/lib/x86_64-w64-windows-gnu/libclang_rt.profile.a", list_proc.stdout)
        self.assertIn("mingw-w64-clang/lib/clang/21/lib/windows/libclang_rt.profile.a", list_proc.stdout)
        self.assertIn("mingw-w64-clang/lib/clang/21/lib/windows/libclang_rt.profile-x86_64.a", list_proc.stdout)

        # Second call should skip cleanly
        injected2 = mod.inject_into_compiler_archives(self.upstream, found, log_file)
        self.assertEqual(injected2, 0)


    def test_inject_and_wrap_llvm_strip(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("injector", INJECTOR)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        found = mod.find_runtime(self.upstream, self.tools, self.base)
        self.assertIsNotNone(found)

        # Prepare dummy out/mingw-w64-clang archive with bin/llvm-strip
        mwc_dir = self.upstream / "out/mingw-w64-clang"
        mwc_dir.mkdir(parents=True, exist_ok=True)

        staging = self.base / "staging_strip/mingw-w64-clang"
        (staging / "lib/clang/21").mkdir(parents=True)
        (staging / "bin").mkdir(parents=True)
        (staging / "lib/clang/21/dummy.txt").write_text("header")
        (staging / "bin/llvm-strip").write_text("#!/bin/sh\necho original\n")
        os.chmod(staging / "bin/llvm-strip", 0o755)

        tar_path = self.base / "archive_strip.tar"
        subprocess.run(
            ["tar", "-cf", str(tar_path), "mingw-w64-clang"],
            cwd=self.base / "staging_strip",
            check=True,
        )

        tar_zst = mwc_dir / "mingw-w64-clang-test2-21.1.8.tar.zst"
        subprocess.run(["zstd", "-f", str(tar_path), "-o", str(tar_zst)], check=True)

        log_file = self.base / "strip_injector.log"
        injected = mod.inject_into_compiler_archives(self.upstream, found, log_file)
        self.assertEqual(injected, 1)

        # Extract to verify
        dest = self.base / "extracted_strip"
        dest.mkdir()
        subprocess.run(["tar", "-xaf", str(tar_zst), "-C", str(dest)], check=True)

        strip_bin = dest / "mingw-w64-clang/bin/llvm-strip"
        real_bin = dest / "mingw-w64-clang/bin/llvm-strip.real"
        self.assertTrue(strip_bin.is_file())
        self.assertTrue(real_bin.is_file())
        self.assertIn("llvm-strip.real", strip_bin.read_text())
        self.assertEqual(real_bin.read_text(), "#!/bin/sh\necho original\n")

if __name__ == "__main__":
    unittest.main()
