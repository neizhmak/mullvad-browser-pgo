#!/usr/bin/env python3
"""Unit tests for inject-pgo-profile-runtime.py"""
import os
from pathlib import Path
import shutil
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

        # 2. simulate container appearance
        container = self.upstream / "tmp/rbm-containers/test-container-123"
        clang_dir = container / "var/tmp/dist/mingw-w64-clang/lib/clang/21"
        clang_dir.mkdir(parents=True)

        # 3. run injection logic
        count = mod.inject_into_containers(self.upstream, found)
        self.assertGreater(count, 0)

        # 4. verify destinations exist and match
        dest1 = clang_dir / "lib/x86_64-w64-windows-gnu/libclang_rt.profile.a"
        dest2 = clang_dir / "lib/windows/libclang_rt.profile-x86_64.a"
        dest3 = clang_dir / "lib/windows/libclang_rt.profile.a"

        for dest in (dest1, dest2, dest3):
            self.assertTrue(dest.is_file(), f"Missing {dest}")
            self.assertEqual(dest.read_bytes(), self.runtime.read_bytes())


if __name__ == "__main__":
    unittest.main()
