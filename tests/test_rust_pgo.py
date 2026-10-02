#!/usr/bin/env python3
"""Behavioral checks for the isolated Windows Rust PGO toolchain (no builds)."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts/preflight-pgo-rust.sh"
IDENTITY = ROOT / "scripts/resolve-pgo-rust-identity.py"
PATCH = ROOT / "patches/firefox-pgo-generate.patch"
TARGET = "x86_64-pc-windows-gnullvm"
RUST_FILENAME = "rust-1.94.1-windows-profiler-test.tar.gz"
MINGW_FILENAME = "mingw-w64-clang-pinned.tar.gz"
RUST_BUILD = r'''# binaries do.

../configure \
  --prefix=$distdir \
  --disable-docs --disable-compiler-docs \
  --enable-local-rust \
  --enable-vendor \
  --enable-extended \
  --release-channel=stable \
  --sysconfdir=etc \
  --set rust.jemalloc \
  --target=x86_64-unknown-linux-gnu,wasm32-unknown-unknown,[% c("var/target") %] \
  --set target.x86_64-unknown-linux-gnu.linker=clang \
  --set target.x86_64-unknown-linux-gnu.ar=llvm-ar \
  --set target.x86_64-unknown-linux-gnu.ranlib=llvm-ranlib \
  --set target.wasm32-unknown-unknown.linker=clang \
  --set target.wasm32-unknown-unknown.ar=llvm-ar \
  --set target.wasm32-unknown-unknown.ranlib=llvm-ranlib \
  --set rust.lld=true \
  [% c("var/target_flags") %]
'''
RUST_CONFIG = '''targets:
  windows:
    var:
      target: x86_64-pc-windows-gnullvm,i686-pc-windows-gnullvm
      target_flags: --set target.x86_64-pc-windows-gnullvm.linker=x86_64-w64-mingw32-clang --set target.i686-pc-windows-gnullvm.linker=i686-w64-mingw32-clang
      arch_deps:
        - pkg-config

input_files:
  - project: container-image
  - project: cmake
'''
PERL_RENDERER = r'''use strict;
use warnings;
use Template;
use JSON::PP;
my ($template, $values_file, $output) = @ARGV;
open my $file, '<', $values_file or die $!;
local $/;
my $values = decode_json(<$file>);
my $tt = Template->new({ ABSOLUTE => 1, RELATIVE => 1 });
$tt->process($template, { c => sub { return $values->{$_[0]} // 0 } }, $output)
    or die $tt->error();
'''
FAKE_RBM = r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
assert args[0] == "showconf", args
project, key = args[1:3]
pgo = "pgo-generate" in args or "pgo-use" in args
values = {
    ("rust", "filename"): os.environ.get("FAKE_PGO_FILENAME", "rust-1.94.1-windows-profiler-test.tar.gz") if pgo else "rust-official.tar.gz",
    ("rust", "var/target"): os.environ.get("FAKE_RUST_TARGETS", "x86_64-pc-windows-gnullvm,i686-pc-windows-gnullvm"),
    ("rust", "version"): "1.94.1",
    ("rust", "input_files"): "pinned sources and compiler",
    ("mingw-w64-clang", "filename"): "mingw-w64-clang-pinned.tar.gz",
}
print(values[project, key])
'''
FAKE_RUSTC = r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
# Rust is relocatable and this models the named, symlinked bin/rustc entry.
root = Path(sys.argv[0]).parent.parent
if "--version" in args:
    print("rustc 1.94.1\nLLVM version: 21.1.8")
elif "--print" in args:
    value = args[args.index("--print") + 1]
    if value == "sysroot":
        print(os.environ.get("FAKE_RUST_SYSROOT", str(root)))
    else:
        assert value == "target-libdir", args
        assert args[args.index("--sysroot") + 1] == str(root), args
        target = args[args.index("--target") + 1]
        print(os.environ.get("FAKE_RUST_LIBDIR", str(root / "lib/rustlib" / target / "lib")))
else:
    Path(os.environ["FAKE_RUST_INVOCATION"]).write_text(json.dumps(args))
    assert args[args.index("--target") + 1] == "x86_64-pc-windows-gnullvm", args
    assert args[args.index("--sysroot") + 1] == str(root), args
    codegen = [args[i+1] for i, arg in enumerate(args) if arg == "-C"]
    linker = next(arg.split("=", 1)[1] for arg in codegen if arg.startswith("linker="))
    mingw_root = Path(linker).parent.parent
    assert Path(linker).is_file() and os.access(linker, os.X_OK), linker
    assert "link-arg=--sysroot=" + str(mingw_root / "x86_64-w64-mingw32") in codegen, codegen
    assert any(arg.startswith("profile-generate=") for arg in codegen), codegen
    if os.environ.get("FAKE_NO_PROFILER") == "1":
        print("error: profiler_builtins missing", file=sys.stderr)
        sys.exit(1)
    output = Path(args[args.index("-o") + 1])
    output.write_bytes(b"MZ functional link fixture")
'''


def executable_source(source):
    return (f"#!{sys.executable}\n" + source).encode()


def make_archive(path, files, links=None, directories=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for name in directories:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        for name, (content, mode) in files.items():
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.mode = 0o777
            member.linkname = target
            archive.addfile(member)


class RustFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rust-pgo-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream"
        self.runtime = self.base / "runner temp"
        self.runtime.mkdir()
        (self.upstream / "rbm").mkdir(parents=True)
        rbm = self.upstream / "rbm/rbm"
        rbm.write_bytes(executable_source(FAKE_RBM))
        rbm.chmod(0o755)
        (self.upstream / "projects/rust").mkdir(parents=True)
        (self.upstream / "projects/rust/config").write_text(RUST_CONFIG)
        (self.upstream / "projects/rust/build").write_text(RUST_BUILD)
        self.env = os.environ | {"UPSTREAM": str(self.upstream),
                                 "RUNNER_TEMP": str(self.runtime),
                                 "FAKE_RUST_INVOCATION": str(self.base / "rustc-args.json")}
        self.rust_archive = self.upstream / "out/rust" / RUST_FILENAME
        self.mingw_archive = self.upstream / "out/mingw-w64-clang" / MINGW_FILENAME
        self.make_rust()
        make_archive(self.mingw_archive,
                     {"mingw-w64-clang/libexec/clang-wrapper": (b"#!/bin/sh\nexit 0\n", 0o755)},
                     {"mingw-w64-clang/bin/x86_64-w64-mingw32-clang": "../libexec/clang-wrapper"},
                     ["mingw-w64-clang/x86_64-w64-mingw32"])
        # Decoys must not be selected or included in the immutable identity.
        (self.rust_archive.parent / "aaa-stale.tar.gz").write_bytes(b"not a tar archive")
        (self.mingw_archive.parent / "aaa-stale.tar.gz").write_bytes(b"not a tar archive")

    def make_rust(self, link="../libexec/rustc-real"):
        make_archive(self.rust_archive,
                     {"rust/libexec/rustc-real": (executable_source(FAKE_RUSTC), 0o755),
                      f"rust/lib/rustlib/{TARGET}/lib/libprofiler_builtins.rlib": (b"runtime fixture", 0o644)},
                     {"rust/bin/rustc": link})

    def preflight(self):
        return subprocess.run(["bash", PREFLIGHT], env=self.env, text=True,
                              capture_output=True, timeout=20)

    def identity(self):
        output = self.base / "identity.json"
        result = subprocess.run([sys.executable, IDENTITY, "--upstream", str(self.upstream),
                                 "--output", str(output)], env=self.env, text=True,
                                capture_output=True, timeout=20)
        return result, json.loads(output.read_text()) if result.returncode == 0 else None

    def test_preflight_links_with_symlink_tools_and_exact_artifacts(self):
        result = self.preflight()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.runtime / "pgo-rust-preflight.exe").stat().st_size)
        args = json.loads((self.base / "rustc-args.json").read_text())
        self.assertEqual(args[args.index("--target") + 1], TARGET)
        self.assertIn("profile-generate=" + str(self.runtime / "pgo-rust-profile"), args)
        self.assertIn("rustc 1.94.1", (self.runtime / "pgo-rust-compiler-version.txt").read_text())
        self.assertIn("libprofiler_builtins", (self.runtime / "pgo-rust-runtime-inventory.log").read_text())

    def test_preflight_fails_if_real_profile_link_fails(self):
        self.env["FAKE_NO_PROFILER"] = "1"
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profiler_builtins missing", result.stderr)
        self.assertFalse((self.runtime / "pgo-rust-preflight.exe").exists())

    def test_preflight_rejects_missing_exact_mingw_despite_decoys(self):
        self.mingw_archive.unlink()
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected MinGW input is missing", result.stderr)

    def test_preflight_rejects_external_sysroot(self):
        self.env["FAKE_RUST_SYSROOT"] = str(self.base)
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the restored PGO artifact", result.stderr)

    def test_preflight_rejects_external_target_libdir(self):
        self.env["FAKE_RUST_LIBDIR"] = str(self.base)
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("target libdir outside", result.stderr)

    def test_preflight_rejects_executable_symlink_escape(self):
        self.make_rust(link=sys.executable)
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rustc symlink escapes", result.stderr)

    def test_preflight_rejects_ambiguous_windows_target(self):
        self.env["FAKE_RUST_TARGETS"] = TARGET + "," + TARGET
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not derive the pinned", result.stderr)

    def test_identity_binds_only_selected_mingw_and_preserves_output(self):
        result, data = self.identity()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data["rust"]["output_filename"], RUST_FILENAME)
        self.assertEqual(data["rust"]["profiler_targets"], [TARGET])
        self.assertEqual(data["rust"]["std_targets"], [TARGET, "i686-pc-windows-gnullvm"])
        self.assertEqual(data["mingw_w64_clang"], [{"path": "out/mingw-w64-clang/" + MINGW_FILENAME,
                         "size": self.mingw_archive.stat().st_size,
                         "sha256": hashlib.sha256(self.mingw_archive.read_bytes()).hexdigest()}])
        (self.mingw_archive.parent / "another-stale-output").write_bytes(b"ignored")
        again, same = self.identity()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(same, data)

    def test_identity_rejects_missing_selected_mingw(self):
        self.mingw_archive.unlink()
        result, _ = self.identity()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing pinned mingw-w64-clang dependency", result.stderr)

    def test_identity_rejects_official_or_path_filename(self):
        for filename in ("rust-official.tar.gz", "../rust-profiler.tar.gz"):
            with self.subTest(filename=filename):
                self.env["FAKE_PGO_FILENAME"] = filename
                result, _ = self.identity()
                self.assertNotEqual(result.returncode, 0)


class RustRenderTests(unittest.TestCase):
    def setUp(self):
        check = subprocess.run(["perl", "-MTemplate", "-e", "1"], capture_output=True)
        if check.returncode:
            self.skipTest("Template Toolkit is required for native recipe rendering")
        self.temp = tempfile.TemporaryDirectory(prefix="rust-render-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.build = self.base / "projects/rust/build"
        self.build.parent.mkdir(parents=True)
        self.build.write_text(RUST_BUILD)
        self.config = self.base / "projects/rust/config"
        self.config.write_text(RUST_CONFIG)
        applied = subprocess.run(["git", "apply", "--include=projects/rust/build",
                                  "--include=projects/rust/config", str(PATCH)],
                                 cwd=self.base, text=True, capture_output=True)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.renderer = self.base / "render.pl"
        self.renderer.write_text(PERL_RENDERER)

    def variables(self, target=None):
        values = {"var/windows-x86_64": 1, "var/platform": "windows",
                  "var/filename_targets": "windows",
                  "var/target": TARGET + ",i686-pc-windows-gnullvm",
                  "var/target_flags": "--set target." + TARGET + ".linker=x86_64-w64-mingw32-clang --set target.i686-pc-windows-gnullvm.linker=i686-w64-mingw32-clang"}
        # Resolve the small target overlay from the actual patched YAML. RBM
        # scalar aliases select the referenced target's exact variables.
        text = self.config.read_text().split("input_files:", 1)[0]
        aliases = dict(re.findall(r"^  ([\w-]+): ([\w-]+)$", text, re.M))
        while target in aliases:
            target = aliases[target]
        if target:
            match = re.search(r"^  " + re.escape(target) + r":\n(.*?)(?=^  \S|\Z)", text, re.M | re.S)
            self.assertIsNotNone(match)
            for name, value in re.findall(r"^      ([\w-]+): (.+)$", match[1], re.M):
                values["var/" + name] = value[1:-1] if value.startswith('"') else int(value)
        return values

    def render(self, template, values):
        source = self.base / "source.tt"
        source.write_text(template)
        config = self.base / "values.json"
        config.write_text(json.dumps(values))
        output = self.base / "rendered"
        result = subprocess.run(["perl", self.renderer, source, config, output],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_text()

    def configure_args(self, template, values):
        rendered = self.render(template, values)
        build_dir = self.base / "build"
        build_dir.mkdir(exist_ok=True)
        configure = self.base / "configure"
        configure.write_bytes(executable_source("import json, os, sys\nfrom pathlib import Path\nPath(os.environ['CONFIGURE_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"))
        configure.chmod(0o755)
        capture = self.base / "configure-args.json"
        result = subprocess.run(["bash", "-euc", rendered], cwd=build_dir,
                                env=os.environ | {"CONFIGURE_ARGS": str(capture), "distdir": "/fixture/rust"},
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(capture.read_text()), rendered

    def test_non_pgo_render_and_argv_remain_exactly_official(self):
        values = self.variables()
        baseline, original = self.configure_args(RUST_BUILD, values)
        patched, rendered = self.configure_args(self.build.read_text(), values)
        self.assertEqual(rendered, original)
        self.assertEqual(patched, baseline)

    def test_pgo_changes_only_windows_x86_64_profiler_arg(self):
        baseline, _ = self.configure_args(RUST_BUILD, self.variables())
        pgo, _ = self.configure_args(self.build.read_text(), self.variables("pgo-generate"))
        self.assertEqual(pgo[:2], ["--set", "target." + TARGET + ".profiler=true"])
        self.assertEqual(pgo[2:], baseline)
        # Model 1.94.1 Config::profiler_enabled: target override, otherwise
        # build.profiler (false in official recipe and dist defaults).
        settings = dict(pgo[i+1].split("=", 1) for i, arg in enumerate(pgo)
                        if arg == "--set" and "=" in pgo[i+1])
        enabled = lambda target: settings.get("target." + target + ".profiler", settings.get("build.profiler", "false")) == "true"
        self.assertTrue(enabled(TARGET))
        for other in ("wasm32-unknown-unknown", "x86_64-unknown-linux-gnu", "i686-pc-windows-gnullvm"):
            self.assertFalse(enabled(other), other)

    def test_profile_use_resolves_same_recipe_and_profiler_filename(self):
        generate = self.variables("pgo-generate")
        use = self.variables("pgo-use")
        self.assertEqual(use, generate)
        self.assertEqual(self.configure_args(self.build.read_text(), use)[0],
                         self.configure_args(self.build.read_text(), generate)[0])
        filename_target = self.render(generate["var/filename_targets"], generate)
        self.assertEqual(filename_target, "windows-profiler")
        self.assertEqual(filename_target, self.render(use["var/filename_targets"], use))

    def test_wrong_platform_never_enables_windows_profiler(self):
        values = self.variables("pgo-generate")
        values["var/windows-x86_64"] = 0
        patched, _ = self.configure_args(self.build.read_text(), values)
        baseline, _ = self.configure_args(RUST_BUILD, values)
        self.assertEqual(patched, baseline)


if __name__ == "__main__":
    unittest.main()
