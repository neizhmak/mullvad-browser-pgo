#!/usr/bin/env python3
"""Native behavioral tests for root PGO provenance and generation helpers.

Run: python3 tests/test_pgo_provenance.py -v
All compiler/RBM commands are fixture executables. Git reads real local source
objects; its fixture wrapper rejects every clone, fetch, and other write command.
No network, compiler build, project import, or third-party dependency is used.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
TARGETS = ["alpha", "mullvadbrowser-windows-x86_64", "pgo-generate"]
TARGET_ARGUMENTS = [argument for target in TARGETS for argument in ("--target", target)]
CLANG_FILENAME = "mingw-w64-clang-selected-21.1.8.tar.zst"
RUST_FILENAME = "rust-1.94.1-windows-profiler-selected.tar.xz"
FIREFOX_FILENAME = "firefox-mullvad-browser-selected-windows-x86_64"
CLANG_VERSION = "clang version 21.1.8 (pinned fixture 8eab9d)"
RUST_VERSION = "rustc 1.94.1 (pinned fixture 4c09d1)"
CPP_COMMAND = "clang++ -c widget.cpp -fprofile-generate=/tmp/profiles -o widget.o\n"
RUST_COMMAND = "rustc webrender.rs -Cprofile-generate=/tmp/profiles -o webrender.rlib\n"
CONFIGURE_LOG = "./mach configure --enable-profile-generate=cross\n"
GOOD_LOG = CONFIGURE_LOG + CPP_COMMAND + RUST_COMMAND

FAKE_RBM = r"""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['RBM_CALLS'], 'a') as stream:
    stream.write(json.dumps({'args': args, 'cwd': str(Path.cwd())}) + '\n')
config = json.loads(Path(os.environ['RBM_FIXTURE']).read_text())
targets = ['--target', 'alpha', '--target', 'mullvadbrowser-windows-x86_64', '--target', 'pgo-generate']
if args[:2] == ['build', 'firefox']:
    assert args[2:] == targets, args
    if config.get('project_log') is not None:
        path = Path('logs/firefox-windows-x86_64.log')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config['project_log'])
    print(config.get('build_stdout', 'fixture Firefox build'), end='\n')
    sys.exit(config.get('build_exit', 0))
assert args[0] == 'showconf' and args[3:] == targets, args
print(config['show'][args[1] + ':' + args[2]])
"""

FAKE_GIT = r"""import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ['GIT_CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
command = args[2:] if args[:1] == ['-C'] else args
# This test suite proves reuse. An unexpected init/clone/fetch cannot use a
# local fallback, let alone reach a real remote.
if not command or command[0] not in ('rev-parse', 'remote', 'show'):
    print('fixture prohibits source writes and network commands', file=sys.stderr)
    sys.exit(93)
if command[0] == 'remote' and command[1:] != ['get-url', 'origin']:
    sys.exit(94)
sys.exit(subprocess.call([os.environ['REAL_GIT'], *args]))
"""


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return digest_bytes(Path(path).read_bytes())


def put_json(path, data):
    Path(path).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def executable(path, source):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\n" + source)
    path.chmod(0o755)
    return path


class NativeFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pgo-provenance-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream with spaces"
        self.runtime = self.base / "runner temp"
        self.bin = self.base / "bin"
        self.runtime.mkdir()
        self.bin.mkdir()
        self.rbm_calls = self.base / "rbm-calls.jsonl"
        self.config_path = self.base / "rbm-fixture.json"
        self.config = {"show": {"firefox:filename": FIREFOX_FILENAME,
                                "firefox:build_log": "logs/firefox-windows-x86_64.log",
                                "firefox:var/exe_name": "mullvadbrowser"}}
        self.env = os.environ | {
            "PATH": os.pathsep.join((str(self.bin), str(Path(sys.executable).parent),
                                     os.environ.get("PATH", ""))),
            "UPSTREAM": str(self.upstream), "RUNNER_TEMP": str(self.runtime),
            "RBM_CALLS": str(self.rbm_calls), "RBM_FIXTURE": str(self.config_path),
            "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        }
        self.env.pop("GITHUB_ENV", None)
        executable(self.upstream / "rbm/rbm", FAKE_RBM)

    def command(self, *args):
        return subprocess.run(list(map(str, args)), cwd=ROOT, env=self.env,
                              text=True, capture_output=True, timeout=20)

    def helper(self, name, *args):
        put_json(self.config_path, self.config)
        return self.command(sys.executable, SCRIPTS / name, *args)

    def good(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def bad(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def calls(self, path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class SourceProvenanceTests(NativeFixture):
    def setUp(self):
        super().setUp()
        self.real_git = shutil.which("git")
        if not self.real_git:
            self.skipTest("native git is required for local source object fixtures")
        self.checkout = self.upstream / "git_clones/firefox"
        self.checkout.mkdir(parents=True)
        self.repository = self.base / "local-origin.git"
        self.git_calls = self.base / "git-calls.jsonl"
        self.env.update({"REAL_GIT": self.real_git, "GIT_CALLS": str(self.git_calls),
                         "GIT_AUTHOR_NAME": "Fixture", "GIT_COMMITTER_NAME": "Fixture",
                         "GIT_AUTHOR_EMAIL": "fixture@example.test",
                         "GIT_COMMITTER_EMAIL": "fixture@example.test",
                         "GIT_AUTHOR_DATE": "2024-01-01T00:00:00Z",
                         "GIT_COMMITTER_DATE": "2024-01-01T00:00:00Z"})
        self.good(self.command(self.real_git, "init", "--bare", self.repository))
        self.git("init")
        self.git("remote", "add", "origin", self.repository)
        self.workload = self.checkout / "build/pgo/profileserver.py"
        self.workload.parent.mkdir(parents=True)
        self.selected_workload = b"# exact selected workload\r\nprint('pinned workload')\r\n"
        self.workload.write_bytes(self.selected_workload)
        self.git("add", "build/pgo/profileserver.py")
        self.git("commit", "-m", "selected workload")
        self.revision = self.git("rev-parse", "HEAD").stdout.strip()
        self.ref = "firefox-selected-tag"
        self.git("tag", "-a", self.ref, "-m", "selected annotated tag")
        self.workload.write_bytes(b"# different committed HEAD workload\n")
        self.git("add", "build/pgo/profileserver.py")
        self.git("commit", "-m", "unselected workload")
        self.other_revision = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("tag", "firefox-other-tag")
        self.workload.write_bytes(b"# dirty worktree must not become the workload\n")
        self.config["show"].update({
            "firefox:git_url": str(self.repository), "firefox:git_hash": self.ref,
            "firefox:var/git_commit": self.revision, "firefox:git_clone_dir": "git_clones",
        })
        executable(self.bin / "git", FAKE_GIT)
        self.build_path = self.runtime / "provenance/build.json"
        self.server_path = self.runtime / "provenance/profileserver.py"

    def git(self, *args):
        return self.good(self.command(self.real_git, "-C", self.checkout, *args))

    def resolve(self):
        return self.helper("resolve-pgo-provenance.py")

    def source_failure(self):
        self.bad(self.resolve())
        self.assertFalse(self.build_path.exists())
        self.assertFalse(self.server_path.exists())

    def test_records_exact_tag_revision_and_committed_workload_reusing_rbm_clone(self):
        env_path = self.base / "github-env"
        self.env["GITHUB_ENV"] = str(env_path)
        for clone_root in ("git_clones", str(self.checkout.parent)):
            with self.subTest(clone_root=clone_root):
                self.config["show"]["firefox:git_clone_dir"] = clone_root
                env_path.write_text("")
                self.good(self.resolve())
                data = json.loads(self.build_path.read_text())
                self.assertEqual(data, {
                    "schema": 2,
                    "upstream_lock": json.loads((ROOT / "upstream.lock.json").read_text()),
                    "firefox": {"repository": str(self.repository), "ref": self.ref,
                                "revision": self.revision},
                    "browser_executable": "mullvadbrowser.exe",
                    "profileserver": {"path": "build/pgo/profileserver.py",
                                      "revision": self.revision,
                                      "sha256": digest_bytes(self.selected_workload)},
                    "pgo_overlay_sha256": digest(ROOT / "patches/firefox-pgo-generate.patch"),
                    "pgo_languages": ["c++", "rust"], "generation_targets": TARGETS,
                    "generation_configure_flags": ["--enable-profile-generate=cross"],
                })
                self.assertEqual(self.server_path.read_bytes(), self.selected_workload)
                self.assertEqual(env_path.read_text().splitlines(), [
                    f"FIREFOX_REPOSITORY={self.repository}", f"FIREFOX_REF={self.ref}",
                    f"FIREFOX_REVISION={self.revision}"])
                self.assertFalse((self.runtime / "firefox-provenance-source").exists())
                source_calls = self.calls(self.git_calls)
                self.assertTrue(source_calls)
                self.assertTrue(all(args[:2] == ["-C", str(self.checkout)] for args in source_calls))
                self.assertIn(["-C", str(self.checkout), "show",
                               f"{self.revision}:build/pgo/profileserver.py"], source_calls)
                self.assertTrue(all(record["cwd"] == str(self.upstream)
                                    for record in self.calls(self.rbm_calls)))

    def test_rejects_non_mullvad_browser_executable_selection(self):
        for name in ("firefox", "torbrowser", "mullvadbrowser.exe", "../mullvadbrowser", ""):
            with self.subTest(executable=name):
                self.config["show"]["firefox:var/exe_name"] = name
                self.source_failure()
                self.assertFalse(self.git_calls.exists())

    def test_rejects_wrong_exact_source_revision(self):
        self.config["show"]["firefox:var/git_commit"] = self.other_revision
        self.source_failure()

    def test_rejects_wrong_or_missing_selected_ref(self):
        for ref in ("firefox-other-tag", "firefox-absent-tag"):
            with self.subTest(ref=ref):
                self.config["show"]["firefox:git_hash"] = ref
                self.source_failure()

    def test_rejects_rbm_repository_not_matching_reused_clone(self):
        self.config["show"]["firefox:git_url"] = str(self.base / "wrong-origin.git")
        self.source_failure()

    def test_rejects_invalid_revision_before_reading_source(self):
        for revision in ("", "abc123", "g" * 40, "A" * 40, "a" * 41, "a" * 40 + "\nother"):
            with self.subTest(revision=revision):
                self.config["show"]["firefox:var/git_commit"] = revision
                self.source_failure()
                self.assertFalse(self.git_calls.exists())

    def test_rejects_empty_workload_from_exact_source_object(self):
        self.workload.write_bytes(b"")
        self.git("add", "build/pgo/profileserver.py")
        self.git("commit", "-m", "empty workload")
        empty_revision = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("tag", "firefox-empty-workload")
        self.config["show"].update({"firefox:git_hash": "firefox-empty-workload",
                                   "firefox:var/git_commit": empty_revision})
        self.source_failure()


class ToolchainCaptureTests(NativeFixture):
    def setUp(self):
        super().setUp()
        self.tools = self.base / "restored tools"
        self.tool_calls = self.base / "tool-calls.jsonl"
        self.env["TOOL_CALLS"] = str(self.tool_calls)
        self.tool_paths = {
            "clang": self.tools / "mingw/mingw-w64-clang/bin/clang",
            "rust": self.tools / "rust/rust/bin/rustc",
        }
        for name in self.tool_paths:
            self.make_compiler(name)
        self.archives = {
            "clang": self.upstream / "out/mingw-w64-clang" / CLANG_FILENAME,
            "rust": self.upstream / "out/rust" / RUST_FILENAME,
        }
        for name, path in self.archives.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"selected archive bytes\x00\xff\n" + name.encode())
            (path.parent / "aaa-stale-output.tar.zst").write_bytes(b"wrong archive bytes")
            (path.parent / "zzz-other-output.tar.xz").write_bytes(b"other wrong archive bytes")
        self.config["show"].update({"mingw-w64-clang:filename": CLANG_FILENAME,
                                    "rust:filename": RUST_FILENAME})
        self.package = self.base / "instrumented browser.tar.zst"
        self.package.write_bytes(b"instrumented runtime bytes\x00\xff\n")
        self.build = {
            "schema": 2, "upstream_lock": json.loads((ROOT / "upstream.lock.json").read_text()),
            "firefox": {"repository": str(self.base / "local-source.git"),
                        "ref": "firefox-selected-tag", "revision": "c" * 40},
            "browser_executable": "mullvadbrowser.exe",
            "profileserver": {"path": "build/pgo/profileserver.py", "revision": "c" * 40,
                              "sha256": digest_bytes(b"# selected workload\n")},
            "pgo_overlay_sha256": digest(ROOT / "patches/firefox-pgo-generate.patch"),
            "pgo_languages": ["c++", "rust"], "generation_targets": TARGETS,
            "generation_configure_flags": ["--enable-profile-generate=cross"],
        }
        self.identity = {
            "schema": 1, "kind": "firefox-cross-pgo-rust", "upstream": copy.deepcopy(self.build["upstream_lock"]),
            "overlay": {"path": "patches/firefox-pgo-generate.patch",
                        "sha256": self.build["pgo_overlay_sha256"]},
            "rust": {"version": "1.94.1", "source_inputs": "fixture source and compiler",
                     "rbm_target": ",".join(TARGETS), "output_filename": RUST_FILENAME,
                     "official_output_filename": "rust-official.tar.xz",
                     "std_targets": ["x86_64-pc-windows-gnullvm", "i686-pc-windows-gnullvm"],
                     "profiler_targets": ["x86_64-pc-windows-gnullvm"],
                     "config_sha256": digest_bytes(b"fixture Rust config"),
                     "build_sha256": digest_bytes(b"fixture Rust build")},
            "mingw_w64_clang": [{"path": str(self.archives["clang"].relative_to(self.upstream)),
                                 "size": self.archives["clang"].stat().st_size,
                                 "sha256": digest(self.archives["clang"])}],
        }
        self.build_path = self.base / "build.json"
        self.identity_path = self.base / "rust-identity.json"
        put_json(self.build_path, self.build)

    def make_compiler(self, name):
        version = {"clang": CLANG_VERSION + "\nTarget: x86_64-w64-windows-gnu\n",
                   "rust": RUST_VERSION + "\nLLVM version: 21.1.8\n"}[name]
        source = ("import json, os, sys\n"
                  "with open(os.environ['TOOL_CALLS'], 'a') as stream:\n"
                  "    stream.write(json.dumps({'executable': sys.argv[0], 'args': sys.argv[1:]}) + '\\n')\n"
                  "assert sys.argv[1:] == ['--version'], sys.argv\n"
                  f"if os.environ.get('EMPTY_COMPILER_VERSION') != {name!r}:\n"
                  f"    print({version!r}, end='')\n")
        return executable(self.tool_paths[name], source)

    def capture(self, package=None):
        put_json(self.identity_path, self.identity)
        args = ["--upstream", self.upstream, "--provenance", self.build_path,
                "--rust-identity", self.identity_path, "--tools", self.tools]
        if package is not None:
            args += ["--instrumented-package", package]
        return self.helper("capture-pgo-toolchains.py", *args)

    def capture_failure(self, package=None):
        before = self.build_path.read_bytes()
        self.bad(self.capture(package))
        self.assertEqual(self.build_path.read_bytes(), before)
        self.assertFalse(self.build_path.with_suffix(".tmp").exists())

    def test_binds_exact_selected_archive_bytes_versions_rust_identity_and_package(self):
        # Restored compilers can be symlinked wrappers, but must stay in tools.
        for path in self.tool_paths.values():
            real_path = path.parent.parent / "libexec" / path.name
            real_path.parent.mkdir()
            path.replace(real_path)
            path.symlink_to(Path("../libexec") / path.name)
        self.good(self.capture(self.package))
        data = json.loads(self.build_path.read_text())
        expected = copy.deepcopy(self.build)
        expected.update({
            "clang_identity": CLANG_VERSION, "rust_identity": RUST_VERSION,
            "toolchains": {name: {"archive_filename": path.name, "sha256": digest(path),
                                   "size": path.stat().st_size,
                                   "version": CLANG_VERSION if name == "clang" else RUST_VERSION}
                           for name, path in self.archives.items()},
            "pgo_rust_identity": self.identity, "rust_pgo_identity_sha256": digest(self.identity_path),
            "instrumented_package_sha256": digest(self.package),
        })
        self.assertEqual(data, expected)
        self.assertEqual(self.calls(self.tool_calls), [
            {"executable": str(path), "args": ["--version"]} for path in self.tool_paths.values()])
        # A second capture must be byte-identical; unselected outputs are not inputs.
        for path in self.archives.values():
            (path.parent / "aaa-stale-output.tar.zst").write_bytes(b"changed decoy")
        before = self.build_path.read_bytes()
        self.good(self.capture(self.package))
        self.assertEqual(self.build_path.read_bytes(), before)

    def test_package_is_optional_but_explicit_missing_or_empty_package_is_fatal(self):
        self.good(self.capture())
        self.assertNotIn("instrumented_package_sha256", json.loads(self.build_path.read_text()))
        for package in (self.base / "missing-browser.tar.zst", self.package):
            with self.subTest(package=package):
                if package == self.package:
                    package.write_bytes(b"")
                self.capture_failure(package)

    def test_rejects_wrong_upstream_lock_or_overlay(self):
        original = copy.deepcopy(self.identity)
        for field in ("upstream", "overlay"):
            with self.subTest(field=field):
                self.identity = copy.deepcopy(original)
                if field == "upstream":
                    self.identity["upstream"]["commit"] = "f" * 40
                else:
                    self.identity["overlay"]["sha256"] = "f" * 64
                self.capture_failure()
                self.assertFalse(self.tool_calls.exists())

    def test_rejects_mingw_hash_mismatch_or_ambiguous_identity(self):
        original = copy.deepcopy(self.identity["mingw_w64_clang"])
        bad_hash = copy.deepcopy(original)
        bad_hash[0]["sha256"] = "f" * 64
        for records in (bad_hash, [], original * 2):
            with self.subTest(records=records):
                self.identity["mingw_w64_clang"] = records
                self.capture_failure()

    def test_rejects_wrong_identity_bound_rust_filename(self):
        with self.subTest(defect="wrong identity filename"):
            self.identity["rust"]["output_filename"] = "rust-official.tar.xz"
            self.capture_failure()
        with self.subTest(defect="RBM selects official instead of profiler Rust"):
            self.identity["rust"]["output_filename"] = RUST_FILENAME
            self.config["show"]["rust:filename"] = "rust-official.tar.xz"
            (self.archives["rust"].parent / "rust-official.tar.xz").write_bytes(b"official non-PGO Rust")
            self.capture_failure()

    def test_rejects_missing_compiler_or_empty_version_identity(self):
        for name, path in self.tool_paths.items():
            with self.subTest(compiler=name, defect="missing"):
                path.unlink()
                self.capture_failure()
                self.make_compiler(name)
            with self.subTest(compiler=name, defect="empty-version"):
                self.env["EMPTY_COMPILER_VERSION"] = name
                self.capture_failure()
                self.env.pop("EMPTY_COMPILER_VERSION")

    def test_rejects_compiler_symlink_outside_restored_tools(self):
        for name, path in self.tool_paths.items():
            with self.subTest(compiler=name):
                outside = self.base / (name + "-outside-tools")
                shutil.copyfile(path, outside)
                outside.chmod(0o755)
                path.unlink()
                path.symlink_to(outside)
                before_calls = len(self.calls(self.tool_calls))
                self.capture_failure()
                invoked = [record["executable"]
                           for record in self.calls(self.tool_calls)[before_calls:]]
                self.assertNotIn(str(outside), invoked)
                self.assertNotIn(str(path), invoked)
                path.unlink()
                self.make_compiler(name)

    def test_rejects_missing_or_empty_selected_archive_despite_decoys(self):
        for name, path in self.archives.items():
            saved = path.read_bytes()
            for defect in ("missing", "empty"):
                with self.subTest(compiler=name, defect=defect):
                    if defect == "missing":
                        path.unlink()
                    else:
                        path.write_bytes(b"")
                    self.capture_failure()
                    path.write_bytes(saved)


class GenerationHelperTests(NativeFixture):
    def setUp(self):
        super().setUp()
        self.selected = self.upstream / "out/firefox" / FIREFOX_FILENAME
        self.selected.mkdir(parents=True)
        self.project_log = self.upstream / "logs/firefox-windows-x86_64.log"
        self.config["project_log"] = GOOD_LOG
        self.config["build_stdout"] = "RBM stdout is not the project configure log"
        (self.selected / "nsis-plugins.tar.zst").write_bytes(b"NSIS is not Firefox")
        decoy_directory = self.selected.parent / "firefox-unselected-stale"
        decoy_directory.mkdir()
        (decoy_directory / "browser.tar.zst").write_bytes(b"stale runtime decoy")
        (self.selected.parent / "browser.tar.xz").write_bytes(b"wrong output root decoy")
        (self.selected.parent / (FIREFOX_FILENAME + ".tar.zst")).write_bytes(b"wrong flattened output")
        self.destination = self.runtime / "instrumented"

    def generate(self):
        put_json(self.config_path, self.config)
        return self.command("bash", SCRIPTS / "run-pgo-generate.sh")

    def reset_run(self):
        if self.destination.exists():
            shutil.rmtree(self.destination)
        if self.project_log.exists():
            self.project_log.unlink()

    def generation_failure(self):
        self.reset_run()
        self.bad(self.generate())
        self.assertFalse(self.destination.exists())

    def runtime_archive(self, extension="zst"):
        path = self.selected / ("browser.tar." + extension)
        path.write_bytes(b"exact selected instrumented runtime\x00\xff" + extension.encode())
        return path

    def test_selects_browser_runtime_only_from_exact_rbm_output_directory(self):
        for extension in ("zst", "xz"):
            with self.subTest(extension=extension):
                self.reset_run()
                package = self.runtime_archive(extension)
                self.config["project_log"] = GOOD_LOG if extension == "zst" else (
                    CONFIGURE_LOG + CPP_COMMAND.replace("=/tmp/profiles", "")
                    + RUST_COMMAND.replace("-Cprofile-generate=", "-C profile-generate="))
                self.good(self.generate())
                copied = self.destination / package.name
                self.assertEqual(copied.read_bytes(), package.read_bytes())
                self.assertEqual({path.name for path in self.destination.iterdir()},
                                 {package.name, "package.sha256"})
                recorded_hash, recorded_path = (self.destination / "package.sha256").read_text().strip().split(maxsplit=1)
                self.assertEqual(recorded_hash, digest(package))
                self.assertEqual(recorded_path, str(copied))
                commands = [record["args"] for record in self.calls(self.rbm_calls)]
                self.assertIn(["build", "firefox", *TARGET_ARGUMENTS], commands)
                self.assertIn(["showconf", "firefox", "filename", *TARGET_ARGUMENTS], commands)
                self.assertTrue(all(record["cwd"] == str(self.upstream)
                                    for record in self.calls(self.rbm_calls)))
                package.unlink()

    def test_rejects_nsis_only_outputs_and_ambiguous_browser_archives(self):
        with self.subTest(defect="NSIS and decoys only"):
            self.generation_failure()
        for extension in ("zst", "xz"):
            self.runtime_archive(extension)
        with self.subTest(defect="two browser runtimes"):
            self.generation_failure()

    def test_rejects_empty_or_symlink_browser_runtime_archive(self):
        for extension in ("zst", "xz"):
            package = self.selected / ("browser.tar." + extension)
            with self.subTest(extension=extension, defect="empty"):
                package.write_bytes(b"")
                try:
                    self.generation_failure()
                finally:
                    package.unlink()
            with self.subTest(extension=extension, defect="symlink"):
                outside = self.base / ("external-browser.tar." + extension)
                outside.write_bytes(b"nonempty external runtime must not be copied")
                package.symlink_to(outside)
                try:
                    self.generation_failure()
                finally:
                    package.unlink()

    def test_rejects_unsafe_or_empty_rbm_output_filename(self):
        self.runtime_archive()
        for filename in ("", "../" + FIREFOX_FILENAME, str(self.selected)):
            with self.subTest(filename=filename):
                self.config["show"]["firefox:filename"] = filename
                self.generation_failure()

    def test_requires_nonempty_project_configure_log_not_stdout_evidence(self):
        self.runtime_archive()
        self.config["build_stdout"] = GOOD_LOG
        for project_log in (None, "", CPP_COMMAND + RUST_COMMAND):
            with self.subTest(project_log=project_log):
                self.config["project_log"] = project_log
                self.generation_failure()

    def test_requires_both_cpp_and_rust_generation_compiler_flags(self):
        self.runtime_archive()
        self.config["build_stdout"] = GOOD_LOG
        for project_log in (CONFIGURE_LOG + RUST_COMMAND, CONFIGURE_LOG + CPP_COMMAND):
            with self.subTest(missing="C++" if CPP_COMMAND not in project_log else "Rust"):
                self.config["project_log"] = project_log
                self.generation_failure()

    def test_rejects_profile_use_and_failed_rbm_build(self):
        self.runtime_archive()
        with self.subTest(defect="profile-use in generation"):
            self.config["project_log"] = GOOD_LOG + "./mach configure --enable-profile-use=cross\n"
            self.generation_failure()
        with self.subTest(defect="native RBM failure despite plausible logs and output"):
            self.config["project_log"] = GOOD_LOG
            self.config["build_exit"] = 27
            self.generation_failure()


if __name__ == "__main__":
    unittest.main()
