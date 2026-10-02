#!/usr/bin/env python3
"""Offline fixture tests; fake Git/RBM never proves actual 865 or native PGO.

The public saved Rust/Node identity objects below test serialization semantics
only. All integration archive bytes and native namespace evidence are synthetic.
No fixture starts a compiler, fetch, clone, dependency install, or remote API.
"""
import copy
import hashlib
import importlib.util
import io
import contextlib
import json
import os
from pathlib import Path
import shutil
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/validate-pgo-resource-policy.py"
TARGETS = ["alpha", "mullvadbrowser-windows-x86_64", "pgo-generate"]
OFFICIAL_TARGETS = TARGETS[:2]
RUST_CHECKPOINT_FILE_SHA256 = "610dce67882933fdffb6df9c16633ef37c4f5f0e625ebe74d315b1dff44fe2b3"
NODE_CHECKPOINT_CANONICAL_SHA256 = "f93c137e502ea4bbdf5d05b8791ab32a80d1d7d51600867e8a144f83dd3eb78c"
NODE_CHECKPOINT_PRETTY_SHA256 = "c0bf5a26c853512bc67142c2bd41e2f007294ffdbbdf3d62c759f3e669b4d98c"

# Saved public identity JSON, not payload bytes or source/controller proof.
RUST_CHECKPOINT = json.loads(r'''{
  "kind": "firefox-cross-pgo-rust",
  "mingw_w64_clang": [
    {
      "path": "out/mingw-w64-clang/mingw-w64-clang-00349888007f-21.1.8-7b871a.tar.zst",
      "sha256": "f7c2285bdcb245c576ad89398ecca51ec5a5c2410b387952b7a7029dcacdf450",
      "size": 1147155703
    }
  ],
  "overlay": {
    "path": "patches/firefox-pgo-generate.patch",
    "sha256": "0cbac319281d57d5136192775c817bb644ae521cb70b320c48a00fcdd5ff466d"
  },
  "rust": {
    "build_sha256": "4db9c272852cca77d7ef3bb9f1a4901f7e6f5acb2ad8ba3ec424f069ba0c1f63",
    "config_sha256": "af8793678f6a4f5307dc33365f4da3a7d8e6fd1a7bdd7a29ad5da52533f2d015",
    "official_output_filename": "rust-1.94.1-windows-dec527.tar.zst",
    "output_filename": "rust-1.94.1-windows-profiler-20993c.tar.zst",
    "profiler_targets": [
      "x86_64-pc-windows-gnullvm"
    ],
    "rbm_target": "alpha,mullvadbrowser-windows-x86_64,pgo-generate",
    "source_inputs": "---\n- project: container-image\n- name: cmake\n  project: cmake\n- name: '[% c(\"var/compiler\") %]'\n  project: '[% c(\"var/compiler\") %]'\n- enable: '[% c(\"var/linux\") || c(\"var/android\") ]'\n  name: clang\n  project: clang\n- name: ninja\n  project: ninja\n- URL: https://static.rust-lang.org/dist/rustc-[% c(\"version\") %]-src.tar.gz\n  file_gpg_id: 1\n  gpg_keyring: rust.gpg\n  name: rust\n  sig_ext: asc\n- URL: https://static.rust-lang.org/dist/rust-[% c(\"version\") %]-x86_64-unknown-linux-gnu.tar.xz\n  file_gpg_id: 1\n  gpg_keyring: rust.gpg\n  name: rust_prebuilt\n  sig_ext: asc\n- enable: '[% c(\"var/linux\") %]'\n  name: python\n  project: python",
    "std_targets": [
      "x86_64-pc-windows-gnullvm",
      "i686-pc-windows-gnullvm"
    ],
    "version": "1.94.1"
  },
  "schema": 1,
  "upstream": {
    "commit": "7dd751cf1837d667908b339aebf82567ece55e20",
    "repository": "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git",
    "tag": "mb-16.0a9-build1",
    "tag_object": "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721"
  }
}
''')
NODE_CHECKPOINT = json.loads(r'''{
  "build_sha256": "4d4835e8c3f9cfeed1fc8a957a62a3c5e1b05983cf508ce7d4897c9ba1602230",
  "compiler_inputs": [],
  "config_sha256": "70e06036c93c339c8c6a79e04e906e20e0bcd838b076bfddfda782ffc13350b8",
  "container": {
    "arch": "amd64",
    "build_sha256": "13a6e353c4b74d0d58d36cf91be213318e21f67fa6180bf6a76ec556ce72d4dd",
    "config_sha256": "33d02b0e048d348ee3d727f6c3088adda8246e7062bec490cc1e62c610ec5c25",
    "suite": "trixie"
  },
  "kind": "official-rbm-support-node",
  "output_filename": "node-22.16.0-782ba9.tar.zst",
  "project": "node",
  "rbm_conf_sha256": "cf632dc0a9252f6425e528b94a945ea628ea1b38b542348391245233eb206c11",
  "rbm_gitlink": "865f2c9842520958879665d5c9b820d9ed51761e",
  "schema": 1,
  "source": {
    "sha256": "720894f323e5c1ac24968eb2676660c90730d715cb7f090be71a668662a17c37",
    "url": "https://nodejs.org/dist/v22.16.0/node-v22.16.0.tar.xz"
  },
  "source_inputs": "---\n- URL: https://nodejs.org/dist/v[% c(\"var/node_version\") %]/node-v[% c(\"var/node_version\")\n    %].tar.xz\n  name: node\n  sha256sum: '[% c(\"var/node_sha256\") %]'\n- project: container-image\n- enable: '[% c(\"var/linux\") %]'\n  name: binutils\n  project: binutils\n  target:\n  - '[% c(\"var/channel\") %]'\n  - '[% c(\"var/projectname\") %]-linux-x86_64'\n- enable: '[% c(\"var/linux\") %]'\n  name: '[% c(\"var/compiler\") %]'\n  project: '[% c(\"var/compiler\") %]'\n- enable: '[% c(\"var/linux\") %]'\n  name: python\n  project: python",
  "targets": [
    "alpha",
    "mullvadbrowser-windows-x86_64"
  ],
  "upstream": {
    "commit": "7dd751cf1837d667908b339aebf82567ece55e20",
    "repository": "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git",
    "tag": "mb-16.0a9-build1",
    "tag_object": "729e1f7ccd88bbc75f33d29cbf39da26ca2e2721"
  },
  "version": "22.16.0"
}
''')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pretty_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def compact_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pretty_bytes(value))


def install_python(path, source):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!" + sys.executable + "\n" + source, encoding="utf-8")
    path.chmod(0o755)


def native_environment():
    # Test commands do not need controller credentials or unrelated host values.
    keys = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PERL5LIB", "PYTHONPATH")
    return {key: os.environ[key] for key in keys if key in os.environ} | {"PYTHONDONTWRITEBYTECODE": "1"}


def load_validator(path=HELPER):
    spec = importlib.util.spec_from_file_location("pgo_resource_policy_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



class ResourceSerializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_validator()

    def test_saved_rust610_is_exact_sorted_pretty_file_not_compact_object(self):
        pretty = pretty_bytes(RUST_CHECKPOINT)
        self.assertEqual(len(pretty), 1988)
        self.assertEqual(digest(pretty), RUST_CHECKPOINT_FILE_SHA256)
        self.assertNotEqual(self.policy.canonical_sha(RUST_CHECKPOINT), RUST_CHECKPOINT_FILE_SHA256)
        self.assertEqual(self.policy.strict_json(pretty), RUST_CHECKPOINT)
        self.assertTrue(pretty.endswith(b"\n"))
        self.assertNotEqual(digest(pretty.rstrip(b"\n")), RUST_CHECKPOINT_FILE_SHA256)
        # Parsing equality cannot replace immutable Rust FILE-byte equality.
        compact = compact_bytes(RUST_CHECKPOINT)
        self.assertEqual(self.policy.strict_json(compact), RUST_CHECKPOINT)
        self.assertNotEqual(digest(compact), RUST_CHECKPOINT_FILE_SHA256)

    def test_saved_nodef93_is_canonical_object_not_pretty_file(self):
        self.assertEqual(self.policy.canonical_sha(NODE_CHECKPOINT), NODE_CHECKPOINT_CANONICAL_SHA256)
        self.assertEqual(digest(pretty_bytes(NODE_CHECKPOINT)), NODE_CHECKPOINT_PRETTY_SHA256)
        self.assertNotEqual(NODE_CHECKPOINT_PRETTY_SHA256, NODE_CHECKPOINT_CANONICAL_SHA256)
        # Reordered/compact presentation is valid Node identity, not Rust identity.
        reordered = dict(reversed(list(NODE_CHECKPOINT.items())))
        self.assertEqual(self.policy.canonical_sha(reordered), NODE_CHECKPOINT_CANONICAL_SHA256)
        self.assertEqual(self.policy.strict_json(compact_bytes(reordered)), NODE_CHECKPOINT)

    def test_canonical_hash_uses_ascii_escapes_no_newline_and_sorted_keys(self):
        value = {"z": "\u2603", "a": {"é": "\U0001f680"}}
        expected = digest(compact_bytes(value))
        self.assertEqual(self.policy.canonical_sha(value), expected)
        utf8 = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertNotEqual(expected, digest(utf8))
        self.assertNotEqual(expected, digest(compact_bytes(value) + b"\n"))

    def test_every_rust_identity_leaf_is_bound_by_exact_file_hash(self):
        for path, original in identity_leaves(RUST_CHECKPOINT):
            with self.subTest(path=path):
                mutated = copy.deepcopy(RUST_CHECKPOINT)
                set_leaf(mutated, path, different(original))
                self.assertNotEqual(digest(pretty_bytes(mutated)), RUST_CHECKPOINT_FILE_SHA256)
                self.assertNotEqual(self.policy.strict_json(pretty_bytes(mutated)), RUST_CHECKPOINT)

    def test_every_node_identity_leaf_is_bound_by_canonical_object_hash(self):
        for path, original in identity_leaves(NODE_CHECKPOINT):
            with self.subTest(path=path):
                mutated = copy.deepcopy(NODE_CHECKPOINT)
                set_leaf(mutated, path, different(original))
                self.assertNotEqual(self.policy.canonical_sha(mutated), NODE_CHECKPOINT_CANONICAL_SHA256)
                self.assertNotEqual(self.policy.strict_json(pretty_bytes(mutated)), NODE_CHECKPOINT)

    def test_identity_additions_deletions_and_empty_compiler_input_changes_are_not_equal(self):
        for original, expected, hash_fn in (
                (RUST_CHECKPOINT, RUST_CHECKPOINT_FILE_SHA256, lambda value: digest(pretty_bytes(value))),
                (NODE_CHECKPOINT, NODE_CHECKPOINT_CANONICAL_SHA256, self.policy.canonical_sha)):
            for path, value in identity_objects(original):
                for operation in ("add", "delete"):
                    with self.subTest(identity=original["kind"], path=path, operation=operation):
                        changed = copy.deepcopy(original)
                        selected = get_leaf(changed, path)
                        if operation == "add":
                            selected["unexpected_fixture_field"] = "fixture"
                        else:
                            del selected[next(iter(value))]
                        self.assertNotEqual(hash_fn(changed), expected)
            changed = copy.deepcopy(original)
            if original is NODE_CHECKPOINT:
                changed["compiler_inputs"] = ["unexpected compiler branch"]
                self.assertNotEqual(hash_fn(changed), expected)

    def test_strict_json_rejects_duplicate_keys_at_every_depth_without_private_values(self):
        for raw in (b'{"schema":1,"schema":1}',
                    b'{"rust":{"version":"private-secret","version":"x"}}',
                    b'{"a":[{"same":1,"same":2}]}'):
            with self.subTest(raw=raw):
                with self.assertRaises(self.policy.GateError) as failure:
                    self.policy.strict_json(raw)
                self.assertNotIn("private-secret", str(failure.exception))

    def test_strict_json_rejects_nonfinite_trailing_malformed_and_non_utf8_values(self):
        for raw in (b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}',
                    b'{}{}', b'{"broken":', b'\xff', b'{"x":"\xff"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(self.policy.GateError):
                    self.policy.strict_json(raw)

    def test_strict_json_enforces_raw_byte_limit(self):
        with self.assertRaises(self.policy.GateError):
            self.policy.strict_json(b'{"private":"never-print-this"}', max_bytes=8)
        self.assertEqual(self.policy.strict_json(b'{}', max_bytes=2), {})


def identity_leaves(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from identity_leaves(child, path + (key,))
    elif isinstance(value, list) and value:
        for index, child in enumerate(value):
            yield from identity_leaves(child, path + (index,))
    else:
        yield path, value


def identity_objects(value, path=()):
    if isinstance(value, dict):
        if value:
            yield path, value
        for key, child in value.items():
            yield from identity_objects(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from identity_objects(child, path + (index,))


def get_leaf(value, path):
    for part in path:
        value = value[part]
    return value


def set_leaf(value, path, replacement):
    parent = get_leaf(value, path[:-1])
    parent[path[-1]] = replacement


def different(value):
    if type(value) is int:
        return value + 1
    if isinstance(value, str):
        return value + "-fixture-change"
    if isinstance(value, list):
        return value + ["unexpected-fixture-item"]
    raise AssertionError("unsupported fixture leaf")


class ResourceNativeRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_validator()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-native-runner-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.environment = native_environment()

    def native(self, source, *, seconds=1, total=2):
        return self.policy.run_native([sys.executable, "-c", source], cwd=self.base,
                                      environment=self.environment,
                                      deadline=self.policy.Deadline(total), seconds=seconds)

    def assert_dead(self, pid):
        # SIGKILL delivery is asynchronous. Wait on the kernel exit event.
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            ready, _, _ = select.select([descriptor], [], [], 1)
            self.assertTrue(ready, "owned native descendant survived cleanup")
        finally:
            os.close(descriptor)

    def test_native_exit_status_and_both_streams_are_lossless(self):
        result = self.native("import os; os.write(1,b'out\\r\\n'); os.write(2,b'err\\r\\n'); raise SystemExit(7)")
        self.assertEqual(result, (7, b"out\r\n", b"err\r\n"))

    def test_native_deadline_kills_private_session(self):
        before = time.monotonic()
        with self.assertRaisesRegex(self.policy.GateError, "native_deadline"):
            self.native("import signal; signal.pause()", seconds=0.12)
        self.assertLess(time.monotonic() - before, 2)

    def test_expired_global_deadline_does_not_start_native_program(self):
        marker = self.base / "started"
        with self.assertRaisesRegex(self.policy.GateError, "global_deadline"):
            self.native(f"open({str(marker)!r}, 'w').write('started')", total=-1)
        self.assertFalse(marker.exists())

    def test_global_deadline_bounds_longer_per_call_deadline(self):
        with self.assertRaisesRegex(self.policy.GateError, "native_deadline"):
            self.native("import signal; signal.pause()", seconds=5, total=0.12)

    def test_stdout_and_stderr_share_one_bounded_capture(self):
        with self.assertRaisesRegex(self.policy.GateError, "native_output_limit"):
            self.native("import os; os.write(1,b'A'*140000); os.write(2,b'B'*140000)")

    def test_missing_native_program_has_public_fixed_code(self):
        with self.assertRaisesRegex(self.policy.GateError, "native_start_failed") as failure:
            self.policy.run_native([str(self.base / "private-missing-program")], cwd=self.base,
                                   environment=self.environment, deadline=self.policy.Deadline(1))
        self.assertNotIn("private-missing", str(failure.exception))

    def test_exit_leader_with_inherited_pipe_orphan_is_killed_on_deadline(self):
        pidfile = self.base / "pid"
        code = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"
                "'import signal; signal.pause()']); "
                f"open({str(pidfile)!r},'w').write(str(p.pid)); print('done',flush=True)")
        with self.assertRaisesRegex(self.policy.GateError, "native_deadline"):
            self.native(code, seconds=0.2)
        self.assert_dead(int(pidfile.read_text()))

    def test_exit_leader_with_closed_stdio_orphan_is_still_killed(self):
        pidfile = self.base / "pid"
        code = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"
                "'import signal; signal.pause()'],stdin=subprocess.DEVNULL,"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                f"open({str(pidfile)!r},'w').write(str(p.pid)); print('done',flush=True)")
        status, stdout, stderr = self.native(code)
        self.assertEqual((status, stdout, stderr), (0, b"done\n", b""))
        self.assert_dead(int(pidfile.read_text()))


MOZCONFIG_PREFIX = (
    '# Synthetic operational fixture, not a Firefox build.\n'
    'ac_add_options --enable-optimize="-O2"\n'
    'ac_add_options --enable-debug-symbols\n'
    'ac_add_options --disable-tests\n'
    'ac_add_options --disable-crashreporter\n'
    'export CFLAGS="-O2 -g1 -flto=thin"\n'
    'export RUSTFLAGS="-Ccodegen-units=1 -Cprofile-generate"\n'
)


def operational_mozconfig(count):
    return MOZCONFIG_PREFIX + f"mk_add_options MOZ_PARALLEL_BUILD={count}\n"


def operational_build(count, *, pack=False):
    compression = max(2, count)
    text = ('#!/bin/bash\nset -e\n'
            f'export XZ_DEFAULTS="-T{compression}"\n'
            f'export ZSTD_NBTHREADS={compression}\n'
            'export CXXFLAGS="-O2 -g1 -flto=thin -fprofile-generate"\n'
            './mach configure \\\n  --with-distribution-id=org.torproject \\\n'
            '  --enable-profile-generate=cross \\\n  --without-wasm-sandboxed-libraries\n'
            './mach build --verbose\n')
    if pack:
        text += f"xz --threads={compression} -f 'firefox-140.4.0.tar'\n"
    return text


class ResourceNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_validator()

    def normalize(self, text, count, kind):
        return self.policy.normalize_rendered(text, count, kind)

    def test_only_moz_parallel_line_normalizes_four_two_one(self):
        results = [self.normalize(operational_mozconfig(count), count, "mozconfig")
                   for count in (4, 2, 1)]
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])
        for required in ('-O2', '-g1', '-flto=thin', '-Ccodegen-units=1',
                         '-Cprofile-generate', '--disable-crashreporter'):
            self.assertIn(required, results[0])

    def test_compression_uses_at_least_two_threads_for_metadata_one(self):
        results = [self.normalize(operational_build(count), count, "build")
                   for count in (4, 2, 1)]
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])
        self.assertIn('--enable-profile-generate=cross', results[0])
        self.assertIn('-fprofile-generate', results[0])
        self.assertIn('-flto=thin', results[0])

    def test_optional_exact_pinned_pack_xz_position_normalizes(self):
        results = [self.normalize(operational_build(count, pack=True), count, "build")
                   for count in (4, 2, 1)]
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_moz_resource_line_wrong_count_duplicate_missing_or_mutated_is_rejected(self):
        valid = operational_mozconfig(2)
        for bad in (valid.replace('MOZ_PARALLEL_BUILD=2', 'MOZ_PARALLEL_BUILD=4'),
                    valid + 'mk_add_options MOZ_PARALLEL_BUILD=2\n',
                    valid.replace('mk_add_options MOZ_PARALLEL_BUILD=2\n', ''),
                    valid.replace('mk_add_options MOZ_PARALLEL_BUILD=2',
                                  'mk_add_options MOZ_PARALLEL_BUILD=2; echo private'),
                    valid.replace('MOZ_PARALLEL_BUILD=2', 'MOZ_PARALLEL_BUILD=02')):
            with self.subTest(bad=bad):
                with self.assertRaises(self.policy.GateError):
                    self.normalize(bad, 2, "mozconfig")

    def test_build_export_lines_are_unique_exact_and_bound_to_count(self):
        valid = operational_build(2)
        for bad in (valid.replace('XZ_DEFAULTS="-T2"', 'XZ_DEFAULTS="-T1"'),
                    valid.replace('ZSTD_NBTHREADS=2', 'ZSTD_NBTHREADS=1'),
                    valid + 'export XZ_DEFAULTS="-T2"\n',
                    valid + 'export ZSTD_NBTHREADS=2\n',
                    valid.replace('export XZ_DEFAULTS="-T2"\n', ''),
                    valid.replace('export ZSTD_NBTHREADS=2\n', ''),
                    valid.replace('XZ_DEFAULTS="-T2"', 'XZ_DEFAULTS="-T2 -9"'),
                    valid.replace('ZSTD_NBTHREADS=2', 'ZSTD_NBTHREADS=02')):
            with self.subTest(bad=bad):
                with self.assertRaises(self.policy.GateError):
                    self.normalize(bad, 2, "build")

    def test_one_cpu_compression_one_is_never_valid(self):
        bad = operational_build(1).replace('XZ_DEFAULTS="-T2"', 'XZ_DEFAULTS="-T1"')
        with self.assertRaises(self.policy.GateError):
            self.normalize(bad, 1, "build")

    def assert_not_erased(self, kind, extra_four, extra_two):
        maker = operational_mozconfig if kind == "mozconfig" else operational_build
        left = maker(4) + extra_four
        right = maker(2) + extra_two
        try:
            normalized_left = self.normalize(left, 4, kind)
            normalized_right = self.normalize(right, 2, kind)
        except self.policy.GateError:
            return  # A stricter rejection is also fail-closed.
        self.assertNotEqual(normalized_left, normalized_right,
                            "unapproved non-resource change was erased")

    def test_no_generic_numeric_job_lto_cpp_rust_or_profile_flag_whitelist(self):
        changes = [
            ('make -j4\n', 'make -j2\n'),
            ('./mach build -j4\n', './mach build -j2\n'),
            ('export CFLAGS="-O4"\n', 'export CFLAGS="-O2"\n'),
            ('export CFLAGS="-flto=4"\n', 'export CFLAGS="-flto=2"\n'),
            ('export CFLAGS="-fprofile-generate=4"\n', 'export CFLAGS="-fprofile-generate=2"\n'),
            ('export RUSTFLAGS="-Ccodegen-units=4"\n', 'export RUSTFLAGS="-Ccodegen-units=2"\n'),
            ('export RUSTFLAGS="-Copt-level=4"\n', 'export RUSTFLAGS="-Copt-level=2"\n'),
            ('export CARGO_BUILD_JOBS=4\n', 'export CARGO_BUILD_JOBS=2\n'),
            ('export CPPFLAGS="-DWORKERS=4"\n', 'export CPPFLAGS="-DWORKERS=2"\n'),
            ('ar archive-4.tar\n', 'ar archive-2.tar\n'),
            ('export PRIVATE_NUMBER=4\n', 'export PRIVATE_NUMBER=2\n'),
            ('# constant 4\n', '# constant 2\n'),
            ('xz -T4 -f arbitrary.tar\n', 'xz -T2 -f arbitrary.tar\n'),
            ('xz --threads=4 -f arbitrary.tar\n', 'xz --threads=2 -f arbitrary.tar\n'),
        ]
        for kind in ("mozconfig", "build"):
            for left, right in changes:
                with self.subTest(kind=kind, left=left):
                    self.assert_not_erased(kind, left, right)

    def test_pgo_and_hardening_flags_cannot_be_removed_by_resource_normalization(self):
        for kind, old, new in (
                ("mozconfig", '--disable-crashreporter', '--enable-crashreporter'),
                ("mozconfig", '-Cprofile-generate', '-Cprofile-use=unverified'),
                ("mozconfig", '-flto=thin', '-flto=full'),
                ("mozconfig", '-Ccodegen-units=1', '-Ccodegen-units=2'),
                ("build", '--enable-profile-generate=cross', '--disable-rust'),
                ("build", '-fprofile-generate', '-fprofile-use=unverified'),
                ("build", '-flto=thin', '-flto=full')):
            maker = operational_mozconfig if kind == "mozconfig" else operational_build
            with self.subTest(kind=kind, old=old):
                try:
                    original = self.normalize(maker(4), 4, kind)
                    changed = self.normalize(maker(2).replace(old, new), 2, kind)
                except self.policy.GateError:
                    continue
                self.assertNotEqual(original, changed)

    def test_renderer_kind_cpu_count_and_byte_cap_are_closed(self):
        for kind, count in (("arbitrary", 2), ("mozconfig", 3), ("mozconfig", 0),
                            ("mozconfig", True), ("build", False)):
            with self.subTest(kind=kind, count=count):
                with self.assertRaises(self.policy.GateError):
                    self.normalize(operational_mozconfig(1), count, kind)
        with self.assertRaises(self.policy.GateError):
            self.normalize(operational_mozconfig(2) + "X" * 300000, 2, "mozconfig")

    def test_crlf_or_trailing_command_bytes_are_not_silently_canonicalized(self):
        baseline = self.normalize(operational_mozconfig(4), 4, "mozconfig")
        for bad in (operational_mozconfig(2).replace('\n', '\r\n'),
                    operational_mozconfig(2) + '\n',
                    operational_mozconfig(2) + '# extra text\n'):
            with self.subTest(bad=bad):
                try:
                    changed = self.normalize(bad, 2, "mozconfig")
                except self.policy.GateError:
                    continue
                self.assertNotEqual(baseline, changed)


class PolicyInputFixture:
    """Small restored-input data, never actual compiler or official payload bytes."""
    def make_inputs(self):
        self.upstream = self.base / "upstream with spaces"
        self.upstream.mkdir()
        self.support = self.base / "node support"
        self.support.mkdir()
        self.rust_file = self.base / "rust identity.json"
        self.provenance_file = self.base / "provenance.json"
        self.output = self.base / "policy.json"
        self.diagnostic = self.base / "diagnostics"
        self.lock = copy.deepcopy(RUST_CHECKPOINT["upstream"])
        self.rust = copy.deepcopy(RUST_CHECKPOINT)
        self.node = copy.deepcopy(NODE_CHECKPOINT)
        self.source_files = {
            "rbm.conf": b"# synthetic RBM configuration\n",
            "projects/rust/config": b"# synthetic instrumentable Rust recipe\n",
            "projects/rust/build": b"# synthetic Rust build recipe, never executed\n",
            "projects/node/config": b"# synthetic official Node recipe\n",
            "projects/node/build": b"# synthetic Node recipe, never executed\n",
            "projects/container-image/config": b"# synthetic container recipe\n",
            "projects/container-image/build": b"# synthetic container build, never executed\n",
        }
        for relative, content in self.source_files.items():
            path = self.upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.rust["rust"]["config_sha256"] = digest(self.source_files["projects/rust/config"])
        self.rust["rust"]["build_sha256"] = digest(self.source_files["projects/rust/build"])
        self.node["config_sha256"] = digest(self.source_files["projects/node/config"])
        self.node["build_sha256"] = digest(self.source_files["projects/node/build"])
        self.node["rbm_conf_sha256"] = digest(self.source_files["rbm.conf"])
        self.node["container"]["config_sha256"] = digest(self.source_files["projects/container-image/config"])
        self.node["container"]["build_sha256"] = digest(self.source_files["projects/container-image/build"])
        self.compiler_filename = Path(self.rust["mingw_w64_clang"][0]["path"]).name
        self.rust_filename = self.rust["rust"]["output_filename"]
        self.node_filename = self.node["output_filename"]
        self.archive_bytes = {
            "out/mingw-w64-clang/" + self.compiler_filename: b"synthetic compiler archive, never executable",
            "out/rust/" + self.rust_filename: b"synthetic profiler Rust archive, never executable",
            "out/node/" + self.node_filename: b"synthetic official Node archive, never executable",
        }
        for relative, content in self.archive_bytes.items():
            path = self.upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        compiler = self.archive_descriptor("out/mingw-w64-clang/" + self.compiler_filename)
        self.rust["mingw_w64_clang"] = [
            {"path": "out/mingw-w64-clang/" + self.compiler_filename, **compiler}]
        write_json(self.rust_file, self.rust)
        self.rust_sha = digest(self.rust_file.read_bytes())
        self.node_sha = digest(compact_bytes(self.node))
        self.node_record = {"identity_sha256": self.node_sha, "archive_filename": self.node_filename,
                            **self.archive_descriptor("out/node/" + self.node_filename)}
        self.node_support = {"release": "pgo-support-" + self.lock["tag"] + "-" + self.node_sha,
                             **self.node_record}
        self.node_registry = {
            "schema": 1, "stage": "node", "upstream": self.lock, "identity": self.node,
            "artifacts": [{"path": "out/node/" + self.node_filename, "project": "node",
                           "filename": self.node_filename,
                           "asset": "rbm-" + self.lock["commit"][:12] + "--node--" + self.node_filename,
                           **self.archive_descriptor("out/node/" + self.node_filename)}],
        }
        self.workload = b"# public synthetic profileserver workload, never executed\n"
        self.provenance = {
            "schema": 2, "upstream_lock": self.lock,
            "firefox": {"repository": "https://gitlab.torproject.org/tpo/applications/mullvad-browser.git",
                        "ref": "mullvad-browser-140.4.0esr-16.0-1-build1", "revision": "a" * 40},
            "profileserver": {"path": "build/pgo/profileserver.py", "revision": "a" * 40,
                              "sha256": digest(self.workload)},
            "pgo_overlay_sha256": self.rust["overlay"]["sha256"],
            "pgo_languages": ["c++", "rust"], "generation_targets": TARGETS,
            "generation_configure_flags": ["--enable-profile-generate=cross"],
            "browser_executable": "mullvadbrowser.exe",
            "clang_identity": "clang version 21.1.8 (synthetic fixture)",
            "rust_identity": "rustc 1.94.1 (synthetic fixture)",
            "rust_pgo_identity_sha256": self.rust_sha,
            "pgo_rust_identity": self.rust,
            "toolchains": {
                "clang": {"archive_filename": self.compiler_filename, **compiler,
                          "version": "clang version 21.1.8 (synthetic fixture)"},
                "rust": {"archive_filename": self.rust_filename,
                         **self.archive_descriptor("out/rust/" + self.rust_filename),
                         "version": "rustc 1.94.1 (synthetic fixture)"},
            },
            "build_support": {"node": self.node_record},
        }
        self.selected_inputs = [
            {"filename": Path(relative).name, "path": str(self.upstream / relative),
             "kind": "project", "project": relative.split("/")[1],
             "id": "fixture-id:" + digest(data), "checksums": {}}
            for relative, data in sorted(self.archive_bytes.items())
        ]
        self.write_inputs()
        self.environment = native_environment()
        for key in ("RBM_NUM_PROCS", "OMP_NUM_THREADS", "OMP_THREAD_LIMIT"):
            self.environment.pop(key, None)
        self.environment.update({"GITHUB_SHA": "f" * 40, "GITHUB_RUN_ID": "12345",
                                 "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "gen",
                                 "RUNNER_TEMP": str(self.base / "runner-temp"),
                                 "PYTHONDONTWRITEBYTECODE": "1"})
        self.general_archive_bytes = {
            "out/clang/clang-21.1.8-official-fixture.tar.zst": b"synthetic original Clang restored archive",
            "out/rust/" + self.rust["rust"]["official_output_filename"]: b"synthetic original Rust restored archive",
        }
        for relative, content in self.general_archive_bytes.items():
            path = self.upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        directory.mkdir(parents=True)
        self.general_registries = {}
        for stage, relative in (
                ("clang", "out/clang/clang-21.1.8-official-fixture.tar.zst"),
                ("mingw-w64-clang", "out/mingw-w64-clang/" + self.compiler_filename),
                ("rust", "out/rust/" + self.rust["rust"]["official_output_filename"]),
                ("rust-pgo", "out/rust/" + self.rust_filename)):
            project, filename = relative.split("/")[1], Path(relative).name
            registry = {"schema": 1, "stage": stage, "upstream": self.lock,
                        "identity": self.rust if stage == "rust-pgo" else {"upstream": self.lock},
                        "artifacts": [{"path": relative, "project": project, "filename": filename,
                                       "asset": "rbm-" + self.lock["commit"][:12] + "--" + project + "--" + filename,
                                       **self.archive_descriptor(relative)}]}
            self.general_registries[stage] = registry
            write_json(directory / ("registry-" + stage + ".json"), registry)
        self.args = type("FixtureArguments", (), {})()
        for key, value in {"upstream": self.upstream, "rust_identity": self.rust_file,
                           "node_support_directory": self.support,
                           "provenance": self.provenance_file, "output": self.output,
                           "diagnostic_directory": self.diagnostic}.items():
            setattr(self.args, key, value)

    def archive_descriptor(self, relative):
        data = (self.upstream / relative).read_bytes()
        return {"sha256": digest(data), "size": len(data)}

    def write_inputs(self):
        write_json(self.rust_file, self.rust)
        write_json(self.support / "node-identity.json", self.node)
        write_json(self.support / "node-support.json", self.node_support)
        write_json(self.support / "registry/registry-node.json", self.node_registry)
        write_json(self.provenance_file, self.provenance)

    def cli_arguments(self):
        return ["--upstream", str(self.upstream), "--rust-identity", str(self.rust_file),
                "--node-support-directory", str(self.support), "--provenance", str(self.provenance_file),
                "--output", str(self.output), "--diagnostic-directory", str(self.diagnostic)]


class ResourceInputBindingTests(PolicyInputFixture, unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-input-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.make_inputs()
        self.policy = load_validator()
        for name, value in (("EXPECTED_RUST_SHA", self.rust_sha), ("EXPECTED_NODE_SHA", self.node_sha)):
            patcher = patch.object(self.policy, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def load(self):
        return self.policy.load_inputs(self.args)

    def rejected(self, expected=None):
        with self.assertRaises(self.policy.GateError) as failure:
            self.load()
        if expected is not None:
            self.assertEqual(str(failure.exception), expected)
        self.assertFalse(self.output.exists())
        return str(failure.exception)

    def test_complete_small_fixture_binds_exact_file_object_archives_and_source_scope(self):
        inputs = self.load()
        self.assertEqual(inputs["rust"], self.rust)
        self.assertEqual(inputs["rust_raw"], self.rust_file.read_bytes())
        self.assertEqual(inputs["node"], self.node)
        self.assertEqual(inputs["provenance"], self.provenance)
        self.assertEqual(set(inputs["archives"]), set(self.archive_bytes))
        self.assertEqual(self.policy.archive_records(self.upstream, inputs, self.policy.Deadline(5)),
                         inputs["archives"])
        self.assertNotEqual(self.rust_sha, RUST_CHECKPOINT_FILE_SHA256)
        self.assertNotEqual(self.node_sha, NODE_CHECKPOINT_CANONICAL_SHA256)
        self.assertNotIn("instrumented_package_sha256", self.provenance)
        self.assertNotIn("training", self.provenance)

    def test_rust_compact_or_missing_newline_is_rejected_even_with_file_sha_patched(self):
        for changed in (compact_bytes(self.rust), pretty_bytes(self.rust).rstrip(b"\n")):
            with self.subTest(changed=changed[:20]):
                self.rust_file.write_bytes(changed)
                with patch.object(self.policy, "EXPECTED_RUST_SHA", digest(changed)):
                    self.rejected("rust_complete_identity_mismatch")
        self.rust_file.write_bytes(pretty_bytes(self.rust))

    def test_node_compact_presentation_uses_unchanged_canonical_identity(self):
        (self.support / "node-identity.json").write_bytes(compact_bytes(self.node))
        self.assertEqual(self.load()["node"], self.node)

    def test_node_pretty_file_sha_is_not_accepted_as_canonical_release_key(self):
        wrong = digest(pretty_bytes(self.node))
        self.assertNotEqual(wrong, self.node_sha)
        with patch.object(self.policy, "EXPECTED_NODE_SHA", wrong):
            self.rejected("node_complete_identity_mismatch")

    def test_every_rust_and_node_manifest_leaf_mutation_is_rejected(self):
        for name, original, path in (("rust", self.rust, self.rust_file),
                                     ("node", self.node, self.support / "node-identity.json")):
            for keypath, value in identity_leaves(original):
                with self.subTest(identity=name, path=keypath):
                    changed = copy.deepcopy(original)
                    set_leaf(changed, keypath, different(value))
                    write_json(path, changed)
                    self.rejected(name + "_complete_identity_mismatch")
            write_json(path, original)

    def test_manifest_key_deletion_or_addition_at_any_object_depth_is_rejected(self):
        for name, original, path in (("rust", self.rust, self.rust_file),
                                     ("node", self.node, self.support / "node-identity.json")):
            for keypath, value in identity_objects(original):
                for operation in ("add", "delete"):
                    with self.subTest(identity=name, path=keypath, operation=operation):
                        changed = copy.deepcopy(original)
                        selected = get_leaf(changed, keypath)
                        if operation == "add":
                            selected["unexpected_fixture_field"] = 1
                        else:
                            del selected[next(iter(value))]
                        write_json(path, changed)
                        self.rejected(name + "_complete_identity_mismatch")
            write_json(path, original)

    def test_all_generation_targets_flags_languages_executable_and_overlay_are_required(self):
        changes = {
            "schema": 1,
            "upstream_lock": {**self.lock, "commit": "0" * 40},
            "pgo_rust_identity": {**self.rust, "kind": "changed"},
            "rust_pgo_identity_sha256": digest(compact_bytes(self.rust)),
            "pgo_overlay_sha256": "0" * 64,
            "pgo_languages": ["c++"],
            "generation_targets": list(reversed(TARGETS)),
            "generation_configure_flags": ["--enable-profile-use"],
            "browser_executable": "firefox.exe",
        }
        for key, replacement in changes.items():
            with self.subTest(key=key):
                changed = copy.deepcopy(self.provenance)
                changed[key] = replacement
                write_json(self.provenance_file, changed)
                self.rejected()
        write_json(self.provenance_file, self.provenance)

    def test_profile_workload_path_revision_and_hash_must_remain_source_bound(self):
        for key, replacement in (("path", "other/profileserver.py"), ("revision", "b" * 40),
                                 ("sha256", "not-a-digest")):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.provenance)
                changed["profileserver"][key] = replacement
                write_json(self.provenance_file, changed)
                self.rejected("invalid_source_binding")
        write_json(self.provenance_file, self.provenance)

    def test_compiler_descriptors_reject_extra_keys_bad_bytes_boolean_size_and_identity_drift(self):
        for name in ("clang", "rust"):
            for key, replacement in (("sha256", "bad"), ("size", True), ("size", 0),
                                     ("archive_filename", "../escape.tar.zst"),
                                     ("version", ""), ("version", "different compiler version")):
                with self.subTest(name=name, key=key, replacement=replacement):
                    changed = copy.deepcopy(self.provenance)
                    changed["toolchains"][name][key] = replacement
                    write_json(self.provenance_file, changed)
                    self.rejected()
            changed = copy.deepcopy(self.provenance)
            changed["toolchains"][name]["unbound"] = "extra field"
            write_json(self.provenance_file, changed)
            self.rejected("invalid_toolchain_binding")
        write_json(self.provenance_file, self.provenance)

    def test_every_node_build_support_descriptor_field_matches_the_committed_registry(self):
        for key, replacement in (("identity_sha256", "0" * 64), ("archive_filename", "other.tar.zst"),
                                 ("sha256", "0" * 64), ("size", self.node_record["size"] + 1),
                                 ("size", True)):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.provenance)
                changed["build_support"]["node"][key] = replacement
                write_json(self.provenance_file, changed)
                self.rejected()
        write_json(self.provenance_file, self.provenance)

    def test_node_support_metadata_release_and_every_record_field_are_required(self):
        support_path = self.support / "node-support.json"
        for key in self.node_support:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.node_support)
                del changed[key]
                write_json(support_path, changed)
                self.rejected("node_support_record_mismatch")
        changed = copy.deepcopy(self.node_support)
        changed["extra"] = "private-not-printed"
        write_json(support_path, changed)
        self.rejected("node_support_record_mismatch")
        write_json(support_path, self.node_support)

    def test_node_registry_requires_exact_identity_upstream_stage_and_one_matching_archive(self):
        path = self.support / "registry/registry-node.json"
        mutations = []
        for key, replacement in (("schema", 2), ("stage", "rust"), ("upstream", {}), ("identity", {}),
                                 ("artifacts", []), ("artifacts", self.node_registry["artifacts"] * 2)):
            value = copy.deepcopy(self.node_registry)
            value[key] = replacement
            mutations.append(value)
        for key, replacement in (("path", "out/node/other.tar.zst"), ("project", "rust"),
                                 ("filename", "other.tar.zst"), ("sha256", "0" * 64),
                                 ("size", 1), ("size", True)):
            value = copy.deepcopy(self.node_registry)
            value["artifacts"][0][key] = replacement
            mutations.append(value)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                write_json(path, changed)
                self.rejected()
        write_json(path, self.node_registry)

    def test_restored_archives_are_hashed_not_accepted_by_filename_or_size(self):
        inputs = self.load()
        for relative, original in self.archive_bytes.items():
            path = self.upstream / relative
            with self.subTest(archive=relative):
                path.write_bytes(b"X" * len(original))
                with self.assertRaisesRegex(self.policy.GateError, "restored_archive_bytes_mismatch"):
                    self.policy.archive_records(self.upstream, inputs, self.policy.Deadline(5))
                path.write_bytes(original)

    def test_missing_empty_symlink_or_hardlinked_restored_archive_is_rejected(self):
        relative = next(iter(self.archive_bytes))
        path, original = self.upstream / relative, self.archive_bytes[relative]
        for mode in ("missing", "empty", "symlink", "hardlink"):
            with self.subTest(mode=mode):
                inputs = self.load()
                path.unlink()
                target = self.base / ("archive-" + mode)
                if mode == "empty":
                    path.write_bytes(b"")
                elif mode == "symlink":
                    target.write_bytes(original)
                    path.symlink_to(target)
                elif mode == "hardlink":
                    path.write_bytes(original)
                    os.link(path, target)
                with self.assertRaises(self.policy.GateError):
                    self.policy.archive_records(self.upstream, inputs, self.policy.Deadline(5))
                path.unlink(missing_ok=True)
                target.unlink(missing_ok=True)
                path.write_bytes(original)

    def test_identity_and_provenance_assets_reject_symlink_and_hardlink_components(self):
        original = self.rust_file.read_bytes()
        target = self.base / "identity-target"
        target.write_bytes(original)
        self.rust_file.unlink()
        self.rust_file.symlink_to(target)
        self.rejected("unsafe_path")
        self.rust_file.unlink()
        os.link(target, self.rust_file)
        self.rejected("unsafe_regular_file")
        self.rust_file.unlink()
        self.rust_file.write_bytes(original)

    def test_duplicate_or_private_input_errors_have_fixed_diagnostics(self):
        self.rust_file.write_bytes(b'{"private-secret-key":"private-secret-value","private-secret-key":1}')
        code = self.rejected("json_duplicate_key")
        self.assertNotIn("private-secret", code)


class PolicyMechanicsFixture(PolicyInputFixture):
    """Mocked metadata cases test policy mechanics, not native RBM authority."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-policy-mechanics-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.make_inputs()
        self.policy = load_validator()
        self.actual_affinity = sorted(os.sched_getaffinity(0))
        self.actual_environment = dict(os.environ)
        self.parent = [8, 11, 16, 19]
        self.seen_cases = []
        self.before_archives = copy.deepcopy(self.archive_bytes)
        self.sources = {name: digest(data) for name, data in self.source_files.items()}
        self.case_mutation = None
        self.patchers = []
        self.mock_method("EXPECTED_RUST_SHA", self.rust_sha)
        self.mock_method("EXPECTED_NODE_SHA", self.node_sha)
        self.mock_method("source_records", return_value=self.sources)
        self.mock_method("execute_case", side_effect=self.case)
        self.mock_method("os.sched_getaffinity", return_value=set(self.parent))

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.assertEqual(sorted(os.sched_getaffinity(0)), self.actual_affinity)
        self.assertTrue(dict(os.environ) == self.actual_environment, "parent environment changed")

    def mock_method(self, name, value=None, **kwargs):
        target, key = (self.policy.os, name.split(".")[1]) if name.startswith("os.") else (self.policy, name)
        patcher = patch.object(target, key, value, **kwargs) if value is not None else patch.object(target, key, **kwargs)
        patched = patcher.start()
        self.patchers.append(patcher)
        return patched

    def case(self, args, cpus, count, inputs, environment, deadline, namespace, case):
        self.seen_cases.append({"cpus": list(cpus), "count": count, "path": case,
                                "environment": {key: environment[key] for key in self.policy.INFLUENCERS if key in environment}})
        self.assertFalse(args.output.exists(), "policy created before all metadata cases passed")
        moz, build = operational_mozconfig(count), operational_build(count)
        result = {
            "metadata": {"schema": 1, "num_procs": count, "logical_cpu_count": 64,
                         "affinity": list(cpus), "path_tiny_version": "0.144",
                         "path_tiny_source_sha256": "e" * 64,
                         "atomic_spew_hardlink_verified": True},
            "filenames": {"firefox": "firefox-mullvad-140.4.0-windows-x86_64-fixture",
                          "rust-profiler": self.rust_filename,
                          "rust-official": self.rust["rust"]["official_output_filename"],
                          "mingw": self.compiler_filename, "node": self.node_filename,
                          "selected_inputs": copy.deepcopy(self.selected_inputs),
                          "named": {"rust": self.rust_filename, "node": self.node_filename,
                                    "mingw-w64-clang": self.compiler_filename,
                                    "nasm": "nasm-2.16-fixture.tar.zst"}},
            "normalized": {"mozconfig": self.policy.normalize_rendered(moz, count, "mozconfig"),
                           "build": self.policy.normalize_rendered(build, count, "build")},
            "mozconfig": moz, "build": build,
        }
        if self.case_mutation:
            self.case_mutation(count, result)
        return result

    def validate(self):
        return self.policy.validate(self.args, environment=self.environment)

    def failure(self, code=None):
        with self.assertRaises(self.policy.GateError) as failure:
            self.validate()
        if code:
            self.assertEqual(str(failure.exception), code)
        self.assertFalse(self.output.exists(), "failed gate created an executable policy")
        report = json.loads((self.diagnostic / "validation.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["compiled_browser_verified"])
        self.assertFalse(report["profile_training_verified"])
        self.assertEqual(report["error"]["code"], str(failure.exception))
        return report



class ResourcePolicyMechanicsTests(PolicyMechanicsFixture, unittest.TestCase):
    def test_policy_exact_contract_keys_only_after_three_metadata_cases(self):
        policy = self.validate()
        self.assertEqual(set(policy), {"schema", "kind", "verified", "target", "binding", "upstream_lock",
                         "rbm_commit", "parent_affinity", "selected_affinity", "expected_num_procs",
                         "rust_identity_sha256", "node_identity_sha256"})
        self.assertEqual(policy["schema"], 1)
        self.assertIs(policy["verified"], True)
        self.assertEqual(policy["kind"], "pgo-generation-resource-policy")
        self.assertEqual(policy["target"], "pgo-generate")
        self.assertEqual(policy["parent_affinity"], self.parent)
        self.assertEqual(policy["selected_affinity"], self.parent[:2])
        self.assertEqual(policy["expected_num_procs"], 2)
        self.assertEqual(policy["rust_identity_sha256"], self.rust_sha)
        self.assertEqual(policy["node_identity_sha256"], self.node_sha)
        self.assertEqual(policy["binding"], {"head": "f" * 40, "run": "12345", "attempt": "1",
                                          "job": "gen", "upstream": str(self.upstream)})
        self.assertEqual(json.loads(self.output.read_text()), policy)
        self.assertEqual([(case["cpus"], case["count"]) for case in self.seen_cases],
                         [(self.parent, 4), (self.parent[:2], 2), (self.parent[:1], 1)])
        for case in self.seen_cases:
            self.assertTrue(all(key not in case["environment"] for key in self.policy.INFLUENCERS))
        report = json.loads((self.diagnostic / "validation.json").read_text())
        self.assertEqual(report["status"], "verified-metadata-only")
        self.assertEqual([row["case"] for row in report["cases"]],
                         ["baseline", "selected-two", "one-metadata-only"])
        self.assertFalse(report["compiled_browser_verified"])
        self.assertFalse(report["profile_training_verified"])
        self.assertFalse(any(path.name.startswith(".private-native-") for path in self.diagnostic.iterdir()))
        self.assertFalse(list(self.base.rglob(".resource-policy-*")))
        self.assertTrue(all((self.upstream / name).read_bytes() == data
                            for name, data in self.before_archives.items()))

    def test_one_cpu_is_comparison_only_and_never_automatic_build_retry(self):
        def fail_selected(count, record):
            if count == 2:
                raise self.policy.GateError("native_nonzero")
        self.case_mutation = fail_selected
        self.failure("native_nonzero")
        self.assertEqual([case["count"] for case in self.seen_cases], [4, 2])

    def test_non_resource_render_change_prevents_policy(self):
        def change(count, record):
            if count == 2:
                record["normalized"]["build"] += 'export CFLAGS="-flto=full"\n'
        self.case_mutation = change
        self.failure("non_resource_render_change")

    def test_every_selected_filename_and_named_dependency_must_match_baseline(self):
        for label in ("firefox", "rust-profiler", "rust-official", "mingw", "node", "named"):
            with self.subTest(label=label):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                def change(count, record):
                    if count == 2:
                        if label == "named":
                            record["filenames"][label]["nasm"] = "different-nasm.tar.zst"
                        else:
                            record["filenames"][label] += "-changed"
                self.case_mutation = change
                self.failure("selected_filename_change")

    def test_host_path_tiny_version_logical_count_and_source_bytes_must_match_modes(self):
        for field, replacement in (("logical_cpu_count", 65), ("path_tiny_version", "0.146"),
                                   ("path_tiny_source_sha256", "d" * 64)):
            with self.subTest(field=field):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                def change(count, record):
                    if count == 2:
                        record["metadata"][field] = replacement
                self.case_mutation = change
                self.failure("host_metadata_change")

    def test_source_change_after_native_case_is_rejected(self):
        with patch.object(self.policy, "source_records", side_effect=[self.sources, {**self.sources, "rbm.conf": "0" * 64}]):
            self.failure("source_changed")

    def test_general_restored_registry_archives_are_verified_even_when_not_metadata_selected(self):
        relative = "out/nasm/nasm-general-fixture.tar.zst"
        path = self.upstream / relative
        path.parent.mkdir()
        original = b"synthetic registered general archive"
        path.write_bytes(original)
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        directory.mkdir(parents=True, exist_ok=True)
        registry = {"schema": 1, "stage": "nasm", "upstream": self.lock,
                    "artifacts": [{"path": relative, "project": "nasm", "filename": path.name,
                                   "asset": "rbm-general-fixture.tar.zst", **self.archive_descriptor(relative)}]}
        write_json(directory / "registry-nasm.json", registry)
        path.write_bytes(b"X" * len(original))
        self.failure("restored_archive_bytes_mismatch")
        self.assertFalse(self.seen_cases, "metadata started before existing registered archive authentication")

    def test_existing_registered_archive_mutation_after_metadata_is_fail_closed(self):
        relative = "out/nasm/nasm-general-fixture.tar.zst"
        path = self.upstream / relative
        path.parent.mkdir()
        original = b"synthetic registered general archive"
        path.write_bytes(original)
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        directory.mkdir(parents=True, exist_ok=True)
        registry = {"schema": 1, "stage": "nasm", "upstream": self.lock,
                    "artifacts": [{"path": relative, "project": "nasm", "filename": path.name,
                                   "asset": "rbm-general-fixture.tar.zst", **self.archive_descriptor(relative)}]}
        write_json(directory / "registry-nasm.json", registry)
        def mutate(count, record):
            if count == 1:
                path.write_bytes(b"X" * len(original))
        self.case_mutation = mutate
        self.failure("unexpected_runtime_mutation")

    def test_ignored_node_registry_asset_extra_bytes_are_still_immutable_after_cases(self):
        def mutate(count, record):
            if count == 1:
                changed = copy.deepcopy(self.node_registry)
                changed["artifacts"][0]["asset"] += "-changed"
                write_json(self.support / "registry/registry-node.json", changed)
        self.case_mutation = mutate
        self.failure("source_or_identity_changed")

    def test_new_archive_or_source_clone_side_effect_is_rejected(self):
        for relative in ("out/node/new-output.tar.zst", "git_clones/unexpected/object"):
            with self.subTest(relative=relative):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                def mutate(count, record):
                    if count == 4:
                        path = self.upstream / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(b"must-not-build-or-fetch")
                self.case_mutation = mutate
                self.failure("unexpected_runtime_mutation")
                (self.upstream / relative).unlink()

    def test_empty_source_clone_creation_is_rejected_but_empty_output_dirs_are_metadata_only(self):
        def mutate(count, record):
            if count == 4:
                (self.upstream / "git_clones/new-empty-clone").mkdir(parents=True)
        self.case_mutation = mutate
        self.failure("unexpected_runtime_mutation")
        shutil.rmtree(self.upstream / "git_clones")
        shutil.rmtree(self.diagnostic)
        def metadata_directory(count, record):
            (self.upstream / "out/cbindgen").mkdir(exist_ok=True)
        self.case_mutation = metadata_directory
        self.assertTrue(self.validate()["verified"])
        self.assertFalse(list((self.upstream / "out/cbindgen").iterdir()))

    def test_changed_archive_bytes_are_rejected_after_cases_before_policy(self):
        relative = "out/rust/" + self.rust_filename
        def mutate(count, record):
            if count == 1:
                path = self.upstream / relative
                path.write_bytes(b"X" * len(self.archive_bytes[relative]))
        self.case_mutation = mutate
        self.failure("selected_restored_archive_mismatch")

    def test_generated_mozconfig_may_refresh_only_exact_id_time_baseline(self):
        generated = self.upstream / "out/firefox/mozconfig"
        generated.parent.mkdir()
        def mutate(count, record):
            generated.write_text(operational_mozconfig(4))
        self.case_mutation = mutate
        self.assertTrue(self.validate()["verified"])
        self.output.unlink()
        shutil.rmtree(self.diagnostic)
        def unexpected(count, record):
            generated.write_text('private unexpected generated content\n')
        self.case_mutation = unexpected
        report = self.failure("unexpected_generated_mozconfig")
        self.assertNotIn("private unexpected", json.dumps(report))

    def test_registries_manifests_and_provenance_must_remain_equal_after_cases(self):
        def mutate(count, record):
            if count == 1:
                changed = copy.deepcopy(self.provenance)
                changed["generation_configure_flags"] = ["--disable-rust"]
                write_json(self.provenance_file, changed)
        self.case_mutation = mutate
        self.failure("generation_scope_mismatch")

    def test_influencer_presence_even_empty_value_fails_before_metadata(self):
        for name in self.policy.INFLUENCERS:
            for value in ("", "private-influencer-value"):
                with self.subTest(name=name, value=value):
                    if self.diagnostic.exists():
                        shutil.rmtree(self.diagnostic)
                    self.environment[name] = value
                    report = self.failure("uncontrolled_cpu_environment")
                    self.assertNotIn("private-influencer-value", json.dumps(report))
                    self.environment.pop(name)
        self.assertFalse(self.seen_cases)

    def test_credentials_fail_before_metadata_and_never_enter_public_evidence(self):
        for name in ("PGO_TELEMETRY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
            with self.subTest(name=name):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                self.environment[name] = "private-credential-value"
                report = self.failure("unexpected_credential_environment")
                self.assertNotIn("private-credential-value", json.dumps(report))
                self.environment.pop(name)
        self.assertFalse(self.seen_cases)

    def test_all_four_existing_compiler_registries_are_required_before_metadata(self):
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        for stage in ("clang", "mingw-w64-clang", "rust", "rust-pgo"):
            with self.subTest(stage=stage):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                path = directory / ("registry-" + stage + ".json")
                original = path.read_bytes()
                path.unlink()
                self.failure("missing_restored_compiler_registry")
                path.write_bytes(original)
        self.assertFalse(self.seen_cases)

    def test_non_four_cpu_parent_fails_without_promoting_one_cpu_fallback(self):
        for cpus in ([8], [8, 11], [8, 11, 16], [8, 11, 16, 19, 21]):
            with self.subTest(cpus=cpus):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                with patch.object(self.policy.os, "sched_getaffinity", return_value=set(cpus)):
                    self.failure("expected_four_cpu_parent")
        self.assertFalse(self.seen_cases)

    def test_invalid_run_binding_fails_without_echoing_private_values(self):
        for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"):
            with self.subTest(key=key):
                if self.diagnostic.exists():
                    shutil.rmtree(self.diagnostic)
                original = self.environment[key]
                self.environment[key] = "private-invalid/binding"
                report = self.failure("invalid_run_binding")
                self.assertNotIn("private-invalid/binding", json.dumps(report))
                self.environment[key] = original
        self.assertFalse(self.seen_cases)

    def test_existing_policy_cannot_be_replaced_on_failure(self):
        self.output.write_bytes(b"existing-public-policy")
        with self.assertRaisesRegex(self.policy.GateError, "unsafe_or_existing_policy"):
            self.validate()
        self.assertEqual(self.output.read_bytes(), b"existing-public-policy")
        self.assertFalse(self.seen_cases)

    def test_output_or_diagnostics_cannot_overlap_upstream(self):
        for key in ("output", "diagnostic_directory"):
            original = getattr(self.args, key)
            for value in (self.upstream, self.upstream / "nested/evidence", self.upstream.parent):
                with self.subTest(key=key, value=value):
                    setattr(self.args, key, value)
                    with self.assertRaises(self.policy.GateError):
                        self.validate()
                    self.assertFalse(self.output.exists())
            setattr(self.args, key, original)
        self.assertFalse(self.seen_cases)

    def test_private_native_case_directory_removed_on_failure(self):
        def fail(count, record):
            directory = self.seen_cases[-1]["path"]
            (directory / "private-native-stderr").write_text("private-native-secret")
            raise self.policy.GateError("native_nonzero")
        self.case_mutation = fail
        report = self.failure("native_nonzero")
        self.assertNotIn("private-native-secret", json.dumps(report))
        self.assertEqual([path.name for path in self.diagnostic.iterdir()], ["validation.json"])

    def test_final_policy_write_failure_never_leaves_policy_or_native_temporary_assets(self):
        original_atomic = self.policy.atomic_json
        def atomic(path, value, *args, **kwargs):
            if path == self.output:
                raise self.policy.GateError("report_write_failed")
            return original_atomic(path, value, *args, **kwargs)
        with patch.object(self.policy, "atomic_json", side_effect=atomic):
            self.failure("report_write_failed")
        self.assertFalse(list(self.base.rglob(".resource-policy-*")))
        self.assertFalse(any(path.name.startswith(".private-native-") for path in self.diagnostic.iterdir()))

    def test_public_failure_report_is_bounded_and_contains_only_fixed_native_error(self):
        with patch.object(self.policy, "execute_case", side_effect=self.policy.GateError("native_output_limit")):
            report = self.failure("native_output_limit")
        raw = (self.diagnostic / "validation.json").read_bytes()
        self.assertLess(len(raw), 64 * 1024)
        self.assertNotIn(str(self.base).encode(), raw)
        self.assertEqual(report["cases"], [])


FAKE_POLICY_CONTAINER = r"""
import json, os, sys
from pathlib import Path
config = json.loads(Path(os.environ['POLICY_NATIVE_CONFIG']).read_text())
args = sys.argv[1:]
assert args[:3] == ['run', '--disable-network', '--'], 'not the approved no-chroot controller'
with Path(os.environ['POLICY_NATIVE_CALLS']).open('a') as stream:
    stream.write(json.dumps({'args': args[:3], 'cwd': str(Path.cwd()),
                             'affinity': sorted(os.sched_getaffinity(0))}) + '\n')
if config.get('native_nonzero'):
    print('private-native-credential', file=sys.stderr)
    raise SystemExit(23)
if config.get('flood'):
    sys.stdout.buffer.write(b'private-native-credential' * 20000)
    raise SystemExit(0)
command = args[3:]
assert command[1] == '-c', 'namespace evidence wrapper was replaced'
if config.get('widen'):
    os.sched_setaffinity(0, set(config['parent_cpus']))
namespace = os.readlink('/proc/self/ns/net') if config.get('same_namespace') else 'net:[0]'
prefix = 'import os; os.readlink=lambda path: ' + repr(namespace) + '\n'
if config.get('influencer'):
    prefix += "os.environ['OMP_NUM_THREADS']='private-influencer-secret'\n"
command[2] = prefix + command[2]
os.execv(command[0], command)
"""


class ResourceOfflineNativeTests(unittest.TestCase):
    """Fake namespace values test transport/masking, never actual network isolation."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-offline-native-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.upstream = self.base / "upstream with spaces"
        self.upstream.mkdir()
        self.config = self.base / "fixture.json"
        self.calls = self.base / "calls.jsonl"
        install_python(self.upstream / "rbm/container", FAKE_POLICY_CONTAINER)
        self.policy = load_validator()
        self.parent = sorted(os.sched_getaffinity(0))
        if len(self.parent) < 2:
            self.skipTest("native mask fixture needs two currently allowed CPUs")
        self.environment = native_environment()
        for key in self.policy.INFLUENCERS:
            self.environment.pop(key, None)
        self.environment.update({"POLICY_NATIVE_CONFIG": str(self.config),
                                 "POLICY_NATIVE_CALLS": str(self.calls),
                                 "PYTHONDONTWRITEBYTECODE": "1"})
        self.settings = {"parent_cpus": self.parent}
        self.config.write_text(json.dumps(self.settings))
        self.namespace = os.readlink("/proc/self/ns/net")

    def tearDown(self):
        self.assertEqual(sorted(os.sched_getaffinity(0)), self.parent)

    def configure(self, **values):
        self.settings.update(values)
        self.config.write_text(json.dumps(self.settings))

    def offline(self, source, cpus=None):
        return self.policy.offline([sys.executable, "-c", source], cpus or self.parent[:2],
                                   self.upstream, self.environment, self.policy.Deadline(5), self.namespace)

    def test_native_mask_uses_actual_allowed_nonzero_members_and_original_project_cwd(self):
        self.assertEqual(self.offline("import os,json; print(json.dumps(sorted(os.sched_getaffinity(0))))"),
                         (json.dumps(self.parent[:2]) + "\n").encode())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"], ["run", "--disable-network", "--"])
        self.assertEqual(calls[0]["cwd"], str(self.upstream))
        self.assertEqual(calls[0]["affinity"], self.parent[:2])

    def test_namespace_exec_resolves_relative_perl_from_original_path_without_rewriting_argv(self):
        perl = self.base / "bin/perl"
        install_python(perl, "import json,os,sys; print(json.dumps({'argv':sys.argv[1:],'cwd':os.getcwd(),"
                       "'affinity':sorted(os.sched_getaffinity(0)),'sentinel':os.environ['PUBLIC_SENTINEL']}))")
        environment = self.environment | {"PATH": str(perl.parent) + os.pathsep + self.environment["PATH"],
                                          "PUBLIC_SENTINEL": "fixture-preserved-value"}
        original_argv = ["perl", "--upstream", "path with spaces", "--output-directory", "case directory"]
        raw = self.policy.offline(original_argv, self.parent[:2], self.upstream, environment,
                                  self.policy.Deadline(5), self.namespace)
        self.assertEqual(json.loads(raw), {"argv": original_argv[1:], "cwd": str(self.upstream),
                          "affinity": self.parent[:2], "sentinel": "fixture-preserved-value"})
        self.assertEqual(original_argv[0], "perl", "wrapper changed original renderer argv")
        self.assertEqual(sorted(os.sched_getaffinity(0)), self.parent)

    def test_one_cpu_is_native_metadata_mask_only(self):
        self.assertEqual(self.offline("import os; print(len(os.sched_getaffinity(0)))", self.parent[:1]), b"1\n")
        self.assertEqual(sorted(os.sched_getaffinity(0)), self.parent)

    def test_native_same_namespace_is_not_an_offline_proof(self):
        self.configure(same_namespace=True)
        with self.assertRaisesRegex(self.policy.GateError, "invalid_namespace_evidence"):
            self.offline("print('metadata')")

    def test_native_mask_widening_is_rejected(self):
        if len(self.parent) == 2:
            self.skipTest("widening fixture needs more than two allowed CPUs")
        self.configure(widen=True)
        with self.assertRaisesRegex(self.policy.GateError, "invalid_namespace_evidence"):
            self.offline("print('metadata')")

    def test_native_nonzero_is_not_retried_and_does_not_echo_stderr(self):
        self.configure(native_nonzero=True)
        with self.assertRaisesRegex(self.policy.GateError, "native_nonzero") as failure:
            self.offline("print('metadata')")
        self.assertNotIn("private-native", str(failure.exception))
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)

    def test_namespace_injected_cpu_influencer_is_fail_closed_without_private_values(self):
        self.configure(influencer=True)
        with self.assertRaises(self.policy.GateError) as failure:
            self.offline("print('metadata')")
        self.assertNotIn("private-influencer-secret", str(failure.exception))

    def test_native_output_flood_is_capped_with_fixed_error(self):
        self.configure(flood=True)
        with self.assertRaisesRegex(self.policy.GateError, "native_output_limit") as failure:
            self.offline("print('metadata')")
        self.assertNotIn("private-native", str(failure.exception))

    def test_showconf_preserves_target_order_no_fetch_and_exact_arguments(self):
        captured = []
        def fake(command, *arguments):
            captured.append((command, arguments))
            return b"safe-filename.tar.zst\n"
        with patch.object(self.policy, "offline", side_effect=fake):
            selected = self.policy.showconf(self.upstream, "rust", "filename", TARGETS,
                       self.parent[:2], self.environment, self.policy.Deadline(1), self.namespace)
        self.assertEqual(selected, "safe-filename.tar.zst")
        command = captured[0][0]
        self.assertEqual(command[:5], ["perl", "-I", str(self.upstream / "rbm/lib"), "-MRBM", "-e"])
        self.assertEqual(command[5], self.policy.NATIVE_GUARD_CODE)
        self.assertEqual(command[6:], [str(self.upstream), "rust", "filename", json.dumps(TARGETS), "showconf"])
        self.assertIn("reject() if RBM::git_need_fetch", command[5])

    def test_namespace_missing_extra_boolean_affinity_and_private_text_are_rejected(self):
        good = {"affinity": self.parent[:2], "network_namespace": "net:[0]"}
        mutations = [b"not-namespace-private\nmetadata", b"", b"PGO_RESOURCE_NS {}\nmetadata"]
        for key, value in (("affinity", [True, self.parent[1]]), ("network_namespace", "private-net"),
                           ("network_namespace", self.namespace), ("affinity", self.parent[:1])):
            changed = dict(good)
            changed[key] = value
            mutations.append(b"PGO_RESOURCE_NS " + compact_bytes(changed) + b"\nmetadata")
        changed = {**good, "unexpected": "private-secret"}
        mutations.append(b"PGO_RESOURCE_NS " + compact_bytes(changed) + b"\nmetadata")
        for raw in mutations:
            with self.subTest(raw=raw[:30]):
                with patch.object(self.policy, "checked", return_value=raw):
                    with self.assertRaises(self.policy.GateError) as failure:
                        self.offline("print('metadata')")
                    self.assertNotIn("private", str(failure.exception))


class ResourceCaseBindingTests(PolicyInputFixture, unittest.TestCase):
    """Synthetic resolver/render writes exercise full objects and native argv."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-case-binding-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.make_inputs()
        self.policy = load_validator()
        for name, value in (("EXPECTED_RUST_SHA", self.rust_sha), ("EXPECTED_NODE_SHA", self.node_sha)):
            patcher = patch.object(self.policy, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.inputs = self.policy.load_inputs(self.args)
        self.cpus = [8, 11]
        self.count = 2
        self.rust_regenerated = self.rust_file.read_bytes()
        self.node_regenerated = self.node
        self.metadata = {"schema": 1, "num_procs": 2, "logical_cpu_count": 64,
                         "affinity": self.cpus, "path_tiny_version": "0.144",
                         "path_tiny_source_sha256": "e" * 64,
                         "atomic_spew_hardlink_verified": True}
        self.mozconfig = operational_mozconfig(2)
        self.build = operational_build(2)
        self.commands = []
        self.names = {"rust": self.rust_filename, "node": self.node_filename,
                      "mingw-w64-clang": self.compiler_filename, "nasm": "nasm-2.16-fixture.tar.zst"}
        self.selected = {("firefox", "filename", True): "firefox-mullvad-140.4.0-windows-x86_64-fixture",
                         ("rust", "filename", True): self.rust_filename,
                         ("rust", "filename", False): self.rust["rust"]["official_output_filename"],
                         ("mingw-w64-clang", "filename", True): self.compiler_filename,
                         ("node", "filename", False): self.node_filename,
                         ("firefox", "git_url", True): self.provenance["firefox"]["repository"],
                         ("firefox", "git_hash", True): self.provenance["firefox"]["ref"],
                         ("firefox", "var/git_commit", True): self.provenance["firefox"]["revision"],
                         ("firefox", "var/exe_name", True): "mullvadbrowser"}

    def offline(self, command, cpus, upstream, environment, deadline, namespace):
        self.commands.append(command)
        self.assertEqual(cpus, self.cpus)
        self.assertEqual(upstream, self.upstream)
        self.assertTrue(all(key not in environment for key in self.policy.INFLUENCERS))
        if command[0] == sys.executable:
            self.assertEqual(command[1], "-c")
            self.assertEqual(command[2], self.policy.RESOLVER_CODE)
            self.assertEqual(command[3], str(HELPER))
            name = Path(command[4]).name
            self.assertIn(name, ("resolve-pgo-rust-identity.py", "resolve-pgo-support-identity.py"))
            self.assertEqual(command[5:7], ["--upstream", str(self.upstream)])
            self.assertEqual(command[7], "--output")
            path = Path(command[8])
            if name == "resolve-pgo-rust-identity.py":
                path.write_bytes(self.rust_regenerated)
            else:
                write_json(path, self.node_regenerated)
            return b"ignored successful resolver output\n"
        if command[0] == "perl" and Path(command[1]).name == "render-pgo-resource-metadata.pl":
            self.assertEqual(command[2:4], ["--upstream", str(self.upstream)])
            self.assertEqual(command[4], "--output-directory")
            directory = Path(command[5])
            directory.mkdir()
            write_json(directory / "metadata.json", self.metadata)
            (directory / "mozconfig.operational").write_text(self.mozconfig)
            (directory / "firefox-build.operational").write_text(self.build)
            return b""
        self.assertEqual(command, self.policy.perl_command(self.upstream, "firefox", "", TARGETS, "named"))
        self.assertIn("git_need_fetch", command[5])
        return compact_bytes({"named": self.names, "selected_inputs": self.selected_inputs}) + b"\n"

    def showconf(self, upstream, project, key, targets, cpus, environment, deadline, namespace):
        self.assertEqual(upstream, self.upstream)
        self.assertEqual(cpus, self.cpus)
        self.assertIn(tuple(targets), (tuple(TARGETS), tuple(OFFICIAL_TARGETS)))
        return self.selected[(project, key, "pgo-generate" in targets)]

    def execute(self):
        case = self.base / "case"
        if case.exists():
            shutil.rmtree(case)
        case.mkdir()
        with patch.object(self.policy, "offline", side_effect=self.offline), \
             patch.object(self.policy, "showconf", side_effect=self.showconf):
            return self.policy.execute_case(self.args, self.cpus, self.count, self.inputs,
                       self.environment, self.policy.Deadline(5), "net:[1]", case)

    def rejected(self, expected):
        with self.assertRaises(self.policy.GateError) as failure:
            self.execute()
        self.assertEqual(str(failure.exception), expected)
        self.assertFalse(self.output.exists())

    def test_full_case_uses_existing_resolvers_exact_targeted_renderer_and_named_inputs(self):
        result = self.execute()
        self.assertEqual(result["metadata"], self.metadata)
        self.assertEqual(result["filenames"]["named"], self.names)
        self.assertEqual(result["mozconfig"], self.mozconfig)
        self.assertEqual(result["build"], self.build)
        self.assertEqual(len(self.commands), 4)
        self.assertEqual([Path(command[4]).name for command in self.commands[:2]],
                         ["resolve-pgo-rust-identity.py", "resolve-pgo-support-identity.py"])
        self.assertEqual(self.commands[2], self.policy.perl_command(self.upstream, "firefox", "", TARGETS, "named"))
        self.assertEqual(Path(self.commands[3][1]).name, "render-pgo-resource-metadata.pl")

    def test_rust_regeneration_requires_complete_equal_object_and_exact_old_file_bytes(self):
        for path, value in identity_leaves(self.rust):
            with self.subTest(path=path):
                changed = copy.deepcopy(self.rust)
                set_leaf(changed, path, different(value))
                self.rust_regenerated = pretty_bytes(changed)
                self.rejected("regenerated_rust_identity_mismatch")
        self.rust_regenerated = compact_bytes(self.rust)
        self.rejected("regenerated_rust_identity_mismatch")

    def test_node_regeneration_requires_complete_canonical_equal_object(self):
        for path, value in identity_leaves(self.node):
            with self.subTest(path=path):
                changed = copy.deepcopy(self.node)
                set_leaf(changed, path, different(value))
                self.node_regenerated = changed
                self.rejected("regenerated_node_identity_mismatch")

    def test_renderer_requires_exact_seven_keys_host_source_sha_and_atomic_link_proof(self):
        for field in self.metadata:
            with self.subTest(missing=field):
                original = self.metadata
                self.metadata = {key: value for key, value in original.items() if key != field}
                self.rejected("invalid_renderer_metadata")
                self.metadata = original
        for field, value in (("schema", True), ("num_procs", True), ("num_procs", 1),
                             ("affinity", [True, 11]), ("affinity", [8]),
                             ("logical_cpu_count", True), ("path_tiny_version", "private-invalid"),
                             ("path_tiny_source_sha256", "not-a-digest"),
                             ("atomic_spew_hardlink_verified", False),
                             ("atomic_spew_hardlink_verified", 1)):
            with self.subTest(field=field, value=value):
                original = self.metadata
                self.metadata = {**original, field: value}
                self.rejected("invalid_renderer_metadata")
                self.metadata = original
        self.metadata["private-extra-field"] = "private-value"
        self.rejected("invalid_renderer_metadata")

    def test_generation_command_must_have_one_cross_flag_no_profile_use_and_verbose_native_build(self):
        original = self.build
        for bad in (original.replace('--enable-profile-generate=cross', ''),
                    original + '--enable-profile-generate=cross\n',
                    original + '--enable-profile-use=private-profile\n',
                    original.replace('./mach configure', 'echo configure'),
                    original.replace('./mach build --verbose', './mach build')):
            with self.subTest(bad=bad[:40]):
                self.build = bad
                self.rejected("generation_configure_render_mismatch")
        self.build = original

    def test_each_selected_identity_filename_and_source_tuple_field_is_checked(self):
        for key in self.selected:
            with self.subTest(key=key):
                original = self.selected[key]
                self.selected[key] += "-changed"
                expected = "selected_source_scope_mismatch" if key[1] != "filename" else "selected_identity_filename_mismatch"
                if key[0] == "firefox" and key[1] == "filename":
                    # Firefox output is compared across modes by validate(), not a source identity.
                    self.execute()
                else:
                    self.rejected(expected)
                self.selected[key] = original

    def test_named_inputs_require_exact_compiler_node_rust_and_safe_all_dependency_names(self):
        original = copy.deepcopy(self.names)
        for key in ("rust", "node", "mingw-w64-clang"):
            with self.subTest(key=key):
                self.names = {**original, key: "wrong-archive.tar.zst"}
                self.rejected("named_compiler_selection_mismatch")
        for bad in ({}, {**original, "nasm": "../escape.tar.zst"},
                    {**original, "private/key": "nasm-fixture.tar.zst"}, {**original, "nasm": True}):
            with self.subTest(bad=bad):
                self.names = bad
                self.rejected("invalid_named_inputs")
        self.names = original


class ResourceNativeGitAuthorityTests(unittest.TestCase):
    """Real local Git objects verify mechanics, not actual locked RBM865 source."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-local-git-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repository = self.base / "local repository"
        self.environment = native_environment()
        self.git_environment = self.environment | {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        self.policy = load_validator()
        self.native_git("init", "--quiet", str(self.repository), outside=True)
        self.source = self.repository / "source.txt"
        self.source.write_bytes(b"original fixture source\n")
        self.native_git("add", "source.txt")
        self.native_git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "original")
        self.original = self.native_git("rev-parse", "HEAD").decode().strip()
        self.source.write_bytes(b"replacement fixture source\n")
        self.native_git("add", "source.txt")
        self.native_git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "replacement")
        self.replacement = self.native_git("rev-parse", "HEAD").decode().strip()
        self.native_git("reset", "--hard", "--quiet", self.original)

    def native_git(self, *arguments, outside=False):
        result = subprocess.run(["git", "--no-pager", "-c", "core.hooksPath=/dev/null", *arguments],
                                cwd=self.base if outside else self.repository, env=self.git_environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, "offline local Git fixture command failed")
        return result.stdout

    def test_native_replace_ref_does_not_change_validator_git_tree_bytes(self):
        self.native_git("replace", self.original, self.replacement)
        self.assertEqual(self.native_git("show", "HEAD:source.txt"), b"replacement fixture source\n")
        self.assertEqual(self.policy.git(self.repository, ["show", "HEAD:source.txt"],
                                        self.environment, self.policy.Deadline(5)), b"original fixture source\n")
        self.assertIn(self.original.encode(), self.native_git("replace", "--list"))

    def test_graft_and_custom_replace_environment_rejected_even_empty_without_values(self):
        for key in ("GIT_GRAFT_FILE", "GIT_REPLACE_REF_BASE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                    "GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            for value in ("", "private-git-authority-value"):
                with self.subTest(key=key, value=value):
                    environment = self.environment | {key: value}
                    with self.assertRaisesRegex(self.policy.GateError, "uncontrolled_git_authority_environment") as failure:
                        self.policy.git(self.repository, ["rev-parse", "HEAD"], environment, self.policy.Deadline(5))
                    self.assertNotIn("private-git-authority-value", str(failure.exception))

    def test_git_replace_disable_cannot_be_overridden_in_native_authority_environment(self):
        with self.assertRaisesRegex(self.policy.GateError, "uncontrolled_git_authority_environment"):
            self.policy.git(self.repository, ["rev-parse", "HEAD"],
                            self.environment | {"GIT_NO_REPLACE_OBJECTS": "0"}, self.policy.Deadline(5))

    def test_every_git_command_disables_replacements_hooks_and_fsmonitor(self):
        with patch.object(self.policy, "checked", return_value=b"fixture") as checked:
            self.policy.git(self.repository, ["show", "HEAD:source.txt"], self.environment, self.policy.Deadline(5))
        command = checked.call_args.args[0]
        self.assertEqual(command[:3], ["git", "--no-replace-objects", "--no-pager"])
        self.assertIn("core.fsmonitor=false", command)
        self.assertIn("core.hooksPath=/dev/null", command)


class ResourceAtomicEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_validator()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-atomic-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.output = self.base / "policy.json"

    def test_atomic_json_matches_exact_pretty_bytes_and_leaves_no_temporary_asset(self):
        value = {"kind": "public fixture", "schema": 1}
        self.policy.atomic_json(self.output, value)
        self.assertEqual(self.output.read_bytes(), pretty_bytes(value))
        self.assertEqual([path.name for path in self.base.iterdir()], ["policy.json"])

    def test_atomic_json_failed_rename_preserves_existing_destination_and_cleans_temp(self):
        self.output.write_bytes(b"original immutable destination")
        with patch.object(self.policy.os, "replace", side_effect=OSError("private-system-error")):
            with self.assertRaisesRegex(self.policy.GateError, "report_write_failed") as failure:
                self.policy.atomic_json(self.output, {"schema": 1})
        self.assertNotIn("private-system-error", str(failure.exception))
        self.assertEqual(self.output.read_bytes(), b"original immutable destination")
        self.assertEqual([path.name for path in self.base.iterdir()], ["policy.json"])

    def test_atomic_json_size_limit_never_creates_destination(self):
        with self.assertRaisesRegex(self.policy.GateError, "report_limit"):
            self.policy.atomic_json(self.output, {"large": "X" * 70000})
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.base.iterdir()))

    def test_atomic_json_cannot_follow_output_or_parent_symlinks(self):
        target = self.base / "immutable-target"
        target.write_bytes(b"immutable")
        self.output.symlink_to(target)
        with self.assertRaisesRegex(self.policy.GateError, "unsafe_path"):
            self.policy.atomic_json(self.output, {"schema": 1})
        self.assertEqual(target.read_bytes(), b"immutable")

    def test_inventory_allows_only_generated_mozconfig_not_new_payloads_or_clone_objects(self):
        upstream = self.base / "upstream"
        upstream.mkdir()
        (upstream / "out/firefox").mkdir(parents=True)
        before = self.policy.immutable_inventory(upstream)
        (upstream / "out/firefox/mozconfig").write_bytes(b"expected transient metadata")
        self.assertEqual(self.policy.immutable_inventory(upstream), before)
        for relative in ("out/firefox/new-browser.tar.zst", "git_clones/extra/object", "hg_clones/extra/object"):
            with self.subTest(relative=relative):
                path = upstream / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"unapproved source or output bytes")
                self.assertNotEqual(self.policy.immutable_inventory(upstream), before)
                path.unlink()

    def test_inventory_rejects_runtime_symlink_even_for_allowed_generated_mozconfig(self):
        upstream = self.base / "upstream"
        (upstream / "out/node").mkdir(parents=True)
        (upstream / "out/node/unsafe").symlink_to(self.base / "missing")
        with self.assertRaisesRegex(self.policy.GateError, "unsafe_runtime_tree"):
            self.policy.immutable_inventory(upstream)


FAKE_POLICY_GIT = r"""
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
assert args[:3] == ['--no-replace-objects', '--no-pager', '-c'], 'unsafe Git authority invocation'
position = args.index('-C')
directory = Path(args[position + 1])
command = args[position + 2:]
config = json.loads(Path(os.environ['POLICY_GIT_CONFIG']).read_text())
with Path(os.environ['POLICY_GIT_CALLS']).open('a') as stream:
    stream.write(json.dumps({'cwd': str(directory), 'args': command}) + '\n')
kind = 'firefox' if directory.name == 'firefox' else 'rbm' if directory.name == 'rbm' else 'upstream'
lock = config['lock']
if config.get('native_failure'):
    print('private-git-stderr-token', file=sys.stderr)
    raise SystemExit(23)
if command[:1] == ['rev-parse']:
    if '--git-path' in command:
        print(config.get('graft_path', str(directory / '.git/info/grafts')))
    elif command[1] == '--show-toplevel':
        print(config.get('wrong_root', str(directory)))
    elif command[1] == 'HEAD':
        print(config.get(kind + '_head', config['rbm_commit'] if kind == 'rbm' else lock['commit']))
    elif command[1] == config['firefox']['ref'] + '^{commit}':
        print(config.get('firefox_revision', config['firefox']['revision']))
    elif command[1].endswith('^{}'):
        print(config.get('peeled', lock['commit']))
    else:
        print(config.get('tag_object', lock['tag_object']))
elif command[:1] == ['remote']:
    expected = config['firefox']['repository'] if kind == 'firefox' else config['rbm_repository'] if kind == 'rbm' else lock['repository']
    print(config.get(kind + '_origin', expected))
elif command[:1] == ['for-each-ref']:
    print(config.get('replace_refs', ''))
elif command[:1] == ['ls-files']:
    print(config.get('index_flags', 'H tracked-source'))
elif command[:1] == ['cat-file']:
    print(config.get('tag_type', 'tag'))
elif command[:1] == ['ls-tree']:
    print(config.get('gitlink', '160000 commit ' + config['rbm_commit'] + '\trbm'))
elif command[:1] == ['config']:
    print(config.get('submodule_path', 'rbm') if command[-1].endswith('.path') else config.get('submodule_url', config['rbm_repository']))
elif command[:1] == ['show']:
    if kind == 'firefox':
        sys.stdout.buffer.write(bytes.fromhex(config.get('workload', config['workload_hex'])))
    else:
        relative = command[1].split(':', 1)[1]
        sys.stdout.buffer.write(bytes.fromhex(config['official'][relative]))
elif command[:1] == ['diff']:
    print(config.get('changed', '\n'.join(config['overlay_paths'])))
elif command[:1] == ['status']:
    if kind == 'rbm':
        print(config.get('rbm_status', ''))
    else:
        print(config.get('upstream_status', '\n'.join(' M ' + name for name in config['overlay_paths'])))
else:
    raise SystemExit(90)
"""


def overlay_preimages(patch_text):
    """Synthetic full preimages retain each trusted patch context at its offset."""
    result = {}
    relative, old_lines, start = None, None, None
    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if relative is not None:
                result[relative] = ("# synthetic public preimage\n" * (start - 1) + "".join(old_lines)).encode()
            relative, old_lines, start = None, [], None
        elif line.startswith("+++ b/"):
            relative = line[len("+++ b/"):].strip()
        elif line.startswith("@@ "):
            start = int(line.split()[1][1:].split(",")[0])
        elif relative is not None and start is not None and line[:1] in (" ", "-"):
            old_lines.append(line[1:])
    if relative is not None:
        result[relative] = ("# synthetic public preimage\n" * (start - 1) + "".join(old_lines)).encode()
    return result


class ResourceSourceGuardFixtureTests(PolicyInputFixture, unittest.TestCase):
    """Native fake Git verifies guards with tiny bytes; no actual865 proof."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-source-guard-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.make_inputs()
        self.policy = load_validator()
        self.overlay = self.base / "overlay root"
        (self.overlay / "patches").mkdir(parents=True)
        shutil.copyfile(ROOT / "upstream.lock.json", self.overlay / "upstream.lock.json")
        shutil.copyfile(ROOT / "patches/firefox-pgo-generate.patch", self.overlay / "patches/firefox-pgo-generate.patch")
        self.original = overlay_preimages((self.overlay / "patches/firefox-pgo-generate.patch").read_text())
        self.overlay_paths = sorted(self.original)
        self.original.update({"projects/firefox/mozconfig.in": b"mk_add_options MOZ_PARALLEL_BUILD=[% c('num_procs') %]\n",
                              "projects/node/config": self.source_files["projects/node/config"],
                              "projects/node/build": self.source_files["projects/node/build"],
                              "projects/container-image/config": self.source_files["projects/container-image/config"],
                              "projects/container-image/build": self.source_files["projects/container-image/build"]})
        for relative, data in self.original.items():
            path = self.upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        # Real local git apply defines existing protected overlay semantics.
        native_git = shutil.which("git")
        result = subprocess.run([native_git, "apply", str(self.overlay / "patches/firefox-pgo-generate.patch")],
                                cwd=self.upstream, env=native_environment(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, "native protected-overlay fixture application failed")
        runtime = {"rbm/rbm": b"# synthetic rbm entry, never executed\n",
                   "rbm/container": b"# synthetic controller, never executed\n",
                   "rbm/lib/RBM.pm": b"# synthetic RBM module\n",
                   "rbm/lib/RBM/CaptureExec.pm": b"# synthetic capture module\n",
                   "rbm/lib/RBM/DefaultConfig.pm": b"# synthetic default config\n"}
        for relative, data in runtime.items():
            path = self.upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.source_sha = {"rbm.conf": digest(self.source_files["rbm.conf"]), **{key: digest(value) for key, value in runtime.items()}}
        (self.upstream / "git_clones/firefox").mkdir(parents=True)
        (self.provenance_file.parent / "profileserver.py").write_bytes(self.workload)
        self.inputs = {"provenance": self.provenance, "provenance_path": self.provenance_file}
        self.config = self.base / "git-fixture.json"
        self.calls = self.base / "git-calls.jsonl"
        self.settings = {"lock": self.lock, "rbm_commit": self.policy.RBM_COMMIT,
                         "rbm_repository": self.policy.RBM_REPOSITORY, "firefox": self.provenance["firefox"],
                         "official": {name: value.hex() for name, value in self.original.items()},
                         "workload_hex": self.workload.hex(), "overlay_paths": self.overlay_paths}
        self.config.write_text(json.dumps(self.settings))
        bindir = self.base / "bin"
        install_python(bindir / "git", FAKE_POLICY_GIT)
        self.environment.update({"PATH": str(bindir) + os.pathsep + self.environment.get("PATH", ""),
                                 "POLICY_GIT_CONFIG": str(self.config), "POLICY_GIT_CALLS": str(self.calls)})
        for name, value in (("ROOT", self.overlay), ("SOURCE_SHA", self.source_sha)):
            patcher = patch.object(self.policy, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def configure(self, **values):
        self.settings.update(values)
        self.config.write_text(json.dumps(self.settings))

    def execute(self):
        return self.policy.source_records(self.upstream, self.inputs, self.environment, self.policy.Deadline(10))

    def rejected(self, code):
        with self.assertRaises(self.policy.GateError) as failure:
            self.execute()
        self.assertEqual(str(failure.exception), code)
        self.assertNotIn("private", str(failure.exception))

    def test_complete_fake_guard_accepts_only_native_applied_existing_overlay_and_workload(self):
        records = self.execute()
        self.assertEqual(records["profileserver.py"], digest(self.workload))
        self.assertEqual(set(records), set(self.source_sha) | set(self.original) | {"profileserver.py"})
        self.assertFalse(self.output.exists())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all(record["args"][0] not in ("fetch", "clone", "build") for record in calls))

    def test_wrong_source_tag_gitlink_origin_or_rbm_commit_fails_with_public_fixed_codes(self):
        changes = [("upstream_head", "0" * 40, "source_commit_mismatch"),
                   ("rbm_head", "0" * 40, "source_commit_mismatch"),
                   ("upstream_origin", "https://private-token@example.invalid", "source_origin_mismatch"),
                   ("rbm_origin", "https://private-token@example.invalid", "source_origin_mismatch"),
                   ("tag_object", "0" * 40, "source_pin_mismatch"),
                   ("peeled", "0" * 40, "source_pin_mismatch"),
                   ("tag_type", "commit", "source_pin_mismatch"),
                   ("gitlink", "100644 blob " + "0" * 40 + "\trbm", "source_pin_mismatch"),
                   ("submodule_path", "private-module", "source_pin_mismatch"),
                   ("submodule_url", "https://private-token@example.invalid", "source_pin_mismatch")]
        for key, value, expected in changes:
            with self.subTest(key=key):
                self.configure(**{key: value})
                self.rejected(expected)
                self.settings.pop(key)
                self.configure()

    def test_replacement_refs_and_hidden_index_flags_are_rejected(self):
        self.configure(replace_refs="refs/replace/" + "a" * 40)
        self.rejected("unsupported_git_replacements")
        self.settings.pop("replace_refs")
        for value in ("h tracked-source", "S tracked-source"):
            self.configure(index_flags=value)
            self.rejected("hidden_worktree_changes")

    def test_real_graft_metadata_presence_and_parent_symlink_are_rejected_without_contents(self):
        graft = self.upstream / ".git/info/grafts"
        graft.parent.mkdir(parents=True)
        graft.write_text("private-graft-content")
        self.rejected("unsupported_git_grafts")
        graft.unlink()
        graft.parent.rmdir()
        target = self.base / "git-info-target"
        target.mkdir()
        graft.parent.symlink_to(target, target_is_directory=True)
        self.rejected("unsafe_path")

    def test_ignored_module_or_template_state_is_visible_and_rejected_outside_runtime_dirs(self):
        for relative in ("rbm/lib/ignored-module.pm", "projects/firefox/ignored-template.in"):
            with self.subTest(relative=relative):
                self.configure(upstream_status="!! " + relative)
                self.rejected("uncontrolled_source_file")
        self.configure(upstream_status="!! out/\n!! logs/\n!! tmp/\n!! git_clones/\n!! hg_clones/")
        self.execute()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        upstream_status = [row["args"] for row in calls if row["cwd"] == str(self.upstream)
                           and row["args"][:1] == ["status"]]
        self.assertTrue(upstream_status)
        self.assertTrue(all("--ignored=matching" in command for command in upstream_status))

    def test_local_config_untracked_sources_dirty_rbm_or_recipe_change_is_rejected(self):
        local = self.upstream / "rbm.local.conf"
        local.write_text("private-unapproved-config")
        self.rejected("uncontrolled_rbm_config")
        local.unlink()
        self.configure(upstream_status="?? private-source-file")
        self.rejected("uncontrolled_source_file")
        self.settings.pop("upstream_status")
        self.configure(rbm_status=" M lib/RBM.pm")
        self.rejected("dirty_rbm_source")
        self.settings.pop("rbm_status")
        self.configure()
        path = self.upstream / "projects/firefox/mozconfig.in"
        path.write_bytes(path.read_bytes() + b"private-unapproved-change")
        self.rejected("recipe_source_mismatch")

    def test_source_module_bytes_changed_or_symlinked_are_rejected(self):
        path = self.upstream / "rbm/lib/RBM.pm"
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        self.rejected("rbm_source_mismatch")
        path.unlink()
        target = self.base / "module-target"
        target.write_bytes(original)
        path.symlink_to(target)
        self.rejected("unsafe_path")

    def test_firefox_workload_source_tuple_and_exact_saved_file_are_verified(self):
        for key, value, expected in (("firefox_origin", "https://private-source.invalid", "firefox_source_origin_mismatch"),
                                     ("firefox_revision", "0" * 40, "firefox_source_revision_mismatch"),
                                     ("workload", b"wrong workload".hex(), "workload_mismatch")):
            with self.subTest(key=key):
                self.configure(**{key: value})
                self.rejected(expected)
                self.settings.pop(key)
                self.configure()
        (self.provenance_file.parent / "profileserver.py").write_bytes(b"changed saved workload")
        self.rejected("workload_file_mismatch")

    def test_native_git_failure_is_not_retried_or_reported_with_private_stderr(self):
        self.configure(native_failure=True)
        self.rejected("native_nonzero")
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)


class ResourcePolicyCliTests(PolicyMechanicsFixture, unittest.TestCase):
    """Six-argument main uses the same explicitly mocked metadata mechanics."""
    # Do not rerun all inherited mechanics under this specialized CLI class.
    def main(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", [str(HELPER), *self.cli_arguments(), *extra]), \
             patch.dict(os.environ, self.environment, clear=True), \
             patch.object(self.policy.signal, "signal"), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = self.policy.main()
        return status, stdout.getvalue(), stderr.getvalue()

    def test_six_exact_cli_flags_create_policy_only_with_explicit_metadata_only_footer(self):
        status, stdout, stderr = self.main()
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, "PGO resource metadata policy verified only; native compiler/archive/profile proof remains separate.\n")
        self.assertTrue(self.output.exists())
        self.assertFalse(json.loads((self.diagnostic / "validation.json").read_text())["compiled_browser_verified"])

    def test_six_flag_cli_failure_has_no_secrets_or_execution_policy(self):
        self.rust_file.write_bytes(b'{"private-secret":"private-value","private-secret":1}')
        status, stdout, stderr = self.main()
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "PGO resource metadata validation failed; no execution policy was created.\n")
        self.assertNotIn("private", stdout + stderr)
        self.assertFalse(self.output.exists())
        raw = (self.diagnostic / "validation.json").read_text()
        self.assertNotIn("private", raw)
        self.assertEqual(json.loads(raw)["error"]["code"], "json_duplicate_key")

    def test_private_unknown_argument_or_abbreviated_flag_is_never_echoed_or_accepted(self):
        for extra in (("--private-argument", "private-token-value"), ("--workers", "1")):
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(extra=extra[0]), patch.object(sys, "argv", [str(HELPER), *self.cli_arguments(), *extra]), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as failure:
                    self.policy.main()
                self.assertEqual(failure.exception.code, 2)
                self.assertNotIn("private-token-value", stdout.getvalue() + stderr.getvalue())
                self.assertNotIn("--private-argument", stdout.getvalue() + stderr.getvalue())
        argv = [str(HELPER), *self.cli_arguments()]
        argv[argv.index("--diagnostic-directory")] = "--diagnostic-dir"
        with patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as failure:
                self.policy.main()
        self.assertEqual(failure.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_unknown_flag_is_rejected_instead_of_becoming_an_execution_override(self):
        with self.assertRaises(SystemExit) as failure:
            self.main("--workers", "1")
        self.assertEqual(failure.exception.code, 2)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.seen_cases)




class ResourceSelectedInputTests(PolicyInputFixture, unittest.TestCase):
    """Actual small files test complete native-selection and registry binding."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-selected-inputs-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.make_inputs()
        self.policy = load_validator()
        for name, value in (("EXPECTED_RUST_SHA", self.rust_sha), ("EXPECTED_NODE_SHA", self.node_sha)):
            patcher = patch.object(self.policy, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.inputs = self.policy.load_inputs(self.args)
        self.registries = {"archives": {}, "bytes": {}}
        # registry_records unit tests deliberately use their own minimal directory.
        self.environment["RUNNER_TEMP"] = str(self.base / "isolated-registry-runner")

    def validate(self, selected=None):
        return self.policy.validate_selected_inputs(self.upstream, self.selected_inputs if selected is None else selected,
                                                    self.inputs, self.registries, self.policy.Deadline(5))

    def rejection(self, selected, code=None):
        with self.assertRaises(self.policy.GateError) as failure:
            self.validate(selected)
        if code:
            self.assertEqual(str(failure.exception), code)
        self.assertFalse(self.output.exists())

    def item(self, relative, kind="file", project="", checksums=None):
        return {"filename": Path(relative).name, "path": str(self.upstream / relative), "kind": kind,
                "project": project, "id": "selected-fixture-id", "checksums": checksums or {}}

    def test_all_required_restored_archives_are_selected_and_exactly_hashed(self):
        records = self.validate()
        self.assertEqual(len(records), 3)
        self.assertEqual({item["path"] for item in records}, set(self.archive_bytes))
        for item in records:
            self.assertEqual({key: item[key] for key in ("sha256", "size")}, self.archive_descriptor(item["path"]))
        for index in range(3):
            with self.subTest(missing=index):
                self.rejection(self.selected_inputs[:index] + self.selected_inputs[index + 1:],
                               "selected_required_archive_missing")

    def test_every_selection_record_key_kind_name_path_id_and_checksum_type_is_checked(self):
        for field in self.selected_inputs[0]:
            changed = copy.deepcopy(self.selected_inputs)
            del changed[0][field]
            with self.subTest(missing=field):
                self.rejection(changed, "invalid_selected_inputs")
        changes = {"filename": "../escape", "path": True, "kind": "exec", "project": "../compiler",
                   "id": "", "checksums": {"md5": "unbound"}}
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(self.selected_inputs)
                changed[0][field] = value
                self.rejection(changed, "invalid_selected_inputs")
        changed = copy.deepcopy(self.selected_inputs)
        changed[0]["extra"] = "private-value"
        self.rejection(changed, "invalid_selected_inputs")

    def test_selection_path_escape_duplicate_missing_or_wrong_project_is_rejected(self):
        for field, value, code in (("path", str(self.base / "escape"), "selected_input_escape"),
                                   ("filename", "different.tar.zst", "ambiguous_selected_inputs"),
                                   ("project", "wrong-project", "unexpected_selected_archive")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.selected_inputs)
                changed[0][field] = value
                self.rejection(changed, code)
        self.rejection(self.selected_inputs + [self.selected_inputs[0]], "ambiguous_selected_inputs")
        changed = copy.deepcopy(self.selected_inputs)
        path = self.upstream / "out/node/missing.tar.zst"
        changed[0]["path"], changed[0]["filename"] = str(path), path.name
        self.rejection(changed, "missing_archive")

    def test_present_registered_dependency_is_bound_without_requiring_future_dependency_cache(self):
        relative = "out/nasm/nasm-fixture.tar.zst"
        path = self.upstream / relative
        path.parent.mkdir()
        path.write_bytes(b"synthetic named dependency bytes")
        selected = self.selected_inputs + [self.item(relative, "project", "nasm")]
        # A present future dependency may be observed without a cache promise.
        self.assertEqual(self.validate(selected)[-1]["path"], relative)
        self.registries["archives"][relative] = self.archive_descriptor(relative)
        self.assertEqual(self.validate(selected)[-1]["path"], relative)
        path.write_bytes(b"X" * path.stat().st_size)
        self.rejection(selected, "selected_restored_archive_mismatch")

    def test_future_project_and_checksummed_url_need_no_materialized_payload_for_metadata(self):
        future_project = {"filename": "cbindgen-fixture.tar.zst", "path": "", "kind": "project",
                          "project": "cbindgen", "id": "metadata-only-input-ID", "checksums": {}}
        future_url = {"filename": "checksum-source-fixture.tar.gz", "path": "", "kind": "url",
                      "project": "", "id": "metadata-only-checksum-ID", "checksums": {"sha256sum": "a" * 64}}
        self.assertEqual(len(self.validate(self.selected_inputs + [future_project, future_url])), 3)
        self.assertFalse((self.upstream / "out/cbindgen").exists())
        for kind in ("file", "content"):
            with self.subTest(kind=kind):
                missing = {**future_url, "kind": kind, "checksums": {}}
                self.rejection(self.selected_inputs + [missing], "missing_metadata_input")
        # Required restored compiler/support checkpoints are not future inputs.
        changed = copy.deepcopy(self.selected_inputs)
        changed[0]["path"] = ""
        self.rejection(changed, "selected_required_archive_missing")

    def test_absent_url_payload_still_requires_a_valid_native_checksum_identity(self):
        missing = {"filename": "future-source-input.tar.gz", "path": "", "kind": "url",
                   "project": "", "id": "native-metadata-checksum-ID", "checksums": {}}
        self.rejection(self.selected_inputs + [missing], "missing_metadata_input")
        for algorithm, value in (("sha256sum", "bad"), ("sha512sum", "a" * 64),
                                 ("sha256sum", True)):
            with self.subTest(algorithm=algorithm, value=value):
                missing["checksums"] = {algorithm: value}
                self.rejection(self.selected_inputs + [missing], "invalid_selected_checksum")
        missing["checksums"] = {"sha256sum": "a" * 64, "sha512sum": "b" * 128}
        self.assertEqual(len(self.validate(self.selected_inputs + [missing])), 3)
        self.assertFalse((self.upstream / "out/firefox/future-source-input.tar.gz").exists())

    def test_selected_url_requires_exact_actual_sha256_or_sha512_checksums(self):
        relative = "out/firefox/source-input.tar.gz"
        path = self.upstream / relative
        path.parent.mkdir()
        content = b"synthetic checksum-bound source input"
        path.write_bytes(content)
        selected = self.selected_inputs + [self.item(relative, "url")]
        self.rejection(selected, "unbound_selected_url")
        for algorithm, expected in (("sha256sum", digest(content)),
                                    ("sha512sum", hashlib.sha512(content).hexdigest())):
            with self.subTest(algorithm=algorithm):
                selected[-1]["checksums"] = {algorithm: expected}
                self.assertEqual(self.validate(selected)[-1]["path"], relative)
                selected[-1]["checksums"] = {algorithm: "0" * len(expected)}
                self.rejection(selected, "selected_checksum_mismatch")
                selected[-1]["checksums"] = {algorithm: "invalid-private-digest"}
                self.rejection(selected, "invalid_selected_checksum")

    def test_selected_file_must_be_authenticated_recipe_or_keyring_tree_and_regular(self):
        relative = "projects/firefox/fixture-input"
        path = self.upstream / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"public synthetic tracked input")
        selected = self.selected_inputs + [self.item(relative)]
        self.assertEqual(self.validate(selected)[-1]["path"], relative)
        unsafe = "out/firefox/unbound-file"
        target = self.upstream / unsafe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"not an authenticated source input")
        self.rejection(self.selected_inputs + [self.item(unsafe)], "unbound_selected_file")
        path.unlink()
        path.symlink_to(target)
        self.rejection(selected, "unsafe_path")

    def test_generated_content_exception_is_only_the_exact_mozconfig_location(self):
        selected = self.selected_inputs + [self.item("out/firefox/mozconfig", "content")]
        self.assertEqual(len(self.validate(selected)), 3)
        for relative in ("out/firefox/arbitrary-content", "out/node/mozconfig"):
            with self.subTest(relative=relative):
                self.rejection(self.selected_inputs + [self.item(relative, "content")], "unexpected_generated_input")
        selected[-1]["checksums"] = {"sha256sum": "0" * 64}
        self.rejection(selected, "unexpected_generated_input")

    def test_general_registry_complete_raw_bytes_archive_keys_and_conflicts_are_bound(self):
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        directory.mkdir(parents=True)
        relative = "out/nasm/nasm-fixture.tar.zst"
        registry = {"schema": 1, "stage": "nasm", "upstream": self.lock, "identity": {"upstream": self.lock},
                    "artifacts": [{"path": relative, "project": "nasm", "filename": "nasm-fixture.tar.zst",
                                   "asset": "rbm-fixture--nasm.tar.zst", "sha256": "a" * 64, "size": 123}]}
        path = directory / "registry-nasm.json"
        write_json(path, registry)
        actual = self.policy.registry_records(self.environment)
        self.assertEqual(actual["bytes"][path.name], path.read_bytes())
        self.assertEqual(actual["archives"][relative], {"sha256": "a" * 64, "size": 123})
        changed = copy.deepcopy(registry)
        changed["artifacts"][0]["extra"] = "public fixture metadata"
        write_json(path, changed)
        self.assertNotEqual(self.policy.registry_records(self.environment), actual)
        conflicting = copy.deepcopy(registry)
        conflicting["stage"] = "other"
        conflicting["artifacts"][0]["sha256"] = "b" * 64
        write_json(directory / "registry-other.json", conflicting)
        with self.assertRaisesRegex(self.policy.GateError, "conflicting_registry_artifact"):
            self.policy.registry_records(self.environment)

    def test_general_registry_invalid_schema_stage_source_path_asset_size_or_duplicate_fails(self):
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        directory.mkdir(parents=True)
        base = {"schema": 1, "stage": "nasm", "upstream": self.lock,
                "artifacts": [{"path": "out/nasm/nasm-fixture.tar.zst", "project": "nasm",
                               "filename": "nasm-fixture.tar.zst", "asset": "rbm-nasm-fixture.tar.zst",
                               "sha256": "a" * 64, "size": 123}]}
        mutations = []
        for field, value in (("schema", True), ("schema", 1.0), ("stage", "other"), ("upstream", {}), ("identity", {}),
                             ("artifacts", []), ("artifacts", base["artifacts"] * 2)):
            changed = copy.deepcopy(base)
            changed[field] = value
            mutations.append(changed)
        for field, value in (("path", "out/nasm/../escape"), ("asset", "../escape"),
                             ("filename", "wrong.tar.zst"), ("project", "wrong"),
                             ("sha256", "private-invalid"), ("size", True)):
            changed = copy.deepcopy(base)
            changed["artifacts"][0][field] = value
            mutations.append(changed)
        path = directory / "registry-nasm.json"
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                write_json(path, changed)
                with self.assertRaises(self.policy.GateError) as failure:
                    self.policy.registry_records(self.environment)
                self.assertNotIn("private-invalid", str(failure.exception))

    def test_general_rust_pgo_registry_requires_complete_rust_identity_not_official_placeholder(self):
        directory = Path(self.environment["RUNNER_TEMP"]) / "rbm-registry"
        directory.mkdir(parents=True)
        relative = "out/rust/" + self.rust_filename
        registry = {"schema": 1, "stage": "rust-pgo", "upstream": self.lock, "identity": self.rust,
                    "artifacts": [{"path": relative, "project": "rust", "filename": self.rust_filename,
                                   "asset": "rbm-fixture--rust-profiler.tar.zst",
                                   **self.archive_descriptor(relative)}]}
        path = directory / "registry-rust-pgo.json"
        write_json(path, registry)
        result = self.policy.registry_records(self.environment, self.inputs)
        self.assertEqual(result["archives"][relative], self.archive_descriptor(relative))
        self.assertEqual(result["bytes"][path.name], path.read_bytes())
        for identity in ({"upstream": self.lock}, {**self.rust, "kind": "wrong-profiler"}):
            with self.subTest(identity=identity["kind"] if "kind" in identity else "official-placeholder"):
                registry["identity"] = identity
                write_json(path, registry)
                with self.assertRaisesRegex(self.policy.GateError, "general_registry_binding_mismatch"):
                    self.policy.registry_records(self.environment, self.inputs)

    def test_complete_node_registry_bytes_and_support_bytes_are_part_of_post_guard_inputs(self):
        immutable = self.inputs["immutable_input_bytes"]
        self.assertEqual(set(immutable), {"node", "provenance", "registry", "support"})
        original = copy.deepcopy(self.inputs)
        self.node_registry["artifacts"][0]["asset"] += "-changed"
        write_json(self.support / "registry/registry-node.json", self.node_registry)
        changed = self.policy.load_inputs(self.args)
        self.assertNotEqual(changed, original)
        self.assertNotEqual(changed["immutable_input_bytes"]["registry"], immutable["registry"])


FAKE_GUARD_RBM = r"""
package RBM;
use strict; use warnings; use JSON::PP; use Cwd qw(abs_path getcwd);
our $config = {run => {}};
our $fixture;
sub settings {
    if (!defined($fixture)) {
        open(my $stream, '<', $ENV{POLICY_PERL_CONFIG}) or die "fixture missing\n";
        local $/; $fixture = JSON::PP->new->decode(<$stream>); close($stream);
    }
    return $fixture;
}
sub record {
    my ($action) = @_;
    open(my $stream, '>>', $ENV{POLICY_PERL_CALLS}) or die "fixture log failed\n";
    print $stream JSON::PP->new->canonical->encode({action => $action, cwd => getcwd(),
          targets => $config->{run}{target} || [], num_procs => $config->{opt}{num_procs}}), "\n"; close($stream);
}
sub load_config { my $data = settings(); $config = {run => {}, opt => {num_procs => $data->{operational_num_procs} || 4}}; record('load_config'); }
sub set_default_env { record('set_default_env'); }
sub load_system_config { record('load_system_config'); }
sub load_local_config { record('load_local_config'); }
sub load_modules_config { record('load_modules_config'); }
sub valid_project { record('valid_project'); }
sub exit_error { die "Error: Undefined\n"; }
sub project_config {
    my ($project, $key, $options) = @_;
    return 'build' if $key eq 'pkg_type';
    my $data = settings();
    return $data->{clone_root} if $key eq 'git_clone_dir';
    return $data->{origin} if $key eq 'git_url';
    return $data->{ref} if $key eq 'git_hash';
    if ($key eq 'filename') {
        my $action = $data->{action} || '';
        git_clone_fetch_chdir($project, $options) if $action eq 'git';
        urlget() if $action eq 'urlget';
        build_pkg() if $action eq 'build_pkg';
        build_run() if $action eq 'build_run';
        hg_clone_fetch_chdir() if $action eq 'hg';
        git_submodule_init_sync_update() if $action eq 'submodule';
        input_files('link', $project, {}) if $action eq 'link';
        run_script('firefox', 'metadata execute', \&capture_exec) if $action eq 'script-capture';
        run_script('firefox', 'cold exec', sub { record('FORBIDDEN_system_exec'); }) if $action eq 'script-system';
        # Model the pinned filename/build-ID option scope, never raw caller CPU2/1.
        local $config->{opt}{num_procs} = 4;
        input_files('input_files_id', $project, {pkg_type => 'build'});
        return $data->{filename};
    }
    return undef;
}
sub rbm_path { return $_[0]; }
sub git_clone_fetch_chdir { record('original_git'); }
sub git_submodule_init_sync_update { record('FORBIDDEN_submodule'); }
sub hg_clone_fetch_chdir { record('FORBIDDEN_hg'); }
sub urlget { record('FORBIDDEN_urlget'); }
sub build_pkg { record('FORBIDDEN_build_pkg'); }
sub build_run { record('FORBIDDEN_build_run'); }
sub run_script { record('original_run_script'); return 'original captured metadata'; }
sub git_need_fetch { record('git_need_fetch'); return settings()->{cold_fetch} || 0; }
sub capture_exec {
    my @args = @_;
    my $data = settings();
    my $text = join(' ', @args);
    return ('', '', 0) if $text =~ /config --get/;
    my $value = $text =~ /--show-toplevel/ ? getcwd()
              : $text =~ /--git-path info\/grafts/ ? getcwd().'/.git/info/grafts'
              : $text =~ /--git-path hooks/ ? getcwd().'/.git/hooks'
              : $text =~ /for-each-ref/ ? ($data->{replacement} || '')
              : $text =~ /remote get-url/ ? ($data->{actual_origin} || $data->{origin})
              : $text =~ /--verify HEAD/ ? ($data->{actual_head} || $data->{revision})
              : $text =~ /rev-parse --verify/ ? $data->{revision} : '';
    return ($value."\n", '', 1);
}
sub input_files {
    my ($action, $project, $options) = @_;
    record('input_files:'.$action);
    my $data = settings();
    if ($action eq 'input_files_id') {
        if ($data->{generated_mozconfig}) {
            open(my $generated, '>', $data->{generated_mozconfig}) or die "fixture write failed\n";
            print $generated "mk_add_options MOZ_PARALLEL_BUILD=", $config->{opt}{num_procs}, "\n";
            close($generated);
        }
        for my $item (@{$data->{selected}}) {
            my %input;
            $input{$item->{kind} eq 'url' ? 'URL' : $item->{kind}} = 1 if $item->{kind} ne 'file';
            $input{project} = $item->{project} if $item->{kind} eq 'project';
            my $t = sub { return $_[0] eq 'project' ? $item->{project} : $item->{checksums}{$_[0]}; };
            input_file_id(\%input, $t, $item->{path}, $item->{filename});
        }
        return 'original-full-input-ID';
    }
    my %names;
    for my $name (keys %{$data->{named}}) {
        my $value = $data->{named}{$name}; $names{$name} = sub { return $value; };
    }
    return \%names;
}
sub input_file_id { return 'original-native-fixture-ID'; }
1;
"""


class ResourceNativeMetadataGuardTests(unittest.TestCase):
    """Run real Perl with a fake RBM module; never actual865/identity proof."""
    def setUp(self):
        if shutil.which("perl") is None:
            self.skipTest("native Perl is needed for the metadata guard fixture")
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-native-perl-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.upstream = self.base / "upstream"
        self.upstream.mkdir()
        self.policy = load_validator()
        module = self.upstream / "rbm/lib/RBM.pm"
        module.parent.mkdir(parents=True)
        module.write_text(FAKE_GUARD_RBM)
        self.config = self.base / "perl-config.json"
        self.calls = self.base / "perl-calls.jsonl"
        self.environment = native_environment() | {"POLICY_PERL_CONFIG": str(self.config),
                                                  "POLICY_PERL_CALLS": str(self.calls)}
        self.clone_root = self.upstream / "git_clones"
        self.clone = self.clone_root / "firefox"
        self.clone.mkdir(parents=True)
        self.source = self.upstream / "projects/firefox/fixture-input"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"synthetic static native input")
        self.settings = {"filename": "unchanged-native-fixture.tar.zst", "clone_root": str(self.clone_root),
                         "origin": "https://official-fixture.invalid", "ref": "fixture-ref",
                         "revision": "a" * 40, "named": {"fixture": self.source.name},
                         "selected": [{"filename": self.source.name, "path": str(self.source), "kind": "file",
                                       "project": "", "checksums": {}}]}
        self.config.write_text(json.dumps(self.settings))

    def configure(self, **values):
        self.settings.update(values)
        self.config.write_text(json.dumps(self.settings))

    def native(self, action="showconf"):
        command = self.policy.perl_command(self.upstream, "firefox", "filename" if action == "showconf" else "", TARGETS, action)
        return self.policy.run_native(command, cwd=self.upstream, environment=self.environment,
                                      deadline=self.policy.Deadline(3), seconds=2)

    def actions(self):
        return [json.loads(line)["action"] for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_native_initializer_and_target_order_preserve_the_original_metadata_value(self):
        status, stdout, stderr = self.native()
        self.assertEqual((status, stdout, stderr), (0, b"unchanged-native-fixture.tar.zst\n", b""))
        self.assertEqual(self.actions()[:5], ["load_config", "set_default_env", "load_system_config",
                                            "load_local_config", "load_modules_config"])
        records = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all(row["cwd"] == str(self.upstream) for row in records))
        self.assertEqual(records[-1]["targets"], TARGETS)

    def test_actual_native_guard_blocks_compiler_fetch_submodule_hg_and_generic_link_before_entry(self):
        for action in ("urlget", "build_pkg", "build_run", "hg", "submodule", "link"):
            with self.subTest(action=action):
                self.configure(action=action)
                status, stdout, stderr = self.native()
                self.assertNotEqual(status, 0)
                self.assertEqual(stdout, b"")
                self.assertIn(b"warm_metadata_required", stderr)
                self.assertFalse(any(name.startswith("FORBIDDEN_") for name in self.actions()))
                self.assertNotIn("input_files:link", self.actions())

    def test_actual_native_guard_allows_only_already_warm_exact_git_ref_and_origin(self):
        self.configure(action="git")
        status, stdout, _stderr = self.native()
        self.assertEqual((status, stdout), (0, b"unchanged-native-fixture.tar.zst\n"))
        self.assertIn("original_git", self.actions())
        for field, value in (("cold_fetch", True), ("actual_head", "not-a-commit"),
                             ("actual_origin", "https://wrong.invalid"), ("replacement", "refs/replace/fixture")):
            with self.subTest(field=field):
                self.calls.unlink()
                self.configure(**{field: value})
                status, stdout, stderr = self.native()
                self.assertNotEqual(status, 0)
                self.assertEqual(stdout, b"")
                self.assertIn(b"warm_metadata_required", stderr)
                self.assertNotIn("original_git", self.actions())
                self.settings.pop(field)
                self.configure()

    def test_actual_native_generic_system_exec_callback_is_blocked_before_script_entry(self):
        self.configure(action="script-capture")
        status, stdout, stderr = self.native()
        self.assertEqual((status, stdout, stderr), (0, b"unchanged-native-fixture.tar.zst\n", b""))
        self.assertIn("original_run_script", self.actions())
        self.calls.unlink()
        self.configure(action="script-system")
        status, stdout, stderr = self.native()
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, b"")
        self.assertIn(b"warm_metadata_required", stderr)
        self.assertNotIn("original_run_script", self.actions())
        self.assertNotIn("FORBIDDEN_system_exec", self.actions())

    def test_actual_native_cold_clone_absence_cannot_start_original_clone_function(self):
        self.configure(action="git")
        shutil.rmtree(self.clone)
        status, stdout, stderr = self.native()
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, b"")
        self.assertIn(b"warm_metadata_required", stderr)
        self.assertNotIn("original_git", self.actions())
        self.assertFalse(self.clone.exists())

    def test_actual_native_grafts_active_hooks_or_symlink_clone_cannot_enter_git_checkout(self):
        self.configure(action="git")
        for relative in (".git/info/grafts", ".git/hooks/post-checkout"):
            with self.subTest(relative=relative):
                path = self.clone / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("private-unapproved-git-authority")
                self.calls.unlink(missing_ok=True)
                status, stdout, stderr = self.native()
                self.assertNotEqual(status, 0)
                self.assertEqual(stdout, b"")
                self.assertIn(b"warm_metadata_required", stderr)
                self.assertNotIn("original_git", self.actions())
                path.unlink()
        target = self.base / "other-clone"
        self.clone.rename(target)
        self.clone.symlink_to(target, target_is_directory=True)
        status, stdout, stderr = self.native()
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, b"")
        self.assertIn(b"warm_metadata_required", stderr)
        self.assertNotIn("original_git", self.actions())

    def test_actual_native_named_closures_and_input_file_id_records_are_not_static_substitution(self):
        status, stdout, stderr = self.native("named")
        self.assertEqual(status, 0, "native synthetic named fixture failed")
        self.assertEqual(stderr, b"")
        selected = json.loads(stdout)
        self.assertEqual(set(selected), {"named", "selected_inputs"})
        self.assertEqual(selected["named"], {"fixture": self.source.name})
        item = selected["selected_inputs"][0]
        self.assertEqual(set(item), {"filename", "path", "kind", "project", "id", "checksums"})
        self.assertEqual(item["id"], "original-native-fixture-ID")
        self.assertEqual(item["path"], str(self.source))
        self.assertEqual(item["kind"], "file")
        self.assertEqual(self.actions().count("input_files:input_files_id"), 1)
        self.assertEqual(self.actions().count("input_files:getfnames"), 1)

    def test_native_named_id_scope_refreshes_four_without_relabeling_operational_two_or_one(self):
        generated = self.upstream / "out/firefox/mozconfig"
        generated.parent.mkdir(parents=True)
        for count in (4, 2, 1):
            with self.subTest(count=count):
                self.calls.unlink(missing_ok=True)
                self.configure(operational_num_procs=count, generated_mozconfig=str(generated))
                status, stdout, stderr = self.native("named")
                self.assertEqual((status, stderr), (0, b""))
                self.assertEqual(generated.read_text(), operational_mozconfig(4).splitlines()[-1] + "\n")
                records = [json.loads(line) for line in self.calls.read_text().splitlines()]
                id_calls = [row for row in records if row["action"] == "input_files:input_files_id"]
                self.assertEqual(len(id_calls), 1, "guard repeated raw input-ID outside native filename scope")
                self.assertEqual(id_calls[0]["num_procs"], 4)
                self.assertEqual(records[-1]["num_procs"], count, "caller operational options were not restored")
                selected = json.loads(stdout)
                self.assertEqual(selected["selected_inputs"][0]["id"], "original-native-fixture-ID")
                # The generated ID-time file4 is NOT operational content2/1.
                if count != 4:
                    self.assertNotEqual(generated.read_text(), f"mk_add_options MOZ_PARALLEL_BUILD={count}\n")

    def test_actual_native_missing_static_input_fails_without_fetch_build_or_output(self):
        self.source.unlink()
        status, stdout, stderr = self.native("named")
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, b"")
        self.assertIn(b"warm_metadata_required", stderr)
        self.assertFalse(any(name.startswith("FORBIDDEN_") for name in self.actions()))


# Previously authenticated local 7dd recipe blobs. These are patch/serialization
# fixtures only, not a real source checkout, native build, or RBM865 proof.
FIREFOX_CONFIG_PREIMAGE = r'''# vim: filetype=yaml sw=2
version: '[% c("abbrev") %]'
filename: 'firefox-[% c("var/project-name") %]-[% c("version") %]-[% c("var/osname") %]-[% c("var/build_id") %]'
git_hash: '[% c("var/project-name") %]-[% c("var/firefox_version") %]-[% c("var/browser_branch") %]-build[% c("var/browser_build") %]'
tag_gpg_id: 1
git_url: https://gitlab.torproject.org/tpo/applications/tor-browser.git
gpg_keyring:
  - boklm.gpg
  - brizental.gpg
  - clairehurst.gpg
  - dan_b.gpg
  - henry.gpg
  - jwilde.gpg
  - ma1.gpg
  - morgan.gpg
  - pierov.gpg
container:
  use_container: 1

var:
  firefox_platform_version: '153.0'
  firefox_version: '[% c("var/firefox_platform_version") %]esr'
  browser_series: '16.0'
  browser_rebase: 1
  browser_branch: '[% c("var/browser_series") %]-[% c("var/browser_rebase") %]'
  browser_build: 2
  upstream_firefox_commit: FIREFOX_NIGHTLY_153_END
  copyright_year: '[% exec("git show -s --format=%ci " _ c("git_hash") _ "^{commit}", { exec_noco => 1 }).remove("-.*") %]'
  nightly_updates_publish_dir: '[% c("var/nightly_updates_publish_dir_prefix") %]nightly-[% c("var/osname") %]'
  gitlab_project: https://gitlab.torproject.org/tpo/applications/tor-browser
  git_commit: '[% exec("git rev-parse " _ c("git_hash") _ "^{commit}", { exec_noco => 1 }) %]'
  deps:
    - build-essential
    - autoconf
    - yasm
    - pkg-config
  has_l10n: '[% !c("var/testbuild") && c("var/locales").size %]'
  # For testing purposes use override_updater_url, as it will also override the
  # certificate.
  updater_url: 'https://aus1.torproject.org/torbrowser/update_3/'
  mar_id_prefix: 'torbrowser-torproject'
  mar_channel_id: '[% c("var/mar_id_prefix") %]-[% c("var/channel") %]'

  # Uncomment this if you want to test the updater. You will need to provide a
  # marsigner.der in this directory, too. It will replace either the release
  # key, or the nightly key, depending on the channel you are building.
  # override_updater_url: 'https://tb-build-05.torproject.org/~you/update_3/'

  rezip: |
    rezip_tmpdir=$(mktemp -d)
    mkdir -p "$rezip_tmpdir/z"
    unzip -q -d "$rezip_tmpdir/z" -- [% c("rezip_file") %] || [ $? -lt 3 ]
    pushd "$rezip_tmpdir/z"
    [% c("zip", {
      zip_src => [ '.' ],
      zip_args => '$rezip_tmpdir/new.zip',
    }) %]
    popd
    mv -f -- "$rezip_tmpdir/new.zip" [% c("rezip_file") %]
    rm -Rf "$rezip_tmpdir"

  l10n-changesets: '[% exec("git --no-pager show " _ c("git_hash") _ ":browser/locales/l10n-changesets.json", { exec_noco => 1 }) %]'

  windows_rs_version: '0.62.2'
  windows_rs_sha256sum: 527fadee13e0c05939a6a05d5bd6eec6cd2e3dbd648b9f8e447c6518133d8580

  firefox_versions_infos: '[% exec(c("basedir") _ "/tools/toolchain-updates/extract-firefox-versions-infos") %]'

steps:
  src-tarballs:
    filename: 'src-[% project %]-[% c("version") %].tar.xz'
    version: '[% c("git_hash") %]'
    input_files:
      - project: container-image
        pkg_type: build
    compress_tar: ''
    container:
      use_container: 1
    var:
      # single-thread and multi-thread xz will generate a different result,
      # se we use at least 2 threads
      xz_threads: '[% c("num_procs") == "1" ? "2" : c("num_procs") %]'
    src-tarballs: |
      #!/bin/bash
      set -e
      mkdir -p '[% dest_dir %]'
      # Files copied to the container are owned by group root (rbm#40074),
      # and it seems xz doesn't like that and exits with an error
      chgrp rbm '[% project %]-[% c("version") %].tar'
      xz --threads=[% c("var/xz_threads") %] -f '[% project %]-[% c("version") %].tar'
      mv -vf '[% project %]-[% c("version") %].tar.xz' '[% dest_dir %]/[% c("filename") %]'
    targets:
      nightly:
        version: '[% c("abbrev") %]'

targets:
  firefoxbrowser:
    git_hash: '[% c("var/upstream_firefox_commit") %]'
    tag_gpg_id: 0
    var:
      updater_url: ''
      has_l10n: 0

  nightly:
    git_hash: '[% c("var/project-name") %]-[% c("var/firefox_version") %]-[% c("var/browser_branch") %]'
    tag_gpg_id: 0
    var:
      updater_url: 'https://nightlies.tbb.torproject.org/nightly-updates/updates/[% c("var/nightly_updates_publish_dir") %]'

  mullvadbrowser:
    git_url: https://gitlab.torproject.org/tpo/applications/mullvad-browser.git
    var:
      gitlab_project: https://gitlab.torproject.org/tpo/applications/mullvad-browser
      updater_url: 'https://cdn.mullvad.net/browser/update_responses/update_1/'
      mar_id_prefix: 'mullvadbrowser-mullvad'
      nightly_updates_publish_dir_prefix: mullvadbrowser-
  linux-x86_64:
    var:
      arch_deps:
        - libgtk2.0-dev
        - libgtk-3-dev
        - libdbus-glib-1-dev
        - libxt-dev
        # To pass configure since ESR 31
        - libpulse-dev
        # To pass configure since ESR 52
        - libx11-xcb-dev
        # To pass configure since ESR 102
        - libasound2-dev
        # To support Wayland mode
        - libdrm-dev

  linux-aarch64:
    var:
      no_install_recommends: 1
      arch_deps:
        - libgtk2.0-dev:arm64
        - libgtk-3-dev:arm64
        - libdbus-glib-1-dev:arm64
        - libxt-dev:arm64
        # To pass configure since ESR 31
        - libpulse-dev:arm64
        # To pass configure since ESR 52
        - libx11-xcb-dev:arm64
        # To pass configure since ESR 102
        - libasound2-dev:arm64
        # To support Wayland mode
        - libdrm-dev:arm64

  macos:
    var:
      nightly_updates_publish_dir: '[% c("var/nightly_updates_publish_dir_prefix") %]nightly-macos'
      arch_deps:
        - python3
        - python3-zstandard
        - rsync

  windows:
    var:
      arch_deps:
        - python3
        - python3-zstandard
        - wine

  list_toolchain_updates:
    git_hash: '[% c("var/upstream_firefox_commit") %]'
    tag_gpg_id: 0

input_files:
  - project: container-image
  - filename: 'mozconfig'
    content: '[% INCLUDE "mozconfig.in" %]'
    refresh_input: 1
  - name: '[% c("var/compiler") %]'
    project: '[% c("var/compiler") %]'
    # Cross-binutils are already included in the cross-compiler
  - project: binutils
    name: binutils
    enable: '[% c("var/linux") && ! c("var/linux-cross") %]'
  - filename: rename-branding-strings.py
    enable: '[% c("var/has_l10n") && c("var/tor-browser") %]'
  - filename: fix-info-plist.py
    enable: '[% c("var/macos") %]'
  - project: rust
    name: rust
  - project: cbindgen
    name: cbindgen
  - project: firefox-l10n
    name: firefox-l10n
    enable: '[% c("var/has_l10n") %]'
  - project: wasi-sysroot
    name: wasi-sysroot
    enable: '[% c("var/rlbox") %]'
  - project: node
    name: node
  - project: nasm
    name: nasm
    enable: '[% ! c("var/linux-aarch64") %]'
  - project: python
    name: python
    enable: '[% c("var/linux") %]'
  - project: clang-linux
    name: clang
    enable: '[% c("var/linux") %]'
  - project: fxc2
    name: fxc2
    enable: '[% c("var/windows") %]'
    target_prepend:
      - torbrowser-windows-x86_64
  - URL: 'https://static.crates.io/crates/windows/windows-[% c("var/windows_rs_version") %].crate'
    name: windows-rs
    filename: 'windows-rs-[% c("var/windows_rs_version") %].tar.gz'
    sha256sum: '[% c("var/windows_rs_sha256sum") %]'
    enable: '[% c("var/windows") %]'
  - project: windows-app-sdk
    name: windows-app-sdk
    enable: '[% c("var/windows") %]'
  - filename: abicheck.cc
    enable: '[% c("var/linux") %]'
  - project: translation
    name: translation-base-browser
    pkg_type: base-browser
    enable: '[% c("var/has_l10n") %]'
  - project: translation
    name: translation-tor-browser
    pkg_type: tor-browser
    enable: '[% c("var/tor-browser") && c("var/has_l10n") %]'
  - project: translation
    name: translation-mullvad-browser
    pkg_type: mullvad-browser
    enable: '[% c("var/mullvad-browser") && c("var/has_l10n") %]'
  - filename: marsigner.der
    enable: '[% c("var/override_updater_url") %]'
  - project: python-zstandard
    enable: '[% c("var/linux") && c("var/dev_artifacts") %]'
    name: python-zstandard
  - filename: dmg-root
    enable: '[% c("var/macos") && c("var/dev_artifacts") %]'
  - project: hfsplus-tools
    name: hfsplus-tools
    enable: '[% c("var/macos") && c("var/dev_artifacts") %]'
  - project: libdmg-hfsplus
    name: libdmg
    enable: '[% c("var/macos") && c("var/dev_artifacts") %]'
  # When building upstream firefox we need this patch to be able to
  # build for Windows
  - filename: firefoxbrowser-BB-29320.patch
    enable: '[% c("var/firefox-browser") && c("var/windows") %]'
'''.encode('utf-8')
FIREFOX_BUILD_PREIMAGE = r'''#!/bin/bash
[% c("var/set_default_env") -%]
[% pc(c('var/compiler'), 'var/setup', {
        compiler_tarfile => c('input_files_by_name/' _ c('var/compiler')),
        hardened_gcc => 0, # don't set hardened_gcc since firefox is setting the hardened flags
      }) %]
distdir=/var/tmp/dist/[% project %]
mkdir -p /var/tmp/build
[% SET out_dir = dest_dir _ '/' _ c('filename') -%]
mkdir -p [% out_dir %]

[% IF c("var/windows") -%]
  # Setting up fxc2
  tar -C /var/tmp/dist -xf [% c('input_files_by_name/fxc2') %]
  export PATH="/var/tmp/dist/fxc2/bin:$PATH"

  tar -C /var/tmp/dist -xf [% c('input_files_by_name/windows-rs') %]
  export MOZ_WINDOWS_RS_DIR="$(dirname $(find /var/tmp/dist/windows-* -name 'Cargo.toml' -print -quit))"

  tar -C /var/tmp/dist -xf [% c('input_files_by_name/windows-app-sdk') %]
  export MOZ_WINDOWS_APP_SDK_DIR=/var/tmp/dist/windows-app-sdk
[% END -%]

tar -C /var/tmp/dist -xf [% c('input_files_by_name/rust') %]
tar -C /var/tmp/dist -xf [% c('input_files_by_name/cbindgen') %]
tar -C /var/tmp/dist -xf [% c('input_files_by_name/node') %]
[% IF ! c("var/linux-aarch64") -%]
  tar -C /var/tmp/dist -xf [% c('input_files_by_name/nasm') %]
  export PATH="/var/tmp/dist/nasm/bin:$PATH"
[% END -%]
export PATH="/var/tmp/dist/rust/bin:/var/tmp/dist/cbindgen:/var/tmp/dist/node/bin:$PATH"

[% IF c("var/linux") -%]
  tar -C /var/tmp/dist -xf [% c('input_files_by_name/clang') %]
  tar -C /var/tmp/dist -xf [% c('input_files_by_name/python') %]
  export PATH="/var/tmp/dist/python/bin:$PATH"
  # For OpenSSL, see Python's README.md.
  export LD_LIBRARY_PATH=/var/tmp/dist/python/lib:$LD_LIBRARY_PATH
  [% IF ! c("var/linux-cross") -%]
    tar -C /var/tmp/dist -xf $rootdir/[% c('input_files_by_name/binutils') %]
    export PATH="/var/tmp/dist/binutils/bin:$PATH"
  [% END -%]
  # Use clang for everything on Linux now if we don't build with ASan.
  [% IF ! c("var/asan") -%]
    export PATH="/var/tmp/dist/clang-linux/bin:$PATH"
  [% END -%]
  [% IF c("var/linux-cross") -%]
    # Exporting `PKG_CONFIG_PATH` in the mozconfig file is causing build
    # breakage in Rust code. It seems that environment variable is not passed
    # down properly in that case. Thus, we set it here in the build script.
    export PKG_CONFIG_PATH="/usr/lib/[% c('var/crosstarget') %]/pkgconfig:${PKG_CONFIG_PATH:-}"
  [% END -%]
  [% IF c("var/dev_artifacts") -%]
    python3 -m pip install $rootdir/[% c('input_files_by_name/python-zstandard') %]/*.whl
  [% END -%]
[% END -%]

[% IF c("var/macos") && c("var/dev_artifacts") %]
  tar -C /var/tmp/dist -xf $rootdir/[% c('input_files_by_name/hfsplus-tools') %]
  tar -C /var/tmp/dist -xf $rootdir/[% c('input_files_by_name/libdmg') %]
[% END %]

[% IF c("var/rlbox") -%]
  tar -C /var/tmp/dist -xf [% c('input_files_by_name/wasi-sysroot') %]
  export WASI_SYSROOT=/var/tmp/dist/wasi-sysroot
[% END -%]

tar -C /var/tmp/build -xf [% project %]-[% c('version') %].tar.[% c('compress_tar') %]

mkdir -p $distdir/[% IF ! c("var/macos") %]Browser[% END %]

cd /var/tmp/build/[% project %]-[% c("version") %]
cp $rootdir/mozconfig ./

[% IF c("var/asan") -%]
  # Without disabling LSan our build is blowing up:
  # https://bugs.torproject.org/10599#comment:52
  export ASAN_OPTIONS="detect_leaks=0"
[% END -%]

[% c("var/set_MOZ_BUILD_DATE") %]

[% IF c("var/windows") -%]
  # Make sure widl is not inserting random timestamps, see #21837.
  export WIDL_TIME_OVERRIDE="0"
  # mingw-w64 does not support SEH on 32bit systems. Be explicit about that.
  export LDFLAGS="[% c('var/flag_noSEH') %]"
[% END -%]

[% IF c("var/override_updater_url") -%]
  [% IF c("var/release") || c("var/alpha") -%]
    cp $rootdir/marsigner.der toolkit/mozapps/update/updater/release_secondary.der
  [% ELSIF c("var/nightly") -%]
    cp $rootdir/marsigner.der toolkit/mozapps/update/updater/nightly_aurora_level3_secondary.der
  [% END -%]
[% END -%]

export MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE=system

# Create .mozbuild to avoid interactive prompt in configure
mkdir "$HOME/.mozbuild"

[% INCLUDE 'browser-localization' %]

# PyYAML tries to read files as ASCII, otherwise
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

[% IF c("var/firefox-browser") && c("var/windows") -%]
  patch -p1 < $rootdir/firefoxbrowser-BB-29320.patch
[% END -%]

[% IF c("var/dev_artifacts") -%]
  [% IF c("var/macos") -%]
    export MOZ_PKG_MAC_BACKGROUND=$(find $rootdir/dmg-root/[% c('var/ProjectName') %].dmg/.background  -type f)
    export MOZ_PKG_MAC_DSSTORE=$rootdir/dmg-root/[% c('var/ProjectName') %].dmg/nightly.DS_Store
    export MOZ_PKG_MAC_ICON=$rootdir/dmg-root/[% c('var/ProjectName') %].dmg/.VolumeIcon.icns
  [% END -%]
[% END -%]

echo "Starting ./mach configure $(date)"
./mach configure \
  --with-distribution-id=org.torproject \
  [% IF !c("var/firefox-browser") %]--with-base-browser-version=[% c("var/torbrowser_version") %][% END %] \
  [% IF c("var/updater_enabled") -%]--enable-update-channel=[% c("var/channel") %][% END %] \
  [% IF !c("var/firefox-browser") -%]--with-branding="$branding_dir"[% END %] \
  [% IF !c("var/rlbox") -%]--without-wasm-sandboxed-libraries[% END %]

echo "Starting ./mach build $(date)"
./mach build --verbose

[% IF c("var/firefox-browser") && c("var/windows"); RETURN; END; -%]

[% IF c("var/has_l10n") -%]
  echo "Starting to merge locales $(date)"
  export MOZ_CHROME_MULTILOCALE="$supported_locales"
  # No quotes on purpose, see https://firefox-source-docs.mozilla.org/build/buildsystem/locales.html#instructions-for-multi-locale-builds
  ./mach package-multi-locale --locales en-US $MOZ_CHROME_MULTILOCALE
  AB_CD=multi ./mach build stage-package
  echo "Locales merged $(date)"
[% ELSE -%]
  ./mach build stage-package
[% END -%]

[% IF c("var/dev_artifacts") -%]
  echo "Building development artifacts"

  # Package the browser and also create all the test artifacts.
  #
  # MOZ_SIMPLE_PACKAGE_NAME will force all artifact files to start with "target",
  # instead of the name of the package, which would be something like: firefox-140.4.0.en-US.linux-x86_64.
  # This is the same convention used by upstream.
  #
  # Also it just makes it easier to copy all artifacts over in the next step.
  MOZ_SIMPLE_PACKAGE_NAME="target" ./mach build package package-tests

  artifactsdir=[% out_dir %]/artifacts/[% c("var/osname") %]
  mkdir -p $artifactsdir
  mv obj-*/dist/target.* $artifactsdir

  ./mach python -m mozbuild.action.test_archive mozharness mozharness.zip
  mv mozharness.zip $artifactsdir

  echo -n '[% c("var/firefox_platform_version") %]' > "$artifactsdir/firefox_platform_version.txt"
[% END %]

[% IF c("var/macos") -%]
  cp -a obj-*/dist/[% c('var/exe_name') %]/* $distdir
  [% IF c("var/firefox-browser") -%]
    mv "$distdir/Nightly.app" "$distdir/[% c('var/display_name') %].app"
  [% END -%]
  app_bundle="[% c('var/display_name') %].app"
  # Remove firefox-bin (we don't use it, see ticket #10126)
  rm -f "$distdir/$app_bundle/Contents/MacOS/[% c('var/exe_name') %]-bin"

  # Adjust the Info.plist file
  INFO_PLIST="$distdir/$app_bundle/Contents/Info.plist"
  python3 $rootdir/fix-info-plist.py \
    "$INFO_PLIST" \
    '[% c("var/Project_Name") %]' \
    '[% c("var/torbrowser_version") %]' \
    '[% c("var/copyright_year") %]' \
    [% IF c("var/mullvad-browser") -%]'Mullvad, Tor Browser and Mozilla Developers'[% ELSE -%]'The Tor Project'[% END %]
[% END -%]

[% IF c("var/linux") -%]
  cp -a obj-*/dist/[% c('var/exe_name') %]/* $distdir/Browser/
  mkdir -p $distdir/Debug
  # Some include files are symlinks, so use -Lr, or the tarball will fail
  # silently. Also, on Linux we populate the debug symbols by stripping later.
  cp -Lr obj-*/dist/include $distdir/Debug/
  # Remove firefox-bin (we don't use it, see ticket #10126)
  rm -f "$distdir/Browser/[% c('var/exe_name') %]-bin"
  # TODO: There goes FIPS-140.. We could upload these somewhere unique and
  # subsequent builds could test to see if they've been uploaded before...
  # But let's find out if it actually matters first..
  rm -f $distdir/Browser/*.chk
  # Replace $exe_name by a wrapper script (#25485)
  mv "$distdir/Browser/[% c('var/exe_name') %]" "$distdir/Browser/[% c('var/exe_name') %].real"
  cat > "$distdir/Browser/[% c('var/exe_name') %]" << 'RBM_TB_EOF'
[% INCLUDE 'start-firefox' -%]
RBM_TB_EOF
  chmod 755 "$distdir/Browser/[% c('var/exe_name') %]"
[% END -%]
[% IF c("var/linux-x86_64") -%]
  cp -L obj-*/dist/host/bin/geckodriver $distdir
[% END -%]

[% IF c("var/windows") -%]
  cp -a obj-*/dist/[% c('var/exe_name') %]/* $distdir/Browser/
  [% IF c("var/windows-i686") -%]
    cp -a /var/tmp/dist/fxc2/bin/d3dcompiler_47_32.dll $distdir/Browser/d3dcompiler_47.dll
  [% ELSE -%]
    cp -a /var/tmp/dist/fxc2/bin/d3dcompiler_47.dll $distdir/Browser
  [% END -%]
  mkdir -p $distdir/Debug/Browser
  pushd obj-*
  cp -Lr dist/include $distdir/Debug/
  find . -path ./_tests -prune -o -name '*.pdb' -exec cp -l {} $distdir/Debug/Browser/ \;
  popd
[% END -%]

[% IF c("var/updater_enabled") -%]
  # Make MAR-based update tools available for use during the bundle phase.
  # Note that mar and mbsdiff are standalone tools, compiled for the build
  # host's architecture.  We also include signmar, certutil, and the libraries
  # they require; these utilities and libraries are built for the target
  # architecture.
  MARTOOLS=$distdir/mar-tools
  mkdir -p $MARTOOLS
  cp -p config/createprecomplete.py $MARTOOLS/
  cp -p tools/update-packaging/*.sh $MARTOOLS/
  cp -p obj-*/dist/host/bin/mar $MARTOOLS/
  cp -p obj-*/dist/host/bin/mbsdiff $MARTOOLS/
  [% IF c("var/linux") || c("var/macos") -%]
    cp -p obj-*/dist/bin/signmar $MARTOOLS/
    cp -p obj-*/dist/bin/certutil $MARTOOLS/
    cp -p obj-*/dist/bin/pk12util $MARTOOLS/
    [% IF c("var/linux") -%]
      NSS_LIBS="libfreeblpriv3.so libmozsqlite3.so libnss3.so libnssutil3.so libsmime3.so libsoftokn3.so libssl3.so"
      NSPR_LIBS="libnspr4.so libplc4.so libplds4.so"
    [% ELSE -%]
      NSS_LIBS="libfreebl3.dylib libmozglue.dylib libnss3.dylib libsoftokn3.dylib"
      # No NSPR_LIBS for macOS
      NSPR_LIBS=""
    [% END -%]
    for LIB in $NSS_LIBS $NSPR_LIBS; do
      cp -p obj-*/dist/bin/$LIB $MARTOOLS/
    done
  [% END -%]
  [% IF c("var/windows") -%]
    cp -p obj-*/dist/bin/signmar.exe $MARTOOLS/
    cp -p obj-*/dist/bin/certutil.exe $MARTOOLS/
    cp -p obj-*/dist/bin/pk12util.exe $MARTOOLS/
    NSS_LIBS="freebl3.dll mozglue.dll nss3.dll softokn3.dll"
    for LIB in $NSS_LIBS; do
        cp -p obj-*/dist/bin/$LIB $MARTOOLS/
    done
  [% END -%]
[% END -%]

[% IF c("var/mullvad-browser") && c("var/windows") -%]
  function make_nsis_plugin {
    pushd "other-licenses/nsis/Contrib/$1"
    make CXX=[% c("arch") %]-w64-mingw32-clang++
    cp "$1.dll" $distdir/nsis-plugins/
    [% c("touch") %] "$distdir/nsis-plugins/$1.dll"
    popd
  }

  mkdir -p $distdir/nsis-plugins
  make_nsis_plugin ApplicationID
  make_nsis_plugin CityHash
[% END -%]

cd $distdir

[% IF c("var/linux") -%]
  CROSS_PREFIX=[% IF c("var/linux-cross") %][% c("var/crosstarget") %]-[% END %]
  OBJCOPY="${CROSS_PREFIX}objcopy"
  STRIP="${CROSS_PREFIX}strip"

  mkdir -p $distdir/Debug/Browser
  # Strip and generate debuginfo for the firefox binary that we keep, all *.so
  # files, and the updater (see ticket #10126)
  for LIB in Browser/*.so "Browser/[% c('var/exe_name') %].real" [% IF c("var/updater_enabled") -%]Browser/updater[% END %]
  do
    "$OBJCOPY" --only-keep-debug $LIB Debug/$LIB
    "$STRIP" $LIB
    "$OBJCOPY" --add-gnu-debuglink=./Debug/$LIB $LIB
  done
[% END -%]

# Re-zipping the omni.ja files is not needed to make them reproductible,
# however if we don't re-zip them, the files become corrupt when we
# update them using 'zip' and firefox will silently fail to load some
# parts.
[% IF c("var/windows") || c("var/linux") -%]
  [% c("var/rezip", { rezip_file => 'Browser/omni.ja' }) %]
  [% c("var/rezip", { rezip_file => 'Browser/browser/omni.ja' }) %]
[% ELSIF c("var/macos") -%]
  [% c("var/rezip", { rezip_file => '"$app_bundle/Contents/Resources/omni.ja"' }) %]
  [% c("var/rezip", { rezip_file => '"$app_bundle/Contents/Resources/browser/omni.ja"' }) %]
[% END -%]

[%
IF c("var/macos");
  SET browserdir='"$app_bundle/Contents"';
ELSE;
  SET browserdir='Browser';
END;
%]

[% IF c("var/linux") -%]
  /var/tmp/dist/gcc/bin/"${CROSS_PREFIX}g++" $rootdir/abicheck.cc -o Browser/abicheck -std=c++17
  libdest=Browser/libstdc++
  mkdir -p "$libdest"
  libdir=lib64
  [% IF c("var/linux-cross") -%]
    libdir="[% c("var/crosstarget") %]/$libdir"
  [% END -%]
  # Not copying libstdc++.so.* as that dups with the full libstdc++.so.6.0.xx the .6 links to
  # and libstdc++.so.6.0.28-gdb.py which is also not needed
  cp "/var/tmp/dist/gcc/$libdir/libstdc++.so.6" "$libdest"
  [% IF c("var/asan") -%]
    cp "/var/tmp/dist/gcc/$libdir/libasan.so."* "$libdest"
    cp "/var/tmp/dist/gcc/$libdir/libubsan.so."* "$libdest"
  [% END -%]
  # Strip and generate debuginfo for libs
  for LIB in "$libdest"/*so*
  do
    "$STRIP" "$LIB"
  done
[% END -%]

echo "Starting to package artifacts $(date)"

[% c('tar', {
        tar_src => [ browserdir ],
        tar_args => '-caf ' _ out_dir _ '/browser.tar.' _ c('compress_tar'),
    }) %]

# Debug symbols
[% IF c("var/linux") -%]
  pushd Debug
  mkdir -p [% c('var/project-name') %]/Browser
  mv Browser [% c('var/project-name') %]/Browser/.debug
  mv include [% c('var/project-name') %]/
  [% c('tar', {
      tar_src => [ c('var/project-name') ],
      tar_args => '-cJf ' _ out_dir _ '/browser-debug-symbols.tar.xz',
    }) %]
  popd
[% ELSIF c("var/windows") -%]
  [% c('zip', {
      zip_src => [ 'Debug' ],
      zip_args => out_dir _ '/browser-debug-symbols.zip',
    }) %]
[% END -%]

[% IF c("var/linux-x86_64") -%]
  # Geckodriver
  llvm-strip geckodriver
  [% c('tar', {
      tar_src => [ 'geckodriver' ],
      tar_args => '-cJf ' _ out_dir _ '/geckodriver.tar.xz',
    }) %]
[% END -%]

# MAR tools
[% IF c("var/updater_enabled") -%]
  [% c('zip', {
      zip_src => [ 'mar-tools' ],
      zip_args => out_dir _ '/' _ 'mar-tools-' _ c("var/osname") _ '-' _ c("var/torbrowser_version") _ '.zip',
    }) %]
[% END -%]

[% IF c("var/mullvad-browser") && c("var/windows") -%]
  [% c('tar', {
      tar_src => [ 'nsis-plugins' ],
      tar_args => '-caf ' _ out_dir _ '/nsis-plugins.tar.' _ c('compress_tar'),
    }) %]
[% END -%]

[% IF c("var/build_infos_json") -%]
  cat > "[% out_dir _ '/build-infos.json' %]" << EOF_BUILDINFOS
  {
      "firefox_platform_version" : "[% c("var/firefox_platform_version") %]",
      "firefox_buildid" : "$MOZ_BUILD_DATE"
  }
EOF_BUILDINFOS
[% END -%]
'''.encode('utf-8')


class ResourceExactOverlaySemanticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-exact-overlay-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.policy = load_validator()
        self.patch_file = ROOT / "patches/firefox-pgo-generate.patch"
        self.patch_bytes = self.patch_file.read_bytes()

    def test_saved_actual_7dd_firefox_preimages_and_exact_immutable_overlay_match_native_git(self):
        self.assertEqual(digest(FIREFOX_CONFIG_PREIMAGE), "7d20906ce5a05e5ccda46109bf9136e72c06141dfcf82f394205509ee53785a3")
        self.assertEqual(digest(FIREFOX_BUILD_PREIMAGE), "5f322cb45ce132755c628b46604797964d94d2ce0c2a27d0678b8b18330c4eff")
        self.assertEqual(digest(self.patch_bytes), RUST_CHECKPOINT["overlay"]["sha256"])
        original = overlay_preimages(self.patch_bytes.decode())
        original["projects/firefox/config"] = FIREFOX_CONFIG_PREIMAGE
        original["projects/firefox/build"] = FIREFOX_BUILD_PREIMAGE
        for relative, content in original.items():
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        # Default Git declared-hunk semantics, not --recount or a patched header.
        status = subprocess.run(["git", "apply", str(self.patch_file)], cwd=self.base,
                                 env=native_environment(), capture_output=True, timeout=5)
        self.assertEqual(status.returncode, 0, "native immutable overlay fixture failed")
        for relative, content in original.items():
            with self.subTest(relative=relative):
                self.assertEqual(self.policy.apply_overlay(content, self.patch_bytes, relative),
                                 (self.base / relative).read_bytes())
        self.assertIn("tag_gpg_id: 0", (self.base / "projects/firefox/config").read_text())
        self.assertEqual(self.patch_file.read_bytes(), self.patch_bytes, "protected patch changed")

    def test_exact_context_mismatch_cannot_be_treated_as_a_permitted_source_overlay(self):
        changed = FIREFOX_CONFIG_PREIMAGE.replace(b"\ntargets:\n", b"\nchanged_targets:\n", 1)
        with self.assertRaisesRegex(self.policy.GateError, "overlay_preimage_mismatch"):
            self.policy.apply_overlay(changed, self.patch_bytes, "projects/firefox/config")
        unrelated = b"unrelated pinned recipe source\n"
        self.assertEqual(self.policy.apply_overlay(unrelated, self.patch_bytes, "projects/node/config"), unrelated)


FAKE_RESOLVER_PERL = r"""
import json, os, subprocess, sys
from pathlib import Path
config = json.loads(Path(os.environ['POLICY_RESOLVER_CONFIG']).read_text())
record = {'pid': os.getpid(), 'pgrp': os.getpgrp(), 'sid': os.getsid(0),
          'git_no_replace_objects': os.environ.get('GIT_NO_REPLACE_OBJECTS')}
with Path(os.environ['POLICY_RESOLVER_CALLS']).open('a') as stream:
    stream.write(json.dumps(record) + '\n')
if config.get('orphan'):
    child = subprocess.Popen([sys.executable, '-c', 'import signal; signal.pause()'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    Path(os.environ['POLICY_RESOLVER_PID']).write_text(str(child.pid))
if config.get('flood'):
    os.write(1, b'A' * 140000)
    os.write(2, b'B' * 140000)
else:
    print('preserved fixture metadata', flush=True)
"""


class ResourceResolverOwnedSessionTests(unittest.TestCase):
    """Native runpy driver + fake metadata child remain in the owned session."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgo-resource-resolver-owned-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.policy = load_validator()
        self.config = self.base / "config.json"
        self.calls = self.base / "calls.jsonl"
        self.pidfile = self.base / "orphan.pid"
        self.settings = {}
        self.config.write_text(json.dumps(self.settings))
        install_python(self.base / "bin/perl", FAKE_RESOLVER_PERL)
        self.environment = native_environment() | {
            "PATH": str(self.base / "bin") + os.pathsep + os.environ.get("PATH", ""),
            "POLICY_RESOLVER_CONFIG": str(self.config), "POLICY_RESOLVER_CALLS": str(self.calls),
            "POLICY_RESOLVER_PID": str(self.pidfile)}
        self.resolver = self.base / "fixture-resolver.py"
        self.resolver.write_text(
            'import json,os\nfrom pathlib import Path\nfrom rbm_network import showconf\n'
            'print("RESOLVER_SESSION " + json.dumps({"pid":os.getpid(),"pgrp":os.getpgrp(),"sid":os.getsid(0)}),flush=True)\n'
            f'print(showconf(Path({str(self.base)!r}), "rust", "filename", {TARGETS!r}),flush=True)\n')

    def native_driver(self, **settings):
        self.settings.update(settings)
        self.config.write_text(json.dumps(self.settings))
        return self.policy.run_native([sys.executable, "-c", self.policy.RESOLVER_CODE,
                       str(HELPER), str(self.resolver)], cwd=self.base, environment=self.environment,
                       deadline=self.policy.Deadline(3), seconds=2)

    def assert_dead(self, pid):
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            ready, _, _ = select.select([descriptor], [], [], 1)
            self.assertTrue(ready, "nested resolver descendant survived owned-session cleanup")
        finally:
            os.close(descriptor)

    def test_nested_metadata_child_and_orphan_inherit_outer_owned_session_and_are_killed(self):
        status, stdout, stderr = self.native_driver(orphan=True)
        self.assertEqual(status, 0, "native fixture resolver failed")
        self.assertEqual(stderr, b"")
        lines = stdout.decode().splitlines()
        self.assertEqual(len(lines), 2)
        leader = json.loads(lines[0].removeprefix("RESOLVER_SESSION "))
        self.assertEqual(lines[1], "preserved fixture metadata")
        child = json.loads(self.calls.read_text())
        self.assertEqual(child["pgrp"], leader["pgrp"])
        self.assertEqual(child["sid"], leader["sid"])
        self.assertEqual(leader["pgrp"], leader["pid"])
        self.assertEqual(leader["sid"], leader["pid"])
        self.assertEqual(child["git_no_replace_objects"], "1")
        self.assert_dead(int(self.pidfile.read_text()))
        self.assertEqual(len(self.calls.read_text().splitlines()), 1, "resolver retried metadata")

    def test_nested_stdout_and_stderr_share_one_cap_without_retry_or_new_session(self):
        status, stdout, stderr = self.native_driver(flood=True)
        self.assertNotEqual(status, 0)
        self.assertNotIn(b'A' * 1024, stdout + stderr)
        self.assertNotIn(b'B' * 1024, stdout + stderr)
        self.assertIn(b'native_output_limit', stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
