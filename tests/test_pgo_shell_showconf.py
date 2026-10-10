#!/usr/bin/env python3
"""Offline native coverage for shell PGO showconf calls (no browser builds)."""
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
SCRIPTS = ("validate-pgo-overlay.sh", "preflight-pgo-rust.sh", "run-pgo-generate.sh",
           "run-pgo-use.sh", "prepare-pgo-use.sh")
COMMON = ["--target", "alpha", "--target", "mullvadbrowser-windows-x86_64"]
GENERATE = COMMON + ["--target", "pgo-generate"]
USE = COMMON + ["--target", "pgo-use"]
BASELINE = ("  # rendering whitespace must survive\n\n./mach configure \\\n"
            "  --with-base-browser-version=16.0a9\n\n\n")
GENERATION = BASELINE.replace("  --with-base", "  --enable-profile-generate=cross \\\n  --with-base")
PROFILE_USE = BASELINE.replace("  --with-base", "  --enable-profile-use=cross \\\n"
    "  --with-pgo-profile-path=/var/tmp/dist/pgo/merged.profdata \\\n"
    "  --with-pgo-jarlog=/var/tmp/dist/pgo/jarlog \\\n  --with-base")

FAKE_RBM = r"""import json, os, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[1]
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as stream:
 stream.write(json.dumps({'argv': args, 'cwd': os.getcwd(), 'PWD': os.environ.get('PWD'),
  'UPSTREAM': os.environ['UPSTREAM'], 'sentinel': os.environ['FIXTURE_SENTINEL']}) + '\n')
config = json.loads((root / 'values.json').read_text())
if args[0] == 'showconf':
 project, key = args[1:3]
 if config.get('failure_key') == project + '|' + key:
  sys.stdout.write('FAILED OUTPUT MUST NOT BECOME A RENDER OR IDENTITY\n')
  sys.stderr.write('compiler or checksum failure is not a retryable transport error\n')
  sys.exit(config.get('failure_code', 17))
 target = args[-1] if len(args) > 3 else ''
 value = config.get(project + '|' + key + '|' + target, config.get(project + '|' + key))
 if value is None:
  raise SystemExit('unexpected fixture showconf ' + repr(args))
 sys.stdout.write(value)
elif args[0] == 'build':
 if config.get('build_failure'):
  sys.stderr.write(config.get('build_stderr', 'native build failed; it must not be retried\n'))
  sys.exit(config['build_failure'])
 assert args[1] == 'firefox', args
 (root / 'logs').mkdir(exist_ok=True)
 if args[-1] == 'pgo-generate':
  evidence = '--enable-profile-generate=cross\nclang -fprofile-generate\nrustc -C profile-generate=/tmp/fixture\n'
 else:
  assert args[-1] == 'pgo-use', args
  evidence = '--enable-profile-use=cross\n-fprofile-use=/var/tmp/dist/pgo/merged.profdata\nrustc -C profile-use=/var/tmp/dist/pgo/merged.profdata\n'
 (root / 'logs/firefox-windows-x86_64.log').write_text(evidence)
 destination = root / 'out/firefox/firefox-selected'
 destination.mkdir(parents=True, exist_ok=True)
 (destination / 'browser.tar.xz').write_bytes(b'instrumented runtime fixture')
 if config.get('ambiguous_runtime'):
  (destination / 'browser.tar.zst').write_bytes(b'other runtime fixture')
else:
 raise SystemExit('unexpected fixture RBM command ' + repr(args))
"""
FAKE_PROFILE = r"""import pathlib, shutil, sys
args = sys.argv[1:]
if args[0] == 'restore':
 source = pathlib.Path(args[args.index('--source-directory') + 1])
 destination = pathlib.Path(args[args.index('--directory') + 1])
 destination.mkdir(parents=True, exist_ok=True)
 for name in ['merged.profdata', 'jarlog']:
  shutil.copyfile(source / name, destination / name)
else:
 assert args[0] == 'validate', args
"""
FAKE_COLLECT = r"""import json, os, pathlib, sys
assert sys.argv[1] == 'snapshot-firefox', sys.argv
pathlib.Path(os.environ['COLLECT_CALL']).write_text(json.dumps(sys.argv[1:]))
"""
FAKE_GIT = r"""import json, os, sys
args = sys.argv[1:]
assert args[:2] == ['-C', os.environ['UPSTREAM']], args
if args[2:] == ['rev-parse', 'HEAD']:
 print(os.environ['LOCK_COMMIT'])
else:
 assert args[2:] in [['apply', '--reverse', '--check', os.environ['PATCH_PATH']], ['diff', '--check']], args
"""
FAKE_RUSTC = r"""import json, os, pathlib, sys
root = pathlib.Path(sys.argv[0]).parent.parent
args = sys.argv[1:]
if '--version' in args:
 print('rustc functional fixture')
elif '--print' in args:
 key = args[args.index('--print') + 1]
 print(root if key == 'sysroot' else root / 'lib/rustlib/x86_64-pc-windows-gnullvm/lib')
else:
 pathlib.Path(os.environ['RUST_CALL']).write_text(json.dumps(args))
 pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'MZnative link fixture')
"""


def executable(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!' + sys.executable + '\n' + source)
    path.chmod(0o755)


def archive(path, files, directories=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w:gz') as output:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            output.addfile(info)
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.mode, info.size = 0o755, len(data)
            output.addfile(info, io.BytesIO(data))


class ShellShowconfTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pgo-shell-showconf-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.overlay = self.base / 'overlay with spaces'
        self.upstream = self.base / 'upstream with spaces'
        self.runtime = self.base / 'runner temp'
        self.runtime.mkdir()
        self.relative_upstream = self.upstream.relative_to(self.base).as_posix()
        for name in [*SCRIPTS, 'rbm_network.py', 'validate-pgo-rendering.py', 'observe-rbm-build.py']:
            destination = self.overlay / 'scripts' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'scripts' / name, destination)
        executable(self.upstream / 'rbm/rbm', FAKE_RBM)
        executable(self.overlay / 'scripts/profile-artifacts.py', FAKE_PROFILE)
        executable(self.overlay / 'scripts/collect-pgo-packages.py', FAKE_COLLECT)
        (self.upstream / 'projects/firefox').mkdir(parents=True)
        (self.overlay / 'patches').mkdir()
        self.patch = self.overlay / 'patches/firefox-pgo-use.patch'
        self.patch.write_text('unused exact-already-applied fixture')
        shutil.copyfile(ROOT / 'upstream.lock.json', self.overlay / 'upstream.lock.json')
        self.profile = self.base / 'source profile'
        self.profile.mkdir()
        (self.profile / 'merged.profdata').write_bytes(b'profile fixture')
        (self.profile / 'jarlog').write_bytes(b'jarlog fixture')
        shutil.copytree(self.profile, self.runtime / 'pgo-use/profile')
        self.bin = self.base / 'bin'
        executable(self.bin / 'git', FAKE_GIT)
        self.env = dict(os.environ, UPSTREAM=self.relative_upstream, RUNNER_TEMP=str(self.runtime),
            PGO_PROFILE_DIR=str(self.profile), PGO_EXPECTED_PROVENANCE=str(self.base / 'expected.json'),
            PGO_PROFILE_IDENTITY='b' * 64, FIXTURE_SENTINEL='do-not-mutate',
            COLLECT_CALL=str(self.base / 'collect.json'), RUST_CALL=str(self.base / 'rust.json'),
            LOCK_COMMIT=json.loads((ROOT / 'upstream.lock.json').read_text())['commit'], PATCH_PATH=str(self.patch))
        self.env['PATH'] = str(self.bin) + os.pathsep + str(Path(sys.executable).parent) + os.pathsep + self.env.get('PATH', '')
        self.values = {
            'firefox|build|mullvadbrowser-windows-x86_64': BASELINE,
            'firefox|build|pgo-generate': GENERATION,
            'firefox|build|pgo-use': PROFILE_USE,
            'firefox|filename': 'firefox-selected\n',
            'firefox|build_log': 'logs/firefox-windows-x86_64.log\n',
            'firefox|input_files': ' exact inputs\n\n',
            'firefox|input_files_by_name/rust': 'rust-profiler-selected.tar.gz\n',
            'rust|filename': 'rust-profiler-selected.tar.gz\n',
            'rust|filename|mullvadbrowser-windows-x86_64': 'rust-official.tar.gz\n',
            'rust|var/target': 'x86_64-pc-windows-gnullvm,i686-pc-windows-gnullvm\n',
            'mingw-w64-clang|filename': 'mingw-selected.tar.gz\n',
        }

    def execute(self, name, *args):
        (self.upstream / 'values.json').write_text(json.dumps(self.values))
        return subprocess.run(['bash', str(self.overlay / 'scripts' / name), *args], cwd=self.base,
                              env=self.env, capture_output=True, text=True, timeout=12)

    def calls(self):
        return [json.loads(line) for line in (self.upstream / 'calls.jsonl').read_text().splitlines()]

    def assert_calls(self, expected):
        calls = self.calls()
        self.assertEqual([call['argv'] for call in calls], expected)
        for call in calls:
            self.assertEqual(call['cwd'], str(self.upstream))
            if call['argv'][0] == 'showconf':
                self.assertEqual(call['PWD'], str(self.upstream))
            self.assertEqual(call['UPSTREAM'], self.env['UPSTREAM'])
            self.assertEqual(call['sentinel'], 'do-not-mutate')

    def make_toolchains(self):
        archive(self.upstream / 'out/rust/rust-profiler-selected.tar.gz',
            {'rust/bin/rustc': ('#!' + sys.executable + '\n' + FAKE_RUSTC).encode(),
             'rust/lib/rustlib/x86_64-pc-windows-gnullvm/lib/libprofiler_builtins.rlib': b'runtime'})
        archive(self.upstream / 'out/mingw-w64-clang/mingw-selected.tar.gz',
            {'mingw-w64-clang/bin/x86_64-w64-mingw32-clang': b'#!/bin/sh\nexit 0\n'},
            ['mingw-w64-clang/x86_64-w64-mingw32'])

    def test_all_five_scripts_use_cli_no_bare_showconf_or_build_retry(self):
        for name in SCRIPTS:
            source = (ROOT / 'scripts' / name).read_text()
            with self.subTest(script=name):
                self.assertIn('"$root/scripts/rbm_network.py"', source)
                self.assertIn('--upstream "$PWD"', source)
                self.assertNotRegex(source, r'\./rbm/rbm\s+showconf')
                self.assertNotRegex(source, r'rbm_network\.py[^\n]*\./rbm/rbm\s+build')
        generate = (ROOT / 'scripts/run-pgo-generate.sh').read_text()
        use = (ROOT / 'scripts/run-pgo-use.sh').read_text()
        preflight = (ROOT / 'scripts/preflight-pgo-rust.sh').read_text()
        self.assertIn('-- ./rbm/rbm build firefox "${common[@]}"', generate)
        self.assertIn('-- ./rbm/rbm build firefox "${args[@]}"', use)
        self.assertIn('(cd "$UPSTREAM" && ./rbm/rbm build browser "${args[@]}")', use)
        self.assertLess(preflight.index('root='), preflight.index('cd "$UPSTREAM"'))

    def test_overlay_cli_preserves_render_bytes_targets_pwd_and_relative_upstream(self):
        result = self.execute('validate-pgo-overlay.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.runtime / 'firefox-build-baseline.rendered').read_bytes(), BASELINE.encode())
        self.assertEqual((self.runtime / 'firefox-build-pgo.rendered').read_bytes(), GENERATION.encode())
        self.assert_calls([['showconf', 'firefox', 'build', *COMMON], ['showconf', 'firefox', 'build', *GENERATE]])

    def test_overlay_still_rejects_flag_outside_configure(self):
        self.values['firefox|build|pgo-generate'] = BASELINE + '--enable-profile-generate=cross\n'
        result = self.execute('validate-pgo-overlay.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not an argument', result.stderr)

    def test_failed_overlay_showconf_emits_no_render_and_retains_exit(self):
        self.values.update(failure_key='firefox|build', failure_code=17)
        result = self.execute('validate-pgo-overlay.sh')
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertEqual((self.runtime / 'firefox-build-baseline.rendered').read_bytes(), b'')
        self.assertIn('FAILED OUTPUT', result.stderr)
        self.assertNotIn('FAILED OUTPUT', result.stdout)
        self.assert_calls([['showconf', 'firefox', 'build', *COMMON]])

    def test_preflight_cli_preserves_all_four_queries_and_link_command(self):
        self.make_toolchains()
        result = self.execute('preflight-pgo-rust.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_calls([['showconf', 'rust', 'filename', *GENERATE],
            ['showconf', 'rust', 'filename', *COMMON], ['showconf', 'mingw-w64-clang', 'filename', *GENERATE],
            ['showconf', 'rust', 'var/target', *GENERATE]])
        args = json.loads((self.base / 'rust.json').read_text())
        self.assertEqual(args[args.index('--target') + 1], 'x86_64-pc-windows-gnullvm')
        self.assertIn('profile-generate=' + str(self.runtime / 'pgo-rust-profile'), args)
        self.assertTrue((self.runtime / 'pgo-rust-preflight.exe').is_file())

    def test_generation_keeps_native_build_and_exact_output_selection(self):
        self.env['UPSTREAM'] = str(self.upstream)
        decoy = self.upstream / 'out/firefox/aaa-decoy'
        decoy.mkdir(parents=True)
        (decoy / 'browser.tar.xz').write_bytes(b'decoy never selected')
        result = self.execute('run-pgo-generate.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_calls([['build', 'firefox', *GENERATE], ['showconf', 'firefox', 'filename', *GENERATE]])
        self.assertEqual((self.runtime / 'instrumented/browser.tar.xz').read_bytes(), b'instrumented runtime fixture')

    def test_generation_build_failure_is_native_and_never_retried(self):
        self.env['UPSTREAM'] = str(self.upstream)
        self.values['build_failure'] = 23
        self.values['build_stderr'] = ("error: RPC failed; HTTP 500 curl 22 The requested URL returned error: 500\n"
            "fatal: expected 'packfile'\nError: Error cloning https://git.savannah.gnu.org/git/config.git\n")
        result = self.execute('run-pgo-generate.sh')
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assert_calls([['build', 'firefox', *GENERATE]])
        self.assertFalse((self.runtime / 'instrumented').exists())

    def test_generation_still_rejects_ambiguous_runtime_archives(self):
        self.env['UPSTREAM'] = str(self.upstream)
        self.values['ambiguous_runtime'] = True
        result = self.execute('run-pgo-generate.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Expected one browser runtime archive, found 2', result.stderr)

    def test_use_cli_preserves_target_order_native_build_and_selected_path(self):
        result = self.execute('run-pgo-use.sh', '--stage', 'firefox')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_calls([['showconf', 'firefox', 'filename', *USE],
            ['showconf', 'firefox', 'build_log', *USE], ['build', 'firefox', *USE]])
        args = json.loads((self.base / 'collect.json').read_text())
        self.assertEqual(args[args.index('--directory') + 1], self.relative_upstream + '/out/firefox/firefox-selected')
        self.assertTrue((self.runtime / 'pgo-use/firefox-project.log').is_file())

    def test_use_still_rejects_unsafe_selected_filename_before_build(self):
        self.values['firefox|filename'] = '../unsafe\n'
        result = self.execute('run-pgo-use.sh', '--stage', 'firefox')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsafe RBM output filename', result.stderr)
        self.assert_calls([['showconf', 'firefox', 'filename', *USE]])

    def test_prepare_cli_preserves_identity_queries_input_logs_and_raw_renders(self):
        result = self.execute('prepare-pgo-use.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_calls([['showconf', 'rust', 'filename', *GENERATE], ['showconf', 'rust', 'filename', *USE],
            ['showconf', 'firefox', 'input_files_by_name/rust', *USE], ['showconf', 'firefox', 'build', *COMMON],
            ['showconf', 'firefox', 'build', *USE], ['showconf', 'firefox', 'input_files', *USE]])
        self.assertEqual((self.runtime / 'pgo-use/firefox-baseline.rendered').read_bytes(), BASELINE.encode())
        self.assertEqual((self.runtime / 'pgo-use/firefox-pgo-use.rendered').read_bytes(), PROFILE_USE.encode())
        self.assertEqual((self.runtime / 'pgo-use/firefox-inputs.log').read_bytes(), b' exact inputs\n\n')

    def test_prepare_still_rejects_wrong_profile_use_configure_render(self):
        self.values['firefox|build|pgo-use'] = PROFILE_USE.replace('--with-pgo-jarlog=', '--incorrect-jarlog=')
        result = self.execute('prepare-pgo-use.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('profile-use argument missing from configure', result.stderr)


if __name__ == '__main__':
    unittest.main()
