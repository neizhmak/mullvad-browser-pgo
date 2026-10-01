#!/usr/bin/env python3
"""Behavioral tests with fake native tools. No network/builds/dependencies.

Run from repository root: python3 tests/test_profile_pipeline.py
Windows package extraction still needs a real hosted Windows run.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

FAKE_LLVM = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
with open(os.environ['TOOL_CALLS'],'a') as stream: stream.write(json.dumps(args)+'\n')
mode=os.environ.get('LLVM_MODE','good')
if args==['--version']:
 print('llvm-profdata\nLLVM version '+('22.1.0' if mode=='version-mismatch' else '21.1.8'));sys.exit(0)
if args[0]=='merge':
 if mode=='merge-fail':print('raw profile version mismatch',file=sys.stderr);sys.exit(23)
 target=pathlib.Path(args[args.index('-o')+1])
 target.write_bytes(b'' if mode=='empty-merge' else b'merged:'+b','.join(pathlib.Path(a).read_bytes() for a in args[args.index('-o')+2:]))
 sys.exit(0)
if args[0]=='show':
 assert '--summary-only' not in args
 if mode=='show-fail':print('bad indexed profile',file=sys.stderr);sys.exit(29)
 summary='Instrumentation level: IR\nTotal functions: 2\nMaximum function count: 0\nMaximum internal block count: 5\nTotal number of blocks: 3\nTotal count: 9\n'
 if mode=='zero':summary='Total functions: 2\nMaximum function count: 0\nMaximum internal block count: 0\nTotal number of blocks: 3\nTotal count: 0\n'
 if mode=='bad-summary':summary='unsupported profile format'
 if '--all-functions' in args:
  print('Counters:')
  if mode!='no-cpp':
   print('  _ZN7mozilla6Widget5PaintEv:\n    Hash: 0x123\n    Counters: 2\n    Block counts: [4, 0]')
  if mode!='no-rust':
   print('  '+('_RNvCs123_7webrender5paint' if mode=='rust-v0' else '_ZN9webrender5paint17h0123456789abcdefE')+':\n    Hash: 0x456\n    Counters: 1\n    Block counts: ['+('0' if mode=='zero-rust' else '5')+']')
 print(summary,end='');sys.exit(0)
sys.exit(91)
'''

FAKE_GH = r'''#!/usr/bin/env python3
import json,os,pathlib,shutil,sys
args=sys.argv[1:]
with open(os.environ['GH_CALLS'],'a') as stream:stream.write(json.dumps(args)+'\n')
base=pathlib.Path(os.environ['RELEASE_STORE'])
command,tag=args[1:3]
release=base/tag
mode=os.environ.get('GH_MODE','good')
if command=='view':
 if not release.is_dir():print('release missing',file=sys.stderr);sys.exit(44)
 assets=[{'name':p.name,'size':p.stat().st_size} for p in sorted(release.iterdir()) if p.is_file()]
 if mode=='duplicate-assets' and assets:assets.append(assets[0])
 print(json.dumps({'assets':assets,'isPrerelease':mode!='stable-release'}));sys.exit(0)
if command=='download':
 name=args[args.index('--pattern')+1];dest=pathlib.Path(args[args.index('--output')+1])
 if mode=='download-fail':print('download denied',file=sys.stderr);sys.exit(67)
 if not (release/name).is_file():sys.exit(4)
 if dest.exists():print('download already exists',file=sys.stderr);sys.exit(5)
 shutil.copyfile(release/name,dest)
 if mode=='download-corrupt' and name=='merged.profdata':dest.write_bytes(b'tampered')
 sys.exit(0)
if command=='upload':
 source=pathlib.Path(args[3]);dest=release/source.name
 if dest.exists():print('immutable asset exists',file=sys.stderr);sys.exit(9)
 shutil.copyfile(source,dest)
 if mode=='upload-corrupt' and source.name=='merged.profdata':dest.write_bytes(b'bad')
 sys.exit(0)
sys.exit(92)
'''

FAKE_MACH = r'''import json,os,pathlib,sys
args=sys.argv[1:]
assert args[:3]==['python','--virtualenv','build'],args
out=pathlib.Path(os.environ['UPLOAD_PATH'])
with open(out/'mach-calls.jsonl','a') as stream:stream.write(json.dumps({'args':args,'env':{k:os.environ.get(k) for k in ['LLVM_PROFDATA','LLVM_PROFILE_FILE','JARLOG_FILE','MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE','MOZ_FETCHES_DIR']}})+'\n')
mode=os.environ.get('MACH_MODE','good')
if args[3]=='-c':
 if mode=='bootstrap-fail':print('cannot import mozrunner',file=sys.stderr);sys.exit(17)
 print('Pinned build Python: fake probe');sys.exit(0)
assert args[3]=='build/pgo/profileserver.py' and args[4]=='--binary',args
pathlib.Path('default_123_random_456.profraw').write_bytes(b'firefox C++ AND Rust counters')
(out/'profile-run-1.log').write_text('native initialization complete\n')
(out/'profile-run-2.log').write_text('LLVM Profile Error: invalid profile' if mode=='llvm-error' else 'native workload complete\n')
print('native profileserver workload')
if mode=='workload-fail':sys.exit(19)
if mode=='crash':(out/'crash.dmp').write_bytes(b'minidump')
if mode=='empty-logs':
 (out/'profile-run-1.log').write_text('')
 (out/'profile-run-2.log').write_text('')
if mode=='timeout':
 import subprocess,time
 child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
 (out/'child.pid').write_text(str(child.pid))
 time.sleep(60)
if mode=='no-raw':pathlib.Path('default_123_random_456.profraw').unlink()
if mode=='no-jarlog':sys.exit(0)
pathlib.Path(os.environ['JARLOG_FILE']).write_text('omni.ja startup resources\n')
'''

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def put_json(path, data):
    Path(path).write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')


class ProfilePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='profile-tests-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.source = self.base / 'source'
        (self.source / 'build/pgo').mkdir(parents=True)
        (self.source / 'build/pgo/profileserver.py').write_text('# exact pinned workload fixture\n')
        (self.source / 'mach').write_text(FAKE_MACH)
        self.package = self.base / 'instrumented.tar.xz'
        self.package.write_bytes(b'instrumented Windows Firefox package')
        self.binary = self.base / 'firefox.exe'
        self.binary.write_bytes(b'MZ binary fixture')
        self.training = self.base / 'training'
        self.training.mkdir()
        self.output = self.base / 'profile'
        self.release_store = self.base / 'releases'
        self.release_store.mkdir()
        self.calls = self.base / 'llvm-calls.jsonl'
        self.gh_calls = self.base / 'gh-calls.jsonl'
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.bin)+os.pathsep+self.env.get('PATH',''),
                        TOOL_CALLS=str(self.calls),GH_CALLS=str(self.gh_calls),
                        RELEASE_STORE=str(self.release_store))
        for name, text in [('llvm-profdata',FAKE_LLVM),('gh',FAKE_GH)]:
            path = self.bin / name
            path.write_text('#!'+sys.executable+'\n'+text.split('\n',1)[1])
            path.chmod(0o755)
        self.build = {'schema':2,'upstream_lock':{'repository':'https://example.test/build.git','tag':'mb-16.0a9-build1','commit':'a'*40,'tag_object':'b'*40},
                      'firefox':{'repository':'https://example.test/firefox.git','ref':'firefox-tag','revision':'c'*40},
                      'profileserver':{'path':'build/pgo/profileserver.py','revision':'c'*40,'sha256':digest(self.source/'build/pgo/profileserver.py')},
                      'pgo_overlay_sha256':'d'*64,'pgo_languages':['c++','rust'],'rust_pgo_identity_sha256':'e'*64,
                      'instrumented_package_sha256':digest(self.package),
                      'clang_identity':'clang version 21.1.8 (pinned source)','rust_identity':'rustc 1.94.0 (pinned source)',
                      'toolchains':{'clang':{'archive_filename':'mingw-clang.tar.zst','sha256':'f'*64,'size':8,'version':'clang version 21.1.8'},
                                    'rust':{'archive_filename':'rust-profiler.tar.zst','sha256':'0'*64,'size':9,'version':'rustc 1.94.0 (LLVM 22.0)'}},
                      'generation_targets':['alpha','mullvadbrowser-windows-x86_64','pgo-generate'],
                      'generation_configure_flags':['--enable-profile-generate=cross']}
        self.build_path = self.base/'build.json'
        put_json(self.build_path,self.build)

    def run_tool(self, name, *args, env=None):
        return subprocess.run([sys.executable,str(SCRIPTS/name),*map(str,args)],cwd=ROOT,
                              env=env or self.env,text=True,capture_output=True)

    def good(self, result):
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
        return result

    def training_fixture(self):
        (self.training/'default_123_random_456.profraw').write_bytes(b'C++ counters')
        (self.training/'default_124_random_457.profraw').write_bytes(b'Rust counters')
        (self.training/'jarlog').write_bytes(b'omni.ja ordered jar resources\n')
        for name in ('profileserver.log','profile-run-1.log','profile-run-2.log'):
            (self.training/name).write_text('native Firefox exited 0\n')
        put_json(self.training/'native-status.json',{'schema':1,'bootstrap_exit_code':0,'profileserver_exit_code':0,'timed_out':False})
        self.record()

    def record(self):
        return self.good(self.run_tool('profile-artifacts.py','record-training',
                         '--training-directory',self.training,'--build-provenance',self.build_path,
                         '--source-directory',self.source,'--instrumented-package',self.package))

    def merge(self, mode='good', good=True):
        self.env['LLVM_MODE']=mode
        result=self.run_tool('merge-pgo-profile.py','--llvm-profdata',self.bin/'llvm-profdata',
                             '--training-directory',self.training,'--build-provenance',self.build_path,
                             '--output-directory',self.output)
        return self.good(result) if good else result

    def bundle(self, mode='good'):
        self.training_fixture()
        self.merge(mode)
        self.registry=json.loads((self.output/'profile-registry.json').read_text())
        self.tag=self.registry['release_tag']
        self.release=self.release_store/self.tag
        self.release.mkdir()
        return self.registry

    def publish(self):
        return self.run_tool('publish-pgo-profile.py','--repository','owner/repo',
                             '--release',self.tag,'--directory',self.output)

    def uploads(self):
        if not self.gh_calls.exists():return []
        return [json.loads(line)[3] for line in self.gh_calls.read_text().splitlines()
                if json.loads(line)[1]=='upload']

    def restore(self, destination=None, source=True, identity=None, expected=None):
        args=['restore','--directory',destination or self.base/'restored',
              '--expected-provenance',expected or self.build_path,
              '--expected-identity',identity or self.registry['identity_sha256']]
        args+=['--source-directory',self.output] if source else ['--repository','owner/repo','--release',self.tag]
        return self.run_tool('profile-artifacts.py',*args)

    def train(self,mode='good'):
        self.env['MACH_MODE']=mode
        return self.run_tool('profile-artifacts.py','run-profileserver','--source-directory',self.source,
                             '--binary',self.binary,'--output-directory',self.training,
                             '--build-provenance',self.build_path)

    def test_training_native_mach_contract_and_env(self):
        self.env['LLVM_PROFDATA']='wrong-host-tool'
        self.env['LLVM_PROFILE_FILE']='preflight.profraw'
        self.env['MACH_USE_SYSTEM_PYTHON']='1'
        (self.source/'stale.profraw').write_bytes(b'do not include')
        self.good(self.train())
        self.record()
        calls=[json.loads(line) for line in (self.training/'mach-calls.jsonl').read_text().splitlines()]
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[1]['args'][3:5],['build/pgo/profileserver.py','--binary'])
        self.assertEqual(calls[1]['env']['MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE'],'pip')
        self.assertIsNone(calls[1]['env']['LLVM_PROFDATA'])
        self.assertIsNone(calls[1]['env']['LLVM_PROFILE_FILE'])
        self.assertFalse((self.source/'stale.profraw').exists())
        self.assertNotIn('stale.profraw',(self.training/'training-manifest.json').read_text())

    def test_training_silent_browser_logs_are_accepted(self):
        self.good(self.train('empty-logs'))
        self.record()
        self.assertEqual((self.training/'profile-run-2.log').stat().st_size,0)

    def test_training_timeout_preserves_status_and_partial_diagnostics(self):
        self.env['MACH_MODE']='timeout'
        result=self.run_tool('profile-artifacts.py','run-profileserver','--source-directory',self.source,
                             '--binary',self.binary,'--output-directory',self.training,
                             '--build-provenance',self.build_path,'--timeout-seconds','1')
        self.assertEqual(result.returncode,124,result.stderr)
        status=json.loads((self.training/'native-status.json').read_text())
        self.assertTrue(status['timed_out'])
        self.assertEqual(status['profileserver_exit_code'],124)
        self.assertTrue((self.training/'default_123_random_456.profraw').exists())
        self.assertIn('exceeded its timeout',(self.training/'profileserver.log').read_text())
        # Linux process-state check is nonblocking; zombie children are dead.
        pid=int((self.training/'child.pid').read_text())
        proc=Path('/proc')/str(pid)/'stat'
        if proc.exists():
            self.assertEqual(proc.read_text().split()[2],'Z')

    def test_training_bootstrap_native_failure_preserved(self):
        result=self.train('bootstrap-fail')
        self.assertEqual(result.returncode,17,result.stderr)
        self.assertTrue((self.training/'bootstrap.log').is_file())
        self.assertEqual(json.loads((self.training/'native-status.json').read_text())['bootstrap_exit_code'],17)
        self.assertFalse((self.training/'profileserver.log').exists())

    def test_training_workload_native_failure_and_raw_diagnostics_preserved(self):
        result=self.train('workload-fail')
        self.assertEqual(result.returncode,19,result.stderr)
        self.assertTrue((self.training/'default_123_random_456.profraw').is_file())
        self.assertEqual(json.loads((self.training/'native-status.json').read_text())['profileserver_exit_code'],19)
        self.assertFalse((self.training/'training-manifest.json').exists())

    def test_training_checks_second_browser_log(self):
        result=self.train('llvm-error')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('profile-run-2.log',result.stderr)
        self.assertTrue((self.training/'default_123_random_456.profraw').exists())

    def test_training_crash_is_fatal_even_native_status_zero(self):
        result=self.train('crash')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue((self.training/'crash.dmp').exists())

    def test_training_record_rejects_package_hash_mismatch(self):
        self.good(self.train())
        self.package.write_bytes(b'package changed after generation')
        result=self.run_tool('profile-artifacts.py','record-training','--training-directory',self.training,
                             '--build-provenance',self.build_path,'--source-directory',self.source,
                             '--instrumented-package',self.package)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('package SHA-256',result.stderr)

    def test_training_record_rejects_missing_raw(self):
        self.good(self.train('no-raw'))
        result=self.run_tool('profile-artifacts.py','record-training','--training-directory',self.training,
                             '--build-provenance',self.build_path,'--source-directory',self.source,
                             '--instrumented-package',self.package)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('no raw',result.stderr)

    def test_training_record_rejects_missing_jarlog(self):
        self.good(self.train('no-jarlog'))
        result=self.run_tool('profile-artifacts.py','record-training','--training-directory',self.training,
                             '--build-provenance',self.build_path,'--source-directory',self.source,
                             '--instrumented-package',self.package)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('jarlog',result.stderr)

    def test_training_rejects_stale_outputs_before_native_command(self):
        (self.training/'old.profraw').write_bytes(b'old')
        result=self.train()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.training/'mach-calls.jsonl').exists())

    def test_training_rejects_profileserver_hash_mismatch(self):
        (self.source/'build/pgo/profileserver.py').write_text('# modified server')
        result=self.train()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.training/'mach-calls.jsonl').exists())

    def test_merge_ordinary_show_useful_cpp_and_rust(self):
        registry=self.bundle()
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls[2],['show',str(self.output/'merged.profdata')])
        self.assertIn('--failure-mode=any',calls[1])
        self.assertIn('--all-functions',calls[3])
        evidence=registry['provenance']['counter_evidence']
        self.assertEqual(evidence['positive_cpp_functions'],1)
        self.assertEqual(evidence['positive_rust_functions'],1)
        for name in ('merged.profdata','jarlog','provenance.json'):
            self.assertEqual(registry['assets'][name]['sha256'],digest(self.output/name))
        self.assertIn(registry['identity_sha256'],self.tag)

    def test_merge_rust_v0_symbols_accepted(self):
        registry=self.bundle('rust-v0')
        self.assertEqual(registry['provenance']['counter_evidence']['positive_rust_functions'],1)

    def test_merge_preserves_native_failure_and_log(self):
        self.training_fixture()
        result=self.merge('merge-fail',False)
        self.assertEqual(result.returncode,23,result.stderr)
        self.assertIn('raw profile version mismatch',(self.output/'llvm-profdata-merge.log').read_text())
        self.assertFalse((self.output/'profile-registry.json').exists())

    def test_merge_preserves_show_native_failure(self):
        self.training_fixture()
        result=self.merge('show-fail',False)
        self.assertEqual(result.returncode,29,result.stderr)
        self.assertFalse((self.output/'profile-registry.json').exists())

    def test_merge_rejects_zero_counters(self):
        self.training_fixture()
        self.assertNotEqual(self.merge('zero',False).returncode,0)
        self.assertFalse((self.output/'profile-registry.json').exists())

    def test_merge_rejects_rust_absent(self):
        self.training_fixture()
        self.assertIn('no positive Rust',self.merge('no-rust',False).stderr)

    def test_merge_rejects_cpp_absent(self):
        self.training_fixture()
        self.assertIn('no positive C++',self.merge('no-cpp',False).stderr)

    def test_merge_rejects_rust_zero_only(self):
        self.training_fixture()
        self.assertIn('no positive Rust',self.merge('zero-rust',False).stderr)

    def test_merge_rejects_empty_merge_file(self):
        self.training_fixture()
        self.assertNotEqual(self.merge('empty-merge',False).returncode,0)
        self.assertFalse((self.output/'profile-registry.json').exists())

    def test_merge_rejects_unknown_show_summary(self):
        self.training_fixture()
        self.assertIn('incomplete instrumentation',self.merge('bad-summary',False).stderr)

    def test_merge_rejects_wrong_profdata_version_before_merge(self):
        self.training_fixture()
        result=self.merge('version-mismatch',False)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(len(self.calls.read_text().splitlines()),1)

    def test_merge_rejects_raw_hash_tampering(self):
        self.training_fixture()
        (self.training/'default_123_random_456.profraw').write_bytes(b'changed')
        self.assertIn('asset hash/size mismatch',self.merge(good=False).stderr)
        self.assertFalse(self.calls.exists())

    def test_merge_rejects_preflight_or_unrecorded_raw(self):
        self.training_fixture()
        (self.training/'preflight.profraw').write_bytes(b'separate Rust preflight')
        self.assertIn('unrecorded/missing raw',self.merge(good=False).stderr)

    def test_merge_rejects_changed_build_provenance(self):
        self.training_fixture()
        self.build['firefox']['revision']='a'*40
        self.build['profileserver']['revision']='a'*40
        put_json(self.build_path,self.build)
        self.assertIn('different build provenance',self.merge(good=False).stderr)

    def test_training_rejects_out_of_scope_generation_target(self):
        self.build['generation_targets']=['alpha','mullvadbrowser-linux-x86_64','pgo-generate']
        put_json(self.build_path,self.build)
        result=self.train()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Alpha Windows x86_64',result.stderr)

    def test_training_rejects_profile_generate_use_overlap(self):
        self.build['generation_configure_flags'].append('--enable-profile-use')
        put_json(self.build_path,self.build)
        result=self.train()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('generation flags',result.stderr)

    def test_merge_rejects_cpp_only_build_declaration(self):
        self.build['pgo_languages']=['c++']
        put_json(self.build_path,self.build)
        result=self.train()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('C++ AND Rust',result.stderr)

    def test_publish_registry_last_and_download_payloads_back(self):
        self.bundle()
        self.good(self.publish())
        uploads=[Path(path).name for path in self.uploads()]
        self.assertEqual(uploads,['merged.profdata','jarlog','provenance.json','profile-registry.json'])
        self.assertEqual({p.name for p in self.release.iterdir()},set(uploads))
        calls=[json.loads(line) for line in self.gh_calls.read_text().splitlines()]
        self.assertEqual(sum(c[1]=='download' for c in calls),3)

    def test_publish_committed_idempotence_checks_all_payloads(self):
        self.bundle()
        self.good(self.publish())
        self.gh_calls.write_text('')
        self.good(self.publish())
        self.assertEqual(self.uploads(),[])
        downloads=[json.loads(line) for line in self.gh_calls.read_text().splitlines() if json.loads(line)[1]=='download']
        self.assertEqual(len(downloads),4)

    def test_publish_identical_registry_does_not_hide_tampered_payload(self):
        self.bundle()
        self.good(self.publish())
        (self.release/'merged.profdata').write_bytes(b'tampered committed asset')
        self.gh_calls.write_text('')
        result=self.publish()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.uploads(),[])
        self.assertEqual((self.release/'merged.profdata').read_bytes(),b'tampered committed asset')

    def test_publish_identical_registry_does_not_hide_missing_payload(self):
        self.bundle()
        self.good(self.publish())
        (self.release/'jarlog').unlink()
        self.gh_calls.write_text('')
        self.assertNotEqual(self.publish().returncode,0)
        self.assertEqual(self.uploads(),[])

    def test_publish_resume_interrupted_identical_payload(self):
        self.bundle()
        (self.release/'merged.profdata').write_bytes((self.output/'merged.profdata').read_bytes())
        self.good(self.publish())
        self.assertEqual([Path(path).name for path in self.uploads()],['jarlog','provenance.json','profile-registry.json'])

    def test_publish_conflicting_interrupted_asset_rejects_before_any_upload(self):
        self.bundle()
        (self.release/'provenance.json').write_bytes(b'conflict')
        self.assertNotEqual(self.publish().returncode,0)
        self.assertEqual(self.uploads(),[])

    def test_publish_upload_corruption_never_commits_registry(self):
        self.bundle()
        self.env['GH_MODE']='upload-corrupt'
        self.assertNotEqual(self.publish().returncode,0)
        self.assertFalse((self.release/'profile-registry.json').exists())

    def test_publish_requires_identity_tag(self):
        self.bundle()
        self.tag='pgo-profile-mb-16.0a9-build1'
        result=self.publish()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.gh_calls.exists())

    def test_publish_rejects_stable_release(self):
        self.bundle()
        self.env['GH_MODE']='stable-release'
        self.assertNotEqual(self.publish().returncode,0)
        self.assertEqual(self.uploads(),[])

    def test_publish_gh_native_exit_preserved(self):
        self.bundle()
        (self.release/'merged.profdata').write_bytes((self.output/'merged.profdata').read_bytes())
        self.env['GH_MODE']='download-fail'
        result=self.publish()
        self.assertEqual(result.returncode,67,result.stderr)

    def test_restore_strict_local_bundle_and_idempotence(self):
        self.bundle()
        self.good(self.restore())
        self.good(self.restore())
        self.assertEqual(digest(self.base/'restored/merged.profdata'),digest(self.output/'merged.profdata'))

    def test_restore_strict_remote_bundle(self):
        self.bundle()
        self.good(self.publish())
        self.good(self.restore(source=False))
        self.assertTrue((self.base/'restored/profile-registry.json').is_file())

    def test_restore_rejects_wrong_identity_before_destination(self):
        self.bundle()
        self.assertNotEqual(self.restore(identity='f'*64).returncode,0)
        self.assertFalse((self.base/'restored').exists())

    def test_restore_rejects_expected_source_mismatch(self):
        self.bundle()
        self.build['firefox']['ref']='other-tag'
        put_json(self.build_path,self.build)
        result=self.restore()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('unexpected profile build provenance: firefox',result.stderr)
        self.assertFalse((self.base/'restored').exists())

    def test_restore_rejects_expected_toolchain_mismatch(self):
        self.bundle()
        self.build['toolchains']['rust']['sha256']='7'*64
        put_json(self.build_path,self.build)
        self.assertNotEqual(self.restore().returncode,0)

    def test_restore_final_build_expectation_can_omit_generation_package(self):
        self.bundle()
        del self.build['instrumented_package_sha256']
        put_json(self.build_path,self.build)
        self.good(self.restore())

    def test_restore_does_not_overwrite_unknown_destination(self):
        self.bundle()
        destination=self.base/'restored'
        destination.mkdir()
        (destination/'unknown').write_bytes(b'keep')
        self.assertNotEqual(self.restore().returncode,0)
        self.assertEqual((destination/'unknown').read_bytes(),b'keep')

    def test_restore_rejects_corrupt_remote_download_atomically(self):
        self.bundle()
        self.good(self.publish())
        self.env['GH_MODE']='download-corrupt'
        self.assertNotEqual(self.restore(source=False).returncode,0)
        self.assertFalse((self.base/'restored').exists())

    def test_registry_wrong_payload_hash_is_fatal(self):
        self.bundle()
        registry=json.loads((self.output/'profile-registry.json').read_text())
        registry['assets']['jarlog']['sha256']='2'*64
        put_json(self.output/'profile-registry.json',registry)
        self.assertNotEqual(self.restore().returncode,0)

    def test_registry_duplicate_keys_are_fatal(self):
        self.bundle()
        path=self.output/'profile-registry.json'
        path.write_text(path.read_text().replace('"schema": 2','"schema": 2, "schema": 2'))
        self.assertIn('duplicate JSON key',self.restore().stderr)

    def test_registry_asset_path_injection_is_fatal(self):
        self.bundle()
        registry=self.registry
        registry['assets']['../../evil']=registry['assets'].pop('jarlog')
        put_json(self.output/'profile-registry.json',registry)
        self.assertNotEqual(self.restore().returncode,0)

    def test_immutable_retraining_identity_changes_same_upstream(self):
        self.bundle()
        first_tag=self.tag
        first_identity=self.registry['identity_sha256']
        second=self.base/'profile2'
        (self.training/'default_123_random_456.profraw').write_bytes(b'new real training counters')
        self.record()
        self.output=second
        self.merge()
        registry=json.loads((second/'profile-registry.json').read_text())
        self.assertNotEqual(registry['identity_sha256'],first_identity)
        self.assertNotEqual(registry['release_tag'],first_tag)
        self.assertIn(self.build['upstream_lock']['tag'],registry['release_tag'])

    @unittest.skipUnless(shutil.which('pwsh'), 'native PowerShell is not installed')
    def test_native_powershell_training_script_parses(self):
        # Parse through native PowerShell, not a text/string assertion.
        path=str(SCRIPTS/'train-pgo.ps1').replace("'", "''")
        command=("$tokens=$null; $errors=$null; "
                 f"[System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$tokens, [ref]$errors) | Out-Null; "
                 "if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }")
        result=subprocess.run(['pwsh','-NoLogo','-NoProfile','-Command',command],cwd=ROOT,
                              env=self.env,text=True,capture_output=True)
        self.good(result)

    @unittest.skipUnless(shutil.which('pwsh'), 'native PowerShell is not installed')
    def test_native_powershell_git_exit_preserved(self):
        runner=self.base/'runner'
        (runner/'provenance').mkdir(parents=True)
        put_json(runner/'provenance/build.json',self.build)
        fakegit=self.bin/'git'
        fakegit.write_text('#!'+sys.executable+'\nimport sys;print("fake git failure",file=sys.stderr);sys.exit(37)\n')
        fakegit.chmod(0o755)
        self.env.update(RUNNER_TEMP=str(runner),FIREFOX_REPOSITORY=self.build['firefox']['repository'],
                        FIREFOX_REF=self.build['firefox']['ref'],FIREFOX_REVISION=self.build['firefox']['revision'])
        result=subprocess.run(['pwsh','-NoLogo','-NoProfile','-File',str(SCRIPTS/'train-pgo.ps1')],
                              cwd=ROOT,env=self.env,text=True,capture_output=True)
        self.assertEqual(result.returncode,37,result.stdout+result.stderr)
        self.assertTrue((runner/'training-output/training-failure.json').is_file())

    def test_identity_and_release_tag_cli_emit_only_values(self):
        self.bundle()
        result=self.good(self.run_tool('profile-artifacts.py','identity','--directory',self.output))
        self.assertEqual(result.stdout.strip(),self.registry['identity_sha256'])
        result=self.good(self.run_tool('profile-artifacts.py','release-tag','--directory',self.output))
        self.assertEqual(result.stdout.strip(),self.tag)


if __name__ == '__main__':
    unittest.main()
