#!/usr/bin/env python3
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=(ROOT/'.github/workflows/pgo-stage4a.yml').read_text()
PATCH=(ROOT/'patches/firefox-pgo-generate.patch').read_text()
TRAIN=(ROOT/'scripts/train-pgo.ps1').read_text()
RUN=(ROOT/'scripts/run-pgo-generate.sh').read_text()
PUBLISH=(ROOT/'scripts/publish-pgo-profile.py').read_text()
PREFLIGHT=(ROOT/'scripts/preflight-pgo-rust.sh').read_text()
RUST_IDENTITY=(ROOT/'scripts/resolve-pgo-rust-identity.py').read_text()
RELEASES=(ROOT/'scripts/rbm-release-artifacts.py').read_text()
TOOLCHAIN=(ROOT/'.github/workflows/pgo-toolchain.yml').read_text()
MERGE=(ROOT/'scripts/merge-pgo-profile.py').read_text()
PROFILE=(ROOT/'scripts/profile-artifacts.py').read_text()
VALIDATOR=ROOT/'scripts/validate-pgo-rendering.py'
BASELINE=(ROOT/'.github/workflows/baseline.yml').read_text()
class Stage4ATests(unittest.TestCase):
 def test_baseline_remains_non_pgo_control(self):
  self.assertNotIn('profile-generate',BASELINE); self.assertNotIn('pgo-generate',BASELINE)
  self.assertIn('make mullvadbrowser-alpha-windows-x86_64', (ROOT/'scripts/run-baseline-build.sh').read_text())
 def test_overlay_is_explicit_cross_generation_only(self):
  self.assertIn('--enable-profile-generate=cross',PATCH)
  self.assertIn('pgo-generate:',PATCH); self.assertNotIn('--enable-profile-use',PATCH)
  self.assertIn('--target pgo-generate',RUN)
  self.assertIn('./scripts/validate-pgo-overlay.sh',WORKFLOW)
 def test_effective_rendering_places_option_inside_configure_only_for_pgo(self):
  baseline = ("#!/bin/bash\necho Starting\n./mach configure \\\n"
              "  --with-distribution-id=org.torproject \\\n"
              "  --with-base-browser-version=16.0a9 \\\n"
              "  --without-wasm-sandboxed-libraries\n")
  pgo = baseline.replace("  --with-base", "  --enable-profile-generate=cross \\\n  --with-base")
  with tempfile.TemporaryDirectory() as directory:
   baseline_path=Path(directory)/'baseline'; pgo_path=Path(directory)/'pgo'
   baseline_path.write_text(baseline); pgo_path.write_text(pgo)
   result=subprocess.run([VALIDATOR,'--baseline',baseline_path,'--pgo',pgo_path],text=True,capture_output=True)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertIn('contains --enable-profile-generate=cross',result.stdout)
  with tempfile.TemporaryDirectory() as directory:
   baseline_path=Path(directory)/'baseline'; pgo_path=Path(directory)/'pgo'
   baseline_path.write_text(baseline)
   pgo_path.write_text(baseline + "--enable-profile-generate=cross\n")
   standalone=subprocess.run([VALIDATOR,'--baseline',baseline_path,'--pgo',pgo_path],text=True,capture_output=True)
  self.assertNotEqual(standalone.returncode,0)
 def test_windows_uses_pinned_mach_python_and_collects_profileserver_location(self):
  self.assertIn("actions/setup-python@v5",WORKFLOW)
  self.assertIn("python-version: '3.12'",WORKFLOW)
  self.assertIn('python mach python --virtualenv build build/pgo/profileserver.py',TRAIN)
  self.assertNotIn('$env:LLVM_PROFILE_FILE',TRAIN)
  self.assertIn("Get-ChildItem $source -File -Filter '*.profraw'",TRAIN)
  self.assertIn('Remove-Item -Force',TRAIN)
  self.assertIn('Move-Item -LiteralPath',TRAIN)
  self.assertIn('profileserver.py SHA-256 does not match generation provenance',TRAIN)
 def test_namespace_setup_reuses_nonoverlapping_range_logic(self):
  self.assertIn('conflicts = [stop for start, stop in ranges',WORKFLOW)
  self.assertIn('missing_files=()',WORKFLOW)
  self.assertNotIn('echo "$user:100000:65536"',WORKFLOW)
 def test_generate_and_use_are_mutually_excluded(self):
  self.assertIn("grep -F -- '--enable-profile-use'",RUN)
  self.assertIn('profile-use was accidentally enabled',RUN)
 def test_training_is_native_windows_exact_profileserver(self):
  self.assertIn('runs-on: windows-2025',WORKFLOW)
  self.assertIn('build\\pgo\\profileserver.py',TRAIN)
  self.assertIn("'-C', $source, 'fetch', '--depth=1', 'origin'",TRAIN)
  self.assertIn('$env:FIREFOX_REF',TRAIN)
  self.assertNotIn('wine', (WORKFLOW+TRAIN).lower())
  self.assertNotIn('speedometer', (WORKFLOW+TRAIN).lower())
 def test_training_rejects_empty_outputs(self):
  self.assertIn("'*.profraw'",TRAIN); self.assertIn('Length -gt 0',TRAIN)
  self.assertIn('no non-empty jarlog was produced',TRAIN)
 def test_merge_uses_restored_matching_profdata_and_rejects_empty(self):
  self.assertIn('--stage mingw-w64-clang',WORKFLOW)
  self.assertIn('LLVM_PROFDATA=$profdata',WORKFLOW)
  self.assertIn('.toolchains.clang.sha256',WORKFLOW)
  self.assertIn('sha256sum --check --strict',WORKFLOW)
  self.assertIn('Merge and verify C++ AND Rust profile counters',WORKFLOW)
  self.assertNotIn('--summary-only',WORKFLOW)
  self.assertNotIn('"--summary-only"',MERGE)
  self.assertIn('--training-directory',WORKFLOW)
 def test_publication_registry_is_commit_marker_uploaded_last(self):
  self.assertIn('profile-artifacts.py release-tag',WORKFLOW)
  self.assertIn('profile-artifacts.py identity',WORKFLOW)
  self.assertIn('Publish verified payloads with registry last',WORKFLOW)
  self.assertIn('Technical C++/Rust profile checkpoint',WORKFLOW)
  self.assertIn('--latest=false',WORKFLOW)
  self.assertIn('artifacts.publish(args.repository, args.release, args.directory)',PUBLISH)
 def test_pgo_target_alone_selects_distinct_profiler_rust(self):
  self.assertIn('pgo-generate:',PATCH)
  self.assertIn('filename_targets: "[% c(\'var/platform\') %]-profiler"',PATCH)
  self.assertIn('--set target.x86_64-pc-windows-gnullvm.profiler=true',PATCH)
  self.assertNotIn('--set build.profiler=true',PATCH)
  self.assertNotIn('build.profiler',BASELINE)
  self.assertIn("normal == pgo",RUST_IDENTITY)
 def test_official_rust_release_is_never_used_for_pgo_publication(self):
  self.assertIn('pgo-toolchains-$(jq -r .tag upstream.lock.json)-$sha',TOOLCHAIN)
  self.assertIn('--release "$PGO_TOOLCHAIN_RELEASE" --stage rust-pgo',WORKFLOW+TOOLCHAIN)
  self.assertNotIn('publish --upstream "$UPSTREAM" --release "$RBM_RELEASE" --stage rust-pgo',WORKFLOW)
  self.assertIn('conflicting existing RBM output',RELEASES)
 def test_pgo_rust_registry_has_separate_bound_provenance(self):
  for field in ('upstream','rust','overlay','mingw_w64_clang','sha256','size'):
   self.assertIn(field,RUST_IDENTITY)
  self.assertIn('"identity": identity',RELEASES)
  self.assertIn('expected_identity',RELEASES)
  self.assertLess(RELEASES.index('for path, artifact in zip(paths, artifacts):'),
                  RELEASES.rindex('upload_asset(args, registry)'))
 def test_committed_pgo_rust_is_restored_and_build_skipped(self):
  self.assertIn("stage-complete",TOOLCHAIN); self.assertIn("complete=true",TOOLCHAIN)
  self.assertIn("steps.cache.outputs.complete == 'true'",TOOLCHAIN)
  self.assertIn("steps.cache.outputs.complete != 'true'",TOOLCHAIN)
  self.assertIn('rust-native-check',TOOLCHAIN)
 def test_profile_generate_link_preflight_is_fatal_before_firefox(self):
  self.assertIn('-C "profile-generate=$profile"',PREFLIGHT)
  self.assertIn('--target "$target"',PREFLIGHT)
  self.assertIn('rustc sysroot:',PREFLIGHT); self.assertIn('--print target-libdir',PREFLIGHT)
  self.assertIn('pgo-rust-runtime-inventory.log',PREFLIGHT)
  self.assertLess(WORKFLOW.index('./scripts/preflight-pgo-rust.sh'),
                  WORKFLOW.index('Build only instrumented Firefox'))
 def test_no_rust_pgo_workaround(self):
  combined=WORKFLOW+PATCH+RUN+PREFLIGHT
  self.assertNotIn('MOZ_PGO_RUST=0',combined)
  self.assertNotIn('--disable-profile-generate',combined)
  self.assertIn('--enable-profile-generate=cross',combined)
if __name__=='__main__': unittest.main()
