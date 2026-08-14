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
  self.assertIn('git -C $source fetch --depth=1 origin',TRAIN)
  self.assertIn('$env:FIREFOX_REF',TRAIN)
  self.assertNotIn('wine', (WORKFLOW+TRAIN).lower())
  self.assertNotIn('speedometer', (WORKFLOW+TRAIN).lower())
 def test_training_rejects_empty_outputs(self):
  self.assertIn("'*.profraw'",TRAIN); self.assertIn('Length -gt 0',TRAIN)
  self.assertIn('no non-empty jarlog was produced',TRAIN)
 def test_merge_uses_restored_matching_profdata_and_rejects_empty(self):
  self.assertIn('restore-required --upstream "$UPSTREAM" --stage mingw-w64-clang',WORKFLOW)
  self.assertIn('LLVM_PROFDATA=$profdata',WORKFLOW)
  self.assertIn("-name '*.profraw' -size +0c",WORKFLOW)
  self.assertIn("test -s \"$RUNNER_TEMP/training/jarlog\"",WORKFLOW)
  self.assertIn('show --summary-only',WORKFLOW)
 def test_publication_registry_is_commit_marker_uploaded_last(self):
  self.assertIn("payload=[d/'merged.profdata',d/'jarlog',d/'provenance.json']",PUBLISH)
  self.assertLess(PUBLISH.index("for f in payload:"),PUBLISH.rindex("str(registry)"))
  self.assertIn("if 'profile-registry.json' in current",PUBLISH)
  self.assertIn('conflicting verified profile already committed',PUBLISH)
  self.assertIn('committed:true',WORKFLOW)
 def test_pgo_target_alone_selects_distinct_profiler_rust(self):
  self.assertIn('pgo-generate:',PATCH)
  self.assertIn('filename_targets: "[% c(\'var/platform\') %]-profiler"',PATCH)
  self.assertIn('--set build.profiler=true',PATCH)
  self.assertNotIn('build.profiler',BASELINE)
  self.assertIn("normal == pgo",RUST_IDENTITY)
 def test_official_rust_release_is_never_used_for_pgo_publication(self):
  self.assertIn('PGO_TOOLCHAIN_RELEASE=pgo-toolchains-$tag',WORKFLOW)
  self.assertIn('--release "$PGO_TOOLCHAIN_RELEASE" --stage rust-pgo',WORKFLOW)
  self.assertNotIn('publish --upstream "$UPSTREAM" --release "$RBM_RELEASE" --stage rust-pgo',WORKFLOW)
  self.assertIn('conflicting existing RBM output',RELEASES)
 def test_pgo_rust_registry_has_separate_bound_provenance(self):
  for field in ('upstream','rust','overlay','mingw_w64_clang','sha256','size'):
   self.assertIn(field,RUST_IDENTITY)
  self.assertIn('"identity": identity',RELEASES)
  self.assertIn('registry_identity(data) != expected_identity',RELEASES)
  self.assertLess(RELEASES.index('for path, artifact in zip(paths, artifacts):'),
                  RELEASES.rindex('upload_asset(args, registry)'))
 def test_committed_pgo_rust_is_restored_and_build_skipped(self):
  self.assertIn("stage-complete",WORKFLOW); self.assertIn("complete=true",WORKFLOW)
  self.assertIn("steps.pgo_rust.outputs.complete == 'true'",WORKFLOW)
  self.assertIn("steps.pgo_rust.outputs.complete != 'true'",WORKFLOW)
 def test_profile_generate_link_preflight_is_fatal_before_firefox(self):
  self.assertIn('-C "profile-generate=$profile"',PREFLIGHT)
  self.assertIn('--target "$target"',PREFLIGHT)
  self.assertIn('rustc sysroot:',PREFLIGHT); self.assertIn('--print target-libdir',PREFLIGHT)
  self.assertIn('pgo-rust-runtime-inventory.log',PREFLIGHT)
  self.assertLess(WORKFLOW.index('Functionally preflight exact Firefox PGO Rust toolchain'),
                  WORKFLOW.index('Build only instrumented Firefox'))
 def test_no_rust_pgo_workaround(self):
  combined=WORKFLOW+PATCH+RUN+PREFLIGHT
  self.assertNotIn('MOZ_PGO_RUST=0',combined)
  self.assertNotIn('--disable-profile-generate',combined)
  self.assertIn('--enable-profile-generate=cross',combined)
if __name__=='__main__': unittest.main()
