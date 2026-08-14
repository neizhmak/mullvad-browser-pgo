#!/usr/bin/env python3
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=(ROOT/'.github/workflows/pgo-stage4a.yml').read_text()
PATCH=(ROOT/'patches/firefox-pgo-generate.patch').read_text()
TRAIN=(ROOT/'scripts/train-pgo.ps1').read_text()
RUN=(ROOT/'scripts/run-pgo-generate.sh').read_text()
PUBLISH=(ROOT/'scripts/publish-pgo-profile.py').read_text()
BASELINE=(ROOT/'.github/workflows/baseline.yml').read_text()
class Stage4ATests(unittest.TestCase):
 def test_baseline_remains_non_pgo_control(self):
  self.assertNotIn('profile-generate',BASELINE); self.assertNotIn('pgo-generate',BASELINE)
  self.assertIn('make mullvadbrowser-alpha-windows-x86_64', (ROOT/'scripts/run-baseline-build.sh').read_text())
 def test_overlay_is_explicit_cross_generation_only(self):
  self.assertIn('--enable-profile-generate=cross',PATCH)
  self.assertIn('pgo-generate:',PATCH); self.assertNotIn('--enable-profile-use',PATCH)
  self.assertIn('--target pgo-generate',RUN)
 def test_generate_and_use_are_mutually_excluded(self):
  self.assertIn("grep -F -- '--enable-profile-use'",RUN)
  self.assertIn('profile-use was accidentally enabled',RUN)
 def test_training_is_native_windows_exact_profileserver(self):
  self.assertIn('runs-on: windows-2025',WORKFLOW)
  self.assertIn('build\\pgo\\profileserver.py',TRAIN)
  self.assertIn('git -C $env:RUNNER_TEMP\\firefox-source fetch --depth=1 origin $env:FIREFOX_REVISION',TRAIN)
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
if __name__=='__main__': unittest.main()
